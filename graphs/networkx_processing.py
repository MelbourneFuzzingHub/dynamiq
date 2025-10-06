import os
import subprocess
import sys
import networkx as nx
import logging
from datetime import datetime
import math
from enum import Enum
import re
import json
from concurrent.futures import ThreadPoolExecutor

from utils import helpers
import globals

class ParsingState(Enum):
  INITIAL = 1
  PARSING_FUNCTION_INFO = 2
  PARSING_FILE_INFO = 3

def extract_callgraph(dot_file):
  logging.info("[Initialization] extract_callgraph starts at: %s", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
  print("[+] Analyzing call graph... this can take some time depending on program size.")

  # Read call graph from .dot file and convert to a directed graph (DiGraph)
  CG = nx.DiGraph(nx.nx_pydot.read_dot(dot_file)) 

  # Regex to match labels we want to delete
  unwanted_prefixes = re.compile(r'^(llvm\.|sancov\.|__sanitizer_cov_)')

  # Use ThreadPoolExecutor to speed up processing of nodes (if needed)
  v_fname_dict = {}
  fname_v_dict = {}
  deleted_nodes = []

  def process_node(n):
    try:
      label = CG.nodes[n]['label'].strip('{}"')  # String cleaning
      if unwanted_prefixes.match(label):  # Prefix filtering
        return n, None, None  # Mark node for deletion
      return None, n, label  # Keep node
    except KeyError:
      return n, None, None  # Mark node for deletion

  # Process nodes in parallel
  with ThreadPoolExecutor() as executor:
    results = executor.map(process_node, list(CG.nodes))

  # Store results in dicts
  for del_node, keep_node, func_name in results:
    if del_node:
      deleted_nodes.append(del_node)
    if keep_node and func_name:
      v_fname_dict[keep_node] = func_name
      fname_v_dict[func_name] = keep_node

  # Batch delete unwanted nodes
  CG.remove_nodes_from(deleted_nodes)

  # Find `main` or `LLVMFuzzerTestOneInput` as the main node
  for n in CG.nodes:
    label = CG.nodes[n].get('label', '').strip()
    
    # Extract text inside { } if present
    match = re.search(r"\{([^}]+)\}", label)
    if match:
      label = match.group(1).strip()

    if label == "main" or label == "LLVMFuzzerTestOneInput":  # Direct match
      main_v = n
      break
  else:
    logging.error("No function `main` or `LLVMFuzzerTestOneInput` found in the call graph.")
    exit()

  logging.info("[Initialization] Main function: %s", v_fname_dict[main_v])
  logging.info(
    "[Initialization] Total nodes: %d; deleted: %d; remaining: %d",
    len(CG.nodes) + len(deleted_nodes),
    len(deleted_nodes),
    len(CG.nodes),
  )

  logging.info("[Initialization] extract_callgraph ends at: %s", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
  return CG, v_fname_dict, fname_v_dict, main_v

#remove a node from a given graph and associated dictionaries
def remove_node(CG, v, v_fname_dict, fname_v_dict):
  fname_v_dict.pop(v_fname_dict[v], None)
  v_fname_dict.pop(v, None)
  CG.remove_node(v)

#prune callgraph
def prune_callgraph(CG, main_v, v_fname_dict, fname_v_dict, fname_bbs_dict, fname_src_dict, prune_level=2):
  # prune_level == 1: do all 3 pruning steps
  # prune_level == 2: only do pruning 2 and 3 (skip the first prune phase)
  # prune_level == 3: only do pruning 2 (skip prune 1 and 3)
  # prune_level == 0: only report functions with BB info but not in the call graph
  logging.debug("[CallGraph] prune_callgraph starts at: %s", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))

  deleted_pairs = set()

  # Check if the function has basic block info but is not in the call graph
  missing_bb_funcs = set(fname_bbs_dict.keys()) - set(v_fname_dict.values())
  logging.debug("[CallGraph] Functions with BB info but NOT in call graph: %d", len(missing_bb_funcs))
  for function_name in missing_bb_funcs:
    if function_name in fname_src_dict:
      for (srcFileName, hashId) in fname_src_dict[function_name]:
        deleted_pairs.add((srcFileName, function_name))
  
  # --- If level 0, we only report those and skip all pruning ---
  if prune_level == 0:
    logging.debug("[CallGraph] Skipping graph pruning (level 0 diagnostic mode).")
    return deleted_pairs

  # ---------------- PRUNE PHASE 1 ----------------
  if prune_level == 1:
    logging.debug("[CallGraph] Pruning phase 1: Remove functions missing basic block (BB) info.")

    logging.debug("[CallGraph]  Nodes-before-pruning-1: %d", len(CG.nodes))
    logging.debug("[CallGraph]  Edges-before-pruning-1: %d", len(CG.edges))

    deleted_nodes = []
    try:
      for v in CG.nodes:
        if v_fname_dict[v] not in fname_bbs_dict:
          deleted_nodes.append(v)
    except KeyError:
      pass

    for v in deleted_nodes:
      try:
        if globals.VERBOSE_LEVEL > 3:
          logging.debug("[CallGraph] Deleted-phase-1: %s", v_fname_dict[v])
        globals.spare_functions_set.remove(v_fname_dict[v])
      except KeyError:
        pass
      remove_node(CG, v, v_fname_dict, fname_v_dict)

  # ---------------- PRUNE PHASE 2 ----------------
  logging.debug("[CallGraph] Pruning phase 2: Remove disconnected nodes (no in or out edges).")
  logging.debug("[CallGraph] Nodes and Edges before pruning 2: %d, %d", len(CG.nodes), len(CG.edges))

  deleted_nodes = []
  try:
    for v in CG.nodes:
      if CG.in_degree(v) == 0 and CG.out_degree(v) == 0:
        deleted_nodes.append(v)
  except KeyError:
    pass

  for v in deleted_nodes:
    function_name = v_fname_dict.get(v, "")
    if function_name in fname_src_dict:
      for (srcFileName, hashId) in fname_src_dict[function_name]:
        deleted_pairs.add((srcFileName, function_name))

    if globals.VERBOSE_LEVEL > 3:
      logging.debug("[CallGraph] Deleted-phase-2: %s", v_fname_dict[v])
    globals.spare_functions_set.add(v_fname_dict[v])
    remove_node(CG, v, v_fname_dict, fname_v_dict)

  # ---------------- PRUNE PHASE 3 ----------------
  if prune_level in [1, 2]:
    logging.debug("[CallGraph] Pruning phase 3: Remove nodes not reachable from main.")
    logging.debug("[CallGraph] Nodes and Edges before pruning 3: %d, %d", len(CG.nodes), len(CG.edges))

    deleted_nodes = []
    try:
      for v in CG.nodes:
        if v == main_v:
          continue
        try:
          nx.shortest_path_length(CG, main_v, v)
        except nx.NetworkXNoPath:
          deleted_nodes.append(v)
    except KeyError:
      logging.debug("[CallGraph] Unexpected KeyError when checking reachability.")

    for v in deleted_nodes:
      function_name = v_fname_dict.get(v, "")
      if function_name in fname_src_dict:
        for (srcFileName, hashId) in fname_src_dict[function_name]:
          deleted_pairs.add((srcFileName, function_name))

      if globals.VERBOSE_LEVEL > 3:
        logging.debug("[CallGraph] Deleted-phase-3: %s", v_fname_dict[v])
      globals.spare_functions_set.add(v_fname_dict[v])
      remove_node(CG, v, v_fname_dict, fname_v_dict)

  logging.debug("[CallGraph] Nodes and Edges after all pruning: %d, %d, prune_callgraph ends at: %s", len(CG.nodes), len(CG.edges), datetime.now().strftime("%d/%m/%Y %H:%M:%S"))

  return deleted_pairs

#check and insert functions from tmpFunctions list to Functions list
def update_function_list(Functions, tmpFunctions):
  for f1 in tmpFunctions:
    '''
    Handle cases in which we have more than one function having the same name.
    For example, two test drivers can both have their main function.
    To distinguish them, normally we need to use the source file as well.
    However, in this implementation, we assume that the bcovered info of the target function 
    has the largest value.
    '''
    isExisting = False
    for f2 in Functions:
      if f1.name == f2.name:
        if f1.bcovered > f2.bcovered:
          f2.fname = f1.fname
          f2.fpath = f1.fpath
          f2.btotal = f1.btotal
          f2.bcovered = f1.bcovered     
        #break as long as f1.name equals f2.name
        #so that we do not insert the same function name from files that are not targeted
        isExisting = True
        break

    if isExisting == False:
      Functions.append(f1)

def add_nodes_and_edges(CG, v_fname_dict, fname_v_dict, logFilePath, fname_src_dict):
  added_pairs = set() # Track newly added pairs
  edgeSet = set() # Avoid redundant edges

  if not os.path.exists(logFilePath):
    return added_pairs

  with open(logFilePath, "r") as f:
    # sample line: Function: pngmem.c:png_malloc_base->malloc
    for line in f:
      tmpStrs = line.strip().split(" ")[1].strip().split("->")
      if len(tmpStrs) != 2:
        continue
      if line.strip() in edgeSet:
        continue

      edgeSet.add(line.strip())
      caller = tmpStrs[0].strip().split(":")[1]
      callee = tmpStrs[1].strip()

      for func in [caller, callee]:
        if func not in fname_v_dict:
          CG.add_node(func, style="dashed")
          fname_v_dict[func] = func
          try:
            globals.spare_functions_set.remove(func)
          except KeyError:
              pass

          # Add to added_pairs if source file known
          if func in fname_src_dict:
            for (srcFileName, _) in fname_src_dict[func]:
              added_pairs.add((srcFileName, func))

      # Add metadata and edges
      for func in [caller, callee]:
        CG.nodes[fname_v_dict[func]].update({
          'label': f"{{{func}}}",
          'shape': 'record'
        })
        v_fname_dict[fname_v_dict[func]] = func

      if not CG.has_edge(fname_v_dict[caller], fname_v_dict[callee]):
        CG.add_edge(fname_v_dict[caller], fname_v_dict[callee], style="dashed")

  # logging.debug("Added pairs: %s", added_pairs)
  return added_pairs


def remove_gcov_files(gcov_folders):
  """
  Removes gcov-related files (.gcda) from multiple folders.
  """
  # Ensure DYNAMIQ is set in the environment
  dynamiq_dir = os.environ.get('DYNAMIQ')
  if not dynamiq_dir:
    raise EnvironmentError("The DynamiQ environment variable is not set.")

  # Path to the bash script
  script_path = os.path.join(dynamiq_dir, "remove-gcda-files.sh")

  # Check if the script exists
  if not os.path.isfile(script_path):
    raise FileNotFoundError(f"The script {script_path} does not exist.")

  # Process each gcov folder
  for gcov_folder in gcov_folders:
    # Construct and run the command
    command = f"{script_path} {gcov_folder}"
    # logging.debug("remove_gcov_files: %s", command)
    with open(os.devnull, 'w') as FNULL:
        p = subprocess.Popen(command.split(" "), stdout=FNULL, stderr=FNULL)
        p.wait()
    logging.info(f"[Initialization] Removed gcov files from {gcov_folder}")


def extract_gcov_profiling(gcov_folders, coverage_type="branch"):
  """
  Extract coverage data (branch or line) from gcov results.

  Args:
      gcov_folders (list): List of folders containing gcov outputs.
      coverage_type (str): Type of coverage to extract ("branch" or "line"). Default is "branch".

  Returns:
      list: Functions with coverage details.
  """
  Functions = []

  # Ensure DynamiQ is set in the environment
  dynamiq_dir = os.environ.get('DYNAMIQ')

  if not dynamiq_dir:
    raise EnvironmentError("The DynamiQ environment variable is not set.")

  # Process each gcov folder
  for gcov_folder in gcov_folders:
    logging.debug(f"[Profiling] Processing gcov folder: {gcov_folder}")

    # Run gcov on the folder keeping gcov-enabled binary
    with open(os.devnull, 'w') as FNULL:
      command = os.path.join(dynamiq_dir, "run-gcov.sh") + " " + gcov_folder
      p = subprocess.Popen(command.split(" "), stdout=FNULL, stderr=FNULL)
      p.wait()

    # Process the gcov.log file in the folder
    gcov_log_path = os.path.join(gcov_folder, "gcov.log")
    if not os.path.exists(gcov_log_path):
      logging.warning(f"gcov.log not found in {gcov_folder}")
      continue

    # Process gcov.log file
    with open(gcov_log_path, "r") as flog:
      curParsingState = ParsingState.INITIAL
      curFunction = globals.Function("", "", "", 0, 0)

      tmpFunctions = []
      for line in flog:
        # Only process lines of interest and ignore others
        if line.startswith("Function"):
          # Example: Function 'png_write_image'
          tmpStrs = line.split("'")
          if len(tmpStrs) >= 2:
            curFunction.name = tmpStrs[1]
            curParsingState = ParsingState.PARSING_FUNCTION_INFO
          else:
            logging.warning(f"Malformed Function line: {line.strip()}")
          continue
        if line.startswith("File "):
          # Example: File 'pngimage.c'
          tmpStrs = line.split("'")
          if len(tmpStrs) >= 2:
            fpath = tmpStrs[1]
            fname = fpath.rsplit("/", 1)[-1]
            # Update all functions in a specific source file
            for f in tmpFunctions:
                f.fname = fname
                f.fpath = fpath
            # Update parsing state
            curParsingState = ParsingState.PARSING_FILE_INFO
          else:
            logging.warning(f"Malformed File line: {line.strip()}")
          continue

        # Extract coverage data based on coverage_type
        if coverage_type == "branch" and line.startswith("Taken at least once"):
          if curParsingState == ParsingState.PARSING_FUNCTION_INFO:
            # Example: Taken at least once:52.94% of 34
            try:
                tmpStrs = line.split("% of ")
                btotal = int(tmpStrs[1].strip())
                bper = float(tmpStrs[0].split(":")[1].strip())
                bcovered = math.floor((bper * btotal) / 100)
                curFunction.btotal = btotal
                curFunction.bcovered = bcovered
            except (ValueError, IndexError):
                curFunction.btotal = 0
                curFunction.bcovered = 0
            continue
        elif coverage_type == "line" and line.startswith("Lines executed"):
          if curParsingState == ParsingState.PARSING_FUNCTION_INFO:
            try:
              # Example: Lines executed:100.00% of 10
              tmpStrs = line.split("% of ")
              if len(tmpStrs) < 2:
                raise ValueError("Malformed 'Lines executed' line")
              
              btotal = int(tmpStrs[1].strip())
              bper = float(tmpStrs[0].split(":")[1].strip())
              bcovered = math.floor((bper * btotal) / 100)
              
              curFunction.btotal = btotal
              curFunction.bcovered = bcovered
            except (ValueError, IndexError) as e:
              # logging.debug(f"Error parsing line: {line.strip()} -> {e}")
              # Set defaults for cases like '-nan%' or other errors
              curFunction.btotal = 0
              curFunction.bcovered = 0
            continue

        # Check for end of function/file
        if line.strip() == "":
          if curParsingState == ParsingState.PARSING_FUNCTION_INFO:
            # Add the curFunction to the tmpFunctions list
            tmpFunctions.append(curFunction)
          if curParsingState == ParsingState.PARSING_FILE_INFO:
            # Move functions from tmpFunctions list to Functions list
            update_function_list(Functions, tmpFunctions)
            # Clear tmpFunctions
            tmpFunctions.clear()
          # Initialize a new function
          curFunction = globals.Function("", "", "", 0, 0)
          # Update parsing state
          curParsingState = ParsingState.INITIAL

  return Functions

def extract_llvm_profiling(binary_path, seeds, profraw_path, profdata_path, output_json_path):
  """
  Aggregate and extract function coverage from LLVM profiling.

  Args:
      binary_path (str): Path to the LLVM-instrumented binary.
      seeds (list): List of seed file paths used for profiling.
      profraw_path (str): Path to the collected raw profile file (profraw).
      profdata_path (str): Path where merged profdata will be written.
      output_json_path (str): Path where coverage json will be dumped.

  Returns:
      list: Functions with coverage details.
  """
  Functions = []

  # Ensure profile raw exists
  if not os.path.exists(profraw_path):
    raise FileNotFoundError(f"profraw file {profraw_path} does not exist.")

  # Merge profraw -> profdata
  with open(os.devnull, 'w') as FNULL:
    subprocess.run(["llvm-profdata", "merge", "-sparse", profraw_path, "-o", profdata_path], stdout=FNULL, stderr=FNULL)

  # Export coverage json
  with open(output_json_path, "w") as fout:
    subprocess.run([
      "llvm-cov", "export",
      binary_path,
      "-instr-profile=" + profdata_path,
      "-skip-expansions"
    ], stdout=fout)

  # Parse coverage.json
  if not os.path.exists(output_json_path):
    raise FileNotFoundError(f"Coverage JSON {output_json_path} not generated.")

  with open(output_json_path, "r") as fjson:
    cov_data = json.load(fjson)

  for data_entry in cov_data.get("data", []):
    # Parse top-level "functions"
    for func in data_entry.get("functions", []):
      func_name = func["name"]
      if ":" in func_name:
        func_name = func_name.split(":", 1)[1]  # Remove prefix
      # logging.debug(f"all functions statistcs: {func}")

      btotal = 0
      bcovered = 0

      # for branch in func.get("branches", []):
      #   # Taken at least once
      #   # branch: [line_start, col_start, line_end, col_end, true_count, false_count, ...]
      #   true_count = branch[4]
      #   false_count = branch[5]

      #   btotal += 2  # true and false edge
      #   if true_count > 0:
      #     bcovered += 1
      #   if false_count > 0:
      #     bcovered += 1
      #   # if func_name == "LLVMFuzzerTestOneInput":
      #   #   logging.debug(f"=== Debug Info for Function: {func_name} ===")
      #   #   logging.debug(f"true_count: {true_count}, false_count: {false_count}")

      for region in func.get("regions", []):
        # region: [line_start, col_start, line_end, col_end, execution_count, file_id, expanded_file_id, kind]
        count = region[4]
        if count >= 0:  
          btotal += 1
          if count > 0:
            bcovered += 1

      curFunction = globals.Function(
        func_name,
        "",  # filename is not available here
        "",  # full path not available
        0,
        0
      )
      curFunction.btotal = btotal
      curFunction.bcovered = bcovered

      Functions.append(curFunction)


  return Functions

def update_callgraph(
    binary_name, pre_args, post_args, CG, v_fname_dict, fname_v_dict, fname_src_dict,
    profiling_binary, gcov_binary, gcov_folders, seed_dir, isFirstRun, llvm=False
):
  logging.debug("[CallGraph] update_callgraph starts at: %s", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))

  # Track dynamically covered functions
  covered_funcs = []

  # Define profiling log file path
  log_dir = f"/tmp/{binary_name}"
  log_file_path = f"{log_dir}/covered_functions.log"

  # Ensure the directory exists but **only remove the specific log file**
  if os.path.exists(log_file_path):
    os.remove(log_file_path)

  # If LLVM coverage is used, define profiling output paths
  if llvm:
    profraw_path = f"/tmp/{binary_name}.profraw"
    profdata_path = f"/tmp/{binary_name}.profdata"
    output_json_path = f"/tmp/{binary_name}_coverage.json"

  # Prepare command prefixes
  timeout_cmd = ["timeout", "-k", "0", "5s"]
  profiling_env = ["env", f"HF_BINARY={binary_name}"]

  # Process seed files sequentially
  with open(os.devnull, 'w') as FNULL:
    for seed in os.listdir(seed_dir):
      seed_path = os.path.join(seed_dir, seed)

      if not os.path.isfile(seed_path):  # Skip directories
        continue

      if not isFirstRun:
        if seed in globals.profiled_seeds or ("+cov" not in seed and "orig" not in seed):
          continue  # Skip non-coverage increasing or already profiled seeds
        
        globals.profiled_seeds.add(seed)  # Use a set instead of a list for faster lookups

      # (1) Run profiling binary to collect dynamic call edges (NO LLVM_PROFILE_FILE here)
      profiling_command = timeout_cmd + profiling_env + [profiling_binary]
      if pre_args:
        profiling_command.append(pre_args)
      profiling_command.append(seed_path)
      if post_args:
        profiling_command.append(post_args)

      subprocess.run(profiling_command, stdout=FNULL, stderr=FNULL)

      if llvm:
        # (2) If llvm coverage, run the binary again with LLVM_PROFILE_FILE set
        coverage_command = timeout_cmd + ["env", f"LLVM_PROFILE_FILE=/tmp/{binary_name}.profraw", gcov_binary]
        if pre_args:
          coverage_command.append(pre_args)
        coverage_command.append(seed_path)
        if post_args:
          coverage_command.append(post_args)

        subprocess.run(coverage_command, stdout=FNULL, stderr=FNULL)

      else:
        # (3) Otherwise, run llvm-cov gcov binary
        gcov_command = timeout_cmd + [gcov_binary]
        if pre_args:
            gcov_command.append(pre_args)
        gcov_command.append(seed_path)
        if post_args:
            gcov_command.append(post_args)

        subprocess.run(gcov_command, stdout=FNULL, stderr=FNULL)

  # Extract function coverage information
  helpers.deduplicate_covered_functions(binary_name)
  added_pairs = add_nodes_and_edges(CG, v_fname_dict, fname_v_dict, log_file_path, fname_src_dict)

  # Extract profiling data
  if not llvm:
      # Extract gcov profiling data
      Functions = extract_gcov_profiling(gcov_folders, coverage_type="line")
  else:
      # Extract llvm-cov profiling data
      Functions = extract_llvm_profiling(
          binary_path=gcov_binary,
          seeds=[os.path.join(seed_dir, s) for s in os.listdir(seed_dir) if os.path.isfile(os.path.join(seed_dir, s))],
          profraw_path=profraw_path,
          profdata_path=profdata_path,
          output_json_path=output_json_path
      )

  # Update graph properties
  for f in Functions:
      if f.name in fname_v_dict:
          v = fname_v_dict[f.name]
          v_dict = CG.nodes[v]

          # Initialize node properties
          if "btotal" not in v_dict:
              CG.nodes[v].update({
                  "btotal": f.btotal,
                  "bcovered_pre": 0,
                  "bcovered_cur": f.bcovered,
                  "attempts": 0
              })
          else:
              CG.nodes[v]["bcovered_pre"] = CG.nodes[v]["bcovered_cur"]
              CG.nodes[v]["bcovered_cur"] = f.bcovered

              # Adjust attempt counter based on progress
              if CG.nodes[v]["bcovered_cur"] == CG.nodes[v]["btotal"]:
                  CG.nodes[v]["attempts"] = 0  # Reset if fully covered
              elif CG.nodes[v]["bcovered_cur"] > CG.nodes[v]["bcovered_pre"]:
                  CG.nodes[v]["attempts"] = 0  # Reset if progress made
              else:
                  CG.nodes[v]["attempts"] += 1  # Increment if coverage stagnates

  logging.debug("[CallGraph] update_callgraph ends at: %s", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
  return added_pairs
