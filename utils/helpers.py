import psutil
import logging
import os
import shutil
import sys
import time

#check if a tuple of (srcName, hashId) exist
def tuple_exist(tDict, tKey, srcName, hashId):
  for (tName, tHash) in tDict[tKey]:
    if ((tName == srcName) and (tHash == hashId)):
      return True
  return False

# Function to get available core by checking core usage of running processes
def get_next_available_core(threshold=12.0):
  core_usage = psutil.cpu_percent(percpu=True)
  logging.info(f"[Initialization] Current CPU core usage: {core_usage}")

  # Find all cores under the threshold
  candidates = [(i, usage) for i, usage in enumerate(core_usage) if usage < threshold]

  if not candidates:
    raise RuntimeError("No available cores found!")

  # Select the one with the minimum usage
  best_core = min(candidates, key=lambda x: x[1])[0]
  return best_core

def sync_unique_testcases(src_dirs, dest_dir):
    """
    Efficiently syncs unique testcases (based on 16-byte filename prefix) from multiple source
    directories into a shared sync directory, skipping hidden files and duplicates.

    Args:
      src_dirs (list of str): List of source directories
      dest_dir (str): Destination directory (shared_sync)
    """
    def extract_seed_key(filename):
      return filename[:16]

    os.makedirs(dest_dir, exist_ok=True)
    
    # Gather already present keys in destination
    existing_keys = {
      extract_seed_key(f) for f in os.listdir(dest_dir)
      if not f.startswith('.') and os.path.isfile(os.path.join(dest_dir, f))
    }

    added = 0

    for src in src_dirs:
      if not os.path.exists(src):
        logging.warning(f"[!] Source directory not found: {src}")
        continue
      for fname in os.listdir(src):
        if fname.startswith('.'):
          continue

        key = extract_seed_key(fname)
        if key not in existing_keys:
          src_path = os.path.join(src, fname)
          dst_path = os.path.join(dest_dir, fname)
          if os.path.isfile(src_path) and not os.path.exists(dst_path):
            shutil.copy2(src_path, dst_path)
            existing_keys.add(key)
            added += 1

    logging.debug(f"[Sync] Added {added} unique testcases to shared sync directory: {dest_dir}")

def deduplicate_tmp_logs(binary_name):
    """
    Deduplicate log files under /tmp/<binary_name>/.
    """

    def dedup_file(filepath, key_func):
      if not os.path.exists(filepath):
        logging.info(f"[!] File not found: {filepath}")
        return 0, 0, 0

      with open(filepath, "r") as f:
        lines = f.readlines()

      seen = set()
      unique_lines = []
      for line in lines:
        key = key_func(line.strip())
        if key not in seen:
          seen.add(key)
          unique_lines.append(line)

      with open(filepath, "w") as f:
        f.writelines(unique_lines)

      original = len(lines)
      remaining = len(unique_lines)
      removed = original - remaining
      return original, removed, remaining

    base_path = f"/tmp/{binary_name}"
    results = {}

    results["func_ids.log"] = dedup_file(os.path.join(base_path, "func_ids.log"), lambda l: l.strip())
    results["func_bbs.log"] = dedup_file(os.path.join(base_path, "func_bbs.log"), lambda l: l.strip())
    results["covered_functions.log"] = dedup_file(os.path.join(base_path, "covered_functions.log"), lambda l: l.strip())

    logging.info("[Deduplication] Deduplication Summary")
    for name, (orig, rem, remain) in results.items():
      logging.info(f"[Deduplication] {name}: Original={orig}, Removed={rem}, Remaining={remain}")

def deduplicate_covered_functions(binary_name):
  """
  Deduplicate /tmp/<binary_name>/covered_functions.log using streaming.
  """
  path = f"/tmp/{binary_name}/covered_functions.log"
  if not os.path.exists(path):
    logging.info(f"[!] File not found: {path}")
    return 0, 0, 0

  temp_path = path + ".tmp"
  seen = set()
  original = 0
  kept = 0

  with open(path, "r") as infile, open(temp_path, "w") as outfile:
    for line in infile:
      original += 1
      key = line.strip()
      if key not in seen:
        seen.add(key)
        outfile.write(line)
        kept += 1

  os.replace(temp_path, path)
  removed = original - kept

  logging.info("[Deduplication] Deduplication Summary for covered_functions.log")
  logging.info("[Deduplication] -----------------------------------------------")
  logging.info(f"[Deduplication] Original={original}, Removed={removed}, Remaining={kept}")
  logging.info("[Deduplication] -----------------------------------------------")

  return original, removed, kept

def validate_func_logs(binary_name):
  func_ids_path = f"/tmp/{binary_name}/func_ids.log"
  func_bbs_path = f"/tmp/{binary_name}/func_bbs.log"
  if not os.path.exists(func_ids_path):
    print(f"[!] Missing profiling required file: {func_ids_path}")
    sys.exit(f"Error: func_ids.log not found for binary '{binary_name}' at {func_ids_path}")
  if not os.path.exists(func_bbs_path):
    print(f"[!] Missing profiling required file: {func_bbs_path}")
    sys.exit(f"Error: func_bbs.log not found for binary '{binary_name}' at {func_bbs_path}")
  print(f"[+] Found required profiling files for binary '{binary_name}' at {func_ids_path} and {func_bbs_path}")
  return func_ids_path, func_bbs_path

def count_seeds_in_seed_dir(seed_corpus_path, curRound, copy_seeds=False, seedDir=None):
  """
  Counts the number of seeds in seed_corpus_path that match the filtering criteria.
  """
  count = 0
  if seedDir:
    os.makedirs(seedDir, exist_ok=True)
  for seed in os.listdir(seed_corpus_path):
    seed_path = os.path.join(seed_corpus_path, seed)
    if os.path.isfile(seed_path):
      # For rounds > 1, filter seeds that don't contain '+cov' or 'orig'
      if curRound > 1 and ("+cov" not in seed) and ("orig" not in seed):
        continue
      count += 1  # Increment count instead of copying
      if copy_seeds:
        # Copy the seed to the seed directory
        dest_path = os.path.join(seedDir, f"seed_{count}")
        try:
          shutil.copy2(seed_path, dest_path)
        except Exception as e:
          logging.error(f"Failed to copy seed {seed_path} to {dest_path}: {e}")
  logging.debug(f"[round {curRound}] Total {count} seeds found in {seed_corpus_path}")
  if copy_seeds:
    logging.debug(f"[round {curRound}] Copied {count} seeds to {seedDir}")
  return count  # Return the count of valid seeds

def validate_paths(args):
    """Validate required binary files, gcov folders, and essential input paths."""

    # Required binaries
    required_files = {
      'afl_binary': args.afl_binary,
      'profiling_binary': args.profiling_binary,
      'gcov_binary': args.gcov_binary,
      'dot_file': args.dot_file,
    }

    for name, path in required_files.items():
      if not os.path.isfile(path):
        sys.exit(f"[!] Error: Required file '{name}' not found at: {path}")

    # Optional files
    optional_files = {
      'cmplog_binary': args.cmplog_binary,
      'dict': args.dict,
    }

    for name, path in optional_files.items():
      if path and not os.path.isfile(path):
        print(f"[!] Warning: Optional file '{name}' not found at: {path} — skipping.")

    # Required directories
    required_dirs = {
      'seed_corpus': args.seed_corpus,
    }

    for name, path in required_dirs.items():
      if not os.path.isdir(path):
        sys.exit(f"[!] Error: Required directory '{name}' not found at: {path}")

    # Multiple gcov folders
    for folder in args.gcov_folders:
      if not os.path.isdir(folder):
        sys.exit(f"[!] Error: GCOV folder not found: {folder}")

#Simple stopping condition based on timeout
def should_stop_timeout(timeout):
    try:
        time.sleep(timeout)
    except KeyboardInterrupt:
        logging.debug("Timeout interrupted manually by user (KeyboardInterrupt)")
        raise  # Re-raise the exception to propagate it for further handling
    return 0