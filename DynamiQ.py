import sys
import argparse
import os
import signal
import time
import subprocess
import psutil
from shutil import copyfile
import logging
import shutil
import hashlib
import uuid
import csv
import re
import threading

# Import DynamiQ's modules
from utils import helpers
from utils import extractors
from graphs import networkx_processing as nxp
from tasks import ldg_partitioning as ldg
from tasks import fennel_partitioning as fennel
from tasks import hrdf_partitioning as hrdf
from tasks import random_partitioning as random_part

'''
Main loop of DynamiQ
'''

def env_flag(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def prune_queue_dirs(queue_dirs):
    pruned = 0
    for queue_dir in queue_dirs:
        if not os.path.isdir(queue_dir):
            continue
        try:
            shutil.rmtree(queue_dir)
            os.makedirs(queue_dir, exist_ok=True)
            pruned += 1
        except OSError as exc:
            logging.warning("[Sync] Failed to prune worker queue %s: %s", queue_dir, exc)
    return pruned


class ExecutionSampler:
    def __init__(self, out_folder, log_file, interval):
        self.out_folder = out_folder
        self.log_file = log_file
        self.interval = max(1, interval)
        self.start_time = time.time()
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.phase = "initializing"
        self.round = 0
        self.libafl_offset = 0
        self.active_libafl_logs = []
        self.thread = None

    def start(self):
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        if not os.path.exists(self.log_file):
            with open(self.log_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp",
                    "elapsed_seconds",
                    "round",
                    "phase",
                    "total_execs",
                    "afl_monitor_execs",
                    "libafl_execs",
                    "libafl_offset",
                    "libafl_live_execs",
                ])
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        logging.info("[ExecutionSampler] Sampling executions every %d seconds into %s",
                     self.interval, self.log_file)

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=2)
        self.sample()

    def set_phase(self, phase, round_id=None):
        with self.lock:
            self.phase = phase
            if round_id is not None:
                self.round = round_id

    def set_active_libafl_logs(self, paths):
        with self.lock:
            self.active_libafl_logs = list(paths)

    def clear_active_libafl_logs(self):
        with self.lock:
            self.active_libafl_logs = []

    def rollover_libafl_execs(self):
        with self.lock:
            live_execs = self._read_libafl_live_execs_locked()
            self.libafl_offset += live_execs
            self.active_libafl_logs = []
            logging.info("[ExecutionSampler] Rolled over LibAFL executions: live=%d, offset=%d",
                         live_execs, self.libafl_offset)

    def _run(self):
        next_sample = self.start_time
        while not self.stop_event.wait(max(0, next_sample - time.time())):
            self.sample()
            next_sample += self.interval

    def sample(self):
        with self.lock:
            timestamp = time.time()
            elapsed = timestamp - self.start_time
            afl_execs = self._read_afl_monitor_execs()
            libafl_live = self._read_libafl_live_execs_locked()
            libafl_total = self.libafl_offset + libafl_live
            total_execs = afl_execs + libafl_total
            row = [
                int(timestamp),
                f"{elapsed:.3f}",
                self.round,
                self.phase,
                total_execs,
                afl_execs,
                libafl_total,
                self.libafl_offset,
                libafl_live,
            ]

        with open(self.log_file, "a", newline="") as f:
            csv.writer(f).writerow(row)

    def _read_afl_monitor_execs(self):
        stats_path = os.path.join(self.out_folder, "active_runs", "monitor", "fuzzer_stats")
        try:
            with open(stats_path, "r") as f:
                for line in f:
                    if line.startswith("execs_done"):
                        return int(line.split(":", 1)[1].strip())
        except (OSError, ValueError, IndexError):
            pass
        return 0

    def _read_libafl_live_execs_locked(self):
        latest_by_log = []
        for path in self.active_libafl_logs:
            execs = self._read_latest_libafl_execs(path)
            if execs is not None:
                latest_by_log.append(execs)
        return sum(latest_by_log)

    @staticmethod
    def _read_latest_libafl_execs(path):
        try:
            with open(path, "rb") as f:
                f.seek(0, os.SEEK_END)
                pos = f.tell()
                data = b""
                block = 8192
                while pos > 0 and len(data.splitlines()) < 200:
                    read_size = min(block, pos)
                    pos -= read_size
                    f.seek(pos)
                    data = f.read(read_size) + data
            lines = data.decode(errors="ignore").splitlines()
            latest_by_core = {}
            for raw_line in reversed(lines):
                core_match = re.search(r"Core\s+(\d+):.*executions:\s*([0-9][0-9,]*)", raw_line)
                if core_match:
                    core = core_match.group(1)
                    if core not in latest_by_core:
                        latest_by_core[core] = int(core_match.group(2).replace(",", ""))
            if latest_by_core:
                return sum(latest_by_core.values())
            for raw_line in reversed(lines):
                if "(GLOBAL)" not in raw_line:
                    continue
                match = re.search(r"executions:\s*([0-9][0-9,]*)", raw_line)
                if match:
                    return int(match.group(1).replace(",", ""))
            for raw_line in reversed(lines):
                match = re.search(r"executions:\s*([0-9][0-9,]*)", raw_line)
                if match:
                    return int(match.group(1).replace(",", ""))
        except (OSError, ValueError):
            return None
        return None


def append_timing_event(out_folder, event, round_id, seconds, **fields):
    path = os.path.join(out_folder, "timing_events.csv")
    needs_header = not os.path.exists(path)
    fieldnames = ["timestamp", "event", "round", "seconds", "algorithm", "core", "task", "binary", "success"]
    row = {name: "" for name in fieldnames}
    row.update({
        "timestamp": int(time.time()),
        "event": event,
        "round": round_id,
        "seconds": f"{seconds:.3f}",
    })
    row.update(fields)
    with open(path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if needs_header:
            writer.writeheader()
        writer.writerow(row)


def resolve_libafl_command(binary, libafl_dir, libafl_bin_dir=None, use_cargo=False):
    if use_cargo:
        return ["cargo", "run", "--release", "--bin", binary, "--"]

    candidates = []
    if libafl_bin_dir:
        candidates.append(os.path.join(libafl_bin_dir, binary))
    env_bin_dir = os.environ.get("DYNAMIQ_LIBAFL_BIN_DIR")
    if env_bin_dir:
        candidates.append(os.path.join(env_bin_dir, binary))
    if libafl_dir:
        candidates.append(os.path.join(libafl_dir, "target", "release", binary))
    candidates.append(os.path.join("/opt/libafl-fuzzers", "target", "release", binary))

    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            logging.info("[Initialization] Using compiled LibAFL binary for %s: %s", binary, candidate)
            return [candidate]

    path_candidate = shutil.which(binary)
    if path_candidate:
        logging.info("[Initialization] Using LibAFL binary from PATH for %s: %s", binary, path_candidate)
        return [path_candidate]

    logging.warning(
        "[Initialization] No compiled LibAFL binary found for %s; falling back to cargo run",
        binary,
    )
    return ["cargo", "run", "--release", "--bin", binary, "--"]


def build_libafl_binaries(libafl_dir, env, use_cmplog=False, skip_build=False):
    if skip_build:
        logging.info("[Initialization] Skipping LibAFL Rust build by request")
        return

    cargo_toml = os.path.join(libafl_dir, "Cargo.toml") if libafl_dir else None
    if not cargo_toml or not os.path.isfile(cargo_toml):
        raise FileNotFoundError(f"LibAFL Cargo.toml not found under {libafl_dir}")

    bins = ["run", "compile"]
    if use_cmplog:
        bins.extend(["parallel_sync_cmplog", "advanced_cmplog"])
    else:
        bins.extend(["parallel_sync", "advanced_sync"])
    command = ["cargo", "build", "--release"]
    for binary in bins:
        command.extend(["--bin", binary])

    build_env = env.copy()
    build_env.pop("CC", None)
    build_env.pop("CXX", None)
    build_env.pop("AFL_CC", None)
    build_env.pop("AFL_CXX", None)
    build_env.pop("AFL_PATH", None)
    build_env.pop("AFL_LLVM_INSTRUMENT", None)
    build_env.pop("AFL_OLD_FORKSERVER", None)
    raw_path = build_env.get("PATH", "")
    blocked_path_fragments = (
        "AFLplusplus",
        "AFLplusplus4.22a",
    )
    path_entries = []
    for entry in raw_path.split(os.pathsep):
        if not entry or entry == ".":
            continue
        if any(fragment in entry for fragment in blocked_path_fragments):
            continue
        path_entries.append(entry)
    preferred_entries = [
        os.path.join(build_env.get("CARGO_HOME", "/root/.cargo"), "bin"),
        build_env.get("LLVM_COMPILER_PATH", ""),
        "/usr/local/sbin",
        "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
    ]
    sanitized_path = []
    for entry in preferred_entries + path_entries:
        if entry and entry not in sanitized_path:
            sanitized_path.append(entry)
    build_env["PATH"] = os.pathsep.join(sanitized_path)

    logging.info("[Initialization] Building LibAFL Rust binaries: %s", " ".join(command))
    start = time.monotonic()
    proc = subprocess.run(
        command,
        cwd=libafl_dir,
        env=build_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    elapsed = time.monotonic() - start
    logging.info("[Initialization] LibAFL Rust build finished in %.3fs with status %d", elapsed, proc.returncode)
    if proc.returncode != 0:
        logging.error("[Initialization] LibAFL Rust build failed with output:\n%s", proc.stdout)
        raise RuntimeError(f"LibAFL Rust build failed with status {proc.returncode}")


def tail_file(path, max_lines=40):
    try:
        with open(path, "r", errors="ignore") as f:
            return "".join(f.readlines()[-max_lines:])
    except OSError as err:
        return f"<unable to read {path}: {err}>"


def wait_phase_timeout(timeout, popens, log_paths, phase_name):
    deadline = time.time() + max(0, timeout)
    while True:
        for proc in popens:
            if not isinstance(proc, subprocess.Popen):
                continue
            ret = proc.poll()
            if ret is not None:
                tails = []
                for log_path in log_paths:
                    tails.append(f"--- {log_path} ---\n{tail_file(log_path)}")
                raise RuntimeError(
                    f"{phase_name} LibAFL worker exited early with status {ret}.\n"
                    + "\n".join(tails)
                )

        remaining = deadline - time.time()
        if remaining <= 0:
            return 0
        time.sleep(min(1.0, remaining))


def main(binary_name, afl_binary, profiling_binary, gcov_binary, gcov_folders, pre_args, post_args,
         seed_corpus, out_folder, dict_file, dot_file, func_ids, func_bbs, cores, algorithm,
         total_timeout, scanning_timeout, expl_timeout, target_folder, libafl_dir=None, cmplog_binary=None,
         use_cmplog_in_task=False, exec_log_file=None, exec_log_interval=300,
         libafl_bin_dir=None, libafl_use_cargo=False, libafl_skip_build=False,
         parallel_map_size=None):
    # Create a log file
    LOG_FILENAME = os.path.join(out_folder, "DynamiQ.log")
    logging.basicConfig(filename=LOG_FILENAME, level=logging.DEBUG)
    logging.info("[Initialization] DynamiQ starts")

    build_env = os.environ.copy()
    if libafl_bin_dir:
        build_env["DYNAMIQ_LIBAFL_BIN_DIR"] = libafl_bin_dir
    if libafl_use_cargo:
        build_env["DYNAMIQ_LIBAFL_USE_CARGO"] = "1"
    build_libafl_binaries(libafl_dir, build_env, use_cmplog_in_task, libafl_skip_build)

    sampler = None
    if exec_log_file:
        exec_log_path = exec_log_file if os.path.isabs(exec_log_file) else os.path.join(out_folder, exec_log_file)
        sampler = ExecutionSampler(out_folder, exec_log_path, exec_log_interval)
        sampler.start()

     # Check if profiling_binary and gcov_binary exist
    if not os.path.exists(profiling_binary):
        logging.warning(f"Warning: Profiling binary '{profiling_binary}' does not exist. Proceeding anyway.")
    
    if not os.path.exists(gcov_binary):
        logging.warning(f"Warning: GCOV binary '{gcov_binary}' does not exist. Proceeding anyway.")

    # Remove gcov files if they exist
    nxp.remove_gcov_files(gcov_folders)

    # Get the initial callgraph & related information
    # v_fname_dict: a dictionary to map from vertices to function names
    # fname_v_dict: a dictionary to map from function names to vertices
    # main_v: the root vertex
    (CG, v_fname_dict, fname_v_dict, main_v) = nxp.extract_callgraph(dot_file)

    # Get all functions and their corresponding source files based on
    # the func_ids.log file generated by HF_BINARY afl-clang-fast
    fname_src_dict = extractors.extract_fname_src_dict(func_ids)

    # Get all functions and their corresponding basic block count
    fname_bbs_dict = extractors.extract_fname_bbs_dict(func_bbs)

    # Start the monitoring fuzzer which is always running
    # Prepare necessary directories
    activeDir = os.path.join(out_folder, "active_runs")
    instanceDir = os.path.join(out_folder, "instances")
    originalSeedDir = os.path.join(activeDir, "seeds_origin")
    seedDir = os.path.join(activeDir, "seeds")
    taskDir = os.path.join(activeDir, "tasks")
    shared_sync_dir = os.path.join(activeDir, "shared_sync")
    prune_worker_queues_after_sync = env_flag("DYNAMIQ_PRUNE_WORKER_QUEUES_AFTER_SYNC", False)

    # Create them all in a loop
    for d in [activeDir, instanceDir, originalSeedDir, seedDir, taskDir, shared_sync_dir]:
        os.makedirs(d, exist_ok=True)

    # Copy seed corpus to original seed directory
    for seed in os.listdir(seed_corpus):
        seed_path = os.path.join(seed_corpus, seed)
        if os.path.isfile(seed_path):
            copyfile(seed_path, os.path.join(originalSeedDir, seed))

    # Base fuzzing options
    common_fuzzing_options = ["-m", "2G", "-t", "20000+", "-o", activeDir]
    if dict_file:  # Include dictionary if provided
        common_fuzzing_options += ["-x", dict_file]
    # Define the specific fuzzing options
    team_name = f"DynamiQ-{binary_name}"
    specific_fuzzing_options = common_fuzzing_options + ["-i", originalSeedDir, "-M", "monitor", "-T", team_name]

    # Generate the -F options for each fuzzer_x from 1 to (cores - 1)
    for i in range(1, cores):
        fuzzer_queue = os.path.join(instanceDir, f"fuzzer_{i}/queue")
        specific_fuzzing_options += ["-F", fuzzer_queue]

    # Appeng the shared sync directory to the monitor command
    specific_fuzzing_options += ["-F", shared_sync_dir]

   # Build the fuzzing command with cmplog binary if specified
    fuzz_command = ["afl-fuzz"] + specific_fuzzing_options
    if cmplog_binary:
        fuzz_command += ["-c", cmplog_binary]
    
    fuzz_command += [afl_binary]

    # Add pre-arguments if any
    if pre_args.strip():
        fuzz_command += pre_args.strip().split()

    # Add the input placeholder
    fuzz_command += ["@@"]

    # Add post-arguments if any
    if post_args.strip():
        fuzz_command += post_args.strip().split()

    # Set environment variables
    env = os.environ.copy()
    env['AFL_SYNC_TIME'] = '15'
    env['AFL_FINAL_SYNC'] = '1'
    env['AFL_REMOVE_ACKED_SHARED_SYNC'] = '1'
    # DynamiQ assigns the monitor explicitly and reserves that CPU for it.
    # Prevent AFL++ from replacing this affinity during its own startup.
    env['AFL_NO_AFFINITY'] = '1'
    rust_env = env.copy()
    if libafl_bin_dir:
        rust_env["DYNAMIQ_LIBAFL_BIN_DIR"] = libafl_bin_dir
    if libafl_use_cargo:
        rust_env["DYNAMIQ_LIBAFL_USE_CARGO"] = "1"
    interrupted = False  # Flag to detect manual interruption

    # Execute the command
    logging.info("[Initialization] Monitor command: %s", ' '.join(fuzz_command))

    # Get an available core
    try:
        monitor_core = helpers.get_next_available_core()
    except RuntimeError as e:
        logging.error("Could not find an available core: %s", e)
        sys.exit(1)

    # Execute the monitor command on the selected core
    # Start the process without specifying cpu_affinity initially
    pmonitor = subprocess.Popen(
        fuzz_command,
        env=env
    )

    # Set affinity to the desired core
    psutil.Process(pmonitor.pid).cpu_affinity([monitor_core])

    # Small delay to allow the OS to finalize any core assignments
    time.sleep(0.1)

    # Re-check the actual affinity, either with psutil or taskset as an external command
    actual_core_affinity = psutil.Process(pmonitor.pid).cpu_affinity()

    # Alternatively, using taskset to verify:
    taskset_check = subprocess.check_output(f"taskset -pc {pmonitor.pid}", shell=True).decode().strip()

    logging.info("[Initialization] Monitor PID: %d, Requested Core: %d, Psutil Core Affinity: %s, Taskset Check: %s",
                pmonitor.pid, monitor_core, actual_core_affinity, taskset_check)

    all_deleted_pairs = set()

    # Create map size
    map_size = str(parallel_map_size) if parallel_map_size else "65536"

    # Whether to use llvm coverage
    use_llvm = False
    use_unit_diameter = False
    if binary_name=="ossfuzz":
        use_llvm = True
        use_unit_diameter = True
        map_size = str(parallel_map_size) if parallel_map_size else "262144"
        logging.info(f"[Initialization] Setting parallel AFL_MAP_SIZE to {map_size} for {binary_name}")
    elif parallel_map_size:
        logging.info(f"[Initialization] Setting parallel AFL_MAP_SIZE to {map_size} from override")

    # Create the combined command-line arguments
    cmdline = []
    if pre_args and pre_args.strip():
        cmdline.extend(pre_args.strip().split())
    cmdline.append("@@")
    if post_args and post_args.strip():
        cmdline.extend(post_args.strip().split())
    cmdline_str = ' '.join(cmdline)  # Convert to string for logging/debugging

    # Log the constructed command line
    # logging.info("[Initialization] Constructed Command Line: {cmdline_str}")

    # Generate an 8-char hash as dir name
    raw_hash = hashlib.sha1(str(uuid.uuid4()).encode()).hexdigest()[:8]
    logging.info(f"[Initialization] Generated unique hash for this run: {raw_hash}")
    logging.info("[Initialization] Prune worker queues after sync: %s", prune_worker_queues_after_sync)
    # This is for running expriments in parallel, otherwise using binary_name should be enough
    extracted_binary_name = os.path.basename(os.path.dirname(func_ids))
    logging.info("[Initialization] Extracted binary name: %s", extracted_binary_name)
    helpers.deduplicate_tmp_logs(extracted_binary_name)

    # Record the start time of the entire process
    start_time = time.time()

    # Start other fuzzing instances
    exploitMode = False  # Start in exploration mode
    curRound = 1
    failure_status = 0
    while True:
        if sampler:
            sampler.set_phase("round_setup", curRound)
        logging.info("-------------------------------------------------------------------------------------------------------------------")
        logging.debug(f"[round {curRound}] Starting DynamiQ round with exploitMode={exploitMode}")

        # Step-0. Save results from the previous round & clean results
        if curRound > 1:
            backupDir = os.path.join(out_folder, f"backup_round_{curRound - 1}")
            os.makedirs(backupDir, exist_ok=True)

            # Save the defined tasks for analysis/debugging
            if os.path.exists(os.path.join(activeDir, "tasks")):
                shutil.move(os.path.join(activeDir, "tasks"), backupDir)

            # Sync seeds from all fuzzer instances into shared_sync
            if curRound == 2:
                src_dirs = [os.path.join(instanceDir, "fuzzer_1", "queue")]
            else:
                src_dirs = [os.path.join(instanceDir, f"fuzzer_{i}", "queue") for i in range(1, cores)]
            helpers.sync_unique_testcases(
                src_dirs,
                shared_sync_dir,
                used_cores_file=os.path.join(out_folder, "used_cores.txt"),
            )
            if prune_worker_queues_after_sync:
                pruned = prune_queue_dirs(src_dirs)
                logging.info("[Sync] Pruned %d stopped worker queues after syncing to shared_sync", pruned)

            # Save intermediate output log
            if os.path.exists(os.path.join(instanceDir, "output.txt")):
                shutil.move(os.path.join(instanceDir, "output.txt"), backupDir)
            if os.path.exists(os.path.join(instanceDir, "cpu_bindings.txt")):
                shutil.move(os.path.join(instanceDir, "cpu_bindings.txt"), backupDir)
        # Step-1. Prepare seed corpus
        seed_corpus_path = os.path.join(activeDir, "monitor", "queue")
        if curRound == 1:
            seed_corpus_path = seed_corpus
            seed_corpus_path_sync = os.path.join(activeDir, "monitor", "queue")

        helpers.count_seeds_in_seed_dir(seed_corpus_path, curRound)

        if curRound == 1:
            logging.debug("[round 1]  Skip updating the callgraph in round 1")

        # Step-2. Do task generation in exploitation mode
        else:
            exploitMode = True  # Set exploitation mode to True after the first round

            # Update the callgraph
            logging.debug("[CallGraph] Nodes and Edges before update in round %d: %d, %d", curRound, len(CG.nodes), len(CG.edges))
            added_pairs = nxp.update_callgraph(extracted_binary_name, pre_args, post_args, CG, v_fname_dict, fname_v_dict, fname_src_dict,
                                 profiling_binary, gcov_binary, gcov_folders,
                                 os.path.join(activeDir, "monitor", "queue"), False, use_llvm) # true if use llvm coverage
            logging.debug("[CallGraph] Nodes and Edges after update in round %d: %d, %d", curRound, len(CG.nodes), len(CG.edges))
            logging.debug("[CallGraph] Added pairs after update: %d", len(added_pairs))
            # logging.debug("Is CG still acyclic?: %s", nx.is_directed_acyclic_graph(CG))

            # For HRDF: Use prune_level = 3 → Skip first and third phases.
            # Reason: - HRDF partitioner does NOT assign isolated nodes (no edges), so we must retain them in the graph.
            prune_level = 3 if algorithm == "hrdf" else 0  # Others run in diagnostic mode (no pruning)

            deleted_pairs = nxp.prune_callgraph(CG, main_v, v_fname_dict, fname_v_dict,
                                                fname_bbs_dict, fname_src_dict, prune_level)
            # Update global deleted pair set
            all_deleted_pairs.update(deleted_pairs)
            # Only subtract those added pairs that were not deleted again
            # logging.debug("All added pairs that were not deleted: %d", len(added_pairs - deleted_pairs))
            all_deleted_pairs.difference_update(added_pairs - deleted_pairs)
            logging.debug("[CallGraph] All deleted pairs after pruning: %d", len(all_deleted_pairs))

            # Create a directory to store all tasks if necessary
            if not os.path.exists(taskDir):
                os.mkdir(taskDir)

            logging.info("[Partitioning] Starting task generation with algorithm: %s", algorithm)
            if sampler:
                sampler.set_phase("partitioning", curRound)
            partition_start = time.monotonic()
            # Proceed with the normal task generation process
            partitioners = {
                "ldg": ldg.LDGPartitioner,
                "fennel": fennel.FennelPartitioner,
                "hrdf": hrdf.HDRFPartitioner,
                "random": random_part.RandomPartitioner,
            }

            if algorithm in partitioners:
                partitioner = partitioners[algorithm]()
                partitioner.partition(
                    CG, main_v, v_fname_dict, fname_src_dict, fname_bbs_dict,
                    cores - 1, taskDir, all_deleted_pairs, None, use_unit_diameter
                )
                partition_elapsed = time.monotonic() - partition_start
                logging.info("[Timing] partition round=%d algorithm=%s seconds=%.3f",
                             curRound, algorithm, partition_elapsed)
                append_timing_event(out_folder, "partition", curRound, partition_elapsed, algorithm=algorithm)
            else:
                raise ValueError(f"Unsupported partitioning algorithm: {algorithm}")

        # Step-3. Start fuzzing instances
        popens = []
        logging.debug(f"[round {curRound}] Starting fuzzing instances")
        if exploitMode:
            # Navigate to the libafl fuzzer directory
            os.chdir(libafl_dir)

            # Start fuzzing instances in exploitation mode
            rust_command = resolve_libafl_command(
                "run", libafl_dir, libafl_bin_dir, libafl_use_cargo
            ) + [
                "--corpus-dir", seed_corpus_path,
                "--active-dir", instanceDir,
                "--task-dir", taskDir,
                "--target-dir", target_folder,
                "--binary-name", binary_name,
                "--num-cores", str(cores - 1),
                "--skip-cores", str(monitor_core),
                "--output-folder", out_folder,
                "--sync-instrumentation" # Enable instrumentaion in parallel
            ]
            # Indicate whether it is the first round for exploitation
            if curRound == 2:
                rust_command += ["--first-run"]
            # Add optional dictionary if provided
            if dict_file:
                rust_command += ["--token-file", dict_file]
            if raw_hash:
                rust_command += ["--hash", raw_hash]
            if cmplog_binary and use_cmplog_in_task:
                rust_command += ["--cmplog-binary", cmplog_binary]
            # Add the command line last
            rust_command += ["--cmdline", cmdline_str]
            logging.debug(f"[round {curRound}] Exploitation rust command: {' '.join(rust_command)}")

            # Define output file for Rust fuzzer logs
            output_file_path = os.path.join(instanceDir, "cpu_bindings.txt")
            # Open the output file to redirect stdout and stderr
            with open(output_file_path, "w") as output_file:
                rust_proc = subprocess.Popen(
                    rust_command,
                    stdout=output_file,
                    stderr=output_file,
                    env=rust_env,
                    preexec_fn=os.setsid
                )
                popens.append(rust_proc)
            os.chdir('..')
            if sampler:
                sampler.set_active_libafl_logs([os.path.join(instanceDir, "output.txt")])
                sampler.set_phase("exploitation", curRound)

        elif exploitMode == False and scanning_timeout > 0:
            # Navigate to the libafl fuzzer directory
            os.chdir(libafl_dir)
            logging.debug(f"[round {curRound}] Seed corpus: %s", seed_corpus_path)

            # Start fuzzing instances in exploration mode
            exploration_bin = "parallel_sync_cmplog" if cmplog_binary and use_cmplog_in_task else "parallel_sync"
            rust_command = resolve_libafl_command(
                exploration_bin, libafl_dir, libafl_bin_dir, libafl_use_cargo
            ) + [
                "--core-num", str(cores - 1),
                "--skip-cores", str(monitor_core),
                "--initial-corpus", os.path.join(instanceDir, "fuzzer_1", "queue"),
                "--corpus-dir", seed_corpus_path,
                "--binary-path", afl_binary,
                "--output-folder", out_folder,
            ]

            # Add optional dictionary if provided
            if dict_file:
                rust_command += ["--token-file", dict_file]
            rust_command += ["--map-size", map_size]
            # Add optional cmplog binary
            if cmplog_binary and use_cmplog_in_task:
                rust_command += ["--cmplog-dir", cmplog_binary]
            rust_command += ["--cmdline", cmdline_str]
            logging.debug(f"[round {curRound}] Exploration rust command: {' '.join(rust_command)}")
            output_file_path = os.path.join(out_folder, "parallel_output.txt")
            with open(output_file_path, "w") as output_file:
                rust_proc = subprocess.Popen(
                    rust_command, 
                    stdout=output_file, 
                    stderr=output_file, 
                    env=rust_env,
                    preexec_fn=os.setsid
                )
            os.chdir('..')
            popens.append(rust_proc)
            if sampler:
                sampler.set_active_libafl_logs([output_file_path])
                sampler.set_phase("exploration", curRound)
        else:
            logging.debug(f"[round {curRound}] Skipping exploration phase (scanning_timeout = 0)")
            if sampler:
                sampler.clear_active_libafl_logs()
                sampler.set_phase("idle", curRound)

        # Step-4. Wait until the stopping criteria meet
        current_time = time.time()
        elapsed_time = current_time - start_time
        time_left = total_timeout - elapsed_time

        try:
            if exploitMode:
                # Adjust the exploitation timeout if necessary
                adjusted_expl_timeout = min(expl_timeout, max(0, time_left))
                logging.debug(f"[round {curRound}] Exploitation mode: waiting for {adjusted_expl_timeout} seconds")
                wait_phase_timeout(
                    adjusted_expl_timeout,
                    popens,
                    [os.path.join(instanceDir, "cpu_bindings.txt"), os.path.join(instanceDir, "output.txt")],
                    f"round {curRound} exploitation",
                )
            else:
                # Adjust the scanning timeout if necessary
                adjusted_scanning_timeout = min(scanning_timeout, max(0, time_left))
                logging.debug(f"[round {curRound}] Scanning mode: waiting for {adjusted_scanning_timeout} seconds")
                wait_phase_timeout(
                    adjusted_scanning_timeout,
                    popens,
                    [os.path.join(out_folder, "parallel_output.txt")],
                    f"round {curRound} exploration",
                )
        except KeyboardInterrupt:
            logging.debug(f"[round {curRound}] Fuzzing interrupted manually; preparing to shut down after cleanup.")
            interrupted = True  # Mark for post-cleanup exit
        except RuntimeError as err:
            logging.error("%s", err)
            interrupted = True
            failure_status = 1

        # Update elapsed time after waiting
        current_time = time.time()
        elapsed_time = current_time - start_time
        logging.debug(f"[round {curRound}] Elapsed time: {elapsed_time} seconds")

        # After waiting, read the PIDs from the file if it exists
        pid_file = os.path.join(out_folder, "pids.txt")
        if os.path.exists(pid_file):
            with open(pid_file, 'r') as f:
                pids = [int(line.strip()) for line in f.readlines() if line.strip()]

            for pid in pids:
                try:
                    proc = psutil.Process(pid)
                    popens.append(proc)
                    # logging.debug("Captured PID: %d", pid)
                except psutil.NoSuchProcess:
                    logging.debug(f"[round {curRound}] Process with PID {pid} does not exist")

        # Send SIGTERM signal to stop fuzzing instances
        if sampler:
            sampler.set_phase("stopping_workers", curRound)
        for p in popens:
            try:
                # Wrap Popen objects with psutil.Process to check process status
                proc = psutil.Process(p.pid)
                if proc.is_running():
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    p.wait()  # Wait for the process to terminate
                    logging.debug(f"[round {curRound}] Process {proc.pid} terminated successfully.")
                else:
                    logging.debug(f"[round {curRound}] Process {proc.pid} is not running and does not need termination.")
            except psutil.NoSuchProcess:
                pass
                # logging.debug(f"Process {p.pid} does not exist or is already terminated.")
            except Exception as e:
                logging.error(f"[round {curRound}] Failed to terminate process {p.pid}: {e}")

        if sampler:
            sampler.rollover_libafl_execs()

        # Delete the pids.txt file after stopping the processes
        if os.path.exists(pid_file):
            os.remove(pid_file)
            logging.debug(f"[round {curRound}] Deleted PID file: {pid_file}")

        # Finalize round
        if interrupted:
            logging.debug(f"[round {curRound}] Cleanup complete after interruption, exiting.")
            break  # Exit main loop after cleanup

        # Step-5. Finalize current round and prepare for next round
        curRound += 1

        # Break the loop if total_timeout is reached
        if elapsed_time >= total_timeout:
            logging.debug(f"[round {curRound}] Total timeout reached, ending fuzzing")
            break

    # Copy final seeds to the seed directory before terminating
    helpers.count_seeds_in_seed_dir(os.path.join(activeDir, "monitor", "queue"), curRound, copy_seeds=True, seedDir=seedDir)

    # Terminate the monitor process
    os.kill(pmonitor.pid, signal.SIGTERM)
    pmonitor.wait()

    logging.debug(f"[round {curRound}] DynamiQ ends!!!")
    if sampler:
        sampler.set_phase("finished", curRound)
        sampler.stop()
    return failure_status

# Parse the input arguments
if __name__ == '__main__':
    print(
        r"""
                                                                                                           
        ██████╗ ██╗   ██╗███╗   ██╗ █████╗ ███╗   ███╗██╗ ██████╗ 
        ██╔══██╗╚██╗ ██╔╝████╗  ██║██╔══██╗████╗ ████║██║██╔═══██╗
        ██║  ██║ ╚████╔╝ ██╔██╗ ██║███████║██╔████╔██║██║██║   ██║
        ██║  ██║  ╚██╔╝  ██║╚██╗██║██╔══██║██║╚██╔╝██║██║██║▄▄ ██║
        ██████╔╝   ██║   ██║ ╚████║██║  ██║██║ ╚═╝ ██║██║╚██████╔╝
        ╚═════╝    ╚═╝   ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝ ╚══▀▀═╝ 
                                                                                                        
                                                                                                                                                            
        DynamiQ - Dynamic Task Allocation in Parallel Fuzzing
        """
    )
    parser = argparse.ArgumentParser()
    parser.add_argument('-bn', '--binary', type=str, required=True,
                        help="Binary name (e.g., libpng_read_fuzzer)")
    parser.add_argument('-ab', '--afl_binary', type=str, required=True,
                        help="Full path to the afl-instrumented binary")
    parser.add_argument('-pb', '--profiling_binary', type=str, required=True,
                        help="Full path to the profiling binary")
    parser.add_argument('-gb', '--gcov_binary', type=str, required=True,
                        help="Full path to the gcov binary")
    parser.add_argument('-gf', '--gcov_folders', type=str, required=True, nargs='+',
                        help="Full paths to the gcov folders, separated by spaces")
    parser.add_argument('-ea1', '--pre_arguments', type=str, required=True,
                        help="Extra argument(s) to run the binary that needs to be in front of @@")
    parser.add_argument('-ea2', '--post_arguments', type=str, required=True,
                        help="Extra argument(s) to run the binary that needs to be behind @@")
    parser.add_argument('-i', '--seed_corpus', type=str, required=True,
                        help="Full path to the seed corpus")
    parser.add_argument('-o', '--out_folder', type=str, required=True,
                        help="Full path to the output folder keeping all results")
    parser.add_argument('-x', '--dict', type=str, required=False,
                        help="Full path to the dictionary file (optional)")
    parser.add_argument('-d', '--dot_file', type=str, required=True,
                        help="Full path to dot file generated by LLVM opt")
    parser.add_argument('-c', '--cores', type=int, required=True,
                        help="Number of CPU cores")
    parser.add_argument('-a', '--algorithm', type=str, required=True, choices=["ldg", "fennel", "hrdf", "random"],
                        help="Partitioning algorithm (e.g., ldg, fennel, hrdf, random)")
    parser.add_argument('-tt', '--total_timeout', type=int, required=True,
                        help="Timeout in seconds for the whole experiment")
    parser.add_argument('-st', '--scanning_timeout', type=int, required=True,
                        help="Timeout in seconds for scanning/exploration phase")
    parser.add_argument('-et', '--expl_timeout', type=int, required=True,
                        help="Timeout in seconds for exploitation phase")
    parser.add_argument('-tf', '--target_folder', type=str, required=True,
                        help="Full path to the target directory for applying selective instrumentation")
    parser.add_argument('-ld', '--libafl_dir', type=str, required=False, help=argparse.SUPPRESS)
    parser.add_argument('-cb', '--cmplog_binary', type=str, help="Optional cmplog binary")
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--use_cmplog_in_task', dest='use_cmplog_in_task', action='store_true', help=argparse.SUPPRESS)
    group.add_argument('--no-use_cmplog_in_task', dest='use_cmplog_in_task', action='store_false', help=argparse.SUPPRESS)
    parser.set_defaults(use_cmplog_in_task=None)  # default is "unspecified"
    parser.add_argument('-f', '--func_ids', type=str, required=False, help=argparse.SUPPRESS)
    parser.add_argument('-b', '--func_bbs', type=str, required=False, help=argparse.SUPPRESS)
    parser.add_argument('--exec-log-file', type=str, required=False,
                        help="Optional CSV path for cumulative execution samples")
    parser.add_argument('--exec-log-interval', type=int, default=300,
                        help="Execution sampling interval in seconds")
    parser.add_argument('--libafl-bin-dir', type=str, required=False, help=argparse.SUPPRESS)
    parser.add_argument('--libafl-use-cargo', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--libafl-skip-build', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--parallel-map-size', type=int, required=False, help=argparse.SUPPRESS)
    args = parser.parse_args()
    helpers.validate_out_folder(args.out_folder)
    # Resolve libafl_dir to the default (fuzzers/ under current script directory) if not provided
    if args.libafl_dir:
        libafl_dir = args.libafl_dir
    else:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        libafl_dir = os.path.join(script_dir, "fuzzers")
        print(f"[+] Using default libafl_dir: {libafl_dir}")
    if args.func_ids and args.func_bbs:
        func_ids = args.func_ids
        func_bbs = args.func_bbs
    else:
        func_ids, func_bbs = helpers.validate_func_logs(args.binary)
    helpers.validate_paths(args)
    # Determine if cmplog should be used per task
    if args.use_cmplog_in_task is None:
        # If unspecified, enable only if cmplog_binary is set
        args.use_cmplog_in_task = bool(args.cmplog_binary)
        if args.use_cmplog_in_task:
            print("[*] Using cmplog within each task (default behavior, binary provided).")
    else:
        # If explicitly set
        if args.use_cmplog_in_task:
            if not args.cmplog_binary:
                print("[!] Ignoring --use_cmplog_in_task since no --cmplog_binary is provided.")
                args.use_cmplog_in_task = False
            else:
                print("[*] Using cmplog within each task as explicitly enabled.")
        else:
            if args.cmplog_binary:
                print("[*] --no-use_cmplog_in_task specified, cmplog binary will not be used in each task.")
    sys.exit(main(args.binary, args.afl_binary, args.profiling_binary, args.gcov_binary, args.gcov_folders,
                  args.pre_arguments, args.post_arguments, args.seed_corpus, args.out_folder, args.dict,
                  args.dot_file, func_ids, func_bbs, args.cores, args.algorithm, args.total_timeout,
                  args.scanning_timeout, args.expl_timeout, args.target_folder, libafl_dir, args.cmplog_binary,
                  args.use_cmplog_in_task, args.exec_log_file, args.exec_log_interval,
                  args.libafl_bin_dir, args.libafl_use_cargo, args.libafl_skip_build,
                  args.parallel_map_size))
