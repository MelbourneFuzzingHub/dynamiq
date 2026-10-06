import psutil
import logging
import os
import shutil
import sys
import time
import errno
import hashlib
import re
import sqlite3
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import closing

#check if a tuple of (srcName, hashId) exist
def tuple_exist(tDict, tKey, srcName, hashId):
  for (tName, tHash) in tDict[tKey]:
    if ((tName == srcName) and (tHash == hashId)):
      return True
  return False

# Function to get available core by checking core usage of running processes
def get_next_available_core(threshold=12.0):
  try:
    allowed_cores = psutil.Process().cpu_affinity()
  except Exception:
    allowed_cores = list(range(psutil.cpu_count()))

  core_usage = psutil.cpu_percent(percpu=True)
  logging.info(f"[Initialization] Current CPU core usage: {core_usage}")

  # Find all cores under the threshold that are allowed
  candidates = [(i, core_usage[i]) for i in allowed_cores if i < len(core_usage) and core_usage[i] < threshold]

  if not candidates:
    logging.warning("[Initialization] No core below %.1f%% usage; falling back to least-busy allowed core", threshold)
    candidates = [(i, core_usage[i]) for i in allowed_cores if i < len(core_usage)]

  if not candidates:
    return 0

  # Select the one with the minimum usage
  best_core = min(candidates, key=lambda x: x[1])[0]
  return best_core

SYNC_INDEX_SUFFIX = ".sync-index.sqlite3"
LIBAFL_NAME_RE = re.compile(r"^([0-9a-f]{16})(?:-\d+)?$")

def _is_sync_candidate(filename):
  # AFL++ uses id:... names, while LibAFL queue entries can be hash-like names.
  # Hidden files cover LibAFL metadata and lock sidecars.
  return not filename.startswith(".")

def file_sha1(path, bufsize=1 << 20):
  h = hashlib.sha1()
  with open(path, "rb") as f:
    while True:
      b = f.read(bufsize)
      if not b:
        break
      h.update(b)
  return h.hexdigest()

def _open_sync_index(dest_dir):
  index_path = dest_dir.rstrip(os.sep) + SYNC_INDEX_SUFFIX
  conn = sqlite3.connect(index_path)
  conn.execute("PRAGMA journal_mode=WAL")
  conn.execute("PRAGMA synchronous=NORMAL")
  conn.execute(
      "CREATE TABLE IF NOT EXISTS testcase_keys ("
      "filename TEXT PRIMARY KEY, key_type TEXT NOT NULL, key TEXT NOT NULL)"
  )
  conn.execute(
      "CREATE INDEX IF NOT EXISTS testcase_keys_key "
      "ON testcase_keys(key_type, key)"
  )
  return conn

def _sync_key_for_file(fname, path, sync_mode):
  if sync_mode == "libafl":
    match = LIBAFL_NAME_RE.match(fname)
    if match:
      return ("libafl-name", match.group(1))
  return ("sha1", file_sha1(path))

def _libafl_filename_key(filename):
  match = LIBAFL_NAME_RE.match(filename)
  if match:
    return match.group(1)
  return filename[:16]

def _queue_dirs(src_dirs):
  queue_dirs = []
  for src in src_dirs:
    if not os.path.exists(src):
      logging.warning(f"[!] Source directory not found: {src}")
      continue
    queue_dirs.append(
        os.path.join(src, "queue")
        if os.path.isdir(os.path.join(src, "queue"))
        else src
    )
  return queue_dirs

def _load_shared_sync_keys(dest_dir, conn, sync_mode):
  dest_files = {
      f for f in os.listdir(dest_dir)
      if _is_sync_candidate(f) and os.path.isfile(os.path.join(dest_dir, f))
  }
  indexed = {
      filename: (key_type, key)
      for filename, key_type, key in conn.execute(
          "SELECT filename, key_type, key FROM testcase_keys"
      )
  }

  missing_files = dest_files - set(indexed)
  logging.debug(
      "[Sync] Shared-sync %s index: %d historical, %d unindexed files",
      sync_mode, len(indexed), len(missing_files),
  )
  for fname in missing_files:
    path = os.path.join(dest_dir, fname)
    try:
      indexed[fname] = _sync_key_for_file(fname, path, sync_mode)
    except Exception as e:
      logging.warning(f"[sync] key generation failed for {path}: {e}")

  if missing_files:
    conn.executemany(
        "INSERT OR REPLACE INTO testcase_keys(filename, key_type, key) "
        "VALUES (?, ?, ?)",
        ((f, indexed[f][0], indexed[f][1]) for f in missing_files if f in indexed),
    )
  conn.commit()
  return set(indexed.values())

def _read_used_cores(used_cores_file):
  if not used_cores_file or not os.path.isfile(used_cores_file):
    return []
  try:
    with open(used_cores_file, "r") as f:
      return [
          int(core.strip()) for core in f.read().split(",")
          if core.strip()
      ]
  except (OSError, ValueError) as e:
    logging.warning(f"[sync] failed to read {used_cores_file}: {e}")
    return []

def _scan_queue(qdir, sync_mode, core=None):
  if core is not None and hasattr(os, "sched_setaffinity"):
    try:
      os.sched_setaffinity(0, {core})
    except OSError as e:
      logging.warning(f"[sync] failed to bind scanning of {qdir} to core {core}: {e}")

  testcases = []
  for fname in os.listdir(qdir):
    if not _is_sync_candidate(fname):
      continue
    src_path = os.path.join(qdir, fname)
    if not os.path.isfile(src_path):
      continue
    try:
      key_type, key = _sync_key_for_file(fname, src_path, sync_mode)
      testcases.append((fname, src_path, key_type, key))
    except Exception as e:
      logging.warning(f"[sync] key generation failed for {src_path}: {e}")
  return testcases

def _available_destination(dest_dir, fname, sync_key, reserved_names=None):
  reserved_names = reserved_names or set()
  dst_path = os.path.join(dest_dir, fname)
  if not os.path.exists(dst_path) and fname not in reserved_names:
    return dst_path

  candidate = f"{fname}+key:{sync_key[:8]}"
  dst_path = os.path.join(dest_dir, candidate)
  suffix = 1
  candidate_name = candidate
  while os.path.exists(dst_path) or candidate_name in reserved_names:
    candidate_name = f"{candidate}.{suffix}"
    dst_path = os.path.join(dest_dir, candidate_name)
    suffix += 1
  return dst_path

def _atomic_copy2(src_path, dst_path):
  dest_dir = os.path.dirname(dst_path)
  staging_dir = os.path.dirname(dest_dir)
  fd, staging_path = tempfile.mkstemp(
      prefix=f".{os.path.basename(dest_dir)}-copy-",
      dir=staging_dir,
  )
  os.close(fd)
  try:
    os.remove(staging_path)
    try:
      os.link(src_path, staging_path)
    except OSError as e:
      if e.errno not in {
          errno.EXDEV,
          errno.EPERM,
          errno.EACCES,
          errno.EMLINK,
          errno.ENOTSUP,
      }:
        raise
      shutil.copy2(src_path, staging_path)
    os.replace(staging_path, dst_path)
  finally:
    if os.path.exists(staging_path):
      os.remove(staging_path)

def sync_unique_testcases(src_dirs, dest_dir, use_aflpp=False, used_cores_file=None, sync_mode=None):
    """Sync unique testcases into dest_dir."""
    os.makedirs(dest_dir, exist_ok=True)
    added = 0
    if sync_mode is None:
      sync_mode = "aflpp" if use_aflpp else "libafl"

    if sync_mode == "libafl":
      existing_keys = {
        _libafl_filename_key(f) for f in os.listdir(dest_dir)
        if _is_sync_candidate(f) and os.path.isfile(os.path.join(dest_dir, f))
      }

      for qdir in _queue_dirs(src_dirs):
        for fname in os.listdir(qdir):
          if not _is_sync_candidate(fname):
            continue
          src_path = os.path.join(qdir, fname)
          if not os.path.isfile(src_path):
            continue
          key = _libafl_filename_key(fname)
          if key in existing_keys:
            continue
          dst_path = _available_destination(dest_dir, fname, key)
          _atomic_copy2(src_path, dst_path)
          existing_keys.add(key)
          added += 1

      logging.debug(f"[Sync] Added {added} unique LibAFL testcases to shared sync directory: {dest_dir}")
      return

    if sync_mode in ("aflpp", "libafl-sqlite"):
      index_mode = "libafl" if sync_mode == "libafl-sqlite" else sync_mode
      with closing(_open_sync_index(dest_dir)) as conn:
        existing_keys = _load_shared_sync_keys(dest_dir, conn, index_mode)
        reserved_names = {
            row[0] for row in conn.execute("SELECT filename FROM testcase_keys")
        }
        queue_dirs = _queue_dirs(src_dirs)

        used_cores = _read_used_cores(used_cores_file)
        if used_cores:
          workers = min(len(queue_dirs), len(used_cores))
        else:
          workers = min(len(queue_dirs), os.cpu_count() or 1)
        logging.debug(
            "[Sync] Scanning %d worker queues in %s mode with %d threads on cores %s",
            len(queue_dirs), sync_mode, workers or 1,
            used_cores[:workers] if used_cores else "unbound",
        )
        pending_index_writes = 0
        with ThreadPoolExecutor(max_workers=workers or 1) as executor:
          futures = [
              executor.submit(
                  _scan_queue,
                  qdir,
                  index_mode,
                  used_cores[i % workers] if used_cores else None,
              )
              for i, qdir in enumerate(queue_dirs)
          ]
          for future in as_completed(futures):
            for fname, src_path, key_type, key in future.result():
              sync_key = (key_type, key)
              if sync_key in existing_keys:
                continue
              dst_path = _available_destination(
                  dest_dir, fname, key, reserved_names
              )
              _atomic_copy2(src_path, dst_path)
              dst_name = os.path.basename(dst_path)
              conn.execute(
                  "INSERT OR REPLACE INTO testcase_keys(filename, key_type, key) "
                  "VALUES (?, ?, ?)",
                  (dst_name, key_type, key),
              )
              reserved_names.add(dst_name)
              existing_keys.add(sync_key)
              added += 1
              pending_index_writes += 1
              if pending_index_writes >= 1000:
                conn.commit()
                pending_index_writes = 0
        conn.commit()
      logging.debug(f"[Sync] Added {added} unique {sync_mode} testcases to shared sync directory: {dest_dir}")
      return

    if sync_mode != "legacy":
      raise ValueError(f"Unsupported sync_mode: {sync_mode}")

    def extract_seed_key(filename):
      return filename[:16]

    # Gather already present keys in destination
    existing_keys = {
      extract_seed_key(f) for f in os.listdir(dest_dir)
      if not f.startswith('.') and os.path.isfile(os.path.join(dest_dir, f))
    }

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

def validate_out_folder(out_path: str):
    """Create a missing output folder, allow an empty one, abort on non-empty."""
    out_path = os.path.abspath(out_path)

    if not os.path.exists(out_path):
        os.makedirs(out_path, exist_ok=True)
        print(f"[+] Created new out_folder: {out_path}")
        return

    try:
        with os.scandir(out_path) as it:
            if next(it, None) is None:
                print(f"[+] out_folder exists but is empty: {out_path}")
                return
    except PermissionError:
        print(f"[!] Permission denied when accessing out_folder: {out_path}")
        sys.exit(1)

    print(f"[!] out_folder exists and is not empty: {out_path}")
    print("[!] To avoid accidental overwrite, please empty it or choose a new path.")
    sys.exit(1)

#Simple stopping condition based on timeout
def should_stop_timeout(timeout):
    try:
        time.sleep(timeout)
    except KeyboardInterrupt:
        logging.debug("Timeout interrupted manually by user (KeyboardInterrupt)")
        raise  # Re-raise the exception to propagate it for further handling
    return 0
