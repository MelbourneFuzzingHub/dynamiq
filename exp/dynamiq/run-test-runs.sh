#!/usr/bin/env bash
# DynamiQ Test Run Orchestration Script
# Runs the default targets (or TARGETS) in configurable batches on cores starting at 0.
# Repeats 3 times (rep 1, 2, and 3), each run takes 24 hours (86400s, 3h explore, 3h exploit), using 5 cores.

set -euo pipefail

# Ensure we run in the directory of the script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# Configurations (can be overridden by environment variables)
TOTAL="${TOTAL:-86400}"          # 24 hours total timeout per run
SCAN="${SCAN:-10800}"            # 3 hours exploration
EXPLOIT="${EXPLOIT:-10800}"      # 3 hours exploitation per round
CORES="${CORES:-5}"            # 5 cores per target
REPETITIONS="${REPETITIONS:-3}"
BATCH_SIZE="${BATCH_SIZE:-6}"  # Number of targets to run concurrently
LAUNCH_INTERVAL="${LAUNCH_INTERVAL:-0}"  # Seconds between target launches within a batch
CLEAN_OUT="${CLEAN_OUT:-1}"    # Clean previous output directory
ALG="${ALG:-hrdf}"             # Default DynamiQ algorithm
REBUILD="${REBUILD:-0}"        # Set to 1 to force rebuilding all targets
FIX_RESULT_PERMS="${FIX_RESULT_PERMS:-1}"  # Fix Docker-created result ownership after each target
PRUNE_WORKER_QUEUES="${PRUNE_WORKER_QUEUES:-1}"  # Prune stopped worker queues after sync
POST_CLEAN="${POST_CLEAN:-1}"  # Set to 0 to retain raw worker and phase logs

HOST_WORKDIR="${WORKDIR:-${SCRIPT_DIR}/..}"
RESULTS_DIR="${RESULTS_DIR:-${HOST_WORKDIR}/results}"
mkdir -p "${RESULTS_DIR}"
runner_id="$$"
active_containers=()

cleanup_campaign() {
  local status=$?
  trap - EXIT INT TERM

  if (( ${#active_containers[@]} > 0 )); then
    docker rm -f "${active_containers[@]}" >/dev/null 2>&1 || true
  fi

  docker run --rm \
    -v "${HOST_WORKDIR}/subjects:/workdir/subjects" \
    "${IMAGE_NAME:-dynamiq:latest}" \
    find /workdir/subjects -mindepth 2 -maxdepth 2 -type d \
      -name 'builddir-*' -exec rm -rf -- {} + \
    >/dev/null 2>&1 || true

  exit "${status}"
}

trap cleanup_campaign EXIT
trap 'exit 130' INT TERM

# 1. Docker Image Check & Build
IMAGE_NAME="${DYNAMIQ_IMAGE:-dynamiq:latest}"
if ! docker inspect --type=image "${IMAGE_NAME}" >/dev/null 2>&1; then
  echo "[*] Docker image '${IMAGE_NAME}' not found locally. Building it now..."
  make -C "${SCRIPT_DIR}" image
fi

# 2. Check and Build AFL++
AFL_FUZZ_BIN="../../AFLplusplus4.22a/afl-fuzz"
if [[ ! -f "${AFL_FUZZ_BIN}" ]]; then
  echo "[*] AFL++ binary not found at '${AFL_FUZZ_BIN}'. Compiling AFL++ inside docker..."
  ./run-in-docker.sh bash -lc "cd /dynamiq/AFLplusplus4.22a && make source-only NO_NYX=1"
fi

default_targets=(
  "harfbuzz"
  "libpcap"
  "mbedtls"
  "libjpeg-turbo"
  "libpng"
  "libxml2"
  "libaom"
  "freetype2"
  "bloaty"
  "lcms"
  "sqlite3"
  "libxslt"
)
read -r -a targets <<< "${TARGETS:-${default_targets[*]}}"

if (( ${#targets[@]} == 0 )); then
  echo "[-] TARGETS must contain at least one target." >&2
  exit 2
fi

echo "======================================================================"
echo "Starting DynamiQ parallel test run orchestrator"
echo "Total targets: ${#targets[@]}"
echo "Duration per run: ${TOTAL} seconds (Exploration: ${SCAN}s, Exploitation: ${EXPLOIT}s)"
echo "Cores per target: ${CORES}"
echo "Repetitions: ${REPETITIONS}"
echo "Concurrent targets per batch: ${BATCH_SIZE}"
echo "Launch interval within each batch: ${LAUNCH_INTERVAL} seconds"
echo "Algorithm: ${ALG}"
echo "Results output directory: ${RESULTS_DIR}"
echo "Fix result permissions: ${FIX_RESULT_PERMS}"
echo "Prune worker queues after sync: ${PRUNE_WORKER_QUEUES}"
echo "Post-clean enabled: ${POST_CLEAN}"
echo "======================================================================"

# 3. Check and Build Targets
for target in "${targets[@]}"; do
  if [[ "${REBUILD}" == "1" ]] || ! ./run-in-docker.sh bash -lc "
    source /dynamiq/exp/dynamiq/targets.sh
    set_target_vars '${target}'
    test -x \"\${AFL_BIN}\" &&
    test -x \"\${PROF_BIN}\" &&
    test -x \"\${COV_BIN}\" &&
    test -f \"\${DOT_FILE}\" &&
    test -d \"\${SEEDS}\"
  "; then
    echo "[*] Subject target '${target}' is not built for DynamiQ. Building it now inside docker..."
    ./run-in-docker.sh make -f /dynamiq/oss/Makefile "${target}-dynamiq"
  else
    echo "[+] Subject target '${target}' is already built for DynamiQ."
  fi
done

# Function to run a single target with a cpuset
run_target() {
  local target="$1"
  local cpuset="$2"
  local rep="$3"
  local log_file="${RESULTS_DIR}/run-${target}-${rep}.log"
  local out_dir="${RESULTS_DIR}/out-${target}-dynamiq-${rep}"
  local container_name="dynamiq-${runner_id}-${target//[^a-zA-Z0-9_.-]/-}-rep${rep}"

  echo "[+] [$(date +'%Y-%m-%d %H:%M:%S')] Launching target '${target}' on cores ${cpuset} (Run ${rep})..."
  echo "    Log file: ${log_file}"

  # Execute the run in docker container under the specified cpuset
  # Redirect outputs to target log file
  (
    RESULTS_DIR="${RESULTS_DIR}" DOCKER_CPUSET="${cpuset}" DOCKER_NAME="${container_name}" ./run-in-docker.sh bash -lc "
      TARGET=${target} CORES=${CORES} TOTAL=${TOTAL} SCAN=${SCAN} EXPLOIT=${EXPLOIT} ALG=${ALG} \
      CLEAN_OUT=${CLEAN_OUT} \
      POST_CLEAN=${POST_CLEAN} \
      PRUNE_WORKER_QUEUES=${PRUNE_WORKER_QUEUES} \
      OUT=/results/out-${target}-dynamiq-${rep} \
        /dynamiq/exp/dynamiq/run-dynamiq.sh
    "
    run_status=$?

    if [[ "${FIX_RESULT_PERMS}" == "1" || "${FIX_RESULT_PERMS}" == "true" || "${FIX_RESULT_PERMS}" == "yes" ]]; then
      echo "[*] [$(date +'%Y-%m-%d %H:%M:%S')] Fixing permissions for ${out_dir}"
      if ! sudo -n chown -R "$(id -u):$(id -g)" "${out_dir}" 2>/dev/null; then
        echo "[!] Could not fix permissions automatically. Run:"
        echo "    sudo chown -R \"\$USER\":\"\$USER\" \"${out_dir}\""
      fi
    fi

    exit "${run_status}"
  ) > "${log_file}" 2>&1 &
}

if ! [[ "$REPETITIONS" =~ ^[1-9][0-9]*$ && "$BATCH_SIZE" =~ ^[1-9][0-9]*$ ]]; then
  echo "[-] REPETITIONS and BATCH_SIZE must be positive integers." >&2
  exit 2
fi
if (( BATCH_SIZE * CORES > 32 )); then
  echo "[-] BATCH_SIZE * CORES exceeds the 32 available CPU IDs." >&2
  exit 2
fi

campaign_batches=(
)
for ((rep = 1; rep <= REPETITIONS; rep++)); do
  for ((batch_start = 0; batch_start < ${#targets[@]}; batch_start += BATCH_SIZE)); do
    batch=""
    batch_end=$((batch_start + BATCH_SIZE))
    ((batch_end > ${#targets[@]})) && batch_end=${#targets[@]}
    for ((i = batch_start; i < batch_end; i++)); do
      batch+="${batch:+ }${targets[i]}:${rep}"
    done
    campaign_batches+=("$batch")
  done
done

for ((batch_index = 0; batch_index < ${#campaign_batches[@]}; batch_index++)); do
  batch_num=$((batch_index + 1))
  read -r -a batch_jobs <<< "${campaign_batches[batch_index]}"

  echo ""
  echo "======================================================================"
  echo " [$(date +'%Y-%m-%d %H:%M:%S')] STARTING BATCH ${batch_num}/${#campaign_batches[@]}"
  echo "======================================================================"

  echo "Jobs: ${campaign_batches[batch_index]}"
  batch_start_time=$(date +%s)
  batch_pids=()
  batch_containers=()

  for ((i = 0; i < ${#batch_jobs[@]}; i++)); do
    job="${batch_jobs[i]}"
    target="${job%:*}"
    rep="${job##*:}"
    start_core=$((i * CORES))
    end_core=$((start_core + CORES - 1))
    cpuset="${start_core}-${end_core}"
    run_target "${target}" "${cpuset}" "${rep}"
    batch_pids+=($!)
    batch_containers+=("dynamiq-${runner_id}-${target//[^a-zA-Z0-9_.-]/-}-rep${rep}")
    active_containers=("${batch_containers[@]}")

    if (( LAUNCH_INTERVAL > 0 && i + 1 < ${#batch_jobs[@]} )); then
      echo "[*] Waiting ${LAUNCH_INTERVAL}s before launching the next target..."
      sleep "${LAUNCH_INTERVAL}"
    fi
  done

  echo "[*] [$(date +'%Y-%m-%d %H:%M:%S')] Waiting for Batch ${batch_num} targets to finish..."
  remaining_pids=("${batch_pids[@]}")
  while (( ${#remaining_pids[@]} > 0 )); do
    finished_pid=""
    if wait -n -p finished_pid "${remaining_pids[@]}"; then
      wait_status=0
    else
      wait_status=$?
    fi

    next_pids=()
    for pid in "${remaining_pids[@]}"; do
      [[ "${pid}" == "${finished_pid}" ]] || next_pids+=("${pid}")
    done
    remaining_pids=("${next_pids[@]}")

    if (( wait_status != 0 )); then
      echo "[-] [$(date +'%Y-%m-%d %H:%M:%S')] Target process ${finished_pid} finished with status ${wait_status}"
      echo "[-] Batch ${batch_num} failed; removing any surviving batch containers."
      docker rm -f "${batch_containers[@]}" >/dev/null 2>&1 || true
      exit 1
    fi
  done
  active_containers=()
  batch_end_time=$(date +%s)
  batch_duration=$((batch_end_time - batch_start_time))
  echo "[*] [$(date +'%Y-%m-%d %H:%M:%S')] Batch ${batch_num} finished! (Duration: ${batch_duration}s)"
done

echo ""
echo "======================================================================"
echo "All DynamiQ test runs completed successfully!"
echo "Outputs are stored at: ${RESULTS_DIR}/out-<target>-dynamiq-<rep>"
echo "Logs are stored at: ${RESULTS_DIR}/run-<target>-<rep>.log"
echo "======================================================================"
