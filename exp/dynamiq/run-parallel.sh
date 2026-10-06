#!/usr/bin/env bash
set -euo pipefail

if (( $# == 0 )); then
  echo "Usage: START_CPU=16 CORES=5 TOTAL=1500 SCAN=180 EXPLOIT=660 ./run-parallel.sh target [target ...]" >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dynamiq_dir="$(cd "$script_dir/../.." && pwd)"
host_workdir="${WORKDIR:-$dynamiq_dir/exp}"
cores="${CORES:-5}"
total="${TOTAL:-86400}"
scan="${SCAN:-10800}"
exploit="${EXPLOIT:-10800}"
start_cpu="${START_CPU:-0}"
run_id="$(date +%Y%m%d-%H%M%S)-$$"
targets=("$@")
pids=()
containers=()

for value in "$cores" "$total" "$scan" "$exploit" "$start_cpu"; do
  [[ "$value" =~ ^[0-9]+$ ]] || { echo "CPU and time settings must be nonnegative integers" >&2; exit 2; }
done
(( cores > 0 && total > 0 )) || { echo "CORES and TOTAL must be positive" >&2; exit 2; }
for target in "${targets[@]}"; do
  [[ "$target" =~ ^[a-zA-Z0-9_-]+$ ]] || { echo "Invalid target: $target" >&2; exit 2; }
done

mkdir -p "$host_workdir/subjects" "$host_workdir/results"

cleanup() {
  if (( ${#containers[@]} > 0 )); then
    docker rm -f "${containers[@]}" >/dev/null 2>&1 || true
  fi
}
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

for i in "${!targets[@]}"; do
  target="${targets[i]}"
  first_cpu=$(( start_cpu + i * cores ))
  last_cpu=$(( first_cpu + cores - 1 ))
  cpuset="${first_cpu}-${last_cpu}"
  container="dynamiq-${target}-${run_id}-${i}"
  log="$host_workdir/results/${target}-${run_id}.log"
  containers+=("$container")

  DOCKER_CPUSET="$cpuset" DOCKER_NAME="$container" TARGET="$target" \
    CORES="$cores" TOTAL="$total" SCAN="$scan" EXPLOIT="$exploit" \
    OUT="/workdir/results/out-${target}-${run_id}" \
    "$script_dir/run-in-docker.sh" /dynamiq/exp/dynamiq/run-dynamiq.sh \
    </dev/null >"$log" 2>&1 &
  pids+=("$!")
  printf '%s: CPUs %s, log %s\n' "$target" "$cpuset" "$log"
done

failed=0
for i in "${!pids[@]}"; do
  if wait "${pids[i]}"; then
    printf '%s: complete\n' "${targets[i]}"
  else
    printf '%s: failed (see log)\n' "${targets[i]}" >&2
    failed=1
  fi
done
exit "$failed"
