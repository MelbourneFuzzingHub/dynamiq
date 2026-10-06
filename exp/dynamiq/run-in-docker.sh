#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DYNAMIQ_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
IMAGE="${DYNAMIQ_IMAGE:-dynamiq:latest}"
HOST_WORKDIR="${WORKDIR:-${DYNAMIQ_DIR}/exp}"
HOST_RESULTS_DIR="${RESULTS_DIR:-${HOST_WORKDIR}/results}"
DOCKER_CPUSET="${DOCKER_CPUSET:-}"
DOCKER_NAME="${DOCKER_NAME:-}"

mkdir -p "${HOST_WORKDIR}/subjects" "${HOST_RESULTS_DIR}"

DOCKER_TTY=(-i)
if [[ -t 0 && -t 1 ]]; then
  DOCKER_TTY=(-it)
fi

docker_args=(run --rm)
docker_args+=("${DOCKER_TTY[@]}")
if [[ -n "$DOCKER_CPUSET" ]]; then
  docker_args+=(--cpuset-cpus "$DOCKER_CPUSET")
fi
if [[ -n "$DOCKER_NAME" ]]; then
  docker_args+=(--name "$DOCKER_NAME")
fi
for variable in TARGET CORES TOTAL SCAN EXPLOIT ALG USE_CMPLOG EXEC_LOG_INTERVAL OUT BUILD CLEAN_OUT POST_CLEAN; do
  if [[ -v "$variable" ]]; then
    docker_args+=(-e "$variable=${!variable}")
  fi
done
docker_args+=(
  --network host
  -e AFLPLUSPLUS=/dynamiq/AFLplusplus4.22a
  -e AFL_PATH=/dynamiq/AFLplusplus4.22a
  -e AFL_AS=/usr/bin/as
  -e DYNAMIQ=/dynamiq
  -e WORKDIR=/workdir
  -e LLVM_CONFIG=llvm-config-15
  -e LLVM_COMPILER=clang
  -e LLVM_COMPILER_PATH=/usr/lib/llvm-15/bin
  -e AFL_SKIP_CPUFREQ=1
  -e AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
  -v "${DYNAMIQ_DIR}:/dynamiq"
  -v "${HOST_WORKDIR}:/workdir"
  -v "${HOST_RESULTS_DIR}:/workdir/results"
  -w /workdir/subjects
  "${IMAGE}"
)

docker "${docker_args[@]}" "$@"
