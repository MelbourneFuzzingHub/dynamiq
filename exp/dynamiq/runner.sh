#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/targets.sh"
source "${SCRIPT_DIR}/../common/post-clean.sh"

TARGET="${TARGET:-libpng}"
CORES="${CORES:-5}"
if (( CORES < 2 )); then
  echo "CORES must be at least 2 for DynamiQ" >&2
  exit 2
fi
TOTAL="${TOTAL:-86400}"
SCAN="${SCAN:-10800}"
EXPLOIT="${EXPLOIT:-10800}"
ALG="${ALG:-hrdf}"
OUT="${OUT:-/workdir/results/out-${TARGET}-dynamiq-${CORES}core}"
BUILD="${BUILD:-0}"
CLEAN_OUT="${CLEAN_OUT:-0}"
USE_CMPLOG="${USE_CMPLOG:-0}"
EXEC_LOG_INTERVAL="${EXEC_LOG_INTERVAL:-300}"
PRUNE_WORKER_QUEUES="${PRUNE_WORKER_QUEUES:-1}"

fuzzers_dir_arg="/dynamiq/fuzzers"

set_target_vars "$TARGET"
if [[ ! -d "$SEEDS" || -z "$(find "$SEEDS" -maxdepth 1 -type f -print -quit)" ]]; then
  echo "No seed files directly in $SEEDS" >&2
  exit 1
fi

cmplog_args=(--no-use_cmplog_in_task)
use_cmplog=0
if [[ "$USE_CMPLOG" == "1" && -x "$CMPLOG_BIN" ]]; then
  cmplog_args=(-cb "$CMPLOG_BIN" --use_cmplog_in_task)
  use_cmplog=1
fi

if [[ -f /.dockerenv ]]; then
  DYNAMIQ_FUZZERS_BUILD_ROOT="${DYNAMIQ_FUZZERS_BUILD_ROOT:-/workdir/fuzzers_build}"
  export DYNAMIQ_FUZZERS_BUILD_ROOT
  prepare_fuzzers_build "dynamiq-${TARGET}" "$use_cmplog"
  fuzzers_dir_arg="${DYNAMIQ_FUZZERS_BUILD_ROOT}/dynamiq-${TARGET}"
  export RUSTUP_TOOLCHAIN=1.82.0
  export AFL_PATH="${AFL_PATH:-/dynamiq/AFLplusplus4.22a}"
  export AFLPLUSPLUS="${AFLPLUSPLUS:-/dynamiq/AFLplusplus4.22a}"
fi

if [[ "$BUILD" == "1" ]]; then
  make -f /dynamiq/oss/Makefile "${DYNAMIQ_BUILD_TARGET}"
fi

poppler_artifacts=("$AFL_BIN" "$PROF_BIN" "$COV_BIN" "$DOT_FILE")
if [[ "$use_cmplog" == "1" ]]; then
  poppler_artifacts+=("$CMPLOG_BIN")
fi
verify_target_artifacts "${poppler_artifacts[@]}"

if [[ "$CLEAN_OUT" == "1" ]]; then
  rm -rf "$OUT"
fi
mkdir -p "$OUT"

if [[ -n "${PROF_LOGS:-}" && -d "$PROF_LOGS" ]]; then
  rm -rf "/tmp/$BIN_NAME"
  cp -a "$PROF_LOGS" "/tmp/$BIN_NAME"
fi

dict_args=()
if [[ -n "${DICT:-}" && -f "$DICT" ]]; then
  dict_args=(-x "$DICT")
fi

echo "target=$TARGET_NAME"
echo "out=$OUT"
echo "cores=$CORES total=$TOTAL scan=$SCAN exploit=$EXPLOIT alg=$ALG"
echo "prune_worker_queues_after_sync=$PRUNE_WORKER_QUEUES"
echo "seed_corpus=$(find "$SEEDS" -type f | wc -l)"

set +e
DYNAMIQ_PRUNE_WORKER_QUEUES_AFTER_SYNC="$PRUNE_WORKER_QUEUES" python3 /dynamiq/DynamiQ.py \
  -bn "$BIN_NAME" \
  -ab "$AFL_BIN" \
  -pb "$PROF_BIN" \
  -gb "$COV_BIN" \
  -gf $COV_DIRS \
  -tf "$TARGET_DIR" \
  -d "$DOT_FILE" \
  -i "$SEEDS" \
  "${dict_args[@]}" \
  -c "$CORES" \
  -o "$OUT" \
  -a "$ALG" \
  -tt "$TOTAL" \
  -st "$SCAN" \
  -et "$EXPLOIT" \
  -ea1 "$PRE_ARGS" \
  -ea2 "$POST_ARGS" \
  -ld "$fuzzers_dir_arg" \
  --parallel-map-size "$MAP_SIZE" \
  "${cmplog_args[@]}" \
  --exec-log-file exec_samples.csv \
  --exec-log-interval "$EXEC_LOG_INTERVAL"
status=$?
set -e
echo "status=$status"
echo "queue_count=$(find "$OUT" -path '*/queue/*' -type f 2>/dev/null | wc -l)"
echo "crash_count=$(find "$OUT" -path '*/crashes/*' -type f 2>/dev/null | wc -l)"
post_clean_dynamiq "$OUT"
exit "$status"
