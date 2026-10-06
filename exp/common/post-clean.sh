#!/usr/bin/env bash

post_clean_enabled() {
  [[ "${POST_CLEAN:-1}" == "1" || "${POST_CLEAN:-1}" == "true" || "${POST_CLEAN:-1}" == "yes" ]]
}

post_clean_rm() {
  local path
  for path in "$@"; do
    rm -rf -- "$path" 2>/dev/null || true
  done
}

post_clean_make_visible() {
  local out="$1"
  [[ -n "$out" && -d "$out" ]] || return 0
  chmod -R a+rwX "$out" 2>/dev/null || true
}

post_clean_dynamiq() {
  local out="$1"
  if post_clean_enabled; then
    echo "post_clean=1"
    find "$out" -path '*/queue/.state' -type d -prune -exec rm -rf {} + 2>/dev/null || true
    find "$out" -path '*/backup_round_*/output.txt' -type f -delete 2>/dev/null || true
    post_clean_rm \
      "$out"/instances/seeds* \
      "$out"/instances/fuzzer_*/queue \
      "$out"/instances/shared_sync \
      "$out"/active_runs/shared_sync \
      "$out"/active_runs/seeds

    local clean_root
    for clean_root in "${TARGET_DIR:-}" ${EXTRA_BUILD_DIR_CLEAN_ROOTS:-}; do
      if [[ -n "$clean_root" && -d "$clean_root" ]]; then
        rm -rf "$clean_root"/builddir-* 2>/dev/null || true
      fi
    done
  fi
  post_clean_make_visible "$out"
  true
}
