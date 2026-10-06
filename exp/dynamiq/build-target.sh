#!/usr/bin/env bash
set -euo pipefail

if (( $# == 0 )); then
  echo "Usage: build-target.sh target [target ...]" >&2
  exit 2
fi
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
image="${DYNAMIQ_IMAGE:-dynamiq:latest}"

if ! docker image inspect "$image" >/dev/null 2>&1; then
  docker build -t "$image" -f "$script_dir/Dockerfile" "$script_dir/../.."
fi

"$script_dir/run-in-docker.sh" bash -lc '
  if [[ ! -x /dynamiq/AFLplusplus4.22a/afl-fuzz ]]; then
    make -C /dynamiq/AFLplusplus4.22a source-only NO_NYX=1
  fi
  for target in "$@"; do
    make -f /dynamiq/oss/Makefile "$target-dynamiq"
  done
' _ "$@"
