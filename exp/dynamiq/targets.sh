#!/usr/bin/env bash

set_target_vars() {
  local target="${1:-libpng}"
  EXTRA_BUILD_DIR_CLEAN_ROOTS=""
  case "$target" in
    libpng|libpng_read_fuzzer)
      TARGET_NAME=libpng
      DYNAMIQ_BUILD_TARGET=libpng-dynamiq
      BIN_NAME=libpng_read_fuzzer
      AFL_BIN=/workdir/subjects/libpng/build-afl/libpng_read_fuzzer
      CMPLOG_BIN=/workdir/subjects/libpng/build-cmplog/libpng_read_fuzzer
      PROF_BIN=/workdir/subjects/libpng/build-profiling/libpng_read_fuzzer
      PROF_LOGS=/workdir/subjects/libpng/build-profiling/libpng_read_fuzzer-profiling-logs
      COV_BIN=/workdir/subjects/libpng/build-cov/libpng_read_fuzzer
      COV_DIRS="/workdir/subjects/libpng/build-cov"
      TARGET_DIR=/workdir/subjects/libpng
      DOT_FILE=/workdir/subjects/libpng/build-wllvm/libpng_read_fuzzer.dot
      SEEDS=/workdir/subjects/libpng/seed_corpus
      DICT=/workdir/subjects/libpng/png.dict
      PRE_ARGS=""
      POST_ARGS=""
      CMDLINE="@@"
      MAP_SIZE="${MAP_SIZE:-262144}"
      ;;
    sqlite3|ossfuzz)
      TARGET_NAME=sqlite3
      DYNAMIQ_BUILD_TARGET=sqlite3-dynamiq
      BIN_NAME=ossfuzz
      AFL_BIN=/workdir/subjects/sqlite3/build-afl/ossfuzz
      CMPLOG_BIN=/workdir/subjects/sqlite3/build-cmplog/ossfuzz
      PROF_BIN=/workdir/subjects/sqlite3/build-profiling/ossfuzz
      PROF_LOGS=/workdir/subjects/sqlite3/build-profiling/ossfuzz-profiling-logs
      COV_BIN=/workdir/subjects/sqlite3/build-cov/ossfuzz
      COV_DIRS="/workdir/subjects/sqlite3/build-cov"
      TARGET_DIR=/workdir/subjects/sqlite3
      DOT_FILE=/workdir/subjects/sqlite3/build-wllvm/ossfuzz.dot
      SEEDS=/workdir/subjects/sqlite3/ossfuzz_seed_corpus
      DICT=/workdir/subjects/sqlite3/sql.dict
      PRE_ARGS=""
      POST_ARGS=""
      CMDLINE="@@"
      MAP_SIZE="${MAP_SIZE:-262144}"
      ;;
    harfbuzz|hb-shape-fuzzer)
      TARGET_NAME=harfbuzz
      DYNAMIQ_BUILD_TARGET=harfbuzz-dynamiq
      BIN_NAME=hb-shape-fuzzer
      AFL_BIN=/workdir/subjects/harfbuzz/build-afl/hb-shape-fuzzer
      CMPLOG_BIN=/workdir/subjects/harfbuzz/build-cmplog/hb-shape-fuzzer
      PROF_BIN=/workdir/subjects/harfbuzz/build-profiling/hb-shape-fuzzer
      PROF_LOGS=/workdir/subjects/harfbuzz/build-profiling/hb-shape-fuzzer-profiling-logs
      COV_BIN=/workdir/subjects/harfbuzz/build-cov/hb-shape-fuzzer
      COV_DIRS="/workdir/subjects/harfbuzz/build-cov"
      TARGET_DIR=/workdir/subjects/harfbuzz
      DOT_FILE=/workdir/subjects/harfbuzz/build-wllvm/hb-shape-fuzzer.dot
      SEEDS=/workdir/subjects/harfbuzz/all-fonts
      DICT=
      PRE_ARGS=""
      POST_ARGS=""
      CMDLINE="@@"
      MAP_SIZE="${MAP_SIZE:-65536}"
      ;;
    bloaty|bloaty_fuzz_target|fuzz_target)
      TARGET_NAME=bloaty
      DYNAMIQ_BUILD_TARGET=bloaty-dynamiq
      BIN_NAME=bloaty_fuzz_target
      AFL_BIN=/workdir/subjects/bloaty/build-afl/bloaty_fuzz_target
      CMPLOG_BIN=/workdir/subjects/bloaty/build-cmplog/bloaty_fuzz_target
      PROF_BIN=/workdir/subjects/bloaty/build-profiling/bloaty_fuzz_target
      PROF_LOGS=/workdir/subjects/bloaty/build-profiling/bloaty_fuzz_target-profiling-logs
      COV_BIN=/workdir/subjects/bloaty/build-cov/bloaty_fuzz_target
      COV_DIRS="/workdir/subjects/bloaty/build-cov"
      TARGET_DIR=/workdir/subjects/bloaty
      DOT_FILE=/workdir/subjects/bloaty/build-wllvm/bloaty_fuzz_target.dot
      SEEDS=/workdir/subjects/bloaty/fuzz_corpus
      DICT=
      PRE_ARGS=""
      POST_ARGS=""
      CMDLINE="@@"
      MAP_SIZE="${MAP_SIZE:-262144}"
      ;;
    freetype2|ftfuzzer)
      TARGET_NAME=freetype2
      DYNAMIQ_BUILD_TARGET=freetype2-dynamiq
      BIN_NAME=ftfuzzer
      AFL_BIN=/workdir/subjects/freetype2/build-afl/ftfuzzer
      CMPLOG_BIN=/workdir/subjects/freetype2/build-cmplog/ftfuzzer
      PROF_BIN=/workdir/subjects/freetype2/build-profiling/ftfuzzer
      PROF_LOGS=/workdir/subjects/freetype2/build-profiling/ftfuzzer-profiling-logs
      COV_BIN=/workdir/subjects/freetype2/build-cov/ftfuzzer
      COV_DIRS="/workdir/subjects/freetype2/build-cov /workdir/subjects/libarchive-3.4.3/build-cov"
      TARGET_DIR=/workdir/subjects/freetype2
      EXTRA_BUILD_DIR_CLEAN_ROOTS="/workdir/subjects/libarchive-3.4.3"
      DOT_FILE=/workdir/subjects/freetype2/build-wllvm/ftfuzzer.dot
      SEEDS=/workdir/subjects/freetype2/seeds
      DICT=
      PRE_ARGS=""
      POST_ARGS=""
      CMDLINE="@@"
      MAP_SIZE="${MAP_SIZE:-262144}"
      ;;
    libxslt|xpath)
      TARGET_NAME=libxslt
      DYNAMIQ_BUILD_TARGET=libxslt-dynamiq
      BIN_NAME=xpath
      AFL_BIN=/workdir/subjects/libxslt/build-afl/xpath
      CMPLOG_BIN=/workdir/subjects/libxslt/build-cmplog/xpath
      PROF_BIN=/workdir/subjects/libxslt/build-profiling/xpath
      PROF_LOGS=/workdir/subjects/libxslt/build-profiling/xpath-profiling-logs
      COV_BIN=/workdir/subjects/libxslt/build-cov/xpath
      COV_DIRS="/workdir/subjects/libxslt/build-cov /workdir/subjects/libxml2-xslt/build-cov"
      TARGET_DIR=/workdir/subjects/libxslt
      EXTRA_BUILD_DIR_CLEAN_ROOTS="/workdir/subjects/libxml2-xslt"
      DOT_FILE=/workdir/subjects/libxslt/build-wllvm/xpath.dot
      SEEDS=/workdir/subjects/libxslt/build-afl/tests/fuzz/seed/xpath
      DICT=
      PRE_ARGS=""
      POST_ARGS=""
      CMDLINE="@@"
      MAP_SIZE="${MAP_SIZE:-262144}"
      ;;
    libpcap|fuzz_both|libpcap_fuzz_both)
      TARGET_NAME=libpcap
      DYNAMIQ_BUILD_TARGET=libpcap-dynamiq
      BIN_NAME=libpcap_fuzz_both
      AFL_BIN=/workdir/subjects/libpcap/build-afl/libpcap_fuzz_both
      CMPLOG_BIN=/workdir/subjects/libpcap/build-cmplog/libpcap_fuzz_both
      PROF_BIN=/workdir/subjects/libpcap/build-profiling/libpcap_fuzz_both
      PROF_LOGS=/workdir/subjects/libpcap/build-profiling/libpcap_fuzz_both-profiling-logs
      COV_BIN=/workdir/subjects/libpcap/build-cov/libpcap_fuzz_both
      COV_DIRS="/workdir/subjects/libpcap/build-cov"
      TARGET_DIR=/workdir/subjects/libpcap
      DOT_FILE=/workdir/subjects/libpcap/build-wllvm/libpcap_fuzz_both.dot
      SEEDS=/workdir/subjects/libpcap/corpus/fuzz_both
      DICT=
      PRE_ARGS=""
      POST_ARGS=""
      CMDLINE="@@"
      MAP_SIZE="${MAP_SIZE:-262144}"
      ;;
    libaom|av1_dec_fuzzer)
      TARGET_NAME=libaom
      DYNAMIQ_BUILD_TARGET=libaom-dynamiq
      BIN_NAME=av1_dec_fuzzer
      AFL_BIN=/workdir/subjects/libaom/build-afl/av1_dec_fuzzer
      CMPLOG_BIN=/workdir/subjects/libaom/build-cmplog/av1_dec_fuzzer
      PROF_BIN=/workdir/subjects/libaom/build-profiling/av1_dec_fuzzer
      PROF_LOGS=/workdir/subjects/libaom/build-profiling/av1_dec_fuzzer-profiling-logs
      COV_BIN=/workdir/subjects/libaom/build-cov/av1_dec_fuzzer
      COV_DIRS="/workdir/subjects/libaom/build-cov"
      TARGET_DIR=/workdir/subjects/libaom
      DOT_FILE=/workdir/subjects/libaom/build-wllvm/av1_dec_fuzzer.dot
      SEEDS=/workdir/subjects/libaom/av1_dec_fuzzer_seed_corpus/testdata
      DICT=/workdir/subjects/libaom/av1_dec_fuzzer.dict
      PRE_ARGS=""
      POST_ARGS=""
      CMDLINE="@@"
      MAP_SIZE="${MAP_SIZE:-262144}"
      ;;
    libjpeg|libjpeg-turbo|libjpeg_turbo_fuzzer)
      TARGET_NAME=libjpeg-turbo
      DYNAMIQ_BUILD_TARGET=libjpeg-turbo-dynamiq
      BIN_NAME=libjpeg_turbo_fuzzer
      AFL_BIN=/workdir/subjects/libjpeg-turbo/build-afl/libjpeg_turbo_fuzzer
      CMPLOG_BIN=/workdir/subjects/libjpeg-turbo/build-cmplog/libjpeg_turbo_fuzzer
      PROF_BIN=/workdir/subjects/libjpeg-turbo/build-profiling/libjpeg_turbo_fuzzer
      PROF_LOGS=/workdir/subjects/libjpeg-turbo/build-profiling/libjpeg_turbo_fuzzer-profiling-logs
      COV_BIN=/workdir/subjects/libjpeg-turbo/build-cov/libjpeg_turbo_fuzzer
      COV_DIRS="/workdir/subjects/libjpeg-turbo/build-cov"
      TARGET_DIR=/workdir/subjects/libjpeg-turbo
      DOT_FILE=/workdir/subjects/libjpeg-turbo/build-wllvm/libjpeg_turbo_fuzzer.dot
      SEEDS=/workdir/subjects/libjpeg-turbo/seeds
      DICT=
      PRE_ARGS=""
      POST_ARGS=""
      CMDLINE="@@"
      MAP_SIZE="${MAP_SIZE:-262144}"
      ;;
    libxml2|xml|fuzz-xml)
      TARGET_NAME=libxml2
      DYNAMIQ_BUILD_TARGET=libxml2-dynamiq
      BIN_NAME=fuzz-xml
      AFL_BIN=/workdir/subjects/libxml2/build-afl/fuzz-xml
      CMPLOG_BIN=/workdir/subjects/libxml2/build-cmplog/fuzz-xml-cmplog
      PROF_BIN=/workdir/subjects/libxml2/build-profiling/fuzz-xml
      PROF_LOGS=/workdir/subjects/libxml2/build-profiling/fuzz-xml-profiling-logs
      COV_BIN=/workdir/subjects/libxml2/build-cov/fuzz-xml
      COV_DIRS="/workdir/subjects/libxml2/build-cov"
      TARGET_DIR=/workdir/subjects/libxml2
      DOT_FILE=/workdir/subjects/libxml2/build-wllvm/fuzz-xml-wllvm.dot
      SEEDS=/workdir/subjects/libxml2/build-afl/seed/xml
      DICT=/workdir/subjects/libxml2/build-afl/seed/xml.dict
      PRE_ARGS=""
      POST_ARGS=""
      CMDLINE="@@"
      MAP_SIZE="${MAP_SIZE:-262144}"
      ;;
    lcms|cms_transform_fuzzer|cms_transform)
      TARGET_NAME=lcms
      DYNAMIQ_BUILD_TARGET=lcms-dynamiq
      BIN_NAME=cms_transform_fuzzer
      AFL_BIN=/workdir/subjects/lcms/build-afl/cms_transform_fuzzer
      CMPLOG_BIN=/workdir/subjects/lcms/build-cmplog/cms_transform_fuzzer
      PROF_BIN=/workdir/subjects/lcms/build-profiling/cms_transform_fuzzer
      PROF_LOGS=/workdir/subjects/lcms/build-profiling/cms_transform_fuzzer-profiling-logs
      COV_BIN=/workdir/subjects/lcms/build-cov/cms_transform_fuzzer
      COV_DIRS="/workdir/subjects/lcms/build-cov"
      TARGET_DIR=/workdir/subjects/lcms
      DOT_FILE=/workdir/subjects/lcms/build-wllvm/cms_transform_fuzzer.dot
      SEEDS=/workdir/subjects/lcms/seeds
      DICT=/workdir/subjects/lcms/dict/icc.dict
      PRE_ARGS=""
      POST_ARGS=""
      CMDLINE="@@"
      MAP_SIZE="${MAP_SIZE:-262144}"
      ;;
    mbedtls|fuzz_dtlsclient|dtlsclient)
      TARGET_NAME=mbedtls
      DYNAMIQ_BUILD_TARGET=mbedtls-dynamiq
      BIN_NAME=fuzz_dtlsclient
      AFL_BIN=/workdir/subjects/mbedtls/build-afl/fuzz_dtlsclient
      CMPLOG_BIN=/workdir/subjects/mbedtls/build-cmplog/fuzz_dtlsclient
      PROF_BIN=/workdir/subjects/mbedtls/build-profiling/fuzz_dtlsclient
      PROF_LOGS=/workdir/subjects/mbedtls/build-profiling/fuzz_dtlsclient-profiling-logs
      COV_BIN=/workdir/subjects/mbedtls/build-cov/fuzz_dtlsclient
      COV_DIRS="/workdir/subjects/mbedtls/build-cov"
      TARGET_DIR=/workdir/subjects/mbedtls
      DOT_FILE=/workdir/subjects/mbedtls/build-wllvm/fuzz_dtlsclient.dot
      SEEDS=/workdir/subjects/mbedtls/corpus/dtlsclient
      DICT=
      PRE_ARGS=""
      POST_ARGS=""
      CMDLINE="@@"
      MAP_SIZE="${MAP_SIZE:-262144}"
      ;;
    php|php-fuzz-parser)
      TARGET_NAME=php
      DYNAMIQ_BUILD_TARGET=php-dynamiq
      BIN_NAME=php-fuzz-parser
      AFL_BIN=/workdir/subjects/php-src/build-afl/php-fuzz-parser
      CMPLOG_BIN=/workdir/subjects/php-src/build-cmplog/php-fuzz-parser
      PROF_BIN=/workdir/subjects/php-src/build-profiling/php-fuzz-parser
      PROF_LOGS=/workdir/subjects/php-src/build-profiling/php-fuzz-parser-profiling-logs
      COV_BIN=/workdir/subjects/php-src/build-cov/php-fuzz-parser
      COV_DIRS="/workdir/subjects/php-src/build-cov"
      TARGET_DIR=/workdir/subjects/php-src
      DOT_FILE=/workdir/subjects/php-src/build-wllvm/sapi/fuzzer/php-fuzz-parser.dot
      # Magma keeps one corpus directory per PHP harness. This target runs
      # php-fuzz-parser, and the runners only import regular files directly from
      # SEEDS, so point at the parser corpus rather than its parent directory.
      SEEDS=/workdir/subjects/php-src/sapi/fuzzer/corpus/parser
      DICT=
      PRE_ARGS=""
      POST_ARGS=""
      CMDLINE="@@"
      MAP_SIZE="${MAP_SIZE:-262144}"
      ;;
    openssl|x509)
      TARGET_NAME=openssl
      DYNAMIQ_BUILD_TARGET=openssl-dynamiq
      BIN_NAME=x509
      AFL_BIN=/workdir/subjects/openssl/build-afl/x509
      CMPLOG_BIN=/workdir/subjects/openssl/build-cmplog/x509
      PROF_BIN=/workdir/subjects/openssl/build-profiling/x509
      PROF_LOGS=/workdir/subjects/openssl/build-profiling/x509-logs
      COV_BIN=/workdir/subjects/openssl/build-cov/x509
      COV_DIRS="/workdir/subjects/openssl"
      TARGET_DIR=/workdir/subjects/openssl
      DOT_FILE=/workdir/subjects/openssl/build-wllvm/x509.dot
      SEEDS=/workdir/subjects/openssl/seed_corpus
      DICT=/workdir/subjects/openssl/x509.dict
      PRE_ARGS=""
      POST_ARGS=""
      CMDLINE="@@"
      MAP_SIZE="${MAP_SIZE:-262144}"
      ;;
    poppler|pdf_fuzzer)
      POPPLER_REF="${POPPLER_REF:-1d23101ccebe14261c6afc024ea14f29d209e760}"
      FREETYPE_REF="${FREETYPE_REF:-50d0033f7ee600c5f5831b28877353769d1f7d48}"
      export POPPLER_REF FREETYPE_REF
      TARGET_NAME=poppler
      DYNAMIQ_BUILD_TARGET=poppler-dynamiq
      BIN_NAME=pdf_fuzzer
      AFL_BIN=/workdir/subjects/poppler/build-afl/pdf_fuzzer
      CMPLOG_BIN=/workdir/subjects/poppler/build-cmplog/pdf_fuzzer_cmplog
      PROF_BIN=/workdir/subjects/poppler/build-profiling/pdf_fuzzer_profiling
      PROF_LOGS=/workdir/subjects/poppler/build-profiling/pdf_fuzzer-profiling-logs
      COV_BIN=/workdir/subjects/poppler/build-cov/pdf_fuzzer_cov
      COV_DIRS="/workdir/subjects/poppler/repo/build-cov /workdir/subjects/poppler/freetype2/build-cov"
      TARGET_DIR=/workdir/subjects/poppler
      EXTRA_BUILD_DIR_CLEAN_ROOTS="/workdir/subjects/poppler/repo /workdir/subjects/poppler/freetype2"
      DOT_FILE=/workdir/subjects/poppler/build-wllvm/pdf_fuzzer.dot
      SEEDS=/workdir/subjects/poppler/seeds
      DICT=
      PRE_ARGS=""
      POST_ARGS=""
      CMDLINE="@@"
      MAP_SIZE="${MAP_SIZE:-262144}"
      ;;
    lua|fuzz_lua)
      TARGET_NAME=lua
      DYNAMIQ_BUILD_TARGET=lua-dynamiq
      BIN_NAME=fuzz_lua
      AFL_BIN=/workdir/subjects/lua/build-afl/fuzz_lua
      CMPLOG_BIN=/workdir/subjects/lua/build-cmplog/fuzz_lua
      PROF_BIN=/workdir/subjects/lua/build-profiling/fuzz_lua
      PROF_LOGS=/workdir/subjects/lua/build-profiling/fuzz_lua-profiling-logs
      COV_BIN=/workdir/subjects/lua/build-cov/fuzz_lua
      COV_DIRS="/workdir/subjects/lua/build-cov"
      TARGET_DIR=/workdir/subjects/lua
      DOT_FILE=/workdir/subjects/lua/build-wllvm/fuzz_lua.dot
      SEEDS=/workdir/subjects/lua/seed_corpus
      DICT=
      PRE_ARGS=""
      POST_ARGS=""
      CMDLINE="@@"
      MAP_SIZE="${MAP_SIZE:-262144}"
      ;;
    libsndfile|sndfile_fuzzer)
      TARGET_NAME=libsndfile
      DYNAMIQ_BUILD_TARGET=libsndfile-dynamiq
      BIN_NAME=sndfile_fuzzer
      AFL_BIN=/workdir/subjects/libsndfile/build-afl/sndfile_fuzzer
      CMPLOG_BIN=/workdir/subjects/libsndfile/build-cmplog/sndfile_fuzzer
      PROF_BIN=/workdir/subjects/libsndfile/build-profiling/sndfile_fuzzer
      PROF_LOGS=/workdir/subjects/libsndfile/build-profiling/sndfile_fuzzer-profiling-logs
      COV_BIN=/workdir/subjects/libsndfile/build-cov/sndfile_fuzzer
      COV_DIRS="/workdir/subjects/libsndfile/build-cov"
      TARGET_DIR=/workdir/subjects/libsndfile
      DOT_FILE=/workdir/subjects/libsndfile/build-wllvm/sndfile_fuzzer.dot
      SEEDS=/workdir/subjects/libsndfile/seed_corpus
      DICT=
      PRE_ARGS=""
      POST_ARGS=""
      CMDLINE="@@"
      MAP_SIZE="${MAP_SIZE:-262144}"
      ;;
    libtiff|tiff_read_rgba_fuzzer)
      TARGET_NAME=libtiff
      DYNAMIQ_BUILD_TARGET=libtiff-dynamiq
      BIN_NAME=tiff_read_rgba_fuzzer
      AFL_BIN=/workdir/subjects/libtiff/build-afl/tiff_read_rgba_fuzzer
      CMPLOG_BIN=/workdir/subjects/libtiff/build-cmplog/tiff_read_rgba_fuzzer
      PROF_BIN=/workdir/subjects/libtiff/build-profiling/tiff_read_rgba_fuzzer
      PROF_LOGS=/workdir/subjects/libtiff/build-profiling/tiff_read_rgba_fuzzer-profiling-logs
      COV_BIN=/workdir/subjects/libtiff/build-cov/tiff_read_rgba_fuzzer
      COV_DIRS="/workdir/subjects/libtiff/build-cov"
      TARGET_DIR=/workdir/subjects/libtiff
      DOT_FILE=/workdir/subjects/libtiff/build-wllvm/tiff_read_rgba_fuzzer.dot
      SEEDS=/workdir/subjects/libtiff/seed_corpus/tiff_read_rgba_fuzzer
      DICT=
      PRE_ARGS=""
      POST_ARGS=""
      CMDLINE="@@"
      MAP_SIZE="${MAP_SIZE:-262144}"
      ;;
    *)
      echo "Unknown TARGET '$target'" >&2
      return 2
      ;;
  esac
}

verify_target_artifacts() {
  [[ "${TARGET_NAME:-}" == "poppler" ]] || return 0

  local poppler_head freetype_head artifact stamp
  poppler_head="$(git -C "${TARGET_DIR}/repo" rev-parse HEAD)"
  freetype_head="$(git -C "${TARGET_DIR}/freetype2" rev-parse HEAD)"
  [[ "$poppler_head" == "$POPPLER_REF" ]] || {
    echo "Poppler checkout mismatch: expected $POPPLER_REF, found $poppler_head" >&2
    return 1
  }
  [[ "$freetype_head" == "$FREETYPE_REF" ]] || {
    echo "Freetype checkout mismatch: expected $FREETYPE_REF, found $freetype_head" >&2
    return 1
  }

  for artifact in "$@"; do
    [[ -e "$artifact" ]] || {
      echo "Missing Poppler artifact: $artifact" >&2
      return 1
    }
    stamp="$(dirname "$artifact")/source-refs"
    [[ -f "$stamp" ]] || {
      echo "Missing Poppler provenance stamp: $stamp" >&2
      return 1
    }
    grep -Fxq "POPPLER_REF=$POPPLER_REF" "$stamp" || return 1
    grep -Fxq "FREETYPE_REF=$FREETYPE_REF" "$stamp" || return 1
  done
  echo "[+] Verified Poppler/Freetype pinned artifacts"
}

prepare_fuzzers_build() {
  local profile="${1:-dynamiq}"
  local use_cmplog="${2:-0}"
  local build_root="${DYNAMIQ_FUZZERS_BUILD_ROOT:-/workdir/fuzzers_build}"
  local build_dir="$build_root/$profile"
  local -a cargo_bins

  case "$profile" in
    dynamiq*)
      if [[ "$use_cmplog" == "1" ]]; then
        cargo_bins=(run compile parallel_sync_cmplog advanced_cmplog)
      else
        cargo_bins=(run compile parallel_sync advanced_sync)
      fi
      ;;
    *)
      echo "Unknown fuzzer build profile '$profile' (expected dynamiq*)" >&2
      return 2
      ;;
  esac

  local aflpp_dir="${AFLPLUSPLUS:-${AFL_PATH:-/dynamiq/AFLplusplus4.22a}}"

  # Symlink AFL++ compiler binaries to /usr/local/bin/ to match host configuration
  if [[ -f /.dockerenv ]]; then
    echo "[+] Symlinking AFL++ compiler binaries to /usr/local/bin/..."
    ln -sf "$aflpp_dir/afl-clang-fast" /usr/local/bin/afl-clang-fast
    ln -sf "$aflpp_dir/afl-clang-fast++" /usr/local/bin/afl-clang-fast++
    ln -sf "$aflpp_dir/afl-as" /usr/local/bin/afl-as
    ln -sf "$aflpp_dir/afl-cc" /usr/local/bin/afl-cc
    ln -sf "$aflpp_dir/afl-c++" /usr/local/bin/afl-c++
  fi

  echo "[+] Syncing fresh fuzzer source code to $build_dir..."
  mkdir -p "$build_dir"
  mkdir -p "$build_root/target"
  rm -rf "$build_dir/target"
  ln -s "$build_root/target" "$build_dir/target"
  cp -pf /dynamiq/fuzzers/Cargo.toml "$build_dir/"
  cp -pf /dynamiq/fuzzers/Cargo.lock "$build_dir/" 2>/dev/null || true
  cp -pf /dynamiq/fuzzers/*.rs "$build_dir/" 2>/dev/null || true
  rm -rf "$build_dir/src" "$build_dir/task" "$build_dir/build_tasks"
  cp -a /dynamiq/fuzzers/src "$build_dir/"
  cp -a /dynamiq/fuzzers/task "$build_dir/"
  cp -a /dynamiq/fuzzers/build_tasks "$build_dir/"

  # Always run cargo build inside the container using Rust 1.82.0 toolchain to compile
  echo "[+] Compiling patched fuzzers inside container using Rust 1.82.0..."
  (
    cd "$build_dir"
    rustup toolchain install 1.82.0
    export RUSTUP_TOOLCHAIN=1.82.0
    export CARGO_TARGET_DIR="$build_root/target"
    local sanitized_path=""
    local entry
    IFS=':' read -r -a path_entries <<< "$PATH"
    for entry in "${path_entries[@]}"; do
      if [[ "$entry" == "$aflpp_dir" ]]; then
        continue
      fi
      if [[ -z "$sanitized_path" ]]; then
        sanitized_path="$entry"
      else
        sanitized_path="$sanitized_path:$entry"
      fi
    done
    export PATH="$sanitized_path"
    local -a build_cmd=(cargo build --release --locked)
    for bin in "${cargo_bins[@]}"; do
      build_cmd+=(--bin "$bin")
    done
    "${build_cmd[@]}"
  )

  printf '%s\n' "$build_dir"
}
