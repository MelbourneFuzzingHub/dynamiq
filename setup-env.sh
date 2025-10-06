#!/bin/sh

# Set and create WORKDIR if missing
export WORKDIR=~/fuzzingdynamiq
echo "WORKDIR: $WORKDIR"
[ ! -d "$WORKDIR" ] && mkdir -p "$WORKDIR"

# LLVM/Clang environment
export LLVM_CONFIG=llvm-config-15
export LLVM_COMPILER=clang-15
export LLVM_AR=/usr/lib/llvm-15/bin/llvm-ar
export LLVM_RANLIB=/usr/lib/llvm-15/bin/llvm-ranlib

# Core directories
export SUBJECTS=$WORKDIR/subjects
export RESULTS=$WORKDIR/results

# Tools and paths
export DYNAMIQ=~/DynamiQ
export AFLPLUSPLUS=~/DynamiQ/AFLplusplus4.22a

# AFL++ sync behavior
export AFL_SYNC_TIME=15
export AFL_FINAL_SYNC=1

