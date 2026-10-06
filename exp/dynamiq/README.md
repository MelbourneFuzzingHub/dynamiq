# DynamiQ Experiment Setup

## Build The Image

```sh
cd $DYNAMIQ/exp/dynamiq
make image
make check
```

## Build Targets

DynamiQ needs AFL, CmpLog, profiling, coverage, and WLLVM target builds:

```sh
./build-target.sh libpng
```

The script builds AFL++ if needed. Use `./build-target.sh [targets]` for one or
more names from the `*-dynamiq` targets in `oss/Makefile`, such as `libpng`,
`libtiff`, `freetype2`, or `sqlite3`.

## Run DynamiQ

Default: 24 hours total, 3 hours exploration, 3 hours exploitation, 5 cores.

```sh
./run-in-docker.sh bash -lc '
TARGET=libpng CORES=5 TOTAL=86400 SCAN=10800 EXPLOIT=10800 \
OUT=/workdir/results/out-libpng-dynamiq-24h \
  /dynamiq/exp/dynamiq/run-dynamiq.sh
'
```

Useful variables:

```sh
CORES=5
TOTAL=86400
SCAN=10800
EXPLOIT=10800
ALG=hrdf
USE_CMPLOG=1
EXEC_LOG_INTERVAL=300
OUT=/workdir/results/out-name
BUILD=1
CLEAN_OUT=1
POST_CLEAN=1
```

`POST_CLEAN=1` is the default and removes large transient per-worker queues,
shared sync directories, copied seeds, and AFL `.state` directories after the
run. It preserves the monitor/final queue, logs, task files, stats, plot data,
and `exec_samples.csv`. Use `POST_CLEAN=0` to keep everything.
