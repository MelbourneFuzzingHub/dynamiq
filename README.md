# Build DynamiQ (Tested on Ubuntu 22.04)
## Install the dependencies
```bash
sudo apt-get update
sudo apt-get install -y build-essential python3-dev cmake automake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools cargo libgtk-3-dev
sudo apt-get install -y lld-15 llvm-15 llvm-15-dev clang-15 || sudo apt-get install -y lld llvm llvm-dev clang
sudo apt-get install -y gcc-$(gcc --version | head -n1 | sed 's/.* //' | sed 's/\..*//')-plugin-dev libstdc++-$(gcc --version | head -n1 | sed 's/.* //' | sed 's/\..*//')-dev

sudo apt-get install -y ninja-build meson # for some targets like harfbuzz
```
##  Setup path
```bash
export WORKDIR=~/fuzzingdynamiq
export DYNAMIQ=~/DynamiQ
export AFLPLUSPLUS=~/DynamiQ/AFLplusplus4.22a
```
# Install Rust
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

# Setup DynamiQ
```bash
cd $HOME
git clone https://github.com/iany0/DynamiQ.git && cd DynamiQ
source setup-env.sh $(pwd)
make -f $DYNAMIQ/oss/Makefile prerequisites
source ~/.bashrc
which llvm-link
which wllvm
```
## Build AFL++ with function profiling and hash sync
```bash
cd $AFLPLUSPLUS
export LLVM_CONFIG="llvm-config-15"
make source-only NO_NYX=1
sudo make install

export AFL_SYNC_TIME=20
export AFL_FINAL_SYNC=1
```
##  Core Dump Configuration
AFL++ expects the system to allow writing core dumps directly. If not properly configured, AFL++ may abort.

### Option 1: Non-root, for testing
Skip strict crash detection:
```bash
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
```
### Option 2: Fix core pattern (Root only)
```bash
echo core | sudo tee /proc/sys/kernel/core_pattern
```
This allows AFL++ to capture crashes correctly via `waitpid()`.
## Setup required packages & environment variables
```bash
cd $WORKDIR
mkdir subjects
mkdir results
```
## Running DynamiQ

To see all available options and required arguments, run:

```bash
python3 DynamiQ.py --help
```

This will show the flags for configuring the binary, profiling tools, corpus, number of cores, timeouts, and instrumentation setup.

---


### Running Experiments

To run fuzzing experiments using DynamiQ, please refer to the setup:

[oss/README.md](https://github.com/iany0/DynamiQ/blob/main/oss/README.md)

