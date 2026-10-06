SHELL:=/bin/bash

# Derive the absolute path of the directory containing this Makefile
OSS_DIR := $(patsubst %/,%,$(abspath $(dir $(lastword $(MAKEFILE_LIST)))))
DYNAMIQ_DIR := $(patsubst %/,%,$(abspath $(OSS_DIR)/..))
KRAKEN ?= $(DYNAMIQ_DIR)/exp/kraken/Kraken
ALPHA_CLANG ?= $(KRAKEN)/tools/alpha-clang
ALPHA_CLANGXX ?= $(KRAKEN)/tools/alpha-clang++
KRAKEN_DRIVER ?= $(DYNAMIQ_DIR)/exp/kraken/llvmfuzzer_file_driver.cc
AFL_EDGE ?= /opt/afl-edge
AFL_EDGE_AFL ?= $(AFL_EDGE)/afl
AFL_EDGE_CLANG ?= $(AFL_EDGE_AFL)/afl-clang-fast
AFL_EDGE_CLANGXX ?= $(AFL_EDGE_AFL)/afl-clang-fast++
AFL_EDGE_PASS ?= $(AFL_EDGE)/passes/CFG_edge_pass/build/splitEdge_inst/libsplit_edge.so
AFL_EDGE_RUNTIME ?= $(AFL_EDGE)/passes/CFG_edge_pass/build/runtime/libruntime.a
AFL_EDGE_DRIVER ?= $(DYNAMIQ_DIR)/exp/afl-edge/llvmfuzzer_file_driver.cc
MUFUZZ ?= /opt/mufuzz
MUFUZZ_AFL_CLANG ?= $(AFLPLUSPLUS)/afl-clang-fast
MUFUZZ_AFL_CLANGXX ?= $(AFLPLUSPLUS)/afl-clang-fast++
MUFUZZ_DRIVER ?= $(DYNAMIQ_DIR)/exp/mufuzz/llvmfuzzer_file_driver.cc
MUFUZZ_AFL_ENV ?= AFL_LLVM_INSTRUMENT=CLASSIC AFL_OLD_FORKSERVER=1
SQLITE3_FUZZ_CFLAGS ?= -DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 -DSQLITE_MAX_MEMORY=25000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 -DSQLITE_DEBUG=1 -DSQLITE_MAX_PAGE_COUNT=16384
SQLITE3_CC_FOR_BUILD ?= /usr/bin/gcc
SQLITE3_BUILD_PATH ?= /usr/local/go/bin:/root/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/llvm-15/bin:/usr/lib/llvm-10/bin
HARFBUZZ_FUZZ_CFLAGS ?= -fno-sanitize=vptr -DHB_NO_VISIBILITY
HARFBUZZ_FUZZ_CXXFLAGS ?= $(HARFBUZZ_FUZZ_CFLAGS)
OSS_TARGET ?= libpng
EXP_FUZZER ?= dynamiq
EXP_TARGETS ?= libpng sqlite3 harfbuzz bloaty freetype2 libxslt libpcap libaom libjpeg-turbo libxml2 lcms mbedtls
EXP_FUZZERS ?= dynamiq
EXP_DYNAMIQ_TARGETS ?= $(EXP_TARGETS) php openssl poppler lua libsndfile libtiff
EXP_KRAKEN_TARGETS ?= $(EXP_TARGETS) php openssl poppler lua libsndfile libtiff
EXP_MUFUZZ_TARGETS ?= $(EXP_TARGETS) php openssl poppler lua libsndfile libtiff
EXP_AFL_EDGE_TARGETS ?= $(EXP_TARGETS) php openssl poppler lua libsndfile libtiff
EXP_AFLTEAM_TARGETS ?= $(EXP_TARGETS) php openssl poppler lua libsndfile libtiff
MAGMA_REPO := https://github.com/HexHive/magma.git
MAGMA_REF := v1.2
TEXT_RENDERING_TESTS_REF := 5823ddb172570f376e4b181688f85a7977866d9f
TCPDUMP_REF := 82abba2bae5c606ecc2219bc3e087a9d3a7c1931
OSS_FUZZ_INPUTS_REF := 9905549cb14269aac9880913a6139937135c489d

# First, set up WORKDIR to fit your system
ifeq ($(WORKDIR),)
  $(error The env variable WORKDIR is not set)
endif

# print WORKDIR info
$(info The env variable WORKDIR is set to: $(WORKDIR))

# First, set up AFLPLUSPLUS to fit your system
ifeq ($(AFLPLUSPLUS),)
  $(error The AFLPLUSPLUS variable WORKDIR is not set)
endif

# print WORKDIR info
$(info The AFLPLUSPLUS variable WORKDIR is set to: $(AFLPLUSPLUS))

prerequisites:
	sudo apt-get update && \
	sudo apt-get install --fix-missing -y build-essential autoconf automake cmake nasm git htop tmux libtool zlib1g-dev gdb flex bison python3-pip texinfo clang zip unzip && \
	sudo apt-get install -y llvm-15 llvm-15-dev clang-15 && \
	pip3 install --user "wllvm" "networkx" "psutil" "pydot<2.0" "numpy==2.2.6" "scipy>=1.14.0" "scikit-learn>=1.5.0" && \
	echo 'export PATH="$$HOME/.local/bin:/usr/lib/llvm-15/bin:$$PATH"' >> $$HOME/.bashrc && \
	echo 'export LLVM_COMPILER=clang' >> $$HOME/.bashrc && \
	echo 'export LLVM_COMPILER_PATH=/usr/lib/llvm-15/bin' >> $$HOME/.bashrc && \
	. $$HOME/.bashrc && \
	export PATH="$$HOME/.local/bin:/usr/lib/llvm-15/bin:$$PATH" && \
	export LLVM_COMPILER=clang && \
	export LLVM_COMPILER_PATH=/usr/lib/llvm-15/bin && \
	which wllvm && wllvm --version && \
	which llvm-link && llvm-link --version

# Fuzzers
aflsmart:
	git clone https://github.com/aflsmart/aflsmart.git

# Subject programs
# Clone the libpng repository and checkout
libpng:
	git clone https://github.com/pnggroup/libpng.git libpng
	cd libpng && \
	git checkout ba980b8 && \
    cat scripts/pnglibconf.dfa | \
    sed -e "s/option STDIO/option STDIO disabled/" \
        -e "s/option WARNING /option WARNING disabled/" \
        -e "s/option WRITE enables WRITE_INT_FUNCTIONS/option WRITE disabled/" \
    > scripts/pnglibconf.dfa.temp && \
    mv scripts/pnglibconf.dfa.temp scripts/pnglibconf.dfa && \
    autoreconf -f -i && \
	mkdir -p seed_corpus && \
	find . -name "*.png" | grep -v crashers | xargs -I {} cp {} seed_corpus/ && \
    cp contrib/oss-fuzz/png.dict .

# Set up AFL++ with a fuzzing harness
libpng-afl: libpng
	cd libpng && \
    mkdir -p build-afl && cd build-afl && \
    CC=afl-clang-fast CXX=afl-clang-fast++ ../configure --disable-shared && \
    make clean all -j$(nproc) && \
	afl-clang-fast++ -std=c++11 -I. \
		../contrib/oss-fuzz/libpng_read_fuzzer.cc \
		-o libpng_read_fuzzer \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		.libs/libpng16.a \
		-lz -lm -lstdc++

# LibPNG CmpLog
libpng-cmplog: libpng
	cd libpng && \
    mkdir -p build-cmplog && cd build-cmplog && \
	export AFL_LLVM_CMPLOG=1 && \
    CC=afl-clang-fast CXX=afl-clang-fast++ ../configure --disable-shared && \
    make clean all -j$(nproc) && \
	AFL_LLVM_CMPLOG=1 afl-clang-fast++ -std=c++11 -I. \
		../contrib/oss-fuzz/libpng_read_fuzzer.cc \
		-o libpng_read_fuzzer \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		.libs/libpng16.a \
		-lz -lm -lstdc++ && \
	unset AFL_LLVM_CMPLOG

# LibPNG WLLVM (Whole Program LLVM)
libpng-wllvm: libpng
	cd libpng && \
    mkdir -p build-wllvm && cd build-wllvm && \
    export LLVM_COMPILER=clang && \
    CC=wllvm CXX=wllvm++ ../configure --disable-shared && \
    make clean all -j$(nproc) && \
    wllvm -g -fsanitize=fuzzer \
        ../contrib/oss-fuzz/libpng_read_fuzzer.cc \
        -o libpng_read_fuzzer \
        $(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
        .libs/libpng16.a \
        -lz -lm -lstdc++ && \
    extract-bc libpng_read_fuzzer && \
    opt-15 -passes=dot-callgraph -disable-output < libpng_read_fuzzer.bc && \
    mv '<stdin>.callgraph.dot' libpng_read_fuzzer.dot


# LibPNG Profiling
libpng-profiling: libpng
	cd libpng && \
    mkdir -p build-profiling && cd build-profiling && \
    rm -rf /tmp/libpng_read_fuzzer && mkdir /tmp/libpng_read_fuzzer && \
    HF_BINARY=libpng_read_fuzzer HORSEFUZZ_CG_PROFILING=1 CC=afl-clang-fast CXX=afl-clang-fast++ ../configure --disable-shared && \
    HF_BINARY=libpng_read_fuzzer HORSEFUZZ_CG_PROFILING=1 make clean all -j$(nproc) && \
    HF_BINARY=libpng_read_fuzzer HORSEFUZZ_CG_PROFILING=1 afl-clang-fast++ -o libpng_read_fuzzer \
        ../contrib/oss-fuzz/libpng_read_fuzzer.cc \
        -o libpng_read_fuzzer \
        $(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
        .libs/libpng16.a \
        -lz -lm -lstdc++ && \
    cp -r /tmp/libpng_read_fuzzer libpng_read_fuzzer-profiling-logs


# LibPNG Coverage
libpng-cov: libpng
	cd libpng && \
    mkdir -p build-cov && cd build-cov && \
    export LLVM_COMPILER=clang && \
    CC=clang CXX=clang++ CFLAGS="-g -fprofile-arcs -ftest-coverage" CXXFLAGS="-g -fprofile-arcs -ftest-coverage" ../configure --disable-shared && \
    make clean all -j$(nproc) && \
    clang -g -fsanitize=fuzzer -fprofile-arcs -ftest-coverage -I. -I.. \
        ../contrib/oss-fuzz/libpng_read_fuzzer.cc \
        -o libpng_read_fuzzer \
        $(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
        .libs/libpng16.a \
        -lz -lm -lstdc++

# Aggregate Targets
libpng-all: libpng-afl libpng-wllvm libpng-profiling libpng-cov

# Clean all builds
libpng-clean-all:
	rm -rf libpng libpng/build-* /tmp/libpng_read_fuzzer

# Build and prepare FreeType2 with AFL++ Instrumentation
freetype2:
	git clone https://github.com/freetype/freetype.git freetype2 && \
	cd freetype2 && \
	git checkout cd02d35 && \
	cp -r src/tools/ftfuzzer /tmp/ && \
	git checkout 82090e6 && \
	mkdir -p src/tools && mv /tmp/ftfuzzer src/tools/ && \
	git clone https://github.com/unicode-org/text-rendering-tests.git TRT && \
	cd TRT && git checkout $(TEXT_RENDERING_TESTS_REF) && cd .. && \
	mkdir -p seeds && \
	cp TRT/fonts/TestKERNOne.otf seeds/ && \
	cp TRT/fonts/TestGLYFOne.ttf seeds/ && \
	./autogen.sh && \
	if [ "$(IS_KRAKEN)" = "1" ]; then ./configure --with-brotli=no; else ./configure --with-brotli=yes; fi && \
	make -j$$(nproc) && \
	cd .. && \
	wget https://github.com/libarchive/libarchive/releases/download/v3.4.3/libarchive-3.4.3.tar.xz && \
	tar xf libarchive-3.4.3.tar.xz

# Build FreeType2 with AFL++ Instrumentation (Includes libarchive)
freetype2-afl: freetype2
	cd libarchive-3.4.3 && \
	rm -rf build-afl && mkdir -p build-afl && cd build-afl && \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	../configure --disable-shared --prefix=$$(pwd)/install && \
	make clean && make -j$(nproc) && make install && \
	cd ../..
	cd freetype2 && \
	rm -rf build-afl && mkdir -p build-afl && cd build-afl && \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	../configure --prefix=$$(pwd)/install --with-harfbuzz=no --with-bzip2=no --with-png=no --without-zlib --with-brotli=no && \
	make clean && make all -j$(nproc) && make install && \
	afl-clang-fast++ -std=c++11 -I ../include -I .. \
		-I $$(pwd)/../../libarchive-3.4.3/build-afl/install/include \
		../src/tools/ftfuzzer/ftfuzzer.cc \
		$$(pwd)/install/lib/libfreetype.a \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		$$(pwd)/../../libarchive-3.4.3/build-afl/install/lib/libarchive.a \
		-o ftfuzzer

# Build FreeType2 with Whole-Program LLVM (wllvm) and extract the call graph
freetype2-wllvm: freetype2
	cd libarchive-3.4.3 && \
	rm -rf build-wllvm && mkdir -p build-wllvm && cd build-wllvm && \
	export LLVM_COMPILER=clang && \
	CC=wllvm CXX=wllvm++ \
	../configure --disable-shared --prefix=$$(pwd)/install && \
	make clean && make -j$(nproc) && make install && \
	cd ../..
	cd freetype2 && \
	rm -rf build-wllvm && mkdir -p build-wllvm && cd build-wllvm && \
	export LLVM_COMPILER=clang && \
	CC=wllvm CXX=wllvm++ \
	../configure --prefix=$$(pwd)/install --with-harfbuzz=no --with-bzip2=no --with-png=no --without-zlib --with-brotli=no && \
	make clean && make all -j$(nproc) && make install && \
	wllvm++ -g -fsanitize=fuzzer -std=c++11 -I ../include -I .. \
		-I $$(pwd)/../../libarchive-3.4.3/build-wllvm/install/include \
		../src/tools/ftfuzzer/ftfuzzer.cc \
		$$(pwd)/install/lib/libfreetype.a \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		$$(pwd)/../../libarchive-3.4.3/build-wllvm/install/lib/libarchive.a \
		-o ftfuzzer && \
	extract-bc ftfuzzer && \
	opt-15 -passes=dot-callgraph -disable-output < ftfuzzer.bc && \
	mv '<stdin>.callgraph.dot' ftfuzzer.dot

# Build FreeType2 with profiling (with instrumented fuzzing harness and logging)
freetype2-profiling: freetype2
	cd libarchive-3.4.3 && \
	rm -rf build-profiling && mkdir -p build-profiling && cd build-profiling && \
	rm -rf /tmp/ftfuzzer && mkdir /tmp/ftfuzzer && \
	HF_BINARY=ftfuzzer HORSEFUZZ_CG_PROFILING=1 \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	../configure --disable-shared --prefix=$$(pwd)/install && \
	HF_BINARY=ftfuzzer HORSEFUZZ_CG_PROFILING=1 make clean && HF_BINARY=ftfuzzer HORSEFUZZ_CG_PROFILING=1 make -j$(nproc) && HF_BINARY=ftfuzzer HORSEFUZZ_CG_PROFILING=1 make install && \
	cd ../..
	cd freetype2 && \
	rm -rf build-profiling && mkdir -p build-profiling && cd build-profiling && \
	HF_BINARY=ftfuzzer HORSEFUZZ_CG_PROFILING=1 \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	../configure --prefix=$$(pwd)/install --with-harfbuzz=no --with-bzip2=no --with-png=no --without-zlib --with-brotli=no && \
	HF_BINARY=ftfuzzer HORSEFUZZ_CG_PROFILING=1 make clean && HF_BINARY=ftfuzzer HORSEFUZZ_CG_PROFILING=1 make all -j$(nproc) && HF_BINARY=ftfuzzer HORSEFUZZ_CG_PROFILING=1 make install && \
	cd ..
	cd freetype2/build-profiling && \
	HF_BINARY=ftfuzzer HORSEFUZZ_CG_PROFILING=1 \
	afl-clang-fast++ -std=c++11 -I ../include -I .. \
		-I $$(pwd)/../../libarchive-3.4.3/build-profiling/install/include \
		../src/tools/ftfuzzer/ftfuzzer.cc \
		$$(pwd)/install/lib/libfreetype.a \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		$$(pwd)/../../libarchive-3.4.3/build-profiling/install/lib/libarchive.a \
		-o ftfuzzer && \
	cp -r /tmp/ftfuzzer ftfuzzer-profiling-logs

# Build FreeType2 with coverage instrumentation
freetype2-cov: freetype2
	cd libarchive-3.4.3 && \
	rm -rf build-cov && mkdir -p build-cov && cd build-cov && \
	CC=clang CXX=clang++ \
	CFLAGS="-g -fprofile-arcs -ftest-coverage" CXXFLAGS="-g -fprofile-arcs -ftest-coverage" \
	../configure --disable-shared --prefix=$$(pwd)/install && \
	make clean && make -j$(nproc) && make install && \
	cd ../..
	cd freetype2 && \
	rm -rf build-cov && mkdir -p build-cov && cd build-cov && \
	CC=clang CXX=clang++ \
	CFLAGS="-g -fprofile-arcs -ftest-coverage" CXXFLAGS="-g -fprofile-arcs -ftest-coverage" \
	../configure --prefix=$$(pwd)/install --with-harfbuzz=no --with-bzip2=no --with-png=no --without-zlib --with-brotli=no && \
	make clean && make all -j$(nproc) && make install && \
	cd ..
	cd freetype2/build-cov && \
	clang++ -g -fsanitize=fuzzer -fprofile-arcs -ftest-coverage -std=c++11 -I ../include -I .. \
		-I $$(pwd)/../../libarchive-3.4.3/build-cov/install/include \
		../src/tools/ftfuzzer/ftfuzzer.cc \
		$$(pwd)/install/lib/libfreetype.a \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		$$(pwd)/../../libarchive-3.4.3/build-cov/install/lib/libarchive.a \
		-o ftfuzzer

freetype2-cmplog: freetype2
	cd libarchive-3.4.3 && \
	export AFL_LLVM_CMPLOG=1 && \
	rm -rf build-cmplog && mkdir -p build-cmplog && cd build-cmplog && \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	../configure --disable-shared --prefix=$$(pwd)/install && \
	make clean && make -j$(nproc) && make install && \
	unset AFL_LLVM_CMPLOG && \
	cd ../..
	cd freetype2 && \
	export AFL_LLVM_CMPLOG=1 && \
	rm -rf build-cmplog && mkdir -p build-cmplog && cd build-cmplog && \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	../configure --prefix=$$(pwd)/install --with-harfbuzz=no --with-bzip2=no --with-png=no --without-zlib --with-brotli=no && \
	make clean && make all -j$(nproc) && make install && \
	afl-clang-fast++ -std=c++11 -I ../include -I .. \
		-I $$(pwd)/../../libarchive-3.4.3/build-cmplog/install/include \
		../src/tools/ftfuzzer/ftfuzzer.cc \
		$$(pwd)/install/lib/libfreetype.a \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		$$(pwd)/../../libarchive-3.4.3/build-cmplog/install/lib/libarchive.a \
		-o ftfuzzer && \
	unset AFL_LLVM_CMPLOG

freetype2-all: freetype2-afl freetype2-wllvm freetype2-profiling freetype2-cov
freetype2-clean-all:
	rm -rf freetype2 libarchive-3.4.3 libarchive-3.4.3.tar.xz /tmp/ftfuzzer*

sqlite3:
	@echo "=== Downloading and building SQLite3 ==="
	mkdir -p sqlite3
	cd sqlite3 && \
		git clone https://github.com/sqlite/sqlite.git . && \
		git checkout 4d9384cba35ce7971431da9b543e0f9d68975947
	@echo "=== Generating corpus from *.test files ==="
	cd sqlite3 && \
		mkdir -p ossfuzz_seed_corpus && \
		find . -name "*.test" -exec cp {} ossfuzz_seed_corpus/ \;
	@echo "=== Downloading sql.dict ==="
	cd sqlite3 && \
		curl -L 'https://github.com/google/oss-fuzz/raw/9905549cb14269aac9880913a6139937135c489d/projects/sqlite3/sql.dict' -o sql.dict

sqlite3-afl: sqlite3
	@echo "=== Building SQLite3 with AFL instrumentation ==="
	cd sqlite3 && \
	rm -rf build-afl && mkdir -p build-afl && cd build-afl && \
		CC=afl-clang-fast CXX=afl-clang-fast++ \
		CFLAGS="-DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 -DSQLITE_MAX_MEMORY=25000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 -DSQLITE_DEBUG=1 -DSQLITE_MAX_PAGE_COUNT=16384" \
		../configure --shared=0 && \
		make -j$$(nproc) && \
		make sqlite3.c && \
		afl-clang-fast -DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 -DSQLITE_MAX_MEMORY=25000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 -DSQLITE_DEBUG=1 -DSQLITE_MAX_PAGE_COUNT=16384 -I. -c ../test/ossfuzz.c -o ossfuzz.o && \
		afl-clang-fast++ ossfuzz.o -o ossfuzz $(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a sqlite3.o -pthread -ldl -lz

sqlite3-afl-asan: sqlite3
	@echo "=== Building SQLite3 with AFL instrumentation ==="
	cd sqlite3 && \
	mkdir -p build-afl-asan && cd build-afl-asan && \
		export AFL_USE_ASAN=1 && \
		CC=afl-clang-fast CXX=afl-clang-fast++ \
		CFLAGS="-DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 -DSQLITE_MAX_MEMORY=25000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 -DSQLITE_DEBUG=1 -DSQLITE_MAX_PAGE_COUNT=16384" \
		../configure --shared=0 && \
		make -j$$(nproc) && \
		make sqlite3.c && \
		afl-clang-fast -DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 -DSQLITE_MAX_MEMORY=25000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 -DSQLITE_DEBUG=1 -DSQLITE_MAX_PAGE_COUNT=16384 -I. -c ../test/ossfuzz.c -o ossfuzz.o && \
		afl-clang-fast++ ossfuzz.o -o ossfuzz $(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a sqlite3.o -pthread -ldl -lz

sqlite3-cmplog: sqlite3
	@echo "=== Building SQLite3 with AFL-CmpLog instrumentation ==="
	cd sqlite3 && \
	rm -rf build-cmplog && mkdir -p build-cmplog && cd build-cmplog && \
		export AFL_LLVM_CMPLOG=1 && \
		CC=afl-clang-fast CXX=afl-clang-fast++ \
		CFLAGS="-DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 -DSQLITE_MAX_MEMORY=25000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 -DSQLITE_DEBUG=1 -DSQLITE_MAX_PAGE_COUNT=16384" \
		../configure --shared=0 && \
		make -j$$(nproc) && \
		make sqlite3.c && \
		afl-clang-fast -DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 -DSQLITE_MAX_MEMORY=25000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 -DSQLITE_DEBUG=1 -DSQLITE_MAX_PAGE_COUNT=16384 -I. -c ../test/ossfuzz.c -o ossfuzz.o && \
		afl-clang-fast++ ossfuzz.o -o ossfuzz $(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a sqlite3.o -pthread -ldl -lz && \
		unset AFL_LLVM_CMPLOG

# Build SQLite3 with Whole-Program LLVM (wllvm) and extract the call graph
sqlite3-wllvm: sqlite3
	@echo "=== Building SQLite3 with wllvm and extracting call graph ==="
	cd sqlite3 && \
	rm -rf build-wllvm && mkdir -p build-wllvm && cd build-wllvm && \
	export LLVM_COMPILER=clang && \
	CC=wllvm CXX=wllvm++ \
	CFLAGS="-DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 -DSQLITE_MAX_MEMORY=25000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 -DSQLITE_DEBUG=1 -DSQLITE_MAX_PAGE_COUNT=16384" \
	../configure --shared=0 && \
	make -j$$(nproc) && \
	make sqlite3.c && \
	wllvm -g -fsanitize=fuzzer -DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 -DSQLITE_MAX_MEMORY=25000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 -DSQLITE_DEBUG=1 -DSQLITE_MAX_PAGE_COUNT=16384 -I. -c ../test/ossfuzz.c -o ../test/ossfuzz.o && \
	wllvm++ -g -fsanitize=fuzzer ../test/ossfuzz.o -o ossfuzz $(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a sqlite3.o -pthread -ldl -lz && \
	extract-bc $$(pwd)/ossfuzz && \
	opt-15 -passes=dot-callgraph -disable-output $$(pwd)/ossfuzz.bc && \
	mv $$(pwd)/ossfuzz.bc.callgraph.dot $$(pwd)/ossfuzz.dot

# Build SQLite3 for profiling (with instrumented fuzzing harness and logging)
sqlite3-profiling: sqlite3
	@echo "=== Building SQLite3 with AFL instrumentation ==="
	cd sqlite3 && \
	rm -rf build-profiling && mkdir -p build-profiling && cd build-profiling && \
		HF_BINARY=ossfuzz HORSEFUZZ_CG_PROFILING=1 \
		CC=afl-clang-fast CXX=afl-clang-fast++ \
		CFLAGS="-DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 -DSQLITE_MAX_MEMORY=25000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 -DSQLITE_DEBUG=1 -DSQLITE_MAX_PAGE_COUNT=16384" \
		../configure --shared=0 && \
		HF_BINARY=ossfuzz HORSEFUZZ_CG_PROFILING=1 make -j$$(nproc) && \
		HF_BINARY=ossfuzz HORSEFUZZ_CG_PROFILING=1 make sqlite3.c && \
		HF_BINARY=ossfuzz HORSEFUZZ_CG_PROFILING=1 afl-clang-fast -DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 -DSQLITE_MAX_MEMORY=25000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 -DSQLITE_DEBUG=1 -DSQLITE_MAX_PAGE_COUNT=16384 -I. -c ../test/ossfuzz.c -o ../test/ossfuzz.o && \
		HF_BINARY=ossfuzz HORSEFUZZ_CG_PROFILING=1 afl-clang-fast++ ../test/ossfuzz.o -o ossfuzz $(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a sqlite3.o -pthread -ldl -lz && \
		cp -r /tmp/ossfuzz ossfuzz-profiling-logs

# Build SQLite3 with LLVM source-profile instrumentation.
sqlite3-cov: sqlite3
	@echo "=== Building SQLite3 with LLVM source-profile coverage ==="
	cd sqlite3 && \
	rm -rf build-cov && mkdir -p build-cov && cd build-cov && \
	export LLVM_COMPILER=clang && \
	export PATH=$(SQLITE3_BUILD_PATH) && \
	CC=clang CXX=clang++ \
	CFLAGS="-g -fprofile-instr-generate -fcoverage-mapping \
	        -DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 \
	        -DSQLITE_MAX_MEMORY=25000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
	        -DSQLITE_DEBUG=1 -DSQLITE_MAX_PAGE_COUNT=16384" \
	../configure --shared=0 && \
	make -j$$(nproc) && \
	make sqlite3.c && \
	clang -g -fprofile-instr-generate -fcoverage-mapping -I. \
		-DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 \
		-DSQLITE_MAX_MEMORY=25000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
		-DSQLITE_DEBUG=1 -DSQLITE_MAX_PAGE_COUNT=16384 \
		-c ../test/ossfuzz.c -o ossfuzz.o && \
	clang++ -g -fprofile-instr-generate -fcoverage-mapping \
		ossfuzz.o -o ossfuzz \
		-fsanitize=fuzzer sqlite3.o -pthread -Wl,--no-as-needed -Wl,-ldl -Wl,-lm

# gcov-compatible SQLite harness used for comparable saved-queue line and
# branch-arc coverage. LLVM 10 source profiles do not expose branch totals.
sqlite3-queue-cov: sqlite3-cov
	cd sqlite3 && \
	rm -rf build-queue-cov && mkdir -p build-queue-cov && cd build-queue-cov && \
	export PATH=$(SQLITE3_BUILD_PATH) && \
	clang -g -fprofile-arcs -ftest-coverage -I../build-cov \
		-DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 \
		-DSQLITE_MAX_MEMORY=25000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
		-DSQLITE_DEBUG=1 -DSQLITE_MAX_PAGE_COUNT=16384 \
		-c ../build-cov/sqlite3.c -o sqlite3.o && \
	clang -g -fprofile-arcs -ftest-coverage -I../build-cov \
		-DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 \
		-DSQLITE_MAX_MEMORY=25000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
		-DSQLITE_DEBUG=1 -DSQLITE_MAX_PAGE_COUNT=16384 \
		-c ../test/ossfuzz.c -o ossfuzz.o && \
	clang++ -g -fprofile-arcs -ftest-coverage ossfuzz.o sqlite3.o -o ossfuzz \
		-fsanitize=fuzzer -pthread -Wl,--no-as-needed -Wl,-ldl -Wl,-lm

sqlite3-all: sqlite3-afl sqlite3-wllvm sqlite3-profiling sqlite3-cov
sqlite3-clean-all:
	rm -rf sqlite3 sqlite3/build-* /tmp/ossfuzz*

# libxslt Base Setup
libxslt:
	git clone https://github.com/GNOME/libxml2.git libxml2-xslt && \
	cd libxml2-xslt && \
	git checkout 3b38f19 && \
	if [ "$(IS_KRAKEN)" = "1" ]; then sed -i 's/1\.16\.3/1.16.1/g' configure.ac; fi && \
	autoreconf -if -Wall && \
	cd .. && \
	git clone https://gitlab.gnome.org/GNOME/libxslt.git libxslt && \
	cd libxslt && \
	git checkout 7504032 && \
	if [ "$(IS_KRAKEN)" = "1" ]; then sed -i 's/1\.16\.3/1.16.1/g' configure.ac; fi && \
	autoreconf -if -Wall

libxslt-afl: libxslt
	cd libxml2-xslt && \
	rm -rf build-afl && mkdir -p build-afl && cd build-afl && \
	cp -r ../include . && \
	CC=afl-clang-fast CXX=afl-clang-fast++ ../configure \
		--disable-shared --without-c14n --without-push --without-python \
		--without-reader --without-regexps --without-sax1 --without-schemas \
		--without-schematron --without-valid --without-writer --without-zlib \
		--without-lzma && \
	make -j$(nproc) && cd ../../libxslt && \
	rm -rf build-afl && mkdir -p build-afl && cd build-afl && \
	CC=afl-clang-fast CXX=afl-clang-fast++ ../configure \
		--with-libxml-src=$(WORKDIR)/subjects/libxml2-xslt/build-afl \
		--disable-shared --without-python --without-crypto --without-debug \
		--without-debugger --without-profiler && \
	make -j$(nproc) && cd tests/fuzz && \
	mkdir -p seed/xpath && make seed/xpath.stamp fuzz.o xpath.o && \
	afl-clang-fast++ -std=c++11 xpath.o fuzz.o -o ../../xpath \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		../../libexslt/.libs/libexslt.a ../../libxslt/.libs/libxslt.a \
		$(WORKDIR)/subjects/libxml2-xslt/build-afl/.libs/libxml2.a

# libxslt with WLLVM
libxslt-wllvm: libxslt
	cd libxml2-xslt && \
	rm -rf build-wllvm && mkdir -p build-wllvm && cd build-wllvm && \
	cp -r ../include . && \
	export LLVM_COMPILER=clang && \
	CC=wllvm CXX=wllvm++ ../configure \
		--disable-shared --without-c14n --without-push --without-python \
		--without-reader --without-regexps --without-sax1 --without-schemas \
		--without-schematron --without-valid --without-writer --without-zlib \
		--without-lzma && \
	make -j$(nproc) && cd ../../libxslt && \
	rm -rf build-wllvm && mkdir -p build-wllvm && cd build-wllvm && \
	export LLVM_COMPILER=clang && \
	CC=wllvm CXX=wllvm++ ../configure \
		--with-libxml-src=$(WORKDIR)/subjects/libxml2-xslt/build-wllvm \
		--disable-shared --without-python --without-crypto --without-debug \
		--without-debugger --without-profiler && \
	make -j$(nproc) && cd tests/fuzz && \
	make fuzz.o xpath.o && \
	wllvm++ -g -fsanitize=fuzzer xpath.o fuzz.o -o ../../xpath \
		../../libexslt/.libs/libexslt.a ../../libxslt/.libs/libxslt.a \
		$(WORKDIR)/subjects/libxml2-xslt/build-wllvm/.libs/libxml2.a && \
	extract-bc ../../xpath && \
	opt-15 -passes=dot-callgraph -disable-output < ../../xpath.bc && \
	mv '<stdin>.callgraph.dot' ../../xpath.dot

# libxslt with Profiling
libxslt-profiling: libxslt
	cd libxml2-xslt && \
	rm -rf build-profiling && mkdir -p build-profiling && cd build-profiling && \
	rm -rf /tmp/xpath && mkdir -p /tmp/xpath && \
	cp -r ../include . && \
	HF_BINARY=xpath HORSEFUZZ_CG_PROFILING=1 CC=afl-clang-fast CXX=afl-clang-fast++ ../configure \
		--disable-shared --without-c14n --without-push --without-python \
		--without-reader --without-regexps --without-sax1 --without-schemas \
		--without-schematron --without-valid --without-writer --without-zlib \
		--without-lzma && \
	HF_BINARY=xpath HORSEFUZZ_CG_PROFILING=1 make -j$(nproc) && cd ../../libxslt && \
	rm -rf build-profiling && mkdir -p build-profiling && cd build-profiling && \
	HF_BINARY=xpath HORSEFUZZ_CG_PROFILING=1 CC=afl-clang-fast CXX=afl-clang-fast++ ../configure \
		--with-libxml-src=$(WORKDIR)/subjects/libxml2-xslt/build-profiling \
		--disable-shared --without-python --without-crypto --without-debug \
		--without-debugger --without-profiler && \
	HF_BINARY=xpath HORSEFUZZ_CG_PROFILING=1 make -j$(nproc) && cd tests/fuzz && \
	HF_BINARY=xpath HORSEFUZZ_CG_PROFILING=1 make fuzz.o xpath.o && \
	HF_BINARY=xpath HORSEFUZZ_CG_PROFILING=1 afl-clang-fast++ xpath.o fuzz.o -o ../../xpath \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		../../libexslt/.libs/libexslt.a ../../libxslt/.libs/libxslt.a \
		$(WORKDIR)/subjects/libxml2-xslt/build-profiling/.libs/libxml2.a && \
	cp -r /tmp/xpath ../../xpath-profiling-logs

# libxslt with Coverage
.PHONY: libxml2-xslt-source
libxml2-xslt-source:
	@if [ ! -d libxml2-xslt/.git ]; then \
		echo "Cloning the libxml2 source required by libxslt"; \
		rm -rf libxml2-xslt; \
		git clone https://github.com/GNOME/libxml2.git libxml2-xslt; \
		cd libxml2-xslt; \
		git checkout 3b38f19; \
		sed -i 's/1\.16\.3/1.16.1/g' configure.ac; \
		autoreconf -if -Wall; \
	fi

libxslt-cov: libxslt libxml2-xslt-source
	cd libxml2-xslt && \
	rm -rf build-cov && mkdir -p build-cov && cd build-cov && \
	cp -r ../include . && \
	CC=clang CXX=clang++ CFLAGS="-g -fprofile-arcs -ftest-coverage" \
		CXXFLAGS="-g -fprofile-arcs -ftest-coverage" ../configure \
		--disable-shared --without-c14n --without-push --without-python \
		--without-reader --without-regexps --without-sax1 --without-schemas \
		--without-schematron --without-valid --without-writer --without-zlib \
		--without-lzma && \
	make -j$(nproc) && cd ../../libxslt && \
	rm -rf build-cov && mkdir -p build-cov && cd build-cov && \
	CC=clang CXX=clang++ CFLAGS="-g -fprofile-arcs -ftest-coverage" \
		CXXFLAGS="-g -fprofile-arcs -ftest-coverage" ../configure \
		--with-libxml-src=$(WORKDIR)/subjects/libxml2-xslt/build-cov \
		--disable-shared --without-python --without-crypto --without-debug \
		--without-debugger --without-profiler && \
	make -j$(nproc) && cd tests/fuzz && \
	make fuzz.o xpath.o && \
	clang++ -g -fsanitize=fuzzer -fprofile-arcs -ftest-coverage xpath.o fuzz.o -o ../../xpath \
		../../libexslt/.libs/libexslt.a ../../libxslt/.libs/libxslt.a \
		$(WORKDIR)/subjects/libxml2-xslt/build-cov/.libs/libxml2.a


libxslt-cmplog: libxslt
	cd libxml2-xslt && \
	export AFL_LLVM_CMPLOG=1 && \
	rm -rf build-cmplog && mkdir -p build-cmplog && cd build-cmplog && \
	cp -r ../include . && \
	CC=afl-clang-fast CXX=afl-clang-fast++ ../configure \
		--disable-shared --without-c14n --without-push --without-python \
		--without-reader --without-regexps --without-sax1 --without-schemas \
		--without-schematron --without-valid --without-writer --without-zlib \
		--without-lzma && \
	make -j$(nproc) && cd ../../libxslt && \
	rm -rf build-cmplog && mkdir -p build-cmplog && cd build-cmplog && \
	CC=afl-clang-fast CXX=afl-clang-fast++ ../configure \
		--with-libxml-src=$(WORKDIR)/subjects/libxml2-xslt/build-cmplog \
		--disable-shared --without-python --without-crypto --without-debug \
		--without-debugger --without-profiler && \
	make -j$(nproc) && cd tests/fuzz && \
	make fuzz.o xpath.o && \
	afl-clang-fast++ -std=c++11 xpath.o fuzz.o -o ../../xpath \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		../../libexslt/.libs/libexslt.a ../../libxslt/.libs/libxslt.a \
		$(WORKDIR)/subjects/libxml2-xslt/build-cmplog/.libs/libxml2.a && \
	unset AFL_LLVM_CMPLOG

# aggregate targets
libxslt-all: libxslt-afl libxslt-wllvm libxslt-profiling libxslt-cov
libxslt-clean-all:
	rm -rf libxml2-xslt libxslt libxslt/build-* /tmp/xpath

# HarfBuzz Base Setup
harfbuzz:
	git clone https://github.com/harfbuzz/harfbuzz.git harfbuzz
	cd harfbuzz && \
	git checkout a1d9bfe && \
	mkdir -p all-fonts && \
	for d in \
		test/shape/data/in-house/fonts \
		test/shape/data/aots/fonts \
		test/shape/data/text-rendering-tests/fonts \
		test/api/fonts \
		test/fuzzing/fonts \
		perf/fonts; do \
		mkdir -p all-fonts; \
		cp -r $$d/* all-fonts/; \
	done

# HarfBuzz with AFL++ Instrumentation
harfbuzz-afl: harfbuzz
	cd harfbuzz && \
	mkdir -p build-afl && cd build-afl && \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	CFLAGS="-fno-sanitize=vptr -DHB_NO_VISIBILITY" \
	CXXFLAGS="-fno-sanitize=vptr -DHB_NO_VISIBILITY" \
	meson .. --default-library=static --wrap-mode=nodownload \
		-Dexperimental_api=true \
		-Dfuzzer_ldflags="${AFLPLUSPLUS}/utils/aflpp_driver/libAFLDriver.a" && \
	ninja -v -j$$(nproc) test/fuzzing/hb-shape-fuzzer && \
	mv test/fuzzing/hb-shape-fuzzer .

harfbuzz-afl-asan: harfbuzz
	cd harfbuzz && \
	mkdir -p build-afl-asan && cd build-afl-asan && \
	export AFL_USE_ASAN=1 && \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	CFLAGS="-fno-sanitize=vptr -DHB_NO_VISIBILITY" \
	CXXFLAGS="-fno-sanitize=vptr -DHB_NO_VISIBILITY" \
	meson .. --default-library=static --wrap-mode=nodownload \
		-Dexperimental_api=true \
		-Dfuzzer_ldflags="${AFLPLUSPLUS}/utils/aflpp_driver/libAFLDriver.a" && \
	ninja -v -j$$(nproc) test/fuzzing/hb-shape-fuzzer && \
	mv test/fuzzing/hb-shape-fuzzer .

# HarfBuzz with WLLVM (Whole Program LLVM)
harfbuzz-wllvm: harfbuzz
	cd harfbuzz && \
	mkdir -p build-wllvm && cd build-wllvm && \
	export LLVM_COMPILER=clang && \
	CC=wllvm CXX=wllvm++ \
	CFLAGS="-fno-sanitize=vptr -DHB_NO_VISIBILITY" \
	CXXFLAGS="-fno-sanitize=vptr -DHB_NO_VISIBILITY" \
	meson .. --default-library=static --wrap-mode=nodownload \
		-Dexperimental_api=true \
		-Dfuzzer_ldflags="-fsanitize=fuzzer" && \
	ninja -v -j$$(nproc) test/fuzzing/hb-shape-fuzzer && \
	extract-bc test/fuzzing/hb-shape-fuzzer && \
	opt-15 -passes=dot-callgraph -disable-output < test/fuzzing/hb-shape-fuzzer.bc && \
	mv '<stdin>.callgraph.dot' hb-shape-fuzzer.dot

# HarfBuzz with Profiling
harfbuzz-profiling: harfbuzz
	cd harfbuzz && \
	mkdir -p build-profiling && cd build-profiling && \
	HF_BINARY=hb-shape-fuzzer HORSEFUZZ_CG_PROFILING=1 \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	CFLAGS="-fno-sanitize=vptr -DHB_NO_VISIBILITY" \
	CXXFLAGS="-fno-sanitize=vptr -DHB_NO_VISIBILITY" \
	meson .. --default-library=static --wrap-mode=nodownload \
		-Dexperimental_api=true \
		-Dfuzzer_ldflags="${AFLPLUSPLUS}/utils/aflpp_driver/libAFLDriver.a" && \
	HF_BINARY=hb-shape-fuzzer HORSEFUZZ_CG_PROFILING=1 ninja -v -j$$(nproc) test/fuzzing/hb-shape-fuzzer && \
	mv test/fuzzing/hb-shape-fuzzer . && \
	cp -r /tmp/hb-shape-fuzzer hb-shape-fuzzer-profiling-logs

# HarfBuzz with Coverage
harfbuzz-cov: harfbuzz
	cd harfbuzz && \
	mkdir -p build-cov && cd build-cov && \
	CC=clang CXX=clang++ \
	CFLAGS="-g -fprofile-arcs -ftest-coverage -fno-sanitize=vptr -DHB_NO_VISIBILITY" \
	CXXFLAGS="-g -fprofile-arcs -ftest-coverage -fno-sanitize=vptr -DHB_NO_VISIBILITY" \
	meson .. --default-library=static --wrap-mode=nodownload \
		-Dexperimental_api=true \
		-Dfuzzer_ldflags="-fsanitize=fuzzer" && \
	ninja -v -j$$(nproc) test/fuzzing/hb-shape-fuzzer && \
	mv test/fuzzing/hb-shape-fuzzer .

# HarfBuzz with AFL++ Instrumentation
harfbuzz-mufuzz: harfbuzz mufuzz-check
	cd harfbuzz && \
	mkdir -p build-afl-mufuzz && cd build-afl-mufuzz && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(MUFUZZ_AFL_CLANGXX) -std=c++11 -c $(MUFUZZ_DRIVER) -o mufuzz_driver.o && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) CC=$(MUFUZZ_AFL_CLANG) CXX=$(MUFUZZ_AFL_CLANGXX) \
	CFLAGS="$(HARFBUZZ_FUZZ_CFLAGS)" \
	CXXFLAGS="$(HARFBUZZ_FUZZ_CXXFLAGS)" \
	meson .. --default-library=static --wrap-mode=nodownload \
		-Dexperimental_api=true \
		-Dfuzzer_ldflags="$$(pwd)/mufuzz_driver.o" && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) ninja -v -j$$(nproc) test/fuzzing/hb-shape-fuzzer && \
	mv test/fuzzing/hb-shape-fuzzer .

harfbuzz-cmplog: harfbuzz
	export AFL_LLVM_CMPLOG=1 && \
	cd harfbuzz && \
	mkdir -p build-cmplog && cd build-cmplog && \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	CFLAGS="-fno-sanitize=vptr -DHB_NO_VISIBILITY" \
	CXXFLAGS="-fno-sanitize=vptr -DHB_NO_VISIBILITY" \
	meson .. --default-library=static --wrap-mode=nodownload \
		-Dexperimental_api=true \
		-Dfuzzer_ldflags="${AFLPLUSPLUS}/utils/aflpp_driver/libAFLDriver.a" && \
	ninja -v -j$$(nproc) test/fuzzing/hb-shape-fuzzer && \
	mv test/fuzzing/hb-shape-fuzzer . && \
	unset AFL_LLVM_CMPLOG

# aggregate targets
harfbuzz-all: harfbuzz-afl harfbuzz-wllvm harfbuzz-profiling harfbuzz-cov
harfbuzz-clean-all:
	rm -rf harfbuzz harfbuzz/build-* /tmp/hb-shape-fuzzer

# libxml2 Base Setup
libxml2:
	git clone https://gitlab.gnome.org/GNOME/libxml2.git && \
	cd libxml2 && git checkout 66453240c94b5cbd3e9ae9b32016fdafb13cdf18 && \
	if [ "$(IS_KRAKEN)" = "1" ]; then sed -i 's/1\.16\.3/1.16.1/g' configure.ac; fi && \
	autoreconf -f -i

libxml2-afl: libxml2
	cd libxml2 && \
	mkdir -p build-afl && cd build-afl && \
	CC=afl-clang-fast CXX=afl-clang-fast++ ../configure --disable-shared --without-debug --without-http --without-python --with-zlib --with-lzma && \
	make -j$(nproc) && \
	afl-clang-fast -I../include -I../build-afl/include -c ../fuzz/fuzz.c -o ../fuzz/fuzz.o && \
	afl-clang-fast -I../include -I../build-afl/include -c ../fuzz/xml.c -o ../fuzz/xml.o && \
	afl-clang-fast \
		../fuzz/xml.o ../fuzz/fuzz.o \
		-o fuzz-xml \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		.libs/libxml2.a \
		-Wl,-Bstatic -lz -llzma -Wl,-Bdynamic -lm && \
	\
	# Build genSeed with proper include paths \
	afl-clang-fast -I../include -I. -I../build-afl/include -c ../fuzz/genSeed.c -o ../fuzz/genSeed.o && \
	afl-clang-fast++ ../fuzz/genSeed.o ../fuzz/fuzz.o \
	    -o ../fuzz/genSeed \
	    -I../include -I. -I../build-afl/include \
	    -L. -L../build-afl/.libs -lxml2 -lz -llzma -lm && \
	\
	mkdir -p seed/xml && \
	../fuzz/genSeed xml \
		'../test/*' \
		'../test/errors/*.xml' \
		'../test/errors10/*.xml' \
		'../test/namespaces/*' \
		'../test/recurse/*.xml' \
		'../test/SVG/*.xml' \
		'../test/valid/*.xml' \
		'../test/VC/*' \
		'../test/VCM/*' \
		'../test/XInclude/docs/*' \
		'../test/XInclude/without-reader/*' \
		'../test/xmlid/*' && \
	touch seed/xml.stamp && \
	cp ../fuzz/xml.dict seed/

libxml2-cmplog: libxml2
	cd libxml2 && \
	mkdir -p build-cmplog && cd build-cmplog && \
	export AFL_LLVM_CMPLOG=1 && \
	CC=afl-clang-fast CXX=afl-clang-fast++ ../configure --disable-shared --without-debug --without-http --without-python --with-zlib --with-lzma && \
	make -j$(nproc) && \
	afl-clang-fast -I../include -I../build-cmplog/include -c ../fuzz/fuzz.c -o ../fuzz/fuzz.o && \
	afl-clang-fast -I../include -I../build-cmplog/include -c ../fuzz/xml.c -o ../fuzz/xml.o && \
	afl-clang-fast \
		../fuzz/xml.o ../fuzz/fuzz.o \
		-o fuzz-xml-cmplog \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		.libs/libxml2.a \
		-Wl,-Bstatic -lz -llzma -Wl,-Bdynamic -lm && \
	unset AFL_LLVM_CMPLOG

# libxml2 WLLVM with fuzz/xml.c as harness
libxml2-wllvm: libxml2
	cd libxml2 && \
	mkdir -p build-wllvm && cd build-wllvm && \
	export LLVM_COMPILER=clang && \
	CC=wllvm CXX=wllvm++ ../configure --disable-shared --without-debug --without-http --without-python --with-zlib --with-lzma && \
	make -j$(nproc) && \
	wllvm -I../include -I../build-wllvm/include -c ../fuzz/fuzz.c -o ../fuzz/fuzz.o && \
	wllvm -I../include -I../build-wllvm/include -c ../fuzz/xml.c -o ../fuzz/xml.o && \
	wllvm \
		../fuzz/xml.o ../fuzz/fuzz.o \
		-o fuzz-xml-wllvm \
		-g -fsanitize=fuzzer \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		.libs/libxml2.a \
		-Wl,-Bstatic -lz -llzma -Wl,-Bdynamic -lm && \
	extract-bc fuzz-xml-wllvm && \
	opt-15 -passes=dot-callgraph -disable-output < fuzz-xml-wllvm.bc && \
	mv '<stdin>.callgraph.dot' fuzz-xml-wllvm.dot

# libxml2 Profiling with fuzz/xml.c as harness
libxml2-profiling: libxml2
	cd libxml2 && \
	mkdir -p build-profiling && cd build-profiling && \
	rm -rf /tmp/fuzz-xml && mkdir -p /tmp/fuzz-xml && \
	HF_BINARY=fuzz-xml HORSEFUZZ_CG_PROFILING=1 CC=afl-clang-fast CXX=afl-clang-fast++ \
		../configure --disable-shared --without-debug --without-http --without-python --with-zlib --with-lzma && \
	HF_BINARY=fuzz-xml HORSEFUZZ_CG_PROFILING=1 make -j$(nproc) && \
	HF_BINARY=fuzz-xml HORSEFUZZ_CG_PROFILING=1 afl-clang-fast -I../include -I../build-afl/include -c ../fuzz/fuzz.c -o ../fuzz/fuzz.o && \
	HF_BINARY=fuzz-xml HORSEFUZZ_CG_PROFILING=1 afl-clang-fast -I../include -I../build-afl/include -c ../fuzz/xml.c -o ../fuzz/xml.o && \
	HF_BINARY=fuzz-xml HORSEFUZZ_CG_PROFILING=1 afl-clang-fast \
		../fuzz/xml.o ../fuzz/fuzz.o \
		-o fuzz-xml \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		.libs/libxml2.a \
		-Wl,-Bstatic -lz -llzma -Wl,-Bdynamic -lm && \
	cp -r /tmp/fuzz-xml fuzz-xml-profiling-logs

# libxml2 Coverage with fuzz/xml.c as harness
libxml2-cov: libxml2
	cd libxml2 && \
	mkdir -p build-cov && cd build-cov && \
	export LLVM_COMPILER=clang && \
	CC=clang CXX=clang++ CFLAGS="-g -fprofile-arcs -ftest-coverage" CXXFLAGS="-g -fprofile-arcs -ftest-coverage" \
		../configure --disable-shared --without-debug --without-http --without-python --with-zlib --with-lzma && \
	make -j$(nproc) && \
	clang -I../include -I../build-cov/include -c ../fuzz/fuzz.c -o ../fuzz/fuzz.o -g -fprofile-arcs -ftest-coverage && \
	clang -I../include -I../build-cov/include -c ../fuzz/xml.c -o ../fuzz/xml.o -g -fprofile-arcs -ftest-coverage && \
	clang \
		-g -fsanitize=fuzzer -fprofile-arcs -ftest-coverage \
		../fuzz/xml.o ../fuzz/fuzz.o \
		-o fuzz-xml \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		.libs/libxml2.a \
		-Wl,-Bstatic -lz -llzma -Wl,-Bdynamic -lm

libxml2-all: libxml2 libxml2-afl libxml2-wllvm libxml2-profiling libxml2-cov

libxml2-clean-all:
	rm -rf libxml2 libxml2/build-* libxml2-2.13.6.tar.xz /tmp/fuzz-xml


# OpenSSL Base Setup
openssl:
	@echo "=== Downloading and preparing OpenSSL ==="
	git clone --no-checkout https://github.com/openssl/openssl.git openssl
	cd openssl && \
		git checkout bf41baa2bf3215625d44f7c0dc438ab1b2e3a3d0 && \
		mkdir -p seed_corpus && \
		rm -rf magma_corpus && \
		git clone --depth 1 --branch $(MAGMA_REF) --filter=blob:none $(MAGMA_REPO) magma_corpus && \
		cd magma_corpus && \
		git sparse-checkout init --cone && \
		git sparse-checkout set targets/openssl/corpus/x509 targets/openssl/src && \
		git checkout && \
		cp targets/openssl/corpus/x509/* ../seed_corpus/ && \
		cp targets/openssl/src/abilist.txt .. && \
		cd .. && rm -rf magma_corpus && \
		cp fuzz/oids.txt x509.dict

# OpenSSL with AFL++ Instrumentation (x509 only)
openssl-afl: openssl
	@echo "=== Building OpenSSL with AFL instrumentation (x509) ==="
	cd openssl && \
		rm -rf build-afl && mkdir -p build-afl && \
		CC=afl-clang-fast CXX=afl-clang-fast++ \
		./config --debug enable-fuzz-libfuzzer enable-fuzz-afl disable-tests -DPEDANTIC \
			-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION no-shared no-module \
			enable-tls1_3 enable-rc5 enable-md2 enable-ec_nistp_64_gcc_128 \
			enable-nextprotoneg enable-weak-ssl-ciphers \
			-fno-sanitize=alignment --prefix=$$(pwd)/build-afl && \
		make clean && \
		make -j$$(nproc) build_libs && \
		make -j$$(nproc) LDCMD="afl-clang-fast++ $(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a" \
			fuzz/x509 && \
		cp fuzz/x509 build-afl/x509

# OpenSSL with AFL++ CMPLOG
openssl-cmplog: openssl
	@echo "=== Building OpenSSL with AFL-CmpLog instrumentation (x509) ==="
	cd openssl && \
		rm -rf build-cmplog && mkdir -p build-cmplog && \
		export AFL_LLVM_CMPLOG=1 && \
		CC=afl-clang-fast CXX=afl-clang-fast++ \
		./config --debug enable-fuzz-libfuzzer enable-fuzz-afl disable-tests -DPEDANTIC \
			-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION no-shared no-module \
			enable-tls1_3 enable-rc5 enable-md2 enable-ec_nistp_64_gcc_128 \
			enable-nextprotoneg enable-weak-ssl-ciphers \
			-fno-sanitize=alignment --prefix=$$(pwd)/build-cmplog && \
		make clean && \
		make -j$$(nproc) build_libs && \
		make -j$$(nproc) LDCMD="afl-clang-fast++ $(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a" \
			fuzz/x509 && \
		cp fuzz/x509 build-cmplog/x509 && \
		unset AFL_LLVM_CMPLOG

# OpenSSL with Whole-Program LLVM (wllvm)
openssl-wllvm: openssl
	@echo "=== Building OpenSSL with wllvm (x509) ==="
	cd openssl && \
		rm -rf build-wllvm && mkdir -p build-wllvm && \
		export LLVM_COMPILER=clang && \
		CC=wllvm CXX=wllvm++ \
		./config --debug enable-fuzz-libfuzzer disable-tests -DPEDANTIC \
			-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION no-shared no-module \
			enable-tls1_3 enable-rc5 enable-md2 enable-ec_nistp_64_gcc_128 \
			enable-nextprotoneg enable-weak-ssl-ciphers \
			-fno-sanitize=alignment -g -fsanitize=fuzzer --prefix=$$(pwd)/build-wllvm && \
		make clean && \
		make -j$$(nproc) build_libs && \
		make -j$$(nproc) LDCMD="wllvm++ -g -fsanitize=fuzzer" \
			fuzz/x509 && \
		cp fuzz/x509 build-wllvm/x509 && \
		cd build-wllvm && \
		extract-bc x509 && \
		opt-15 -passes=dot-callgraph -disable-output x509.bc && \
		mv x509.bc.callgraph.dot x509.dot

# OpenSSL with Profiling
openssl-profiling: openssl
	@echo "=== Building OpenSSL with profiling (x509) ==="
	cd openssl && \
		rm -rf build-profiling && mkdir -p build-profiling && \
		rm -rf /tmp/x509 && mkdir -p /tmp/x509 && \
		HF_BINARY=x509 HORSEFUZZ_CG_PROFILING=1 CC=afl-clang-fast CXX=afl-clang-fast++ \
		./config --debug enable-fuzz-libfuzzer enable-fuzz-afl disable-tests -DPEDANTIC \
			-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION no-shared no-module \
			enable-tls1_3 enable-rc5 enable-md2 enable-ec_nistp_64_gcc_128 \
			enable-nextprotoneg enable-weak-ssl-ciphers \
			-fno-sanitize=alignment --prefix=$$(pwd)/build-profiling && \
		make clean && \
		HF_BINARY=x509 HORSEFUZZ_CG_PROFILING=1 make -j$$(nproc) build_libs && \
		HF_BINARY=x509 HORSEFUZZ_CG_PROFILING=1 make -j$$(nproc) \
			LDCMD="afl-clang-fast++ $(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a" \
			fuzz/x509 && \
		cp fuzz/x509 build-profiling/x509 && \
		cp -r /tmp/x509 build-profiling/x509-logs

# OpenSSL with Coverage
openssl-cov: openssl
	@echo "=== Building OpenSSL with coverage (x509) ==="
	cd openssl && \
		rm -rf build-cov && mkdir -p build-cov && \
		CC=clang CXX=clang++ \
		CFLAGS="-g -fprofile-arcs -ftest-coverage" CXXFLAGS="-g -fprofile-arcs -ftest-coverage" \
		./config --debug enable-fuzz-libfuzzer disable-tests -DPEDANTIC \
			-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION no-shared no-module \
			enable-tls1_3 enable-rc5 enable-md2 enable-ec_nistp_64_gcc_128 \
			enable-nextprotoneg enable-weak-ssl-ciphers \
			-fno-sanitize=alignment --prefix=$$(pwd)/build-cov && \
		make clean && \
		make -j$$(nproc) build_libs && \
		make -j$$(nproc) LDCMD="clang++ -g -fsanitize=fuzzer -fprofile-arcs -ftest-coverage" \
			fuzz/x509 && \
		cp fuzz/x509 build-cov/x509

openssl-all: openssl-afl openssl-cmplog openssl-wllvm openssl-profiling openssl-cov

openssl-clean-all:
	rm -rf openssl /tmp/x509

# libpcap Base Setup
libpcap:
	git clone https://github.com/the-tcpdump-group/libpcap.git libpcap
	cd libpcap && \
	git checkout bbcbc91

tcpdump:
	git clone https://github.com/the-tcpdump-group/tcpdump.git tcpdump
	cd tcpdump && git checkout $(TCPDUMP_REF)

libpcap-prepare: libpcap tcpdump
	# Create corpus directory
	cd libpcap && mkdir -p corpus/fuzz_both

	# cp all test cases from tcpdump/tests/
	cd tcpdump && \
	cp -r tests/* ../libpcap/corpus/fuzz_both/

	# Copy all .pcap test cases from tcpdump/tests/
	# cd tcpdump && \
	# find tests/ -type f -name "*.pcap" -exec cp {} ../libpcap/corpus/fuzz_both/ \;

	# Copy BPF filter expression files (full content)
	# cd libpcap/testprogs/BPF && \
	# find . -type f -name "*.txt" -exec cp {} ../../corpus/fuzz_both/ \;

	# Confirm corpus preparation
	echo "Corpus prepared in libpcap/corpus/fuzz_both"

libpcap-afl: libpcap-prepare
	cd libpcap && \
	mkdir -p build-afl && cd build-afl && \
	CC=afl-clang-fast CXX=afl-clang-fast++ cmake .. && \
	make clean all -j$(nproc) && \
	afl-clang-fast -I.. -c ../testprogs/fuzz/fuzz_both.c -o fuzz_both.o && \
	afl-clang-fast++ fuzz_both.o -o libpcap_fuzz_both libpcap.a $(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a -ldbus-1

libpcap-mufuzz: libpcap-prepare
	cd libpcap && \
	mkdir -p build-mufuzz && cd build-mufuzz && \
	export AFL_LLVM_INSTRUMENT=CLASSIC AFL_OLD_FORKSERVER=1 && \
	CC=afl-clang-fast CXX=afl-clang-fast++ cmake .. && \
	make clean all -j$(nproc) && \
	afl-clang-fast -I.. -c ../testprogs/fuzz/fuzz_both.c -o fuzz_both.o && \
	afl-clang-fast++ fuzz_both.o -o libpcap_fuzz_both libpcap.a $(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a -ldbus-1

# LibPCAP WLLVM (Whole Program LLVM)
libpcap-wllvm: libpcap
	cd libpcap && \
	mkdir -p build-wllvm && cd build-wllvm && \
	export LLVM_COMPILER=clang && \
	CC=wllvm CXX=wllvm++ cmake .. && \
	make clean all -j$(nproc) && \
	wllvm -g -fsanitize=fuzzer -I.. -c ../testprogs/fuzz/fuzz_both.c -o fuzz_both.o && \
	wllvm++ -g -fsanitize=fuzzer fuzz_both.o -o libpcap_fuzz_both libpcap.a $(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a -ldbus-1 && \
	extract-bc libpcap_fuzz_both && \
	opt-15 -passes=dot-callgraph -disable-output < libpcap_fuzz_both.bc && \
	mv '<stdin>.callgraph.dot' libpcap_fuzz_both.dot

# LibPCAP Profiling
libpcap-profiling: libpcap
	cd libpcap && \
	mkdir -p build-profiling && cd build-profiling && \
	rm -rf /tmp/libpcap_fuzz_both && mkdir /tmp/libpcap_fuzz_both && \
	HF_BINARY=libpcap_fuzz_both HORSEFUZZ_CG_PROFILING=1 CC=afl-clang-fast CXX=afl-clang-fast++ cmake .. && \
	HF_BINARY=libpcap_fuzz_both HORSEFUZZ_CG_PROFILING=1 make clean all -j$(nproc) && \
	HF_BINARY=libpcap_fuzz_both HORSEFUZZ_CG_PROFILING=1 afl-clang-fast -I.. -c ../testprogs/fuzz/fuzz_both.c -o fuzz_both.o && \
	HF_BINARY=libpcap_fuzz_both HORSEFUZZ_CG_PROFILING=1 afl-clang-fast++ fuzz_both.o -o libpcap_fuzz_both libpcap.a $(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a -ldbus-1 && \
	cp -r /tmp/libpcap_fuzz_both libpcap_fuzz_both-profiling-logs

# LibPCAP Coverage
libpcap-cov: libpcap
	cd libpcap && \
	mkdir -p build-cov && cd build-cov && \
	export LLVM_COMPILER=clang && \
	CC=clang CXX=clang++ CFLAGS="-g -fprofile-arcs -ftest-coverage" CXXFLAGS="-g -fprofile-arcs -ftest-coverage" cmake .. && \
	make clean all -j$(nproc) && \
	clang -g -I.. -fsanitize=fuzzer -fprofile-arcs -ftest-coverage -c ../testprogs/fuzz/fuzz_both.c -o fuzz_both.o && \
	clang++ -g -fsanitize=fuzzer -fprofile-arcs -ftest-coverage fuzz_both.o -o libpcap_fuzz_both libpcap.a

libpcap-cmplog: libpcap-prepare
	cd libpcap && \
	mkdir -p build-cmplog && cd build-cmplog && \
	export AFL_LLVM_CMPLOG=1 && \
	CC=afl-clang-fast CXX=afl-clang-fast++ cmake .. && \
	make clean all -j$(nproc) && \
	afl-clang-fast -I.. -c ../testprogs/fuzz/fuzz_both.c -o fuzz_both.o && \
	afl-clang-fast++ fuzz_both.o -o libpcap_fuzz_both libpcap.a $(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a -ldbus-1 && \
	unset AFL_LLVM_CMPLOG

# Aggregate Targets
libpcap-all: libpcap-afl libpcap-wllvm libpcap-profiling libpcap-cov

# Clean all builds
libpcap-clean-all:
	rm -rf libpcap libpcap/build-* /tmp/libpcap_fuzz_both

libaom:
	@echo "=== Cloning and building libaom ==="
# git clone --depth 1 https://aomedia.googlesource.com/aom libaom &&
	git clone https://aomedia.googlesource.com/aom libaom && \
	cd libaom && \
	git checkout 3b624af45b86646a20b11a9ff803aeae588cdee6 && \
	cd .. && \
	mkdir -p libaom/people.xiph.org && touch libaom/people.xiph.org/dummy.ogg && \
	curl -L 'https://storage.googleapis.com/aom-test-data/fuzzer/dec_fuzzer_seed_corpus.zip' -o libaom/dec_fuzzer_seed_corpus.zip
	@echo "=== Extracting seed corpus into libaom ==="
	if command -v unzip >/dev/null 2>&1; then unzip -o libaom/dec_fuzzer_seed_corpus.zip -d libaom/av1_dec_fuzzer_seed_corpus; else python3 -m zipfile -e libaom/dec_fuzzer_seed_corpus.zip libaom/av1_dec_fuzzer_seed_corpus; fi
	@echo "=== Removing all subdirectories from seed corpus ==="
	find libaom/av1_dec_fuzzer_seed_corpus/testdata/ -mindepth 1 -type d -exec rm -rf {} +
	@echo "=== Copying dictionary into libaom ==="
	cp libaom/examples/av1_dec_fuzzer.dict libaom/av1_dec_fuzzer.dict

libaom-afl: libaom
	@echo "=== Building libaom av1_dec_fuzzer with AFL instrumentation ==="
	cd libaom && \
	rm -rf build-afl && mkdir -p build-afl && cd build-afl && \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	cmake .. -DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_C_FLAGS_RELEASE='-O3 -g' \
		-DCMAKE_CXX_FLAGS_RELEASE='-O3 -g' \
		-DCONFIG_PIC=1 \
		-DCONFIG_LOWBITDEPTH=1 \
		-DCONFIG_AV1_ENCODER=0 \
		-DENABLE_EXAMPLES=0 \
		-DENABLE_DOCS=0 \
		-DENABLE_TESTS=0 \
		-DCONFIG_SIZE_LIMIT=1 \
		-DDECODE_HEIGHT_LIMIT=12288 \
		-DDECODE_WIDTH_LIMIT=12288 \
		-DAOM_EXTRA_C_FLAGS="-DAOM_MAX_ALLOCABLE_MEMORY=1073741824 -DDO_RANGE_CHECK_CLAMP=1" \
		-DENABLE_TOOLS=0 \
		-DAOM_EXTRA_CXX_FLAGS="-DAOM_MAX_ALLOCABLE_MEMORY=1073741824 -DDO_RANGE_CHECK_CLAMP=1" && \
	make -j$$(nproc) && \
	afl-clang-fast++ -std=c++11 \
		-I../ \
		-I. \
		-Ibuild-afl \
		-Wl,--start-group \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		../examples/av1_dec_fuzzer.cc \
		-o av1_dec_fuzzer \
		libaom.a -Wl,--end-group

libaom-wllvm: libaom
	@echo "=== Building libaom av1_dec_fuzzer with Whole Program LLVM ==="
	cd libaom && \
	rm -rf build-wllvm && mkdir -p build-wllvm && cd build-wllvm && \
	export LLVM_COMPILER=clang && \
	CC=wllvm CXX=wllvm++ \
	cmake .. -DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_C_FLAGS_RELEASE='-O3 -g0' \
		-DCMAKE_CXX_FLAGS_RELEASE='-O3 -g0' \
		-DCONFIG_PIC=1 \
		-DCONFIG_LOWBITDEPTH=1 \
		-DCONFIG_AV1_ENCODER=0 \
		-DENABLE_EXAMPLES=0 \
		-DENABLE_DOCS=0 \
		-DENABLE_TESTS=0 \
		-DCONFIG_SIZE_LIMIT=1 \
		-DDECODE_HEIGHT_LIMIT=12288 \
		-DDECODE_WIDTH_LIMIT=12288 \
		-DAOM_EXTRA_C_FLAGS="-DAOM_MAX_ALLOCABLE_MEMORY=1073741824 -DDO_RANGE_CHECK_CLAMP=1" \
		-DENABLE_TOOLS=0 \
		-DAOM_EXTRA_CXX_FLAGS="-DAOM_MAX_ALLOCABLE_MEMORY=1073741824 -DDO_RANGE_CHECK_CLAMP=1" && \
	make -j$$(nproc) && \
	wllvm++ -g -fsanitize=fuzzer -std=c++11 \
		-I../ \
		-I. \
		-Ibuild-wllvm \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		../examples/av1_dec_fuzzer.cc \
		-o av1_dec_fuzzer \
		libaom.a && \
	extract-bc av1_dec_fuzzer && \
	opt-15 -passes=dot-callgraph -disable-output < av1_dec_fuzzer.bc && \
	mv '<stdin>.callgraph.dot' av1_dec_fuzzer.dot

libaom-profiling: libaom
	@echo "=== Building libaom av1_dec_fuzzer with profiling instrumentation ==="
	cd libaom && \
	rm -rf build-profiling && mkdir -p build-profiling && cd build-profiling && \
	HF_BINARY=av1_dec_fuzzer HORSEFUZZ_CG_PROFILING=1 \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	cmake .. -DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_C_FLAGS_RELEASE='-O3 -g' \
		-DCMAKE_CXX_FLAGS_RELEASE='-O3 -g' \
		-DCONFIG_PIC=1 \
		-DCONFIG_LOWBITDEPTH=1 \
		-DCONFIG_AV1_ENCODER=0 \
		-DENABLE_EXAMPLES=0 \
		-DENABLE_DOCS=0 \
		-DENABLE_TESTS=0 \
		-DCONFIG_SIZE_LIMIT=1 \
		-DDECODE_HEIGHT_LIMIT=12288 \
		-DDECODE_WIDTH_LIMIT=12288 \
		-DAOM_EXTRA_C_FLAGS="-DAOM_MAX_ALLOCABLE_MEMORY=1073741824 -DDO_RANGE_CHECK_CLAMP=1" \
		-DENABLE_TOOLS=0 \
		-DAOM_EXTRA_CXX_FLAGS="-DAOM_MAX_ALLOCABLE_MEMORY=1073741824 -DDO_RANGE_CHECK_CLAMP=1" && \
	HF_BINARY=av1_dec_fuzzer HORSEFUZZ_CG_PROFILING=1 \
	make -j$$(nproc) && \
	HF_BINARY=av1_dec_fuzzer HORSEFUZZ_CG_PROFILING=1 \
	afl-clang-fast++ -std=c++11 \
		-I../ \
		-I. \
		-Ibuild-profiling \
		-Wl,--start-group \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		../examples/av1_dec_fuzzer.cc \
		-o av1_dec_fuzzer \
		libaom.a -Wl,--end-group && \
	cp -r /tmp/av1_dec_fuzzer av1_dec_fuzzer-profiling-logs

libaom-cov: libaom
	@echo "=== Building libaom av1_dec_fuzzer with coverage instrumentation ==="
	cd libaom && \
	rm -rf build-cov && mkdir -p build-cov && cd build-cov && \
	CC=clang CXX=clang++ \
	cmake .. -DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_C_FLAGS_RELEASE='-O3 -g0 -fprofile-arcs -ftest-coverage' \
		-DCMAKE_CXX_FLAGS_RELEASE='-O3 -g0 -fprofile-arcs -ftest-coverage' \
		-DCONFIG_PIC=1 \
		-DCONFIG_LOWBITDEPTH=1 \
		-DCONFIG_AV1_ENCODER=0 \
		-DENABLE_EXAMPLES=0 \
		-DENABLE_DOCS=0 \
		-DENABLE_TESTS=0 \
		-DCONFIG_SIZE_LIMIT=1 \
		-DDECODE_HEIGHT_LIMIT=12288 \
		-DDECODE_WIDTH_LIMIT=12288 \
		-DAOM_EXTRA_C_FLAGS="-DAOM_MAX_ALLOCABLE_MEMORY=1073741824 -DDO_RANGE_CHECK_CLAMP=1" \
		-DENABLE_TOOLS=0 \
		-DAOM_EXTRA_CXX_FLAGS="-DAOM_MAX_ALLOCABLE_MEMORY=1073741824 -DDO_RANGE_CHECK_CLAMP=1" && \
	make -j$$(nproc) && \
	clang++ -g -fsanitize=fuzzer -fprofile-arcs -ftest-coverage -std=c++11 \
		-I../ \
		-I. \
		-Ibuild-cov \
		-Wl,--start-group \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		../examples/av1_dec_fuzzer.cc \
		-o av1_dec_fuzzer \
		libaom.a -Wl,--end-group

libaom-cmplog: libaom
	@echo "=== Building libaom av1_dec_fuzzer with CMPLOG instrumentation ==="
	export AFL_LLVM_CMPLOG=1 && \
	cd libaom && \
	rm -rf build-cmplog && mkdir -p build-cmplog && cd build-cmplog && \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	cmake .. -DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_C_FLAGS_RELEASE='-O3 -g' \
		-DCMAKE_CXX_FLAGS_RELEASE='-O3 -g' \
		-DCONFIG_PIC=1 \
		-DCONFIG_LOWBITDEPTH=1 \
		-DCONFIG_AV1_ENCODER=0 \
		-DENABLE_EXAMPLES=0 \
		-DENABLE_DOCS=0 \
		-DENABLE_TESTS=0 \
		-DCONFIG_SIZE_LIMIT=1 \
		-DDECODE_HEIGHT_LIMIT=12288 \
		-DDECODE_WIDTH_LIMIT=12288 \
		-DAOM_EXTRA_C_FLAGS="-DAOM_MAX_ALLOCABLE_MEMORY=1073741824 -DDO_RANGE_CHECK_CLAMP=1" \
		-DENABLE_TOOLS=0 \
		-DAOM_EXTRA_CXX_FLAGS="-DAOM_MAX_ALLOCABLE_MEMORY=1073741824 -DDO_RANGE_CHECK_CLAMP=1" && \
	make -j$$(nproc) && \
	afl-clang-fast++ -std=c++11 \
		-I../ \
		-I. \
		-Ibuild-cmplog \
		-Wl,--start-group \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		../examples/av1_dec_fuzzer.cc \
		-o av1_dec_fuzzer \
		libaom.a -Wl,--end-group && \
	unset AFL_LLVM_CMPLOG

libaom-all: libaom-afl libaom-wllvm libaom-profiling libaom-cov
libaom-clean-all:
	rm -rf libaom libaom-build-* libaom/people.xiph.org /tmp/av1_dec_fuzzer*

# Ensure re2c is installed (≥ 1.0.3)
check-re2c:
	@if ! command -v re2c >/dev/null 2>&1; then \
		echo "[+] re2c not found, installing..."; \
		if command -v sudo >/dev/null 2>&1; then sudo apt-get update && sudo apt-get install -y re2c; \
		elif [ "$$(id -u)" = 0 ]; then apt-get update && apt-get install -y re2c; \
		else echo "error: re2c is required" >&2; exit 1; fi; \
	else \
		echo "[✓] re2c already installed: $$(re2c --version)"; \
	fi

# Clone PHP and checkout the desired commit
php-src:
	git clone https://github.com/php/php-src.git php-src

php-checkout: check-re2c php-src
	cd php-src && \
	git fetch --all --tags && \
	git checkout 52cc9236ce160977297565a77c4620aeffb92a51 && \
	./buildconf --force

# Configure & build PHP using AFL++ compilers inside php-src/build-afl
php-build-afl: php-checkout
	cd php-src && \
	rm -rf build-afl && mkdir -p build-afl && \
	cd build-afl && \
	LIB_FUZZING_ENGINE="$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a" \
	FUZZING_CC="afl-clang-fast++" \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	CFLAGS="-fno-sanitize=object-size -DPROFITABILITY_CHECKS=0" \
	CXXFLAGS="-fno-sanitize=object-size -DPROFITABILITY_CHECKS=0" \
	../configure \
	  --disable-all \
	  --enable-debug-assertions \
	  --enable-option-checking=fatal \
	  --enable-fuzzer \
	  --enable-exif \
	  --without-pcre-jit \
	  --disable-phpdbg \
	  --disable-cgi \
	  --enable-pic && \
	LIB_FUZZING_ENGINE="$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a" \
    FUZZING_CC="afl-clang-fast++" \
    CC=afl-clang-fast CXX=afl-clang-fast++ \
    make -j$$(nproc) libs sapi/cli/php && \
    LIB_FUZZING_ENGINE="$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a" \
    FUZZING_CC="afl-clang-fast++" \
    CC=afl-clang-fast CXX=afl-clang-fast++ \
    make -j$$(nproc) PHP_FUZZER_BINARIES='sapi/fuzzer/php-fuzz-parser' && \
	mv sapi/fuzzer/php-fuzz-parser .

php-build-afl-asan: php-checkout
	cd php-src && \
	rm -rf build-afl-asan && mkdir -p build-afl-asan && \
	cd build-afl-asan && \
	export AFL_USE_ASAN=1 && \
	LIB_FUZZING_ENGINE="$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a" \
	FUZZING_CC="afl-clang-fast++" \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	../configure \
	  --disable-all \
	  --enable-debug-assertions \
	  --enable-option-checking=fatal \
	  --enable-fuzzer \
	  --enable-exif \
	  --without-pcre-jit \
	  --disable-phpdbg \
	  --disable-cgi \
	  --enable-pic && \
	LIB_FUZZING_ENGINE="$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a" \
    FUZZING_CC="afl-clang-fast++" \
    CC=afl-clang-fast CXX=afl-clang-fast++ \
    make -j$$(nproc) libs sapi/cli/php && \
	export AFL_USE_ASAN=1 && \
    LIB_FUZZING_ENGINE="$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a" \
    FUZZING_CC="afl-clang-fast++" \
    CC=afl-clang-fast CXX=afl-clang-fast++ \
    make -j$$(nproc) PHP_FUZZER_BINARIES='sapi/fuzzer/php-fuzz-parser' && \
	mv sapi/fuzzer/php-fuzz-parser .

# Generate corpora/dicts using the CLI built in build-afl
php-generate: php-build-afl
	cd php-src/build-afl && \
	if [ -x sapi/cli/php ]; then \
	  sapi/cli/php ../sapi/fuzzer/generate_all.php || true; \
	else \
	  echo "php CLI not built; skipping generate_all.php"; \
	fi

# === WLLVM (bitcode) ===
php-build-wllvm: php-checkout
	cd php-src && \
	rm -rf build-wllvm && mkdir -p build-wllvm && \
	cd build-wllvm && \
	LLVM_COMPILER=clang \
	CC=wllvm CXX=wllvm++ \
	CFLAGS="-fno-sanitize=object-size -DPROFITABILITY_CHECKS=0" \
	CXXFLAGS="-fno-sanitize=object-size -DPROFITABILITY_CHECKS=0" \
	../configure \
	  --disable-all \
	  --enable-debug-assertions \
	  --enable-option-checking=fatal \
	  --enable-fuzzer \
	  --enable-exif \
	  --without-pcre-jit \
	  --disable-phpdbg \
	  --disable-cgi \
	  --enable-pic && \
	LLVM_COMPILER=clang \
	FUZZING_CC="wllvm++" \
	CC=wllvm CXX=wllvm++ \
	make -j$$(nproc) libs sapi/cli/php && \
	LLVM_COMPILER=clang \
	FUZZING_CC="wllvm++" \
	CC=wllvm CXX=wllvm++ \
	make -j$$(nproc) PHP_FUZZER_BINARIES='sapi/fuzzer/php-fuzz-parser' && \
	extract-bc sapi/fuzzer/php-fuzz-parser && \
	opt-15 -passes=dot-callgraph -disable-output < sapi/fuzzer/php-fuzz-parser.bc && \
	mv '<stdin>.callgraph.dot' sapi/fuzzer/php-fuzz-parser.dot

# === Profiling (your HORSEFUZZ-style flags) ===
php-build-profiling: php-checkout
	cd php-src && \
	rm -rf build-profiling && mkdir -p build-profiling && \
	cd build-profiling && \
	HF_BINARY=php-fuzz-parser HORSEFUZZ_CG_PROFILING=1 \
	LIB_FUZZING_ENGINE="$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a" \
	FUZZING_CC="afl-clang-fast++" \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	CFLAGS="-fno-sanitize=object-size -DPROFITABILITY_CHECKS=0" \
	CXXFLAGS="-fno-sanitize=object-size -DPROFITABILITY_CHECKS=0" \
	../configure \
	  --disable-all \
	  --enable-debug-assertions \
	  --enable-option-checking=fatal \
	  --enable-fuzzer \
	  --enable-exif \
	  --without-pcre-jit \
	  --disable-phpdbg \
	  --disable-cgi \
	  --enable-pic && \
	HF_BINARY=php-fuzz-parser HORSEFUZZ_CG_PROFILING=1 \
	LIB_FUZZING_ENGINE="$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a" \
	FUZZING_CC="afl-clang-fast++" \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	make -j$$(nproc) libs sapi/cli/php && \
	HF_BINARY=php-fuzz-parser HORSEFUZZ_CG_PROFILING=1 \
	LIB_FUZZING_ENGINE="$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a" \
	FUZZING_CC="afl-clang-fast++" \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	make -j$$(nproc) PHP_FUZZER_BINARIES='sapi/fuzzer/php-fuzz-parser' && \
	test -d /tmp/php-fuzz-parser && cp -r /tmp/php-fuzz-parser php-fuzz-parser-profiling-logs || true && \
	mv sapi/fuzzer/php-fuzz-parser .

# === Coverage (gcov-style) ===
php-build-cov: php-checkout
	cd php-src && \
	rm -rf build-cov && mkdir -p build-cov && \
	cd build-cov && \
	CC=clang CXX=clang++ \
	CFLAGS="-fno-sanitize=object-size -fprofile-arcs -ftest-coverage -DPROFITABILITY_CHECKS=0" \
	CXXFLAGS="-fno-sanitize=object-size -fprofile-arcs -ftest-coverage -DPROFITABILITY_CHECKS=0" \
	LDFLAGS="--coverage" \
	../configure \
	  --disable-all \
	  --enable-debug-assertions \
	  --enable-option-checking=fatal \
	  --enable-fuzzer \
	  --enable-exif \
	  --without-pcre-jit \
	  --disable-phpdbg \
	  --disable-cgi \
	  --enable-pic && \
	CC=clang CXX=clang++ \
	CFLAGS="-g -fprofile-arcs -ftest-coverage" \
	CXXFLAGS="-g -fprofile-arcs -ftest-coverage" \
	LDFLAGS="--coverage" \
	make -j$$(nproc) libs sapi/cli/php && \
	CC=clang CXX=clang++ \
	CFLAGS="-g -fprofile-arcs -ftest-coverage" \
	CXXFLAGS="-g -fprofile-arcs -ftest-coverage" \
	LDFLAGS="--coverage" \
	make -j$$(nproc) PHP_FUZZER_BINARIES='sapi/fuzzer/php-fuzz-parser' fuzzer && \
	mv sapi/fuzzer/php-fuzz-parser .

# === CMPLOG (AFL++ cmplog) ===
php-build-cmplog: php-checkout
	cd php-src && \
	rm -rf build-cmplog && mkdir -p build-cmplog && \
	cd build-cmplog && \
	AFL_LLVM_CMPLOG=1 \
	LIB_FUZZING_ENGINE="$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a" \
	FUZZING_CC="afl-clang-fast++" \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	CFLAGS="-fno-sanitize=object-size -DPROFITABILITY_CHECKS=0" \
	CXXFLAGS="-fno-sanitize=object-size -DPROFITABILITY_CHECKS=0" \
	../configure \
	  --disable-all \
	  --enable-debug-assertions \
	  --enable-option-checking=fatal \
	  --enable-fuzzer \
	  --enable-exif \
	  --without-pcre-jit \
	  --disable-phpdbg \
	  --disable-cgi \
	  --enable-pic && \
	AFL_LLVM_CMPLOG=1 \
	LIB_FUZZING_ENGINE="$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a" \
	FUZZING_CC="afl-clang-fast++" \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	make -j$$(nproc) libs sapi/cli/php && \
	AFL_LLVM_CMPLOG=1 \
	LIB_FUZZING_ENGINE="$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a" \
	FUZZING_CC="afl-clang-fast++" \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	make -j$$(nproc) PHP_FUZZER_BINARIES='sapi/fuzzer/php-fuzz-parser' && \
	mv sapi/fuzzer/php-fuzz-parser .

# Aggregate Targets
php-all: php-generate php-build-wllvm php-build-profiling php-build-cov
php-clean-all:
	rm -rf php-src php-src/build-* /tmp/php-fuzz-parser*

# Bloaty Base Setup
bloaty:
	git clone https://github.com/google/bloaty.git bloaty && \
	cd bloaty && \
	git checkout 3f36edba803388e98de51647ca0a23e174dc316f && \
	mv tests/testdata/fuzz_corpus/ . && \
	if [ "$(IS_KRAKEN)" = "1" ]; then rm -f fuzz_corpus/testcase-5896363763695616; fi

# Bloaty with AFL++ Instrumentation
bloaty-afl: bloaty
	cd bloaty && rm -rf build-afl && mkdir -p build-afl && cd build-afl && \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	LIB_FUZZING_ENGINE=${AFLPLUSPLUS}/utils/aflpp_driver/libAFLDriver.a \
	cmake -G Ninja -DBUILD_TESTING=false .. && \
	ninja -j$$(nproc) && \
	mv fuzz_target bloaty_fuzz_target

bloaty-cmplog: bloaty
	cd bloaty && rm -rf build-cmplog && mkdir -p build-cmplog && cd build-cmplog && \
	export AFL_LLVM_CMPLOG=1 && \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	LIB_FUZZING_ENGINE=${AFLPLUSPLUS}/utils/aflpp_driver/libAFLDriver.a \
	cmake -G Ninja -DBUILD_TESTING=false .. && \
	ninja -j$$(nproc) && \
	mv fuzz_target bloaty_fuzz_target && \
	unset AFL_LLVM_CMPLOG

bloaty-wllvm: bloaty
	cd bloaty && rm -rf build-wllvm && mkdir -p build-wllvm && cd build-wllvm && \
	export LLVM_COMPILER=clang && \
	CC=wllvm CXX=wllvm++ \
	LIB_FUZZING_ENGINE=-fsanitize=fuzzer \
	cmake -G Ninja -DBUILD_TESTING=false .. && \
	ninja -j$$(nproc) && \
	mv fuzz_target bloaty_fuzz_target && \
	extract-bc bloaty_fuzz_target && \
	opt-15 -passes=dot-callgraph -disable-output < bloaty_fuzz_target.bc && \
	mv '<stdin>.callgraph.dot' bloaty_fuzz_target.dot

bloaty-profiling: bloaty
	cd bloaty && rm -rf build-profiling && mkdir -p build-profiling && cd build-profiling && \
	HF_BINARY=bloaty_fuzz_target HORSEFUZZ_CG_PROFILING=1 \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	LIB_FUZZING_ENGINE=${AFLPLUSPLUS}/utils/aflpp_driver/libAFLDriver.a \
	cmake -G Ninja -DBUILD_TESTING=false .. && \
	HF_BINARY=bloaty_fuzz_target HORSEFUZZ_CG_PROFILING=1 \
	ninja -j$$(nproc) && \
	mv fuzz_target bloaty_fuzz_target && \
	cp -r /tmp/bloaty_fuzz_target bloaty_fuzz_target-profiling-logs

bloaty-cov: bloaty
	cd bloaty && rm -rf build-cov && mkdir -p build-cov && cd build-cov && \
	CC=clang CXX=clang++ \
	CFLAGS="-g -fprofile-arcs -ftest-coverage" CXXFLAGS="-g -fprofile-arcs -ftest-coverage" \
	LIB_FUZZING_ENGINE=-fsanitize=fuzzer \
	cmake -G Ninja -DBUILD_TESTING=false .. && \
	ninja -j$$(nproc) && \
	mv fuzz_target bloaty_fuzz_target

bloaty-all: bloaty-afl bloaty-wllvm bloaty-profiling bloaty-cov
bloaty-clean-all:
	rm -rf bloaty bloaty/build-* bloaty/fuzz_corpus /tmp/bloaty_fuzz_target*

# mbedTLS Base Setup
mbedtls:
	git clone --recursive -b mbedtls-3.6 https://github.com/Mbed-TLS/mbedtls.git mbedtls && \
	cd mbedtls && \
	git checkout b55fd70a05e9e289c898014c53908b409b7ebeb0 && \
	git submodule update --init --recursive && \
	perl scripts/config.py full && \
	perl scripts/config.py set MBEDTLS_PLATFORM_TIME_ALT && \
	perl scripts/config.py unset MBEDTLS_USE_PSA_CRYPTO && \
	mkdir -p corpus/dtlsclient && \
	cp programs/fuzz/corpuses/dtlsclient corpus/dtlsclient/

mbedtls-deps:
	pip3 install jinja2 jsonschema || true

# mbedTLS with AFL++ Instrumentation
mbedtls-afl: mbedtls mbedtls-deps
	cd mbedtls && \
	mkdir -p build-afl && cd build-afl && \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	FUZZER_LIB=${AFLPLUSPLUS}/utils/aflpp_driver/libAFLDriver.a  \
	cmake .. \
		-DENABLE_TESTING=OFF && \
	make -j$$(nproc) && \
	mv programs/fuzz/fuzz_dtlsclient .

mbedtls-cmplog: mbedtls mbedtls-deps
	cd mbedtls && \
	mkdir -p build-cmplog && cd build-cmplog && \
	export AFL_LLVM_CMPLOG=1 && \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	FUZZER_LIB=${AFLPLUSPLUS}/utils/aflpp_driver/libAFLDriver.a  \
	cmake .. \
		-DENABLE_TESTING=OFF && \
	make -j$$(nproc) && \
	mv programs/fuzz/fuzz_dtlsclient . && \
	unset AFL_LLVM_CMPLOG

# mbedTLS with Whole-Program LLVM (wllvm) and extract the call graph
mbedtls-wllvm: mbedtls mbedtls-deps
	cd mbedtls && \
	mkdir -p build-wllvm && cd build-wllvm && \
	export LLVM_COMPILER=clang && \
	CC=wllvm CXX=wllvm++ \
	LIB_FUZZING_ENGINE=-fsanitize=fuzzer \
	cmake .. \
		-DENABLE_TESTING=OFF && \
	make -j$$(nproc) && \
	extract-bc programs/fuzz/fuzz_dtlsclient && \
	opt-15 -passes=dot-callgraph -disable-output < programs/fuzz/fuzz_dtlsclient.bc && \
	mv '<stdin>.callgraph.dot' fuzz_dtlsclient.dot

# mbedTLS with profiling (with instrumented fuzzing harness and logging)
mbedtls-profiling: mbedtls mbedtls-deps
	cd mbedtls && \
	mkdir -p build-profiling && cd build-profiling && \
	HF_BINARY=fuzz_dtlsclient HORSEFUZZ_CG_PROFILING=1 \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	LIB_FUZZING_ENGINE=${AFLPLUSPLUS}/utils/aflpp_driver/libAFLDriver.a  \
	cmake .. \
		-DENABLE_TESTING=OFF && \
	HF_BINARY=fuzz_dtlsclient HORSEFUZZ_CG_PROFILING=1 make -j$$(nproc) && \
	mv programs/fuzz/fuzz_dtlsclient . && \
	cp -r /tmp/fuzz_dtlsclient fuzz_dtlsclient-profiling-logs

# mbedTLS with coverage instrumentation
mbedtls-cov: mbedtls mbedtls-deps
	cd mbedtls && \
	mkdir -p build-cov && cd build-cov && \
	CC=clang CXX=clang++ \
	CFLAGS="-g -fprofile-arcs -ftest-coverage" CXXFLAGS="-g -fprofile-arcs -ftest-coverage" \
	LIB_FUZZING_ENGINE=-fsanitize=fuzzer \
	cmake .. \
		-DENABLE_TESTING=OFF && \
	make -j$$(nproc) && \
	mv programs/fuzz/fuzz_dtlsclient .

mbedtls-all: mbedtls-afl mbedtls-wllvm mbedtls-profiling mbedtls-cov
mbedtls-clean-all:
	rm -rf mbedtls mbedtls/build-* mbedtls/corpus /tmp/fuzz_dtlsclient*

# LibJPEG-turbo
# LibJPEG-Turbo Base Setup
libjpeg-turbo:
	git clone https://github.com/libjpeg-turbo/libjpeg-turbo.git libjpeg-turbo
	cd libjpeg-turbo && git checkout f29eda6

# Prepare the Decompression Seed Corpus - fuzzbench
libjpeg-turbo-decompress-corpus: libjpeg-turbo
	mkdir -p libjpeg-turbo/seeds
	wget -O libjpeg-turbo/seeds/seed.jpg https://github.com/google/fuzzbench/raw/2a2ca6ae4c5d171a52b3e20d9b7a72da306fe5b8/benchmarks/libjpeg-turbo_libjpeg_turbo_fuzzer/seeds/seed.jpg

# Prepare LibJPEG-Turbo AFL
libjpeg-turbo-afl: libjpeg-turbo-decompress-corpus
	cd libjpeg-turbo && \
	mkdir -p build-afl && cd build-afl && \
	CC=afl-clang-fast CXX=afl-clang-fast++ cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo \
		-DENABLE_STATIC=1 \
		-DENABLE_SHARED=0 \
		-DCMAKE_C_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" \
		-DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" \
		-DCMAKE_INSTALL_PREFIX=$$(pwd)/install \
		-DWITH_FUZZ=1 \
		-DFUZZ_BINDIR=$$(pwd) \
		-DFUZZ_LIBRARY=$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a  && \
	make clean all -j$(nproc) && \
	make install

libjpeg-turbo-afl-asan: libjpeg-turbo-decompress-corpus
	cd libjpeg-turbo && \
	export AFL_USE_ASAN=1 && \
	mkdir -p build-afl-asan && cd build-afl-asan && \
	CC=afl-clang-fast CXX=afl-clang-fast++ cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo \
		-DENABLE_STATIC=1 \
		-DENABLE_SHARED=0 \
		-DCMAKE_C_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" \
		-DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" \
		-DCMAKE_INSTALL_PREFIX=$$(pwd)/install \
		-DWITH_FUZZ=1 \
		-DFUZZ_BINDIR=$$(pwd) \
		-DFUZZ_LIBRARY=$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a  && \
	make clean all -j$(nproc) && \
	make install

libjpeg-turbo-cmplog: libjpeg-turbo-decompress-corpus
	cd libjpeg-turbo && \
	export AFL_LLVM_CMPLOG=1 && \
	mkdir -p build-cmplog && cd build-cmplog && \
	CC=afl-clang-fast CXX=afl-clang-fast++ cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo \
		-DENABLE_STATIC=1 \
		-DENABLE_SHARED=0 \
		-DCMAKE_C_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" \
		-DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" \
		-DCMAKE_INSTALL_PREFIX=$$(pwd)/install \
		-DWITH_FUZZ=1 \
		-DFUZZ_BINDIR=$$(pwd) \
		-DFUZZ_LIBRARY=$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a  && \
	make clean all -j$(nproc) && \
	make install && \
	unset AFL_LLVM_CMPLOG

# Compile libjpeg_turbo_fuzzer with wllvm and Extract Call Graph
libjpeg-turbo-wllvm: libjpeg-turbo
	cd libjpeg-turbo && \
	mkdir -p build-wllvm && cd build-wllvm && \
	export LLVM_COMPILER=clang && \
	CC=wllvm CXX=wllvm++ cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo \
		-DENABLE_STATIC=1 \
		-DENABLE_SHARED=0 \
		-DCMAKE_C_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" \
		-DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" \
		-DCMAKE_INSTALL_PREFIX=$$(pwd)/install \
		-DWITH_FUZZ=1 \
		-DFUZZ_BINDIR=$$(pwd) \
		-DFUZZ_LIBRARY="-fsanitize=fuzzer"  && \
	make clean all -j$(nproc) && \
	make install && \
	extract-bc $$(pwd)/libjpeg_turbo_fuzzer && \
	opt-15 -passes=dot-callgraph -disable-output $$(pwd)/libjpeg_turbo_fuzzer.bc && \
	mv $$(pwd)/libjpeg_turbo_fuzzer.bc.callgraph.dot $$(pwd)/libjpeg_turbo_fuzzer.dot

# Prepare LibJPEG-Turbo profiling
libjpeg-turbo-profiling: libjpeg-turbo
	cd libjpeg-turbo && \
	mkdir -p build-profiling && cd build-profiling && \
	HF_BINARY=libjpeg_turbo_fuzzer HORSEFUZZ_CG_PROFILING=1 CC=afl-clang-fast CXX=afl-clang-fast++ cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo \
		-DENABLE_STATIC=1 \
		-DENABLE_SHARED=0 \
		-DCMAKE_C_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" \
		-DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" \
		-DCMAKE_INSTALL_PREFIX=$$(pwd)/install \
		-DWITH_FUZZ=1 \
		-DFUZZ_BINDIR=$$(pwd) \
		-DFUZZ_LIBRARY=$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a  && \
	HF_BINARY=libjpeg_turbo_fuzzer HORSEFUZZ_CG_PROFILING=1 make clean all -j$(nproc) && \
	HF_BINARY=libjpeg_turbo_fuzzer HORSEFUZZ_CG_PROFILING=1 make install && \
	cp -r /tmp/libjpeg_turbo_fuzzer libjpeg_turbo_fuzzer-profiling-logs

# LibJPEG-Turbo Coverage
libjpeg-turbo-cov: libjpeg-turbo
	cd libjpeg-turbo && \
	mkdir -p build-cov && cd build-cov && \
	export LLVM_COMPILER=clang && \
	CC=clang CXX=clang++ CFLAGS="-g -fprofile-arcs -ftest-coverage" CXXFLAGS="-g -fprofile-arcs -ftest-coverage" \
		cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo \
		-DENABLE_STATIC=1 \
		-DENABLE_SHARED=0 \
		-DCMAKE_INSTALL_PREFIX=$$(pwd)/install \
		-DWITH_FUZZ=1 \
		-DFUZZ_BINDIR=$$(pwd) \
		-DFUZZ_LIBRARY="-fsanitize=fuzzer"  && \
	make clean all -j$(nproc) && \
	make install

libjpeg-turbo-all: libjpeg-turbo libjpeg-turbo-afl libjpeg-turbo-wllvm libjpeg-turbo-profiling libjpeg-turbo-cov

libjpeg-turbo-clean-all:
	rm -rf libjpeg-turbo /tmp/libjpeg_turbo_fuzzer

# LCMS Base Setup
# fuzzbench seed
lcms:
	git clone https://github.com/mm2/Little-CMS.git lcms && \
	cd lcms && \
	git checkout 08f4abb && \
	mkdir -p seeds && \
	wget -O seeds/seed https://raw.githubusercontent.com/google/fuzzbench/2a2ca6ae4c5d171a52b3e20d9b7a72da306fe5b8/benchmarks/lcms_cms_transform_fuzzer/seeds/seed && \
	mkdir -p oss-fuzz && \
	wget -O oss-fuzz/cms_transform_fuzzer.c https://raw.githubusercontent.com/google/oss-fuzz/$(OSS_FUZZ_INPUTS_REF)/projects/lcms/cms_transform_fuzzer.c && \
	mkdir -p dict && \
	wget -O dict/icc.dict https://raw.githubusercontent.com/google/oss-fuzz/$(OSS_FUZZ_INPUTS_REF)/projects/lcms/icc.dict

# LCMS with AFL++ Instrumentation
lcms-afl: lcms
	cd lcms && \
	rm -rf build-afl && mkdir -p build-afl && cd build-afl && \
	CC=afl-clang-fast CXX=afl-clang-fast++ ../configure --enable-shared=no && \
	make clean all -j$(nproc) && \
	afl-clang-fast -c -I../include ../oss-fuzz/cms_transform_fuzzer.c -o cms_transform_fuzzer.o && \
	afl-clang-fast++ cms_transform_fuzzer.o -o cms_transform_fuzzer \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		src/.libs/liblcms2.a -lz

lcms-mufuzz-seed: lcms
	@if [ ! -s lcms/seeds/seed ] || head -c 256 lcms/seeds/seed | grep -Eqi '<(!doctype|html)'; then \
		echo "Replacing invalid LCMS HTML seed with the raw FuzzBench seed"; \
		wget -O lcms/seeds/seed.tmp https://raw.githubusercontent.com/google/fuzzbench/2a2ca6ae4c5d171a52b3e20d9b7a72da306fe5b8/benchmarks/lcms_cms_transform_fuzzer/seeds/seed && \
		mv lcms/seeds/seed.tmp lcms/seeds/seed; \
	fi

lcms-afl-mufuzz: lcms-mufuzz-seed
	cd lcms && \
	mkdir -p build-afl-mufuzz && cd build-afl-mufuzz && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) CC=$(MUFUZZ_AFL_CLANG) CXX=$(MUFUZZ_AFL_CLANGXX) ../configure --enable-shared=no && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make clean && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make all -j$$(nproc) && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(MUFUZZ_AFL_CLANG) -c -I../include ../oss-fuzz/cms_transform_fuzzer.c -o cms_transform_fuzzer.o && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(MUFUZZ_AFL_CLANGXX) cms_transform_fuzzer.o -o cms_transform_fuzzer \
		$(MUFUZZ_DRIVER) \
		src/.libs/liblcms2.a -lz

lcms-mufuzz: lcms-afl-mufuzz

lcms-cmplog: lcms
	cd lcms && \
	rm -rf build-cmplog && mkdir -p build-cmplog && cd build-cmplog && \
	export AFL_LLVM_CMPLOG=1 && \
	CC=afl-clang-fast CXX=afl-clang-fast++ ../configure --enable-shared=no && \
	make clean all -j$(nproc) && \
	afl-clang-fast -c -I../include ../oss-fuzz/cms_transform_fuzzer.c -o cms_transform_fuzzer.o && \
	afl-clang-fast++ cms_transform_fuzzer.o -o cms_transform_fuzzer \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		src/.libs/liblcms2.a -lz && \
	unset AFL_LLVM_CMPLOG

# LCMS WLLVM (Whole Program LLVM)
lcms-wllvm: lcms
	cd lcms && \
	rm -rf build-wllvm && mkdir -p build-wllvm && cd build-wllvm && \
	export LLVM_COMPILER=clang && \
	CC=wllvm CXX=wllvm++ ../configure --enable-shared=no && \
	make clean all -j$(nproc) && \
	wllvm -c -g -fsanitize=fuzzer -I../include ../oss-fuzz/cms_transform_fuzzer.c -o cms_transform_fuzzer.o && \
	wllvm++ cms_transform_fuzzer.o -g -fsanitize=fuzzer -o cms_transform_fuzzer \
		src/.libs/liblcms2.a -lz && \
	extract-bc cms_transform_fuzzer && \
	opt-15 -passes=dot-callgraph -disable-output < cms_transform_fuzzer.bc && \
	mv '<stdin>.callgraph.dot' cms_transform_fuzzer.dot

# LCMS with Profiling
lcms-profiling: lcms
	cd lcms && \
	rm -rf build-profiling && mkdir -p build-profiling && cd build-profiling && \
	HF_BINARY=cms_transform_fuzzer HORSEFUZZ_CG_PROFILING=1 CC=afl-clang-fast CXX=afl-clang-fast++ ../configure --enable-shared=no && \
	HF_BINARY=cms_transform_fuzzer HORSEFUZZ_CG_PROFILING=1 make clean all -j$(nproc) && \
	HF_BINARY=cms_transform_fuzzer HORSEFUZZ_CG_PROFILING=1 afl-clang-fast -c -I../include ../oss-fuzz/cms_transform_fuzzer.c -o cms_transform_fuzzer.o && \
	HF_BINARY=cms_transform_fuzzer HORSEFUZZ_CG_PROFILING=1 afl-clang-fast++ cms_transform_fuzzer.o -o cms_transform_fuzzer \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		src/.libs/liblcms2.a -lz && \
	cp -r /tmp/cms_transform_fuzzer cms_transform_fuzzer-profiling-logs

# LCMS with Coverage
lcms-cov: lcms
	cd lcms && \
	rm -rf build-cov && mkdir -p build-cov && cd build-cov && \
	CC=clang CXX=clang++ CFLAGS="-g -fprofile-arcs -ftest-coverage" CXXFLAGS="-g -fprofile-arcs -ftest-coverage" ../configure --enable-shared=no && \
	make clean all -j$(nproc) && \
	clang -c -g -fsanitize=fuzzer -fprofile-arcs -ftest-coverage -I../include ../oss-fuzz/cms_transform_fuzzer.c -o cms_transform_fuzzer.o && \
	clang++ -g -fsanitize=fuzzer -fprofile-arcs -ftest-coverage cms_transform_fuzzer.o -o cms_transform_fuzzer \
		src/.libs/liblcms2.a -lz

# Aggregate Targets
lcms-all: lcms-afl lcms-wllvm lcms-profiling lcms-cov

# Clean all builds
lcms-clean-all:
	rm -rf lcms lcms/build-* /tmp/cms_transform_fuzzer /tmp/lcms_transform_fuzzer

POPPLER_REF ?= 1d23101ccebe14261c6afc024ea14f29d209e760
FREETYPE_REF ?= 50d0033f7ee600c5f5831b28877353769d1f7d48
POPPLER_CMAKE ?= cmake

# Poppler Prerequisites
poppler-prerequisites:
	@missing="$$(for p in pkg-config libjpeg-dev libopenjp2-7-dev libpng-dev libcairo2-dev libtiff-dev liblcms2-dev libboost-dev; do dpkg-query -W -f='$${Status}' "$$p" 2>/dev/null | grep -q 'ok installed' || printf '%s ' "$$p"; done)"; \
	if [ -n "$$missing" ]; then \
		if command -v sudo >/dev/null 2>&1; then sudo apt-get install -y $$missing; \
		elif [ "$$(id -u)" = 0 ]; then apt-get install -y $$missing; \
		else echo "error: missing Poppler packages: $$missing" >&2; exit 1; fi; \
	fi
	@if ! command -v "$(POPPLER_CMAKE)" >/dev/null 2>&1 || ! "$(POPPLER_CMAKE)" --version | python3 -c 'import re, sys; data=sys.stdin.read(); m=re.search(r"cmake version ([0-9]+)\.([0-9]+)", data); sys.exit(0 if m and tuple(map(int, m.groups())) >= (3, 10) else 1)'; then \
		echo "[+] Installing user-local CMake >= 3.10 for pinned Poppler"; \
		python3 -m pip install --user "cmake>=3.10"; \
	fi
	"$(POPPLER_CMAKE)" --version

# Poppler Base Setup
poppler: poppler-prerequisites
	mkdir -p poppler
	rm -rf poppler/repo poppler/freetype2
	git init poppler/repo
	cd poppler/repo && git remote add origin https://gitlab.freedesktop.org/poppler/poppler.git && git fetch --depth 1 origin $(POPPLER_REF) && git checkout --detach FETCH_HEAD
	git init poppler/freetype2
	cd poppler/freetype2 && git remote add origin https://gitlab.freedesktop.org/freetype/freetype.git && git fetch --depth 1 origin $(FREETYPE_REF) && git checkout --detach FETCH_HEAD
	# Patch source code to fix C++20/23 ranges compatibility
	POPPLER_REPO=poppler/repo python3 $(dir $(abspath $(lastword $(MAKEFILE_LIST))))patch_poppler.py
	mkdir -p poppler/seeds
	# Fetch seeds from Magma repo
	git clone --depth 1 --branch $(MAGMA_REF) --filter=blob:none $(MAGMA_REPO) poppler/magma_seeds && \
	cd poppler/magma_seeds && \
	git sparse-checkout init --cone && \
	git sparse-checkout set targets/poppler/corpus/pdf_fuzzer && \
	git checkout && \
	cp targets/poppler/corpus/pdf_fuzzer/* ../seeds/ && \
	cd ../.. && rm -rf poppler/magma_seeds

# Poppler with AFL++
poppler-afl: poppler
	# Build Freetype
	cd poppler/freetype2 && \
	./autogen.sh && \
	mkdir -p build-afl && cd build-afl && \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	../configure --prefix=$$(pwd)/../../install-afl --disable-shared PKG_CONFIG_PATH=$$(pwd)/../../install-afl/lib/pkgconfig \
		--with-harfbuzz=no --with-bzip2=no --with-png=no --with-brotli=no && \
	make clean && make -j$(nproc) && make install

	# Build Poppler
	cd poppler/repo && \
	mkdir -p build-afl && cd build-afl && \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	CFLAGS="-D_GNU_SOURCE" CXXFLAGS="-D_GNU_SOURCE" \
	$(POPPLER_CMAKE) .. \
		-DCMAKE_BUILD_TYPE=debug \
		-DBUILD_SHARED_LIBS=OFF \
		-DENABLE_FUZZER=OFF \
		-DFONT_CONFIGURATION=generic \
		-DENABLE_DCTDECODER=libjpeg \
		-DENABLE_GOBJECT_INTROSPECTION=OFF \
		-DENABLE_LIBPNG=OFF \
		-DENABLE_ZLIB=OFF \
		-DENABLE_LIBTIFF=OFF \
		-DENABLE_LIBJPEG=ON \
		-DENABLE_GLIB=OFF \
		-DENABLE_LIBCURL=OFF \
		-DENABLE_BOOST=OFF \
		-DENABLE_GPGME=OFF \
		-DENABLE_NSS3=OFF \
		-DENABLE_QT6=OFF \
		-DENABLE_QT5=OFF \
		-DENABLE_UTILS=OFF \
		-DWITH_Cairo=OFF \
		-DCMAKE_CXX_STANDARD=14 \
		-DFREETYPE_INCLUDE_DIR_ft2build=$$(pwd)/../../install-afl/include/freetype2 \
		-DFREETYPE_INCLUDE_DIR_freetype2=$$(pwd)/../../install-afl/include/freetype2 \
		-DFREETYPE_LIBRARY=$$(pwd)/../../install-afl/lib/libfreetype.a \
		-DICONV_LIBRARIES="/usr/lib/x86_64-linux-gnu/libc.so" && \
	make -j$(nproc) poppler poppler-cpp

	mkdir -p poppler/build-afl
	afl-clang-fast++ -std=c++14 -D_GNU_SOURCE -Ipoppler/repo/cpp -Ipoppler/repo/build-afl/cpp \
		poppler/repo/cpp/tests/fuzzing/pdf_fuzzer.cc -o poppler/build-afl/pdf_fuzzer \
		poppler/repo/build-afl/cpp/libpoppler-cpp.a \
		poppler/repo/build-afl/libpoppler.a \
		poppler/install-afl/lib/libfreetype.a \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		-ljpeg -lz -lopenjp2 -lpng -ltiff -llcms2 -lm -lpthread -pthread
	printf 'POPPLER_REF=%s\nFREETYPE_REF=%s\n' '$(POPPLER_REF)' '$(FREETYPE_REF)' > poppler/build-afl/source-refs

# Poppler with AFL++ and AddressSanitizer
poppler-afl-asan: poppler
	# Build Freetype
	cd poppler/freetype2 && \
	./autogen.sh && \
	mkdir -p build-afl-asan && cd build-afl-asan && \
	export AFL_USE_ASAN=1 && \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	../configure --prefix=$$(pwd)/../../install-afl-asan --disable-shared PKG_CONFIG_PATH=$$(pwd)/../../install-afl-asan/lib/pkgconfig \
		--with-harfbuzz=no --with-bzip2=no --with-png=no --with-brotli=no && \
	make clean && make -j$$(nproc) && make install

	# Build Poppler
	cd poppler/repo && \
	mkdir -p build-afl-asan && cd build-afl-asan && \
	export AFL_USE_ASAN=1 && \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	CFLAGS="-D_GNU_SOURCE" CXXFLAGS="-D_GNU_SOURCE" \
	$(POPPLER_CMAKE) .. \
		-DCMAKE_BUILD_TYPE=debug \
		-DBUILD_SHARED_LIBS=OFF \
		-DENABLE_FUZZER=OFF \
		-DFONT_CONFIGURATION=generic \
		-DENABLE_DCTDECODER=libjpeg \
		-DENABLE_GOBJECT_INTROSPECTION=OFF \
		-DENABLE_LIBPNG=OFF \
		-DENABLE_ZLIB=OFF \
		-DENABLE_LIBTIFF=OFF \
		-DENABLE_LIBJPEG=ON \
		-DENABLE_GLIB=OFF \
		-DENABLE_LIBCURL=OFF \
		-DENABLE_BOOST=OFF \
		-DENABLE_GPGME=OFF \
		-DENABLE_NSS3=OFF \
		-DENABLE_QT6=OFF \
		-DENABLE_QT5=OFF \
		-DENABLE_UTILS=OFF \
		-DWITH_Cairo=OFF \
		-DCMAKE_CXX_STANDARD=14 \
		-DFREETYPE_INCLUDE_DIR_ft2build=$$(pwd)/../../install-afl-asan/include/freetype2 \
		-DFREETYPE_INCLUDE_DIR_freetype2=$$(pwd)/../../install-afl-asan/include/freetype2 \
		-DFREETYPE_LIBRARY=$$(pwd)/../../install-afl-asan/lib/libfreetype.a \
		-DICONV_LIBRARIES="/usr/lib/x86_64-linux-gnu/libc.so" && \
	make -j$$(nproc) poppler poppler-cpp

	mkdir -p poppler/build-afl-asan
	export AFL_USE_ASAN=1 && \
	afl-clang-fast++ -std=c++14 -D_GNU_SOURCE -Ipoppler/repo/cpp -Ipoppler/repo/build-afl-asan/cpp \
		poppler/repo/cpp/tests/fuzzing/pdf_fuzzer.cc -o poppler/build-afl-asan/pdf_fuzzer \
		poppler/repo/build-afl-asan/cpp/libpoppler-cpp.a \
		poppler/repo/build-afl-asan/libpoppler.a \
		poppler/install-afl-asan/lib/libfreetype.a \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		-ljpeg -lz -lopenjp2 -lpng -ltiff -llcms2 -lm -lpthread -pthread

# Poppler with WLLVM
poppler-wllvm: poppler
	# Build Freetype
	cd poppler/freetype2 && \
	./autogen.sh && \
	mkdir -p build-wllvm && cd build-wllvm && \
	export LLVM_COMPILER=clang && \
	CC=wllvm CXX=wllvm++ \
	../configure --prefix=$$(pwd)/../../install-wllvm --disable-shared PKG_CONFIG_PATH=$$(pwd)/../../install-wllvm/lib/pkgconfig \
		--with-harfbuzz=no --with-bzip2=no --with-png=no --with-brotli=no && \
	make clean && make -j$(nproc) && make install

	# Build Poppler
	cd poppler/repo && \
	mkdir -p build-wllvm && cd build-wllvm && \
	export LLVM_COMPILER=clang && \
	CC=wllvm CXX=wllvm++ \
	CFLAGS="-D_GNU_SOURCE" CXXFLAGS="-D_GNU_SOURCE" \
	$(POPPLER_CMAKE) .. \
		-DCMAKE_BUILD_TYPE=debug \
		-DBUILD_SHARED_LIBS=OFF \
		-DENABLE_FUZZER=OFF \
		-DFONT_CONFIGURATION=generic \
		-DENABLE_DCTDECODER=libjpeg \
		-DENABLE_GOBJECT_INTROSPECTION=OFF \
		-DENABLE_LIBPNG=OFF \
		-DENABLE_ZLIB=OFF \
		-DENABLE_LIBTIFF=OFF \
		-DENABLE_LIBJPEG=ON \
		-DENABLE_GLIB=OFF \
		-DENABLE_LIBCURL=OFF \
		-DENABLE_BOOST=OFF \
		-DENABLE_GPGME=OFF \
		-DENABLE_NSS3=OFF \
		-DENABLE_QT6=OFF \
		-DENABLE_QT5=OFF \
		-DENABLE_UTILS=OFF \
		-DWITH_Cairo=OFF \
		-DCMAKE_CXX_STANDARD=14 \
		-DFREETYPE_INCLUDE_DIR_ft2build=$$(pwd)/../../install-wllvm/include/freetype2 \
		-DFREETYPE_INCLUDE_DIR_freetype2=$$(pwd)/../../install-wllvm/include/freetype2 \
		-DFREETYPE_LIBRARY=$$(pwd)/../../install-wllvm/lib/libfreetype.a \
		-DICONV_LIBRARIES="/usr/lib/x86_64-linux-gnu/libc.so" && \
	make -j$(nproc) poppler poppler-cpp

	mkdir -p poppler/build-wllvm
	export LLVM_COMPILER=clang && \
	wllvm++ -g -fsanitize=fuzzer -std=c++14 -D_GNU_SOURCE -Ipoppler/repo/cpp -Ipoppler/repo/build-wllvm/cpp \
		poppler/repo/cpp/tests/fuzzing/pdf_fuzzer.cc -o poppler/build-wllvm/pdf_fuzzer \
		poppler/repo/build-wllvm/cpp/libpoppler-cpp.a \
		poppler/repo/build-wllvm/libpoppler.a \
		poppler/install-wllvm/lib/libfreetype.a \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		-ljpeg -lz -lopenjp2 -lpng -ltiff -llcms2 -lm -lpthread -pthread && \
	extract-bc poppler/build-wllvm/pdf_fuzzer && \
	opt-15 -passes=dot-callgraph -disable-output < poppler/build-wllvm/pdf_fuzzer.bc && \
	mv '<stdin>.callgraph.dot' poppler/build-wllvm/pdf_fuzzer.dot
	printf 'POPPLER_REF=%s\nFREETYPE_REF=%s\n' '$(POPPLER_REF)' '$(FREETYPE_REF)' > poppler/build-wllvm/source-refs

# Poppler with Profiling
poppler-profiling: poppler
	# Build Freetype
	cd poppler/freetype2 && \
	./autogen.sh && \
	mkdir -p build-profiling && cd build-profiling && \
	HF_BINARY=pdf_fuzzer HORSEFUZZ_CG_PROFILING=1 \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	../configure --prefix=$$(pwd)/../../install-profiling --disable-shared PKG_CONFIG_PATH=$$(pwd)/../../install-profiling/lib/pkgconfig \
		--with-harfbuzz=no --with-bzip2=no --with-png=no --with-brotli=no && \
	HF_BINARY=pdf_fuzzer HORSEFUZZ_CG_PROFILING=1 make clean && \
	HF_BINARY=pdf_fuzzer HORSEFUZZ_CG_PROFILING=1 make -j$(nproc) && \
	HF_BINARY=pdf_fuzzer HORSEFUZZ_CG_PROFILING=1 make install

	# Build Poppler
	cd poppler/repo && \
	mkdir -p build-profiling && cd build-profiling && \
	HF_BINARY=pdf_fuzzer HORSEFUZZ_CG_PROFILING=1 \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	CFLAGS="-D_GNU_SOURCE" CXXFLAGS="-D_GNU_SOURCE" \
	$(POPPLER_CMAKE) .. \
		-DCMAKE_BUILD_TYPE=debug \
		-DBUILD_SHARED_LIBS=OFF \
		-DENABLE_FUZZER=OFF \
		-DFONT_CONFIGURATION=generic \
		-DENABLE_DCTDECODER=libjpeg \
		-DENABLE_GOBJECT_INTROSPECTION=OFF \
		-DENABLE_LIBPNG=OFF \
		-DENABLE_ZLIB=OFF \
		-DENABLE_LIBTIFF=OFF \
		-DENABLE_LIBJPEG=ON \
		-DENABLE_GLIB=OFF \
		-DENABLE_LIBCURL=OFF \
		-DENABLE_BOOST=OFF \
		-DENABLE_GPGME=OFF \
		-DENABLE_NSS3=OFF \
		-DENABLE_QT6=OFF \
		-DENABLE_QT5=OFF \
		-DENABLE_UTILS=OFF \
		-DWITH_Cairo=OFF \
		-DCMAKE_CXX_STANDARD=14 \
		-DFREETYPE_INCLUDE_DIR_ft2build=$$(pwd)/../../install-profiling/include/freetype2 \
		-DFREETYPE_INCLUDE_DIR_freetype2=$$(pwd)/../../install-profiling/include/freetype2 \
		-DFREETYPE_LIBRARY=$$(pwd)/../../install-profiling/lib/libfreetype.a \
		-DICONV_LIBRARIES="/usr/lib/x86_64-linux-gnu/libc.so" && \
	HF_BINARY=pdf_fuzzer HORSEFUZZ_CG_PROFILING=1 make -j$(nproc) poppler poppler-cpp

	mkdir -p poppler/build-profiling
	HF_BINARY=pdf_fuzzer HORSEFUZZ_CG_PROFILING=1 \
	afl-clang-fast++ -std=c++14 -D_GNU_SOURCE -Ipoppler/repo/cpp -Ipoppler/repo/build-profiling/cpp \
		poppler/repo/cpp/tests/fuzzing/pdf_fuzzer.cc -o poppler/build-profiling/pdf_fuzzer_profiling \
		poppler/repo/build-profiling/cpp/libpoppler-cpp.a \
		poppler/repo/build-profiling/libpoppler.a \
		poppler/install-profiling/lib/libfreetype.a \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		-ljpeg -lz -lopenjp2 -lpng -ltiff -llcms2 -lm -lpthread -pthread && \
	cp -r /tmp/pdf_fuzzer poppler/build-profiling/pdf_fuzzer-profiling-logs
	printf 'POPPLER_REF=%s\nFREETYPE_REF=%s\n' '$(POPPLER_REF)' '$(FREETYPE_REF)' > poppler/build-profiling/source-refs

# Poppler with CmpLog
poppler-cmplog: poppler
	# Build Freetype
	cd poppler/freetype2 && \
	./autogen.sh && \
	mkdir -p build-cmplog && cd build-cmplog && \
	export AFL_LLVM_CMPLOG=1 && \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	../configure --prefix=$$(pwd)/../../install-cmplog --disable-shared PKG_CONFIG_PATH=$$(pwd)/../../install-cmplog/lib/pkgconfig \
		--with-harfbuzz=no --with-bzip2=no --with-png=no --with-brotli=no && \
	make clean && make -j$(nproc) && make install

	# Build Poppler
	cd poppler/repo && \
	mkdir -p build-cmplog && cd build-cmplog && \
	export AFL_LLVM_CMPLOG=1 && \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	CFLAGS="-D_GNU_SOURCE" CXXFLAGS="-D_GNU_SOURCE" \
	$(POPPLER_CMAKE) .. \
		-DCMAKE_BUILD_TYPE=debug \
		-DBUILD_SHARED_LIBS=OFF \
		-DENABLE_FUZZER=OFF \
		-DFONT_CONFIGURATION=generic \
		-DENABLE_DCTDECODER=libjpeg \
		-DENABLE_GOBJECT_INTROSPECTION=OFF \
		-DENABLE_LIBPNG=OFF \
		-DENABLE_ZLIB=OFF \
		-DENABLE_LIBTIFF=OFF \
		-DENABLE_LIBJPEG=ON \
		-DENABLE_GLIB=OFF \
		-DENABLE_LIBCURL=OFF \
		-DENABLE_BOOST=OFF \
		-DENABLE_GPGME=OFF \
		-DENABLE_NSS3=OFF \
		-DENABLE_QT6=OFF \
		-DENABLE_QT5=OFF \
		-DENABLE_UTILS=OFF \
		-DWITH_Cairo=OFF \
		-DCMAKE_CXX_STANDARD=14 \
		-DFREETYPE_INCLUDE_DIR_ft2build=$$(pwd)/../../install-cmplog/include/freetype2 \
		-DFREETYPE_INCLUDE_DIR_freetype2=$$(pwd)/../../install-cmplog/include/freetype2 \
		-DFREETYPE_LIBRARY=$$(pwd)/../../install-cmplog/lib/libfreetype.a \
		-DICONV_LIBRARIES="/usr/lib/x86_64-linux-gnu/libc.so" && \
	make -j$(nproc) poppler poppler-cpp

	mkdir -p poppler/build-cmplog
	export AFL_LLVM_CMPLOG=1 && \
	afl-clang-fast++ -std=c++14 -D_GNU_SOURCE -Ipoppler/repo/cpp -Ipoppler/repo/build-cmplog/cpp \
		poppler/repo/cpp/tests/fuzzing/pdf_fuzzer.cc -o poppler/build-cmplog/pdf_fuzzer_cmplog \
		poppler/repo/build-cmplog/cpp/libpoppler-cpp.a \
		poppler/repo/build-cmplog/libpoppler.a \
		poppler/install-cmplog/lib/libfreetype.a \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		-ljpeg -lz -lopenjp2 -lpng -ltiff -llcms2 -lm -lpthread -pthread && \
	unset AFL_LLVM_CMPLOG
	printf 'POPPLER_REF=%s\nFREETYPE_REF=%s\n' '$(POPPLER_REF)' '$(FREETYPE_REF)' > poppler/build-cmplog/source-refs

# Poppler with Coverage
poppler-cov: poppler
	# Build Freetype
	cd poppler/freetype2 && \
	./autogen.sh && \
	mkdir -p build-cov && cd build-cov && \
	CC=clang CXX=clang++ \
	CFLAGS="-g -fprofile-arcs -ftest-coverage -D_GNU_SOURCE" CXXFLAGS="-g -fprofile-arcs -ftest-coverage -D_GNU_SOURCE" \
	../configure --prefix=$$(pwd)/../../install-cov --disable-shared PKG_CONFIG_PATH=$$(pwd)/../../install-cov/lib/pkgconfig \
		--with-harfbuzz=no --with-bzip2=no --with-png=no --with-brotli=no && \
	make clean && make -j$(nproc) && make install

	# Build Poppler
	cd poppler/repo && \
	mkdir -p build-cov && cd build-cov && \
	CC=clang CXX=clang++ \
	CFLAGS="-g -fprofile-arcs -ftest-coverage -D_GNU_SOURCE" CXXFLAGS="-g -fprofile-arcs -ftest-coverage -D_GNU_SOURCE" \
	$(POPPLER_CMAKE) .. \
		-DCMAKE_BUILD_TYPE=debug \
		-DBUILD_SHARED_LIBS=OFF \
		-DFONT_CONFIGURATION=generic \
		-DBUILD_GTK_TESTS=OFF \
		-DBUILD_QT5_TESTS=OFF \
		-DBUILD_CPP_TESTS=OFF \
		-DENABLE_LIBPNG=OFF \
		-DENABLE_LIBTIFF=OFF \
		-DENABLE_LIBJPEG=ON \
		-DENABLE_SPLASH=ON \
		-DENABLE_UTILS=OFF \
		-DWITH_Cairo=OFF \
		-DENABLE_CMS=none \
		-DENABLE_LIBCURL=OFF \
		-DENABLE_BOOST=OFF \
		-DENABLE_GLIB=OFF \
		-DENABLE_GOBJECT_INTROSPECTION=OFF \
		-DENABLE_QT5=OFF \
		-DENABLE_QT6=OFF \
		-DENABLE_NSS3=OFF \
		-DENABLE_GPGME=OFF \
		-DENABLE_ZLIB=OFF \
		-DENABLE_DCTDECODER=libjpeg \
		-DENABLE_FUZZER=OFF \
		-DCMAKE_CXX_STANDARD=14 \
		-DFREETYPE_INCLUDE_DIR_ft2build=$$(pwd)/../../install-cov/include/freetype2 \
		-DFREETYPE_INCLUDE_DIR_freetype2=$$(pwd)/../../install-cov/include/freetype2 \
		-DFREETYPE_LIBRARY=$$(pwd)/../../install-cov/lib/libfreetype.a \
		-DICONV_LIBRARIES="/usr/lib/x86_64-linux-gnu/libc.so" && \
	make -j$(nproc) poppler poppler-cpp

	# Build pdf_fuzzer
	mkdir -p poppler/build-cov
	clang++ -g -fsanitize=fuzzer -fprofile-arcs -ftest-coverage -std=c++14 -D_GNU_SOURCE -Ipoppler/repo/cpp -Ipoppler/repo/build-cov/cpp \
		poppler/repo/cpp/tests/fuzzing/pdf_fuzzer.cc -o poppler/build-cov/pdf_fuzzer_cov \
		poppler/repo/build-cov/cpp/libpoppler-cpp.a \
		poppler/repo/build-cov/libpoppler.a \
		poppler/install-cov/lib/libfreetype.a \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		-ljpeg -lz -lopenjp2 -lpng -ltiff -llcms2 -lm -lpthread -pthread
	printf 'POPPLER_REF=%s\nFREETYPE_REF=%s\n' '$(POPPLER_REF)' '$(FREETYPE_REF)' > poppler/build-cov/source-refs


poppler-all: poppler poppler-afl poppler-wllvm poppler-profiling poppler-cmplog poppler-cov
poppler-clean-all:
	rm -rf poppler /tmp/pdf_fuzzer

# LibTIFF Base Setup
libtiff:
	@echo "=== Cloning and preparing LibTIFF ==="
	rm -rf libtiff
	git clone https://gitlab.com/libtiff/libtiff.git libtiff
	cd libtiff && \
		git checkout b40dc6ec4997d4d2e62152fe62dac20c3a23f557 && \
		./autogen.sh
	@echo "=== Fetching seed corpus from Magma v1.2 ==="
	mkdir -p libtiff/seed_corpus/tiff_read_rgba_fuzzer
	rm -rf libtiff/magma_corpus
	git clone --depth 1 --branch $(MAGMA_REF) --filter=blob:none $(MAGMA_REPO) libtiff/magma_corpus
	cd libtiff/magma_corpus && \
		git sparse-checkout init --cone && \
		git sparse-checkout set targets/libtiff/corpus/tiff_read_rgba_fuzzer && \
		git checkout && \
		cp targets/libtiff/corpus/tiff_read_rgba_fuzzer/* ../seed_corpus/tiff_read_rgba_fuzzer/
	rm -rf libtiff/magma_corpus

# LibTIFF with AFL++ Instrumentation
libtiff-afl: libtiff
	@echo "=== Building LibTIFF with AFL instrumentation ==="
	cd libtiff && \
		rm -rf build-afl && mkdir -p build-afl && cd build-afl && \
		CC=afl-clang-fast CXX=afl-clang-fast++ \
		../configure --disable-shared --prefix=$$(pwd)/install --disable-zstd --disable-webp --disable-pixarlog --disable-libdeflate && \
		make clean && make -j$$(nproc) && make install && \
		afl-clang-fast++ -std=c++11 -Iinstall/include \
			../contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc -o tiff_read_rgba_fuzzer \
			$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
			install/lib/libtiffxx.a install/lib/libtiff.a \
			-lz -ljpeg -ljbig -Wl,-Bstatic -llzma -Wl,-Bdynamic -lm

# LibTIFF CmpLog
libtiff-cmplog: libtiff
	@echo "=== Building LibTIFF with CmpLog instrumentation === "
	cd libtiff && \
		rm -rf build-cmplog && mkdir -p build-cmplog && cd build-cmplog && \
		export AFL_LLVM_CMPLOG=1 && \
		CC=afl-clang-fast CXX=afl-clang-fast++ \
		../configure --disable-shared --prefix=$$(pwd)/install --disable-zstd --disable-webp --disable-pixarlog --disable-libdeflate && \
		make clean && make -j$$(nproc) && make install && \
		AFL_LLVM_CMPLOG=1 afl-clang-fast++ -std=c++11 -Iinstall/include \
			../contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc -o tiff_read_rgba_fuzzer \
			$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
			install/lib/libtiffxx.a install/lib/libtiff.a \
			-lz -ljpeg -ljbig -Wl,-Bstatic -llzma -Wl,-Bdynamic -lm && \
		unset AFL_LLVM_CMPLOG

# LibTIFF WLLVM
libtiff-wllvm: libtiff
	@echo "=== Building LibTIFF with WLLVM === "
	cd libtiff && \
		rm -rf build-wllvm && mkdir -p build-wllvm && cd build-wllvm && \
		export LLVM_COMPILER=clang && \
		CC=wllvm CXX=wllvm++ \
		../configure --disable-shared --prefix=$$(pwd)/install --disable-zstd --disable-webp --disable-pixarlog --disable-libdeflate && \
		make clean && make -j$$(nproc) && make install && \
		wllvm -g -fsanitize=fuzzer -std=c++11 -Iinstall/include \
			../contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc -o tiff_read_rgba_fuzzer \
			$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
			install/lib/libtiffxx.a install/lib/libtiff.a \
			-lz -ljpeg -ljbig -Wl,-Bstatic -llzma -Wl,-Bdynamic -lm && \
		extract-bc tiff_read_rgba_fuzzer && \
		opt-15 -passes=dot-callgraph -disable-output < tiff_read_rgba_fuzzer.bc && \
		mv '<stdin>.callgraph.dot' tiff_read_rgba_fuzzer.dot

# LibTIFF Profiling
libtiff-profiling: libtiff
	@echo "=== Building LibTIFF with Profiling === "
	cd libtiff && \
		rm -rf build-profiling && mkdir -p build-profiling && cd build-profiling && \
		rm -rf /tmp/tiff_read_rgba_fuzzer && mkdir -p /tmp/tiff_read_rgba_fuzzer && \
		HF_BINARY=tiff_read_rgba_fuzzer HORSEFUZZ_CG_PROFILING=1 \
		CC=afl-clang-fast CXX=afl-clang-fast++ \
		../configure --disable-shared --prefix=$$(pwd)/install --disable-zstd --disable-webp --disable-pixarlog --disable-libdeflate && \
		HF_BINARY=tiff_read_rgba_fuzzer HORSEFUZZ_CG_PROFILING=1 make clean && \
		HF_BINARY=tiff_read_rgba_fuzzer HORSEFUZZ_CG_PROFILING=1 make -j$$(nproc) && \
		HF_BINARY=tiff_read_rgba_fuzzer HORSEFUZZ_CG_PROFILING=1 make install && \
		HF_BINARY=tiff_read_rgba_fuzzer HORSEFUZZ_CG_PROFILING=1 \
		afl-clang-fast++ -std=c++11 -Iinstall/include \
			../contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc -o tiff_read_rgba_fuzzer \
			$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
			install/lib/libtiffxx.a install/lib/libtiff.a \
			-lz -ljpeg -ljbig -Wl,-Bstatic -llzma -Wl,-Bdynamic -lm && \
		cp -r /tmp/tiff_read_rgba_fuzzer tiff_read_rgba_fuzzer-profiling-logs

# LibTIFF Coverage
libtiff-cov: libtiff
	@echo "=== Building LibTIFF with Coverage === "
	cd libtiff && \
		rm -rf build-cov && mkdir -p build-cov && cd build-cov && \
		export LLVM_COMPILER=clang && \
		CC=clang CXX=clang++ CFLAGS="-g -fprofile-arcs -ftest-coverage" CXXFLAGS="-g -fprofile-arcs -ftest-coverage" \
		../configure --disable-shared --prefix=$$(pwd)/install --disable-zstd --disable-webp --disable-pixarlog --disable-libdeflate && \
		make clean && make -j$$(nproc) && make install && \
		clang -g -fsanitize=fuzzer -fprofile-arcs -ftest-coverage -std=c++11 -Iinstall/include \
			../contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc -o tiff_read_rgba_fuzzer \
			$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
			install/lib/libtiffxx.a install/lib/libtiff.a \
			-lz -ljpeg -ljbig -Wl,-Bstatic -llzma -Wl,-Bdynamic -lm

libtiff-all: libtiff-afl libtiff-cmplog libtiff-wllvm libtiff-profiling libtiff-cov
libtiff-clean-all:
	rm -rf libtiff /tmp/tiff_read_rgba_fuzzer

# Lua Base Setup
lua:
	@echo "=== Cloning and preparing Lua ==="
	rm -rf lua
	git clone --no-checkout https://github.com/lua/lua.git lua
	cd lua && \
		git checkout 40b76de2d77e66b70a9d4bf989c3f5340919973f
	@echo "=== Fetching seed corpus from Magma v1.2 ==="
	mkdir -p lua/seed_corpus
	rm -rf lua/magma_corpus
	git clone --depth 1 --branch $(MAGMA_REF) --filter=blob:none $(MAGMA_REPO) lua/magma_corpus
	cd lua/magma_corpus && \
		git sparse-checkout init --cone && \
		git sparse-checkout set targets/lua/corpus/lua && \
		git checkout && \
		cp targets/lua/corpus/lua/* ../seed_corpus/
	rm -rf lua/magma_corpus

# Lua with AFL++ Instrumentation
lua-afl: lua
	@echo "=== Building Lua with AFL instrumentation ==="
	rm -rf lua/build-afl && mkdir -p lua/build-afl
	cp -al lua/* lua/build-afl/ || true
	cd lua/build-afl && \
		make -j$$(nproc) clean && \
		make -j$$(nproc) CC=afl-clang-fast MYCFLAGS="-DLUA_USE_LINUX" liblua.a && \
		make -j$$(nproc) CC=afl-clang-fast MYCFLAGS="-DLUA_USE_LINUX" MYLIBS="-ldl" lua && \
		cp $(OSS_DIR)/lua_setup/fuzz_lua.c . && \
		afl-clang-fast -DLUA_USE_LINUX -c fuzz_lua.c -o fuzz_lua.o && \
		afl-clang-fast++ fuzz_lua.o -o fuzz_lua \
			$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
			liblua.a -lm -ldl

# Lua CmpLog
lua-cmplog: lua
	@echo "=== Building Lua with CmpLog instrumentation === "
	rm -rf lua/build-cmplog && mkdir -p lua/build-cmplog
	cp -al lua/* lua/build-cmplog/ || true
	cd lua/build-cmplog && \
		make -j$$(nproc) clean && \
		export AFL_LLVM_CMPLOG=1 && \
		make -j$$(nproc) CC=afl-clang-fast MYCFLAGS="-DLUA_USE_LINUX" liblua.a && \
		make -j$$(nproc) CC=afl-clang-fast MYCFLAGS="-DLUA_USE_LINUX" MYLIBS="-ldl" lua && \
		cp $(OSS_DIR)/lua_setup/fuzz_lua.c . && \
		AFL_LLVM_CMPLOG=1 afl-clang-fast -DLUA_USE_LINUX -c fuzz_lua.c -o fuzz_lua.o && \
		AFL_LLVM_CMPLOG=1 afl-clang-fast++ fuzz_lua.o -o fuzz_lua \
			$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
			liblua.a -lm -ldl && \
		unset AFL_LLVM_CMPLOG

# Lua WLLVM
lua-wllvm: lua
	@echo "=== Building Lua with WLLVM === "
	rm -rf lua/build-wllvm && mkdir -p lua/build-wllvm
	cp -al lua/* lua/build-wllvm/ || true
	cd lua/build-wllvm && \
		make -j$$(nproc) clean && \
		export LLVM_COMPILER=clang && \
		make -j$$(nproc) CC=wllvm MYCFLAGS="-DLUA_USE_LINUX" liblua.a && \
		make -j$$(nproc) CC=wllvm MYCFLAGS="-DLUA_USE_LINUX" MYLIBS="-ldl" lua && \
		cp $(OSS_DIR)/lua_setup/fuzz_lua.c . && \
		wllvm -g -fsanitize=fuzzer -DLUA_USE_LINUX -c fuzz_lua.c -o fuzz_lua.o && \
		wllvm++ -g -fsanitize=fuzzer fuzz_lua.o -o fuzz_lua \
			$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
			liblua.a -lm -ldl && \
		extract-bc fuzz_lua && \
		opt-15 -passes=dot-callgraph -disable-output < fuzz_lua.bc && \
		mv '<stdin>.callgraph.dot' fuzz_lua.dot

# Lua Profiling
lua-profiling: lua
	@echo "=== Building Lua with Profiling === "
	rm -rf lua/build-profiling && mkdir -p lua/build-profiling
	cp -al lua/* lua/build-profiling/ || true
	cd lua/build-profiling && \
		make -j$$(nproc) clean && \
		rm -rf /tmp/fuzz_lua && mkdir -p /tmp/fuzz_lua && \
		HF_BINARY=fuzz_lua HORSEFUZZ_CG_PROFILING=1 \
		make -j$$(nproc) CC=afl-clang-fast MYCFLAGS="-DLUA_USE_LINUX" liblua.a && \
		HF_BINARY=fuzz_lua HORSEFUZZ_CG_PROFILING=1 \
		make -j$$(nproc) CC=afl-clang-fast MYCFLAGS="-DLUA_USE_LINUX" MYLIBS="-ldl" lua && \
		cp $(OSS_DIR)/lua_setup/fuzz_lua.c . && \
		HF_BINARY=fuzz_lua HORSEFUZZ_CG_PROFILING=1 \
		afl-clang-fast -DLUA_USE_LINUX -c fuzz_lua.c -o fuzz_lua.o && \
		HF_BINARY=fuzz_lua HORSEFUZZ_CG_PROFILING=1 \
		afl-clang-fast++ fuzz_lua.o -o fuzz_lua \
			$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
			liblua.a -lm -ldl && \
		cp -r /tmp/fuzz_lua fuzz_lua-profiling-logs

# Lua Coverage
lua-cov: lua
	@echo "=== Building Lua with Coverage === "
	rm -rf lua/build-cov && mkdir -p lua/build-cov
	cp -al lua/* lua/build-cov/ || true
	cd lua/build-cov && \
		make -j$$(nproc) clean && \
		export LLVM_COMPILER=clang && \
		make -j$$(nproc) CC=clang MYCFLAGS="-g --coverage -DLUA_USE_LINUX" liblua.a && \
		make -j$$(nproc) CC=clang MYCFLAGS="-g --coverage -DLUA_USE_LINUX" MYLIBS="-ldl --coverage" lua && \
		cp $(OSS_DIR)/lua_setup/fuzz_lua.c . && \
		clang -g -fsanitize=fuzzer --coverage -DLUA_USE_LINUX -c fuzz_lua.c -o fuzz_lua.o && \
		clang -g -fsanitize=fuzzer --coverage fuzz_lua.o -o fuzz_lua \
			$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
			liblua.a -lm -ldl

lua-all: lua-afl lua-cmplog lua-wllvm lua-profiling lua-cov
lua-clean-all:
	rm -rf lua /tmp/fuzz_lua

# libsndfile Base Setup
libsndfile-prerequisites:
	@missing="$$(for p in python3 autoconf automake libtool pkg-config; do dpkg-query -W -f='$${Status}' "$$p" 2>/dev/null | grep -q 'ok installed' || printf '%s ' "$$p"; done)"; \
	if [ -n "$$missing" ]; then \
		if command -v sudo >/dev/null 2>&1; then sudo apt-get install -y $$missing; \
		elif [ "$$(id -u)" = 0 ]; then apt-get install -y $$missing; \
		else echo "error: missing libsndfile packages: $$missing" >&2; exit 1; fi; \
	fi

libsndfile: libsndfile-prerequisites
	@echo "=== Cloning and preparing libsndfile ==="
	rm -rf libsndfile
	git clone --no-checkout https://github.com/libsndfile/libsndfile.git libsndfile
	cd libsndfile && \
		git checkout 68f6c16fe1407eff4cdde158566694c3ed666c2f && \
		sed -i 's/AX_COMPILER_VERSION/# AX_COMPILER_VERSION (disabled for clang 15 compatibility) #/g' configure.ac
	@echo "=== Fetching seed corpus from Magma v1.2 ==="
	rm -rf libsndfile/magma_corpus

# Engine-specific builds must coexist.  Depending directly on the phony
# libsndfile setup target would reclone the source tree and erase artifacts
# produced for another engine every time either engine is rebuilt.
libsndfile/seed_corpus:
	$(MAKE) -f $(OSS_DIR)/Makefile libsndfile
	mkdir -p libsndfile/seed_corpus
	rm -rf libsndfile/magma_corpus
	git clone --depth 1 --branch $(MAGMA_REF) --filter=blob:none $(MAGMA_REPO) libsndfile/magma_corpus
	cd libsndfile/magma_corpus && \
		git sparse-checkout init --cone && \
		git sparse-checkout set targets/libsndfile/corpus/sndfile_fuzzer && \
		git checkout && \
		cp targets/libsndfile/corpus/sndfile_fuzzer/* ../seed_corpus/
	rm -rf libsndfile/magma_corpus

# libsndfile with AFL++ Instrumentation
libsndfile-afl: libsndfile/seed_corpus
	@echo "=== Building libsndfile with AFL instrumentation ==="
	rm -rf libsndfile/build-afl && mkdir -p libsndfile/build-afl
	find libsndfile -maxdepth 1 ! -name "libsndfile" ! -name "build-*" ! -name "seed_corpus" -exec cp -al {} libsndfile/build-afl/ \;
	cd libsndfile/build-afl && \
		autoreconf -vif && \
		CC=afl-clang-fast CXX=afl-clang-fast++ ./configure --disable-shared --enable-ossfuzzers && \
		make -j$$(nproc) clean && \
		make -j$$(nproc) CC=afl-clang-fast CXX=afl-clang-fast++ ossfuzz/sndfile_fuzzer ossfuzz/sndfile_alt_fuzzer && \
		cp ossfuzz/sndfile_fuzzer ossfuzz/sndfile_alt_fuzzer .

# libsndfile CmpLog
libsndfile-cmplog: libsndfile/seed_corpus
	@echo "=== Building libsndfile with CmpLog instrumentation === "
	rm -rf libsndfile/build-cmplog && mkdir -p libsndfile/build-cmplog
	find libsndfile -maxdepth 1 ! -name "libsndfile" ! -name "build-*" ! -name "seed_corpus" -exec cp -al {} libsndfile/build-cmplog/ \;
	cd libsndfile/build-cmplog && \
		autoreconf -vif && \
		export AFL_LLVM_CMPLOG=1 && \
		CC=afl-clang-fast CXX=afl-clang-fast++ ./configure --disable-shared --enable-ossfuzzers && \
		make -j$$(nproc) clean && \
		make -j$$(nproc) CC=afl-clang-fast CXX=afl-clang-fast++ ossfuzz/sndfile_fuzzer ossfuzz/sndfile_alt_fuzzer && \
		cp ossfuzz/sndfile_fuzzer ossfuzz/sndfile_alt_fuzzer .

# libsndfile WLLVM
libsndfile-wllvm: libsndfile/seed_corpus
	@echo "=== Building libsndfile with WLLVM === "
	rm -rf libsndfile/build-wllvm && mkdir -p libsndfile/build-wllvm
	find libsndfile -maxdepth 1 ! -name "libsndfile" ! -name "build-*" ! -name "seed_corpus" -exec cp -al {} libsndfile/build-wllvm/ \;
	cd libsndfile/build-wllvm && \
		autoreconf -vif && \
		export LLVM_COMPILER=clang && \
		CC=wllvm CXX=wllvm++ ./configure --disable-shared --enable-ossfuzzers && \
		make -j$$(nproc) clean && \
		make -j$$(nproc) CC=wllvm CXX=wllvm++ ossfuzz/sndfile_fuzzer && \
		cp ossfuzz/sndfile_fuzzer . && \
		extract-bc sndfile_fuzzer && \
		opt-15 -passes=dot-callgraph -disable-output < sndfile_fuzzer.bc && \
		mv '<stdin>.callgraph.dot' sndfile_fuzzer.dot

# libsndfile Profiling
libsndfile-profiling: libsndfile/seed_corpus
	@echo "=== Building libsndfile with Profiling === "
	rm -rf libsndfile/build-profiling && mkdir -p libsndfile/build-profiling
	find libsndfile -maxdepth 1 ! -name "libsndfile" ! -name "build-*" ! -name "seed_corpus" -exec cp -al {} libsndfile/build-profiling/ \;
	cd libsndfile/build-profiling && \
		autoreconf -vif && \
		rm -rf /tmp/sndfile_fuzzer && mkdir -p /tmp/sndfile_fuzzer && \
		HF_BINARY=sndfile_fuzzer HORSEFUZZ_CG_PROFILING=1 \
		CC=afl-clang-fast CXX=afl-clang-fast++ ./configure --disable-shared --enable-ossfuzzers && \
		make -j$$(nproc) clean && \
		HF_BINARY=sndfile_fuzzer HORSEFUZZ_CG_PROFILING=1 \
		make -j$$(nproc) CC=afl-clang-fast CXX=afl-clang-fast++ ossfuzz/sndfile_fuzzer && \
		cp ossfuzz/sndfile_fuzzer . && \
		cp -r /tmp/sndfile_fuzzer sndfile_fuzzer-profiling-logs

# libsndfile Coverage
libsndfile-cov: libsndfile/seed_corpus
	@echo "=== Building libsndfile with Coverage === "
	rm -rf libsndfile/build-cov && mkdir -p libsndfile/build-cov
	find libsndfile -maxdepth 1 ! -name "libsndfile" ! -name "build-*" ! -name "seed_corpus" -exec cp -al {} libsndfile/build-cov/ \;
	cd libsndfile/build-cov && \
		autoreconf -vif && \
		export LLVM_COMPILER=clang && \
		CC=clang CXX=clang++ CFLAGS="-g --coverage" CXXFLAGS="-g --coverage" LDFLAGS="--coverage" \
		./configure --disable-shared --enable-ossfuzzers && \
		make -j$$(nproc) clean && \
		make -j$$(nproc) CC=clang CXX=clang++ ossfuzz/sndfile_fuzzer && \
		cp ossfuzz/sndfile_fuzzer .

libsndfile-all: libsndfile-afl libsndfile-cmplog libsndfile-wllvm libsndfile-profiling libsndfile-cov
libsndfile-clean-all:
	rm -rf libsndfile /tmp/sndfile_fuzzer

# Kraken / AlphaFuzz builds for selected OSS targets.
#
# These targets build runnable OSS-Fuzz harness binaries with Kraken's
# compile-time instrumentation. The existing AFL++ libFuzzer driver supplies
# the LLVMFuzzerTestOneInput entrypoint wrapper used by these harnesses.

.PHONY: kraken-check libpng-kraken sqlite3-kraken harfbuzz-kraken libxslt-kraken libxml2-kraken \
	bloaty-kraken freetype2-kraken libpcap-kraken libaom-kraken libjpeg-turbo-kraken \
	lcms-kraken mbedtls-kraken php-kraken openssl-kraken poppler-kraken lua-kraken \
	libsndfile-kraken libtiff-kraken

kraken-check:
	test -x "$(ALPHA_CLANG)"
	test -x "$(ALPHA_CLANGXX)"
	test -f "$(KRAKEN_DRIVER)"

libpng-kraken: libpng kraken-check
	cd libpng && \
	mkdir -p build-kraken && cd build-kraken && \
	ALPHA_PATH=$(KRAKEN) CC=$(ALPHA_CLANG) CXX=$(ALPHA_CLANGXX) ../configure --disable-shared && \
	ALPHA_PATH=$(KRAKEN) make clean all -j$$(nproc) && \
	ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANGXX) -std=c++11 -I. -I.. \
		../contrib/oss-fuzz/libpng_read_fuzzer.cc \
		$(KRAKEN_DRIVER) \
		-o libpng_read_fuzzer \
		.libs/libpng16.a \
		-lz -lm -lstdc++

sqlite3-kraken: sqlite3 kraken-check
	@echo "=== Building SQLite3 with Kraken instrumentation ==="
	cd sqlite3 && \
	mkdir -p build-kraken && cd build-kraken && \
		CC_FOR_BUILD=$(SQLITE3_CC_FOR_BUILD) PATH=$(SQLITE3_BUILD_PATH) ALPHA_PATH=$(KRAKEN) CC=$(ALPHA_CLANG) CXX=$(ALPHA_CLANGXX) \
		CFLAGS="$(SQLITE3_FUZZ_CFLAGS)" \
		../configure --shared=0 && \
		CC_FOR_BUILD=$(SQLITE3_CC_FOR_BUILD) PATH=$(SQLITE3_BUILD_PATH) ALPHA_PATH=$(KRAKEN) make -j$$(nproc) && \
		CC_FOR_BUILD=$(SQLITE3_CC_FOR_BUILD) PATH=$(SQLITE3_BUILD_PATH) ALPHA_PATH=$(KRAKEN) make sqlite3.c && \
		ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANG) $(SQLITE3_FUZZ_CFLAGS) -I. -c ../test/ossfuzz.c -o ossfuzz.o && \
		ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANGXX) ossfuzz.o $(KRAKEN_DRIVER) -o ossfuzz sqlite3.o -pthread -ldl -lz

harfbuzz-kraken: harfbuzz kraken-check
	cd harfbuzz && \
	mkdir -p build-kraken && cd build-kraken && \
	ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANGXX) -std=c++11 -c $(KRAKEN_DRIVER) -o kraken_driver.o && \
	CC=clang CXX=clang++ \
	CFLAGS="$(HARFBUZZ_FUZZ_CFLAGS)" \
	CXXFLAGS="$(HARFBUZZ_FUZZ_CXXFLAGS)" \
	meson .. --default-library=static --wrap-mode=nodownload \
		-Dexperimental_api=true \
		-Dfuzzer_ldflags="$$(pwd)/kraken_driver.o" && \
	sed -i \
		-e 's#^ command = clang # command = $(ALPHA_CLANG) #' \
		-e 's#^ command = clang++ # command = $(ALPHA_CLANGXX) #' \
		build.ninja && \
	ninja -t clean test/fuzzing/hb-shape-fuzzer >/dev/null && \
	ALPHA_PATH=$(KRAKEN) ninja -v -j$$(nproc) test/fuzzing/hb-shape-fuzzer && \
	mv test/fuzzing/hb-shape-fuzzer .

libxslt-kraken: IS_KRAKEN=1
libxslt-kraken: libxslt kraken-check
	cd libxml2-xslt && \
	mkdir -p build-kraken && cd build-kraken && \
	cp -r ../include . && \
	ALPHA_PATH=$(KRAKEN) CC=$(ALPHA_CLANG) CXX=$(ALPHA_CLANGXX) ../configure \
		--disable-shared --without-c14n --without-push --without-python \
		--without-reader --without-regexps --without-sax1 --without-schemas \
		--without-schematron --without-valid --without-writer --without-zlib \
		--without-lzma && \
	ALPHA_PATH=$(KRAKEN) make -j$$(nproc) && cd ../../libxslt && \
	mkdir -p build-kraken && cd build-kraken && \
	ALPHA_PATH=$(KRAKEN) CC=$(ALPHA_CLANG) CXX=$(ALPHA_CLANGXX) ../configure \
		--with-libxml-src=$(WORKDIR)/subjects/libxml2-xslt/build-kraken \
		--disable-shared --without-python --without-crypto --without-debug \
		--without-debugger --without-profiler && \
	ALPHA_PATH=$(KRAKEN) make -j$$(nproc) && cd tests/fuzz && \
	mkdir -p seed/xpath && make seed/xpath.stamp fuzz.o xpath.o && \
	ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANGXX) -std=c++11 xpath.o fuzz.o $(KRAKEN_DRIVER) -o ../../xpath \
		../../libexslt/.libs/libexslt.a ../../libxslt/.libs/libxslt.a \
		$(WORKDIR)/subjects/libxml2-xslt/build-kraken/.libs/libxml2.a \
		-pthread -lz -lm -ldl

libxml2-kraken: IS_KRAKEN=1
libxml2-kraken: libxml2 kraken-check
	cd libxml2 && \
	git fetch origin 66453240c94b5cbd3e9ae9b32016fdafb13cdf18 && \
	git checkout --detach 66453240c94b5cbd3e9ae9b32016fdafb13cdf18 && \
	mkdir -p build-kraken && cd build-kraken && \
	ALPHA_PATH=$(KRAKEN) CC=$(ALPHA_CLANG) CXX=$(ALPHA_CLANGXX) ../configure --disable-shared --without-debug --without-http --without-python --with-zlib --with-lzma && \
	ALPHA_PATH=$(KRAKEN) make -j$$(nproc) && \
	ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANG) -I../include -I../build-kraken/include -c ../fuzz/fuzz.c -o ../fuzz/fuzz.o && \
	ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANG) -I../include -I../build-kraken/include -c ../fuzz/xml.c -o ../fuzz/xml.o && \
	ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANGXX) \
		../fuzz/xml.o ../fuzz/fuzz.o \
		$(KRAKEN_DRIVER) \
		-o fuzz-xml \
		.libs/libxml2.a \
		-Wl,-Bstatic -lz -llzma -Wl,-Bdynamic -lm -pthread && \
	ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANG) -I../include -I. -I../build-kraken/include -c ../fuzz/genSeed.c -o ../fuzz/genSeed.o && \
	ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANGXX) ../fuzz/genSeed.o ../fuzz/fuzz.o \
	    -o ../fuzz/genSeed \
	    -I../include -I. -I../build-kraken/include \
	    -L. -L../build-kraken/.libs -lxml2 -lz -llzma -lm -pthread && \
	mkdir -p seed/xml && \
	../fuzz/genSeed xml \
		'../test/*' \
		'../test/errors/*.xml' \
		'../test/errors10/*.xml' \
		'../test/namespaces/*' \
		'../test/recurse/*.xml' \
		'../test/SVG/*.xml' \
		'../test/valid/*.xml' \
		'../test/VC/*' \
		'../test/VCM/*' \
		'../test/XInclude/docs/*' \
		'../test/XInclude/without-reader/*' \
		'../test/xmlid/*' && \
	touch seed/xml.stamp && \
	cp ../fuzz/xml.dict seed/

bloaty-kraken: IS_KRAKEN=1
bloaty-kraken: bloaty kraken-check
	cd bloaty && \
	rm -rf build-kraken && mkdir -p build-kraken && cd build-kraken && \
	ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANGXX) -std=c++11 -c $(KRAKEN_DRIVER) -o kraken_driver.o && \
	ALPHA_PATH=$(KRAKEN) ar rcs libkraken_driver.a kraken_driver.o && \
	ALPHA_PATH=$(KRAKEN) CC=$(ALPHA_CLANG) CXX=$(ALPHA_CLANGXX) \
	LIB_FUZZING_ENGINE=$$(pwd)/libkraken_driver.a \
	cmake -G Ninja -DBUILD_TESTING=false .. && \
	ALPHA_PATH=$(KRAKEN) ninja -j$$(nproc) && \
	mv fuzz_target bloaty_fuzz_target

freetype2-kraken: IS_KRAKEN=1
freetype2-kraken: freetype2 kraken-check
	cd libarchive-3.4.3 && \
	rm -rf build-kraken && mkdir -p build-kraken && cd build-kraken && \
	ALPHA_PATH=$(KRAKEN) CC=$(ALPHA_CLANG) CXX=$(ALPHA_CLANGXX) \
	../configure --disable-shared --prefix=$$(pwd)/install && \
	ALPHA_PATH=$(KRAKEN) make clean && ALPHA_PATH=$(KRAKEN) make -j$$(nproc) && ALPHA_PATH=$(KRAKEN) make install
	cd freetype2 && \
	rm -rf build-kraken && mkdir -p build-kraken && cd build-kraken && \
	ALPHA_PATH=$(KRAKEN) CC=$(ALPHA_CLANG) CXX=$(ALPHA_CLANGXX) \
	../configure --prefix=$$(pwd)/install --with-harfbuzz=no --with-bzip2=no --with-png=no --without-zlib --with-brotli=no && \
	ALPHA_PATH=$(KRAKEN) make clean && ALPHA_PATH=$(KRAKEN) make all -j$$(nproc) && ALPHA_PATH=$(KRAKEN) make install && \
	ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANGXX) -std=c++11 -I ../include -I .. \
		-I $$(pwd)/../../libarchive-3.4.3/build-kraken/install/include \
		../src/tools/ftfuzzer/ftfuzzer.cc \
		$(KRAKEN_DRIVER) \
		$$(pwd)/install/lib/libfreetype.a \
		$$(pwd)/../../libarchive-3.4.3/build-kraken/install/lib/libarchive.a \
		-o ftfuzzer

libpcap-kraken: libpcap-prepare kraken-check
	cd libpcap && \
	rm -rf build-kraken && mkdir -p build-kraken && cd build-kraken && \
	ALPHA_PATH=$(KRAKEN) CC=$(ALPHA_CLANG) CXX=$(ALPHA_CLANGXX) cmake -DDISABLE_DBUS=ON .. && \
	ALPHA_PATH=$(KRAKEN) make clean all -j$$(nproc) && \
	ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANG) -I.. -c ../testprogs/fuzz/fuzz_both.c -o fuzz_both.o && \
	ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANGXX) fuzz_both.o $(KRAKEN_DRIVER) -o libpcap_fuzz_both libpcap.a

libaom-kraken: libaom kraken-check
	cd libaom && \
	rm -rf build-kraken && mkdir -p build-kraken && cd build-kraken && \
	ALPHA_PATH=$(KRAKEN) CC=$(ALPHA_CLANG) CXX=$(ALPHA_CLANGXX) \
	cmake .. -DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_C_FLAGS_RELEASE='-O3 -g' \
		-DCMAKE_CXX_FLAGS_RELEASE='-O3 -g' \
		-DCONFIG_PIC=1 \
		-DCONFIG_LOWBITDEPTH=1 \
		-DCONFIG_AV1_ENCODER=0 \
		-DENABLE_EXAMPLES=0 \
		-DENABLE_DOCS=0 \
		-DENABLE_TESTS=0 \
		-DCONFIG_SIZE_LIMIT=1 \
		-DDECODE_HEIGHT_LIMIT=12288 \
		-DDECODE_WIDTH_LIMIT=12288 \
		-DAOM_EXTRA_C_FLAGS="-DAOM_MAX_ALLOCABLE_MEMORY=1073741824 -DDO_RANGE_CHECK_CLAMP=1" \
		-DENABLE_TOOLS=0 \
		-DAOM_EXTRA_CXX_FLAGS="-DAOM_MAX_ALLOCABLE_MEMORY=1073741824 -DDO_RANGE_CHECK_CLAMP=1" && \
	ALPHA_PATH=$(KRAKEN) make -j$$(nproc) && \
	ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANGXX) -std=c++11 \
		-I../ \
		-I. \
		-Ibuild-kraken \
		-Wl,--start-group \
		$(KRAKEN_DRIVER) \
		../examples/av1_dec_fuzzer.cc \
		-o av1_dec_fuzzer \
		libaom.a -Wl,--end-group -pthread -lm

libjpeg-turbo-kraken: libjpeg-turbo-decompress-corpus kraken-check
	cd libjpeg-turbo && \
	rm -rf build-kraken && mkdir -p build-kraken && cd build-kraken && \
	ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANGXX) -std=c++11 -c $(KRAKEN_DRIVER) -o kraken_driver.o && \
	ALPHA_PATH=$(KRAKEN) ar rcs libkraken_driver.a kraken_driver.o && \
	ALPHA_PATH=$(KRAKEN) CC=$(ALPHA_CLANG) CXX=$(ALPHA_CLANGXX) cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo \
		-DENABLE_STATIC=1 \
		-DENABLE_SHARED=0 \
		-DCMAKE_C_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" \
		-DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" \
		-DCMAKE_INSTALL_PREFIX=$$(pwd)/install \
		-DWITH_FUZZ=1 \
		-DFUZZ_BINDIR=$$(pwd) \
		-DFUZZ_LIBRARY=$$(pwd)/libkraken_driver.a && \
	ALPHA_PATH=$(KRAKEN) make clean all -j$$(nproc) && \
	ALPHA_PATH=$(KRAKEN) make install

lcms-kraken: lcms kraken-check
	cd lcms && \
	rm -rf build-kraken && mkdir -p build-kraken && cd build-kraken && \
	ALPHA_PATH=$(KRAKEN) CC=$(ALPHA_CLANG) CXX=$(ALPHA_CLANGXX) ../configure --enable-shared=no && \
	ALPHA_PATH=$(KRAKEN) make clean all -j$$(nproc) && \
	ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANG) -c -I../include ../oss-fuzz/cms_transform_fuzzer.c -o cms_transform_fuzzer.o && \
	ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANGXX) cms_transform_fuzzer.o $(KRAKEN_DRIVER) -o cms_transform_fuzzer \
		src/.libs/liblcms2.a -lz

mbedtls-kraken: IS_KRAKEN=1
mbedtls-kraken: mbedtls kraken-check mbedtls-deps
	cd mbedtls && \
	rm -rf build-kraken && mkdir -p build-kraken && cd build-kraken && \
	ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANGXX) -std=c++11 -c $(KRAKEN_DRIVER) -o kraken_driver.o && \
	ALPHA_PATH=$(KRAKEN) ar rcs libkraken_driver.a kraken_driver.o && \
	ALPHA_PATH=$(KRAKEN) CC=$(ALPHA_CLANG) CXX=$(ALPHA_CLANGXX) \
	FUZZER_LIB=$$(pwd)/libkraken_driver.a LIB_FUZZING_ENGINE=$$(pwd)/libkraken_driver.a \
	cmake .. \
		-DENABLE_TESTING=OFF && \
	ALPHA_PATH=$(KRAKEN) make -j$$(nproc) && \
	mv programs/fuzz/fuzz_dtlsclient . && \
	cd .. && \
	if [ -f corpus/dtlsclient ]; then \
		rm -rf corpus/dtlsclient_dir; \
		mkdir -p corpus/dtlsclient_dir; \
		mv corpus/dtlsclient corpus/dtlsclient_dir/seed; \
		mv corpus/dtlsclient_dir corpus/dtlsclient; \
	fi

php-kraken: php-checkout kraken-check
	cd php-src && rm -rf build-kraken && mkdir build-kraken && cd build-kraken && \
	ALPHA_PATH=$(KRAKEN) LIB_FUZZING_ENGINE="$(KRAKEN_DRIVER)" FUZZING_CC="$(ALPHA_CLANGXX)" \
	CC=$(ALPHA_CLANG) CXX=$(ALPHA_CLANGXX) \
	CFLAGS="-fno-sanitize=object-size -DPROFITABILITY_CHECKS=0" \
	CXXFLAGS="-fno-sanitize=object-size -DPROFITABILITY_CHECKS=0" ../configure \
		--disable-all --enable-debug-assertions --enable-option-checking=fatal \
		--enable-fuzzer --enable-exif --without-pcre-jit --disable-phpdbg \
		--disable-cgi --enable-pic && \
	ALPHA_PATH=$(KRAKEN) LIB_FUZZING_ENGINE="$(KRAKEN_DRIVER)" FUZZING_CC="$(ALPHA_CLANGXX)" \
	CC=$(ALPHA_CLANG) CXX=$(ALPHA_CLANGXX) make -j$$(nproc) libs sapi/cli/php && \
	ALPHA_PATH=$(KRAKEN) LIB_FUZZING_ENGINE="$(KRAKEN_DRIVER)" FUZZING_CC="$(ALPHA_CLANGXX)" \
	CC=$(ALPHA_CLANG) CXX=$(ALPHA_CLANGXX) make -j$$(nproc) PHP_FUZZER_BINARIES='sapi/fuzzer/php-fuzz-parser' && \
	mv sapi/fuzzer/php-fuzz-parser .

openssl-kraken: openssl kraken-check
	cd openssl && rm -rf build-kraken && mkdir build-kraken && \
	ALPHA_PATH=$(KRAKEN) CC=$(ALPHA_CLANG) CXX=$(ALPHA_CLANGXX) \
	./config --debug enable-fuzz-libfuzzer disable-tests -DPEDANTIC \
		-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION no-shared no-module \
		enable-tls1_3 enable-rc5 enable-md2 enable-ec_nistp_64_gcc_128 \
		enable-nextprotoneg enable-weak-ssl-ciphers -fno-sanitize=alignment \
		--prefix=$$(pwd)/build-kraken && \
	ALPHA_PATH=$(KRAKEN) make clean && ALPHA_PATH=$(KRAKEN) make -j$$(nproc) build_libs && \
	ALPHA_PATH=$(KRAKEN) make -j$$(nproc) LDCMD="$(ALPHA_CLANGXX) $(KRAKEN_DRIVER)" fuzz/x509 && \
	cp fuzz/x509 build-kraken/x509 && cp fuzz/oids.txt x509.dict

lua-kraken: lua kraken-check
	rm -rf lua/build-kraken && mkdir lua/build-kraken
	cp -al lua/* lua/build-kraken/ || true
	cd lua/build-kraken && make clean && \
	ALPHA_PATH=$(KRAKEN) make -j$$(nproc) CC=$(ALPHA_CLANG) MYCFLAGS="-DLUA_USE_LINUX" liblua.a && \
	cp $(OSS_DIR)/lua_setup/fuzz_lua.c . && \
	ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANG) -DLUA_USE_LINUX -c fuzz_lua.c -o fuzz_lua.o && \
	ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANGXX) fuzz_lua.o $(KRAKEN_DRIVER) -o fuzz_lua liblua.a -lm -ldl

libsndfile-kraken: libsndfile/seed_corpus kraken-check
	cd libsndfile && git checkout --detach 68f6c16fe1407eff4cdde158566694c3ed666c2f
	rm -rf libsndfile/build-kraken && mkdir libsndfile/build-kraken
	find libsndfile -maxdepth 1 ! -name libsndfile ! -name 'build-*' ! -name seed_corpus -exec cp -al {} libsndfile/build-kraken/ \;
	cd libsndfile/build-kraken && autoreconf -vif && \
	ALPHA_PATH=$(KRAKEN) CC=$(ALPHA_CLANG) CXX=$(ALPHA_CLANGXX) \
	LIB_FUZZING_ENGINE="$(KRAKEN_DRIVER)" ./configure --disable-shared --enable-ossfuzzers && \
	ALPHA_PATH=$(KRAKEN) make -j$$(nproc) ossfuzz/sndfile_fuzzer && cp ossfuzz/sndfile_fuzzer .

libtiff-kraken: libtiff kraken-check
	cd libtiff && git fetch origin b40dc6ec4997d4d2e62152fe62dac20c3a23f557 && \
	git checkout --detach b40dc6ec4997d4d2e62152fe62dac20c3a23f557 && ./autogen.sh
	cd libtiff && rm -rf build-kraken && mkdir build-kraken && cd build-kraken && \
	ALPHA_PATH=$(KRAKEN) CC=$(ALPHA_CLANG) CXX=$(ALPHA_CLANGXX) \
	../configure --disable-shared --prefix=$$(pwd)/install --disable-zstd --disable-webp --disable-pixarlog && \
	ALPHA_PATH=$(KRAKEN) make -j$$(nproc) && make install && \
	ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANGXX) -std=c++11 -Iinstall/include \
		../contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc $(KRAKEN_DRIVER) -o tiff_read_rgba_fuzzer \
		install/lib/libtiffxx.a install/lib/libtiff.a -lz -ljpeg -ldeflate -ljbig \
		-Wl,-Bstatic -llzma -Wl,-Bdynamic -lm

poppler-kraken: poppler kraken-check
	cd poppler/repo && git fetch --depth 1 origin $(POPPLER_REF) && git checkout --detach FETCH_HEAD
	cd poppler/freetype2 && git fetch --depth 1 origin $(FREETYPE_REF) && git checkout --detach FETCH_HEAD
	POPPLER_REPO=poppler/repo python3 $(OSS_DIR)/patch_poppler.py
	cd poppler/freetype2 && ./autogen.sh && rm -rf build-kraken && mkdir build-kraken && cd build-kraken && \
	ALPHA_PATH=$(KRAKEN) CC=$(ALPHA_CLANG) CXX=$(ALPHA_CLANGXX) ../configure \
		--prefix=$$(pwd)/../../install-kraken --disable-shared --with-harfbuzz=no \
		--with-bzip2=no --with-png=no --with-brotli=no && \
	ALPHA_PATH=$(KRAKEN) make -j$$(nproc) && make install
	cd poppler/repo && rm -rf build-kraken && mkdir build-kraken && cd build-kraken && \
	ALPHA_PATH=$(KRAKEN) CC=$(ALPHA_CLANG) CXX=$(ALPHA_CLANGXX) CFLAGS="-D_GNU_SOURCE" CXXFLAGS="-D_GNU_SOURCE" \
	cmake .. -DCMAKE_BUILD_TYPE=debug -DBUILD_SHARED_LIBS=OFF -DENABLE_FUZZER=OFF \
		-DFONT_CONFIGURATION=generic -DENABLE_DCTDECODER=libjpeg -DENABLE_GOBJECT_INTROSPECTION=OFF \
		-DENABLE_LIBPNG=OFF -DENABLE_ZLIB=OFF -DENABLE_LIBTIFF=OFF -DENABLE_LIBJPEG=ON \
		-DENABLE_GLIB=OFF -DENABLE_LIBCURL=OFF -DENABLE_BOOST=OFF -DENABLE_GPGME=OFF \
		-DENABLE_NSS3=OFF -DENABLE_QT6=OFF -DENABLE_QT5=OFF -DENABLE_UTILS=OFF -DWITH_Cairo=OFF \
		-DCMAKE_CXX_STANDARD=14 \
		-DFREETYPE_INCLUDE_DIR_ft2build=$$(pwd)/../../install-kraken/include/freetype2 \
		-DFREETYPE_INCLUDE_DIR_freetype2=$$(pwd)/../../install-kraken/include/freetype2 \
		-DFREETYPE_LIBRARY=$$(pwd)/../../install-kraken/lib/libfreetype.a \
		-DICONV_LIBRARIES=/usr/lib/x86_64-linux-gnu/libc.so && \
	ALPHA_PATH=$(KRAKEN) make -j$$(nproc) poppler poppler-cpp
	mkdir -p poppler/build-kraken && ALPHA_PATH=$(KRAKEN) $(ALPHA_CLANGXX) -std=c++14 -D_GNU_SOURCE \
		-Ipoppler/repo/cpp -Ipoppler/repo/build-kraken/cpp poppler/repo/cpp/tests/fuzzing/pdf_fuzzer.cc \
		$(KRAKEN_DRIVER) -o poppler/build-kraken/pdf_fuzzer poppler/repo/build-kraken/cpp/libpoppler-cpp.a \
		poppler/repo/build-kraken/libpoppler.a poppler/install-kraken/lib/libfreetype.a \
		-ljpeg -lz -lopenjp2 -lpng -ltiff -llcms2 -lm -lpthread

# AFL-EDGE Edge-method builds for selected OSS targets.
#
# AFL-EDGE needs two binaries: an AFL-instrumented binary used by afl-fuzz, and
# a gclang/bitcode-derived Edge binary used by the scheduling script.

.PHONY: afl-edge-check libpng-afl-edge sqlite3-afl-edge harfbuzz-afl-edge \
	bloaty-afl-edge freetype2-afl-edge libxslt-afl-edge libpcap-afl-edge \
	libaom-afl-edge libjpeg-turbo-afl-edge libxml2-afl-edge lcms-afl-edge \
	mbedtls-afl-edge php-afl-edge openssl-afl-edge poppler-afl-edge lua-afl-edge \
	libsndfile-afl-edge libtiff-afl-edge

afl-edge-check:
	test -x "$(AFL_EDGE_AFL)/afl-fuzz"
	test -x "$(AFL_EDGE_CLANG)"
	test -x "$(AFL_EDGE_CLANGXX)"
	test -x "$$(command -v gclang)"
	test -x "$$(command -v gclang++)"
	test -x "$$(command -v get-bc)"
	test -f "$(AFL_EDGE_PASS)"
	test -f "$(AFL_EDGE_RUNTIME)"
	test -f "$(AFL_EDGE_DRIVER)"

libpng-afl-edge: libpng afl-edge-check
	cd libpng && \
	mkdir -p build-afl-edge-afl && cd build-afl-edge-afl && \
	AFL_PATH=$(AFL_EDGE_AFL) CC=$(AFL_EDGE_CLANG) CXX=$(AFL_EDGE_CLANGXX) ../configure --disable-shared && \
	AFL_PATH=$(AFL_EDGE_AFL) make clean all -j$$(nproc) && \
	AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANGXX) -std=c++11 -I. -I.. \
		../contrib/oss-fuzz/libpng_read_fuzzer.cc \
		$(AFL_EDGE_DRIVER) \
		-o libpng_read_fuzzer_afl \
		.libs/libpng16.a \
		-lz -lm -lstdc++ && \
	cd ../.. && \
	cd libpng && \
	mkdir -p build-afl-edge-instru && cd build-afl-edge-instru && \
	LLVM_COMPILER=clang CC=gclang CXX=gclang++ ../configure --disable-shared && \
	LLVM_COMPILER=clang make clean all -j$$(nproc) && \
	LLVM_COMPILER=clang gclang++ -std=c++11 -I. -I.. \
		../contrib/oss-fuzz/libpng_read_fuzzer.cc \
		$(AFL_EDGE_DRIVER) \
		-o libpng_read_fuzzer_instru \
		.libs/libpng16.a \
		-lz -lm -lstdc++ && \
	LLVM_COMPILER=clang get-bc libpng_read_fuzzer_instru && \
	opt -load "$(AFL_EDGE_PASS)" -iterateAllBB libpng_read_fuzzer_instru.bc -S -o libpng_read_fuzzer_edge.bc && \
	clang++ -o libpng_read_fuzzer_edge libpng_read_fuzzer_edge.bc \
		-ldl "$(AFL_EDGE_RUNTIME)" \
		-lz -lm -lstdc++

sqlite3-afl-edge: sqlite3 afl-edge-check
	@echo "=== Building SQLite3 with AFL-EDGE instrumentation ==="
	cd sqlite3 && \
	mkdir -p build-afl-edge-afl && cd build-afl-edge-afl && \
	CC_FOR_BUILD=$(SQLITE3_CC_FOR_BUILD) PATH=$(SQLITE3_BUILD_PATH) AFL_PATH=$(AFL_EDGE_AFL) CC=$(AFL_EDGE_CLANG) CXX=$(AFL_EDGE_CLANGXX) \
	CFLAGS="$(SQLITE3_FUZZ_CFLAGS)" \
	../configure --shared=0 && \
	CC_FOR_BUILD=$(SQLITE3_CC_FOR_BUILD) PATH=$(SQLITE3_BUILD_PATH) AFL_PATH=$(AFL_EDGE_AFL) make -j$$(nproc) && \
	CC_FOR_BUILD=$(SQLITE3_CC_FOR_BUILD) PATH=$(SQLITE3_BUILD_PATH) AFL_PATH=$(AFL_EDGE_AFL) make sqlite3.c && \
	AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANG) $(SQLITE3_FUZZ_CFLAGS) -I. -c ../test/ossfuzz.c -o ossfuzz.o && \
	AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANGXX) ossfuzz.o $(AFL_EDGE_DRIVER) -o ossfuzz_afl sqlite3.o -pthread -ldl -lz && \
	cd ../.. && \
	cd sqlite3 && \
	mkdir -p build-afl-edge-instru && cd build-afl-edge-instru && \
	CC_FOR_BUILD=$(SQLITE3_CC_FOR_BUILD) PATH=$(SQLITE3_BUILD_PATH) LLVM_COMPILER=clang CC=gclang CXX=gclang++ \
	CFLAGS="$(SQLITE3_FUZZ_CFLAGS)" \
	../configure --shared=0 && \
	CC_FOR_BUILD=$(SQLITE3_CC_FOR_BUILD) PATH=$(SQLITE3_BUILD_PATH) LLVM_COMPILER=clang make -j$$(nproc) && \
	CC_FOR_BUILD=$(SQLITE3_CC_FOR_BUILD) PATH=$(SQLITE3_BUILD_PATH) LLVM_COMPILER=clang make sqlite3.c && \
	LLVM_COMPILER=clang gclang $(SQLITE3_FUZZ_CFLAGS) -I. -c ../test/ossfuzz.c -o ossfuzz.o && \
	LLVM_COMPILER=clang gclang++ ossfuzz.o $(AFL_EDGE_DRIVER) -o ossfuzz_instru sqlite3.o -pthread -ldl -lz && \
	LLVM_COMPILER=clang get-bc ossfuzz_instru && \
	opt -load "$(AFL_EDGE_PASS)" -iterateAllBB ossfuzz_instru.bc -S -o ossfuzz_edge.bc && \
	clang++ -o ossfuzz_edge ossfuzz_edge.bc \
		-ldl "$(AFL_EDGE_RUNTIME)" \
		-pthread -lz

harfbuzz-afl-edge: harfbuzz afl-edge-check
	@echo "=== Building HarfBuzz with AFL-EDGE instrumentation ==="
	cd harfbuzz && \
	mkdir -p build-afl-edge-afl && cd build-afl-edge-afl && \
	AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANGXX) -std=c++11 -c $(AFL_EDGE_DRIVER) -o afl_edge_driver.o && \
	AFL_PATH=$(AFL_EDGE_AFL) CC=$(AFL_EDGE_CLANG) CXX=$(AFL_EDGE_CLANGXX) \
	CFLAGS="$(HARFBUZZ_FUZZ_CFLAGS)" \
	CXXFLAGS="$(HARFBUZZ_FUZZ_CXXFLAGS)" \
	meson .. --default-library=static --wrap-mode=nodownload \
		-Dexperimental_api=true \
		-Dfuzzer_ldflags="$$(pwd)/afl_edge_driver.o" && \
	AFL_PATH=$(AFL_EDGE_AFL) ninja -v -j$$(nproc) test/fuzzing/hb-shape-fuzzer && \
	mv test/fuzzing/hb-shape-fuzzer hb-shape-fuzzer_afl && \
	cd ../.. && \
	cd harfbuzz && \
	mkdir -p build-afl-edge-instru && cd build-afl-edge-instru && \
	LLVM_COMPILER=clang gclang++ -std=c++11 -c $(AFL_EDGE_DRIVER) -o afl_edge_driver.o && \
	LLVM_COMPILER=clang CC=gclang CXX=gclang++ \
	CFLAGS="$(HARFBUZZ_FUZZ_CFLAGS)" \
	CXXFLAGS="$(HARFBUZZ_FUZZ_CXXFLAGS)" \
	meson .. --default-library=static --wrap-mode=nodownload \
		-Dexperimental_api=true \
		-Dfuzzer_ldflags="$$(pwd)/afl_edge_driver.o" && \
	LLVM_COMPILER=clang ninja -v -j$$(nproc) test/fuzzing/hb-shape-fuzzer && \
	mv test/fuzzing/hb-shape-fuzzer hb-shape-fuzzer_instru && \
	LLVM_COMPILER=clang get-bc hb-shape-fuzzer_instru && \
	opt -load "$(AFL_EDGE_PASS)" -iterateAllBB hb-shape-fuzzer_instru.bc -S -o hb-shape-fuzzer_edge.bc && \
	clang++ -o hb-shape-fuzzer_edge hb-shape-fuzzer_edge.bc \
		-ldl "$(AFL_EDGE_RUNTIME)" \
		-lm -pthread -lstdc++

bloaty-afl-edge: IS_KRAKEN=1
bloaty-afl-edge: bloaty afl-edge-check
	cd bloaty && \
	rm -rf build-afl-edge-afl && mkdir -p build-afl-edge-afl && cd build-afl-edge-afl && \
	AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANGXX) -std=c++11 -c $(AFL_EDGE_DRIVER) -o afl_edge_driver.o && \
	ar rcs libafl_edge_driver.a afl_edge_driver.o && \
	AFL_PATH=$(AFL_EDGE_AFL) CC=$(AFL_EDGE_CLANG) CXX=$(AFL_EDGE_CLANGXX) \
	LIB_FUZZING_ENGINE=$$(pwd)/libafl_edge_driver.a \
	cmake -G Ninja -DBUILD_TESTING=false .. && \
	AFL_PATH=$(AFL_EDGE_AFL) ninja -j$$(nproc) && \
	mv fuzz_target bloaty_fuzz_target
	cd bloaty && \
	rm -rf build-afl-edge-instru && mkdir -p build-afl-edge-instru && cd build-afl-edge-instru && \
	LLVM_COMPILER=clang gclang++ -std=c++11 -c $(AFL_EDGE_DRIVER) -o afl_edge_driver.o && \
	ar rcs libafl_edge_driver.a afl_edge_driver.o && \
	LLVM_COMPILER=clang CC=gclang CXX=gclang++ \
	LIB_FUZZING_ENGINE=$$(pwd)/libafl_edge_driver.a \
	cmake -G Ninja -DBUILD_TESTING=false .. && \
	LLVM_COMPILER=clang ninja -j$$(nproc) && \
	mv fuzz_target bloaty_fuzz_target_instru && \
	LLVM_COMPILER=clang get-bc bloaty_fuzz_target_instru && \
	opt -load "$(AFL_EDGE_PASS)" -iterateAllBB bloaty_fuzz_target_instru.bc -S -o bloaty_fuzz_target_edge.bc && \
	clang++ -o bloaty_fuzz_target bloaty_fuzz_target_edge.bc \
		"$(AFL_EDGE_RUNTIME)" -ldl -pthread -lz -lm -lstdc++

freetype2-afl-edge: IS_KRAKEN=1
freetype2-afl-edge: freetype2 afl-edge-check
	cd libarchive-3.4.3 && \
	rm -rf build-afl-edge-afl && mkdir -p build-afl-edge-afl && cd build-afl-edge-afl && \
	AFL_PATH=$(AFL_EDGE_AFL) CC=$(AFL_EDGE_CLANG) CXX=$(AFL_EDGE_CLANGXX) \
	../configure --disable-shared --prefix=$$(pwd)/install && \
	AFL_PATH=$(AFL_EDGE_AFL) make clean && AFL_PATH=$(AFL_EDGE_AFL) make -j$$(nproc) && make install
	cd freetype2 && \
	rm -rf build-afl-edge-afl && mkdir -p build-afl-edge-afl && cd build-afl-edge-afl && \
	AFL_PATH=$(AFL_EDGE_AFL) CC=$(AFL_EDGE_CLANG) CXX=$(AFL_EDGE_CLANGXX) \
	../configure --prefix=$$(pwd)/install --with-harfbuzz=no --with-bzip2=no --with-png=no --without-zlib --with-brotli=no && \
	AFL_PATH=$(AFL_EDGE_AFL) make clean && AFL_PATH=$(AFL_EDGE_AFL) make all -j$$(nproc) && make install && \
	AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANGXX) -std=c++11 -I../include -I.. \
		-I$$(pwd)/../../libarchive-3.4.3/build-afl-edge-afl/install/include \
		../src/tools/ftfuzzer/ftfuzzer.cc $(AFL_EDGE_DRIVER) \
		$$(pwd)/install/lib/libfreetype.a \
		$$(pwd)/../../libarchive-3.4.3/build-afl-edge-afl/install/lib/libarchive.a \
		-o ftfuzzer
	cd libarchive-3.4.3 && \
	rm -rf build-afl-edge-instru && mkdir -p build-afl-edge-instru && cd build-afl-edge-instru && \
	LLVM_COMPILER=clang CC=gclang CXX=gclang++ \
	../configure --disable-shared --prefix=$$(pwd)/install && \
	LLVM_COMPILER=clang make clean && LLVM_COMPILER=clang make -j$$(nproc) && make install
	cd freetype2 && \
	rm -rf build-afl-edge-instru && mkdir -p build-afl-edge-instru && cd build-afl-edge-instru && \
	LLVM_COMPILER=clang CC=gclang CXX=gclang++ \
	../configure --prefix=$$(pwd)/install --with-harfbuzz=no --with-bzip2=no --with-png=no --without-zlib --with-brotli=no && \
	LLVM_COMPILER=clang make clean && LLVM_COMPILER=clang make all -j$$(nproc) && make install && \
	LLVM_COMPILER=clang gclang++ -std=c++11 -I../include -I.. \
		-I$$(pwd)/../../libarchive-3.4.3/build-afl-edge-instru/install/include \
		../src/tools/ftfuzzer/ftfuzzer.cc $(AFL_EDGE_DRIVER) \
		$$(pwd)/install/lib/libfreetype.a \
		$$(pwd)/../../libarchive-3.4.3/build-afl-edge-instru/install/lib/libarchive.a \
		-o ftfuzzer_instru && \
	LLVM_COMPILER=clang get-bc ftfuzzer_instru && \
	opt -load "$(AFL_EDGE_PASS)" -iterateAllBB ftfuzzer_instru.bc -S -o ftfuzzer_edge.bc && \
	clang++ -o ftfuzzer ftfuzzer_edge.bc "$(AFL_EDGE_RUNTIME)" -ldl -pthread -lm -lstdc++

libxslt-afl-edge: IS_KRAKEN=1
libxslt-afl-edge: libxslt afl-edge-check
	cd libxml2-xslt && \
	rm -rf build-afl-edge-afl && mkdir -p build-afl-edge-afl && cd build-afl-edge-afl && \
	cp -r ../include . && \
	AFL_PATH=$(AFL_EDGE_AFL) CC=$(AFL_EDGE_CLANG) CXX=$(AFL_EDGE_CLANGXX) ../configure \
		--disable-shared --without-c14n --without-push --without-python \
		--without-reader --without-regexps --without-sax1 --without-schemas \
		--without-schematron --without-valid --without-writer --without-zlib --without-lzma && \
	AFL_PATH=$(AFL_EDGE_AFL) make -j$$(nproc)
	cd libxslt && \
	rm -rf build-afl-edge-afl && mkdir -p build-afl-edge-afl && cd build-afl-edge-afl && \
	AFL_PATH=$(AFL_EDGE_AFL) CC=$(AFL_EDGE_CLANG) CXX=$(AFL_EDGE_CLANGXX) ../configure \
		--with-libxml-src=$(WORKDIR)/subjects/libxml2-xslt/build-afl-edge-afl \
		--disable-shared --without-python --without-crypto --without-debug \
		--without-debugger --without-profiler && \
	AFL_PATH=$(AFL_EDGE_AFL) make -j$$(nproc) && cd tests/fuzz && \
	mkdir -p seed/xpath && make seed/xpath.stamp fuzz.o xpath.o && \
	AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANGXX) -std=c++11 xpath.o fuzz.o $(AFL_EDGE_DRIVER) -o ../../xpath \
		../../libexslt/.libs/libexslt.a ../../libxslt/.libs/libxslt.a \
		$(WORKDIR)/subjects/libxml2-xslt/build-afl-edge-afl/.libs/libxml2.a \
		-pthread -lz -lm -ldl
	cd libxml2-xslt && \
	rm -rf build-afl-edge-instru && mkdir -p build-afl-edge-instru && cd build-afl-edge-instru && \
	cp -r ../include . && \
	LLVM_COMPILER=clang CC=gclang CXX=gclang++ ../configure \
		--disable-shared --without-c14n --without-push --without-python \
		--without-reader --without-regexps --without-sax1 --without-schemas \
		--without-schematron --without-valid --without-writer --without-zlib --without-lzma && \
	LLVM_COMPILER=clang make -j$$(nproc)
	cd libxslt && \
	rm -rf build-afl-edge-instru && mkdir -p build-afl-edge-instru && cd build-afl-edge-instru && \
	LLVM_COMPILER=clang CC=gclang CXX=gclang++ ../configure \
		--with-libxml-src=$(WORKDIR)/subjects/libxml2-xslt/build-afl-edge-instru \
		--disable-shared --without-python --without-crypto --without-debug \
		--without-debugger --without-profiler && \
	LLVM_COMPILER=clang make -j$$(nproc) && cd tests/fuzz && \
	mkdir -p seed/xpath && make seed/xpath.stamp fuzz.o xpath.o && \
	LLVM_COMPILER=clang gclang++ -std=c++11 xpath.o fuzz.o $(AFL_EDGE_DRIVER) -o ../../xpath_instru \
		../../libexslt/.libs/libexslt.a ../../libxslt/.libs/libxslt.a \
		$(WORKDIR)/subjects/libxml2-xslt/build-afl-edge-instru/.libs/libxml2.a \
		-pthread -lz -lm -ldl && cd ../.. && \
	LLVM_COMPILER=clang get-bc xpath_instru && \
	opt -load "$(AFL_EDGE_PASS)" -iterateAllBB xpath_instru.bc -S -o xpath_edge.bc && \
	clang++ -o xpath xpath_edge.bc "$(AFL_EDGE_RUNTIME)" -ldl -pthread -lz -lm -lstdc++

libpcap-afl-edge: libpcap-prepare afl-edge-check
	cd libpcap && \
	rm -rf build-afl-edge-afl && mkdir -p build-afl-edge-afl && cd build-afl-edge-afl && \
	AFL_PATH=$(AFL_EDGE_AFL) CC=$(AFL_EDGE_CLANG) CXX=$(AFL_EDGE_CLANGXX) cmake -DDISABLE_DBUS=ON .. && \
	AFL_PATH=$(AFL_EDGE_AFL) make clean all -j$$(nproc) && \
	AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANG) -I.. -c ../testprogs/fuzz/fuzz_both.c -o fuzz_both.o && \
	AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANGXX) fuzz_both.o $(AFL_EDGE_DRIVER) -o libpcap_fuzz_both libpcap.a
	cd libpcap && \
	rm -rf build-afl-edge-instru && mkdir -p build-afl-edge-instru && cd build-afl-edge-instru && \
	LLVM_COMPILER=clang CC=gclang CXX=gclang++ cmake -DDISABLE_DBUS=ON .. && \
	LLVM_COMPILER=clang make clean all -j$$(nproc) && \
	LLVM_COMPILER=clang gclang -I.. -c ../testprogs/fuzz/fuzz_both.c -o fuzz_both.o && \
	LLVM_COMPILER=clang gclang++ fuzz_both.o $(AFL_EDGE_DRIVER) -o libpcap_fuzz_both_instru libpcap.a && \
	LLVM_COMPILER=clang get-bc libpcap_fuzz_both_instru && \
	opt -load "$(AFL_EDGE_PASS)" -iterateAllBB libpcap_fuzz_both_instru.bc -S -o libpcap_fuzz_both_edge.bc && \
	clang++ -o libpcap_fuzz_both libpcap_fuzz_both_edge.bc "$(AFL_EDGE_RUNTIME)" -ldl -pthread -lm -lstdc++

libaom-afl-edge: libaom afl-edge-check
	cd libaom && \
	rm -rf build-afl-edge-afl && mkdir -p build-afl-edge-afl && cd build-afl-edge-afl && \
	AFL_PATH=$(AFL_EDGE_AFL) CC=$(AFL_EDGE_CLANG) CXX=$(AFL_EDGE_CLANGXX) \
	cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS_RELEASE='-O3 -g' -DCMAKE_CXX_FLAGS_RELEASE='-O3 -g' \
		-DAOM_TARGET_CPU=generic \
		-DCONFIG_PIC=1 -DCONFIG_LOWBITDEPTH=1 -DCONFIG_AV1_ENCODER=0 \
		-DENABLE_EXAMPLES=0 -DENABLE_DOCS=0 -DENABLE_TESTS=0 -DENABLE_TOOLS=0 \
		-DCONFIG_SIZE_LIMIT=1 -DDECODE_HEIGHT_LIMIT=12288 -DDECODE_WIDTH_LIMIT=12288 \
		-DAOM_EXTRA_C_FLAGS="-DAOM_MAX_ALLOCABLE_MEMORY=1073741824 -DDO_RANGE_CHECK_CLAMP=1" \
		-DAOM_EXTRA_CXX_FLAGS="-DAOM_MAX_ALLOCABLE_MEMORY=1073741824 -DDO_RANGE_CHECK_CLAMP=1" && \
	AFL_PATH=$(AFL_EDGE_AFL) make -j$$(nproc) && \
	AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANGXX) -std=c++11 -I../ -I. \
		-Wl,--start-group $(AFL_EDGE_DRIVER) ../examples/av1_dec_fuzzer.cc \
		-o av1_dec_fuzzer libaom.a -Wl,--end-group -pthread -lm
	cd libaom && \
	rm -rf build-afl-edge-instru && mkdir -p build-afl-edge-instru && cd build-afl-edge-instru && \
	LLVM_COMPILER=clang CC=gclang CXX=gclang++ \
	cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS_RELEASE='-O3 -g' -DCMAKE_CXX_FLAGS_RELEASE='-O3 -g' \
		-DAOM_TARGET_CPU=generic \
		-DCONFIG_PIC=1 -DCONFIG_LOWBITDEPTH=1 -DCONFIG_AV1_ENCODER=0 \
		-DENABLE_EXAMPLES=0 -DENABLE_DOCS=0 -DENABLE_TESTS=0 -DENABLE_TOOLS=0 \
		-DCONFIG_SIZE_LIMIT=1 -DDECODE_HEIGHT_LIMIT=12288 -DDECODE_WIDTH_LIMIT=12288 \
		-DAOM_EXTRA_C_FLAGS="-DAOM_MAX_ALLOCABLE_MEMORY=1073741824 -DDO_RANGE_CHECK_CLAMP=1" \
		-DAOM_EXTRA_CXX_FLAGS="-DAOM_MAX_ALLOCABLE_MEMORY=1073741824 -DDO_RANGE_CHECK_CLAMP=1" && \
	LLVM_COMPILER=clang make -j$$(nproc) && \
	LLVM_COMPILER=clang gclang++ -std=c++11 -I../ -I. -c $(AFL_EDGE_DRIVER) -o afl_edge_driver.o && \
	LLVM_COMPILER=clang gclang++ -std=c++11 -I../ -I. -c ../examples/av1_dec_fuzzer.cc -o av1_dec_fuzzer.o && \
	LLVM_COMPILER=clang gclang++ -Wl,--start-group afl_edge_driver.o av1_dec_fuzzer.o \
		-o av1_dec_fuzzer_instru libaom.a -Wl,--end-group -pthread -lm && \
	LLVM_COMPILER=clang get-bc av1_dec_fuzzer_instru && \
	opt -load "$(AFL_EDGE_PASS)" -iterateAllBB av1_dec_fuzzer_instru.bc -S -o av1_dec_fuzzer_edge.bc && \
	clang++ -o av1_dec_fuzzer av1_dec_fuzzer_edge.bc "$(AFL_EDGE_RUNTIME)" -ldl -pthread -lm -lstdc++

libjpeg-turbo-afl-edge: libjpeg-turbo-decompress-corpus afl-edge-check
	cd libjpeg-turbo && \
	rm -rf build-afl-edge-afl && mkdir -p build-afl-edge-afl && cd build-afl-edge-afl && \
	AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANGXX) -std=c++11 -c $(AFL_EDGE_DRIVER) -o afl_edge_driver.o && \
	ar rcs libafl_edge_driver.a afl_edge_driver.o && \
	AFL_PATH=$(AFL_EDGE_AFL) CC=$(AFL_EDGE_CLANG) CXX=$(AFL_EDGE_CLANGXX) cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo \
		-DENABLE_STATIC=1 -DENABLE_SHARED=0 -DWITH_SIMD=0 \
		-DCMAKE_C_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" \
		-DCMAKE_INSTALL_PREFIX=$$(pwd)/install -DWITH_FUZZ=1 -DFUZZ_BINDIR=$$(pwd) \
		-DFUZZ_LIBRARY=$$(pwd)/libafl_edge_driver.a && \
	AFL_PATH=$(AFL_EDGE_AFL) make clean all -j$$(nproc) && make install
	cd libjpeg-turbo && \
	rm -rf build-afl-edge-instru && mkdir -p build-afl-edge-instru && cd build-afl-edge-instru && \
	LLVM_COMPILER=clang gclang++ -std=c++11 -c $(AFL_EDGE_DRIVER) -o afl_edge_driver.o && \
	ar rcs libafl_edge_driver.a afl_edge_driver.o && \
	LLVM_COMPILER=clang CC=gclang CXX=gclang++ cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo \
		-DENABLE_STATIC=1 -DENABLE_SHARED=0 -DWITH_SIMD=0 \
		-DCMAKE_C_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" \
		-DCMAKE_INSTALL_PREFIX=$$(pwd)/install -DWITH_FUZZ=1 -DFUZZ_BINDIR=$$(pwd) \
		-DFUZZ_LIBRARY=$$(pwd)/libafl_edge_driver.a && \
	LLVM_COMPILER=clang make clean all -j$$(nproc) && make install && \
	mv libjpeg_turbo_fuzzer libjpeg_turbo_fuzzer_instru && \
	LLVM_COMPILER=clang get-bc libjpeg_turbo_fuzzer_instru && \
	opt -load "$(AFL_EDGE_PASS)" -iterateAllBB libjpeg_turbo_fuzzer_instru.bc -S -o libjpeg_turbo_fuzzer_edge.bc && \
	clang++ -o libjpeg_turbo_fuzzer libjpeg_turbo_fuzzer_edge.bc "$(AFL_EDGE_RUNTIME)" -ldl -pthread -lm -lstdc++

libxml2-afl-edge: IS_KRAKEN=1
libxml2-afl-edge: libxml2 afl-edge-check
	cd libxml2 && \
	git fetch origin 66453240c94b5cbd3e9ae9b32016fdafb13cdf18 && \
	git checkout --detach 66453240c94b5cbd3e9ae9b32016fdafb13cdf18 && \
	rm -rf build-afl-edge-afl && mkdir -p build-afl-edge-afl && cd build-afl-edge-afl && \
	AFL_PATH=$(AFL_EDGE_AFL) CC=$(AFL_EDGE_CLANG) CXX=$(AFL_EDGE_CLANGXX) \
	../configure --disable-shared --without-debug --without-http --without-python --with-zlib --with-lzma && \
	AFL_PATH=$(AFL_EDGE_AFL) make -j$$(nproc) && \
	AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANG) -I../include -I./include -c ../fuzz/fuzz.c -o fuzz.o && \
	AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANG) -I../include -I./include -c ../fuzz/xml.c -o xml.o && \
	AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANGXX) xml.o fuzz.o $(AFL_EDGE_DRIVER) -o fuzz-xml \
		.libs/libxml2.a -Wl,-Bstatic -lz -llzma -Wl,-Bdynamic -lm -pthread && \
	AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANG) -I../include -I. -I./include -c ../fuzz/genSeed.c -o genSeed.o && \
	AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANGXX) genSeed.o fuzz.o -o genSeed \
		-L. -L.libs -lxml2 -lz -llzma -lm -pthread && \
	mkdir -p seed/xml && ./genSeed xml \
		'../test/*' '../test/errors/*.xml' '../test/errors10/*.xml' '../test/namespaces/*' \
		'../test/recurse/*.xml' '../test/SVG/*.xml' '../test/valid/*.xml' '../test/VC/*' \
		'../test/VCM/*' '../test/XInclude/docs/*' '../test/XInclude/without-reader/*' '../test/xmlid/*' && \
	touch seed/xml.stamp && cp ../fuzz/xml.dict seed/
	cd libxml2 && \
	rm -rf build-afl-edge-instru && mkdir -p build-afl-edge-instru && cd build-afl-edge-instru && \
	LLVM_COMPILER=clang CC=gclang CXX=gclang++ \
	../configure --disable-shared --without-debug --without-http --without-python --with-zlib --with-lzma && \
	LLVM_COMPILER=clang make -j$$(nproc) && \
	LLVM_COMPILER=clang gclang -I../include -I./include -c ../fuzz/fuzz.c -o fuzz.o && \
	LLVM_COMPILER=clang gclang -I../include -I./include -c ../fuzz/xml.c -o xml.o && \
	LLVM_COMPILER=clang gclang++ xml.o fuzz.o $(AFL_EDGE_DRIVER) -o fuzz-xml_instru \
		.libs/libxml2.a -Wl,-Bstatic -lz -llzma -Wl,-Bdynamic -lm -pthread && \
	LLVM_COMPILER=clang get-bc fuzz-xml_instru && \
	opt -load "$(AFL_EDGE_PASS)" -iterateAllBB fuzz-xml_instru.bc -S -o fuzz-xml_edge.bc && \
	clang++ -o fuzz-xml fuzz-xml_edge.bc "$(AFL_EDGE_RUNTIME)" -ldl -pthread -lz -llzma -lm -lstdc++ && \
	cp -r ../build-afl-edge-afl/seed .

lcms-afl-edge: lcms afl-edge-check
	cd lcms && \
	rm -rf build-afl-edge-afl && mkdir -p build-afl-edge-afl && cd build-afl-edge-afl && \
	AFL_PATH=$(AFL_EDGE_AFL) CC=$(AFL_EDGE_CLANG) CXX=$(AFL_EDGE_CLANGXX) ../configure --enable-shared=no && \
	AFL_PATH=$(AFL_EDGE_AFL) make clean all -j$$(nproc) && \
	AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANG) -c -I../include ../oss-fuzz/cms_transform_fuzzer.c -o cms_transform_fuzzer.o && \
	AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANGXX) cms_transform_fuzzer.o $(AFL_EDGE_DRIVER) -o cms_transform_fuzzer \
		src/.libs/liblcms2.a -lz
	cd lcms && \
	rm -rf build-afl-edge-instru && mkdir -p build-afl-edge-instru && cd build-afl-edge-instru && \
	LLVM_COMPILER=clang CC=gclang CXX=gclang++ ../configure --enable-shared=no && \
	LLVM_COMPILER=clang make clean all -j$$(nproc) && \
	LLVM_COMPILER=clang gclang -c -I../include ../oss-fuzz/cms_transform_fuzzer.c -o cms_transform_fuzzer.o && \
	LLVM_COMPILER=clang gclang++ cms_transform_fuzzer.o $(AFL_EDGE_DRIVER) -o cms_transform_fuzzer_instru \
		src/.libs/liblcms2.a -lz && \
	LLVM_COMPILER=clang get-bc cms_transform_fuzzer_instru && \
	opt -load "$(AFL_EDGE_PASS)" -iterateAllBB cms_transform_fuzzer_instru.bc -S -o cms_transform_fuzzer_edge.bc && \
	clang++ -o cms_transform_fuzzer cms_transform_fuzzer_edge.bc "$(AFL_EDGE_RUNTIME)" -ldl -pthread -lz -lm -lstdc++

mbedtls-afl-edge: IS_KRAKEN=1
mbedtls-afl-edge: mbedtls afl-edge-check mbedtls-deps
	cd mbedtls && \
	rm -rf build-afl-edge-afl && mkdir -p build-afl-edge-afl && cd build-afl-edge-afl && \
	AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANGXX) -std=c++11 -c $(AFL_EDGE_DRIVER) -o afl_edge_driver.o && \
	ar rcs libafl_edge_driver.a afl_edge_driver.o && \
	AFL_PATH=$(AFL_EDGE_AFL) CC=$(AFL_EDGE_CLANG) CXX=$(AFL_EDGE_CLANGXX) \
	FUZZER_LIB=$$(pwd)/libafl_edge_driver.a LIB_FUZZING_ENGINE=$$(pwd)/libafl_edge_driver.a \
	cmake .. -DENABLE_TESTING=OFF && \
	AFL_PATH=$(AFL_EDGE_AFL) make -j$$(nproc) && \
	mv programs/fuzz/fuzz_dtlsclient .
	cd mbedtls && \
	rm -rf build-afl-edge-instru && mkdir -p build-afl-edge-instru && cd build-afl-edge-instru && \
	LLVM_COMPILER=clang gclang++ -std=c++11 -c $(AFL_EDGE_DRIVER) -o afl_edge_driver.o && \
	ar rcs libafl_edge_driver.a afl_edge_driver.o && \
	LLVM_COMPILER=clang CC=gclang CXX=gclang++ \
	FUZZER_LIB=$$(pwd)/libafl_edge_driver.a LIB_FUZZING_ENGINE=$$(pwd)/libafl_edge_driver.a \
	cmake .. -DENABLE_TESTING=OFF && \
	LLVM_COMPILER=clang make -j$$(nproc) && \
	mv programs/fuzz/fuzz_dtlsclient fuzz_dtlsclient_instru && \
	LLVM_COMPILER=clang get-bc fuzz_dtlsclient_instru && \
	opt -load "$(AFL_EDGE_PASS)" -iterateAllBB fuzz_dtlsclient_instru.bc -S -o fuzz_dtlsclient_edge.bc && \
	clang++ -o fuzz_dtlsclient fuzz_dtlsclient_edge.bc "$(AFL_EDGE_RUNTIME)" -ldl -pthread -lm -lstdc++ && \
	cd .. && \
	if [[ -f corpus/dtlsclient ]]; then \
		rm -rf corpus/dtlsclient_dir && mkdir -p corpus/dtlsclient_dir && \
		cp corpus/dtlsclient corpus/dtlsclient_dir/seed && rm -f corpus/dtlsclient && \
		mv corpus/dtlsclient_dir corpus/dtlsclient; \
	fi

php-afl-edge: php-checkout afl-edge-check
	cd php-src && rm -rf build-afl-edge-afl && mkdir build-afl-edge-afl && cd build-afl-edge-afl && \
	AFL_PATH=$(AFL_EDGE_AFL) LIB_FUZZING_ENGINE="$(AFL_EDGE_DRIVER)" FUZZING_CC="$(AFL_EDGE_CLANGXX)" \
	CC=$(AFL_EDGE_CLANG) CXX=$(AFL_EDGE_CLANGXX) \
	CFLAGS="-fno-sanitize=object-size -DPROFITABILITY_CHECKS=0" \
	CXXFLAGS="-fno-sanitize=object-size -DPROFITABILITY_CHECKS=0" ../configure \
		--disable-all --enable-debug-assertions --enable-option-checking=fatal --enable-fuzzer \
		--enable-exif --without-pcre-jit --disable-phpdbg --disable-cgi --enable-pic && \
	AFL_PATH=$(AFL_EDGE_AFL) LIB_FUZZING_ENGINE="$(AFL_EDGE_DRIVER)" FUZZING_CC="$(AFL_EDGE_CLANGXX)" \
	CC=$(AFL_EDGE_CLANG) CXX=$(AFL_EDGE_CLANGXX) make -j$$(nproc) libs sapi/cli/php && \
	AFL_PATH=$(AFL_EDGE_AFL) LIB_FUZZING_ENGINE="$(AFL_EDGE_DRIVER)" FUZZING_CC="$(AFL_EDGE_CLANGXX)" \
	CC=$(AFL_EDGE_CLANG) CXX=$(AFL_EDGE_CLANGXX) make -j$$(nproc) PHP_FUZZER_BINARIES='sapi/fuzzer/php-fuzz-parser' && \
	mv sapi/fuzzer/php-fuzz-parser php-fuzz-parser_afl
	cd php-src && rm -rf build-afl-edge-instru && mkdir build-afl-edge-instru && cd build-afl-edge-instru && \
	LLVM_COMPILER=clang LIB_FUZZING_ENGINE="$(AFL_EDGE_DRIVER)" FUZZING_CC=gclang++ CC=gclang CXX=gclang++ \
	CFLAGS="-fno-sanitize=object-size -DPROFITABILITY_CHECKS=0" \
	CXXFLAGS="-fno-sanitize=object-size -DPROFITABILITY_CHECKS=0" ../configure \
		--disable-all --enable-debug-assertions --enable-option-checking=fatal --enable-fuzzer \
		--enable-exif --without-pcre-jit --disable-phpdbg --disable-cgi --enable-pic && \
	LLVM_COMPILER=clang LIB_FUZZING_ENGINE="$(AFL_EDGE_DRIVER)" FUZZING_CC=gclang++ CC=gclang CXX=gclang++ \
	make -j$$(nproc) libs sapi/cli/php && \
	LLVM_COMPILER=clang LIB_FUZZING_ENGINE="$(AFL_EDGE_DRIVER)" FUZZING_CC=gclang++ CC=gclang CXX=gclang++ \
	make -j$$(nproc) PHP_FUZZER_BINARIES='sapi/fuzzer/php-fuzz-parser' && \
	mv sapi/fuzzer/php-fuzz-parser php-fuzz-parser_instru && LLVM_COMPILER=clang get-bc php-fuzz-parser_instru && \
	opt -load "$(AFL_EDGE_PASS)" -iterateAllBB php-fuzz-parser_instru.bc -S -o php-fuzz-parser_edge.bc && \
	clang++ php-fuzz-parser_edge.bc "$(AFL_EDGE_RUNTIME)" \
		ext/standard/base64.o ext/standard/string.o \
		Zend/asm/make_x86_64_sysv_elf_gas.o Zend/asm/jump_x86_64_sysv_elf_gas.o \
		-o php-fuzz-parser_edge -Wl,--allow-multiple-definition \
		-lresolv -lutil -lrt -ldl -pthread -lm -lc++ -lc++abi

openssl-afl-edge: openssl afl-edge-check
	cd openssl && rm -rf build-afl-edge-afl && mkdir build-afl-edge-afl && \
	AFL_PATH=$(AFL_EDGE_AFL) CC=$(AFL_EDGE_CLANG) CXX=$(AFL_EDGE_CLANGXX) \
	./config --debug enable-fuzz-libfuzzer disable-tests no-asm -DPEDANTIC \
		-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION no-shared no-module \
		enable-tls1_3 enable-rc5 enable-md2 enable-ec_nistp_64_gcc_128 enable-nextprotoneg \
		enable-weak-ssl-ciphers -fno-sanitize=alignment --prefix=$$(pwd)/build-afl-edge-afl && \
	AFL_PATH=$(AFL_EDGE_AFL) make clean && AFL_PATH=$(AFL_EDGE_AFL) make -j$$(nproc) build_libs && \
	AFL_PATH=$(AFL_EDGE_AFL) make -j$$(nproc) LDCMD="$(AFL_EDGE_CLANGXX) $(AFL_EDGE_DRIVER)" fuzz/x509 && \
	cp fuzz/x509 build-afl-edge-afl/x509_afl && cp fuzz/oids.txt x509.dict
	cd openssl && rm -rf build-afl-edge-instru && mkdir build-afl-edge-instru && \
	LLVM_COMPILER=clang CC=gclang CXX=gclang++ ./config --debug enable-fuzz-libfuzzer disable-tests no-asm -DPEDANTIC \
		-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION no-shared no-module \
		enable-tls1_3 enable-rc5 enable-md2 enable-ec_nistp_64_gcc_128 enable-nextprotoneg \
		enable-weak-ssl-ciphers -fno-sanitize=alignment --prefix=$$(pwd)/build-afl-edge-instru && \
	LLVM_COMPILER=clang make clean && LLVM_COMPILER=clang make -j$$(nproc) build_libs && \
	LLVM_COMPILER=clang make -j$$(nproc) LDCMD="gclang++ $(AFL_EDGE_DRIVER)" fuzz/x509 && \
	cp fuzz/x509 build-afl-edge-instru/x509_instru && cd build-afl-edge-instru && \
	LLVM_COMPILER=clang get-bc x509_instru && opt -load "$(AFL_EDGE_PASS)" -iterateAllBB x509_instru.bc -S -o x509_edge.bc && \
	clang++ x509_edge.bc "$(AFL_EDGE_RUNTIME)" -o x509_edge -ldl -pthread -lm -lstdc++ && \
	cp ../fuzz/oids.txt ../x509.dict

lua-afl-edge: lua afl-edge-check
	rm -rf lua/build-afl-edge-afl && mkdir lua/build-afl-edge-afl
	cp -al lua/* lua/build-afl-edge-afl/ || true
	cd lua/build-afl-edge-afl && make clean && AFL_PATH=$(AFL_EDGE_AFL) make -j$$(nproc) CC=$(AFL_EDGE_CLANG) MYCFLAGS="-DLUA_USE_LINUX" liblua.a && \
	cp $(OSS_DIR)/lua_setup/fuzz_lua.c . && AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANG) -DLUA_USE_LINUX -c fuzz_lua.c -o fuzz_lua.o && \
	AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANGXX) fuzz_lua.o $(AFL_EDGE_DRIVER) -o fuzz_lua_afl liblua.a -lm -ldl
	rm -rf lua/build-afl-edge-instru && mkdir lua/build-afl-edge-instru
	cp -al lua/* lua/build-afl-edge-instru/ || true
	cd lua/build-afl-edge-instru && make clean && LLVM_COMPILER=clang make -j$$(nproc) CC=gclang MYCFLAGS="-DLUA_USE_LINUX" liblua.a && \
	cp $(OSS_DIR)/lua_setup/fuzz_lua.c . && LLVM_COMPILER=clang gclang -DLUA_USE_LINUX -c fuzz_lua.c -o fuzz_lua.o && \
	LLVM_COMPILER=clang gclang++ fuzz_lua.o $(AFL_EDGE_DRIVER) -o fuzz_lua_instru liblua.a -lm -ldl && \
	LLVM_COMPILER=clang get-bc fuzz_lua_instru && opt -load "$(AFL_EDGE_PASS)" -iterateAllBB fuzz_lua_instru.bc -S -o fuzz_lua_edge.bc && \
	clang++ fuzz_lua_edge.bc "$(AFL_EDGE_RUNTIME)" -o fuzz_lua_edge -ldl -pthread -lm -lstdc++

libsndfile-afl-edge: libsndfile/seed_corpus afl-edge-check
	cd libsndfile && git checkout --detach 68f6c16fe1407eff4cdde158566694c3ed666c2f
	rm -rf libsndfile/build-afl-edge-afl && mkdir libsndfile/build-afl-edge-afl
	find libsndfile -maxdepth 1 ! -name libsndfile ! -name 'build-*' ! -name seed_corpus -exec cp -al {} libsndfile/build-afl-edge-afl/ \;
	cd libsndfile/build-afl-edge-afl && autoreconf -vif && AFL_PATH=$(AFL_EDGE_AFL) \
	CC=$(AFL_EDGE_CLANG) CXX=$(AFL_EDGE_CLANGXX) LIB_FUZZING_ENGINE="$(AFL_EDGE_DRIVER)" \
	./configure --disable-shared --enable-ossfuzzers && AFL_PATH=$(AFL_EDGE_AFL) make -j$$(nproc) ossfuzz/sndfile_fuzzer && \
	cp ossfuzz/sndfile_fuzzer sndfile_fuzzer_afl
	rm -rf libsndfile/build-afl-edge-instru && mkdir libsndfile/build-afl-edge-instru
	find libsndfile -maxdepth 1 ! -name libsndfile ! -name 'build-*' ! -name seed_corpus -exec cp -al {} libsndfile/build-afl-edge-instru/ \;
	cd libsndfile/build-afl-edge-instru && autoreconf -vif && LLVM_COMPILER=clang CC=gclang CXX=gclang++ \
	LIB_FUZZING_ENGINE="$(AFL_EDGE_DRIVER)" ./configure --disable-shared --enable-ossfuzzers && \
	LLVM_COMPILER=clang make -j$$(nproc) ossfuzz/sndfile_fuzzer && cp ossfuzz/sndfile_fuzzer sndfile_fuzzer_instru && \
	LLVM_COMPILER=clang get-bc sndfile_fuzzer_instru && opt -load "$(AFL_EDGE_PASS)" -iterateAllBB sndfile_fuzzer_instru.bc -S -o sndfile_fuzzer_edge.bc && \
	clang++ sndfile_fuzzer_edge.bc "$(AFL_EDGE_RUNTIME)" -o sndfile_fuzzer_edge -ldl -pthread -lm -lstdc++

libtiff-afl-edge: libtiff afl-edge-check
	cd libtiff && git fetch origin b40dc6ec4997d4d2e62152fe62dac20c3a23f557 && \
	git checkout --detach b40dc6ec4997d4d2e62152fe62dac20c3a23f557 && ./autogen.sh
	cd libtiff && rm -rf build-afl-edge-afl && mkdir build-afl-edge-afl && cd build-afl-edge-afl && \
	AFL_PATH=$(AFL_EDGE_AFL) CC=$(AFL_EDGE_CLANG) CXX=$(AFL_EDGE_CLANGXX) \
	../configure --disable-shared --prefix=$$(pwd)/install --disable-zstd --disable-webp --disable-pixarlog && \
	AFL_PATH=$(AFL_EDGE_AFL) make -j$$(nproc) && make install && AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANGXX) \
	-std=c++11 -Iinstall/include ../contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc $(AFL_EDGE_DRIVER) -o tiff_read_rgba_fuzzer_afl \
	install/lib/libtiffxx.a install/lib/libtiff.a -lz -ljpeg -ldeflate -ljbig -Wl,-Bstatic -llzma -Wl,-Bdynamic -lm
	cd libtiff && rm -rf build-afl-edge-instru && mkdir build-afl-edge-instru && cd build-afl-edge-instru && \
	LLVM_COMPILER=clang CC=gclang CXX=gclang++ ../configure --disable-shared --prefix=$$(pwd)/install \
	--disable-zstd --disable-webp --disable-pixarlog && LLVM_COMPILER=clang make -j$$(nproc) && make install && \
	LLVM_COMPILER=clang gclang++ -std=c++11 -Iinstall/include ../contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc \
	$(AFL_EDGE_DRIVER) -o tiff_read_rgba_fuzzer_instru install/lib/libtiffxx.a install/lib/libtiff.a \
	-lz -ljpeg -ldeflate -ljbig -Wl,-Bstatic -llzma -Wl,-Bdynamic -lm && \
	LLVM_COMPILER=clang get-bc tiff_read_rgba_fuzzer_instru && \
	opt -load "$(AFL_EDGE_PASS)" -iterateAllBB tiff_read_rgba_fuzzer_instru.bc -S -o tiff_read_rgba_fuzzer_edge.bc && \
	clang++ tiff_read_rgba_fuzzer_edge.bc "$(AFL_EDGE_RUNTIME)" -o tiff_read_rgba_fuzzer_edge \
	-ldl -pthread -lz -ljpeg -ldeflate -ljbig -llzma -lm -lstdc++

poppler-afl-edge: poppler afl-edge-check
	cd poppler/repo && git fetch --depth 1 origin $(POPPLER_REF) && git checkout --detach FETCH_HEAD
	cd poppler/freetype2 && git fetch --depth 1 origin $(FREETYPE_REF) && git checkout --detach FETCH_HEAD
	POPPLER_REPO=poppler/repo python3 $(OSS_DIR)/patch_poppler.py
	cd poppler/freetype2 && ./autogen.sh && rm -rf build-afl-edge-afl && mkdir build-afl-edge-afl && cd build-afl-edge-afl && \
	AFL_PATH=$(AFL_EDGE_AFL) CC=$(AFL_EDGE_CLANG) CXX=$(AFL_EDGE_CLANGXX) ../configure \
		--prefix=$$(pwd)/../../install-afl-edge-afl --disable-shared --with-harfbuzz=no \
		--with-bzip2=no --with-png=no --with-brotli=no && AFL_PATH=$(AFL_EDGE_AFL) make -j$$(nproc) && make install
	cd poppler/repo && rm -rf build-afl-edge-afl && mkdir build-afl-edge-afl && cd build-afl-edge-afl && \
	AFL_PATH=$(AFL_EDGE_AFL) CC=$(AFL_EDGE_CLANG) CXX=$(AFL_EDGE_CLANGXX) CFLAGS="-D_GNU_SOURCE" CXXFLAGS="-D_GNU_SOURCE" \
	cmake .. -DCMAKE_BUILD_TYPE=debug -DBUILD_SHARED_LIBS=OFF -DENABLE_FUZZER=OFF -DFONT_CONFIGURATION=generic \
		-DENABLE_DCTDECODER=libjpeg -DENABLE_GOBJECT_INTROSPECTION=OFF -DENABLE_LIBPNG=OFF -DENABLE_ZLIB=OFF \
		-DENABLE_LIBTIFF=OFF -DENABLE_LIBJPEG=ON -DENABLE_GLIB=OFF -DENABLE_LIBCURL=OFF -DENABLE_BOOST=OFF \
		-DENABLE_GPGME=OFF -DENABLE_NSS3=OFF -DENABLE_QT6=OFF -DENABLE_QT5=OFF -DENABLE_UTILS=OFF -DWITH_Cairo=OFF \
		-DCMAKE_CXX_STANDARD=14 -DFREETYPE_INCLUDE_DIR_ft2build=$$(pwd)/../../install-afl-edge-afl/include/freetype2 \
		-DFREETYPE_INCLUDE_DIR_freetype2=$$(pwd)/../../install-afl-edge-afl/include/freetype2 \
		-DFREETYPE_LIBRARY=$$(pwd)/../../install-afl-edge-afl/lib/libfreetype.a \
		-DICONV_LIBRARIES=/usr/lib/x86_64-linux-gnu/libc.so && AFL_PATH=$(AFL_EDGE_AFL) make -j$$(nproc) poppler poppler-cpp
	mkdir -p poppler/build-afl-edge-afl && AFL_PATH=$(AFL_EDGE_AFL) $(AFL_EDGE_CLANGXX) -std=c++14 -D_GNU_SOURCE \
		-Ipoppler/repo/cpp -Ipoppler/repo/build-afl-edge-afl/cpp poppler/repo/cpp/tests/fuzzing/pdf_fuzzer.cc \
		$(AFL_EDGE_DRIVER) -o poppler/build-afl-edge-afl/pdf_fuzzer_afl poppler/repo/build-afl-edge-afl/cpp/libpoppler-cpp.a \
		poppler/repo/build-afl-edge-afl/libpoppler.a poppler/install-afl-edge-afl/lib/libfreetype.a \
		-ljpeg -lz -lopenjp2 -lpng -ltiff -llcms2 -lm -lpthread
	cd poppler/freetype2 && rm -rf build-afl-edge-instru && mkdir build-afl-edge-instru && cd build-afl-edge-instru && \
	LLVM_COMPILER=clang CC=gclang CXX=gclang++ ../configure --prefix=$$(pwd)/../../install-afl-edge-instru \
		--disable-shared --with-harfbuzz=no --with-bzip2=no --with-png=no --with-brotli=no && \
	LLVM_COMPILER=clang make -j$$(nproc) && make install
	cd poppler/repo && rm -rf build-afl-edge-instru && mkdir build-afl-edge-instru && cd build-afl-edge-instru && \
	LLVM_COMPILER=clang CC=gclang CXX=gclang++ CFLAGS="-D_GNU_SOURCE" CXXFLAGS="-D_GNU_SOURCE" cmake .. \
		-DCMAKE_BUILD_TYPE=debug -DBUILD_SHARED_LIBS=OFF -DENABLE_FUZZER=OFF -DFONT_CONFIGURATION=generic \
		-DENABLE_DCTDECODER=libjpeg -DENABLE_GOBJECT_INTROSPECTION=OFF -DENABLE_LIBPNG=OFF -DENABLE_ZLIB=OFF \
		-DENABLE_LIBTIFF=OFF -DENABLE_LIBJPEG=ON -DENABLE_GLIB=OFF -DENABLE_LIBCURL=OFF -DENABLE_BOOST=OFF \
		-DENABLE_GPGME=OFF -DENABLE_NSS3=OFF -DENABLE_QT6=OFF -DENABLE_QT5=OFF -DENABLE_UTILS=OFF -DWITH_Cairo=OFF \
		-DCMAKE_CXX_STANDARD=14 -DFREETYPE_INCLUDE_DIR_ft2build=$$(pwd)/../../install-afl-edge-instru/include/freetype2 \
		-DFREETYPE_INCLUDE_DIR_freetype2=$$(pwd)/../../install-afl-edge-instru/include/freetype2 \
		-DFREETYPE_LIBRARY=$$(pwd)/../../install-afl-edge-instru/lib/libfreetype.a \
		-DICONV_LIBRARIES=/usr/lib/x86_64-linux-gnu/libc.so && LLVM_COMPILER=clang make -j$$(nproc) poppler poppler-cpp
	mkdir -p poppler/build-afl-edge-instru && LLVM_COMPILER=clang gclang++ -std=c++14 -D_GNU_SOURCE \
		-Ipoppler/repo/cpp -Ipoppler/repo/build-afl-edge-instru/cpp poppler/repo/cpp/tests/fuzzing/pdf_fuzzer.cc \
		$(AFL_EDGE_DRIVER) -o poppler/build-afl-edge-instru/pdf_fuzzer_instru \
		poppler/repo/build-afl-edge-instru/cpp/libpoppler-cpp.a poppler/repo/build-afl-edge-instru/libpoppler.a \
		poppler/install-afl-edge-instru/lib/libfreetype.a -ljpeg -lz -lopenjp2 -lpng -ltiff -llcms2 -lm -lpthread && \
	cd poppler/build-afl-edge-instru && LLVM_COMPILER=clang get-bc pdf_fuzzer_instru && \
	opt -load "$(AFL_EDGE_PASS)" -iterateAllBB pdf_fuzzer_instru.bc -S -o pdf_fuzzer_edge.bc && \
	clang++ pdf_fuzzer_edge.bc "$(AFL_EDGE_RUNTIME)" -o pdf_fuzzer_edge -ldl -pthread \
		-ljpeg -lz -lopenjp2 -lpng -ltiff -llcms2 -lm -lstdc++

.PHONY: mufuzz-check libpng-mufuzz sqlite3-mufuzz harfbuzz-mufuzz bloaty-mufuzz \
	freetype2-mufuzz libxslt-mufuzz libpcap-mufuzz libaom-mufuzz \
	libjpeg-turbo-mufuzz libxml2-mufuzz lcms-mufuzz lcms-mufuzz-seed mbedtls-mufuzz \
	php-mufuzz openssl-mufuzz poppler-mufuzz lua-mufuzz libsndfile-mufuzz libtiff-mufuzz

mufuzz-check:
	test -x "$(MUFUZZ)/target/release/mufuzz"
	test -x "$(MUFUZZ_AFL_CLANG)"
	test -x "$(MUFUZZ_AFL_CLANGXX)"
	test -f "$(MUFUZZ_DRIVER)"

poppler-mufuzz: poppler mufuzz-check
	cd poppler/freetype2 && ./autogen.sh && rm -rf build-mufuzz && mkdir build-mufuzz && cd build-mufuzz && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) CC=$(MUFUZZ_AFL_CLANG) CXX=$(MUFUZZ_AFL_CLANGXX) ../configure \
		--prefix=$$(pwd)/../../install-mufuzz --disable-shared --with-harfbuzz=no \
		--with-bzip2=no --with-png=no --with-brotli=no && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make -j$$(nproc) && make install
	cd poppler/repo && rm -rf build-mufuzz && mkdir build-mufuzz && cd build-mufuzz && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) CC=$(MUFUZZ_AFL_CLANG) CXX=$(MUFUZZ_AFL_CLANGXX) \
	CFLAGS="-D_GNU_SOURCE" CXXFLAGS="-D_GNU_SOURCE" cmake .. -DCMAKE_BUILD_TYPE=debug \
		-DBUILD_SHARED_LIBS=OFF -DENABLE_FUZZER=OFF -DFONT_CONFIGURATION=generic \
		-DENABLE_DCTDECODER=libjpeg -DENABLE_GOBJECT_INTROSPECTION=OFF -DENABLE_LIBPNG=OFF \
		-DENABLE_ZLIB=OFF -DENABLE_LIBTIFF=OFF -DENABLE_LIBJPEG=ON -DENABLE_GLIB=OFF \
		-DENABLE_LIBCURL=OFF -DENABLE_BOOST=OFF -DENABLE_GPGME=OFF -DENABLE_NSS3=OFF \
		-DENABLE_QT6=OFF -DENABLE_QT5=OFF -DENABLE_UTILS=OFF -DWITH_Cairo=OFF \
		-DCMAKE_CXX_STANDARD=14 \
		-DFREETYPE_INCLUDE_DIR_ft2build=$$(pwd)/../../install-mufuzz/include/freetype2 \
		-DFREETYPE_INCLUDE_DIR_freetype2=$$(pwd)/../../install-mufuzz/include/freetype2 \
		-DFREETYPE_LIBRARY=$$(pwd)/../../install-mufuzz/lib/libfreetype.a \
		-DICONV_LIBRARIES=/usr/lib/x86_64-linux-gnu/libc.so && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make -j$$(nproc) poppler poppler-cpp
	mkdir -p poppler/build-mufuzz && $(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) \
	$(MUFUZZ_AFL_CLANGXX) -std=c++14 -D_GNU_SOURCE -Ipoppler/repo/cpp -Ipoppler/repo/build-mufuzz/cpp \
		poppler/repo/cpp/tests/fuzzing/pdf_fuzzer.cc $(MUFUZZ_DRIVER) -o poppler/build-mufuzz/pdf_fuzzer \
		poppler/repo/build-mufuzz/cpp/libpoppler-cpp.a poppler/repo/build-mufuzz/libpoppler.a \
		poppler/install-mufuzz/lib/libfreetype.a -ljpeg -lz -lopenjp2 -lpng -ltiff -llcms2 -lm -lpthread

php-mufuzz: php-checkout mufuzz-check
	cd php-src && rm -rf build-mufuzz && mkdir build-mufuzz && cd build-mufuzz && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(MUFUZZ_AFL_CLANGXX) -stdlib=libc++ \
		-nostdinc++ -isystem /usr/lib/llvm-14/include/c++/v1 -c $(MUFUZZ_DRIVER) -o mufuzz_driver.o && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) LIB_FUZZING_ENGINE="$$(pwd)/mufuzz_driver.o" \
	FUZZING_CC="$(MUFUZZ_AFL_CLANGXX) -nostdinc++ -isystem /usr/lib/llvm-14/include/c++/v1 -L/usr/lib/llvm-14/lib" \
	CC=$(MUFUZZ_AFL_CLANG) CXX=$(MUFUZZ_AFL_CLANGXX) \
	CFLAGS="-fno-sanitize=object-size -DPROFITABILITY_CHECKS=0" \
	CXXFLAGS="-fno-sanitize=object-size -DPROFITABILITY_CHECKS=0" ../configure \
		--disable-all --enable-debug-assertions --enable-option-checking=fatal \
		--enable-fuzzer --enable-exif --without-pcre-jit --disable-phpdbg \
		--disable-cgi --enable-pic && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) LIB_FUZZING_ENGINE="$$(pwd)/mufuzz_driver.o" \
	FUZZING_CC="$(MUFUZZ_AFL_CLANGXX) -nostdinc++ -isystem /usr/lib/llvm-14/include/c++/v1 -L/usr/lib/llvm-14/lib" \
	CC=$(MUFUZZ_AFL_CLANG) CXX=$(MUFUZZ_AFL_CLANGXX) \
	make -j$$(nproc) libs sapi/cli/php && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) LIB_FUZZING_ENGINE="$$(pwd)/mufuzz_driver.o" \
	FUZZING_CC="$(MUFUZZ_AFL_CLANGXX) -nostdinc++ -isystem /usr/lib/llvm-14/include/c++/v1 -L/usr/lib/llvm-14/lib" \
	CC=$(MUFUZZ_AFL_CLANG) CXX=$(MUFUZZ_AFL_CLANGXX) \
	make -j$$(nproc) PHP_FUZZER_BINARIES='sapi/fuzzer/php-fuzz-parser' && \
	mv sapi/fuzzer/php-fuzz-parser .

openssl-mufuzz: openssl mufuzz-check
	cd openssl && rm -rf build-mufuzz && mkdir build-mufuzz && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) CC=$(MUFUZZ_AFL_CLANG) CXX=$(MUFUZZ_AFL_CLANGXX) \
	./config --debug enable-fuzz-libfuzzer disable-tests -DPEDANTIC \
		-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION no-shared no-module \
		enable-tls1_3 enable-rc5 enable-md2 enable-ec_nistp_64_gcc_128 \
		enable-nextprotoneg enable-weak-ssl-ciphers -fno-sanitize=alignment \
		--prefix=$$(pwd)/build-mufuzz && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make clean && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make -j$$(nproc) build_libs && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make -j$$(nproc) \
		LDCMD="$(MUFUZZ_AFL_CLANGXX) $(MUFUZZ_DRIVER)" fuzz/x509 && \
	cp fuzz/x509 build-mufuzz/x509 && cp fuzz/oids.txt x509.dict

lua-mufuzz: lua mufuzz-check
	rm -rf lua/build-mufuzz && mkdir lua/build-mufuzz
	cp -al lua/* lua/build-mufuzz/ || true
	cd lua/build-mufuzz && make clean && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make -j$$(nproc) CC=$(MUFUZZ_AFL_CLANG) MYCFLAGS="-DLUA_USE_LINUX" liblua.a && \
	cp $(OSS_DIR)/lua_setup/fuzz_lua.c . && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(MUFUZZ_AFL_CLANG) -DLUA_USE_LINUX -c fuzz_lua.c -o fuzz_lua.o && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(MUFUZZ_AFL_CLANGXX) fuzz_lua.o $(MUFUZZ_DRIVER) -o fuzz_lua liblua.a -lm -ldl

libsndfile-mufuzz: libsndfile/seed_corpus mufuzz-check
	cd libsndfile && git checkout --detach 68f6c16fe1407eff4cdde158566694c3ed666c2f
	rm -rf libsndfile/build-mufuzz && mkdir libsndfile/build-mufuzz
	find libsndfile -maxdepth 1 ! -name libsndfile ! -name 'build-*' ! -name seed_corpus -exec cp -al {} libsndfile/build-mufuzz/ \;
	cd libsndfile/build-mufuzz && autoreconf -vif && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) CC=$(MUFUZZ_AFL_CLANG) CXX=$(MUFUZZ_AFL_CLANGXX) \
	LIB_FUZZING_ENGINE="$(MUFUZZ_DRIVER)" ./configure --disable-shared --enable-ossfuzzers && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make -j$$(nproc) ossfuzz/sndfile_fuzzer && \
	cp ossfuzz/sndfile_fuzzer .

libtiff-mufuzz: libtiff mufuzz-check
	cd libtiff && rm -rf build-mufuzz && mkdir build-mufuzz && cd build-mufuzz && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) CC=$(MUFUZZ_AFL_CLANG) CXX=$(MUFUZZ_AFL_CLANGXX) \
	../configure --disable-shared --prefix=$$(pwd)/install --disable-zstd --disable-webp --disable-pixarlog && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make -j$$(nproc) && make install && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(MUFUZZ_AFL_CLANGXX) -std=c++11 -Iinstall/include \
		../contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc $(MUFUZZ_DRIVER) -o tiff_read_rgba_fuzzer \
		install/lib/libtiffxx.a install/lib/libtiff.a -lz -ljpeg -ldeflate -ljbig \
		-Wl,-Bstatic -llzma -Wl,-Bdynamic -lm

libpng-mufuzz: libpng mufuzz-check
	cd libpng && \
	mkdir -p build-mufuzz && cd build-mufuzz && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) CC=$(MUFUZZ_AFL_CLANG) CXX=$(MUFUZZ_AFL_CLANGXX) ../configure --disable-shared && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make clean all -j$$(nproc) && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(MUFUZZ_AFL_CLANGXX) -std=c++11 -I. -I.. \
		../contrib/oss-fuzz/libpng_read_fuzzer.cc \
		$(MUFUZZ_DRIVER) \
		-o libpng_read_fuzzer \
		.libs/libpng16.a \
		-lz -lm -lstdc++

sqlite3-mufuzz: sqlite3 mufuzz-check
	@echo "=== Building SQLite3 with muFuzz/AFL forkserver instrumentation ==="
	cd sqlite3 && \
	mkdir -p build-mufuzz && cd build-mufuzz && \
	CC_FOR_BUILD=$(SQLITE3_CC_FOR_BUILD) PATH=$(SQLITE3_BUILD_PATH) $(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) CC=$(MUFUZZ_AFL_CLANG) CXX=$(MUFUZZ_AFL_CLANGXX) \
	CFLAGS="$(SQLITE3_FUZZ_CFLAGS)" \
	../configure --shared=0 && \
	CC_FOR_BUILD=$(SQLITE3_CC_FOR_BUILD) PATH=$(SQLITE3_BUILD_PATH) $(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make -j$$(nproc) && \
	CC_FOR_BUILD=$(SQLITE3_CC_FOR_BUILD) PATH=$(SQLITE3_BUILD_PATH) $(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make sqlite3.c && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(MUFUZZ_AFL_CLANG) $(SQLITE3_FUZZ_CFLAGS) -I. -c ../test/ossfuzz.c -o ossfuzz.o && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(MUFUZZ_AFL_CLANGXX) ossfuzz.o $(MUFUZZ_DRIVER) -o ossfuzz sqlite3.o -pthread -ldl -lz

bloaty-mufuzz: IS_KRAKEN=1
bloaty-mufuzz: bloaty mufuzz-check
	cd bloaty && \
	rm -rf build-mufuzz && mkdir -p build-mufuzz && cd build-mufuzz && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(MUFUZZ_AFL_CLANGXX) -std=c++11 -c $(MUFUZZ_DRIVER) -o mufuzz_driver.o && \
	ar rcs libmufuzz_driver.a mufuzz_driver.o && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) CC=$(MUFUZZ_AFL_CLANG) CXX=$(MUFUZZ_AFL_CLANGXX) \
	LIB_FUZZING_ENGINE=$$(pwd)/libmufuzz_driver.a \
	cmake -G Ninja -DBUILD_TESTING=false .. && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) ninja -j$$(nproc) && \
	mv fuzz_target bloaty_fuzz_target

freetype2-mufuzz: IS_KRAKEN=1
freetype2-mufuzz: freetype2 mufuzz-check
	cd libarchive-3.4.3 && \
	rm -rf build-mufuzz && mkdir -p build-mufuzz && cd build-mufuzz && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) CC=$(MUFUZZ_AFL_CLANG) CXX=$(MUFUZZ_AFL_CLANGXX) \
	../configure --disable-shared --prefix=$$(pwd)/install && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make -j$$(nproc) && make install
	cd freetype2 && \
	rm -rf build-mufuzz && mkdir -p build-mufuzz && cd build-mufuzz && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) CC=$(MUFUZZ_AFL_CLANG) CXX=$(MUFUZZ_AFL_CLANGXX) \
	../configure --prefix=$$(pwd)/install --with-harfbuzz=no --with-bzip2=no --with-png=no --without-zlib --with-brotli=no && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make -j$$(nproc) && make install && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(MUFUZZ_AFL_CLANGXX) -std=c++11 -I../include -I.. \
		-I$$(pwd)/../../libarchive-3.4.3/build-mufuzz/install/include \
		../src/tools/ftfuzzer/ftfuzzer.cc $(MUFUZZ_DRIVER) \
		$$(pwd)/install/lib/libfreetype.a \
		$$(pwd)/../../libarchive-3.4.3/build-mufuzz/install/lib/libarchive.a \
		-o ftfuzzer

libxslt-mufuzz: IS_KRAKEN=1
libxslt-mufuzz: libxslt mufuzz-check
	cd libxml2-xslt && \
	rm -rf build-mufuzz && mkdir -p build-mufuzz && cd build-mufuzz && \
	cp -r ../include . && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) CC=$(MUFUZZ_AFL_CLANG) CXX=$(MUFUZZ_AFL_CLANGXX) ../configure \
		--disable-shared --without-c14n --without-push --without-python \
		--without-reader --without-regexps --without-sax1 --without-schemas \
		--without-schematron --without-valid --without-writer --without-zlib --without-lzma && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make -j$$(nproc)
	cd libxslt && \
	rm -rf build-mufuzz && mkdir -p build-mufuzz && cd build-mufuzz && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) CC=$(MUFUZZ_AFL_CLANG) CXX=$(MUFUZZ_AFL_CLANGXX) ../configure \
		--with-libxml-src=$(WORKDIR)/subjects/libxml2-xslt/build-mufuzz \
		--disable-shared --without-python --without-crypto --without-debug \
		--without-debugger --without-profiler && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make -j$$(nproc) && cd tests/fuzz && \
	mkdir -p seed/xpath && make seed/xpath.stamp fuzz.o xpath.o && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(MUFUZZ_AFL_CLANGXX) -std=c++11 xpath.o fuzz.o $(MUFUZZ_DRIVER) -o ../../xpath \
		../../libexslt/.libs/libexslt.a ../../libxslt/.libs/libxslt.a \
		$(WORKDIR)/subjects/libxml2-xslt/build-mufuzz/.libs/libxml2.a \
		-pthread -lz -lm -ldl

libaom-mufuzz: libaom mufuzz-check
	cd libaom && \
	rm -rf build-mufuzz && mkdir -p build-mufuzz && cd build-mufuzz && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) CC=$(MUFUZZ_AFL_CLANG) CXX=$(MUFUZZ_AFL_CLANGXX) \
	cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS_RELEASE='-O3 -g' -DCMAKE_CXX_FLAGS_RELEASE='-O3 -g' \
		-DAOM_TARGET_CPU=generic -DCONFIG_PIC=1 -DCONFIG_LOWBITDEPTH=1 -DCONFIG_AV1_ENCODER=0 \
		-DENABLE_EXAMPLES=0 -DENABLE_DOCS=0 -DENABLE_TESTS=0 -DENABLE_TOOLS=0 \
		-DCONFIG_SIZE_LIMIT=1 -DDECODE_HEIGHT_LIMIT=12288 -DDECODE_WIDTH_LIMIT=12288 \
		-DAOM_EXTRA_C_FLAGS="-DAOM_MAX_ALLOCABLE_MEMORY=1073741824 -DDO_RANGE_CHECK_CLAMP=1" \
		-DAOM_EXTRA_CXX_FLAGS="-DAOM_MAX_ALLOCABLE_MEMORY=1073741824 -DDO_RANGE_CHECK_CLAMP=1" && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make -j$$(nproc) && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(MUFUZZ_AFL_CLANGXX) -std=c++11 -I../ -I. \
		-Wl,--start-group $(MUFUZZ_DRIVER) ../examples/av1_dec_fuzzer.cc \
		-o av1_dec_fuzzer libaom.a -Wl,--end-group -pthread -lm

libjpeg-turbo-mufuzz: libjpeg-turbo-decompress-corpus mufuzz-check
	cd libjpeg-turbo && \
	rm -rf build-mufuzz && mkdir -p build-mufuzz && cd build-mufuzz && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(MUFUZZ_AFL_CLANGXX) -std=c++11 -c $(MUFUZZ_DRIVER) -o mufuzz_driver.o && \
	ar rcs libmufuzz_driver.a mufuzz_driver.o && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) CC=$(MUFUZZ_AFL_CLANG) CXX=$(MUFUZZ_AFL_CLANGXX) cmake .. \
		-DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_STATIC=1 -DENABLE_SHARED=0 -DWITH_SIMD=0 \
		-DCMAKE_C_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" \
		-DCMAKE_INSTALL_PREFIX=$$(pwd)/install -DWITH_FUZZ=1 -DFUZZ_BINDIR=$$(pwd) \
		-DFUZZ_LIBRARY=$$(pwd)/libmufuzz_driver.a && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make -j$$(nproc) && make install

libxml2-mufuzz: IS_KRAKEN=1
libxml2-mufuzz: libxml2 mufuzz-check
	cd libxml2 && \
	rm -rf build-mufuzz && mkdir -p build-mufuzz && cd build-mufuzz && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) CC=$(MUFUZZ_AFL_CLANG) CXX=$(MUFUZZ_AFL_CLANGXX) \
	../configure --disable-shared --without-debug --without-http --without-python --with-zlib --with-lzma && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make -j$$(nproc) && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(MUFUZZ_AFL_CLANG) -I../include -I./include -c ../fuzz/fuzz.c -o fuzz.o && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(MUFUZZ_AFL_CLANG) -I../include -I./include -c ../fuzz/xml.c -o xml.o && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(MUFUZZ_AFL_CLANGXX) xml.o fuzz.o $(MUFUZZ_DRIVER) -o fuzz-xml \
		.libs/libxml2.a -Wl,-Bstatic -lz -llzma -Wl,-Bdynamic -lm -pthread && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(MUFUZZ_AFL_CLANG) -I../include -I. -I./include -c ../fuzz/genSeed.c -o genSeed.o && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(MUFUZZ_AFL_CLANGXX) genSeed.o fuzz.o -o genSeed \
		-L. -L.libs -lxml2 -lz -llzma -lm -pthread && \
	mkdir -p seed/xml && ./genSeed xml \
		'../test/*' '../test/errors/*.xml' '../test/errors10/*.xml' '../test/namespaces/*' \
		'../test/recurse/*.xml' '../test/SVG/*.xml' '../test/valid/*.xml' '../test/VC/*' \
		'../test/VCM/*' '../test/XInclude/docs/*' '../test/XInclude/without-reader/*' '../test/xmlid/*' && \
	touch seed/xml.stamp && cp ../fuzz/xml.dict seed/

mbedtls-mufuzz: IS_KRAKEN=1
mbedtls-mufuzz: mbedtls mufuzz-check mbedtls-deps
	cd mbedtls && \
	rm -rf build-mufuzz && mkdir -p build-mufuzz && cd build-mufuzz && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(MUFUZZ_AFL_CLANGXX) -std=c++11 -c $(MUFUZZ_DRIVER) -o mufuzz_driver.o && \
	ar rcs libmufuzz_driver.a mufuzz_driver.o && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) CC=$(MUFUZZ_AFL_CLANG) CXX=$(MUFUZZ_AFL_CLANGXX) \
	FUZZER_LIB=$$(pwd)/libmufuzz_driver.a LIB_FUZZING_ENGINE=$$(pwd)/libmufuzz_driver.a \
	cmake .. -DENABLE_TESTING=OFF && \
	$(MUFUZZ_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make -j$$(nproc) && \
	mv programs/fuzz/fuzz_dtlsclient . && \
	cd .. && \
	if [[ -f corpus/dtlsclient ]]; then \
		rm -rf corpus/dtlsclient_dir && mkdir -p corpus/dtlsclient_dir && \
		cp corpus/dtlsclient corpus/dtlsclient_dir/seed && rm -f corpus/dtlsclient && \
		mv corpus/dtlsclient_dir corpus/dtlsclient; \
	fi

.PHONY: libpng-dynamiq sqlite3-dynamiq harfbuzz-dynamiq bloaty-dynamiq freetype2-dynamiq libxslt-dynamiq libpcap-dynamiq libaom-dynamiq libjpeg-turbo-dynamiq libxml2-dynamiq lcms-dynamiq mbedtls-dynamiq php-dynamiq openssl-dynamiq poppler-dynamiq lua-dynamiq libsndfile-dynamiq libtiff-dynamiq

libpng-libafl: libpng libpng-cmplog
	cd libpng && \
	mkdir -p build-libafl && cd build-libafl && \
	$(LIBAFL_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) CC=$(LIBAFL_AFL_CLANG) CXX=$(LIBAFL_AFL_CLANGXX) ../configure --disable-shared && \
	$(LIBAFL_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make clean all -j$$(nproc) && \
	$(LIBAFL_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(LIBAFL_AFL_CLANGXX) -std=c++11 -I. \
		../contrib/oss-fuzz/libpng_read_fuzzer.cc \
		-o libpng_read_fuzzer \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		.libs/libpng16.a \
		-lz -lm -lstdc++

sqlite3-libafl: sqlite3 sqlite3-cmplog
	@echo "=== Building SQLite3 with LibAFL-compatible AFL forkserver instrumentation ==="
	cd sqlite3 && \
	mkdir -p build-libafl && cd build-libafl && \
	CC_FOR_BUILD=$(SQLITE3_CC_FOR_BUILD) PATH=$(SQLITE3_BUILD_PATH) $(LIBAFL_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) CC=$(LIBAFL_AFL_CLANG) CXX=$(LIBAFL_AFL_CLANGXX) \
	CFLAGS="$(SQLITE3_FUZZ_CFLAGS)" \
	../configure --shared=0 && \
	CC_FOR_BUILD=$(SQLITE3_CC_FOR_BUILD) PATH=$(SQLITE3_BUILD_PATH) $(LIBAFL_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make -j$$(nproc) && \
	CC_FOR_BUILD=$(SQLITE3_CC_FOR_BUILD) PATH=$(SQLITE3_BUILD_PATH) $(LIBAFL_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) make sqlite3.c && \
	$(LIBAFL_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(LIBAFL_AFL_CLANG) $(SQLITE3_FUZZ_CFLAGS) -I. -c ../test/ossfuzz.c -o ossfuzz.o && \
	$(LIBAFL_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) $(LIBAFL_AFL_CLANGXX) ossfuzz.o -o ossfuzz $(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a sqlite3.o -pthread -ldl -lz

harfbuzz-libafl: harfbuzz harfbuzz-cmplog
	@echo "=== Building HarfBuzz with LibAFL-compatible AFL forkserver instrumentation ==="
	cd harfbuzz && \
	mkdir -p build-libafl && cd build-libafl && \
	$(LIBAFL_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) CC=$(LIBAFL_AFL_CLANG) CXX=$(LIBAFL_AFL_CLANGXX) \
	CFLAGS="$(HARFBUZZ_FUZZ_CFLAGS)" \
	CXXFLAGS="$(HARFBUZZ_FUZZ_CXXFLAGS)" \
	meson .. --default-library=static --wrap-mode=nodownload \
		-Dexperimental_api=true \
		-Dfuzzer_ldflags="$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a" && \
	$(LIBAFL_AFL_ENV) AFL_PATH=$(AFLPLUSPLUS) ninja -v -j$$(nproc) test/fuzzing/hb-shape-fuzzer && \
	mv test/fuzzing/hb-shape-fuzzer .

bloaty-libafl: bloaty-afl bloaty-cmplog

freetype2-libafl: freetype2-afl freetype2-cmplog

libxslt-libafl: libxslt-afl libxslt-cmplog

libpcap-libafl: libpcap-afl libpcap-cmplog

libaom-libafl: libaom-afl libaom-cmplog

libjpeg-turbo-libafl: libjpeg-turbo-afl libjpeg-turbo-cmplog

libxml2-libafl: libxml2-afl libxml2-cmplog

lcms-libafl: lcms-afl lcms-cmplog

mbedtls-libafl: mbedtls-afl mbedtls-cmplog

php-libafl: php-generate php-build-cmplog

openssl-libafl: openssl-afl openssl-cmplog

poppler-libafl: poppler-afl poppler-cmplog

lua-libafl: lua-afl lua-cmplog

libsndfile-libafl: libsndfile-afl libsndfile-cmplog

libtiff-libafl: libtiff-afl libtiff-cmplog

libpng-dynamiq: libpng-all libpng-cmplog

sqlite3-dynamiq: sqlite3-all sqlite3-cmplog

harfbuzz-dynamiq: harfbuzz-all harfbuzz-cmplog

bloaty-dynamiq: bloaty-all bloaty-cmplog

freetype2-dynamiq: freetype2-all freetype2-cmplog

libxslt-dynamiq: libxslt-all libxslt-cmplog

libpcap-dynamiq: libpcap-all libpcap-cmplog

libaom-dynamiq: libaom-all libaom-cmplog

libjpeg-turbo-dynamiq: libjpeg-turbo-all libjpeg-turbo-cmplog

libxml2-dynamiq: libxml2-all libxml2-cmplog

lcms-dynamiq: lcms-all lcms-cmplog

mbedtls-dynamiq: mbedtls-all mbedtls-cmplog

php-dynamiq: php-all php-build-cmplog

openssl-dynamiq: openssl-all

poppler-dynamiq: poppler-all

lua-dynamiq: lua-all

libsndfile-dynamiq: libsndfile-all

libtiff-dynamiq: libtiff-all

%-aflteam:
	$(MAKE) -f $(DYNAMIQ_DIR)/exp/Vanillaflteam/oss/Makefile \
		AFLTEAM_CC=$${AFL:-$${WORKDIR}/afl}/afl-clang-fast \
		AFLTEAM_CXX=$${AFL:-$${WORKDIR}/afl}/afl-clang-fast++ \
		AFL_DRIVER=$${AFL:-$${WORKDIR}/afl}/llvm_mode/libAFL.a \
		$*-all

.PHONY: exp-build exp-build-all

exp-build:
	$(MAKE) -f $(lastword $(MAKEFILE_LIST)) $(OSS_TARGET)-$(EXP_FUZZER)

exp-build-all: $(foreach target,$(EXP_DYNAMIQ_TARGETS),$(target)-dynamiq)
