SHELL:=/bin/bash

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
	pip3 install --user "wllvm" "networkx" "psutil" "pydot<2.0" "numpy" "scikit-learn" && \
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
    clang -g -fsanitize=fuzzer -fprofile-arcs -ftest-coverage \
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
	mkdir -p seeds && \
	cp TRT/fonts/TestKERNOne.otf seeds/ && \
	cp TRT/fonts/TestGLYFOne.ttf seeds/ && \
	./autogen.sh && \
	./configure --with-brotli=yes && \
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
	mkdir -p build-afl && cd build-afl && \
		CC=afl-clang-fast CXX=afl-clang-fast++ \
		CFLAGS="-DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 -DSQLITE_MAX_MEMORY=25000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 -DSQLITE_DEBUG=1 -DSQLITE_MAX_PAGE_COUNT=16384" \
		../configure --shared=0 && \
		make -j$$(nproc) && \
		make sqlite3.c && \
		afl-clang-fast -DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 -DSQLITE_MAX_MEMORY=25000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 -DSQLITE_DEBUG=1 -DSQLITE_MAX_PAGE_COUNT=16384 -I. -c ../test/ossfuzz.c -o ossfuzz.o && \
		afl-clang-fast++ ossfuzz.o -o ossfuzz $(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a sqlite3.o -pthread -ldl -lz

# Build SQLite3 with Whole-Program LLVM (wllvm) and extract the call graph
sqlite3-wllvm: sqlite3
	@echo "=== Building SQLite3 with wllvm and extracting call graph ==="
	cd sqlite3 && \
	mkdir -p build-wllvm && cd build-wllvm && \
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
	mkdir -p build-profiling && cd build-profiling && \
		HF_BINARY=ossfuzz HORSEFUZZ_CG_PROFILING=1 \
		CC=afl-clang-fast CXX=afl-clang-fast++ \
		CFLAGS="-DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 -DSQLITE_MAX_MEMORY=25000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 -DSQLITE_DEBUG=1 -DSQLITE_MAX_PAGE_COUNT=16384" \
		../configure --shared=0 && \
		HF_BINARY=ossfuzz HORSEFUZZ_CG_PROFILING=1 make -j$$(nproc) && \
		HF_BINARY=ossfuzz HORSEFUZZ_CG_PROFILING=1 make sqlite3.c && \
		HF_BINARY=ossfuzz HORSEFUZZ_CG_PROFILING=1 afl-clang-fast -DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 -DSQLITE_MAX_MEMORY=25000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 -DSQLITE_DEBUG=1 -DSQLITE_MAX_PAGE_COUNT=16384 -I. -c ../test/ossfuzz.c -o ../test/ossfuzz.o && \
		HF_BINARY=ossfuzz HORSEFUZZ_CG_PROFILING=1 afl-clang-fast++ ../test/ossfuzz.o -o ossfuzz $(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a sqlite3.o -pthread -ldl -lz && \
		cp -r /tmp/ossfuzz ossfuzz-profiling-logs

# Build SQLite3 with coverage instrumentation, -fprofile-arcs -ftest-coverage not working for some reason
sqlite3-cov: sqlite3
	@echo "=== Building SQLite3 with coverage (-fprofile-arcs -ftest-coverage) ==="
	cd sqlite3 && \
	mkdir -p build-cov && cd build-cov && \
	export LLVM_COMPILER=clang && \
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

sqlite3-all: sqlite3-afl sqlite3-wllvm sqlite3-profiling sqlite3-cov
sqlite3-clean-all:
	rm -rf sqlite3 sqlite3/build-* /tmp/ossfuzz*

# libxslt Base Setup
libxslt:
	git clone https://github.com/GNOME/libxml2.git libxml2 && \
	cd libxml2 && \
	git checkout 3b38f19 && \
	autoreconf -if -Wall && \
	cd .. && \
	git clone https://gitlab.gnome.org/GNOME/libxslt.git libxslt && \
	cd libxslt && \
	git checkout 7504032 && \
	autoreconf -if -Wall

libxslt-afl: libxslt
	cd libxml2 && \
	mkdir -p build-afl && cd build-afl && \
	cp -r ../include . && \
	CC=afl-clang-fast CXX=afl-clang-fast++ ../configure \
		--disable-shared --without-c14n --without-push --without-python \
		--without-reader --without-regexps --without-sax1 --without-schemas \
		--without-schematron --without-valid --without-writer --without-zlib \
		--without-lzma && \
	make -j$(nproc) && cd ../../libxslt && \
	mkdir -p build-afl && cd build-afl && \
	CC=afl-clang-fast CXX=afl-clang-fast++ ../configure \
		--with-libxml-src=$(WORKDIR)/subjects/libxml2/build-afl \
		--disable-shared --without-python --without-crypto --without-debug \
		--without-debugger --without-profiler && \
	make -j$(nproc) && cd tests/fuzz && \
	mkdir -p seed/xpath && make seed/xpath.stamp fuzz.o xpath.o && \
	afl-clang-fast++ -std=c++11 xpath.o fuzz.o -o ../../xpath \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		../../libexslt/.libs/libexslt.a ../../libxslt/.libs/libxslt.a \
		$(WORKDIR)/subjects/libxml2/build-afl/.libs/libxml2.a

# libxslt with WLLVM
libxslt-wllvm: libxslt
	cd libxml2 && \
	mkdir -p build-wllvm && cd build-wllvm && \
	cp -r ../include . && \
	export LLVM_COMPILER=clang && \
	CC=wllvm CXX=wllvm++ ../configure \
		--disable-shared --without-c14n --without-push --without-python \
		--without-reader --without-regexps --without-sax1 --without-schemas \
		--without-schematron --without-valid --without-writer --without-zlib \
		--without-lzma && \
	make -j$(nproc) && cd ../../libxslt && \
	mkdir -p build-wllvm && cd build-wllvm && \
	export LLVM_COMPILER=clang && \
	CC=wllvm CXX=wllvm++ ../configure \
		--with-libxml-src=$(WORKDIR)/subjects/libxml2/build-wllvm \
		--disable-shared --without-python --without-crypto --without-debug \
		--without-debugger --without-profiler && \
	make -j$(nproc) && cd tests/fuzz && \
	make fuzz.o xpath.o && \
	wllvm++ -g -fsanitize=fuzzer xpath.o fuzz.o -o ../../xpath \
		../../libexslt/.libs/libexslt.a ../../libxslt/.libs/libxslt.a \
		$(WORKDIR)/subjects/libxml2/build-wllvm/.libs/libxml2.a && \
	extract-bc ../../xpath && \
	opt-15 -passes=dot-callgraph -disable-output < ../../xpath.bc && \
	mv '<stdin>.callgraph.dot' ../../xpath.dot

# libxslt with Profiling
libxslt-profiling: libxslt
	cd libxml2 && \
	mkdir -p build-profiling && cd build-profiling && \
	rm -rf /tmp/xpath && mkdir -p /tmp/xpath && \
	cp -r ../include . && \
	HF_BINARY=xpath HORSEFUZZ_CG_PROFILING=1 CC=afl-clang-fast CXX=afl-clang-fast++ ../configure \
		--disable-shared --without-c14n --without-push --without-python \
		--without-reader --without-regexps --without-sax1 --without-schemas \
		--without-schematron --without-valid --without-writer --without-zlib \
		--without-lzma && \
	HF_BINARY=xpath HORSEFUZZ_CG_PROFILING=1 make -j$(nproc) && cd ../../libxslt && \
	mkdir -p build-profiling && cd build-profiling && \
	HF_BINARY=xpath HORSEFUZZ_CG_PROFILING=1 CC=afl-clang-fast CXX=afl-clang-fast++ ../configure \
		--with-libxml-src=$(WORKDIR)/subjects/libxml2/build-profiling \
		--disable-shared --without-python --without-crypto --without-debug \
		--without-debugger --without-profiler && \
	HF_BINARY=xpath HORSEFUZZ_CG_PROFILING=1 make -j$(nproc) && cd tests/fuzz && \
	HF_BINARY=xpath HORSEFUZZ_CG_PROFILING=1 make fuzz.o xpath.o && \
	HF_BINARY=xpath HORSEFUZZ_CG_PROFILING=1 afl-clang-fast++ xpath.o fuzz.o -o ../../xpath \
		$(AFLPLUSPLUS)/utils/aflpp_driver/libAFLDriver.a \
		../../libexslt/.libs/libexslt.a ../../libxslt/.libs/libxslt.a \
		$(WORKDIR)/subjects/libxml2/build-profiling/.libs/libxml2.a && \
	cp -r /tmp/xpath ../../xpath-profiling-logs

# libxslt with Coverage
libxslt-cov: libxslt
	cd libxml2 && \
	mkdir -p build-cov && cd build-cov && \
	cp -r ../include . && \
	CC=clang CXX=clang++ CFLAGS="-g -fprofile-arcs -ftest-coverage" \
		CXXFLAGS="-g -fprofile-arcs -ftest-coverage" ../configure \
		--disable-shared --without-c14n --without-push --without-python \
		--without-reader --without-regexps --without-sax1 --without-schemas \
		--without-schematron --without-valid --without-writer --without-zlib \
		--without-lzma && \
	make -j$(nproc) && cd ../../libxslt && \
	mkdir -p build-cov && cd build-cov && \
	CC=clang CXX=clang++ CFLAGS="-g -fprofile-arcs -ftest-coverage" \
		CXXFLAGS="-g -fprofile-arcs -ftest-coverage" ../configure \
		--with-libxml-src=$(WORKDIR)/subjects/libxml2/build-cov \
		--disable-shared --without-python --without-crypto --without-debug \
		--without-debugger --without-profiler && \
	make -j$(nproc) && cd tests/fuzz && \
	make fuzz.o xpath.o && \
	clang++ -g -fsanitize=fuzzer -fprofile-arcs -ftest-coverage xpath.o fuzz.o -o ../../xpath \
		../../libexslt/.libs/libexslt.a ../../libxslt/.libs/libxslt.a \
		$(WORKDIR)/subjects/libxml2/build-cov/.libs/libxml2.a

# aggregate targets
libxslt-all: libxslt-afl libxslt-wllvm libxslt-profiling libxslt-cov
libxslt-clean-all:
	rm -rf libxml2 libxslt libxml2/build-* libxslt/build-* /tmp/xpath

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
harfbuzz-mufuzz: harfbuzz
	export AFL_LLVM_INSTRUMENT=CLASSIC AFL_OLD_FORKSERVER=1 && \
	cd harfbuzz && \
	mkdir -p build-afl-mufuzz && cd build-afl-mufuzz && \
	CC=afl-clang-fast CXX=afl-clang-fast++ \
	CFLAGS="-fno-sanitize=vptr -DHB_NO_VISIBILITY" \
	CXXFLAGS="-fno-sanitize=vptr -DHB_NO_VISIBILITY" \
	meson .. --default-library=static --wrap-mode=nodownload \
		-Dexperimental_api=true \
		-Dfuzzer_ldflags="${AFLPLUSPLUS}/utils/aflpp_driver/libAFLDriver.a" && \
	ninja -v -j$$(nproc) test/fuzzing/hb-shape-fuzzer && \
	mv test/fuzzing/hb-shape-fuzzer .

# aggregate targets
harfbuzz-all: harfbuzz-afl harfbuzz-wllvm harfbuzz-profiling harfbuzz-cov
harfbuzz-clean-all:
	rm -rf harfbuzz harfbuzz/build-* /tmp/hb-shape-fuzzer