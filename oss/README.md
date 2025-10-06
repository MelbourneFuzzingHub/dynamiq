# Example: libpng
```bash
cd $WORKDIR/subjects
make -f $DYNAMIQ/oss/Makefile libpng-all
mkdir $WORKDIR/results/out-libpng_read_fuzzer-dynamiq
cd $WORKDIR/results/out-libpng_read_fuzzer-dynamiq
```
Run DynamiQ
```bash
python3 $DYNAMIQ/DynamiQ.py \
    -bn libpng_read_fuzzer\
    -ab $WORKDIR/subjects/libpng/build-afl/libpng_read_fuzzer \
    -pb $WORKDIR/subjects/libpng/build-profiling/libpng_read_fuzzer \
    -gb $WORKDIR/subjects/libpng/build-cov/libpng_read_fuzzer  \
    -gf $WORKDIR/subjects/libpng/build-cov \
    -tf $WORKDIR/subjects/libpng \
    -d $WORKDIR/subjects/libpng/build-wllvm/libpng_read_fuzzer.dot \
    -i $WORKDIR/subjects/libpng/seed_corpus \
    -x $WORKDIR/subjects/libpng/png.dict \
    -c 5 \
    -o $WORKDIR/results/out-libpng_read_fuzzer-dynamiq \
    -a hrdf \
    -tt 1100 \
    -st 100 \
    -et 500 \
    -ea1 "" \
    -ea2 "" 
```

# Example: freetype2
```bash
cd $WORKDIR/subjects
make -f $DYNAMIQ/oss/Makefile freetype2-all
mkdir $WORKDIR/results/out-ftfuzzer-dynamiq
cd $WORKDIR/results/out-ftfuzzer-dynamiq
```
Run DynamiQ
```bash
python3 $DYNAMIQ/DynamiQ.py \
    -bn ftfuzzer \
    -ab $WORKDIR/subjects/freetype2/build-afl/ftfuzzer \
    -pb $WORKDIR/subjects/freetype2/build-profiling/ftfuzzer \
    -gb $WORKDIR/subjects/freetype2/build-cov/ftfuzzer \
    -gf $WORKDIR/subjects/freetype2/build-cov $WORKDIR/subjects/libarchive-3.4.3/build-cov \
    -tf $WORKDIR/subjects/freetype2\
    -d $WORKDIR/subjects/freetype2/build-wllvm/ftfuzzer.dot \
    -i $WORKDIR/subjects/freetype2/seeds \
    -c 5 \
    -o $WORKDIR/results/out-ftfuzzer-dynamiq \
    -a hrdf \
    -tt 1100 \
    -st 100 \
    -et 500 \
    -ea1 "" \
    -ea2 ""
```

# Example: sqlite3
```bash
cd $WORKDIR/subjects
make -f $DYNAMIQ/oss/Makefile sqlite3-all
mkdir $WORKDIR/results/out-ossfuzz-dynamiq
cd $WORKDIR/results/out-ossfuzz-dynamiq
```
Run DynamiQ
```bash
python3 $DYNAMIQ/DynamiQ.py \
    -bn ossfuzz \
    -ab $WORKDIR/subjects/sqlite3/build-afl/ossfuzz \
    -pb $WORKDIR/subjects/sqlite3/build-profiling/ossfuzz \
    -gb $WORKDIR/subjects/sqlite3/build-cov/ossfuzz \
    -gf $WORKDIR/subjects/sqlite3/build-cov \
    -tf $WORKDIR/subjects/sqlite3\
    -d $WORKDIR/subjects/sqlite3/build-wllvm/ossfuzz.dot \
    -i $WORKDIR/subjects/sqlite3/ossfuzz_seed_corpus \
    -x $WORKDIR/subjects/sqlite3/sql.dict \
    -c 5 \
    -o $WORKDIR/results/out-ossfuzz-dynamiq \
    -a hrdf \
    -tt 1100 \
    -st 100 \
    -et 500 \
    -ea1 "" \
    -ea2 ""
```

# Example: harfbuzz
```bash
cd $WORKDIR/subjects
make -f $DYNAMIQ/oss/Makefile harfbuzz-all
mkdir $WORKDIR/results/out-hb-shape-fuzzer-dynamiq
cd $WORKDIR/results/out-hb-shape-fuzzer-dynamiq
```
Run DynamiQ
```bash
python3 $DYNAMIQ/DynamiQ.py \
    -bn hb-shape-fuzzer \
    -ab $WORKDIR/subjects/harfbuzz/build-afl/hb-shape-fuzzer \
    -pb $WORKDIR/subjects/harfbuzz/build-profiling/hb-shape-fuzzer \
    -gb $WORKDIR/subjects/harfbuzz/build-cov/hb-shape-fuzzer  \
    -gf $WORKDIR/subjects/harfbuzz/build-cov \
    -tf $WORKDIR/subjects/harfbuzz \
    -d $WORKDIR/subjects/harfbuzz/build-wllvm/hb-shape-fuzzer.dot \
    -i $WORKDIR/subjects/harfbuzz/all-fonts \
    -c 5 \
    -o $WORKDIR/results/out-hb-shape-fuzzer-dynamiq \
    -a hrdf \
    -tt 1200  \
    -st 30 \
    -et 600 \
    -ea1 "" \
    -ea2 "" 
```

# Example: libxslt
```bash
cd $WORKDIR/subjects
make -f $DYNAMIQ/oss/Makefile libxslt-all
mkdir $WORKDIR/results/out-xpath-dynamiq
cd $WORKDIR/results/out-xpath-dynamiq
```
Run DynamiQ
```bash
python3 $DYNAMIQ/DynamiQ.py \
    -bn xpath \
    -ab $WORKDIR/subjects/libxslt/build-afl/xpath \
    -pb $WORKDIR/subjects/libxslt/build-profiling/xpath \
    -gb $WORKDIR/subjects/libxslt/build-cov/xpath \
    -gf $WORKDIR/subjects/libxslt/build-cov $WORKDIR/subjects/libxml2/build-cov \
    -tf $WORKDIR/subjects/libxslt \
    -d $WORKDIR/subjects/libxslt/build-wllvm/xpath.dot \
    -i $WORKDIR/subjects/libxslt/build-afl/tests/fuzz/seed/xpath \
    -x $WORKDIR/subjects/libxslt/tests/fuzz/xpath.dict \
    -c 10 \
    -o $WORKDIR/results/out-xpath-dynamiq \
    -a hrdf \
    -tt 1100 \
    -st 100 \
    -et 500 \
    -ea1 "" \
    -ea2 ""
```


