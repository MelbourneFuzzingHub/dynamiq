use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn build_sqlite3_afl(target_dir: &Path, task_id: Option<String>) {
    println!("=== Building SQLite3 with AFL instrumentation ===");

    // Define build directory format
    let build_dir = if let Some(id) = task_id {
        target_dir.join(format!("builddir-{}", id))
    } else {
        target_dir.join("builddir")
    };

    // Remove existing build directory if it exists
    if build_dir.exists() {
        fs::remove_dir_all(&build_dir).expect("Failed to remove existing build directory");
    }
    fs::create_dir_all(&build_dir).expect("Failed to create build directory");

    // Set environment variables
    let cc = "afl-clang-fast";
    let cxx = "afl-clang-fast++";
    let aflplusplus_path = env::var("AFLPLUSPLUS").expect("AFLPLUSPLUS environment variable not set");

    let cflags = "-DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 \
                  -DSQLITE_MAX_MEMORY=25000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
                  -DSQLITE_DEBUG=1 -DSQLITE_MAX_PAGE_COUNT=16384";

    // Configure SQLite3
    let configure_status = Command::new("../configure")
        .arg("--shared=0")
        .env("CC", cc)
        .env("CXX", cxx)
        .env("CFLAGS", cflags)
        .current_dir(&build_dir)
        .status()
        .expect("Failed to configure SQLite3 with AFL");
    if !configure_status.success() {
        panic!("Configuration failed.");
    }

    // Run `make -j$(nproc)`
    let make_status = Command::new("make")
        .arg(format!("-j{}", num_cpus::get()))
        .current_dir(&build_dir)
        .status()
        .expect("Failed to build SQLite3 with AFL");
    if !make_status.success() {
        panic!("Make build failed.");
    }

    // Generate `sqlite3.c`
    let sqlite3_status = Command::new("make")
        .arg("sqlite3.c")
        .current_dir(&build_dir)
        .status()
        .expect("Failed to generate sqlite3.c");
    if !sqlite3_status.success() {
        panic!("Make sqlite3.c failed.");
    }

    // Compile `ossfuzz.c`
    let ossfuzz_obj = build_dir.join("ossfuzz.o");
    let ossfuzz_compile = Command::new(cc)
        .arg("-I.")
        .arg("-c")
        .arg("../test/ossfuzz.c")
        .arg("-o")
        .arg(&ossfuzz_obj)
        .arg(cflags)
        .current_dir(&build_dir)
        .status()
        .expect("Failed to compile ossfuzz.c");
    if !ossfuzz_compile.success() {
        panic!("Failed to compile ossfuzz.c.");
    }

    // Link `ossfuzz`
    let ossfuzz_binary = build_dir.join("ossfuzz");

    // Remove existing binary if it exists to avoid permission issues
    if ossfuzz_binary.exists() {
        fs::remove_file(&ossfuzz_binary).expect("Failed to remove existing ossfuzz binary");
    }

    let link_status = Command::new(cxx)
        .arg("-o")
        .arg(&ossfuzz_binary)
        .arg(&ossfuzz_obj)
        .arg("sqlite3.o")
        .arg(format!("{}/utils/aflpp_driver/libAFLDriver.a", aflplusplus_path))
        .current_dir(&build_dir)
        .status()
        .expect("Failed to link ossfuzz binary");

    if !link_status.success() {
        panic!("Linking failed.");
    }

    println!("SQLite3 with AFL built successfully!");
}
