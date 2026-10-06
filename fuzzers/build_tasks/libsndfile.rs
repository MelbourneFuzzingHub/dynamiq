use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn build_sndfile_fuzzer(target_dir: &Path, task_id: Option<String>) {
    println!("Building sndfile_fuzzer");

    let build_dir = if let Some(id) = task_id {
        target_dir.join(format!("builddir-{}", id))
    } else {
        target_dir.join("builddir")
    };

    if build_dir.exists() {
        fs::remove_dir_all(&build_dir).expect("Failed to remove existing build directory");
    }

    fs::create_dir_all(&build_dir).expect("Failed to create build directory");

    // Canonicalize target_dir to get an absolute path to the source
    let source_dir = target_dir
        .canonicalize()
        .expect("Couldn't canonicalize source directory");

    println!("Creating isolated build directory with robust hardlink copy...");

    // Instead of find + bash, iterate in Rust and copy each entry.
    // This avoids recursion by explicitly skipping any 'build*' or 'seed_corpus' folders.
    for entry in fs::read_dir(&source_dir).expect("Failed to read source directory") {
        let entry = entry.expect("Failed to read entry");
        let path = entry.path();
        let name = path.file_name().unwrap().to_str().unwrap();

        // Skip build directories and seed corpus to avoid recursive copying
        if name.starts_with("build") || name == "seed_corpus" {
            continue;
        }

        Command::new("cp")
            .arg("-al")
            .arg(&path)
            .arg(&build_dir)
            .status()
            .expect("Failed to cp -al entry");
    }

    // Determine CC and CXX from environment
    let cc = env::var("CC").unwrap_or_else(|_| "afl-clang-fast".to_string());
    let cxx = env::var("CXX").unwrap_or_else(|_| "afl-clang-fast++".to_string());

    // Bootstrapping with autoreconf
    println!("Running autoreconf -vif...");
    let status = Command::new("autoreconf")
        .arg("-vif")
        .current_dir(&build_dir)
        .status()
        .expect("Failed to run autoreconf");

    if !status.success() {
        panic!("autoreconf failed");
    }

    // Run `./configure`
    println!("Configuring libsndfile...");
    let status = Command::new("./configure")
        .arg("--disable-shared")
        .arg("--enable-ossfuzzers")
        .env("CC", &cc)
        .env("CXX", &cxx)
        .current_dir(&build_dir)
        .status()
        .expect("Failed to run configure");

    if !status.success() {
        panic!("configure failed");
    }

    // Run `make clean`
    Command::new("make")
        .arg("clean")
        .current_dir(&build_dir)
        .status()
        .expect("Failed to run make clean");

    // Run `make ossfuzz/sndfile_fuzzer`
    println!("Building sndfile_fuzzer...");
    let status = Command::new("make")
        .arg(format!("-j{}", num_cpus::get()))
        .arg("ossfuzz/sndfile_fuzzer")
        .env("CC", &cc)
        .env("CXX", &cxx)
        .current_dir(&build_dir)
        .status()
        .expect("Failed to build sndfile_fuzzer");

    if !status.success() {
        panic!("make ossfuzz/sndfile_fuzzer failed");
    }

    // Copy the resulting fuzzer to the root of the build directory
    let binary_src = build_dir.join("ossfuzz/sndfile_fuzzer");
    let binary_dest = build_dir.join("sndfile_fuzzer");

    if binary_src.exists() {
        fs::copy(&binary_src, &binary_dest).expect("Failed to copy sndfile_fuzzer binary");
        println!("Binary copied to: {:?}", binary_dest);
    } else {
        panic!("sndfile_fuzzer binary not found at {:?}", binary_src);
    }
}
