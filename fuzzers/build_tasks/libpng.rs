use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn build_libpng_read_fuzzer(target_dir: &Path, task_id: Option<String>) {
    println!("Building libpng_read_fuzzer");

    let build_dir = if let Some(id) = task_id {
        target_dir.join(format!("builddir-{}", id))
    } else {
        target_dir.join("builddir")
    };

    if build_dir.exists() {
        fs::remove_dir_all(&build_dir).expect("Failed to remove existing build directory");
    }

    fs::create_dir_all(&build_dir).expect("Failed to create build directory");

    // Configure the build
    Command::new("../configure")
        .arg("--disable-shared")
        .env("CC", "/usr/local/bin/afl-clang-fast")
        .env("CXX", "/usr/local/bin/afl-clang-fast++")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't configure libpng_read_fuzzer with AFL++");

    // Run `make clean all`
    Command::new("make")
        .arg("clean")
        .arg("all")
        .arg(format!("-j{}", num_cpus::get()))
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't build libpng_read_fuzzer with make");

    // Retrieve the AFL++ path from the environment variable
    let aflplusplus_path = env::var("AFLPLUSPLUS").expect("AFLPLUSPLUS environment variable not set");

    // Compile the libpng_read_fuzzer binary
    Command::new("afl-clang-fast++")
        .arg("-std=c++11")
        .arg("-I.")
        .arg("../contrib/oss-fuzz/libpng_read_fuzzer.cc")
        .arg("-o")
        .arg("libpng_read_fuzzer")
        .arg(format!("{}/utils/aflpp_driver/libAFLDriver.a", aflplusplus_path))
        .arg(".libs/libpng16.a")
        .arg("-lz")
        .arg("-lm")
        .arg("-lstdc++")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't compile libpng_read_fuzzer binary");
}