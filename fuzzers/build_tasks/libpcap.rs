use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn build_libpcap_fuzz_both(target_dir: &Path, task_id: Option<String>) {
    println!("Building libpcap_fuzz_both");

    // Determine build directory based on task number
    let build_dir = if let Some(id) = task_id {
        target_dir.join(format!("builddir-{}", id))
    } else {
        target_dir.join("builddir")
    };

    // Clean and create build directory
    if build_dir.exists() {
        fs::remove_dir_all(&build_dir).expect("Failed to remove existing build directory");
    }

    fs::create_dir_all(&build_dir).expect("Failed to create build directory");

    // Configure the build using cmake
    Command::new("cmake")
        .arg("..")
        .env("CC", "afl-clang-fast")
        .env("CXX", "afl-clang-fast++")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't configure libpcap with AFL++");

    // Run `make clean all`
    Command::new("make")
        .arg("clean")
        .arg("all")
        .arg(format!("-j{}", num_cpus::get()))
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't build libpcap with make");

    // Retrieve the AFL++ path from the environment variable
    let aflplusplus_path = env::var("AFLPLUSPLUS").expect("AFLPLUSPLUS environment variable not set");

    // Compile the fuzz_both.o object file
    Command::new("afl-clang-fast")
        .arg("-I..")
        .arg("-c")
        .arg("../testprogs/fuzz/fuzz_both.c")
        .arg("-o")
        .arg("fuzz_both.o")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't compile fuzz_both.c to fuzz_both.o");

    // Link the final binary
    Command::new("afl-clang-fast++")
        .arg("fuzz_both.o")
        .arg("-o")
        .arg("libpcap_fuzz_both")
        .arg("libpcap.a")
        .arg(format!("{}/utils/aflpp_driver/libAFLDriver.a", aflplusplus_path))
        .arg("-ldbus-1")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't link libpcap_fuzz_both binary");
}