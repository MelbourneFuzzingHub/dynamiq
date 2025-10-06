use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn build_jsoncpp_fuzzer(target_dir: &Path, task_id: Option<String>) {
    println!("Building jsoncpp_fuzzer");

    // Set the build directory
    let build_dir = if let Some(id) = task_id {
        target_dir.join(format!("builddir-{}", id))
    } else {
        target_dir.join("builddir")
    };

    // Remove and recreate the build directory
    if build_dir.exists() {
        fs::remove_dir_all(&build_dir).expect("Failed to remove existing build directory");
    }
    fs::create_dir_all(&build_dir).expect("Failed to create build directory");

    // Configure the build using cmake
    Command::new("cmake")
        .arg("-DBUILD_SHARED_LIBS=OFF")
        .arg("-G")
        .arg("Unix Makefiles")
        .arg("..") // Assuming the jsoncpp source directory is the parent directory
        .env("CC", "/usr/local/bin/afl-clang-fast")
        .env("CXX", "/usr/local/bin/afl-clang-fast++")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't configure jsoncpp_fuzzer with cmake");

    // Run `make clean all`
    Command::new("make")
        .arg("clean")
        .arg("all")
        .arg(format!("-j{}", num_cpus::get()))
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't build jsoncpp_fuzzer with make");

    // Retrieve the AFL++ path from the environment variable
    let aflplusplus_path = env::var("AFLPLUSPLUS").expect("AFLPLUSPLUS environment variable not set");

    // Compile the jsoncpp_fuzzer binary
    Command::new("afl-clang-fast++")
        .arg("-I../include")
        .arg(format!("{}/utils/aflpp_driver/libAFLDriver.a", aflplusplus_path))
        .arg("../src/test_lib_json/fuzz.cpp")
        .arg("-o")
        .arg("jsoncpp_fuzzer")
        .arg("lib/libjsoncpp.a")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't compile jsoncpp_fuzzer binary");
}
