use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn build_cms_transform_fuzzer(target_dir: &Path, task_id: Option<String>) {
    println!("Building cms_transform_fuzzer");

    // Determine build directory based on task number
    let build_dir = if let Some(id) = task_id {
        target_dir.join(format!("builddir-{}", id))
    } else {
        target_dir.join("builddir")
    };

    // Remove the existing build directory, if any
    if build_dir.exists() {
        fs::remove_dir_all(&build_dir).expect("Failed to remove existing build directory");
    }

    // Create the build directory
    fs::create_dir_all(&build_dir).expect("Failed to create build directory");

    // Configure the build
    Command::new("../configure")
        .arg("--enable-shared=no")
        .env("CC", "/usr/local/bin/afl-clang-fast")
        .env("CXX", "/usr/local/bin/afl-clang-fast++")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't configure cms_transform_fuzzer with AFL++");

    // Run `make clean all`
    Command::new("make")
        .arg("clean")
        .arg("all")
        .arg(format!("-j{}", num_cpus::get()))
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't build cms_transform_fuzzer with make");

    // Retrieve the AFL++ path from the environment variable
    let aflplusplus_path = env::var("AFLPLUSPLUS").expect("AFLPLUSPLUS environment variable not set");

    // Compile the cms_transform_fuzzer object file
    Command::new("afl-clang-fast")
        .arg("-c")
        .arg("-I../include")
        .arg("../oss-fuzz/cms_transform_fuzzer.c")
        .arg("-o")
        .arg("cms_transform_fuzzer.o")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't compile cms_transform_fuzzer object file");

    // Link the cms_transform_fuzzer executable
    Command::new("afl-clang-fast++")
        .arg("cms_transform_fuzzer.o")
        .arg("-o")
        .arg("cms_transform_fuzzer")
        .arg(format!("{}/utils/aflpp_driver/libAFLDriver.a", aflplusplus_path))
        .arg("src/.libs/liblcms2.a")
        .arg("-lz")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't link cms_transform_fuzzer executable");
}
