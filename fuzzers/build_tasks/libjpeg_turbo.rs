use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn build_libjpeg_turbo_fuzzer(target_dir: &Path, task_id: Option<String>) {
    println!("Building libjpeg-turbo fuzzer");

    let build_dir = if let Some(id) = task_id {
        target_dir.join(format!("builddir-{}", id))
    } else {
        target_dir.join("builddir")
    };

    if build_dir.exists() {
        fs::remove_dir_all(&build_dir).expect("Failed to remove existing build directory");
    }

    fs::create_dir_all(&build_dir).expect("Failed to create build directory");

    // Retrieve AFL++ path from environment variable
    let aflplusplus_path = env::var("AFLPLUSPLUS").expect("AFLPLUSPLUS environment variable not set");

    // Configure the build using CMake
    Command::new("cmake")
        .args([
            "..",
            "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
            "-DENABLE_STATIC=1",
            "-DENABLE_SHARED=0",
            "-DCMAKE_C_FLAGS_RELWITHDEBINFO=-g -DNDEBUG",
            "-DCMAKE_CXX_FLAGS_RELWITHDEBINFO=-g -DNDEBUG",
            &format!("-DCMAKE_INSTALL_PREFIX={}", build_dir.join("install").display()),
            "-DWITH_FUZZ=1",
            &format!("-DFUZZ_BINDIR={}", build_dir.display()),
            &format!("-DFUZZ_LIBRARY={}/utils/aflpp_driver/libAFLDriver.a", aflplusplus_path),
        ])
        .env("CC", "/usr/local/bin/afl-clang-fast")
        .env("CXX", "/usr/local/bin/afl-clang-fast++")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't configure libjpeg-turbo fuzzer with AFL++");

    // Run `make clean all`
    Command::new("make")
        .args(["clean", "all", &format!("-j{}", num_cpus::get())])
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't build libjpeg-turbo fuzzer with make");

    // Install the compiled binaries
    Command::new("make")
        .arg("install")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't install libjpeg-turbo fuzzer");
}
