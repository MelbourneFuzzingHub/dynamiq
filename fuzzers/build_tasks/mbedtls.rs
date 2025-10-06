use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Builds mbedTLS with AFL++ instrumentation and moves `fuzz_dtlsclient` binary.
pub fn build_fuzz_dtlsclient(target_dir: &Path, task_id: Option<String>) {
    println!("Building mbedTLS fuzz_dtlsclient with AFL++ instrumentation...");

    // Determine build directory based on task number
    let build_dir = if let Some(id) = task_id {
        target_dir.join(format!("builddir-{}", id))
    } else {
        target_dir.join("builddir")
    };

    // Remove existing build directory if it exists
    if build_dir.exists() {
        fs::remove_dir_all(&build_dir).expect("Failed to remove existing build directory");
    }

    // Create the build directory
    fs::create_dir_all(&build_dir).expect("Failed to create build directory");

    // Get AFL++ path
    let aflplusplus_path = env::var("AFLPLUSPLUS").expect("AFLPLUSPLUS environment variable not set");
    let fuzzing_engine = format!("{}/utils/aflpp_driver/libAFLDriver.a", aflplusplus_path);

    // Set environment variables for AFL++
    env::set_var("CC", "afl-clang-fast");
    env::set_var("CXX", "afl-clang-fast++");
    env::set_var("LIB_FUZZING_ENGINE", &fuzzing_engine);

    // Run CMake with AFL++ instrumentation
    Command::new("cmake")
        .arg("..")
        .arg("-DENABLE_TESTING=OFF")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't configure mbedTLS with AFL++");

    // Run `make -j$(nproc)`
    Command::new("make")
        .arg(format!("-j{}", num_cpus::get()))
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't build mbedTLS with make");

    // Move the compiled binary to `builddir-{task_number}`
    let fuzz_binary_src = build_dir.join("programs/fuzz/fuzz_dtlsclient");
    let fuzz_binary_dest = build_dir.join("fuzz_dtlsclient");

    if fuzz_binary_src.exists() {
        fs::rename(&fuzz_binary_src, &fuzz_binary_dest)
            .expect("Failed to move fuzz_dtlsclient to build directory");
        println!("Moved fuzz_dtlsclient to {:?}", fuzz_binary_dest);
    } else {
        println!("Warning: fuzz_dtlsclient binary not found in programs/fuzz/");
    }

    println!("mTLS build completed: {:?}", build_dir);
}
