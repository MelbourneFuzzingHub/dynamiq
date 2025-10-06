use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn build_bloaty_fuzzer(target_dir: &Path, task_id: Option<String>) {
    println!("Building Bloaty fuzzer with AFL++");

    // Determine build directory with optional task number
    let build_dir = if let Some(id) = task_id {
        target_dir.join(format!("builddir-{}", id))
    } else {
        target_dir.join("builddir")
    };

    // Ensure the build directory is fresh
    if build_dir.exists() {
        fs::remove_dir_all(&build_dir).expect("Failed to remove existing Bloaty build directory");
    }
    fs::create_dir_all(&build_dir).expect("Failed to create Bloaty build directory");

    // Retrieve the AFL++ path from environment variables
    let aflplusplus_path = env::var("AFLPLUSPLUS").expect("AFLPLUSPLUS environment variable not set");

    // Run CMake configuration
    println!("Configuring Bloaty with CMake...");
    Command::new("cmake")
        .arg("-G")
        .arg("Ninja")
        .arg("-DBUILD_TESTING=false")
        .arg("..")  // Assume source is in parent directory
        .env("CC", "afl-clang-fast")
        .env("CXX", "afl-clang-fast++")
        .env("LIB_FUZZING_ENGINE", format!("{}/utils/aflpp_driver/libAFLDriver.a", aflplusplus_path))
        .env("MAP_SIZE_POW2", "17")
        .current_dir(&build_dir)
        .status()
        .expect("Failed to configure Bloaty with CMake");

    // Run Ninja build
    println!("Building Bloaty fuzzer...");
    Command::new("ninja")
        .arg(format!("-j{}", num_cpus::get()))
        .arg("fuzz_target")
        .current_dir(&build_dir)
        .status()
        .expect("Failed to build Bloaty fuzzer");

    // Rename fuzz_target to bloaty_fuzz_target
    let fuzz_target = build_dir.join("fuzz_target");
    let renamed_fuzz_target = build_dir.join("bloaty_fuzz_target");

    if fuzz_target.exists() {
        fs::rename(&fuzz_target, &renamed_fuzz_target)
            .expect("Failed to rename fuzz_target to bloaty_fuzz_target");
        println!("Renamed fuzz_target -> bloaty_fuzz_target");
    } else {
        eprintln!("Warning: fuzz_target not found, skipping rename.");
    }
}
