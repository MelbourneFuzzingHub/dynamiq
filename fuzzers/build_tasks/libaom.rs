use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn build_av1_dec_fuzzer(target_dir: &Path, task_id: Option<String>) {
    println!("Building av1_dec_fuzzer with AFL++ instrumentation");

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

    // Configure CMake build with AFL++
    Command::new("cmake")
        .args([
            "..", "-DCMAKE_BUILD_TYPE=Release",
            "-DCMAKE_C_FLAGS_RELEASE=-O3 -g",
            "-DCMAKE_CXX_FLAGS_RELEASE=-O3 -g",
            "-DCONFIG_PIC=1", "-DCONFIG_LOWBITDEPTH=1",
            "-DCONFIG_AV1_ENCODER=0", "-DENABLE_EXAMPLES=0",
            "-DENABLE_DOCS=0", "-DENABLE_TESTS=0",
            "-DCONFIG_SIZE_LIMIT=1",
            "-DDECODE_HEIGHT_LIMIT=12288", "-DDECODE_WIDTH_LIMIT=12288",
            "-DAOM_EXTRA_C_FLAGS=-DAOM_MAX_ALLOCABLE_MEMORY=1073741824 -DDO_RANGE_CHECK_CLAMP=1",
            "-DENABLE_TOOLS=0",
            "-DAOM_EXTRA_CXX_FLAGS=-DAOM_MAX_ALLOCABLE_MEMORY=1073741824 -DDO_RANGE_CHECK_CLAMP=1"
        ])
        .env("CC", "afl-clang-fast")
        .env("CXX", "afl-clang-fast++")
        .current_dir(&build_dir)
        .status()
        .expect("Failed to configure av1_dec_fuzzer with CMake");

    // Build the project
    Command::new("make")
        .arg(format!("-j{}", num_cpus::get()))
        .current_dir(&build_dir)
        .status()
        .expect("Failed to build av1_dec_fuzzer with make");

    // Retrieve AFL++ path from environment variable
    let aflplusplus_path = env::var("AFLPLUSPLUS").expect("AFLPLUSPLUS environment variable not set");

    // Compile and link av1_dec_fuzzer
    Command::new("afl-clang-fast++")
        .args([
            "-std=c++11",
            "-I../", "-I.", &format!("-I{}", build_dir.display()),
            "-o", "av1_dec_fuzzer",
            "../examples/av1_dec_fuzzer.cc",
            "libaom.a",
            &format!("{}/utils/aflpp_driver/libAFLDriver.a", aflplusplus_path),
        ])
        .current_dir(&build_dir)
        .status()
        .expect("Failed to compile av1_dec_fuzzer");
}
