use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn build_hb_shape_fuzzer(target_dir: &Path, task_id: Option<String>) {
    println!("Building hb-shape-fuzzer");

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
    let aflplusplus_path = env::var("AFLPLUSPLUS")
        .expect("AFLPLUSPLUS environment variable not set");

    // Configure the build using Meson
    let meson_status = Command::new("meson")
        .arg("..")
        .arg("--default-library=static")
        .arg("--wrap-mode=nodownload")
        .arg("-Dexperimental_api=true")
        .arg(format!("-Dfuzzer_ldflags={}/utils/aflpp_driver/libAFLDriver.a", aflplusplus_path))
        .env("CC", "afl-clang-fast")
        .env("CXX", "afl-clang-fast++")
        .env("CFLAGS", "-fno-sanitize=vptr -DHB_NO_VISIBILITY")
        .env("CXXFLAGS", "-fno-sanitize=vptr -DHB_NO_VISIBILITY")
        .current_dir(&build_dir)
        .status()
        .expect("Failed to configure HarfBuzz with Meson");

    if !meson_status.success() {
        panic!("Meson configuration failed.");
    }

    // Compile with Ninja
    let ninja_status = Command::new("ninja")
        .arg("-v")
        .arg(format!("-j{}", num_cpus::get()))
        .arg("test/fuzzing/hb-shape-fuzzer")
        .current_dir(&build_dir)
        .status()
        .expect("Failed to build HarfBuzz fuzzers with Ninja");

    if !ninja_status.success() {
        panic!("Ninja build failed.");
    }

    // Move the built fuzzer
    let fuzzer_path = build_dir.join("test/fuzzing/hb-shape-fuzzer");
    let output_fuzzer_path = build_dir.join("hb-shape-fuzzer");

    if fuzzer_path.exists() {
        fs::rename(&fuzzer_path, &output_fuzzer_path)
            .expect("Failed to move the built hb-shape-fuzzer binary");
    } else {
        panic!("Fuzzer binary not found!");
    }

    println!("HarfBuzz AFL++ fuzzer built successfully: {:?}", output_fuzzer_path);
}
