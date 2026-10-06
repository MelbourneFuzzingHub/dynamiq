use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn build_harfbuzz_fuzzer(target_dir: &Path, task_id: Option<String>, fuzzer_name: &str) {
    println!("Building {}", fuzzer_name);

    let build_dir = if let Some(id) = task_id {
        target_dir.join(format!("builddir-{}", id))
    } else {
        target_dir.join("builddir")
    };

    if build_dir.exists() {
        fs::remove_dir_all(&build_dir).expect("Failed to remove existing build directory");
    }

    fs::create_dir_all(&build_dir).expect("Failed to create build directory");

    let aflplusplus_path =
        env::var("AFLPLUSPLUS").expect("AFLPLUSPLUS environment variable not set");

    let meson_status = Command::new("meson")
        .arg("..")
        .arg("--default-library=static")
        .arg("--wrap-mode=nodownload")
        .arg("-Dexperimental_api=true")
        .arg(format!(
            "-Dfuzzer_ldflags={}/utils/aflpp_driver/libAFLDriver.a",
            aflplusplus_path
        ))
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

    let meson_target = format!("test/fuzzing/{}", fuzzer_name);
    let ninja_status = Command::new("ninja")
        .arg("-v")
        .arg(format!("-j{}", num_cpus::get()))
        .arg(&meson_target)
        .current_dir(&build_dir)
        .status()
        .expect("Failed to build HarfBuzz fuzzer with Ninja");

    if !ninja_status.success() {
        panic!("Ninja build failed.");
    }

    let fuzzer_path = build_dir.join(&meson_target);
    let output_fuzzer_path = build_dir.join(fuzzer_name);

    if fuzzer_path.exists() {
        fs::rename(&fuzzer_path, &output_fuzzer_path)
            .unwrap_or_else(|_| panic!("Failed to move the built {} binary", fuzzer_name));
    } else {
        panic!("{} binary not found!", fuzzer_name);
    }

    println!(
        "HarfBuzz AFL++ fuzzer built successfully: {:?}",
        output_fuzzer_path
    );
}

pub fn build_hb_shape_fuzzer(target_dir: &Path, task_id: Option<String>) {
    build_harfbuzz_fuzzer(target_dir, task_id, "hb-shape-fuzzer");
}

pub fn build_hb_subset_fuzzer(target_dir: &Path, task_id: Option<String>) {
    build_harfbuzz_fuzzer(target_dir, task_id, "hb-subset-fuzzer");
}
