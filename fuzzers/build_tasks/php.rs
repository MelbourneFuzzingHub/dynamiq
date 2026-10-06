use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn run(cmd: &mut Command, where_: &Path, what: &str) {
    let status = cmd
        .current_dir(where_)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn {}: {}", what, e));
    if !status.success() {
        panic!("{} failed with status {:?}", what, status.code());
    }
}

/// Build a php-src fuzz target with AFL++ (autoconf flow).
/// `target_dir` should be the `php-src` root. The build output goes to:
///   - {target_dir}/builddir-<task_id>  if task_id is Some(...)
///   - {target_dir}/builddir            otherwise
fn build_php_fuzzer_afl(target_dir: &Path, task_id: Option<String>, fuzzer_name: &str) {
    // Resolve AFL++ paths / env
    let aflpp = env::var("AFLPLUSPLUS")
        .expect("AFLPLUSPLUS environment variable not set (path to AFL++ repo)");
    let lib_fuzzing_engine = format!("{}/utils/aflpp_driver/libAFLDriver.a", aflpp);
    let fuzzer_path = format!("sapi/fuzzer/{}", fuzzer_name);

    // 1) set build dir using your requested pattern
    let build_dir: PathBuf = if let Some(id) = task_id {
        target_dir.join(format!("builddir-{}", id))
    } else {
        target_dir.join("builddir")
    };

    if build_dir.exists() {
        fs::remove_dir_all(&build_dir).expect("failed to remove existing builddir");
    }
    fs::create_dir_all(&build_dir).expect("failed to create builddir");

    // 2) ../configure with required env (mirrors your Makefile)
    let mut cfg = Command::new("../configure");
    cfg.env("LIB_FUZZING_ENGINE", &lib_fuzzing_engine)
        .env("FUZZING_CC", "afl-clang-fast++")
        .env("CC", "afl-clang-fast")
        .env("CXX", "afl-clang-fast++")
        .env(
            "CFLAGS",
            "-fno-sanitize=object-size -DPROFITABILITY_CHECKS=0",
        )
        .env(
            "CXXFLAGS",
            "-fno-sanitize=object-size -DPROFITABILITY_CHECKS=0",
        )
        .args([
            "--disable-all",
            "--enable-debug-assertions",
            "--enable-option-checking=fatal",
            "--enable-fuzzer",
            "--enable-exif",
            "--without-pcre-jit",
            "--disable-phpdbg",
            "--disable-cgi",
            "--enable-pic",
        ]);
    run(&mut cfg, &build_dir, "configure");

    // 3) make libs and CLI first (same env)
    let mut make_libs = Command::new("make");
    make_libs
        .env("LIB_FUZZING_ENGINE", &lib_fuzzing_engine)
        .env("FUZZING_CC", "afl-clang-fast++")
        .env("CC", "afl-clang-fast")
        .env("CXX", "afl-clang-fast++")
        .arg(format!("-j{}", num_cpus::get()))
        .args(["libs", "sapi/cli/php"]);
    run(&mut make_libs, &build_dir, "make libs + cli");

    // 4) build only the selected fuzzer (respect PHP_FUZZER_BINARIES)
    let mut make_fuzzer = Command::new("make");
    make_fuzzer
        .env("LIB_FUZZING_ENGINE", &lib_fuzzing_engine)
        .env("FUZZING_CC", "afl-clang-fast++")
        .env("CC", "afl-clang-fast")
        .env("CXX", "afl-clang-fast++")
        .env("PHP_FUZZER_BINARIES", &fuzzer_path)
        .arg(format!("-j{}", num_cpus::get()))
        .arg("fuzzer");
    run(
        &mut make_fuzzer,
        &build_dir,
        &format!("make {}", fuzzer_name),
    );

    // 5) copy the binary to the build dir root for convenience (like `mv`)
    let src = build_dir.join(&fuzzer_path);
    let dst = build_dir.join(fuzzer_name);
    fs::copy(&src, &dst)
        .unwrap_or_else(|e| panic!("failed to copy {} to build root: {}", fuzzer_name, e));
    println!("Built: {}", dst.display());
}

pub fn build_php_fuzz_parser_afl(target_dir: &Path, task_id: Option<String>) {
    build_php_fuzzer_afl(target_dir, task_id, "php-fuzz-parser");
}

pub fn build_php_fuzz_exif_afl(target_dir: &Path, task_id: Option<String>) {
    build_php_fuzzer_afl(target_dir, task_id, "php-fuzz-exif");
}
