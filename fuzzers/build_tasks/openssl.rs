use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn build_openssl_x509(target_dir: &Path, task_id: Option<String>) {
    println!("Building openssl x509");

    let build_dir = if let Some(id) = task_id {
        target_dir.join(format!("builddir-{}", id))
    } else {
        target_dir.join("builddir")
    };

    if build_dir.exists() {
        fs::remove_dir_all(&build_dir).expect("Failed to remove existing build directory");
    }

    fs::create_dir_all(&build_dir).expect("Failed to create build directory");

    let mut aflplusplus_path =
        env::var("AFLPLUSPLUS").expect("AFLPLUSPLUS environment variable not set");
    if aflplusplus_path.starts_with("~/") {
        if let Ok(home) = env::var("HOME") {
            aflplusplus_path = aflplusplus_path.replacen("~", &home, 1);
        }
    }

    // Canonicalize target_dir to get an absolute path to the source
    let source_dir = target_dir
        .canonicalize()
        .expect("Couldn't canonicalize source directory");

    // CRITICAL: Clean up build artifacts in the source tree that block out-of-source builds
    let artifacts_to_clean = vec![
        source_dir.join("Makefile"),
        source_dir.join("Makefile.in"),
        source_dir.join("configdata.pm"),
        source_dir.join("include/openssl/configuration.h"),
    ];

    for artifact in artifacts_to_clean {
        if artifact.exists() {
            println!("Cleaning up source artifact: {:?}", artifact);
            let _ = fs::remove_file(artifact);
        }
    }

    // Copy the dictionary file
    let dict_src = source_dir.join("fuzz/oids.txt");
    let dict_dest = source_dir.join("x509.dict");
    if dict_src.exists() {
        let _ = fs::copy(&dict_src, &dict_dest); // Ignore failure if already exists or permission issue
    }

    // CRITICAL: Mimic the build process exactly.
    // Since out-of-source builds are flaky in OpenSSL 4.0.0-dev, we create a private copy of the source.
    // We use manual top-level iteration + cp -al to create hardlinks safely without recursion.
    println!("Creating isolated build directory with manual hardlink copy...");

    let entries = fs::read_dir(&source_dir).expect("Failed to read source directory");
    for entry in entries {
        let entry = entry.expect("Failed to read dir entry");
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        // Skip build directories and self to avoid recursion
        if name.starts_with("builddir-") || name.starts_with("build-") || name == ".git" {
            continue;
        }

        // Use cp -al for recursive hardlinking of this entry
        // This preserves the directory structure and uses zero disk space for files
        Command::new("cp")
            .arg("-al")
            .arg(&path)
            .arg(&build_dir)
            .status()
            .expect("Failed to cp -al entry");
    }

    // CRITICAL: Remove any hardlinked artifacts or nested build directories to ensure a fresh build
    // This prevents conflicts between parallel tasks.
    let _ = fs::remove_file(build_dir.join("Makefile"));
    let _ = fs::remove_file(build_dir.join("Makefile.in"));
    let _ = fs::remove_file(build_dir.join("configdata.pm"));
    let _ = fs::remove_file(build_dir.join("include/openssl/configuration.h"));

    // Also remove any nested build directories that were hardlinked
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "rm -rf {}/builddir-* {}/build-*",
            build_dir.display(),
            build_dir.display()
        ))
        .status();

    // Configure the build using ./config IN the build_dir (now a private copy)
    Command::new("./config")
        .arg("--debug")
        .arg("enable-fuzz-libfuzzer")
        .arg("enable-fuzz-afl")
        .arg("disable-tests")
        .arg("-DPEDANTIC")
        .arg("-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION")
        .arg("no-shared")
        .arg("no-module")
        .arg("enable-tls1_3")
        .arg("enable-rc5")
        .arg("enable-md2")
        .arg("enable-ec_nistp_64_gcc_128")
        .arg("enable-nextprotoneg")
        .arg("enable-weak-ssl-ciphers")
        .arg("-fno-sanitize=alignment")
        .arg(format!("--prefix={}/build-afl", build_dir.display()))
        .env("CC", "afl-clang-fast")
        .env("CXX", "afl-clang-fast++")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't configure OpenSSL with ./config");

    // Run `make clean`
    Command::new("make")
        .arg("clean")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't make clean OpenSSL");

    // Run `make build_libs`
    Command::new("make")
        .arg(format!("-j{}", num_cpus::get()))
        .arg("build_libs")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't build OpenSSL libraries");

    // Link the x509 fuzzer
    Command::new("make")
        .arg(format!("-j{}", num_cpus::get()))
        .arg(format!(
            "LDCMD=afl-clang-fast++ {}/utils/aflpp_driver/libAFLDriver.a",
            aflplusplus_path
        ))
        .arg("fuzz/x509")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't compile OpenSSL x509 fuzzer binary");

    // Copy the built fuzzer to the root of build_dir so compile.rs can find it
    let fuzzer_src = build_dir.join("fuzz/x509");
    let fuzzer_dest = build_dir.join("x509");
    if fuzzer_src.exists() {
        fs::copy(&fuzzer_src, &fuzzer_dest).expect("Failed to copy x509 fuzzer binary");
    } else {
        panic!("x509 fuzzer binary not found in fuzz/ directory");
    }
}
