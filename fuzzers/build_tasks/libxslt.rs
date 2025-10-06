use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::io;

fn copy_dir_recursive(src: &Path, dst: &Path) -> io::Result<()> {
    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

pub fn build_xpath(target_dir: &Path, task_id: Option<String>) {
    println!("Building libxslt with AFL instrumentation");

    // Determine build directories
    let libxml2_target_dir = target_dir.parent().unwrap().join("libxml2");
    let libxml2_build_dir = if let Some(id) = task_id.as_ref() {
        libxml2_target_dir.join(format!("builddir-{}", id))
    } else {
        libxml2_target_dir.join("builddir")
    };

    let libxslt_build_dir = if let Some(id) = task_id.as_ref() {
        target_dir.join(format!("builddir-{}", id))
    } else {    
        target_dir.join("builddir")
    };

    // Prepare the AFL++ path
    let aflplusplus_path = env::var("AFLPLUSPLUS").expect("AFLPLUSPLUS environment variable not set");

    // 1. Build libxml2
    if libxml2_build_dir.exists() {
        fs::remove_dir_all(&libxml2_build_dir).expect("Failed to remove existing libxml2 build directory");
    }
    fs::create_dir_all(&libxml2_build_dir).expect("Failed to create libxml2 build directory");

    // Mandatory copy of the include directory
    let include_dir = libxml2_target_dir.join("include");
    let include_dst = libxml2_build_dir.join("include");

    if include_dir.exists() {
        copy_dir_recursive(&include_dir, &include_dst).expect("Failed to copy include directory");
    } else {
        panic!("Include directory not found at {:?}", include_dir);
    }

    Command::new("../configure")
        .args([
            "--disable-shared",
            "--without-c14n",
            "--without-push",
            "--without-python",
            "--without-reader",
            "--without-regexps",
            "--without-sax1",
            "--without-schemas",
            "--without-schematron",
            "--without-valid",
            "--without-writer",
            "--without-zlib",
            "--without-lzma",
        ])
        .env("CC", "afl-clang-fast")
        .env("CXX", "afl-clang-fast++")
        .current_dir(&libxml2_build_dir)
        .status()
        .expect("Failed to configure libxml2");

    Command::new("make")
        .arg(format!("-j{}", num_cpus::get()))
        .current_dir(&libxml2_build_dir)
        .status()
        .expect("Failed to build libxml2");

    // 2. Build libxslt
    if libxslt_build_dir.exists() {
        fs::remove_dir_all(&libxslt_build_dir).expect("Failed to remove existing libxslt build directory");
    }
    fs::create_dir_all(&libxslt_build_dir).expect("Failed to create libxslt build directory");

    Command::new("../configure")
        .args([
            &format!("--with-libxml-src={}", libxml2_build_dir.display()),
            "--disable-shared",
            "--without-python",
            "--without-crypto",
            "--without-debug",
            "--without-debugger",
            "--without-profiler",
        ])
        .env("CC", "afl-clang-fast")
        .env("CXX", "afl-clang-fast++")
        .env("CPPFLAGS", &format!("-I{}", libxml2_build_dir.join("include").display()))
        .env("LDFLAGS", &format!("-L{}", libxml2_build_dir.join(".libs").display()))
        .current_dir(&libxslt_build_dir)
        .status()
        .expect("Failed to configure libxslt");

    Command::new("make")
        .arg(format!("-j{}", num_cpus::get()))
        .current_dir(&libxslt_build_dir)
        .status()
        .expect("Failed to build libxslt");

    // 3. Build xpath fuzzer
    let tests_fuzz_dir = libxslt_build_dir.join("tests").join("fuzz");

    Command::new("make")
        .args(["fuzz.o", "xpath.o"])
        .current_dir(&tests_fuzz_dir)
        .status()
        .expect("Failed to build fuzz.o and xpath.o");

    Command::new("afl-clang-fast++")
        .args([
            "-std=c++11",
            "xpath.o",
            "fuzz.o",
            "-o",
            "../../xpath",
            &format!("{}/utils/aflpp_driver/libAFLDriver.a", aflplusplus_path),
            "../../libexslt/.libs/libexslt.a",
            "../../libxslt/.libs/libxslt.a",
            &format!("{}/.libs/libxml2.a", libxml2_build_dir.display()),
        ])
        .current_dir(&tests_fuzz_dir)
        .status()
        .expect("Failed to build xpath fuzzer");

    println!("Successfully built xpath fuzzer");
}
