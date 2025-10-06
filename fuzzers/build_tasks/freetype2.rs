use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn build_ftfuzzer(target_dir: &Path, task_id: Option<String>) {
    println!("Building FreeType2 ftfuzzer with AFL++ instrumentation");

    // Define build directories
    let build_dir = if let Some(id) = task_id.as_ref() {
        target_dir.join(format!("builddir-{}", id))
    } else {
        target_dir.join("builddir")
    };

    // Define libarchive build directory with task number
    let libarchive_build_dir = if let Some(id) = task_id.as_ref() {
        target_dir
            .parent()
            .unwrap()
            .join(format!("libarchive-3.4.3/builddir-{}", id))
    } else {
        target_dir
            .parent()
            .unwrap()
            .join("libarchive-3.4.3/builddir")
    };

    // Clean existing directories
    if build_dir.exists() {
        fs::remove_dir_all(&build_dir).expect("Failed to remove existing FreeType2 build directory");
    }
    if libarchive_build_dir.exists() {
        fs::remove_dir_all(&libarchive_build_dir).expect("Failed to remove existing libarchive build directory");
    }

    //Define install directory inside FreeType2 build directory
    let freetype_install_dir = build_dir.join("install");

    // Define install directory inside libarchive build directory
    let libarchive_install_dir = libarchive_build_dir.join("install");

    fs::create_dir_all(&build_dir).expect("Failed to create FreeType2 build directory");
    fs::create_dir_all(&libarchive_build_dir).expect("Failed to create libarchive build directory");

    // Set environment variables
    let cc = "afl-clang-fast";
    let cxx = "afl-clang-fast++";
    let aflplusplus_path = env::var("AFLPLUSPLUS").expect("AFLPLUSPLUS environment variable not set");

    // === Build libarchive with AFL++ ===
    println!("Building libarchive with AFL++");
    Command::new("../configure")
        .arg("--disable-shared")
        .arg(format!("--prefix={}", libarchive_install_dir.display()))
        .env("CC", cc)
        .env("CXX", cxx)
        .current_dir(&libarchive_build_dir)
        .status()
        .expect("Failed to configure libarchive");

    Command::new("make")
        .arg(format!("-j{}", num_cpus::get()))
        .current_dir(&libarchive_build_dir)
        .status()
        .expect("Failed to build libarchive");

    Command::new("make")
        .arg("install")
        .current_dir(&libarchive_build_dir)
        .status()
        .expect("Failed to install libarchive");

    // === Build FreeType2 with AFL++ ===
    println!("Building FreeType2 with AFL++");
    Command::new("../configure")
        .arg(format!("--prefix={}", freetype_install_dir.display()))
        .arg("--with-harfbuzz=no")
        .arg("--with-bzip2=no")
        .arg("--with-png=no")
        .arg("--without-zlib")
        .arg("--with-brotli=no")
        .env("CC", cc)
        .env("CXX", cxx)
        .current_dir(&build_dir)
        .status()
        .expect("Failed to configure FreeType2");

    Command::new("make")
        .arg("clean")
        .current_dir(&build_dir)
        .status()
        .expect("Failed to clean FreeType2 build");

    Command::new("make")
        .arg(format!("-j{}", num_cpus::get()))
        .current_dir(&build_dir)
        .status()
        .expect("Failed to build FreeType2");

    Command::new("make")
        .arg("install")
        .current_dir(&build_dir)
        .status()
        .expect("Failed to install FreeType2");

    // === Compile and Link Fuzzer ===
    let libfreetype_path = build_dir.join("install/lib/libfreetype.a");
    let libarchive_path = libarchive_build_dir.join("install/lib/libarchive.a");
    let libarchive_include_path = libarchive_build_dir.join("install/include");
    let fuzzer_output = build_dir.join("ftfuzzer");

    println!("Linking FreeType2 fuzzer...");
    Command::new(cxx)
        .arg("-std=c++11")
        .arg("-I../include")
        .arg("-I..")
        .arg(format!("-I{}", libarchive_include_path.display()))
        .arg("../src/tools/ftfuzzer/ftfuzzer.cc")
        .arg(libfreetype_path.to_str().unwrap())
        .arg(format!("{}/utils/aflpp_driver/libAFLDriver.a", aflplusplus_path))
        .arg(libarchive_path.to_str().unwrap())
        .arg("-o")
        .arg(fuzzer_output.to_str().unwrap())
        .current_dir(&build_dir)
        .status()
        .expect("Failed to compile FreeType2 fuzzer");

    println!("FreeType2 fuzzer built successfully: {:?}", fuzzer_output);
}
