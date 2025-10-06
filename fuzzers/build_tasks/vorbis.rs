use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn build_vorbis(target_dir: &Path, task_id: Option<String>) {
    println!("Building Vorbis with AFL instrumentation");

    // Determine build directories dynamically
    let build_dir_suffix = if let Some(id) = task_id {
        format!("builddir-{}", id)
    } else {
        "builddir".to_string()
    };

    let vorbis_build_dir = target_dir.parent().unwrap().join(&build_dir_suffix);
    let ogg_build_dir = target_dir.parent().unwrap().join("ogg").join(&build_dir_suffix);
    let vorbis_build_afl = target_dir.join(&build_dir_suffix);

    // Prepare the AFL++ path
    let aflplusplus_path = env::var("AFLPLUSPLUS").expect("AFLPLUSPLUS environment variable not set");

    // 1. Remove existing Vorbis build directory and recreate it
    if vorbis_build_dir.exists() {
        fs::remove_dir_all(&vorbis_build_dir).expect("Failed to remove existing Vorbis build directory");
    }
    fs::create_dir_all(&vorbis_build_dir).expect("Failed to create Vorbis build directory");

    // 2. Build Ogg
    if ogg_build_dir.exists() {
        fs::remove_dir_all(&ogg_build_dir).expect("Failed to remove existing Ogg build directory");
    }
    fs::create_dir_all(&ogg_build_dir).expect("Failed to create Ogg build directory");

    Command::new("../autogen.sh")
        .env("CC", "afl-clang-fast")
        .env("CXX", "afl-clang-fast++")
        .current_dir(&ogg_build_dir)
        .status()
        .expect("Failed to run autogen.sh for Ogg");

    Command::new("../configure")
        .args([
            &format!("--prefix={}/install", vorbis_build_dir.display()),
            "--enable-static",
            "--disable-shared",
            "--disable-crc",
        ])
        .env("CC", "afl-clang-fast")
        .env("CXX", "afl-clang-fast++")
        .current_dir(&ogg_build_dir)
        .status()
        .expect("Failed to configure Ogg");

    Command::new("make")
        .args(["clean", &format!("-j{}", num_cpus::get())])
        .current_dir(&ogg_build_dir)
        .status()
        .expect("Failed to clean Ogg build");

    Command::new("make")
        .arg("install")
        .current_dir(&ogg_build_dir)
        .status()
        .expect("Failed to install Ogg");

    // 3. Build Vorbis
    if vorbis_build_afl.exists() {
        fs::remove_dir_all(&vorbis_build_afl).expect("Failed to remove existing Vorbis build directory");
    }
    fs::create_dir_all(&vorbis_build_afl).expect("Failed to create Vorbis build directory");

    Command::new("../autogen.sh")
        .env("CC", "afl-clang-fast")
        .env("CXX", "afl-clang-fast++")
        .current_dir(&vorbis_build_afl)
        .status()
        .expect("Failed to run autogen.sh for Vorbis");

    Command::new("../configure")
        .args([
            &format!("--prefix={}/install", vorbis_build_dir.display()),
            "--enable-static",
            "--disable-shared",
        ])
        .env("CC", "afl-clang-fast")
        .env("CXX", "afl-clang-fast++")
        .current_dir(&vorbis_build_afl)
        .status()
        .expect("Failed to configure Vorbis");

    Command::new("make")
        .args(["clean", &format!("-j{}", num_cpus::get())])
        .current_dir(&vorbis_build_afl)
        .status()
        .expect("Failed to clean Vorbis build");

    Command::new("make")
        .arg("install")
        .current_dir(&vorbis_build_afl)
        .status()
        .expect("Failed to install Vorbis");

    // 4. Build decode_fuzzer
    let decode_fuzzer_path = vorbis_build_afl.join("decode_fuzzer");
    Command::new("afl-clang-fast++")
        .args([
            "../contrib/oss-fuzz/decode_fuzzer.cc",
            "-o",
            decode_fuzzer_path.to_str().unwrap(),
            "-I",
            &format!("{}/install/include", vorbis_build_dir.display()),
            "-L",
            &format!("{}/install/lib", vorbis_build_dir.display()),
            &format!("{}/utils/aflpp_driver/libAFLDriver.a", aflplusplus_path),
            "-lvorbisfile",
            "-lvorbis",
            "-logg",
        ])
        .current_dir(&vorbis_build_afl)
        .status()
        .expect("Failed to build decode_fuzzer");

    println!("Successfully built Vorbis with AFL instrumentation!");
}
