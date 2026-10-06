use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn build_tiff_read_rgba_fuzzer(target_dir: &Path, task_id: Option<String>) {
    println!("Building tiff_read_rgba_fuzzer");

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

    // Configure the build
    Command::new("../configure")
        .arg("--disable-shared")
        .arg(format!("--prefix={}/install", build_dir.display()))
        .arg("--disable-zstd")
        .arg("--disable-webp")
        .arg("--disable-pixarlog")
        .env("CC", "afl-clang-fast")
        .env("CXX", "afl-clang-fast++")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't configure libtiff with AFL++");

    // Run `make clean`
    Command::new("make")
        .arg("clean")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't make clean libtiff");

    // Run `make -j$(nproc)`
    Command::new("make")
        .arg(format!("-j{}", num_cpus::get()))
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't build libtiff with make");

    // Run `make install`
    Command::new("make")
        .arg("install")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't install libtiff");

    // Compile the fuzzer binary
    Command::new("afl-clang-fast++")
        .arg("-std=c++11")
        .arg("-Iinstall/include")
        .arg("../contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc")
        .arg("-o")
        .arg("tiff_read_rgba_fuzzer")
        .arg(format!(
            "{}/utils/aflpp_driver/libAFLDriver.a",
            aflplusplus_path
        ))
        .arg("install/lib/libtiffxx.a")
        .arg("install/lib/libtiff.a")
        .arg("-lz")
        .arg("-ljpeg")
        .arg("-ldeflate")
        .arg("-ljbig")
        .arg("-Wl,-Bstatic")
        .arg("-llzma")
        .arg("-Wl,-Bdynamic")
        .arg("-lm")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't compile tiff_read_rgba_fuzzer binary");
}
