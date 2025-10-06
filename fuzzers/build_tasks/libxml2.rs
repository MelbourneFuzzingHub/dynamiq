use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

pub fn build_fuzz_xml(target_dir: &Path, task_id: Option<String>) {
    println!("Building fuzz-xml");

    // Define build directory format
    let build_dir = if let Some(id) = task_id {
        target_dir.join(format!("builddir-{}", id))
    } else {
        target_dir.join("builddir")
    };

    if build_dir.exists() {
        fs::remove_dir_all(&build_dir).expect("Failed to remove existing build directory");
    }

    fs::create_dir_all(&build_dir).expect("Failed to create build directory");

    // Set environment variables
    let cc = "afl-clang-fast";
    let cxx = "afl-clang-fast++";
    let aflplusplus_path = env::var("AFLPLUSPLUS").expect("AFLPLUSPLUS environment variable not set");

    // Configure the build
    Command::new("../configure")
        .arg("--disable-shared")
        .arg("--without-debug")
        .arg("--without-http")
        .arg("--without-python")
        .arg("--with-zlib")
        .arg("--with-lzma")
        .env("CC", cc)
        .env("CXX", cxx)
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't configure fuzz-xml with AFL++");

    // Run `make -j$(nproc)`
    Command::new("make")
        .arg(format!("-j{}", num_cpus::get()))
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't build fuzz-xml with make");

    // Use correct include paths to avoid missing xmlversion.h
    let include_path = format!("-I{}", build_dir.join("include").display());

    let source_files = vec!["../fuzz/fuzz.c", "../fuzz/xml.c"];
    for source in source_files {
        let output_file = format!("../fuzz/{}.o", Path::new(source).file_stem().unwrap().to_str().unwrap());
        Command::new(cc)
            .arg("-c")
            .arg(source)
            .arg("-o")
            .arg(output_file)
            .arg(&include_path)  // Fix: Use builddir-{}/include
            .arg(format!("-I{}", target_dir.join("include").display()))
            .current_dir(&build_dir)
            .status()
            .expect(&format!("Couldn't compile {}", source));
    }
 
    // Check if fuzz.o and xml.o exist
    let fuzz_o_path = build_dir.join("../fuzz/fuzz.o");
    let xml_o_path = build_dir.join("../fuzz/xml.o");

    if !fuzz_o_path.exists() || !xml_o_path.exists() {
        panic!("Error: fuzz.o or xml.o not found. Ensure `make` completed successfully.");
    }
 
    // Link the fuzz-xml binary
    let fuzz_binary = build_dir.join("fuzz-xml");
    Command::new(cc)
        .arg("-o")
        .arg(&fuzz_binary)
        .arg("../fuzz/xml.o")
        .arg("../fuzz/fuzz.o")
        .arg(format!("{}/utils/aflpp_driver/libAFLDriver.a", aflplusplus_path))
        .arg(".libs/libxml2.a")
        .arg("-Wl,-Bstatic")
        .arg("-lz")
        .arg("-llzma")
        .arg("-Wl,-Bdynamic")
        .arg("-lm")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't compile fuzz-xml binary");
}
