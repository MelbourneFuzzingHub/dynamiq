use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn copy_source_to_build_dir(source_dir: &Path, build_dir: &Path) {
    println!("Creating isolated Lua build directory with manual hardlink copy...");

    let entries = fs::read_dir(source_dir).expect("Failed to read source directory");
    for entry in entries {
        let entry = entry.expect("Failed to read dir entry");
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        if name.starts_with("builddir-") || name.starts_with("build-") || name == ".git" {
            continue;
        }

        Command::new("cp")
            .arg("-al")
            .arg(&path)
            .arg(build_dir)
            .status()
            .expect("Failed to cp -al entry");
    }
}

fn make_lua_binary(build_dir: &Path) {
    let cc = env::var("CC").unwrap_or_else(|_| "afl-clang-fast".to_string());

    Command::new("make")
        .arg("clean")
        .current_dir(build_dir)
        .status()
        .expect("Couldn't make clean Lua");

    let lib_status = Command::new("make")
        .arg(format!("-j{}", num_cpus::get()))
        .arg(format!("CC={}", cc))
        .arg("MYCFLAGS=-DLUA_USE_LINUX")
        .arg("liblua.a")
        .current_dir(build_dir)
        .status()
        .expect("Couldn't build liblua.a");

    if !lib_status.success() {
        panic!("Failed to build liblua.a");
    }

    let lua_status = Command::new("make")
        .arg(format!("-j{}", num_cpus::get()))
        .arg(format!("CC={}", cc))
        .arg("MYCFLAGS=-DLUA_USE_LINUX")
        .arg("MYLIBS=-ldl")
        .arg("lua")
        .current_dir(build_dir)
        .status()
        .expect("Couldn't build lua binary");

    if !lua_status.success() {
        panic!("Failed to build lua binary");
    }
}

pub fn build_lua_cli(target_dir: &Path, task_id: Option<String>) {
    println!("Building lua");

    let build_dir = if let Some(id) = task_id {
        target_dir.join(format!("builddir-{}", id))
    } else {
        target_dir.join("builddir")
    };

    if build_dir.exists() {
        fs::remove_dir_all(&build_dir).expect("Failed to remove existing build directory");
    }

    fs::create_dir_all(&build_dir).expect("Failed to create build directory");

    let source_dir = target_dir
        .canonicalize()
        .expect("Couldn't canonicalize source directory");
    copy_source_to_build_dir(&source_dir, &build_dir);
    make_lua_binary(&build_dir);
}

pub fn build_lua_fuzzer(target_dir: &Path, task_id: Option<String>) {
    println!("Building fuzz_lua");

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
        Command::new("cp")
            .arg("-al")
            .arg(&path)
            .arg(&build_dir)
            .status()
            .expect("Failed to cp -al entry");
    }

    // Determine CC and CXX from environment or use afl-clang-fast as default
    let cc = env::var("CC").unwrap_or_else(|_| "afl-clang-fast".to_string());
    let cxx = env::var("CXX").unwrap_or_else(|_| "afl-clang-fast++".to_string());

    // Run `make clean`
    Command::new("make")
        .arg("clean")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't make clean Lua");

    // Run `make liblua.a`
    Command::new("make")
        .arg(format!("-j{}", num_cpus::get()))
        .arg(format!("CC={}", cc))
        .arg("MYCFLAGS=-DLUA_USE_LINUX")
        .arg("liblua.a")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't build liblua.a");

    // Run `make lua`
    Command::new("make")
        .arg(format!("-j{}", num_cpus::get()))
        .arg(format!("CC={}", cc))
        .arg("MYCFLAGS=-DLUA_USE_LINUX")
        .arg("MYLIBS=-ldl")
        .arg("lua")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't build lua binary");

    // Find the fuzz driver (fuzz_lua.c) robustly
    let fuzz_driver_src = if build_dir.join("fuzz_lua.c").exists() {
        build_dir.join("fuzz_lua.c")
    } else if source_dir.join("fuzz_lua.c").exists() {
        source_dir.join("fuzz_lua.c")
    } else if source_dir
        .parent()
        .map(|p| p.join("lua_setup/fuzz_lua.c"))
        .map_or(false, |p| p.exists())
    {
        source_dir.parent().unwrap().join("lua_setup/fuzz_lua.c")
    } else if let Ok(dynamiq_raw) = env::var("DYNAMIQ") {
        let dynamiq = if dynamiq_raw.starts_with("~/") {
            if let Ok(home) = env::var("HOME") {
                dynamiq_raw.replacen("~", &home, 1)
            } else {
                dynamiq_raw
            }
        } else {
            dynamiq_raw
        };
        let p = Path::new(&dynamiq).join("oss/lua_setup/fuzz_lua.c");
        if p.exists() {
            p
        } else {
            panic!("Fuzz driver not found at {:?} or other common locations", p);
        }
    } else {
        panic!("Fuzz driver not found in build dir, source dir, or lua_setup directory");
    };

    println!("Using fuzz driver at: {:?}", fuzz_driver_src);

    // Compile the fuzz driver
    Command::new(&cc)
        .arg("-DLUA_USE_LINUX")
        .arg("-I.")
        .arg("-c")
        .arg(&fuzz_driver_src)
        .arg("-o")
        .arg("fuzz_lua.o")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't compile fuzz_lua.o");

    // Link the final fuzzer binary
    Command::new(&cxx)
        .arg("fuzz_lua.o")
        .arg("-o")
        .arg("fuzz_lua")
        .arg(format!(
            "{}/utils/aflpp_driver/libAFLDriver.a",
            aflplusplus_path
        ))
        .arg("liblua.a")
        .arg("-lm")
        .arg("-ldl")
        .current_dir(&build_dir)
        .status()
        .expect("Couldn't link fuzz_lua binary");
}
