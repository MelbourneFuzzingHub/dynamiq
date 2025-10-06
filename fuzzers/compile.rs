use clap::Parser;
use std::{env, fs};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::os::unix::fs::PermissionsExt;

mod build_tasks;
use build_tasks::{jsoncpp, lcms, libjpeg_turbo, libpcap, libpng, libxml2, libxslt, harfbuzz, sqlite3, vorbis, libaom, mbedtls, freetype2, bloaty};

#[derive(Parser)]
struct Args {
    /// Path to the task file
    #[arg(short = 't', long)]
    task_file: PathBuf,

    /// Path to the target directory
    #[arg(short = 'd', long)]
    target_dir: PathBuf,

    /// Name of the binary to build
    #[arg(short = 'b', long)]
    binary_name: String,

    /// Task number (optional)
    #[arg(long)]
    task_number: Option<usize>,

    /// Ctx K Value (optional)
    #[arg(long)]
    ctx_k: Option<usize>,

    /// Optional 8-character hash value 
    #[arg(short = 'a', long)]
    hash: Option<String>,
}

fn create_allowlist_from_task(task_file: &Path, allowlist_file: &Path) -> io::Result<()> {
    let file = File::open(task_file)?;
    let reader = BufReader::new(file);
    let mut allowlist = File::create(allowlist_file)?;

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() == 2 {
            writeln!(allowlist, "src:{} fun:{}", parts[0], parts[1])?;
        }
    }

    Ok(())
}

fn configure_and_build_with_cmake(build_dir: &Path, target_dir: &str) {
    let cmake_files_dir = format!("{}/CMakeFiles", target_dir);

    if Path::new(&cmake_files_dir).exists() {
        println!("Removing existing CMakeFiles directory: {:?}", cmake_files_dir);
        fs::remove_dir_all(&cmake_files_dir).expect("Failed to remove existing CMakeFiles directory");
    }
    println!("Configuring with CMake...");
    Command::new("cmake")
        .arg("-G")
        .arg("Unix Makefiles")
        .arg(&format!("-DCMAKE_INSTALL_PREFIX={}/install", build_dir.display()))
        .arg("..")
        .env("CC", "/usr/local/bin/afl-clang-fast")
        .env("CXX", "/usr/local/bin/afl-clang-fast++")
        .current_dir(build_dir)
        .status()
        .expect("Couldn't configure target with CMake");

    Command::new("make")
        .arg("clean")
        .arg("all")
        .current_dir(build_dir)
        .status()
        .expect("Couldn't build with CMake");
}

fn configure_and_build_with_makefile(build_dir: &Path, target_dir: &str, binary_name: &str) {
    let _ = target_dir;
    println!("Configuring with Makefile...");

    Command::new("../configure")
        .arg(&format!("--prefix={}/install", build_dir.display()))
        .arg("--disable-shared")
        .env("CC", "/usr/local/bin/afl-clang-fast")
        .env("CXX", "/usr/local/bin/afl-clang-fast++")
        .current_dir(build_dir)
        .status()
        .expect("Couldn't configure target with Makefile");

    if binary_name == "sqlite3" {
        Command::new("make")
            .arg("sqlite3")
            .current_dir(build_dir)
            .status()
            .expect("Couldn't make sqlite3 binary");
    } else {
        Command::new("make")
            .arg("clean")
            .arg("all")
            .current_dir(build_dir)
            .status()
            .expect("Couldn't make target");
    }
}

fn generic_build_process(args: &Args, target_dir: &str, binary_name: &str) {
    let build_dir = if let Some(task_no) = args.task_number {
        Path::new(target_dir).join(format!("builddir-{}", task_no))
    } else {
        Path::new(target_dir).join("builddir")
    };

    // Ensure a clean build directory
    if build_dir.exists() {
        println!("Removing existing build directory: {:?}", build_dir);
        fs::remove_dir_all(&build_dir).expect("Failed to remove existing build directory");
    }
    println!("Creating build directory: {:?}", build_dir);
    fs::create_dir_all(&build_dir).expect("Failed to create build directory");

    // Handle CMake-based or Makefile-based builds
    let cmake_list_file = Path::new(target_dir).join("CMakeLists.txt");
    if cmake_list_file.exists() && !binary_name.contains("tiff") && !binary_name.contains("png") {
        configure_and_build_with_cmake(&build_dir, target_dir);
    } else {
        configure_and_build_with_makefile(&build_dir, target_dir, binary_name);
    }
}

fn main() {
    let args = Args::parse();

    let target_dir = args.target_dir.to_string_lossy().to_string();
    println!("target_dir {}", target_dir);

    let binary_name = args.binary_name.clone();

    // Path to the task file
    let task_file = args.task_file.clone();
    let task_file_stem = task_file.file_stem().unwrap().to_str().unwrap();

    // Compute allowlist filename
    let allowlist_name = format!("{}_{}_allowlist.txt", task_file_stem, binary_name);

    let allowlist_file = if let Some(hash) = &args.hash {
        let hash_dir = Path::new(hash);
        // Ensure the hash directory exists
        if !hash_dir.exists() {
            fs::create_dir_all(hash_dir).expect("Failed to create hash directory for allowlist");
        }
        hash_dir.join(&allowlist_name)
    } else {
        PathBuf::from(&allowlist_name)
    };

    // Create allowlist from task file
    create_allowlist_from_task(&task_file, &allowlist_file).expect("Couldn't create allowlist");

    // Verify the allowlist file exists and print its path for debugging
    if allowlist_file.exists() {
        println!("Allowlist file created at: {:?}", allowlist_file);
    } else {
        panic!("Allowlist file was not created.");
    }

    // Ensure the allowlist file has correct permissions
    fs::set_permissions(&allowlist_file, fs::Permissions::from_mode(0o644)).expect("Couldn't set permissions for allowlist file");

    // Export LLVM_CONFIG
    env::set_var("LLVM_CONFIG", "llvm-config-15");

    // Set AFL_LLVM_ALLOWLIST to the absolute path of the allowlist file
    let allowlist_path = allowlist_file.canonicalize().expect("Couldn't get canonical path of allowlist file");
    env::set_var("AFL_LLVM_ALLOWLIST", allowlist_path.to_string_lossy().to_string());

    // Verify the environment variable is set correctly
    if let Ok(value) = env::var("AFL_LLVM_ALLOWLIST") {
        println!("AFL_LLVM_ALLOWLIST is set to: {}", value);
    } else {
        println!("AFL_LLVM_ALLOWLIST is not set.");
    }

    env::set_var("AFL_LLVM_INSTRUMENT", "CLASSIC");
    println!("AFL_LLVM_INSTRUMENT: {}", env::var("AFL_LLVM_INSTRUMENT").unwrap_or("Not Set".to_string()));
    // Determine ctx_k value
    let ctx_k_value = if let Some(ctx_k_arg) = args.ctx_k {
        ctx_k_arg
    } else {
        // Fall back to default based on binary_name
        match binary_name.as_str() {
            "ossfuzz" => 2,
            _ => 4,
        }
    };

    if ctx_k_value != 0 {
        env::set_var("AFL_LLVM_CTX_K", ctx_k_value.to_string());
        println!("AFL_LLVM_CTX_K: {}", env::var("AFL_LLVM_CTX_K").unwrap_or("Not Set".to_string()));
    } else {
        println!("AFL_LLVM_CTX_K is 0, skipping export.");
    }

    // Compose the unique task ID used in builddir name
    let task_id = match (args.task_number, &args.hash) {
        (Some(n), Some(h)) => format!("{}-{}", h, n),
        (Some(n), None)    => n.to_string(),
        (None, Some(h))    => h.clone(),
        (None, None)       => String::from("default"),
    };

    println!("Composed task ID: {}", task_id);

    match binary_name.as_str() {
        "libpng_read_fuzzer" => libpng::build_libpng_read_fuzzer(&Path::new(&target_dir), Some(task_id.clone())),
        "libpcap_fuzz_both" => libpcap::build_libpcap_fuzz_both(&Path::new(&target_dir), Some(task_id.clone())),
        "fuzz-xml" => libxml2::build_fuzz_xml(&Path::new(&target_dir), Some(task_id.clone())),
        "jsoncpp_fuzzer" => jsoncpp::build_jsoncpp_fuzzer(&Path::new(&target_dir), Some(task_id.clone())),
        "cms_transform_fuzzer" => lcms::build_cms_transform_fuzzer(&Path::new(&target_dir), Some(task_id.clone())),
        "xpath" => libxslt::build_xpath(&Path::new(&target_dir), Some(task_id.clone())),
        "libjpeg_turbo_fuzzer" => libjpeg_turbo::build_libjpeg_turbo_fuzzer(&Path::new(&target_dir), Some(task_id.clone())),
        "hb-shape-fuzzer" => harfbuzz::build_hb_shape_fuzzer(&Path::new(&target_dir), Some(task_id.clone())),
        "ossfuzz" => sqlite3::build_sqlite3_afl(&Path::new(&target_dir), Some(task_id.clone())),
        "decode_fuzzer" => vorbis::build_vorbis(&Path::new(&target_dir), Some(task_id.clone())),
        "av1_dec_fuzzer" => libaom::build_av1_dec_fuzzer(&Path::new(&target_dir), Some(task_id.clone())),
        "fuzz_dtlsclient" => mbedtls::build_fuzz_dtlsclient(&Path::new(&target_dir), Some(task_id.clone())),
        "ftfuzzer" => freetype2::build_ftfuzzer(&Path::new(&target_dir), Some(task_id.clone())),
        "bloaty_fuzz_target" => bloaty::build_bloaty_fuzzer(&Path::new(&target_dir), Some(task_id.clone())),
        _ => generic_build_process(&args, &target_dir, &binary_name),
    }

    // Determine the build directory
    let build_dir = format!("{}/builddir-{}", target_dir, task_id);

    // Possible binary paths
    let binary_paths = vec![
        format!("{}/test/fuzzing/{}", build_dir, binary_name), // Default build
        format!("{}/.libs/{}", build_dir, binary_name),
        format!("{}/bin/{}", build_dir, binary_name),
        format!("{}/{}", build_dir, binary_name),
        format!("{}/tools/{}", build_dir, binary_name),
    ];

    println!("Binary paths: {:?}", binary_paths);

    let compiled_binary = format!("{}_{}.afl", task_file_stem, binary_name);

    // Search for the binary in the list of possible locations
    let mut found_path = None;
    for binary_path in &binary_paths {
        if Path::new(binary_path).exists() {
            found_path = Some(binary_path.clone());
            break;
        }
    }

    // If the binary is found, proceed, otherwise panic
    if let Some(path) = found_path {
        println!("Binary found at: {}", path);
    
        if let Some(hash) = &args.hash {
            let hash_dir = Path::new(hash);
            let binary_name = Path::new(&compiled_binary)
                .file_name()
                .expect("Invalid binary name");
    
            // Create the hash directory if it doesn't exist
            if !hash_dir.exists() {
                fs::create_dir_all(hash_dir).expect("Failed to create hash directory");
            }
    
            // Build the destination path: hash/compiled_binary
            let dest_path = hash_dir.join(binary_name);
    
            // Remove the existing binary if it exists
            if dest_path.exists() {
                fs::remove_file(&dest_path).expect("Failed to remove existing binary in hash dir");
                println!("Removed old binary at: {}", dest_path.display());
            }
    
            // Copy to hash directory
            fs::copy(&path, &dest_path).expect("Failed to copy binary to hash directory");
            println!("Copied binary to: {}", dest_path.display());
        } else {
            // Default: overwrite compiled_binary path
            let compiled_binary_path = Path::new(&compiled_binary);
            if compiled_binary_path.exists() {
                fs::remove_file(compiled_binary_path).expect("Failed to remove existing binary");
                println!("Removed old binary: {}", compiled_binary);
            }
    
            fs::copy(&path, compiled_binary_path).expect("Failed to copy binary");
            println!("Copied binary to: {}", compiled_binary);
        }
    } else {
        panic!("{} binary not found after build in any of the expected locations", binary_name);
    }

}
