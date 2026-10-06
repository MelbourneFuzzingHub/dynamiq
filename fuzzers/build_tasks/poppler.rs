use std::env;
use std::fs::{self, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::Path;
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

fn ensure_freetype_configure(source_dir: &Path) {
    let lock_path = source_dir.join(".dynamiq-autogen.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&lock_path)
        .unwrap_or_else(|e| panic!("failed to open {}: {}", lock_path.display(), e));

    let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) };
    if result != 0 {
        panic!(
            "failed to lock {}: {}",
            lock_path.display(),
            std::io::Error::last_os_error()
        );
    }

    if !source_dir.join("configure").is_file() {
        let mut autogen = Command::new("./autogen.sh");
        run(&mut autogen, source_dir, "autogen.sh");
    }
}

fn verify_checkout(source_dir: &Path, variable: &str) {
    let expected =
        env::var(variable).unwrap_or_else(|_| panic!("{} environment variable not set", variable));
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(source_dir)
        .output()
        .unwrap_or_else(|e| panic!("failed to inspect {}: {}", source_dir.display(), e));
    if !output.status.success() {
        panic!("git rev-parse failed for {}", source_dir.display());
    }
    let actual = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if actual != expected {
        panic!(
            "{} checkout mismatch at {}: expected {}, found {}",
            variable,
            source_dir.display(),
            expected,
            actual
        );
    }
}

fn verify_pinned_sources(target_dir: &Path) {
    verify_checkout(&target_dir.join("repo"), "POPPLER_REF");
    verify_checkout(&target_dir.join("freetype2"), "FREETYPE_REF");
}

pub fn build_pdf_fuzzer(target_dir: &Path, task_id: Option<String>) {
    println!("Building Poppler pdf_fuzzer with AFL++ instrumentation");
    verify_pinned_sources(target_dir);

    // Define build directory with task ID
    let build_dir = if let Some(id) = task_id.as_ref() {
        target_dir.join(format!("builddir-{}", id))
    } else {
        target_dir.join("builddir")
    };

    // Clean existing build directory
    if build_dir.exists() {
        fs::remove_dir_all(&build_dir).expect("Failed to remove existing build directory");
    }
    fs::create_dir_all(&build_dir).expect("Failed to create build directory");

    let install_dir = build_dir.join("install");
    let freetype_build_dir = build_dir.join("freetype_build");
    let poppler_build_dir = build_dir.join("poppler_build");

    fs::create_dir_all(&freetype_build_dir).expect("Failed to create freetype build dir");
    fs::create_dir_all(&poppler_build_dir).expect("Failed to create poppler build dir");

    let aflplusplus_path =
        env::var("AFLPLUSPLUS").expect("AFLPLUSPLUS environment variable not set");
    let cc = "afl-clang-fast";
    let cxx = "afl-clang-fast++";

    // === 1. Build Freetype ===
    println!("Building Freetype...");

    ensure_freetype_configure(&target_dir.join("freetype2"));

    let mut ft_cfg = Command::new("../../freetype2/configure");
    ft_cfg
        .arg(format!("--prefix={}", install_dir.display()))
        .arg("--disable-shared")
        .arg(format!(
            "PKG_CONFIG_PATH={}/lib/pkgconfig",
            install_dir.display()
        ))
        .arg("--with-harfbuzz=no")
        .arg("--with-bzip2=no")
        .arg("--with-png=no")
        .arg("--with-brotli=no")
        .env("CC", cc)
        .env("CXX", cxx);
    run(&mut ft_cfg, &freetype_build_dir, "configure freetype");

    let mut ft_make = Command::new("make");
    ft_make.arg(format!("-j{}", num_cpus::get()));
    run(&mut ft_make, &freetype_build_dir, "make freetype");

    let mut ft_install = Command::new("make");
    ft_install.arg("install");
    run(
        &mut ft_install,
        &freetype_build_dir,
        "make install freetype",
    );

    // === 2. Build Poppler ===
    println!("Building Poppler...");

    let mut cmake = Command::new("cmake");
    cmake
        .arg("../../repo")
        .arg("-DCMAKE_BUILD_TYPE=debug")
        .arg("-DBUILD_SHARED_LIBS=OFF")
        .arg("-DFONT_CONFIGURATION=generic")
        .arg("-DBUILD_GTK_TESTS=OFF")
        .arg("-DBUILD_QT5_TESTS=OFF")
        .arg("-DBUILD_CPP_TESTS=OFF")
        .arg("-DENABLE_LIBPNG=OFF")
        .arg("-DENABLE_LIBTIFF=OFF")
        .arg("-DENABLE_LIBJPEG=ON")
        .arg("-DENABLE_BOOST=OFF")
        .arg("-DENABLE_SPLASH=ON")
        .arg("-DENABLE_UTILS=OFF")
        .arg("-DWITH_Cairo=OFF")
        .arg("-DENABLE_LCMS=OFF")
        .arg("-DENABLE_LIBCURL=OFF")
        .arg("-DENABLE_GLIB=OFF")
        .arg("-DENABLE_GOBJECT_INTROSPECTION=OFF")
        .arg("-DENABLE_QT5=OFF")
        .arg("-DENABLE_QT6=OFF")
        .arg("-DENABLE_NSS3=OFF")
        .arg("-DENABLE_GPGME=OFF")
        .arg("-DENABLE_ZLIB=OFF")
        .arg("-DENABLE_DCTDECODER=libjpeg")
        .arg("-DENABLE_FUZZER=OFF")
        .arg("-DCMAKE_CXX_STANDARD=14")
        .arg(format!(
            "-DFREETYPE_INCLUDE_DIR_ft2build={}/include/freetype2",
            install_dir.display()
        ))
        .arg(format!(
            "-DFREETYPE_INCLUDE_DIR_freetype2={}/include/freetype2",
            install_dir.display()
        ))
        .arg(format!(
            "-DFREETYPE_LIBRARY={}/lib/libfreetype.a",
            install_dir.display()
        ))
        .arg("-DICONV_LIBRARIES=/usr/lib/x86_64-linux-gnu/libc.so")
        .env("CC", cc)
        .env("CXX", cxx)
        .env("CFLAGS", "-D_GNU_SOURCE")
        .env("CXXFLAGS", "-D_GNU_SOURCE");
    run(&mut cmake, &poppler_build_dir, "cmake poppler");

    let mut pop_make = Command::new("make");
    pop_make
        .arg(format!("-j{}", num_cpus::get()))
        .arg("poppler")
        .arg("poppler-cpp");
    run(&mut pop_make, &poppler_build_dir, "make poppler");

    // === 3. Build pdf_fuzzer ===
    println!("Building pdf_fuzzer...");

    let mut fuzzer_build = Command::new(cxx);
    fuzzer_build
        .arg("-std=c++14")
        .arg("-D_GNU_SOURCE")
        .arg(format!("-I{}/repo/cpp", target_dir.display()))
        .arg(format!("-I{}/cpp", poppler_build_dir.display()))
        .arg(format!(
            "{}/repo/cpp/tests/fuzzing/pdf_fuzzer.cc",
            target_dir.display()
        ))
        .arg("-o")
        .arg("pdf_fuzzer")
        .arg(format!(
            "{}/cpp/libpoppler-cpp.a",
            poppler_build_dir.display()
        ))
        .arg(format!("{}/libpoppler.a", poppler_build_dir.display()))
        .arg(format!("{}/lib/libfreetype.a", install_dir.display()))
        .arg(format!(
            "{}/utils/aflpp_driver/libAFLDriver.a",
            aflplusplus_path
        ))
        .arg("-ljpeg")
        .arg("-lz")
        .arg("-lopenjp2")
        .arg("-lpng")
        .arg("-ltiff")
        .arg("-llcms2")
        .arg("-lm")
        .arg("-lpthread")
        .arg("-pthread");
    run(&mut fuzzer_build, &build_dir, "compile pdf_fuzzer");

    println!(
        "Poppler pdf_fuzzer built successfully at: {}/pdf_fuzzer",
        build_dir.display()
    );
}

pub fn build_pdftoppm(target_dir: &Path, task_id: Option<String>) {
    println!("Building Poppler pdftoppm with AFL++ instrumentation");
    verify_pinned_sources(target_dir);

    let build_dir = if let Some(id) = task_id.as_ref() {
        target_dir.join(format!("builddir-{}", id))
    } else {
        target_dir.join("builddir")
    };

    if build_dir.exists() {
        fs::remove_dir_all(&build_dir).expect("Failed to remove existing build directory");
    }
    fs::create_dir_all(&build_dir).expect("Failed to create build directory");

    let install_dir = build_dir.join("install");
    let freetype_build_dir = build_dir.join("freetype_build");
    let poppler_build_dir = build_dir.join("poppler_build");

    fs::create_dir_all(&freetype_build_dir).expect("Failed to create freetype build dir");
    fs::create_dir_all(&poppler_build_dir).expect("Failed to create poppler build dir");

    let cc = "afl-clang-fast";
    let cxx = "afl-clang-fast++";

    println!("Building Freetype...");
    ensure_freetype_configure(&target_dir.join("freetype2"));

    let mut ft_cfg = Command::new("../../freetype2/configure");
    ft_cfg
        .arg(format!("--prefix={}", install_dir.display()))
        .arg("--disable-shared")
        .arg(format!(
            "PKG_CONFIG_PATH={}/lib/pkgconfig",
            install_dir.display()
        ))
        .arg("--with-harfbuzz=no")
        .arg("--with-bzip2=no")
        .arg("--with-png=no")
        .arg("--with-brotli=no")
        .env("CC", cc)
        .env("CXX", cxx);
    run(&mut ft_cfg, &freetype_build_dir, "configure freetype");

    let mut ft_make = Command::new("make");
    ft_make.arg(format!("-j{}", num_cpus::get()));
    run(&mut ft_make, &freetype_build_dir, "make freetype");

    let mut ft_install = Command::new("make");
    ft_install.arg("install");
    run(
        &mut ft_install,
        &freetype_build_dir,
        "make install freetype",
    );

    println!("Building Poppler pdftoppm...");

    let cmake_bin = env::var("POPPLER_CMAKE").unwrap_or_else(|_| "cmake".to_string());
    let mut cmake = Command::new(cmake_bin);
    cmake
        .arg("../../repo")
        .arg("-DCMAKE_BUILD_TYPE=debug")
        .arg("-DBUILD_SHARED_LIBS=OFF")
        .arg("-DFONT_CONFIGURATION=generic")
        .arg("-DBUILD_GTK_TESTS=OFF")
        .arg("-DBUILD_QT5_TESTS=OFF")
        .arg("-DBUILD_CPP_TESTS=OFF")
        .arg("-DENABLE_LIBPNG=OFF")
        .arg("-DENABLE_LIBTIFF=OFF")
        .arg("-DENABLE_LIBJPEG=ON")
        .arg("-DENABLE_BOOST=OFF")
        .arg("-DENABLE_SPLASH=ON")
        .arg("-DENABLE_UTILS=ON")
        .arg("-DWITH_Cairo=OFF")
        .arg("-DENABLE_LCMS=OFF")
        .arg("-DENABLE_LIBCURL=OFF")
        .arg("-DENABLE_GLIB=OFF")
        .arg("-DENABLE_GOBJECT_INTROSPECTION=OFF")
        .arg("-DENABLE_QT5=OFF")
        .arg("-DENABLE_QT6=OFF")
        .arg("-DENABLE_NSS3=OFF")
        .arg("-DENABLE_GPGME=OFF")
        .arg("-DENABLE_ZLIB=OFF")
        .arg("-DENABLE_DCTDECODER=libjpeg")
        .arg("-DENABLE_FUZZER=OFF")
        .arg("-DCMAKE_CXX_STANDARD=14")
        .arg(format!(
            "-DFREETYPE_INCLUDE_DIR_ft2build={}/include/freetype2",
            install_dir.display()
        ))
        .arg(format!(
            "-DFREETYPE_INCLUDE_DIR_freetype2={}/include/freetype2",
            install_dir.display()
        ))
        .arg(format!(
            "-DFREETYPE_LIBRARY={}/lib/libfreetype.a",
            install_dir.display()
        ))
        .arg("-DICONV_LIBRARIES=/usr/lib/x86_64-linux-gnu/libc.so")
        .env("CC", cc)
        .env("CXX", cxx)
        .env("CFLAGS", "-D_GNU_SOURCE")
        .env("CXXFLAGS", "-D_GNU_SOURCE");
    run(&mut cmake, &poppler_build_dir, "cmake poppler pdftoppm");

    let mut pop_make = Command::new("make");
    pop_make
        .arg(format!("-j{}", num_cpus::get()))
        .arg("pdftoppm");
    run(&mut pop_make, &poppler_build_dir, "make pdftoppm");

    let src = poppler_build_dir.join("utils/pdftoppm");
    let dst = build_dir.join("pdftoppm");
    fs::copy(&src, &dst).unwrap_or_else(|e| panic!("failed to copy pdftoppm to build root: {}", e));

    println!("Poppler pdftoppm built successfully at: {}", dst.display());
}
