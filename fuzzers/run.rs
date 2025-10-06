use clap::Parser;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::io::{BufRead, BufReader};
use num_cpus;
use psutil::cpu::CpuTimesPercentCollector;
use psutil::cpu::CpuTimesPercent;

use libc::{cpu_set_t, sched_setaffinity, CPU_SET, CPU_ZERO};
use std::os::unix::process::CommandExt;

/// Command-line arguments for the fuzzing tool
#[derive(Parser)]
struct Args {
    /// Path to the token file (optional)
    #[arg(short = 't', long)]
    token_file: Option<PathBuf>,

    /// Path to the input corpus directory
    #[arg(short = 'c', long)]
    corpus_dir: PathBuf,

    /// Path to the initial corpus directory (activeDir)
    #[arg(short = 'a', long)]
    active_dir: PathBuf,

    /// Path to the task directory
    #[arg(short = 'f', long)]
    task_dir: PathBuf,

    /// Path to the target directory
    #[arg(short = 'd', long)]
    target_dir: PathBuf,

    /// Path to the output folder where the PIDs will be written
    #[arg(short = 'o', long)]
    output_folder: PathBuf,

    /// Name of the binary (default: "basic") to run with cargo
    #[arg(short = 'x', long, default_value = "advanced_sync")]
    cargo_bin: String,

    /// Name of the binary to build 
    #[arg(short = 'b', long)]
    binary_name: String,

    /// Number of cores to use
    #[arg(short = 'n', long)]
    num_cores: Option<usize>,

    /// Full command line to pass to the binary
    #[arg(long, num_args = 0.., allow_hyphen_values = true)]
    cmdline: String,

    /// Whether to synchronize instrumentation
    #[arg(long, default_value_t = false)]
    sync_instrumentation: bool,

    /// Optional path to the cmplog binary
    #[arg(short = 'm', long)]
    cmplog_binary: Option<PathBuf>,

    /// AFL Map Size (optional, default 65536)
    #[arg(long, default_value_t = 65536)]
    map_size: usize,

    /// Optional 8-character hash value (e.g., run identifier)
    #[arg(short = 'a', long)]
    hash: Option<String>,

    /// Whether this is the first run (build with cargo)
    #[arg(long, default_value_t = false)]
    first_run: bool,
}

fn get_available_cores() -> Vec<usize> {
    // Total number of cores
    let total_cores = num_cpus::get();
    println!("Total cores: {}", total_cores);
    let mut vacant_cores = Vec::new();

    // Get CPU usage per core using psutil
    let mut cpu_collector = CpuTimesPercentCollector::new().unwrap();

    thread::sleep(Duration::from_millis(100));
    let _ = cpu_collector.cpu_times_percent_percpu(); // first call to init
    thread::sleep(Duration::from_secs(1));  // Collect data after 1 second

    let cpu_times: Vec<CpuTimesPercent> = cpu_collector.cpu_times_percent_percpu().unwrap();

    for (i, cpu) in cpu_times.iter().enumerate() {
        if cpu.idle() > 97.0 { // Assume a core is 'available' if idle percentage > 97%
            vacant_cores.push(i);
        }
    }

    vacant_cores
}

fn spawn_with_affinity(core: usize, args: Vec<String>) -> std::process::Child {
    let mut command = Command::new(&args[0]);
    command.args(&args[1..]);

    unsafe {
        command.pre_exec(move || {
            let mut set: cpu_set_t = std::mem::zeroed();
            CPU_ZERO(&mut set);
            CPU_SET(core, &mut set);
            if sched_setaffinity(0, std::mem::size_of::<cpu_set_t>(), &set) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to execute command with CPU affinity")
}

fn run_command(
    core: usize,
    args: Vec<String>,
    pid_file: Arc<Mutex<PathBuf>>,
    signal: Arc<Mutex<bool>>,
    output_file: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Running command on core {}: taskset {:?}", core, args);
    
    // Open the file in append mode
    let output_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(output_file)?;
    let mut writer = BufWriter::new(output_file);

    let mut child = spawn_with_affinity(core, args);
    // let mut child = Command::new("taskset")
    //     .arg(format!("0x{:x}", 1 << core)) // Set affinity to the specific core
    //     .args(&args)
    //     .stdout(Stdio::piped())
    //     .stderr(Stdio::piped())
    //     .spawn()
    //     .expect("Failed to execute command");

   // Write the PID to the file within a mutex lock
   {
    let file_lock = pid_file.lock().unwrap();
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&*file_lock)?;
    writeln!(file, "{}", child.id())?;
    }

    if let Some(stdout) = child.stdout.take() {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            let line = line?;
            writeln!(writer, "Core {}: {}", core, line)?;

            if line.contains("Compiled binary path:") {
                let mut signal_guard = signal.lock().unwrap();
                *signal_guard = true;
                drop(signal_guard); // Release the lock before sleeping
            }
        }
    }

    if let Some(stderr) = child.stderr.take() {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            let line = line?;
            writeln!(writer, "Core {}: [stderr] {}", core, line)?;
        }
    }

    child.wait()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Get available cores
    let used_cores_file = args.output_folder.join("used_cores.txt");

    let (mut available_cores, from_file): (Vec<usize>, bool) = if used_cores_file.exists() {
        println!("Reading used cores from {:?}", used_cores_file);
        let contents = fs::read_to_string(&used_cores_file)
            .expect("Failed to read used_cores.txt");
        let cores = contents
            .trim()
            .split(',')
            .filter_map(|s| s.parse::<usize>().ok())
            .collect();
        (cores, true)
    } else {
        println!("used_cores.txt not found, detecting available cores...");
        let cores = get_available_cores();
        (cores, false)
    };

    println!(
        "Available cores: {:?} (source: {})",
        available_cores,
        if from_file { "used_cores.txt" } else { "live detection" }
    );

    let num_cores = args.num_cores.unwrap_or_else(num_cpus::get);
    println!("Limiting to {} cores", num_cores);

    if available_cores.len() > num_cores {
        available_cores.truncate(num_cores);
    }


    // Wrap the pid_file in an Arc<Mutex> for thread-safe access
    let pid_file = Arc::new(Mutex::new(args.output_folder.join("pids.txt")));

    // Clean the pid file at the start
    {
        let pid_path = pid_file.lock().unwrap(); // Lock the mutex to access the PathBuf
        let _ = File::create(&*pid_path)?; // Dereference to get the Path
    }
    let output_file = args.active_dir.join("output.txt");


    let mut commands = vec![];

    // Assign tasks to available cores, but only up to `num_cores` tasks
    for (i, core) in available_cores.into_iter().enumerate() {
        // Limit task assignment to `num_cores` tasks
        if i >= num_cores {
            break;
        }

        let task_file = args.task_dir.join(format!("task_{}.txt", i + 1));
        let initial_corpus = args.active_dir.join(format!("fuzzer_{}/queue", i + 1));

        if task_file.exists() {
            let mut cargo_bin = args.cargo_bin.clone();

            // If `cmplog_binary` is set, change the `cargo_bin` to "advanced_cmplog"
            if args.cmplog_binary.is_some() {
                cargo_bin = "advanced_cmplog".to_string();
            }
            
            // Build the initial command arguments
            let mut command_args = if args.first_run {
                println!("First run: compiling and running with `cargo run`");
                vec![
                    "cargo".to_string(),
                    "run".to_string(),
                    "--release".to_string(),
                    "--bin".to_string(),
                    cargo_bin.clone(),
                    "--".to_string(),
                ]
            } else {
                println!("Not first run: using prebuilt binary at ./target/release/{}", cargo_bin);
                vec![format!("./target/release/{}", cargo_bin.clone())]
            };
            command_args.extend(vec![
                "-c".to_string(), args.corpus_dir.to_string_lossy().to_string(),
                "-f".to_string(), task_file.to_string_lossy().to_string(),
                "-i".to_string(), initial_corpus.to_string_lossy().to_string(),
                "-d".to_string(), args.target_dir.to_string_lossy().to_string(),
                "-b".to_string(), args.binary_name.clone(),
                "-s".to_string(), args.corpus_dir.to_string_lossy().to_string(),
                "-o".to_string(), args.output_folder.join("crashes").to_string_lossy().to_string(),
                "--core-id".to_string(), core.to_string(),
            ]);

            // Add `-m` with the `cmplog_binary` if it is set
            if let Some(cmplog_binary) = &args.cmplog_binary {
                command_args.push("-m".to_string());
                command_args.push(cmplog_binary.to_string_lossy().to_string());
            }

            // If `token_file` is provided, append it with the `-t` flag
            if let Some(token_file) = &args.token_file {
                command_args.push("-t".to_string());
                command_args.push(token_file.to_string_lossy().to_string());
            }

            // If `hash` is provided, append it with the `-h` flag
            if let Some(hash) = &args.hash {
                command_args.push("-a".to_string());
                command_args.push(hash.clone());
            }

            // Add `task_number` if `sync_instrumentation` is set
            if args.sync_instrumentation {
                command_args.push("--task-number".to_string());
                command_args.push((i + 1).to_string());
            }

            // Add the map size if it's different from the default (65536)
            if args.map_size != 65536 {
                command_args.push("--map-size".to_string());
                command_args.push(args.map_size.to_string());
            }
            
            // Add the full command line provided in `cmdline` as `-p`
            command_args.push("-p".to_string());
            command_args.push(args.cmdline.clone());

            println!("Command {}: {:?}", i, command_args);
            commands.push((core, command_args));
        } else {
            println!("Task file {} does not exist. Skipping.", task_file.display());
        }
    }

    if commands.is_empty() {
        println!("No valid task files found. Exiting.");
        return Ok(());
    }

    let signal = Arc::new(Mutex::new(false));
    let mut handles = vec![];

    if args.sync_instrumentation {
        println!("Spawning tasks simultaneously on all available cores");
        // Spawn all tasks simultaneously on all available cores
        for (core, command_args) in commands {
            let pid_file_clone = Arc::clone(&pid_file);
            let signal_clone = Arc::clone(&signal);
            let output_file_clone = output_file.clone();

            let handle = thread::spawn(move || {
                run_command(core, command_args, pid_file_clone, signal_clone, &output_file_clone)
                    .expect("Failed to run command");
            });

            handles.push(handle);
        }
    } else {
        // Sequentially spawn tasks
        let (core, command_args) = commands.remove(0);
        let pid_file_clone = Arc::clone(&pid_file);
        let signal_clone = Arc::clone(&signal);
        let output_file_clone = output_file.clone();

        let handle = thread::spawn(move || {
            run_command(core, command_args, pid_file_clone, signal_clone, &output_file_clone)
                .expect("Failed to run command");
        });
        handles.push(handle);

        // Start the monitoring process for sequential tasks
        let signal_listener = Arc::clone(&signal);
        let output_file_clone = output_file.clone();
        let handle_listener = thread::spawn(move || {
            let mut next_command_index = 0;

            while next_command_index < commands.len() {
                let mut signal_guard = signal_listener.lock().unwrap();

                if *signal_guard {
                    drop(signal_guard); // Drop the lock before starting the next command

                    println!("Listener detected compiled binary. Starting next command in 5 seconds...");
                    thread::sleep(Duration::from_secs(5));

                    let (core, command_args) = commands[next_command_index].clone();
                    println!("Assigning task {} to core {}", next_command_index, core);

                    let pid_file_clone = pid_file.clone();
                    let signal_clone = Arc::clone(&signal_listener);
                    let output_file_clone = output_file_clone.clone();

                    thread::spawn(move || {
                        run_command(core, command_args, pid_file_clone, signal_clone, &output_file_clone)
                            .expect("Failed to run command");
                    });

                    // Reset signal and prepare for the next task
                    signal_guard = signal_listener.lock().unwrap();
                    *signal_guard = false;
                    next_command_index += 1;
                } else {
                    drop(signal_guard); // Drop the lock before sleeping
                    thread::sleep(Duration::from_millis(100));
                }
            }

            println!("All fuzzing instances have started. Stopping listener.");
        });

        handles.push(handle_listener);
    }

    // Wait for all handles to finish
    for handle in handles {
        handle.join().expect("Thread failed");
    }

    Ok(())
}
