// Basic selective instrumentation fuzzer for libpng
include!("../task/mod.rs");
use custom_sync::SyncFromDiskStage;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use std::fs;
use std::io::{BufRead, BufReader};
use clap::Parser;
use libafl::monitors::MultiMonitor;
use libafl::prelude::powersched::PowerSchedule;
use libafl::prelude::{AflMapFeedback, CrashFeedback, StdMOptMutator, StdWeightedScheduler};
use libafl_bolts::rands::StdRand;
use libafl_bolts::shmem::{ShMem, ShMemProvider, StdShMemProvider};
use libafl_bolts::tuples::{tuple_list, Merge};
use libafl_bolts::{current_nanos, AsSliceMut};
use libafl::corpus::{Corpus, CorpusMinimizer, InMemoryOnDiskCorpus, OnDiskCorpus};
use libafl::events::SimpleEventManager;
use libafl::executors::ForkserverExecutor;
use libafl::feedbacks::{TimeFeedback, TimeoutFeedback};
use libafl::inputs::BytesInput;
#[cfg(feature = "tui")]
use libafl::monitors::tui::{ui::TuiUI, TuiMonitor};
#[cfg(not(feature = "tui"))]
use libafl::mutators::{havoc_mutations, tokens_mutations, Tokens};
use libafl::observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver};
use libafl::schedulers::IndexesLenTimeMinimizerScheduler;
use libafl::stages::{CalibrationStage, StdPowerMutationalStage};
use libafl::state::{HasCorpus, StdState};
use libafl::{feedback_or, feedback_or_fast, Fuzzer, HasMetadata, StdFuzzer};

#[derive(Parser, Debug)]
#[command(name = "fuzzer")]
#[command(about = "A fuzzer for libpng", long_about = None)]
struct Args {
    /// Path to the token file
    #[arg(short = 't', long)]
    token_file: Option<PathBuf>,

    /// Path to input corpus
    #[arg(short = 'c', long, default_value = "./corpus")]
    corpus_dir: PathBuf,

    /// Directory containing all test cases
    #[arg(short = 'i', long, default_value = "./queue")]
    initial_corpus: PathBuf,

    /// Directory to store timeouts/hangs
    #[arg(short = 'o', long, default_value = "./timeouts")]
    timeouts_dir: PathBuf,

    /// Path to the task file
    #[arg(short = 'f', long)]
    task: Option<PathBuf>,

    /// Core ID to bind the process
    #[arg(long, default_value = "0")]
    core_id: usize,

    /// Path to the target directory
    #[arg(short = 'd', long)]
    target_dir: PathBuf,

    /// Name of the binary to build
    #[arg(short = 'b', long)]
    binary_name: String,

    /// Interval for foreign synchronization in seconds
    #[arg(long, default_value_t = 15 * 60)]
    foreign_sync_interval: u64,

    /// Directory for foreign synchronization
    #[arg(short = 's', long)]
    foreign_sync_dirs: Vec<PathBuf>,

    /// Full command-line string to run the target binary
    #[arg(short = 'p', long, num_args = 0.., allow_hyphen_values = true)]
    cmdline: String,

    /// Task number to pass to compile.rs (optional)
    #[arg(short = 'n', long)]
    task_number: Option<usize>,

    /// AFL Map Size (optional, default 131072)
    #[arg(long, default_value_t = 262144)]
    map_size: usize,

    /// Optional 8-character hash value 
    #[arg(short = 'a', long)]
    hash: Option<String>,
}

impl Args {
    /// Get the foreign sync interval as a `Duration`, considering the environment variable
    fn get_foreign_sync_interval(&self) -> Duration {
        if let Ok(env_sync_time) = std::env::var("AFL_SYNC_TIME") {
            if let Ok(parsed) = env_sync_time.parse::<u64>() {
                return Duration::from_secs(parsed * 60);
            }
        }
        Duration::from_secs(self.foreign_sync_interval)
    }
}

/// Round up to the next power-of-two-like bucket (1, 2, 4, 8, 16 max).
/// If `use_bucket` is false, return the original `value`.
fn bucketize(value: usize, use_bucket: bool) -> usize {
    if !use_bucket {
        return value.min(16);
    }

    match value {
        0 => 0,
        1 => 1,
        _ => {
            let mut bucket = 1;
            while (bucket << 1) <= value && bucket < 16 {
                bucket <<= 1;
            }
            bucket
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let target_dir = args.target_dir.to_string_lossy().to_string();

    let map_size = args.map_size;
    println!("Using AFL_MAP_SIZE: {}", map_size);

    // Pass the task file to the compilation script
    let task_file_path = args.task.clone().unwrap_or(PathBuf::from("default_task_file.txt"));

    // Generate unique binary names based on the task file name
    let task_file_stem = task_file_path.file_stem().unwrap().to_str().unwrap();
    let binary_name = args.binary_name.clone(); 
    let compiled_binary = format!("{}_{}.afl", task_file_stem, binary_name.clone());

    let sync_interval = args.get_foreign_sync_interval();
    println!("Foreign sync interval: {:?}", sync_interval);
    
    // Call the compile script with the task file path
    let mut compile_command = Command::new("taskset");
    compile_command
        .arg(format!("0x{:x}", 1 << args.core_id)) 
        .arg("cargo")
        .arg("run")
        .arg("--bin")
        .arg("compile")
        .arg("--")
        .arg("--task-file")
        .arg(&task_file_path)
        .arg("--target-dir")
        .arg(target_dir)
        .arg("--binary-name")
        .arg(binary_name.clone());

    // Include task_number if provided
    if let Some(task_number) = args.task_number {
        compile_command.arg("--task-number").arg(task_number.to_string());
    }

    // Include hash if provided
    if let Some(hash) = &args.hash {
        compile_command.arg("--hash").arg(hash);
    }

    // Check if task_diameters.txt exists in the parent dir
    if let Some(parent_dir) = task_file_path.parent() {
        let diam_path = parent_dir.join("task_diameters.txt");
        if let Ok(file) = fs::File::open(&diam_path) {
            let reader = BufReader::new(file);
            for line in reader.lines().flatten() {
                if let Some((task, value)) = line.split_once(':') {
                    if task.trim() == task_file_stem {
                        if let Ok(d) = value.trim().parse::<usize>() {
                            let k_val = bucketize(d, false);
                            println!("ctx_k for {}: {} (raw: {})", task, k_val, d);
                            compile_command.arg("--ctx-k").arg(k_val.to_string());
                        }
                        break;
                    }
                }
            }
        }
    }
    println!("Running compilation command: {:?}", compile_command);

    compile_command.status().expect("Failed to run compilation script");
    //
    // Component: Corpus
    //

    let corpus_dirs = vec![args.corpus_dir];

    // Corpus that will be evolved, we keep it in memory for performance
    let input_corpus = InMemoryOnDiskCorpus::<BytesInput>::new(args.initial_corpus)?;

    // Corpus in which we store solutions on disk so the user can get them after stopping the fuzzer
    let timeouts_corpus = OnDiskCorpus::new(args.timeouts_dir)?;

    //
    // Component: Observer
    //

    let time_observer = TimeObserver::new("time");

    // Generate a unique shared memory ID for each instance
    // let shm_id = format!("__AFL_SHM_ID_{}", uuid::Uuid::new_v4().to_string());

    // Set up shared memory
    let mut shmem_provider = StdShMemProvider::new().unwrap();
    let mut shmem = shmem_provider.new_shmem(map_size)?;
    shmem.write_to_env("__AFL_SHM_ID")?;
    let shmem_buf = shmem.as_slice_mut();
    // To let know the AFL++ binary that we have a big map
    std::env::set_var("AFL_MAP_SIZE", format!("{}", map_size));

    let edges_observer = unsafe {
        HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmem_buf)).track_indices()
    };

    // Disable to ensure fair comparison with other fuzzers
    // let minimizer = StdCorpusMinimizer::new(&edges_observer);

    //
    // Component: Feedback
    //
    
    // let map_feedback = MaxMapFeedback::new(&edges_observer);
    let map_feedback = AflMapFeedback::new(&edges_observer);

    let calibration = CalibrationStage::new(&map_feedback);

    let mut feedback = feedback_or!(
        map_feedback,
        TimeFeedback::new(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

    //
    // Component: Monitor
    //

    #[cfg(not(feature = "tui"))]
    let monitor = MultiMonitor::new(|s| println!("{s}"));
    #[cfg(feature = "tui")]
    let ui = TuiUI::with_version(String::from("Fuzzer"), String::from("0.0.1"), false);
    #[cfg(feature = "tui")]
    let monitor = TuiMonitor::new(ui);

    //
    // Component: EventManager
    //

    let mut mgr = SimpleEventManager::new(monitor);

    //
    // Component: State
    //

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        input_corpus,
        timeouts_corpus,
        &mut feedback,
        &mut objective,
    )?;

    //
    // Component: Mutator
    //

    // Setup a MOPT mutator
    let mutator = StdMOptMutator::new(
        &mut state,
        havoc_mutations().merge(tokens_mutations()),
        7,
        5,
    )?;
    // let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));

    let power = StdPowerMutationalStage::new(mutator);

    //
    // Component: Scheduler
    //

    let scheduler = IndexesLenTimeMinimizerScheduler::new(
        &edges_observer,
        StdWeightedScheduler::with_schedule(
            &mut state,
            &edges_observer,
            Some(PowerSchedule::EXPLORE),
        ),
    );

    //
    // Component: Fuzzer
    //

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    //
    // Component: Executor
    //

    let timeout = Duration::from_secs(20);

    // Determine the compiled binary path based on whether hash is set
    let compiled_binary_path = if let Some(hash) = &args.hash {
        let hash_dir = Path::new(hash);
        hash_dir.join(&compiled_binary)
    } else {
        PathBuf::from(&compiled_binary)
    };

    // Verify the compiled binary exists
    if !compiled_binary_path.exists() {
        panic!("Compiled binary not found: {}", compiled_binary_path.display());
    } else {
        println!("Compiled binary found: {}", compiled_binary_path.display());
    }

    // Show current working directory
    println!("Current directory: {}", std::env::current_dir()?.display());

    // Canonical path
    let compiled_binary_path = std::fs::canonicalize(&compiled_binary_path)?;
    println!("Canonical binary path: {}", compiled_binary_path.display());


    let full_cmdline = args.cmdline.split_whitespace().collect::<Vec<_>>();
    println!("Constructed Command in Rust: {:?}", full_cmdline);

    let mut tokens = Tokens::new();
    let is_deferred = binary_name != "fuzz_dtlsclient";
    println!("Using deferred forkserver: {}", is_deferred);
    let mut executor = ForkserverExecutor::builder()
        .program(compiled_binary_path.to_str().unwrap()) 
        .autotokens(&mut tokens)
        .shmem_provider(&mut shmem_provider)
        .parse_afl_cmdline(full_cmdline)            
        .is_persistent(true)
        .is_deferred_frksrv(is_deferred)
        .coverage_map_size(map_size)
        .timeout(timeout)
        .build_dynamic_map(edges_observer, tuple_list!(time_observer))
        .unwrap();

    // Load the token dictionary if provided
    if let Some(token_file) = &args.token_file {
        println!("Token file: {:?}", token_file);
        tokens.add_from_file(token_file)?;
    }
    if !tokens.is_empty() {
        state.add_metadata(tokens);
    }

    // In case the corpus is empty (i.e. on first run), load existing test cases from on-disk
    // corpus
    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
            .unwrap_or_else(|err| {
                panic!(
                    "Failed to load initial corpus at {:?}: {:?}",
                    &corpus_dirs, err
                )
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    //
    // Component: Corpus Minimizer
    //
    // let orig_size = state.corpus().count();                                                                                                                                         
    // let msg = "Started distillation...".to_string();
    // println!("{}", msg);
    // minimizer.minimize(&mut fuzzer, &mut executor, &mut mgr, &mut state)?;
    // let msg = format!("Distilled out {} cases", orig_size - state.corpus().count());
    // println!("{}", msg);

    //
    // Component: Stage
    //

    // Create a Sync stage to sync from foreign fuzzers
    println!("empty folder ? {}", args.foreign_sync_dirs.is_empty());
    println!("sync interval: {:?}", sync_interval);

    let sync_stage = SyncFromDiskStage::with_from_file(
        args.foreign_sync_dirs.clone(), 
        sync_interval
    );

    let mut stages = tuple_list!(calibration, power, sync_stage);

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

    Ok(())
}
