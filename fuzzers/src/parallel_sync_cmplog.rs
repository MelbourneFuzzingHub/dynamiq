include!("../task/mod.rs");
use custom_sync::SyncFromDiskStage;
use libafl::stages::mutational::MultiMutationalStage;
use libafl_bolts::prelude::OwnedRefMut;
use libafl_targets::{AFLppCmpLogMap, AFLppCmpLogObserver, AFLppCmplogTracingStage};

use libafl::prelude::powersched::PowerSchedule;
use libafl::prelude::{tokens_mutations, AFLppRedQueen, AflMapFeedback, CrashFeedback, StdMOptMutator, StdWeightedScheduler, Tokens};
use libafl_bolts::rands::StdRand;
use libafl_bolts::shmem::{ShMem, ShMemProvider, StdShMemProvider};
use libafl_bolts::tuples::{tuple_list, Handled, Merge};
use libafl_bolts::core_affinity::Cores;
use libafl_bolts::{current_nanos, AsSliceMut};
use libafl::corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus};
use libafl::events::{EventConfig, launcher::Launcher};
use libafl::executors::ForkserverExecutor;
use libafl::feedbacks::{TimeFeedback, TimeoutFeedback};
use libafl::inputs::BytesInput;
#[cfg(feature = "tui")]
use libafl::monitors::tui::{ui::TuiUI, TuiMonitor};
#[cfg(not(feature = "tui"))]
use libafl::prelude::MultiMonitor;
use libafl::mutators::havoc_mutations;
use libafl::observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver};
use libafl::schedulers::{IndexesLenTimeMinimizerScheduler};
use libafl::stages::{CalibrationStage, ColorizationStage, IfStage, StdPowerMutationalStage};
use libafl::state::{HasCorpus, HasCurrentTestcase, StdState};
use libafl::{feedback_or, feedback_or_fast, Error, Fuzzer, HasMetadata, StdFuzzer};
use std::path::PathBuf;
use std::time::Duration;
use std::env;
use clap::Parser;
use std::fs::OpenOptions;
use std::io::Write;
use psutil::cpu::CpuTimesPercentCollector;
use std::net::{TcpListener, SocketAddr};


// Function to get available cores based on idle threshold
/// Returns up to `core_count` idle cores, excluding any in `skip`.
fn get_available_cores(core_count: usize, skip: Option<&[usize]>) -> Vec<usize> {
    let total_cores = num_cpus::get();
    println!("Total cores on machine: {}", total_cores);

    // parse skip into a HashSet for O(1) lookups
    let skip_set: std::collections::HashSet<usize> = skip
        .unwrap_or(&[])
        .iter()
        .copied()
        .collect();

    let mut vacant = Vec::new();
    let mut cpu_col = CpuTimesPercentCollector::new()
        .expect("Failed to create CPU collector");

    // warm up collector
    std::thread::sleep(Duration::from_millis(100));
    let _ = cpu_col.cpu_times_percent_percpu();
    std::thread::sleep(Duration::from_secs(1));

    let cpu_times = cpu_col
        .cpu_times_percent_percpu()
        .expect("Failed to get CPU times");

    for (i, cpu) in cpu_times.iter().enumerate() {
        // skip any cores the caller asked us to skip:
        if skip_set.contains(&i) {
            continue;
        }
        if cpu.idle() > 97.0 {
            vacant.push(i);
            if vacant.len() == core_count {
                break;
            }
        }
    }

    if vacant.len() < core_count {
        eprintln!(
            "Warning: Only found {} free cores (skipping {:?}), but {} were requested.",
            vacant.len(),
            skip_set,
            core_count
        );
    }

    println!("Selected cores (after skip): {:?}", vacant);
    vacant
}

/// Attempts to find an open port within the given range.
fn find_open_port(start: u16, end: u16) -> Option<u16> {
    for port in start..=end {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        if TcpListener::bind(addr).is_ok() {
            return Some(port); // Return the first available port
        }
    }
    None // Return None if no ports are available in the range
}

#[derive(Parser, Debug)]
#[command(name = "parallel_fuzzer")]
#[command(about = "A parallel fuzzer using libafl", long_about = None)]
struct Args {
    /// Number of cores to use
    #[arg(short = 'n', long, default_value = "1")]
    core_num: usize,

    /// Comma-separated list of core IDs to *not* use
    #[arg(long)]
    skip_cores: Option<String>,

    /// Path to input corpus
    #[arg(short = 'c', long, default_value = "./corpus")]
    corpus_dir: PathBuf,

    /// Directory containing all test cases
    #[arg(short = 'i', long, default_value = "./queue")]
    initial_corpus: PathBuf,

    /// Directory to store timeouts/hangs
    #[arg(short = 'o', long, default_value = "./timeouts")]
    timeouts_dir: PathBuf,

    /// Path to the binary to fuzz
    #[arg(short = 'b', long)]
    binary_path: PathBuf,

    /// Path to the token file (dictionary)
    #[arg(short = 't', long)]
    token_file: Option<PathBuf>,

    /// Path to the output folder where the PIDs will be written
    #[arg(short = 'u', long)]
    output_folder: PathBuf,

    /// Interval for foreign synchronization in seconds
    #[arg(long, default_value_t = 20 * 60)]
    foreign_sync_interval: u64,

    /// Directory for foreign synchronization
    #[arg(short = 's', long)]
    foreign_sync_dirs: Vec<PathBuf>,

    /// Full command line to pass to the binary
    #[arg(long, num_args = 0.., allow_hyphen_values = true)]
    cmdline: String,

    /// Path to the cmplog directory
    #[arg(short = 'm', long)]
    cmplog_dir: PathBuf,

    /// AFL Map Size (optional, default 262144)
    #[arg(long, default_value_t = 262144)]
    map_size: usize,
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

fn main() -> Result<(), Error> {
    let args = Args::parse();

    let broker_port_range = (1337, 1342);
    let broker_port = match find_open_port(broker_port_range.0, broker_port_range.1) {
        Some(port) => {
            println!("Selected open port: {}", port);
            port
        },
        None => {
            eprintln!("No open port found in the range {}-{}", broker_port_range.0, broker_port_range.1);
            return Err(Error::unknown("No open broker port available"));
        },
    };

    let map_size = args.map_size;
    println!("Using AFL_MAP_SIZE: {}", map_size);

    // parse skip_cores string into Vec<usize> once:
    let skip_vec: Vec<usize> = args
        .skip_cores
        .as_deref()
        .unwrap_or("")
        .split(',')
        .filter_map(|s| s.parse().ok())
        .collect();

    println!("Skip cores: {:?}", skip_vec);
    // Use get_available_cores to determine which cores are available
    let available_cores = get_available_cores(args.core_num, Some(&skip_vec));
    // Convert available_cores to a comma-separated string format, e.g., "1,3,5-7"
    let available_cores_str = available_cores
        .iter()
        .map(|core| core.to_string())
        .collect::<Vec<String>>()
        .join(",");

    // Convert available cores to a format compatible with `Cores`
    let cores = Cores::from_cmdline(&available_cores_str )
        .expect("Failed to create cores list from available core IDs");

    // Save the used cores to a shared file
    let cores_file_path = args.output_folder.join("used_cores.txt");
    std::fs::write(&cores_file_path, &available_cores_str)
        .expect("Unable to write used cores to file");

    println!("Using cores: {:?}", available_cores);

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    let sync_interval = args.get_foreign_sync_interval();
    println!("Foreign sync interval: {:?}", sync_interval);

    let cmplog_binary_name = args.cmplog_dir.to_string_lossy().to_string();
    println!("Cmplog binary name: {}", cmplog_binary_name);

    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    #[cfg(not(feature = "tui"))]
    let monitor = MultiMonitor::new(|s| println!("{s}"));
    #[cfg(feature = "tui")]
    let ui = TuiUI::with_version(String::from("Fuzzer"), String::from("0.0.1"), false);
    #[cfg(feature = "tui")]
    let monitor = TuiMonitor::new(ui);

    let pid_file_path = args.output_folder.join("pids.txt");

    let mut run_client = |state: Option<_>, mut restarting_mgr, _core_id| {
        let pid = std::process::id(); // Get the PID of the current process
        println!("PID: {}", pid);

        // Append the PID to the file
        let mut pid_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&pid_file_path)
            .expect("Unable to open PID file");
        writeln!(pid_file, "{}", pid).expect("Unable to write PID to file");

        //
        // Component: Corpus
        //

        let corpus_dirs = vec![args.corpus_dir.clone()];
        let input_corpus = InMemoryOnDiskCorpus::<BytesInput>::new(args.initial_corpus.clone())?;
        let timeouts_corpus = OnDiskCorpus::new(args.timeouts_dir.clone())?;

        //
        // Component: Observer
        //

        let time_observer = TimeObserver::new("time");

        let mut shmem_provider = StdShMemProvider::new()?;
        let mut shmem = shmem_provider.new_shmem(map_size)?;
        shmem.write_to_env("__AFL_SHM_ID")?;
        let shmem_buf = shmem.as_slice_mut();

        // To let know the AFL++ binary that we have a big map
        std::env::set_var("AFL_MAP_SIZE", format!("{}", map_size));

        let edges_observer = unsafe {
            HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmem_buf)).track_indices()
        };

        //
        // Component: Feedback
        //
        let map_feedback = AflMapFeedback::new(&edges_observer);

        let calibration = CalibrationStage::new(&map_feedback);

        let mut feedback = feedback_or!(
            // MaxMapFeedback::new(&edges_observer),
            map_feedback,
            TimeFeedback::new(&time_observer)
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

        //
        // Component: State
        //

        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                StdRand::with_seed(current_nanos()),
                input_corpus,
                timeouts_corpus,
                &mut feedback,
                &mut objective,
            ).unwrap()
        });

        //
        // Component: Mutator
        //

        // let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
        let mutator = StdMOptMutator::new(
            &mut state,
            havoc_mutations().merge(tokens_mutations()),
            7,
            5,
        )?;

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

        let colorization = ColorizationStage::new(&edges_observer);

        //
        // Component: Executor
        //

        let full_cmdline = args.cmdline.split_whitespace().collect::<Vec<_>>();

        println!("Constructed Command in Rust: {:?}", full_cmdline);

        let timeout = Duration::from_secs(20);
        let mut tokens = Tokens::new();
        let binary_path_str = args.binary_path.to_str().unwrap().to_string();
        let is_deferred = !binary_path_str.contains("fuzz_dtlsclient");//hardcode for now
        println!("Using deferred forkserver: {}", is_deferred);
        let mut executor = ForkserverExecutor::builder()
            .program(&binary_path_str)  // Use the binary path argument
            .autotokens(&mut tokens)
            .parse_afl_cmdline(full_cmdline.clone())
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

        if state.corpus().count() < 1 {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut restarting_mgr, &corpus_dirs)
                .unwrap_or_else(|err| {
                    panic!(
                        "Failed to load initial corpus at {:?}: {:?}",
                        &corpus_dirs, err
                    )
                });
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

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

        // The cmplog map shared between observer and executor
        let mut cmplog_shmem = shmem_provider.uninit_on_shmem::<AFLppCmpLogMap>().unwrap();
        // let the forkserver know the shmid
        cmplog_shmem.write_to_env("__AFL_CMPLOG_SHM_ID").unwrap();
        let cmpmap = unsafe { OwnedRefMut::from_shmem(&mut cmplog_shmem) };

        let cmplog_observer = AFLppCmpLogObserver::new("cmplog", cmpmap, true);
        let cmplog_ref = cmplog_observer.handle();

        let cmplog_binary_path = std::fs::canonicalize(&cmplog_binary_name)?;
        println!("Compiled cmplog binary path: {}", cmplog_binary_path.display()); 

        let cmplog_executor = ForkserverExecutor::builder()
                .program(cmplog_binary_path.to_str().unwrap())
                .shmem_provider(&mut shmem_provider)
                .parse_afl_cmdline(full_cmdline)
                .is_persistent(true)
                .is_deferred_frksrv(is_deferred)
                .timeout(timeout * 10)
                .build(tuple_list!(cmplog_observer))
                .unwrap();

        let tracing = AFLppCmplogTracingStage::new(cmplog_executor, cmplog_ref);

        // Setup a random Input2State stage
        let rq = MultiMutationalStage::new(AFLppRedQueen::with_cmplog_options(true, true));

        let cb = |_fuzzer: &mut _,
                    _executor: &mut _,
                    state: &mut StdState<_, InMemoryOnDiskCorpus<_>, _, _>,
                    _event_manager: &mut _|
            -> Result<bool, Error> {
            let testcase = state.current_testcase()?;
            let res = testcase.scheduled_count() == 1; // let's try on the 2nd trial

            Ok(res)
        };

        let cmplog = IfStage::new(cb, tuple_list!(colorization, tracing, rq));

        let mut stages = tuple_list!(calibration, cmplog, power, sync_stage);

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr)?;
        Ok(())
    };
    
    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_name("default"))
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        .broker_port(broker_port)
        .build()
        .launch()
    {
        Ok(()) => Ok(()),
        Err(Error::ShuttingDown) => {
            println!("Fuzzing stopped by user. Good bye.");
            Ok(())
        }
        Err(err) => panic!("Failed to run launcher: {:?}", err),
    }
}