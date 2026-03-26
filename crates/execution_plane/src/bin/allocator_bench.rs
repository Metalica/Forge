use control_plane::benchmark::{QueueBenchmarkConfig, run_queue_benchmark};
use execution_plane::allocator_build::active_allocator_build_mode;
use execution_plane::benchmark::{
    AgentBenchmarkConfig, IndexBenchmarkConfig, WorkloadMetrics, run_agent_benchmark,
    run_indexing_benchmark,
};
use std::error::Error;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "allocator-mimalloc")]
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "allocator-jemalloc")]
#[global_allocator]
static GLOBAL_ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(feature = "allocator-snmalloc")]
#[global_allocator]
static GLOBAL_ALLOCATOR: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BenchmarkArgs {
    queue_iterations: usize,
    queue_workers: usize,
    queue_window: usize,
    agent_iterations: usize,
    agent_window: usize,
    index_documents: usize,
    index_tokens: usize,
    index_retained_documents: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ArgParseError {
    message: String,
}

impl ArgParseError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ArgParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ArgParseError {}

impl From<ArgParseError> for String {
    fn from(value: ArgParseError) -> Self {
        value.to_string()
    }
}

impl Default for BenchmarkArgs {
    fn default() -> Self {
        Self {
            queue_iterations: 20_000,
            queue_workers: 16,
            queue_window: 96,
            agent_iterations: 18_000,
            agent_window: 128,
            index_documents: 1_200,
            index_tokens: 192,
            index_retained_documents: 96,
        }
    }
}

fn main() {
    match run() {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}

fn run() -> Result<String, String> {
    let args = parse_args(std::env::args().skip(1))?;
    let queue = run_queue_benchmark(QueueBenchmarkConfig {
        iterations: args.queue_iterations,
        worker_count: args.queue_workers,
        outstanding_window: args.queue_window,
    });
    let agent = run_agent_benchmark(AgentBenchmarkConfig {
        iterations: args.agent_iterations,
        outstanding_window: args.agent_window,
    });
    let indexing = run_indexing_benchmark(IndexBenchmarkConfig {
        documents: args.index_documents,
        tokens_per_document: args.index_tokens,
        retained_documents: args.index_retained_documents,
    });

    let allocator = active_allocator_build_mode().as_feature_name();
    Ok(render_report_json(
        allocator,
        current_unix_ms(),
        &[workload_metrics_from_queue(&queue), agent, indexing],
    ))
}

fn parse_args<I>(args: I) -> Result<BenchmarkArgs, String>
where
    I: IntoIterator<Item = String>,
{
    let mut parsed = BenchmarkArgs::default();
    let mut pending_flag: Option<String> = None;

    for token in args {
        if let Some(flag) = pending_flag.take() {
            apply_flag_value(&mut parsed, &flag, &token)?;
            continue;
        }

        if token == "--help" || token == "-h" {
            return Err(usage_text());
        }
        if token.starts_with("--") {
            pending_flag = Some(token);
            continue;
        }
        return Err(format!(
            "unexpected positional argument: {token}\n{}",
            usage_text()
        ));
    }

    if let Some(flag) = pending_flag {
        return Err(format!("missing value for flag: {flag}\n{}", usage_text()));
    }

    Ok(parsed)
}

fn apply_flag_value(
    args: &mut BenchmarkArgs,
    flag: &str,
    value: &str,
) -> Result<(), ArgParseError> {
    let parsed_value = value.parse::<usize>().map_err(|_| {
        ArgParseError::new(format!(
            "invalid numeric value `{value}` for {flag}\n{}",
            usage_text()
        ))
    })?;

    match flag {
        "--queue-iterations" => args.queue_iterations = parsed_value,
        "--queue-workers" => args.queue_workers = parsed_value,
        "--queue-window" => args.queue_window = parsed_value,
        "--agent-iterations" => args.agent_iterations = parsed_value,
        "--agent-window" => args.agent_window = parsed_value,
        "--index-documents" => args.index_documents = parsed_value,
        "--index-tokens" => args.index_tokens = parsed_value,
        "--index-retained-documents" => args.index_retained_documents = parsed_value,
        _ => {
            return Err(ArgParseError::new(format!(
                "unknown flag: {flag}\n{}",
                usage_text()
            )));
        }
    }
    Ok(())
}

fn usage_text() -> String {
    [
        "allocator_bench usage:",
        "  --queue-iterations <usize>",
        "  --queue-workers <usize>",
        "  --queue-window <usize>",
        "  --agent-iterations <usize>",
        "  --agent-window <usize>",
        "  --index-documents <usize>",
        "  --index-tokens <usize>",
        "  --index-retained-documents <usize>",
    ]
    .join("\n")
}

fn workload_metrics_from_queue(
    queue: &control_plane::benchmark::QueueBenchmarkMetrics,
) -> WorkloadMetrics {
    WorkloadMetrics {
        workload: queue.workload,
        operations: queue.operations,
        elapsed_ms: queue.elapsed_ms,
        throughput_ops_per_sec: queue.throughput_ops_per_sec,
        p50_latency_us: queue.p50_latency_us,
        p95_latency_us: queue.p95_latency_us,
        max_latency_us: queue.max_latency_us,
        peak_live_bytes: queue.peak_live_bytes,
        peak_reserved_bytes: queue.peak_reserved_bytes,
        fragmentation_permille: queue.fragmentation_permille,
    }
}

fn render_report_json(
    allocator_feature: &str,
    generated_at_unix_ms: u64,
    workloads: &[WorkloadMetrics],
) -> String {
    let workloads_json = workloads
        .iter()
        .map(render_workload_json)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"allocator\":\"{allocator_feature}\",\"generated_at_unix_ms\":{generated_at_unix_ms},\"workloads\":[{workloads_json}]}}"
    )
}

fn render_workload_json(workload: &WorkloadMetrics) -> String {
    format!(
        "{{\"name\":\"{}\",\"operations\":{},\"elapsed_ms\":{},\"throughput_ops_per_sec\":{:.4},\"p50_latency_us\":{},\"p95_latency_us\":{},\"max_latency_us\":{},\"peak_live_bytes\":{},\"peak_reserved_bytes\":{},\"fragmentation_permille\":{}}}",
        workload.workload,
        workload.operations,
        workload.elapsed_ms,
        workload.throughput_ops_per_sec,
        workload.p50_latency_us,
        workload.p95_latency_us,
        workload.max_latency_us,
        workload.peak_live_bytes,
        workload.peak_reserved_bytes,
        workload.fragmentation_permille
    )
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}
