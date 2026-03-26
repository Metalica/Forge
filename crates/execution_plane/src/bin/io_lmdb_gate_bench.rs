use control_plane::feature_policy::FeaturePolicyRegistry;
use control_plane::io_policy::select_workload_io_policy;
use execution_plane::benchmark::{
    IndexBenchmarkBackend, IndexBenchmarkConfig, WorkloadMetrics,
    run_indexing_benchmark_with_backend,
};
use execution_plane::io_path::{
    HostPlatform, IoBackend, IoUringCapability, KernelVersion,
    resolve_workload_io_backend_with_capability,
};
use std::error::Error;
use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use urm::feature_policy::{ActivationChecks, FeatureId, FeatureState};
use urm::io_policy::IoWorkloadClass;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GateBenchArgs {
    io_iterations: usize,
    index_documents: usize,
    index_tokens: usize,
    index_retained_documents: usize,
}

impl Default for GateBenchArgs {
    fn default() -> Self {
        Self {
            io_iterations: 250_000,
            index_documents: 900,
            index_tokens: 144,
            index_retained_documents: 96,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct IoScenarioMetrics {
    operations: u64,
    elapsed_ms: u128,
    throughput_ops_per_sec: f64,
    p50_latency_us: u64,
    p95_latency_us: u64,
    max_latency_us: u64,
    io_uring_selection_count: u64,
    fallback_count: u64,
    requirement_not_met_count: u64,
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

    let io_baseline = run_io_scenario(
        args.io_iterations,
        FeatureState::Disabled,
        IoUringCapability {
            platform: HostPlatform::Linux,
            feature_gate_enabled: true,
            kernel_version: Some(KernelVersion { major: 6, minor: 8 }),
            io_uring_disabled_flag: Some(0),
        },
    )?;
    let io_candidate = run_io_scenario(
        args.io_iterations,
        FeatureState::Enabled,
        IoUringCapability {
            platform: HostPlatform::Linux,
            feature_gate_enabled: true,
            kernel_version: Some(KernelVersion { major: 6, minor: 8 }),
            io_uring_disabled_flag: Some(0),
        },
    )?;

    let lmdb_baseline = run_indexing_benchmark_with_backend(
        IndexBenchmarkConfig {
            documents: args.index_documents,
            tokens_per_document: args.index_tokens,
            retained_documents: args.index_retained_documents,
        },
        IndexBenchmarkBackend::LegacyInMemory,
    );
    let lmdb_candidate = run_indexing_benchmark_with_backend(
        IndexBenchmarkConfig {
            documents: args.index_documents,
            tokens_per_document: args.index_tokens,
            retained_documents: args.index_retained_documents,
        },
        IndexBenchmarkBackend::Lmdb,
    );

    Ok(render_json_report(
        current_unix_ms(),
        io_baseline,
        io_candidate,
        lmdb_baseline,
        lmdb_candidate,
    ))
}

fn parse_args<I>(args: I) -> Result<GateBenchArgs, String>
where
    I: IntoIterator<Item = String>,
{
    let mut parsed = GateBenchArgs::default();
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
    args: &mut GateBenchArgs,
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
        "--io-iterations" => args.io_iterations = parsed_value,
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
        "io_lmdb_gate_bench usage:",
        "  --io-iterations <usize>",
        "  --index-documents <usize>",
        "  --index-tokens <usize>",
        "  --index-retained-documents <usize>",
    ]
    .join("\n")
}

fn run_io_scenario(
    iterations: usize,
    requested_state: FeatureState,
    capability: IoUringCapability,
) -> Result<IoScenarioMetrics, String> {
    if iterations == 0 {
        return Ok(IoScenarioMetrics {
            operations: 0,
            elapsed_ms: 0,
            throughput_ops_per_sec: 0.0,
            p50_latency_us: 0,
            p95_latency_us: 0,
            max_latency_us: 0,
            io_uring_selection_count: 0,
            fallback_count: 0,
            requirement_not_met_count: 0,
        });
    }

    let mut registry = FeaturePolicyRegistry::with_defaults();
    registry
        .set_requested_state(FeatureId::IoUring, requested_state)
        .map_err(|error| format!("failed to set io_uring state: {error:?}"))?;
    let state = registry
        .evaluate(FeatureId::IoUring, full_checks())
        .map_err(|error| format!("failed to evaluate io_uring state: {error:?}"))?;
    if matches!(state, FeatureState::Auto) {
        return Err("unexpected auto state after io benchmark setup".to_string());
    }

    let workloads = [
        IoWorkloadClass::Download,
        IoWorkloadClass::Indexing,
        IoWorkloadClass::LogStreaming,
        IoWorkloadClass::FileCopy,
    ];
    let operations = (iterations.saturating_mul(workloads.len())) as u64;
    let mut latencies_us = Vec::with_capacity(operations as usize);
    let mut io_uring_selection_count = 0u64;
    let mut fallback_count = 0u64;
    let mut requirement_not_met_count = 0u64;

    let suite_start = Instant::now();
    for _ in 0..iterations {
        for workload in workloads {
            let start = Instant::now();
            let policy = select_workload_io_policy(&registry, workload);
            let decision = resolve_workload_io_backend_with_capability(
                workload,
                policy.policy_mode,
                capability,
            );
            if matches!(decision.backend, IoBackend::IoUring) {
                io_uring_selection_count = io_uring_selection_count.saturating_add(1);
            }
            if decision.fallback_used {
                fallback_count = fallback_count.saturating_add(1);
            }
            if decision.requirement_not_met {
                requirement_not_met_count = requirement_not_met_count.saturating_add(1);
            }
            latencies_us.push(duration_to_us(start.elapsed()));
        }
    }
    let elapsed = suite_start.elapsed();
    let (p50_latency_us, p95_latency_us, max_latency_us) = latency_summary_us(&latencies_us);
    let throughput_ops_per_sec = if elapsed.is_zero() {
        0.0
    } else {
        operations as f64 / elapsed.as_secs_f64()
    };

    Ok(IoScenarioMetrics {
        operations,
        elapsed_ms: elapsed.as_millis(),
        throughput_ops_per_sec,
        p50_latency_us,
        p95_latency_us,
        max_latency_us,
        io_uring_selection_count,
        fallback_count,
        requirement_not_met_count,
    })
}

fn full_checks() -> ActivationChecks {
    ActivationChecks {
        platform_compatible: true,
        hardware_compatible: true,
        runtime_validation_ok: true,
        health_checks_ok: true,
        benchmark_sanity_ok: true,
        no_critical_conflict: true,
        measurable_benefit: true,
    }
}

fn duration_to_us(duration: Duration) -> u64 {
    duration.as_micros().min(u64::MAX as u128) as u64
}

fn latency_summary_us(latencies_us: &[u64]) -> (u64, u64, u64) {
    if latencies_us.is_empty() {
        return (0, 0, 0);
    }
    let mut sorted = latencies_us.to_vec();
    sorted.sort_unstable();
    let max_latency_us = *sorted.last().unwrap_or(&0);
    let p50 = percentile_u64(&sorted, 50);
    let p95 = percentile_u64(&sorted, 95);
    (p50, p95, max_latency_us)
}

fn percentile_u64(sorted_values: &[u64], percentile: usize) -> u64 {
    if sorted_values.is_empty() {
        return 0;
    }
    let last = sorted_values.len().saturating_sub(1);
    let index = (last.saturating_mul(percentile)) / 100;
    sorted_values[index]
}

fn percent_delta(candidate: f64, baseline: f64) -> f64 {
    if baseline.abs() < f64::EPSILON {
        return 0.0;
    }
    ((candidate - baseline) / baseline) * 100.0
}

fn percent_delta_inverse(candidate: f64, baseline: f64) -> f64 {
    if baseline.abs() < f64::EPSILON {
        return 0.0;
    }
    ((baseline - candidate) / baseline) * 100.0
}

fn render_json_report(
    generated_at_unix_ms: u64,
    io_baseline: IoScenarioMetrics,
    io_candidate: IoScenarioMetrics,
    lmdb_baseline: WorkloadMetrics,
    lmdb_candidate: WorkloadMetrics,
) -> String {
    let io_throughput_delta = percent_delta(
        io_candidate.throughput_ops_per_sec,
        io_baseline.throughput_ops_per_sec,
    );
    let io_p95_improvement = percent_delta_inverse(
        io_candidate.p95_latency_us as f64,
        io_baseline.p95_latency_us as f64,
    );

    let lmdb_throughput_delta = percent_delta(
        lmdb_candidate.throughput_ops_per_sec,
        lmdb_baseline.throughput_ops_per_sec,
    );
    let lmdb_p95_improvement = percent_delta_inverse(
        lmdb_candidate.p95_latency_us as f64,
        lmdb_baseline.p95_latency_us as f64,
    );
    let lmdb_fragmentation_improvement = percent_delta_inverse(
        lmdb_candidate.fragmentation_permille as f64,
        lmdb_baseline.fragmentation_permille as f64,
    );

    format!(
        "{{\"generated_at_unix_ms\":{generated_at_unix_ms},\"io\":{{\"baseline\":{},\"candidate\":{},\"delta\":{{\"throughput_percent\":{:.4},\"p95_latency_improvement_percent\":{:.4}}}}},\"lmdb\":{{\"baseline\":{},\"candidate\":{},\"delta\":{{\"throughput_percent\":{:.4},\"p95_latency_improvement_percent\":{:.4},\"fragmentation_improvement_percent\":{:.4}}}}}}}",
        render_io_metrics_json(io_baseline),
        render_io_metrics_json(io_candidate),
        io_throughput_delta,
        io_p95_improvement,
        render_workload_metrics_json(&lmdb_baseline),
        render_workload_metrics_json(&lmdb_candidate),
        lmdb_throughput_delta,
        lmdb_p95_improvement,
        lmdb_fragmentation_improvement
    )
}

fn render_io_metrics_json(value: IoScenarioMetrics) -> String {
    format!(
        "{{\"operations\":{},\"elapsed_ms\":{},\"throughput_ops_per_sec\":{:.4},\"p50_latency_us\":{},\"p95_latency_us\":{},\"max_latency_us\":{},\"io_uring_selection_count\":{},\"fallback_count\":{},\"requirement_not_met_count\":{}}}",
        value.operations,
        value.elapsed_ms,
        value.throughput_ops_per_sec,
        value.p50_latency_us,
        value.p95_latency_us,
        value.max_latency_us,
        value.io_uring_selection_count,
        value.fallback_count,
        value.requirement_not_met_count
    )
}

fn render_workload_metrics_json(value: &WorkloadMetrics) -> String {
    format!(
        "{{\"name\":\"{}\",\"operations\":{},\"elapsed_ms\":{},\"throughput_ops_per_sec\":{:.4},\"p50_latency_us\":{},\"p95_latency_us\":{},\"max_latency_us\":{},\"peak_live_bytes\":{},\"peak_reserved_bytes\":{},\"fragmentation_permille\":{}}}",
        value.workload,
        value.operations,
        value.elapsed_ms,
        value.throughput_ops_per_sec,
        value.p50_latency_us,
        value.p95_latency_us,
        value.max_latency_us,
        value.peak_live_bytes,
        value.peak_reserved_bytes,
        value.fragmentation_permille
    )
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}
