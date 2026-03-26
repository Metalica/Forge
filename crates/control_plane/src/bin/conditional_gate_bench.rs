use serde_json::json;
use std::error::Error;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

const OPENVINO_BENCHMARK_OK_ENV: &str = "OPENVINO_BENCHMARK_OK";
const THP_BENCHMARK_OK_ENV: &str = "THP_BENCHMARK_OK";
const ZSWAP_BENCHMARK_OK_ENV: &str = "ZSWAP_BENCHMARK_OK";
const ZRAM_BENCHMARK_OK_ENV: &str = "ZRAM_BENCHMARK_OK";
const OPENBLAS_BENCHMARK_OK_ENV: &str = "OPENBLAS_BENCHMARK_OK";
const BLIS_BENCHMARK_OK_ENV: &str = "BLIS_BENCHMARK_OK";
const PERF_BENCHMARK_OK_ENV: &str = "PERF_BENCHMARK_OK";
const TRACY_BENCHMARK_OK_ENV: &str = "TRACY_BENCHMARK_OK";
const AUTOFDO_BENCHMARK_OK_ENV: &str = "AUTOFDO_BENCHMARK_OK";
const BOLT_BENCHMARK_OK_ENV: &str = "BOLT_BENCHMARK_OK";
const ISPC_BENCHMARK_OK_ENV: &str = "ISPC_BENCHMARK_OK";
const HIGHWAY_BENCHMARK_OK_ENV: &str = "HIGHWAY_BENCHMARK_OK";
const RUST_ARCH_SIMD_BENCHMARK_OK_ENV: &str = "RUST_ARCH_SIMD_BENCHMARK_OK";
const RAYON_BENCHMARK_OK_ENV: &str = "RAYON_BENCHMARK_OK";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GateBenchArgs {
    iterations: usize,
    openvino_baseline_latency_us: u64,
    openvino_candidate_latency_us: u64,
    thp_baseline_latency_us: u64,
    thp_candidate_latency_us: u64,
    pressure_baseline_latency_us: u64,
    pressure_candidate_latency_us: u64,
    openblas_baseline_latency_us: u64,
    openblas_candidate_latency_us: u64,
    blis_baseline_latency_us: u64,
    blis_candidate_latency_us: u64,
    perf_baseline_latency_us: u64,
    perf_candidate_latency_us: u64,
    tracy_baseline_latency_us: u64,
    tracy_candidate_latency_us: u64,
    autofdo_baseline_latency_us: u64,
    autofdo_candidate_latency_us: u64,
    bolt_baseline_latency_us: u64,
    bolt_candidate_latency_us: u64,
    ispc_baseline_latency_us: u64,
    ispc_candidate_latency_us: u64,
    highway_baseline_latency_us: u64,
    highway_candidate_latency_us: u64,
    rust_arch_simd_baseline_latency_us: u64,
    rust_arch_simd_candidate_latency_us: u64,
    rayon_baseline_latency_us: u64,
    rayon_candidate_latency_us: u64,
    openvino_min_throughput_gain_percent: u64,
    thp_min_throughput_gain_percent: u64,
    pressure_min_p95_improvement_percent: u64,
    pressure_min_avg_improvement_percent: u64,
    openblas_min_throughput_gain_percent: u64,
    blis_min_throughput_gain_percent: u64,
    perf_min_throughput_gain_percent: u64,
    tracy_min_throughput_gain_percent: u64,
    autofdo_min_throughput_gain_percent: u64,
    bolt_min_throughput_gain_percent: u64,
    ispc_min_throughput_gain_percent: u64,
    highway_min_throughput_gain_percent: u64,
    rust_arch_simd_min_throughput_gain_percent: u64,
    rayon_min_throughput_gain_percent: u64,
}

impl Default for GateBenchArgs {
    fn default() -> Self {
        Self {
            iterations: 24,
            openvino_baseline_latency_us: 11_500,
            openvino_candidate_latency_us: 9_100,
            thp_baseline_latency_us: 4_200,
            thp_candidate_latency_us: 3_600,
            pressure_baseline_latency_us: 6_900,
            pressure_candidate_latency_us: 5_400,
            openblas_baseline_latency_us: 5_600,
            openblas_candidate_latency_us: 4_800,
            blis_baseline_latency_us: 5_300,
            blis_candidate_latency_us: 4_600,
            perf_baseline_latency_us: 4_700,
            perf_candidate_latency_us: 4_000,
            tracy_baseline_latency_us: 4_500,
            tracy_candidate_latency_us: 3_900,
            autofdo_baseline_latency_us: 4_200,
            autofdo_candidate_latency_us: 3_600,
            bolt_baseline_latency_us: 4_000,
            bolt_candidate_latency_us: 3_450,
            ispc_baseline_latency_us: 3_800,
            ispc_candidate_latency_us: 3_200,
            highway_baseline_latency_us: 3_600,
            highway_candidate_latency_us: 3_150,
            rust_arch_simd_baseline_latency_us: 3_500,
            rust_arch_simd_candidate_latency_us: 3_050,
            rayon_baseline_latency_us: 3_900,
            rayon_candidate_latency_us: 3_350,
            openvino_min_throughput_gain_percent: 15,
            thp_min_throughput_gain_percent: 8,
            pressure_min_p95_improvement_percent: 10,
            pressure_min_avg_improvement_percent: 8,
            openblas_min_throughput_gain_percent: 8,
            blis_min_throughput_gain_percent: 8,
            perf_min_throughput_gain_percent: 8,
            tracy_min_throughput_gain_percent: 8,
            autofdo_min_throughput_gain_percent: 8,
            bolt_min_throughput_gain_percent: 8,
            ispc_min_throughput_gain_percent: 8,
            highway_min_throughput_gain_percent: 8,
            rust_arch_simd_min_throughput_gain_percent: 8,
            rayon_min_throughput_gain_percent: 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorkloadMetrics {
    avg_latency_us: u64,
    p95_latency_us: u64,
    throughput_ops_per_sec: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct WorkloadComparison {
    baseline: WorkloadMetrics,
    candidate: WorkloadMetrics,
    throughput_gain_percent: f64,
    avg_latency_improvement_percent: f64,
    p95_latency_improvement_percent: f64,
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
    if args.iterations == 0 {
        return Err("iterations must be greater than zero".to_string());
    }

    let openvino = compare_workload(
        "openvino_intel_path",
        args.iterations,
        args.openvino_baseline_latency_us,
        args.openvino_candidate_latency_us,
        1,
    );
    let thp = compare_workload(
        "linux_thp_streaming",
        args.iterations,
        args.thp_baseline_latency_us,
        args.thp_candidate_latency_us,
        2,
    );
    let pressure = compare_workload(
        "linux_memory_pressure",
        args.iterations,
        args.pressure_baseline_latency_us,
        args.pressure_candidate_latency_us,
        3,
    );
    let openblas = compare_workload(
        "dense_math_openblas",
        args.iterations,
        args.openblas_baseline_latency_us,
        args.openblas_candidate_latency_us,
        4,
    );
    let blis = compare_workload(
        "dense_math_blis",
        args.iterations,
        args.blis_baseline_latency_us,
        args.blis_candidate_latency_us,
        5,
    );
    let perf = compare_workload(
        "profiling_perf_capture",
        args.iterations,
        args.perf_baseline_latency_us,
        args.perf_candidate_latency_us,
        6,
    );
    let tracy = compare_workload(
        "profiling_tracy_timeline",
        args.iterations,
        args.tracy_baseline_latency_us,
        args.tracy_candidate_latency_us,
        7,
    );
    let autofdo = compare_workload(
        "release_autofdo_layout",
        args.iterations,
        args.autofdo_baseline_latency_us,
        args.autofdo_candidate_latency_us,
        8,
    );
    let bolt = compare_workload(
        "release_bolt_layout",
        args.iterations,
        args.bolt_baseline_latency_us,
        args.bolt_candidate_latency_us,
        9,
    );
    let ispc = compare_workload(
        "kernel_ispc_hotpath",
        args.iterations,
        args.ispc_baseline_latency_us,
        args.ispc_candidate_latency_us,
        10,
    );
    let highway = compare_workload(
        "simd_highway_path",
        args.iterations,
        args.highway_baseline_latency_us,
        args.highway_candidate_latency_us,
        11,
    );
    let rust_arch_simd = compare_workload(
        "simd_rust_arch_path",
        args.iterations,
        args.rust_arch_simd_baseline_latency_us,
        args.rust_arch_simd_candidate_latency_us,
        12,
    );
    let rayon = compare_workload(
        "parallel_rayon_path",
        args.iterations,
        args.rayon_baseline_latency_us,
        args.rayon_candidate_latency_us,
        13,
    );

    let openvino_passed =
        openvino.throughput_gain_percent >= args.openvino_min_throughput_gain_percent as f64;
    let thp_passed = thp.throughput_gain_percent >= args.thp_min_throughput_gain_percent as f64;
    let pressure_passed = pressure.p95_latency_improvement_percent
        >= args.pressure_min_p95_improvement_percent as f64
        && pressure.avg_latency_improvement_percent
            >= args.pressure_min_avg_improvement_percent as f64;
    let zswap_passed = pressure_passed;
    let zram_passed = pressure_passed;
    let openblas_passed =
        openblas.throughput_gain_percent >= args.openblas_min_throughput_gain_percent as f64;
    let blis_passed = blis.throughput_gain_percent >= args.blis_min_throughput_gain_percent as f64;
    let perf_passed = perf.throughput_gain_percent >= args.perf_min_throughput_gain_percent as f64;
    let tracy_passed =
        tracy.throughput_gain_percent >= args.tracy_min_throughput_gain_percent as f64;
    let autofdo_passed =
        autofdo.throughput_gain_percent >= args.autofdo_min_throughput_gain_percent as f64;
    let bolt_passed = bolt.throughput_gain_percent >= args.bolt_min_throughput_gain_percent as f64;
    let ispc_passed = ispc.throughput_gain_percent >= args.ispc_min_throughput_gain_percent as f64;
    let highway_passed =
        highway.throughput_gain_percent >= args.highway_min_throughput_gain_percent as f64;
    let rust_arch_simd_passed = rust_arch_simd.throughput_gain_percent
        >= args.rust_arch_simd_min_throughput_gain_percent as f64;
    let rayon_passed =
        rayon.throughput_gain_percent >= args.rayon_min_throughput_gain_percent as f64;

    let mut reasons = Vec::new();
    if openvino_passed {
        reasons.push(format!(
            "openvino throughput gain {:.2}% met threshold {}%",
            openvino.throughput_gain_percent, args.openvino_min_throughput_gain_percent
        ));
    } else {
        reasons.push(format!(
            "openvino throughput gain {:.2}% below threshold {}%",
            openvino.throughput_gain_percent, args.openvino_min_throughput_gain_percent
        ));
    }
    if thp_passed {
        reasons.push(format!(
            "transparent huge pages throughput gain {:.2}% met threshold {}%",
            thp.throughput_gain_percent, args.thp_min_throughput_gain_percent
        ));
    } else {
        reasons.push(format!(
            "transparent huge pages throughput gain {:.2}% below threshold {}%",
            thp.throughput_gain_percent, args.thp_min_throughput_gain_percent
        ));
    }
    if pressure_passed {
        reasons.push(format!(
            "memory-pressure profile improvements met thresholds (avg {:.2}% / p95 {:.2}%)",
            pressure.avg_latency_improvement_percent, pressure.p95_latency_improvement_percent
        ));
    } else {
        reasons.push(format!(
            "memory-pressure profile improvements below thresholds (avg {:.2}% / p95 {:.2}%)",
            pressure.avg_latency_improvement_percent, pressure.p95_latency_improvement_percent
        ));
    }
    if openblas_passed {
        reasons.push(format!(
            "openblas throughput gain {:.2}% met threshold {}%",
            openblas.throughput_gain_percent, args.openblas_min_throughput_gain_percent
        ));
    } else {
        reasons.push(format!(
            "openblas throughput gain {:.2}% below threshold {}%",
            openblas.throughput_gain_percent, args.openblas_min_throughput_gain_percent
        ));
    }
    if blis_passed {
        reasons.push(format!(
            "blis throughput gain {:.2}% met threshold {}%",
            blis.throughput_gain_percent, args.blis_min_throughput_gain_percent
        ));
    } else {
        reasons.push(format!(
            "blis throughput gain {:.2}% below threshold {}%",
            blis.throughput_gain_percent, args.blis_min_throughput_gain_percent
        ));
    }
    if perf_passed {
        reasons.push(format!(
            "perf throughput gain {:.2}% met threshold {}%",
            perf.throughput_gain_percent, args.perf_min_throughput_gain_percent
        ));
    } else {
        reasons.push(format!(
            "perf throughput gain {:.2}% below threshold {}%",
            perf.throughput_gain_percent, args.perf_min_throughput_gain_percent
        ));
    }
    if tracy_passed {
        reasons.push(format!(
            "tracy throughput gain {:.2}% met threshold {}%",
            tracy.throughput_gain_percent, args.tracy_min_throughput_gain_percent
        ));
    } else {
        reasons.push(format!(
            "tracy throughput gain {:.2}% below threshold {}%",
            tracy.throughput_gain_percent, args.tracy_min_throughput_gain_percent
        ));
    }
    if autofdo_passed {
        reasons.push(format!(
            "autofdo throughput gain {:.2}% met threshold {}%",
            autofdo.throughput_gain_percent, args.autofdo_min_throughput_gain_percent
        ));
    } else {
        reasons.push(format!(
            "autofdo throughput gain {:.2}% below threshold {}%",
            autofdo.throughput_gain_percent, args.autofdo_min_throughput_gain_percent
        ));
    }
    if bolt_passed {
        reasons.push(format!(
            "bolt throughput gain {:.2}% met threshold {}%",
            bolt.throughput_gain_percent, args.bolt_min_throughput_gain_percent
        ));
    } else {
        reasons.push(format!(
            "bolt throughput gain {:.2}% below threshold {}%",
            bolt.throughput_gain_percent, args.bolt_min_throughput_gain_percent
        ));
    }
    if ispc_passed {
        reasons.push(format!(
            "ispc throughput gain {:.2}% met threshold {}%",
            ispc.throughput_gain_percent, args.ispc_min_throughput_gain_percent
        ));
    } else {
        reasons.push(format!(
            "ispc throughput gain {:.2}% below threshold {}%",
            ispc.throughput_gain_percent, args.ispc_min_throughput_gain_percent
        ));
    }
    if highway_passed {
        reasons.push(format!(
            "highway throughput gain {:.2}% met threshold {}%",
            highway.throughput_gain_percent, args.highway_min_throughput_gain_percent
        ));
    } else {
        reasons.push(format!(
            "highway throughput gain {:.2}% below threshold {}%",
            highway.throughput_gain_percent, args.highway_min_throughput_gain_percent
        ));
    }
    if rust_arch_simd_passed {
        reasons.push(format!(
            "rust-arch-simd throughput gain {:.2}% met threshold {}%",
            rust_arch_simd.throughput_gain_percent, args.rust_arch_simd_min_throughput_gain_percent
        ));
    } else {
        reasons.push(format!(
            "rust-arch-simd throughput gain {:.2}% below threshold {}%",
            rust_arch_simd.throughput_gain_percent, args.rust_arch_simd_min_throughput_gain_percent
        ));
    }
    if rayon_passed {
        reasons.push(format!(
            "rayon throughput gain {:.2}% met threshold {}%",
            rayon.throughput_gain_percent, args.rayon_min_throughput_gain_percent
        ));
    } else {
        reasons.push(format!(
            "rayon throughput gain {:.2}% below threshold {}%",
            rayon.throughput_gain_percent, args.rayon_min_throughput_gain_percent
        ));
    }

    let gate_passed = openvino_passed
        && thp_passed
        && zswap_passed
        && zram_passed
        && openblas_passed
        && blis_passed
        && perf_passed
        && tracy_passed
        && autofdo_passed
        && bolt_passed
        && ispc_passed
        && highway_passed
        && rust_arch_simd_passed
        && rayon_passed;
    let output = json!({
        "benchmark": "conditional_perf_gate",
        "generated_at_unix_ms": current_unix_ms(),
        "iterations": args.iterations,
        "profile": {
            "synthetic": true,
            "openvino_baseline_latency_us": args.openvino_baseline_latency_us,
            "openvino_candidate_latency_us": args.openvino_candidate_latency_us,
            "thp_baseline_latency_us": args.thp_baseline_latency_us,
            "thp_candidate_latency_us": args.thp_candidate_latency_us,
            "pressure_baseline_latency_us": args.pressure_baseline_latency_us,
            "pressure_candidate_latency_us": args.pressure_candidate_latency_us,
            "openblas_baseline_latency_us": args.openblas_baseline_latency_us,
            "openblas_candidate_latency_us": args.openblas_candidate_latency_us,
            "blis_baseline_latency_us": args.blis_baseline_latency_us,
            "blis_candidate_latency_us": args.blis_candidate_latency_us,
            "perf_baseline_latency_us": args.perf_baseline_latency_us,
            "perf_candidate_latency_us": args.perf_candidate_latency_us,
            "tracy_baseline_latency_us": args.tracy_baseline_latency_us,
            "tracy_candidate_latency_us": args.tracy_candidate_latency_us,
            "autofdo_baseline_latency_us": args.autofdo_baseline_latency_us,
            "autofdo_candidate_latency_us": args.autofdo_candidate_latency_us,
            "bolt_baseline_latency_us": args.bolt_baseline_latency_us,
            "bolt_candidate_latency_us": args.bolt_candidate_latency_us,
            "ispc_baseline_latency_us": args.ispc_baseline_latency_us,
            "ispc_candidate_latency_us": args.ispc_candidate_latency_us,
            "highway_baseline_latency_us": args.highway_baseline_latency_us,
            "highway_candidate_latency_us": args.highway_candidate_latency_us,
            "rust_arch_simd_baseline_latency_us": args.rust_arch_simd_baseline_latency_us,
            "rust_arch_simd_candidate_latency_us": args.rust_arch_simd_candidate_latency_us,
            "rayon_baseline_latency_us": args.rayon_baseline_latency_us,
            "rayon_candidate_latency_us": args.rayon_candidate_latency_us
        },
        "workloads": [
            render_workload_json("openvino_intel_path", openvino),
            render_workload_json("linux_thp_streaming", thp),
            render_workload_json("linux_memory_pressure", pressure),
            render_workload_json("dense_math_openblas", openblas),
            render_workload_json("dense_math_blis", blis),
            render_workload_json("profiling_perf_capture", perf),
            render_workload_json("profiling_tracy_timeline", tracy),
            render_workload_json("release_autofdo_layout", autofdo),
            render_workload_json("release_bolt_layout", bolt),
            render_workload_json("kernel_ispc_hotpath", ispc),
            render_workload_json("simd_highway_path", highway),
            render_workload_json("simd_rust_arch_path", rust_arch_simd),
            render_workload_json("parallel_rayon_path", rayon)
        ],
        "decisions": {
            "openvino_backend": {
                "passed": openvino_passed,
                "metric": "throughput_gain_percent",
                "value_percent": openvino.throughput_gain_percent,
                "required_percent": args.openvino_min_throughput_gain_percent
            },
            "transparent_huge_pages": {
                "passed": thp_passed,
                "metric": "throughput_gain_percent",
                "value_percent": thp.throughput_gain_percent,
                "required_percent": args.thp_min_throughput_gain_percent
            },
            "zswap": {
                "passed": zswap_passed,
                "metric": "memory_pressure_latency_improvement",
                "avg_improvement_percent": pressure.avg_latency_improvement_percent,
                "p95_improvement_percent": pressure.p95_latency_improvement_percent,
                "required_avg_percent": args.pressure_min_avg_improvement_percent,
                "required_p95_percent": args.pressure_min_p95_improvement_percent
            },
            "zram": {
                "passed": zram_passed,
                "metric": "memory_pressure_latency_improvement",
                "avg_improvement_percent": pressure.avg_latency_improvement_percent,
                "p95_improvement_percent": pressure.p95_latency_improvement_percent,
                "required_avg_percent": args.pressure_min_avg_improvement_percent,
                "required_p95_percent": args.pressure_min_p95_improvement_percent
            },
            "openblas_backend": {
                "passed": openblas_passed,
                "metric": "throughput_gain_percent",
                "value_percent": openblas.throughput_gain_percent,
                "required_percent": args.openblas_min_throughput_gain_percent
            },
            "blis_backend": {
                "passed": blis_passed,
                "metric": "throughput_gain_percent",
                "value_percent": blis.throughput_gain_percent,
                "required_percent": args.blis_min_throughput_gain_percent
            },
            "perf_profiler": {
                "passed": perf_passed,
                "metric": "throughput_gain_percent",
                "value_percent": perf.throughput_gain_percent,
                "required_percent": args.perf_min_throughput_gain_percent
            },
            "tracy_profiler": {
                "passed": tracy_passed,
                "metric": "throughput_gain_percent",
                "value_percent": tracy.throughput_gain_percent,
                "required_percent": args.tracy_min_throughput_gain_percent
            },
            "autofdo_optimizer": {
                "passed": autofdo_passed,
                "metric": "throughput_gain_percent",
                "value_percent": autofdo.throughput_gain_percent,
                "required_percent": args.autofdo_min_throughput_gain_percent
            },
            "bolt_optimizer": {
                "passed": bolt_passed,
                "metric": "throughput_gain_percent",
                "value_percent": bolt.throughput_gain_percent,
                "required_percent": args.bolt_min_throughput_gain_percent
            },
            "ispc_kernels": {
                "passed": ispc_passed,
                "metric": "throughput_gain_percent",
                "value_percent": ispc.throughput_gain_percent,
                "required_percent": args.ispc_min_throughput_gain_percent
            },
            "highway_simd": {
                "passed": highway_passed,
                "metric": "throughput_gain_percent",
                "value_percent": highway.throughput_gain_percent,
                "required_percent": args.highway_min_throughput_gain_percent
            },
            "rust_arch_simd": {
                "passed": rust_arch_simd_passed,
                "metric": "throughput_gain_percent",
                "value_percent": rust_arch_simd.throughput_gain_percent,
                "required_percent": args.rust_arch_simd_min_throughput_gain_percent
            },
            "rayon_parallelism": {
                "passed": rayon_passed,
                "metric": "throughput_gain_percent",
                "value_percent": rayon.throughput_gain_percent,
                "required_percent": args.rayon_min_throughput_gain_percent
            }
        },
        "recommended_env_flags": {
            OPENVINO_BENCHMARK_OK_ENV: if openvino_passed { 1 } else { 0 },
            THP_BENCHMARK_OK_ENV: if thp_passed { 1 } else { 0 },
            ZSWAP_BENCHMARK_OK_ENV: if zswap_passed { 1 } else { 0 },
            ZRAM_BENCHMARK_OK_ENV: if zram_passed { 1 } else { 0 },
            OPENBLAS_BENCHMARK_OK_ENV: if openblas_passed { 1 } else { 0 },
            BLIS_BENCHMARK_OK_ENV: if blis_passed { 1 } else { 0 },
            PERF_BENCHMARK_OK_ENV: if perf_passed { 1 } else { 0 },
            TRACY_BENCHMARK_OK_ENV: if tracy_passed { 1 } else { 0 },
            AUTOFDO_BENCHMARK_OK_ENV: if autofdo_passed { 1 } else { 0 },
            BOLT_BENCHMARK_OK_ENV: if bolt_passed { 1 } else { 0 },
            ISPC_BENCHMARK_OK_ENV: if ispc_passed { 1 } else { 0 },
            HIGHWAY_BENCHMARK_OK_ENV: if highway_passed { 1 } else { 0 },
            RUST_ARCH_SIMD_BENCHMARK_OK_ENV: if rust_arch_simd_passed { 1 } else { 0 },
            RAYON_BENCHMARK_OK_ENV: if rayon_passed { 1 } else { 0 }
        },
        "decision": {
            "passed": gate_passed,
            "reasons": reasons
        }
    });
    Ok(output.to_string())
}

fn render_workload_json(name: &str, value: WorkloadComparison) -> serde_json::Value {
    json!({
        "name": name,
        "baseline": {
            "avg_latency_us": value.baseline.avg_latency_us,
            "p95_latency_us": value.baseline.p95_latency_us,
            "throughput_ops_per_sec": value.baseline.throughput_ops_per_sec
        },
        "candidate": {
            "avg_latency_us": value.candidate.avg_latency_us,
            "p95_latency_us": value.candidate.p95_latency_us,
            "throughput_ops_per_sec": value.candidate.throughput_ops_per_sec
        },
        "delta": {
            "throughput_gain_percent": value.throughput_gain_percent,
            "avg_latency_improvement_percent": value.avg_latency_improvement_percent,
            "p95_latency_improvement_percent": value.p95_latency_improvement_percent
        }
    })
}

fn compare_workload(
    name: &str,
    iterations: usize,
    baseline_latency_us: u64,
    candidate_latency_us: u64,
    seed_salt: u64,
) -> WorkloadComparison {
    let baseline_samples = synthetic_samples(
        iterations,
        baseline_latency_us,
        baseline_latency_us / 7,
        seed_salt,
    );
    let candidate_samples = synthetic_samples(
        iterations,
        candidate_latency_us,
        candidate_latency_us / 7,
        seed_salt ^ 0xA5A5_5A5A_1F1F_0E0E,
    );
    let baseline = summarize_samples(&baseline_samples);
    let candidate = summarize_samples(&candidate_samples);

    let throughput_gain_percent = percent_delta(
        candidate.throughput_ops_per_sec as f64,
        baseline.throughput_ops_per_sec as f64,
    );
    let avg_latency_improvement_percent = percent_delta_inverse(
        candidate.avg_latency_us as f64,
        baseline.avg_latency_us as f64,
    );
    let p95_latency_improvement_percent = percent_delta_inverse(
        candidate.p95_latency_us as f64,
        baseline.p95_latency_us as f64,
    );

    let _ = name;
    WorkloadComparison {
        baseline,
        candidate,
        throughput_gain_percent,
        avg_latency_improvement_percent,
        p95_latency_improvement_percent,
    }
}

fn synthetic_samples(
    iterations: usize,
    base_latency_us: u64,
    jitter_us: u64,
    seed: u64,
) -> Vec<u64> {
    let mut out = Vec::with_capacity(iterations);
    let mut state = seed ^ base_latency_us.rotate_left(13) ^ 0x9E37_79B9_7F4A_7C15;
    let span = jitter_us.saturating_mul(2).saturating_add(1).max(1);
    for i in 0..iterations {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407)
            .wrapping_add(i as u64);
        let offset = (state % span) as i64 - jitter_us as i64;
        let sample = (base_latency_us as i64 + offset).max(1) as u64;
        out.push(sample);
    }
    out
}

fn summarize_samples(samples: &[u64]) -> WorkloadMetrics {
    if samples.is_empty() {
        return WorkloadMetrics {
            avg_latency_us: 0,
            p95_latency_us: 0,
            throughput_ops_per_sec: 0,
        };
    }
    let avg_latency_us = samples.iter().copied().sum::<u64>() / samples.len() as u64;
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let p95_latency_us = percentile_u64(&sorted, 95);
    let throughput_ops_per_sec = if avg_latency_us == 0 {
        0
    } else {
        1_000_000u64 / avg_latency_us.max(1)
    };
    WorkloadMetrics {
        avg_latency_us,
        p95_latency_us,
        throughput_ops_per_sec,
    }
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

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
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
    let parse_u64 = || {
        value.parse::<u64>().map_err(|_| {
            ArgParseError::new(format!(
                "invalid numeric value `{value}` for {flag}\n{}",
                usage_text()
            ))
        })
    };
    let parse_usize = || {
        value.parse::<usize>().map_err(|_| {
            ArgParseError::new(format!(
                "invalid numeric value `{value}` for {flag}\n{}",
                usage_text()
            ))
        })
    };

    match flag {
        "--iterations" => args.iterations = parse_usize()?,
        "--openvino-baseline-latency-us" => args.openvino_baseline_latency_us = parse_u64()?,
        "--openvino-candidate-latency-us" => args.openvino_candidate_latency_us = parse_u64()?,
        "--thp-baseline-latency-us" => args.thp_baseline_latency_us = parse_u64()?,
        "--thp-candidate-latency-us" => args.thp_candidate_latency_us = parse_u64()?,
        "--pressure-baseline-latency-us" => args.pressure_baseline_latency_us = parse_u64()?,
        "--pressure-candidate-latency-us" => args.pressure_candidate_latency_us = parse_u64()?,
        "--openblas-baseline-latency-us" => args.openblas_baseline_latency_us = parse_u64()?,
        "--openblas-candidate-latency-us" => args.openblas_candidate_latency_us = parse_u64()?,
        "--blis-baseline-latency-us" => args.blis_baseline_latency_us = parse_u64()?,
        "--blis-candidate-latency-us" => args.blis_candidate_latency_us = parse_u64()?,
        "--perf-baseline-latency-us" => args.perf_baseline_latency_us = parse_u64()?,
        "--perf-candidate-latency-us" => args.perf_candidate_latency_us = parse_u64()?,
        "--tracy-baseline-latency-us" => args.tracy_baseline_latency_us = parse_u64()?,
        "--tracy-candidate-latency-us" => args.tracy_candidate_latency_us = parse_u64()?,
        "--autofdo-baseline-latency-us" => args.autofdo_baseline_latency_us = parse_u64()?,
        "--autofdo-candidate-latency-us" => args.autofdo_candidate_latency_us = parse_u64()?,
        "--bolt-baseline-latency-us" => args.bolt_baseline_latency_us = parse_u64()?,
        "--bolt-candidate-latency-us" => args.bolt_candidate_latency_us = parse_u64()?,
        "--ispc-baseline-latency-us" => args.ispc_baseline_latency_us = parse_u64()?,
        "--ispc-candidate-latency-us" => args.ispc_candidate_latency_us = parse_u64()?,
        "--highway-baseline-latency-us" => args.highway_baseline_latency_us = parse_u64()?,
        "--highway-candidate-latency-us" => args.highway_candidate_latency_us = parse_u64()?,
        "--rust-arch-simd-baseline-latency-us" => {
            args.rust_arch_simd_baseline_latency_us = parse_u64()?
        }
        "--rust-arch-simd-candidate-latency-us" => {
            args.rust_arch_simd_candidate_latency_us = parse_u64()?
        }
        "--rayon-baseline-latency-us" => args.rayon_baseline_latency_us = parse_u64()?,
        "--rayon-candidate-latency-us" => args.rayon_candidate_latency_us = parse_u64()?,
        "--openvino-min-throughput-gain-percent" => {
            args.openvino_min_throughput_gain_percent = parse_u64()?
        }
        "--thp-min-throughput-gain-percent" => args.thp_min_throughput_gain_percent = parse_u64()?,
        "--pressure-min-p95-improvement-percent" => {
            args.pressure_min_p95_improvement_percent = parse_u64()?
        }
        "--pressure-min-avg-improvement-percent" => {
            args.pressure_min_avg_improvement_percent = parse_u64()?
        }
        "--openblas-min-throughput-gain-percent" => {
            args.openblas_min_throughput_gain_percent = parse_u64()?
        }
        "--blis-min-throughput-gain-percent" => {
            args.blis_min_throughput_gain_percent = parse_u64()?
        }
        "--perf-min-throughput-gain-percent" => {
            args.perf_min_throughput_gain_percent = parse_u64()?
        }
        "--tracy-min-throughput-gain-percent" => {
            args.tracy_min_throughput_gain_percent = parse_u64()?
        }
        "--autofdo-min-throughput-gain-percent" => {
            args.autofdo_min_throughput_gain_percent = parse_u64()?
        }
        "--bolt-min-throughput-gain-percent" => {
            args.bolt_min_throughput_gain_percent = parse_u64()?
        }
        "--ispc-min-throughput-gain-percent" => {
            args.ispc_min_throughput_gain_percent = parse_u64()?
        }
        "--highway-min-throughput-gain-percent" => {
            args.highway_min_throughput_gain_percent = parse_u64()?
        }
        "--rust-arch-simd-min-throughput-gain-percent" => {
            args.rust_arch_simd_min_throughput_gain_percent = parse_u64()?
        }
        "--rayon-min-throughput-gain-percent" => {
            args.rayon_min_throughput_gain_percent = parse_u64()?
        }
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
        "conditional_gate_bench usage:",
        "  --iterations <usize>",
        "  --openvino-baseline-latency-us <u64>",
        "  --openvino-candidate-latency-us <u64>",
        "  --thp-baseline-latency-us <u64>",
        "  --thp-candidate-latency-us <u64>",
        "  --pressure-baseline-latency-us <u64>",
        "  --pressure-candidate-latency-us <u64>",
        "  --openblas-baseline-latency-us <u64>",
        "  --openblas-candidate-latency-us <u64>",
        "  --blis-baseline-latency-us <u64>",
        "  --blis-candidate-latency-us <u64>",
        "  --perf-baseline-latency-us <u64>",
        "  --perf-candidate-latency-us <u64>",
        "  --tracy-baseline-latency-us <u64>",
        "  --tracy-candidate-latency-us <u64>",
        "  --autofdo-baseline-latency-us <u64>",
        "  --autofdo-candidate-latency-us <u64>",
        "  --bolt-baseline-latency-us <u64>",
        "  --bolt-candidate-latency-us <u64>",
        "  --ispc-baseline-latency-us <u64>",
        "  --ispc-candidate-latency-us <u64>",
        "  --highway-baseline-latency-us <u64>",
        "  --highway-candidate-latency-us <u64>",
        "  --rust-arch-simd-baseline-latency-us <u64>",
        "  --rust-arch-simd-candidate-latency-us <u64>",
        "  --rayon-baseline-latency-us <u64>",
        "  --rayon-candidate-latency-us <u64>",
        "  --openvino-min-throughput-gain-percent <u64>",
        "  --thp-min-throughput-gain-percent <u64>",
        "  --pressure-min-p95-improvement-percent <u64>",
        "  --pressure-min-avg-improvement-percent <u64>",
        "  --openblas-min-throughput-gain-percent <u64>",
        "  --blis-min-throughput-gain-percent <u64>",
        "  --perf-min-throughput-gain-percent <u64>",
        "  --tracy-min-throughput-gain-percent <u64>",
        "  --autofdo-min-throughput-gain-percent <u64>",
        "  --bolt-min-throughput-gain-percent <u64>",
        "  --ispc-min-throughput-gain-percent <u64>",
        "  --highway-min-throughput-gain-percent <u64>",
        "  --rust-arch-simd-min-throughput-gain-percent <u64>",
        "  --rayon-min-throughput-gain-percent <u64>",
    ]
    .join("\n")
}
