use argon2::{Algorithm, Argon2, Params, Version};
use serde::Serialize;
use std::env;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
struct BenchArgs {
    out_path: PathBuf,
    runs: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Argon2BenchError {
    message: String,
}

impl Argon2BenchError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for Argon2BenchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for Argon2BenchError {}

#[derive(Debug, Serialize)]
struct Argon2BenchReport {
    schema_version: u32,
    generated_at_unix_ms: u64,
    runs_per_profile: usize,
    profiles: Vec<Argon2BenchProfile>,
}

#[derive(Debug, Serialize)]
struct Argon2BenchProfile {
    name: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    output_len_bytes: usize,
    avg_ms: f64,
    p95_ms: f64,
    min_ms: f64,
    max_ms: f64,
}

impl BenchArgs {
    fn parse() -> Result<Self, Argon2BenchError> {
        let mut out_path = None::<PathBuf>;
        let mut runs = 12usize;
        let mut args = env::args().skip(1);
        while let Some(flag) = args.next() {
            if flag == "--help" || flag == "-h" {
                return Err(Argon2BenchError::new(Self::usage()));
            }
            let value = args.next().ok_or_else(|| {
                Argon2BenchError::new(format!(
                    "missing value for argument {flag}\n\n{}",
                    Self::usage()
                ))
            })?;
            match flag.as_str() {
                "--out" => out_path = Some(PathBuf::from(value)),
                "--runs" => {
                    runs = value.parse::<usize>().map_err(|_| {
                        Argon2BenchError::new(format!(
                            "invalid --runs value {value}; expected positive integer"
                        ))
                    })?;
                }
                _ => {
                    return Err(Argon2BenchError::new(format!(
                        "unknown argument {flag}\n\n{}",
                        Self::usage()
                    )));
                }
            }
        }

        let out_path = out_path.ok_or_else(|| {
            Argon2BenchError::new(format!("missing --out argument\n\n{}", Self::usage()))
        })?;
        if runs == 0 {
            return Err(Argon2BenchError::new("--runs must be at least 1"));
        }

        Ok(Self { out_path, runs })
    }

    fn usage() -> String {
        "Usage:\n  argon2id_bench_report --out <path> [--runs <n>]\n\nExample:\n  cargo run -p forge_security --bin argon2id_bench_report -- --out E:/Forge/.tmp/security/argon2id_benchmark_report.json --runs 12".to_string()
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Argon2BenchError> {
    let args = BenchArgs::parse()?;
    let passphrase = b"forge-security-argon2id-benchmark-passphrase";
    let salt = b"forge-security-argon2id-benchmark-salt";
    let profiles = vec![
        ("fallback-default", 19 * 1024, 2, 1),
        ("migration-low-memory", 8 * 1024, 2, 1),
        ("migration-high-memory", 32 * 1024, 2, 1),
    ];

    let mut report_profiles = Vec::with_capacity(profiles.len());
    for (name, memory_kib, iterations, parallelism) in profiles {
        let result = benchmark_profile(
            name,
            passphrase,
            salt,
            memory_kib,
            iterations,
            parallelism,
            args.runs,
        )?;
        report_profiles.push(result);
    }

    let report = Argon2BenchReport {
        schema_version: 1,
        generated_at_unix_ms: now_unix_ms(),
        runs_per_profile: args.runs,
        profiles: report_profiles,
    };
    if let Some(parent) = args.out_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|error| {
                Argon2BenchError::new(format!(
                    "failed to create benchmark artifact directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
    }
    let encoded = serde_json::to_string_pretty(&report).map_err(|error| {
        Argon2BenchError::new(format!("argon2id benchmark serialization failed: {error}"))
    })?;
    fs::write(args.out_path.as_path(), encoded).map_err(|error| {
        Argon2BenchError::new(format!(
            "argon2id benchmark report write failed at {}: {error}",
            args.out_path.display()
        ))
    })?;

    println!(
        "argon2id benchmark report exported to {}",
        args.out_path.display()
    );
    Ok(())
}

fn benchmark_profile(
    name: &str,
    passphrase: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    runs: usize,
) -> Result<Argon2BenchProfile, Argon2BenchError> {
    let params = Params::new(memory_kib, iterations, parallelism, Some(32))
        .map_err(|_| Argon2BenchError::new("argon2id parameters are invalid"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut durations_ms = Vec::with_capacity(runs);
    for _ in 0..runs {
        let mut output = [0u8; 32];
        let started = Instant::now();
        argon2
            .hash_password_into(passphrase, salt, output.as_mut_slice())
            .map_err(|_| Argon2BenchError::new("argon2id derivation failed during benchmark"))?;
        std::hint::black_box(output);
        durations_ms.push(duration_to_millis(started.elapsed()));
    }
    durations_ms.sort_by(|left, right| left.total_cmp(right));
    let min_ms = *durations_ms.first().unwrap_or(&0.0);
    let max_ms = *durations_ms.last().unwrap_or(&0.0);
    let sum_ms: f64 = durations_ms.iter().sum();
    let avg_ms = if durations_ms.is_empty() {
        0.0
    } else {
        sum_ms / durations_ms.len() as f64
    };
    let p95_index = if durations_ms.is_empty() {
        0
    } else {
        (((durations_ms.len() as f64) * 0.95).ceil() as usize)
            .saturating_sub(1)
            .min(durations_ms.len().saturating_sub(1))
    };
    let p95_ms = *durations_ms.get(p95_index).unwrap_or(&0.0);

    Ok(Argon2BenchProfile {
        name: name.to_string(),
        memory_kib,
        iterations,
        parallelism,
        output_len_bytes: 32,
        avg_ms,
        p95_ms,
        min_ms,
        max_ms,
    })
}

fn duration_to_millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .unwrap_or(Duration::from_millis(0))
        .as_millis()
        .min(u64::MAX as u128) as u64
}
