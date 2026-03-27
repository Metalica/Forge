use runtime_registry::confidential_relay::{
    AttestationEvidence, AttestationVerifierBackend, AttestationVerifierConfig,
    ConfidentialEndpointMetadata, ConfidentialRelayMode, ConfidentialRelayPolicy,
    ConfidentialRelaySessionStore, RelayEncryptionMode, unix_time_ms_now,
};
use runtime_registry::provider_adapter::{
    ChatTaskRequest, ConfidentialChatTaskRequest, run_chat_task_with_source,
    run_confidential_chat_task_with_source,
};
use runtime_registry::source_registry::{SourceEntry, SourceKind, SourceRole};
use serde_json::{Value, json};
use std::error::Error;
use std::fmt;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

const INSECURE_LOCALHOST_HTTP_ENV: &str = "CONFIDENTIAL_ALLOW_INSECURE_LOCALHOST_HTTP";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BenchmarkArgs {
    iterations: usize,
    chat_base_delay_ms: u64,
    chat_tokens_per_ms_divisor: u64,
    verifier_delay_ms: u64,
    small_max_tokens: u32,
    medium_max_tokens: u32,
    large_max_tokens: u32,
    small_overhead_max_percent: u64,
    medium_overhead_max_percent: u64,
    large_overhead_max_percent: u64,
}

impl Default for BenchmarkArgs {
    fn default() -> Self {
        Self {
            iterations: 12,
            chat_base_delay_ms: 6,
            chat_tokens_per_ms_divisor: 16,
            verifier_delay_ms: 3,
            small_max_tokens: 128,
            medium_max_tokens: 512,
            large_max_tokens: 2048,
            small_overhead_max_percent: 30,
            medium_overhead_max_percent: 20,
            large_overhead_max_percent: 12,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorkloadSpec {
    name: &'static str,
    max_tokens: u32,
    overhead_max_percent: u64,
}

#[derive(Debug, Clone, PartialEq)]
struct WorkloadResult {
    name: &'static str,
    max_tokens: u32,
    sample_count: usize,
    routed_avg_ms: u64,
    routed_p95_ms: u64,
    confidential_avg_ms: u64,
    confidential_p95_ms: u64,
    verify_avg_ms: u64,
    verify_p95_ms: u64,
    relay_avg_ms: u64,
    relay_p95_ms: u64,
    total_path_avg_ms: u64,
    total_path_p95_ms: u64,
    overhead_avg_ms: i64,
    overhead_percent: u64,
    threshold_percent: u64,
    threshold_passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecisionSummary {
    passed: bool,
    reasons: Vec<String>,
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
        Ok(output) => println!("{output}"),
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
    let workloads = [
        WorkloadSpec {
            name: "small",
            max_tokens: args.small_max_tokens,
            overhead_max_percent: args.small_overhead_max_percent,
        },
        WorkloadSpec {
            name: "medium",
            max_tokens: args.medium_max_tokens,
            overhead_max_percent: args.medium_overhead_max_percent,
        },
        WorkloadSpec {
            name: "large",
            max_tokens: args.large_max_tokens,
            overhead_max_percent: args.large_overhead_max_percent,
        },
    ];
    for workload in workloads {
        if workload.max_tokens == 0 {
            return Err(format!("{} max_tokens must be > 0", workload.name));
        }
    }

    let localhost_http_enabled = std::env::var(INSECURE_LOCALHOST_HTTP_ENV)
        .ok()
        .map(|value| value.trim() == "1")
        .unwrap_or(false);
    if !localhost_http_enabled {
        return Err(format!(
            "benchmark requires {}=1 for localhost mock endpoints",
            INSECURE_LOCALHOST_HTTP_ENV
        ));
    }

    let expected_chat_requests = args
        .iterations
        .saturating_mul(workloads.len())
        .saturating_mul(2);
    let expected_verifier_requests = args.iterations.saturating_mul(workloads.len());
    let (chat_endpoint, chat_handle) = spawn_chat_server(
        expected_chat_requests,
        args.chat_base_delay_ms,
        args.chat_tokens_per_ms_divisor,
    )?;
    let (verifier_endpoint, verifier_handle) =
        spawn_verifier_server(expected_verifier_requests, args.verifier_delay_ms)?;

    let source = SourceEntry {
        id: "bench-mode-a-sidecar".to_string(),
        display_name: "Bench Mode A Sidecar".to_string(),
        kind: SourceKind::SidecarBridge,
        target: chat_endpoint.clone(),
        enabled: true,
        eligible_roles: vec![SourceRole::Chat],
        default_roles: vec![SourceRole::Chat],
        confidential_endpoint: Some(ConfidentialEndpointMetadata {
            enabled: true,
            expected_target_prefix: "http://127.0.0.1".to_string(),
            expected_attestation_provider: Some("bench-provider".to_string()),
            expected_measurement_prefixes: vec!["sha256:bench-".to_string()],
            attestation_verifier: AttestationVerifierConfig {
                backend: AttestationVerifierBackend::HttpJsonV1,
                endpoint: verifier_endpoint,
                api_key_env_var: None,
                timeout_ms: 2_500,
            },
            encryption_mode: RelayEncryptionMode::TlsHttps,
            declared_logging_policy: runtime_registry::confidential_relay::default_declared_logging_policy(),
        }),
    };

    let mut session_store = ConfidentialRelaySessionStore::new();
    let mut workload_results = Vec::<WorkloadResult>::new();
    let mut now = unix_time_ms_now();
    for workload in workloads {
        let mut routed_samples = Vec::<u64>::with_capacity(args.iterations);
        let mut confidential_samples = Vec::<u64>::with_capacity(args.iterations);
        let mut verify_samples = Vec::<u64>::with_capacity(args.iterations);
        let mut relay_samples = Vec::<u64>::with_capacity(args.iterations);
        let mut total_path_samples = Vec::<u64>::with_capacity(args.iterations);

        for iteration in 0..args.iterations {
            now = now.saturating_add(31);
            let prompt = format!(
                "forge confidential relay benchmark workload={} iteration={iteration}",
                workload.name
            );
            let routed_request = ChatTaskRequest::new(prompt.clone(), workload.max_tokens)?;
            let routed_start = Instant::now();
            let routed_response = run_chat_task_with_source(&source, &routed_request)?;
            let routed_elapsed_ms =
                u64::try_from(routed_start.elapsed().as_millis()).unwrap_or(u64::MAX);
            if routed_response.output_text.is_empty() {
                return Err("routed benchmark response unexpectedly empty".to_string());
            }
            routed_samples.push(routed_elapsed_ms.max(1));

            let attestation = AttestationEvidence {
                provider: "bench-provider".to_string(),
                measurement: format!("sha256:bench-{}-{iteration}", workload.name),
                nonce: format!("nonce-{}-{iteration}-{now}", workload.name),
                cpu_confidential: true,
                gpu_confidential: true,
                issued_at_unix_ms: now.saturating_sub(500),
                expires_at_unix_ms: now.saturating_add(60_000),
                signature: format!("bench-signature-{}-{iteration}", workload.name),
            };
            let confidential_request = ConfidentialChatTaskRequest {
                prompt,
                max_tokens: workload.max_tokens,
                attestation,
                policy: ConfidentialRelayPolicy {
                    mode: ConfidentialRelayMode::Required,
                    require_confidential_cpu: true,
                    require_confidential_gpu: true,
                    max_attestation_age_ms: 120_000,
                },
            };
            let confidential_start = Instant::now();
            let confidential_response = run_confidential_chat_task_with_source(
                &source,
                &confidential_request,
                &mut session_store,
                now,
            )?;
            let confidential_elapsed_ms =
                u64::try_from(confidential_start.elapsed().as_millis()).unwrap_or(u64::MAX);
            if confidential_response.output_text.is_empty() {
                return Err("confidential benchmark response unexpectedly empty".to_string());
            }
            confidential_samples.push(confidential_elapsed_ms.max(1));
            verify_samples.push(confidential_response.attestation_verify_ms.max(1));
            relay_samples.push(confidential_response.relay_roundtrip_ms.max(1));
            total_path_samples.push(confidential_response.total_path_ms.max(1));
        }

        let routed_avg_ms = average_u64(&routed_samples);
        let routed_p95_ms = percentile_u64(&routed_samples, 95);
        let confidential_avg_ms = average_u64(&confidential_samples);
        let confidential_p95_ms = percentile_u64(&confidential_samples, 95);
        let verify_avg_ms = average_u64(&verify_samples);
        let verify_p95_ms = percentile_u64(&verify_samples, 95);
        let relay_avg_ms = average_u64(&relay_samples);
        let relay_p95_ms = percentile_u64(&relay_samples, 95);
        let total_path_avg_ms = average_u64(&total_path_samples);
        let total_path_p95_ms = percentile_u64(&total_path_samples, 95);
        let overhead_avg_ms = i64::try_from(confidential_avg_ms)
            .unwrap_or(i64::MAX)
            .saturating_sub(i64::try_from(routed_avg_ms).unwrap_or(i64::MAX));
        let overhead_percent = percent_overhead(confidential_avg_ms, routed_avg_ms);
        let threshold_passed = overhead_percent <= workload.overhead_max_percent;

        workload_results.push(WorkloadResult {
            name: workload.name,
            max_tokens: workload.max_tokens,
            sample_count: args.iterations,
            routed_avg_ms,
            routed_p95_ms,
            confidential_avg_ms,
            confidential_p95_ms,
            verify_avg_ms,
            verify_p95_ms,
            relay_avg_ms,
            relay_p95_ms,
            total_path_avg_ms,
            total_path_p95_ms,
            overhead_avg_ms,
            overhead_percent,
            threshold_percent: workload.overhead_max_percent,
            threshold_passed,
        });
    }

    let _ = chat_handle.join();
    let _ = verifier_handle.join();

    let decision = evaluate_decision(&workload_results);
    let output = render_report_json(
        unix_time_ms_now(),
        args,
        &workload_results,
        &decision,
        localhost_http_enabled,
    );
    Ok(output)
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
    let parse_u64 = || {
        value.parse::<u64>().map_err(|_| {
            ArgParseError::new(format!(
                "invalid numeric value `{value}` for {flag}\n{}",
                usage_text()
            ))
        })
    };
    let parse_u32 = || {
        value.parse::<u32>().map_err(|_| {
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
        "--chat-base-delay-ms" => args.chat_base_delay_ms = parse_u64()?,
        "--chat-tokens-per-ms-divisor" => args.chat_tokens_per_ms_divisor = parse_u64()?,
        "--verifier-delay-ms" => args.verifier_delay_ms = parse_u64()?,
        "--small-max-tokens" => args.small_max_tokens = parse_u32()?,
        "--medium-max-tokens" => args.medium_max_tokens = parse_u32()?,
        "--large-max-tokens" => args.large_max_tokens = parse_u32()?,
        "--small-overhead-max-percent" => args.small_overhead_max_percent = parse_u64()?,
        "--medium-overhead-max-percent" => args.medium_overhead_max_percent = parse_u64()?,
        "--large-overhead-max-percent" => args.large_overhead_max_percent = parse_u64()?,
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
        "confidential_relay_gate_bench usage:",
        "  --iterations <usize>",
        "  --chat-base-delay-ms <u64>",
        "  --chat-tokens-per-ms-divisor <u64>",
        "  --verifier-delay-ms <u64>",
        "  --small-max-tokens <u32>",
        "  --medium-max-tokens <u32>",
        "  --large-max-tokens <u32>",
        "  --small-overhead-max-percent <u64>",
        "  --medium-overhead-max-percent <u64>",
        "  --large-overhead-max-percent <u64>",
    ]
    .join("\n")
}

fn spawn_chat_server(
    request_count: usize,
    base_delay_ms: u64,
    tokens_per_ms_divisor: u64,
) -> Result<(String, thread::JoinHandle<()>), String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    let endpoint = format!("http://127.0.0.1:{}/v1/chat/completions", address.port());
    let divisor = tokens_per_ms_divisor.max(1);

    let handle = thread::spawn(move || {
        for _ in 0..request_count {
            let accepted = listener.accept();
            let (mut stream, _) = match accepted {
                Ok(value) => value,
                Err(_) => break,
            };
            let request = read_full_http_request(&mut stream);
            let body = extract_http_body(&request);
            let max_tokens = serde_json::from_str::<Value>(body)
                .ok()
                .and_then(|json| json.get("max_tokens").and_then(Value::as_u64))
                .unwrap_or(64);
            let computed_delay_ms = base_delay_ms.saturating_add(max_tokens / divisor);
            if computed_delay_ms > 0 {
                thread::sleep(Duration::from_millis(computed_delay_ms));
            }
            let response_body = json!({
                "id": "chatcmpl-bench",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": format!("bench-ok delay_ms={computed_delay_ms}")},
                    "finish_reason": "stop"
                }],
                "usage": {"total_tokens": max_tokens}
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    Ok((endpoint, handle))
}

fn spawn_verifier_server(
    request_count: usize,
    delay_ms: u64,
) -> Result<(String, thread::JoinHandle<()>), String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    let endpoint = format!("http://127.0.0.1:{}/attest/verify", address.port());
    let handle = thread::spawn(move || {
        for _ in 0..request_count {
            let accepted = listener.accept();
            let (mut stream, _) = match accepted {
                Ok(value) => value,
                Err(_) => break,
            };
            let request = read_full_http_request(&mut stream);
            let payload = serde_json::from_str::<Value>(extract_http_body(&request)).ok();
            let provider = payload
                .as_ref()
                .and_then(|json| {
                    json.get("evidence")
                        .and_then(|evidence| evidence.get("provider"))
                        .and_then(Value::as_str)
                })
                .unwrap_or("bench-provider");
            let measurement = payload
                .as_ref()
                .and_then(|json| {
                    json.get("evidence")
                        .and_then(|evidence| evidence.get("measurement"))
                        .and_then(Value::as_str)
                })
                .unwrap_or("sha256:bench-default");
            let issued = payload
                .as_ref()
                .and_then(|json| {
                    json.get("evidence")
                        .and_then(|evidence| evidence.get("issued_at_unix_ms"))
                        .and_then(Value::as_u64)
                })
                .unwrap_or_else(unix_time_ms_now);
            let expires = payload
                .as_ref()
                .and_then(|json| {
                    json.get("evidence")
                        .and_then(|evidence| evidence.get("expires_at_unix_ms"))
                        .and_then(Value::as_u64)
                })
                .unwrap_or_else(|| issued.saturating_add(60_000));

            if delay_ms > 0 {
                thread::sleep(Duration::from_millis(delay_ms));
            }

            let response_body = json!({
                "verified": true,
                "provider": provider,
                "measurement": measurement,
                "cpu_confidential": true,
                "gpu_confidential": true,
                "issued_at_unix_ms": issued,
                "expires_at_unix_ms": expires,
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    Ok((endpoint, handle))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn parse_content_length(headers: &str) -> usize {
    for line in headers.lines() {
        let trimmed = line.trim();
        if trimmed.to_ascii_lowercase().starts_with("content-length:")
            && let Some((_, value)) = trimmed.split_once(':')
        {
            return value.trim().parse::<usize>().unwrap_or(0);
        }
    }
    0
}

fn read_full_http_request(stream: &mut impl Read) -> String {
    let mut buffer = Vec::<u8>::new();
    let mut chunk = [0u8; 1024];
    let mut expected_total_len = None;
    loop {
        let read = stream.read(&mut chunk).unwrap_or(0);
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if expected_total_len.is_none()
            && let Some(position) = find_bytes(&buffer, b"\r\n\r\n")
        {
            let end = position + 4;
            let headers = String::from_utf8_lossy(&buffer[..end]).to_string();
            let content_length = parse_content_length(&headers);
            expected_total_len = Some(end + content_length);
        }
        if let Some(expected_total_len) = expected_total_len
            && buffer.len() >= expected_total_len
        {
            break;
        }
    }
    String::from_utf8_lossy(&buffer).to_string()
}

fn extract_http_body(request: &str) -> &str {
    match request.split_once("\r\n\r\n") {
        Some((_, body)) => body,
        None => "",
    }
}

fn average_u64(values: &[u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let sum = values.iter().copied().sum::<u64>();
    sum / u64::try_from(values.len()).unwrap_or(1)
}

fn percentile_u64(values: &[u64], percentile: usize) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let index = sorted.len().saturating_sub(1).saturating_mul(percentile) / 100;
    sorted[index]
}

fn percent_overhead(candidate_ms: u64, baseline_ms: u64) -> u64 {
    if baseline_ms == 0 {
        return 0;
    }
    let delta = candidate_ms.saturating_sub(baseline_ms);
    delta.saturating_mul(100) / baseline_ms
}

fn evaluate_decision(workloads: &[WorkloadResult]) -> DecisionSummary {
    let mut reasons = Vec::<String>::new();
    let mut passed = true;
    for workload in workloads {
        if !workload.threshold_passed {
            passed = false;
            reasons.push(format!(
                "{} overhead {}% exceeded threshold {}%",
                workload.name, workload.overhead_percent, workload.threshold_percent
            ));
        }
    }
    let small = workloads.iter().find(|workload| workload.name == "small");
    let large = workloads.iter().find(|workload| workload.name == "large");
    if let (Some(small), Some(large)) = (small, large) {
        if large.overhead_percent > small.overhead_percent {
            passed = false;
            reasons.push(format!(
                "large workload overhead {}% should not exceed small workload overhead {}%",
                large.overhead_percent, small.overhead_percent
            ));
        }
    }
    if reasons.is_empty() {
        reasons.push("all confidential overhead thresholds passed".to_string());
    }
    DecisionSummary { passed, reasons }
}

fn render_report_json(
    generated_at_unix_ms: u64,
    args: BenchmarkArgs,
    workloads: &[WorkloadResult],
    decision: &DecisionSummary,
    localhost_http_enabled: bool,
) -> String {
    let workload_json = workloads
        .iter()
        .map(|workload| {
            json!({
                "name": workload.name,
                "max_tokens": workload.max_tokens,
                "sample_count": workload.sample_count,
                "routed": {
                    "avg_ms": workload.routed_avg_ms,
                    "p95_ms": workload.routed_p95_ms,
                },
                "confidential": {
                    "avg_ms": workload.confidential_avg_ms,
                    "p95_ms": workload.confidential_p95_ms,
                    "verify_avg_ms": workload.verify_avg_ms,
                    "verify_p95_ms": workload.verify_p95_ms,
                    "relay_avg_ms": workload.relay_avg_ms,
                    "relay_p95_ms": workload.relay_p95_ms,
                    "total_path_avg_ms": workload.total_path_avg_ms,
                    "total_path_p95_ms": workload.total_path_p95_ms,
                },
                "overhead": {
                    "avg_ms": workload.overhead_avg_ms,
                    "percent": workload.overhead_percent,
                    "max_allowed_percent": workload.threshold_percent,
                    "threshold_passed": workload.threshold_passed,
                }
            })
        })
        .collect::<Vec<_>>();
    json!({
        "benchmark": "phase4_confidential_relay_gate",
        "generated_at_unix_ms": generated_at_unix_ms,
        "iterations": args.iterations,
        "profile": {
            "chat_base_delay_ms": args.chat_base_delay_ms,
            "chat_tokens_per_ms_divisor": args.chat_tokens_per_ms_divisor,
            "verifier_delay_ms": args.verifier_delay_ms,
            "localhost_http_override_env": INSECURE_LOCALHOST_HTTP_ENV,
            "localhost_http_override_enabled": localhost_http_enabled,
        },
        "workloads": workload_json,
        "decision": {
            "passed": decision.passed,
            "reasons": decision.reasons,
        }
    })
    .to_string()
}
