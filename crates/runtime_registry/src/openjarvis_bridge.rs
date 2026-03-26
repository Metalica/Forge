use crate::health::{
    RuntimeBackend, RuntimeBenchmarkRecord, RuntimeEntry, RuntimeHealth, RuntimeRollbackRecord,
    RuntimeType,
};
use serde_json::Value;
use std::error::Error;
use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenJarvisModeAValidationError {
    message: String,
}

impl OpenJarvisModeAValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for OpenJarvisModeAValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for OpenJarvisModeAValidationError {}

impl From<OpenJarvisModeAValidationError> for String {
    fn from(value: OpenJarvisModeAValidationError) -> Self {
        value.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenJarvisBridgeModeAConfig {
    pub host: String,
    pub port: u16,
    pub api_base_path: String,
    pub default_model: String,
}

impl Default for OpenJarvisBridgeModeAConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8000,
            api_base_path: "/v1".to_string(),
            default_model: "qwen3:8b".to_string(),
        }
    }
}

impl OpenJarvisBridgeModeAConfig {
    pub fn validate(&self) -> Result<(), OpenJarvisModeAValidationError> {
        if self.host.trim().is_empty() {
            return Err(OpenJarvisModeAValidationError::new(
                "openjarvis host cannot be empty",
            ));
        }
        if self.port == 0 {
            return Err(OpenJarvisModeAValidationError::new(
                "openjarvis port must be greater than zero",
            ));
        }
        if self.default_model.trim().is_empty() {
            return Err(OpenJarvisModeAValidationError::new(
                "openjarvis model cannot be empty",
            ));
        }
        if self.api_base_path.trim().is_empty() {
            return Err(OpenJarvisModeAValidationError::new(
                "openjarvis api_base_path cannot be empty",
            ));
        }
        Ok(())
    }

    pub fn normalized_base_path(&self) -> String {
        normalize_path(&self.api_base_path)
    }

    pub fn base_url(&self) -> String {
        format!(
            "http://{}:{}{}",
            self.host,
            self.port,
            self.normalized_base_path()
        )
    }

    pub fn health_endpoint(&self) -> String {
        format!("http://{}:{}/health", self.host, self.port)
    }

    pub fn models_endpoint(&self) -> String {
        format!("{}/models", self.base_url())
    }

    pub fn chat_completions_endpoint(&self) -> String {
        format!("{}/chat/completions", self.base_url())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenJarvisChatCompletionRequest {
    pub prompt: String,
    pub max_tokens: u32,
    pub model: Option<String>,
}

impl OpenJarvisChatCompletionRequest {
    pub fn validate(&self) -> Result<(), OpenJarvisModeAValidationError> {
        if self.prompt.trim().is_empty() {
            return Err(OpenJarvisModeAValidationError::new(
                "openjarvis prompt cannot be empty",
            ));
        }
        if self.max_tokens == 0 {
            return Err(OpenJarvisModeAValidationError::new(
                "openjarvis max_tokens must be greater than zero",
            ));
        }
        Ok(())
    }

    fn resolve_model(&self, config: &OpenJarvisBridgeModeAConfig) -> String {
        self.model
            .as_ref()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| config.default_model.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenJarvisChatCompletionResponse {
    pub text: String,
    pub finish_reason: Option<String>,
    pub endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenJarvisHealthStatus {
    pub healthy: bool,
    pub detail: String,
}

pub fn default_openjarvis_mode_a_runtime() -> RuntimeEntry {
    let config = OpenJarvisBridgeModeAConfig::default();
    RuntimeEntry {
        id: "openjarvis-mode-a".to_string(),
        display_name: "OpenJarvis (Mode A)".to_string(),
        runtime_type: RuntimeType::OpenJarvisManaged,
        binary_or_endpoint: config.chat_completions_endpoint(),
        version: "mode-a-foundation".to_string(),
        backend: RuntimeBackend::RemoteApi,
        health: RuntimeHealth::Unknown,
        pinned_version: false,
        default_local_runtime: false,
        last_benchmark_ms: None,
        rollback_version: None,
        benchmark_history: Vec::<RuntimeBenchmarkRecord>::new(),
        rollback_history: Vec::<RuntimeRollbackRecord>::new(),
        updated_at: SystemTime::now(),
    }
}

pub fn probe_openjarvis_mode_a_health(
    config: &OpenJarvisBridgeModeAConfig,
) -> Result<OpenJarvisHealthStatus, String> {
    probe_openjarvis_mode_a_health_with_timeout(config, Duration::from_secs(2))
}

fn probe_openjarvis_mode_a_health_with_timeout(
    config: &OpenJarvisBridgeModeAConfig,
    timeout: Duration,
) -> Result<OpenJarvisHealthStatus, String> {
    config.validate()?;
    let endpoint = format!("{}:{}", config.host, config.port);
    let address = resolve_socket_address(&endpoint)?;

    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| format!("openjarvis health connect failed: {error}"))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let request = format!(
        "GET /health HTTP/1.1\r\nHost: {endpoint}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("openjarvis health write failed: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("openjarvis health flush failed: {error}"))?;

    let response = read_http_response(stream)?;
    let parsed = parse_http_json_response(&response)?;

    let detail = parsed
        .body_json
        .get("status")
        .and_then(Value::as_str)
        .or_else(|| parsed.body_json.get("detail").and_then(Value::as_str))
        .unwrap_or("ok")
        .to_string();

    Ok(OpenJarvisHealthStatus {
        healthy: true,
        detail,
    })
}

pub fn run_openjarvis_mode_a_chat_completion(
    config: &OpenJarvisBridgeModeAConfig,
    request: &OpenJarvisChatCompletionRequest,
) -> Result<OpenJarvisChatCompletionResponse, String> {
    run_openjarvis_mode_a_chat_completion_with_timeout(config, request, Duration::from_secs(20))
}

fn run_openjarvis_mode_a_chat_completion_with_timeout(
    config: &OpenJarvisBridgeModeAConfig,
    request: &OpenJarvisChatCompletionRequest,
    timeout: Duration,
) -> Result<OpenJarvisChatCompletionResponse, String> {
    config.validate()?;
    request.validate()?;

    let endpoint = format!("{}:{}", config.host, config.port);
    let address = resolve_socket_address(&endpoint)?;
    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| format!("openjarvis bridge connect failed: {error}"))?;

    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let request_path = format!("{}/chat/completions", config.normalized_base_path());
    let payload = serde_json::json!({
        "model": request.resolve_model(config),
        "messages": [{
            "role": "user",
            "content": request.prompt.trim(),
        }],
        "max_tokens": request.max_tokens,
        "stream": false,
    });
    let body = serde_json::to_string(&payload)
        .map_err(|error| format!("openjarvis request serialization failed: {error}"))?;

    let http_request = format!(
        "POST {request_path} HTTP/1.1\r\nHost: {endpoint}\r\nContent-Type: application/json\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );

    stream
        .write_all(http_request.as_bytes())
        .map_err(|error| format!("openjarvis bridge write failed: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("openjarvis bridge flush failed: {error}"))?;

    let response = read_http_response(stream)?;
    let parsed = parse_http_json_response(&response)?;

    let choice = parsed
        .body_json
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .ok_or_else(|| "openjarvis response missing choices[0]".to_string())?;

    let text = choice
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .or_else(|| choice.get("text").and_then(Value::as_str))
        .ok_or_else(|| "openjarvis response missing choices[0].message.content".to_string())?
        .to_string();

    let finish_reason = choice
        .get("finish_reason")
        .and_then(Value::as_str)
        .map(|value| value.to_string());

    Ok(OpenJarvisChatCompletionResponse {
        text,
        finish_reason,
        endpoint,
    })
}

fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    let mut normalized = if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    };
    while normalized.ends_with('/') {
        normalized.pop();
    }
    if normalized.is_empty() {
        "/v1".to_string()
    } else {
        normalized
    }
}

fn resolve_socket_address(endpoint: &str) -> Result<std::net::SocketAddr, String> {
    endpoint
        .to_socket_addrs()
        .map_err(|error| format!("failed resolving {endpoint}: {error}"))?
        .next()
        .ok_or_else(|| format!("no socket addresses resolved for {endpoint}"))
}

fn read_http_response(mut stream: TcpStream) -> Result<String, String> {
    let mut buffer = String::new();
    stream
        .read_to_string(&mut buffer)
        .map_err(|error| format!("openjarvis bridge read failed: {error}"))?;
    if buffer.trim().is_empty() {
        return Err("openjarvis bridge returned empty response".to_string());
    }
    Ok(buffer)
}

struct ParsedHttpJsonResponse {
    body_json: Value,
}

fn parse_http_json_response(raw: &str) -> Result<ParsedHttpJsonResponse, String> {
    let (headers, body) = raw
        .split_once("\r\n\r\n")
        .ok_or_else(|| "invalid HTTP response (missing headers/body separator)".to_string())?;

    let mut header_lines = headers.lines();
    let status_line = header_lines
        .next()
        .ok_or_else(|| "invalid HTTP response (missing status line)".to_string())?;
    if !status_line.starts_with("HTTP/1.1 200") && !status_line.starts_with("HTTP/1.0 200") {
        return Err(format!(
            "openjarvis bridge non-success status: {status_line}"
        ));
    }

    let header_pairs = header_lines
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| {
            (
                key.trim().to_ascii_lowercase(),
                value.trim().to_ascii_lowercase(),
            )
        })
        .collect::<Vec<_>>();

    let decoded_body = if header_pairs
        .iter()
        .any(|(key, value)| key == "transfer-encoding" && value.contains("chunked"))
    {
        decode_chunked_body(body)?
    } else {
        body.to_string()
    };

    let body_json = serde_json::from_str::<Value>(decoded_body.trim())
        .map_err(|error| format!("openjarvis response JSON parse failed: {error}"))?;

    Ok(ParsedHttpJsonResponse { body_json })
}

fn decode_chunked_body(body: &str) -> Result<String, String> {
    let mut remaining = body;
    let mut decoded = String::new();

    loop {
        let size_end = remaining.find("\r\n").ok_or_else(|| {
            "invalid chunked openjarvis response: missing chunk size terminator".to_string()
        })?;
        let size_hex = remaining[..size_end].trim();
        let chunk_size = u64::from_str_radix(size_hex, 16)
            .map_err(|_| "invalid chunked openjarvis response: invalid chunk size".to_string())?;
        remaining = &remaining[(size_end + 2)..];

        if chunk_size == 0 {
            break;
        }

        let chunk_size_usize = chunk_size as usize;
        if remaining.len() < chunk_size_usize {
            return Err("invalid chunked openjarvis response: truncated payload".to_string());
        }

        decoded.push_str(&remaining[..chunk_size_usize]);
        remaining = &remaining[chunk_size_usize..];

        if !remaining.starts_with("\r\n") {
            return Err(
                "invalid chunked openjarvis response: missing chunk terminator".to_string(),
            );
        }
        remaining = &remaining[2..];
    }

    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::{
        OpenJarvisBridgeModeAConfig, OpenJarvisChatCompletionRequest,
        default_openjarvis_mode_a_runtime, probe_openjarvis_mode_a_health_with_timeout,
        run_openjarvis_mode_a_chat_completion_with_timeout,
    };
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    fn spawn_mock_server(response: String) -> Option<u16> {
        let listener = TcpListener::bind("127.0.0.1:0").ok()?;
        let port = listener.local_addr().ok()?.port();

        thread::spawn(move || {
            let accepted = listener.accept();
            let (mut stream, _) = match accepted {
                Ok(value) => value,
                Err(_) => return,
            };
            let mut request_buffer = [0u8; 4096];
            let _ = stream.read(&mut request_buffer);
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        });

        Some(port)
    }

    #[test]
    fn mode_a_config_normalizes_paths() {
        let config = OpenJarvisBridgeModeAConfig {
            api_base_path: "v1/".to_string(),
            ..OpenJarvisBridgeModeAConfig::default()
        };
        assert_eq!(config.normalized_base_path(), "/v1");
        assert!(
            config
                .chat_completions_endpoint()
                .ends_with("/v1/chat/completions")
        );
        assert!(config.models_endpoint().ends_with("/v1/models"));
        assert!(config.health_endpoint().ends_with("/health"));
    }

    #[test]
    fn default_mode_a_runtime_entry_points_to_localhost_bridge() {
        let runtime = default_openjarvis_mode_a_runtime();
        assert_eq!(runtime.id, "openjarvis-mode-a");
        assert!(runtime.binary_or_endpoint.contains("/v1/chat/completions"));
    }

    #[test]
    fn chat_completion_request_validation_rejects_empty_prompt() {
        let request = OpenJarvisChatCompletionRequest {
            prompt: "   ".to_string(),
            max_tokens: 64,
            model: None,
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn health_probe_parses_ok_response() {
        let body = r#"{"status":"ok"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let port = spawn_mock_server(response);
        assert!(port.is_some());
        let port = match port {
            Some(value) => value,
            None => return,
        };

        let config = OpenJarvisBridgeModeAConfig {
            port,
            ..OpenJarvisBridgeModeAConfig::default()
        };
        let status = probe_openjarvis_mode_a_health_with_timeout(&config, Duration::from_secs(2));
        assert!(status.is_ok());
        let status = match status {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(status.healthy);
        assert_eq!(status.detail, "ok");
    }

    #[test]
    fn chat_completion_parses_openai_compatible_response() {
        let body = r#"{"id":"cmpl-1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"hello from openjarvis"},"finish_reason":"stop"}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let port = spawn_mock_server(response);
        assert!(port.is_some());
        let port = match port {
            Some(value) => value,
            None => return,
        };

        let config = OpenJarvisBridgeModeAConfig {
            port,
            ..OpenJarvisBridgeModeAConfig::default()
        };
        let request = OpenJarvisChatCompletionRequest {
            prompt: "say hi".to_string(),
            max_tokens: 64,
            model: None,
        };
        let completion = run_openjarvis_mode_a_chat_completion_with_timeout(
            &config,
            &request,
            Duration::from_secs(2),
        );
        assert!(completion.is_ok());
        let completion = match completion {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(completion.text, "hello from openjarvis");
        assert_eq!(completion.finish_reason.as_deref(), Some("stop"));
        assert!(completion.endpoint.ends_with(&format!(":{port}")));
    }
}
