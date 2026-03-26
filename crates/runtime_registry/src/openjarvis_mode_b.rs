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
pub struct OpenJarvisModeBValidationError {
    message: String,
}

impl OpenJarvisModeBValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for OpenJarvisModeBValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for OpenJarvisModeBValidationError {}

impl From<OpenJarvisModeBValidationError> for String {
    fn from(value: OpenJarvisModeBValidationError) -> Self {
        value.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenJarvisBridgeModeBConfig {
    pub host: String,
    pub port: u16,
    pub task_path: String,
    pub health_path: String,
    pub default_model: String,
}

impl Default for OpenJarvisBridgeModeBConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8100,
            task_path: "/forge/bridge/v1/task".to_string(),
            health_path: "/healthz".to_string(),
            default_model: "qwen3:8b-instruct".to_string(),
        }
    }
}

impl OpenJarvisBridgeModeBConfig {
    pub fn validate(&self) -> Result<(), OpenJarvisModeBValidationError> {
        if self.host.trim().is_empty() {
            return Err(OpenJarvisModeBValidationError::new(
                "openjarvis mode b host cannot be empty",
            ));
        }
        if self.port == 0 {
            return Err(OpenJarvisModeBValidationError::new(
                "openjarvis mode b port must be greater than zero",
            ));
        }
        if self.default_model.trim().is_empty() {
            return Err(OpenJarvisModeBValidationError::new(
                "openjarvis mode b default_model cannot be empty",
            ));
        }
        if self.task_path.trim().is_empty() {
            return Err(OpenJarvisModeBValidationError::new(
                "openjarvis mode b task_path cannot be empty",
            ));
        }
        if self.health_path.trim().is_empty() {
            return Err(OpenJarvisModeBValidationError::new(
                "openjarvis mode b health_path cannot be empty",
            ));
        }
        Ok(())
    }

    pub fn normalized_task_path(&self) -> String {
        normalize_path(&self.task_path)
    }

    pub fn normalized_health_path(&self) -> String {
        normalize_path(&self.health_path)
    }

    pub fn endpoint_base(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }

    pub fn task_endpoint(&self) -> String {
        format!("{}{}", self.endpoint_base(), self.normalized_task_path())
    }

    pub fn health_endpoint(&self) -> String {
        format!("{}{}", self.endpoint_base(), self.normalized_health_path())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenJarvisBridgeTaskKind {
    Chat,
    Plan,
    Code,
    Debug,
    Verify,
}

impl OpenJarvisBridgeTaskKind {
    fn as_str(self) -> &'static str {
        match self {
            OpenJarvisBridgeTaskKind::Chat => "chat",
            OpenJarvisBridgeTaskKind::Plan => "plan",
            OpenJarvisBridgeTaskKind::Code => "code",
            OpenJarvisBridgeTaskKind::Debug => "debug",
            OpenJarvisBridgeTaskKind::Verify => "verify",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenJarvisBridgeModeBTaskRequest {
    pub request_id: String,
    pub kind: OpenJarvisBridgeTaskKind,
    pub prompt: String,
    pub max_tokens: u32,
    pub model: Option<String>,
}

impl OpenJarvisBridgeModeBTaskRequest {
    pub fn validate(&self) -> Result<(), OpenJarvisModeBValidationError> {
        if self.request_id.trim().is_empty() {
            return Err(OpenJarvisModeBValidationError::new(
                "openjarvis mode b request_id cannot be empty",
            ));
        }
        if self.prompt.trim().is_empty() {
            return Err(OpenJarvisModeBValidationError::new(
                "openjarvis mode b prompt cannot be empty",
            ));
        }
        if self.max_tokens == 0 {
            return Err(OpenJarvisModeBValidationError::new(
                "openjarvis mode b max_tokens must be greater than zero",
            ));
        }
        Ok(())
    }

    fn resolve_model(&self, config: &OpenJarvisBridgeModeBConfig) -> String {
        self.model
            .as_ref()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| config.default_model.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenJarvisBridgeModeBTaskResponse {
    pub request_id: String,
    pub status: String,
    pub output_text: String,
    pub tokens_used: Option<u32>,
    pub endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenJarvisBridgeModeBHealthStatus {
    pub healthy: bool,
    pub detail: String,
}

pub fn default_openjarvis_mode_b_runtime() -> RuntimeEntry {
    let config = OpenJarvisBridgeModeBConfig::default();
    RuntimeEntry {
        id: "openjarvis-mode-b".to_string(),
        display_name: "OpenJarvis (Mode B Sidecar)".to_string(),
        runtime_type: RuntimeType::OpenJarvisManaged,
        binary_or_endpoint: config.task_endpoint(),
        version: "mode-b-foundation".to_string(),
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

pub fn probe_openjarvis_mode_b_health(
    config: &OpenJarvisBridgeModeBConfig,
) -> Result<OpenJarvisBridgeModeBHealthStatus, String> {
    probe_openjarvis_mode_b_health_with_timeout(config, Duration::from_secs(2))
}

fn probe_openjarvis_mode_b_health_with_timeout(
    config: &OpenJarvisBridgeModeBConfig,
    timeout: Duration,
) -> Result<OpenJarvisBridgeModeBHealthStatus, String> {
    config.validate()?;
    let endpoint = format!("{}:{}", config.host, config.port);
    let address = resolve_socket_address(&endpoint)?;
    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| format!("openjarvis mode b health connect failed: {error}"))?;

    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {endpoint}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        config.normalized_health_path()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("openjarvis mode b health write failed: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("openjarvis mode b health flush failed: {error}"))?;

    let response = read_http_response(stream)?;
    let parsed = parse_http_json_response(&response)?;
    let detail = parsed
        .body_json
        .get("status")
        .and_then(Value::as_str)
        .or_else(|| parsed.body_json.get("detail").and_then(Value::as_str))
        .unwrap_or("ok")
        .to_string();

    Ok(OpenJarvisBridgeModeBHealthStatus {
        healthy: true,
        detail,
    })
}

pub fn run_openjarvis_mode_b_task(
    config: &OpenJarvisBridgeModeBConfig,
    request: &OpenJarvisBridgeModeBTaskRequest,
) -> Result<OpenJarvisBridgeModeBTaskResponse, String> {
    run_openjarvis_mode_b_task_with_timeout(config, request, Duration::from_secs(25))
}

fn run_openjarvis_mode_b_task_with_timeout(
    config: &OpenJarvisBridgeModeBConfig,
    request: &OpenJarvisBridgeModeBTaskRequest,
    timeout: Duration,
) -> Result<OpenJarvisBridgeModeBTaskResponse, String> {
    config.validate()?;
    request.validate()?;

    let endpoint = format!("{}:{}", config.host, config.port);
    let address = resolve_socket_address(&endpoint)?;
    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| format!("openjarvis mode b connect failed: {error}"))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let payload = serde_json::json!({
        "request_id": request.request_id.trim(),
        "task": {
            "kind": request.kind.as_str(),
            "prompt": request.prompt.trim(),
            "max_tokens": request.max_tokens,
            "model": request.resolve_model(config),
        }
    });
    let body = serde_json::to_string(&payload)
        .map_err(|error| format!("openjarvis mode b request serialization failed: {error}"))?;
    let request_path = config.normalized_task_path();
    let http_request = format!(
        "POST {request_path} HTTP/1.1\r\nHost: {endpoint}\r\nContent-Type: application/json\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(http_request.as_bytes())
        .map_err(|error| format!("openjarvis mode b write failed: {error}"))?;
    stream
        .flush()
        .map_err(|error| format!("openjarvis mode b flush failed: {error}"))?;

    let response = read_http_response(stream)?;
    let parsed = parse_http_json_response(&response)?;
    let request_id = parsed
        .body_json
        .get("request_id")
        .and_then(Value::as_str)
        .or_else(|| parsed.body_json.get("id").and_then(Value::as_str))
        .unwrap_or(request.request_id.trim())
        .to_string();
    let status = parsed
        .body_json
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("ok")
        .to_string();
    let output_text = parsed
        .body_json
        .get("result")
        .and_then(|result| result.get("text"))
        .and_then(Value::as_str)
        .or_else(|| parsed.body_json.get("output").and_then(Value::as_str))
        .or_else(|| parsed.body_json.get("text").and_then(Value::as_str))
        .ok_or_else(|| "openjarvis mode b response missing output text".to_string())?
        .to_string();
    let tokens_used = parsed
        .body_json
        .get("result")
        .and_then(|result| result.get("tokens_used"))
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());

    Ok(OpenJarvisBridgeModeBTaskResponse {
        request_id,
        status,
        output_text,
        tokens_used,
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
        "/".to_string()
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
        .map_err(|error| format!("openjarvis mode b read failed: {error}"))?;
    if buffer.trim().is_empty() {
        return Err("openjarvis mode b returned empty response".to_string());
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
            "openjarvis mode b non-success status: {status_line}"
        ));
    }
    let body_json = serde_json::from_str::<Value>(body.trim())
        .map_err(|error| format!("openjarvis mode b response JSON parse failed: {error}"))?;
    Ok(ParsedHttpJsonResponse { body_json })
}

#[cfg(test)]
mod tests {
    use super::{
        OpenJarvisBridgeModeBConfig, OpenJarvisBridgeModeBTaskRequest, OpenJarvisBridgeTaskKind,
        default_openjarvis_mode_b_runtime, probe_openjarvis_mode_b_health_with_timeout,
        run_openjarvis_mode_b_task_with_timeout,
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
    fn default_mode_b_runtime_entry_points_to_sidecar_task_endpoint() {
        let runtime = default_openjarvis_mode_b_runtime();
        assert_eq!(runtime.id, "openjarvis-mode-b");
        assert!(runtime.binary_or_endpoint.contains("/forge/bridge/v1/task"));
    }

    #[test]
    fn mode_b_request_validation_rejects_empty_prompt() {
        let request = OpenJarvisBridgeModeBTaskRequest {
            request_id: "req-1".to_string(),
            kind: OpenJarvisBridgeTaskKind::Plan,
            prompt: " ".to_string(),
            max_tokens: 64,
            model: None,
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn mode_b_health_probe_reads_status() {
        let body = r#"{"status":"ok-sidecar"}"#;
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

        let config = OpenJarvisBridgeModeBConfig {
            port,
            ..OpenJarvisBridgeModeBConfig::default()
        };
        let status = probe_openjarvis_mode_b_health_with_timeout(&config, Duration::from_secs(2));
        assert!(status.is_ok());
        let status = match status {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(status.healthy);
        assert_eq!(status.detail, "ok-sidecar");
    }

    #[test]
    fn mode_b_task_parses_typed_response() {
        let body = r#"{"request_id":"req-1","status":"ok","result":{"text":"typed sidecar response","tokens_used":33}}"#;
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
        let config = OpenJarvisBridgeModeBConfig {
            port,
            ..OpenJarvisBridgeModeBConfig::default()
        };
        let request = OpenJarvisBridgeModeBTaskRequest {
            request_id: "req-1".to_string(),
            kind: OpenJarvisBridgeTaskKind::Code,
            prompt: "write a rust fn".to_string(),
            max_tokens: 128,
            model: None,
        };
        let task_result =
            run_openjarvis_mode_b_task_with_timeout(&config, &request, Duration::from_secs(2));
        assert!(task_result.is_ok());
        let task_result = match task_result {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(task_result.request_id, "req-1");
        assert_eq!(task_result.status, "ok");
        assert_eq!(task_result.output_text, "typed sidecar response");
        assert_eq!(task_result.tokens_used, Some(33));
        assert!(task_result.endpoint.ends_with(&format!(":{port}")));
    }
}
