use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt::Write as _;
use std::{
    env, fmt, fs,
    io::Read,
    path::Path,
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

const STORE_SCHEMA_VERSION: u32 = 1;
const SESSION_HISTORY_LIMIT: usize = 256;
const DEFAULT_VERIFIER_TIMEOUT_MS: u64 = 5_000;
const INSECURE_LOCALHOST_HTTP_ENV: &str = "CONFIDENTIAL_ALLOW_INSECURE_LOCALHOST_HTTP";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfidentialRelayValidationError {
    message: String,
}

impl ConfidentialRelayValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfidentialRelayValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ConfidentialRelayValidationError {}

impl From<ConfidentialRelayValidationError> for String {
    fn from(value: ConfidentialRelayValidationError) -> Self {
        value.to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ConfidentialRelayMode {
    #[default]
    Disabled,
    Enabled,
    Required,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialRelayPolicy {
    pub mode: ConfidentialRelayMode,
    pub require_confidential_cpu: bool,
    pub require_confidential_gpu: bool,
    pub max_attestation_age_ms: u64,
}

impl Default for ConfidentialRelayPolicy {
    fn default() -> Self {
        Self {
            mode: ConfidentialRelayMode::Disabled,
            require_confidential_cpu: true,
            require_confidential_gpu: true,
            max_attestation_age_ms: 5 * 60 * 1000,
        }
    }
}

impl ConfidentialRelayPolicy {
    pub fn validate(&self) -> Result<(), ConfidentialRelayValidationError> {
        if self.max_attestation_age_ms == 0 {
            return Err(ConfidentialRelayValidationError::new(
                "confidential relay max_attestation_age_ms must be greater than zero",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationEvidence {
    pub provider: String,
    pub measurement: String,
    pub nonce: String,
    pub cpu_confidential: bool,
    pub gpu_confidential: bool,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub signature: String,
}

impl AttestationEvidence {
    pub fn validate(&self) -> Result<(), ConfidentialRelayValidationError> {
        if self.provider.trim().is_empty() {
            return Err(ConfidentialRelayValidationError::new(
                "attestation provider cannot be empty",
            ));
        }
        if self.measurement.trim().is_empty() {
            return Err(ConfidentialRelayValidationError::new(
                "attestation measurement cannot be empty",
            ));
        }
        if self.nonce.trim().is_empty() {
            return Err(ConfidentialRelayValidationError::new(
                "attestation nonce cannot be empty",
            ));
        }
        if self.signature.trim().is_empty() {
            return Err(ConfidentialRelayValidationError::new(
                "attestation signature cannot be empty",
            ));
        }
        if self.expires_at_unix_ms <= self.issued_at_unix_ms {
            return Err(ConfidentialRelayValidationError::new(
                "attestation expires_at_unix_ms must be greater than issued_at_unix_ms",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    pub provider: String,
    pub measurement: String,
    pub cpu_confidential: bool,
    pub gpu_confidential: bool,
    pub verified_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayEncryptionMode {
    TlsHttps,
    MtlsTunnel,
    EnclaveStreamV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AttestationVerifierBackend {
    #[default]
    HttpJsonV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationVerifierConfig {
    pub backend: AttestationVerifierBackend,
    pub endpoint: String,
    pub api_key_env_var: Option<String>,
    pub timeout_ms: u64,
}

impl Default for AttestationVerifierConfig {
    fn default() -> Self {
        Self {
            backend: AttestationVerifierBackend::HttpJsonV1,
            endpoint: String::new(),
            api_key_env_var: None,
            timeout_ms: DEFAULT_VERIFIER_TIMEOUT_MS,
        }
    }
}

impl AttestationVerifierConfig {
    pub fn validate(&self) -> Result<(), ConfidentialRelayValidationError> {
        let endpoint = self.endpoint.trim();
        if endpoint.is_empty() {
            return Err(ConfidentialRelayValidationError::new(
                "attestation verifier endpoint cannot be empty",
            ));
        }
        let localhost_http_allowed = allow_insecure_localhost_http_endpoint(endpoint);
        if !endpoint.starts_with("https://") && !localhost_http_allowed {
            return Err(ConfidentialRelayValidationError::new(
                "attestation verifier endpoint must be https (localhost http requires CONFIDENTIAL_ALLOW_INSECURE_LOCALHOST_HTTP=1)",
            ));
        }
        if self.timeout_ms == 0 {
            return Err(ConfidentialRelayValidationError::new(
                "attestation verifier timeout_ms must be greater than zero",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialEndpointMetadata {
    pub enabled: bool,
    pub expected_target_prefix: String,
    pub expected_attestation_provider: Option<String>,
    pub expected_measurement_prefixes: Vec<String>,
    pub attestation_verifier: AttestationVerifierConfig,
    pub encryption_mode: RelayEncryptionMode,
    #[serde(default = "default_declared_logging_policy")]
    pub declared_logging_policy: String,
}

pub fn default_declared_logging_policy() -> String {
    "provider_audit_redacted_export_only".to_string()
}

fn default_fallback_state() -> String {
    "unknown".to_string()
}

fn default_release_binding() -> String {
    String::new()
}

impl Default for ConfidentialEndpointMetadata {
    fn default() -> Self {
        Self {
            enabled: false,
            expected_target_prefix: String::new(),
            expected_attestation_provider: None,
            expected_measurement_prefixes: Vec::new(),
            attestation_verifier: AttestationVerifierConfig::default(),
            encryption_mode: RelayEncryptionMode::TlsHttps,
            declared_logging_policy: crate::confidential_relay::default_declared_logging_policy(),
        }
    }
}

impl ConfidentialEndpointMetadata {
    pub fn validate_for_source(
        &self,
        source_id: &str,
        source_target: &str,
    ) -> Result<(), ConfidentialRelayValidationError> {
        if !self.enabled {
            return Err(ConfidentialRelayValidationError::new(format!(
                "source {source_id} is not enabled for confidential relay endpoint routing"
            )));
        }
        let expected_target_prefix = self.expected_target_prefix.trim();
        if expected_target_prefix.is_empty() {
            return Err(ConfidentialRelayValidationError::new(format!(
                "source {source_id} confidential endpoint metadata is missing expected_target_prefix"
            )));
        }
        if !source_target.trim().starts_with(expected_target_prefix) {
            return Err(ConfidentialRelayValidationError::new(format!(
                "source {source_id} target `{}` does not match confidential expected prefix `{}`",
                source_target.trim(),
                expected_target_prefix
            )));
        }
        if self.declared_logging_policy.trim().is_empty() {
            return Err(ConfidentialRelayValidationError::new(format!(
                "source {source_id} confidential endpoint metadata is missing declared_logging_policy"
            )));
        }
        self.attestation_verifier.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialRelaySessionRecord {
    pub session_id: String,
    pub session_key_id: String,
    pub request_nonce: String,
    #[serde(default)]
    pub policy_identity: String,
    pub source_id: String,
    pub source_display_name: String,
    pub route: String,
    pub transport_encrypted: bool,
    pub verified_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub attestation_verify_ms: u64,
    pub relay_roundtrip_ms: u64,
    pub total_path_ms: u64,
    pub attestation_provider: String,
    pub measurement: String,
    pub cpu_confidential: bool,
    pub gpu_confidential: bool,
    pub encryption_mode: RelayEncryptionMode,
    #[serde(default = "default_declared_logging_policy")]
    pub declared_logging_policy: String,
    #[serde(default)]
    pub fallback_consent_required: bool,
    #[serde(default)]
    pub fallback_consent_granted: bool,
    #[serde(default)]
    pub fallback_consent_source: String,
    #[serde(default)]
    pub fallback_consent_captured_at_unix_ms: Option<u64>,
    #[serde(default = "default_fallback_state")]
    pub fallback_state: String,
    #[serde(default = "default_release_binding")]
    pub release_binding: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedConfidentialRelaySessionState {
    schema_version: u32,
    sessions: Vec<ConfidentialRelaySessionRecord>,
}

#[derive(Debug, Default, Clone)]
pub struct ConfidentialRelaySessionStore {
    sessions: Vec<ConfidentialRelaySessionRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfidentialRelayPathProfileSummary {
    pub sample_count: usize,
    pub attestation_verify_avg_ms: u64,
    pub attestation_verify_p95_ms: u64,
    pub relay_roundtrip_avg_ms: u64,
    pub relay_roundtrip_p95_ms: u64,
    pub total_path_avg_ms: u64,
    pub total_path_p95_ms: u64,
}

impl ConfidentialRelaySessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_session(&mut self, record: ConfidentialRelaySessionRecord) {
        self.sessions
            .retain(|existing| existing.session_id != record.session_id);
        self.sessions.insert(0, record);
        if self.sessions.len() > SESSION_HISTORY_LIMIT {
            self.sessions.truncate(SESSION_HISTORY_LIMIT);
        }
    }

    pub fn latest_session(&self) -> Option<&ConfidentialRelaySessionRecord> {
        self.sessions.first()
    }

    pub fn sessions(&self) -> &[ConfidentialRelaySessionRecord] {
        &self.sessions
    }

    pub fn clear(&mut self) -> usize {
        let cleared = self.sessions.len();
        self.sessions.clear();
        cleared
    }

    pub fn prune_expired(&mut self, now_unix_ms: u64) -> usize {
        let before = self.sessions.len();
        self.sessions
            .retain(|session| session.expires_at_unix_ms >= now_unix_ms);
        before.saturating_sub(self.sessions.len())
    }

    pub fn is_nonce_replay(&self, source_id: &str, nonce: &str, now_unix_ms: u64) -> bool {
        let nonce = nonce.trim();
        if nonce.is_empty() {
            return false;
        }
        self.sessions.iter().any(|session| {
            session.source_id == source_id
                && session.request_nonce.trim() == nonce
                && session.expires_at_unix_ms >= now_unix_ms
        })
    }

    pub fn profile_summary(
        &self,
        sample_limit: usize,
    ) -> Option<ConfidentialRelayPathProfileSummary> {
        let window = if sample_limit == 0 || sample_limit >= self.sessions.len() {
            &self.sessions[..]
        } else {
            &self.sessions[..sample_limit]
        };
        if window.is_empty() {
            return None;
        }

        let mut verify_values = window
            .iter()
            .map(|session| session.attestation_verify_ms)
            .collect::<Vec<_>>();
        let mut relay_values = window
            .iter()
            .map(|session| session.relay_roundtrip_ms)
            .collect::<Vec<_>>();
        let mut total_values = window
            .iter()
            .map(|session| session.total_path_ms)
            .collect::<Vec<_>>();
        verify_values.sort_unstable();
        relay_values.sort_unstable();
        total_values.sort_unstable();

        Some(ConfidentialRelayPathProfileSummary {
            sample_count: window.len(),
            attestation_verify_avg_ms: average_ms(&verify_values),
            attestation_verify_p95_ms: percentile_ms(&verify_values, 95),
            relay_roundtrip_avg_ms: average_ms(&relay_values),
            relay_roundtrip_p95_ms: percentile_ms(&relay_values, 95),
            total_path_avg_ms: average_ms(&total_values),
            total_path_p95_ms: percentile_ms(&total_values, 95),
        })
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), ConfidentialRelayValidationError> {
        let state = PersistedConfidentialRelaySessionState {
            schema_version: STORE_SCHEMA_VERSION,
            sessions: self.sessions.clone(),
        };
        let encoded = serde_json::to_string_pretty(&state).map_err(|error| {
            ConfidentialRelayValidationError::new(format!(
                "failed to serialize confidential relay sessions: {error}"
            ))
        })?;
        fs::write(path, encoded).map_err(|error| {
            ConfidentialRelayValidationError::new(format!(
                "failed to write confidential relay sessions at {}: {error}",
                path.display()
            ))
        })
    }

    pub fn load_from_path(path: &Path) -> Result<Self, String> {
        let contents = fs::read_to_string(path).map_err(|error| error.to_string())?;
        let state = serde_json::from_str::<PersistedConfidentialRelaySessionState>(&contents)
            .map_err(|error| error.to_string())?;
        if state.schema_version != STORE_SCHEMA_VERSION {
            return Err(format!(
                "unsupported confidential relay schema version: {}",
                state.schema_version
            ));
        }
        Ok(Self {
            sessions: state.sessions,
        })
    }
}

fn average_ms(values: &[u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let sum = values.iter().copied().sum::<u64>();
    sum / u64::try_from(values.len()).unwrap_or(1)
}

fn percentile_ms(values: &[u64], percentile: u8) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let idx = ((values.len() - 1) * usize::from(percentile)).div_ceil(100);
    values[idx]
}

pub fn verify_attestation(
    source_id: &str,
    source_target: &str,
    endpoint: &ConfidentialEndpointMetadata,
    evidence: &AttestationEvidence,
    policy: &ConfidentialRelayPolicy,
    now_unix_ms: u64,
) -> Result<VerifiedAttestation, String> {
    policy.validate()?;
    if matches!(policy.mode, ConfidentialRelayMode::Disabled) {
        return Err("confidential relay is disabled by policy".to_string());
    }

    endpoint.validate_for_source(source_id, source_target)?;
    evidence.validate()?;

    let backend_claims =
        verify_attestation_with_backend(source_id, source_target, endpoint, evidence, policy)?;
    if now_unix_ms < backend_claims.issued_at_unix_ms {
        return Err("attestation not yet valid (issued_at in the future)".to_string());
    }
    if now_unix_ms > backend_claims.expires_at_unix_ms {
        return Err("attestation expired".to_string());
    }
    let age_ms = now_unix_ms.saturating_sub(backend_claims.issued_at_unix_ms);
    if age_ms > policy.max_attestation_age_ms {
        return Err(format!(
            "attestation too old: age={}ms exceeds {}ms",
            age_ms, policy.max_attestation_age_ms
        ));
    }

    if policy.require_confidential_cpu && !backend_claims.cpu_confidential {
        return Err("attestation rejected: confidential CPU mode is required".to_string());
    }
    if policy.require_confidential_gpu && !backend_claims.gpu_confidential {
        return Err("attestation rejected: confidential GPU mode is required".to_string());
    }

    if let Some(expected_provider) = endpoint.expected_attestation_provider.as_ref() {
        let expected_provider = expected_provider.trim();
        if !expected_provider.is_empty() && backend_claims.provider != expected_provider {
            return Err(format!(
                "attestation provider mismatch: expected `{expected_provider}` got `{}`",
                backend_claims.provider
            ));
        }
    }
    if !endpoint.expected_measurement_prefixes.is_empty() {
        let matches_any_prefix = endpoint
            .expected_measurement_prefixes
            .iter()
            .map(|prefix| prefix.trim())
            .filter(|prefix| !prefix.is_empty())
            .any(|prefix| backend_claims.measurement.starts_with(prefix));
        if !matches_any_prefix {
            return Err(format!(
                "attestation measurement mismatch for source {source_id}: `{}` does not match configured prefixes",
                backend_claims.measurement
            ));
        }
    }

    Ok(VerifiedAttestation {
        provider: backend_claims.provider,
        measurement: backend_claims.measurement,
        cpu_confidential: backend_claims.cpu_confidential,
        gpu_confidential: backend_claims.gpu_confidential,
        verified_at_unix_ms: now_unix_ms,
        expires_at_unix_ms: backend_claims.expires_at_unix_ms,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BackendAttestationClaims {
    provider: String,
    measurement: String,
    cpu_confidential: bool,
    gpu_confidential: bool,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

fn verify_attestation_with_backend(
    source_id: &str,
    source_target: &str,
    endpoint: &ConfidentialEndpointMetadata,
    evidence: &AttestationEvidence,
    policy: &ConfidentialRelayPolicy,
) -> Result<BackendAttestationClaims, String> {
    match endpoint.attestation_verifier.backend {
        AttestationVerifierBackend::HttpJsonV1 => verify_attestation_with_http_json_v1(
            source_id,
            source_target,
            endpoint,
            evidence,
            policy,
        ),
    }
}

fn verify_attestation_with_http_json_v1(
    source_id: &str,
    source_target: &str,
    endpoint: &ConfidentialEndpointMetadata,
    evidence: &AttestationEvidence,
    policy: &ConfidentialRelayPolicy,
) -> Result<BackendAttestationClaims, String> {
    let verifier = &endpoint.attestation_verifier;
    let timeout = Duration::from_millis(verifier.timeout_ms.max(250));
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .timeout_write(timeout)
        .build();

    let mut request = agent
        .post(verifier.endpoint.trim())
        .set("Accept", "application/json")
        .set("Content-Type", "application/json");
    if let Some(api_key_env_var) = verifier.api_key_env_var.as_ref() {
        let key = env::var(api_key_env_var.trim()).map_err(|_| {
            format!(
                "attestation verifier requires env var `{}` but it is not set",
                api_key_env_var.trim()
            )
        })?;
        let key = key.trim();
        if key.is_empty() {
            return Err(format!(
                "attestation verifier env var `{}` is empty",
                api_key_env_var.trim()
            ));
        }
        request = request.set("Authorization", &format!("Bearer {key}"));
    }

    let payload = json!({
        "source": {
            "id": source_id,
            "target": source_target,
            "expected_target_prefix": endpoint.expected_target_prefix.trim(),
        },
        "policy": {
            "mode": policy.mode,
            "require_confidential_cpu": policy.require_confidential_cpu,
            "require_confidential_gpu": policy.require_confidential_gpu,
            "max_attestation_age_ms": policy.max_attestation_age_ms,
        },
        "evidence": {
            "provider": evidence.provider.trim(),
            "measurement": evidence.measurement.trim(),
            "nonce": evidence.nonce.trim(),
            "cpu_confidential": evidence.cpu_confidential,
            "gpu_confidential": evidence.gpu_confidential,
            "issued_at_unix_ms": evidence.issued_at_unix_ms,
            "expires_at_unix_ms": evidence.expires_at_unix_ms,
            "signature": evidence.signature.trim(),
        }
    });

    let response = match request.send_json(payload) {
        Ok(response) => response,
        Err(ureq::Error::Status(code, response)) => {
            let body = clip_text(read_response_body(response).trim(), 220);
            if body.is_empty() {
                return Err(format!(
                    "attestation verifier rejected request with status {code}"
                ));
            }
            return Err(format!(
                "attestation verifier rejected request with status {code}: {body}"
            ));
        }
        Err(error) => {
            return Err(format!("attestation verifier request failed: {error}"));
        }
    };

    let response_body = read_response_body(response);
    let parsed: Value = serde_json::from_str(&response_body)
        .map_err(|error| format!("attestation verifier returned invalid json: {error}"))?;
    let verified = parsed
        .get("verified")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !verified {
        let reason = parsed
            .get("reason")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|reason| !reason.is_empty())
            .unwrap_or("verifier returned verified=false");
        return Err(format!("attestation rejected by verifier: {reason}"));
    }

    let provider = parsed
        .get("provider")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| evidence.provider.trim())
        .to_string();
    let measurement = parsed
        .get("measurement")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| evidence.measurement.trim())
        .to_string();
    let cpu_confidential = parsed
        .get("cpu_confidential")
        .and_then(Value::as_bool)
        .unwrap_or(evidence.cpu_confidential);
    let gpu_confidential = parsed
        .get("gpu_confidential")
        .and_then(Value::as_bool)
        .unwrap_or(evidence.gpu_confidential);
    let issued_at_unix_ms = parsed
        .get("issued_at_unix_ms")
        .and_then(Value::as_u64)
        .unwrap_or(evidence.issued_at_unix_ms);
    let expires_at_unix_ms = parsed
        .get("expires_at_unix_ms")
        .and_then(Value::as_u64)
        .unwrap_or(evidence.expires_at_unix_ms);

    if provider.is_empty() {
        return Err("attestation verifier response is missing provider".to_string());
    }
    if measurement.is_empty() {
        return Err("attestation verifier response is missing measurement".to_string());
    }
    if expires_at_unix_ms <= issued_at_unix_ms {
        return Err("attestation verifier response has invalid validity window".to_string());
    }

    Ok(BackendAttestationClaims {
        provider,
        measurement,
        cpu_confidential,
        gpu_confidential,
        issued_at_unix_ms,
        expires_at_unix_ms,
    })
}

fn is_localhost_http_endpoint(endpoint: &str) -> bool {
    let trimmed = endpoint.trim();
    let without_scheme = match trimmed.strip_prefix("http://") {
        Some(value) => value,
        None => return false,
    };
    let authority = without_scheme.split('/').next().unwrap_or_default();
    let host = authority.split(':').next().unwrap_or_default().trim();
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

pub(crate) fn insecure_localhost_http_allowed() -> bool {
    if cfg!(test) {
        return true;
    }
    env::var(INSECURE_LOCALHOST_HTTP_ENV)
        .ok()
        .map(|value| value.trim() == "1")
        .unwrap_or(false)
}

pub(crate) fn allow_insecure_localhost_http_endpoint(endpoint: &str) -> bool {
    insecure_localhost_http_allowed() && is_localhost_http_endpoint(endpoint)
}

fn read_response_body(response: ureq::Response) -> String {
    let mut body = String::new();
    let mut reader = response.into_reader();
    let _ = reader.read_to_string(&mut body);
    body
}

fn clip_text(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    value.chars().take(max_chars).collect::<String>() + "..."
}

fn relay_mode_identity(mode: ConfidentialRelayMode) -> &'static str {
    match mode {
        ConfidentialRelayMode::Disabled => "disabled",
        ConfidentialRelayMode::Enabled => "enabled",
        ConfidentialRelayMode::Required => "required",
    }
}

fn relay_encryption_identity(mode: RelayEncryptionMode) -> &'static str {
    match mode {
        RelayEncryptionMode::TlsHttps => "tls_https",
        RelayEncryptionMode::MtlsTunnel => "mtls_tunnel",
        RelayEncryptionMode::EnclaveStreamV1 => "enclave_stream_v1",
    }
}

fn relay_attestation_backend_identity(backend: AttestationVerifierBackend) -> &'static str {
    match backend {
        AttestationVerifierBackend::HttpJsonV1 => "http_json_v1",
    }
}

fn fnv1a64_hex(input: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("fnv1a64:{hash:016x}")
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(7 + digest.len() * 2);
    out.push_str("sha256:");
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub fn build_confidential_policy_identity(
    source_id: &str,
    endpoint: &ConfidentialEndpointMetadata,
    policy: &ConfidentialRelayPolicy,
) -> String {
    let mut measurement_prefixes = endpoint
        .expected_measurement_prefixes
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    measurement_prefixes.sort();
    measurement_prefixes.dedup();
    let measurement_identity = if measurement_prefixes.is_empty() {
        "any".to_string()
    } else {
        measurement_prefixes.join("|")
    };
    let provider_identity = endpoint
        .expected_attestation_provider
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("any");
    let verifier_api_key_env = endpoint
        .attestation_verifier
        .api_key_env_var
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("none");
    let canonical = format!(
        "source={};target_prefix={};provider={};measurements={};verifier_backend={};verifier_endpoint={};verifier_timeout_ms={};verifier_api_key_env={};encryption={};logging_policy={};policy_mode={};policy_req_cpu={};policy_req_gpu={};policy_max_age_ms={}",
        source_id.trim(),
        endpoint.expected_target_prefix.trim(),
        provider_identity,
        measurement_identity,
        relay_attestation_backend_identity(endpoint.attestation_verifier.backend),
        endpoint.attestation_verifier.endpoint.trim(),
        endpoint.attestation_verifier.timeout_ms,
        verifier_api_key_env,
        relay_encryption_identity(endpoint.encryption_mode),
        endpoint.declared_logging_policy.trim(),
        relay_mode_identity(policy.mode),
        policy.require_confidential_cpu,
        policy.require_confidential_gpu,
        policy.max_attestation_age_ms,
    );
    fnv1a64_hex(canonical.as_str())
}

pub fn build_confidential_release_binding(
    source_id: &str,
    source_target: &str,
    session_id: &str,
    request_nonce: &str,
    policy_identity: &str,
    verified: &VerifiedAttestation,
    endpoint: &ConfidentialEndpointMetadata,
) -> String {
    let canonical = format!(
        "binding_v=1;source={};target={};session={};nonce={};policy_identity={};attestation_provider={};measurement={};verified_at={};expires_at={};cpu_confidential={};gpu_confidential={};encryption={};logging_policy={}",
        source_id.trim(),
        source_target.trim(),
        session_id.trim(),
        request_nonce.trim(),
        policy_identity.trim(),
        verified.provider.trim(),
        verified.measurement.trim(),
        verified.verified_at_unix_ms,
        verified.expires_at_unix_ms,
        verified.cpu_confidential,
        verified.gpu_confidential,
        relay_encryption_identity(endpoint.encryption_mode),
        endpoint.declared_logging_policy.trim(),
    );
    sha256_hex(canonical.as_str())
}

pub fn build_confidential_session_id(source_id: &str, now_unix_ms: u64, nonce: &str) -> String {
    let normalized_source = source_id
        .chars()
        .map(|value| {
            if value.is_ascii_alphanumeric() || value == '-' || value == '_' {
                value
            } else {
                '-'
            }
        })
        .collect::<String>();
    let normalized_nonce = nonce
        .chars()
        .map(|value| {
            if value.is_ascii_alphanumeric() || value == '-' || value == '_' {
                value
            } else {
                '-'
            }
        })
        .collect::<String>();
    format!("relay-{normalized_source}-{now_unix_ms}-{normalized_nonce}")
}

pub fn build_confidential_session_key_id(source_id: &str, now_unix_ms: u64, nonce: &str) -> String {
    let normalized_source = source_id
        .chars()
        .map(|value| {
            if value.is_ascii_alphanumeric() || value == '-' || value == '_' {
                value
            } else {
                '-'
            }
        })
        .collect::<String>();
    let normalized_nonce = nonce
        .chars()
        .map(|value| {
            if value.is_ascii_alphanumeric() || value == '-' || value == '_' {
                value
            } else {
                '-'
            }
        })
        .collect::<String>();
    format!("relay-key-{normalized_source}-{now_unix_ms}-{normalized_nonce}")
}

pub fn unix_time_ms_now() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(value) => u64::try_from(value.as_millis()).unwrap_or(u64::MAX),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AttestationEvidence, AttestationVerifierConfig, ConfidentialEndpointMetadata,
        ConfidentialRelayMode, ConfidentialRelayPolicy, ConfidentialRelaySessionRecord,
        ConfidentialRelaySessionStore, RelayEncryptionMode, build_confidential_policy_identity,
        build_confidential_release_binding, verify_attestation,
    };
    use std::{
        env, fs,
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

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
        let mut header_end = None;
        let mut expected_total_len = None;
        loop {
            let read = stream.read(&mut chunk).unwrap_or(0);
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if header_end.is_none() {
                if let Some(position) = find_bytes(&buffer, b"\r\n\r\n") {
                    let end = position + 4;
                    let headers = String::from_utf8_lossy(&buffer[..end]).to_string();
                    let content_length = parse_content_length(&headers);
                    header_end = Some(end);
                    expected_total_len = Some(end + content_length);
                }
            }
            if let Some(expected_total_len) = expected_total_len
                && buffer.len() >= expected_total_len
            {
                break;
            }
        }
        String::from_utf8_lossy(&buffer).to_string()
    }

    fn sample_evidence(now: u64) -> AttestationEvidence {
        AttestationEvidence {
            provider: "azure-teechat".to_string(),
            measurement: "sha256:trusted-launch-abc".to_string(),
            nonce: "nonce-1".to_string(),
            cpu_confidential: true,
            gpu_confidential: true,
            issued_at_unix_ms: now.saturating_sub(1_000),
            expires_at_unix_ms: now + 5_000,
            signature: "attestation-evidence-signature".to_string(),
        }
    }

    fn enabled_policy() -> ConfidentialRelayPolicy {
        ConfidentialRelayPolicy {
            mode: ConfidentialRelayMode::Required,
            require_confidential_cpu: true,
            require_confidential_gpu: true,
            max_attestation_age_ms: 10_000,
        }
    }

    fn endpoint_metadata(verifier_endpoint: String) -> ConfidentialEndpointMetadata {
        ConfidentialEndpointMetadata {
            enabled: true,
            expected_target_prefix: "https://api.openai.com/v1".to_string(),
            expected_attestation_provider: Some("azure-teechat".to_string()),
            expected_measurement_prefixes: vec!["sha256:trusted-".to_string()],
            attestation_verifier: AttestationVerifierConfig {
                endpoint: verifier_endpoint,
                timeout_ms: 1_500,
                ..AttestationVerifierConfig::default()
            },
            encryption_mode: RelayEncryptionMode::TlsHttps,
            declared_logging_policy: crate::confidential_relay::default_declared_logging_policy(),
        }
    }

    fn spawn_verifier_response(body: &str) -> Option<(String, thread::JoinHandle<()>)> {
        let listener = TcpListener::bind("127.0.0.1:0").ok()?;
        let local_addr = listener.local_addr().ok()?;
        let endpoint = format!("http://127.0.0.1:{}/attest/verify", local_addr.port());
        let body = body.to_string();
        let handle = thread::spawn(move || {
            let accepted = listener.accept();
            assert!(accepted.is_ok());
            let (mut stream, _) = match accepted {
                Ok(value) => value,
                Err(_) => return,
            };
            let request = read_full_http_request(&mut stream);
            assert!(request.contains("POST /attest/verify HTTP/1.1"));

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        });
        Some((endpoint, handle))
    }

    #[test]
    fn verify_attestation_fails_when_policy_disabled() {
        let now = 123_000;
        let evidence = sample_evidence(now);
        let policy = ConfidentialRelayPolicy::default();
        let endpoint = endpoint_metadata("http://127.0.0.1:1/attest/verify".to_string());
        let result = verify_attestation(
            "api-openai",
            "https://api.openai.com/v1",
            &endpoint,
            &evidence,
            &policy,
            now,
        );
        assert!(result.is_err());
    }

    #[test]
    fn verify_attestation_fails_closed_when_verifier_rejects_evidence() {
        let now = 321_000;
        let evidence = sample_evidence(now);
        let verifier =
            spawn_verifier_response(r#"{"verified":false,"reason":"signature mismatch"}"#);
        assert!(verifier.is_some());
        let (verifier_endpoint, handle) = match verifier {
            Some(value) => value,
            None => return,
        };
        let endpoint = endpoint_metadata(verifier_endpoint);
        let result = verify_attestation(
            "api-openai",
            "https://api.openai.com/v1",
            &endpoint,
            &evidence,
            &enabled_policy(),
            now,
        );
        assert!(result.is_err());
        if let Err(error) = result {
            assert!(error.contains("signature"));
        }
        let _ = handle.join();
    }

    #[test]
    fn verify_attestation_rejects_unexpected_measurement_prefix() {
        let now = 777_000;
        let evidence = sample_evidence(now);
        let verifier = spawn_verifier_response(
            r#"{"verified":true,"provider":"azure-teechat","measurement":"sha256:unknown","cpu_confidential":true,"gpu_confidential":true,"issued_at_unix_ms":776000,"expires_at_unix_ms":785000}"#,
        );
        assert!(verifier.is_some());
        let (verifier_endpoint, handle) = match verifier {
            Some(value) => value,
            None => return,
        };
        let endpoint = endpoint_metadata(verifier_endpoint);
        let result = verify_attestation(
            "api-openai",
            "https://api.openai.com/v1",
            &endpoint,
            &evidence,
            &enabled_policy(),
            now,
        );
        assert!(result.is_err());
        if let Err(error) = result {
            assert!(error.contains("measurement"));
        }
        let _ = handle.join();
    }

    #[test]
    fn verify_attestation_accepts_verified_http_backend_claims() {
        let now = 910_000;
        let evidence = sample_evidence(now);
        let verifier = spawn_verifier_response(
            r#"{"verified":true,"provider":"azure-teechat","measurement":"sha256:trusted-launch-abc","cpu_confidential":true,"gpu_confidential":true,"issued_at_unix_ms":909000,"expires_at_unix_ms":920000}"#,
        );
        assert!(verifier.is_some());
        let (verifier_endpoint, handle) = match verifier {
            Some(value) => value,
            None => return,
        };
        let endpoint = endpoint_metadata(verifier_endpoint);
        let result = verify_attestation(
            "api-openai",
            "https://api.openai.com/v1",
            &endpoint,
            &evidence,
            &enabled_policy(),
            now,
        );
        assert!(result.is_ok(), "{result:?}");
        let result = match result {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(result.provider, "azure-teechat");
        assert_eq!(result.measurement, "sha256:trusted-launch-abc");
        let _ = handle.join();
    }

    #[test]
    fn session_store_persists_records() {
        let mut store = ConfidentialRelaySessionStore::new();
        store.record_session(ConfidentialRelaySessionRecord {
            session_id: "relay-a".to_string(),
            session_key_id: "relay-key-a".to_string(),
            request_nonce: "nonce-1".to_string(),
            source_id: "api-openai".to_string(),
            source_display_name: "OpenAI API".to_string(),
            route: "https://api.openai.com/v1/chat/completions".to_string(),
            transport_encrypted: true,
            verified_at_unix_ms: 2_000,
            expires_at_unix_ms: 5_000,
            attestation_verify_ms: 12,
            relay_roundtrip_ms: 47,
            total_path_ms: 63,
            attestation_provider: "forge-manual".to_string(),
            measurement: "sha256:abcd".to_string(),
            cpu_confidential: true,
            gpu_confidential: true,
            encryption_mode: RelayEncryptionMode::TlsHttps,
            declared_logging_policy: crate::confidential_relay::default_declared_logging_policy(),
            policy_identity: "fnv1a64:test-policy-a".to_string(),
            fallback_consent_required: true,
            fallback_consent_granted: false,
            fallback_consent_source: "tests.confidential_relay".to_string(),
            fallback_consent_captured_at_unix_ms: Some(1_900),
            fallback_state: "not_used".to_string(),
            release_binding: "sha256:test-binding-a".to_string(),
        });

        let path = env::temp_dir().join("forge_confidential_relay_store_test.json");
        let save_result = store.save_to_path(&path);
        assert!(save_result.is_ok());
        let loaded = ConfidentialRelaySessionStore::load_from_path(&path);
        assert!(loaded.is_ok());
        let loaded = match loaded {
            Ok(value) => value,
            Err(_) => {
                let _ = fs::remove_file(&path);
                return;
            }
        };
        let _ = fs::remove_file(&path);

        let latest = loaded.latest_session();
        assert!(latest.is_some());
        let latest = match latest {
            Some(value) => value,
            None => return,
        };
        assert_eq!(latest.session_id, "relay-a");
        assert_eq!(latest.source_id, "api-openai");
    }

    #[test]
    fn session_store_prune_and_clear_manage_history() {
        let mut store = ConfidentialRelaySessionStore::new();
        store.record_session(ConfidentialRelaySessionRecord {
            session_id: "relay-old".to_string(),
            session_key_id: "relay-key-old".to_string(),
            request_nonce: "nonce-old".to_string(),
            source_id: "api-openai".to_string(),
            source_display_name: "OpenAI API".to_string(),
            route: "https://api.openai.com/v1/chat/completions".to_string(),
            transport_encrypted: true,
            verified_at_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
            attestation_verify_ms: 14,
            relay_roundtrip_ms: 40,
            total_path_ms: 61,
            attestation_provider: "forge-manual".to_string(),
            measurement: "sha256:old".to_string(),
            cpu_confidential: true,
            gpu_confidential: true,
            encryption_mode: RelayEncryptionMode::TlsHttps,
            declared_logging_policy: crate::confidential_relay::default_declared_logging_policy(),
            policy_identity: "fnv1a64:test-policy-old".to_string(),
            fallback_consent_required: true,
            fallback_consent_granted: false,
            fallback_consent_source: "tests.confidential_relay".to_string(),
            fallback_consent_captured_at_unix_ms: Some(900),
            fallback_state: "not_used".to_string(),
            release_binding: "sha256:test-binding-old".to_string(),
        });
        store.record_session(ConfidentialRelaySessionRecord {
            session_id: "relay-new".to_string(),
            session_key_id: "relay-key-new".to_string(),
            request_nonce: "nonce-new".to_string(),
            source_id: "api-openai".to_string(),
            source_display_name: "OpenAI API".to_string(),
            route: "https://api.openai.com/v1/chat/completions".to_string(),
            transport_encrypted: true,
            verified_at_unix_ms: 3_000,
            expires_at_unix_ms: 9_000,
            attestation_verify_ms: 18,
            relay_roundtrip_ms: 44,
            total_path_ms: 70,
            attestation_provider: "forge-manual".to_string(),
            measurement: "sha256:new".to_string(),
            cpu_confidential: true,
            gpu_confidential: true,
            encryption_mode: RelayEncryptionMode::TlsHttps,
            declared_logging_policy: crate::confidential_relay::default_declared_logging_policy(),
            policy_identity: "fnv1a64:test-policy-new".to_string(),
            fallback_consent_required: true,
            fallback_consent_granted: false,
            fallback_consent_source: "tests.confidential_relay".to_string(),
            fallback_consent_captured_at_unix_ms: Some(2_900),
            fallback_state: "not_used".to_string(),
            release_binding: "sha256:test-binding-new".to_string(),
        });

        let pruned = store.prune_expired(2_500);
        assert_eq!(pruned, 1);
        assert_eq!(store.sessions().len(), 1);
        assert_eq!(store.sessions()[0].session_id, "relay-new");

        let cleared = store.clear();
        assert_eq!(cleared, 1);
        assert!(store.sessions().is_empty());
    }

    #[test]
    fn session_store_nonce_replay_detects_active_session_nonce_reuse() {
        let mut store = ConfidentialRelaySessionStore::new();
        store.record_session(ConfidentialRelaySessionRecord {
            session_id: "relay-active".to_string(),
            session_key_id: "relay-key-active".to_string(),
            request_nonce: "nonce-replay".to_string(),
            source_id: "api-openai".to_string(),
            source_display_name: "OpenAI API".to_string(),
            route: "https://api.openai.com/v1/chat/completions".to_string(),
            transport_encrypted: true,
            verified_at_unix_ms: 4_000,
            expires_at_unix_ms: 12_000,
            attestation_verify_ms: 14,
            relay_roundtrip_ms: 41,
            total_path_ms: 60,
            attestation_provider: "forge-manual".to_string(),
            measurement: "sha256:active".to_string(),
            cpu_confidential: true,
            gpu_confidential: true,
            encryption_mode: RelayEncryptionMode::TlsHttps,
            declared_logging_policy: crate::confidential_relay::default_declared_logging_policy(),
            policy_identity: "fnv1a64:test-policy-active".to_string(),
            fallback_consent_required: true,
            fallback_consent_granted: true,
            fallback_consent_source: "tests.confidential_relay".to_string(),
            fallback_consent_captured_at_unix_ms: Some(3_900),
            fallback_state: "not_used".to_string(),
            release_binding: "sha256:test-binding-active".to_string(),
        });
        store.record_session(ConfidentialRelaySessionRecord {
            session_id: "relay-expired".to_string(),
            session_key_id: "relay-key-expired".to_string(),
            request_nonce: "nonce-replay".to_string(),
            source_id: "api-openai".to_string(),
            source_display_name: "OpenAI API".to_string(),
            route: "https://api.openai.com/v1/chat/completions".to_string(),
            transport_encrypted: true,
            verified_at_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
            attestation_verify_ms: 11,
            relay_roundtrip_ms: 33,
            total_path_ms: 48,
            attestation_provider: "forge-manual".to_string(),
            measurement: "sha256:expired".to_string(),
            cpu_confidential: true,
            gpu_confidential: true,
            encryption_mode: RelayEncryptionMode::TlsHttps,
            declared_logging_policy: crate::confidential_relay::default_declared_logging_policy(),
            policy_identity: "fnv1a64:test-policy-expired".to_string(),
            fallback_consent_required: true,
            fallback_consent_granted: false,
            fallback_consent_source: "tests.confidential_relay".to_string(),
            fallback_consent_captured_at_unix_ms: Some(800),
            fallback_state: "not_used".to_string(),
            release_binding: "sha256:test-binding-expired".to_string(),
        });

        assert!(store.is_nonce_replay("api-openai", "nonce-replay", 6_000));
        assert!(!store.is_nonce_replay("api-openai", "nonce-replay", 13_000));
        assert!(!store.is_nonce_replay("api-openai", "nonce-other", 6_000));
    }

    #[test]
    fn session_store_profile_summary_reports_avg_and_p95() {
        let mut store = ConfidentialRelaySessionStore::new();
        for (idx, verify_ms, relay_ms, total_ms) in [
            (1_u64, 10_u64, 20_u64, 31_u64),
            (2_u64, 20_u64, 30_u64, 52_u64),
            (3_u64, 30_u64, 40_u64, 73_u64),
            (4_u64, 40_u64, 50_u64, 94_u64),
            (5_u64, 50_u64, 60_u64, 115_u64),
        ] {
            store.record_session(ConfidentialRelaySessionRecord {
                session_id: format!("relay-{idx}"),
                session_key_id: format!("relay-key-{idx}"),
                request_nonce: format!("nonce-{idx}"),
                source_id: "api-openai".to_string(),
                source_display_name: "OpenAI API".to_string(),
                route: "https://api.openai.com/v1/chat/completions".to_string(),
                transport_encrypted: true,
                verified_at_unix_ms: idx * 1_000,
                expires_at_unix_ms: idx * 1_000 + 30_000,
                attestation_verify_ms: verify_ms,
                relay_roundtrip_ms: relay_ms,
                total_path_ms: total_ms,
                attestation_provider: "forge-manual".to_string(),
                measurement: format!("sha256:{idx}"),
                cpu_confidential: true,
                gpu_confidential: true,
                encryption_mode: RelayEncryptionMode::TlsHttps,
                declared_logging_policy: crate::confidential_relay::default_declared_logging_policy(
                ),
                policy_identity: format!("fnv1a64:test-policy-{idx}"),
                fallback_consent_required: true,
                fallback_consent_granted: idx % 2 == 0,
                fallback_consent_source: "tests.confidential_relay".to_string(),
                fallback_consent_captured_at_unix_ms: Some(idx * 1_000),
                fallback_state: "not_used".to_string(),
                release_binding: format!("sha256:test-binding-{idx}"),
            });
        }

        let summary = store.profile_summary(5);
        assert!(summary.is_some());
        let summary = match summary {
            Some(value) => value,
            None => return,
        };
        assert_eq!(summary.sample_count, 5);
        assert_eq!(summary.attestation_verify_avg_ms, 30);
        assert_eq!(summary.attestation_verify_p95_ms, 50);
        assert_eq!(summary.relay_roundtrip_avg_ms, 40);
        assert_eq!(summary.relay_roundtrip_p95_ms, 60);
        assert_eq!(summary.total_path_avg_ms, 73);
        assert_eq!(summary.total_path_p95_ms, 115);
    }

    #[test]
    fn policy_identity_is_stable_for_equivalent_metadata_order() {
        let policy = enabled_policy();
        let endpoint_a = ConfidentialEndpointMetadata {
            enabled: true,
            expected_target_prefix: "https://api.openai.com/v1".to_string(),
            expected_attestation_provider: Some("azure-teechat".to_string()),
            expected_measurement_prefixes: vec![
                "sha256:trusted-b".to_string(),
                "sha256:trusted-a".to_string(),
            ],
            attestation_verifier: AttestationVerifierConfig {
                endpoint: "https://attest.example/verify".to_string(),
                timeout_ms: 1_500,
                ..AttestationVerifierConfig::default()
            },
            encryption_mode: RelayEncryptionMode::TlsHttps,
            declared_logging_policy: crate::confidential_relay::default_declared_logging_policy(),
        };
        let endpoint_b = ConfidentialEndpointMetadata {
            expected_measurement_prefixes: vec![
                "sha256:trusted-a".to_string(),
                "sha256:trusted-b".to_string(),
            ],
            ..endpoint_a.clone()
        };

        let identity_a = build_confidential_policy_identity("api-openai", &endpoint_a, &policy);
        let identity_b = build_confidential_policy_identity("api-openai", &endpoint_b, &policy);
        assert_eq!(identity_a, identity_b);
    }

    #[test]
    fn release_binding_changes_when_policy_identity_changes() {
        let endpoint = ConfidentialEndpointMetadata {
            enabled: true,
            expected_target_prefix: "https://api.openai.com/v1".to_string(),
            expected_attestation_provider: Some("azure-teechat".to_string()),
            expected_measurement_prefixes: vec!["sha256:trusted-a".to_string()],
            attestation_verifier: AttestationVerifierConfig {
                endpoint: "https://attest.example/verify".to_string(),
                timeout_ms: 1_500,
                ..AttestationVerifierConfig::default()
            },
            encryption_mode: RelayEncryptionMode::TlsHttps,
            declared_logging_policy: crate::confidential_relay::default_declared_logging_policy(),
        };
        let verified = super::VerifiedAttestation {
            provider: "azure-teechat".to_string(),
            measurement: "sha256:trusted-a".to_string(),
            cpu_confidential: true,
            gpu_confidential: true,
            verified_at_unix_ms: 1_000,
            expires_at_unix_ms: 8_000,
        };
        let a = build_confidential_release_binding(
            "api-openai",
            "https://api.openai.com/v1",
            "relay-a",
            "nonce-a",
            "fnv1a64:policy-a",
            &verified,
            &endpoint,
        );
        let b = build_confidential_release_binding(
            "api-openai",
            "https://api.openai.com/v1",
            "relay-a",
            "nonce-a",
            "fnv1a64:policy-b",
            &verified,
            &endpoint,
        );
        assert_ne!(a, b);
        assert!(a.starts_with("sha256:"));
        assert_eq!(a.len(), "sha256:".len() + 64);
    }

    #[test]
    fn session_store_load_legacy_records_defaults_new_identity_and_fallback_fields() {
        let json = r#"{
  "schema_version": 1,
  "sessions": [
    {
      "session_id": "relay-legacy",
      "session_key_id": "relay-key-legacy",
      "request_nonce": "nonce-legacy",
      "source_id": "api-openai",
      "source_display_name": "OpenAI API",
      "route": "https://api.openai.com/v1/chat/completions",
      "transport_encrypted": true,
      "verified_at_unix_ms": 1000,
      "expires_at_unix_ms": 5000,
      "attestation_verify_ms": 12,
      "relay_roundtrip_ms": 24,
      "total_path_ms": 36,
      "attestation_provider": "forge-manual",
      "measurement": "sha256:legacy",
      "cpu_confidential": true,
      "gpu_confidential": true,
      "encryption_mode": "TlsHttps"
    }
  ]
}"#;

        let mut path = env::temp_dir();
        path.push("forge_confidential_relay_legacy_session_schema.json");
        let _ = fs::remove_file(&path);
        assert!(fs::write(&path, json).is_ok());

        let loaded = ConfidentialRelaySessionStore::load_from_path(&path);
        assert!(loaded.is_ok());
        let loaded = match loaded {
            Ok(value) => value,
            Err(_) => {
                let _ = fs::remove_file(&path);
                return;
            }
        };
        let _ = fs::remove_file(&path);

        let latest = loaded.latest_session();
        assert!(latest.is_some());
        let latest = match latest {
            Some(value) => value,
            None => return,
        };
        assert_eq!(latest.session_id, "relay-legacy");
        assert!(latest.policy_identity.is_empty());
        assert_eq!(
            latest.declared_logging_policy,
            crate::confidential_relay::default_declared_logging_policy()
        );
        assert!(!latest.fallback_consent_required);
        assert!(!latest.fallback_consent_granted);
        assert!(latest.fallback_consent_source.is_empty());
        assert_eq!(latest.fallback_consent_captured_at_unix_ms, None);
        assert_eq!(latest.fallback_state, "unknown");
        assert!(latest.release_binding.is_empty());
    }
}
