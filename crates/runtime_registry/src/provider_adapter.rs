use crate::confidential_relay::{
    AttestationEvidence, ConfidentialRelayMode, ConfidentialRelayPolicy,
    ConfidentialRelaySessionRecord, ConfidentialRelaySessionStore, RelayEncryptionMode,
    allow_insecure_localhost_http_endpoint, build_confidential_session_id,
    build_confidential_session_key_id, verify_attestation,
};
use crate::local_api_hardening::guard_and_audit_provider_route;
use crate::openjarvis_bridge::{
    OpenJarvisBridgeModeAConfig, OpenJarvisChatCompletionRequest,
    run_openjarvis_mode_a_chat_completion,
};
use crate::openjarvis_mode_b::{
    OpenJarvisBridgeModeBConfig, OpenJarvisBridgeModeBTaskRequest, OpenJarvisBridgeTaskKind,
    run_openjarvis_mode_b_task,
};
use crate::source_registry::{SourceEntry, SourceKind, SourceRegistry, SourceRole};
use forge_security::broker::{SecretInjectionTarget, with_global_secret_broker};
use serde_json::{Value, json};
use std::env;
use std::error::Error;
use std::fmt;
use std::io::Read;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAdapterValidationError {
    message: String,
}

impl ProviderAdapterValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ProviderAdapterValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ProviderAdapterValidationError {}

impl From<ProviderAdapterValidationError> for String {
    fn from(value: ProviderAdapterValidationError) -> Self {
        value.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexSpecialistTaskRequest {
    pub request_id: String,
    pub prompt: String,
    pub max_tokens: u32,
}

impl CodexSpecialistTaskRequest {
    pub fn new(
        request_id: impl Into<String>,
        prompt: impl Into<String>,
        max_tokens: u32,
    ) -> Result<Self, String> {
        let request = Self {
            request_id: request_id.into(),
            prompt: prompt.into(),
            max_tokens,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), ProviderAdapterValidationError> {
        if self.request_id.trim().is_empty() {
            return Err(ProviderAdapterValidationError::new(
                "codex specialist request_id cannot be empty",
            ));
        }
        if self.prompt.trim().is_empty() {
            return Err(ProviderAdapterValidationError::new(
                "codex specialist prompt cannot be empty",
            ));
        }
        if self.max_tokens == 0 {
            return Err(ProviderAdapterValidationError::new(
                "codex specialist max_tokens must be greater than zero",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexSpecialistTaskResponse {
    pub source_id: String,
    pub source_display_name: String,
    pub route: String,
    pub output_text: String,
    pub tokens_used: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatTaskRequest {
    pub prompt: String,
    pub max_tokens: u32,
}

impl ChatTaskRequest {
    pub fn new(prompt: impl Into<String>, max_tokens: u32) -> Result<Self, String> {
        let request = Self {
            prompt: prompt.into(),
            max_tokens,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), ProviderAdapterValidationError> {
        if self.prompt.trim().is_empty() {
            return Err(ProviderAdapterValidationError::new(
                "chat prompt cannot be empty",
            ));
        }
        if self.max_tokens == 0 {
            return Err(ProviderAdapterValidationError::new(
                "chat max_tokens must be greater than zero",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatTaskResponse {
    pub source_id: String,
    pub source_display_name: String,
    pub route: String,
    pub output_text: String,
    pub tokens_used: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfidentialChatTaskRequest {
    pub prompt: String,
    pub max_tokens: u32,
    pub attestation: AttestationEvidence,
    pub policy: ConfidentialRelayPolicy,
}

impl ConfidentialChatTaskRequest {
    pub fn validate(&self) -> Result<(), ProviderAdapterValidationError> {
        if self.prompt.trim().is_empty() {
            return Err(ProviderAdapterValidationError::new(
                "confidential chat prompt cannot be empty",
            ));
        }
        if self.max_tokens == 0 {
            return Err(ProviderAdapterValidationError::new(
                "confidential chat max_tokens must be greater than zero",
            ));
        }
        self.policy
            .validate()
            .map_err(|error| ProviderAdapterValidationError::new(error.to_string()))?;
        self.attestation
            .validate()
            .map_err(|error| ProviderAdapterValidationError::new(error.to_string()))?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfidentialChatTaskResponse {
    pub source_id: String,
    pub source_display_name: String,
    pub route: String,
    pub output_text: String,
    pub tokens_used: Option<u32>,
    pub session_id: String,
    pub session_key_id: String,
    pub request_nonce: String,
    pub verified_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub transport_encrypted: bool,
    pub attestation_verify_ms: u64,
    pub relay_roundtrip_ms: u64,
    pub total_path_ms: u64,
    pub attestation_provider: String,
    pub measurement: String,
    pub cpu_confidential: bool,
    pub gpu_confidential: bool,
    pub encryption_mode: RelayEncryptionMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleTaskRequest {
    pub request_id: String,
    pub prompt: String,
    pub max_tokens: u32,
}

impl RoleTaskRequest {
    pub fn new(
        request_id: impl Into<String>,
        prompt: impl Into<String>,
        max_tokens: u32,
    ) -> Result<Self, String> {
        let request = Self {
            request_id: request_id.into(),
            prompt: prompt.into(),
            max_tokens,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), ProviderAdapterValidationError> {
        if self.request_id.trim().is_empty() {
            return Err(ProviderAdapterValidationError::new(
                "role task request_id cannot be empty",
            ));
        }
        if self.prompt.trim().is_empty() {
            return Err(ProviderAdapterValidationError::new(
                "role task prompt cannot be empty",
            ));
        }
        if self.max_tokens == 0 {
            return Err(ProviderAdapterValidationError::new(
                "role task max_tokens must be greater than zero",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleTaskResponse {
    pub source_id: String,
    pub source_display_name: String,
    pub route: String,
    pub output_text: String,
    pub tokens_used: Option<u32>,
}

pub fn run_codex_specialist_task(
    source_registry: &SourceRegistry,
    request: &CodexSpecialistTaskRequest,
) -> Result<CodexSpecialistTaskResponse, String> {
    request.validate()?;
    let sources = resolve_codex_specialist_sources(source_registry);
    if sources.is_empty() {
        return Err("no enabled source available for codex specialist role".to_string());
    }

    let mut errors = Vec::new();
    for source in &sources {
        match execute_codex_specialist_with_source(source, request) {
            Ok(result) => return Ok(result),
            Err(error) => errors.push(format!("{}: {}", source.id, error)),
        }
    }
    Err(format!(
        "codex specialist routing failed across {} source(s): {}",
        sources.len(),
        errors.join(" | ")
    ))
}

pub fn run_chat_task_with_source(
    source: &SourceEntry,
    request: &ChatTaskRequest,
) -> Result<ChatTaskResponse, String> {
    request.validate()?;
    if !source.enabled {
        return Err(format!("source {} is disabled for chat routing", source.id));
    }

    guard_and_audit_provider_route(source, "chat", || match source.kind {
        SourceKind::LocalModel => Err(format!(
            "local source {} should be handled through runtime process path",
            source.id
        )),
        SourceKind::SidecarBridge => execute_chat_mode_a(source, request),
        SourceKind::ApiModel => {
            if source.target.trim().starts_with("https://") {
                execute_secure_https_chat_api(source, request)
            } else if looks_like_mode_a(source) && is_localhost_http_endpoint(&source.target) {
                execute_chat_mode_a(source, request)
            } else {
                Err(format!(
                    "api source {} must use a secure https endpoint or a localhost mode-a bridge",
                    source.id
                ))
            }
        }
    })
}

pub fn run_confidential_chat_task_with_source(
    source: &SourceEntry,
    request: &ConfidentialChatTaskRequest,
    session_store: &mut ConfidentialRelaySessionStore,
    now_unix_ms: u64,
) -> Result<ConfidentialChatTaskResponse, String> {
    let total_start = Instant::now();
    request.validate()?;
    if matches!(request.policy.mode, ConfidentialRelayMode::Disabled) {
        return Err("confidential relay blocked: policy mode is disabled".to_string());
    }
    if !source.enabled {
        return Err(format!(
            "source {} is disabled for confidential chat routing",
            source.id
        ));
    }
    let source_target = source.target.trim();
    let localhost_http_allowed = allow_insecure_localhost_http_endpoint(source_target);
    if !source_target.starts_with("https://") && !localhost_http_allowed {
        return Err(format!(
            "source {} is not eligible for confidential relay; secure https endpoint required",
            source.id
        ));
    }
    let Some(endpoint) = source.confidential_endpoint.as_ref() else {
        return Err(format!(
            "source {} is not configured with confidential endpoint metadata",
            source.id
        ));
    };
    let _ = session_store.prune_expired(now_unix_ms);
    if session_store.is_nonce_replay(&source.id, &request.attestation.nonce, now_unix_ms) {
        return Err(format!(
            "confidential relay rejected: nonce replay detected for source {}",
            source.id
        ));
    }

    let verify_start = Instant::now();
    let verified = verify_attestation(
        &source.id,
        &source.target,
        endpoint,
        &request.attestation,
        &request.policy,
        now_unix_ms,
    )?;
    let attestation_verify_ms =
        u64::try_from(verify_start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let base_request = ChatTaskRequest::new(request.prompt.clone(), request.max_tokens)?;
    let relay_start = Instant::now();
    let response = run_chat_task_with_source(source, &base_request)?;
    let relay_roundtrip_ms = u64::try_from(relay_start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let total_path_ms = u64::try_from(total_start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let session_id =
        build_confidential_session_id(&source.id, now_unix_ms, &request.attestation.nonce);
    let session_key_id =
        build_confidential_session_key_id(&source.id, now_unix_ms, &request.attestation.nonce);
    let request_nonce = request.attestation.nonce.trim().to_string();
    let transport_encrypted = true;

    let record = ConfidentialRelaySessionRecord {
        session_id: session_id.clone(),
        session_key_id: session_key_id.clone(),
        request_nonce: request_nonce.clone(),
        source_id: source.id.clone(),
        source_display_name: source.display_name.clone(),
        route: response.route.clone(),
        transport_encrypted,
        verified_at_unix_ms: verified.verified_at_unix_ms,
        expires_at_unix_ms: verified.expires_at_unix_ms,
        attestation_verify_ms,
        relay_roundtrip_ms,
        total_path_ms,
        attestation_provider: verified.provider.clone(),
        measurement: verified.measurement.clone(),
        cpu_confidential: verified.cpu_confidential,
        gpu_confidential: verified.gpu_confidential,
        encryption_mode: endpoint.encryption_mode,
    };
    session_store.record_session(record);

    Ok(ConfidentialChatTaskResponse {
        source_id: response.source_id,
        source_display_name: response.source_display_name,
        route: response.route,
        output_text: response.output_text,
        tokens_used: response.tokens_used,
        session_id,
        session_key_id,
        request_nonce,
        verified_at_unix_ms: verified.verified_at_unix_ms,
        expires_at_unix_ms: verified.expires_at_unix_ms,
        transport_encrypted,
        attestation_verify_ms,
        relay_roundtrip_ms,
        total_path_ms,
        attestation_provider: verified.provider,
        measurement: verified.measurement,
        cpu_confidential: verified.cpu_confidential,
        gpu_confidential: verified.gpu_confidential,
        encryption_mode: endpoint.encryption_mode,
    })
}

pub fn run_role_task_with_source(
    source: &SourceEntry,
    role: SourceRole,
    request: &RoleTaskRequest,
) -> Result<RoleTaskResponse, String> {
    request.validate()?;
    if !matches!(
        role,
        SourceRole::Planner | SourceRole::Debugger | SourceRole::Verifier
    ) {
        return Err(format!(
            "role task adapter supports planner/debugger/verifier roles only; got {}",
            role.label()
        ));
    }
    if !source.enabled {
        return Err(format!(
            "source {} is disabled for {} routing",
            source.id,
            role.label()
        ));
    }
    if !source.supports_role(role) {
        return Err(format!(
            "source {} does not support role {}",
            source.id,
            role.label()
        ));
    }

    guard_and_audit_provider_route(source, role.label(), || match source.kind {
        SourceKind::LocalModel => Err(format!(
            "local source {} should be handled through runtime process path",
            source.id
        )),
        SourceKind::SidecarBridge => {
            if looks_like_mode_b(source) {
                execute_role_mode_b(source, role, request)
            } else if looks_like_mode_a(source) {
                execute_role_mode_a(source, role, request)
            } else {
                Err(format!(
                    "sidecar source {} is not recognized by provider adapter",
                    source.id
                ))
            }
        }
        SourceKind::ApiModel => {
            if source.target.trim().starts_with("https://") {
                execute_secure_https_role_api(source, role, request)
            } else if looks_like_mode_a(source) && is_localhost_http_endpoint(&source.target) {
                execute_role_mode_a(source, role, request)
            } else {
                Err(format!(
                    "api source {} must use a secure https endpoint or a localhost mode-a bridge",
                    source.id
                ))
            }
        }
    })
}

fn resolve_codex_specialist_sources(source_registry: &SourceRegistry) -> Vec<SourceEntry> {
    let mut ordered = Vec::new();
    if let Some(entry) = source_registry.default_for(SourceRole::CodexSpecialist) {
        push_unique_source(&mut ordered, entry.clone());
    }
    if let Some(entry) = source_registry.default_for(SourceRole::Coder) {
        push_unique_source(&mut ordered, entry.clone());
    }
    for entry in source_registry.eligible_for(SourceRole::CodexSpecialist) {
        push_unique_source(&mut ordered, entry.clone());
    }
    for entry in source_registry.eligible_for(SourceRole::Coder) {
        push_unique_source(&mut ordered, entry.clone());
    }
    ordered
}

fn push_unique_source(ordered: &mut Vec<SourceEntry>, candidate: SourceEntry) {
    if !ordered.iter().any(|entry| entry.id == candidate.id) {
        ordered.push(candidate);
    }
}

fn execute_codex_specialist_with_source(
    source: &SourceEntry,
    request: &CodexSpecialistTaskRequest,
) -> Result<CodexSpecialistTaskResponse, String> {
    if !source.enabled {
        return Err(format!(
            "source {} is disabled for codex specialist routing",
            source.id
        ));
    }

    guard_and_audit_provider_route(source, "codex_specialist", || match source.kind {
        SourceKind::SidecarBridge => {
            if looks_like_mode_b(source) {
                execute_mode_b(source, request)
            } else if looks_like_mode_a(source) {
                execute_mode_a(source, request)
            } else {
                Err(format!(
                    "sidecar source {} is not recognized by provider adapter",
                    source.id
                ))
            }
        }
        SourceKind::ApiModel => {
            if source.target.trim().starts_with("https://") {
                execute_secure_https_api(source, request)
            } else if looks_like_mode_a(source) && is_localhost_http_endpoint(&source.target) {
                execute_mode_a(source, request)
            } else {
                Err(format!(
                    "api source {} must use a secure https endpoint or a localhost mode-a bridge",
                    source.id
                ))
            }
        }
        SourceKind::LocalModel => Err(format!(
            "local source {} is not a codex specialist provider adapter target",
            source.id
        )),
    })
}

fn execute_mode_b(
    source: &SourceEntry,
    request: &CodexSpecialistTaskRequest,
) -> Result<CodexSpecialistTaskResponse, String> {
    let parsed = parse_http_endpoint(&source.target, 8100)?;
    let config = OpenJarvisBridgeModeBConfig {
        host: parsed.host,
        port: parsed.port,
        task_path: parsed.path,
        ..OpenJarvisBridgeModeBConfig::default()
    };

    let mode_b_request = OpenJarvisBridgeModeBTaskRequest {
        request_id: request.request_id.clone(),
        kind: OpenJarvisBridgeTaskKind::Code,
        prompt: request.prompt.clone(),
        max_tokens: request.max_tokens,
        model: None,
    };
    let result = run_openjarvis_mode_b_task(&config, &mode_b_request)?;
    Ok(CodexSpecialistTaskResponse {
        source_id: source.id.clone(),
        source_display_name: source.display_name.clone(),
        route: config.task_endpoint(),
        output_text: result.output_text,
        tokens_used: result.tokens_used,
    })
}

fn execute_mode_a(
    source: &SourceEntry,
    request: &CodexSpecialistTaskRequest,
) -> Result<CodexSpecialistTaskResponse, String> {
    let parsed = parse_http_endpoint(&source.target, 8000)?;
    let config = OpenJarvisBridgeModeAConfig {
        host: parsed.host,
        port: parsed.port,
        api_base_path: derive_mode_a_base_path(&parsed.path),
        ..OpenJarvisBridgeModeAConfig::default()
    };

    let mode_a_request = OpenJarvisChatCompletionRequest {
        prompt: request.prompt.clone(),
        max_tokens: request.max_tokens,
        model: None,
    };
    let result = run_openjarvis_mode_a_chat_completion(&config, &mode_a_request)?;
    Ok(CodexSpecialistTaskResponse {
        source_id: source.id.clone(),
        source_display_name: source.display_name.clone(),
        route: config.chat_completions_endpoint(),
        output_text: result.text,
        tokens_used: None,
    })
}

fn execute_chat_mode_a(
    source: &SourceEntry,
    request: &ChatTaskRequest,
) -> Result<ChatTaskResponse, String> {
    let parsed = parse_http_endpoint(&source.target, 8000)?;
    let config = OpenJarvisBridgeModeAConfig {
        host: parsed.host,
        port: parsed.port,
        api_base_path: derive_mode_a_base_path(&parsed.path),
        ..OpenJarvisBridgeModeAConfig::default()
    };

    let mode_a_request = OpenJarvisChatCompletionRequest {
        prompt: request.prompt.clone(),
        max_tokens: request.max_tokens,
        model: None,
    };
    let result = run_openjarvis_mode_a_chat_completion(&config, &mode_a_request)?;
    Ok(ChatTaskResponse {
        source_id: source.id.clone(),
        source_display_name: source.display_name.clone(),
        route: config.chat_completions_endpoint(),
        output_text: result.text,
        tokens_used: None,
    })
}

fn execute_role_mode_b(
    source: &SourceEntry,
    role: SourceRole,
    request: &RoleTaskRequest,
) -> Result<RoleTaskResponse, String> {
    let parsed = parse_http_endpoint(&source.target, 8100)?;
    let config = OpenJarvisBridgeModeBConfig {
        host: parsed.host,
        port: parsed.port,
        task_path: parsed.path,
        ..OpenJarvisBridgeModeBConfig::default()
    };
    let kind = role_to_mode_b_task_kind(role)?;
    let mode_b_request = OpenJarvisBridgeModeBTaskRequest {
        request_id: request.request_id.clone(),
        kind,
        prompt: request.prompt.clone(),
        max_tokens: request.max_tokens,
        model: None,
    };
    let result = run_openjarvis_mode_b_task(&config, &mode_b_request)?;
    Ok(RoleTaskResponse {
        source_id: source.id.clone(),
        source_display_name: source.display_name.clone(),
        route: config.task_endpoint(),
        output_text: result.output_text,
        tokens_used: result.tokens_used,
    })
}

fn execute_role_mode_a(
    source: &SourceEntry,
    role: SourceRole,
    request: &RoleTaskRequest,
) -> Result<RoleTaskResponse, String> {
    let parsed = parse_http_endpoint(&source.target, 8000)?;
    let config = OpenJarvisBridgeModeAConfig {
        host: parsed.host,
        port: parsed.port,
        api_base_path: derive_mode_a_base_path(&parsed.path),
        ..OpenJarvisBridgeModeAConfig::default()
    };
    let prompt = compose_role_mode_a_prompt(role, &request.prompt)?;
    let mode_a_request = OpenJarvisChatCompletionRequest {
        prompt,
        max_tokens: request.max_tokens,
        model: None,
    };
    let result = run_openjarvis_mode_a_chat_completion(&config, &mode_a_request)?;
    Ok(RoleTaskResponse {
        source_id: source.id.clone(),
        source_display_name: source.display_name.clone(),
        route: config.chat_completions_endpoint(),
        output_text: result.text,
        tokens_used: None,
    })
}

fn execute_secure_https_api(
    source: &SourceEntry,
    request: &CodexSpecialistTaskRequest,
) -> Result<CodexSpecialistTaskResponse, String> {
    let endpoint = derive_openai_chat_completions_endpoint(&source.target)?;
    let model = resolve_codex_specialist_model();
    let auth_header = resolve_openai_bearer_auth_header()?;

    let payload = json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "You are Forge Codex Specialist. Return practical implementation guidance and concrete, safe code changes."
            },
            {
                "role": "user",
                "content": request.prompt.trim(),
            }
        ],
        "max_tokens": request.max_tokens,
        "temperature": 0.2,
    });

    let response = ureq::post(&endpoint)
        .set("Authorization", &auth_header)
        .set("Content-Type", "application/json")
        .set("Accept", "application/json")
        .send_json(payload);

    let body_json = match response {
        Ok(success) => success
            .into_json::<Value>()
            .map_err(|error| format!("openai response parse failed: {error}"))?,
        Err(ureq::Error::Status(code, response)) => {
            let body = read_response_body(response);
            return Err(format!(
                "openai api returned HTTP {code}: {}",
                clip_text(&body, 240)
            ));
        }
        Err(ureq::Error::Transport(error)) => {
            return Err(format!("openai transport failure: {error}"));
        }
    };

    let output_text = extract_openai_message_content(&body_json)
        .ok_or_else(|| "openai response missing choices[0].message.content".to_string())?;
    let tokens_used = body_json
        .get("usage")
        .and_then(|usage| usage.get("total_tokens"))
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());

    Ok(CodexSpecialistTaskResponse {
        source_id: source.id.clone(),
        source_display_name: source.display_name.clone(),
        route: endpoint,
        output_text,
        tokens_used,
    })
}

fn execute_secure_https_chat_api(
    source: &SourceEntry,
    request: &ChatTaskRequest,
) -> Result<ChatTaskResponse, String> {
    let endpoint = derive_openai_chat_completions_endpoint(&source.target)?;
    let model = resolve_chat_model();
    let auth_header = resolve_openai_bearer_auth_header()?;

    let payload = json!({
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": request.prompt.trim(),
            }
        ],
        "max_tokens": request.max_tokens,
        "temperature": 0.4,
    });

    let response = ureq::post(&endpoint)
        .set("Authorization", &auth_header)
        .set("Content-Type", "application/json")
        .set("Accept", "application/json")
        .send_json(payload);

    let body_json = match response {
        Ok(success) => success
            .into_json::<Value>()
            .map_err(|error| format!("openai response parse failed: {error}"))?,
        Err(ureq::Error::Status(code, response)) => {
            let body = read_response_body(response);
            return Err(format!(
                "openai api returned HTTP {code}: {}",
                clip_text(&body, 240)
            ));
        }
        Err(ureq::Error::Transport(error)) => {
            return Err(format!("openai transport failure: {error}"));
        }
    };

    let output_text = extract_openai_message_content(&body_json)
        .ok_or_else(|| "openai response missing choices[0].message.content".to_string())?;
    let tokens_used = body_json
        .get("usage")
        .and_then(|usage| usage.get("total_tokens"))
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());

    Ok(ChatTaskResponse {
        source_id: source.id.clone(),
        source_display_name: source.display_name.clone(),
        route: endpoint,
        output_text,
        tokens_used,
    })
}

fn execute_secure_https_role_api(
    source: &SourceEntry,
    role: SourceRole,
    request: &RoleTaskRequest,
) -> Result<RoleTaskResponse, String> {
    let endpoint = derive_openai_chat_completions_endpoint(&source.target)?;
    let model = resolve_role_model(role);
    let auth_header = resolve_openai_bearer_auth_header()?;
    let system_prompt = role_system_prompt(role)?;

    let payload = json!({
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": system_prompt,
            },
            {
                "role": "user",
                "content": request.prompt.trim(),
            }
        ],
        "max_tokens": request.max_tokens,
        "temperature": 0.3,
    });

    let response = ureq::post(&endpoint)
        .set("Authorization", &auth_header)
        .set("Content-Type", "application/json")
        .set("Accept", "application/json")
        .send_json(payload);

    let body_json = match response {
        Ok(success) => success
            .into_json::<Value>()
            .map_err(|error| format!("openai response parse failed: {error}"))?,
        Err(ureq::Error::Status(code, response)) => {
            let body = read_response_body(response);
            return Err(format!(
                "openai api returned HTTP {code}: {}",
                clip_text(&body, 240)
            ));
        }
        Err(ureq::Error::Transport(error)) => {
            return Err(format!("openai transport failure: {error}"));
        }
    };

    let output_text = extract_openai_message_content(&body_json)
        .ok_or_else(|| "openai response missing choices[0].message.content".to_string())?;
    let tokens_used = body_json
        .get("usage")
        .and_then(|usage| usage.get("total_tokens"))
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());

    Ok(RoleTaskResponse {
        source_id: source.id.clone(),
        source_display_name: source.display_name.clone(),
        route: endpoint,
        output_text,
        tokens_used,
    })
}

fn derive_openai_chat_completions_endpoint(target: &str) -> Result<String, String> {
    let trimmed = target.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err("api endpoint cannot be empty".to_string());
    }
    if !trimmed.starts_with("https://") {
        return Err("secure https endpoint required for direct API provider route".to_string());
    }
    if trimmed.ends_with("/chat/completions") {
        return Ok(trimmed.to_string());
    }
    if trimmed.ends_with("/v1") {
        return Ok(format!("{trimmed}/chat/completions"));
    }
    if let Some((prefix, _)) = trimmed.split_once("/v1/") {
        return Ok(format!("{prefix}/v1/chat/completions"));
    }
    Ok(format!("{trimmed}/chat/completions"))
}

fn resolve_openai_bearer_auth_header() -> Result<String, String> {
    let raw_key = resolve_openai_api_key_from_env()?;
    with_global_secret_broker(|broker| {
        let handle = broker.store_secret("OPENAI_API_KEY", raw_key)?;
        let auth_header =
            broker.inject_secret(&handle, SecretInjectionTarget::HttpAuthorizationBearer)?;
        broker.rotate_or_revoke_secret(&handle, None)?;
        Ok(auth_header)
    })
    .map_err(|error| format!("openai key broker flow failed: {error}"))
}

fn resolve_openai_api_key_from_env() -> Result<String, String> {
    for key_name in ["OPENAI_API_KEY"] {
        if let Ok(value) = env::var(key_name) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }
    }
    Err("missing OpenAI API key: set OPENAI_API_KEY".to_string())
}

fn resolve_codex_specialist_model() -> String {
    env::var("CODEX_SPECIALIST_MODEL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "gpt-5.3-codex".to_string())
}

fn resolve_chat_model() -> String {
    env::var("CHAT_MODEL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "gpt-5.2".to_string())
}

fn resolve_role_model(role: SourceRole) -> String {
    let env_key = match role {
        SourceRole::Planner => "PLANNER_MODEL",
        SourceRole::Debugger => "DEBUGGER_MODEL",
        SourceRole::Verifier => "VERIFIER_MODEL",
        _ => return resolve_chat_model(),
    };
    env::var(env_key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(resolve_chat_model)
}

fn role_to_mode_b_task_kind(role: SourceRole) -> Result<OpenJarvisBridgeTaskKind, String> {
    match role {
        SourceRole::Planner => Ok(OpenJarvisBridgeTaskKind::Plan),
        SourceRole::Debugger => Ok(OpenJarvisBridgeTaskKind::Debug),
        SourceRole::Verifier => Ok(OpenJarvisBridgeTaskKind::Verify),
        _ => Err(format!(
            "mode-b role task kind is unsupported for role {}",
            role.label()
        )),
    }
}

fn role_system_prompt(role: SourceRole) -> Result<&'static str, String> {
    match role {
        SourceRole::Planner => Ok(
            "You are Forge Planner. Produce an actionable implementation plan with acceptance checks.",
        ),
        SourceRole::Debugger => Ok(
            "You are Forge Debugger. Find likely root causes, propose fixes, and call out regression risks.",
        ),
        SourceRole::Verifier => Ok(
            "You are Forge Verifier. Validate outcomes, highlight gaps, and report pass/fail evidence.",
        ),
        _ => Err(format!(
            "system prompt is unsupported for role {}",
            role.label()
        )),
    }
}

fn compose_role_mode_a_prompt(role: SourceRole, prompt: &str) -> Result<String, String> {
    let system_prompt = role_system_prompt(role)?;
    Ok(format!(
        "{}\n\nTask Input:\n{}",
        system_prompt,
        prompt.trim()
    ))
}

fn read_response_body(response: ureq::Response) -> String {
    let mut body = String::new();
    let mut reader = response.into_reader();
    let _ = reader.read_to_string(&mut body);
    body
}

fn extract_openai_message_content(body_json: &Value) -> Option<String> {
    match body_json
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|first| first.get("message"))
        .and_then(|message| message.get("content"))
    {
        Some(Value::String(text)) => Some(text.trim().to_string()),
        Some(Value::Array(items)) => {
            let mut segments = Vec::new();
            for item in items {
                let maybe_text = item
                    .get("text")
                    .and_then(Value::as_str)
                    .or_else(|| item.get("content").and_then(Value::as_str));
                if let Some(text) = maybe_text {
                    let text = text.trim();
                    if !text.is_empty() {
                        segments.push(text.to_string());
                    }
                }
            }
            if segments.is_empty() {
                None
            } else {
                Some(segments.join("\n"))
            }
        }
        _ => None,
    }
}

fn clip_text(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    value.chars().take(max_chars).collect::<String>() + "..."
}

fn looks_like_mode_b(source: &SourceEntry) -> bool {
    source.id.contains("mode-b")
        || source.target.contains("/forge/bridge/v1/task")
        || source.target.contains("/bridge/v1/task")
}

fn looks_like_mode_a(source: &SourceEntry) -> bool {
    source.id.contains("mode-a")
        || source.target.contains("/v1/chat/completions")
        || source.target.ends_with("/v1")
}

fn is_localhost_http_endpoint(target: &str) -> bool {
    let trimmed = target.trim();
    let without_scheme = trimmed.strip_prefix("http://").unwrap_or(trimmed);
    let authority = without_scheme.split('/').next().unwrap_or_default();
    let host = authority.split(':').next().unwrap_or_default().trim();
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

fn derive_mode_a_base_path(path: &str) -> String {
    if let Some(prefix) = path.strip_suffix("/chat/completions") {
        let trimmed = prefix.trim();
        if trimmed.is_empty() {
            return "/v1".to_string();
        }
        return normalize_path(trimmed);
    }
    normalize_path(path)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedHttpEndpoint {
    host: String,
    port: u16,
    path: String,
}

fn parse_http_endpoint(endpoint: &str, default_port: u16) -> Result<ParsedHttpEndpoint, String> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return Err("provider endpoint cannot be empty".to_string());
    }
    if trimmed.starts_with("https://") {
        return Err(
            "https endpoints are not supported by this adapter; use a localhost http bridge"
                .to_string(),
        );
    }
    let without_scheme = trimmed.strip_prefix("http://").unwrap_or(trimmed);
    let (authority, raw_path) = match without_scheme.split_once('/') {
        Some((value, path)) => (value, format!("/{}", path.trim_start_matches('/'))),
        None => (without_scheme, "/".to_string()),
    };
    if authority.trim().is_empty() {
        return Err("provider endpoint is missing host".to_string());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port_token)) => {
            let parsed_port = port_token.parse::<u16>().map_err(|error| {
                format!("provider endpoint has invalid port `{port_token}`: {error}")
            })?;
            (host.to_string(), parsed_port)
        }
        None => (authority.to_string(), default_port),
    };
    if host.trim().is_empty() {
        return Err("provider endpoint host cannot be empty".to_string());
    }

    Ok(ParsedHttpEndpoint {
        host: host.trim().to_string(),
        port,
        path: normalize_path(&raw_path),
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

#[cfg(test)]
mod tests {
    use super::{
        ChatTaskRequest, CodexSpecialistTaskRequest, ConfidentialChatTaskRequest, RoleTaskRequest,
        derive_openai_chat_completions_endpoint, run_chat_task_with_source,
        run_codex_specialist_task, run_confidential_chat_task_with_source,
        run_role_task_with_source,
    };
    use crate::confidential_relay::{
        AttestationEvidence, AttestationVerifierConfig, ConfidentialEndpointMetadata,
        ConfidentialRelayMode, ConfidentialRelayPolicy, ConfidentialRelaySessionRecord,
        ConfidentialRelaySessionStore, RelayEncryptionMode,
    };
    use crate::local_api_hardening::{
        ProviderAdapterAuditDecision, ProviderAdapterRouteClass,
        latest_provider_adapter_audit_events,
    };
    use crate::source_registry::{SourceEntry, SourceKind, SourceRegistry, SourceRole};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

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

    fn sample_confidential_endpoint(verifier_endpoint: String) -> ConfidentialEndpointMetadata {
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
            encryption_mode: crate::confidential_relay::RelayEncryptionMode::TlsHttps,
            declared_logging_policy: crate::confidential_relay::default_declared_logging_policy(),
        }
    }

    fn spawn_attestation_verifier(body: &str) -> Option<(String, thread::JoinHandle<()>)> {
        let listener = TcpListener::bind("127.0.0.1:0").ok()?;
        let address = listener.local_addr().ok()?;
        let endpoint = format!("http://127.0.0.1:{}/attest/verify", address.port());
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
    fn codex_specialist_routes_to_mode_b_sidecar_source() {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(value) => value,
            Err(_) => return,
        };
        let address = match listener.local_addr() {
            Ok(value) => value,
            Err(_) => return,
        };

        let handle = thread::spawn(move || {
            let accepted = listener.accept();
            assert!(accepted.is_ok());
            let (mut stream, _) = match accepted {
                Ok(value) => value,
                Err(_) => return,
            };
            let mut buffer = [0u8; 4096];
            let read = stream.read(&mut buffer).unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..read]).to_string();
            assert!(request.contains("POST /forge/bridge/v1/task HTTP/1.1"));
            assert!(request.contains("\"kind\":\"code\""));
            assert!(request.contains("fix parser edge-case"));

            let body = r#"{"request_id":"r-1","status":"ok","result":{"text":"patched code path","tokens_used":77}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        });

        let mut registry = SourceRegistry::new();
        registry.register(SourceEntry {
            id: "codex-specialist-openjarvis-mode-b".to_string(),
            display_name: "Codex Specialist Sidecar".to_string(),
            kind: SourceKind::SidecarBridge,
            target: format!("http://127.0.0.1:{}/forge/bridge/v1/task", address.port()),
            enabled: true,
            eligible_roles: vec![SourceRole::CodexSpecialist],
            default_roles: vec![SourceRole::CodexSpecialist],
            confidential_endpoint: None,
        });
        let request = CodexSpecialistTaskRequest::new("r-1", "fix parser edge-case", 256);
        assert!(request.is_ok());
        let request = match request {
            Ok(value) => value,
            Err(_) => return,
        };
        let result = run_codex_specialist_task(&registry, &request);
        assert!(result.is_ok());
        let result = match result {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(result.output_text, "patched code path");
        assert_eq!(result.tokens_used, Some(77));
        assert_eq!(result.source_id, "codex-specialist-openjarvis-mode-b");

        let join_result = handle.join();
        assert!(join_result.is_ok());
    }

    #[test]
    fn codex_specialist_rejects_insecure_api_endpoint() {
        let mut registry = SourceRegistry::new();
        registry.register(SourceEntry {
            id: "api-openai".to_string(),
            display_name: "OpenAI API".to_string(),
            kind: SourceKind::ApiModel,
            target: "http://api.openai.com/v1".to_string(),
            enabled: true,
            eligible_roles: vec![SourceRole::CodexSpecialist],
            default_roles: vec![SourceRole::CodexSpecialist],
            confidential_endpoint: None,
        });

        let request = CodexSpecialistTaskRequest::new("req-2", "audit auth flow", 200);
        assert!(request.is_ok());
        let request = match request {
            Ok(value) => value,
            Err(_) => return,
        };
        let result = run_codex_specialist_task(&registry, &request);
        assert!(result.is_err());
        let error = match result {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(error.contains("secure https endpoint"));
    }

    #[test]
    fn openai_endpoint_builder_accepts_v1_base() {
        let endpoint = derive_openai_chat_completions_endpoint("https://api.openai.com/v1");
        assert!(endpoint.is_ok());
        let endpoint = match endpoint {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(endpoint, "https://api.openai.com/v1/chat/completions");
    }

    #[test]
    fn openai_endpoint_builder_rejects_non_https() {
        let endpoint = derive_openai_chat_completions_endpoint("http://api.openai.com/v1");
        assert!(endpoint.is_err());
    }

    #[test]
    fn chat_task_routes_to_mode_a_sidecar_source() {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(value) => value,
            Err(_) => return,
        };
        let address = match listener.local_addr() {
            Ok(value) => value,
            Err(_) => return,
        };

        let handle = thread::spawn(move || {
            let accepted = listener.accept();
            assert!(accepted.is_ok());
            let (mut stream, _) = match accepted {
                Ok(value) => value,
                Err(_) => return,
            };
            let mut buffer = [0u8; 4096];
            let read = stream.read(&mut buffer).unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..read]).to_string();
            assert!(request.contains("POST /v1/chat/completions HTTP/1.1"));
            assert!(request.contains("hello routed chat"));

            let body = r#"{"id":"chatcmpl-1","choices":[{"index":0,"message":{"role":"assistant","content":"chat ok"},"finish_reason":"stop"}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        });

        let source = SourceEntry {
            id: "openjarvis-mode-a".to_string(),
            display_name: "OpenJarvis (Mode A)".to_string(),
            kind: SourceKind::SidecarBridge,
            target: format!("http://127.0.0.1:{}/v1/chat/completions", address.port()),
            enabled: true,
            eligible_roles: vec![SourceRole::Chat],
            default_roles: vec![SourceRole::Chat],
            confidential_endpoint: None,
        };
        let request = ChatTaskRequest::new("hello routed chat", 64);
        assert!(request.is_ok());
        let request = match request {
            Ok(value) => value,
            Err(_) => return,
        };
        let result = run_chat_task_with_source(&source, &request);
        assert!(result.is_ok());
        let result = match result {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(result.output_text, "chat ok");
        assert_eq!(result.source_id, "openjarvis-mode-a");

        let join_result = handle.join();
        assert!(join_result.is_ok());
    }

    #[test]
    fn local_api_hardening_blocks_direct_db_surface_routes() {
        let source = SourceEntry {
            id: "mode-b-lmdb-attempt".to_string(),
            display_name: "Mode B LMDB Attempt".to_string(),
            kind: SourceKind::SidecarBridge,
            target: "http://127.0.0.1:8100/forge/bridge/v1/task?op=lmdb_read".to_string(),
            enabled: true,
            eligible_roles: vec![SourceRole::Chat],
            default_roles: vec![SourceRole::Chat],
            confidential_endpoint: None,
        };
        let request = ChatTaskRequest::new("probe local db route", 32);
        assert!(request.is_ok());
        let request = match request {
            Ok(value) => value,
            Err(_) => return,
        };
        let result = run_chat_task_with_source(&source, &request);
        assert!(result.is_err());
        let error = match result {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(error.contains("direct db/secret read surfaces are blocked"));
    }

    #[test]
    fn local_api_hardening_blocks_policy_and_telemetry_bypass_routes() {
        let source = SourceEntry {
            id: "mode-b-policy-bypass-attempt".to_string(),
            display_name: "Mode B Policy Bypass Attempt".to_string(),
            kind: SourceKind::SidecarBridge,
            target: "http://127.0.0.1:8100/forge/bridge/v1/task/admin/policy".to_string(),
            enabled: true,
            eligible_roles: vec![SourceRole::Chat],
            default_roles: vec![SourceRole::Chat],
            confidential_endpoint: None,
        };
        let request = ChatTaskRequest::new("probe policy bypass", 32);
        assert!(request.is_ok());
        let request = match request {
            Ok(value) => value,
            Err(_) => return,
        };
        let result = run_chat_task_with_source(&source, &request);
        assert!(result.is_err());
        let error = match result {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(error.contains("policy/telemetry bypass route is not allowed"));
    }

    #[test]
    fn provider_adapter_audit_records_provenance_for_local_and_remote_routes() {
        let local_source = SourceEntry {
            id: "audit-local-hardening".to_string(),
            display_name: "Audit Local".to_string(),
            kind: SourceKind::SidecarBridge,
            target: "http://127.0.0.1:8100/forge/bridge/v1/task?op=lmdb_read".to_string(),
            enabled: true,
            eligible_roles: vec![SourceRole::Chat],
            default_roles: vec![SourceRole::Chat],
            confidential_endpoint: None,
        };
        let remote_source = SourceEntry {
            id: "audit-remote-hardening".to_string(),
            display_name: "Audit Remote".to_string(),
            kind: SourceKind::ApiModel,
            target: "http://api.openai.com/v1".to_string(),
            enabled: true,
            eligible_roles: vec![SourceRole::Chat],
            default_roles: vec![SourceRole::Chat],
            confidential_endpoint: None,
        };
        let request = ChatTaskRequest::new("audit parity", 32);
        assert!(request.is_ok());
        let request = match request {
            Ok(value) => value,
            Err(_) => return,
        };
        let _ = run_chat_task_with_source(&local_source, &request);
        let _ = run_chat_task_with_source(&remote_source, &request);

        let events = latest_provider_adapter_audit_events(256);
        let local_event = events
            .iter()
            .rev()
            .find(|event| event.source_id == "audit-local-hardening");
        assert!(local_event.is_some());
        let local_event = match local_event {
            Some(value) => value,
            None => return,
        };
        assert!(matches!(
            local_event.route_class,
            ProviderAdapterRouteClass::LocalBridge
        ));
        assert_eq!(local_event.decision, ProviderAdapterAuditDecision::Denied);
        assert_eq!(
            local_event.trust_label,
            "trusted.local.api.bridge.policy_enforced"
        );
        assert!(local_event.provenance.starts_with("local-api://"));

        let remote_event = events
            .iter()
            .rev()
            .find(|event| event.source_id == "audit-remote-hardening");
        assert!(remote_event.is_some());
        let remote_event = match remote_event {
            Some(value) => value,
            None => return,
        };
        assert!(matches!(
            remote_event.route_class,
            ProviderAdapterRouteClass::RemoteApi
        ));
        assert_eq!(remote_event.decision, ProviderAdapterAuditDecision::Denied);
        assert_eq!(
            remote_event.trust_label,
            "trusted.remote.api.provider.policy_enforced"
        );
        assert!(remote_event.provenance.starts_with("remote-api://"));
    }

    #[test]
    fn confidential_chat_rejects_insecure_non_https_source() {
        let source = SourceEntry {
            id: "mode-a-local".to_string(),
            display_name: "Mode A Local".to_string(),
            kind: SourceKind::SidecarBridge,
            target: "http://127.0.0.1:8100/v1/chat/completions".to_string(),
            enabled: true,
            eligible_roles: vec![SourceRole::Chat],
            default_roles: vec![SourceRole::Chat],
            confidential_endpoint: None,
        };
        let now = 1_000_000;
        let measurement = "sha256:test";
        let nonce = "nonce-1";
        let request = ConfidentialChatTaskRequest {
            prompt: "hello".to_string(),
            max_tokens: 64,
            attestation: AttestationEvidence {
                provider: "forge-manual".to_string(),
                measurement: measurement.to_string(),
                nonce: nonce.to_string(),
                cpu_confidential: true,
                gpu_confidential: true,
                issued_at_unix_ms: now - 1_000,
                expires_at_unix_ms: now + 10_000,
                signature: "signed-evidence".to_string(),
            },
            policy: ConfidentialRelayPolicy {
                mode: ConfidentialRelayMode::Required,
                require_confidential_cpu: true,
                require_confidential_gpu: true,
                max_attestation_age_ms: 30_000,
            },
        };
        let mut store = ConfidentialRelaySessionStore::new();
        let result = run_confidential_chat_task_with_source(&source, &request, &mut store, now);
        assert!(result.is_err());
        assert!(store.latest_session().is_none());
    }

    #[test]
    fn confidential_chat_rejects_bad_attestation_before_request() {
        let verifier =
            spawn_attestation_verifier(r#"{"verified":false,"reason":"measurement mismatch"}"#);
        assert!(verifier.is_some());
        let (verifier_endpoint, handle) = match verifier {
            Some(value) => value,
            None => return,
        };
        let source = SourceEntry {
            id: "api-openai".to_string(),
            display_name: "OpenAI API".to_string(),
            kind: SourceKind::ApiModel,
            target: "https://api.openai.com/v1".to_string(),
            enabled: true,
            eligible_roles: vec![SourceRole::Chat],
            default_roles: vec![SourceRole::Chat],
            confidential_endpoint: Some(sample_confidential_endpoint(verifier_endpoint)),
        };
        let now = 2_000_000;
        let request = ConfidentialChatTaskRequest {
            prompt: "hello".to_string(),
            max_tokens: 64,
            attestation: AttestationEvidence {
                provider: "azure-teechat".to_string(),
                measurement: "sha256:trusted-attestation".to_string(),
                nonce: "nonce-2".to_string(),
                cpu_confidential: true,
                gpu_confidential: true,
                issued_at_unix_ms: now - 1_000,
                expires_at_unix_ms: now + 10_000,
                signature: "opaque-signature".to_string(),
            },
            policy: ConfidentialRelayPolicy {
                mode: ConfidentialRelayMode::Required,
                require_confidential_cpu: true,
                require_confidential_gpu: true,
                max_attestation_age_ms: 30_000,
            },
        };
        let mut store = ConfidentialRelaySessionStore::new();
        let result = run_confidential_chat_task_with_source(&source, &request, &mut store, now);
        assert!(result.is_err());
        assert!(store.latest_session().is_none());
        let _ = handle.join();
    }

    #[test]
    fn confidential_chat_rejects_replayed_nonce_from_active_session_history() {
        let source = SourceEntry {
            id: "api-openai".to_string(),
            display_name: "OpenAI API".to_string(),
            kind: SourceKind::ApiModel,
            target: "https://api.openai.com/v1".to_string(),
            enabled: true,
            eligible_roles: vec![SourceRole::Chat],
            default_roles: vec![SourceRole::Chat],
            confidential_endpoint: Some(sample_confidential_endpoint(
                "https://attest.example/verify".to_string(),
            )),
        };
        let now = 9_000_000;
        let mut store = ConfidentialRelaySessionStore::new();
        store.record_session(ConfidentialRelaySessionRecord {
            session_id: "relay-existing".to_string(),
            session_key_id: "relay-key-existing".to_string(),
            request_nonce: "nonce-replay".to_string(),
            source_id: source.id.clone(),
            source_display_name: source.display_name.clone(),
            route: "https://api.openai.com/v1/chat/completions".to_string(),
            transport_encrypted: true,
            verified_at_unix_ms: now - 1_000,
            expires_at_unix_ms: now + 30_000,
            attestation_verify_ms: 12,
            relay_roundtrip_ms: 25,
            total_path_ms: 38,
            attestation_provider: "azure-teechat".to_string(),
            measurement: "sha256:trusted-existing".to_string(),
            cpu_confidential: true,
            gpu_confidential: true,
            encryption_mode: RelayEncryptionMode::TlsHttps,
        });
        let request = ConfidentialChatTaskRequest {
            prompt: "hello".to_string(),
            max_tokens: 64,
            attestation: AttestationEvidence {
                provider: "azure-teechat".to_string(),
                measurement: "sha256:trusted-new".to_string(),
                nonce: "nonce-replay".to_string(),
                cpu_confidential: true,
                gpu_confidential: true,
                issued_at_unix_ms: now - 2_000,
                expires_at_unix_ms: now + 10_000,
                signature: "opaque-signature".to_string(),
            },
            policy: ConfidentialRelayPolicy {
                mode: ConfidentialRelayMode::Required,
                require_confidential_cpu: true,
                require_confidential_gpu: true,
                max_attestation_age_ms: 30_000,
            },
        };

        let result = run_confidential_chat_task_with_source(&source, &request, &mut store, now);
        assert!(result.is_err());
        let error = result.err().unwrap_or_default();
        assert!(error.contains("nonce replay"));
    }

    fn assert_role_task_routes_to_mode_b_sidecar_source(
        role: SourceRole,
        expected_kind: &str,
        prompt: &str,
    ) {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(value) => value,
            Err(_) => return,
        };
        let address = match listener.local_addr() {
            Ok(value) => value,
            Err(_) => return,
        };

        let expected_kind = expected_kind.to_string();
        let prompt_for_request = prompt.to_string();
        let prompt_for_assertion = prompt_for_request.clone();
        let handle = thread::spawn(move || {
            let accepted = listener.accept();
            assert!(accepted.is_ok());
            let (mut stream, _) = match accepted {
                Ok(value) => value,
                Err(_) => return,
            };
            let mut buffer = [0u8; 4096];
            let read = stream.read(&mut buffer).unwrap_or(0);
            let request = String::from_utf8_lossy(&buffer[..read]).to_string();
            assert!(request.contains("POST /forge/bridge/v1/task HTTP/1.1"));
            assert!(request.contains(&format!("\"kind\":\"{expected_kind}\"")));
            assert!(request.contains(&prompt_for_assertion));

            let body = r#"{"request_id":"role-1","status":"ok","result":{"text":"role ok","tokens_used":51}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        });

        let source = SourceEntry {
            id: "openjarvis-mode-b-sidecar".to_string(),
            display_name: "OpenJarvis Mode B Sidecar".to_string(),
            kind: SourceKind::SidecarBridge,
            target: format!("http://127.0.0.1:{}/forge/bridge/v1/task", address.port()),
            enabled: true,
            eligible_roles: vec![role],
            default_roles: vec![role],
            confidential_endpoint: None,
        };
        let request = RoleTaskRequest::new("role-1", prompt_for_request, 160);
        assert!(request.is_ok());
        let request = match request {
            Ok(value) => value,
            Err(_) => return,
        };
        let result = run_role_task_with_source(&source, role, &request);
        assert!(result.is_ok());
        let result = match result {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(result.output_text, "role ok");
        assert_eq!(result.tokens_used, Some(51));
        assert_eq!(result.source_id, "openjarvis-mode-b-sidecar");

        let join_result = handle.join();
        assert!(join_result.is_ok());
    }

    #[test]
    fn planner_role_task_routes_to_mode_b_sidecar_source() {
        assert_role_task_routes_to_mode_b_sidecar_source(
            SourceRole::Planner,
            "plan",
            "produce migration plan",
        );
    }

    #[test]
    fn debugger_role_task_routes_to_mode_b_sidecar_source() {
        assert_role_task_routes_to_mode_b_sidecar_source(
            SourceRole::Debugger,
            "debug",
            "find root cause for failure",
        );
    }

    #[test]
    fn verifier_role_task_routes_to_mode_b_sidecar_source() {
        assert_role_task_routes_to_mode_b_sidecar_source(
            SourceRole::Verifier,
            "verify",
            "validate release checklist",
        );
    }
}
