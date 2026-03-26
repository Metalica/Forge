use crate::source_registry::{SourceEntry, SourceKind};
use std::sync::{Mutex, OnceLock};

const MAX_PROVIDER_ADAPTER_AUDIT_EVENTS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderAdapterRouteClass {
    LocalBridge,
    RemoteApi,
}

impl ProviderAdapterRouteClass {
    pub const fn label(self) -> &'static str {
        match self {
            ProviderAdapterRouteClass::LocalBridge => "local_bridge",
            ProviderAdapterRouteClass::RemoteApi => "remote_api",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderAdapterAuditDecision {
    Allowed,
    Denied,
}

impl ProviderAdapterAuditDecision {
    pub const fn label(self) -> &'static str {
        match self {
            ProviderAdapterAuditDecision::Allowed => "allowed",
            ProviderAdapterAuditDecision::Denied => "denied",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAdapterAuditEvent {
    pub operation: String,
    pub source_id: String,
    pub source_kind: String,
    pub target: String,
    pub route_class: ProviderAdapterRouteClass,
    pub trust_label: String,
    pub provenance: String,
    pub decision: ProviderAdapterAuditDecision,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderAdapterRouteContext {
    route_class: ProviderAdapterRouteClass,
    trust_label: String,
    provenance: String,
}

static PROVIDER_ADAPTER_AUDIT_EVENTS: OnceLock<Mutex<Vec<ProviderAdapterAuditEvent>>> =
    OnceLock::new();

fn provider_adapter_audit_log() -> &'static Mutex<Vec<ProviderAdapterAuditEvent>> {
    PROVIDER_ADAPTER_AUDIT_EVENTS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn latest_provider_adapter_audit_events(limit: usize) -> Vec<ProviderAdapterAuditEvent> {
    if limit == 0 {
        return Vec::new();
    }
    let guard = match provider_adapter_audit_log().lock() {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    let start = guard.len().saturating_sub(limit);
    guard[start..].to_vec()
}

pub fn guard_and_audit_provider_route<T, F>(
    source: &SourceEntry,
    operation: &str,
    action: F,
) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String>,
{
    let context = build_route_context(source);
    if let Err(error) = enforce_local_api_hardening(source, &context) {
        record_provider_adapter_audit_event(
            source,
            operation,
            &context,
            ProviderAdapterAuditDecision::Denied,
            error.as_str(),
        );
        return Err(error);
    }

    match action() {
        Ok(value) => {
            record_provider_adapter_audit_event(
                source,
                operation,
                &context,
                ProviderAdapterAuditDecision::Allowed,
                "provider adapter route completed",
            );
            Ok(value)
        }
        Err(error) => {
            record_provider_adapter_audit_event(
                source,
                operation,
                &context,
                ProviderAdapterAuditDecision::Denied,
                error.as_str(),
            );
            Err(error)
        }
    }
}

fn build_route_context(source: &SourceEntry) -> ProviderAdapterRouteContext {
    let route_class = if is_local_bridge_source(source) {
        ProviderAdapterRouteClass::LocalBridge
    } else {
        ProviderAdapterRouteClass::RemoteApi
    };
    match route_class {
        ProviderAdapterRouteClass::LocalBridge => ProviderAdapterRouteContext {
            route_class,
            trust_label: "trusted.local.api.bridge.policy_enforced".to_string(),
            provenance: format!("local-api://{}", source.id),
        },
        ProviderAdapterRouteClass::RemoteApi => ProviderAdapterRouteContext {
            route_class,
            trust_label: "trusted.remote.api.provider.policy_enforced".to_string(),
            provenance: format!("remote-api://{}", source.id),
        },
    }
}

fn enforce_local_api_hardening(
    source: &SourceEntry,
    context: &ProviderAdapterRouteContext,
) -> Result<(), String> {
    if !matches!(context.route_class, ProviderAdapterRouteClass::LocalBridge) {
        return Ok(());
    }
    let target_lower = source.target.trim().to_ascii_lowercase();
    if looks_like_db_or_secret_read_surface(target_lower.as_str()) {
        return Err(format!(
            "local API hardening blocked source {}: direct db/secret read surfaces are blocked",
            source.id
        ));
    }
    if looks_like_policy_or_telemetry_bypass_surface(target_lower.as_str()) {
        return Err(format!(
            "local API hardening blocked source {}: policy/telemetry bypass route is not allowed",
            source.id
        ));
    }
    if !is_allowlisted_local_bridge_route(target_lower.as_str()) {
        return Err(format!(
            "local API hardening blocked source {}: local route must be mode-a /v1 chat or mode-b task bridge",
            source.id
        ));
    }
    Ok(())
}

fn is_local_bridge_source(source: &SourceEntry) -> bool {
    matches!(source.kind, SourceKind::SidecarBridge)
        || (matches!(source.kind, SourceKind::ApiModel)
            && is_localhost_http_endpoint(source.target.as_str()))
}

fn is_localhost_http_endpoint(target: &str) -> bool {
    let trimmed = target.trim();
    let without_scheme = trimmed.strip_prefix("http://").unwrap_or(trimmed);
    let authority = without_scheme.split('/').next().unwrap_or_default();
    let host = authority.split(':').next().unwrap_or_default().trim();
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

fn is_allowlisted_local_bridge_route(target_lower: &str) -> bool {
    target_lower.contains("/forge/bridge/v1/task")
        || target_lower.contains("/bridge/v1/task")
        || target_lower.contains("/v1/chat/completions")
        || target_lower.ends_with("/v1")
        || target_lower.ends_with("/v1/")
}

fn looks_like_db_or_secret_read_surface(target_lower: &str) -> bool {
    [
        "lmdb",
        "leveldb",
        "rocksdb",
        "sqlite",
        ".db",
        ".mdb",
        "secret-handle",
        "/secrets",
        "secret_store",
        "broker",
    ]
    .iter()
    .any(|token| target_lower.contains(token))
}

fn looks_like_policy_or_telemetry_bypass_surface(target_lower: &str) -> bool {
    [
        "/policy",
        "/telemetry",
        "/metrics",
        "/admin/policy",
        "/admin/telemetry",
        "/trace/export",
    ]
    .iter()
    .any(|token| target_lower.contains(token))
}

fn record_provider_adapter_audit_event(
    source: &SourceEntry,
    operation: &str,
    context: &ProviderAdapterRouteContext,
    decision: ProviderAdapterAuditDecision,
    detail: &str,
) {
    let event = ProviderAdapterAuditEvent {
        operation: clip_text(operation.trim(), 48),
        source_id: source.id.clone(),
        source_kind: match source.kind {
            SourceKind::LocalModel => "local_model".to_string(),
            SourceKind::ApiModel => "api_model".to_string(),
            SourceKind::SidecarBridge => "sidecar_bridge".to_string(),
        },
        target: clip_text(source.target.trim(), 160),
        route_class: context.route_class,
        trust_label: context.trust_label.clone(),
        provenance: context.provenance.clone(),
        decision,
        detail: clip_text(detail.trim(), 240),
    };
    let mut guard = match provider_adapter_audit_log().lock() {
        Ok(value) => value,
        Err(_) => return,
    };
    guard.push(event);
    if guard.len() > MAX_PROVIDER_ADAPTER_AUDIT_EVENTS {
        let overflow = guard
            .len()
            .saturating_sub(MAX_PROVIDER_ADAPTER_AUDIT_EVENTS);
        guard.drain(0..overflow);
    }
}

fn clip_text(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    value.chars().take(max_chars).collect::<String>() + "..."
}
