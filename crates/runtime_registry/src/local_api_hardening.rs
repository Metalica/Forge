use crate::source_registry::{SourceEntry, SourceKind};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_PROVIDER_ADAPTER_AUDIT_EVENTS: usize = 4096;
const PROVIDER_ADAPTER_AUDIT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderAdapterAuditEvent {
    pub at_unix_ms: u64,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedProviderAdapterAuditLog {
    schema_version: u32,
    events: Vec<ProviderAdapterAuditEvent>,
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

pub fn save_redacted_provider_adapter_audit_events_to_path(path: &Path) -> Result<(), String> {
    let events = {
        let guard = provider_adapter_audit_log()
            .lock()
            .map_err(|_| "provider adapter audit log lock poisoned".to_string())?;
        guard.clone()
    };
    let payload = PersistedProviderAdapterAuditLog {
        schema_version: PROVIDER_ADAPTER_AUDIT_SCHEMA_VERSION,
        events,
    };
    let encoded = serde_json::to_string_pretty(&payload)
        .map_err(|error| format!("provider adapter audit serialization failed: {error}"))?;
    fs::write(path, encoded).map_err(|error| {
        format!(
            "provider adapter audit write failed at {}: {error}",
            path.display()
        )
    })
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
    let normalized_target = normalize_target_for_policy_scan(source.target.as_str());
    if looks_like_db_or_secret_read_surface(normalized_target.as_str()) {
        return Err(format!(
            "local API hardening blocked source {}: direct db/secret read surfaces are blocked",
            source.id
        ));
    }
    if looks_like_policy_or_telemetry_bypass_surface(normalized_target.as_str()) {
        return Err(format!(
            "local API hardening blocked source {}: policy/telemetry bypass route is not allowed",
            source.id
        ));
    }
    let normalized_path = normalize_target_path(normalized_target.as_str());
    if !is_allowlisted_local_bridge_route(normalized_path.as_str()) {
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
    target_lower.ends_with("/forge/bridge/v1/task")
        || target_lower.ends_with("/bridge/v1/task")
        || target_lower.ends_with("/v1/chat/completions")
        || target_lower.ends_with("/v1")
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
    let sanitized_target = sanitize_target_for_audit(source.target.as_str());
    let event = ProviderAdapterAuditEvent {
        at_unix_ms: now_unix_ms(),
        operation: clip_text(operation.trim(), 48),
        source_id: clip_text(redact_secret_like_tokens(source.id.as_str()).as_str(), 96),
        source_kind: match source.kind {
            SourceKind::LocalModel => "local_model".to_string(),
            SourceKind::ApiModel => "api_model".to_string(),
            SourceKind::SidecarBridge => "sidecar_bridge".to_string(),
        },
        target: clip_text(
            redact_secret_like_tokens(sanitized_target.as_str()).as_str(),
            160,
        ),
        route_class: context.route_class,
        trust_label: clip_text(
            redact_secret_like_tokens(context.trust_label.as_str()).as_str(),
            160,
        ),
        provenance: clip_text(
            redact_secret_like_tokens(context.provenance.as_str()).as_str(),
            240,
        ),
        decision,
        detail: clip_text(redact_secret_like_tokens(detail.trim()).as_str(), 240),
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

fn redact_secret_like_tokens(input: &str) -> String {
    let mut output = input.to_string();
    output = redact_prefixed_tokens(output.as_str(), "sk-", 20);
    output = redact_prefixed_tokens(output.as_str(), "bearer ", 24);
    output = redact_prefixed_tokens(output.as_str(), "authorization: bearer ", 24);
    output
}

fn redact_prefixed_tokens(input: &str, prefix: &str, min_token_len: usize) -> String {
    let mut output = String::with_capacity(input.len());
    let lowercase = input.to_ascii_lowercase();
    let mut index = 0usize;
    while index < input.len() {
        let remaining = &lowercase[index..];
        if remaining.starts_with(prefix) {
            let token_end = find_token_boundary(input, index + prefix.len());
            if token_end.saturating_sub(index) >= min_token_len {
                output.push_str("[REDACTED]");
                index = token_end;
                continue;
            }
        }
        if let Some(ch) = input[index..].chars().next() {
            output.push(ch);
            index += ch.len_utf8();
        } else {
            break;
        }
    }
    output
}

fn find_token_boundary(value: &str, start: usize) -> usize {
    let mut end = start;
    while end < value.len() {
        let Some(ch) = value[end..].chars().next() else {
            break;
        };
        if ch.is_whitespace() || ch == '"' || ch == '\'' || ch == ',' || ch == ';' {
            break;
        }
        end += ch.len_utf8();
    }
    end
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn normalize_target_for_policy_scan(target: &str) -> String {
    let mut value = target.trim().to_string();
    for _ in 0..3 {
        let next = decode_percent_encoding_once(value.as_str());
        if next == value {
            break;
        }
        value = next;
    }
    value.to_ascii_lowercase()
}

fn decode_percent_encoding_once(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = String::with_capacity(value.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let (Some(hi), Some(lo)) =
                (hex_nibble(bytes[index + 1]), hex_nibble(bytes[index + 2]))
        {
            let byte = (hi << 4) | lo;
            if byte.is_ascii() {
                output.push(char::from(byte));
            } else {
                output.push('%');
                output.push(char::from(bytes[index + 1]));
                output.push(char::from(bytes[index + 2]));
            }
            index += 3;
            continue;
        }
        output.push(char::from(bytes[index]));
        index += 1;
    }
    output
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn normalize_target_path(target: &str) -> String {
    let trimmed = target.trim();
    let without_scheme = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .unwrap_or(trimmed);
    let raw_path = if let Some((_, path_with_suffix)) = without_scheme.split_once('/') {
        format!("/{}", path_with_suffix)
    } else {
        "/".to_string()
    };
    let path_without_query_or_fragment = raw_path
        .split(['?', '#'])
        .next()
        .unwrap_or("/")
        .trim()
        .to_string();
    normalize_route_path(path_without_query_or_fragment.as_str())
}

fn normalize_route_path(path: &str) -> String {
    let mut normalized_segments = Vec::new();
    for segment in path.split('/') {
        let trimmed = segment.trim();
        if trimmed.is_empty() || trimmed == "." {
            continue;
        }
        if trimmed == ".." {
            let _ = normalized_segments.pop();
            continue;
        }
        normalized_segments.push(trimmed);
    }
    if normalized_segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", normalized_segments.join("/"))
    }
}

fn sanitize_target_for_audit(target: &str) -> String {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let without_fragment = trimmed.split('#').next().unwrap_or_default();
    let without_query = without_fragment.split('?').next().unwrap_or_default();
    if let Some((scheme, rest)) = without_query.split_once("://") {
        if let Some((authority, path)) = rest.split_once('/') {
            let safe_authority = strip_authority_userinfo(authority);
            return format!(
                "{scheme}://{safe_authority}/{}",
                path.trim_start_matches('/')
            );
        }
        let safe_authority = strip_authority_userinfo(rest);
        return format!("{scheme}://{safe_authority}");
    }
    without_query.to_string()
}

fn strip_authority_userinfo(authority: &str) -> String {
    authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority)
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        ProviderAdapterAuditDecision, guard_and_audit_provider_route,
        latest_provider_adapter_audit_events, save_redacted_provider_adapter_audit_events_to_path,
    };
    use crate::source_registry::{SourceEntry, SourceKind, SourceRole};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_path(prefix: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        path.push(format!("forge_provider_audit_{prefix}_{nonce}.json"));
        path
    }

    #[test]
    fn hardening_blocks_allowlist_bypass_when_allowed_path_appears_only_in_query() {
        let source = SourceEntry {
            id: "query-allowlist-bypass-attempt".to_string(),
            display_name: "Query Allowlist Bypass Attempt".to_string(),
            kind: SourceKind::SidecarBridge,
            target: "http://127.0.0.1:8100/admin/debug?next=/v1/chat/completions".to_string(),
            enabled: true,
            eligible_roles: vec![SourceRole::Chat],
            default_roles: vec![SourceRole::Chat],
            confidential_endpoint: None,
        };

        let result = guard_and_audit_provider_route(&source, "chat", || Ok(()));
        assert!(result.is_err());
        let error = result.err().unwrap_or_default();
        assert!(error.contains("local route must be mode-a /v1 chat or mode-b task bridge"));
    }

    #[test]
    fn hardening_blocks_percent_encoded_db_probe_tokens() {
        let source = SourceEntry {
            id: "encoded-db-probe-attempt".to_string(),
            display_name: "Encoded DB Probe Attempt".to_string(),
            kind: SourceKind::SidecarBridge,
            target: "http://127.0.0.1:8100/forge/bridge/v1/task?op=%256c%256d%2564%2562_read"
                .to_string(),
            enabled: true,
            eligible_roles: vec![SourceRole::Chat],
            default_roles: vec![SourceRole::Chat],
            confidential_endpoint: None,
        };

        let result = guard_and_audit_provider_route(&source, "chat", || Ok(()));
        assert!(result.is_err());
        let error = result.err().unwrap_or_default();
        assert!(error.contains("direct db/secret read surfaces are blocked"));
    }

    #[test]
    fn audit_target_redacts_credentials_query_and_fragment() {
        let source_id = "audit-redaction-check";
        let source = SourceEntry {
            id: source_id.to_string(),
            display_name: "Audit Redaction Check".to_string(),
            kind: SourceKind::ApiModel,
            target: "https://forge-user:forge-pass@api.openai.com/v1/chat/completions?api_key=sk-test-secret#inline-fragment".to_string(),
            enabled: true,
            eligible_roles: vec![SourceRole::Chat],
            default_roles: vec![SourceRole::Chat],
            confidential_endpoint: None,
        };

        let _: Result<(), String> =
            guard_and_audit_provider_route(&source, "chat", || Err("synthetic deny".to_string()));
        let events = latest_provider_adapter_audit_events(128);
        let maybe_event = events.iter().rev().find(|event| {
            event.source_id == source_id && event.decision == ProviderAdapterAuditDecision::Denied
        });
        assert!(maybe_event.is_some());
        let event = match maybe_event {
            Some(value) => value,
            None => return,
        };
        assert_eq!(event.target, "https://api.openai.com/v1/chat/completions");
        assert!(!event.target.contains("forge-user"));
        assert!(!event.target.contains("api_key"));
        assert!(!event.target.contains("sk-test-secret"));
    }

    #[test]
    fn exported_provider_audit_log_redacts_secret_like_detail_tokens() {
        let source = SourceEntry {
            id: "provider-audit-export-redaction".to_string(),
            display_name: "Provider Audit Export Redaction".to_string(),
            kind: SourceKind::ApiModel,
            target: "https://api.openai.com/v1/chat/completions".to_string(),
            enabled: true,
            eligible_roles: vec![SourceRole::Chat],
            default_roles: vec![SourceRole::Chat],
            confidential_endpoint: None,
        };
        let _: Result<(), String> = guard_and_audit_provider_route(&source, "chat", || {
            Err("authorization: bearer sk-live-secret-token-1234567890".to_string())
        });

        let path = unique_temp_path("export_redaction");
        let saved = save_redacted_provider_adapter_audit_events_to_path(path.as_path());
        assert!(saved.is_ok());

        let raw = fs::read_to_string(path.as_path());
        assert!(raw.is_ok());
        let raw = match raw {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(raw.contains("\"schema_version\""));
        assert!(raw.contains("[REDACTED]"));
        assert!(!raw.contains("sk-live-secret-token-1234567890"));

        let _ = fs::remove_file(path);
    }
}
