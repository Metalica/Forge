use sha2::{Digest, Sha256};
#[cfg(test)]
use std::cell::RefCell;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

type QuarantineResult<T = ()> = Result<T, String>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentResponseQuarantinePolicy {
    pub mode_enabled: bool,
    pub recovery_endpoint_allowlist: Vec<String>,
    pub marker_path: Option<String>,
    pub evidence_bundle_path: Option<String>,
    pub evidence_digest_path: Option<String>,
    pub require_reattestation_before_exit: bool,
    pub reattested: bool,
    pub reverified: bool,
    pub extensions_frozen: bool,
    pub mcp_frozen: bool,
    pub secret_handles_revoked: bool,
    pub caches_invalidated: bool,
    pub memory_lanes_invalidated: bool,
    pub relay_blocked: bool,
}

impl IncidentResponseQuarantinePolicy {
    pub fn from_env() -> Self {
        let recovery_endpoint_allowlist = env::var("FORGE_QUARANTINE_RECOVERY_ENDPOINTS")
            .ok()
            .map(|value| parse_csv_list(value.as_str()))
            .unwrap_or_default();
        let marker_path = read_optional_env("FORGE_QUARANTINE_MARKER_PATH");
        let evidence_bundle_path = read_optional_env("FORGE_QUARANTINE_EVIDENCE_BUNDLE_PATH");
        let evidence_digest_path = read_optional_env("FORGE_QUARANTINE_EVIDENCE_DIGEST_PATH");
        Self {
            mode_enabled: env_flag("FORGE_QUARANTINE_MODE").unwrap_or(false),
            recovery_endpoint_allowlist,
            marker_path,
            evidence_bundle_path,
            evidence_digest_path,
            require_reattestation_before_exit: env_flag(
                "FORGE_QUARANTINE_REQUIRE_REATTESTATION_BEFORE_EXIT",
            )
            .unwrap_or(true),
            reattested: env_flag("FORGE_QUARANTINE_REATTESTED").unwrap_or(false),
            reverified: env_flag("FORGE_QUARANTINE_REVERIFIED").unwrap_or(false),
            extensions_frozen: env_flag("FORGE_QUARANTINE_EXTENSIONS_FROZEN").unwrap_or(false),
            mcp_frozen: env_flag("FORGE_QUARANTINE_MCP_FROZEN").unwrap_or(false),
            secret_handles_revoked: env_flag("FORGE_QUARANTINE_SECRET_HANDLES_REVOKED")
                .unwrap_or(false),
            caches_invalidated: env_flag("FORGE_QUARANTINE_CACHES_INVALIDATED").unwrap_or(false),
            memory_lanes_invalidated: env_flag("FORGE_QUARANTINE_MEMORY_LANES_INVALIDATED")
                .unwrap_or(false),
            relay_blocked: env_flag("FORGE_QUARANTINE_RELAY_BLOCKED").unwrap_or(true),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentResponseQuarantineDecision {
    pub mode_enabled: bool,
    pub recovery_endpoint_allowed: bool,
    pub reattested: bool,
    pub reverified: bool,
}

pub fn enforce_incident_response_quarantine(
    route_label: &str,
    endpoint: &str,
    relay_requested: bool,
) -> QuarantineResult<IncidentResponseQuarantineDecision> {
    let policy = current_policy();
    enforce_incident_response_quarantine_with_policy(
        route_label,
        endpoint,
        relay_requested,
        &policy,
    )
}

#[cfg(not(test))]
fn current_policy() -> IncidentResponseQuarantinePolicy {
    IncidentResponseQuarantinePolicy::from_env()
}

#[cfg(test)]
fn current_policy() -> IncidentResponseQuarantinePolicy {
    let overridden = TEST_POLICY_OVERRIDE.with(|slot| slot.borrow().clone());
    if let Some(policy) = overridden {
        return policy;
    }
    IncidentResponseQuarantinePolicy::from_env()
}

#[cfg(test)]
thread_local! {
    #[allow(clippy::missing_const_for_thread_local)]
    static TEST_POLICY_OVERRIDE: RefCell<Option<IncidentResponseQuarantinePolicy>> = RefCell::new(None);
}

#[cfg(test)]
pub(crate) fn set_test_policy_override(policy: Option<IncidentResponseQuarantinePolicy>) {
    TEST_POLICY_OVERRIDE.with(|slot| {
        *slot.borrow_mut() = policy;
    });
}

fn enforce_incident_response_quarantine_with_policy(
    route_label: &str,
    endpoint: &str,
    relay_requested: bool,
    policy: &IncidentResponseQuarantinePolicy,
) -> QuarantineResult<IncidentResponseQuarantineDecision> {
    let marker_present = policy
        .marker_path
        .as_ref()
        .map(|path| Path::new(path.as_str()).exists())
        .unwrap_or(false);
    let recovery_endpoint_allowed =
        endpoint_is_allowlisted(endpoint, policy.recovery_endpoint_allowlist.as_slice());

    if policy.mode_enabled {
        if !policy.extensions_frozen {
            return Err(format!(
                "incident-response quarantine blocked {route_label}: extensions are not frozen"
            ));
        }
        if !policy.mcp_frozen {
            return Err(format!(
                "incident-response quarantine blocked {route_label}: MCP is not frozen"
            ));
        }
        if !policy.secret_handles_revoked {
            return Err(format!(
                "incident-response quarantine blocked {route_label}: active secret handles are not revoked"
            ));
        }
        if !policy.caches_invalidated || !policy.memory_lanes_invalidated {
            return Err(format!(
                "incident-response quarantine blocked {route_label}: cache/memory invalidation is incomplete"
            ));
        }
        if !marker_present {
            return Err(format!(
                "incident-response quarantine blocked {route_label}: quarantine marker is missing"
            ));
        }
        ensure_tamper_evident_evidence_bundle(policy, route_label)?;
        if !policy.relay_blocked {
            return Err(format!(
                "incident-response quarantine blocked {route_label}: relay-block control is disabled"
            ));
        }
        if relay_requested {
            return Err(format!(
                "incident-response quarantine blocked {route_label}: relay mode is disabled during quarantine"
            ));
        }
        if !recovery_endpoint_allowed {
            return Err(format!(
                "incident-response quarantine blocked {route_label}: endpoint is not in recovery allow-list"
            ));
        }
    } else if marker_present
        && policy.require_reattestation_before_exit
        && (!policy.reattested || !policy.reverified)
    {
        return Err(format!(
            "incident-response quarantine blocked {route_label}: re-attestation and re-verification are required before leaving quarantine"
        ));
    }

    Ok(IncidentResponseQuarantineDecision {
        mode_enabled: policy.mode_enabled,
        recovery_endpoint_allowed,
        reattested: policy.reattested,
        reverified: policy.reverified,
    })
}

fn ensure_tamper_evident_evidence_bundle(
    policy: &IncidentResponseQuarantinePolicy,
    route_label: &str,
) -> QuarantineResult {
    let bundle_path = policy
        .evidence_bundle_path
        .as_ref()
        .ok_or_else(|| {
            format!(
                "incident-response quarantine blocked {route_label}: evidence bundle path is not configured"
            )
        })?
        .trim()
        .to_string();
    if bundle_path.is_empty() || !Path::new(bundle_path.as_str()).exists() {
        return Err(format!(
            "incident-response quarantine blocked {route_label}: evidence bundle is missing"
        ));
    }

    let digest_path = policy
        .evidence_digest_path
        .as_ref()
        .ok_or_else(|| {
            format!(
                "incident-response quarantine blocked {route_label}: evidence digest path is not configured"
            )
        })?
        .trim()
        .to_string();
    if digest_path.is_empty() || !Path::new(digest_path.as_str()).exists() {
        return Err(format!(
            "incident-response quarantine blocked {route_label}: evidence digest file is missing"
        ));
    }

    let actual_digest = compute_sha256_hex(bundle_path.as_str())?;
    let expected_digest = read_expected_digest(digest_path.as_str())?;
    if actual_digest != expected_digest {
        return Err(format!(
            "incident-response quarantine blocked {route_label}: evidence digest mismatch detected"
        ));
    }
    Ok(())
}

fn compute_sha256_hex(path: &str) -> QuarantineResult<String> {
    let bytes = fs::read(path).map_err(|error| {
        format!("failed to read evidence bundle for digest calculation: {error}")
    })?;
    let digest = Sha256::digest(bytes.as_slice());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    Ok(hex)
}

fn read_expected_digest(path: &str) -> QuarantineResult<String> {
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("failed to read evidence digest file: {error}"))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("evidence digest file is empty".to_string());
    }

    if trimmed.starts_with('{')
        && let Ok(parsed) = serde_json::from_str::<serde_json::Value>(trimmed)
    {
        let maybe = parsed
            .get("sha256")
            .and_then(serde_json::Value::as_str)
            .or_else(|| parsed.get("digest").and_then(serde_json::Value::as_str));
        if let Some(value) = maybe {
            return Ok(normalize_digest(value));
        }
    }

    Ok(normalize_digest(trimmed))
}

fn normalize_digest(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("sha256:")
        .to_ascii_lowercase()
}

fn endpoint_is_allowlisted(endpoint: &str, allowlist: &[String]) -> bool {
    let normalized_endpoint = endpoint.trim().to_ascii_lowercase();
    if normalized_endpoint.is_empty() {
        return false;
    }
    allowlist
        .iter()
        .map(|prefix| prefix.trim())
        .filter(|prefix| !prefix.is_empty())
        .any(|prefix| is_safe_allowlist_prefix_match(&normalized_endpoint, prefix))
}

fn is_safe_allowlist_prefix_match(endpoint: &str, prefix: &str) -> bool {
    if !endpoint.starts_with(prefix) {
        return false;
    }
    if prefix.ends_with('/') {
        return true;
    }
    let remainder = &endpoint[prefix.len()..];
    remainder.is_empty()
        || remainder.starts_with('/')
        || remainder.starts_with('?')
        || remainder.starts_with('#')
}

fn parse_csv_list(raw: &str) -> Vec<String> {
    raw.split([';', ','])
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
}

fn read_optional_env(name: &str) -> Option<String> {
    env::var(name).ok().and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn env_flag(name: &str) -> Option<bool> {
    let raw = env::var(name).ok()?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        IncidentResponseQuarantinePolicy, enforce_incident_response_quarantine,
        set_test_policy_override,
    };
    use sha2::Digest;
    use std::env;
    use std::fs;

    fn sample_policy(root: &str) -> IncidentResponseQuarantinePolicy {
        IncidentResponseQuarantinePolicy {
            mode_enabled: true,
            recovery_endpoint_allowlist: vec!["https://recovery.example".to_string()],
            marker_path: Some(format!("{root}/QUARANTINE_MODE.flag")),
            evidence_bundle_path: Some(format!("{root}/evidence_bundle.json")),
            evidence_digest_path: Some(format!("{root}/evidence_bundle.sha256")),
            require_reattestation_before_exit: true,
            reattested: false,
            reverified: false,
            extensions_frozen: true,
            mcp_frozen: true,
            secret_handles_revoked: true,
            caches_invalidated: true,
            memory_lanes_invalidated: true,
            relay_blocked: true,
        }
    }

    fn write_bundle_and_digest(root: &str, tamper_digest: bool) {
        let _ = fs::create_dir_all(root);
        let marker_path = format!("{root}/QUARANTINE_MODE.flag");
        let bundle_path = format!("{root}/evidence_bundle.json");
        let digest_path = format!("{root}/evidence_bundle.sha256");
        let _ = fs::write(marker_path, "quarantine");
        let _ = fs::write(bundle_path.as_str(), "{\"ok\":true}");

        let digest = sha2::Sha256::digest(b"{\"ok\":true}");
        let mut hex = String::new();
        for byte in digest {
            hex.push_str(format!("{byte:02x}").as_str());
        }
        if tamper_digest {
            let _ = fs::write(digest_path, "0000");
        } else {
            let _ = fs::write(digest_path, hex);
        }
    }

    #[test]
    fn quarantine_blocks_non_recovery_endpoint() {
        let root = env::temp_dir()
            .join("forge_incident_quarantine_non_recovery")
            .to_string_lossy()
            .to_string();
        write_bundle_and_digest(root.as_str(), false);
        set_test_policy_override(Some(sample_policy(root.as_str())));
        let result = enforce_incident_response_quarantine(
            "chat.remote_api",
            "https://api.openai.com/v1/chat/completions",
            false,
        );
        set_test_policy_override(None);
        assert!(result.is_err());
        let error = result.err().unwrap_or_default();
        assert!(error.contains("recovery allow-list"));
    }

    #[test]
    fn quarantine_allows_recovery_endpoint_when_controls_are_satisfied() {
        let root = env::temp_dir()
            .join("forge_incident_quarantine_recovery_allowed")
            .to_string_lossy()
            .to_string();
        write_bundle_and_digest(root.as_str(), false);
        set_test_policy_override(Some(sample_policy(root.as_str())));
        let result = enforce_incident_response_quarantine(
            "chat.recovery",
            "https://recovery.example/attestation/verify",
            false,
        );
        set_test_policy_override(None);
        assert!(result.is_ok());
        if let Ok(decision) = result {
            assert!(decision.mode_enabled);
            assert!(decision.recovery_endpoint_allowed);
        }
    }

    #[test]
    fn quarantine_blocks_relay_requests() {
        let root = env::temp_dir()
            .join("forge_incident_quarantine_relay_block")
            .to_string_lossy()
            .to_string();
        write_bundle_and_digest(root.as_str(), false);
        set_test_policy_override(Some(sample_policy(root.as_str())));
        let result = enforce_incident_response_quarantine(
            "chat.confidential_relay",
            "https://recovery.example/attestation/verify",
            true,
        );
        set_test_policy_override(None);
        assert!(result.is_err());
        let error = result.err().unwrap_or_default();
        assert!(error.contains("relay mode is disabled"));
    }

    #[test]
    fn quarantine_exit_requires_reattestation_and_reverification_when_marker_exists() {
        let root = env::temp_dir()
            .join("forge_incident_quarantine_exit_requirements")
            .to_string_lossy()
            .to_string();
        write_bundle_and_digest(root.as_str(), false);
        let mut policy = sample_policy(root.as_str());
        policy.mode_enabled = false;
        set_test_policy_override(Some(policy));
        let result = enforce_incident_response_quarantine(
            "chat.remote_api",
            "https://api.openai.com/v1/chat/completions",
            false,
        );
        set_test_policy_override(None);
        assert!(result.is_err());
        let error = result.err().unwrap_or_default();
        assert!(error.contains("re-attestation"));
    }

    #[test]
    fn quarantine_blocks_tampered_evidence_bundle_digest() {
        let root = env::temp_dir()
            .join("forge_incident_quarantine_tamper")
            .to_string_lossy()
            .to_string();
        write_bundle_and_digest(root.as_str(), true);
        set_test_policy_override(Some(sample_policy(root.as_str())));
        let result = enforce_incident_response_quarantine(
            "chat.recovery",
            "https://recovery.example/attestation/verify",
            false,
        );
        set_test_policy_override(None);
        assert!(result.is_err());
        let error = result.err().unwrap_or_default();
        assert!(error.contains("digest mismatch"));
    }

    #[test]
    fn quarantine_blocks_deceptive_recovery_prefix_endpoint() {
        let root = env::temp_dir()
            .join("forge_incident_quarantine_deceptive_prefix")
            .to_string_lossy()
            .to_string();
        write_bundle_and_digest(root.as_str(), false);
        set_test_policy_override(Some(sample_policy(root.as_str())));
        let result = enforce_incident_response_quarantine(
            "chat.recovery",
            "https://recovery.example.evil.com/attestation/verify",
            false,
        );
        set_test_policy_override(None);
        assert!(result.is_err());
        let error = result.err().unwrap_or_default();
        assert!(error.contains("recovery allow-list"));
    }
}
