use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExtensionClass {
    Viewer,
    Tool,
    ImportExport,
    ModelProvider,
    Agent,
    WorkflowNode,
}

impl ExtensionClass {
    pub const fn label(self) -> &'static str {
        match self {
            ExtensionClass::Viewer => "viewer",
            ExtensionClass::Tool => "tool",
            ExtensionClass::ImportExport => "import_export",
            ExtensionClass::ModelProvider => "model_provider",
            ExtensionClass::Agent => "agent",
            ExtensionClass::WorkflowNode => "workflow_node",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExtensionPermission {
    FilesystemEdits,
    Shell,
    Network,
    Git,
    ModelDownloads,
    ExternalApis,
}

impl ExtensionPermission {
    pub const fn label(self) -> &'static str {
        match self {
            ExtensionPermission::FilesystemEdits => "filesystem_edits",
            ExtensionPermission::Shell => "shell",
            ExtensionPermission::Network => "network",
            ExtensionPermission::Git => "git",
            ExtensionPermission::ModelDownloads => "model_downloads",
            ExtensionPermission::ExternalApis => "external_apis",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionManifestSignature {
    pub key_id: String,
    pub algorithm: String,
    pub value: String,
}

impl ExtensionManifestSignature {
    fn is_complete(&self) -> bool {
        !self.key_id.trim().is_empty()
            && !self.algorithm.trim().is_empty()
            && !self.value.trim().is_empty()
    }
}

fn default_manifest_publisher() -> String {
    "unknown".to_string()
}

fn default_manifest_version() -> String {
    "0.0.0".to_string()
}

fn default_manifest_minimum_forge_version() -> String {
    "0.0.0".to_string()
}

fn parse_semver_core(version: &str) -> Option<(u32, u32, u32)> {
    let normalized = version.trim().trim_start_matches('v');
    let core = normalized.split(['-', '+']).next()?.trim();
    if core.is_empty() {
        return None;
    }
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next().unwrap_or("0").parse::<u32>().ok()?;
    let patch = parts.next().unwrap_or("0").parse::<u32>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|candidate| candidate.is_ascii_hexdigit())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionSecurityGateError {
    UnsignedManifest,
    RevokedManifest,
    IncompatibleForgeVersion { minimum: String, current: String },
    MissingMetadata(&'static str),
}

impl fmt::Display for ExtensionSecurityGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtensionSecurityGateError::UnsignedManifest => {
                f.write_str("unsigned manifest blocked")
            }
            ExtensionSecurityGateError::RevokedManifest => {
                f.write_str("manifest revoked by publisher")
            }
            ExtensionSecurityGateError::IncompatibleForgeVersion { minimum, current } => write!(
                f,
                "requires Forge version {minimum} or newer (current={current})"
            ),
            ExtensionSecurityGateError::MissingMetadata(field) => {
                write!(f, "manifest missing required metadata: {field}")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionManifest {
    pub id: String,
    pub display_name: String,
    #[serde(default = "default_manifest_publisher")]
    pub publisher: String,
    #[serde(default = "default_manifest_version")]
    pub version: String,
    #[serde(default = "default_manifest_minimum_forge_version")]
    pub minimum_forge_version: String,
    #[serde(default)]
    pub package_checksum_sha256: String,
    pub class: ExtensionClass,
    pub idle_cost_mb: u32,
    pub startup_cost_ms: u32,
    pub memory_budget_mb: u32,
    pub cpu_budget_percent: u32,
    pub requires_network: bool,
    pub background_activity: String,
    pub requested_permissions: Vec<ExtensionPermission>,
    #[serde(default)]
    pub declared_capabilities: Vec<String>,
    #[serde(default)]
    pub declared_side_effects: Vec<String>,
    #[serde(default)]
    pub signature: Option<ExtensionManifestSignature>,
    #[serde(default)]
    pub revoked: bool,
}

impl ExtensionManifest {
    pub fn validate(&self) -> Result<(), ExtensionManifestValidationError> {
        if self.id.trim().is_empty() {
            return Err(ExtensionManifestValidationError::new(
                "extension id cannot be empty",
            ));
        }
        if self.display_name.trim().is_empty() {
            return Err(ExtensionManifestValidationError::new(
                "extension display_name cannot be empty",
            ));
        }
        if self.memory_budget_mb == 0 {
            return Err(ExtensionManifestValidationError::new(
                "extension memory_budget_mb must be greater than zero",
            ));
        }
        if self.cpu_budget_percent == 0 || self.cpu_budget_percent > 100 {
            return Err(ExtensionManifestValidationError::new(
                "extension cpu_budget_percent must be within 1..=100",
            ));
        }
        if self.background_activity.trim().is_empty() {
            return Err(ExtensionManifestValidationError::new(
                "extension background_activity cannot be empty",
            ));
        }
        if self.requires_network
            && self
                .requested_permissions
                .iter()
                .all(|permission| *permission != ExtensionPermission::Network)
        {
            return Err(ExtensionManifestValidationError::new(
                "extension requires_network=true but network permission is not requested",
            ));
        }
        Ok(())
    }

    fn security_gate(&self, forge_version: &str) -> Result<(), ExtensionSecurityGateError> {
        if self.revoked {
            return Err(ExtensionSecurityGateError::RevokedManifest);
        }
        if self.publisher.trim().is_empty() {
            return Err(ExtensionSecurityGateError::MissingMetadata("publisher"));
        }
        if self.version.trim().is_empty() {
            return Err(ExtensionSecurityGateError::MissingMetadata("version"));
        }
        if self.minimum_forge_version.trim().is_empty() {
            return Err(ExtensionSecurityGateError::MissingMetadata(
                "minimum_forge_version",
            ));
        }
        if self.package_checksum_sha256.trim().is_empty() {
            return Err(ExtensionSecurityGateError::MissingMetadata(
                "package_checksum_sha256",
            ));
        }
        if !is_sha256_hex(self.package_checksum_sha256.trim()) {
            return Err(ExtensionSecurityGateError::MissingMetadata(
                "package_checksum_sha256",
            ));
        }
        if self.declared_capabilities.is_empty() {
            return Err(ExtensionSecurityGateError::MissingMetadata(
                "declared_capabilities",
            ));
        }
        if self.declared_side_effects.is_empty() {
            return Err(ExtensionSecurityGateError::MissingMetadata(
                "declared_side_effects",
            ));
        }
        let signature = match self.signature.as_ref() {
            Some(value) if value.is_complete() => value,
            _ => return Err(ExtensionSecurityGateError::UnsignedManifest),
        };
        if !signature.algorithm.eq_ignore_ascii_case("ed25519") {
            return Err(ExtensionSecurityGateError::MissingMetadata(
                "signature.algorithm",
            ));
        }
        let minimum = parse_semver_core(self.minimum_forge_version.as_str()).ok_or(
            ExtensionSecurityGateError::MissingMetadata("minimum_forge_version"),
        )?;
        let current = parse_semver_core(forge_version)
            .ok_or(ExtensionSecurityGateError::MissingMetadata("forge_version"))?;
        if current < minimum {
            return Err(ExtensionSecurityGateError::IncompatibleForgeVersion {
                minimum: self.minimum_forge_version.clone(),
                current: forge_version.to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionManifestValidationError {
    message: String,
}

impl ExtensionManifestValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ExtensionManifestValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ExtensionManifestValidationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExtensionResourceTotals {
    pub enabled_count: usize,
    pub ram_idle_mb: u32,
    pub ram_budget_mb: u32,
    pub cpu_budget_percent: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtensionState {
    Disabled,
    Enabled,
    FailedIsolated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionPermissionGrantSnapshot {
    pub permission: ExtensionPermission,
    pub granted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionRuntimeSnapshot {
    pub manifest: ExtensionManifest,
    pub state: ExtensionState,
    pub last_error: Option<String>,
    pub granted_permissions: Vec<ExtensionPermissionGrantSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionRuntime {
    pub manifest: ExtensionManifest,
    pub state: ExtensionState,
    pub last_error: Option<String>,
    granted_permissions: HashMap<ExtensionPermission, bool>,
}

impl ExtensionRuntime {
    fn new(manifest: ExtensionManifest) -> Self {
        let mut granted_permissions = HashMap::new();
        for permission in &manifest.requested_permissions {
            granted_permissions.insert(*permission, false);
        }
        Self {
            manifest,
            state: ExtensionState::Disabled,
            last_error: None,
            granted_permissions,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionPermissionCheck {
    pub missing_permissions: Vec<ExtensionPermission>,
    pub can_enable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionHostError {
    NotFound(String),
    InvalidManifest(String),
    FailedIsolated(String),
    SecurityPolicyBlocked {
        extension_id: String,
        reason: String,
    },
    MissingPermissions {
        extension_id: String,
        missing: Vec<ExtensionPermission>,
    },
}

#[derive(Debug)]
pub struct ExtensionHost {
    extensions: HashMap<String, ExtensionRuntime>,
    forge_version: String,
}

impl Default for ExtensionHost {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtensionHost {
    pub fn new() -> Self {
        Self::with_forge_version(env!("CARGO_PKG_VERSION"))
    }

    pub fn with_forge_version(forge_version: impl Into<String>) -> Self {
        let normalized = forge_version.into();
        let normalized = if normalized.trim().is_empty() {
            "0.0.0".to_string()
        } else {
            normalized
        };
        Self {
            extensions: HashMap::new(),
            forge_version: normalized,
        }
    }

    pub fn register(&mut self, manifest: ExtensionManifest) -> Result<(), ExtensionHostError> {
        if let Err(error) = manifest.validate() {
            return Err(ExtensionHostError::InvalidManifest(error.to_string()));
        }
        self.extensions
            .insert(manifest.id.clone(), ExtensionRuntime::new(manifest));
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&ExtensionRuntime> {
        self.extensions.get(id)
    }

    pub fn list(&self) -> Vec<&ExtensionRuntime> {
        let mut values = self.extensions.values().collect::<Vec<_>>();
        values.sort_by_key(|value| value.manifest.display_name.as_str());
        values
    }

    pub fn set_permission(
        &mut self,
        id: &str,
        permission: ExtensionPermission,
        granted: bool,
    ) -> Result<(), ExtensionHostError> {
        let runtime = self
            .extensions
            .get_mut(id)
            .ok_or_else(|| ExtensionHostError::NotFound(id.to_string()))?;
        if runtime
            .manifest
            .requested_permissions
            .iter()
            .all(|candidate| *candidate != permission)
        {
            return Ok(());
        }
        runtime.granted_permissions.insert(permission, granted);
        Ok(())
    }

    pub fn grant_all_permissions(&mut self, id: &str) -> Result<(), ExtensionHostError> {
        let runtime = self
            .extensions
            .get_mut(id)
            .ok_or_else(|| ExtensionHostError::NotFound(id.to_string()))?;
        let requested = runtime.manifest.requested_permissions.clone();
        for permission in requested {
            runtime.granted_permissions.insert(permission, true);
        }
        Ok(())
    }

    pub fn revoke_all_permissions(&mut self, id: &str) -> Result<(), ExtensionHostError> {
        let runtime = self
            .extensions
            .get_mut(id)
            .ok_or_else(|| ExtensionHostError::NotFound(id.to_string()))?;
        let requested = runtime.manifest.requested_permissions.clone();
        for permission in requested {
            runtime.granted_permissions.insert(permission, false);
        }
        Ok(())
    }

    pub fn permission_check(
        &self,
        id: &str,
    ) -> Result<ExtensionPermissionCheck, ExtensionHostError> {
        let runtime = self
            .extensions
            .get(id)
            .ok_or_else(|| ExtensionHostError::NotFound(id.to_string()))?;
        let mut missing = Vec::new();
        for permission in &runtime.manifest.requested_permissions {
            let granted = runtime
                .granted_permissions
                .get(permission)
                .copied()
                .unwrap_or(false);
            if !granted {
                missing.push(*permission);
            }
        }
        Ok(ExtensionPermissionCheck {
            can_enable: missing.is_empty(),
            missing_permissions: missing,
        })
    }

    pub fn permission_grants(
        &self,
        id: &str,
    ) -> Result<Vec<ExtensionPermissionGrantSnapshot>, ExtensionHostError> {
        let runtime = self
            .extensions
            .get(id)
            .ok_or_else(|| ExtensionHostError::NotFound(id.to_string()))?;
        let mut grants = runtime
            .manifest
            .requested_permissions
            .iter()
            .map(|permission| ExtensionPermissionGrantSnapshot {
                permission: *permission,
                granted: runtime
                    .granted_permissions
                    .get(permission)
                    .copied()
                    .unwrap_or(false),
            })
            .collect::<Vec<_>>();
        grants.sort_by_key(|entry| entry.permission.label());
        Ok(grants)
    }

    pub fn set_enabled(&mut self, id: &str, enabled: bool) -> Result<(), ExtensionHostError> {
        if enabled {
            let runtime = self
                .extensions
                .get(id)
                .ok_or_else(|| ExtensionHostError::NotFound(id.to_string()))?;
            if let Err(error) = runtime.manifest.security_gate(self.forge_version.as_str()) {
                return Err(ExtensionHostError::SecurityPolicyBlocked {
                    extension_id: id.to_string(),
                    reason: error.to_string(),
                });
            }
            let check = self.permission_check(id)?;
            if !check.can_enable {
                return Err(ExtensionHostError::MissingPermissions {
                    extension_id: id.to_string(),
                    missing: check.missing_permissions,
                });
            }
        }

        let runtime = self
            .extensions
            .get_mut(id)
            .ok_or_else(|| ExtensionHostError::NotFound(id.to_string()))?;
        if enabled {
            if matches!(runtime.state, ExtensionState::FailedIsolated) {
                return Err(ExtensionHostError::FailedIsolated(id.to_string()));
            }
            runtime.state = ExtensionState::Enabled;
        } else if matches!(runtime.state, ExtensionState::Enabled) {
            runtime.state = ExtensionState::Disabled;
        }
        Ok(())
    }

    pub fn isolate_failure(
        &mut self,
        id: &str,
        reason: impl Into<String>,
    ) -> Result<(), ExtensionHostError> {
        let runtime = self
            .extensions
            .get_mut(id)
            .ok_or_else(|| ExtensionHostError::NotFound(id.to_string()))?;
        runtime.state = ExtensionState::FailedIsolated;
        runtime.last_error = Some(reason.into());
        Ok(())
    }

    pub fn recover_isolated(&mut self, id: &str) -> Result<(), ExtensionHostError> {
        let runtime = self
            .extensions
            .get_mut(id)
            .ok_or_else(|| ExtensionHostError::NotFound(id.to_string()))?;
        if matches!(runtime.state, ExtensionState::FailedIsolated) {
            runtime.state = ExtensionState::Disabled;
            runtime.last_error = None;
        }
        Ok(())
    }

    pub fn active_resource_totals(&self) -> ExtensionResourceTotals {
        let mut totals = ExtensionResourceTotals::default();
        for runtime in self.extensions.values() {
            if !matches!(runtime.state, ExtensionState::Enabled) {
                continue;
            }
            totals.enabled_count = totals.enabled_count.saturating_add(1);
            totals.ram_idle_mb = totals
                .ram_idle_mb
                .saturating_add(runtime.manifest.idle_cost_mb);
            totals.ram_budget_mb = totals
                .ram_budget_mb
                .saturating_add(runtime.manifest.memory_budget_mb);
            totals.cpu_budget_percent = totals
                .cpu_budget_percent
                .saturating_add(runtime.manifest.cpu_budget_percent);
        }
        totals
    }

    pub fn snapshot(&self) -> Vec<ExtensionRuntimeSnapshot> {
        let mut snapshots = self
            .extensions
            .values()
            .map(|runtime| {
                let mut granted_permissions = runtime
                    .granted_permissions
                    .iter()
                    .map(|(permission, granted)| ExtensionPermissionGrantSnapshot {
                        permission: *permission,
                        granted: *granted,
                    })
                    .collect::<Vec<_>>();
                granted_permissions.sort_by_key(|entry| entry.permission.label());
                ExtensionRuntimeSnapshot {
                    manifest: runtime.manifest.clone(),
                    state: runtime.state,
                    last_error: runtime.last_error.clone(),
                    granted_permissions,
                }
            })
            .collect::<Vec<_>>();
        snapshots.sort_by_key(|entry| entry.manifest.display_name.clone());
        snapshots
    }

    pub fn restore(snapshot: Vec<ExtensionRuntimeSnapshot>) -> Result<Self, String> {
        let mut host = ExtensionHost::new();
        for entry in snapshot {
            if let Err(error) = entry.manifest.validate() {
                return Err(format!("invalid manifest {}: {error}", entry.manifest.id));
            }

            let mut runtime = ExtensionRuntime::new(entry.manifest);
            runtime.state = entry.state;
            runtime.last_error = entry.last_error;

            for grant in entry.granted_permissions {
                runtime
                    .granted_permissions
                    .insert(grant.permission, grant.granted);
            }

            for permission in &runtime.manifest.requested_permissions {
                runtime
                    .granted_permissions
                    .entry(*permission)
                    .or_insert(false);
            }

            host.extensions.insert(runtime.manifest.id.clone(), runtime);
        }
        Ok(host)
    }
}

pub fn default_extension_host() -> ExtensionHost {
    let mut host = ExtensionHost::new();
    let _ = host.register(ExtensionManifest {
        id: "viewer-session-inspector".to_string(),
        display_name: "Session Inspector".to_string(),
        publisher: "forge-core".to_string(),
        version: "1.0.0".to_string(),
        minimum_forge_version: "0.1.0".to_string(),
        package_checksum_sha256: "1111111111111111111111111111111111111111111111111111111111111111"
            .to_string(),
        class: ExtensionClass::Viewer,
        idle_cost_mb: 24,
        startup_cost_ms: 40,
        memory_budget_mb: 128,
        cpu_budget_percent: 4,
        requires_network: false,
        background_activity: "none".to_string(),
        requested_permissions: Vec::new(),
        declared_capabilities: vec!["session.inspect".to_string()],
        declared_side_effects: vec!["none".to_string()],
        signature: Some(ExtensionManifestSignature {
            key_id: "forge-builtin-ed25519".to_string(),
            algorithm: "ed25519".to_string(),
            value: "builtin-signature-viewer-session-inspector-v1".to_string(),
        }),
        revoked: false,
    });
    let _ = host.register(ExtensionManifest {
        id: "provider-openai".to_string(),
        display_name: "OpenAI Provider Adapter".to_string(),
        publisher: "forge-core".to_string(),
        version: "1.0.0".to_string(),
        minimum_forge_version: "0.1.0".to_string(),
        package_checksum_sha256: "2222222222222222222222222222222222222222222222222222222222222222"
            .to_string(),
        class: ExtensionClass::ModelProvider,
        idle_cost_mb: 35,
        startup_cost_ms: 90,
        memory_budget_mb: 256,
        cpu_budget_percent: 12,
        requires_network: true,
        background_activity: "request-response only".to_string(),
        requested_permissions: vec![
            ExtensionPermission::Network,
            ExtensionPermission::ExternalApis,
        ],
        declared_capabilities: vec![
            "provider.chat".to_string(),
            "provider.confidential_relay".to_string(),
        ],
        declared_side_effects: vec!["network-egress".to_string()],
        signature: Some(ExtensionManifestSignature {
            key_id: "forge-builtin-ed25519".to_string(),
            algorithm: "ed25519".to_string(),
            value: "builtin-signature-provider-openai-v1".to_string(),
        }),
        revoked: false,
    });
    host
}

#[cfg(test)]
mod tests {
    use super::{
        ExtensionClass, ExtensionHost, ExtensionHostError, ExtensionManifest,
        ExtensionManifestSignature, ExtensionPermission, ExtensionState, default_extension_host,
    };

    fn provider_manifest() -> ExtensionManifest {
        ExtensionManifest {
            id: "provider".to_string(),
            display_name: "Provider".to_string(),
            publisher: "forge-test".to_string(),
            version: "1.0.0".to_string(),
            minimum_forge_version: "0.1.0".to_string(),
            package_checksum_sha256:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            class: ExtensionClass::ModelProvider,
            idle_cost_mb: 30,
            startup_cost_ms: 45,
            memory_budget_mb: 256,
            cpu_budget_percent: 16,
            requires_network: true,
            background_activity: "request-response".to_string(),
            requested_permissions: vec![
                ExtensionPermission::Network,
                ExtensionPermission::ExternalApis,
            ],
            declared_capabilities: vec!["provider.chat".to_string()],
            declared_side_effects: vec!["network-egress".to_string()],
            signature: Some(ExtensionManifestSignature {
                key_id: "forge-test-ed25519".to_string(),
                algorithm: "ed25519".to_string(),
                value: "test-signature-provider-v1".to_string(),
            }),
            revoked: false,
        }
    }

    #[test]
    fn enabling_requires_requested_permissions() {
        let mut host = ExtensionHost::new();
        assert!(host.register(provider_manifest()).is_ok());

        let enable = host.set_enabled("provider", true);
        assert!(enable.is_err());
        let error = match enable {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            error,
            ExtensionHostError::MissingPermissions { .. }
        ));

        assert!(
            host.set_permission("provider", ExtensionPermission::Network, true)
                .is_ok()
        );
        assert!(
            host.set_permission("provider", ExtensionPermission::ExternalApis, true)
                .is_ok()
        );
        assert!(host.set_enabled("provider", true).is_ok());
        let runtime = host.get("provider");
        assert!(runtime.is_some());
        let runtime = match runtime {
            Some(value) => value,
            None => return,
        };
        assert_eq!(runtime.state, ExtensionState::Enabled);
    }

    #[test]
    fn enabling_unsigned_manifest_is_blocked() {
        let mut host = ExtensionHost::new();
        let mut manifest = provider_manifest();
        manifest.signature = None;
        assert!(host.register(manifest).is_ok());
        assert!(host.grant_all_permissions("provider").is_ok());

        let enable = host.set_enabled("provider", true);
        assert!(enable.is_err());
        let error = match enable {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            error,
            ExtensionHostError::SecurityPolicyBlocked { .. }
        ));
    }

    #[test]
    fn enabling_revoked_manifest_is_blocked() {
        let mut host = ExtensionHost::new();
        let mut manifest = provider_manifest();
        manifest.revoked = true;
        assert!(host.register(manifest).is_ok());
        assert!(host.grant_all_permissions("provider").is_ok());

        let enable = host.set_enabled("provider", true);
        assert!(enable.is_err());
        let error = match enable {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            error,
            ExtensionHostError::SecurityPolicyBlocked { .. }
        ));
    }

    #[test]
    fn enabling_manifest_with_newer_minimum_forge_version_is_blocked() {
        let mut host = ExtensionHost::with_forge_version("0.1.0");
        let mut manifest = provider_manifest();
        manifest.minimum_forge_version = "9.0.0".to_string();
        assert!(host.register(manifest).is_ok());
        assert!(host.grant_all_permissions("provider").is_ok());

        let enable = host.set_enabled("provider", true);
        assert!(enable.is_err());
        let error = match enable {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            error,
            ExtensionHostError::SecurityPolicyBlocked { .. }
        ));
    }

    #[test]
    fn isolate_blocks_reenable_until_recovered() {
        let mut host = ExtensionHost::new();
        assert!(host.register(provider_manifest()).is_ok());
        assert!(host.grant_all_permissions("provider").is_ok());
        assert!(host.set_enabled("provider", true).is_ok());
        assert!(
            host.isolate_failure("provider", "sandbox violation")
                .is_ok()
        );

        let reenable = host.set_enabled("provider", true);
        assert!(reenable.is_err());
        let error = match reenable {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(error, ExtensionHostError::FailedIsolated(_)));

        assert!(host.recover_isolated("provider").is_ok());
        assert!(host.set_enabled("provider", true).is_ok());
    }

    #[test]
    fn active_resource_totals_reflect_enabled_extensions_only() {
        let mut host = default_extension_host();
        let baseline = host.active_resource_totals();
        assert_eq!(baseline.enabled_count, 0);
        assert_eq!(baseline.ram_idle_mb, 0);
        assert_eq!(baseline.ram_budget_mb, 0);
        assert_eq!(baseline.cpu_budget_percent, 0);

        assert!(host.grant_all_permissions("provider-openai").is_ok());
        assert!(host.set_enabled("provider-openai", true).is_ok());

        let totals = host.active_resource_totals();
        assert_eq!(totals.enabled_count, 1);
        assert_eq!(totals.ram_idle_mb, 35);
        assert_eq!(totals.ram_budget_mb, 256);
        assert_eq!(totals.cpu_budget_percent, 12);
    }

    #[test]
    fn revoke_all_permissions_resets_enable_eligibility() {
        let mut host = ExtensionHost::new();
        assert!(host.register(provider_manifest()).is_ok());
        assert!(host.grant_all_permissions("provider").is_ok());

        let granted_check = host.permission_check("provider");
        assert!(granted_check.is_ok());
        let granted_check = match granted_check {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(granted_check.can_enable);

        assert!(host.revoke_all_permissions("provider").is_ok());
        let revoked_check = host.permission_check("provider");
        assert!(revoked_check.is_ok());
        let revoked_check = match revoked_check {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(!revoked_check.can_enable);
        assert_eq!(revoked_check.missing_permissions.len(), 2);
    }

    #[test]
    fn permission_grants_reflect_granted_and_revoked_state() {
        let mut host = ExtensionHost::new();
        assert!(host.register(provider_manifest()).is_ok());
        assert!(host.grant_all_permissions("provider").is_ok());
        assert!(host.revoke_all_permissions("provider").is_ok());
        assert!(
            host.set_permission("provider", ExtensionPermission::Network, true)
                .is_ok()
        );

        let grants = host.permission_grants("provider");
        assert!(grants.is_ok());
        let grants = match grants {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(grants.len(), 2);
        assert!(grants.iter().any(|entry| {
            matches!(entry.permission, ExtensionPermission::Network) && entry.granted
        }));
        assert!(grants.iter().any(|entry| {
            matches!(entry.permission, ExtensionPermission::ExternalApis) && !entry.granted
        }));
    }

    #[test]
    fn snapshot_restore_round_trip_preserves_permissions_and_state() {
        let mut host = default_extension_host();
        assert!(host.grant_all_permissions("provider-openai").is_ok());
        assert!(host.set_enabled("provider-openai", true).is_ok());
        assert!(
            host.isolate_failure("provider-openai", "quota exceeded")
                .is_ok()
        );

        let snapshot = host.snapshot();
        let restored = ExtensionHost::restore(snapshot);
        assert!(restored.is_ok());
        let restored = match restored {
            Ok(value) => value,
            Err(_) => return,
        };
        let provider = restored.get("provider-openai");
        assert!(provider.is_some());
        let provider = match provider {
            Some(value) => value,
            None => return,
        };
        assert_eq!(provider.state, ExtensionState::FailedIsolated);
        assert_eq!(provider.last_error.as_deref(), Some("quota exceeded"));
        let check = restored.permission_check("provider-openai");
        assert!(check.is_ok());
        let check = match check {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(check.can_enable);
        assert!(check.missing_permissions.is_empty());
    }
}
