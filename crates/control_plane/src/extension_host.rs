use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::env;
use std::error::Error;
use std::fmt;

const FORGE_BUILTIN_MANIFEST_KEY_ID: &str = "forge-builtin-ed25519";
const FORGE_BUILTIN_MANIFEST_PUBLISHER: &str = "forge-core";
const FORGE_BUILTIN_MANIFEST_VERIFYING_KEY_BASE64: &str =
    "F1qqNodtL7k6RpJJondaLah9baz17Xcr/zpYfLMEy3M=";
const FORGE_BUILTIN_VIEWER_SIGNATURE_BASE64: &str =
    "2t65gf6EXW2qWKg+zd1oqNX3YF57bMtwwohUEzr4QGnZjGZwPOm7ej22FrMAU9Ca6iIe1RhQsMwSt4XQxdthCQ==";
const FORGE_BUILTIN_PROVIDER_SIGNATURE_BASE64: &str =
    "NGtxyV67AtWHKp867w0e1ktT+A7JVBvxobEKXMO9c58YvJL4pM9yDpxaFD8MkXwupbiKC8uxNLndqDmDjetKCg==";
const MCP_SCOPED_TOKEN_BYTES: usize = 32;

#[derive(Debug, Clone)]
pub struct TrustedManifestSigner {
    pub key_id: String,
    pub publisher: String,
    pub verifying_key: VerifyingKey,
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpToolPolicy {
    pub tool_name: String,
    pub required_scope: String,
    pub audience: String,
    pub risk_class: McpToolRiskClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum McpToolRiskClass {
    ReadOnly,
    Mutating,
    Destructive,
}

impl McpToolRiskClass {
    pub const fn label(self) -> &'static str {
        match self {
            McpToolRiskClass::ReadOnly => "read_only",
            McpToolRiskClass::Mutating => "mutating",
            McpToolRiskClass::Destructive => "destructive",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpScopedToken {
    pub token: String,
    pub extension_id: String,
    pub session_id: String,
    pub audience: String,
    pub scopes: Vec<String>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct McpTokenLease {
    extension_id: String,
    session_id: String,
    audience: String,
    scopes: Vec<String>,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    revoked: bool,
}

impl McpTokenLease {
    fn to_snapshot(&self, token: String) -> McpScopedToken {
        McpScopedToken {
            token,
            extension_id: self.extension_id.clone(),
            session_id: self.session_id.clone(),
            audience: self.audience.clone(),
            scopes: self.scopes.clone(),
            issued_at_unix_ms: self.issued_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpAuthorizedToolCall {
    pub extension_id: String,
    pub session_id: String,
    pub tool_name: String,
    pub audience: String,
    pub required_scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpToolPolicyError {
    InvalidToolName,
    InvalidScope,
    InvalidAudience,
}

impl fmt::Display for McpToolPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            McpToolPolicyError::InvalidToolName => f.write_str("MCP tool name cannot be empty"),
            McpToolPolicyError::InvalidScope => f.write_str("MCP required scope cannot be empty"),
            McpToolPolicyError::InvalidAudience => f.write_str("MCP audience cannot be empty"),
        }
    }
}

impl Error for McpToolPolicyError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpTokenIssueError {
    ExtensionNotFound(String),
    ExtensionNotEnabled(String),
    QuarantineModeActive,
    InvalidSessionId,
    InvalidAudience,
    InvalidScope,
    InvalidTtl,
    ScopeNotDeclared {
        extension_id: String,
        scope: String,
    },
    NoMatchingToolPolicy {
        audience: String,
        scopes: Vec<String>,
    },
}

impl fmt::Display for McpTokenIssueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            McpTokenIssueError::ExtensionNotFound(id) => {
                write!(f, "extension not found: {id}")
            }
            McpTokenIssueError::ExtensionNotEnabled(id) => {
                write!(f, "extension is not enabled: {id}")
            }
            McpTokenIssueError::QuarantineModeActive => {
                f.write_str("MCP token issuance blocked while quarantine mode is active")
            }
            McpTokenIssueError::InvalidSessionId => f.write_str("MCP session_id cannot be empty"),
            McpTokenIssueError::InvalidAudience => f.write_str("MCP audience cannot be empty"),
            McpTokenIssueError::InvalidScope => f.write_str("MCP scopes cannot be empty"),
            McpTokenIssueError::InvalidTtl => {
                f.write_str("MCP token ttl_ms must be greater than zero")
            }
            McpTokenIssueError::ScopeNotDeclared {
                extension_id,
                scope,
            } => write!(
                f,
                "MCP scope `{scope}` is not declared by extension {extension_id}"
            ),
            McpTokenIssueError::NoMatchingToolPolicy { audience, scopes } => write!(
                f,
                "no MCP tool policy matches audience `{audience}` for scopes [{}]",
                scopes.join(", ")
            ),
        }
    }
}

impl Error for McpTokenIssueError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpTokenAuthorizationError {
    InvalidToken,
    InvalidToolName,
    InvalidAudience,
    QuarantineModeActive,
    ToolPolicyNotFound(String),
    PolicyAudienceMismatch {
        tool_name: String,
        expected: String,
        actual: String,
    },
    TokenAudienceMismatch {
        expected: String,
        actual: String,
    },
    TokenExpired {
        expires_at_unix_ms: u64,
        now_unix_ms: u64,
    },
    TokenRevoked,
    ScopeMissing {
        required_scope: String,
    },
    DestructiveToolBlocked {
        tool_name: String,
        reason: String,
    },
    ExtensionInactive(String),
}

impl fmt::Display for McpTokenAuthorizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            McpTokenAuthorizationError::InvalidToken => f.write_str("MCP token is unknown"),
            McpTokenAuthorizationError::InvalidToolName => {
                f.write_str("MCP tool name cannot be empty")
            }
            McpTokenAuthorizationError::InvalidAudience => {
                f.write_str("MCP audience cannot be empty")
            }
            McpTokenAuthorizationError::QuarantineModeActive => {
                f.write_str("MCP authorization blocked while quarantine mode is active")
            }
            McpTokenAuthorizationError::ToolPolicyNotFound(tool_name) => {
                write!(f, "MCP tool policy not found for tool `{tool_name}`")
            }
            McpTokenAuthorizationError::PolicyAudienceMismatch {
                tool_name,
                expected,
                actual,
            } => write!(
                f,
                "MCP audience mismatch for tool `{tool_name}` expected={expected} actual={actual}"
            ),
            McpTokenAuthorizationError::TokenAudienceMismatch { expected, actual } => write!(
                f,
                "MCP token audience mismatch expected={expected} actual={actual}"
            ),
            McpTokenAuthorizationError::TokenExpired {
                expires_at_unix_ms,
                now_unix_ms,
            } => write!(
                f,
                "MCP token expired at {expires_at_unix_ms} (now={now_unix_ms})"
            ),
            McpTokenAuthorizationError::TokenRevoked => f.write_str("MCP token has been revoked"),
            McpTokenAuthorizationError::ScopeMissing { required_scope } => {
                write!(f, "MCP token is missing required scope `{required_scope}`")
            }
            McpTokenAuthorizationError::DestructiveToolBlocked { tool_name, reason } => write!(
                f,
                "MCP destructive tool `{tool_name}` blocked by policy: {reason}"
            ),
            McpTokenAuthorizationError::ExtensionInactive(id) => write!(
                f,
                "extension is not enabled for MCP token authorization: {id}"
            ),
        }
    }
}

impl Error for McpTokenAuthorizationError {}

fn is_high_risk_extension_permission(permission: ExtensionPermission) -> bool {
    matches!(
        permission,
        ExtensionPermission::FilesystemEdits
            | ExtensionPermission::Shell
            | ExtensionPermission::Network
            | ExtensionPermission::Git
            | ExtensionPermission::ModelDownloads
            | ExtensionPermission::ExternalApis
    )
}

fn is_overbroad_permission_set(permissions: &[ExtensionPermission]) -> bool {
    let has_shell = permissions
        .iter()
        .any(|permission| matches!(permission, ExtensionPermission::Shell));
    let has_network = permissions.iter().any(|permission| {
        matches!(
            permission,
            ExtensionPermission::Network | ExtensionPermission::ExternalApis
        )
    });
    let has_write_surface = permissions.iter().any(|permission| {
        matches!(
            permission,
            ExtensionPermission::FilesystemEdits
                | ExtensionPermission::Git
                | ExtensionPermission::ModelDownloads
        )
    });
    let high_risk_count = permissions
        .iter()
        .filter(|permission| is_high_risk_extension_permission(**permission))
        .count();

    ((has_shell || has_write_surface) && has_network) || high_risk_count >= 3
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

fn normalize_non_empty_label(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

fn normalize_mcp_scope_set(scopes: &[String]) -> Option<Vec<String>> {
    let mut normalized = scopes
        .iter()
        .filter_map(|value| normalize_non_empty_label(value))
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    if normalized.is_empty() {
        return None;
    }
    Some(normalized)
}

fn normalize_mcp_tool_key(tool_name: &str) -> Option<String> {
    normalize_non_empty_label(tool_name).map(|value| value.to_ascii_lowercase())
}

fn env_flag(name: &str) -> Option<bool> {
    let raw = env::var(name).ok()?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn quarantine_mode_from_env() -> bool {
    env_flag("FORGE_QUARANTINE_MODE").unwrap_or(false)
}

fn looks_destructive_keyword(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    [
        "delete", "remove", "destroy", "wipe", "drop", "truncate", "reset", "revoke", "shutdown",
        "kill", "exec", "shell", "write", "patch", "modify", "chmod", "chown", "unlink", "purge",
    ]
    .iter()
    .any(|token| lowered.contains(token))
}

fn looks_read_only_keyword(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    [
        "read", "list", "get", "fetch", "query", "search", "view", "status", "describe", "inspect",
        "health", "info",
    ]
    .iter()
    .any(|token| lowered.contains(token))
}

fn policy_looks_destructive(policy: &McpToolPolicy) -> bool {
    looks_destructive_keyword(policy.tool_name.as_str())
        || looks_destructive_keyword(policy.required_scope.as_str())
}

fn policy_looks_read_only(policy: &McpToolPolicy) -> bool {
    looks_read_only_keyword(policy.tool_name.as_str())
        || looks_read_only_keyword(policy.required_scope.as_str())
}

fn has_granted_destructive_permission(runtime: &ExtensionRuntime) -> bool {
    [
        ExtensionPermission::FilesystemEdits,
        ExtensionPermission::Shell,
        ExtensionPermission::Git,
        ExtensionPermission::ModelDownloads,
    ]
    .iter()
    .any(|permission| {
        runtime
            .granted_permissions
            .get(permission)
            .copied()
            .unwrap_or(false)
    })
}

fn declared_destructive_side_effect(runtime: &ExtensionRuntime) -> bool {
    runtime
        .manifest
        .declared_side_effects
        .iter()
        .any(|value| looks_destructive_keyword(value))
}

fn mint_mcp_scoped_token_secret() -> String {
    let mut token_bytes = [0u8; MCP_SCOPED_TOKEN_BYTES];
    let mut rng = OsRng;
    rng.fill_bytes(&mut token_bytes);
    BASE64_URL_SAFE_NO_PAD.encode(token_bytes)
}

fn default_manifest_signers() -> HashMap<String, TrustedManifestSigner> {
    let Some(verifying_key) = builtin_manifest_verifying_key() else {
        return HashMap::new();
    };
    let mut signers = HashMap::new();
    signers.insert(
        FORGE_BUILTIN_MANIFEST_KEY_ID.to_string(),
        TrustedManifestSigner {
            key_id: FORGE_BUILTIN_MANIFEST_KEY_ID.to_string(),
            publisher: FORGE_BUILTIN_MANIFEST_PUBLISHER.to_string(),
            verifying_key,
        },
    );
    signers
}

fn builtin_manifest_verifying_key() -> Option<VerifyingKey> {
    let decoded = BASE64_STANDARD
        .decode(FORGE_BUILTIN_MANIFEST_VERIFYING_KEY_BASE64.as_bytes())
        .ok()?;
    let bytes: [u8; 32] = decoded.as_slice().try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

#[derive(Debug, Clone, Serialize)]
struct ManifestSignaturePayload {
    id: String,
    display_name: String,
    publisher: String,
    version: String,
    minimum_forge_version: String,
    package_checksum_sha256: String,
    class: String,
    idle_cost_mb: u32,
    startup_cost_ms: u32,
    memory_budget_mb: u32,
    cpu_budget_percent: u32,
    requires_network: bool,
    background_activity: String,
    requested_permissions: Vec<String>,
    declared_capabilities: Vec<String>,
    declared_side_effects: Vec<String>,
    revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionSecurityGateError {
    UnsignedManifest,
    RevokedManifest,
    IncompatibleForgeVersion { minimum: String, current: String },
    MissingMetadata(&'static str),
    UntrustedManifestSigner(String),
    InvalidSignatureEncoding,
    SignatureVerificationFailed,
    SignerPublisherMismatch { expected: String, actual: String },
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
            ExtensionSecurityGateError::UntrustedManifestSigner(key_id) => {
                write!(f, "untrusted manifest signer key_id={key_id}")
            }
            ExtensionSecurityGateError::InvalidSignatureEncoding => {
                f.write_str("manifest signature payload is not valid base64 or length")
            }
            ExtensionSecurityGateError::SignatureVerificationFailed => {
                f.write_str("manifest signature verification failed")
            }
            ExtensionSecurityGateError::SignerPublisherMismatch { expected, actual } => write!(
                f,
                "manifest signer publisher mismatch expected={expected} actual={actual}"
            ),
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

    fn signature_payload_json(&self) -> Option<Vec<u8>> {
        let mut permissions = self
            .requested_permissions
            .iter()
            .map(|permission| permission.label().to_string())
            .collect::<Vec<_>>();
        permissions.sort();
        permissions.dedup();

        let mut capabilities = self
            .declared_capabilities
            .iter()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        capabilities.sort();
        capabilities.dedup();

        let mut side_effects = self
            .declared_side_effects
            .iter()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        side_effects.sort();
        side_effects.dedup();

        let payload = ManifestSignaturePayload {
            id: self.id.clone(),
            display_name: self.display_name.clone(),
            publisher: self.publisher.clone(),
            version: self.version.clone(),
            minimum_forge_version: self.minimum_forge_version.clone(),
            package_checksum_sha256: self.package_checksum_sha256.clone(),
            class: self.class.label().to_string(),
            idle_cost_mb: self.idle_cost_mb,
            startup_cost_ms: self.startup_cost_ms,
            memory_budget_mb: self.memory_budget_mb,
            cpu_budget_percent: self.cpu_budget_percent,
            requires_network: self.requires_network,
            background_activity: self.background_activity.clone(),
            requested_permissions: permissions,
            declared_capabilities: capabilities,
            declared_side_effects: side_effects,
            revoked: self.revoked,
        };
        serde_json::to_vec(&payload).ok()
    }

    fn requires_overbroad_approval(&self) -> bool {
        is_overbroad_permission_set(&self.requested_permissions)
    }

    fn security_gate(
        &self,
        forge_version: &str,
        trusted_manifest_signers: &HashMap<String, TrustedManifestSigner>,
    ) -> Result<(), ExtensionSecurityGateError> {
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
        let signer = trusted_manifest_signers
            .get(signature.key_id.as_str())
            .ok_or_else(|| {
                ExtensionSecurityGateError::UntrustedManifestSigner(signature.key_id.clone())
            })?;
        if !signer
            .publisher
            .eq_ignore_ascii_case(self.publisher.as_str())
        {
            return Err(ExtensionSecurityGateError::SignerPublisherMismatch {
                expected: signer.publisher.clone(),
                actual: self.publisher.clone(),
            });
        }

        let payload =
            self.signature_payload_json()
                .ok_or(ExtensionSecurityGateError::MissingMetadata(
                    "signature_payload",
                ))?;
        let signature_bytes = BASE64_STANDARD
            .decode(signature.value.as_bytes())
            .map_err(|_| ExtensionSecurityGateError::InvalidSignatureEncoding)?;
        let parsed_signature = Signature::try_from(signature_bytes.as_slice())
            .map_err(|_| ExtensionSecurityGateError::InvalidSignatureEncoding)?;
        signer
            .verifying_key
            .verify(payload.as_slice(), &parsed_signature)
            .map_err(|_| ExtensionSecurityGateError::SignatureVerificationFailed)?;

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
    #[serde(default)]
    pub overbroad_approved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionRuntime {
    pub manifest: ExtensionManifest,
    pub state: ExtensionState,
    pub last_error: Option<String>,
    pub overbroad_approved: bool,
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
            overbroad_approved: false,
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
    QuarantineModeActive {
        action: String,
    },
    SecurityPolicyBlocked {
        extension_id: String,
        reason: String,
    },
    OverbroadApprovalRequired {
        extension_id: String,
        permissions: Vec<ExtensionPermission>,
    },
    MissingPermissions {
        extension_id: String,
        missing: Vec<ExtensionPermission>,
    },
}

#[derive(Debug)]
pub struct ExtensionHost {
    extensions: HashMap<String, ExtensionRuntime>,
    mcp_tool_policies: HashMap<String, McpToolPolicy>,
    mcp_tokens: HashMap<String, McpTokenLease>,
    forge_version: String,
    quarantine_mode: bool,
    trusted_manifest_signers: HashMap<String, TrustedManifestSigner>,
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
            mcp_tool_policies: HashMap::new(),
            mcp_tokens: HashMap::new(),
            forge_version: normalized,
            quarantine_mode: quarantine_mode_from_env(),
            trusted_manifest_signers: default_manifest_signers(),
        }
    }

    pub fn register_trusted_manifest_signer(&mut self, signer: TrustedManifestSigner) {
        self.trusted_manifest_signers
            .insert(signer.key_id.clone(), signer);
    }

    pub fn register(&mut self, manifest: ExtensionManifest) -> Result<(), ExtensionHostError> {
        if let Err(error) = manifest.validate() {
            return Err(ExtensionHostError::InvalidManifest(error.to_string()));
        }
        self.revoke_mcp_tokens_for_extension(manifest.id.as_str());
        self.extensions
            .insert(manifest.id.clone(), ExtensionRuntime::new(manifest));
        Ok(())
    }

    fn revoke_mcp_tokens_for_extension(&mut self, extension_id: &str) -> usize {
        let mut revoked = 0usize;
        for lease in self.mcp_tokens.values_mut() {
            if lease.extension_id == extension_id && !lease.revoked {
                lease.revoked = true;
                revoked = revoked.saturating_add(1);
            }
        }
        revoked
    }

    fn revoke_all_mcp_tokens(&mut self) -> usize {
        let mut revoked = 0usize;
        for lease in self.mcp_tokens.values_mut() {
            if !lease.revoked {
                lease.revoked = true;
                revoked = revoked.saturating_add(1);
            }
        }
        revoked
    }

    pub fn set_quarantine_mode(&mut self, enabled: bool) {
        self.quarantine_mode = enabled;
        if enabled {
            let _ = self.revoke_all_mcp_tokens();
        }
    }

    pub fn refresh_quarantine_mode_from_env(&mut self) {
        self.set_quarantine_mode(quarantine_mode_from_env());
    }

    fn extension_declared_scope_set(runtime: &ExtensionRuntime) -> HashSet<String> {
        runtime
            .manifest
            .declared_capabilities
            .iter()
            .filter_map(|value| normalize_non_empty_label(value))
            .collect::<HashSet<_>>()
    }

    pub fn set_mcp_tool_policy(
        &mut self,
        tool_name: &str,
        required_scope: &str,
        audience: &str,
    ) -> Result<(), McpToolPolicyError> {
        self.set_mcp_tool_policy_with_risk(
            tool_name,
            required_scope,
            audience,
            McpToolRiskClass::Mutating,
        )
    }

    pub fn set_mcp_tool_policy_with_risk(
        &mut self,
        tool_name: &str,
        required_scope: &str,
        audience: &str,
        risk_class: McpToolRiskClass,
    ) -> Result<(), McpToolPolicyError> {
        let Some(tool_key) = normalize_mcp_tool_key(tool_name) else {
            return Err(McpToolPolicyError::InvalidToolName);
        };
        let Some(normalized_scope) = normalize_non_empty_label(required_scope) else {
            return Err(McpToolPolicyError::InvalidScope);
        };
        let Some(normalized_audience) = normalize_non_empty_label(audience) else {
            return Err(McpToolPolicyError::InvalidAudience);
        };
        self.mcp_tool_policies.insert(
            tool_key,
            McpToolPolicy {
                tool_name: tool_name.trim().to_string(),
                required_scope: normalized_scope,
                audience: normalized_audience,
                risk_class,
            },
        );
        Ok(())
    }

    pub fn remove_mcp_tool_policy(&mut self, tool_name: &str) -> bool {
        let Some(tool_key) = normalize_mcp_tool_key(tool_name) else {
            return false;
        };
        self.mcp_tool_policies.remove(tool_key.as_str()).is_some()
    }

    pub fn mcp_tool_policy(&self, tool_name: &str) -> Option<McpToolPolicy> {
        let tool_key = normalize_mcp_tool_key(tool_name)?;
        self.mcp_tool_policies.get(tool_key.as_str()).cloned()
    }

    pub fn issue_mcp_scoped_token(
        &mut self,
        extension_id: &str,
        session_id: &str,
        audience: &str,
        scopes: Vec<String>,
        ttl_ms: u64,
        now_unix_ms: u64,
    ) -> Result<McpScopedToken, McpTokenIssueError> {
        if self.quarantine_mode {
            return Err(McpTokenIssueError::QuarantineModeActive);
        }
        let Some(normalized_session_id) = normalize_non_empty_label(session_id) else {
            return Err(McpTokenIssueError::InvalidSessionId);
        };
        let Some(normalized_audience) = normalize_non_empty_label(audience) else {
            return Err(McpTokenIssueError::InvalidAudience);
        };
        if ttl_ms == 0 {
            return Err(McpTokenIssueError::InvalidTtl);
        }
        let Some(normalized_scopes) = normalize_mcp_scope_set(scopes.as_slice()) else {
            return Err(McpTokenIssueError::InvalidScope);
        };

        let runtime = self
            .extensions
            .get(extension_id)
            .ok_or_else(|| McpTokenIssueError::ExtensionNotFound(extension_id.to_string()))?;
        if !matches!(runtime.state, ExtensionState::Enabled) {
            return Err(McpTokenIssueError::ExtensionNotEnabled(
                extension_id.to_string(),
            ));
        }

        let declared_scopes = Self::extension_declared_scope_set(runtime);
        for scope in &normalized_scopes {
            if !declared_scopes.contains(scope) {
                return Err(McpTokenIssueError::ScopeNotDeclared {
                    extension_id: extension_id.to_string(),
                    scope: scope.clone(),
                });
            }
        }

        let matches_policy = self.mcp_tool_policies.values().any(|policy| {
            policy.audience == normalized_audience
                && normalized_scopes
                    .iter()
                    .any(|scope| scope == &policy.required_scope)
        });
        if !matches_policy {
            return Err(McpTokenIssueError::NoMatchingToolPolicy {
                audience: normalized_audience.clone(),
                scopes: normalized_scopes.clone(),
            });
        }

        let token = mint_mcp_scoped_token_secret();
        let expires_at_unix_ms = now_unix_ms.saturating_add(ttl_ms);
        let lease = McpTokenLease {
            extension_id: extension_id.to_string(),
            session_id: normalized_session_id,
            audience: normalized_audience,
            scopes: normalized_scopes,
            issued_at_unix_ms: now_unix_ms,
            expires_at_unix_ms,
            revoked: false,
        };
        self.mcp_tokens.insert(token.clone(), lease.clone());
        self.prune_expired_mcp_tokens(now_unix_ms);
        Ok(lease.to_snapshot(token))
    }

    pub fn authorize_mcp_tool_call(
        &self,
        token: &str,
        tool_name: &str,
        audience: &str,
        now_unix_ms: u64,
    ) -> Result<McpAuthorizedToolCall, McpTokenAuthorizationError> {
        if self.quarantine_mode {
            return Err(McpTokenAuthorizationError::QuarantineModeActive);
        }
        let Some(trimmed_token) = normalize_non_empty_label(token) else {
            return Err(McpTokenAuthorizationError::InvalidToken);
        };
        let Some(tool_key) = normalize_mcp_tool_key(tool_name) else {
            return Err(McpTokenAuthorizationError::InvalidToolName);
        };
        let Some(normalized_audience) = normalize_non_empty_label(audience) else {
            return Err(McpTokenAuthorizationError::InvalidAudience);
        };

        let policy = self
            .mcp_tool_policies
            .get(tool_key.as_str())
            .ok_or_else(|| {
                McpTokenAuthorizationError::ToolPolicyNotFound(tool_name.trim().to_string())
            })?;
        if policy.audience != normalized_audience {
            return Err(McpTokenAuthorizationError::PolicyAudienceMismatch {
                tool_name: policy.tool_name.clone(),
                expected: policy.audience.clone(),
                actual: normalized_audience.clone(),
            });
        }

        let lease = self
            .mcp_tokens
            .get(trimmed_token.as_str())
            .ok_or(McpTokenAuthorizationError::InvalidToken)?;
        if lease.revoked {
            return Err(McpTokenAuthorizationError::TokenRevoked);
        }
        if now_unix_ms >= lease.expires_at_unix_ms {
            return Err(McpTokenAuthorizationError::TokenExpired {
                expires_at_unix_ms: lease.expires_at_unix_ms,
                now_unix_ms,
            });
        }
        if lease.audience != normalized_audience {
            return Err(McpTokenAuthorizationError::TokenAudienceMismatch {
                expected: lease.audience.clone(),
                actual: normalized_audience,
            });
        }

        let Some(runtime) = self.extensions.get(lease.extension_id.as_str()) else {
            return Err(McpTokenAuthorizationError::ExtensionInactive(
                lease.extension_id.clone(),
            ));
        };
        if !matches!(runtime.state, ExtensionState::Enabled) {
            return Err(McpTokenAuthorizationError::ExtensionInactive(
                lease.extension_id.clone(),
            ));
        }
        if !lease
            .scopes
            .iter()
            .any(|scope| scope == &policy.required_scope)
        {
            return Err(McpTokenAuthorizationError::ScopeMissing {
                required_scope: policy.required_scope.clone(),
            });
        }
        if !runtime
            .manifest
            .declared_capabilities
            .iter()
            .any(|scope| scope.trim() == policy.required_scope)
        {
            return Err(McpTokenAuthorizationError::ScopeMissing {
                required_scope: policy.required_scope.clone(),
            });
        }
        let extension_has_destructive_surface = has_granted_destructive_permission(runtime)
            || declared_destructive_side_effect(runtime);
        if matches!(policy.risk_class, McpToolRiskClass::ReadOnly)
            && !policy_looks_read_only(policy)
        {
            return Err(McpTokenAuthorizationError::DestructiveToolBlocked {
                tool_name: policy.tool_name.clone(),
                reason: "read-only risk class requires explicit read-only scope/tool semantics"
                    .to_string(),
            });
        }
        if extension_has_destructive_surface
            && !matches!(policy.risk_class, McpToolRiskClass::Destructive)
            && !policy_looks_read_only(policy)
        {
            return Err(McpTokenAuthorizationError::DestructiveToolBlocked {
                tool_name: policy.tool_name.clone(),
                reason: "extension has destructive surface; ambiguous tool policies must use destructive risk class"
                    .to_string(),
            });
        }
        if policy_looks_destructive(policy)
            && !matches!(policy.risk_class, McpToolRiskClass::Destructive)
        {
            return Err(McpTokenAuthorizationError::DestructiveToolBlocked {
                tool_name: policy.tool_name.clone(),
                reason: "policy risk class must be destructive for destructive semantics"
                    .to_string(),
            });
        }
        if matches!(policy.risk_class, McpToolRiskClass::Destructive) {
            if !has_granted_destructive_permission(runtime) {
                return Err(McpTokenAuthorizationError::DestructiveToolBlocked {
                    tool_name: policy.tool_name.clone(),
                    reason: "extension lacks granted destructive permissions".to_string(),
                });
            }
            if !declared_destructive_side_effect(runtime) {
                return Err(McpTokenAuthorizationError::DestructiveToolBlocked {
                    tool_name: policy.tool_name.clone(),
                    reason: "manifest declared_side_effects missing destructive disclosure"
                        .to_string(),
                });
            }
            if runtime.manifest.requires_overbroad_approval() && !runtime.overbroad_approved {
                return Err(McpTokenAuthorizationError::DestructiveToolBlocked {
                    tool_name: policy.tool_name.clone(),
                    reason: "overbroad approval required for destructive tool".to_string(),
                });
            }
        }

        Ok(McpAuthorizedToolCall {
            extension_id: lease.extension_id.clone(),
            session_id: lease.session_id.clone(),
            tool_name: policy.tool_name.clone(),
            audience: policy.audience.clone(),
            required_scope: policy.required_scope.clone(),
        })
    }

    pub fn revoke_mcp_session_tokens(&mut self, session_id: &str) -> usize {
        let Some(normalized_session_id) = normalize_non_empty_label(session_id) else {
            return 0;
        };
        let mut revoked = 0usize;
        for lease in self.mcp_tokens.values_mut() {
            if lease.session_id == normalized_session_id && !lease.revoked {
                lease.revoked = true;
                revoked = revoked.saturating_add(1);
            }
        }
        revoked
    }

    pub fn prune_expired_mcp_tokens(&mut self, now_unix_ms: u64) -> usize {
        let before = self.mcp_tokens.len();
        self.mcp_tokens
            .retain(|_, lease| lease.expires_at_unix_ms > now_unix_ms);
        before.saturating_sub(self.mcp_tokens.len())
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
        let mut revoke_mcp_tokens = false;
        {
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
            if !granted && matches!(runtime.state, ExtensionState::Enabled) {
                runtime.state = ExtensionState::Disabled;
                runtime.last_error = Some(format!(
                    "permission {} revoked while enabled; extension disabled fail-closed",
                    permission.label()
                ));
                revoke_mcp_tokens = true;
            }
        }
        if revoke_mcp_tokens {
            let _ = self.revoke_mcp_tokens_for_extension(id);
        }
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
        let mut revoke_mcp_tokens = false;
        {
            let runtime = self
                .extensions
                .get_mut(id)
                .ok_or_else(|| ExtensionHostError::NotFound(id.to_string()))?;
            let requested = runtime.manifest.requested_permissions.clone();
            for permission in requested {
                runtime.granted_permissions.insert(permission, false);
            }
            if matches!(runtime.state, ExtensionState::Enabled) {
                runtime.state = ExtensionState::Disabled;
                runtime.last_error = Some(
                    "permissions revoked while enabled; extension disabled fail-closed".to_string(),
                );
                revoke_mcp_tokens = true;
            }
        }
        if revoke_mcp_tokens {
            let _ = self.revoke_mcp_tokens_for_extension(id);
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

    pub fn overbroad_approval_required(&self, id: &str) -> Result<bool, ExtensionHostError> {
        let runtime = self
            .extensions
            .get(id)
            .ok_or_else(|| ExtensionHostError::NotFound(id.to_string()))?;
        Ok(runtime.manifest.requires_overbroad_approval())
    }

    pub fn set_overbroad_approved(
        &mut self,
        id: &str,
        approved: bool,
    ) -> Result<(), ExtensionHostError> {
        let mut revoke_mcp_tokens = false;
        {
            let runtime = self
                .extensions
                .get_mut(id)
                .ok_or_else(|| ExtensionHostError::NotFound(id.to_string()))?;
            runtime.overbroad_approved = approved;
            if !approved
                && runtime.manifest.requires_overbroad_approval()
                && matches!(runtime.state, ExtensionState::Enabled)
            {
                runtime.state = ExtensionState::Disabled;
                runtime.last_error = Some(
                    "overbroad approval revoked while enabled; extension disabled fail-closed"
                        .to_string(),
                );
                revoke_mcp_tokens = true;
            }
        }
        if revoke_mcp_tokens {
            let _ = self.revoke_mcp_tokens_for_extension(id);
        }
        Ok(())
    }

    pub fn set_enabled(&mut self, id: &str, enabled: bool) -> Result<(), ExtensionHostError> {
        if enabled {
            if self.quarantine_mode {
                return Err(ExtensionHostError::QuarantineModeActive {
                    action: "enable extension".to_string(),
                });
            }
            let runtime = self
                .extensions
                .get(id)
                .ok_or_else(|| ExtensionHostError::NotFound(id.to_string()))?;
            if let Err(error) = runtime
                .manifest
                .security_gate(self.forge_version.as_str(), &self.trusted_manifest_signers)
            {
                return Err(ExtensionHostError::SecurityPolicyBlocked {
                    extension_id: id.to_string(),
                    reason: error.to_string(),
                });
            }
            if runtime.manifest.requires_overbroad_approval() && !runtime.overbroad_approved {
                return Err(ExtensionHostError::OverbroadApprovalRequired {
                    extension_id: id.to_string(),
                    permissions: runtime.manifest.requested_permissions.clone(),
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

        let mut revoke_mcp_tokens = false;
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
            revoke_mcp_tokens = true;
        } else {
            revoke_mcp_tokens = true;
        }
        if revoke_mcp_tokens {
            let _ = self.revoke_mcp_tokens_for_extension(id);
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
        let _ = self.revoke_mcp_tokens_for_extension(id);
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
                    overbroad_approved: runtime.overbroad_approved,
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
            runtime.overbroad_approved = entry.overbroad_approved;

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
    let viewer_manifest = ExtensionManifest {
        id: "viewer-session-inspector".to_string(),
        display_name: "Session Inspector".to_string(),
        publisher: FORGE_BUILTIN_MANIFEST_PUBLISHER.to_string(),
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
            key_id: FORGE_BUILTIN_MANIFEST_KEY_ID.to_string(),
            algorithm: "ed25519".to_string(),
            value: FORGE_BUILTIN_VIEWER_SIGNATURE_BASE64.to_string(),
        }),
        revoked: false,
    };
    let _ = host.register(viewer_manifest);

    let provider_manifest = ExtensionManifest {
        id: "provider-openai".to_string(),
        display_name: "OpenAI Provider Adapter".to_string(),
        publisher: FORGE_BUILTIN_MANIFEST_PUBLISHER.to_string(),
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
            key_id: FORGE_BUILTIN_MANIFEST_KEY_ID.to_string(),
            algorithm: "ed25519".to_string(),
            value: FORGE_BUILTIN_PROVIDER_SIGNATURE_BASE64.to_string(),
        }),
        revoked: false,
    };
    let _ = host.register(provider_manifest);
    host
}

#[cfg(test)]
mod tests {
    use super::{
        ExtensionClass, ExtensionHost, ExtensionHostError, ExtensionManifest,
        ExtensionManifestSignature, ExtensionPermission, ExtensionState, McpToolRiskClass,
        TrustedManifestSigner, default_extension_host,
    };
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};

    const TEST_MANIFEST_KEY_ID: &str = "test-ed25519";
    const TEST_MANIFEST_PUBLISHER: &str = "forge-test";

    fn test_manifest_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[
            0x99, 0x04, 0x1a, 0x2b, 0x74, 0x88, 0x5d, 0x03, 0x18, 0xa4, 0xcd, 0x56, 0xf0, 0x32,
            0x0f, 0x44, 0x5e, 0x6a, 0x9d, 0x11, 0x70, 0x1c, 0xe8, 0x05, 0xb3, 0x63, 0x27, 0xfa,
            0x80, 0x9c, 0xde, 0x6b,
        ])
    }

    fn register_test_manifest_signer(host: &mut ExtensionHost) {
        let signing_key = test_manifest_signing_key();
        host.register_trusted_manifest_signer(TrustedManifestSigner {
            key_id: TEST_MANIFEST_KEY_ID.to_string(),
            publisher: TEST_MANIFEST_PUBLISHER.to_string(),
            verifying_key: signing_key.verifying_key(),
        });
    }

    fn sign_manifest_for_tests(manifest: &ExtensionManifest) -> Option<ExtensionManifestSignature> {
        let payload = manifest.signature_payload_json()?;
        let signing_key = test_manifest_signing_key();
        let signature = signing_key.sign(payload.as_slice());
        Some(ExtensionManifestSignature {
            key_id: TEST_MANIFEST_KEY_ID.to_string(),
            algorithm: "ed25519".to_string(),
            value: super::BASE64_STANDARD.encode(signature.to_bytes()),
        })
    }

    fn provider_manifest() -> ExtensionManifest {
        let mut manifest = ExtensionManifest {
            id: "provider".to_string(),
            display_name: "Provider".to_string(),
            publisher: TEST_MANIFEST_PUBLISHER.to_string(),
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
            signature: None,
            revoked: false,
        };
        manifest.signature = sign_manifest_for_tests(&manifest);
        manifest
    }

    fn overbroad_manifest() -> ExtensionManifest {
        let mut manifest = ExtensionManifest {
            id: "overbroad-tool".to_string(),
            display_name: "Overbroad Tool".to_string(),
            publisher: TEST_MANIFEST_PUBLISHER.to_string(),
            version: "1.0.0".to_string(),
            minimum_forge_version: "0.1.0".to_string(),
            package_checksum_sha256:
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
            class: ExtensionClass::Tool,
            idle_cost_mb: 18,
            startup_cost_ms: 55,
            memory_budget_mb: 128,
            cpu_budget_percent: 20,
            requires_network: true,
            background_activity: "tool execution".to_string(),
            requested_permissions: vec![
                ExtensionPermission::Shell,
                ExtensionPermission::Network,
                ExtensionPermission::FilesystemEdits,
            ],
            declared_capabilities: vec!["tool.exec".to_string()],
            declared_side_effects: vec![
                "filesystem-write".to_string(),
                "network-egress".to_string(),
            ],
            signature: None,
            revoked: false,
        };
        manifest.signature = sign_manifest_for_tests(&manifest);
        manifest
    }

    fn overbroad_ambiguous_manifest() -> ExtensionManifest {
        let mut manifest = ExtensionManifest {
            id: "overbroad-ambiguous-tool".to_string(),
            display_name: "Overbroad Ambiguous Tool".to_string(),
            publisher: TEST_MANIFEST_PUBLISHER.to_string(),
            version: "1.0.0".to_string(),
            minimum_forge_version: "0.1.0".to_string(),
            package_checksum_sha256:
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_string(),
            class: ExtensionClass::Tool,
            idle_cost_mb: 18,
            startup_cost_ms: 55,
            memory_budget_mb: 128,
            cpu_budget_percent: 20,
            requires_network: true,
            background_activity: "tool execution".to_string(),
            requested_permissions: vec![
                ExtensionPermission::Shell,
                ExtensionPermission::Network,
                ExtensionPermission::FilesystemEdits,
            ],
            declared_capabilities: vec!["tool.task".to_string()],
            declared_side_effects: vec![
                "filesystem-write".to_string(),
                "network-egress".to_string(),
            ],
            signature: None,
            revoked: false,
        };
        manifest.signature = sign_manifest_for_tests(&manifest);
        manifest
    }

    #[test]
    fn set_mcp_tool_policy_defaults_risk_class_to_mutating() {
        let mut host = ExtensionHost::new();
        let configured = host.set_mcp_tool_policy("health.status", "health.status", "mcp://tools");
        assert!(configured.is_ok());
        let policy = host.mcp_tool_policy("health.status");
        assert!(policy.is_some());
        let policy = match policy {
            Some(value) => value,
            None => return,
        };
        assert!(matches!(policy.risk_class, McpToolRiskClass::Mutating));
    }

    #[test]
    fn enabling_requires_requested_permissions() {
        let mut host = ExtensionHost::new();
        register_test_manifest_signer(&mut host);
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
        register_test_manifest_signer(&mut host);
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
    fn enabling_manifest_with_unknown_signer_key_is_blocked() {
        let mut host = ExtensionHost::new();
        register_test_manifest_signer(&mut host);
        let mut manifest = provider_manifest();
        let signature = manifest.signature.clone();
        assert!(signature.is_some());
        let mut signature = match signature {
            Some(value) => value,
            None => return,
        };
        signature.key_id = "unknown-signer".to_string();
        manifest.signature = Some(signature);
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
    fn enabling_manifest_with_tampered_signature_payload_is_blocked() {
        let mut host = ExtensionHost::new();
        register_test_manifest_signer(&mut host);
        let mut manifest = provider_manifest();
        manifest.display_name = "Provider (tampered)".to_string();
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
    fn overbroad_manifest_requires_explicit_approval() {
        let mut host = ExtensionHost::new();
        register_test_manifest_signer(&mut host);
        assert!(host.register(overbroad_manifest()).is_ok());
        assert!(host.grant_all_permissions("overbroad-tool").is_ok());

        let required = host.overbroad_approval_required("overbroad-tool");
        assert_eq!(required.ok(), Some(true));

        let enable_without_approval = host.set_enabled("overbroad-tool", true);
        assert!(enable_without_approval.is_err());
        let error = match enable_without_approval {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            error,
            ExtensionHostError::OverbroadApprovalRequired { .. }
        ));

        assert!(host.set_overbroad_approved("overbroad-tool", true).is_ok());
        assert!(host.set_enabled("overbroad-tool", true).is_ok());
    }

    #[test]
    fn revoking_overbroad_approval_disables_extension_and_revokes_mcp_tokens() {
        let mut host = ExtensionHost::new();
        register_test_manifest_signer(&mut host);
        assert!(host.register(overbroad_manifest()).is_ok());
        assert!(host.grant_all_permissions("overbroad-tool").is_ok());
        assert!(host.set_overbroad_approved("overbroad-tool", true).is_ok());
        assert!(host.set_enabled("overbroad-tool", true).is_ok());
        assert!(
            host.set_mcp_tool_policy("tool.exec", "tool.exec", "mcp://tools/exec")
                .is_ok()
        );

        let issued = host.issue_mcp_scoped_token(
            "overbroad-tool",
            "session-overbroad-revoke",
            "mcp://tools/exec",
            vec!["tool.exec".to_string()],
            10_000,
            1_000,
        );
        assert!(issued.is_ok());
        let issued = match issued {
            Ok(value) => value,
            Err(_) => return,
        };

        assert!(host.set_overbroad_approved("overbroad-tool", false).is_ok());
        let runtime = host.get("overbroad-tool");
        assert!(runtime.is_some());
        let runtime = match runtime {
            Some(value) => value,
            None => return,
        };
        assert_eq!(runtime.state, ExtensionState::Disabled);
        assert!(
            runtime
                .last_error
                .as_deref()
                .unwrap_or_default()
                .contains("overbroad approval revoked")
        );

        let denied = host.authorize_mcp_tool_call(
            issued.token.as_str(),
            "tool.exec",
            "mcp://tools/exec",
            1_100,
        );
        assert!(denied.is_err());
        let denied = match denied {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            denied,
            super::McpTokenAuthorizationError::TokenRevoked
        ));

        let reenable = host.set_enabled("overbroad-tool", true);
        assert!(reenable.is_err());
        let reenable = match reenable {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            reenable,
            ExtensionHostError::OverbroadApprovalRequired { .. }
        ));
    }

    #[test]
    fn enabling_revoked_manifest_is_blocked() {
        let mut host = ExtensionHost::new();
        register_test_manifest_signer(&mut host);
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
        register_test_manifest_signer(&mut host);
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
        register_test_manifest_signer(&mut host);
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
        register_test_manifest_signer(&mut host);
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
    fn revoking_permission_while_enabled_disables_extension_and_revokes_tokens() {
        let mut host = ExtensionHost::new();
        register_test_manifest_signer(&mut host);
        assert!(host.register(provider_manifest()).is_ok());
        assert!(host.grant_all_permissions("provider").is_ok());
        assert!(host.set_enabled("provider", true).is_ok());
        assert!(
            host.set_mcp_tool_policy("chat.send", "provider.chat", "mcp://tools/chat")
                .is_ok()
        );

        let issued = host.issue_mcp_scoped_token(
            "provider",
            "session-permission-revoke",
            "mcp://tools/chat",
            vec!["provider.chat".to_string()],
            10_000,
            1_000,
        );
        assert!(issued.is_ok());
        let issued = match issued {
            Ok(value) => value,
            Err(_) => return,
        };

        assert!(
            host.set_permission("provider", ExtensionPermission::Network, false)
                .is_ok()
        );
        let runtime = host.get("provider");
        assert!(runtime.is_some());
        let runtime = match runtime {
            Some(value) => value,
            None => return,
        };
        assert_eq!(runtime.state, ExtensionState::Disabled);
        assert!(
            runtime
                .last_error
                .as_deref()
                .unwrap_or_default()
                .contains("permission network revoked")
        );

        let denied = host.authorize_mcp_tool_call(
            issued.token.as_str(),
            "chat.send",
            "mcp://tools/chat",
            1_100,
        );
        assert!(denied.is_err());
        let denied = match denied {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            denied,
            super::McpTokenAuthorizationError::TokenRevoked
        ));
    }

    #[test]
    fn revoking_all_permissions_while_enabled_disables_extension_and_revokes_tokens() {
        let mut host = ExtensionHost::new();
        register_test_manifest_signer(&mut host);
        assert!(host.register(provider_manifest()).is_ok());
        assert!(host.grant_all_permissions("provider").is_ok());
        assert!(host.set_enabled("provider", true).is_ok());
        assert!(
            host.set_mcp_tool_policy("chat.send", "provider.chat", "mcp://tools/chat")
                .is_ok()
        );

        let issued = host.issue_mcp_scoped_token(
            "provider",
            "session-bulk-revoke",
            "mcp://tools/chat",
            vec!["provider.chat".to_string()],
            10_000,
            1_000,
        );
        assert!(issued.is_ok());
        let issued = match issued {
            Ok(value) => value,
            Err(_) => return,
        };

        assert!(host.revoke_all_permissions("provider").is_ok());
        let runtime = host.get("provider");
        assert!(runtime.is_some());
        let runtime = match runtime {
            Some(value) => value,
            None => return,
        };
        assert_eq!(runtime.state, ExtensionState::Disabled);
        assert!(
            runtime
                .last_error
                .as_deref()
                .unwrap_or_default()
                .contains("permissions revoked while enabled")
        );

        let denied = host.authorize_mcp_tool_call(
            issued.token.as_str(),
            "chat.send",
            "mcp://tools/chat",
            1_100,
        );
        assert!(denied.is_err());
        let denied = match denied {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            denied,
            super::McpTokenAuthorizationError::TokenRevoked
        ));
    }

    #[test]
    fn permission_grants_reflect_granted_and_revoked_state() {
        let mut host = ExtensionHost::new();
        register_test_manifest_signer(&mut host);
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

    #[test]
    fn snapshot_restore_round_trip_preserves_overbroad_approval() {
        let mut host = ExtensionHost::new();
        register_test_manifest_signer(&mut host);
        assert!(host.register(overbroad_manifest()).is_ok());
        assert!(host.set_overbroad_approved("overbroad-tool", true).is_ok());

        let snapshot = host.snapshot();
        let restored = ExtensionHost::restore(snapshot);
        assert!(restored.is_ok());
        let restored = match restored {
            Ok(value) => value,
            Err(_) => return,
        };
        let overbroad = restored.get("overbroad-tool");
        assert!(overbroad.is_some());
        let overbroad = match overbroad {
            Some(value) => value,
            None => return,
        };
        assert!(overbroad.overbroad_approved);
    }

    #[test]
    fn mcp_scoped_token_authorization_enforces_scope_and_audience() {
        let mut host = ExtensionHost::new();
        register_test_manifest_signer(&mut host);
        assert!(host.register(provider_manifest()).is_ok());
        assert!(host.grant_all_permissions("provider").is_ok());
        assert!(host.set_enabled("provider", true).is_ok());
        assert!(
            host.set_mcp_tool_policy("chat.send", "provider.chat", "mcp://tools/chat")
                .is_ok()
        );

        let issued = host.issue_mcp_scoped_token(
            "provider",
            "session-alpha",
            "mcp://tools/chat",
            vec!["provider.chat".to_string()],
            10_000,
            1_000,
        );
        assert!(issued.is_ok());
        let issued = match issued {
            Ok(value) => value,
            Err(_) => return,
        };

        let authorized = host.authorize_mcp_tool_call(
            issued.token.as_str(),
            "chat.send",
            "mcp://tools/chat",
            1_500,
        );
        assert!(authorized.is_ok());
        let authorized = match authorized {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(authorized.extension_id, "provider");
        assert_eq!(authorized.session_id, "session-alpha");
        assert_eq!(authorized.required_scope, "provider.chat");

        let audience_mismatch = host.authorize_mcp_tool_call(
            issued.token.as_str(),
            "chat.send",
            "mcp://tools/other",
            1_500,
        );
        assert!(audience_mismatch.is_err());
        let audience_mismatch = match audience_mismatch {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            audience_mismatch,
            super::McpTokenAuthorizationError::PolicyAudienceMismatch { .. }
        ));
    }

    #[test]
    fn destructive_tool_scope_is_blocked_when_policy_risk_class_is_not_destructive() {
        let mut host = ExtensionHost::new();
        register_test_manifest_signer(&mut host);
        assert!(host.register(overbroad_manifest()).is_ok());
        assert!(host.grant_all_permissions("overbroad-tool").is_ok());
        assert!(host.set_overbroad_approved("overbroad-tool", true).is_ok());
        assert!(host.set_enabled("overbroad-tool", true).is_ok());
        assert!(
            host.set_mcp_tool_policy("health.status", "tool.exec", "mcp://tools/exec")
                .is_ok()
        );

        let issued = host.issue_mcp_scoped_token(
            "overbroad-tool",
            "session-danger-default-risk",
            "mcp://tools/exec",
            vec!["tool.exec".to_string()],
            10_000,
            1_000,
        );
        assert!(issued.is_ok());
        let issued = match issued {
            Ok(value) => value,
            Err(_) => return,
        };

        let denied = host.authorize_mcp_tool_call(
            issued.token.as_str(),
            "health.status",
            "mcp://tools/exec",
            1_100,
        );
        assert!(denied.is_err());
        let denied = match denied {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            denied,
            super::McpTokenAuthorizationError::DestructiveToolBlocked { .. }
        ));
    }

    #[test]
    fn ambiguous_tool_scope_on_destructive_extension_requires_explicit_destructive_risk() {
        let mut host = ExtensionHost::new();
        register_test_manifest_signer(&mut host);
        assert!(host.register(overbroad_ambiguous_manifest()).is_ok());
        assert!(
            host.grant_all_permissions("overbroad-ambiguous-tool")
                .is_ok()
        );
        assert!(
            host.set_overbroad_approved("overbroad-ambiguous-tool", true)
                .is_ok()
        );
        assert!(host.set_enabled("overbroad-ambiguous-tool", true).is_ok());
        assert!(
            host.set_mcp_tool_policy("ops.task", "tool.task", "mcp://tools/task")
                .is_ok()
        );

        let issued = host.issue_mcp_scoped_token(
            "overbroad-ambiguous-tool",
            "session-danger-ambiguous",
            "mcp://tools/task",
            vec!["tool.task".to_string()],
            10_000,
            1_000,
        );
        assert!(issued.is_ok());
        let issued = match issued {
            Ok(value) => value,
            Err(_) => return,
        };

        let denied = host.authorize_mcp_tool_call(
            issued.token.as_str(),
            "ops.task",
            "mcp://tools/task",
            1_100,
        );
        assert!(denied.is_err());
        let denied = match denied {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            denied,
            super::McpTokenAuthorizationError::DestructiveToolBlocked { .. }
        ));
    }

    #[test]
    fn destructive_tool_is_allowed_when_policy_is_explicit_and_permissions_match() {
        let mut host = ExtensionHost::new();
        register_test_manifest_signer(&mut host);
        assert!(host.register(overbroad_manifest()).is_ok());
        assert!(host.grant_all_permissions("overbroad-tool").is_ok());
        assert!(host.set_overbroad_approved("overbroad-tool", true).is_ok());
        assert!(host.set_enabled("overbroad-tool", true).is_ok());
        assert!(
            host.set_mcp_tool_policy_with_risk(
                "health.status",
                "tool.exec",
                "mcp://tools/exec",
                McpToolRiskClass::Destructive,
            )
            .is_ok()
        );

        let issued = host.issue_mcp_scoped_token(
            "overbroad-tool",
            "session-danger-explicit-risk",
            "mcp://tools/exec",
            vec!["tool.exec".to_string()],
            10_000,
            1_000,
        );
        assert!(issued.is_ok());
        let issued = match issued {
            Ok(value) => value,
            Err(_) => return,
        };

        let authorized = host.authorize_mcp_tool_call(
            issued.token.as_str(),
            "health.status",
            "mcp://tools/exec",
            1_100,
        );
        assert!(authorized.is_ok());
        let authorized = match authorized {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(authorized.required_scope, "tool.exec");
    }

    #[test]
    fn destructive_policy_is_blocked_without_destructive_permissions_and_disclosure() {
        let mut host = ExtensionHost::new();
        register_test_manifest_signer(&mut host);
        assert!(host.register(provider_manifest()).is_ok());
        assert!(host.grant_all_permissions("provider").is_ok());
        assert!(host.set_enabled("provider", true).is_ok());
        assert!(
            host.set_mcp_tool_policy_with_risk(
                "chat.send",
                "provider.chat",
                "mcp://tools/chat",
                McpToolRiskClass::Destructive,
            )
            .is_ok()
        );

        let issued = host.issue_mcp_scoped_token(
            "provider",
            "session-danger-provider",
            "mcp://tools/chat",
            vec!["provider.chat".to_string()],
            10_000,
            1_000,
        );
        assert!(issued.is_ok());
        let issued = match issued {
            Ok(value) => value,
            Err(_) => return,
        };

        let denied = host.authorize_mcp_tool_call(
            issued.token.as_str(),
            "chat.send",
            "mcp://tools/chat",
            1_100,
        );
        assert!(denied.is_err());
        let denied = match denied {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            denied,
            super::McpTokenAuthorizationError::DestructiveToolBlocked { .. }
        ));
    }

    #[test]
    fn mcp_token_issue_blocks_undeclared_scopes() {
        let mut host = ExtensionHost::new();
        register_test_manifest_signer(&mut host);
        assert!(host.register(provider_manifest()).is_ok());
        assert!(host.grant_all_permissions("provider").is_ok());
        assert!(host.set_enabled("provider", true).is_ok());
        assert!(
            host.set_mcp_tool_policy("chat.send", "provider.chat", "mcp://tools/chat")
                .is_ok()
        );

        let issued = host.issue_mcp_scoped_token(
            "provider",
            "session-alpha",
            "mcp://tools/chat",
            vec!["provider.unknown".to_string()],
            10_000,
            1_000,
        );
        assert!(issued.is_err());
        let issued = match issued {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            issued,
            super::McpTokenIssueError::ScopeNotDeclared { .. }
        ));
    }

    #[test]
    fn mcp_session_revocation_blocks_authorization() {
        let mut host = ExtensionHost::new();
        register_test_manifest_signer(&mut host);
        assert!(host.register(provider_manifest()).is_ok());
        assert!(host.grant_all_permissions("provider").is_ok());
        assert!(host.set_enabled("provider", true).is_ok());
        assert!(
            host.set_mcp_tool_policy("chat.send", "provider.chat", "mcp://tools/chat")
                .is_ok()
        );

        let issued = host.issue_mcp_scoped_token(
            "provider",
            "session-revoke",
            "mcp://tools/chat",
            vec!["provider.chat".to_string()],
            10_000,
            1_000,
        );
        assert!(issued.is_ok());
        let issued = match issued {
            Ok(value) => value,
            Err(_) => return,
        };

        let revoked = host.revoke_mcp_session_tokens("session-revoke");
        assert_eq!(revoked, 1);

        let authorized = host.authorize_mcp_tool_call(
            issued.token.as_str(),
            "chat.send",
            "mcp://tools/chat",
            1_200,
        );
        assert!(authorized.is_err());
        let authorized = match authorized {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            authorized,
            super::McpTokenAuthorizationError::TokenRevoked
        ));
    }

    #[test]
    fn disabling_extension_revokes_mcp_tokens() {
        let mut host = ExtensionHost::new();
        register_test_manifest_signer(&mut host);
        assert!(host.register(provider_manifest()).is_ok());
        assert!(host.grant_all_permissions("provider").is_ok());
        assert!(host.set_enabled("provider", true).is_ok());
        assert!(
            host.set_mcp_tool_policy("chat.send", "provider.chat", "mcp://tools/chat")
                .is_ok()
        );

        let issued = host.issue_mcp_scoped_token(
            "provider",
            "session-disable",
            "mcp://tools/chat",
            vec!["provider.chat".to_string()],
            10_000,
            1_000,
        );
        assert!(issued.is_ok());
        let issued = match issued {
            Ok(value) => value,
            Err(_) => return,
        };

        assert!(host.set_enabled("provider", false).is_ok());

        let authorized = host.authorize_mcp_tool_call(
            issued.token.as_str(),
            "chat.send",
            "mcp://tools/chat",
            1_500,
        );
        assert!(authorized.is_err());
        let authorized = match authorized {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            authorized,
            super::McpTokenAuthorizationError::TokenRevoked
        ));
    }

    #[test]
    fn mcp_issue_requires_matching_tool_policy() {
        let mut host = ExtensionHost::new();
        register_test_manifest_signer(&mut host);
        assert!(host.register(provider_manifest()).is_ok());
        assert!(host.grant_all_permissions("provider").is_ok());
        assert!(host.set_enabled("provider", true).is_ok());

        let issued = host.issue_mcp_scoped_token(
            "provider",
            "session-alpha",
            "mcp://tools/chat",
            vec!["provider.chat".to_string()],
            10_000,
            1_000,
        );
        assert!(issued.is_err());
        let issued = match issued {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            issued,
            super::McpTokenIssueError::NoMatchingToolPolicy { .. }
        ));
    }

    #[test]
    fn quarantine_mode_blocks_extension_enablement() {
        let mut host = ExtensionHost::new();
        host.set_quarantine_mode(true);
        register_test_manifest_signer(&mut host);
        assert!(host.register(provider_manifest()).is_ok());
        assert!(host.grant_all_permissions("provider").is_ok());

        let enabled = host.set_enabled("provider", true);
        assert!(enabled.is_err());
        let enabled = match enabled {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            enabled,
            ExtensionHostError::QuarantineModeActive { .. }
        ));
    }

    #[test]
    fn quarantine_mode_blocks_mcp_issue_and_authorization() {
        let mut host = ExtensionHost::new();
        register_test_manifest_signer(&mut host);
        assert!(host.register(provider_manifest()).is_ok());
        assert!(host.grant_all_permissions("provider").is_ok());
        assert!(host.set_enabled("provider", true).is_ok());
        assert!(
            host.set_mcp_tool_policy("chat.send", "provider.chat", "mcp://tools/chat")
                .is_ok()
        );

        let issued = host.issue_mcp_scoped_token(
            "provider",
            "session-pre-quarantine",
            "mcp://tools/chat",
            vec!["provider.chat".to_string()],
            10_000,
            1_000,
        );
        assert!(issued.is_ok());
        let issued = match issued {
            Ok(value) => value,
            Err(_) => return,
        };

        host.set_quarantine_mode(true);

        let denied_issue = host.issue_mcp_scoped_token(
            "provider",
            "session-quarantine",
            "mcp://tools/chat",
            vec!["provider.chat".to_string()],
            10_000,
            1_100,
        );
        assert!(denied_issue.is_err());
        let denied_issue = match denied_issue {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            denied_issue,
            super::McpTokenIssueError::QuarantineModeActive
        ));

        let denied_auth = host.authorize_mcp_tool_call(
            issued.token.as_str(),
            "chat.send",
            "mcp://tools/chat",
            1_200,
        );
        assert!(denied_auth.is_err());
        let denied_auth = match denied_auth {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            denied_auth,
            super::McpTokenAuthorizationError::QuarantineModeActive
        ));
    }
}
