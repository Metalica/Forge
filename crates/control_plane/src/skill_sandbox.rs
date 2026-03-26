use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SkillArtifactClass {
    Skill,
    Workflow,
    Script,
}

impl SkillArtifactClass {
    pub const fn label(self) -> &'static str {
        match self {
            SkillArtifactClass::Skill => "skill",
            SkillArtifactClass::Workflow => "workflow",
            SkillArtifactClass::Script => "script",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillAssetLock {
    pub relative_path: String,
    pub sha256_hex: String,
    #[serde(default)]
    pub reviewed_offline: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillSandboxManifest {
    pub id: String,
    pub artifact_class: SkillArtifactClass,
    pub sandbox_root: String,
    #[serde(default)]
    pub extension_id: Option<String>,
    #[serde(default)]
    pub allow_network: bool,
    #[serde(default)]
    pub allow_secret_env_inheritance: bool,
    #[serde(default)]
    pub inherited_env_allowlist: Vec<String>,
    #[serde(default)]
    pub asset_locks: Vec<SkillAssetLock>,
}

impl SkillSandboxManifest {
    pub fn validate(&self) -> Result<(), SkillSandboxError> {
        if self.id.trim().is_empty() {
            return Err(SkillSandboxError::InvalidManifest(
                "sandbox id cannot be empty".to_string(),
            ));
        }
        if self.sandbox_root.trim().is_empty() {
            return Err(SkillSandboxError::InvalidManifest(
                "sandbox_root cannot be empty".to_string(),
            ));
        }
        let mut seen_asset_paths = HashSet::new();
        for lock in &self.asset_locks {
            validate_relative_asset_path(lock.relative_path.as_str())?;
            if !is_sha256_hex(lock.sha256_hex.as_str()) {
                return Err(SkillSandboxError::InvalidManifest(format!(
                    "asset lock hash is not sha256 hex: {}",
                    lock.relative_path
                )));
            }
            if !seen_asset_paths.insert(normalize_path_like(lock.relative_path.as_str())) {
                return Err(SkillSandboxError::InvalidManifest(format!(
                    "duplicate asset lock path: {}",
                    lock.relative_path
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillSandboxRuntimeSnapshot {
    pub manifest: SkillSandboxManifest,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SkillSandboxRuntime {
    manifest: SkillSandboxManifest,
    last_error: Option<String>,
}

impl SkillSandboxRuntime {
    fn new(manifest: SkillSandboxManifest) -> Self {
        Self {
            manifest,
            last_error: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillLaunchRequest {
    pub sandbox_id: String,
    pub requested_network: bool,
    pub inherited_env: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillLaunchPlan {
    pub sandbox_id: String,
    pub artifact_class: SkillArtifactClass,
    pub sandbox_root: String,
    pub network_enabled: bool,
    pub inherited_env: HashMap<String, String>,
    pub blocked_env_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkillSandboxError {
    InvalidManifest(String),
    NotFound(String),
    SandboxBoundaryConflict {
        sandbox_id: String,
        sandbox_root: String,
        main_runtime_root: String,
    },
    SandboxOverlapConflict {
        sandbox_id: String,
        existing_sandbox_id: String,
        sandbox_root: String,
        existing_sandbox_root: String,
    },
    NetworkBlockedByDefault {
        sandbox_id: String,
    },
    AssetReviewRequired {
        sandbox_id: String,
        relative_path: String,
    },
    AssetNotLocked {
        sandbox_id: String,
        relative_path: String,
    },
    AssetHashMismatch {
        sandbox_id: String,
        relative_path: String,
        expected_sha256_hex: String,
        actual_sha256_hex: String,
    },
}

impl fmt::Display for SkillSandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SkillSandboxError::InvalidManifest(message) => {
                write!(f, "invalid skill sandbox manifest: {message}")
            }
            SkillSandboxError::NotFound(id) => write!(f, "skill sandbox not found: {id}"),
            SkillSandboxError::SandboxBoundaryConflict {
                sandbox_id,
                sandbox_root,
                main_runtime_root,
            } => write!(
                f,
                "sandbox `{sandbox_id}` root `{sandbox_root}` overlaps main runtime root `{main_runtime_root}`"
            ),
            SkillSandboxError::SandboxOverlapConflict {
                sandbox_id,
                existing_sandbox_id,
                sandbox_root,
                existing_sandbox_root,
            } => write!(
                f,
                "sandbox `{sandbox_id}` root `{sandbox_root}` overlaps existing sandbox `{existing_sandbox_id}` root `{existing_sandbox_root}`"
            ),
            SkillSandboxError::NetworkBlockedByDefault { sandbox_id } => {
                write!(
                    f,
                    "sandbox `{sandbox_id}` network is blocked by default policy"
                )
            }
            SkillSandboxError::AssetReviewRequired {
                sandbox_id,
                relative_path,
            } => write!(
                f,
                "sandbox `{sandbox_id}` asset `{relative_path}` requires offline review before launch"
            ),
            SkillSandboxError::AssetNotLocked {
                sandbox_id,
                relative_path,
            } => write!(
                f,
                "sandbox `{sandbox_id}` asset `{relative_path}` is not locked"
            ),
            SkillSandboxError::AssetHashMismatch {
                sandbox_id,
                relative_path,
                expected_sha256_hex,
                actual_sha256_hex,
            } => write!(
                f,
                "sandbox `{sandbox_id}` asset `{relative_path}` hash mismatch expected={expected_sha256_hex} actual={actual_sha256_hex}"
            ),
        }
    }
}

impl Error for SkillSandboxError {}

#[derive(Debug)]
pub struct SkillSandboxHost {
    main_runtime_root: String,
    sandboxes: HashMap<String, SkillSandboxRuntime>,
}

impl SkillSandboxHost {
    pub fn new(main_runtime_root: impl Into<String>) -> Self {
        Self {
            main_runtime_root: main_runtime_root.into(),
            sandboxes: HashMap::new(),
        }
    }

    pub fn register(&mut self, manifest: SkillSandboxManifest) -> Result<(), SkillSandboxError> {
        manifest.validate()?;
        let sandbox_root = normalize_path_like(manifest.sandbox_root.as_str());
        let main_runtime_root = normalize_path_like(self.main_runtime_root.as_str());
        if paths_overlap(sandbox_root.as_str(), main_runtime_root.as_str()) {
            return Err(SkillSandboxError::SandboxBoundaryConflict {
                sandbox_id: manifest.id.clone(),
                sandbox_root: manifest.sandbox_root.clone(),
                main_runtime_root: self.main_runtime_root.clone(),
            });
        }
        for existing in self.sandboxes.values() {
            if paths_overlap(
                sandbox_root.as_str(),
                normalize_path_like(existing.manifest.sandbox_root.as_str()).as_str(),
            ) {
                return Err(SkillSandboxError::SandboxOverlapConflict {
                    sandbox_id: manifest.id.clone(),
                    existing_sandbox_id: existing.manifest.id.clone(),
                    sandbox_root: manifest.sandbox_root.clone(),
                    existing_sandbox_root: existing.manifest.sandbox_root.clone(),
                });
            }
        }
        self.sandboxes
            .insert(manifest.id.clone(), SkillSandboxRuntime::new(manifest));
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&SkillSandboxManifest> {
        self.sandboxes.get(id).map(|runtime| &runtime.manifest)
    }

    pub fn list(&self) -> Vec<&SkillSandboxManifest> {
        let mut manifests = self
            .sandboxes
            .values()
            .map(|runtime| &runtime.manifest)
            .collect::<Vec<_>>();
        manifests.sort_by_key(|manifest| manifest.id.as_str());
        manifests
    }

    pub fn prepare_launch(
        &mut self,
        request: SkillLaunchRequest,
    ) -> Result<SkillLaunchPlan, SkillSandboxError> {
        let trimmed_id = request.sandbox_id.trim().to_string();
        let runtime = self
            .sandboxes
            .get_mut(trimmed_id.as_str())
            .ok_or_else(|| SkillSandboxError::NotFound(trimmed_id.clone()))?;
        if request.requested_network && !runtime.manifest.allow_network {
            runtime.last_error = Some("network blocked by default".to_string());
            return Err(SkillSandboxError::NetworkBlockedByDefault {
                sandbox_id: runtime.manifest.id.clone(),
            });
        }
        if let Some(lock) = runtime
            .manifest
            .asset_locks
            .iter()
            .find(|lock| !lock.reviewed_offline)
        {
            runtime.last_error = Some(format!(
                "asset requires offline review: {}",
                lock.relative_path
            ));
            return Err(SkillSandboxError::AssetReviewRequired {
                sandbox_id: runtime.manifest.id.clone(),
                relative_path: lock.relative_path.clone(),
            });
        }

        let mut allowlist = default_env_allowlist();
        for key in &runtime.manifest.inherited_env_allowlist {
            if let Some(normalized) = normalize_env_key(key.as_str()) {
                allowlist.insert(normalized);
            }
        }

        let mut inherited_env = HashMap::new();
        let mut blocked_env_keys = Vec::new();
        for (key, value) in request.inherited_env {
            let Some(normalized_key) = normalize_env_key(key.as_str()) else {
                continue;
            };
            if !allowlist.contains(normalized_key.as_str()) {
                blocked_env_keys.push(key);
                continue;
            }
            if !runtime.manifest.allow_secret_env_inheritance
                && is_secret_like_env_key(normalized_key.as_str())
            {
                blocked_env_keys.push(key);
                continue;
            }
            inherited_env.insert(key, value);
        }
        blocked_env_keys.sort();
        blocked_env_keys.dedup();
        runtime.last_error = None;

        Ok(SkillLaunchPlan {
            sandbox_id: runtime.manifest.id.clone(),
            artifact_class: runtime.manifest.artifact_class,
            sandbox_root: runtime.manifest.sandbox_root.clone(),
            network_enabled: request.requested_network && runtime.manifest.allow_network,
            inherited_env,
            blocked_env_keys,
        })
    }

    pub fn lock_asset_from_bytes(
        &mut self,
        sandbox_id: &str,
        relative_path: &str,
        bytes: &[u8],
        reviewed_offline: bool,
    ) -> Result<SkillAssetLock, SkillSandboxError> {
        validate_relative_asset_path(relative_path)?;
        let trimmed_id = sandbox_id.trim().to_string();
        let runtime = self
            .sandboxes
            .get_mut(trimmed_id.as_str())
            .ok_or_else(|| SkillSandboxError::NotFound(trimmed_id.clone()))?;
        let digest_hex = sha256_hex(bytes);
        let normalized = normalize_path_like(relative_path);
        let mut replaced = false;
        for lock in &mut runtime.manifest.asset_locks {
            if normalize_path_like(lock.relative_path.as_str()) == normalized {
                lock.sha256_hex = digest_hex.clone();
                lock.reviewed_offline = reviewed_offline;
                replaced = true;
                break;
            }
        }
        if !replaced {
            runtime.manifest.asset_locks.push(SkillAssetLock {
                relative_path: relative_path.trim().to_string(),
                sha256_hex: digest_hex.clone(),
                reviewed_offline,
            });
        }
        runtime
            .manifest
            .asset_locks
            .sort_by_key(|entry| entry.relative_path.to_ascii_lowercase());
        runtime.last_error = None;
        Ok(SkillAssetLock {
            relative_path: relative_path.trim().to_string(),
            sha256_hex: digest_hex,
            reviewed_offline,
        })
    }

    pub fn set_asset_reviewed(
        &mut self,
        sandbox_id: &str,
        relative_path: &str,
        reviewed_offline: bool,
    ) -> Result<(), SkillSandboxError> {
        validate_relative_asset_path(relative_path)?;
        let trimmed_id = sandbox_id.trim().to_string();
        let runtime = self
            .sandboxes
            .get_mut(trimmed_id.as_str())
            .ok_or_else(|| SkillSandboxError::NotFound(trimmed_id.clone()))?;
        let normalized = normalize_path_like(relative_path);
        for lock in &mut runtime.manifest.asset_locks {
            if normalize_path_like(lock.relative_path.as_str()) == normalized {
                lock.reviewed_offline = reviewed_offline;
                runtime.last_error = None;
                return Ok(());
            }
        }
        Err(SkillSandboxError::AssetNotLocked {
            sandbox_id: runtime.manifest.id.clone(),
            relative_path: relative_path.trim().to_string(),
        })
    }

    pub fn verify_asset_bytes(
        &mut self,
        sandbox_id: &str,
        relative_path: &str,
        bytes: &[u8],
    ) -> Result<SkillAssetLock, SkillSandboxError> {
        validate_relative_asset_path(relative_path)?;
        let trimmed_id = sandbox_id.trim().to_string();
        let runtime = self
            .sandboxes
            .get_mut(trimmed_id.as_str())
            .ok_or_else(|| SkillSandboxError::NotFound(trimmed_id.clone()))?;
        let normalized = normalize_path_like(relative_path);
        let maybe_lock = runtime
            .manifest
            .asset_locks
            .iter()
            .find(|lock| normalize_path_like(lock.relative_path.as_str()) == normalized)
            .cloned();
        let Some(lock) = maybe_lock else {
            runtime.last_error = Some(format!("asset lock missing: {relative_path}"));
            return Err(SkillSandboxError::AssetNotLocked {
                sandbox_id: runtime.manifest.id.clone(),
                relative_path: relative_path.trim().to_string(),
            });
        };
        if !lock.reviewed_offline {
            runtime.last_error = Some(format!("asset review required: {relative_path}"));
            return Err(SkillSandboxError::AssetReviewRequired {
                sandbox_id: runtime.manifest.id.clone(),
                relative_path: lock.relative_path,
            });
        }
        let actual = sha256_hex(bytes);
        if lock.sha256_hex != actual {
            runtime.last_error = Some(format!("asset hash mismatch: {relative_path}"));
            return Err(SkillSandboxError::AssetHashMismatch {
                sandbox_id: runtime.manifest.id.clone(),
                relative_path: lock.relative_path,
                expected_sha256_hex: lock.sha256_hex,
                actual_sha256_hex: actual,
            });
        }
        runtime.last_error = None;
        Ok(lock)
    }

    pub fn snapshot(&self) -> Vec<SkillSandboxRuntimeSnapshot> {
        let mut snapshots = self
            .sandboxes
            .values()
            .map(|runtime| SkillSandboxRuntimeSnapshot {
                manifest: runtime.manifest.clone(),
                last_error: runtime.last_error.clone(),
            })
            .collect::<Vec<_>>();
        snapshots.sort_by_key(|entry| entry.manifest.id.clone());
        snapshots
    }

    pub fn restore(
        main_runtime_root: impl Into<String>,
        snapshot: Vec<SkillSandboxRuntimeSnapshot>,
    ) -> Result<Self, SkillSandboxError> {
        let mut host = SkillSandboxHost::new(main_runtime_root);
        for entry in snapshot {
            host.register(entry.manifest.clone())?;
            if let Some(runtime) = host.sandboxes.get_mut(entry.manifest.id.as_str()) {
                runtime.last_error = entry.last_error.clone();
            }
        }
        Ok(host)
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|candidate| candidate.is_ascii_hexdigit())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push_str(format!("{byte:02x}").as_str());
    }
    output
}

fn normalize_path_like(value: &str) -> String {
    value
        .trim()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

fn paths_overlap(left: &str, right: &str) -> bool {
    if left.is_empty() || right.is_empty() {
        return false;
    }
    if left == right {
        return true;
    }
    let left_prefix = format!("{left}/");
    let right_prefix = format!("{right}/");
    left.starts_with(right_prefix.as_str()) || right.starts_with(left_prefix.as_str())
}

fn validate_relative_asset_path(relative_path: &str) -> Result<(), SkillSandboxError> {
    let trimmed = relative_path.trim();
    if trimmed.is_empty() {
        return Err(SkillSandboxError::InvalidManifest(
            "asset lock path cannot be empty".to_string(),
        ));
    }
    if trimmed.contains("..") || trimmed.starts_with('/') || trimmed.contains(':') {
        return Err(SkillSandboxError::InvalidManifest(format!(
            "asset lock path must be relative and traversal-free: {relative_path}"
        )));
    }
    Ok(())
}

fn normalize_env_key(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_ascii_uppercase())
}

fn is_secret_like_env_key(key: &str) -> bool {
    let candidate = key.to_ascii_uppercase();
    candidate.contains("SECRET")
        || candidate.contains("TOKEN")
        || candidate.contains("PASSWORD")
        || candidate.contains("API_KEY")
        || candidate.contains("AUTH")
        || candidate.contains("CREDENTIAL")
        || candidate.contains("COOKIE")
        || candidate.contains("SESSION")
}

fn default_env_allowlist() -> HashSet<String> {
    [
        "PATH",
        "SYSTEMROOT",
        "WINDIR",
        "HOME",
        "USERPROFILE",
        "TMP",
        "TEMP",
        "TMPDIR",
    ]
    .iter()
    .map(|value| value.to_string())
    .collect::<HashSet<_>>()
}

#[cfg(test)]
mod tests {
    use super::{
        SkillArtifactClass, SkillLaunchRequest, SkillSandboxError, SkillSandboxHost,
        SkillSandboxManifest,
    };
    use std::collections::HashMap;

    fn base_manifest(id: &str, root: &str) -> SkillSandboxManifest {
        SkillSandboxManifest {
            id: id.to_string(),
            artifact_class: SkillArtifactClass::Skill,
            sandbox_root: root.to_string(),
            extension_id: Some("provider-openai".to_string()),
            allow_network: false,
            allow_secret_env_inheritance: false,
            inherited_env_allowlist: vec!["PATH".to_string()],
            asset_locks: Vec::new(),
        }
    }

    #[test]
    fn register_blocks_overlap_with_main_runtime_root() {
        let mut host = SkillSandboxHost::new("E:/Forge/.forge/runtime_main");
        let registered = host.register(base_manifest(
            "skill-a",
            "E:/Forge/.forge/runtime_main/skills",
        ));
        assert!(registered.is_err());
        let error = match registered {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            error,
            SkillSandboxError::SandboxBoundaryConflict { .. }
        ));
    }

    #[test]
    fn prepare_launch_blocks_network_by_default() {
        let mut host = SkillSandboxHost::new("E:/Forge/.forge/runtime_main");
        assert!(
            host.register(base_manifest("skill-a", "E:/Forge/.forge/skill_a"))
                .is_ok()
        );
        let request = SkillLaunchRequest {
            sandbox_id: "skill-a".to_string(),
            requested_network: true,
            inherited_env: HashMap::new(),
        };
        let plan = host.prepare_launch(request);
        assert!(plan.is_err());
        let error = match plan {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            error,
            SkillSandboxError::NetworkBlockedByDefault { .. }
        ));
    }

    #[test]
    fn prepare_launch_filters_secret_and_non_allowlisted_env() {
        let mut host = SkillSandboxHost::new("E:/Forge/.forge/runtime_main");
        assert!(
            host.register(base_manifest("skill-a", "E:/Forge/.forge/skill_a"))
                .is_ok()
        );

        let mut inherited_env = HashMap::new();
        inherited_env.insert("PATH".to_string(), "E:/tools".to_string());
        inherited_env.insert("OPENAI_API_KEY".to_string(), "sk-test".to_string());
        inherited_env.insert("CUSTOM_FLAG".to_string(), "1".to_string());
        let request = SkillLaunchRequest {
            sandbox_id: "skill-a".to_string(),
            requested_network: false,
            inherited_env,
        };
        let plan = host.prepare_launch(request);
        assert!(plan.is_ok());
        let plan = match plan {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(!plan.network_enabled);
        assert_eq!(
            plan.inherited_env.get("PATH").map(String::as_str),
            Some("E:/tools")
        );
        assert!(!plan.inherited_env.contains_key("OPENAI_API_KEY"));
        assert!(!plan.inherited_env.contains_key("CUSTOM_FLAG"));
        assert!(
            plan.blocked_env_keys
                .iter()
                .any(|key| key == "OPENAI_API_KEY")
        );
        assert!(plan.blocked_env_keys.iter().any(|key| key == "CUSTOM_FLAG"));
    }

    #[test]
    fn explicit_opt_in_allows_network_and_secret_inheritance() {
        let mut host = SkillSandboxHost::new("E:/Forge/.forge/runtime_main");
        let mut manifest = base_manifest("skill-a", "E:/Forge/.forge/skill_a");
        manifest.allow_network = true;
        manifest.allow_secret_env_inheritance = true;
        manifest
            .inherited_env_allowlist
            .push("OPENAI_API_KEY".to_string());
        assert!(host.register(manifest).is_ok());

        let mut inherited_env = HashMap::new();
        inherited_env.insert("PATH".to_string(), "E:/tools".to_string());
        inherited_env.insert("OPENAI_API_KEY".to_string(), "sk-test".to_string());
        let request = SkillLaunchRequest {
            sandbox_id: "skill-a".to_string(),
            requested_network: true,
            inherited_env,
        };
        let plan = host.prepare_launch(request);
        assert!(plan.is_ok());
        let plan = match plan {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(plan.network_enabled);
        assert_eq!(
            plan.inherited_env.get("OPENAI_API_KEY").map(String::as_str),
            Some("sk-test")
        );
    }

    #[test]
    fn asset_verify_requires_offline_review_and_matching_hash() {
        let mut host = SkillSandboxHost::new("E:/Forge/.forge/runtime_main");
        assert!(
            host.register(base_manifest("skill-a", "E:/Forge/.forge/skill_a"))
                .is_ok()
        );
        assert!(
            host.lock_asset_from_bytes(
                "skill-a",
                "scripts/build.ps1",
                b"Write-Output 'ok'",
                false,
            )
            .is_ok()
        );

        let verify_before_review =
            host.verify_asset_bytes("skill-a", "scripts/build.ps1", b"Write-Output 'ok'");
        assert!(verify_before_review.is_err());
        let verify_before_review = match verify_before_review {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            verify_before_review,
            SkillSandboxError::AssetReviewRequired { .. }
        ));

        assert!(
            host.set_asset_reviewed("skill-a", "scripts/build.ps1", true)
                .is_ok()
        );
        let verified =
            host.verify_asset_bytes("skill-a", "scripts/build.ps1", b"Write-Output 'ok'");
        assert!(verified.is_ok());
    }

    #[test]
    fn asset_verify_blocks_hash_mismatch() {
        let mut host = SkillSandboxHost::new("E:/Forge/.forge/runtime_main");
        assert!(
            host.register(base_manifest("skill-a", "E:/Forge/.forge/skill_a"))
                .is_ok()
        );
        assert!(
            host.lock_asset_from_bytes("skill-a", "workflow/plan.yaml", b"version: 1", true,)
                .is_ok()
        );
        let verify = host.verify_asset_bytes("skill-a", "workflow/plan.yaml", b"version: 2");
        assert!(verify.is_err());
        let verify = match verify {
            Ok(_) => return,
            Err(value) => value,
        };
        assert!(matches!(
            verify,
            SkillSandboxError::AssetHashMismatch { .. }
        ));
    }

    #[test]
    fn snapshot_restore_preserves_manifest_and_asset_locks() {
        let mut host = SkillSandboxHost::new("E:/Forge/.forge/runtime_main");
        assert!(
            host.register(base_manifest("skill-a", "E:/Forge/.forge/skill_a"))
                .is_ok()
        );
        assert!(
            host.lock_asset_from_bytes("skill-a", "scripts/build.ps1", b"Write-Output 'ok'", true,)
                .is_ok()
        );
        let snapshot = host.snapshot();
        let restored = SkillSandboxHost::restore("E:/Forge/.forge/runtime_main", snapshot);
        assert!(restored.is_ok());
        let restored = match restored {
            Ok(value) => value,
            Err(_) => return,
        };
        let manifest = restored.get("skill-a");
        assert!(manifest.is_some());
        let manifest = match manifest {
            Some(value) => value,
            None => return,
        };
        assert_eq!(manifest.asset_locks.len(), 1);
        assert!(manifest.asset_locks[0].reviewed_offline);
    }
}
