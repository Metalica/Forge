use crate::confidential_relay::ConfidentialEndpointMetadata;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::{collections::HashMap, fs, path::Path};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRegistryError {
    message: String,
}

impl SourceRegistryError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for SourceRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for SourceRegistryError {}

impl From<SourceRegistryError> for String {
    fn from(value: SourceRegistryError) -> Self {
        value.to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceKind {
    LocalModel,
    ApiModel,
    SidecarBridge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceRole {
    Chat,
    Planner,
    Coder,
    CodexSpecialist,
    Debugger,
    Verifier,
    ImageGeneration,
    VideoGeneration,
}

impl SourceRole {
    pub const fn label(self) -> &'static str {
        match self {
            SourceRole::Chat => "chat",
            SourceRole::Planner => "planner",
            SourceRole::Coder => "coder",
            SourceRole::CodexSpecialist => "codex_specialist",
            SourceRole::Debugger => "debugger",
            SourceRole::Verifier => "verifier",
            SourceRole::ImageGeneration => "image_generation",
            SourceRole::VideoGeneration => "video_generation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceEntry {
    pub id: String,
    pub display_name: String,
    pub kind: SourceKind,
    pub target: String,
    pub enabled: bool,
    pub eligible_roles: Vec<SourceRole>,
    pub default_roles: Vec<SourceRole>,
    #[serde(default)]
    pub confidential_endpoint: Option<ConfidentialEndpointMetadata>,
}

impl SourceEntry {
    pub fn supports_role(&self, role: SourceRole) -> bool {
        self.eligible_roles.contains(&role)
    }

    pub fn is_default_for_role(&self, role: SourceRole) -> bool {
        self.default_roles.contains(&role)
    }
}

#[derive(Debug, Default, Clone)]
pub struct SourceRegistry {
    entries: HashMap<String, SourceEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedSourceRegistryState {
    schema_version: u32,
    entries: Vec<SourceEntry>,
}

impl SourceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, entry: SourceEntry) {
        self.entries.insert(entry.id.clone(), entry);
    }

    pub fn get(&self, id: &str) -> Option<&SourceEntry> {
        self.entries.get(id)
    }

    pub fn set_enabled(&mut self, id: &str, enabled: bool) -> bool {
        match self.entries.get_mut(id) {
            Some(entry) => {
                entry.enabled = enabled;
                true
            }
            None => false,
        }
    }

    pub fn set_confidential_endpoint(
        &mut self,
        id: &str,
        metadata: Option<ConfidentialEndpointMetadata>,
    ) -> bool {
        match self.entries.get_mut(id) {
            Some(entry) => {
                entry.confidential_endpoint = metadata;
                true
            }
            None => false,
        }
    }

    pub fn set_confidential_endpoint_enabled(
        &mut self,
        id: &str,
        enabled: bool,
    ) -> Result<(), SourceRegistryError> {
        let entry = self
            .entries
            .get_mut(id)
            .ok_or_else(|| SourceRegistryError::new(format!("source not found: {id}")))?;
        let metadata = entry.confidential_endpoint.as_mut().ok_or_else(|| {
            SourceRegistryError::new(format!("source {id} has no confidential endpoint metadata"))
        })?;
        metadata.enabled = enabled;
        Ok(())
    }

    pub fn list(&self) -> Vec<&SourceEntry> {
        let mut entries: Vec<&SourceEntry> = self.entries.values().collect();
        entries.sort_by_key(|entry| entry.display_name.as_str());
        entries
    }

    pub fn eligible_for(&self, role: SourceRole) -> Vec<&SourceEntry> {
        let mut entries = self
            .entries
            .values()
            .filter(|entry| entry.enabled && entry.supports_role(role))
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.display_name.as_str());
        entries
    }

    pub fn default_for(&self, role: SourceRole) -> Option<&SourceEntry> {
        let mut preferred = self
            .entries
            .values()
            .filter(|entry| {
                entry.enabled && entry.supports_role(role) && entry.is_default_for_role(role)
            })
            .collect::<Vec<_>>();
        preferred.sort_by_key(|entry| entry.display_name.as_str());
        if let Some(first) = preferred.first().copied() {
            return Some(first);
        }

        let mut eligible = self.eligible_for(role);
        eligible.sort_by_key(|entry| entry.display_name.as_str());
        eligible.first().copied()
    }

    pub fn set_default_for_role(
        &mut self,
        role: SourceRole,
        source_id: &str,
    ) -> Result<(), SourceRegistryError> {
        let target = self
            .entries
            .get(source_id)
            .ok_or_else(|| SourceRegistryError::new(format!("source not found: {source_id}")))?;
        if !target.enabled {
            return Err(SourceRegistryError::new(format!(
                "source {source_id} is disabled and cannot be set as default"
            )));
        }
        if !target.supports_role(role) {
            return Err(SourceRegistryError::new(format!(
                "source {source_id} does not support role {}",
                role.label()
            )));
        }

        for entry in self.entries.values_mut() {
            entry.default_roles.retain(|candidate| *candidate != role);
        }
        if let Some(entry) = self.entries.get_mut(source_id) {
            entry.default_roles.push(role);
            entry
                .default_roles
                .sort_by_key(|candidate| candidate.label());
            entry.default_roles.dedup();
        }
        Ok(())
    }

    pub fn clear_default_for_role(&mut self, role: SourceRole) -> bool {
        let mut changed = false;
        for entry in self.entries.values_mut() {
            let previous = entry.default_roles.len();
            entry.default_roles.retain(|candidate| *candidate != role);
            if previous != entry.default_roles.len() {
                changed = true;
            }
        }
        changed
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), SourceRegistryError> {
        let mut entries = self.entries.values().cloned().collect::<Vec<_>>();
        entries.sort_by(|left, right| left.id.cmp(&right.id));
        let state = PersistedSourceRegistryState {
            schema_version: 1,
            entries,
        };
        let encoded = serde_json::to_string_pretty(&state).map_err(|error| {
            SourceRegistryError::new(format!("failed to serialize source registry: {error}"))
        })?;
        fs::write(path, encoded).map_err(|error| {
            SourceRegistryError::new(format!(
                "failed to write source registry at {}: {error}",
                path.display()
            ))
        })
    }

    pub fn load_from_path(path: &Path) -> Result<Self, String> {
        let contents = fs::read_to_string(path).map_err(|error| error.to_string())?;
        let state = serde_json::from_str::<PersistedSourceRegistryState>(&contents)
            .map_err(|error| error.to_string())?;
        if state.schema_version != 1 {
            return Err(format!(
                "unsupported source registry schema version: {}",
                state.schema_version
            ));
        }
        let mut registry = SourceRegistry::new();
        for entry in state.entries {
            registry.register(entry);
        }
        Ok(registry)
    }
}

pub fn default_source_registry() -> SourceRegistry {
    let mut registry = SourceRegistry::new();
    registry.register(SourceEntry {
        id: "local-llama-cpp".to_string(),
        display_name: "Local Llama.cpp".to_string(),
        kind: SourceKind::LocalModel,
        target: "runtime://llama.cpp".to_string(),
        enabled: true,
        eligible_roles: vec![
            SourceRole::Chat,
            SourceRole::Planner,
            SourceRole::Coder,
            SourceRole::CodexSpecialist,
            SourceRole::Debugger,
            SourceRole::Verifier,
        ],
        default_roles: vec![
            SourceRole::Chat,
            SourceRole::Planner,
            SourceRole::Coder,
            SourceRole::Debugger,
            SourceRole::Verifier,
        ],
        confidential_endpoint: None,
    });
    registry.register(SourceEntry {
        id: "local-image-runtime".to_string(),
        display_name: "Local Image Runtime".to_string(),
        kind: SourceKind::LocalModel,
        target: "runtime://image-local".to_string(),
        enabled: true,
        eligible_roles: vec![SourceRole::ImageGeneration],
        default_roles: vec![SourceRole::ImageGeneration],
        confidential_endpoint: None,
    });
    registry.register(SourceEntry {
        id: "local-video-runtime".to_string(),
        display_name: "Local Video Runtime".to_string(),
        kind: SourceKind::LocalModel,
        target: "runtime://video-local".to_string(),
        enabled: true,
        eligible_roles: vec![SourceRole::VideoGeneration],
        default_roles: vec![SourceRole::VideoGeneration],
        confidential_endpoint: None,
    });
    registry.register(SourceEntry {
        id: "openjarvis-mode-b-sidecar".to_string(),
        display_name: "OpenJarvis Mode B Sidecar".to_string(),
        kind: SourceKind::SidecarBridge,
        target: "http://127.0.0.1:8100/forge/bridge/v1/task".to_string(),
        enabled: true,
        eligible_roles: vec![
            SourceRole::Planner,
            SourceRole::Coder,
            SourceRole::Debugger,
            SourceRole::Verifier,
        ],
        default_roles: vec![SourceRole::Planner],
        confidential_endpoint: None,
    });
    registry.register(SourceEntry {
        id: "codex-specialist-openjarvis-mode-b".to_string(),
        display_name: "Codex Specialist (OpenJarvis Sidecar)".to_string(),
        kind: SourceKind::SidecarBridge,
        target: "http://127.0.0.1:8100/forge/bridge/v1/task".to_string(),
        enabled: true,
        eligible_roles: vec![SourceRole::CodexSpecialist, SourceRole::Coder],
        default_roles: vec![SourceRole::CodexSpecialist],
        confidential_endpoint: None,
    });
    registry.register(SourceEntry {
        id: "api-openai".to_string(),
        display_name: "OpenAI API".to_string(),
        kind: SourceKind::ApiModel,
        target: "https://api.openai.com/v1".to_string(),
        enabled: true,
        eligible_roles: vec![
            SourceRole::Chat,
            SourceRole::Planner,
            SourceRole::Coder,
            SourceRole::CodexSpecialist,
            SourceRole::Debugger,
            SourceRole::Verifier,
            SourceRole::ImageGeneration,
            SourceRole::VideoGeneration,
        ],
        default_roles: vec![SourceRole::ImageGeneration, SourceRole::VideoGeneration],
        confidential_endpoint: Some(ConfidentialEndpointMetadata {
            enabled: false,
            expected_target_prefix: "https://api.openai.com/v1".to_string(),
            ..ConfidentialEndpointMetadata::default()
        }),
    });
    registry
}

#[cfg(test)]
mod tests {
    use super::{
        ConfidentialEndpointMetadata, SourceEntry, SourceKind, SourceRegistry, SourceRole,
        default_source_registry,
    };
    use std::{env, fs};

    #[test]
    fn default_registry_contains_local_and_api_sources() {
        let registry = default_source_registry();
        let entries = registry.list();
        assert!(!entries.is_empty());
        let local_count = entries
            .iter()
            .filter(|entry| matches!(entry.kind, SourceKind::LocalModel))
            .count();
        let api_count = entries
            .iter()
            .filter(|entry| matches!(entry.kind, SourceKind::ApiModel))
            .count();
        assert!(local_count >= 2);
        assert!(api_count >= 1);
    }

    #[test]
    fn eligible_for_filters_disabled_sources() {
        let mut registry = SourceRegistry::new();
        registry.register(SourceEntry {
            id: "a".to_string(),
            display_name: "A".to_string(),
            kind: SourceKind::ApiModel,
            target: "https://api.example/v1".to_string(),
            enabled: true,
            eligible_roles: vec![SourceRole::Coder],
            default_roles: Vec::new(),
            confidential_endpoint: None,
        });
        registry.register(SourceEntry {
            id: "b".to_string(),
            display_name: "B".to_string(),
            kind: SourceKind::ApiModel,
            target: "https://api2.example/v1".to_string(),
            enabled: true,
            eligible_roles: vec![SourceRole::Coder],
            default_roles: Vec::new(),
            confidential_endpoint: None,
        });
        assert!(registry.set_enabled("a", false));
        let eligible = registry.eligible_for(SourceRole::Coder);
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].id, "b");
    }

    #[test]
    fn default_for_prefers_role_default_entry() {
        let registry = default_source_registry();
        let default_video = registry.default_for(SourceRole::VideoGeneration);
        assert!(default_video.is_some());
        let default_video = match default_video {
            Some(value) => value,
            None => return,
        };
        assert!(default_video.id == "local-video-runtime" || default_video.id == "api-openai");
        assert!(default_video.supports_role(SourceRole::VideoGeneration));
    }

    #[test]
    fn codex_specialist_role_has_dedicated_default_source() {
        let registry = default_source_registry();
        let source = registry.default_for(SourceRole::CodexSpecialist);
        assert!(source.is_some());
        let source = match source {
            Some(value) => value,
            None => return,
        };
        assert_eq!(source.id, "codex-specialist-openjarvis-mode-b");
        assert!(source.supports_role(SourceRole::CodexSpecialist));
    }

    #[test]
    fn set_default_for_role_reassigns_previous_default() {
        let mut registry = default_source_registry();
        let set = registry.set_default_for_role(SourceRole::Coder, "openjarvis-mode-b-sidecar");
        assert!(set.is_ok());

        let coder_default = registry.default_for(SourceRole::Coder);
        assert!(coder_default.is_some());
        let coder_default = match coder_default {
            Some(value) => value,
            None => return,
        };
        assert_eq!(coder_default.id, "openjarvis-mode-b-sidecar");
    }

    #[test]
    fn source_registry_round_trip_persists_role_default_selection() {
        let mut registry = default_source_registry();
        let set = registry.set_default_for_role(SourceRole::Coder, "openjarvis-mode-b-sidecar");
        assert!(set.is_ok());

        let mut path = env::temp_dir();
        path.push("forge_source_registry_roundtrip.json");
        let _ = fs::remove_file(&path);

        let saved = registry.save_to_path(&path);
        assert!(saved.is_ok());

        let loaded = SourceRegistry::load_from_path(&path);
        assert!(loaded.is_ok());
        let loaded = match loaded {
            Ok(value) => value,
            Err(_) => return,
        };

        let coder_default = loaded.default_for(SourceRole::Coder);
        assert!(coder_default.is_some());
        let coder_default = match coder_default {
            Some(value) => value,
            None => return,
        };
        assert_eq!(coder_default.id, "openjarvis-mode-b-sidecar");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn source_registry_load_accepts_legacy_entries_without_confidential_metadata() {
        let json = r#"{
  "schema_version": 1,
  "entries": [
    {
      "id": "api-openai",
      "display_name": "OpenAI API",
      "kind": "ApiModel",
      "target": "https://api.openai.com/v1",
      "enabled": true,
      "eligible_roles": ["Chat"],
      "default_roles": ["Chat"]
    }
  ]
}"#;
        let mut path = env::temp_dir();
        path.push("forge_source_registry_legacy_schema.json");
        let _ = fs::remove_file(&path);
        assert!(fs::write(&path, json).is_ok());

        let loaded = SourceRegistry::load_from_path(&path);
        assert!(loaded.is_ok());
        let loaded = match loaded {
            Ok(value) => value,
            Err(_) => return,
        };
        let entry = loaded.get("api-openai");
        assert!(entry.is_some());
        let entry = match entry {
            Some(value) => value,
            None => return,
        };
        assert!(entry.confidential_endpoint.is_none());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn set_confidential_endpoint_persists_enable_toggle() {
        let mut registry = default_source_registry();
        let configured = registry.set_confidential_endpoint(
            "api-openai",
            Some(ConfidentialEndpointMetadata {
                enabled: false,
                expected_target_prefix: "https://api.openai.com/v1".to_string(),
                ..ConfidentialEndpointMetadata::default()
            }),
        );
        assert!(configured);

        let enabled = registry.set_confidential_endpoint_enabled("api-openai", true);
        assert!(enabled.is_ok());

        let entry = registry.get("api-openai");
        assert!(entry.is_some());
        let entry = match entry {
            Some(value) => value,
            None => return,
        };
        assert!(
            entry
                .confidential_endpoint
                .as_ref()
                .map(|value| value.enabled)
                .unwrap_or(false)
        );
    }
}
