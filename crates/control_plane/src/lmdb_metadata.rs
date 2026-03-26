use crate::feature_policy::FeaturePolicyRegistry;
use std::path::Path;
use urm::feature_policy::{ActivationChecks, FeatureId, FeatureState};
use urm::lmdb_metadata::{LmdbMetadataStore, LmdbMetadataStoreError, LmdbMetadataStoreOptions};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataStoreBackend {
    Lmdb,
    LegacyInMemory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataStoreDecision {
    pub backend: MetadataStoreBackend,
    pub feature_state: FeatureState,
    pub reason: String,
}

pub fn select_metadata_store_backend(
    feature_registry: &mut FeaturePolicyRegistry,
    checks: ActivationChecks,
) -> MetadataStoreDecision {
    let evaluated = feature_registry
        .evaluate(FeatureId::LmdbMetadata, checks)
        .unwrap_or(FeatureState::Fallback);
    let status = feature_registry.status(FeatureId::LmdbMetadata);
    let reason = status
        .as_ref()
        .map(|value| value.reason.clone())
        .unwrap_or_else(|| "lmdb metadata feature status unavailable".to_string());

    let backend = match evaluated {
        FeatureState::Enabled => MetadataStoreBackend::Lmdb,
        FeatureState::Disabled
        | FeatureState::Available
        | FeatureState::Auto
        | FeatureState::Fallback => MetadataStoreBackend::LegacyInMemory,
    };

    MetadataStoreDecision {
        backend,
        feature_state: evaluated,
        reason,
    }
}

pub fn open_lmdb_metadata_store(
    root: impl AsRef<Path>,
    allow_schema_migration: bool,
) -> Result<LmdbMetadataStore, LmdbMetadataStoreError> {
    LmdbMetadataStore::open_with_options(
        root,
        LmdbMetadataStoreOptions {
            allow_schema_migration,
            ..LmdbMetadataStoreOptions::default()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{MetadataStoreBackend, open_lmdb_metadata_store, select_metadata_store_backend};
    use crate::feature_policy::FeaturePolicyRegistry;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use urm::feature_policy::{ActivationChecks, FeatureId, FeatureState};

    fn full_checks() -> ActivationChecks {
        ActivationChecks {
            platform_compatible: true,
            hardware_compatible: true,
            runtime_validation_ok: true,
            health_checks_ok: true,
            benchmark_sanity_ok: true,
            no_critical_conflict: true,
            measurable_benefit: true,
        }
    }

    fn unique_store_root(label: &str) -> PathBuf {
        let mut root = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|value| value.as_nanos())
            .unwrap_or(0);
        root.push(format!("forge_control_plane_lmdb_{label}_{nanos}"));
        root
    }

    #[test]
    fn enabled_lmdb_feature_selects_lmdb_backend() {
        let mut registry = FeaturePolicyRegistry::with_defaults();
        let set = registry.set_requested_state(FeatureId::LmdbMetadata, FeatureState::Enabled);
        assert!(set.is_ok());

        let decision = select_metadata_store_backend(&mut registry, full_checks());
        assert_eq!(decision.backend, MetadataStoreBackend::Lmdb);
    }

    #[test]
    fn disabled_lmdb_feature_selects_legacy_backend() {
        let mut registry = FeaturePolicyRegistry::with_defaults();
        let set = registry.set_requested_state(FeatureId::LmdbMetadata, FeatureState::Disabled);
        assert!(set.is_ok());

        let decision = select_metadata_store_backend(&mut registry, full_checks());
        assert_eq!(decision.backend, MetadataStoreBackend::LegacyInMemory);
    }

    #[test]
    fn open_store_helper_supports_metadata_round_trip() {
        let root = unique_store_root("open_helper");
        let store = open_lmdb_metadata_store(&root, false);
        assert!(store.is_ok());
        let store = match store {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(store.put_metadata("policy:key", b"value").is_ok());
        assert_eq!(
            store.get_metadata("policy:key").ok().flatten(),
            Some(b"value".to_vec())
        );

        let _ = fs::remove_dir_all(root);
    }
}
