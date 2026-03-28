use crate::data_governance::{DataGovernancePolicy, WorkspaceClassification};
use crate::env_config;
use crate::source_registry::{SourceEntry, SourceKind};
#[cfg(test)]
use std::cell::RefCell;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderPolicyClass {
    LocalModel,
    LocalCompatibleApi,
    RemoteProvider,
}

impl ProviderPolicyClass {
    pub const fn label(self) -> &'static str {
        match self {
            Self::LocalModel => "local_model",
            Self::LocalCompatibleApi => "local_compatible_api",
            Self::RemoteProvider => "remote_provider",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelRiskTier {
    Low,
    Medium,
    High,
    Critical,
}

impl ModelRiskTier {
    fn from_env_value(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
            Self::Critical => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelProviderTrustPolicy {
    pub workspace_classification: WorkspaceClassification,
    pub allowed_provider_ids: Vec<String>,
    pub allow_local_model_class: bool,
    pub allow_local_compatible_api_class: bool,
    pub allow_remote_provider_class: bool,
    pub max_model_risk_tier: ModelRiskTier,
    pub require_local_model_manifest_verified: bool,
    pub local_model_manifest_verified_source_ids: Vec<String>,
    pub require_signed_sources: bool,
    pub signed_source_ids: Vec<String>,
    pub model_risk_overrides: Vec<(String, ModelRiskTier)>,
}

impl ModelProviderTrustPolicy {
    pub fn from_env() -> Self {
        let governance = DataGovernancePolicy::from_env();
        let workspace_classification = governance.workspace_classification;

        let workspace_allowlist_key = workspace_provider_allowlist_env(workspace_classification);
        let allowed_provider_ids =
            env_config::read_optional_non_empty(workspace_allowlist_key.as_str())
                .or_else(|| env_config::read_optional_non_empty("FORGE_PROVIDER_ALLOWLIST"))
                .map(|value| env_config::parse_csv_list_lowercase(value.as_str()))
                .unwrap_or_default();

        let workspace_max_risk_key = workspace_max_risk_tier_env(workspace_classification);
        let max_model_risk_tier =
            env_config::read_optional_non_empty(workspace_max_risk_key.as_str())
                .or_else(|| env_config::read_optional_non_empty("FORGE_MAX_MODEL_RISK_TIER"))
                .and_then(|value| ModelRiskTier::from_env_value(value.as_str()))
                .unwrap_or_else(|| default_max_risk_tier(workspace_classification));

        let allow_local_model_class =
            env_config::read_flexible_flag("FORGE_ALLOW_LOCAL_MODEL_CLASS").unwrap_or(true);
        let allow_local_compatible_api_class =
            env_config::read_flexible_flag("FORGE_ALLOW_LOCAL_COMPATIBLE_API_CLASS")
                .unwrap_or(true);
        let allow_remote_provider_class = env_config::read_flexible_flag(
            "FORGE_ALLOW_REMOTE_PROVIDER_CLASS",
        )
        .unwrap_or(!matches!(
            workspace_classification,
            WorkspaceClassification::Restricted
        ));

        let require_local_model_manifest_verified =
            env_config::read_flexible_flag("FORGE_REQUIRE_LOCAL_MODEL_MANIFEST_VERIFIED")
                .unwrap_or(matches!(
                    workspace_classification,
                    WorkspaceClassification::Confidential | WorkspaceClassification::Restricted
                ));
        let local_model_manifest_verified_source_ids =
            env_config::read_optional_non_empty("FORGE_LOCAL_MODEL_MANIFEST_VERIFIED_SOURCES")
                .map(|value| env_config::parse_csv_list_lowercase(value.as_str()))
                .unwrap_or_default();

        let require_signed_sources = env_config::read_flexible_flag(
            "FORGE_REQUIRE_SIGNED_MODEL_SOURCES",
        )
        .unwrap_or(matches!(
            workspace_classification,
            WorkspaceClassification::Confidential | WorkspaceClassification::Restricted
        ));
        let signed_source_ids = env_config::read_optional_non_empty("FORGE_SIGNED_SOURCE_IDS")
            .map(|value| env_config::parse_csv_list_lowercase(value.as_str()))
            .unwrap_or_default();
        let model_risk_overrides =
            env_config::read_optional_non_empty("FORGE_MODEL_RISK_TIER_OVERRIDES")
                .map(|value| parse_model_risk_overrides(value.as_str()))
                .unwrap_or_default();

        Self {
            workspace_classification,
            allowed_provider_ids,
            allow_local_model_class,
            allow_local_compatible_api_class,
            allow_remote_provider_class,
            max_model_risk_tier,
            require_local_model_manifest_verified,
            local_model_manifest_verified_source_ids,
            require_signed_sources,
            signed_source_ids,
            model_risk_overrides,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelProviderTrustDecision {
    pub workspace_classification: WorkspaceClassification,
    pub source_id: String,
    pub provider_class: ProviderPolicyClass,
    pub model_risk_tier: ModelRiskTier,
}

pub fn enforce_model_provider_trust_policy(
    route_label: &str,
    source: &SourceEntry,
    model_id: &str,
) -> Result<ModelProviderTrustDecision, String> {
    let policy = current_policy();
    enforce_model_provider_trust_policy_with_policy(route_label, source, model_id, &policy)
}

#[cfg(not(test))]
fn current_policy() -> ModelProviderTrustPolicy {
    ModelProviderTrustPolicy::from_env()
}

#[cfg(test)]
fn current_policy() -> ModelProviderTrustPolicy {
    let overridden = TEST_POLICY_OVERRIDE.with(|slot| slot.borrow().clone());
    if let Some(policy) = overridden {
        return policy;
    }
    ModelProviderTrustPolicy::from_env()
}

#[cfg(test)]
thread_local! {
    #[allow(clippy::missing_const_for_thread_local)]
    static TEST_POLICY_OVERRIDE: RefCell<Option<ModelProviderTrustPolicy>> = RefCell::new(None);
}

#[cfg(test)]
pub(crate) fn set_test_policy_override(policy: Option<ModelProviderTrustPolicy>) {
    TEST_POLICY_OVERRIDE.with(|slot| {
        *slot.borrow_mut() = policy;
    });
}

fn enforce_model_provider_trust_policy_with_policy(
    route_label: &str,
    source: &SourceEntry,
    model_id: &str,
    policy: &ModelProviderTrustPolicy,
) -> Result<ModelProviderTrustDecision, String> {
    let source_id = source.id.trim().to_ascii_lowercase();
    let provider_class = classify_provider_class(source);
    let model_risk_tier =
        determine_model_risk_tier(model_id, policy.model_risk_overrides.as_slice());

    if !policy.allowed_provider_ids.is_empty() && !policy.allowed_provider_ids.contains(&source_id)
    {
        return Err(format!(
            "model/provider trust policy blocked {route_label}: source `{}` is not allow-listed for workspace `{}`",
            source.id,
            policy.workspace_classification.label()
        ));
    }

    match provider_class {
        ProviderPolicyClass::LocalModel if !policy.allow_local_model_class => {
            return Err(format!(
                "model/provider trust policy blocked {route_label}: local-model class is disabled"
            ));
        }
        ProviderPolicyClass::LocalCompatibleApi if !policy.allow_local_compatible_api_class => {
            return Err(format!(
                "model/provider trust policy blocked {route_label}: local-compatible-api class is disabled"
            ));
        }
        ProviderPolicyClass::RemoteProvider if !policy.allow_remote_provider_class => {
            return Err(format!(
                "model/provider trust policy blocked {route_label}: remote-provider class is disabled for workspace `{}`",
                policy.workspace_classification.label()
            ));
        }
        _ => {}
    }

    if policy.require_local_model_manifest_verified
        && matches!(provider_class, ProviderPolicyClass::LocalModel)
        && !policy
            .local_model_manifest_verified_source_ids
            .contains(&source_id)
    {
        return Err(format!(
            "model/provider trust policy blocked {route_label}: local model source `{}` lacks verified weight/manifest evidence",
            source.id
        ));
    }

    if policy.require_signed_sources && !policy.signed_source_ids.contains(&source_id) {
        return Err(format!(
            "model/provider trust policy blocked {route_label}: source `{}` is not in signed source allow-list",
            source.id
        ));
    }

    if model_risk_tier.rank() > policy.max_model_risk_tier.rank() {
        return Err(format!(
            "model/provider trust policy blocked {route_label}: model `{}` risk tier `{}` exceeds workspace maximum `{}`",
            model_id.trim(),
            model_risk_tier.label(),
            policy.max_model_risk_tier.label()
        ));
    }

    Ok(ModelProviderTrustDecision {
        workspace_classification: policy.workspace_classification,
        source_id: source.id.clone(),
        provider_class,
        model_risk_tier,
    })
}

fn classify_provider_class(source: &SourceEntry) -> ProviderPolicyClass {
    match source.kind {
        SourceKind::LocalModel => ProviderPolicyClass::LocalModel,
        SourceKind::SidecarBridge => ProviderPolicyClass::LocalCompatibleApi,
        SourceKind::ApiModel => {
            if endpoint_looks_local(source.target.as_str()) {
                ProviderPolicyClass::LocalCompatibleApi
            } else {
                ProviderPolicyClass::RemoteProvider
            }
        }
    }
}

fn endpoint_looks_local(target: &str) -> bool {
    let normalized = target.trim().to_ascii_lowercase();
    normalized.starts_with("runtime://")
        || normalized.contains("127.0.0.1")
        || normalized.contains("localhost")
        || normalized.contains("[::1]")
}

fn determine_model_risk_tier(
    model_id: &str,
    overrides: &[(String, ModelRiskTier)],
) -> ModelRiskTier {
    let normalized = model_id.trim().to_ascii_lowercase();
    for (pattern, tier) in overrides {
        if normalized.contains(pattern.as_str()) {
            return *tier;
        }
    }
    if normalized.contains("risky")
        || normalized.contains("high-risk")
        || normalized.contains("experimental")
    {
        return ModelRiskTier::Critical;
    }
    if normalized.contains("gpt-5.4")
        || normalized.contains("gpt-5.3")
        || normalized.contains("o3")
        || normalized.contains("o4")
        || normalized.contains("opus")
    {
        return ModelRiskTier::High;
    }
    if normalized.contains("mini")
        || normalized.contains("small")
        || normalized.contains("nano")
        || normalized.contains("3b")
        || normalized.contains("7b")
    {
        return ModelRiskTier::Low;
    }
    ModelRiskTier::Medium
}

fn parse_model_risk_overrides(raw: &str) -> Vec<(String, ModelRiskTier)> {
    raw.split([';', ','])
        .filter_map(|entry| {
            let (pattern, tier_text) = entry.split_once(':')?;
            let pattern = pattern.trim().to_ascii_lowercase();
            if pattern.is_empty() {
                return None;
            }
            let tier = ModelRiskTier::from_env_value(tier_text)?;
            Some((pattern, tier))
        })
        .collect::<Vec<_>>()
}

fn default_max_risk_tier(workspace: WorkspaceClassification) -> ModelRiskTier {
    match workspace {
        WorkspaceClassification::Public => ModelRiskTier::Critical,
        WorkspaceClassification::Internal => ModelRiskTier::High,
        WorkspaceClassification::Confidential => ModelRiskTier::High,
        WorkspaceClassification::Restricted => ModelRiskTier::Medium,
    }
}

fn workspace_provider_allowlist_env(workspace: WorkspaceClassification) -> String {
    format!(
        "FORGE_PROVIDER_ALLOWLIST_{}",
        workspace.label().to_ascii_uppercase()
    )
}

fn workspace_max_risk_tier_env(workspace: WorkspaceClassification) -> String {
    format!(
        "FORGE_MAX_MODEL_RISK_TIER_{}",
        workspace.label().to_ascii_uppercase()
    )
}

#[cfg(test)]
mod tests {
    use super::{
        ModelProviderTrustPolicy, ModelRiskTier, enforce_model_provider_trust_policy,
        set_test_policy_override,
    };
    use crate::data_governance::WorkspaceClassification;
    use crate::source_registry::{SourceEntry, SourceKind, SourceRole};

    fn sample_source(id: &str, kind: SourceKind, target: &str) -> SourceEntry {
        SourceEntry {
            id: id.to_string(),
            display_name: id.to_string(),
            kind,
            target: target.to_string(),
            enabled: true,
            eligible_roles: vec![SourceRole::Chat],
            default_roles: vec![SourceRole::Chat],
            confidential_endpoint: None,
        }
    }

    #[test]
    fn remote_provider_is_blocked_for_restricted_workspace_policy() {
        set_test_policy_override(Some(ModelProviderTrustPolicy {
            workspace_classification: WorkspaceClassification::Restricted,
            allowed_provider_ids: vec!["api-openai".to_string()],
            allow_local_model_class: true,
            allow_local_compatible_api_class: true,
            allow_remote_provider_class: false,
            max_model_risk_tier: ModelRiskTier::High,
            require_local_model_manifest_verified: false,
            local_model_manifest_verified_source_ids: Vec::new(),
            require_signed_sources: false,
            signed_source_ids: Vec::new(),
            model_risk_overrides: Vec::new(),
        }));
        let source = sample_source(
            "api-openai",
            SourceKind::ApiModel,
            "https://api.openai.com/v1",
        );
        let result = enforce_model_provider_trust_policy("chat.remote_api", &source, "gpt-5.2");
        set_test_policy_override(None);
        assert!(result.is_err());
        let error = result.err().unwrap_or_default();
        assert!(error.contains("remote-provider class is disabled"));
    }

    #[test]
    fn provider_allowlist_blocks_unknown_source() {
        set_test_policy_override(Some(ModelProviderTrustPolicy {
            workspace_classification: WorkspaceClassification::Internal,
            allowed_provider_ids: vec!["api-openai".to_string()],
            allow_local_model_class: true,
            allow_local_compatible_api_class: true,
            allow_remote_provider_class: true,
            max_model_risk_tier: ModelRiskTier::Critical,
            require_local_model_manifest_verified: false,
            local_model_manifest_verified_source_ids: Vec::new(),
            require_signed_sources: false,
            signed_source_ids: Vec::new(),
            model_risk_overrides: Vec::new(),
        }));
        let source = sample_source(
            "api-another",
            SourceKind::ApiModel,
            "https://api.example/v1",
        );
        let result = enforce_model_provider_trust_policy("chat.remote_api", &source, "gpt-5.2");
        set_test_policy_override(None);
        assert!(result.is_err());
        let error = result.err().unwrap_or_default();
        assert!(error.contains("not allow-listed"));
    }

    #[test]
    fn risk_tier_ceiling_blocks_high_risk_model() {
        set_test_policy_override(Some(ModelProviderTrustPolicy {
            workspace_classification: WorkspaceClassification::Restricted,
            allowed_provider_ids: vec!["api-openai".to_string()],
            allow_local_model_class: true,
            allow_local_compatible_api_class: true,
            allow_remote_provider_class: true,
            max_model_risk_tier: ModelRiskTier::Medium,
            require_local_model_manifest_verified: false,
            local_model_manifest_verified_source_ids: Vec::new(),
            require_signed_sources: false,
            signed_source_ids: Vec::new(),
            model_risk_overrides: Vec::new(),
        }));
        let source = sample_source(
            "api-openai",
            SourceKind::ApiModel,
            "https://api.openai.com/v1",
        );
        let result = enforce_model_provider_trust_policy("chat.remote_api", &source, "gpt-5.4");
        set_test_policy_override(None);
        assert!(result.is_err());
        let error = result.err().unwrap_or_default();
        assert!(error.contains("risk tier"));
        assert!(error.contains("exceeds"));
    }

    #[test]
    fn local_model_requires_verified_manifest_when_policy_requires_it() {
        set_test_policy_override(Some(ModelProviderTrustPolicy {
            workspace_classification: WorkspaceClassification::Confidential,
            allowed_provider_ids: vec!["local-llama-cpp".to_string()],
            allow_local_model_class: true,
            allow_local_compatible_api_class: true,
            allow_remote_provider_class: true,
            max_model_risk_tier: ModelRiskTier::High,
            require_local_model_manifest_verified: true,
            local_model_manifest_verified_source_ids: Vec::new(),
            require_signed_sources: false,
            signed_source_ids: Vec::new(),
            model_risk_overrides: Vec::new(),
        }));
        let source = sample_source(
            "local-llama-cpp",
            SourceKind::LocalModel,
            "runtime://llama.cpp",
        );
        let result = enforce_model_provider_trust_policy("chat.local_model", &source, "llama-7b");
        set_test_policy_override(None);
        assert!(result.is_err());
    }

    #[test]
    fn signed_source_and_risk_controls_allow_trusted_source() {
        set_test_policy_override(Some(ModelProviderTrustPolicy {
            workspace_classification: WorkspaceClassification::Restricted,
            allowed_provider_ids: vec!["api-openai".to_string()],
            allow_local_model_class: true,
            allow_local_compatible_api_class: true,
            allow_remote_provider_class: true,
            max_model_risk_tier: ModelRiskTier::High,
            require_local_model_manifest_verified: false,
            local_model_manifest_verified_source_ids: Vec::new(),
            require_signed_sources: true,
            signed_source_ids: vec!["api-openai".to_string()],
            model_risk_overrides: vec![("gpt-5.2".to_string(), ModelRiskTier::Medium)],
        }));
        let source = sample_source(
            "api-openai",
            SourceKind::ApiModel,
            "https://api.openai.com/v1",
        );
        let result = enforce_model_provider_trust_policy("chat.remote_api", &source, "gpt-5.2");
        set_test_policy_override(None);
        assert!(result.is_ok());
        if let Ok(decision) = result {
            assert_eq!(decision.source_id, "api-openai");
        }
    }
}
