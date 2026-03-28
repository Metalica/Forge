use crate::env_config;
#[cfg(test)]
use std::sync::Mutex;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

impl WorkspaceClassification {
    fn from_env_value(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "public" => Some(Self::Public),
            "internal" => Some(Self::Internal),
            "confidential" => Some(Self::Confidential),
            "restricted" => Some(Self::Restricted),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Confidential => "confidential",
            Self::Restricted => "restricted",
        }
    }
}

fn default_remote_egress_allowed(_workspace_classification: WorkspaceClassification) -> bool {
    false
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataGovernancePolicy {
    pub workspace_classification: WorkspaceClassification,
    pub remote_egress_allowed: bool,
    pub export_approval_required: bool,
    pub export_approved: bool,
    pub retention_days: Option<u32>,
    pub custom_block_patterns: Vec<String>,
}

impl DataGovernancePolicy {
    pub fn from_env() -> Self {
        let workspace_classification =
            env_config::read_optional_non_empty("FORGE_WORKSPACE_CLASSIFICATION")
                .and_then(|value| WorkspaceClassification::from_env_value(value.as_str()))
                .unwrap_or(WorkspaceClassification::Internal);

        let remote_egress_allowed = env_config::read_flexible_flag("FORGE_ALLOW_REMOTE_EGRESS")
            .unwrap_or(default_remote_egress_allowed(workspace_classification));
        let export_approved =
            env_config::read_flexible_flag("FORGE_EXPORT_APPROVED").unwrap_or(false);
        let export_approval_required =
            env_config::read_flexible_flag("FORGE_REQUIRE_EXPORT_APPROVAL").unwrap_or(matches!(
                workspace_classification,
                WorkspaceClassification::Confidential | WorkspaceClassification::Restricted
            ));
        let retention_days = env_config::read_positive_u32("FORGE_WORKSPACE_RETENTION_DAYS");
        let custom_block_patterns = env_config::read_optional_non_empty("FORGE_DLP_BLOCK_PATTERNS")
            .map(|raw| env_config::parse_csv_list_lowercase(raw.as_str()))
            .unwrap_or_default();

        Self {
            workspace_classification,
            remote_egress_allowed,
            export_approval_required,
            export_approved,
            retention_days,
            custom_block_patterns,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataGovernanceDecision {
    pub workspace_classification: WorkspaceClassification,
    pub export_approval_required: bool,
    pub export_approved: bool,
    pub retention_days: Option<u32>,
}

pub fn enforce_remote_egress_policy(
    route_label: &str,
    prompt: &str,
) -> Result<DataGovernanceDecision, String> {
    let policy = current_policy();
    enforce_remote_egress_policy_with_policy(route_label, prompt, &policy)
}

#[cfg(not(test))]
fn current_policy() -> DataGovernancePolicy {
    DataGovernancePolicy::from_env()
}

#[cfg(test)]
fn current_policy() -> DataGovernancePolicy {
    let lock = TEST_POLICY_OVERRIDE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(policy) = lock.clone() {
        return policy;
    }
    DataGovernancePolicy::from_env()
}

#[cfg(test)]
static TEST_POLICY_OVERRIDE: OnceLock<Mutex<Option<DataGovernancePolicy>>> = OnceLock::new();

#[cfg(test)]
pub(crate) fn set_test_policy_override(policy: Option<DataGovernancePolicy>) {
    let mut lock = TEST_POLICY_OVERRIDE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    *lock = policy;
}

fn enforce_remote_egress_policy_with_policy(
    route_label: &str,
    prompt: &str,
    policy: &DataGovernancePolicy,
) -> Result<DataGovernanceDecision, String> {
    if !policy.remote_egress_allowed {
        return Err(format!(
            "data-governance blocked remote egress for {route_label}: remote egress is disabled"
        ));
    }

    if policy.export_approval_required && !policy.export_approved {
        return Err(format!(
            "data-governance blocked remote egress for {route_label}: workspace classification `{}` requires explicit export approval",
            policy.workspace_classification.label()
        ));
    }

    let prompt_lower = prompt.to_ascii_lowercase();
    for pattern in default_dlp_patterns()
        .iter()
        .chain(policy.custom_block_patterns.iter())
    {
        if prompt_lower.contains(pattern.as_str()) {
            return Err(format!(
                "data-governance blocked remote egress for {route_label}: DLP pattern `{pattern}` matched prompt content"
            ));
        }
    }

    Ok(DataGovernanceDecision {
        workspace_classification: policy.workspace_classification,
        export_approval_required: policy.export_approval_required,
        export_approved: policy.export_approved,
        retention_days: policy.retention_days,
    })
}

fn default_dlp_patterns() -> &'static [String] {
    static PATTERNS: OnceLock<Vec<String>> = OnceLock::new();
    PATTERNS
        .get_or_init(|| {
            vec![
                "sk-".to_string(),
                "authorization: bearer".to_string(),
                "api_key=".to_string(),
                "-----begin ".to_string(),
            ]
        })
        .as_slice()
}

#[cfg(test)]
mod tests {
    use super::{
        DataGovernancePolicy, WorkspaceClassification, default_remote_egress_allowed,
        enforce_remote_egress_policy_with_policy,
    };

    #[test]
    fn remote_egress_default_is_fail_closed_for_all_workspace_classes() {
        let all_classes = [
            WorkspaceClassification::Public,
            WorkspaceClassification::Internal,
            WorkspaceClassification::Confidential,
            WorkspaceClassification::Restricted,
        ];
        for class in all_classes {
            assert!(!default_remote_egress_allowed(class));
        }
    }

    #[test]
    fn restricted_workspace_requires_explicit_export_approval() {
        let policy = DataGovernancePolicy {
            workspace_classification: WorkspaceClassification::Restricted,
            remote_egress_allowed: true,
            export_approval_required: true,
            export_approved: false,
            retention_days: Some(30),
            custom_block_patterns: Vec::new(),
        };
        let result =
            enforce_remote_egress_policy_with_policy("chat.remote_api", "safe prompt", &policy);
        assert!(result.is_err());
        let error = result.err().unwrap_or_default();
        assert!(error.contains("requires explicit export approval"));
    }

    #[test]
    fn dlp_blocks_secret_like_prompt_content() {
        let policy = DataGovernancePolicy {
            workspace_classification: WorkspaceClassification::Internal,
            remote_egress_allowed: true,
            export_approval_required: false,
            export_approved: false,
            retention_days: None,
            custom_block_patterns: Vec::new(),
        };
        let result = enforce_remote_egress_policy_with_policy(
            "chat.remote_api",
            "token=sk-live-secret-value",
            &policy,
        );
        assert!(result.is_err());
        let error = result.err().unwrap_or_default();
        assert!(error.contains("DLP pattern"));
    }

    #[test]
    fn custom_dlp_pattern_blocks_prompt_content() {
        let policy = DataGovernancePolicy {
            workspace_classification: WorkspaceClassification::Internal,
            remote_egress_allowed: true,
            export_approval_required: false,
            export_approved: false,
            retention_days: None,
            custom_block_patterns: vec!["finance-export".to_string()],
        };
        let result = enforce_remote_egress_policy_with_policy(
            "chat.remote_api",
            "please send finance-export workbook",
            &policy,
        );
        assert!(result.is_err());
    }

    #[test]
    fn policy_allows_remote_egress_when_requirements_are_satisfied() {
        let policy = DataGovernancePolicy {
            workspace_classification: WorkspaceClassification::Confidential,
            remote_egress_allowed: true,
            export_approval_required: true,
            export_approved: true,
            retention_days: Some(14),
            custom_block_patterns: Vec::new(),
        };
        let result =
            enforce_remote_egress_policy_with_policy("chat.remote_api", "summarize this", &policy);
        assert!(result.is_ok());
        let decision = result.unwrap_or(super::DataGovernanceDecision {
            workspace_classification: WorkspaceClassification::Public,
            export_approval_required: false,
            export_approved: false,
            retention_days: None,
        });
        assert_eq!(
            decision.workspace_classification,
            WorkspaceClassification::Confidential
        );
        assert_eq!(decision.retention_days, Some(14));
    }
}
