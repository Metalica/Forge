use crate::feature_policy::FeaturePolicyRegistry;
use urm::feature_policy::{FeatureId, FeatureState};
use urm::io_policy::{IoPolicyMode, IoWorkloadClass};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoWorkloadPolicyDecision {
    pub workload_class: IoWorkloadClass,
    pub policy_mode: IoPolicyMode,
    pub reason: String,
}

pub fn select_workload_io_policy(
    registry: &FeaturePolicyRegistry,
    workload_class: IoWorkloadClass,
) -> IoWorkloadPolicyDecision {
    let Some(status) = registry.status(FeatureId::IoUring) else {
        return IoWorkloadPolicyDecision {
            workload_class,
            policy_mode: IoPolicyMode::Disabled,
            reason: format!(
                "workload={} | io_uring policy unavailable; baseline async I/O selected",
                workload_class.key()
            ),
        };
    };

    let policy_mode = match status.effective_state {
        FeatureState::Enabled => {
            if matches!(status.requested_state, FeatureState::Enabled) {
                IoPolicyMode::RequireIoUring
            } else {
                IoPolicyMode::PreferIoUring
            }
        }
        FeatureState::Available | FeatureState::Auto => IoPolicyMode::PreferIoUring,
        FeatureState::Disabled | FeatureState::Fallback => IoPolicyMode::Disabled,
    };

    IoWorkloadPolicyDecision {
        workload_class,
        policy_mode,
        reason: format!(
            "workload={} | io_uring requested={:?} effective={:?} | {}",
            workload_class.key(),
            status.requested_state,
            status.effective_state,
            status.reason
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::select_workload_io_policy;
    use crate::feature_policy::FeaturePolicyRegistry;
    use std::collections::HashMap;
    use urm::feature_policy::{
        ActivationChecks, FeatureDeclaration, FeatureId, FeatureState, Platform,
    };
    use urm::io_policy::{IoPolicyMode, IoWorkloadClass};

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

    fn deny_checks() -> ActivationChecks {
        ActivationChecks {
            platform_compatible: false,
            hardware_compatible: false,
            runtime_validation_ok: false,
            health_checks_ok: false,
            benchmark_sanity_ok: false,
            no_critical_conflict: false,
            measurable_benefit: false,
        }
    }

    fn io_registry() -> FeaturePolicyRegistry {
        let declaration = FeatureDeclaration {
            id: FeatureId::IoUring,
            supported_platforms: vec![Platform::current()],
            required_hardware: "test".to_string(),
            expected_benefit: "test".to_string(),
            known_risks: "test".to_string(),
            validation_method: "test".to_string(),
            fallback_path: "baseline".to_string(),
            benchmark_requirement: "test".to_string(),
            present_on_system: true,
        };
        FeaturePolicyRegistry::new(vec![declaration])
    }

    #[test]
    fn enabled_request_maps_to_require_mode() {
        let mut registry = io_registry();
        let _ = registry.set_requested_state(FeatureId::IoUring, FeatureState::Enabled);
        let mut checks = HashMap::new();
        checks.insert(FeatureId::IoUring, full_checks());
        let _ = registry.evaluate_all(&checks);

        let decision = select_workload_io_policy(&registry, IoWorkloadClass::Download);
        assert_eq!(decision.policy_mode, IoPolicyMode::RequireIoUring);
        assert!(decision.reason.contains("effective=Enabled"));
    }

    #[test]
    fn auto_mode_maps_to_prefer_when_enabled() {
        let mut registry = io_registry();
        let _ = registry.set_requested_state(FeatureId::IoUring, FeatureState::Auto);
        let mut checks = HashMap::new();
        checks.insert(FeatureId::IoUring, full_checks());
        let _ = registry.evaluate_all(&checks);

        let decision = select_workload_io_policy(&registry, IoWorkloadClass::Indexing);
        assert_eq!(decision.policy_mode, IoPolicyMode::PreferIoUring);
        assert!(decision.reason.contains("workload=indexing"));
    }

    #[test]
    fn fallback_effective_state_disables_fast_path() {
        let mut registry = io_registry();
        let _ = registry.set_requested_state(FeatureId::IoUring, FeatureState::Enabled);
        let mut checks = HashMap::new();
        checks.insert(FeatureId::IoUring, deny_checks());
        let _ = registry.evaluate_all(&checks);

        let decision = select_workload_io_policy(&registry, IoWorkloadClass::LogStreaming);
        assert_eq!(decision.policy_mode, IoPolicyMode::Disabled);
        assert!(decision.reason.contains("effective=Fallback"));
    }

    #[test]
    fn disabled_state_disables_file_copy_fast_path() {
        let mut registry = io_registry();
        let _ = registry.set_requested_state(FeatureId::IoUring, FeatureState::Disabled);
        let mut checks = HashMap::new();
        checks.insert(FeatureId::IoUring, full_checks());
        let _ = registry.evaluate_all(&checks);

        let decision = select_workload_io_policy(&registry, IoWorkloadClass::FileCopy);
        assert_eq!(decision.policy_mode, IoPolicyMode::Disabled);
        assert!(decision.reason.contains("workload=file_copy"));
    }
}
