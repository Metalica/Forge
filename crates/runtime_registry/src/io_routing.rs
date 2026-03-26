use urm::io_policy::{IoPolicyMode, IoWorkloadClass};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeIoOperation {
    DownloadRuntimeArtifact,
    BuildMetadataIndex,
    StreamRuntimeLogs,
    CopyModelAsset,
}

impl RuntimeIoOperation {
    pub fn workload_class(self) -> IoWorkloadClass {
        match self {
            RuntimeIoOperation::DownloadRuntimeArtifact => IoWorkloadClass::Download,
            RuntimeIoOperation::BuildMetadataIndex => IoWorkloadClass::Indexing,
            RuntimeIoOperation::StreamRuntimeLogs => IoWorkloadClass::LogStreaming,
            RuntimeIoOperation::CopyModelAsset => IoWorkloadClass::FileCopy,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeIoRouteRequest {
    pub operation: RuntimeIoOperation,
    pub workload_class: IoWorkloadClass,
    pub policy_mode: IoPolicyMode,
}

pub fn route_runtime_io_operation(
    operation: RuntimeIoOperation,
    policy_mode: IoPolicyMode,
) -> RuntimeIoRouteRequest {
    RuntimeIoRouteRequest {
        operation,
        workload_class: operation.workload_class(),
        policy_mode,
    }
}

#[cfg(test)]
mod tests {
    use super::{RuntimeIoOperation, route_runtime_io_operation};
    use control_plane::feature_policy::FeaturePolicyRegistry;
    use control_plane::io_policy::select_workload_io_policy;
    use execution_plane::io_path::{
        HostPlatform, IoBackend, IoUringCapability, KernelVersion,
        resolve_workload_io_backend_with_capability,
    };
    use std::collections::HashMap;
    use urm::feature_policy::{
        ActivationChecks, FeatureDeclaration, FeatureId, FeatureState, Platform,
    };
    use urm::io_policy::IoWorkloadClass;

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

    fn linux_io_uring_capability() -> IoUringCapability {
        IoUringCapability {
            platform: HostPlatform::Linux,
            feature_gate_enabled: true,
            kernel_version: Some(KernelVersion { major: 6, minor: 8 }),
            io_uring_disabled_flag: Some(0),
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
    fn operation_to_workload_mapping_is_stable() {
        assert_eq!(
            RuntimeIoOperation::DownloadRuntimeArtifact.workload_class(),
            IoWorkloadClass::Download
        );
        assert_eq!(
            RuntimeIoOperation::BuildMetadataIndex.workload_class(),
            IoWorkloadClass::Indexing
        );
        assert_eq!(
            RuntimeIoOperation::StreamRuntimeLogs.workload_class(),
            IoWorkloadClass::LogStreaming
        );
        assert_eq!(
            RuntimeIoOperation::CopyModelAsset.workload_class(),
            IoWorkloadClass::FileCopy
        );
    }

    #[test]
    fn integrated_policy_and_backend_selection_uses_io_uring_for_enabled_policy() {
        let mut registry = io_registry();
        let _ = registry.set_requested_state(FeatureId::IoUring, FeatureState::Enabled);
        let mut checks = HashMap::new();
        checks.insert(FeatureId::IoUring, full_checks());
        let _ = registry.evaluate_all(&checks);

        let operations = [
            RuntimeIoOperation::DownloadRuntimeArtifact,
            RuntimeIoOperation::BuildMetadataIndex,
            RuntimeIoOperation::StreamRuntimeLogs,
            RuntimeIoOperation::CopyModelAsset,
        ];
        for operation in operations {
            let policy = select_workload_io_policy(&registry, operation.workload_class());
            let route = route_runtime_io_operation(operation, policy.policy_mode);
            let backend = resolve_workload_io_backend_with_capability(
                route.workload_class,
                route.policy_mode,
                linux_io_uring_capability(),
            );
            assert_eq!(backend.backend, IoBackend::IoUring);
        }
    }

    #[test]
    fn integrated_policy_and_backend_selection_falls_back_when_disabled() {
        let mut registry = io_registry();
        let _ = registry.set_requested_state(FeatureId::IoUring, FeatureState::Disabled);
        let _ = registry.evaluate_all(&HashMap::new());

        let operation = RuntimeIoOperation::CopyModelAsset;
        let policy = select_workload_io_policy(&registry, operation.workload_class());
        let route = route_runtime_io_operation(operation, policy.policy_mode);
        let backend = resolve_workload_io_backend_with_capability(
            route.workload_class,
            route.policy_mode,
            linux_io_uring_capability(),
        );
        assert_eq!(backend.backend, IoBackend::BaselineAsync);
    }
}
