use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FeatureState {
    Disabled,
    Available,
    Enabled,
    Auto,
    Fallback,
}

impl FeatureState {
    pub fn is_active(self) -> bool {
        matches!(self, FeatureState::Enabled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FeatureId {
    HwlocTopology,
    NumactlPlacement,
    MimallocAllocator,
    JemallocAllocator,
    SnmallocAllocator,
    VulkanMemoryAllocator,
    IoUring,
    LmdbMetadata,
    OpenVinoBackend,
    TransparentHugePages,
    Zswap,
    Zram,
    OpenBlasBackend,
    BlisBackend,
    PerfProfiler,
    TracyProfiler,
    AutoFdoOptimizer,
    BoltOptimizer,
    IspcKernels,
    HighwaySimd,
    RustArchSimd,
    RayonParallelism,
    ConfidentialRelay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Platform {
    Windows,
    Linux,
    MacOs,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "windows") {
            Platform::Windows
        } else if cfg!(target_os = "linux") {
            Platform::Linux
        } else {
            Platform::MacOs
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureDeclaration {
    pub id: FeatureId,
    pub supported_platforms: Vec<Platform>,
    pub required_hardware: String,
    pub expected_benefit: String,
    pub known_risks: String,
    pub validation_method: String,
    pub fallback_path: String,
    pub benchmark_requirement: String,
    pub present_on_system: bool,
}

impl FeatureDeclaration {
    pub fn supports_platform(&self, platform: Platform) -> bool {
        self.supported_platforms.contains(&platform)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationChecks {
    pub platform_compatible: bool,
    pub hardware_compatible: bool,
    pub runtime_validation_ok: bool,
    pub health_checks_ok: bool,
    pub benchmark_sanity_ok: bool,
    pub no_critical_conflict: bool,
    pub measurable_benefit: bool,
}

impl ActivationChecks {
    pub fn allows_activation(self) -> bool {
        self.platform_compatible
            && self.hardware_compatible
            && self.runtime_validation_ok
            && self.health_checks_ok
            && self.benchmark_sanity_ok
            && self.no_critical_conflict
            && self.measurable_benefit
    }
}

#[cfg(test)]
mod tests {
    use super::{ActivationChecks, FeatureState, Platform};

    #[test]
    fn enabled_state_reports_active() {
        assert!(FeatureState::Enabled.is_active());
        assert!(!FeatureState::Auto.is_active());
        assert!(!FeatureState::Fallback.is_active());
    }

    #[test]
    fn activation_checks_require_all_guards() {
        let checks = ActivationChecks {
            platform_compatible: true,
            hardware_compatible: true,
            runtime_validation_ok: true,
            health_checks_ok: true,
            benchmark_sanity_ok: true,
            no_critical_conflict: true,
            measurable_benefit: true,
        };
        assert!(checks.allows_activation());

        let failed = ActivationChecks {
            measurable_benefit: false,
            ..checks
        };
        assert!(!failed.allows_activation());
    }

    #[test]
    fn current_platform_is_stable_variant() {
        let platform = Platform::current();
        assert!(matches!(
            platform,
            Platform::Windows | Platform::Linux | Platform::MacOs
        ));
    }
}
