use std::fs;
use urm::io_policy::{IoPolicyMode, IoWorkloadClass};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoBackend {
    BaselineAsync,
    IoUring,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPlatform {
    Linux,
    Other,
}

impl HostPlatform {
    fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else {
            Self::Other
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelVersion {
    pub major: u32,
    pub minor: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoUringCapability {
    pub platform: HostPlatform,
    pub feature_gate_enabled: bool,
    pub kernel_version: Option<KernelVersion>,
    pub io_uring_disabled_flag: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoBackendDecision {
    pub backend: IoBackend,
    pub reason: String,
    pub fallback_used: bool,
    pub requirement_not_met: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoWorkloadBackendDecision {
    pub workload_class: IoWorkloadClass,
    pub backend: IoBackend,
    pub reason: String,
    pub fallback_used: bool,
    pub requirement_not_met: bool,
}

pub fn resolve_io_backend(policy_mode: IoPolicyMode) -> IoBackendDecision {
    let capability = probe_io_uring_capability();
    resolve_io_backend_for(policy_mode, capability)
}

pub fn resolve_workload_io_backend(
    workload_class: IoWorkloadClass,
    policy_mode: IoPolicyMode,
) -> IoWorkloadBackendDecision {
    let capability = probe_io_uring_capability();
    resolve_workload_io_backend_with_capability(workload_class, policy_mode, capability)
}

pub fn resolve_workload_io_backend_with_capability(
    workload_class: IoWorkloadClass,
    policy_mode: IoPolicyMode,
    capability: IoUringCapability,
) -> IoWorkloadBackendDecision {
    let decision = resolve_io_backend_for(policy_mode, capability);
    IoWorkloadBackendDecision {
        workload_class,
        backend: decision.backend,
        reason: format!("workload={} | {}", workload_class.key(), decision.reason),
        fallback_used: decision.fallback_used,
        requirement_not_met: decision.requirement_not_met,
    }
}

pub fn probe_io_uring_capability() -> IoUringCapability {
    IoUringCapability {
        platform: HostPlatform::current(),
        feature_gate_enabled: cfg!(all(target_os = "linux", feature = "io-uring")),
        kernel_version: read_kernel_version(),
        io_uring_disabled_flag: read_io_uring_disabled_flag(),
    }
}

fn resolve_io_backend_for(
    policy_mode: IoPolicyMode,
    capability: IoUringCapability,
) -> IoBackendDecision {
    if matches!(policy_mode, IoPolicyMode::Disabled) {
        return IoBackendDecision {
            backend: IoBackend::BaselineAsync,
            reason: String::from("io_uring policy disabled"),
            fallback_used: false,
            requirement_not_met: false,
        };
    }

    let require_mode = matches!(policy_mode, IoPolicyMode::RequireIoUring);

    if !capability.feature_gate_enabled {
        return IoBackendDecision {
            backend: IoBackend::BaselineAsync,
            reason: String::from("io_uring feature gate is disabled at build time"),
            fallback_used: true,
            requirement_not_met: require_mode,
        };
    }

    if !matches!(capability.platform, HostPlatform::Linux) {
        return IoBackendDecision {
            backend: IoBackend::BaselineAsync,
            reason: String::from("io_uring path skipped: host platform is not Linux"),
            fallback_used: true,
            requirement_not_met: require_mode,
        };
    }

    if !kernel_meets_minimum(capability.kernel_version) {
        return IoBackendDecision {
            backend: IoBackend::BaselineAsync,
            reason: String::from("io_uring requires Linux kernel 5.10+"),
            fallback_used: true,
            requirement_not_met: require_mode,
        };
    }

    if !io_uring_allowed(capability.io_uring_disabled_flag) {
        return IoBackendDecision {
            backend: IoBackend::BaselineAsync,
            reason: String::from("io_uring disabled by kernel runtime policy"),
            fallback_used: true,
            requirement_not_met: require_mode,
        };
    }

    IoBackendDecision {
        backend: IoBackend::IoUring,
        reason: String::from("io_uring fast path selected"),
        fallback_used: false,
        requirement_not_met: false,
    }
}

fn kernel_meets_minimum(kernel_version: Option<KernelVersion>) -> bool {
    let Some(version) = kernel_version else {
        return false;
    };
    version.major > 5 || (version.major == 5 && version.minor >= 10)
}

fn io_uring_allowed(io_uring_disabled_flag: Option<u8>) -> bool {
    match io_uring_disabled_flag {
        Some(0) => true,
        Some(_) => false,
        None => true,
    }
}

fn read_kernel_version() -> Option<KernelVersion> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let raw = fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
    parse_kernel_version(&raw)
}

fn read_io_uring_disabled_flag() -> Option<u8> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let raw = fs::read_to_string("/proc/sys/kernel/io_uring_disabled").ok()?;
    raw.trim().parse::<u8>().ok()
}

fn parse_kernel_version(raw: &str) -> Option<KernelVersion> {
    let kernel = raw.trim();
    if kernel.is_empty() {
        return None;
    }
    let numeric_prefix = kernel.split(['-', '+']).next()?;
    let mut pieces = numeric_prefix.split('.');
    let major = pieces.next()?.parse::<u32>().ok()?;
    let minor = pieces.next().unwrap_or("0").parse::<u32>().ok()?;
    Some(KernelVersion { major, minor })
}

#[cfg(test)]
mod tests {
    use super::{
        HostPlatform, IoBackend, IoUringCapability, KernelVersion, parse_kernel_version,
        probe_io_uring_capability, resolve_io_backend_for,
        resolve_workload_io_backend_with_capability,
    };
    use urm::io_policy::{IoPolicyMode, IoWorkloadClass};

    #[test]
    fn linux_fast_path_selected_when_gate_and_capability_are_present() {
        let capability = IoUringCapability {
            platform: HostPlatform::Linux,
            feature_gate_enabled: true,
            kernel_version: Some(KernelVersion { major: 6, minor: 8 }),
            io_uring_disabled_flag: Some(0),
        };
        let decision = resolve_io_backend_for(IoPolicyMode::PreferIoUring, capability);
        assert_eq!(decision.backend, IoBackend::IoUring);
        assert!(!decision.fallback_used);
        assert!(!decision.requirement_not_met);
    }

    #[test]
    fn linux_falls_back_when_feature_gate_is_disabled() {
        let capability = IoUringCapability {
            platform: HostPlatform::Linux,
            feature_gate_enabled: false,
            kernel_version: Some(KernelVersion { major: 6, minor: 8 }),
            io_uring_disabled_flag: Some(0),
        };
        let decision = resolve_io_backend_for(IoPolicyMode::PreferIoUring, capability);
        assert_eq!(decision.backend, IoBackend::BaselineAsync);
        assert!(decision.fallback_used);
        assert!(decision.reason.contains("feature gate"));
    }

    #[test]
    fn non_linux_falls_back_even_with_gate_enabled() {
        let capability = IoUringCapability {
            platform: HostPlatform::Other,
            feature_gate_enabled: true,
            kernel_version: Some(KernelVersion { major: 6, minor: 8 }),
            io_uring_disabled_flag: Some(0),
        };
        let decision = resolve_io_backend_for(IoPolicyMode::PreferIoUring, capability);
        assert_eq!(decision.backend, IoBackend::BaselineAsync);
        assert!(decision.fallback_used);
        assert!(decision.reason.contains("not Linux"));
    }

    #[test]
    fn require_mode_marks_requirement_not_met_when_kernel_too_old() {
        let capability = IoUringCapability {
            platform: HostPlatform::Linux,
            feature_gate_enabled: true,
            kernel_version: Some(KernelVersion { major: 5, minor: 4 }),
            io_uring_disabled_flag: Some(0),
        };
        let decision = resolve_io_backend_for(IoPolicyMode::RequireIoUring, capability);
        assert_eq!(decision.backend, IoBackend::BaselineAsync);
        assert!(decision.fallback_used);
        assert!(decision.requirement_not_met);
    }

    #[test]
    fn parse_kernel_version_handles_common_release_format() {
        let parsed = parse_kernel_version("6.8.12-arch1-1");
        assert_eq!(parsed, Some(KernelVersion { major: 6, minor: 8 }));
    }

    #[test]
    fn host_probe_reports_platform_stably() {
        let capability = probe_io_uring_capability();
        assert!(matches!(
            capability.platform,
            HostPlatform::Linux | HostPlatform::Other
        ));
    }

    #[test]
    fn workload_routing_preserves_workload_label_in_reason() {
        let capability = IoUringCapability {
            platform: HostPlatform::Linux,
            feature_gate_enabled: true,
            kernel_version: Some(KernelVersion { major: 6, minor: 8 }),
            io_uring_disabled_flag: Some(0),
        };
        let decision = resolve_workload_io_backend_with_capability(
            IoWorkloadClass::FileCopy,
            IoPolicyMode::PreferIoUring,
            capability,
        );
        assert_eq!(decision.backend, IoBackend::IoUring);
        assert!(decision.reason.contains("workload=file_copy"));
    }
}
