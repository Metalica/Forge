use crate::env_config;
use std::collections::HashMap;
use urm::feature_policy::{
    ActivationChecks, FeatureDeclaration, FeatureId, FeatureState, Platform,
};

const OPENVINO_PRESENT_ENV: &str = "OPENVINO_PRESENT";
const OPENVINO_BENCHMARK_OK_ENV: &str = "OPENVINO_BENCHMARK_OK";
const THP_BENCHMARK_OK_ENV: &str = "THP_BENCHMARK_OK";
const ZSWAP_BENCHMARK_OK_ENV: &str = "ZSWAP_BENCHMARK_OK";
const ZRAM_BENCHMARK_OK_ENV: &str = "ZRAM_BENCHMARK_OK";
const OPENBLAS_PRESENT_ENV: &str = "OPENBLAS_PRESENT";
const BLIS_PRESENT_ENV: &str = "BLIS_PRESENT";
const MIMALLOC_PRESENT_ENV: &str = "MIMALLOC_PRESENT";
const JEMALLOC_PRESENT_ENV: &str = "JEMALLOC_PRESENT";
const SNMALLOC_PRESENT_ENV: &str = "SNMALLOC_PRESENT";
const OPENBLAS_BENCHMARK_OK_ENV: &str = "OPENBLAS_BENCHMARK_OK";
const BLIS_BENCHMARK_OK_ENV: &str = "BLIS_BENCHMARK_OK";
const MIMALLOC_BENCHMARK_OK_ENV: &str = "MIMALLOC_BENCHMARK_OK";
const JEMALLOC_BENCHMARK_OK_ENV: &str = "JEMALLOC_BENCHMARK_OK";
const SNMALLOC_BENCHMARK_OK_ENV: &str = "SNMALLOC_BENCHMARK_OK";
const PERF_PRESENT_ENV: &str = "PERF_PRESENT";
const TRACY_PRESENT_ENV: &str = "TRACY_PRESENT";
const AUTOFDO_PRESENT_ENV: &str = "AUTOFDO_PRESENT";
const BOLT_PRESENT_ENV: &str = "BOLT_PRESENT";
const ISPC_PRESENT_ENV: &str = "ISPC_PRESENT";
const HIGHWAY_PRESENT_ENV: &str = "HIGHWAY_PRESENT";
const RUST_ARCH_SIMD_PRESENT_ENV: &str = "RUST_ARCH_SIMD_PRESENT";
const RAYON_PRESENT_ENV: &str = "RAYON_PRESENT";
const IO_URING_PRESENT_ENV: &str = "IO_URING_PRESENT";
const LMDB_PRESENT_ENV: &str = "LMDB_PRESENT";
const CONFIDENTIAL_RELAY_PRESENT_ENV: &str = "CONFIDENTIAL_RELAY_PRESENT";
const PERF_BENCHMARK_OK_ENV: &str = "PERF_BENCHMARK_OK";
const TRACY_BENCHMARK_OK_ENV: &str = "TRACY_BENCHMARK_OK";
const AUTOFDO_BENCHMARK_OK_ENV: &str = "AUTOFDO_BENCHMARK_OK";
const BOLT_BENCHMARK_OK_ENV: &str = "BOLT_BENCHMARK_OK";
const ISPC_BENCHMARK_OK_ENV: &str = "ISPC_BENCHMARK_OK";
const HIGHWAY_BENCHMARK_OK_ENV: &str = "HIGHWAY_BENCHMARK_OK";
const RUST_ARCH_SIMD_BENCHMARK_OK_ENV: &str = "RUST_ARCH_SIMD_BENCHMARK_OK";
const RAYON_BENCHMARK_OK_ENV: &str = "RAYON_BENCHMARK_OK";
const IO_URING_BENCHMARK_OK_ENV: &str = "IO_URING_BENCHMARK_OK";
const LMDB_BENCHMARK_OK_ENV: &str = "LMDB_BENCHMARK_OK";
const CONFIDENTIAL_RELAY_BENCHMARK_OK_ENV: &str = "CONFIDENTIAL_RELAY_BENCHMARK_OK";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeaturePolicyError {
    UnknownFeature(FeatureId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeSafetyTrigger {
    Instability,
    RepeatedValidationFailure,
    SevereRegression,
    MemoryPressureSpike,
    HardwareIncompatibility,
    BrokenFallbackBehavior,
    RuntimeError(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VulkanBenchmarkGateConfig {
    pub min_samples: usize,
    pub min_success_ratio_permille: u16,
    pub max_p95_latency_ms: u64,
    pub min_median_tokens_per_second: u32,
}

impl Default for VulkanBenchmarkGateConfig {
    fn default() -> Self {
        Self {
            min_samples: 3,
            min_success_ratio_permille: 800,
            max_p95_latency_ms: 240,
            min_median_tokens_per_second: 20,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VulkanBenchmarkSample {
    pub latency_ms: u64,
    pub tokens_per_second: Option<u32>,
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VulkanBenchmarkGateDecision {
    InsufficientData {
        observed: usize,
        required: usize,
    },
    Pass {
        sample_count: usize,
        success_ratio_permille: u16,
        p95_latency_ms: u64,
        median_tokens_per_second: u32,
    },
    Fail {
        sample_count: usize,
        success_ratio_permille: u16,
        p95_latency_ms: u64,
        median_tokens_per_second: u32,
        reason: String,
    },
}

pub fn evaluate_vulkan_benchmark_gate(
    samples: &[VulkanBenchmarkSample],
    config: VulkanBenchmarkGateConfig,
) -> VulkanBenchmarkGateDecision {
    if samples.len() < config.min_samples {
        return VulkanBenchmarkGateDecision::InsufficientData {
            observed: samples.len(),
            required: config.min_samples,
        };
    }

    let sample_count = samples.len();
    let success_count = samples.iter().filter(|sample| sample.success).count();
    let success_ratio_permille = ((success_count as u128 * 1000) / sample_count as u128) as u16;

    let mut latencies = samples
        .iter()
        .map(|sample| sample.latency_ms)
        .collect::<Vec<u64>>();
    latencies.sort_unstable();
    let p95_latency_ms = percentile_u64(&latencies, 95);

    let mut tps_values = samples
        .iter()
        .filter_map(|sample| sample.tokens_per_second)
        .collect::<Vec<u32>>();
    tps_values.sort_unstable();
    let median_tokens_per_second = percentile_u32(&tps_values, 50);

    let mut failure_reasons = Vec::new();
    if success_ratio_permille < config.min_success_ratio_permille {
        failure_reasons.push(format!(
            "success {}% below threshold {}%",
            success_ratio_permille / 10,
            config.min_success_ratio_permille / 10
        ));
    }
    if p95_latency_ms > config.max_p95_latency_ms {
        failure_reasons.push(format!(
            "p95 latency {p95_latency_ms}ms above threshold {}ms",
            config.max_p95_latency_ms
        ));
    }
    if median_tokens_per_second < config.min_median_tokens_per_second {
        failure_reasons.push(format!(
            "median throughput {} tok/s below threshold {} tok/s",
            median_tokens_per_second, config.min_median_tokens_per_second
        ));
    }

    if failure_reasons.is_empty() {
        VulkanBenchmarkGateDecision::Pass {
            sample_count,
            success_ratio_permille,
            p95_latency_ms,
            median_tokens_per_second,
        }
    } else {
        VulkanBenchmarkGateDecision::Fail {
            sample_count,
            success_ratio_permille,
            p95_latency_ms,
            median_tokens_per_second,
            reason: failure_reasons.join("; "),
        }
    }
}

pub fn apply_vulkan_benchmark_gate(
    registry: &mut FeaturePolicyRegistry,
    decision: &VulkanBenchmarkGateDecision,
) -> Result<String, FeaturePolicyError> {
    match decision {
        VulkanBenchmarkGateDecision::InsufficientData { observed, required } => Ok(format!(
            "vulkan benchmark gate pending: {observed}/{required} samples"
        )),
        VulkanBenchmarkGateDecision::Pass {
            sample_count,
            success_ratio_permille,
            p95_latency_ms,
            median_tokens_per_second,
        } => {
            registry.clear_session_fallback(FeatureId::VulkanMemoryAllocator)?;
            Ok(format!(
                "vulkan benchmark gate passed: samples={sample_count} success={}%, p95={}ms, median_tps={}",
                success_ratio_permille / 10,
                p95_latency_ms,
                median_tokens_per_second
            ))
        }
        VulkanBenchmarkGateDecision::Fail {
            sample_count,
            success_ratio_permille,
            p95_latency_ms,
            median_tokens_per_second,
            reason,
        } => registry.apply_runtime_safety_fallback(
            FeatureId::VulkanMemoryAllocator,
            RuntimeSafetyTrigger::RuntimeError(format!(
                "vulkan benchmark gate failed: samples={sample_count}, success={}%, p95={}ms, median_tps={}, reason={reason}",
                success_ratio_permille / 10,
                p95_latency_ms,
                median_tokens_per_second
            )),
        ),
    }
}

pub fn default_activation_checks_for_declaration(
    declaration: &FeatureDeclaration,
) -> ActivationChecks {
    default_activation_checks_with_env(declaration, env_config::read_optional)
}

pub fn default_activation_checks_for_declaration_with_env<F>(
    declaration: &FeatureDeclaration,
    get_env: F,
) -> ActivationChecks
where
    F: Fn(&str) -> Option<String>,
{
    default_activation_checks_with_env(declaration, get_env)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeaturePolicyStatus {
    pub id: FeatureId,
    pub requested_state: FeatureState,
    pub effective_state: FeatureState,
    pub reason: String,
    pub present_on_system: bool,
    pub supports_current_platform: bool,
}

#[derive(Debug, Clone)]
struct FeatureEntry {
    declaration: FeatureDeclaration,
    requested_state: FeatureState,
    effective_state: FeatureState,
    session_forced_fallback: bool,
    reason: String,
}

#[derive(Debug, Clone)]
pub struct FeaturePolicyRegistry {
    entries: HashMap<FeatureId, FeatureEntry>,
    current_platform: Platform,
}

impl FeaturePolicyRegistry {
    pub fn new(declarations: Vec<FeatureDeclaration>) -> Self {
        let current_platform = Platform::current();
        let mut entries = HashMap::new();

        for declaration in declarations {
            let initial_effective =
                initial_effective_state(&declaration, current_platform, FeatureState::Auto);
            let reason = initial_reason(initial_effective);
            entries.insert(
                declaration.id,
                FeatureEntry {
                    declaration,
                    requested_state: FeatureState::Auto,
                    effective_state: initial_effective,
                    session_forced_fallback: false,
                    reason,
                },
            );
        }

        Self {
            entries,
            current_platform,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(default_feature_declarations())
    }

    pub fn set_requested_state(
        &mut self,
        id: FeatureId,
        requested_state: FeatureState,
    ) -> Result<(), FeaturePolicyError> {
        let Some(entry) = self.entries.get_mut(&id) else {
            return Err(FeaturePolicyError::UnknownFeature(id));
        };

        entry.requested_state = requested_state;
        if matches!(requested_state, FeatureState::Disabled) {
            entry.session_forced_fallback = false;
        }
        Ok(())
    }

    pub fn reset_to_safe_defaults(&mut self) {
        for entry in self.entries.values_mut() {
            entry.requested_state = FeatureState::Auto;
            entry.session_forced_fallback = false;
            entry.effective_state = initial_effective_state(
                &entry.declaration,
                self.current_platform,
                entry.requested_state,
            );
            entry.reason = initial_reason(entry.effective_state);
        }
    }

    pub fn evaluate(
        &mut self,
        id: FeatureId,
        checks: ActivationChecks,
    ) -> Result<FeatureState, FeaturePolicyError> {
        let Some(entry) = self.entries.get_mut(&id) else {
            return Err(FeaturePolicyError::UnknownFeature(id));
        };

        if entry.session_forced_fallback {
            entry.effective_state = FeatureState::Fallback;
            if entry.reason.is_empty() {
                entry.reason = "session fallback is active".to_string();
            }
            return Ok(entry.effective_state);
        }

        let supports_platform = entry.declaration.supports_platform(self.current_platform);
        let present = entry.declaration.present_on_system;

        let previous_state = entry.effective_state;
        let (effective, reason) = match entry.requested_state {
            FeatureState::Disabled => (
                FeatureState::Disabled,
                "disabled by user policy".to_string(),
            ),
            FeatureState::Available => {
                if supports_platform && present {
                    (
                        FeatureState::Available,
                        "available and waiting for activation".to_string(),
                    )
                } else {
                    (
                        FeatureState::Disabled,
                        "not available on this platform/system".to_string(),
                    )
                }
            }
            FeatureState::Enabled => {
                if supports_platform && present && checks.allows_activation() {
                    (
                        FeatureState::Enabled,
                        "enabled after policy checks passed".to_string(),
                    )
                } else {
                    (
                        FeatureState::Fallback,
                        "enabled requested but activation checks failed".to_string(),
                    )
                }
            }
            FeatureState::Auto => {
                if !supports_platform || !present {
                    (
                        FeatureState::Disabled,
                        "auto disabled: unsupported platform or missing component".to_string(),
                    )
                } else if checks.allows_activation() {
                    (
                        FeatureState::Enabled,
                        "auto enabled: checks passed and benefit confirmed".to_string(),
                    )
                } else if matches!(
                    previous_state,
                    FeatureState::Enabled | FeatureState::Fallback
                ) {
                    (
                        FeatureState::Fallback,
                        "auto fallback: checks failed after attempted activation".to_string(),
                    )
                } else {
                    (
                        FeatureState::Available,
                        "auto kept available: checks not sufficient".to_string(),
                    )
                }
            }
            FeatureState::Fallback => (
                FeatureState::Fallback,
                "fallback forced by policy".to_string(),
            ),
        };

        entry.effective_state = effective;
        entry.reason = reason;
        Ok(effective)
    }

    pub fn evaluate_all(
        &mut self,
        checks_by_feature: &HashMap<FeatureId, ActivationChecks>,
    ) -> Vec<FeaturePolicyStatus> {
        let ids: Vec<FeatureId> = self.entries.keys().copied().collect();
        for id in ids {
            let checks = checks_by_feature
                .get(&id)
                .copied()
                .unwrap_or_else(deny_all_checks);
            let _ = self.evaluate(id, checks);
        }
        self.statuses()
    }

    pub fn report_runtime_failure(
        &mut self,
        id: FeatureId,
        reason: impl Into<String>,
    ) -> Result<(), FeaturePolicyError> {
        let Some(entry) = self.entries.get_mut(&id) else {
            return Err(FeaturePolicyError::UnknownFeature(id));
        };
        entry.session_forced_fallback = true;
        entry.effective_state = FeatureState::Fallback;
        entry.reason = format!("runtime fallback: {}", reason.into());
        Ok(())
    }

    pub fn apply_runtime_safety_fallback(
        &mut self,
        id: FeatureId,
        trigger: RuntimeSafetyTrigger,
    ) -> Result<String, FeaturePolicyError> {
        let reason = runtime_trigger_reason(&trigger);
        self.report_runtime_failure(id, reason.clone())?;
        Ok(format!(
            "{} moved to Fallback: {}",
            feature_id_label(id),
            reason
        ))
    }

    pub fn clear_session_fallback(&mut self, id: FeatureId) -> Result<(), FeaturePolicyError> {
        let Some(entry) = self.entries.get_mut(&id) else {
            return Err(FeaturePolicyError::UnknownFeature(id));
        };
        entry.session_forced_fallback = false;
        Ok(())
    }

    pub fn status(&self, id: FeatureId) -> Option<FeaturePolicyStatus> {
        let entry = self.entries.get(&id)?;
        Some(FeaturePolicyStatus {
            id,
            requested_state: entry.requested_state,
            effective_state: entry.effective_state,
            reason: entry.reason.clone(),
            present_on_system: entry.declaration.present_on_system,
            supports_current_platform: entry.declaration.supports_platform(self.current_platform),
        })
    }

    pub fn statuses(&self) -> Vec<FeaturePolicyStatus> {
        let mut items: Vec<FeaturePolicyStatus> = self
            .entries
            .keys()
            .copied()
            .filter_map(|id| self.status(id))
            .collect();
        items.sort_by_key(|status| status.id as u16);
        items
    }

    pub fn feature_ids(&self) -> Vec<FeatureId> {
        let mut ids: Vec<FeatureId> = self.entries.keys().copied().collect();
        ids.sort_by_key(|id| *id as u16);
        ids
    }

    pub fn declaration(&self, id: FeatureId) -> Option<FeatureDeclaration> {
        self.entries.get(&id).map(|entry| entry.declaration.clone())
    }

    pub fn is_active(&self, id: FeatureId) -> Result<bool, FeaturePolicyError> {
        let Some(entry) = self.entries.get(&id) else {
            return Err(FeaturePolicyError::UnknownFeature(id));
        };
        Ok(entry.effective_state.is_active())
    }
}

fn default_activation_checks_with_env<F>(
    declaration: &FeatureDeclaration,
    get_env: F,
) -> ActivationChecks
where
    F: Fn(&str) -> Option<String>,
{
    let platform = Platform::current();
    let platform_ok = declaration.supports_platform(platform);
    let present = declaration.present_on_system;
    let confidential_requires_manual_enable =
        matches!(declaration.id, FeatureId::ConfidentialRelay);
    let benchmark_ok = benchmark_gate_satisfied(declaration.id, get_env);

    ActivationChecks {
        platform_compatible: platform_ok,
        hardware_compatible: present,
        runtime_validation_ok: present && !confidential_requires_manual_enable,
        health_checks_ok: present && !confidential_requires_manual_enable,
        benchmark_sanity_ok: benchmark_ok,
        no_critical_conflict: true,
        measurable_benefit: !confidential_requires_manual_enable && benchmark_ok,
    }
}

fn initial_effective_state(
    declaration: &FeatureDeclaration,
    platform: Platform,
    requested: FeatureState,
) -> FeatureState {
    if !declaration.present_on_system || !declaration.supports_platform(platform) {
        return FeatureState::Disabled;
    }
    match requested {
        FeatureState::Disabled => FeatureState::Disabled,
        FeatureState::Enabled => FeatureState::Available,
        FeatureState::Auto => FeatureState::Available,
        FeatureState::Available => FeatureState::Available,
        FeatureState::Fallback => FeatureState::Fallback,
    }
}

fn initial_reason(state: FeatureState) -> String {
    match state {
        FeatureState::Disabled => "disabled: unsupported platform or missing component".to_string(),
        FeatureState::Available => "available: waiting for user or auto activation".to_string(),
        FeatureState::Enabled => "enabled".to_string(),
        FeatureState::Auto => "auto".to_string(),
        FeatureState::Fallback => "fallback".to_string(),
    }
}

fn deny_all_checks() -> ActivationChecks {
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

fn benchmark_gate_satisfied<F>(id: FeatureId, get_env: F) -> bool
where
    F: Fn(&str) -> Option<String>,
{
    let Some(env_key) = benchmark_gate_env_key(id) else {
        return true;
    };
    get_env(env_key)
        .map(|value| value.trim() == "1")
        .unwrap_or(false)
}

fn benchmark_gate_env_key(id: FeatureId) -> Option<&'static str> {
    match id {
        FeatureId::OpenVinoBackend => Some(OPENVINO_BENCHMARK_OK_ENV),
        FeatureId::TransparentHugePages => Some(THP_BENCHMARK_OK_ENV),
        FeatureId::Zswap => Some(ZSWAP_BENCHMARK_OK_ENV),
        FeatureId::Zram => Some(ZRAM_BENCHMARK_OK_ENV),
        FeatureId::MimallocAllocator => Some(MIMALLOC_BENCHMARK_OK_ENV),
        FeatureId::JemallocAllocator => Some(JEMALLOC_BENCHMARK_OK_ENV),
        FeatureId::SnmallocAllocator => Some(SNMALLOC_BENCHMARK_OK_ENV),
        FeatureId::OpenBlasBackend => Some(OPENBLAS_BENCHMARK_OK_ENV),
        FeatureId::BlisBackend => Some(BLIS_BENCHMARK_OK_ENV),
        FeatureId::PerfProfiler => Some(PERF_BENCHMARK_OK_ENV),
        FeatureId::TracyProfiler => Some(TRACY_BENCHMARK_OK_ENV),
        FeatureId::AutoFdoOptimizer => Some(AUTOFDO_BENCHMARK_OK_ENV),
        FeatureId::BoltOptimizer => Some(BOLT_BENCHMARK_OK_ENV),
        FeatureId::IspcKernels => Some(ISPC_BENCHMARK_OK_ENV),
        FeatureId::HighwaySimd => Some(HIGHWAY_BENCHMARK_OK_ENV),
        FeatureId::RustArchSimd => Some(RUST_ARCH_SIMD_BENCHMARK_OK_ENV),
        FeatureId::RayonParallelism => Some(RAYON_BENCHMARK_OK_ENV),
        FeatureId::IoUring => Some(IO_URING_BENCHMARK_OK_ENV),
        FeatureId::LmdbMetadata => Some(LMDB_BENCHMARK_OK_ENV),
        FeatureId::ConfidentialRelay => Some(CONFIDENTIAL_RELAY_BENCHMARK_OK_ENV),
        _ => None,
    }
}

fn openvino_present_on_host() -> bool {
    env_config::read_strict_one_flag(OPENVINO_PRESENT_ENV).unwrap_or(false)
}

fn openblas_present_on_host() -> bool {
    env_config::read_strict_one_flag(OPENBLAS_PRESENT_ENV).unwrap_or(false)
}

fn blis_present_on_host() -> bool {
    env_config::read_strict_one_flag(BLIS_PRESENT_ENV).unwrap_or(false)
}

fn mimalloc_present_on_host() -> bool {
    env_presence_override(MIMALLOC_PRESENT_ENV).unwrap_or(true)
}

fn jemalloc_present_on_host() -> bool {
    env_presence_override(JEMALLOC_PRESENT_ENV).unwrap_or(true)
}

fn snmalloc_present_on_host() -> bool {
    env_presence_override(SNMALLOC_PRESENT_ENV).unwrap_or(true)
}

fn env_presence_override(env_key: &str) -> Option<bool> {
    env_config::read_strict_one_flag(env_key)
}

fn perf_present_on_host() -> bool {
    if let Some(value) = env_presence_override(PERF_PRESENT_ENV) {
        return value;
    }
    linux_path_exists("/usr/bin/perf") || linux_path_exists("/bin/perf")
}

fn tracy_present_on_host() -> bool {
    env_presence_override(TRACY_PRESENT_ENV).unwrap_or(true)
}

fn autofdo_present_on_host() -> bool {
    if let Some(value) = env_presence_override(AUTOFDO_PRESENT_ENV) {
        return value;
    }
    linux_path_exists("/usr/bin/llvm-profdata") || linux_path_exists("/usr/local/bin/llvm-profdata")
}

fn bolt_present_on_host() -> bool {
    if let Some(value) = env_presence_override(BOLT_PRESENT_ENV) {
        return value;
    }
    linux_path_exists("/usr/bin/llvm-bolt") || linux_path_exists("/usr/local/bin/llvm-bolt")
}

fn ispc_present_on_host() -> bool {
    if let Some(value) = env_presence_override(ISPC_PRESENT_ENV) {
        return value;
    }
    linux_path_exists("/usr/bin/ispc") || linux_path_exists("/usr/local/bin/ispc")
}

fn highway_present_on_host() -> bool {
    env_presence_override(HIGHWAY_PRESENT_ENV).unwrap_or(true)
}

fn rust_arch_simd_present_on_host() -> bool {
    if let Some(value) = env_presence_override(RUST_ARCH_SIMD_PRESENT_ENV) {
        return value;
    }
    cfg!(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "aarch64"
    ))
}

fn rayon_present_on_host() -> bool {
    env_presence_override(RAYON_PRESENT_ENV).unwrap_or(true)
}

fn io_uring_present_on_host() -> bool {
    if let Some(value) = env_presence_override(IO_URING_PRESENT_ENV) {
        return value;
    }
    #[cfg(target_os = "linux")]
    {
        if !linux_path_exists("/proc/sys/kernel/osrelease") {
            return false;
        }
        if let Ok(raw) = std::fs::read_to_string("/proc/sys/kernel/io_uring_disabled") {
            if raw.trim() == "2" {
                return false;
            }
        }
        return true;
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

fn lmdb_present_on_host() -> bool {
    env_presence_override(LMDB_PRESENT_ENV).unwrap_or(true)
}

fn confidential_relay_present_on_host() -> bool {
    env_presence_override(CONFIDENTIAL_RELAY_PRESENT_ENV).unwrap_or(true)
}

fn transparent_huge_pages_present_on_host() -> bool {
    linux_path_exists("/sys/kernel/mm/transparent_hugepage/enabled")
}

fn zswap_present_on_host() -> bool {
    linux_path_exists("/sys/module/zswap/parameters/enabled")
}

fn zram_present_on_host() -> bool {
    linux_path_exists("/sys/class/zram-control/hot_add") || linux_path_exists("/sys/block/zram0")
}

#[cfg(target_os = "linux")]
fn linux_path_exists(path: &str) -> bool {
    std::path::Path::new(path).exists()
}

#[cfg(not(target_os = "linux"))]
fn linux_path_exists(_path: &str) -> bool {
    false
}

fn percentile_u64(sorted_values: &[u64], percentile: usize) -> u64 {
    if sorted_values.is_empty() {
        return 0;
    }
    let last = sorted_values.len().saturating_sub(1);
    let index = (last.saturating_mul(percentile)) / 100;
    sorted_values[index]
}

fn percentile_u32(sorted_values: &[u32], percentile: usize) -> u32 {
    if sorted_values.is_empty() {
        return 0;
    }
    let last = sorted_values.len().saturating_sub(1);
    let index = (last.saturating_mul(percentile)) / 100;
    sorted_values[index]
}

fn runtime_trigger_reason(trigger: &RuntimeSafetyTrigger) -> String {
    match trigger {
        RuntimeSafetyTrigger::Instability => "instability detected".to_string(),
        RuntimeSafetyTrigger::RepeatedValidationFailure => {
            "repeated validation failure".to_string()
        }
        RuntimeSafetyTrigger::SevereRegression => "severe regression detected".to_string(),
        RuntimeSafetyTrigger::MemoryPressureSpike => "memory pressure spike detected".to_string(),
        RuntimeSafetyTrigger::HardwareIncompatibility => {
            "hardware incompatibility detected".to_string()
        }
        RuntimeSafetyTrigger::BrokenFallbackBehavior => "fallback behavior is broken".to_string(),
        RuntimeSafetyTrigger::RuntimeError(reason) => reason.clone(),
    }
}

fn feature_id_label(id: FeatureId) -> &'static str {
    match id {
        FeatureId::HwlocTopology => "hwloc topology",
        FeatureId::NumactlPlacement => "numactl placement",
        FeatureId::MimallocAllocator => "mimalloc allocator",
        FeatureId::JemallocAllocator => "jemalloc allocator",
        FeatureId::SnmallocAllocator => "snmalloc allocator",
        FeatureId::VulkanMemoryAllocator => "vulkan memory allocator",
        FeatureId::IoUring => "io_uring",
        FeatureId::LmdbMetadata => "lmdb metadata",
        FeatureId::OpenVinoBackend => "openvino backend",
        FeatureId::TransparentHugePages => "transparent huge pages",
        FeatureId::Zswap => "zswap",
        FeatureId::Zram => "zram",
        FeatureId::OpenBlasBackend => "openblas backend",
        FeatureId::BlisBackend => "blis backend",
        FeatureId::PerfProfiler => "perf profiler",
        FeatureId::TracyProfiler => "tracy profiler",
        FeatureId::AutoFdoOptimizer => "autofdo optimizer",
        FeatureId::BoltOptimizer => "bolt optimizer",
        FeatureId::IspcKernels => "ispc kernels",
        FeatureId::HighwaySimd => "highway simd",
        FeatureId::RustArchSimd => "rust arch simd",
        FeatureId::RayonParallelism => "rayon parallelism",
        FeatureId::ConfidentialRelay => "confidential relay",
    }
}

pub fn default_feature_declarations() -> Vec<FeatureDeclaration> {
    let openvino_present = openvino_present_on_host();
    let thp_present = transparent_huge_pages_present_on_host();
    let zswap_present = zswap_present_on_host();
    let zram_present = zram_present_on_host();
    let openblas_present = openblas_present_on_host();
    let blis_present = blis_present_on_host();
    let mimalloc_present = mimalloc_present_on_host();
    let jemalloc_present = jemalloc_present_on_host();
    let snmalloc_present = snmalloc_present_on_host();
    let perf_present = perf_present_on_host();
    let tracy_present = tracy_present_on_host();
    let autofdo_present = autofdo_present_on_host();
    let bolt_present = bolt_present_on_host();
    let ispc_present = ispc_present_on_host();
    let highway_present = highway_present_on_host();
    let rust_arch_simd_present = rust_arch_simd_present_on_host();
    let rayon_present = rayon_present_on_host();
    let io_uring_present = io_uring_present_on_host();
    let lmdb_present = lmdb_present_on_host();
    let confidential_relay_present = confidential_relay_present_on_host();

    vec![
        declaration(
            FeatureId::HwlocTopology,
            vec![Platform::Linux],
            "Host with hwloc-compatible topology",
            "Topology-aware placement and locality",
            "Incorrect topology assumptions can misplace work",
            "Topology snapshot + scheduler placement tests",
            "Disable topology mode and use baseline scheduler",
            "Benchmarked scheduling/locality delta",
            true,
        ),
        declaration(
            FeatureId::NumactlPlacement,
            vec![Platform::Linux],
            "NUMA-capable Linux host with numactl support",
            "Improved memory locality and reduced cross-node latency",
            "Over-constrained affinity can regress throughput",
            "Runtime launch validation + placement checks",
            "Fallback to OS default scheduler placement",
            "NUMA benchmark with representative workloads",
            true,
        ),
        declaration(
            FeatureId::MimallocAllocator,
            vec![Platform::Windows, Platform::Linux, Platform::MacOs],
            "Compatible toolchain build for mimalloc",
            "General allocation throughput improvements",
            "Allocator mismatch with workloads",
            "Allocator build matrix + workload benchmarks",
            "Switch to default allocator policy",
            "Allocator benchmark suite required",
            mimalloc_present,
        ),
        declaration(
            FeatureId::JemallocAllocator,
            vec![Platform::Windows, Platform::Linux, Platform::MacOs],
            "Compatible toolchain build for jemalloc",
            "Fragmentation control and concurrency behavior",
            "Binary size/perf tradeoff on some hosts",
            "Allocator build matrix + stress benchmarks",
            "Switch allocator to safe default",
            "Allocator benchmark suite required",
            jemalloc_present,
        ),
        declaration(
            FeatureId::SnmallocAllocator,
            vec![Platform::Windows, Platform::Linux, Platform::MacOs],
            "Compatible toolchain build for snmalloc",
            "Cross-thread allocation/free efficiency",
            "Workload-specific regressions possible",
            "Allocator build matrix + queue benchmarks",
            "Switch allocator to safe default",
            "Allocator benchmark suite required",
            snmalloc_present,
        ),
        declaration(
            FeatureId::VulkanMemoryAllocator,
            vec![Platform::Windows, Platform::Linux],
            "Vulkan-capable GPU and runtime",
            "VRAM suballocation and reduced fragmentation",
            "Driver/runtime compatibility variance",
            "Vulkan allocator lifecycle tests",
            "Fallback to conservative Vulkan allocation path",
            "Vulkan memory benchmark required",
            true,
        ),
        declaration(
            FeatureId::IoUring,
            vec![Platform::Linux],
            "Linux kernel 5.10+ with io_uring support",
            "Lower I/O overhead for heavy async workloads",
            "Kernel/runtime incompatibility",
            "I/O path validation and throughput tests",
            "Fallback to baseline async I/O path",
            "Linux I/O benchmark required",
            io_uring_present,
        ),
        declaration(
            FeatureId::LmdbMetadata,
            vec![Platform::Windows, Platform::Linux, Platform::MacOs],
            "LMDB-compatible storage environment",
            "Fast mmap-based metadata lookup",
            "Schema and locking constraints",
            "Read/write/migration/recovery tests",
            "Fallback to prior metadata store",
            "Metadata benchmark and correctness gate",
            lmdb_present,
        ),
        declaration(
            FeatureId::OpenVinoBackend,
            vec![Platform::Windows, Platform::Linux],
            "Intel-class host and compatible model/runtime",
            "Multi-device inference efficiency",
            "Model compatibility limitations",
            "Backend compatibility and generation tests",
            "Fallback to primary local runtime backend",
            "Backend benchmark and compatibility gate",
            openvino_present,
        ),
        declaration(
            FeatureId::TransparentHugePages,
            vec![Platform::Linux],
            "Linux host with THP controls",
            "Potential TLB and memory-overhead improvements",
            "Host-dependent latency regressions",
            "THP tuning validation and workload sampling",
            "Revert to kernel baseline THP behavior",
            "Linux memory benchmark required",
            thp_present,
        ),
        declaration(
            FeatureId::Zswap,
            vec![Platform::Linux],
            "Linux host with swap and zswap support",
            "Improved degraded-memory behavior on weak PCs",
            "Compression overhead on some workloads",
            "Memory-pressure scenario validation",
            "Disable zswap tuning profile",
            "Weak-PC pressure benchmark required",
            zswap_present,
        ),
        declaration(
            FeatureId::Zram,
            vec![Platform::Linux],
            "Linux host with zram support",
            "Improved compressed memory behavior under pressure",
            "Potential CPU overhead for compression",
            "Memory-pressure scenario validation",
            "Disable zram profile",
            "Weak-PC pressure benchmark required",
            zram_present,
        ),
        declaration(
            FeatureId::OpenBlasBackend,
            vec![Platform::Windows, Platform::Linux, Platform::MacOs],
            "OpenBLAS-compatible build/runtime",
            "Portable BLAS/LAPACK acceleration",
            "Backend-specific numerical/perf variance",
            "Dense-math backend correctness tests",
            "Fallback to selected default backend",
            "Dense-math benchmark suite required",
            openblas_present,
        ),
        declaration(
            FeatureId::BlisBackend,
            vec![Platform::Windows, Platform::Linux, Platform::MacOs],
            "BLIS-compatible build/runtime",
            "Portable dense linear algebra acceleration",
            "Backend-specific tuning complexity",
            "Dense-math backend correctness tests",
            "Fallback to selected default backend",
            "Dense-math benchmark suite required",
            blis_present,
        ),
        declaration(
            FeatureId::PerfProfiler,
            vec![Platform::Linux],
            "Linux perf event support",
            "System-level profiling visibility",
            "Profiling overhead if always-on",
            "Profiling mode validation",
            "Disable perf capture for session",
            "Profiling overhead benchmark",
            perf_present,
        ),
        declaration(
            FeatureId::TracyProfiler,
            vec![Platform::Windows, Platform::Linux, Platform::MacOs],
            "Tracy-compatible build and capture setup",
            "Timeline and contention profiling visibility",
            "Instrumentation overhead",
            "Profiler capture validation",
            "Disable Tracy instrumentation",
            "Profiling overhead benchmark",
            tracy_present,
        ),
        declaration(
            FeatureId::AutoFdoOptimizer,
            vec![Platform::Linux],
            "Linux/Clang perf profile pipeline",
            "Sampled profile-guided layout and optimization gains",
            "Toolchain complexity",
            "Release pipeline validation",
            "Fallback to baseline release build path",
            "Release benchmark delta required",
            autofdo_present,
        ),
        declaration(
            FeatureId::BoltOptimizer,
            vec![Platform::Linux],
            "LLVM BOLT-compatible toolchain",
            "Post-link code layout improvements",
            "Build complexity and toolchain drift",
            "Release pipeline validation",
            "Fallback to non-BOLT optimized binaries",
            "Release benchmark delta required",
            bolt_present,
        ),
        declaration(
            FeatureId::IspcKernels,
            vec![Platform::Windows, Platform::Linux, Platform::MacOs],
            "ISPC toolchain and compatible kernels",
            "SIMD acceleration for selected hotspots",
            "Kernel maintenance complexity",
            "Kernel correctness + perf validation",
            "Fallback to baseline kernel implementation",
            "Kernel benchmark delta required",
            ispc_present,
        ),
        declaration(
            FeatureId::HighwaySimd,
            vec![Platform::Windows, Platform::Linux, Platform::MacOs],
            "Highway-compatible C++ toolchain",
            "Portable SIMD dispatch for kernels",
            "Dispatch overhead in low-gain paths",
            "Kernel correctness + perf validation",
            "Fallback to baseline/vector-specific implementation",
            "Kernel benchmark delta required",
            highway_present,
        ),
        declaration(
            FeatureId::RustArchSimd,
            vec![Platform::Windows, Platform::Linux, Platform::MacOs],
            "Target ISA intrinsics support",
            "Rust-side SIMD speedups in hot paths",
            "ISA-specific maintenance complexity",
            "Per-target correctness + perf validation",
            "Fallback to scalar implementation",
            "Kernel benchmark delta required",
            rust_arch_simd_present,
        ),
        declaration(
            FeatureId::RayonParallelism,
            vec![Platform::Windows, Platform::Linux, Platform::MacOs],
            "Rayon-compatible Rust runtime",
            "Parallel loop throughput in app-owned paths",
            "Thread oversubscription risk",
            "Concurrency budget + workload validation",
            "Fallback to sequential loop path",
            "Throughput/latency benchmark required",
            rayon_present,
        ),
        declaration(
            FeatureId::ConfidentialRelay,
            vec![Platform::Windows, Platform::Linux, Platform::MacOs],
            "Remote attestation-capable confidential endpoint and secure transport",
            "Attested remote inference with fail-closed policy gating",
            "Misconfigured attestation policy can block valid remote routes",
            "Attestation validation + secure transport checks",
            "Fallback to non-confidential routed or local execution",
            "Confidential relay benchmark and policy audit required",
            confidential_relay_present,
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn declaration(
    id: FeatureId,
    supported_platforms: Vec<Platform>,
    required_hardware: &str,
    expected_benefit: &str,
    known_risks: &str,
    validation_method: &str,
    fallback_path: &str,
    benchmark_requirement: &str,
    present_on_system: bool,
) -> FeatureDeclaration {
    FeatureDeclaration {
        id,
        supported_platforms,
        required_hardware: required_hardware.to_string(),
        expected_benefit: expected_benefit.to_string(),
        known_risks: known_risks.to_string(),
        validation_method: validation_method.to_string(),
        fallback_path: fallback_path.to_string(),
        benchmark_requirement: benchmark_requirement.to_string(),
        present_on_system,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FeaturePolicyRegistry, RuntimeSafetyTrigger, VulkanBenchmarkGateConfig,
        VulkanBenchmarkGateDecision, VulkanBenchmarkSample, apply_vulkan_benchmark_gate,
        default_activation_checks_for_declaration, deny_all_checks, evaluate_vulkan_benchmark_gate,
    };
    use std::collections::HashMap;
    use urm::feature_policy::{
        ActivationChecks, FeatureDeclaration, FeatureId, FeatureState, Platform,
    };

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

    fn declaration_for_test(id: FeatureId) -> FeatureDeclaration {
        FeatureDeclaration {
            id,
            supported_platforms: vec![Platform::current()],
            required_hardware: "test".to_string(),
            expected_benefit: "test".to_string(),
            known_risks: "test".to_string(),
            validation_method: "test".to_string(),
            fallback_path: "test".to_string(),
            benchmark_requirement: "test".to_string(),
            present_on_system: true,
        }
    }

    #[test]
    fn confidential_relay_default_checks_require_manual_enable() {
        let checks = default_activation_checks_for_declaration(&declaration_for_test(
            FeatureId::ConfidentialRelay,
        ));
        assert!(!checks.runtime_validation_ok);
        assert!(!checks.health_checks_ok);
        assert!(!checks.measurable_benefit);
        assert!(!checks.allows_activation());
    }

    #[test]
    fn conditional_stack_default_checks_are_benchmark_gated() {
        let openvino_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::OpenVinoBackend),
            |_| None,
        );
        assert!(!openvino_checks.benchmark_sanity_ok);
        assert!(!openvino_checks.measurable_benefit);
        assert!(!openvino_checks.allows_activation());

        let thp_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::TransparentHugePages),
            |_| None,
        );
        assert!(!thp_checks.allows_activation());

        let openblas_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::OpenBlasBackend),
            |_| None,
        );
        assert!(!openblas_checks.allows_activation());

        let blis_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::BlisBackend),
            |_| None,
        );
        assert!(!blis_checks.allows_activation());
    }

    #[test]
    fn conditional_stack_checks_allow_activation_when_benchmark_flags_are_set() {
        let checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::OpenVinoBackend),
            |key| {
                if key == super::OPENVINO_BENCHMARK_OK_ENV {
                    Some("1".to_string())
                } else {
                    None
                }
            },
        );
        assert!(checks.benchmark_sanity_ok);
        assert!(checks.measurable_benefit);
        assert!(checks.allows_activation());

        let openblas_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::OpenBlasBackend),
            |key| {
                if key == super::OPENBLAS_BENCHMARK_OK_ENV {
                    Some("1".to_string())
                } else {
                    None
                }
            },
        );
        assert!(openblas_checks.allows_activation());

        let blis_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::BlisBackend),
            |key| {
                if key == super::BLIS_BENCHMARK_OK_ENV {
                    Some("1".to_string())
                } else {
                    None
                }
            },
        );
        assert!(blis_checks.allows_activation());
    }

    #[test]
    fn optimizer_and_profiler_checks_are_benchmark_gated() {
        let perf_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::PerfProfiler),
            |_| None,
        );
        assert!(!perf_checks.allows_activation());

        let autofdo_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::AutoFdoOptimizer),
            |_| None,
        );
        assert!(!autofdo_checks.allows_activation());

        let ispc_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::IspcKernels),
            |_| None,
        );
        assert!(!ispc_checks.allows_activation());

        let highway_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::HighwaySimd),
            |_| None,
        );
        assert!(!highway_checks.allows_activation());

        let rust_arch_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::RustArchSimd),
            |_| None,
        );
        assert!(!rust_arch_checks.allows_activation());

        let rayon_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::RayonParallelism),
            |_| None,
        );
        assert!(!rayon_checks.allows_activation());

        let io_uring_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::IoUring),
            |_| None,
        );
        assert!(!io_uring_checks.allows_activation());

        let mimalloc_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::MimallocAllocator),
            |_| None,
        );
        assert!(!mimalloc_checks.allows_activation());

        let jemalloc_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::JemallocAllocator),
            |_| None,
        );
        assert!(!jemalloc_checks.allows_activation());

        let snmalloc_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::SnmallocAllocator),
            |_| None,
        );
        assert!(!snmalloc_checks.allows_activation());

        let lmdb_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::LmdbMetadata),
            |_| None,
        );
        assert!(!lmdb_checks.allows_activation());

        let confidential_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::ConfidentialRelay),
            |_| None,
        );
        assert!(!confidential_checks.allows_activation());
        assert!(!confidential_checks.benchmark_sanity_ok);
    }

    #[test]
    fn optimizer_and_profiler_checks_allow_activation_with_flags() {
        let perf_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::PerfProfiler),
            |key| {
                if key == super::PERF_BENCHMARK_OK_ENV {
                    Some("1".to_string())
                } else {
                    None
                }
            },
        );
        assert!(perf_checks.allows_activation());

        let autofdo_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::AutoFdoOptimizer),
            |key| {
                if key == super::AUTOFDO_BENCHMARK_OK_ENV {
                    Some("1".to_string())
                } else {
                    None
                }
            },
        );
        assert!(autofdo_checks.allows_activation());

        let ispc_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::IspcKernels),
            |key| {
                if key == super::ISPC_BENCHMARK_OK_ENV {
                    Some("1".to_string())
                } else {
                    None
                }
            },
        );
        assert!(ispc_checks.allows_activation());

        let highway_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::HighwaySimd),
            |key| {
                if key == super::HIGHWAY_BENCHMARK_OK_ENV {
                    Some("1".to_string())
                } else {
                    None
                }
            },
        );
        assert!(highway_checks.allows_activation());

        let rust_arch_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::RustArchSimd),
            |key| {
                if key == super::RUST_ARCH_SIMD_BENCHMARK_OK_ENV {
                    Some("1".to_string())
                } else {
                    None
                }
            },
        );
        assert!(rust_arch_checks.allows_activation());

        let rayon_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::RayonParallelism),
            |key| {
                if key == super::RAYON_BENCHMARK_OK_ENV {
                    Some("1".to_string())
                } else {
                    None
                }
            },
        );
        assert!(rayon_checks.allows_activation());

        let io_uring_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::IoUring),
            |key| {
                if key == super::IO_URING_BENCHMARK_OK_ENV {
                    Some("1".to_string())
                } else {
                    None
                }
            },
        );
        assert!(io_uring_checks.allows_activation());

        let mimalloc_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::MimallocAllocator),
            |key| {
                if key == super::MIMALLOC_BENCHMARK_OK_ENV {
                    Some("1".to_string())
                } else {
                    None
                }
            },
        );
        assert!(mimalloc_checks.allows_activation());

        let jemalloc_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::JemallocAllocator),
            |key| {
                if key == super::JEMALLOC_BENCHMARK_OK_ENV {
                    Some("1".to_string())
                } else {
                    None
                }
            },
        );
        assert!(jemalloc_checks.allows_activation());

        let snmalloc_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::SnmallocAllocator),
            |key| {
                if key == super::SNMALLOC_BENCHMARK_OK_ENV {
                    Some("1".to_string())
                } else {
                    None
                }
            },
        );
        assert!(snmalloc_checks.allows_activation());

        let lmdb_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::LmdbMetadata),
            |key| {
                if key == super::LMDB_BENCHMARK_OK_ENV {
                    Some("1".to_string())
                } else {
                    None
                }
            },
        );
        assert!(lmdb_checks.allows_activation());

        let confidential_checks = super::default_activation_checks_with_env(
            &declaration_for_test(FeatureId::ConfidentialRelay),
            |key| {
                if key == super::CONFIDENTIAL_RELAY_BENCHMARK_OK_ENV {
                    Some("1".to_string())
                } else {
                    None
                }
            },
        );
        assert!(confidential_checks.benchmark_sanity_ok);
        assert!(!confidential_checks.allows_activation());
    }

    #[test]
    fn defaults_start_in_auto_with_non_active_effective_state() {
        let registry = FeaturePolicyRegistry::with_defaults();
        let status = registry.status(FeatureId::RayonParallelism);
        assert!(status.is_some());
        let status = match status {
            Some(value) => value,
            None => return,
        };
        assert_eq!(status.requested_state, FeatureState::Auto);
        assert!(matches!(
            status.effective_state,
            FeatureState::Available | FeatureState::Disabled
        ));
    }

    #[test]
    fn enabled_requires_checks_or_moves_to_fallback() {
        let mut registry = FeaturePolicyRegistry::with_defaults();
        let set = registry.set_requested_state(FeatureId::RayonParallelism, FeatureState::Enabled);
        assert!(set.is_ok());

        let state = registry.evaluate(FeatureId::RayonParallelism, deny_all_checks());
        assert!(state.is_ok());
        let state = match state {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(state, FeatureState::Fallback);
    }

    #[test]
    fn auto_enables_when_checks_pass() {
        let mut registry = FeaturePolicyRegistry::with_defaults();
        let set = registry.set_requested_state(FeatureId::RayonParallelism, FeatureState::Auto);
        assert!(set.is_ok());

        let state = registry.evaluate(FeatureId::RayonParallelism, full_checks());
        assert!(state.is_ok());
        let state = match state {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(state, FeatureState::Enabled);
    }

    #[test]
    fn runtime_failure_forces_session_fallback_until_cleared() {
        let mut registry = FeaturePolicyRegistry::with_defaults();
        let set = registry.set_requested_state(FeatureId::RayonParallelism, FeatureState::Auto);
        assert!(set.is_ok());

        let first = registry.evaluate(FeatureId::RayonParallelism, full_checks());
        assert!(matches!(first, Ok(FeatureState::Enabled)));

        let failure = registry.report_runtime_failure(FeatureId::RayonParallelism, "stability");
        assert!(failure.is_ok());

        let forced = registry.evaluate(FeatureId::RayonParallelism, full_checks());
        assert!(matches!(forced, Ok(FeatureState::Fallback)));

        let clear = registry.clear_session_fallback(FeatureId::RayonParallelism);
        assert!(clear.is_ok());

        let resumed = registry.evaluate(FeatureId::RayonParallelism, full_checks());
        assert!(matches!(resumed, Ok(FeatureState::Enabled)));
    }

    #[test]
    fn runtime_safety_fallback_returns_user_notification() {
        let mut registry = FeaturePolicyRegistry::with_defaults();
        let set =
            registry.set_requested_state(FeatureId::VulkanMemoryAllocator, FeatureState::Auto);
        assert!(set.is_ok());
        let _ = registry.evaluate(FeatureId::VulkanMemoryAllocator, full_checks());

        let note = registry.apply_runtime_safety_fallback(
            FeatureId::VulkanMemoryAllocator,
            RuntimeSafetyTrigger::RepeatedValidationFailure,
        );
        assert!(note.is_ok());
        let note = match note {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(note.contains("Fallback"));

        let status = registry.status(FeatureId::VulkanMemoryAllocator);
        assert!(status.is_some());
        let status = match status {
            Some(value) => value,
            None => return,
        };
        assert_eq!(status.effective_state, FeatureState::Fallback);
    }

    #[test]
    fn reset_to_safe_defaults_returns_auto_mode() {
        let mut registry = FeaturePolicyRegistry::with_defaults();
        let set = registry.set_requested_state(FeatureId::RayonParallelism, FeatureState::Enabled);
        assert!(set.is_ok());

        let _ = registry.evaluate(FeatureId::RayonParallelism, full_checks());
        registry.reset_to_safe_defaults();

        let status = registry.status(FeatureId::RayonParallelism);
        assert!(status.is_some());
        let status = match status {
            Some(value) => value,
            None => return,
        };
        assert_eq!(status.requested_state, FeatureState::Auto);
        assert!(matches!(
            status.effective_state,
            FeatureState::Available | FeatureState::Disabled
        ));
    }

    #[test]
    fn evaluate_all_uses_per_feature_checks() {
        let mut registry = FeaturePolicyRegistry::with_defaults();
        let set = registry.set_requested_state(FeatureId::RayonParallelism, FeatureState::Auto);
        assert!(set.is_ok());

        let mut checks = HashMap::new();
        checks.insert(FeatureId::RayonParallelism, full_checks());
        let statuses = registry.evaluate_all(&checks);

        let matched = statuses
            .iter()
            .find(|status| status.id == FeatureId::RayonParallelism);
        assert!(matched.is_some());
        let matched = match matched {
            Some(value) => value,
            None => return,
        };
        assert_eq!(matched.effective_state, FeatureState::Enabled);
    }

    #[test]
    fn vulkan_benchmark_gate_requires_minimum_samples() {
        let decision = evaluate_vulkan_benchmark_gate(
            &[VulkanBenchmarkSample {
                latency_ms: 150,
                tokens_per_second: Some(32),
                success: true,
            }],
            VulkanBenchmarkGateConfig::default(),
        );
        assert!(matches!(
            decision,
            VulkanBenchmarkGateDecision::InsufficientData { .. }
        ));
    }

    #[test]
    fn vulkan_benchmark_gate_failure_forces_fallback() {
        let mut registry = FeaturePolicyRegistry::with_defaults();
        let _ = registry.set_requested_state(FeatureId::VulkanMemoryAllocator, FeatureState::Auto);
        let _ = registry.evaluate(FeatureId::VulkanMemoryAllocator, full_checks());

        let decision = evaluate_vulkan_benchmark_gate(
            &[
                VulkanBenchmarkSample {
                    latency_ms: 420,
                    tokens_per_second: Some(8),
                    success: false,
                },
                VulkanBenchmarkSample {
                    latency_ms: 398,
                    tokens_per_second: Some(9),
                    success: false,
                },
                VulkanBenchmarkSample {
                    latency_ms: 377,
                    tokens_per_second: Some(10),
                    success: true,
                },
            ],
            VulkanBenchmarkGateConfig::default(),
        );
        assert!(matches!(decision, VulkanBenchmarkGateDecision::Fail { .. }));

        let applied = apply_vulkan_benchmark_gate(&mut registry, &decision);
        assert!(applied.is_ok());
        let status = registry.status(FeatureId::VulkanMemoryAllocator);
        assert!(status.is_some());
        let status = match status {
            Some(value) => value,
            None => return,
        };
        assert_eq!(status.effective_state, FeatureState::Fallback);
    }

    #[test]
    fn vulkan_benchmark_gate_pass_clears_existing_fallback() {
        let mut registry = FeaturePolicyRegistry::with_defaults();
        let _ = registry.set_requested_state(FeatureId::VulkanMemoryAllocator, FeatureState::Auto);
        let _ = registry.report_runtime_failure(FeatureId::VulkanMemoryAllocator, "seed fallback");

        let decision = evaluate_vulkan_benchmark_gate(
            &[
                VulkanBenchmarkSample {
                    latency_ms: 140,
                    tokens_per_second: Some(34),
                    success: true,
                },
                VulkanBenchmarkSample {
                    latency_ms: 138,
                    tokens_per_second: Some(36),
                    success: true,
                },
                VulkanBenchmarkSample {
                    latency_ms: 145,
                    tokens_per_second: Some(35),
                    success: true,
                },
            ],
            VulkanBenchmarkGateConfig::default(),
        );
        assert!(matches!(decision, VulkanBenchmarkGateDecision::Pass { .. }));

        let applied = apply_vulkan_benchmark_gate(&mut registry, &decision);
        assert!(applied.is_ok());
        let _ = registry.evaluate(FeatureId::VulkanMemoryAllocator, full_checks());

        let status = registry.status(FeatureId::VulkanMemoryAllocator);
        assert!(status.is_some());
        let status = match status {
            Some(value) => value,
            None => return,
        };
        assert_eq!(status.effective_state, FeatureState::Enabled);
    }
}
