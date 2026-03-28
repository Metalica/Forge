const OPENVINO_BENCHMARK_OK_ENV: &str = "OPENVINO_BENCHMARK_OK";
const THP_BENCHMARK_OK_ENV: &str = "THP_BENCHMARK_OK";
const ZSWAP_BENCHMARK_OK_ENV: &str = "ZSWAP_BENCHMARK_OK";
const ZRAM_BENCHMARK_OK_ENV: &str = "ZRAM_BENCHMARK_OK";
const OPENBLAS_BENCHMARK_OK_ENV: &str = "OPENBLAS_BENCHMARK_OK";
const BLIS_BENCHMARK_OK_ENV: &str = "BLIS_BENCHMARK_OK";
const MIMALLOC_BENCHMARK_OK_ENV: &str = "MIMALLOC_BENCHMARK_OK";
const JEMALLOC_BENCHMARK_OK_ENV: &str = "JEMALLOC_BENCHMARK_OK";
const SNMALLOC_BENCHMARK_OK_ENV: &str = "SNMALLOC_BENCHMARK_OK";
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

const GATE_JSON_PREFIX: &str = "conditional-adoption-gate-";
const GATE_JSON_SUFFIX: &str = ".json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedFeaturePreference {
    id: FeatureId,
    requested_state: FeatureState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedFeatureSettings {
    fallback_visibility: bool,
    features: Vec<PersistedFeaturePreference>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct GateSelectedDefaults {
    #[serde(default)]
    openvino_backend: String,
    #[serde(default)]
    linux_memory_tuning_profile: String,
    #[serde(default = "default_gate_selected_disabled")]
    openblas_backend: String,
    #[serde(default = "default_gate_selected_disabled")]
    blis_backend: String,
    #[serde(default = "default_gate_selected_disabled")]
    profiling_mode: String,
    #[serde(default = "default_gate_selected_disabled")]
    release_optimization_mode: String,
    #[serde(default = "default_gate_selected_disabled")]
    ispc_kernels: String,
    #[serde(default = "default_gate_selected_disabled")]
    highway_simd: String,
    #[serde(default = "default_gate_selected_disabled")]
    rust_arch_simd: String,
    #[serde(default = "default_gate_selected_disabled")]
    rayon_parallelism: String,
}

fn default_gate_selected_disabled() -> String {
    "Disabled".to_string()
}

#[derive(Debug, Clone, Default, Deserialize)]
struct GateDecision {
    #[serde(default)]
    passed: bool,
    #[serde(default)]
    reasons: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct ConditionalGateArtifact {
    #[serde(default)]
    generated_at_utc: String,
    #[serde(default)]
    gate_passed: bool,
    #[serde(default)]
    selected_defaults: GateSelectedDefaults,
    #[serde(default)]
    recommended_env_flags: HashMap<String, i64>,
    #[serde(default)]
    decision: GateDecision,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedAgentStudioState {
    schema_version: u32,
    active_run_id: Option<u64>,
    runs: Vec<AgentRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedProjectMemoryState {
    schema_version: u32,
    entries: Vec<MemoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedJobQueueState {
    schema_version: u32,
    queue: JobQueueState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedExtensionHostState {
    schema_version: u32,
    runtimes: Vec<ExtensionRuntimeSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedMediaStudioState {
    schema_version: u32,
    media_prompt: String,
    media_seed: String,
    media_batch_size: String,
    media_gallery: String,
    media_next_asset_id: u64,
    video_prompt: String,
    video_seed: String,
    video_batch_size: String,
    video_duration_seconds: String,
    video_checkpoint_entries: Vec<VideoCheckpointState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedDockLayoutState {
    schema_version: u32,
    sidebar_open: bool,
    inspector_open: bool,
    bottom_open: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedChatConfidentialState {
    schema_version: u32,
    measurement: String,
    policy_mode: String,
    max_attestation_age_ms: String,
    #[serde(default = "default_chat_confidential_profile_window")]
    profile_window_size: String,
    require_confidential_cpu: bool,
    require_confidential_gpu: bool,
    #[serde(default = "default_chat_confidential_allow_remote_fallback")]
    allow_remote_fallback: bool,
}

fn agent_studio_state_path() -> PathBuf {
    match std::env::current_dir() {
        Ok(path) => path.join(".forge_agent_studio.json"),
        Err(_) => PathBuf::from("E:/Forge/.forge_agent_studio.json"),
    }
}

fn load_agent_studio_state(path: &Path) -> Option<PersistedAgentStudioState> {
    let contents = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(_) => return None,
    };
    let state = serde_json::from_str::<PersistedAgentStudioState>(&contents).ok()?;
    if state.schema_version != 1 {
        return None;
    }
    Some(state)
}

fn save_agent_studio_state(
    path: &Path,
    orchestrator: &AgentOrchestrator,
    active_run_id: Option<u64>,
) -> UiOperationResult {
    let state = PersistedAgentStudioState {
        schema_version: 1,
        active_run_id,
        runs: orchestrator.runs_snapshot(),
    };
    let encoded = serde_json::to_string_pretty(&state).map_err(|error| error.to_string())?;
    fs::write(path, encoded).map_err(|error| error.to_string())
}

fn project_memory_state_path() -> PathBuf {
    match std::env::current_dir() {
        Ok(path) => path.join(".forge_project_memory.json"),
        Err(_) => PathBuf::from("E:/Forge/.forge_project_memory.json"),
    }
}

fn media_studio_state_path() -> PathBuf {
    match std::env::current_dir() {
        Ok(path) => path.join(".forge_media_studio.json"),
        Err(_) => PathBuf::from("E:/Forge/.forge_media_studio.json"),
    }
}

fn load_media_studio_state(path: &Path) -> Option<PersistedMediaStudioState> {
    let contents = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(_) => return None,
    };
    let state = serde_json::from_str::<PersistedMediaStudioState>(&contents).ok()?;
    if state.schema_version != 1 {
        return None;
    }
    Some(state)
}

fn save_media_studio_state(path: &Path, state: &PersistedMediaStudioState) -> UiOperationResult {
    let encoded = serde_json::to_string_pretty(state).map_err(|error| error.to_string())?;
    fs::write(path, encoded).map_err(|error| error.to_string())
}

#[allow(clippy::too_many_arguments)]
fn collect_media_studio_state(
    media_prompt: RwSignal<String>,
    media_seed: RwSignal<String>,
    media_batch_size: RwSignal<String>,
    media_gallery: RwSignal<String>,
    media_next_asset_id: RwSignal<u64>,
    video_prompt: RwSignal<String>,
    video_seed: RwSignal<String>,
    video_batch_size: RwSignal<String>,
    video_duration_seconds: RwSignal<String>,
    video_checkpoint_state: &Rc<RefCell<HashMap<u64, VideoCheckpointState>>>,
) -> PersistedMediaStudioState {
    let mut entries = video_checkpoint_state
        .borrow()
        .values()
        .cloned()
        .collect::<Vec<_>>();
    entries.sort_unstable_by_key(|entry| entry.asset_id);
    PersistedMediaStudioState {
        schema_version: 1,
        media_prompt: media_prompt.get(),
        media_seed: media_seed.get(),
        media_batch_size: media_batch_size.get(),
        media_gallery: media_gallery.get(),
        media_next_asset_id: media_next_asset_id.get().max(1),
        video_prompt: video_prompt.get(),
        video_seed: video_seed.get(),
        video_batch_size: video_batch_size.get(),
        video_duration_seconds: video_duration_seconds.get(),
        video_checkpoint_entries: entries,
    }
}

#[allow(clippy::too_many_arguments)]
fn persist_media_state_with_notice(
    media_prompt: RwSignal<String>,
    media_seed: RwSignal<String>,
    media_batch_size: RwSignal<String>,
    media_gallery: RwSignal<String>,
    media_next_asset_id: RwSignal<u64>,
    video_prompt: RwSignal<String>,
    video_seed: RwSignal<String>,
    video_batch_size: RwSignal<String>,
    video_duration_seconds: RwSignal<String>,
    video_checkpoint_state: &Rc<RefCell<HashMap<u64, VideoCheckpointState>>>,
    status_signal: RwSignal<String>,
) {
    let state = collect_media_studio_state(
        media_prompt,
        media_seed,
        media_batch_size,
        media_gallery,
        media_next_asset_id,
        video_prompt,
        video_seed,
        video_batch_size,
        video_duration_seconds,
        video_checkpoint_state,
    );
    if let Err(error) = save_media_studio_state(&media_studio_state_path(), &state) {
        let current = status_signal.get();
        status_signal.set(format!(
            "{} | persist warning: {}",
            clip_text(&current, 120),
            clip_text(&error, 120),
        ));
    }
}

fn load_project_memory_state(path: &Path) -> Option<ProjectMemoryStore> {
    let contents = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(_) => return None,
    };
    let state = serde_json::from_str::<PersistedProjectMemoryState>(&contents).ok()?;
    if state.schema_version != 1 {
        return None;
    }
    Some(ProjectMemoryStore::restore(state.entries))
}

fn save_project_memory_state(path: &Path, store: &ProjectMemoryStore) -> UiOperationResult {
    let state = PersistedProjectMemoryState {
        schema_version: 1,
        entries: store.snapshot(),
    };
    let encoded = serde_json::to_string_pretty(&state).map_err(|error| error.to_string())?;
    fs::write(path, encoded).map_err(|error| error.to_string())
}

fn feature_policy_settings_path() -> PathBuf {
    match std::env::current_dir() {
        Ok(path) => path.join(".forge_feature_policy.json"),
        Err(_) => PathBuf::from("E:/Forge/.forge_feature_policy.json"),
    }
}

fn load_feature_policy_settings(path: &Path) -> Option<PersistedFeatureSettings> {
    let contents = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(_) => return None,
    };
    serde_json::from_str::<PersistedFeatureSettings>(&contents).ok()
}

fn save_feature_policy_settings(
    path: &Path,
    settings: &PersistedFeatureSettings,
) -> UiOperationResult {
    let encoded = serde_json::to_string_pretty(settings).map_err(|error| error.to_string())?;
    fs::write(path, encoded).map_err(|error| error.to_string())
}

fn collect_persisted_feature_settings(
    registry: &FeaturePolicyRegistry,
    fallback_visibility: bool,
) -> PersistedFeatureSettings {
    let features = registry
        .statuses()
        .iter()
        .map(|status| PersistedFeaturePreference {
            id: status.id,
            requested_state: status.requested_state,
        })
        .collect::<Vec<PersistedFeaturePreference>>();
    PersistedFeatureSettings {
        fallback_visibility,
        features,
    }
}

fn evaluate_registry_with_default_checks(registry: &mut FeaturePolicyRegistry) {
    let mut checks_by_feature = HashMap::new();
    for id in registry.feature_ids() {
        if let Some(declaration) = registry.declaration(id) {
            checks_by_feature.insert(id, default_activation_checks(&declaration));
        }
    }
    let _ = registry.evaluate_all(&checks_by_feature);
}

fn apply_topology_mode(
    registry: &mut FeaturePolicyRegistry,
    target_state: FeatureState,
) -> UiOperationResult {
    registry
        .set_requested_state(FeatureId::HwlocTopology, target_state)
        .map_err(|error| format!("failed to set hwloc topology state: {error:?}"))?;
    registry
        .set_requested_state(FeatureId::NumactlPlacement, target_state)
        .map_err(|error| format!("failed to set numactl placement state: {error:?}"))?;
    evaluate_registry_with_default_checks(registry);
    Ok(())
}

fn apply_openvino_mode(
    registry: &mut FeaturePolicyRegistry,
    target_state: FeatureState,
) -> UiOperationResult {
    registry
        .set_requested_state(FeatureId::OpenVinoBackend, target_state)
        .map_err(|error| format!("failed to set openvino backend state: {error:?}"))?;
    evaluate_registry_with_default_checks(registry);
    Ok(())
}

fn apply_linux_memory_tuning_mode(
    registry: &mut FeaturePolicyRegistry,
    target_state: FeatureState,
) -> UiOperationResult {
    registry
        .set_requested_state(FeatureId::TransparentHugePages, target_state)
        .map_err(|error| format!("failed to set transparent huge pages state: {error:?}"))?;
    registry
        .set_requested_state(FeatureId::Zswap, target_state)
        .map_err(|error| format!("failed to set zswap state: {error:?}"))?;
    registry
        .set_requested_state(FeatureId::Zram, target_state)
        .map_err(|error| format!("failed to set zram state: {error:?}"))?;
    evaluate_registry_with_default_checks(registry);
    Ok(())
}

fn apply_dense_math_mode(
    registry: &mut FeaturePolicyRegistry,
    target_state: FeatureState,
) -> UiOperationResult {
    registry
        .set_requested_state(FeatureId::OpenBlasBackend, target_state)
        .map_err(|error| format!("failed to set openblas backend state: {error:?}"))?;
    registry
        .set_requested_state(FeatureId::BlisBackend, target_state)
        .map_err(|error| format!("failed to set blis backend state: {error:?}"))?;
    evaluate_registry_with_default_checks(registry);
    Ok(())
}

fn apply_allocator_mode(
    registry: &mut FeaturePolicyRegistry,
    target_state: FeatureState,
) -> UiOperationResult {
    registry
        .set_requested_state(FeatureId::MimallocAllocator, target_state)
        .map_err(|error| format!("failed to set mimalloc allocator state: {error:?}"))?;
    registry
        .set_requested_state(FeatureId::JemallocAllocator, target_state)
        .map_err(|error| format!("failed to set jemalloc allocator state: {error:?}"))?;
    registry
        .set_requested_state(FeatureId::SnmallocAllocator, target_state)
        .map_err(|error| format!("failed to set snmalloc allocator state: {error:?}"))?;
    evaluate_registry_with_default_checks(registry);
    Ok(())
}

fn apply_profiling_mode(
    registry: &mut FeaturePolicyRegistry,
    target_state: FeatureState,
) -> UiOperationResult {
    registry
        .set_requested_state(FeatureId::PerfProfiler, target_state)
        .map_err(|error| format!("failed to set perf profiler state: {error:?}"))?;
    registry
        .set_requested_state(FeatureId::TracyProfiler, target_state)
        .map_err(|error| format!("failed to set tracy profiler state: {error:?}"))?;
    evaluate_registry_with_default_checks(registry);
    Ok(())
}

fn apply_release_optimization_mode(
    registry: &mut FeaturePolicyRegistry,
    target_state: FeatureState,
) -> UiOperationResult {
    registry
        .set_requested_state(FeatureId::AutoFdoOptimizer, target_state)
        .map_err(|error| format!("failed to set autofdo optimizer state: {error:?}"))?;
    registry
        .set_requested_state(FeatureId::BoltOptimizer, target_state)
        .map_err(|error| format!("failed to set bolt optimizer state: {error:?}"))?;
    evaluate_registry_with_default_checks(registry);
    Ok(())
}

fn apply_ispc_mode(
    registry: &mut FeaturePolicyRegistry,
    target_state: FeatureState,
) -> UiOperationResult {
    registry
        .set_requested_state(FeatureId::IspcKernels, target_state)
        .map_err(|error| format!("failed to set ispc kernels state: {error:?}"))?;
    evaluate_registry_with_default_checks(registry);
    Ok(())
}

fn apply_highway_mode(
    registry: &mut FeaturePolicyRegistry,
    target_state: FeatureState,
) -> UiOperationResult {
    registry
        .set_requested_state(FeatureId::HighwaySimd, target_state)
        .map_err(|error| format!("failed to set highway simd state: {error:?}"))?;
    evaluate_registry_with_default_checks(registry);
    Ok(())
}

fn apply_rust_arch_simd_mode(
    registry: &mut FeaturePolicyRegistry,
    target_state: FeatureState,
) -> UiOperationResult {
    registry
        .set_requested_state(FeatureId::RustArchSimd, target_state)
        .map_err(|error| format!("failed to set rust arch simd state: {error:?}"))?;
    evaluate_registry_with_default_checks(registry);
    Ok(())
}

fn apply_rayon_mode(
    registry: &mut FeaturePolicyRegistry,
    target_state: FeatureState,
) -> UiOperationResult {
    registry
        .set_requested_state(FeatureId::RayonParallelism, target_state)
        .map_err(|error| format!("failed to set rayon parallelism state: {error:?}"))?;
    evaluate_registry_with_default_checks(registry);
    Ok(())
}

fn apply_io_uring_mode(
    registry: &mut FeaturePolicyRegistry,
    target_state: FeatureState,
) -> UiOperationResult {
    registry
        .set_requested_state(FeatureId::IoUring, target_state)
        .map_err(|error| format!("failed to set io_uring state: {error:?}"))?;
    evaluate_registry_with_default_checks(registry);
    Ok(())
}

fn apply_lmdb_metadata_mode(
    registry: &mut FeaturePolicyRegistry,
    target_state: FeatureState,
) -> UiOperationResult {
    registry
        .set_requested_state(FeatureId::LmdbMetadata, target_state)
        .map_err(|error| format!("failed to set lmdb metadata state: {error:?}"))?;
    evaluate_registry_with_default_checks(registry);
    Ok(())
}

fn apply_confidential_relay_feature_mode(
    registry: &mut FeaturePolicyRegistry,
    target_state: FeatureState,
) -> UiOperationResult {
    registry
        .set_requested_state(FeatureId::ConfidentialRelay, target_state)
        .map_err(|error| format!("failed to set confidential relay state: {error:?}"))?;
    evaluate_registry_with_default_checks(registry);
    Ok(())
}

fn format_topology_placement_status(registry: &FeaturePolicyRegistry) -> String {
    let hwloc = registry.status(FeatureId::HwlocTopology);
    let numactl = registry.status(FeatureId::NumactlPlacement);
    let (Some(hwloc), Some(numactl)) = (hwloc, numactl) else {
        return "topology status unavailable".to_string();
    };

    let scheduler_mode = match hwloc.effective_state {
        FeatureState::Enabled => "topology-aware",
        FeatureState::Fallback => "fallback-baseline",
        _ => "baseline",
    };
    let launch_mode = match numactl.effective_state {
        FeatureState::Enabled => "numactl-affinity",
        FeatureState::Fallback => "fallback-os-default",
        _ => "os-default",
    };

    format!(
        "scheduler={} launch={} | hwloc req={:?} eff={:?} | numactl req={:?} eff={:?}",
        scheduler_mode,
        launch_mode,
        hwloc.requested_state,
        hwloc.effective_state,
        numactl.requested_state,
        numactl.effective_state
    )
}

fn format_openvino_status(registry: &FeaturePolicyRegistry) -> String {
    format_gate_feature_status(
        registry,
        FeatureId::OpenVinoBackend,
        "openvino_backend",
        OPENVINO_BENCHMARK_OK_ENV,
    )
}

fn format_linux_memory_tuning_status(registry: &FeaturePolicyRegistry) -> String {
    let thp = format_gate_feature_status(
        registry,
        FeatureId::TransparentHugePages,
        "transparent_huge_pages",
        THP_BENCHMARK_OK_ENV,
    );
    let zswap =
        format_gate_feature_status(registry, FeatureId::Zswap, "zswap", ZSWAP_BENCHMARK_OK_ENV);
    let zram = format_gate_feature_status(registry, FeatureId::Zram, "zram", ZRAM_BENCHMARK_OK_ENV);
    format!("{thp} || {zswap} || {zram}")
}

fn format_dense_math_status(registry: &FeaturePolicyRegistry) -> String {
    let openblas = format_gate_feature_status(
        registry,
        FeatureId::OpenBlasBackend,
        "openblas_backend",
        OPENBLAS_BENCHMARK_OK_ENV,
    );
    let blis = format_gate_feature_status(
        registry,
        FeatureId::BlisBackend,
        "blis_backend",
        BLIS_BENCHMARK_OK_ENV,
    );
    format!("{openblas} || {blis}")
}

fn format_allocator_mode_status(registry: &FeaturePolicyRegistry) -> String {
    let mimalloc = format_gate_feature_status(
        registry,
        FeatureId::MimallocAllocator,
        "mimalloc_allocator",
        MIMALLOC_BENCHMARK_OK_ENV,
    );
    let jemalloc = format_gate_feature_status(
        registry,
        FeatureId::JemallocAllocator,
        "jemalloc_allocator",
        JEMALLOC_BENCHMARK_OK_ENV,
    );
    let snmalloc = format_gate_feature_status(
        registry,
        FeatureId::SnmallocAllocator,
        "snmalloc_allocator",
        SNMALLOC_BENCHMARK_OK_ENV,
    );
    format!("{mimalloc} || {jemalloc} || {snmalloc}")
}

fn format_profiling_stack_status(registry: &FeaturePolicyRegistry) -> String {
    let perf = format_gate_feature_status(
        registry,
        FeatureId::PerfProfiler,
        "perf_profiler",
        PERF_BENCHMARK_OK_ENV,
    );
    let tracy = format_gate_feature_status(
        registry,
        FeatureId::TracyProfiler,
        "tracy_profiler",
        TRACY_BENCHMARK_OK_ENV,
    );
    format!("{perf} || {tracy}")
}

fn format_release_optimization_status(registry: &FeaturePolicyRegistry) -> String {
    let autofdo = format_gate_feature_status(
        registry,
        FeatureId::AutoFdoOptimizer,
        "autofdo_optimizer",
        AUTOFDO_BENCHMARK_OK_ENV,
    );
    let bolt = format_gate_feature_status(
        registry,
        FeatureId::BoltOptimizer,
        "bolt_optimizer",
        BOLT_BENCHMARK_OK_ENV,
    );
    format!("{autofdo} || {bolt}")
}

fn format_ispc_status(registry: &FeaturePolicyRegistry) -> String {
    format_gate_feature_status(
        registry,
        FeatureId::IspcKernels,
        "ispc_kernels",
        ISPC_BENCHMARK_OK_ENV,
    )
}

fn format_highway_status(registry: &FeaturePolicyRegistry) -> String {
    format_gate_feature_status(
        registry,
        FeatureId::HighwaySimd,
        "highway_simd",
        HIGHWAY_BENCHMARK_OK_ENV,
    )
}

fn format_rust_arch_simd_status(registry: &FeaturePolicyRegistry) -> String {
    format_gate_feature_status(
        registry,
        FeatureId::RustArchSimd,
        "rust_arch_simd",
        RUST_ARCH_SIMD_BENCHMARK_OK_ENV,
    )
}

fn format_rayon_parallelism_status(registry: &FeaturePolicyRegistry) -> String {
    format_gate_feature_status(
        registry,
        FeatureId::RayonParallelism,
        "rayon_parallelism",
        RAYON_BENCHMARK_OK_ENV,
    )
}

fn format_io_uring_status(registry: &FeaturePolicyRegistry) -> String {
    format_gate_feature_status(
        registry,
        FeatureId::IoUring,
        "io_uring",
        IO_URING_BENCHMARK_OK_ENV,
    )
}

fn format_lmdb_metadata_status(registry: &FeaturePolicyRegistry) -> String {
    format_gate_feature_status(
        registry,
        FeatureId::LmdbMetadata,
        "lmdb_metadata",
        LMDB_BENCHMARK_OK_ENV,
    )
}

fn format_confidential_relay_feature_status(registry: &FeaturePolicyRegistry) -> String {
    format_gate_feature_status(
        registry,
        FeatureId::ConfidentialRelay,
        "confidential_relay",
        CONFIDENTIAL_RELAY_BENCHMARK_OK_ENV,
    )
}

fn format_gate_feature_status(
    registry: &FeaturePolicyRegistry,
    feature_id: FeatureId,
    label: &str,
    benchmark_flag_env_key: &str,
) -> String {
    let Some(status) = registry.status(feature_id) else {
        return format!("{label}(unavailable)");
    };
    format!(
        "{label}(req={:?},eff={:?},present={},platform_ok={},gate_env={}) reason={}",
        status.requested_state,
        status.effective_state,
        status.present_on_system,
        status.supports_current_platform,
        benchmark_flag_state(benchmark_flag_env_key),
        clip_text(&status.reason, 84),
    )
}

fn benchmark_flag_state(env_key: &str) -> String {
    if let Some(value) = benchmark_flag_override_value(env_key) {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return "override(empty)".to_string();
        }
        return format!("override({})", clip_text(trimmed, 16));
    }
    match std::env::var(env_key) {
        Ok(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                "set(empty)".to_string()
            } else {
                format!("set({})", clip_text(trimmed, 16))
            }
        }
        Err(_) => "unset".to_string(),
    }
}

fn benchmark_flag_enabled(env_key: &str) -> bool {
    benchmark_flag_value(env_key)
        .map(|value| value.trim() == "1")
        .unwrap_or(false)
}

fn benchmark_flag_keys() -> [&'static str; 14] {
    [
        OPENVINO_BENCHMARK_OK_ENV,
        THP_BENCHMARK_OK_ENV,
        ZSWAP_BENCHMARK_OK_ENV,
        ZRAM_BENCHMARK_OK_ENV,
        OPENBLAS_BENCHMARK_OK_ENV,
        BLIS_BENCHMARK_OK_ENV,
        PERF_BENCHMARK_OK_ENV,
        TRACY_BENCHMARK_OK_ENV,
        AUTOFDO_BENCHMARK_OK_ENV,
        BOLT_BENCHMARK_OK_ENV,
        ISPC_BENCHMARK_OK_ENV,
        HIGHWAY_BENCHMARK_OK_ENV,
        RUST_ARCH_SIMD_BENCHMARK_OK_ENV,
        RAYON_BENCHMARK_OK_ENV,
    ]
}

fn benchmark_flag_overrides_store() -> &'static Mutex<HashMap<String, String>> {
    static STORE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn benchmark_flag_override_value(env_key: &str) -> Option<String> {
    let store = benchmark_flag_overrides_store();
    let guard = store.lock().ok()?;
    guard.get(env_key).cloned()
}

fn benchmark_flag_value(env_key: &str) -> Option<String> {
    if let Some(value) = benchmark_flag_override_value(env_key) {
        return Some(value);
    }
    std::env::var(env_key).ok()
}

fn benchmark_flags_snapshot_line() -> String {
    format!(
        "- benchmark_flags | {}={} {}={} {}={} {}={} {}={} {}={} {}={} {}={} {}={} {}={} {}={} {}={} {}={} {}={} {}={} {}={} {}={} {}={} {}={} {}={}",
        OPENVINO_BENCHMARK_OK_ENV,
        benchmark_flag_state(OPENVINO_BENCHMARK_OK_ENV),
        THP_BENCHMARK_OK_ENV,
        benchmark_flag_state(THP_BENCHMARK_OK_ENV),
        ZSWAP_BENCHMARK_OK_ENV,
        benchmark_flag_state(ZSWAP_BENCHMARK_OK_ENV),
        ZRAM_BENCHMARK_OK_ENV,
        benchmark_flag_state(ZRAM_BENCHMARK_OK_ENV),
        OPENBLAS_BENCHMARK_OK_ENV,
        benchmark_flag_state(OPENBLAS_BENCHMARK_OK_ENV),
        BLIS_BENCHMARK_OK_ENV,
        benchmark_flag_state(BLIS_BENCHMARK_OK_ENV),
        MIMALLOC_BENCHMARK_OK_ENV,
        benchmark_flag_state(MIMALLOC_BENCHMARK_OK_ENV),
        JEMALLOC_BENCHMARK_OK_ENV,
        benchmark_flag_state(JEMALLOC_BENCHMARK_OK_ENV),
        SNMALLOC_BENCHMARK_OK_ENV,
        benchmark_flag_state(SNMALLOC_BENCHMARK_OK_ENV),
        PERF_BENCHMARK_OK_ENV,
        benchmark_flag_state(PERF_BENCHMARK_OK_ENV),
        TRACY_BENCHMARK_OK_ENV,
        benchmark_flag_state(TRACY_BENCHMARK_OK_ENV),
        AUTOFDO_BENCHMARK_OK_ENV,
        benchmark_flag_state(AUTOFDO_BENCHMARK_OK_ENV),
        BOLT_BENCHMARK_OK_ENV,
        benchmark_flag_state(BOLT_BENCHMARK_OK_ENV),
        ISPC_BENCHMARK_OK_ENV,
        benchmark_flag_state(ISPC_BENCHMARK_OK_ENV),
        HIGHWAY_BENCHMARK_OK_ENV,
        benchmark_flag_state(HIGHWAY_BENCHMARK_OK_ENV),
        RUST_ARCH_SIMD_BENCHMARK_OK_ENV,
        benchmark_flag_state(RUST_ARCH_SIMD_BENCHMARK_OK_ENV),
        RAYON_BENCHMARK_OK_ENV,
        benchmark_flag_state(RAYON_BENCHMARK_OK_ENV),
        IO_URING_BENCHMARK_OK_ENV,
        benchmark_flag_state(IO_URING_BENCHMARK_OK_ENV),
        LMDB_BENCHMARK_OK_ENV,
        benchmark_flag_state(LMDB_BENCHMARK_OK_ENV),
        CONFIDENTIAL_RELAY_BENCHMARK_OK_ENV,
        benchmark_flag_state(CONFIDENTIAL_RELAY_BENCHMARK_OK_ENV),
    )
}

fn gate_artifacts_dir() -> PathBuf {
    match std::env::current_dir() {
        Ok(path) => path.join(".tmp").join("benchmarks").join("conditional"),
        Err(_) => PathBuf::from("E:/Forge/.tmp/benchmarks/conditional"),
    }
}

fn gate_run_command() -> &'static str {
    if cfg!(windows) {
        "powershell -ExecutionPolicy Bypass -File .\\scripts\\conditional_adoption_gate.ps1 -Iterations 8"
    } else {
        "pwsh -File ./scripts/conditional_adoption_gate.ps1 -Iterations 8"
    }
}

fn find_latest_gate_artifact_path(root: &Path) -> Option<PathBuf> {
    let entries = fs::read_dir(root).ok()?;
    let mut candidates = Vec::<(String, PathBuf)>::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !name.starts_with(GATE_JSON_PREFIX) || !name.ends_with(GATE_JSON_SUFFIX) {
            continue;
        }
        candidates.push((name.to_ascii_lowercase(), path));
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    candidates.into_iter().last().map(|(_, path)| path)
}

fn load_gate_artifact(path: &Path) -> Result<ConditionalGateArtifact, String> {
    let contents = fs::read_to_string(path)
        .map_err(|error| format!("failed reading {}: {error}", path.display()))?;
    serde_json::from_str::<ConditionalGateArtifact>(&contents)
        .map_err(|error| format!("failed parsing {}: {error}", path.display()))
}

fn load_latest_gate_artifact() -> Result<(PathBuf, ConditionalGateArtifact), String> {
    let root = gate_artifacts_dir();
    let Some(path) = find_latest_gate_artifact_path(&root) else {
        return Err(format!("no gate artifact found under {}", root.display()));
    };
    let artifact = load_gate_artifact(&path)?;
    Ok((path, artifact))
}

fn parse_selected_default_state(input: &str) -> Result<FeatureState, String> {
    let normalized = input.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "auto" => Ok(FeatureState::Auto),
        "disabled" => Ok(FeatureState::Disabled),
        "enabled" => Ok(FeatureState::Enabled),
        "available" => Ok(FeatureState::Available),
        _ => Err(format!("unsupported gate default state: {input}")),
    }
}

fn validate_gate_artifact_for_defaults(artifact: &ConditionalGateArtifact) -> UiOperationResult {
    if artifact.gate_passed != artifact.decision.passed {
        return Err("artifact mismatch: gate_passed and decision.passed diverge".to_string());
    }

    let openvino_state =
        parse_selected_default_state(&artifact.selected_defaults.openvino_backend)?;
    let memory_state =
        parse_selected_default_state(&artifact.selected_defaults.linux_memory_tuning_profile)?;
    let openblas_state =
        parse_selected_default_state(&artifact.selected_defaults.openblas_backend)?;
    let blis_state = parse_selected_default_state(&artifact.selected_defaults.blis_backend)?;
    let profiling_state = parse_selected_default_state(&artifact.selected_defaults.profiling_mode)?;
    let release_optimization_state =
        parse_selected_default_state(&artifact.selected_defaults.release_optimization_mode)?;
    let ispc_state = parse_selected_default_state(&artifact.selected_defaults.ispc_kernels)?;
    let highway_state = parse_selected_default_state(&artifact.selected_defaults.highway_simd)?;
    let rust_arch_simd_state =
        parse_selected_default_state(&artifact.selected_defaults.rust_arch_simd)?;
    let rayon_state = parse_selected_default_state(&artifact.selected_defaults.rayon_parallelism)?;
    if !matches!(openvino_state, FeatureState::Auto | FeatureState::Disabled) {
        return Err(format!(
            "openvino default must be Auto/Disabled, got {:?}",
            openvino_state
        ));
    }
    if !matches!(memory_state, FeatureState::Auto | FeatureState::Disabled) {
        return Err(format!(
            "linux memory default must be Auto/Disabled, got {:?}",
            memory_state
        ));
    }
    if !matches!(openblas_state, FeatureState::Auto | FeatureState::Disabled) {
        return Err(format!(
            "openblas default must be Auto/Disabled, got {:?}",
            openblas_state
        ));
    }
    if !matches!(blis_state, FeatureState::Auto | FeatureState::Disabled) {
        return Err(format!(
            "blis default must be Auto/Disabled, got {:?}",
            blis_state
        ));
    }
    if !matches!(profiling_state, FeatureState::Auto | FeatureState::Disabled) {
        return Err(format!(
            "profiling default must be Auto/Disabled, got {:?}",
            profiling_state
        ));
    }
    if !matches!(
        release_optimization_state,
        FeatureState::Auto | FeatureState::Disabled
    ) {
        return Err(format!(
            "release optimization default must be Auto/Disabled, got {:?}",
            release_optimization_state
        ));
    }
    if !matches!(ispc_state, FeatureState::Auto | FeatureState::Disabled) {
        return Err(format!(
            "ispc default must be Auto/Disabled, got {:?}",
            ispc_state
        ));
    }
    if !matches!(highway_state, FeatureState::Auto | FeatureState::Disabled) {
        return Err(format!(
            "highway default must be Auto/Disabled, got {:?}",
            highway_state
        ));
    }
    if !matches!(
        rust_arch_simd_state,
        FeatureState::Auto | FeatureState::Disabled
    ) {
        return Err(format!(
            "rust arch simd default must be Auto/Disabled, got {:?}",
            rust_arch_simd_state
        ));
    }
    if !matches!(rayon_state, FeatureState::Auto | FeatureState::Disabled) {
        return Err(format!(
            "rayon default must be Auto/Disabled, got {:?}",
            rayon_state
        ));
    }

    let required_flags = [
        OPENVINO_BENCHMARK_OK_ENV,
        THP_BENCHMARK_OK_ENV,
        ZSWAP_BENCHMARK_OK_ENV,
        ZRAM_BENCHMARK_OK_ENV,
        OPENBLAS_BENCHMARK_OK_ENV,
        BLIS_BENCHMARK_OK_ENV,
        PERF_BENCHMARK_OK_ENV,
        TRACY_BENCHMARK_OK_ENV,
        AUTOFDO_BENCHMARK_OK_ENV,
        BOLT_BENCHMARK_OK_ENV,
        ISPC_BENCHMARK_OK_ENV,
        HIGHWAY_BENCHMARK_OK_ENV,
        RUST_ARCH_SIMD_BENCHMARK_OK_ENV,
        RAYON_BENCHMARK_OK_ENV,
    ];
    for key in required_flags {
        let Some(value) = artifact.recommended_env_flags.get(key) else {
            return Err(format!("artifact missing recommended env flag {key}"));
        };
        if !matches!(*value, 0 | 1) {
            return Err(format!("artifact flag {key} must be 0 or 1, got {value}"));
        }
    }

    if !artifact.gate_passed
        && (matches!(openvino_state, FeatureState::Auto)
            || matches!(memory_state, FeatureState::Auto)
            || matches!(openblas_state, FeatureState::Auto)
            || matches!(blis_state, FeatureState::Auto)
            || matches!(profiling_state, FeatureState::Auto)
            || matches!(release_optimization_state, FeatureState::Auto)
            || matches!(ispc_state, FeatureState::Auto)
            || matches!(highway_state, FeatureState::Auto)
            || matches!(rust_arch_simd_state, FeatureState::Auto)
            || matches!(rayon_state, FeatureState::Auto))
    {
        return Err(
            "gate did not pass, so selected defaults must remain Disabled for fail-closed policy"
                .to_string(),
        );
    }

    Ok(())
}

fn evaluate_flag_parity_with_env<F>(
    artifact: &ConditionalGateArtifact,
    get_env: F,
) -> (usize, Vec<String>)
where
    F: Fn(&str) -> Option<String>,
{
    let mut matched = 0usize;
    let mut mismatches = Vec::new();
    for key in benchmark_flag_keys() {
        let expected = artifact
            .recommended_env_flags
            .get(key)
            .map(|value| value.to_string())
            .unwrap_or_else(|| "?".to_string());
        let actual = get_env(key)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "unset".to_string());
        if expected == actual {
            matched = matched.saturating_add(1);
        } else {
            mismatches.push(format!("{key}: expected={expected} actual={actual}"));
        }
    }
    (matched, mismatches)
}

fn collect_recommended_flag_pairs(
    artifact: &ConditionalGateArtifact,
) -> Result<Vec<(&'static str, String)>, String> {
    let mut pairs = Vec::new();
    for key in benchmark_flag_keys() {
        let Some(value) = artifact.recommended_env_flags.get(key) else {
            return Err(format!("artifact missing recommended env flag {key}"));
        };
        if !matches!(*value, 0 | 1) {
            return Err(format!("artifact flag {key} must be 0 or 1, got {value}"));
        }
        pairs.push((key, value.to_string()));
    }
    Ok(pairs)
}

fn apply_recommended_flags(artifact: &ConditionalGateArtifact) -> Result<usize, String> {
    let pairs = collect_recommended_flag_pairs(artifact)?;
    let store = benchmark_flag_overrides_store();
    let mut guard = store
        .lock()
        .map_err(|_| "benchmark flag override store is poisoned".to_string())?;
    for (key, value) in pairs {
        guard.insert(key.to_string(), value);
    }
    Ok(guard.len())
}

fn clear_recommended_flags() -> usize {
    let store = benchmark_flag_overrides_store();
    let Ok(mut guard) = store.lock() else {
        return 0;
    };
    for key in benchmark_flag_keys() {
        guard.remove(key);
    }
    benchmark_flag_keys().len()
}

fn format_flag_parity(artifact: &ConditionalGateArtifact) -> String {
    let total = benchmark_flag_keys().len();
    let (matched, mismatches) = evaluate_flag_parity_with_env(artifact, benchmark_flag_value);
    if mismatches.is_empty() {
        return format!("flags match artifact recommendation ({matched}/{total})");
    }
    format!(
        "flags mismatch ({matched}/{total}) | {}",
        clip_text(&mismatches.join(" ; "), 220)
    )
}

fn format_gate_readiness(registry: &FeaturePolicyRegistry) -> String {
    let Some(openvino) = registry.status(FeatureId::OpenVinoBackend) else {
        return "readiness unavailable: openvino status missing".to_string();
    };
    let Some(thp) = registry.status(FeatureId::TransparentHugePages) else {
        return "readiness unavailable: thp status missing".to_string();
    };
    let Some(zswap) = registry.status(FeatureId::Zswap) else {
        return "readiness unavailable: zswap status missing".to_string();
    };
    let Some(zram) = registry.status(FeatureId::Zram) else {
        return "readiness unavailable: zram status missing".to_string();
    };
    let Some(openblas) = registry.status(FeatureId::OpenBlasBackend) else {
        return "readiness unavailable: openblas status missing".to_string();
    };
    let Some(blis) = registry.status(FeatureId::BlisBackend) else {
        return "readiness unavailable: blis status missing".to_string();
    };
    let Some(perf) = registry.status(FeatureId::PerfProfiler) else {
        return "readiness unavailable: perf status missing".to_string();
    };
    let Some(tracy) = registry.status(FeatureId::TracyProfiler) else {
        return "readiness unavailable: tracy status missing".to_string();
    };
    let Some(autofdo) = registry.status(FeatureId::AutoFdoOptimizer) else {
        return "readiness unavailable: autofdo status missing".to_string();
    };
    let Some(bolt) = registry.status(FeatureId::BoltOptimizer) else {
        return "readiness unavailable: bolt status missing".to_string();
    };
    let Some(ispc) = registry.status(FeatureId::IspcKernels) else {
        return "readiness unavailable: ispc status missing".to_string();
    };
    let Some(highway) = registry.status(FeatureId::HighwaySimd) else {
        return "readiness unavailable: highway status missing".to_string();
    };
    let Some(rust_arch_simd) = registry.status(FeatureId::RustArchSimd) else {
        return "readiness unavailable: rust arch simd status missing".to_string();
    };
    let Some(rayon) = registry.status(FeatureId::RayonParallelism) else {
        return "readiness unavailable: rayon status missing".to_string();
    };

    let openvino_ready = openvino.supports_current_platform
        && openvino.present_on_system
        && benchmark_flag_enabled(OPENVINO_BENCHMARK_OK_ENV);
    let thp_ready = thp.supports_current_platform
        && thp.present_on_system
        && benchmark_flag_enabled(THP_BENCHMARK_OK_ENV);
    let zswap_ready = zswap.supports_current_platform
        && zswap.present_on_system
        && benchmark_flag_enabled(ZSWAP_BENCHMARK_OK_ENV);
    let zram_ready = zram.supports_current_platform
        && zram.present_on_system
        && benchmark_flag_enabled(ZRAM_BENCHMARK_OK_ENV);
    let memory_ready = thp_ready && zswap_ready && zram_ready;
    let openblas_ready = openblas.supports_current_platform
        && openblas.present_on_system
        && benchmark_flag_enabled(OPENBLAS_BENCHMARK_OK_ENV);
    let blis_ready = blis.supports_current_platform
        && blis.present_on_system
        && benchmark_flag_enabled(BLIS_BENCHMARK_OK_ENV);
    let dense_math_ready = openblas_ready || blis_ready;
    let perf_ready = perf.supports_current_platform
        && perf.present_on_system
        && benchmark_flag_enabled(PERF_BENCHMARK_OK_ENV);
    let tracy_ready = tracy.supports_current_platform
        && tracy.present_on_system
        && benchmark_flag_enabled(TRACY_BENCHMARK_OK_ENV);
    let profiling_ready = perf_ready && tracy_ready;
    let autofdo_ready = autofdo.supports_current_platform
        && autofdo.present_on_system
        && benchmark_flag_enabled(AUTOFDO_BENCHMARK_OK_ENV);
    let bolt_ready = bolt.supports_current_platform
        && bolt.present_on_system
        && benchmark_flag_enabled(BOLT_BENCHMARK_OK_ENV);
    let release_ready = autofdo_ready && bolt_ready;
    let ispc_ready = ispc.supports_current_platform
        && ispc.present_on_system
        && benchmark_flag_enabled(ISPC_BENCHMARK_OK_ENV);
    let highway_ready = highway.supports_current_platform
        && highway.present_on_system
        && benchmark_flag_enabled(HIGHWAY_BENCHMARK_OK_ENV);
    let rust_arch_simd_ready = rust_arch_simd.supports_current_platform
        && rust_arch_simd.present_on_system
        && benchmark_flag_enabled(RUST_ARCH_SIMD_BENCHMARK_OK_ENV);
    let rayon_ready = rayon.supports_current_platform
        && rayon.present_on_system
        && benchmark_flag_enabled(RAYON_BENCHMARK_OK_ENV);

    format!(
        "openvino={} (platform_ok={},present={},flag={}) | memory_profile={} (thp={},zswap={},zram={}) | dense_math={} (openblas={},blis={}) | profiling={} (perf={},tracy={}) | release_opt={} (autofdo={},bolt={}) | ispc={} | simd={} (highway={},rust_arch={}) | rayon={}",
        if openvino_ready { "ready" } else { "blocked" },
        openvino.supports_current_platform,
        openvino.present_on_system,
        benchmark_flag_state(OPENVINO_BENCHMARK_OK_ENV),
        if memory_ready { "ready" } else { "blocked" },
        if thp_ready { "ready" } else { "blocked" },
        if zswap_ready { "ready" } else { "blocked" },
        if zram_ready { "ready" } else { "blocked" },
        if dense_math_ready { "ready" } else { "blocked" },
        if openblas_ready { "ready" } else { "blocked" },
        if blis_ready { "ready" } else { "blocked" },
        if profiling_ready { "ready" } else { "blocked" },
        if perf_ready { "ready" } else { "blocked" },
        if tracy_ready { "ready" } else { "blocked" },
        if release_ready { "ready" } else { "blocked" },
        if autofdo_ready { "ready" } else { "blocked" },
        if bolt_ready { "ready" } else { "blocked" },
        if ispc_ready { "ready" } else { "blocked" },
        if highway_ready && rust_arch_simd_ready {
            "ready"
        } else {
            "blocked"
        },
        if highway_ready { "ready" } else { "blocked" },
        if rust_arch_simd_ready {
            "ready"
        } else {
            "blocked"
        },
        if rayon_ready { "ready" } else { "blocked" },
    )
}

fn recommended_env_flag(artifact: &ConditionalGateArtifact, key: &str) -> String {
    artifact
        .recommended_env_flags
        .get(key)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "?".to_string())
}

fn format_gate_artifact_status(path: &Path, artifact: &ConditionalGateArtifact) -> String {
    let primary_reason = artifact
        .decision
        .reasons
        .first()
        .map(|value| clip_text(value, 96))
        .unwrap_or_else(|| "no decision reasons provided".to_string());
    format!(
        "loaded={} generated={} gate_passed={} decision_passed={} defaults(openvino={},memory={},openblas={},blis={},profiling={},release_opt={},ispc={},highway={},rust_arch_simd={},rayon={}) flags({}={}, {}={}, {}={}, {}={}, {}={}, {}={}, {}={}, {}={}, {}={}, {}={}, {}={}, {}={}, {}={}, {}={}) reason={}",
        clip_text(&path.display().to_string(), 72),
        clip_text(&artifact.generated_at_utc, 40),
        artifact.gate_passed,
        artifact.decision.passed,
        clip_text(&artifact.selected_defaults.openvino_backend, 20),
        clip_text(&artifact.selected_defaults.linux_memory_tuning_profile, 20),
        clip_text(&artifact.selected_defaults.openblas_backend, 20),
        clip_text(&artifact.selected_defaults.blis_backend, 20),
        clip_text(&artifact.selected_defaults.profiling_mode, 20),
        clip_text(&artifact.selected_defaults.release_optimization_mode, 20),
        clip_text(&artifact.selected_defaults.ispc_kernels, 20),
        clip_text(&artifact.selected_defaults.highway_simd, 20),
        clip_text(&artifact.selected_defaults.rust_arch_simd, 20),
        clip_text(&artifact.selected_defaults.rayon_parallelism, 20),
        OPENVINO_BENCHMARK_OK_ENV,
        recommended_env_flag(artifact, OPENVINO_BENCHMARK_OK_ENV),
        THP_BENCHMARK_OK_ENV,
        recommended_env_flag(artifact, THP_BENCHMARK_OK_ENV),
        ZSWAP_BENCHMARK_OK_ENV,
        recommended_env_flag(artifact, ZSWAP_BENCHMARK_OK_ENV),
        ZRAM_BENCHMARK_OK_ENV,
        recommended_env_flag(artifact, ZRAM_BENCHMARK_OK_ENV),
        OPENBLAS_BENCHMARK_OK_ENV,
        recommended_env_flag(artifact, OPENBLAS_BENCHMARK_OK_ENV),
        BLIS_BENCHMARK_OK_ENV,
        recommended_env_flag(artifact, BLIS_BENCHMARK_OK_ENV),
        PERF_BENCHMARK_OK_ENV,
        recommended_env_flag(artifact, PERF_BENCHMARK_OK_ENV),
        TRACY_BENCHMARK_OK_ENV,
        recommended_env_flag(artifact, TRACY_BENCHMARK_OK_ENV),
        AUTOFDO_BENCHMARK_OK_ENV,
        recommended_env_flag(artifact, AUTOFDO_BENCHMARK_OK_ENV),
        BOLT_BENCHMARK_OK_ENV,
        recommended_env_flag(artifact, BOLT_BENCHMARK_OK_ENV),
        ISPC_BENCHMARK_OK_ENV,
        recommended_env_flag(artifact, ISPC_BENCHMARK_OK_ENV),
        HIGHWAY_BENCHMARK_OK_ENV,
        recommended_env_flag(artifact, HIGHWAY_BENCHMARK_OK_ENV),
        RUST_ARCH_SIMD_BENCHMARK_OK_ENV,
        recommended_env_flag(artifact, RUST_ARCH_SIMD_BENCHMARK_OK_ENV),
        RAYON_BENCHMARK_OK_ENV,
        recommended_env_flag(artifact, RAYON_BENCHMARK_OK_ENV),
        primary_reason,
    )
}

fn format_gate_artifact_status_with_validation(
    path: &Path,
    artifact: &ConditionalGateArtifact,
) -> String {
    let status = format_gate_artifact_status(path, artifact);
    match validate_gate_artifact_for_defaults(artifact) {
        Ok(()) => format!("{status} | defaults_contract=ok"),
        Err(error) => format!(
            "{status} | defaults_contract=invalid ({})",
            clip_text(&error, 96)
        ),
    }
}

fn format_gate_env_commands(artifact: &ConditionalGateArtifact) -> String {
    let windows = benchmark_flag_keys()
        .iter()
        .map(|key| format!("set {key}={}", recommended_env_flag(artifact, key)))
        .collect::<Vec<String>>()
        .join(" ; ");
    let posix = benchmark_flag_keys()
        .iter()
        .map(|key| format!("export {key}={}", recommended_env_flag(artifact, key)))
        .collect::<Vec<String>>()
        .join(" ; ");
    format!("windows: {windows} | posix: {posix}")
}

fn default_activation_checks(
    declaration: &urm::feature_policy::FeatureDeclaration,
) -> ActivationChecks {
    default_activation_checks_for_declaration_with_env(declaration, benchmark_flag_value)
}

fn format_feature_policy_snapshot(registry: &FeaturePolicyRegistry, show_fallback: bool) -> String {
    let mut lines = vec![String::from(
        "Feature policy overview (manual enable/disable/auto + fallback visibility):",
    )];
    for id in registry.feature_ids() {
        let Some(status) = registry.status(id) else {
            continue;
        };
        if !show_fallback && matches!(status.effective_state, FeatureState::Fallback) {
            continue;
        }
        let declaration = registry.declaration(id);
        let benefit = declaration
            .as_ref()
            .map(|value| value.expected_benefit.as_str())
            .unwrap_or("n/a");
        let fallback_path = declaration
            .as_ref()
            .map(|value| value.fallback_path.as_str())
            .unwrap_or("n/a");
        let platform_support = if status.supports_current_platform {
            "platform-ok"
        } else {
            "platform-no"
        };
        lines.push(format!(
            "- {} | requested={:?} effective={:?} active={} {} present={} | why={} | doing={} | fallback={}",
            feature_id_key(id),
            status.requested_state,
            status.effective_state,
            matches!(status.effective_state, FeatureState::Enabled),
            platform_support,
            status.present_on_system,
            clip_text(&status.reason, 90),
            clip_text(benefit, 80),
            clip_text(fallback_path, 80),
        ));
    }
    lines.push(benchmark_flags_snapshot_line());
    lines.push(format_lmdb_metadata_health_line(registry));
    lines.push(String::from(
        "Use feature keys like: hwloc_topology, openvino_backend, transparent_huge_pages, zswap, zram, openblas_backend, blis_backend, perf_profiler, tracy_profiler, autofdo_optimizer, bolt_optimizer, ispc_kernels, highway_simd, rust_arch_simd, io_uring, lmdb_metadata, confidential_relay",
    ));
    lines.join("\n")
}

fn format_lmdb_metadata_health_line(registry: &FeaturePolicyRegistry) -> String {
    let Some(status) = registry.status(FeatureId::LmdbMetadata) else {
        return String::from("- lmdb_metadata_health | unavailable: feature status missing");
    };
    if !matches!(status.effective_state, FeatureState::Enabled) {
        return format!(
            "- lmdb_metadata_health | skipped: effective={:?} | {}",
            status.effective_state,
            clip_text(&status.reason, 80),
        );
    }

    let root = lmdb_health_probe_root();
    let probe = (|| -> UiOperationResult {
        let store = open_lmdb_metadata_store(&root, false)
            .map_err(|error| format!("open failed: {error}"))?;
        store
            .put_metadata("health:forge_probe", b"ok")
            .map_err(|error| format!("write failed: {error}"))?;
        let value = store
            .get_metadata("health:forge_probe")
            .map_err(|error| format!("read failed: {error}"))?;
        if value.as_deref() != Some(b"ok") {
            return Err("readback mismatch".to_string());
        }
        let _ = store
            .delete_metadata("health:forge_probe")
            .map_err(|error| format!("delete failed: {error}"))?;
        Ok(())
    })();
    let _ = fs::remove_dir_all(&root);

    match probe {
        Ok(()) => String::from("- lmdb_metadata_health | healthy: read/write/delete probe passed"),
        Err(error) => format!(
            "- lmdb_metadata_health | degraded: {}",
            clip_text(&error, 90)
        ),
    }
}

fn lmdb_health_probe_root() -> PathBuf {
    let mut root = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    root.push(format!("forge_ui_lmdb_health_probe_{nanos}"));
    root
}

fn feature_id_key(id: FeatureId) -> &'static str {
    match id {
        FeatureId::HwlocTopology => "hwloc_topology",
        FeatureId::NumactlPlacement => "numactl_placement",
        FeatureId::MimallocAllocator => "mimalloc_allocator",
        FeatureId::JemallocAllocator => "jemalloc_allocator",
        FeatureId::SnmallocAllocator => "snmalloc_allocator",
        FeatureId::VulkanMemoryAllocator => "vulkan_memory_allocator",
        FeatureId::IoUring => "io_uring",
        FeatureId::LmdbMetadata => "lmdb_metadata",
        FeatureId::OpenVinoBackend => "openvino_backend",
        FeatureId::TransparentHugePages => "transparent_huge_pages",
        FeatureId::Zswap => "zswap",
        FeatureId::Zram => "zram",
        FeatureId::OpenBlasBackend => "openblas_backend",
        FeatureId::BlisBackend => "blis_backend",
        FeatureId::PerfProfiler => "perf_profiler",
        FeatureId::TracyProfiler => "tracy_profiler",
        FeatureId::AutoFdoOptimizer => "autofdo_optimizer",
        FeatureId::BoltOptimizer => "bolt_optimizer",
        FeatureId::IspcKernels => "ispc_kernels",
        FeatureId::HighwaySimd => "highway_simd",
        FeatureId::RustArchSimd => "rust_arch_simd",
        FeatureId::RayonParallelism => "rayon_parallelism",
        FeatureId::ConfidentialRelay => "confidential_relay",
    }
}

fn parse_feature_id_key(input: &str) -> Option<FeatureId> {
    let normalized = input.trim().to_lowercase().replace('-', "_");
    match normalized.as_str() {
        "hwloc_topology" => Some(FeatureId::HwlocTopology),
        "numactl_placement" => Some(FeatureId::NumactlPlacement),
        "mimalloc_allocator" => Some(FeatureId::MimallocAllocator),
        "jemalloc_allocator" => Some(FeatureId::JemallocAllocator),
        "snmalloc_allocator" => Some(FeatureId::SnmallocAllocator),
        "vulkan_memory_allocator" => Some(FeatureId::VulkanMemoryAllocator),
        "io_uring" => Some(FeatureId::IoUring),
        "lmdb_metadata" => Some(FeatureId::LmdbMetadata),
        "openvino_backend" => Some(FeatureId::OpenVinoBackend),
        "transparent_huge_pages" => Some(FeatureId::TransparentHugePages),
        "zswap" => Some(FeatureId::Zswap),
        "zram" => Some(FeatureId::Zram),
        "openblas_backend" => Some(FeatureId::OpenBlasBackend),
        "blis_backend" => Some(FeatureId::BlisBackend),
        "perf_profiler" => Some(FeatureId::PerfProfiler),
        "tracy_profiler" => Some(FeatureId::TracyProfiler),
        "autofdo_optimizer" => Some(FeatureId::AutoFdoOptimizer),
        "bolt_optimizer" => Some(FeatureId::BoltOptimizer),
        "ispc_kernels" => Some(FeatureId::IspcKernels),
        "highway_simd" => Some(FeatureId::HighwaySimd),
        "rust_arch_simd" => Some(FeatureId::RustArchSimd),
        "rayon_parallelism" => Some(FeatureId::RayonParallelism),
        "confidential_relay" => Some(FeatureId::ConfidentialRelay),
        _ => None,
    }
}
