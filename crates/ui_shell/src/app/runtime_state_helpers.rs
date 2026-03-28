fn sync_job_metrics(
    queue: &JobQueue,
    queued_jobs: RwSignal<u32>,
    running_jobs: RwSignal<u32>,
    completed_jobs: RwSignal<u32>,
    failed_jobs: RwSignal<u32>,
    cancelled_jobs: RwSignal<u32>,
) {
    let snapshot = queue.snapshot();
    queued_jobs.set(snapshot.queued as u32);
    running_jobs.set(snapshot.running as u32);
    completed_jobs.set(snapshot.completed as u32);
    failed_jobs.set(snapshot.failed as u32);
    cancelled_jobs.set(snapshot.cancelled as u32);
}

#[allow(clippy::too_many_arguments)]
fn queue_start_tracked_job(
    queue: &Rc<RefCell<JobQueue>>,
    name: String,
    kind: JobKind,
    priority: JobPriority,
    queued_jobs: RwSignal<u32>,
    running_jobs: RwSignal<u32>,
    completed_jobs: RwSignal<u32>,
    failed_jobs: RwSignal<u32>,
    cancelled_jobs: RwSignal<u32>,
) -> JobId {
    let mut queue_mut = queue.borrow_mut();
    let enqueued_id = queue_mut.enqueue(name, kind, priority);
    let running_id = queue_mut.start_next().unwrap_or(enqueued_id);
    sync_job_metrics(
        &queue_mut,
        queued_jobs,
        running_jobs,
        completed_jobs,
        failed_jobs,
        cancelled_jobs,
    );
    running_id
}

#[allow(clippy::too_many_arguments)]
fn queue_complete_tracked_job(
    queue: &Rc<RefCell<JobQueue>>,
    job_id: JobId,
    queued_jobs: RwSignal<u32>,
    running_jobs: RwSignal<u32>,
    completed_jobs: RwSignal<u32>,
    failed_jobs: RwSignal<u32>,
    cancelled_jobs: RwSignal<u32>,
) -> bool {
    let mut queue_mut = queue.borrow_mut();
    let did_complete = queue_mut.complete(job_id);
    sync_job_metrics(
        &queue_mut,
        queued_jobs,
        running_jobs,
        completed_jobs,
        failed_jobs,
        cancelled_jobs,
    );
    did_complete
}

#[allow(clippy::too_many_arguments)]
fn queue_fail_tracked_job(
    queue: &Rc<RefCell<JobQueue>>,
    job_id: JobId,
    reason: String,
    queued_jobs: RwSignal<u32>,
    running_jobs: RwSignal<u32>,
    completed_jobs: RwSignal<u32>,
    failed_jobs: RwSignal<u32>,
    cancelled_jobs: RwSignal<u32>,
) -> bool {
    let mut queue_mut = queue.borrow_mut();
    let did_fail = queue_mut.fail(job_id, reason);
    sync_job_metrics(
        &queue_mut,
        queued_jobs,
        running_jobs,
        completed_jobs,
        failed_jobs,
        cancelled_jobs,
    );
    did_fail
}

fn sync_runtime_metrics(
    runtime_registry: &RuntimeRegistry,
    runtime_version: RwSignal<String>,
    runtime_health: RwSignal<String>,
) {
    if let Some(entry) = runtime_registry.get("llama.cpp") {
        runtime_version.set(entry.version.clone());
        runtime_health.set(format!("{:?}", entry.health));
    }
}

fn format_video_checkpoint_log(checkpoints: &HashMap<u64, VideoCheckpointState>) -> String {
    if checkpoints.is_empty() {
        return String::new();
    }

    let mut entries = checkpoints.values().cloned().collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.asset_id);

    let mut lines = Vec::with_capacity(entries.len());
    for entry in entries {
        lines.push(format!(
            "video-{} | {}% | state={} | seed={} | duration={}s | source={} ({}) | prompt={}",
            entry.asset_id,
            entry.progress_percent,
            entry.state,
            entry.seed,
            entry.duration_seconds,
            entry.source_display_name,
            format_source_kind_label(entry.source_kind),
            entry.prompt_preview
        ));
    }
    lines.join("\n")
}

fn format_runtime_backend_badge(backend: RuntimeBackend) -> &'static str {
    match backend {
        RuntimeBackend::Cpu => "CPU",
        RuntimeBackend::Vulkan => "Vulkan",
        RuntimeBackend::Cuda => "CUDA",
        RuntimeBackend::Hip => "HIP",
        RuntimeBackend::Sycl => "SYCL",
        RuntimeBackend::Hybrid => "Hybrid",
        RuntimeBackend::RemoteApi => "Remote API",
    }
}

fn format_openjarvis_mode_a_summary(runtime_registry: &RuntimeRegistry) -> String {
    let Some(entry) = runtime_registry.get("openjarvis-mode-a") else {
        return "runtime missing".to_string();
    };
    format!(
        "endpoint={} health={:?} backend={}",
        entry.binary_or_endpoint,
        entry.health,
        format_runtime_backend_badge(entry.backend)
    )
}

fn format_openjarvis_mode_b_summary(runtime_registry: &RuntimeRegistry) -> String {
    let Some(entry) = runtime_registry.get("openjarvis-mode-b") else {
        return "runtime missing".to_string();
    };
    format!(
        "endpoint={} health={:?} backend={}",
        entry.binary_or_endpoint,
        entry.health,
        format_runtime_backend_badge(entry.backend)
    )
}

fn format_source_kind_label(kind: SourceKind) -> &'static str {
    match kind {
        SourceKind::LocalModel => "local",
        SourceKind::ApiModel => "api",
        SourceKind::SidecarBridge => "sidecar",
    }
}

fn resolve_source_route_for_role(
    source_registry: &SourceRegistry,
    role: SourceRole,
) -> Result<SourceRouteSelection, String> {
    let Some(entry) = source_registry.default_for(role) else {
        return Err(format!(
            "no enabled source is configured for role {}",
            role.label()
        ));
    };
    Ok(SourceRouteSelection {
        source_id: entry.id.clone(),
        source_display_name: entry.display_name.clone(),
        source_kind: entry.kind,
    })
}

fn format_source_registry_inventory(source_registry: &SourceRegistry) -> String {
    let entries = source_registry.list();
    let local_count = entries
        .iter()
        .filter(|entry| matches!(entry.kind, SourceKind::LocalModel))
        .count();
    let api_count = entries
        .iter()
        .filter(|entry| matches!(entry.kind, SourceKind::ApiModel))
        .count();
    let sidecar_count = entries
        .iter()
        .filter(|entry| matches!(entry.kind, SourceKind::SidecarBridge))
        .count();
    let confidential_configured = entries
        .iter()
        .filter(|entry| entry.confidential_endpoint.is_some())
        .count();
    let confidential_enabled = entries
        .iter()
        .filter(|entry| {
            entry
                .confidential_endpoint
                .as_ref()
                .map(|metadata| metadata.enabled)
                .unwrap_or(false)
        })
        .count();
    format!(
        "total={} local={} api={} sidecar={} confidential_configured={} confidential_enabled={}",
        entries.len(),
        local_count,
        api_count,
        sidecar_count,
        confidential_configured,
        confidential_enabled
    )
}

fn format_source_role_default(source_registry: &SourceRegistry, role: SourceRole) -> String {
    match source_registry.default_for(role) {
        Some(entry) => entry.display_name.clone(),
        None => format!("none ({})", role.label()),
    }
}

fn format_runtime_pin_rollback_summary(
    runtime_registry: &RuntimeRegistry,
    runtime_id: &str,
) -> String {
    let Some(entry) = runtime_registry.get(runtime_id) else {
        return "runtime not found".to_string();
    };

    let rollback_target = entry
        .rollback_version
        .clone()
        .unwrap_or_else(|| "none".to_string());
    let rollback_history_len = runtime_registry
        .rollback_history(runtime_id)
        .map(|items| items.len())
        .unwrap_or(0);
    let latest_rollback = runtime_registry
        .rollback_history(runtime_id)
        .and_then(|items| items.last())
        .map(|record| format!("{}->{}", record.from_version, record.to_version))
        .unwrap_or_else(|| "none".to_string());

    format!(
        "pinned={} rollback_target={} rollback_events={} latest={}",
        if entry.pinned_version { "yes" } else { "no" },
        rollback_target,
        rollback_history_len,
        latest_rollback
    )
}

fn format_runtime_benchmark_summary(
    runtime_registry: &RuntimeRegistry,
    runtime_id: &str,
) -> String {
    if runtime_registry.get(runtime_id).is_none() {
        return "runtime not found".to_string();
    }
    let Some(history) = runtime_registry.benchmark_history(runtime_id) else {
        return "no benchmark history".to_string();
    };
    if history.is_empty() {
        return "no benchmark history".to_string();
    }

    let latest = match history.last() {
        Some(value) => value,
        None => return "no benchmark history".to_string(),
    };
    let pass_count = history.iter().filter(|record| record.success).count();
    let fail_count = history.len().saturating_sub(pass_count);

    format!(
        "runs={} pass={} fail={} last={}ms {} workload={}",
        history.len(),
        pass_count,
        fail_count,
        latest.latency_ms,
        latest
            .tokens_per_second
            .map(|value| format!("{value} tok/s"))
            .unwrap_or_else(|| "n/a".to_string()),
        latest.workload
    )
}

fn sync_runtime_vulkan_card_status(
    runtime_registry: &RuntimeRegistry,
    feature_registry: &FeaturePolicyRegistry,
    runtime_vulkan_memory_status: RwSignal<String>,
    runtime_vulkan_validation_status: RwSignal<String>,
) {
    let Some(entry) = runtime_registry.get("llama.cpp") else {
        runtime_vulkan_memory_status.set(String::from(
            "VMA disabled | allocator=none | runtime missing",
        ));
        runtime_vulkan_validation_status
            .set(String::from("validation=unavailable | runtime missing"));
        return;
    };

    let feature_status = feature_registry.status(FeatureId::VulkanMemoryAllocator);
    let requested_state = feature_status
        .as_ref()
        .map(|value| value.requested_state)
        .unwrap_or(FeatureState::Disabled);
    let effective_state = feature_status
        .as_ref()
        .map(|value| value.effective_state)
        .unwrap_or(FeatureState::Disabled);
    let feature_reason = feature_status
        .as_ref()
        .map(|value| value.reason.clone())
        .unwrap_or_else(|| String::from("feature policy unavailable"));

    let policy_mode = match requested_state {
        FeatureState::Disabled => VulkanMemoryPolicyMode::Disabled,
        FeatureState::Enabled => VulkanMemoryPolicyMode::RequireVma,
        FeatureState::Fallback => VulkanMemoryPolicyMode::ForceConservative,
        FeatureState::Auto | FeatureState::Available => VulkanMemoryPolicyMode::PreferVma,
    };
    let vma_available = matches!(effective_state, FeatureState::Enabled);
    let vulkan_capable_backend = matches!(
        entry.backend,
        RuntimeBackend::Vulkan | RuntimeBackend::Hybrid
    );
    let resolved = resolve_vulkan_memory_status(
        VulkanMemoryPolicy { mode: policy_mode },
        vulkan_capable_backend,
        vma_available,
    );

    let state_prefix = match resolved.state {
        VulkanMemoryState::Active => "VMA enabled",
        VulkanMemoryState::Fallback => "VMA disabled (fallback)",
        VulkanMemoryState::Disabled => "VMA disabled",
        VulkanMemoryState::Unavailable => "VMA unavailable",
    };
    let allocator = match resolved.allocator {
        Some(VulkanMemoryAllocatorKind::Vma) => "vma",
        Some(VulkanMemoryAllocatorKind::Conservative) => "conservative",
        None => "none",
    };

    runtime_vulkan_memory_status.set(format!(
        "{state_prefix} | allocator={allocator} | {}",
        clip_text(&resolved.reason, 120)
    ));

    let gate_decision = evaluate_vulkan_benchmark_gate(
        &collect_vulkan_benchmark_samples(runtime_registry, "llama.cpp"),
        VulkanBenchmarkGateConfig::default(),
    );
    let gate_summary = format_vulkan_gate_decision(&gate_decision);

    let validation = match effective_state {
        FeatureState::Enabled => "passed",
        FeatureState::Fallback => "failed->fallback",
        FeatureState::Available => "pending",
        FeatureState::Disabled => "disabled",
        FeatureState::Auto => "auto",
    };
    runtime_vulkan_validation_status.set(format!(
        "validation={validation} | gate={} | requested={requested_state:?} effective={effective_state:?} | {}",
        clip_text(&gate_summary, 90),
        clip_text(&feature_reason, 110)
    ));
}

fn sync_resource_metrics(
    resource_manager: &ResourceManager,
    ram_used: RwSignal<u32>,
    vram_used: RwSignal<u32>,
    cpu_percent: RwSignal<u32>,
    ram_budget: RwSignal<u32>,
    vram_budget: RwSignal<u32>,
    spill_hint: RwSignal<String>,
) {
    let usage = resource_manager.usage();
    ram_used.set(usage.ram_used_mb);
    vram_used.set(usage.vram_used_mb);
    cpu_percent.set(usage.cpu_used_percent);
    ram_budget.set(usage.ram_budget_mb);
    vram_budget.set(usage.vram_budget_mb);
    spill_hint.set(format!("{:?}", resource_manager.recommended_spill()));
}

#[allow(clippy::too_many_arguments)]
fn sync_runtime_process_signals(
    process_manager: &mut RuntimeProcessManager,
    runtime_registry: &mut RuntimeRegistry,
    runtime_process_state: RwSignal<String>,
    runtime_process_pid: RwSignal<String>,
    runtime_version: RwSignal<String>,
    runtime_health: RwSignal<String>,
    feature_registry: Rc<RefCell<FeaturePolicyRegistry>>,
    feature_policy_status: RwSignal<String>,
    feature_fallback_visible: RwSignal<bool>,
    feature_policy_snapshot: RwSignal<String>,
    runtime_vulkan_memory_status: RwSignal<String>,
    runtime_vulkan_validation_status: RwSignal<String>,
) {
    if let Some(status) = process_manager.status("llama.cpp") {
        let process_state = status.state.clone();
        let mut state_label = match process_state.clone() {
            RuntimeProcessState::Stopped => String::from("Stopped"),
            RuntimeProcessState::Running => String::from("Running"),
            RuntimeProcessState::Exited(code) => format!("Exited ({code})"),
            RuntimeProcessState::LaunchFailed(reason) => {
                format!("LaunchFailed: {}", clip_text(&reason, 120))
            }
        };
        if let Some(probe) = &status.probe_status {
            if probe.healthy {
                state_label.push_str(" | probe: healthy");
            } else {
                state_label.push_str(" | probe: ");
                state_label.push_str(&clip_text(&probe.detail, 120));
            }
        }
        runtime_process_state.set(state_label);
        runtime_process_pid.set(match status.pid {
            Some(pid) => pid.to_string(),
            None => String::from("n/a"),
        });
        if let Some(signal) = process_manager.consume_safety_signal("llama.cpp") {
            let trigger = match signal {
                RuntimeSafetySignal::LaunchFailed { reason, .. } => {
                    RuntimeSafetyTrigger::RuntimeError(format!(
                        "runtime launch failed: {}",
                        clip_text(&reason, 120)
                    ))
                }
                RuntimeSafetySignal::ProbeUnhealthy { detail, .. } => {
                    RuntimeSafetyTrigger::RuntimeError(format!(
                        "runtime probe unhealthy: {}",
                        clip_text(&detail, 120)
                    ))
                }
                RuntimeSafetySignal::ExitedNonZero { exit_code, .. } => {
                    RuntimeSafetyTrigger::RuntimeError(format!(
                        "runtime exited non-zero: {exit_code}"
                    ))
                }
            };
            let note = {
                let mut registry_mut = feature_registry.borrow_mut();
                let already_fallback = registry_mut
                    .status(FeatureId::VulkanMemoryAllocator)
                    .map(|value| matches!(value.effective_state, FeatureState::Fallback))
                    .unwrap_or(false);
                if already_fallback {
                    None
                } else {
                    let note = registry_mut
                        .apply_runtime_safety_fallback(FeatureId::VulkanMemoryAllocator, trigger)
                        .ok();
                    feature_policy_snapshot.set(format_feature_policy_snapshot(
                        &registry_mut,
                        feature_fallback_visible.get(),
                    ));
                    note
                }
            };
            if let Some(note) = note {
                feature_policy_status.set(note);
            }
        }
        let health = match process_state {
            RuntimeProcessState::Running => {
                if let Some(probe) = &status.probe_status {
                    if probe.healthy {
                        RuntimeHealth::Healthy
                    } else {
                        RuntimeHealth::Degraded
                    }
                } else {
                    RuntimeHealth::Healthy
                }
            }
            RuntimeProcessState::Stopped => RuntimeHealth::Unknown,
            RuntimeProcessState::Exited(0) => RuntimeHealth::Degraded,
            RuntimeProcessState::Exited(_) | RuntimeProcessState::LaunchFailed(_) => {
                RuntimeHealth::Unavailable
            }
        };
        let _ = runtime_registry.set_health("llama.cpp", health);
    } else {
        runtime_process_state.set(String::from("Untracked"));
        runtime_process_pid.set(String::from("n/a"));
        let _ = runtime_registry.set_health("llama.cpp", RuntimeHealth::Unknown);
    }
    sync_runtime_metrics(runtime_registry, runtime_version, runtime_health);
    let registry_ref = feature_registry.borrow();
    sync_runtime_vulkan_card_status(
        runtime_registry,
        &registry_ref,
        runtime_vulkan_memory_status,
        runtime_vulkan_validation_status,
    );
}

#[allow(dead_code)]
fn refresh_code_signals(
    workspace: &WorkspaceHost,
    code_file_list: RwSignal<String>,
    code_editor_path: RwSignal<String>,
    code_editor_preview: RwSignal<String>,
    code_search_query: RwSignal<String>,
    code_search_results: RwSignal<String>,
    code_git_summary: RwSignal<String>,
) {
    match workspace.list_files(60) {
        Ok(files) => code_file_list.set(format_file_list(&files)),
        Err(error) => code_file_list.set(format!("Workspace files error: {error:?}")),
    }
    let path = code_editor_path.get();
    match workspace.read_file_excerpt(&path, 80, 5000) {
        Ok(excerpt) => code_editor_preview.set(excerpt),
        Err(error) => code_editor_preview.set(format!("Editor open failed: {error:?}")),
    }
    let query = code_search_query.get();
    match workspace.search(&query, 20) {
        Ok(hits) => {
            let mut output = format!("Search '{query}' ({} hits)\n", hits.len());
            for hit in hits {
                output.push_str(&format!(
                    "- {}:{} | {}\n",
                    hit.path, hit.line_number, hit.line_excerpt
                ));
            }
            code_search_results.set(output.trim_end().to_string());
        }
        Err(error) => code_search_results.set(format!("Search failed: {error:?}")),
    }
    match workspace.git_status() {
        Ok(summary) => code_git_summary.set(format_git_summary(&summary)),
        Err(error) => code_git_summary.set(format!("Git summary unavailable: {error:?}")),
    }
}

fn format_file_list(files: &[String]) -> String {
    if files.is_empty() {
        return String::from("Workspace files: none");
    }
    let mut output = String::from("Workspace files\n");
    for file in files {
        output.push_str("- ");
        output.push_str(file);
        output.push('\n');
    }
    output.trim_end().to_string()
}

fn format_git_summary(summary: &GitStatusSummary) -> String {
    format!(
        "Git status\nbranch: {}\nahead: {}\nbehind: {}\nstaged: {}\nmodified: {}\nuntracked: {}",
        summary.branch,
        summary.ahead,
        summary.behind,
        summary.staged,
        summary.modified,
        summary.untracked
    )
}

fn format_terminal_output(result: &TerminalCommandResult) -> String {
    let stdout = clip_text(result.stdout.trim(), 1800);
    let stderr = clip_text(result.stderr.trim(), 1800);
    format!(
        "Command: {}\nExit: {}\n\nstdout:\n{}\n\nstderr:\n{}",
        result.command,
        result.exit_code,
        if stdout.is_empty() {
            "<empty>"
        } else {
            &stdout
        },
        if stderr.is_empty() {
            "<empty>"
        } else {
            &stderr
        }
    )
}

fn select_default_gguf_model_path() -> String {
    let models_root = PathBuf::from("E:/Forge/models");
    let mut candidates = Vec::new();
    if let Ok(entries) = fs::read_dir(&models_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            let is_gguf = path
                .extension()
                .and_then(|value| value.to_str())
                .map(|value| value.eq_ignore_ascii_case("gguf"))
                .unwrap_or(false);
            if is_gguf && path.is_file() {
                candidates.push(path);
            }
        }
    }
    if candidates.is_empty() {
        return String::from("E:/Forge/models/default.gguf");
    }
    candidates.sort_by_cached_key(|path| path.to_string_lossy().to_ascii_lowercase());
    candidates
        .into_iter()
        .next()
        .map(|path| path.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|| String::from("E:/Forge/models/default.gguf"))
}

#[allow(clippy::too_many_arguments)]
fn build_launch_request(
    entry: &RuntimeEntry,
    model_path: &str,
    host: &str,
    port: &str,
    ctx_size: &str,
    threads: &str,
    gpu_layers: &str,
    batch_size: &str,
) -> Result<RuntimeLaunchRequest, String> {
    let port = parse_u16(port, "port")?;
    let ctx_size = parse_u32(ctx_size, "ctx-size")?;
    let threads = parse_u16(threads, "threads")?;
    let gpu_layers = parse_u16(gpu_layers, "gpu-layers")?;
    let batch_size = parse_u32(batch_size, "batch-size")?;

    let mut profile = LlamaCppLaunchProfile::new(
        PathBuf::from(&entry.binary_or_endpoint),
        PathBuf::from(model_path.trim()),
    );
    profile.host = host.trim().to_string();
    profile.port = port;
    profile.context_size = ctx_size;
    profile.threads = threads;
    profile.gpu_layers = gpu_layers;
    profile.batch_size = batch_size;
    profile.to_launch_request()
}

fn build_completion_request(
    host: &str,
    port: &str,
    prompt: &str,
    n_predict: &str,
) -> Result<LlamaCppCompletionRequest, String> {
    let port = parse_u16(port, "port")?;
    let n_predict = parse_u32(n_predict, "n_predict")?;
    let request = LlamaCppCompletionRequest {
        host: host.trim().to_string(),
        port,
        prompt: prompt.trim().to_string(),
        n_predict,
    };
    request.validate()?;
    Ok(request)
}

fn clip_text(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    let clipped: String = input.chars().take(max_chars).collect();
    format!("{clipped}...")
}

fn parse_u16(value: &str, label: &str) -> Result<u16, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{label} is empty"));
    }
    match trimmed.parse::<u16>() {
        Ok(parsed) if parsed > 0 => Ok(parsed),
        Ok(_) => Err(format!("{label} must be greater than zero")),
        Err(_) => Err(format!("{label} must be a valid integer")),
    }
}

fn parse_u32(value: &str, label: &str) -> Result<u32, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{label} is empty"));
    }
    match trimmed.parse::<u32>() {
        Ok(parsed) if parsed > 0 => Ok(parsed),
        Ok(_) => Err(format!("{label} must be greater than zero")),
        Err(_) => Err(format!("{label} must be a valid integer")),
    }
}

fn parse_u64(value: &str, label: &str) -> Result<u64, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{label} is empty"));
    }
    match trimmed.parse::<u64>() {
        Ok(parsed) => Ok(parsed),
        Err(_) => Err(format!("{label} must be a valid integer")),
    }
}

fn parse_confidential_mode_input(input: &str) -> Result<ConfidentialRelayMode, String> {
    let normalized = input.trim().to_ascii_lowercase().replace('-', "_");
    match normalized.as_str() {
        "disabled" | "off" => Ok(ConfidentialRelayMode::Disabled),
        "enabled" | "on" => Ok(ConfidentialRelayMode::Enabled),
        "required" | "enforced" => Ok(ConfidentialRelayMode::Required),
        _ => Err(format!(
            "confidential mode must be disabled|enabled|required, got `{}`",
            clip_text(input.trim(), 40)
        )),
    }
}

fn default_chat_confidential_profile_window() -> String {
    "16".to_string()
}

fn default_chat_confidential_allow_remote_fallback() -> bool {
    false
}

fn parse_profile_window_size_input(input: &str) -> Result<usize, String> {
    let value = parse_u64(input, "profile_window_size")?;
    let window = usize::try_from(value)
        .map_err(|_| "profile_window_size exceeds this platform's supported range".to_string())?;
    if window == 0 {
        return Err("profile_window_size must be greater than zero".to_string());
    }
    Ok(window)
}

fn format_terminal_session_state(state: &TerminalSessionState) -> String {
    match state {
        TerminalSessionState::Running => String::from("running"),
        TerminalSessionState::Exited(code) => format!("exited ({code})"),
        TerminalSessionState::FailedToStart(reason) => {
            format!("failed: {}", clip_text(reason, 100))
        }
        TerminalSessionState::Stopped => String::from("stopped"),
    }
}

fn runtime_registry_state_path() -> PathBuf {
    match std::env::current_dir() {
        Ok(path) => path.join(".forge_runtime_registry.json"),
        Err(_) => PathBuf::from("E:/Forge/.forge_runtime_registry.json"),
    }
}

fn job_queue_state_path() -> PathBuf {
    match std::env::current_dir() {
        Ok(path) => path.join(".forge_job_queue.json"),
        Err(_) => PathBuf::from("E:/Forge/.forge_job_queue.json"),
    }
}

fn load_job_queue_state(path: &Path) -> Option<PersistedJobQueueState> {
    let contents = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(_) => return None,
    };
    let state = serde_json::from_str::<PersistedJobQueueState>(&contents).ok()?;
    if state.schema_version != 1 {
        return None;
    }
    Some(state)
}

fn save_job_queue_state(path: &Path, queue: &JobQueue) -> UiOperationResult {
    let state = PersistedJobQueueState {
        schema_version: 1,
        queue: queue.snapshot_state(),
    };
    let encoded = serde_json::to_string_pretty(&state).map_err(|error| error.to_string())?;
    fs::write(path, encoded).map_err(|error| error.to_string())
}

fn load_runtime_registry_state(path: &Path) -> Option<RuntimeRegistry> {
    RuntimeRegistry::load_from_path(path).ok()
}

fn save_runtime_registry_state(path: &Path, registry: &RuntimeRegistry) -> UiOperationResult {
    Ok(registry.save_to_path(path)?)
}

fn source_registry_state_path() -> PathBuf {
    match std::env::current_dir() {
        Ok(path) => path.join(".forge_source_registry.json"),
        Err(_) => PathBuf::from("E:/Forge/.forge_source_registry.json"),
    }
}

fn extension_host_state_path() -> PathBuf {
    match std::env::current_dir() {
        Ok(path) => path.join(".forge_extension_host.json"),
        Err(_) => PathBuf::from("E:/Forge/.forge_extension_host.json"),
    }
}

fn confidential_relay_state_path() -> PathBuf {
    match std::env::current_dir() {
        Ok(path) => path.join(".forge_confidential_relay.json"),
        Err(_) => PathBuf::from("E:/Forge/.forge_confidential_relay.json"),
    }
}

fn chat_confidential_state_path() -> PathBuf {
    match std::env::current_dir() {
        Ok(path) => path.join(".forge_chat_confidential.json"),
        Err(_) => PathBuf::from("E:/Forge/.forge_chat_confidential.json"),
    }
}

fn dock_layout_state_path() -> PathBuf {
    match std::env::current_dir() {
        Ok(path) => path.join(".forge_dock_layout.json"),
        Err(_) => PathBuf::from("E:/Forge/.forge_dock_layout.json"),
    }
}

fn load_confidential_relay_sessions(path: &Path) -> Option<ConfidentialRelaySessionStore> {
    ConfidentialRelaySessionStore::load_from_path(path).ok()
}

fn save_confidential_relay_sessions(
    path: &Path,
    sessions: &ConfidentialRelaySessionStore,
) -> UiOperationResult {
    Ok(sessions.save_to_path(path)?)
}

fn load_chat_confidential_state(path: &Path) -> Option<PersistedChatConfidentialState> {
    let contents = fs::read_to_string(path).ok()?;
    let state = serde_json::from_str::<PersistedChatConfidentialState>(&contents).ok()?;
    if state.schema_version != 1 {
        return None;
    }
    Some(state)
}

fn save_chat_confidential_state(
    path: &Path,
    state: &PersistedChatConfidentialState,
) -> UiOperationResult {
    let encoded = serde_json::to_string_pretty(state).map_err(|error| error.to_string())?;
    fs::write(path, encoded).map_err(|error| error.to_string())
}

fn load_dock_layout_state(path: &Path) -> Option<PersistedDockLayoutState> {
    let contents = fs::read_to_string(path).ok()?;
    let state = serde_json::from_str::<PersistedDockLayoutState>(&contents).ok()?;
    if state.schema_version != 1 {
        return None;
    }
    Some(state)
}

fn save_dock_layout_state(path: &Path, state: &PersistedDockLayoutState) -> UiOperationResult {
    let encoded = serde_json::to_string_pretty(state).map_err(|error| error.to_string())?;
    fs::write(path, encoded).map_err(|error| error.to_string())
}

fn load_extension_host_state(path: &Path) -> Option<ExtensionHost> {
    let contents = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(_) => return None,
    };
    let state = serde_json::from_str::<PersistedExtensionHostState>(&contents).ok()?;
    if state.schema_version != 1 {
        return None;
    }
    ExtensionHost::restore(state.runtimes).ok()
}

fn save_extension_host_state(path: &Path, host: &ExtensionHost) -> UiOperationResult {
    let state = PersistedExtensionHostState {
        schema_version: 1,
        runtimes: host.snapshot(),
    };
    let encoded = serde_json::to_string_pretty(&state).map_err(|error| error.to_string())?;
    fs::write(path, encoded).map_err(|error| error.to_string())
}

fn load_source_registry_state(path: &Path) -> Option<SourceRegistry> {
    SourceRegistry::load_from_path(path).ok()
}

fn save_source_registry_state(path: &Path, registry: &SourceRegistry) -> UiOperationResult {
    Ok(registry.save_to_path(path)?)
}

fn persist_source_registry_with_notice(
    source_registry: &Rc<RefCell<SourceRegistry>>,
    model_source_status: RwSignal<String>,
) {
    let registry = match source_registry.try_borrow() {
        Ok(value) => value,
        Err(error) => {
            let message = format!("source registry persist skipped: busy ({error})");
            model_source_status.set(message.clone());
            log_warn("persist", message);
            return;
        }
    };
    if let Err(error) = save_source_registry_state(&source_registry_state_path(), &registry) {
        let current = model_source_status.get();
        model_source_status.set(format!(
            "{} | persist warning: {}",
            clip_text(&current, 120),
            clip_text(&error, 120),
        ));
        log_warn(
            "persist",
            format!(
                "source registry persist warning: {}",
                clip_text(&error, 120)
            ),
        );
    }
}

fn merge_missing_default_sources(source_registry: &mut SourceRegistry) {
    let defaults = default_source_registry();
    for entry in defaults.list() {
        if source_registry.get(entry.id.as_str()).is_none() {
            source_registry.register(entry.clone());
        }
    }
}

fn merge_missing_default_extensions(extension_host: &mut ExtensionHost) {
    let defaults = default_extension_host();
    for runtime in defaults.list() {
        if extension_host.get(runtime.manifest.id.as_str()).is_none() {
            let _ = extension_host.register(runtime.manifest.clone());
        }
    }
}

fn persist_runtime_registry_with_notice(
    runtimes: &Rc<RefCell<RuntimeRegistry>>,
    runtime_profile_status: RwSignal<String>,
) {
    let registry = match runtimes.try_borrow() {
        Ok(value) => value,
        Err(error) => {
            let message = format!("runtime registry persist skipped: busy ({error})");
            runtime_profile_status.set(message.clone());
            log_warn("persist", message);
            return;
        }
    };
    if let Err(error) = save_runtime_registry_state(&runtime_registry_state_path(), &registry) {
        let current = runtime_profile_status.get();
        runtime_profile_status.set(format!(
            "{} | persist warning: {}",
            clip_text(&current, 120),
            clip_text(&error, 120),
        ));
        log_warn(
            "persist",
            format!(
                "runtime registry persist warning: {}",
                clip_text(&error, 120)
            ),
        );
    }
}

fn persist_job_queue_with_notice(queue: &Rc<RefCell<JobQueue>>, status_signal: RwSignal<String>) {
    let queue_ref = match queue.try_borrow() {
        Ok(value) => value,
        Err(error) => {
            let message = format!("job queue persist skipped: busy ({error})");
            status_signal.set(message.clone());
            log_warn("persist", message);
            return;
        }
    };
    if let Err(error) = save_job_queue_state(&job_queue_state_path(), &queue_ref) {
        let current = status_signal.get();
        status_signal.set(format!(
            "{} | persist warning: {}",
            clip_text(&current, 120),
            clip_text(&error, 120),
        ));
        log_warn(
            "persist",
            format!("job queue persist warning: {}", clip_text(&error, 120)),
        );
    }
}

fn persist_extension_host_with_notice(
    extension_host: &Rc<RefCell<ExtensionHost>>,
    extension_status: RwSignal<String>,
) {
    let host = match extension_host.try_borrow() {
        Ok(value) => value,
        Err(error) => {
            let message = format!("extension host persist skipped: busy ({error})");
            extension_status.set(message.clone());
            log_warn("persist", message);
            return;
        }
    };
    if let Err(error) = save_extension_host_state(&extension_host_state_path(), &host) {
        let current = extension_status.get();
        extension_status.set(format!(
            "{} | persist warning: {}",
            clip_text(&current, 120),
            clip_text(&error, 120),
        ));
        log_warn(
            "persist",
            format!("extension host persist warning: {}", clip_text(&error, 120)),
        );
    }
}

fn persist_confidential_relay_with_notice(
    sessions: &Rc<RefCell<ConfidentialRelaySessionStore>>,
    status_signal: RwSignal<String>,
) {
    let sessions_ref = match sessions.try_borrow() {
        Ok(value) => value,
        Err(error) => {
            let message = format!("confidential relay persist skipped: busy ({error})");
            status_signal.set(message.clone());
            log_warn("persist", message);
            return;
        }
    };
    if let Err(error) =
        save_confidential_relay_sessions(&confidential_relay_state_path(), &sessions_ref)
    {
        let current = status_signal.get();
        status_signal.set(format!(
            "{} | persist warning: {}",
            clip_text(&current, 120),
            clip_text(&error, 120),
        ));
        log_warn(
            "persist",
            format!(
                "confidential relay persist warning: {}",
                clip_text(&error, 120)
            ),
        );
    }
}

fn collect_dock_layout_state(
    sidebar_open: RwSignal<bool>,
    inspector_open: RwSignal<bool>,
    bottom_open: RwSignal<bool>,
) -> PersistedDockLayoutState {
    PersistedDockLayoutState {
        schema_version: 1,
        sidebar_open: sidebar_open.get(),
        inspector_open: inspector_open.get(),
        bottom_open: bottom_open.get(),
    }
}

fn persist_dock_layout_with_notice(
    sidebar_open: RwSignal<bool>,
    inspector_open: RwSignal<bool>,
    bottom_open: RwSignal<bool>,
    status_signal: RwSignal<String>,
) {
    let state = collect_dock_layout_state(sidebar_open, inspector_open, bottom_open);
    if let Err(error) = save_dock_layout_state(&dock_layout_state_path(), &state) {
        let current = status_signal.get();
        status_signal.set(format!(
            "{} | persist warning: {}",
            clip_text(&current, 120),
            clip_text(&error, 120),
        ));
    }
}

fn collect_chat_confidential_state(
    chat_confidential_measurement: RwSignal<String>,
    chat_confidential_policy_mode: RwSignal<String>,
    chat_confidential_max_attestation_age_ms: RwSignal<String>,
    chat_confidential_profile_window: RwSignal<String>,
    chat_confidential_require_cpu: RwSignal<bool>,
    chat_confidential_require_gpu: RwSignal<bool>,
    chat_confidential_allow_remote_fallback: RwSignal<bool>,
) -> PersistedChatConfidentialState {
    PersistedChatConfidentialState {
        schema_version: 1,
        measurement: chat_confidential_measurement.get(),
        policy_mode: chat_confidential_policy_mode.get(),
        max_attestation_age_ms: chat_confidential_max_attestation_age_ms.get(),
        profile_window_size: chat_confidential_profile_window.get(),
        require_confidential_cpu: chat_confidential_require_cpu.get(),
        require_confidential_gpu: chat_confidential_require_gpu.get(),
        allow_remote_fallback: chat_confidential_allow_remote_fallback.get(),
    }
}

#[allow(clippy::too_many_arguments)]
fn persist_chat_confidential_state_with_notice(
    chat_confidential_measurement: RwSignal<String>,
    chat_confidential_policy_mode: RwSignal<String>,
    chat_confidential_max_attestation_age_ms: RwSignal<String>,
    chat_confidential_profile_window: RwSignal<String>,
    chat_confidential_require_cpu: RwSignal<bool>,
    chat_confidential_require_gpu: RwSignal<bool>,
    chat_confidential_allow_remote_fallback: RwSignal<bool>,
    status_signal: RwSignal<String>,
) {
    let state = collect_chat_confidential_state(
        chat_confidential_measurement,
        chat_confidential_policy_mode,
        chat_confidential_max_attestation_age_ms,
        chat_confidential_profile_window,
        chat_confidential_require_cpu,
        chat_confidential_require_gpu,
        chat_confidential_allow_remote_fallback,
    );
    if let Err(error) = save_chat_confidential_state(&chat_confidential_state_path(), &state) {
        let current = status_signal.get();
        status_signal.set(format!(
            "{} | persist warning: {}",
            clip_text(&current, 120),
            clip_text(&error, 120),
        ));
    }
}

fn collect_vulkan_benchmark_samples(
    runtime_registry: &RuntimeRegistry,
    runtime_id: &str,
) -> Vec<VulkanBenchmarkSample> {
    runtime_registry
        .benchmark_history(runtime_id)
        .map(|history| {
            history
                .iter()
                .map(|record| VulkanBenchmarkSample {
                    latency_ms: record.latency_ms,
                    tokens_per_second: record.tokens_per_second,
                    success: record.success,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn format_vulkan_gate_decision(decision: &VulkanBenchmarkGateDecision) -> String {
    match decision {
        VulkanBenchmarkGateDecision::InsufficientData { observed, required } => {
            format!("pending ({observed}/{required} samples)")
        }
        VulkanBenchmarkGateDecision::Pass {
            sample_count,
            success_ratio_permille,
            p95_latency_ms,
            median_tokens_per_second,
        } => format!(
            "pass (samples={sample_count}, success={}%, p95={}ms, median_tps={})",
            success_ratio_permille / 10,
            p95_latency_ms,
            median_tokens_per_second
        ),
        VulkanBenchmarkGateDecision::Fail {
            sample_count,
            success_ratio_permille,
            p95_latency_ms,
            median_tokens_per_second,
            reason,
        } => format!(
            "fail (samples={sample_count}, success={}%, p95={}ms, median_tps={}, reason={})",
            success_ratio_permille / 10,
            p95_latency_ms,
            median_tokens_per_second,
            clip_text(reason, 90)
        ),
    }
}

fn apply_vulkan_benchmark_gate_from_registry(
    runtime_registry: &RuntimeRegistry,
    feature_registry: &mut FeaturePolicyRegistry,
) -> String {
    let samples = collect_vulkan_benchmark_samples(runtime_registry, "llama.cpp");
    let decision = evaluate_vulkan_benchmark_gate(&samples, VulkanBenchmarkGateConfig::default());
    let policy_note = apply_vulkan_benchmark_gate(feature_registry, &decision)
        .unwrap_or_else(|error| format!("policy update failed: {error:?}"));
    evaluate_registry_with_default_checks(feature_registry);
    format!(
        "{} | {}",
        format_vulkan_gate_decision(&decision),
        clip_text(&policy_note, 120)
    )
}
