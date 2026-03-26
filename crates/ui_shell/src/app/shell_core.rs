pub fn launch_desktop() {
    install_forge_panic_hook();
    if let Err(error) = forge_security::process_hardening::enforce_process_dumpability_controls() {
        log_error(
            "startup",
            format!("launch blocked by process hardening: {error}"),
        );
        return;
    }
    log_info("startup", "launch_desktop invoked");
    let mut window_config = WindowConfig::default().title("Forge");
    if let Some(icon) = forge_window_icon() {
        window_config = window_config.window_icon(icon);
    }
    log_info("startup", "running Forge desktop application loop");
    Application::new()
        .window(|_| forge_view(), Some(window_config))
        .run();
}

const FORGE_ICON_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96" viewBox="0 0 512 512" fill="none">
<defs>
<linearGradient id="metal" x1="96" y1="112" x2="420" y2="188" gradientUnits="userSpaceOnUse">
<stop stop-color="#185DD6"/><stop offset="1" stop-color="#73B8FF"/>
</linearGradient>
<linearGradient id="flame" x1="170" y1="492" x2="338" y2="188" gradientUnits="userSpaceOnUse">
<stop stop-color="#FF2600"/><stop offset="0.55" stop-color="#FF7A00"/><stop offset="1" stop-color="#FFD34D"/>
</linearGradient>
</defs>
<path d="M96 112h324l-82 76H182l-32 88H94z" fill="url(#metal)" stroke="#C8ECFF" stroke-width="5"/>
<path d="M148 275l190-87-40 116-80 32-94 156 38-108z" fill="url(#flame)" stroke="#FFA850" stroke-width="4"/>
</svg>"##;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VideoCheckpointState {
    asset_id: u64,
    prompt_preview: String,
    seed: u64,
    duration_seconds: u32,
    source_id: String,
    source_display_name: String,
    source_kind: SourceKind,
    progress_percent: u8,
    state: String,
}

#[derive(Debug, Clone)]
struct SourceRouteSelection {
    source_id: String,
    source_display_name: String,
    source_kind: SourceKind,
}

fn forge_view() -> impl IntoView {
    let forge_view_started = Instant::now();
    log_info("startup", "forge_view init begin");
    let active_view = RwSignal::new(PrimaryView::Workspace);
    let sidebar_open = RwSignal::new(true);
    let inspector_open = RwSignal::new(true);
    let bottom_open = RwSignal::new(false);
    let command_query = RwSignal::new(String::new());

    let cpu_percent = RwSignal::new(12u32);
    let gpu_percent = RwSignal::new(6u32);
    let ram_used = RwSignal::new(0u32);
    let vram_used = RwSignal::new(0u32);
    let ram_budget = RwSignal::new(0u32);
    let vram_budget = RwSignal::new(0u32);
    let spill_hint = RwSignal::new(String::from("None"));
    let queued_jobs = RwSignal::new(0u32);
    let running_jobs = RwSignal::new(0u32);
    let completed_jobs = RwSignal::new(0u32);
    let failed_jobs = RwSignal::new(0u32);
    let cancelled_jobs = RwSignal::new(0u32);
    let running_job_id = RwSignal::new(None::<JobId>);
    let jobs_target_id = RwSignal::new(String::new());
    let jobs_filter = RwSignal::new(String::from("all"));
    let jobs_status = RwSignal::new(String::from("jobs panel ready"));
    let jobs_timeline = RwSignal::new(String::new());

    let runtime_version = RwSignal::new(String::from("unknown"));
    let runtime_health = RwSignal::new(String::from("Unknown"));
    let runtime_vulkan_memory_status = RwSignal::new(String::from("VMA status pending"));
    let runtime_vulkan_validation_status = RwSignal::new(String::from("validation pending"));
    let runtime_process_state = RwSignal::new(String::from("Stopped"));
    let runtime_process_pid = RwSignal::new(String::from("n/a"));
    let runtime_profile_status = RwSignal::new(String::from("profile pending"));
    let llama_model_path = RwSignal::new(select_default_gguf_model_path());
    let llama_host = RwSignal::new(String::from("127.0.0.1"));
    let llama_port = RwSignal::new(String::from("8080"));
    let llama_ctx_size = RwSignal::new(String::from("8192"));
    let llama_threads = RwSignal::new(String::from("8"));
    let llama_gpu_layers = RwSignal::new(String::from("0"));
    let llama_batch_size = RwSignal::new(String::from("512"));

    let workspace_root = match std::env::current_dir() {
        Ok(path) => path,
        Err(_) => PathBuf::from("E:/Forge"),
    };
    let workspace = Rc::new(WorkspaceHost::new(workspace_root.clone()));
    let terminal_sessions = Rc::new(RefCell::new(TerminalSessionManager::new(workspace_root)));
    let code_file_list = RwSignal::new(String::new());
    let code_editor_path = RwSignal::new(String::from("FORGE_DEVELOPMENT_PLAN.md"));
    let code_editor_preview = RwSignal::new(String::new());
    let code_editor_append = RwSignal::new(String::from("// phase1 note"));
    let code_search_query = RwSignal::new(String::from("Phase 1"));
    let code_search_results = RwSignal::new(String::new());
    let code_git_summary = RwSignal::new(String::new());
    let code_terminal_command = RwSignal::new(String::from("git status -sb"));
    let code_terminal_output = RwSignal::new(String::new());
    let code_terminal_session_id = RwSignal::new(None::<u64>);
    let code_terminal_session_state = RwSignal::new(String::from("no active session"));
    let code_terminal_stream_output = RwSignal::new(String::new());
    let code_terminal_stdin = RwSignal::new(String::new());
    let code_queue_status = RwSignal::new(String::from(
        "code queue idle (click Refresh Files to load workspace snapshot)",
    ));
    let chat_prompt = RwSignal::new(String::from(
        "Summarize Forge's local-first mission in 3 bullets.",
    ));
    let chat_n_predict = RwSignal::new(String::from("128"));
    let chat_output = RwSignal::new(String::new());
    let chat_status = RwSignal::new(String::from("idle"));
    let chat_confidential_measurement = RwSignal::new(String::from("sha256:demo-measurement"));
    let chat_confidential_policy_mode = RwSignal::new(String::from("required"));
    let chat_confidential_max_attestation_age_ms = RwSignal::new(String::from("300000"));
    let chat_confidential_profile_window =
        RwSignal::new(default_chat_confidential_profile_window());
    let chat_confidential_require_cpu = RwSignal::new(true);
    let chat_confidential_require_gpu = RwSignal::new(true);
    let chat_confidential_allow_remote_fallback =
        RwSignal::new(default_chat_confidential_allow_remote_fallback());
    let chat_confidential_status = RwSignal::new(String::from("confidential relay idle"));
    let chat_routed_baseline_latency_ms = RwSignal::new(None::<u64>);
    let media_prompt = RwSignal::new(String::from(
        "industrial product render, matte black workstation, softbox lighting",
    ));
    let media_seed = RwSignal::new(String::from("42"));
    let media_batch_size = RwSignal::new(String::from("4"));
    let media_status = RwSignal::new(String::from("idle"));
    let media_gallery = RwSignal::new(String::new());
    let media_next_asset_id = RwSignal::new(1_u64);
    let video_prompt = RwSignal::new(String::from(
        "slow dolly shot around a futuristic workstation with cinematic lights",
    ));
    let video_seed = RwSignal::new(String::from("77"));
    let video_batch_size = RwSignal::new(String::from("2"));
    let video_duration_seconds = RwSignal::new(String::from("8"));
    let video_status = RwSignal::new(String::from("idle"));
    let video_checkpoint_log = RwSignal::new(String::new());
    let video_checkpoint_state = Rc::new(RefCell::new(HashMap::<u64, VideoCheckpointState>::new()));
    let media_state_path = media_studio_state_path();
    if let Some(saved_media_state) = load_media_studio_state(&media_state_path) {
        media_prompt.set(saved_media_state.media_prompt);
        media_seed.set(saved_media_state.media_seed);
        media_batch_size.set(saved_media_state.media_batch_size);
        media_gallery.set(saved_media_state.media_gallery);
        media_next_asset_id.set(saved_media_state.media_next_asset_id.max(1));
        video_prompt.set(saved_media_state.video_prompt);
        video_seed.set(saved_media_state.video_seed);
        video_batch_size.set(saved_media_state.video_batch_size);
        video_duration_seconds.set(saved_media_state.video_duration_seconds);
        let mut restored_checkpoints = HashMap::<u64, VideoCheckpointState>::new();
        for entry in saved_media_state.video_checkpoint_entries {
            restored_checkpoints.insert(entry.asset_id, entry);
        }
        let restored_count = restored_checkpoints.len();
        video_checkpoint_log.set(format_video_checkpoint_log(&restored_checkpoints));
        *video_checkpoint_state.borrow_mut() = restored_checkpoints;
        media_status.set(String::from("media state restored"));
        video_status.set(format!("video checkpoints restored: {restored_count}"));
    }
    {
        let saved = collect_media_studio_state(
            media_prompt,
            media_seed,
            media_batch_size,
            media_gallery,
            media_next_asset_id,
            video_prompt,
            video_seed,
            video_batch_size,
            video_duration_seconds,
            &video_checkpoint_state,
        );
        let _ = save_media_studio_state(&media_state_path, &saved);
    }
    let feature_target = RwSignal::new(String::from("rayon_parallelism"));
    let feature_policy_status = RwSignal::new(String::from("policy idle"));
    let feature_fallback_visible = RwSignal::new(true);
    let feature_policy_snapshot = RwSignal::new(String::new());
    let agent_status_line = RwSignal::new(String::from("agent run not initialized"));
    let agent_steps_line = RwSignal::new(String::new());
    let agent_trace_line = RwSignal::new(String::new());
    let agent_trace_filter_query = RwSignal::new(String::new());
    let agent_trace_filter_kind = RwSignal::new(String::from("all"));
    let agent_trace_filter_role = RwSignal::new(String::from("all"));
    let agent_codex_prompt = RwSignal::new(String::from(
        "Implement the requested coder step with safe, testable edits.",
    ));
    let agent_codex_auto = RwSignal::new(true);
    let agent_codex_max_tokens = RwSignal::new(String::from("512"));
    let agent_codex_status = RwSignal::new(String::from("codex specialist idle"));
    let agent_codex_output = RwSignal::new(String::new());
    let agent_memory_scope = RwSignal::new(String::from("project"));
    let agent_memory_key = RwSignal::new(String::from("workspace-goal"));
    let agent_memory_value = RwSignal::new(String::from("keep changes small and test first"));
    let agent_memory_query = RwSignal::new(String::new());
    let agent_memory_status = RwSignal::new(String::from("memory scope idle"));
    let agent_memory_output = RwSignal::new(String::new());
    let model_source_target = RwSignal::new(String::from("codex-specialist-openjarvis-mode-b"));
    let model_source_role = RwSignal::new(String::from("codex_specialist"));
    let model_confidential_verifier_endpoint = RwSignal::new(
        std::env::var("CONFIDENTIAL_VERIFIER_URL")
            .unwrap_or_else(|_| "https://attest.example/verify".to_string()),
    );
    let model_confidential_expected_provider =
        RwSignal::new(std::env::var("CONFIDENTIAL_EXPECTED_PROVIDER").unwrap_or_default());
    let model_confidential_measurement_prefixes = RwSignal::new(
        std::env::var("CONFIDENTIAL_MEASUREMENT_PREFIXES")
            .unwrap_or_else(|_| "sha256:trusted-".to_string()),
    );
    let model_confidential_timeout_ms = RwSignal::new(
        std::env::var("CONFIDENTIAL_VERIFIER_TIMEOUT_MS").unwrap_or_else(|_| "5000".to_string()),
    );
    let model_confidential_api_key_env_var =
        RwSignal::new(std::env::var("CONFIDENTIAL_VERIFIER_API_KEY_ENV").unwrap_or_default());
    let model_source_status = RwSignal::new(String::from("source registry ready"));
    let active_agent_run_id = RwSignal::new(None::<u64>);
    let project_memory_path = project_memory_state_path();
    let agent_memory_store = Rc::new(RefCell::new(
        load_project_memory_state(&project_memory_path).unwrap_or_default(),
    ));
    {
        let stats = agent_memory_store.borrow().stats();
        agent_memory_status.set(format!(
            "memory loaded: session={} project={} workspace={}",
            stats.session_entries, stats.project_entries, stats.workspace_entries
        ));
        log_info("startup", "project memory state loaded");
    }
    let extension_target = RwSignal::new(String::from("provider-openai"));
    let extension_status = RwSignal::new(String::from("extension host ready"));
    code_file_list.set(String::from(
        "workspace snapshot not loaded yet (open Code panel and click Refresh Files)",
    ));
    code_editor_preview.set(String::from(
        "editor preview not loaded yet (click Load in Code panel)",
    ));
    code_search_results.set(String::from(
        "search not executed yet (enter query and click Run Search)",
    ));
    code_git_summary.set(String::from("git summary not loaded yet (click Refresh Git)"));
    log_info("startup", "deferred heavy code panel scans until manual action");

    let job_queue_path = job_queue_state_path();
    let queue = Rc::new(RefCell::new(
        load_job_queue_state(&job_queue_path)
            .and_then(|state| JobQueue::restore_state(state.queue).ok())
            .unwrap_or_default(),
    ));
    {
        let queue_mut = queue.borrow_mut();
        running_job_id.set(queue_mut.first_running_job());
        sync_job_metrics(
            &queue_mut,
            queued_jobs,
            running_jobs,
            completed_jobs,
            failed_jobs,
            cancelled_jobs,
        );
        jobs_timeline.set(format_job_timeline(
            &queue_mut,
            jobs_filter.get().as_str(),
            24,
        ));
        log_info("startup", "job queue restored");
    }

    let runtime_registry_path = runtime_registry_state_path();
    let runtimes = Rc::new(RefCell::new(
        load_runtime_registry_state(&runtime_registry_path).unwrap_or_else(|| {
            let mut registry = RuntimeRegistry::new();
            registry.register(default_llama_runtime());
            registry.register(default_openjarvis_mode_a_runtime());
            registry.register(default_openjarvis_mode_b_runtime());
            registry
        }),
    ));
    {
        let mut runtimes_mut = runtimes.borrow_mut();
        if runtimes_mut.get("llama.cpp").is_none() {
            runtimes_mut.register(default_llama_runtime());
        }
        if runtimes_mut.get("openjarvis-mode-a").is_none() {
            runtimes_mut.register(default_openjarvis_mode_a_runtime());
        }
        if runtimes_mut.get("openjarvis-mode-b").is_none() {
            runtimes_mut.register(default_openjarvis_mode_b_runtime());
        }
        let _ = runtimes_mut.set_health("llama.cpp", RuntimeHealth::Unknown);
        sync_runtime_metrics(&runtimes_mut, runtime_version, runtime_health);
        log_info("startup", "runtime registry loaded");
    }
    let source_registry_path = source_registry_state_path();
    let source_registry = Rc::new(RefCell::new(
        load_source_registry_state(&source_registry_path).unwrap_or_else(default_source_registry),
    ));
    {
        let mut source_registry_mut = source_registry.borrow_mut();
        merge_missing_default_sources(&mut source_registry_mut);
        model_source_status.set(format!(
            "source registry loaded: {}",
            format_source_registry_inventory(&source_registry_mut)
        ));
        log_info("startup", "source registry loaded");
    }
    let confidential_relay_path = confidential_relay_state_path();
    let confidential_relay_sessions = Rc::new(RefCell::new(
        load_confidential_relay_sessions(&confidential_relay_path).unwrap_or_default(),
    ));
    {
        let sessions = confidential_relay_sessions.borrow();
        if let Some(latest) = sessions.latest_session() {
            chat_confidential_status.set(format!(
                "loaded confidential session {} key={} (provider={}, expires={}, total_ms={})",
                latest.session_id,
                clip_text(&latest.session_key_id, 32),
                latest.attestation_provider,
                latest.expires_at_unix_ms,
                latest.total_path_ms
            ));
        }
        log_info("startup", "confidential relay sessions loaded");
    }
    let chat_confidential_path = chat_confidential_state_path();
    if let Some(saved_chat_confidential) = load_chat_confidential_state(&chat_confidential_path) {
        chat_confidential_measurement.set(saved_chat_confidential.measurement);
        chat_confidential_policy_mode.set(saved_chat_confidential.policy_mode);
        chat_confidential_max_attestation_age_ms
            .set(saved_chat_confidential.max_attestation_age_ms);
        chat_confidential_profile_window.set(saved_chat_confidential.profile_window_size);
        chat_confidential_require_cpu.set(saved_chat_confidential.require_confidential_cpu);
        chat_confidential_require_gpu.set(saved_chat_confidential.require_confidential_gpu);
        chat_confidential_allow_remote_fallback.set(saved_chat_confidential.allow_remote_fallback);
    }
    {
        let _saved = collect_chat_confidential_state(
            chat_confidential_measurement,
            chat_confidential_policy_mode,
            chat_confidential_max_attestation_age_ms,
            chat_confidential_profile_window,
            chat_confidential_require_cpu,
            chat_confidential_require_gpu,
            chat_confidential_allow_remote_fallback,
        );
    }
    let dock_layout_path = dock_layout_state_path();
    if let Some(saved_dock_layout) = load_dock_layout_state(&dock_layout_path) {
        sidebar_open.set(saved_dock_layout.sidebar_open);
        inspector_open.set(saved_dock_layout.inspector_open);
        bottom_open.set(saved_dock_layout.bottom_open);
    }
    {
        let _saved = collect_dock_layout_state(sidebar_open, inspector_open, bottom_open);
    }
    let extension_host_path = extension_host_state_path();
    let extension_host = Rc::new(RefCell::new(
        load_extension_host_state(&extension_host_path).unwrap_or_else(default_extension_host),
    ));
    {
        let mut extension_host_mut = extension_host.borrow_mut();
        merge_missing_default_extensions(&mut extension_host_mut);
        log_info("startup", "extension host loaded");
    }
    let runtime_processes = Rc::new(RefCell::new(RuntimeProcessManager::new()));
    let feature_registry = Rc::new(RefCell::new(FeaturePolicyRegistry::with_defaults()));
    let settings_path = feature_policy_settings_path();
    if let Some(saved) = load_feature_policy_settings(&settings_path) {
        feature_fallback_visible.set(saved.fallback_visibility);
        let mut registry_mut = feature_registry.borrow_mut();
        for feature in saved.features {
            let _ = registry_mut.set_requested_state(feature.id, feature.requested_state);
        }
        evaluate_registry_with_default_checks(&mut registry_mut);
    } else {
        let mut registry_mut = feature_registry.borrow_mut();
        evaluate_registry_with_default_checks(&mut registry_mut);
    }
    {
        let mut registry_mut = feature_registry.borrow_mut();
        let runtime_registry_ref = runtimes.borrow();
        let gate_note =
            apply_vulkan_benchmark_gate_from_registry(&runtime_registry_ref, &mut registry_mut);
        feature_policy_status.set(format!("startup vulkan benchmark gate: {gate_note}"));
        feature_policy_snapshot.set(format_feature_policy_snapshot(
            &registry_mut,
            feature_fallback_visible.get(),
        ));
        sync_runtime_vulkan_card_status(
            &runtime_registry_ref,
            &registry_mut,
            runtime_vulkan_memory_status,
            runtime_vulkan_validation_status,
        );
    }

    let resources = Rc::new(RefCell::new(ResourceManager::new(
        MemoryBudget {
            ram_mb: 32768,
            vram_mb: 16384,
        },
        SpillPolicy::Balanced,
    )));
    {
        let mut resources_mut = resources.borrow_mut();
        resources_mut.set_cpu_used_percent(cpu_percent.get());
        let extension_totals = extension_host.borrow().active_resource_totals();
        let _ = resources_mut.set_extension_overhead(
            extension_totals.ram_budget_mb,
            extension_totals.cpu_budget_percent,
        );
        let _ = resources_mut.reserve_ram(6144);
        let _ = resources_mut.reserve_vram(2048);
        sync_resource_metrics(
            &resources_mut,
            ram_used,
            vram_used,
            cpu_percent,
            ram_budget,
            vram_budget,
            spill_hint,
        );
    }

    let agent_orchestrator = Rc::new(RefCell::new(AgentOrchestrator::new()));
    let agent_state_path = agent_studio_state_path();
    {
        let mut orchestrator_mut = agent_orchestrator.borrow_mut();
        let mut restored = false;
        if let Some(saved_state) = load_agent_studio_state(&agent_state_path) {
            match orchestrator_mut.restore_runs(saved_state.runs) {
                Ok(()) => {
                    let resolved_run =
                        resolve_active_agent_run_id(saved_state.active_run_id, &orchestrator_mut);
                    active_agent_run_id.set(resolved_run);
                    restored = true;
                }
                Err(error) => {
                    agent_status_line.set(format!(
                        "agent state restore failed ({error:?}); creating new run"
                    ));
                }
            }
        }
        if !restored {
            let run = create_default_agent_run(
                &mut orchestrator_mut,
                "Phase 2 Agent Studio bootstrap run",
            );
            if let Ok(run_id) = run {
                active_agent_run_id.set(Some(run_id));
            }
        }
        sync_agent_studio_signals(
            &orchestrator_mut,
            active_agent_run_id.get(),
            agent_status_line,
            agent_steps_line,
            agent_trace_line,
        );
        log_info("startup", "agent studio state prepared");
    }

    let top_shell = h_stack((
        left_rail(active_view, sidebar_open),
        dyn_container(
            move || sidebar_open.get(),
            move |is_open| {
                if is_open {
                    sidebar_panel(active_view).into_any()
                } else {
                    empty().into_any()
                }
            },
        ),
        main_surface(
            active_view,
            command_query,
            resources.clone(),
            queue.clone(),
            workspace.clone(),
            code_file_list,
            code_editor_path,
            code_editor_preview,
            code_editor_append,
            code_search_query,
            code_search_results,
            code_git_summary,
            code_terminal_command,
            code_terminal_output,
            terminal_sessions.clone(),
            code_terminal_session_id,
            code_terminal_session_state,
            code_terminal_stream_output,
            code_terminal_stdin,
            code_queue_status,
            queued_jobs,
            running_jobs,
            completed_jobs,
            failed_jobs,
            cancelled_jobs,
            runtime_version,
            runtime_health,
            runtime_process_state,
            runtime_process_pid,
            runtime_profile_status,
            runtime_vulkan_memory_status,
            runtime_vulkan_validation_status,
            runtime_processes.clone(),
            feature_registry.clone(),
            feature_policy_status,
            feature_fallback_visible,
            feature_policy_snapshot,
            llama_model_path,
            llama_host,
            llama_port,
            llama_ctx_size,
            llama_threads,
            llama_gpu_layers,
            llama_batch_size,
            chat_prompt,
            chat_n_predict,
            chat_output,
            chat_status,
            chat_confidential_measurement,
            chat_confidential_policy_mode,
            chat_confidential_max_attestation_age_ms,
            chat_confidential_profile_window,
            chat_confidential_require_cpu,
            chat_confidential_require_gpu,
            chat_confidential_allow_remote_fallback,
            chat_confidential_status,
            chat_routed_baseline_latency_ms,
            media_prompt,
            media_seed,
            media_batch_size,
            media_status,
            media_gallery,
            media_next_asset_id,
            video_prompt,
            video_seed,
            video_batch_size,
            video_duration_seconds,
            video_status,
            video_checkpoint_log,
            video_checkpoint_state.clone(),
            runtimes.clone(),
            source_registry.clone(),
            confidential_relay_sessions.clone(),
            model_source_target,
            model_source_role,
            model_confidential_verifier_endpoint,
            model_confidential_expected_provider,
            model_confidential_measurement_prefixes,
            model_confidential_timeout_ms,
            model_confidential_api_key_env_var,
            model_source_status,
            agent_orchestrator.clone(),
            active_agent_run_id,
            agent_status_line,
            agent_steps_line,
            agent_trace_line,
            agent_trace_filter_query,
            agent_trace_filter_kind,
            agent_trace_filter_role,
            agent_codex_prompt,
            agent_codex_auto,
            agent_codex_max_tokens,
            agent_codex_status,
            agent_codex_output,
            agent_memory_store.clone(),
            agent_memory_scope,
            agent_memory_key,
            agent_memory_value,
            agent_memory_query,
            agent_memory_status,
            agent_memory_output,
            extension_host.clone(),
            extension_target,
            extension_status,
            feature_target,
            cpu_percent,
            gpu_percent,
            ram_used,
            vram_used,
            ram_budget,
            vram_budget,
            spill_hint,
            sidebar_open,
            inspector_open,
            bottom_open,
        ),
        dyn_container(move || inspector_open.get(), {
            let resources = resources.clone();
            let queue = queue.clone();
            let runtimes = runtimes.clone();
            let runtime_processes = runtime_processes.clone();
            move |is_open| {
                if is_open {
                    inspector_panel(
                        resources.clone(),
                        queue.clone(),
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                        runtimes.clone(),
                        runtime_processes.clone(),
                        feature_registry.clone(),
                        runtime_version,
                        runtime_health,
                        runtime_process_state,
                        runtime_process_pid,
                        runtime_profile_status,
                        runtime_vulkan_memory_status,
                        runtime_vulkan_validation_status,
                        llama_model_path,
                        llama_host,
                        llama_port,
                        llama_ctx_size,
                        llama_threads,
                        llama_gpu_layers,
                        llama_batch_size,
                        cpu_percent,
                        ram_used,
                        vram_used,
                        ram_budget,
                        vram_budget,
                        spill_hint,
                        feature_policy_status,
                        feature_fallback_visible,
                        feature_policy_snapshot,
                    )
                    .into_any()
                } else {
                    empty().into_any()
                }
            }
        }),
    ))
    .style(|s| s.size_full().background(theme::window_bg()));

    let bottom_stack = dyn_container(move || bottom_open.get(), {
        let queue = queue.clone();
        move |is_open| {
            if is_open {
                bottom_panel(
                    queue.clone(),
                    running_job_id,
                    jobs_target_id,
                    jobs_filter,
                    jobs_status,
                    jobs_timeline,
                    queued_jobs,
                    running_jobs,
                    completed_jobs,
                    failed_jobs,
                    cancelled_jobs,
                )
                .into_any()
            } else {
                empty().into_any()
            }
        }
    });

    log_startup_checkpoint("forge_view init", forge_view_started);
    v_stack((top_shell, bottom_stack)).style(|s| {
        s.size_full()
            .background(theme::window_bg())
            .color(theme::text_primary())
    })
}

fn nav_button(
    target: PrimaryView,
    active_view: RwSignal<PrimaryView>,
    sidebar_open: RwSignal<bool>,
) -> impl IntoView {
    button(label(move || {
        format!(
            "{} {}",
            if active_view.get() == target {
                "[*]"
            } else {
                "[ ]"
            },
            target.title()
        )
    }))
    .action(move || {
        active_view.set(target);
        sidebar_open.set(true);
    })
    .style(|s| {
        s.width_full()
            .padding_horiz(8.0)
            .padding_vert(4.0)
            .justify_start()
    })
}

fn forge_window_icon() -> Option<Icon> {
    let size: usize = 128;
    let mut rgba = vec![0_u8; size * size * 4];

    let metal = [
        (24.0_f32, 28.0_f32),
        (105.0, 28.0),
        (84.0, 48.0),
        (46.0, 48.0),
        (38.0, 70.0),
        (23.0, 70.0),
    ];
    let flame = [
        (37.0_f32, 70.0_f32),
        (84.0, 48.0),
        (74.0, 77.0),
        (54.0, 85.0),
        (31.0, 124.0),
        (40.0, 97.0),
    ];

    for y in 0..size {
        for x in 0..size {
            let xf = x as f32 + 0.5;
            let yf = y as f32 + 0.5;
            let idx = (y * size + x) * 4;

            if point_in_polygon(xf, yf, &metal) {
                let t = (x as f32 / (size.saturating_sub(1) as f32)).clamp(0.0, 1.0);
                rgba[idx] = (24.0 + 91.0 * t) as u8;
                rgba[idx + 1] = (93.0 + 90.0 * t) as u8;
                rgba[idx + 2] = (214.0 + 41.0 * t) as u8;
                rgba[idx + 3] = 255;
            }
            if point_in_polygon(xf, yf, &flame) {
                let ty = (y as f32 / (size.saturating_sub(1) as f32)).clamp(0.0, 1.0);
                let tx = (x as f32 / (size.saturating_sub(1) as f32)).clamp(0.0, 1.0);
                rgba[idx] = 255;
                rgba[idx + 1] = (45.0 + 150.0 * (1.0 - ty) + 20.0 * tx).min(255.0) as u8;
                rgba[idx + 2] = (8.0 + 25.0 * (1.0 - ty)).min(255.0) as u8;
                rgba[idx + 3] = 255;
            }
        }
    }

    Icon::from_rgba(rgba, size as u32, size as u32).ok()
}

fn point_in_polygon(x: f32, y: f32, polygon: &[(f32, f32)]) -> bool {
    if polygon.len() < 3 {
        return false;
    }
    let mut inside = false;
    let mut j = polygon.len() - 1;
    for i in 0..polygon.len() {
        let (xi, yi) = polygon[i];
        let (xj, yj) = polygon[j];
        let intersects =
            (yi > y) != (yj > y) && x < (xj - xi) * (y - yi) / (yj - yi + f32::EPSILON) + xi;
        if intersects {
            inside = !inside;
        }
        j = i;
    }
    inside
}

fn left_rail(active_view: RwSignal<PrimaryView>, sidebar_open: RwSignal<bool>) -> impl IntoView {
    v_stack((
        h_stack((
            svg(FORGE_ICON_SVG).style(|s| s.size(24.0, 24.0)),
            label(|| "Forge").style(|s| s.font_size(16.0).color(theme::accent())),
        ))
        .style(|s| s.gap(8.0).items_center().padding_bottom(8.0)),
        nav_button(PrimaryView::Workspace, active_view, sidebar_open),
        nav_button(PrimaryView::Code, active_view, sidebar_open),
        nav_button(PrimaryView::Chat, active_view, sidebar_open),
        nav_button(PrimaryView::Models, active_view, sidebar_open),
        nav_button(PrimaryView::Agents, active_view, sidebar_open),
        nav_button(PrimaryView::Media, active_view, sidebar_open),
        nav_button(PrimaryView::Jobs, active_view, sidebar_open),
        nav_button(PrimaryView::Extensions, active_view, sidebar_open),
        nav_button(PrimaryView::Settings, active_view, sidebar_open),
    ))
    .style(|s| {
        s.width(220.0)
            .height_full()
            .padding(10.0)
            .row_gap(6.0)
            .background(theme::surface_1())
            .border_right(1.0)
    })
}

fn sidebar_panel(active_view: RwSignal<PrimaryView>) -> impl IntoView {
    let title = label(move || format!("{} Sidebar", active_view.get().title()))
        .style(|s| s.font_size(14.0));
    let body = scroll(v_stack((
        label(|| "Project: E:\\Forge"),
        label(|| "Recent files"),
        label(|| "- FORGE_DEVELOPMENT_PLAN.md"),
        label(|| "- SKILL.md"),
        label(|| "- AGENT.md"),
        label(|| "Pinned: Runtime Cards, Agent Graph, Telemetry"),
    )))
    .style(|s| s.size_full().padding(10.0).row_gap(6.0));
    v_stack((title, body)).style(|s| {
        s.width(280.0)
            .height_full()
            .padding(8.0)
            .background(theme::surface_2())
            .border_right(1.0)
    })
}

#[allow(clippy::too_many_arguments)]
fn main_surface(
    active_view: RwSignal<PrimaryView>,
    command_query: RwSignal<String>,
    resources: Rc<RefCell<ResourceManager>>,
    queue: Rc<RefCell<JobQueue>>,
    workspace: Rc<WorkspaceHost>,
    code_file_list: RwSignal<String>,
    code_editor_path: RwSignal<String>,
    code_editor_preview: RwSignal<String>,
    code_editor_append: RwSignal<String>,
    code_search_query: RwSignal<String>,
    code_search_results: RwSignal<String>,
    code_git_summary: RwSignal<String>,
    code_terminal_command: RwSignal<String>,
    code_terminal_output: RwSignal<String>,
    terminal_sessions: Rc<RefCell<TerminalSessionManager>>,
    code_terminal_session_id: RwSignal<Option<u64>>,
    code_terminal_session_state: RwSignal<String>,
    code_terminal_stream_output: RwSignal<String>,
    code_terminal_stdin: RwSignal<String>,
    code_queue_status: RwSignal<String>,
    queued_jobs: RwSignal<u32>,
    running_jobs: RwSignal<u32>,
    completed_jobs: RwSignal<u32>,
    failed_jobs: RwSignal<u32>,
    cancelled_jobs: RwSignal<u32>,
    runtime_version: RwSignal<String>,
    runtime_health: RwSignal<String>,
    runtime_process_state: RwSignal<String>,
    runtime_process_pid: RwSignal<String>,
    runtime_profile_status: RwSignal<String>,
    runtime_vulkan_memory_status: RwSignal<String>,
    runtime_vulkan_validation_status: RwSignal<String>,
    runtime_processes: Rc<RefCell<RuntimeProcessManager>>,
    feature_registry: Rc<RefCell<FeaturePolicyRegistry>>,
    feature_policy_status: RwSignal<String>,
    feature_fallback_visible: RwSignal<bool>,
    feature_policy_snapshot: RwSignal<String>,
    llama_model_path: RwSignal<String>,
    llama_host: RwSignal<String>,
    llama_port: RwSignal<String>,
    llama_ctx_size: RwSignal<String>,
    llama_threads: RwSignal<String>,
    llama_gpu_layers: RwSignal<String>,
    llama_batch_size: RwSignal<String>,
    chat_prompt: RwSignal<String>,
    chat_n_predict: RwSignal<String>,
    chat_output: RwSignal<String>,
    chat_status: RwSignal<String>,
    chat_confidential_measurement: RwSignal<String>,
    chat_confidential_policy_mode: RwSignal<String>,
    chat_confidential_max_attestation_age_ms: RwSignal<String>,
    chat_confidential_profile_window: RwSignal<String>,
    chat_confidential_require_cpu: RwSignal<bool>,
    chat_confidential_require_gpu: RwSignal<bool>,
    chat_confidential_allow_remote_fallback: RwSignal<bool>,
    chat_confidential_status: RwSignal<String>,
    chat_routed_baseline_latency_ms: RwSignal<Option<u64>>,
    media_prompt: RwSignal<String>,
    media_seed: RwSignal<String>,
    media_batch_size: RwSignal<String>,
    media_status: RwSignal<String>,
    media_gallery: RwSignal<String>,
    media_next_asset_id: RwSignal<u64>,
    video_prompt: RwSignal<String>,
    video_seed: RwSignal<String>,
    video_batch_size: RwSignal<String>,
    video_duration_seconds: RwSignal<String>,
    video_status: RwSignal<String>,
    video_checkpoint_log: RwSignal<String>,
    video_checkpoint_state: Rc<RefCell<HashMap<u64, VideoCheckpointState>>>,
    runtimes: Rc<RefCell<RuntimeRegistry>>,
    source_registry: Rc<RefCell<SourceRegistry>>,
    confidential_relay_sessions: Rc<RefCell<ConfidentialRelaySessionStore>>,
    model_source_target: RwSignal<String>,
    model_source_role: RwSignal<String>,
    model_confidential_verifier_endpoint: RwSignal<String>,
    model_confidential_expected_provider: RwSignal<String>,
    model_confidential_measurement_prefixes: RwSignal<String>,
    model_confidential_timeout_ms: RwSignal<String>,
    model_confidential_api_key_env_var: RwSignal<String>,
    model_source_status: RwSignal<String>,
    agent_orchestrator: Rc<RefCell<AgentOrchestrator>>,
    active_agent_run_id: RwSignal<Option<u64>>,
    agent_status_line: RwSignal<String>,
    agent_steps_line: RwSignal<String>,
    agent_trace_line: RwSignal<String>,
    agent_trace_filter_query: RwSignal<String>,
    agent_trace_filter_kind: RwSignal<String>,
    agent_trace_filter_role: RwSignal<String>,
    agent_codex_prompt: RwSignal<String>,
    agent_codex_auto: RwSignal<bool>,
    agent_codex_max_tokens: RwSignal<String>,
    agent_codex_status: RwSignal<String>,
    agent_codex_output: RwSignal<String>,
    agent_memory_store: Rc<RefCell<ProjectMemoryStore>>,
    agent_memory_scope: RwSignal<String>,
    agent_memory_key: RwSignal<String>,
    agent_memory_value: RwSignal<String>,
    agent_memory_query: RwSignal<String>,
    agent_memory_status: RwSignal<String>,
    agent_memory_output: RwSignal<String>,
    extension_host: Rc<RefCell<ExtensionHost>>,
    extension_target: RwSignal<String>,
    extension_status: RwSignal<String>,
    feature_target: RwSignal<String>,
    cpu_percent: RwSignal<u32>,
    gpu_percent: RwSignal<u32>,
    ram_used: RwSignal<u32>,
    vram_used: RwSignal<u32>,
    ram_budget: RwSignal<u32>,
    vram_budget: RwSignal<u32>,
    spill_hint: RwSignal<String>,
    sidebar_open: RwSignal<bool>,
    inspector_open: RwSignal<bool>,
    bottom_open: RwSignal<bool>,
) -> impl IntoView {
    let toolbar_update_runtime = {
        let queue = queue.clone();
        let runtimes = runtimes.clone();
        let feature_registry = feature_registry.clone();
        move || {
            let tracked_job_id = queue_start_tracked_job(
                &queue,
                "toolbar-runtime-update".to_string(),
                JobKind::SystemTask,
                JobPriority::Normal,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, runtime_profile_status);
            let mut runtime_registry = runtimes.borrow_mut();
            let result = runtime_registry.update_version("llama.cpp", "0.1.0-phase1");
            let (update_note, failure_reason) = match result {
                UpdateResult::Updated => {
                    let _ = runtime_registry.set_health("llama.cpp", RuntimeHealth::Unknown);
                    (
                        "toolbar update applied (llama.cpp runtime metadata refreshed)".to_string(),
                        None,
                    )
                }
                UpdateResult::AlreadyCurrent => (
                    "toolbar update skipped (runtime already current)".to_string(),
                    None,
                ),
                UpdateResult::BlockedByPin => (
                    "toolbar update blocked (runtime version pinned)".to_string(),
                    Some("toolbar update blocked by pin".to_string()),
                ),
                UpdateResult::RuntimeNotFound => (
                    "toolbar update failed (runtime missing)".to_string(),
                    Some("toolbar update runtime missing".to_string()),
                ),
            };
            sync_runtime_metrics(&runtime_registry, runtime_version, runtime_health);
            let registry_ref = feature_registry.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry,
                &registry_ref,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
            drop(runtime_registry);
            persist_runtime_registry_with_notice(&runtimes, runtime_profile_status);
            if let Some(reason) = failure_reason {
                let _ = queue_fail_tracked_job(
                    &queue,
                    tracked_job_id,
                    reason,
                    queued_jobs,
                    running_jobs,
                    completed_jobs,
                    failed_jobs,
                    cancelled_jobs,
                );
            } else {
                let _ = queue_complete_tracked_job(
                    &queue,
                    tracked_job_id,
                    queued_jobs,
                    running_jobs,
                    completed_jobs,
                    failed_jobs,
                    cancelled_jobs,
                );
            }
            runtime_profile_status.set(format!("{} [job #{}]", update_note, tracked_job_id.raw()));
            persist_job_queue_with_notice(&queue, runtime_profile_status);
        }
    };

    let toolbar_start_runtime = {
        let queue = queue.clone();
        let runtimes = runtimes.clone();
        let runtime_processes = runtime_processes.clone();
        let feature_registry = feature_registry.clone();
        move || {
            let tracked_job_id = queue_start_tracked_job(
                &queue,
                "toolbar-runtime-start".to_string(),
                JobKind::SystemTask,
                JobPriority::Normal,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, runtime_profile_status);
            let vma_active = {
                let registry = feature_registry.borrow();
                registry
                    .status(FeatureId::VulkanMemoryAllocator)
                    .map(|status| matches!(status.effective_state, FeatureState::Enabled))
                    .unwrap_or(false)
            };
            let configured_gpu_layers = llama_gpu_layers
                .get()
                .trim()
                .parse::<u16>()
                .ok()
                .unwrap_or(0);
            if configured_gpu_layers > 0 && !vma_active {
                llama_gpu_layers.set(String::from("0"));
                runtime_profile_status.set(String::from(
                    "toolbar start forced gpu-layers=0 (vulkan policy inactive)",
                ));
            }
            let launch_request = {
                let runtime_registry = runtimes.borrow();
                if let Some(entry) = runtime_registry.get("llama.cpp") {
                    build_launch_request(
                        entry,
                        llama_model_path.get().as_str(),
                        llama_host.get().as_str(),
                        llama_port.get().as_str(),
                        llama_ctx_size.get().as_str(),
                        llama_threads.get().as_str(),
                        llama_gpu_layers.get().as_str(),
                        llama_batch_size.get().as_str(),
                    )
                } else {
                    Err(String::from("runtime llama.cpp not found"))
                }
            };
            let (status_note, failure_reason) = match launch_request {
                Ok(request) => {
                    let mut process_manager = runtime_processes.borrow_mut();
                    let start_result = process_manager.start("llama.cpp", &request);
                    let mut runtime_registry = runtimes.borrow_mut();
                    sync_runtime_process_signals(
                        &mut process_manager,
                        &mut runtime_registry,
                        runtime_process_state,
                        runtime_process_pid,
                        runtime_version,
                        runtime_health,
                        feature_registry.clone(),
                        feature_policy_status,
                        feature_fallback_visible,
                        feature_policy_snapshot,
                        runtime_vulkan_memory_status,
                        runtime_vulkan_validation_status,
                    );
                    if matches!(start_result, StartResult::LaunchFailed) {
                        (
                            "toolbar start failed (see process state)".to_string(),
                            Some("toolbar runtime start launch failed".to_string()),
                        )
                    } else {
                        ("toolbar start requested for llama.cpp".to_string(), None)
                    }
                }
                Err(error) => {
                    runtime_process_state.set(String::from("toolbar launch aborted"));
                    (
                        format!("toolbar profile invalid: {error}"),
                        Some(format!("toolbar profile invalid: {error}")),
                    )
                }
            };
            if let Some(reason) = failure_reason {
                let _ = queue_fail_tracked_job(
                    &queue,
                    tracked_job_id,
                    reason,
                    queued_jobs,
                    running_jobs,
                    completed_jobs,
                    failed_jobs,
                    cancelled_jobs,
                );
            } else {
                let _ = queue_complete_tracked_job(
                    &queue,
                    tracked_job_id,
                    queued_jobs,
                    running_jobs,
                    completed_jobs,
                    failed_jobs,
                    cancelled_jobs,
                );
            }
            runtime_profile_status.set(format!("{} [job #{}]", status_note, tracked_job_id.raw()));
            persist_job_queue_with_notice(&queue, runtime_profile_status);
        }
    };

    let toolbar_stop_runtime = {
        let queue = queue.clone();
        let runtimes = runtimes.clone();
        let runtime_processes = runtime_processes.clone();
        let feature_registry = feature_registry.clone();
        move || {
            let tracked_job_id = queue_start_tracked_job(
                &queue,
                "toolbar-runtime-stop".to_string(),
                JobKind::SystemTask,
                JobPriority::Normal,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, runtime_profile_status);
            let mut process_manager = runtime_processes.borrow_mut();
            let stop_result = process_manager.stop("llama.cpp");
            let mut runtime_registry = runtimes.borrow_mut();
            sync_runtime_process_signals(
                &mut process_manager,
                &mut runtime_registry,
                runtime_process_state,
                runtime_process_pid,
                runtime_version,
                runtime_health,
                feature_registry.clone(),
                feature_policy_status,
                feature_fallback_visible,
                feature_policy_snapshot,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
            let (status_note, failure_reason) = match stop_result {
                StopResult::Stopped => ("toolbar stop requested for llama.cpp".to_string(), None),
                StopResult::NotRunning => (
                    "toolbar stop skipped (runtime not running)".to_string(),
                    None,
                ),
                StopResult::UnknownRuntime => (
                    "toolbar stop failed (runtime missing)".to_string(),
                    Some("toolbar stop failed: runtime missing".to_string()),
                ),
            };
            if let Some(reason) = failure_reason {
                let _ = queue_fail_tracked_job(
                    &queue,
                    tracked_job_id,
                    reason,
                    queued_jobs,
                    running_jobs,
                    completed_jobs,
                    failed_jobs,
                    cancelled_jobs,
                );
            } else {
                let _ = queue_complete_tracked_job(
                    &queue,
                    tracked_job_id,
                    queued_jobs,
                    running_jobs,
                    completed_jobs,
                    failed_jobs,
                    cancelled_jobs,
                );
            }
            runtime_profile_status.set(format!("{} [job #{}]", status_note, tracked_job_id.raw()));
            persist_job_queue_with_notice(&queue, runtime_profile_status);
        }
    };

    let toolbar_vulkan_on = {
        let queue = queue.clone();
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let tracked_job_id = queue_start_tracked_job(
                &queue,
                "toolbar-vulkan-on".to_string(),
                JobKind::SystemTask,
                JobPriority::Normal,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, runtime_profile_status);
            let mut registry_mut = feature_registry.borrow_mut();
            let set_result = registry_mut
                .set_requested_state(FeatureId::VulkanMemoryAllocator, FeatureState::Enabled);
            if let Err(error) = set_result {
                let _ = queue_fail_tracked_job(
                    &queue,
                    tracked_job_id,
                    format!("toolbar vulkan on failed: {error:?}"),
                    queued_jobs,
                    running_jobs,
                    completed_jobs,
                    failed_jobs,
                    cancelled_jobs,
                );
                runtime_profile_status.set(format!(
                    "toolbar vulkan on failed (policy unavailable) [job #{}]",
                    tracked_job_id.raw()
                ));
                persist_job_queue_with_notice(&queue, runtime_profile_status);
                return;
            }
            evaluate_registry_with_default_checks(&mut registry_mut);
            let status = registry_mut.status(FeatureId::VulkanMemoryAllocator);
            let summary = match status {
                Some(value) => format!(
                    "toolbar vulkan on: requested={:?} effective={:?} ({})",
                    value.requested_state,
                    value.effective_state,
                    clip_text(&value.reason, 90)
                ),
                None => String::from("toolbar vulkan on: status unavailable"),
            };
            feature_policy_status.set(summary);
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
            runtime_profile_status.set(format!(
                "toolbar vulkan policy set to ON for llama.cpp runtime path [job #{}]",
                tracked_job_id.raw()
            ));
            let _ = queue_complete_tracked_job(
                &queue,
                tracked_job_id,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, runtime_profile_status);
        }
    };

    let toolbar_vulkan_off = {
        let queue = queue.clone();
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let tracked_job_id = queue_start_tracked_job(
                &queue,
                "toolbar-vulkan-off".to_string(),
                JobKind::SystemTask,
                JobPriority::Normal,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, runtime_profile_status);
            let mut registry_mut = feature_registry.borrow_mut();
            let set_result = registry_mut
                .set_requested_state(FeatureId::VulkanMemoryAllocator, FeatureState::Disabled);
            if let Err(error) = set_result {
                let _ = queue_fail_tracked_job(
                    &queue,
                    tracked_job_id,
                    format!("toolbar vulkan off failed: {error:?}"),
                    queued_jobs,
                    running_jobs,
                    completed_jobs,
                    failed_jobs,
                    cancelled_jobs,
                );
                runtime_profile_status.set(format!(
                    "toolbar vulkan off failed (policy unavailable) [job #{}]",
                    tracked_job_id.raw()
                ));
                persist_job_queue_with_notice(&queue, runtime_profile_status);
                return;
            }
            evaluate_registry_with_default_checks(&mut registry_mut);
            llama_gpu_layers.set(String::from("0"));
            let status = registry_mut.status(FeatureId::VulkanMemoryAllocator);
            let summary = match status {
                Some(value) => format!(
                    "toolbar vulkan off: requested={:?} effective={:?} ({})",
                    value.requested_state,
                    value.effective_state,
                    clip_text(&value.reason, 90)
                ),
                None => String::from("toolbar vulkan off: status unavailable"),
            };
            feature_policy_status.set(summary);
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
            runtime_profile_status.set(format!(
                "toolbar vulkan policy set to OFF (gpu-layers forced to 0) [job #{}]",
                tracked_job_id.raw()
            ));
            let _ = queue_complete_tracked_job(
                &queue,
                tracked_job_id,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, runtime_profile_status);
        }
    };

    let toolbar_vulkan_update = {
        let queue = queue.clone();
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let tracked_job_id = queue_start_tracked_job(
                &queue,
                "toolbar-vulkan-update".to_string(),
                JobKind::SystemTask,
                JobPriority::Normal,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, runtime_profile_status);
            let mut registry_mut = feature_registry.borrow_mut();
            let runtime_registry_ref = runtimes.borrow();
            let gate_note =
                apply_vulkan_benchmark_gate_from_registry(&runtime_registry_ref, &mut registry_mut);
            let status = registry_mut.status(FeatureId::VulkanMemoryAllocator);
            let summary = match status {
                Some(value) => format!(
                    "toolbar vulkan update: requested={:?} effective={:?} ({}) | gate={}",
                    value.requested_state,
                    value.effective_state,
                    clip_text(&value.reason, 90),
                    clip_text(&gate_note, 90)
                ),
                None => String::from("toolbar vulkan update: status unavailable"),
            };
            feature_policy_status.set(summary);
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
            runtime_profile_status.set(format!(
                "toolbar vulkan update completed (policy re-evaluated) [job #{}]",
                tracked_job_id.raw()
            ));
            let _ = queue_complete_tracked_job(
                &queue,
                tracked_job_id,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, runtime_profile_status);
        }
    };

    let toggle_sidebar = move || {
        sidebar_open.update(|open| *open = !*open);
        persist_dock_layout_with_notice(
            sidebar_open,
            inspector_open,
            bottom_open,
            runtime_profile_status,
        );
    };
    let toggle_inspector = move || {
        inspector_open.update(|open| *open = !*open);
        persist_dock_layout_with_notice(
            sidebar_open,
            inspector_open,
            bottom_open,
            runtime_profile_status,
        );
    };
    let toggle_bottom = move || {
        bottom_open.update(|open| *open = !*open);
        persist_dock_layout_with_notice(
            sidebar_open,
            inspector_open,
            bottom_open,
            runtime_profile_status,
        );
    };
    let apply_dock_balanced = move || {
        sidebar_open.set(true);
        inspector_open.set(true);
        bottom_open.set(false);
        runtime_profile_status.set(String::from(
            "dock preset: balanced (sidebar+inspector on, bottom off)",
        ));
        persist_dock_layout_with_notice(
            sidebar_open,
            inspector_open,
            bottom_open,
            runtime_profile_status,
        );
    };
    let apply_dock_focus = move || {
        sidebar_open.set(false);
        inspector_open.set(false);
        bottom_open.set(false);
        runtime_profile_status.set(String::from(
            "dock preset: focus (single surface, side/bottom hidden)",
        ));
        persist_dock_layout_with_notice(
            sidebar_open,
            inspector_open,
            bottom_open,
            runtime_profile_status,
        );
    };
    let apply_dock_review = move || {
        sidebar_open.set(true);
        inspector_open.set(true);
        bottom_open.set(true);
        runtime_profile_status.set(String::from(
            "dock preset: review (sidebar+inspector+bottom all visible)",
        ));
        persist_dock_layout_with_notice(
            sidebar_open,
            inspector_open,
            bottom_open,
            runtime_profile_status,
        );
    };
    let toolbar_update_runtime = guarded_ui_action(
        "toolbar.update_runtime",
        Some(runtime_profile_status),
        toolbar_update_runtime,
    );
    let toolbar_start_runtime = guarded_ui_action(
        "toolbar.start_runtime",
        Some(runtime_profile_status),
        toolbar_start_runtime,
    );
    let toolbar_stop_runtime = guarded_ui_action(
        "toolbar.stop_runtime",
        Some(runtime_profile_status),
        toolbar_stop_runtime,
    );
    let toolbar_vulkan_on = guarded_ui_action(
        "toolbar.vulkan_on",
        Some(runtime_profile_status),
        toolbar_vulkan_on,
    );
    let toolbar_vulkan_off = guarded_ui_action(
        "toolbar.vulkan_off",
        Some(runtime_profile_status),
        toolbar_vulkan_off,
    );
    let toolbar_vulkan_update = guarded_ui_action(
        "toolbar.vulkan_update",
        Some(runtime_profile_status),
        toolbar_vulkan_update,
    );
    let toggle_sidebar = guarded_ui_action(
        "toolbar.toggle_sidebar",
        Some(runtime_profile_status),
        toggle_sidebar,
    );
    let toggle_inspector = guarded_ui_action(
        "toolbar.toggle_inspector",
        Some(runtime_profile_status),
        toggle_inspector,
    );
    let toggle_bottom = guarded_ui_action(
        "toolbar.toggle_bottom",
        Some(runtime_profile_status),
        toggle_bottom,
    );
    let apply_dock_balanced = guarded_ui_action(
        "toolbar.apply_dock_balanced",
        Some(runtime_profile_status),
        apply_dock_balanced,
    );
    let apply_dock_focus = guarded_ui_action(
        "toolbar.apply_dock_focus",
        Some(runtime_profile_status),
        apply_dock_focus,
    );
    let apply_dock_review = guarded_ui_action(
        "toolbar.apply_dock_review",
        Some(runtime_profile_status),
        apply_dock_review,
    );

    let command_row = h_stack((
        h_stack((
            label(|| "Command"),
            text_input(command_query).style(|s| s.min_width(220.0).padding(6.0).color(theme::input_text())),
        ))
        .style(|s| s.items_center().gap(6.0)),
        h_stack((
            label(|| "llama.cpp"),
            button("On").action(toolbar_start_runtime),
            button("Off").action(toolbar_stop_runtime),
            button("Update").action(toolbar_update_runtime),
        ))
        .style(|s| s.items_center().gap(6.0)),
        h_stack((
            label(|| "Vulkan llama.cpp"),
            button("On").action(toolbar_vulkan_on),
            button("Off").action(toolbar_vulkan_off),
            button("Update").action(toolbar_vulkan_update),
        ))
        .style(|s| s.items_center().gap(6.0)),
        h_stack((
            label(|| "Dock"),
            button("Sidebar").action(toggle_sidebar),
            button("Inspector").action(toggle_inspector),
            button("Bottom").action(toggle_bottom),
            button("Balanced").action(apply_dock_balanced),
            button("Focus").action(apply_dock_focus),
            button("Review").action(apply_dock_review),
        ))
        .style(|s| s.items_center().gap(6.0)),
        label(move || {
            format!(
                "layout: sidebar={} inspector={} bottom={}",
                sidebar_open.get(),
                inspector_open.get(),
                bottom_open.get()
            )
        })
        .style(|s| s.color(theme::text_secondary())),
    ))
    .style(|s| {
        s.width_full()
            .padding(8.0)
            .background(theme::surface_1())
            .gap(12.0)
            .items_center()
    });

    let content = dyn_container(
        move || active_view.get(),
        move |view| {
            main_surface_content(
                view,
                resources.clone(),
                queue.clone(),
                workspace.clone(),
                code_file_list,
                code_editor_path,
                code_editor_preview,
                code_editor_append,
                code_search_query,
                code_search_results,
                code_git_summary,
                code_terminal_command,
                code_terminal_output,
                terminal_sessions.clone(),
                code_terminal_session_id,
                code_terminal_session_state,
                code_terminal_stream_output,
                code_terminal_stdin,
                code_queue_status,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
                runtime_version,
                runtime_health,
                runtime_process_state,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
                llama_host,
                llama_port,
                chat_prompt,
                chat_n_predict,
                chat_output,
                chat_status,
                chat_confidential_measurement,
                chat_confidential_policy_mode,
                chat_confidential_max_attestation_age_ms,
                chat_confidential_profile_window,
                chat_confidential_require_cpu,
                chat_confidential_require_gpu,
                chat_confidential_allow_remote_fallback,
                chat_confidential_status,
                chat_routed_baseline_latency_ms,
                media_prompt,
                media_seed,
                media_batch_size,
                media_status,
                media_gallery,
                media_next_asset_id,
                video_prompt,
                video_seed,
                video_batch_size,
                video_duration_seconds,
                video_status,
                video_checkpoint_log,
                video_checkpoint_state.clone(),
                runtimes.clone(),
                source_registry.clone(),
                confidential_relay_sessions.clone(),
                model_source_target,
                model_source_role,
                model_confidential_verifier_endpoint,
                model_confidential_expected_provider,
                model_confidential_measurement_prefixes,
                model_confidential_timeout_ms,
                model_confidential_api_key_env_var,
                model_source_status,
                agent_orchestrator.clone(),
                active_agent_run_id,
                agent_status_line,
                agent_steps_line,
                agent_trace_line,
                agent_trace_filter_query,
                agent_trace_filter_kind,
                agent_trace_filter_role,
                agent_codex_prompt,
                agent_codex_auto,
                agent_codex_max_tokens,
                agent_codex_status,
                agent_codex_output,
                agent_memory_store.clone(),
                agent_memory_scope,
                agent_memory_key,
                agent_memory_value,
                agent_memory_query,
                agent_memory_status,
                agent_memory_output,
                extension_host.clone(),
                extension_target,
                extension_status,
                cpu_percent,
                ram_used,
                vram_used,
                ram_budget,
                vram_budget,
                spill_hint,
                feature_registry.clone(),
                feature_target,
                feature_policy_status,
                feature_fallback_visible,
                feature_policy_snapshot,
            )
        },
    );

    let telemetry = h_stack((
        label(move || format!("CPU {}%", cpu_percent.get())),
        label(move || format!("GPU {}%", gpu_percent.get())),
        label(move || format!("RAM {} MB", ram_used.get())),
        label(move || format!("VRAM {} MB", vram_used.get())),
    ))
    .style(|s| {
        s.width_full()
            .padding(8.0)
            .gap(18.0)
            .background(theme::surface_1())
            .color(theme::text_secondary())
    });

    v_stack((command_row, content, telemetry))
        .style(|s| s.size_full().background(theme::window_bg()).row_gap(6.0))
}

#[allow(clippy::too_many_arguments)]
fn main_surface_content(
    view: PrimaryView,
    resources: Rc<RefCell<ResourceManager>>,
    queue: Rc<RefCell<JobQueue>>,
    workspace: Rc<WorkspaceHost>,
    code_file_list: RwSignal<String>,
    code_editor_path: RwSignal<String>,
    code_editor_preview: RwSignal<String>,
    code_editor_append: RwSignal<String>,
    code_search_query: RwSignal<String>,
    code_search_results: RwSignal<String>,
    code_git_summary: RwSignal<String>,
    code_terminal_command: RwSignal<String>,
    code_terminal_output: RwSignal<String>,
    terminal_sessions: Rc<RefCell<TerminalSessionManager>>,
    code_terminal_session_id: RwSignal<Option<u64>>,
    code_terminal_session_state: RwSignal<String>,
    code_terminal_stream_output: RwSignal<String>,
    code_terminal_stdin: RwSignal<String>,
    code_queue_status: RwSignal<String>,
    queued_jobs: RwSignal<u32>,
    running_jobs: RwSignal<u32>,
    completed_jobs: RwSignal<u32>,
    failed_jobs: RwSignal<u32>,
    cancelled_jobs: RwSignal<u32>,
    runtime_version: RwSignal<String>,
    runtime_health: RwSignal<String>,
    runtime_process_state: RwSignal<String>,
    runtime_vulkan_memory_status: RwSignal<String>,
    runtime_vulkan_validation_status: RwSignal<String>,
    llama_host: RwSignal<String>,
    llama_port: RwSignal<String>,
    chat_prompt: RwSignal<String>,
    chat_n_predict: RwSignal<String>,
    chat_output: RwSignal<String>,
    chat_status: RwSignal<String>,
    chat_confidential_measurement: RwSignal<String>,
    chat_confidential_policy_mode: RwSignal<String>,
    chat_confidential_max_attestation_age_ms: RwSignal<String>,
    chat_confidential_profile_window: RwSignal<String>,
    chat_confidential_require_cpu: RwSignal<bool>,
    chat_confidential_require_gpu: RwSignal<bool>,
    chat_confidential_allow_remote_fallback: RwSignal<bool>,
    chat_confidential_status: RwSignal<String>,
    chat_routed_baseline_latency_ms: RwSignal<Option<u64>>,
    media_prompt: RwSignal<String>,
    media_seed: RwSignal<String>,
    media_batch_size: RwSignal<String>,
    media_status: RwSignal<String>,
    media_gallery: RwSignal<String>,
    media_next_asset_id: RwSignal<u64>,
    video_prompt: RwSignal<String>,
    video_seed: RwSignal<String>,
    video_batch_size: RwSignal<String>,
    video_duration_seconds: RwSignal<String>,
    video_status: RwSignal<String>,
    video_checkpoint_log: RwSignal<String>,
    video_checkpoint_state: Rc<RefCell<HashMap<u64, VideoCheckpointState>>>,
    runtimes: Rc<RefCell<RuntimeRegistry>>,
    source_registry: Rc<RefCell<SourceRegistry>>,
    confidential_relay_sessions: Rc<RefCell<ConfidentialRelaySessionStore>>,
    model_source_target: RwSignal<String>,
    model_source_role: RwSignal<String>,
    model_confidential_verifier_endpoint: RwSignal<String>,
    model_confidential_expected_provider: RwSignal<String>,
    model_confidential_measurement_prefixes: RwSignal<String>,
    model_confidential_timeout_ms: RwSignal<String>,
    model_confidential_api_key_env_var: RwSignal<String>,
    model_source_status: RwSignal<String>,
    agent_orchestrator: Rc<RefCell<AgentOrchestrator>>,
    active_agent_run_id: RwSignal<Option<u64>>,
    agent_status_line: RwSignal<String>,
    agent_steps_line: RwSignal<String>,
    agent_trace_line: RwSignal<String>,
    agent_trace_filter_query: RwSignal<String>,
    agent_trace_filter_kind: RwSignal<String>,
    agent_trace_filter_role: RwSignal<String>,
    agent_codex_prompt: RwSignal<String>,
    agent_codex_auto: RwSignal<bool>,
    agent_codex_max_tokens: RwSignal<String>,
    agent_codex_status: RwSignal<String>,
    agent_codex_output: RwSignal<String>,
    agent_memory_store: Rc<RefCell<ProjectMemoryStore>>,
    agent_memory_scope: RwSignal<String>,
    agent_memory_key: RwSignal<String>,
    agent_memory_value: RwSignal<String>,
    agent_memory_query: RwSignal<String>,
    agent_memory_status: RwSignal<String>,
    agent_memory_output: RwSignal<String>,
    extension_host: Rc<RefCell<ExtensionHost>>,
    extension_target: RwSignal<String>,
    extension_status: RwSignal<String>,
    cpu_percent: RwSignal<u32>,
    ram_used: RwSignal<u32>,
    vram_used: RwSignal<u32>,
    ram_budget: RwSignal<u32>,
    vram_budget: RwSignal<u32>,
    spill_hint: RwSignal<String>,
    feature_registry: Rc<RefCell<FeaturePolicyRegistry>>,
    feature_target: RwSignal<String>,
    feature_policy_status: RwSignal<String>,
    feature_fallback_visible: RwSignal<bool>,
    feature_policy_snapshot: RwSignal<String>,
) -> AnyView {
    match view {
        PrimaryView::Workspace => v_stack((
            label(|| "Workspace"),
            label(move || workspace.root().display().to_string()),
        ))
        .style(|s| s.size_full().padding(12.0).row_gap(6.0))
        .into_any(),
        PrimaryView::Code => code_studio_panel(
            workspace,
            queue,
            queued_jobs,
            running_jobs,
            completed_jobs,
            failed_jobs,
            cancelled_jobs,
            code_file_list,
            code_editor_path,
            code_editor_preview,
            code_editor_append,
            code_search_query,
            code_search_results,
            code_git_summary,
            code_terminal_command,
            code_terminal_output,
            terminal_sessions,
            code_terminal_session_id,
            code_terminal_session_state,
            code_terminal_stream_output,
            code_terminal_stdin,
            code_queue_status,
        )
        .into_any(),
        PrimaryView::Chat => chat_panel(
            runtime_version,
            runtime_health,
            runtime_process_state,
            llama_host,
            llama_port,
            chat_prompt,
            chat_n_predict,
            chat_output,
            chat_status,
            chat_confidential_measurement,
            chat_confidential_policy_mode,
            chat_confidential_max_attestation_age_ms,
            chat_confidential_profile_window,
            chat_confidential_require_cpu,
            chat_confidential_require_gpu,
            chat_confidential_allow_remote_fallback,
            chat_confidential_status,
            chat_routed_baseline_latency_ms,
            source_registry,
            confidential_relay_sessions,
            feature_registry,
            queue.clone(),
            queued_jobs,
            running_jobs,
            completed_jobs,
            failed_jobs,
            cancelled_jobs,
        )
        .into_any(),
        PrimaryView::Models => model_studio_panel(
            runtime_version,
            runtime_health,
            runtime_vulkan_memory_status,
            runtime_vulkan_validation_status,
            runtimes,
            source_registry,
            model_source_target,
            model_source_role,
            model_confidential_verifier_endpoint,
            model_confidential_expected_provider,
            model_confidential_measurement_prefixes,
            model_confidential_timeout_ms,
            model_confidential_api_key_env_var,
            model_source_status,
        )
        .into_any(),
        PrimaryView::Agents => agent_studio_panel(
            workspace,
            agent_orchestrator,
            source_registry,
            queue.clone(),
            queued_jobs,
            running_jobs,
            completed_jobs,
            failed_jobs,
            cancelled_jobs,
            llama_host,
            llama_port,
            active_agent_run_id,
            agent_status_line,
            agent_steps_line,
            agent_trace_line,
            agent_trace_filter_query,
            agent_trace_filter_kind,
            agent_trace_filter_role,
            agent_codex_prompt,
            agent_codex_auto,
            agent_codex_max_tokens,
            agent_codex_status,
            agent_codex_output,
            agent_memory_store,
            agent_memory_scope,
            agent_memory_key,
            agent_memory_value,
            agent_memory_query,
            agent_memory_status,
            agent_memory_output,
            code_editor_path,
        )
        .into_any(),
        PrimaryView::Media => media_studio_panel(
            queue,
            queued_jobs,
            running_jobs,
            completed_jobs,
            failed_jobs,
            cancelled_jobs,
            media_prompt,
            media_seed,
            media_batch_size,
            media_status,
            media_gallery,
            media_next_asset_id,
            video_prompt,
            video_seed,
            video_batch_size,
            video_duration_seconds,
            video_status,
            video_checkpoint_log,
            video_checkpoint_state,
            source_registry,
        )
        .into_any(),
        PrimaryView::Jobs => v_stack((jobs_panel(
            queue,
            queued_jobs,
            running_jobs,
            completed_jobs,
            failed_jobs,
            cancelled_jobs,
        ),))
        .style(|s| s.size_full().padding(12.0).row_gap(6.0))
        .into_any(),
        PrimaryView::Extensions => extensions_panel(
            extension_host,
            extension_target,
            extension_status,
            resources,
            ram_used,
            vram_used,
            ram_budget,
            vram_budget,
            cpu_percent,
            spill_hint,
        )
        .into_any(),
        PrimaryView::Settings => v_stack((
            label(|| "Settings"),
            settings_panel(
                workspace,
                feature_registry,
                feature_target,
                feature_policy_status,
                feature_fallback_visible,
                feature_policy_snapshot,
                runtimes,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            ),
        ))
        .style(|s| s.size_full().padding(12.0).row_gap(6.0))
        .into_any(),
    }
}

