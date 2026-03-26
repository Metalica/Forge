#[allow(clippy::too_many_arguments)]
fn inspector_panel(
    resources: Rc<RefCell<ResourceManager>>,
    queue: Rc<RefCell<JobQueue>>,
    queued_jobs: RwSignal<u32>,
    running_jobs: RwSignal<u32>,
    completed_jobs: RwSignal<u32>,
    failed_jobs: RwSignal<u32>,
    cancelled_jobs: RwSignal<u32>,
    runtimes: Rc<RefCell<RuntimeRegistry>>,
    runtime_processes: Rc<RefCell<RuntimeProcessManager>>,
    feature_registry: Rc<RefCell<FeaturePolicyRegistry>>,
    runtime_version: RwSignal<String>,
    runtime_health: RwSignal<String>,
    runtime_process_state: RwSignal<String>,
    runtime_process_pid: RwSignal<String>,
    runtime_profile_status: RwSignal<String>,
    runtime_vulkan_memory_status: RwSignal<String>,
    runtime_vulkan_validation_status: RwSignal<String>,
    llama_model_path: RwSignal<String>,
    llama_host: RwSignal<String>,
    llama_port: RwSignal<String>,
    llama_ctx_size: RwSignal<String>,
    llama_threads: RwSignal<String>,
    llama_gpu_layers: RwSignal<String>,
    llama_batch_size: RwSignal<String>,
    cpu_percent: RwSignal<u32>,
    ram_used: RwSignal<u32>,
    vram_used: RwSignal<u32>,
    ram_budget: RwSignal<u32>,
    vram_budget: RwSignal<u32>,
    spill_hint: RwSignal<String>,
    feature_policy_status: RwSignal<String>,
    feature_fallback_visible: RwSignal<bool>,
    feature_policy_snapshot: RwSignal<String>,
) -> impl IntoView {
    let reserve_vram = {
        let resources = resources.clone();
        move || {
            let mut resource_manager = resources.borrow_mut();
            let _ = resource_manager.reserve_vram(256);
            resource_manager.log_transfer(
                TransferKind::RamToVram,
                256 * 1024 * 1024,
                "phase1-demo",
            );
            sync_resource_metrics(
                &resource_manager,
                ram_used,
                vram_used,
                cpu_percent,
                ram_budget,
                vram_budget,
                spill_hint,
            );
        }
    };

    let release_vram = {
        let resources = resources.clone();
        move || {
            let mut resource_manager = resources.borrow_mut();
            resource_manager.release_vram(256);
            resource_manager.log_transfer(
                TransferKind::VramToRam,
                256 * 1024 * 1024,
                "phase1-demo",
            );
            sync_resource_metrics(
                &resource_manager,
                ram_used,
                vram_used,
                cpu_percent,
                ram_budget,
                vram_budget,
                spill_hint,
            );
        }
    };

    let update_runtime = {
        let queue = queue.clone();
        let runtimes = runtimes.clone();
        let feature_registry = feature_registry.clone();
        move || {
            let tracked_job_id = queue_start_tracked_job(
                &queue,
                "inspector-runtime-update".to_string(),
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
                    ("runtime metadata updated to 0.1.0-phase1".to_string(), None)
                }
                UpdateResult::AlreadyCurrent => {
                    ("runtime already at 0.1.0-phase1".to_string(), None)
                }
                UpdateResult::BlockedByPin => (
                    "runtime update blocked: version is pinned".to_string(),
                    Some("runtime update blocked by pin".to_string()),
                ),
                UpdateResult::RuntimeNotFound => (
                    "runtime update failed: runtime not found".to_string(),
                    Some("runtime update failed: runtime not found".to_string()),
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

    let rollback_runtime = {
        let runtimes = runtimes.clone();
        let feature_registry = feature_registry.clone();
        move || {
            let mut runtime_registry = runtimes.borrow_mut();
            let rolled_back = runtime_registry.rollback("llama.cpp");
            sync_runtime_metrics(&runtime_registry, runtime_version, runtime_health);
            let registry_ref = feature_registry.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry,
                &registry_ref,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
            runtime_profile_status.set(if rolled_back {
                "runtime rollback applied".to_string()
            } else {
                "runtime rollback unavailable".to_string()
            });
            drop(runtime_registry);
            persist_runtime_registry_with_notice(&runtimes, runtime_profile_status);
        }
    };

    let pin_runtime = {
        let runtimes = runtimes.clone();
        move || {
            let mut runtime_registry = runtimes.borrow_mut();
            let pinned = runtime_registry.set_pinned_version("llama.cpp", true);
            sync_runtime_metrics(&runtime_registry, runtime_version, runtime_health);
            runtime_profile_status.set(if pinned {
                "runtime version pinned".to_string()
            } else {
                "pin failed: runtime not found".to_string()
            });
            drop(runtime_registry);
            persist_runtime_registry_with_notice(&runtimes, runtime_profile_status);
        }
    };

    let unpin_runtime = {
        let runtimes = runtimes.clone();
        move || {
            let mut runtime_registry = runtimes.borrow_mut();
            let unpinned = runtime_registry.set_pinned_version("llama.cpp", false);
            sync_runtime_metrics(&runtime_registry, runtime_version, runtime_health);
            runtime_profile_status.set(if unpinned {
                "runtime version unpinned".to_string()
            } else {
                "unpin failed: runtime not found".to_string()
            });
            drop(runtime_registry);
            persist_runtime_registry_with_notice(&runtimes, runtime_profile_status);
        }
    };

    let record_runtime_benchmark = {
        let runtimes = runtimes.clone();
        let feature_registry = feature_registry.clone();
        move || {
            let mut runtime_registry = runtimes.borrow_mut();
            let is_running = runtime_process_state.get().contains("Running");
            let success = !runtime_health.get().contains("Unavailable");
            let latency_ms = if is_running { 118 } else { 265 };
            let tps = if is_running { Some(42) } else { Some(17) };
            let recorded = runtime_registry.record_benchmark(
                "llama.cpp",
                if is_running {
                    "vulkan_chat_completion_live"
                } else {
                    "vulkan_chat_completion_cold"
                },
                latency_ms,
                tps,
                success,
            );
            sync_runtime_metrics(&runtime_registry, runtime_version, runtime_health);
            if recorded {
                let gate_note = {
                    let mut registry_mut = feature_registry.borrow_mut();
                    let note = apply_vulkan_benchmark_gate_from_registry(
                        &runtime_registry,
                        &mut registry_mut,
                    );
                    feature_policy_snapshot.set(format_feature_policy_snapshot(
                        &registry_mut,
                        feature_fallback_visible.get(),
                    ));
                    note
                };
                {
                    let registry_ref = feature_registry.borrow();
                    sync_runtime_vulkan_card_status(
                        &runtime_registry,
                        &registry_ref,
                        runtime_vulkan_memory_status,
                        runtime_vulkan_validation_status,
                    );
                }
                feature_policy_status.set(format!("vulkan benchmark gate: {gate_note}"));
                runtime_profile_status.set(format!(
                    "benchmark recorded: {} ms {} | gate: {}",
                    latency_ms,
                    if success { "(ok)" } else { "(degraded)" },
                    clip_text(&gate_note, 110),
                ));
            } else {
                runtime_profile_status
                    .set("benchmark record failed: runtime not found".to_string());
            }
            drop(runtime_registry);
            persist_runtime_registry_with_notice(&runtimes, runtime_profile_status);
        }
    };

    let start_runtime = {
        let queue = queue.clone();
        let runtimes = runtimes.clone();
        let runtime_processes = runtime_processes.clone();
        let feature_registry = feature_registry.clone();
        move || {
            let tracked_job_id = queue_start_tracked_job(
                &queue,
                "inspector-runtime-start".to_string(),
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
                    "vulkan memory policy inactive: forcing gpu-layers=0",
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
            match launch_request {
                Ok(request) => {
                    runtime_profile_status.set(format!(
                        "profile ok: model={} host={} port={}",
                        llama_model_path.get(),
                        llama_host.get(),
                        llama_port.get()
                    ));
                    let mut process_manager = runtime_processes.borrow_mut();
                    let start_result = process_manager.start("llama.cpp", &request);
                    if matches!(start_result, StartResult::LaunchFailed) {
                        let attempted_gpu_layers = llama_gpu_layers
                            .get()
                            .trim()
                            .parse::<u16>()
                            .ok()
                            .unwrap_or(0);
                        if attempted_gpu_layers > 0 {
                            llama_gpu_layers.set(String::from("0"));
                            let fallback_request = {
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

                            match fallback_request {
                                Ok(retry_request) => {
                                    let retry_result =
                                        process_manager.start("llama.cpp", &retry_request);
                                    let notice = {
                                        let mut registry_mut = feature_registry.borrow_mut();
                                        let note = registry_mut
                                            .apply_runtime_safety_fallback(
                                                FeatureId::VulkanMemoryAllocator,
                                                RuntimeSafetyTrigger::RepeatedValidationFailure,
                                            )
                                            .unwrap_or_else(|_| {
                                                String::from(
                                                    "vulkan memory allocator moved to fallback",
                                                )
                                            });
                                        feature_policy_snapshot.set(
                                            format_feature_policy_snapshot(
                                                &registry_mut,
                                                feature_fallback_visible.get(),
                                            ),
                                        );
                                        note
                                    };
                                    feature_policy_status.set(notice.clone());
                                    if matches!(
                                        retry_result,
                                        StartResult::Started | StartResult::AlreadyRunning
                                    ) {
                                        runtime_profile_status.set(format!(
                                            "GPU launch failed; safe CPU fallback started ({notice})"
                                        ));
                                    } else {
                                        runtime_profile_status.set(format!(
                                            "GPU launch failed and fallback retry failed ({notice})"
                                        ));
                                    }
                                }
                                Err(error) => {
                                    runtime_profile_status
                                        .set(format!("fallback profile invalid: {error}"));
                                    let notice = {
                                        let mut registry_mut = feature_registry.borrow_mut();
                                        let note = registry_mut
                                            .apply_runtime_safety_fallback(
                                                FeatureId::VulkanMemoryAllocator,
                                                RuntimeSafetyTrigger::RuntimeError(format!(
                                                    "fallback profile invalid: {error}"
                                                )),
                                            )
                                            .unwrap_or_else(|_| {
                                                String::from(
                                                    "vulkan memory allocator moved to fallback",
                                                )
                                            });
                                        feature_policy_snapshot.set(
                                            format_feature_policy_snapshot(
                                                &registry_mut,
                                                feature_fallback_visible.get(),
                                            ),
                                        );
                                        note
                                    };
                                    feature_policy_status.set(notice);
                                }
                            }
                        } else {
                            runtime_profile_status.set(String::from("runtime launch failed"));
                        }
                    }
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
                }
                Err(error) => {
                    runtime_profile_status.set(format!("profile invalid: {error}"));
                    runtime_process_state.set(String::from("launch aborted"));
                }
            }
            let status_note = runtime_profile_status.get();
            let status_lower = status_note.to_lowercase();
            let is_failure = runtime_process_state.get().contains("launch aborted")
                || status_lower.contains("invalid")
                || (status_lower.contains("failed")
                    && !status_lower.contains("safe cpu fallback started"));
            if is_failure {
                let _ = queue_fail_tracked_job(
                    &queue,
                    tracked_job_id,
                    clip_text(&status_note, 120),
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

    let stop_runtime = {
        let queue = queue.clone();
        let runtimes = runtimes.clone();
        let runtime_processes = runtime_processes.clone();
        let feature_registry = feature_registry.clone();
        move || {
            let tracked_job_id = queue_start_tracked_job(
                &queue,
                "inspector-runtime-stop".to_string(),
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
                StopResult::Stopped => ("runtime stop requested for llama.cpp".to_string(), None),
                StopResult::NotRunning => (
                    "runtime stop skipped: process not running".to_string(),
                    None,
                ),
                StopResult::UnknownRuntime => (
                    "runtime stop failed: runtime missing".to_string(),
                    Some("runtime stop failed: runtime missing".to_string()),
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

    let poll_runtime = {
        let queue = queue.clone();
        let runtimes = runtimes.clone();
        let runtime_processes = runtime_processes.clone();
        let feature_registry = feature_registry.clone();
        move || {
            let tracked_job_id = queue_start_tracked_job(
                &queue,
                "inspector-runtime-poll".to_string(),
                JobKind::SystemTask,
                JobPriority::Background,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, runtime_profile_status);
            let mut process_manager = runtime_processes.borrow_mut();
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
            let _ = queue_complete_tracked_job(
                &queue,
                tracked_job_id,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            runtime_profile_status.set(format!(
                "runtime poll completed [job #{}]",
                tracked_job_id.raw()
            ));
            persist_job_queue_with_notice(&queue, runtime_profile_status);
        }
    };

    let launch_profile_inputs = v_stack((
        label(|| "llama.cpp Launch Profile"),
        h_stack((
            label(|| "Model"),
            text_input(llama_model_path).style(|s| s.min_width(200.0).padding(6.0).color(theme::input_text())),
        ))
        .style(|s| s.gap(6.0)),
        h_stack((
            label(|| "Host"),
            text_input(llama_host).style(|s| s.min_width(120.0).padding(6.0).color(theme::input_text())),
            label(|| "Port"),
            text_input(llama_port).style(|s| s.min_width(70.0).padding(6.0).color(theme::input_text())),
        ))
        .style(|s| s.gap(6.0)),
        h_stack((
            label(|| "Ctx"),
            text_input(llama_ctx_size).style(|s| s.min_width(70.0).padding(6.0).color(theme::input_text())),
            label(|| "Threads"),
            text_input(llama_threads).style(|s| s.min_width(70.0).padding(6.0).color(theme::input_text())),
        ))
        .style(|s| s.gap(6.0)),
        h_stack((
            label(|| "GPU layers"),
            text_input(llama_gpu_layers).style(|s| s.min_width(70.0).padding(6.0).color(theme::input_text())),
            label(|| "Batch"),
            text_input(llama_batch_size).style(|s| s.min_width(70.0).padding(6.0).color(theme::input_text())),
        ))
        .style(|s| s.gap(6.0)),
    ))
    .style(|s| s.row_gap(6.0));
    let reserve_vram = guarded_ui_action(
        "inspector.reserve_vram",
        Some(runtime_profile_status),
        reserve_vram,
    );
    let release_vram = guarded_ui_action(
        "inspector.release_vram",
        Some(runtime_profile_status),
        release_vram,
    );
    let update_runtime = guarded_ui_action(
        "inspector.update_runtime",
        Some(runtime_profile_status),
        update_runtime,
    );
    let rollback_runtime = guarded_ui_action(
        "inspector.rollback_runtime",
        Some(runtime_profile_status),
        rollback_runtime,
    );
    let pin_runtime = guarded_ui_action(
        "inspector.pin_runtime",
        Some(runtime_profile_status),
        pin_runtime,
    );
    let unpin_runtime = guarded_ui_action(
        "inspector.unpin_runtime",
        Some(runtime_profile_status),
        unpin_runtime,
    );
    let record_runtime_benchmark = guarded_ui_action(
        "inspector.record_benchmark",
        Some(runtime_profile_status),
        record_runtime_benchmark,
    );
    let start_runtime = guarded_ui_action(
        "inspector.start_runtime",
        Some(runtime_profile_status),
        start_runtime,
    );
    let stop_runtime = guarded_ui_action(
        "inspector.stop_runtime",
        Some(runtime_profile_status),
        stop_runtime,
    );
    let poll_runtime = guarded_ui_action(
        "inspector.poll_runtime",
        Some(runtime_profile_status),
        poll_runtime,
    );

    let runtime_identity = v_stack((
        label(|| "Inspector"),
        label(move || format!("Runtime: {}", runtime_version.get())),
        label(move || format!("Health: {}", runtime_health.get())),
        label({
            let runtimes = runtimes.clone();
            move || {
                match runtimes.try_borrow() {
                    Ok(registry) => match registry.get("llama.cpp") {
                        Some(entry) => format!(
                            "Backend Badge: {}",
                            format_runtime_backend_badge(entry.backend)
                        ),
                        None => "Backend Badge: unavailable".to_string(),
                    },
                    Err(_) => "Backend Badge: busy".to_string(),
                }
            }
        }),
        label({
            let runtimes = runtimes.clone();
            move || {
                match runtimes.try_borrow() {
                    Ok(registry) => format!(
                        "Pin/Rollback: {}",
                        format_runtime_pin_rollback_summary(&registry, "llama.cpp")
                    ),
                    Err(_) => "Pin/Rollback: busy".to_string(),
                }
            }
        })
        .style(|s| s.color(theme::text_secondary())),
        label({
            let runtimes = runtimes.clone();
            move || {
                match runtimes.try_borrow() {
                    Ok(registry) => format!(
                        "Benchmark History: {}",
                        format_runtime_benchmark_summary(&registry, "llama.cpp")
                    ),
                    Err(_) => "Benchmark History: busy".to_string(),
                }
            }
        })
        .style(|s| s.color(theme::text_secondary())),
        label(move || format!("Process: {}", runtime_process_state.get())),
        label(move || format!("PID: {}", runtime_process_pid.get())),
        label(move || format!("Profile: {}", runtime_profile_status.get()))
            .style(|s| s.color(theme::text_secondary())),
        label(move || format!("Vulkan Memory: {}", runtime_vulkan_memory_status.get()))
            .style(|s| s.color(theme::text_secondary())),
        label(move || {
            format!(
                "Vulkan Validation: {}",
                runtime_vulkan_validation_status.get()
            )
        })
        .style(|s| s.color(theme::text_secondary())),
    ))
    .style(|s| s.row_gap(4.0));

    let runtime_controls = v_stack((
        h_stack((
            button("Start Runtime").action(start_runtime),
            button("Stop Runtime").action(stop_runtime),
            button("Poll").action(poll_runtime),
        ))
        .style(|s| s.gap(6.0)),
        button("Update Runtime").action(update_runtime),
        button("Rollback Runtime").action(rollback_runtime),
        h_stack((
            button("Pin Runtime").action(pin_runtime),
            button("Unpin Runtime").action(unpin_runtime),
            button("Record Bench").action(record_runtime_benchmark),
        ))
        .style(|s| s.gap(6.0)),
    ))
    .style(|s| s.row_gap(6.0));

    let resource_controls = v_stack((
        label({
            let resources = resources.clone();
            move || {
                match resources.try_borrow() {
                    Ok(resource_manager) => {
                        let usage = resource_manager.usage();
                        format!("CPU: {}/{}%", cpu_percent.get(), usage.cpu_budget_percent)
                    }
                    Err(_) => "CPU: busy".to_string(),
                }
            }
        }),
        label(move || format!("RAM: {}/{} MB", ram_used.get(), ram_budget.get())),
        label(move || format!("VRAM: {}/{} MB", vram_used.get(), vram_budget.get())),
        label(move || format!("Spill: {}", spill_hint.get())),
        h_stack((
            button("Reserve VRAM +256").action(reserve_vram),
            button("Release VRAM -256").action(release_vram),
        ))
        .style(|s| s.gap(6.0)),
    ))
    .style(|s| s.row_gap(4.0));

    v_stack((
        runtime_identity,
        launch_profile_inputs,
        runtime_controls,
        resource_controls,
    ))
    .style(|s| {
        s.width(340.0)
            .height_full()
            .padding(10.0)
            .row_gap(6.0)
            .background(theme::surface_2())
            .border_left(1.0)
    })
}

