const DANGEROUS_EXTENSION_CONTROLS_ENV: &str = "FORGE_ENABLE_DANGEROUS_EXTENSION_CONTROLS";

fn parse_opt_in_flag(value: Option<&str>) -> bool {
    let Some(raw) = value else {
        return false;
    };
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on" | "enable" | "enabled"
    )
}

fn dangerous_extension_controls_enabled() -> bool {
    parse_opt_in_flag(
        std::env::var(DANGEROUS_EXTENSION_CONTROLS_ENV)
            .ok()
            .as_deref(),
    )
}

#[allow(clippy::too_many_arguments)]
fn agent_studio_panel(
    workspace: Rc<WorkspaceHost>,
    agent_orchestrator: Rc<RefCell<AgentOrchestrator>>,
    source_registry: Rc<RefCell<SourceRegistry>>,
    queue: Rc<RefCell<JobQueue>>,
    queued_jobs: RwSignal<u32>,
    running_jobs: RwSignal<u32>,
    completed_jobs: RwSignal<u32>,
    failed_jobs: RwSignal<u32>,
    cancelled_jobs: RwSignal<u32>,
    llama_host: RwSignal<String>,
    llama_port: RwSignal<String>,
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
    agent_workspace_context_path: RwSignal<String>,
) -> impl IntoView {
    let create_run_action = {
        let agent_orchestrator = agent_orchestrator.clone();
        move || {
            {
                let mut orchestrator_mut = agent_orchestrator.borrow_mut();
                let run = create_default_agent_run(
                    &mut orchestrator_mut,
                    "Phase 2 Agent Studio run (manual trigger)",
                );
                match run {
                    Ok(run_id) => {
                        active_agent_run_id.set(Some(run_id));
                    }
                    Err(error) => {
                        agent_status_line.set(format!("new run failed: {error}"));
                    }
                }
                sync_agent_studio_signals(
                    &orchestrator_mut,
                    active_agent_run_id.get(),
                    agent_status_line,
                    agent_steps_line,
                    agent_trace_line,
                );
            }
            persist_agent_state_with_notice(
                &agent_orchestrator,
                active_agent_run_id.get(),
                agent_status_line,
            );
        }
    };

    let start_next_action = {
        let workspace = workspace.clone();
        let agent_orchestrator = agent_orchestrator.clone();
        let source_registry = source_registry.clone();
        let agent_memory_store = agent_memory_store.clone();
        let queue = queue.clone();
        move || {
            let mut should_run_auto_codex = false;
            let mut should_run_auto_routed = false;
            {
                let mut orchestrator_mut = agent_orchestrator.borrow_mut();
                let Some(run_id) = active_agent_run_id.get() else {
                    agent_status_line.set(String::from("start skipped: no active run"));
                    return;
                };
                match orchestrator_mut.start_next_step(run_id) {
                    Ok(Some(step_id)) => {
                        if agent_codex_auto.get() {
                            if let Some(run) = orchestrator_mut.run(run_id) {
                                should_run_auto_codex =
                                    should_auto_run_codex_for_started_step(run, &step_id);
                                should_run_auto_routed =
                                    should_auto_run_routed_for_started_step(run, &step_id);
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        agent_status_line.set(format!("start failed: {error:?}"));
                    }
                }
                sync_agent_studio_signals(
                    &orchestrator_mut,
                    Some(run_id),
                    agent_status_line,
                    agent_steps_line,
                    agent_trace_line,
                );
            }
            if should_run_auto_codex {
                let _ = run_codex_specialist_for_active_coder_step(
                    &agent_orchestrator,
                    &source_registry,
                    &agent_memory_store,
                    active_agent_run_id.get(),
                    workspace.as_ref(),
                    agent_workspace_context_path.get().as_str(),
                    agent_codex_prompt,
                    agent_codex_max_tokens,
                    agent_codex_status,
                    agent_codex_output,
                    agent_memory_scope,
                    agent_memory_query,
                    agent_memory_status,
                    agent_status_line,
                    agent_steps_line,
                    agent_trace_line,
                    true,
                    &queue,
                    queued_jobs,
                    running_jobs,
                    completed_jobs,
                    failed_jobs,
                    cancelled_jobs,
                );
            }
            if should_run_auto_routed {
                let _ = run_routed_task_for_active_step(
                    &agent_orchestrator,
                    &source_registry,
                    active_agent_run_id.get(),
                    workspace.as_ref(),
                    agent_workspace_context_path.get().as_str(),
                    llama_host,
                    llama_port,
                    agent_codex_prompt,
                    agent_codex_max_tokens,
                    agent_codex_status,
                    agent_codex_output,
                    agent_status_line,
                    agent_steps_line,
                    agent_trace_line,
                    true,
                    &queue,
                    queued_jobs,
                    running_jobs,
                    completed_jobs,
                    failed_jobs,
                    cancelled_jobs,
                );
            }
            persist_agent_state_with_notice(
                &agent_orchestrator,
                active_agent_run_id.get(),
                agent_status_line,
            );
        }
    };

    let request_approval_action = {
        let agent_orchestrator = agent_orchestrator.clone();
        move || {
            {
                let mut orchestrator_mut = agent_orchestrator.borrow_mut();
                let Some(run_id) = active_agent_run_id.get() else {
                    agent_status_line.set(String::from("approval request skipped: no active run"));
                    return;
                };
                let running_approval_step = orchestrator_mut.run(run_id).and_then(|run| {
                    run.steps
                        .iter()
                        .find(|step| {
                            matches!(step.status, AgentStepStatus::Running)
                                && step.requires_approval
                        })
                        .map(|step| step.step_id.clone())
                });
                if let Some(step_id) = running_approval_step {
                    let _ = orchestrator_mut.request_approval(
                        run_id,
                        &step_id,
                        "manual approval requested from Agent Studio",
                    );
                } else {
                    agent_status_line.set(String::from(
                        "approval request skipped: no running approval-gated step",
                    ));
                }
                sync_agent_studio_signals(
                    &orchestrator_mut,
                    Some(run_id),
                    agent_status_line,
                    agent_steps_line,
                    agent_trace_line,
                );
            }
            persist_agent_state_with_notice(
                &agent_orchestrator,
                active_agent_run_id.get(),
                agent_status_line,
            );
        }
    };

    let approve_action = {
        let agent_orchestrator = agent_orchestrator.clone();
        move || {
            {
                let mut orchestrator_mut = agent_orchestrator.borrow_mut();
                let Some(run_id) = active_agent_run_id.get() else {
                    agent_status_line.set(String::from("approve skipped: no active run"));
                    return;
                };
                let waiting_step = orchestrator_mut.run(run_id).and_then(|run| {
                    run.steps
                        .iter()
                        .find(|step| matches!(step.status, AgentStepStatus::WaitingApproval))
                        .map(|step| step.step_id.clone())
                });
                if let Some(step_id) = waiting_step {
                    let _ = orchestrator_mut.resolve_approval(run_id, &step_id, true, "approved");
                } else {
                    agent_status_line.set(String::from("approve skipped: no waiting step"));
                }
                sync_agent_studio_signals(
                    &orchestrator_mut,
                    Some(run_id),
                    agent_status_line,
                    agent_steps_line,
                    agent_trace_line,
                );
            }
            persist_agent_state_with_notice(
                &agent_orchestrator,
                active_agent_run_id.get(),
                agent_status_line,
            );
        }
    };

    let deny_action = {
        let agent_orchestrator = agent_orchestrator.clone();
        move || {
            {
                let mut orchestrator_mut = agent_orchestrator.borrow_mut();
                let Some(run_id) = active_agent_run_id.get() else {
                    agent_status_line.set(String::from("deny skipped: no active run"));
                    return;
                };
                let waiting_step = orchestrator_mut.run(run_id).and_then(|run| {
                    run.steps
                        .iter()
                        .find(|step| matches!(step.status, AgentStepStatus::WaitingApproval))
                        .map(|step| step.step_id.clone())
                });
                if let Some(step_id) = waiting_step {
                    let _ = orchestrator_mut.resolve_approval(run_id, &step_id, false, "denied");
                } else {
                    agent_status_line.set(String::from("deny skipped: no waiting step"));
                }
                sync_agent_studio_signals(
                    &orchestrator_mut,
                    Some(run_id),
                    agent_status_line,
                    agent_steps_line,
                    agent_trace_line,
                );
            }
            persist_agent_state_with_notice(
                &agent_orchestrator,
                active_agent_run_id.get(),
                agent_status_line,
            );
        }
    };

    let complete_running_action = {
        let agent_orchestrator = agent_orchestrator.clone();
        move || {
            {
                let mut orchestrator_mut = agent_orchestrator.borrow_mut();
                let Some(run_id) = active_agent_run_id.get() else {
                    agent_status_line.set(String::from("complete skipped: no active run"));
                    return;
                };
                let running_step = orchestrator_mut.run(run_id).and_then(|run| {
                    run.steps
                        .iter()
                        .find(|step| matches!(step.status, AgentStepStatus::Running))
                        .map(|step| step.step_id.clone())
                });
                if let Some(step_id) = running_step {
                    let _ = orchestrator_mut.complete_step(
                        run_id,
                        &step_id,
                        format!("completed from Agent Studio action ({step_id})"),
                    );
                } else {
                    agent_status_line.set(String::from("complete skipped: no running step"));
                }
                sync_agent_studio_signals(
                    &orchestrator_mut,
                    Some(run_id),
                    agent_status_line,
                    agent_steps_line,
                    agent_trace_line,
                );
            }
            persist_agent_state_with_notice(
                &agent_orchestrator,
                active_agent_run_id.get(),
                agent_status_line,
            );
        }
    };

    let fail_running_action = {
        let agent_orchestrator = agent_orchestrator.clone();
        move || {
            {
                let mut orchestrator_mut = agent_orchestrator.borrow_mut();
                let Some(run_id) = active_agent_run_id.get() else {
                    agent_status_line.set(String::from("fail skipped: no active run"));
                    return;
                };
                let running_step = orchestrator_mut.run(run_id).and_then(|run| {
                    run.steps
                        .iter()
                        .find(|step| matches!(step.status, AgentStepStatus::Running))
                        .map(|step| step.step_id.clone())
                });
                if let Some(step_id) = running_step {
                    let _ =
                        orchestrator_mut.fail_step(run_id, &step_id, "manual fail action from ui");
                } else {
                    agent_status_line.set(String::from("fail skipped: no running step"));
                }
                sync_agent_studio_signals(
                    &orchestrator_mut,
                    Some(run_id),
                    agent_status_line,
                    agent_steps_line,
                    agent_trace_line,
                );
            }
            persist_agent_state_with_notice(
                &agent_orchestrator,
                active_agent_run_id.get(),
                agent_status_line,
            );
        }
    };

    let run_codex_specialist_action = {
        let workspace = workspace.clone();
        let agent_orchestrator = agent_orchestrator.clone();
        let source_registry = source_registry.clone();
        let agent_memory_store = agent_memory_store.clone();
        let queue = queue.clone();
        move || {
            let did_complete = run_codex_specialist_for_active_coder_step(
                &agent_orchestrator,
                &source_registry,
                &agent_memory_store,
                active_agent_run_id.get(),
                workspace.as_ref(),
                agent_workspace_context_path.get().as_str(),
                agent_codex_prompt,
                agent_codex_max_tokens,
                agent_codex_status,
                agent_codex_output,
                agent_memory_scope,
                agent_memory_query,
                agent_memory_status,
                agent_status_line,
                agent_steps_line,
                agent_trace_line,
                false,
                &queue,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            if did_complete {
                persist_agent_state_with_notice(
                    &agent_orchestrator,
                    active_agent_run_id.get(),
                    agent_status_line,
                );
            }
        }
    };

    let run_routed_active_step_action = {
        let workspace = workspace.clone();
        let agent_orchestrator = agent_orchestrator.clone();
        let source_registry = source_registry.clone();
        let queue = queue.clone();
        move || {
            let did_complete = run_routed_task_for_active_step(
                &agent_orchestrator,
                &source_registry,
                active_agent_run_id.get(),
                workspace.as_ref(),
                agent_workspace_context_path.get().as_str(),
                llama_host,
                llama_port,
                agent_codex_prompt,
                agent_codex_max_tokens,
                agent_codex_status,
                agent_codex_output,
                agent_status_line,
                agent_steps_line,
                agent_trace_line,
                false,
                &queue,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            if did_complete {
                persist_agent_state_with_notice(
                    &agent_orchestrator,
                    active_agent_run_id.get(),
                    agent_status_line,
                );
            }
        }
    };

    let filter_all_events = move || agent_trace_filter_kind.set(String::from("all"));
    let filter_run_events = move || agent_trace_filter_kind.set(String::from("run"));
    let filter_step_events = move || agent_trace_filter_kind.set(String::from("step"));
    let filter_approval_events = move || agent_trace_filter_kind.set(String::from("approval"));
    let filter_failure_events = move || agent_trace_filter_kind.set(String::from("failure"));

    let role_all = move || agent_trace_filter_role.set(String::from("all"));
    let role_planner = move || agent_trace_filter_role.set(String::from("planner"));
    let role_coder = move || agent_trace_filter_role.set(String::from("coder"));
    let role_debugger = move || agent_trace_filter_role.set(String::from("debugger"));
    let role_verifier = move || agent_trace_filter_role.set(String::from("verifier"));
    let codex_auto_on = move || agent_codex_auto.set(true);
    let codex_auto_off = move || agent_codex_auto.set(false);
    let create_run_action = guarded_ui_action(
        "agent.create_run",
        Some(agent_status_line),
        create_run_action,
    );
    let start_next_action = guarded_ui_action(
        "agent.start_next",
        Some(agent_status_line),
        start_next_action,
    );
    let request_approval_action = guarded_ui_action(
        "agent.request_approval",
        Some(agent_status_line),
        request_approval_action,
    );
    let approve_action = guarded_ui_action(
        "agent.approve",
        Some(agent_status_line),
        approve_action,
    );
    let deny_action = guarded_ui_action("agent.deny", Some(agent_status_line), deny_action);
    let complete_running_action = guarded_ui_action(
        "agent.complete_running",
        Some(agent_status_line),
        complete_running_action,
    );
    let fail_running_action = guarded_ui_action(
        "agent.fail_running",
        Some(agent_status_line),
        fail_running_action,
    );
    let run_codex_specialist_action = guarded_ui_action(
        "agent.run_codex_specialist",
        Some(agent_codex_status),
        run_codex_specialist_action,
    );
    let run_routed_active_step_action = guarded_ui_action(
        "agent.run_routed_active_step",
        Some(agent_codex_status),
        run_routed_active_step_action,
    );
    let codex_specialist_section = v_stack((
        label(|| "Agent Provider Adapter").style(|s| {
            s.padding_top(8.0)
                .font_size(13.0)
                .color(theme::text_secondary())
        }),
        h_stack((
            label(move || {
                format!(
                    "Policy: {}",
                    if agent_codex_auto.get() {
                        "Auto-run on coder/planner/debugger/verifier step start"
                    } else {
                        "Manual only"
                    }
                )
            }),
            button("Auto On").action(codex_auto_on),
            button("Auto Off").action(codex_auto_off),
        ))
        .style(|s| s.gap(6.0).items_center()),
        h_stack((
            label(|| "Prompt"),
            text_input(agent_codex_prompt).style(|s| s.min_width(480.0).padding(6.0).color(theme::input_text())),
            label(|| "Max Tokens"),
            text_input(agent_codex_max_tokens).style(|s| s.min_width(90.0).padding(6.0).color(theme::input_text())),
            button("Run Codex Specialist").action(run_codex_specialist_action),
            button("Run Active Routed Step").action(run_routed_active_step_action),
        ))
        .style(|s| s.gap(6.0).items_center()),
        label(move || format!("adapter status: {}", agent_codex_status.get()))
            .style(|s| s.color(theme::text_secondary())),
        scroll(label(move || agent_codex_output.get())).style(|s| {
            s.width_full()
                .height(120.0)
                .padding(8.0)
                .background(theme::surface_1())
        }),
    ))
    .style(|s| s.row_gap(6.0));

    let memory_save_action = {
        let agent_memory_store = agent_memory_store.clone();
        move || {
            let scope_text = agent_memory_scope.get();
            let scope = parse_memory_scope_input(scope_text.as_str());
            let Some(scope) = scope else {
                agent_memory_status.set(format!(
                    "memory save blocked: invalid scope '{}'",
                    clip_text(&scope_text, 40)
                ));
                return;
            };

            let mut store = agent_memory_store.borrow_mut();
            match store.upsert(
                scope,
                agent_memory_key.get(),
                agent_memory_value.get(),
                "agent_studio",
            ) {
                Ok(result) => {
                    let stats = store.stats();
                    agent_memory_status.set(format!(
                        "memory {}: id={} scope={} totals(session={}, project={}, workspace={})",
                        if result.created { "saved" } else { "updated" },
                        result.id,
                        scope.label(),
                        stats.session_entries,
                        stats.project_entries,
                        stats.workspace_entries
                    ));
                    drop(store);
                    persist_project_memory_with_notice(&agent_memory_store, agent_memory_status);
                }
                Err(error) => {
                    agent_memory_status.set(format!("memory save blocked: {error}"));
                }
            }
        }
    };

    let memory_recall_action = {
        let agent_memory_store = agent_memory_store.clone();
        move || {
            let scope_text = agent_memory_scope.get();
            let scope = parse_memory_scope_input(scope_text.as_str());
            let Some(scope) = scope else {
                agent_memory_status.set(format!(
                    "memory recall blocked: invalid scope '{}'",
                    clip_text(&scope_text, 40)
                ));
                return;
            };

            let mut store = agent_memory_store.borrow_mut();
            let hits = store.recall(scope, &agent_memory_query.get(), 8);
            if hits.is_empty() {
                agent_memory_output.set(String::from("no memory hits"));
                agent_memory_status
                    .set(format!("memory recall: no hits in scope={}", scope.label()));
                return;
            }
            let lines = hits
                .iter()
                .map(|hit| {
                    format!(
                        "- [{}] {}={} (source={} hits={})",
                        hit.scope.label(),
                        hit.key,
                        clip_text(&hit.value, 140),
                        hit.source,
                        hit.hit_count
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            agent_memory_output.set(lines);
            agent_memory_status.set(format!(
                "memory recall: {} hit(s) in scope={}",
                hits.len(),
                scope.label()
            ));
            drop(store);
            persist_project_memory_with_notice(&agent_memory_store, agent_memory_status);
        }
    };

    let memory_clear_scope_action = {
        let agent_memory_store = agent_memory_store.clone();
        move || {
            let scope_text = agent_memory_scope.get();
            let scope = parse_memory_scope_input(scope_text.as_str());
            let Some(scope) = scope else {
                agent_memory_status.set(format!(
                    "memory clear blocked: invalid scope '{}'",
                    clip_text(&scope_text, 40)
                ));
                return;
            };

            let mut store = agent_memory_store.borrow_mut();
            let removed = store.clear_scope(scope);
            let stats = store.stats();
            agent_memory_output.set(String::new());
            agent_memory_status.set(format!(
                "memory clear: removed {} entries from {} (remaining session={} project={} workspace={})",
                removed,
                scope.label(),
                stats.session_entries,
                stats.project_entries,
                stats.workspace_entries
            ));
            drop(store);
            persist_project_memory_with_notice(&agent_memory_store, agent_memory_status);
        }
    };
    let memory_save_action = guarded_ui_action(
        "agent.memory_save",
        Some(agent_memory_status),
        memory_save_action,
    );
    let memory_recall_action = guarded_ui_action(
        "agent.memory_recall",
        Some(agent_memory_status),
        memory_recall_action,
    );
    let memory_clear_scope_action = guarded_ui_action(
        "agent.memory_clear_scope",
        Some(agent_memory_status),
        memory_clear_scope_action,
    );

    let memory_scope_section = v_stack((
        label(|| "Memory Scope").style(|s| {
            s.padding_top(8.0)
                .font_size(13.0)
                .color(theme::text_secondary())
        }),
        h_stack((
            label(|| "Scope"),
            text_input(agent_memory_scope).style(|s| s.min_width(140.0).padding(6.0).color(theme::input_text())),
            label(|| "Key"),
            text_input(agent_memory_key).style(|s| s.min_width(220.0).padding(6.0).color(theme::input_text())),
            label(|| "Value"),
            text_input(agent_memory_value).style(|s| s.min_width(360.0).padding(6.0).color(theme::input_text())),
            button("Save Memory").action(memory_save_action),
        ))
        .style(|s| s.gap(6.0).items_center()),
        h_stack((
            label(|| "Recall Query"),
            text_input(agent_memory_query).style(|s| s.min_width(300.0).padding(6.0).color(theme::input_text())),
            button("Recall").action(memory_recall_action),
            button("Clear Scope").action(memory_clear_scope_action),
        ))
        .style(|s| s.gap(6.0).items_center()),
        label(move || format!("memory status: {}", agent_memory_status.get()))
            .style(|s| s.color(theme::text_secondary())),
        scroll(label(move || agent_memory_output.get())).style(|s| {
            s.width_full()
                .height(110.0)
                .padding(8.0)
                .background(theme::surface_1())
        }),
        label(|| "Allowed scopes: session | project | workspace")
            .style(|s| s.color(theme::text_secondary())),
    ))
    .style(|s| s.row_gap(6.0));

    let trace_section = v_stack((
        label(|| "Trace Filters").style(|s| {
            s.padding_top(6.0)
                .font_size(13.0)
                .color(theme::text_secondary())
        }),
        h_stack((
            label(|| "Query"),
            text_input(agent_trace_filter_query).style(|s| s.min_width(220.0).padding(6.0).color(theme::input_text())),
            label(|| "Kind"),
            button("All").action(filter_all_events),
            button("Run").action(filter_run_events),
            button("Step").action(filter_step_events),
            button("Approval").action(filter_approval_events),
            button("Failure").action(filter_failure_events),
        ))
        .style(|s| s.gap(6.0).items_center()),
        h_stack((
            label(|| "Role"),
            button("All").action(role_all),
            button("Planner").action(role_planner),
            button("Coder").action(role_coder),
            button("Debugger").action(role_debugger),
            button("Verifier").action(role_verifier),
        ))
        .style(|s| s.gap(6.0).items_center()),
        label(move || {
            format!(
                "active filters: kind={} role={} query={}",
                agent_trace_filter_kind.get(),
                agent_trace_filter_role.get(),
                if agent_trace_filter_query.get().trim().is_empty() {
                    "(none)".to_string()
                } else {
                    agent_trace_filter_query.get()
                }
            )
        })
        .style(|s| s.color(theme::text_secondary())),
        label(|| "Trace (Filtered)").style(|s| {
            s.padding_top(6.0)
                .font_size(13.0)
                .color(theme::text_secondary())
        }),
        label({
            let agent_orchestrator = agent_orchestrator.clone();
            move || {
                match agent_orchestrator.try_borrow() {
                    Ok(orchestrator_ref) => format_active_agent_trace_filtered(
                        &orchestrator_ref,
                        active_agent_run_id.get(),
                        &agent_trace_filter_query.get(),
                        &agent_trace_filter_kind.get(),
                        &agent_trace_filter_role.get(),
                    ),
                    Err(_) => String::from("trace unavailable: agent orchestrator busy"),
                }
            }
        })
        .style(|s| {
            s.font_family("Consolas".to_string())
                .line_height(1.35)
                .color(theme::text_primary())
        }),
        label(|| "Trace (Recent Raw)").style(|s| {
            s.padding_top(4.0)
                .font_size(13.0)
                .color(theme::text_secondary())
        }),
        label(move || agent_trace_line.get()).style(|s| {
            s.font_family("Consolas".to_string())
                .line_height(1.35)
                .color(theme::text_primary())
        }),
    ))
    .style(|s| s.row_gap(6.0));

    v_stack((
        label(|| "Agent Studio"),
        label(move || agent_status_line.get()).style(|s| s.color(theme::text_secondary())),
        h_stack((
            button("New Run").action(create_run_action),
            button("Start Next").action(start_next_action),
            button("Request Approval").action(request_approval_action),
            button("Approve").action(approve_action),
            button("Deny").action(deny_action),
            button("Complete Running").action(complete_running_action),
            button("Fail Running").action(fail_running_action),
        ))
        .style(|s| s.gap(6.0).items_center()),
        codex_specialist_section,
        memory_scope_section,
        label(|| "Sub-Agent Graph").style(|s| {
            s.padding_top(8.0)
                .font_size(13.0)
                .color(theme::text_secondary())
        }),
        label({
            let agent_orchestrator = agent_orchestrator.clone();
            move || {
                match agent_orchestrator.try_borrow() {
                    Ok(orchestrator_ref) => {
                        format_active_agent_graph(&orchestrator_ref, active_agent_run_id.get())
                    }
                    Err(_) => String::from("graph unavailable: agent orchestrator busy"),
                }
            }
        })
        .style(|s| {
            s.font_family("Consolas".to_string())
                .line_height(1.35)
                .color(theme::text_primary())
        }),
        label(|| "Steps").style(|s| {
            s.padding_top(8.0)
                .font_size(13.0)
                .color(theme::text_secondary())
        }),
        label(move || agent_steps_line.get()).style(|s| {
            s.font_family("Consolas".to_string())
                .line_height(1.4)
                .color(theme::text_primary())
        }),
        trace_section,
    ))
    .style(|s| s.size_full().padding(12.0).row_gap(6.0))
}

#[allow(clippy::too_many_arguments)]
fn extensions_panel(
    extension_host: Rc<RefCell<ExtensionHost>>,
    extension_target: RwSignal<String>,
    extension_status: RwSignal<String>,
    resources: Rc<RefCell<ResourceManager>>,
    ram_used: RwSignal<u32>,
    vram_used: RwSignal<u32>,
    ram_budget: RwSignal<u32>,
    vram_budget: RwSignal<u32>,
    cpu_percent: RwSignal<u32>,
    spill_hint: RwSignal<String>,
) -> impl IntoView {
    let enable_action = {
        let extension_host = extension_host.clone();
        let resources = resources.clone();
        move || {
            let target = extension_target.get().trim().to_string();
            if target.is_empty() {
                extension_status.set(String::from("enable skipped: extension id is empty"));
                return;
            }
            let mut host = extension_host.borrow_mut();
            let was_enabled = match host.get(target.as_str()) {
                Some(runtime) => matches!(runtime.state, ExtensionState::Enabled),
                None => {
                    extension_status.set(format!("extension not found: {target}"));
                    return;
                }
            };
            match host.set_enabled(target.as_str(), true) {
                Ok(()) => {
                    let sync_result = {
                        let mut resource_manager = resources.borrow_mut();
                        sync_extension_resource_overhead(
                            &host,
                            &mut resource_manager,
                            ram_used,
                            vram_used,
                            cpu_percent,
                            ram_budget,
                            vram_budget,
                            spill_hint,
                        )
                    };
                    match sync_result {
                        Ok(totals) => extension_status.set(format!(
                            "extension enabled: {target} (ext_ram_budget={}MB ext_cpu_budget={}%)",
                            totals.ram_budget_mb, totals.cpu_budget_percent
                        )),
                        Err(reason) => {
                            if !was_enabled {
                                let _ = host.set_enabled(target.as_str(), false);
                                let mut resource_manager = resources.borrow_mut();
                                let _ = sync_extension_resource_overhead(
                                    &host,
                                    &mut resource_manager,
                                    ram_used,
                                    vram_used,
                                    cpu_percent,
                                    ram_budget,
                                    vram_budget,
                                    spill_hint,
                                );
                            }
                            extension_status.set(format!(
                                "extension enable blocked by URM budget: {target} ({reason})"
                            ));
                        }
                    }
                }
                Err(error) => {
                    extension_status.set(format_extension_host_error(&target, &error));
                }
            }
            drop(host);
            persist_extension_host_with_notice(&extension_host, extension_status);
        }
    };

    let disable_action = {
        let extension_host = extension_host.clone();
        let resources = resources.clone();
        move || {
            let target = extension_target.get().trim().to_string();
            if target.is_empty() {
                extension_status.set(String::from("disable skipped: extension id is empty"));
                return;
            }
            let mut host = extension_host.borrow_mut();
            match host.set_enabled(target.as_str(), false) {
                Ok(()) => {
                    let mut resource_manager = resources.borrow_mut();
                    match sync_extension_resource_overhead(
                        &host,
                        &mut resource_manager,
                        ram_used,
                        vram_used,
                        cpu_percent,
                        ram_budget,
                        vram_budget,
                        spill_hint,
                    ) {
                        Ok(_) => extension_status.set(format!("extension disabled: {target}")),
                        Err(reason) => extension_status.set(format!(
                            "extension disabled but telemetry sync failed: {reason}"
                        )),
                    }
                }
                Err(error) => {
                    extension_status.set(format_extension_host_error(&target, &error));
                }
            }
            drop(host);
            persist_extension_host_with_notice(&extension_host, extension_status);
        }
    };

    let grant_permissions_action = {
        let extension_host = extension_host.clone();
        move || {
            if !dangerous_extension_controls_enabled() {
                extension_status.set(format!(
                    "grant blocked: dangerous extension controls are disabled in normal UX (set {}=1 for supervised sessions)",
                    DANGEROUS_EXTENSION_CONTROLS_ENV
                ));
                return;
            }
            let target = extension_target.get().trim().to_string();
            if target.is_empty() {
                extension_status.set(String::from("grant skipped: extension id is empty"));
                return;
            }
            let mut host = extension_host.borrow_mut();
            match host.grant_all_permissions(target.as_str()) {
                Ok(()) => extension_status.set(format!("permissions granted for: {target}")),
                Err(error) => {
                    extension_status.set(format_extension_host_error(&target, &error));
                }
            }
            drop(host);
            persist_extension_host_with_notice(&extension_host, extension_status);
        }
    };

    let revoke_permissions_action = {
        let extension_host = extension_host.clone();
        move || {
            let target = extension_target.get().trim().to_string();
            if target.is_empty() {
                extension_status.set(String::from("revoke skipped: extension id is empty"));
                return;
            }
            let mut host = extension_host.borrow_mut();
            match host.revoke_all_permissions(target.as_str()) {
                Ok(()) => extension_status.set(format!("permissions revoked for: {target}")),
                Err(error) => {
                    extension_status.set(format_extension_host_error(&target, &error));
                }
            }
            drop(host);
            persist_extension_host_with_notice(&extension_host, extension_status);
        }
    };

    let approve_overbroad_action = {
        let extension_host = extension_host.clone();
        move || {
            if !dangerous_extension_controls_enabled() {
                extension_status.set(format!(
                    "approve broad scope blocked: dangerous extension controls are disabled in normal UX (set {}=1 for supervised sessions)",
                    DANGEROUS_EXTENSION_CONTROLS_ENV
                ));
                return;
            }
            let target = extension_target.get().trim().to_string();
            if target.is_empty() {
                extension_status.set(String::from(
                    "approve broad scope skipped: extension id is empty",
                ));
                return;
            }
            let mut host = extension_host.borrow_mut();
            match host.set_overbroad_approved(target.as_str(), true) {
                Ok(()) => extension_status.set(format!(
                    "overbroad scope approval granted for: {target}"
                )),
                Err(error) => {
                    extension_status.set(format_extension_host_error(&target, &error));
                }
            }
            drop(host);
            persist_extension_host_with_notice(&extension_host, extension_status);
        }
    };

    let revoke_overbroad_action = {
        let extension_host = extension_host.clone();
        move || {
            let target = extension_target.get().trim().to_string();
            if target.is_empty() {
                extension_status.set(String::from(
                    "revoke broad scope skipped: extension id is empty",
                ));
                return;
            }
            let mut host = extension_host.borrow_mut();
            match host.set_overbroad_approved(target.as_str(), false) {
                Ok(()) => extension_status.set(format!(
                    "overbroad scope approval revoked for: {target}"
                )),
                Err(error) => {
                    extension_status.set(format_extension_host_error(&target, &error));
                }
            }
            drop(host);
            persist_extension_host_with_notice(&extension_host, extension_status);
        }
    };

    let isolate_action = {
        let extension_host = extension_host.clone();
        let resources = resources.clone();
        move || {
            let target = extension_target.get().trim().to_string();
            if target.is_empty() {
                extension_status.set(String::from("isolate skipped: extension id is empty"));
                return;
            }
            let mut host = extension_host.borrow_mut();
            match host.isolate_failure(target.as_str(), "manual isolation from UI") {
                Ok(()) => {
                    let mut resource_manager = resources.borrow_mut();
                    match sync_extension_resource_overhead(
                        &host,
                        &mut resource_manager,
                        ram_used,
                        vram_used,
                        cpu_percent,
                        ram_budget,
                        vram_budget,
                        spill_hint,
                    ) {
                        Ok(_) => extension_status.set(format!("extension isolated: {target}")),
                        Err(reason) => extension_status.set(format!(
                            "extension isolated but telemetry sync failed: {reason}"
                        )),
                    }
                }
                Err(error) => {
                    extension_status.set(format_extension_host_error(&target, &error));
                }
            }
            drop(host);
            persist_extension_host_with_notice(&extension_host, extension_status);
        }
    };

    let recover_action = {
        let extension_host = extension_host.clone();
        let resources = resources.clone();
        move || {
            let target = extension_target.get().trim().to_string();
            if target.is_empty() {
                extension_status.set(String::from("recover skipped: extension id is empty"));
                return;
            }
            let mut host = extension_host.borrow_mut();
            match host.recover_isolated(target.as_str()) {
                Ok(()) => {
                    let mut resource_manager = resources.borrow_mut();
                    match sync_extension_resource_overhead(
                        &host,
                        &mut resource_manager,
                        ram_used,
                        vram_used,
                        cpu_percent,
                        ram_budget,
                        vram_budget,
                        spill_hint,
                    ) {
                        Ok(_) => extension_status
                            .set(format!("extension recovered to disabled: {target}")),
                        Err(reason) => extension_status.set(format!(
                            "extension recovered but telemetry sync failed: {reason}"
                        )),
                    }
                }
                Err(error) => {
                    extension_status.set(format_extension_host_error(&target, &error));
                }
            }
            drop(host);
            persist_extension_host_with_notice(&extension_host, extension_status);
        }
    };

    let permission_check_action = {
        let extension_host = extension_host.clone();
        move || {
            let target = extension_target.get().trim().to_string();
            if target.is_empty() {
                extension_status.set(String::from(
                    "permission check skipped: extension id is empty",
                ));
                return;
            }
            let host = match extension_host.try_borrow() {
                Ok(value) => value,
                Err(error) => {
                    extension_status
                        .set(format!("permission check skipped: extension host busy ({error})"));
                    return;
                }
            };
            match host.permission_check(target.as_str()) {
                Ok(check) => {
                    if check.can_enable {
                        extension_status
                            .set(format!("permission check passed: {target} can be enabled"));
                    } else {
                        extension_status.set(format!(
                            "permission check blocked: {} missing {}",
                            target,
                            format_permission_list(&check.missing_permissions)
                        ));
                    }
                }
                Err(error) => {
                    extension_status.set(format_extension_host_error(&target, &error));
                }
            }
        }
    };
    let enable_action = guarded_ui_action(
        "extensions.enable",
        Some(extension_status),
        enable_action,
    );
    let disable_action = guarded_ui_action(
        "extensions.disable",
        Some(extension_status),
        disable_action,
    );
    let grant_permissions_action = guarded_ui_action(
        "extensions.grant_permissions",
        Some(extension_status),
        grant_permissions_action,
    );
    let revoke_permissions_action = guarded_ui_action(
        "extensions.revoke_permissions",
        Some(extension_status),
        revoke_permissions_action,
    );
    let approve_overbroad_action = guarded_ui_action(
        "extensions.approve_overbroad",
        Some(extension_status),
        approve_overbroad_action,
    );
    let revoke_overbroad_action = guarded_ui_action(
        "extensions.revoke_overbroad",
        Some(extension_status),
        revoke_overbroad_action,
    );
    let isolate_action = guarded_ui_action(
        "extensions.isolate",
        Some(extension_status),
        isolate_action,
    );
    let recover_action = guarded_ui_action(
        "extensions.recover",
        Some(extension_status),
        recover_action,
    );
    let permission_check_action = guarded_ui_action(
        "extensions.permission_check",
        Some(extension_status),
        permission_check_action,
    );

    v_stack((
        label(|| "Extensions"),
        label(|| "Sandbox + permissions are enforced through Extension Host policy")
            .style(|s| s.color(theme::text_secondary())),
        label(move || format!("status: {}", extension_status.get()))
            .style(|s| s.color(theme::text_secondary())),
        h_stack((
            label(|| "Target"),
            text_input(extension_target).style(|s| s.min_width(220.0).padding(6.0).color(theme::input_text())),
            button("Enable").action(enable_action),
            button("Disable").action(disable_action),
            button("Grant Required").action(grant_permissions_action),
            button("Revoke Required").action(revoke_permissions_action),
            button("Approve Broad Scope").action(approve_overbroad_action),
            button("Revoke Broad Scope").action(revoke_overbroad_action),
            button("Check Perms").action(permission_check_action),
            button("Isolate").action(isolate_action),
            button("Recover").action(recover_action),
        ))
        .style(|s| s.gap(6.0).items_center()),
        label({
            let extension_host = extension_host.clone();
            move || {
                match extension_host.try_borrow() {
                    Ok(host) => format_extension_inventory_summary(&host),
                    Err(_) => String::from("inventory: extension host busy"),
                }
            }
        })
        .style(|s| s.color(theme::text_secondary())),
        label(|| "Selected").style(|s| s.color(theme::text_secondary())),
        scroll(label({
            let extension_host = extension_host.clone();
            move || {
                match extension_host.try_borrow() {
                    Ok(host) => format_extension_target_detail(&host, extension_target.get().as_str()),
                    Err(_) => String::from("extension detail unavailable: host busy"),
                }
            }
        }))
        .style(|s| {
            s.width_full()
                .height(110.0)
                .padding(8.0)
                .background(theme::surface_1())
        }),
        label(|| "Inventory").style(|s| s.color(theme::text_secondary())),
        scroll(label({
            let extension_host = extension_host.clone();
            move || {
                match extension_host.try_borrow() {
                    Ok(host) => format_extension_inventory_detail(&host),
                    Err(_) => String::from("inventory detail unavailable: host busy"),
                }
            }
        }))
        .style(|s| {
            s.width_full()
                .height(220.0)
                .padding(8.0)
                .background(theme::surface_1())
        }),
    ))
    .style(|s| s.size_full().padding(12.0).row_gap(8.0))
}

#[allow(clippy::too_many_arguments)]
fn sync_extension_resource_overhead(
    host: &ExtensionHost,
    resource_manager: &mut ResourceManager,
    ram_used: RwSignal<u32>,
    vram_used: RwSignal<u32>,
    cpu_percent: RwSignal<u32>,
    ram_budget: RwSignal<u32>,
    vram_budget: RwSignal<u32>,
    spill_hint: RwSignal<String>,
) -> Result<ExtensionResourceTotals, String> {
    let totals = host.active_resource_totals();
    if !resource_manager.set_extension_overhead(totals.ram_budget_mb, totals.cpu_budget_percent) {
        let usage = resource_manager.usage();
        let base_ram_used = usage
            .ram_used_mb
            .saturating_sub(usage.extension_ram_used_mb);
        let base_cpu_used = usage
            .cpu_used_percent
            .saturating_sub(usage.extension_cpu_used_percent);
        let available_ram = usage.ram_budget_mb.saturating_sub(base_ram_used);
        let available_cpu = usage.cpu_budget_percent.saturating_sub(base_cpu_used);
        return Err(format!(
            "required ram={}MB cpu={}% available ram={}MB cpu={}%",
            totals.ram_budget_mb, totals.cpu_budget_percent, available_ram, available_cpu
        ));
    }

    sync_resource_metrics(
        resource_manager,
        ram_used,
        vram_used,
        cpu_percent,
        ram_budget,
        vram_budget,
        spill_hint,
    );
    Ok(totals)
}

fn format_extension_inventory_summary(host: &ExtensionHost) -> String {
    let entries = host.list();
    let total = entries.len();
    let enabled = entries
        .iter()
        .filter(|entry| matches!(entry.state, ExtensionState::Enabled))
        .count();
    let isolated = entries
        .iter()
        .filter(|entry| matches!(entry.state, ExtensionState::FailedIsolated))
        .count();
    let totals = host.active_resource_totals();
    format!(
        "inventory: total={} enabled={} isolated={} disabled={} ext_ram_budget={}MB ext_cpu_budget={}%",
        total,
        enabled,
        isolated,
        total.saturating_sub(enabled + isolated),
        totals.ram_budget_mb,
        totals.cpu_budget_percent
    )
}

fn format_extension_inventory_detail(host: &ExtensionHost) -> String {
    let entries = host.list();
    if entries.is_empty() {
        return "no extensions registered".to_string();
    }
    let mut lines = Vec::new();
    for entry in entries {
        let signature_status = if entry.manifest.signature.is_some() {
            "signed"
        } else {
            "unsigned"
        };
        lines.push(format!(
            "- {} ({}) state={} class={} publisher={} version={} min_forge={} signature={} revoked={} overbroad_approved={} budget={}MB cpu_budget={}% idle={}MB startup={}ms perms=[{}]",
            entry.manifest.id,
            entry.manifest.display_name,
            format_extension_state(entry.state),
            entry.manifest.class.label(),
            entry.manifest.publisher,
            entry.manifest.version,
            entry.manifest.minimum_forge_version,
            signature_status,
            entry.manifest.revoked,
            entry.overbroad_approved,
            entry.manifest.memory_budget_mb,
            entry.manifest.cpu_budget_percent,
            entry.manifest.idle_cost_mb,
            entry.manifest.startup_cost_ms,
            format_permission_list(&entry.manifest.requested_permissions)
        ));
    }
    lines.join("\n")
}

fn format_extension_target_detail(host: &ExtensionHost, target: &str) -> String {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return "select an extension id to view policy details".to_string();
    }
    let Some(entry) = host.get(trimmed) else {
        return format!("extension not found: {trimmed}");
    };
    let check = host.permission_check(trimmed);
    let permission_line = match check {
        Ok(result) => {
            if result.can_enable {
                "permission-check=pass".to_string()
            } else {
                format!(
                    "permission-check=blocked missing=[{}]",
                    format_permission_list(&result.missing_permissions)
                )
            }
        }
        Err(error) => format!(
            "permission-check=error {}",
            format_extension_host_error(trimmed, &error)
        ),
    };
    let granted_permissions = match host.permission_grants(trimmed) {
        Ok(grants) => {
            let granted = grants
                .into_iter()
                .filter(|entry| entry.granted)
                .map(|entry| entry.permission)
                .collect::<Vec<_>>();
            format_permission_list(&granted)
        }
        Err(error) => format!(
            "error:{}",
            clip_text(&format_extension_host_error(trimmed, &error), 80)
        ),
    };
    let overbroad_required = host
        .overbroad_approval_required(trimmed)
        .map(|value| value.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let signature_status = match entry.manifest.signature.as_ref() {
        Some(signature) => format!(
            "signed key_id={} algorithm={}",
            signature.key_id, signature.algorithm
        ),
        None => "unsigned".to_string(),
    };
    format!(
        "id={id}\nname={name}\nstate={state}\nclass={class}\npublisher={publisher}\nversion={version}\nminimum_forge_version={minimum_forge_version}\npackage_checksum_sha256={checksum}\nsignature={signature_status}\nrevoked={revoked}\noverbroad_approval_required={overbroad_required}\noverbroad_approved={overbroad_approved}\ncapabilities=[{capabilities}]\nside_effects=[{side_effects}]\nmemory_budget_mb={memory_budget}\ncpu_budget_percent={cpu_budget}\nrequires_network={network}\nbackground_activity={activity}\nrequested_permissions=[{permissions}]\ngranted_permissions=[{granted_permissions}]\n{permission_line}\nlast_error={last_error}",
        id = entry.manifest.id,
        name = entry.manifest.display_name,
        state = format_extension_state(entry.state),
        class = entry.manifest.class.label(),
        publisher = entry.manifest.publisher,
        version = entry.manifest.version,
        minimum_forge_version = entry.manifest.minimum_forge_version,
        checksum = entry.manifest.package_checksum_sha256,
        signature_status = signature_status,
        revoked = entry.manifest.revoked,
        overbroad_required = overbroad_required,
        overbroad_approved = entry.overbroad_approved,
        capabilities = format_string_list(&entry.manifest.declared_capabilities),
        side_effects = format_string_list(&entry.manifest.declared_side_effects),
        memory_budget = entry.manifest.memory_budget_mb,
        cpu_budget = entry.manifest.cpu_budget_percent,
        network = entry.manifest.requires_network,
        activity = entry.manifest.background_activity,
        permissions = format_permission_list(&entry.manifest.requested_permissions),
        granted_permissions = granted_permissions,
        permission_line = permission_line,
        last_error = entry
            .last_error
            .clone()
            .unwrap_or_else(|| "none".to_string())
    )
}

fn format_extension_state(state: ExtensionState) -> &'static str {
    match state {
        ExtensionState::Disabled => "disabled",
        ExtensionState::Enabled => "enabled",
        ExtensionState::FailedIsolated => "failed_isolated",
    }
}

fn format_permission_list(permissions: &[ExtensionPermission]) -> String {
    if permissions.is_empty() {
        return "none".to_string();
    }
    permissions
        .iter()
        .map(|permission| permission.label().to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn format_string_list(values: &[String]) -> String {
    if values.is_empty() {
        return "none".to_string();
    }
    let cleaned = values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if cleaned.is_empty() {
        return "none".to_string();
    }
    cleaned.join(",")
}

fn format_extension_host_error(target: &str, error: &ExtensionHostError) -> String {
    match error {
        ExtensionHostError::NotFound(id) => format!("extension not found: {}", clip_text(id, 80)),
        ExtensionHostError::InvalidManifest(reason) => {
            format!("manifest invalid for {target}: {}", clip_text(reason, 120))
        }
        ExtensionHostError::FailedIsolated(id) => {
            format!("extension {id} is isolated; recover before enable")
        }
        ExtensionHostError::QuarantineModeActive { action } => format!(
            "extension action blocked while quarantine mode is active: {}",
            clip_text(action, 80)
        ),
        ExtensionHostError::SecurityPolicyBlocked {
            extension_id,
            reason,
        } => format!(
            "extension {} blocked by manifest security policy: {}",
            extension_id,
            clip_text(reason, 120)
        ),
        ExtensionHostError::OverbroadApprovalRequired {
            extension_id,
            permissions,
        } => format!(
            "extension {} requires explicit broad-scope approval for permissions [{}]",
            extension_id,
            format_permission_list(permissions)
        ),
        ExtensionHostError::MissingPermissions {
            extension_id,
            missing,
        } => format!(
            "extension {} missing permissions [{}]",
            extension_id,
            format_permission_list(missing)
        ),
    }
}

fn parse_memory_scope_input(input: &str) -> Option<MemoryScope> {
    let normalized = input.trim().to_lowercase().replace('-', "_");
    match normalized.as_str() {
        "session" => Some(MemoryScope::Session),
        "project" => Some(MemoryScope::Project),
        "workspace" | "work_space" => Some(MemoryScope::Workspace),
        _ => None,
    }
}

fn parse_source_role_input(input: &str) -> Option<SourceRole> {
    let normalized = input.trim().to_lowercase().replace('-', "_");
    match normalized.as_str() {
        "chat" => Some(SourceRole::Chat),
        "planner" => Some(SourceRole::Planner),
        "coder" => Some(SourceRole::Coder),
        "codex_specialist" | "codex" => Some(SourceRole::CodexSpecialist),
        "debugger" => Some(SourceRole::Debugger),
        "verifier" => Some(SourceRole::Verifier),
        "image_generation" | "image" => Some(SourceRole::ImageGeneration),
        "video_generation" | "video" => Some(SourceRole::VideoGeneration),
        _ => None,
    }
}

fn create_default_agent_run(
    orchestrator: &mut AgentOrchestrator,
    goal: &str,
) -> Result<u64, String> {
    let graph = vec![
        AgentGraphNode::new(
            "planner",
            "Plan implementation",
            AgentRole::Planner,
            "Draft steps and acceptance checks for the requested change.",
        ),
        AgentGraphNode::new(
            "coder",
            "Implement code changes",
            AgentRole::Coder,
            "Apply changes and keep docs/tests synchronized.",
        )
        .with_dependencies(vec!["planner".to_string()])
        .with_approval(true),
        AgentGraphNode::new(
            "debugger",
            "Debug and harden",
            AgentRole::Debugger,
            "Resolve failures and edge-case regressions.",
        )
        .with_dependencies(vec!["coder".to_string()]),
        AgentGraphNode::new(
            "verifier",
            "Verify output",
            AgentRole::Verifier,
            "Run validations and confirm completion criteria.",
        )
        .with_dependencies(vec!["debugger".to_string()])
        .with_approval(true),
    ];

    orchestrator
        .create_run(goal, graph, RetryPolicy::new(2))
        .map_err(|error| format!("{error:?}"))
}

fn build_codex_specialist_prompt(
    run: &AgentRun,
    step_id: &str,
    step_instruction: &str,
    operator_hint: &str,
) -> String {
    let mut completed_context = Vec::new();
    for step in &run.steps {
        if matches!(step.status, AgentStepStatus::Completed) && step.step_id != step_id {
            let output = step
                .output
                .clone()
                .unwrap_or_else(|| "no output recorded".to_string());
            completed_context.push(format!(
                "- {} ({}) => {}",
                step.step_id,
                step.role.label(),
                clip_text(&output, 220)
            ));
        }
    }
    let context = if completed_context.is_empty() {
        "none".to_string()
    } else {
        completed_context.join("\n")
    };
    format!(
        "Forge Agent Run #{run_id}\nGoal: {goal}\nCoder Step: {step_id}\nInstruction: {instruction}\nOperator Hint: {hint}\nCompleted Context:\n{context}\n\nReturn implementation guidance and concrete patch-ready output.",
        run_id = run.run_id,
        goal = run.goal,
        step_id = step_id,
        instruction = step_instruction.trim(),
        hint = operator_hint.trim(),
        context = context
    )
}

fn should_auto_run_codex_for_started_step(run: &AgentRun, started_step_id: &str) -> bool {
    run.steps.iter().any(|step| {
        step.step_id == started_step_id
            && matches!(step.status, AgentStepStatus::Running)
            && matches!(step.role, AgentRole::Coder)
    })
}

fn should_auto_run_routed_for_started_step(run: &AgentRun, started_step_id: &str) -> bool {
    run.steps.iter().any(|step| {
        step.step_id == started_step_id
            && matches!(step.status, AgentStepStatus::Running)
            && matches!(
                step.role,
                AgentRole::Planner | AgentRole::Debugger | AgentRole::Verifier
            )
    })
}

fn source_role_for_agent_role(role: AgentRole) -> Option<SourceRole> {
    match role {
        AgentRole::Planner => Some(SourceRole::Planner),
        AgentRole::Debugger => Some(SourceRole::Debugger),
        AgentRole::Verifier => Some(SourceRole::Verifier),
        AgentRole::Coder => Some(SourceRole::Coder),
    }
}

fn build_routed_role_prompt(
    run: &AgentRun,
    step_id: &str,
    role: AgentRole,
    step_instruction: &str,
    operator_hint: &str,
) -> String {
    let mut completed_context = Vec::new();
    for step in &run.steps {
        if matches!(step.status, AgentStepStatus::Completed) && step.step_id != step_id {
            let output = step
                .output
                .clone()
                .unwrap_or_else(|| "no output recorded".to_string());
            completed_context.push(format!(
                "- {} ({}) => {}",
                step.step_id,
                step.role.label(),
                clip_text(&output, 220)
            ));
        }
    }
    let context = if completed_context.is_empty() {
        "none".to_string()
    } else {
        completed_context.join("\n")
    };
    format!(
        "Forge Agent Run #{run_id}\nGoal: {goal}\nRole Step: {step_id} ({role})\nInstruction: {instruction}\nOperator Hint: {hint}\nCompleted Context:\n{context}\n\nReturn practical, concrete output for this role step.",
        run_id = run.run_id,
        goal = run.goal,
        step_id = step_id,
        role = role.label(),
        instruction = step_instruction.trim(),
        hint = operator_hint.trim(),
        context = context
    )
}

fn append_workspace_provenance_to_prompt(
    prompt: String,
    workspace: &WorkspaceHost,
    workspace_context_path: &str,
) -> String {
    let Some(block) = build_workspace_input_provenance_block(workspace, workspace_context_path)
    else {
        return prompt;
    };
    format!("{prompt}\n\n{block}")
}

fn build_workspace_input_provenance_block(
    workspace: &WorkspaceHost,
    workspace_context_path: &str,
) -> Option<String> {
    let path = workspace_context_path.trim();
    if path.is_empty() {
        return None;
    }
    let excerpt = workspace.read_file_excerpt(path, 80, 3000).ok()?;
    let root = workspace.root().to_string_lossy().replace('\\', "/");
    Some(format!(
        "Workspace Input Provenance:\n- trust_label=trusted.workspace.local.canonical\n- provenance=workspace://{path}\n- workspace_root={root}\n- capture=read_file_excerpt(max_lines=80,max_chars=3000)\n- content_excerpt:\n{excerpt}"
    ))
}

#[allow(clippy::too_many_arguments)]
fn run_routed_task_for_active_step(
    agent_orchestrator: &Rc<RefCell<AgentOrchestrator>>,
    source_registry: &Rc<RefCell<SourceRegistry>>,
    active_run_id: Option<u64>,
    workspace: &WorkspaceHost,
    workspace_context_path: &str,
    llama_host: RwSignal<String>,
    llama_port: RwSignal<String>,
    agent_codex_prompt: RwSignal<String>,
    agent_codex_max_tokens: RwSignal<String>,
    agent_codex_status: RwSignal<String>,
    agent_codex_output: RwSignal<String>,
    agent_status_line: RwSignal<String>,
    agent_steps_line: RwSignal<String>,
    agent_trace_line: RwSignal<String>,
    silent_if_no_running_step: bool,
    queue: &Rc<RefCell<JobQueue>>,
    queued_jobs: RwSignal<u32>,
    running_jobs: RwSignal<u32>,
    completed_jobs: RwSignal<u32>,
    failed_jobs: RwSignal<u32>,
    cancelled_jobs: RwSignal<u32>,
) -> bool {
    let max_tokens = match parse_u32(agent_codex_max_tokens.get().trim(), "adapter max-tokens") {
        Ok(value) => value,
        Err(error) => {
            agent_codex_status.set(format!("routed role rejected: {error}"));
            return false;
        }
    };

    let (run_id, step_id, step_role, source_role, prompt) = {
        let orchestrator_ref = agent_orchestrator.borrow();
        let Some(run_id) = active_run_id else {
            if !silent_if_no_running_step {
                agent_codex_status.set(String::from("routed role skipped: no active run"));
            }
            return false;
        };
        let Some(run) = orchestrator_ref.run(run_id) else {
            if !silent_if_no_running_step {
                agent_codex_status.set(format!("routed role skipped: run {run_id} not found"));
            }
            return false;
        };
        let running_step = run.steps.iter().find(|step| {
            matches!(step.status, AgentStepStatus::Running)
                && matches!(
                    step.role,
                    AgentRole::Planner | AgentRole::Debugger | AgentRole::Verifier
                )
        });
        let Some(step) = running_step else {
            if !silent_if_no_running_step {
                agent_codex_status.set(String::from(
                    "routed role skipped: start planner/debugger/verifier step first",
                ));
            }
            return false;
        };
        let Some(source_role) = source_role_for_agent_role(step.role) else {
            if !silent_if_no_running_step {
                agent_codex_status.set(format!(
                    "routed role skipped: unsupported role {}",
                    step.role.label()
                ));
            }
            return false;
        };
        let prompt = build_routed_role_prompt(
            run,
            &step.step_id,
            step.role,
            step.instruction.as_str(),
            agent_codex_prompt.get().as_str(),
        );
        let prompt =
            append_workspace_provenance_to_prompt(prompt, workspace, workspace_context_path);
        (run_id, step.step_id.clone(), step.role, source_role, prompt)
    };

    let source_entry = {
        let registry = source_registry.borrow();
        let Some(entry) = registry.default_for(source_role) else {
            agent_codex_status.set(format!(
                "routed {} blocked: no enabled source",
                step_role.label()
            ));
            return false;
        };
        entry.clone()
    };

    let tracked_job_id = queue_start_tracked_job(
        queue,
        format!(
            "agent-{}-{}@{}",
            step_role.label().to_lowercase(),
            step_id,
            source_entry.id
        ),
        JobKind::AgentRun,
        JobPriority::Foreground,
        queued_jobs,
        running_jobs,
        completed_jobs,
        failed_jobs,
        cancelled_jobs,
    );
    persist_job_queue_with_notice(queue, agent_codex_status);

    let execution = if matches!(source_entry.kind, SourceKind::LocalModel) {
        let n_predict = max_tokens.to_string();
        let request = match build_completion_request(
            llama_host.get().as_str(),
            llama_port.get().as_str(),
            prompt.as_str(),
            n_predict.as_str(),
        ) {
            Ok(value) => value,
            Err(error) => {
                let _ = queue_fail_tracked_job(
                    queue,
                    tracked_job_id,
                    format!("routed {} request invalid: {error}", step_role.label()),
                    queued_jobs,
                    running_jobs,
                    completed_jobs,
                    failed_jobs,
                    cancelled_jobs,
                );
                agent_codex_status.set(format!(
                    "routed {} request invalid: {error}",
                    step_role.label()
                ));
                persist_job_queue_with_notice(queue, agent_codex_status);
                return false;
            }
        };
        match run_llama_cpp_completion(&request) {
            Ok(result) => Ok((
                source_entry.display_name.clone(),
                result.endpoint,
                result.text,
                None,
            )),
            Err(error) => Err(format!(
                "local runtime failed via {}: {}",
                source_entry.display_name,
                clip_text(&error, 180)
            )),
        }
    } else {
        let request =
            match RoleTaskRequest::new(format!("run-{run_id}-{step_id}"), prompt, max_tokens) {
                Ok(value) => value,
                Err(error) => {
                    let _ = queue_fail_tracked_job(
                        queue,
                        tracked_job_id,
                        format!("routed {} request invalid: {error}", step_role.label()),
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                    agent_codex_status.set(format!(
                        "routed {} request invalid: {error}",
                        step_role.label()
                    ));
                    persist_job_queue_with_notice(queue, agent_codex_status);
                    return false;
                }
            };
        match run_role_task_with_source(&source_entry, source_role, &request) {
            Ok(response) => Ok((
                response.source_display_name,
                response.route,
                response.output_text,
                response.tokens_used,
            )),
            Err(error) => Err(format!(
                "provider adapter failed via {}: {}",
                source_entry.display_name,
                clip_text(&error, 180)
            )),
        }
    };

    match execution {
        Ok((source_display_name, route, output_text, tokens_used)) => {
            let token_text = tokens_used
                .map(|value| value.to_string())
                .unwrap_or_else(|| "n/a".to_string());
            let completion = format!(
                "{} routed source={} route={} tokens={} output={}",
                step_role.label(),
                source_display_name,
                route,
                token_text,
                clip_text(&output_text, 600),
            );
            agent_codex_output.set(output_text);
            agent_codex_status.set(format!(
                "routed {} ok via {} route={} tokens={}",
                step_role.label(),
                source_display_name,
                route,
                token_text
            ));
            {
                let mut orchestrator_mut = agent_orchestrator.borrow_mut();
                let completion_result =
                    orchestrator_mut.complete_step(run_id, &step_id, completion);
                if completion_result.is_err() {
                    agent_codex_status.set(format!(
                        "routed {} output saved but step completion failed for {}",
                        step_role.label(),
                        step_id
                    ));
                }
                sync_agent_studio_signals(
                    &orchestrator_mut,
                    Some(run_id),
                    agent_status_line,
                    agent_steps_line,
                    agent_trace_line,
                );
            }
            let _ = queue_complete_tracked_job(
                queue,
                tracked_job_id,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(queue, agent_codex_status);
            true
        }
        Err(error) => {
            let _ = queue_fail_tracked_job(
                queue,
                tracked_job_id,
                format!(
                    "routed {} failure: {}",
                    step_role.label(),
                    clip_text(&error, 220)
                ),
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            agent_codex_status.set(format!(
                "routed {} failed: {}",
                step_role.label(),
                clip_text(&error, 220)
            ));
            persist_job_queue_with_notice(queue, agent_codex_status);
            false
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_codex_specialist_for_active_coder_step(
    agent_orchestrator: &Rc<RefCell<AgentOrchestrator>>,
    source_registry: &Rc<RefCell<SourceRegistry>>,
    agent_memory_store: &Rc<RefCell<ProjectMemoryStore>>,
    active_run_id: Option<u64>,
    workspace: &WorkspaceHost,
    workspace_context_path: &str,
    agent_codex_prompt: RwSignal<String>,
    agent_codex_max_tokens: RwSignal<String>,
    agent_codex_status: RwSignal<String>,
    agent_codex_output: RwSignal<String>,
    agent_memory_scope: RwSignal<String>,
    agent_memory_query: RwSignal<String>,
    agent_memory_status: RwSignal<String>,
    agent_status_line: RwSignal<String>,
    agent_steps_line: RwSignal<String>,
    agent_trace_line: RwSignal<String>,
    silent_if_no_running_coder: bool,
    queue: &Rc<RefCell<JobQueue>>,
    queued_jobs: RwSignal<u32>,
    running_jobs: RwSignal<u32>,
    completed_jobs: RwSignal<u32>,
    failed_jobs: RwSignal<u32>,
    cancelled_jobs: RwSignal<u32>,
) -> bool {
    let max_tokens = match parse_u32(agent_codex_max_tokens.get().trim(), "codex max-tokens") {
        Ok(value) => value,
        Err(error) => {
            agent_codex_status.set(format!("codex specialist rejected: {error}"));
            return false;
        }
    };

    let (run_id, step_id, prompt) = {
        let orchestrator_ref = agent_orchestrator.borrow();
        let Some(run_id) = active_run_id else {
            if !silent_if_no_running_coder {
                agent_codex_status.set(String::from("codex specialist skipped: no active run"));
            }
            return false;
        };
        let Some(run) = orchestrator_ref.run(run_id) else {
            if !silent_if_no_running_coder {
                agent_codex_status.set(format!("codex specialist skipped: run {run_id} not found"));
            }
            return false;
        };
        let running_coder = run.steps.iter().find(|step| {
            matches!(step.status, AgentStepStatus::Running) && matches!(step.role, AgentRole::Coder)
        });
        let Some(step) = running_coder else {
            if !silent_if_no_running_coder {
                agent_codex_status.set(String::from(
                    "codex specialist skipped: start coder step first",
                ));
            }
            return false;
        };
        let mut operator_hint = agent_codex_prompt.get();
        let scope_input = agent_memory_scope.get();
        if let Some(scope) = parse_memory_scope_input(scope_input.as_str()) {
            let raw_query = agent_memory_query.get();
            let query = if raw_query.trim().is_empty() {
                step.instruction.trim().to_string()
            } else {
                raw_query.trim().to_string()
            };
            let memory_hits = {
                let mut memory_store = agent_memory_store.borrow_mut();
                memory_store.recall(scope, query.as_str(), 6)
            };
            if memory_hits.is_empty() {
                agent_memory_status.set(format!(
                    "codex memory context: no hits in {} (query='{}')",
                    scope.label(),
                    clip_text(&query, 90)
                ));
            } else {
                let formatted_hits = memory_hits
                    .iter()
                    .map(|hit| {
                        let workspace_provenance = if matches!(hit.scope, MemoryScope::Workspace) {
                            format!(
                                " trust_label=trusted.workspace.memory.user_curated provenance=memory://workspace/{}?source={}",
                                hit.key.replace(' ', "_"),
                                hit.source.replace(' ', "_")
                            )
                        } else {
                            String::new()
                        };
                        format!(
                            "- {}={} (source={} hits={}{})",
                            hit.key,
                            clip_text(&hit.value, 200),
                            hit.source,
                            hit.hit_count,
                            workspace_provenance
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                operator_hint = format!(
                    "{base}\n\nMemory Context (scope={scope} query='{query}' hits={hits}):\n{memory}",
                    base = operator_hint,
                    scope = scope.label(),
                    query = clip_text(&query, 90),
                    hits = memory_hits.len(),
                    memory = formatted_hits
                );
                agent_memory_status.set(format!(
                    "codex memory context injected: scope={} hits={} query='{}'",
                    scope.label(),
                    memory_hits.len(),
                    clip_text(&query, 90)
                ));
            }
            persist_project_memory_with_notice(agent_memory_store, agent_memory_status);
        } else {
            agent_memory_status.set(format!(
                "codex memory context skipped: invalid scope '{}'",
                clip_text(&scope_input, 40)
            ));
        }
        let prompt = build_codex_specialist_prompt(
            run,
            &step.step_id,
            step.instruction.as_str(),
            operator_hint.as_str(),
        );
        let prompt =
            append_workspace_provenance_to_prompt(prompt, workspace, workspace_context_path);
        (run_id, step.step_id.clone(), prompt)
    };

    let request = match CodexSpecialistTaskRequest::new(
        format!("run-{run_id}-{step_id}"),
        prompt,
        max_tokens,
    ) {
        Ok(value) => value,
        Err(error) => {
            agent_codex_status.set(format!("codex specialist request invalid: {error}"));
            return false;
        }
    };

    let tracked_job_id = queue_start_tracked_job(
        queue,
        format!("agent-codex-{step_id}"),
        JobKind::AgentRun,
        JobPriority::Foreground,
        queued_jobs,
        running_jobs,
        completed_jobs,
        failed_jobs,
        cancelled_jobs,
    );
    persist_job_queue_with_notice(queue, agent_codex_status);

    let result = {
        let registry_ref = source_registry.borrow();
        run_codex_specialist_task(&registry_ref, &request)
    };

    match result {
        Ok(response) => {
            let completion = format!(
                "codex specialist source={} route={} tokens={} output={}",
                response.source_display_name,
                response.route,
                response
                    .tokens_used
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "n/a".to_string()),
                clip_text(&response.output_text, 600),
            );
            agent_codex_output.set(response.output_text.clone());
            agent_codex_status.set(format!(
                "codex specialist ok via {} ({})",
                response.source_display_name, response.route
            ));
            {
                let mut orchestrator_mut = agent_orchestrator.borrow_mut();
                let completion_result =
                    orchestrator_mut.complete_step(run_id, &step_id, completion);
                if completion_result.is_err() {
                    agent_codex_status.set(format!(
                        "codex specialist output saved but step completion failed for {}",
                        step_id
                    ));
                }
                sync_agent_studio_signals(
                    &orchestrator_mut,
                    Some(run_id),
                    agent_status_line,
                    agent_steps_line,
                    agent_trace_line,
                );
            }
            let _ = queue_complete_tracked_job(
                queue,
                tracked_job_id,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(queue, agent_codex_status);
            true
        }
        Err(error) => {
            let _ = queue_fail_tracked_job(
                queue,
                tracked_job_id,
                format!("codex specialist failure: {}", clip_text(&error, 200)),
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            agent_codex_status.set(format!(
                "codex specialist failed: {}",
                clip_text(&error, 200)
            ));
            persist_job_queue_with_notice(queue, agent_codex_status);
            false
        }
    }
}

fn sync_agent_studio_signals(
    orchestrator: &AgentOrchestrator,
    active_run_id: Option<u64>,
    agent_status_line: RwSignal<String>,
    agent_steps_line: RwSignal<String>,
    agent_trace_line: RwSignal<String>,
) {
    let Some(run_id) = active_run_id else {
        agent_status_line.set(String::from("agent run idle (create a run)"));
        agent_steps_line.set(String::from("no steps"));
        agent_trace_line.set(String::from("no trace"));
        return;
    };

    let Some(run) = orchestrator.run(run_id) else {
        agent_status_line.set(format!("run {run_id} not found"));
        agent_steps_line.set(String::from("no steps"));
        agent_trace_line.set(String::from("no trace"));
        return;
    };

    agent_status_line.set(format_agent_status(run));
    agent_steps_line.set(format_agent_steps(run));
    agent_trace_line.set(format_agent_trace(run));
}

fn format_agent_status(run: &AgentRun) -> String {
    let total = run.steps.len();
    let completed = run
        .steps
        .iter()
        .filter(|step| matches!(step.status, AgentStepStatus::Completed))
        .count();
    let waiting = run
        .steps
        .iter()
        .filter(|step| matches!(step.status, AgentStepStatus::WaitingApproval))
        .count();
    format!(
        "run #{:03} | status={:?} | completed={}/{} | waiting_approval={} | goal={}",
        run.run_id, run.status, completed, total, waiting, run.goal
    )
}

fn format_agent_steps(run: &AgentRun) -> String {
    let mut lines = Vec::new();
    for step in &run.steps {
        let deps = if step.depends_on.is_empty() {
            "-".to_string()
        } else {
            step.depends_on.join(",")
        };
        lines.push(format!(
            "- {} | role={} | status={:?} | attempt={}/{} | approval={} | deps={} | title={}",
            step.step_id,
            step.role.label(),
            step.status,
            step.attempt_count,
            step.max_attempts,
            if step.requires_approval { "yes" } else { "no" },
            deps,
            clip_text(&step.title, 48)
        ));
    }
    lines.join("\n")
}

fn format_agent_trace(run: &AgentRun) -> String {
    if run.trace.is_empty() {
        return String::from("no trace events");
    }

    let mut lines = Vec::new();
    let start = run.trace.len().saturating_sub(10);
    for event in &run.trace[start..] {
        let text = format_agent_trace_event_line(event);
        lines.push(format!("[{}] {}", event.sequence, text));
    }
    lines.join("\n")
}

fn format_agent_trace_event_line(
    event: &control_plane::agent_orchestrator::AgentTraceEvent,
) -> String {
    match &event.kind {
        AgentTraceEventKind::RunCreated { run_id, goal } => {
            format!("run-created #{run_id} goal={}", clip_text(goal, 60))
        }
        AgentTraceEventKind::StepQueued { step_id } => format!("step-queued {step_id}"),
        AgentTraceEventKind::StepStarted {
            step_id,
            role,
            attempt,
        } => {
            format!(
                "step-started {} role={} attempt={}",
                step_id,
                role.label(),
                attempt
            )
        }
        AgentTraceEventKind::ApprovalRequested { step_id, reason } => format!(
            "approval-requested {} reason={}",
            step_id,
            clip_text(reason, 60)
        ),
        AgentTraceEventKind::ApprovalResolved {
            step_id,
            approved,
            note,
        } => format!(
            "approval-resolved {} approved={} note={}",
            step_id,
            approved,
            clip_text(note, 60)
        ),
        AgentTraceEventKind::StepCompleted { step_id } => format!("step-completed {step_id}"),
        AgentTraceEventKind::StepFailed { step_id, error } => {
            format!("step-failed {} error={}", step_id, clip_text(error, 60))
        }
        AgentTraceEventKind::StepRetried {
            step_id,
            next_attempt,
        } => format!("step-retried {} next_attempt={}", step_id, next_attempt),
        AgentTraceEventKind::RunCompleted { run_id } => format!("run-completed #{run_id}"),
        AgentTraceEventKind::RunFailed { run_id, reason } => {
            format!("run-failed #{} reason={}", run_id, clip_text(reason, 60))
        }
    }
}

fn format_active_agent_graph(
    orchestrator: &AgentOrchestrator,
    active_run_id: Option<u64>,
) -> String {
    let Some(run_id) = active_run_id else {
        return String::from("no active run");
    };
    let Some(run) = orchestrator.run(run_id) else {
        return format!("run {run_id} not found");
    };
    format_agent_graph(run)
}

fn format_agent_graph(run: &AgentRun) -> String {
    let mut lines = Vec::new();
    for step in &run.steps {
        let downstream = run
            .steps
            .iter()
            .filter(|candidate| candidate.depends_on.iter().any(|dep| dep == &step.step_id))
            .map(|candidate| candidate.step_id.clone())
            .collect::<Vec<_>>();
        let edge = if downstream.is_empty() {
            "(end)".to_string()
        } else {
            downstream.join(", ")
        };
        lines.push(format!(
            "- {} [{}] status={:?} -> {}",
            step.step_id,
            step.role.label(),
            step.status,
            edge
        ));
    }
    lines.join("\n")
}

fn format_active_agent_trace_filtered(
    orchestrator: &AgentOrchestrator,
    active_run_id: Option<u64>,
    query: &str,
    filter_kind: &str,
    role_filter: &str,
) -> String {
    let Some(run_id) = active_run_id else {
        return String::from("no active run");
    };
    let Some(run) = orchestrator.run(run_id) else {
        return format!("run {run_id} not found");
    };
    format_agent_trace_filtered(run, query, filter_kind, role_filter)
}

fn format_agent_trace_filtered(
    run: &AgentRun,
    query: &str,
    filter_kind: &str,
    role_filter: &str,
) -> String {
    if run.trace.is_empty() {
        return String::from("no trace events");
    }

    let normalized_query = query.trim().to_lowercase();
    let selected_role = parse_trace_role_filter(role_filter);
    let step_roles = run
        .steps
        .iter()
        .map(|step| (step.step_id.as_str(), step.role))
        .collect::<HashMap<_, _>>();

    let mut lines = Vec::new();
    for event in &run.trace {
        if !trace_event_matches_kind(event, filter_kind) {
            continue;
        }
        if let Some(role) = selected_role
            && !trace_event_matches_role(event, role, &step_roles)
        {
            continue;
        }
        let text = format_agent_trace_event_line(event);
        if !normalized_query.is_empty() && !text.to_lowercase().contains(&normalized_query) {
            continue;
        }
        lines.push(format!("[{}] {}", event.sequence, text));
    }

    if lines.is_empty() {
        return String::from("no trace events match active filters");
    }
    let start = lines.len().saturating_sub(14);
    lines[start..].join("\n")
}

fn trace_event_matches_kind(
    event: &control_plane::agent_orchestrator::AgentTraceEvent,
    filter_kind: &str,
) -> bool {
    match filter_kind.trim().to_lowercase().as_str() {
        "all" | "" => true,
        "run" => matches!(
            event.kind,
            AgentTraceEventKind::RunCreated { .. }
                | AgentTraceEventKind::RunCompleted { .. }
                | AgentTraceEventKind::RunFailed { .. }
        ),
        "step" => matches!(
            event.kind,
            AgentTraceEventKind::StepQueued { .. }
                | AgentTraceEventKind::StepStarted { .. }
                | AgentTraceEventKind::StepCompleted { .. }
                | AgentTraceEventKind::StepFailed { .. }
                | AgentTraceEventKind::StepRetried { .. }
        ),
        "approval" => matches!(
            event.kind,
            AgentTraceEventKind::ApprovalRequested { .. }
                | AgentTraceEventKind::ApprovalResolved { .. }
        ),
        "failure" => matches!(
            event.kind,
            AgentTraceEventKind::StepFailed { .. } | AgentTraceEventKind::RunFailed { .. }
        ),
        _ => true,
    }
}

fn parse_trace_role_filter(role_filter: &str) -> Option<AgentRole> {
    match role_filter.trim().to_lowercase().as_str() {
        "all" | "" => None,
        "planner" => Some(AgentRole::Planner),
        "coder" => Some(AgentRole::Coder),
        "debugger" => Some(AgentRole::Debugger),
        "verifier" => Some(AgentRole::Verifier),
        _ => None,
    }
}

fn trace_event_matches_role(
    event: &control_plane::agent_orchestrator::AgentTraceEvent,
    selected_role: AgentRole,
    step_roles: &HashMap<&str, AgentRole>,
) -> bool {
    match &event.kind {
        AgentTraceEventKind::StepStarted { role, .. } => *role == selected_role,
        AgentTraceEventKind::StepQueued { step_id }
        | AgentTraceEventKind::StepCompleted { step_id }
        | AgentTraceEventKind::StepFailed { step_id, .. }
        | AgentTraceEventKind::StepRetried { step_id, .. }
        | AgentTraceEventKind::ApprovalRequested { step_id, .. }
        | AgentTraceEventKind::ApprovalResolved { step_id, .. } => {
            step_roles.get(step_id.as_str()).copied() == Some(selected_role)
        }
        AgentTraceEventKind::RunCreated { .. }
        | AgentTraceEventKind::RunCompleted { .. }
        | AgentTraceEventKind::RunFailed { .. } => false,
    }
}

fn persist_agent_state_with_notice(
    orchestrator: &Rc<RefCell<AgentOrchestrator>>,
    active_run_id: Option<u64>,
    agent_status_line: RwSignal<String>,
) {
    let orchestrator_ref = match orchestrator.try_borrow() {
        Ok(value) => value,
        Err(error) => {
            let message = format!("agent state persist skipped: busy ({error})");
            agent_status_line.set(message.clone());
            log_warn("persist", message);
            return;
        }
    };
    if let Err(error) =
        save_agent_studio_state(&agent_studio_state_path(), &orchestrator_ref, active_run_id)
    {
        let current = agent_status_line.get();
        agent_status_line.set(format!(
            "{} | persist warning: {}",
            clip_text(&current, 120),
            clip_text(&error, 120),
        ));
        log_warn(
            "persist",
            format!("agent state persist warning: {}", clip_text(&error, 120)),
        );
    }
}

fn persist_project_memory_with_notice(
    memory_store: &Rc<RefCell<ProjectMemoryStore>>,
    agent_memory_status: RwSignal<String>,
) {
    let store_ref = match memory_store.try_borrow() {
        Ok(value) => value,
        Err(error) => {
            let message = format!("project memory persist skipped: busy ({error})");
            agent_memory_status.set(message.clone());
            log_warn("persist", message);
            return;
        }
    };
    if let Err(error) = save_project_memory_state(&project_memory_state_path(), &store_ref) {
        let current = agent_memory_status.get();
        agent_memory_status.set(format!(
            "{} | persist warning: {}",
            clip_text(&current, 120),
            clip_text(&error, 120),
        ));
        log_warn(
            "persist",
            format!("project memory persist warning: {}", clip_text(&error, 120)),
        );
    }
}

fn resolve_active_agent_run_id(
    preferred: Option<u64>,
    orchestrator: &AgentOrchestrator,
) -> Option<u64> {
    if let Some(run_id) = preferred
        && orchestrator.run(run_id).is_some()
    {
        return Some(run_id);
    }
    orchestrator.runs_snapshot().last().map(|run| run.run_id)
}

