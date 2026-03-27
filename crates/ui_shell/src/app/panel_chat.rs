fn normalize_confidential_logging_policy_label(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        runtime_registry::confidential_relay::default_declared_logging_policy()
    } else {
        trimmed.to_string()
    }
}

fn source_runtime_class_label(kind: SourceKind) -> &'static str {
    match kind {
        SourceKind::LocalModel => "local_model_runtime",
        SourceKind::ApiModel => "remote_api_model",
        SourceKind::SidecarBridge => "remote_sidecar_bridge",
    }
}

fn source_location_label(source: &SourceEntry) -> String {
    let target = source.target.trim();
    if matches!(source.kind, SourceKind::LocalModel) {
        return format!("local://{target}");
    }
    let authority = target
        .split_once("://")
        .map(|(_, remainder)| remainder)
        .unwrap_or(target)
        .split('/')
        .next()
        .unwrap_or(target)
        .trim();
    if authority.is_empty() {
        "remote://unknown".to_string()
    } else {
        format!("remote://{authority}")
    }
}

fn source_network_state_label(source: &SourceEntry, transport_encrypted: bool) -> &'static str {
    if matches!(source.kind, SourceKind::LocalModel) {
        return "local_process_only";
    }
    if transport_encrypted {
        "remote_tls"
    } else {
        "remote_insecure"
    }
}

fn format_confidential_visibility_status(
    source: &SourceEntry,
    relay_status: &str,
    attestation_status: &str,
    encryption_status: &str,
    fallback_state: &str,
    transport_encrypted: bool,
    logging_policy: &str,
) -> String {
    format!(
        "location={} runtime_class={} network_state={} relay_status={} attestation_status={} encryption_status={} fallback_state={} logging_policy={}",
        source_location_label(source),
        source_runtime_class_label(source.kind),
        source_network_state_label(source, transport_encrypted),
        relay_status,
        attestation_status,
        clip_text(encryption_status, 72),
        fallback_state,
        clip_text(logging_policy, 48)
    )
}

#[allow(clippy::too_many_arguments)]
fn chat_panel(
    runtime_version: RwSignal<String>,
    runtime_health: RwSignal<String>,
    runtime_process_state: RwSignal<String>,
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
    source_registry: Rc<RefCell<SourceRegistry>>,
    confidential_relay_sessions: Rc<RefCell<ConfidentialRelaySessionStore>>,
    feature_registry: Rc<RefCell<FeaturePolicyRegistry>>,
    queue: Rc<RefCell<JobQueue>>,
    queued_jobs: RwSignal<u32>,
    running_jobs: RwSignal<u32>,
    completed_jobs: RwSignal<u32>,
    failed_jobs: RwSignal<u32>,
    cancelled_jobs: RwSignal<u32>,
) -> impl IntoView {
    let generate_local = {
        let queue = queue.clone();
        move || {
            let request = build_completion_request(
                llama_host.get().as_str(),
                llama_port.get().as_str(),
                chat_prompt.get().as_str(),
                chat_n_predict.get().as_str(),
            );
            let request = match request {
                Ok(value) => value,
                Err(error) => {
                    chat_status.set(format!("request invalid: {error}"));
                    return;
                }
            };

            let tracked_job_id = queue_start_tracked_job(
                &queue,
                "chat-local".to_string(),
                JobKind::LlmInference,
                JobPriority::Foreground,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, chat_status);
            chat_status.set(format!(
                "requesting {}:{} (n_predict={}) [job #{}]",
                request.host,
                request.port,
                request.n_predict,
                tracked_job_id.raw()
            ));
            match run_llama_cpp_completion(&request) {
                Ok(result) => {
                    chat_output.set(result.text);
                    chat_status.set(format!(
                        "ok in {} ms via {}",
                        result.latency_ms, result.endpoint
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
                }
                Err(error) => {
                    chat_status.set(format!("generation failed: {}", clip_text(&error, 180)));
                    let _ = queue_fail_tracked_job(
                        &queue,
                        tracked_job_id,
                        format!("chat local failed: {}", clip_text(&error, 180)),
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                }
            }
            persist_job_queue_with_notice(&queue, chat_status);
        }
    };

    let generate_routed = {
        let source_registry = source_registry.clone();
        let queue = queue.clone();
        move || {
            let prompt = chat_prompt.get();
            let max_tokens = match parse_u32(chat_n_predict.get().as_str(), "n_predict") {
                Ok(value) => value,
                Err(error) => {
                    chat_status.set(format!("request invalid: {error}"));
                    return;
                }
            };

            let chat_source = {
                let registry = match source_registry.try_borrow() {
                    Ok(value) => value,
                    Err(error) => {
                        chat_status.set(format!("routed generation blocked: source registry busy ({error})"));
                        return;
                    }
                };
                let Some(entry) = registry.default_for(SourceRole::Chat) else {
                    chat_status.set(String::from(
                        "routed generation blocked: no enabled chat source",
                    ));
                    return;
                };
                entry.clone()
            };

            if matches!(chat_source.kind, SourceKind::LocalModel) {
                let request = build_completion_request(
                    llama_host.get().as_str(),
                    llama_port.get().as_str(),
                    prompt.as_str(),
                    chat_n_predict.get().as_str(),
                );
                let request = match request {
                    Ok(value) => value,
                    Err(error) => {
                        chat_status.set(format!("request invalid: {error}"));
                        return;
                    }
                };
                let tracked_job_id = queue_start_tracked_job(
                    &queue,
                    format!("chat-routed-local@{}", chat_source.id),
                    JobKind::LlmInference,
                    JobPriority::Foreground,
                    queued_jobs,
                    running_jobs,
                    completed_jobs,
                    failed_jobs,
                    cancelled_jobs,
                );
                persist_job_queue_with_notice(&queue, chat_status);
                chat_status.set(format!(
                    "routed local request via {} ({}) [job #{}]",
                    chat_source.display_name,
                    chat_source.id,
                    tracked_job_id.raw()
                ));
                chat_routed_baseline_latency_ms.set(None);
                match run_llama_cpp_completion(&request) {
                    Ok(result) => {
                        chat_output.set(result.text);
                        chat_status.set(format!(
                            "ok in {} ms via {} (source={})",
                            result.latency_ms, result.endpoint, chat_source.display_name
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
                    }
                    Err(error) => {
                        chat_status.set(format!(
                            "generation failed via {}: {}",
                            chat_source.display_name,
                            clip_text(&error, 180)
                        ));
                        let _ = queue_fail_tracked_job(
                            &queue,
                            tracked_job_id,
                            format!(
                                "chat routed local failed via {}: {}",
                                chat_source.display_name,
                                clip_text(&error, 180)
                            ),
                            queued_jobs,
                            running_jobs,
                            completed_jobs,
                            failed_jobs,
                            cancelled_jobs,
                        );
                    }
                }
                persist_job_queue_with_notice(&queue, chat_status);
                return;
            }

            let request = ChatTaskRequest::new(prompt, max_tokens);
            let request = match request {
                Ok(value) => value,
                Err(error) => {
                    chat_status.set(format!("request invalid: {error}"));
                    return;
                }
            };
            let tracked_job_id = queue_start_tracked_job(
                &queue,
                format!("chat-routed@{}", chat_source.id),
                JobKind::LlmInference,
                JobPriority::Foreground,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, chat_status);
            chat_status.set(format!(
                "routed request via {} ({}) [job #{}]",
                chat_source.display_name,
                chat_source.id,
                tracked_job_id.raw()
            ));
            let remote_start = unix_time_ms_now();
            match run_chat_task_with_source(&chat_source, &request) {
                Ok(response) => {
                    let remote_elapsed_ms = unix_time_ms_now().saturating_sub(remote_start);
                    chat_routed_baseline_latency_ms.set(Some(remote_elapsed_ms));
                    chat_output.set(response.output_text);
                    chat_status.set(format!(
                        "ok via {} route={} tokens={} remote_ms={}",
                        response.source_display_name,
                        response.route,
                        response
                            .tokens_used
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "n/a".to_string()),
                        remote_elapsed_ms
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
                }
                Err(error) => {
                    chat_routed_baseline_latency_ms.set(None);
                    chat_status.set(format!(
                        "routed generation failed via {}: {}",
                        chat_source.display_name,
                        clip_text(&error, 180)
                    ));
                    let _ = queue_fail_tracked_job(
                        &queue,
                        tracked_job_id,
                        format!(
                            "chat routed failed via {}: {}",
                            chat_source.display_name,
                            clip_text(&error, 180)
                        ),
                        queued_jobs,
                        running_jobs,
                        completed_jobs,
                        failed_jobs,
                        cancelled_jobs,
                    );
                }
            }
            persist_job_queue_with_notice(&queue, chat_status);
        }
    };

    let generate_confidential = {
        let source_registry = source_registry.clone();
        let confidential_relay_sessions = confidential_relay_sessions.clone();
        let feature_registry = feature_registry.clone();
        let queue = queue.clone();
        move || {
            let relay_enabled = {
                let registry = match feature_registry.try_borrow() {
                    Ok(value) => value,
                    Err(error) => {
                        chat_confidential_status
                            .set(format!("confidential relay blocked: feature registry busy ({error})"));
                        return;
                    }
                };
                registry
                    .status(FeatureId::ConfidentialRelay)
                    .map(|value| matches!(value.effective_state, FeatureState::Enabled))
                    .unwrap_or(false)
            };
            if !relay_enabled {
                chat_confidential_status.set(String::from(
                    "confidential relay blocked: feature policy not enabled (set confidential_relay to Enabled or Auto)",
                ));
                return;
            }

            let prompt = chat_prompt.get();
            let max_tokens = match parse_u32(chat_n_predict.get().as_str(), "n_predict") {
                Ok(value) => value,
                Err(error) => {
                    chat_confidential_status.set(format!("request invalid: {error}"));
                    return;
                }
            };
            let measurement = chat_confidential_measurement.get();
            if measurement.trim().is_empty() {
                chat_confidential_status.set(String::from(
                    "request invalid: attestation measurement is empty",
                ));
                return;
            }
            let policy_mode =
                match parse_confidential_mode_input(chat_confidential_policy_mode.get().as_str()) {
                    Ok(value) => value,
                    Err(error) => {
                        chat_confidential_status.set(format!("request invalid: {error}"));
                        return;
                    }
                };
            let max_attestation_age_ms = match parse_u64(
                chat_confidential_max_attestation_age_ms.get().as_str(),
                "max_attestation_age_ms",
            ) {
                Ok(value) if value > 0 => value,
                Ok(_) => {
                    chat_confidential_status.set(String::from(
                        "request invalid: max_attestation_age_ms must be greater than zero",
                    ));
                    return;
                }
                Err(error) => {
                    chat_confidential_status.set(format!("request invalid: {error}"));
                    return;
                }
            };
            let require_confidential_cpu = chat_confidential_require_cpu.get();
            let require_confidential_gpu = chat_confidential_require_gpu.get();
            let allow_remote_fallback = chat_confidential_allow_remote_fallback.get();

            let chat_source = {
                let registry = match source_registry.try_borrow() {
                    Ok(value) => value,
                    Err(error) => {
                        chat_confidential_status.set(format!(
                            "confidential relay blocked: source registry busy ({error})"
                        ));
                        return;
                    }
                };
                let Some(entry) = registry.default_for(SourceRole::Chat) else {
                    chat_confidential_status.set(String::from(
                        "confidential relay blocked: no enabled chat source",
                    ));
                    return;
                };
                entry.clone()
            };
            let Some(confidential_metadata) = chat_source.confidential_endpoint.as_ref() else {
                chat_confidential_status.set(format!(
                    "confidential relay blocked: source {} is missing enabled confidential endpoint metadata",
                    chat_source.id
                ));
                return;
            };
            if !confidential_metadata.enabled {
                chat_confidential_status.set(format!(
                    "confidential relay blocked: source {} confidential endpoint metadata is disabled",
                    chat_source.id
                ));
                return;
            }
            if let Err(error) =
                confidential_metadata.validate_for_source(&chat_source.id, &chat_source.target)
            {
                chat_confidential_status.set(format!(
                    "confidential relay blocked: source {} metadata invalid: {}",
                    chat_source.id,
                    clip_text(&error.to_string(), 180)
                ));
                return;
            };

            let now = unix_time_ms_now();
            let nonce = format!("chat-{now}-{max_tokens}");
            let fallback_consent_captured_at_unix_ms = now;
            let fallback_consent_source = "ui.chat.confidential_fallback_toggle".to_string();
            let attestation = AttestationEvidence {
                provider: "forge-manual".to_string(),
                measurement: measurement.trim().to_string(),
                nonce: nonce.clone(),
                cpu_confidential: require_confidential_cpu,
                gpu_confidential: require_confidential_gpu,
                issued_at_unix_ms: now.saturating_sub(1_000),
                expires_at_unix_ms: now.saturating_add(max_attestation_age_ms.max(30_000)),
                signature: format!("attestation-evidence:{nonce}"),
            };
            let request = ConfidentialChatTaskRequest {
                prompt: prompt.clone(),
                max_tokens,
                attestation,
                policy: ConfidentialRelayPolicy {
                    mode: policy_mode,
                    require_confidential_cpu,
                    require_confidential_gpu,
                    max_attestation_age_ms,
                },
                fallback_consent: Some(ConfidentialFallbackConsent {
                    allow_remote_fallback,
                    captured_at_unix_ms: fallback_consent_captured_at_unix_ms,
                    source: fallback_consent_source.clone(),
                }),
            };
            let expected_transport_encrypted = true;
            let configured_encryption_status = format!(
                "configured_mode={:?},transport_encrypted_expected={}",
                confidential_metadata.encryption_mode, expected_transport_encrypted
            );
            let declared_logging_policy = normalize_confidential_logging_policy_label(
                confidential_metadata.declared_logging_policy.as_str(),
            );

            let tracked_job_id = queue_start_tracked_job(
                &queue,
                format!("chat-confidential@{}", chat_source.id),
                JobKind::LlmInference,
                JobPriority::Foreground,
                queued_jobs,
                running_jobs,
                completed_jobs,
                failed_jobs,
                cancelled_jobs,
            );
            persist_job_queue_with_notice(&queue, chat_confidential_status);
            chat_confidential_status.set(format!(
                "confidential routed request via {} ({}) [job #{}]",
                chat_source.display_name,
                chat_source.id,
                tracked_job_id.raw()
            ));

            let result = {
                let mut sessions = confidential_relay_sessions.borrow_mut();
                run_confidential_chat_task_with_source(&chat_source, &request, &mut sessions, now)
            };

            match result {
                Ok(response) => {
                    let encryption_status = format!(
                        "mode={:?},transport_encrypted={}",
                        response.encryption_mode, response.transport_encrypted
                    );
                    let visibility = format_confidential_visibility_status(
                        &chat_source,
                        "verified",
                        "verified",
                        encryption_status.as_str(),
                        "not_used",
                        response.transport_encrypted,
                        response.declared_logging_policy.as_str(),
                    );
                    let baseline_remote_ms = chat_routed_baseline_latency_ms.get();
                    let overhead_text = match baseline_remote_ms {
                        Some(baseline) if baseline > 0 => {
                            let delta_ms = i128::from(response.relay_roundtrip_ms)
                                .saturating_sub(i128::from(baseline));
                            let pct = (delta_ms as f64 / baseline as f64) * 100.0;
                            format!(
                                "baseline_remote_ms={} overhead_ms={} overhead_pct={pct:.1}",
                                baseline, delta_ms
                            )
                        }
                        _ => "baseline_remote_ms=n/a overhead_ms=n/a overhead_pct=n/a".to_string(),
                    };
                    chat_output.set(response.output_text);
                    chat_status.set(format!(
                        "ok via {} route={} tokens={}",
                        response.source_display_name,
                        response.route,
                        response
                            .tokens_used
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "n/a".to_string())
                    ));
                    chat_confidential_status.set(format!(
                        "verified session={} key={} nonce={} policy_id={} provider={} measurement={} expires={} enc={:?} transport_encrypted={} mode={:?} req_cpu={} req_gpu={} verify_ms={} relay_ms={} total_ms={} fallback_required={} fallback_consent={} fallback_consent_source={} fallback_consent_unix_ms={} fallback_state={} {} | {}",
                        response.session_id,
                        clip_text(&response.session_key_id, 32),
                        clip_text(&response.request_nonce, 32),
                        clip_text(&response.policy_identity, 40),
                        response.attestation_provider,
                        clip_text(&response.measurement, 48),
                        response.expires_at_unix_ms,
                        response.encryption_mode,
                        response.transport_encrypted,
                        policy_mode,
                        require_confidential_cpu,
                        require_confidential_gpu,
                        response.attestation_verify_ms,
                        response.relay_roundtrip_ms,
                        response.total_path_ms,
                        response.fallback_consent_required,
                        response.fallback_consent_granted,
                        response
                            .fallback_consent_source
                            .as_deref()
                            .unwrap_or("none"),
                        response
                            .fallback_consent_captured_at_unix_ms
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "none".to_string()),
                        response.fallback_state,
                        overhead_text,
                        visibility
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
                }
                Err(error) => {
                    let relay_error = clip_text(&error, 180);
                    if allow_remote_fallback {
                        let fallback_request = ChatTaskRequest::new(prompt.clone(), max_tokens);
                        let fallback_request = match fallback_request {
                            Ok(value) => value,
                            Err(request_error) => {
                                let visibility = format_confidential_visibility_status(
                                    &chat_source,
                                    "failed",
                                    "not_verified",
                                    configured_encryption_status.as_str(),
                                    "blocked",
                                    expected_transport_encrypted,
                                    declared_logging_policy.as_str(),
                                );
                                chat_confidential_status.set(format!(
                                    "confidential relay failed via {}: {} | fallback blocked: {} | consent_source={} consent_unix_ms={} | {}",
                                    chat_source.display_name,
                                    relay_error,
                                    clip_text(&request_error, 120),
                                    fallback_consent_source,
                                    fallback_consent_captured_at_unix_ms,
                                    visibility
                                ));
                                let _ = queue_fail_tracked_job(
                                    &queue,
                                    tracked_job_id,
                                    format!(
                                        "chat confidential failed via {}: {} | fallback blocked: {}",
                                        chat_source.display_name,
                                        relay_error,
                                        clip_text(&request_error, 120)
                                    ),
                                    queued_jobs,
                                    running_jobs,
                                    completed_jobs,
                                    failed_jobs,
                                    cancelled_jobs,
                                );
                                persist_confidential_relay_with_notice(
                                    &confidential_relay_sessions,
                                    chat_confidential_status,
                                );
                                persist_chat_confidential_state_with_notice(
                                    chat_confidential_measurement,
                                    chat_confidential_policy_mode,
                                    chat_confidential_max_attestation_age_ms,
                                    chat_confidential_profile_window,
                                    chat_confidential_require_cpu,
                                    chat_confidential_require_gpu,
                                    chat_confidential_allow_remote_fallback,
                                    chat_confidential_status,
                                );
                                persist_job_queue_with_notice(&queue, chat_confidential_status);
                                return;
                            }
                        };

                        let fallback_start = unix_time_ms_now();
                        match run_chat_task_with_source(&chat_source, &fallback_request) {
                            Ok(fallback_response) => {
                                let fallback_ms = unix_time_ms_now().saturating_sub(fallback_start);
                                chat_routed_baseline_latency_ms.set(Some(fallback_ms));
                                let fallback_transport_encrypted =
                                    chat_source.target.trim().starts_with("https://");
                                let visibility = format_confidential_visibility_status(
                                    &chat_source,
                                    "failed",
                                    "not_verified_after_fallback",
                                    "relay_not_used_after_fallback",
                                    "remote_consented",
                                    fallback_transport_encrypted,
                                    declared_logging_policy.as_str(),
                                );
                                chat_output.set(fallback_response.output_text);
                                chat_status.set(format!(
                                    "fallback ok via {} route={} tokens={} remote_ms={}",
                                    fallback_response.source_display_name,
                                    fallback_response.route,
                                    fallback_response
                                        .tokens_used
                                        .map(|value| value.to_string())
                                        .unwrap_or_else(|| "n/a".to_string()),
                                    fallback_ms
                                ));
                                chat_confidential_status.set(format!(
                                    "confidential relay failed via {}: {} | fallback_state=remote_consented route={} remote_ms={} consent_source={} consent_unix_ms={} | {}",
                                    chat_source.display_name,
                                    relay_error,
                                    fallback_response.route,
                                    fallback_ms,
                                    fallback_consent_source,
                                    fallback_consent_captured_at_unix_ms,
                                    visibility
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
                            }
                            Err(fallback_error) => {
                                chat_routed_baseline_latency_ms.set(None);
                                let visibility = format_confidential_visibility_status(
                                    &chat_source,
                                    "failed",
                                    "not_verified_after_fallback_failure",
                                    "relay_not_used_after_fallback_failure",
                                    "remote_consented_failed",
                                    expected_transport_encrypted,
                                    declared_logging_policy.as_str(),
                                );
                                chat_confidential_status.set(format!(
                                    "confidential relay failed via {}: {} | fallback_state=remote_consented_failed reason={} consent_source={} consent_unix_ms={} | {}",
                                    chat_source.display_name,
                                    relay_error,
                                    clip_text(&fallback_error, 160),
                                    fallback_consent_source,
                                    fallback_consent_captured_at_unix_ms,
                                    visibility
                                ));
                                let _ = queue_fail_tracked_job(
                                    &queue,
                                    tracked_job_id,
                                    format!(
                                        "chat confidential failed via {}: {} | fallback failed: {}",
                                        chat_source.display_name,
                                        relay_error,
                                        clip_text(&fallback_error, 120)
                                    ),
                                    queued_jobs,
                                    running_jobs,
                                    completed_jobs,
                                    failed_jobs,
                                    cancelled_jobs,
                                );
                            }
                        }
                    } else {
                        let visibility = format_confidential_visibility_status(
                            &chat_source,
                            "failed",
                            "not_verified",
                            configured_encryption_status.as_str(),
                            "blocked(no explicit consent)",
                            expected_transport_encrypted,
                            declared_logging_policy.as_str(),
                        );
                        chat_confidential_status.set(format!(
                            "confidential relay failed via {}: {} | fallback_state=blocked(no explicit consent) consent_source={} consent_unix_ms={} | {}",
                            chat_source.display_name,
                            relay_error,
                            fallback_consent_source,
                            fallback_consent_captured_at_unix_ms,
                            visibility
                        ));
                        let _ = queue_fail_tracked_job(
                            &queue,
                            tracked_job_id,
                            format!(
                                "chat confidential failed via {}: {}",
                                chat_source.display_name, relay_error
                            ),
                            queued_jobs,
                            running_jobs,
                            completed_jobs,
                            failed_jobs,
                            cancelled_jobs,
                        );
                    }
                }
            }
            persist_confidential_relay_with_notice(
                &confidential_relay_sessions,
                chat_confidential_status,
            );
            persist_chat_confidential_state_with_notice(
                chat_confidential_measurement,
                chat_confidential_policy_mode,
                chat_confidential_max_attestation_age_ms,
                chat_confidential_profile_window,
                chat_confidential_require_cpu,
                chat_confidential_require_gpu,
                chat_confidential_allow_remote_fallback,
                chat_confidential_status,
            );
            persist_job_queue_with_notice(&queue, chat_confidential_status);
        }
    };
    let set_require_cpu_on = move || {
        chat_confidential_require_cpu.set(true);
        persist_chat_confidential_state_with_notice(
            chat_confidential_measurement,
            chat_confidential_policy_mode,
            chat_confidential_max_attestation_age_ms,
            chat_confidential_profile_window,
            chat_confidential_require_cpu,
            chat_confidential_require_gpu,
            chat_confidential_allow_remote_fallback,
            chat_confidential_status,
        );
    };
    let set_require_cpu_off = move || {
        chat_confidential_require_cpu.set(false);
        persist_chat_confidential_state_with_notice(
            chat_confidential_measurement,
            chat_confidential_policy_mode,
            chat_confidential_max_attestation_age_ms,
            chat_confidential_profile_window,
            chat_confidential_require_cpu,
            chat_confidential_require_gpu,
            chat_confidential_allow_remote_fallback,
            chat_confidential_status,
        );
    };
    let set_require_gpu_on = move || {
        chat_confidential_require_gpu.set(true);
        persist_chat_confidential_state_with_notice(
            chat_confidential_measurement,
            chat_confidential_policy_mode,
            chat_confidential_max_attestation_age_ms,
            chat_confidential_profile_window,
            chat_confidential_require_cpu,
            chat_confidential_require_gpu,
            chat_confidential_allow_remote_fallback,
            chat_confidential_status,
        );
    };
    let set_require_gpu_off = move || {
        chat_confidential_require_gpu.set(false);
        persist_chat_confidential_state_with_notice(
            chat_confidential_measurement,
            chat_confidential_policy_mode,
            chat_confidential_max_attestation_age_ms,
            chat_confidential_profile_window,
            chat_confidential_require_cpu,
            chat_confidential_require_gpu,
            chat_confidential_allow_remote_fallback,
            chat_confidential_status,
        );
    };
    let set_remote_fallback_on = move || {
        chat_confidential_allow_remote_fallback.set(true);
        persist_chat_confidential_state_with_notice(
            chat_confidential_measurement,
            chat_confidential_policy_mode,
            chat_confidential_max_attestation_age_ms,
            chat_confidential_profile_window,
            chat_confidential_require_cpu,
            chat_confidential_require_gpu,
            chat_confidential_allow_remote_fallback,
            chat_confidential_status,
        );
    };
    let set_remote_fallback_off = move || {
        chat_confidential_allow_remote_fallback.set(false);
        persist_chat_confidential_state_with_notice(
            chat_confidential_measurement,
            chat_confidential_policy_mode,
            chat_confidential_max_attestation_age_ms,
            chat_confidential_profile_window,
            chat_confidential_require_cpu,
            chat_confidential_require_gpu,
            chat_confidential_allow_remote_fallback,
            chat_confidential_status,
        );
    };
    let save_confidential_policy = move || {
        persist_chat_confidential_state_with_notice(
            chat_confidential_measurement,
            chat_confidential_policy_mode,
            chat_confidential_max_attestation_age_ms,
            chat_confidential_profile_window,
            chat_confidential_require_cpu,
            chat_confidential_require_gpu,
            chat_confidential_allow_remote_fallback,
            chat_confidential_status,
        );
        let mode = chat_confidential_policy_mode.get();
        let max_age = chat_confidential_max_attestation_age_ms.get();
        let fallback = chat_confidential_allow_remote_fallback.get();
        chat_confidential_status.set(format!(
            "confidential policy saved (mode={} max_age_ms={} fallback_remote={})",
            clip_text(mode.trim(), 40),
            clip_text(max_age.trim(), 40),
            fallback
        ));
    };
    let save_confidential_profile_window = move || {
        let parsed_window = match parse_profile_window_size_input(
            chat_confidential_profile_window.get().as_str(),
        ) {
            Ok(value) => value,
            Err(error) => {
                chat_confidential_status.set(format!("profile window invalid: {error}"));
                return;
            }
        };
        persist_chat_confidential_state_with_notice(
            chat_confidential_measurement,
            chat_confidential_policy_mode,
            chat_confidential_max_attestation_age_ms,
            chat_confidential_profile_window,
            chat_confidential_require_cpu,
            chat_confidential_require_gpu,
            chat_confidential_allow_remote_fallback,
            chat_confidential_status,
        );
        chat_confidential_status.set(format!(
            "confidential profile window saved (samples={parsed_window})"
        ));
    };
    let prune_expired_confidential_sessions = {
        let confidential_relay_sessions = confidential_relay_sessions.clone();
        move || {
            let now = unix_time_ms_now();
            let pruned = {
                let mut sessions = confidential_relay_sessions.borrow_mut();
                sessions.prune_expired(now)
            };
            persist_confidential_relay_with_notice(
                &confidential_relay_sessions,
                chat_confidential_status,
            );
            chat_confidential_status.set(format!(
                "confidential session prune complete: removed={pruned} at unix_ms={now}"
            ));
        }
    };
    let clear_confidential_sessions = {
        let confidential_relay_sessions = confidential_relay_sessions.clone();
        move || {
            let cleared = {
                let mut sessions = confidential_relay_sessions.borrow_mut();
                sessions.clear()
            };
            persist_confidential_relay_with_notice(
                &confidential_relay_sessions,
                chat_confidential_status,
            );
            chat_confidential_status.set(format!(
                "confidential session history cleared: removed={cleared}"
            ));
        }
    };
    let generate_local = guarded_ui_action("chat.generate_local", Some(chat_status), generate_local);
    let generate_routed =
        guarded_ui_action("chat.generate_routed", Some(chat_status), generate_routed);
    let generate_confidential = guarded_ui_action(
        "chat.generate_confidential",
        Some(chat_confidential_status),
        generate_confidential,
    );
    let set_require_cpu_on = guarded_ui_action(
        "chat.require_cpu_on",
        Some(chat_confidential_status),
        set_require_cpu_on,
    );
    let set_require_cpu_off = guarded_ui_action(
        "chat.require_cpu_off",
        Some(chat_confidential_status),
        set_require_cpu_off,
    );
    let set_require_gpu_on = guarded_ui_action(
        "chat.require_gpu_on",
        Some(chat_confidential_status),
        set_require_gpu_on,
    );
    let set_require_gpu_off = guarded_ui_action(
        "chat.require_gpu_off",
        Some(chat_confidential_status),
        set_require_gpu_off,
    );
    let set_remote_fallback_on = guarded_ui_action(
        "chat.fallback_on",
        Some(chat_confidential_status),
        set_remote_fallback_on,
    );
    let set_remote_fallback_off = guarded_ui_action(
        "chat.fallback_off",
        Some(chat_confidential_status),
        set_remote_fallback_off,
    );
    let save_confidential_policy = guarded_ui_action(
        "chat.save_confidential_policy",
        Some(chat_confidential_status),
        save_confidential_policy,
    );
    let save_confidential_profile_window = guarded_ui_action(
        "chat.save_confidential_profile_window",
        Some(chat_confidential_status),
        save_confidential_profile_window,
    );
    let prune_expired_confidential_sessions = guarded_ui_action(
        "chat.prune_confidential_sessions",
        Some(chat_confidential_status),
        prune_expired_confidential_sessions,
    );
    let clear_confidential_sessions = guarded_ui_action(
        "chat.clear_confidential_sessions",
        Some(chat_confidential_status),
        clear_confidential_sessions,
    );

    v_stack((
        label(|| "Chat"),
        v_stack((
            label(move || format!("Runtime: llama.cpp {}", runtime_version.get())),
            label(move || format!("Health: {}", runtime_health.get())),
            label(move || format!("Process: {}", runtime_process_state.get())),
            label({
                let source_registry = source_registry.clone();
                move || {
                    match source_registry.try_borrow() {
                        Ok(registry) => format!(
                            "chat source default: {}",
                            format_source_role_default(&registry, SourceRole::Chat)
                        ),
                        Err(_) => "chat source default: busy".to_string(),
                    }
                }
            }),
            label({
                let source_registry = source_registry.clone();
                let confidential_relay_sessions = confidential_relay_sessions.clone();
                move || {
                    let registry = match source_registry.try_borrow() {
                        Ok(value) => value,
                        Err(_) => return "placement visibility: busy".to_string(),
                    };
                    let chat_sources = registry.eligible_for(SourceRole::Chat);
                    let local_candidates = chat_sources
                        .iter()
                        .filter(|entry| matches!(entry.kind, SourceKind::LocalModel))
                        .count();
                    let remote_candidates = chat_sources.len().saturating_sub(local_candidates);
                    let confidential_ready = chat_sources
                        .iter()
                        .filter(|entry| {
                            entry
                                .confidential_endpoint
                                .as_ref()
                                .map(|metadata| metadata.enabled)
                                .unwrap_or(false)
                        })
                        .count();
                    let latest_confidential = {
                        match confidential_relay_sessions.try_borrow() {
                            Ok(sessions) => sessions
                                .latest_session()
                                .map(|session| session.source_id.clone())
                                .unwrap_or_else(|| "none".to_string()),
                            Err(_) => "busy".to_string(),
                        }
                    };
                    format!(
                        "placement visibility: local_candidates={} remote_candidates={} confidential_ready={} latest_confidential_source={}",
                        local_candidates, remote_candidates, confidential_ready, latest_confidential
                    )
                }
            }),
            label({
                let confidential_relay_sessions = confidential_relay_sessions.clone();
                move || {
                    let profile_window =
                        parse_profile_window_size_input(chat_confidential_profile_window.get().as_str())
                            .unwrap_or(16);
                    match confidential_relay_sessions.try_borrow() {
                        Ok(sessions) => {
                            let total = sessions.sessions().len();
                            match sessions.profile_summary(profile_window) {
                                Some(summary) => format!(
                                    "confidential profile: samples={} (window={}, total={}) verify(avg/p95)={}/{}ms relay(avg/p95)={}/{}ms total(avg/p95)={}/{}ms",
                                    summary.sample_count,
                                    profile_window,
                                    total,
                                    summary.attestation_verify_avg_ms,
                                    summary.attestation_verify_p95_ms,
                                    summary.relay_roundtrip_avg_ms,
                                    summary.relay_roundtrip_p95_ms,
                                    summary.total_path_avg_ms,
                                    summary.total_path_p95_ms
                                ),
                                None => format!(
                                    "confidential profile: no samples (window={}, total={})",
                                    profile_window, total
                                ),
                            }
                        }
                        Err(_) => "confidential profile: busy".to_string(),
                    }
                }
            }),
            label(move || {
                let baseline = chat_routed_baseline_latency_ms
                    .get()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "n/a".to_string());
                let fallback = chat_confidential_allow_remote_fallback.get();
                format!(
                    "routed baseline: remote_ms={} fallback_remote_consent={}",
                    baseline, fallback
                )
            }),
        ))
        .style(|s| s.row_gap(4.0).color(theme::text_secondary())),
        h_stack((
            label(|| "Host"),
            text_input(llama_host).style(|s| s.min_width(120.0).padding(6.0).color(theme::input_text())),
            label(|| "Port"),
            text_input(llama_port).style(|s| s.min_width(70.0).padding(6.0).color(theme::input_text())),
        ))
        .style(|s| s.gap(6.0)),
        h_stack((
            label(|| "n_predict"),
            text_input(chat_n_predict).style(|s| s.min_width(80.0).padding(6.0).color(theme::input_text())),
            button("Generate Local").action(generate_local),
            button("Generate Routed").action(generate_routed),
            button("Generate Confidential").action(generate_confidential),
        ))
        .style(|s| s.gap(8.0)),
        v_stack((
            h_stack((
                label(|| "Attestation measurement"),
                text_input(chat_confidential_measurement).style(|s| s.min_width(320.0).padding(6.0).color(theme::input_text())),
            )),
            h_stack((
                label(|| "Policy mode"),
                text_input(chat_confidential_policy_mode).style(|s| s.min_width(120.0).padding(6.0).color(theme::input_text())),
                label(|| "Max attestation age ms"),
                text_input(chat_confidential_max_attestation_age_ms)
                    .style(|s| s.min_width(140.0).padding(6.0).color(theme::input_text())),
            )),
            h_stack((
                label(move || {
                    format!(
                        "CPU required={}",
                        if chat_confidential_require_cpu.get() {
                            "true"
                        } else {
                            "false"
                        }
                    )
                }),
                button("CPU Req On").action(set_require_cpu_on),
                button("CPU Req Off").action(set_require_cpu_off),
                label(move || {
                    format!(
                        "GPU required={}",
                        if chat_confidential_require_gpu.get() {
                            "true"
                        } else {
                            "false"
                        }
                    )
                }),
                button("GPU Req On").action(set_require_gpu_on),
                button("GPU Req Off").action(set_require_gpu_off),
                label(move || {
                    format!(
                        "Fallback remote={}",
                        if chat_confidential_allow_remote_fallback.get() {
                            "true"
                        } else {
                            "false"
                        }
                    )
                }),
                button("Fallback On").action(set_remote_fallback_on),
                button("Fallback Off").action(set_remote_fallback_off),
                button("Save Confidential Policy").action(save_confidential_policy),
            )),
            h_stack((
                label(|| "Profile window"),
                text_input(chat_confidential_profile_window)
                    .style(|s| s.min_width(100.0).padding(6.0).color(theme::input_text())),
                button("Save Window").action(save_confidential_profile_window),
                button("Prune Expired Sessions").action(prune_expired_confidential_sessions),
                button("Clear Session History").action(clear_confidential_sessions),
            )),
        ))
        .style(|s| s.row_gap(8.0)),
        h_stack((
            label(|| "Prompt"),
            text_input(chat_prompt).style(|s| s.min_width(420.0).padding(6.0).color(theme::input_text())),
        ))
        .style(|s| s.gap(8.0)),
        label(move || format!("Status: {}", chat_status.get()))
            .style(|s| s.color(theme::text_secondary())),
        label(move || format!("Confidential: {}", chat_confidential_status.get()))
            .style(|s| s.color(theme::text_secondary())),
        scroll(label(move || chat_output.get())).style(|s| {
            s.width_full()
                .height(220.0)
                .padding(8.0)
                .background(theme::surface_1())
        }),
    ))
    .style(|s| s.size_full().padding(12.0).row_gap(8.0))
}

