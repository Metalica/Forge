#[allow(clippy::too_many_arguments)]
fn model_studio_panel(
    runtime_version: RwSignal<String>,
    runtime_health: RwSignal<String>,
    runtime_vulkan_memory_status: RwSignal<String>,
    runtime_vulkan_validation_status: RwSignal<String>,
    runtimes: Rc<RefCell<RuntimeRegistry>>,
    source_registry: Rc<RefCell<SourceRegistry>>,
    model_source_target: RwSignal<String>,
    model_source_role: RwSignal<String>,
    model_confidential_verifier_endpoint: RwSignal<String>,
    model_confidential_expected_provider: RwSignal<String>,
    model_confidential_measurement_prefixes: RwSignal<String>,
    model_confidential_timeout_ms: RwSignal<String>,
    model_confidential_api_key_env_var: RwSignal<String>,
    model_source_status: RwSignal<String>,
) -> impl IntoView {
    fn parse_measurement_prefixes_input(input: &str) -> Vec<String> {
        let mut values = input
            .split([',', ';', '\n', '\r'])
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        values.sort();
        values.dedup();
        values
    }

    fn parse_expected_provider_input(input: &str) -> Option<String> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    fn parse_api_key_env_var_input(input: &str) -> Result<Option<String>, String> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let valid = trimmed
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || value == '_');
        if !valid {
            return Err(
                "verifier api-key env var must contain only A-Z, a-z, 0-9, and _".to_string(),
            );
        }
        Ok(Some(trimmed.to_string()))
    }

    fn default_confidential_metadata(
        source: &SourceEntry,
        verifier_endpoint: &str,
        expected_provider: Option<String>,
        measurement_prefixes: Vec<String>,
        timeout_ms: u64,
        api_key_env_var: Option<String>,
    ) -> ConfidentialEndpointMetadata {
        ConfidentialEndpointMetadata {
            enabled: false,
            expected_target_prefix: source.target.trim().to_string(),
            expected_attestation_provider: expected_provider,
            expected_measurement_prefixes: measurement_prefixes,
            attestation_verifier: AttestationVerifierConfig {
                endpoint: verifier_endpoint.trim().to_string(),
                api_key_env_var,
                timeout_ms,
                ..AttestationVerifierConfig::default()
            },
            encryption_mode: RelayEncryptionMode::TlsHttps,
            declared_logging_policy:
                runtime_registry::confidential_relay::default_declared_logging_policy(),
        }
    }

    let enable_source_action = {
        let source_registry = source_registry.clone();
        move || {
            let target = model_source_target.get().trim().to_string();
            if target.is_empty() {
                model_source_status.set(String::from("source enable skipped: source id is empty"));
                return;
            }
            let mut registry = source_registry.borrow_mut();
            if registry.set_enabled(target.as_str(), true) {
                model_source_status.set(format!("source enabled: {target}"));
                drop(registry);
                persist_source_registry_with_notice(&source_registry, model_source_status);
            } else {
                model_source_status.set(format!("source not found: {target}"));
            }
        }
    };

    let disable_source_action = {
        let source_registry = source_registry.clone();
        move || {
            let target = model_source_target.get().trim().to_string();
            if target.is_empty() {
                model_source_status.set(String::from("source disable skipped: source id is empty"));
                return;
            }
            let mut registry = source_registry.borrow_mut();
            if registry.set_enabled(target.as_str(), false) {
                model_source_status.set(format!("source disabled: {target}"));
                drop(registry);
                persist_source_registry_with_notice(&source_registry, model_source_status);
            } else {
                model_source_status.set(format!("source not found: {target}"));
            }
        }
    };

    let set_role_default_action = {
        let source_registry = source_registry.clone();
        move || {
            let target = model_source_target.get().trim().to_string();
            if target.is_empty() {
                model_source_status.set(String::from("set default skipped: source id is empty"));
                return;
            }
            let role_input = model_source_role.get();
            let Some(role) = parse_source_role_input(role_input.as_str()) else {
                model_source_status.set(format!(
                    "set default blocked: invalid role '{}'",
                    clip_text(&role_input, 80)
                ));
                return;
            };
            let mut registry = source_registry.borrow_mut();
            match registry.set_default_for_role(role, target.as_str()) {
                Ok(()) => {
                    model_source_status.set(format!(
                        "default source set: role={} source={target}",
                        role.label()
                    ));
                    drop(registry);
                    persist_source_registry_with_notice(&source_registry, model_source_status);
                }
                Err(error) => {
                    model_source_status.set(format!(
                        "set default failed: {}",
                        clip_text(&error.to_string(), 140)
                    ));
                }
            }
        }
    };

    let configure_confidential_source_action = {
        let source_registry = source_registry.clone();
        move || {
            let target = model_source_target.get().trim().to_string();
            if target.is_empty() {
                model_source_status.set(String::from(
                    "confidential configure skipped: source id is empty",
                ));
                return;
            }
            let verifier_endpoint = model_confidential_verifier_endpoint
                .get()
                .trim()
                .to_string();
            if verifier_endpoint.is_empty() {
                model_source_status.set(String::from(
                    "confidential configure blocked: verifier endpoint is empty",
                ));
                return;
            }
            if !verifier_endpoint.starts_with("https://") {
                model_source_status.set(String::from(
                    "confidential configure blocked: verifier endpoint must use https",
                ));
                return;
            }
            let expected_provider =
                parse_expected_provider_input(&model_confidential_expected_provider.get());
            let measurement_prefixes =
                parse_measurement_prefixes_input(&model_confidential_measurement_prefixes.get());
            let timeout_ms = match parse_u64(
                model_confidential_timeout_ms.get().as_str(),
                "verifier timeout-ms",
            ) {
                Ok(value) if value > 0 => value,
                Ok(_) => {
                    model_source_status.set(String::from(
                        "confidential configure blocked: verifier timeout-ms must be greater than zero",
                    ));
                    return;
                }
                Err(error) => {
                    model_source_status.set(format!("confidential configure blocked: {error}"));
                    return;
                }
            };
            let api_key_env_var =
                match parse_api_key_env_var_input(&model_confidential_api_key_env_var.get()) {
                    Ok(value) => value,
                    Err(error) => {
                        model_source_status.set(format!("confidential configure blocked: {error}"));
                        return;
                    }
                };

            let mut registry = source_registry.borrow_mut();
            let Some(source) = registry.get(target.as_str()).cloned() else {
                model_source_status.set(format!("source not found: {target}"));
                return;
            };
            if !source.target.trim().starts_with("https://") {
                model_source_status.set(format!(
                    "confidential configure blocked: source {} target is not https",
                    source.id
                ));
                return;
            }

            let mut metadata = source.confidential_endpoint.clone().unwrap_or_else(|| {
                default_confidential_metadata(
                    &source,
                    verifier_endpoint.as_str(),
                    expected_provider.clone(),
                    measurement_prefixes.clone(),
                    timeout_ms,
                    api_key_env_var.clone(),
                )
            });
            metadata.expected_target_prefix = source.target.trim().to_string();
            metadata.attestation_verifier.endpoint = verifier_endpoint.clone();
            metadata.attestation_verifier.timeout_ms = timeout_ms;
            metadata.attestation_verifier.api_key_env_var = api_key_env_var;
            metadata.expected_attestation_provider = expected_provider;
            metadata.expected_measurement_prefixes = measurement_prefixes;
            if metadata.declared_logging_policy.trim().is_empty() {
                metadata.declared_logging_policy =
                    runtime_registry::confidential_relay::default_declared_logging_policy();
            }
            if metadata.attestation_verifier.timeout_ms == 0 {
                metadata.attestation_verifier.timeout_ms = 5_000;
            }

            if registry.set_confidential_endpoint(target.as_str(), Some(metadata)) {
                model_source_status.set(format!(
                    "confidential metadata configured for {} (verifier={})",
                    target, verifier_endpoint
                ));
                drop(registry);
                persist_source_registry_with_notice(&source_registry, model_source_status);
            } else {
                model_source_status.set(format!("source not found: {target}"));
            }
        }
    };

    let enable_confidential_source_action = {
        let source_registry = source_registry.clone();
        move || {
            let target = model_source_target.get().trim().to_string();
            if target.is_empty() {
                model_source_status
                    .set(String::from("confidential on skipped: source id is empty"));
                return;
            }
            let verifier_endpoint = model_confidential_verifier_endpoint
                .get()
                .trim()
                .to_string();
            if verifier_endpoint.is_empty() {
                model_source_status.set(String::from(
                    "confidential on blocked: verifier endpoint is empty",
                ));
                return;
            }
            if !verifier_endpoint.starts_with("https://") {
                model_source_status.set(String::from(
                    "confidential on blocked: verifier endpoint must use https",
                ));
                return;
            }
            let expected_provider =
                parse_expected_provider_input(&model_confidential_expected_provider.get());
            let measurement_prefixes =
                parse_measurement_prefixes_input(&model_confidential_measurement_prefixes.get());
            let timeout_ms = match parse_u64(
                model_confidential_timeout_ms.get().as_str(),
                "verifier timeout-ms",
            ) {
                Ok(value) if value > 0 => value,
                Ok(_) => {
                    model_source_status.set(String::from(
                        "confidential on blocked: verifier timeout-ms must be greater than zero",
                    ));
                    return;
                }
                Err(error) => {
                    model_source_status.set(format!("confidential on blocked: {error}"));
                    return;
                }
            };
            let api_key_env_var =
                match parse_api_key_env_var_input(&model_confidential_api_key_env_var.get()) {
                    Ok(value) => value,
                    Err(error) => {
                        model_source_status.set(format!("confidential on blocked: {error}"));
                        return;
                    }
                };

            let mut registry = source_registry.borrow_mut();
            let Some(source) = registry.get(target.as_str()).cloned() else {
                model_source_status.set(format!("source not found: {target}"));
                return;
            };
            if !source.target.trim().starts_with("https://") {
                model_source_status.set(format!(
                    "confidential on blocked: source {} target is not https",
                    source.id
                ));
                return;
            }

            let mut metadata = source.confidential_endpoint.clone().unwrap_or_else(|| {
                default_confidential_metadata(
                    &source,
                    verifier_endpoint.as_str(),
                    expected_provider.clone(),
                    measurement_prefixes.clone(),
                    timeout_ms,
                    api_key_env_var.clone(),
                )
            });
            metadata.enabled = true;
            metadata.expected_target_prefix = source.target.trim().to_string();
            metadata.attestation_verifier.endpoint = verifier_endpoint.clone();
            metadata.attestation_verifier.timeout_ms = timeout_ms;
            metadata.attestation_verifier.api_key_env_var = api_key_env_var;
            metadata.expected_attestation_provider = expected_provider;
            metadata.expected_measurement_prefixes = measurement_prefixes;
            if metadata.declared_logging_policy.trim().is_empty() {
                metadata.declared_logging_policy =
                    runtime_registry::confidential_relay::default_declared_logging_policy();
            }
            if let Err(error) = metadata.validate_for_source(&source.id, &source.target) {
                model_source_status.set(format!(
                    "confidential on blocked for {}: {}",
                    source.id,
                    clip_text(&error.to_string(), 180)
                ));
                return;
            }

            if registry.set_confidential_endpoint(target.as_str(), Some(metadata)) {
                model_source_status
                    .set(format!("confidential routing enabled for source {target}"));
                drop(registry);
                persist_source_registry_with_notice(&source_registry, model_source_status);
            } else {
                model_source_status.set(format!("source not found: {target}"));
            }
        }
    };

    let disable_confidential_source_action = {
        let source_registry = source_registry.clone();
        move || {
            let target = model_source_target.get().trim().to_string();
            if target.is_empty() {
                model_source_status
                    .set(String::from("confidential off skipped: source id is empty"));
                return;
            }
            let mut registry = source_registry.borrow_mut();
            match registry.set_confidential_endpoint_enabled(target.as_str(), false) {
                Ok(()) => {
                    model_source_status
                        .set(format!("confidential routing disabled for source {target}"));
                    drop(registry);
                    persist_source_registry_with_notice(&source_registry, model_source_status);
                }
                Err(error) => {
                    model_source_status.set(format!(
                        "confidential off failed: {}",
                        clip_text(&error.to_string(), 180)
                    ));
                }
            }
        }
    };

    let reset_sources_action = {
        let source_registry = source_registry.clone();
        move || {
            {
                let mut registry = source_registry.borrow_mut();
                *registry = default_source_registry();
            }
            model_source_status.set(String::from("source registry reset to defaults"));
            persist_source_registry_with_notice(&source_registry, model_source_status);
        }
    };

    let reload_sources_action = {
        let source_registry = source_registry.clone();
        move || {
            let path = source_registry_state_path();
            let Some(mut loaded) = load_source_registry_state(&path) else {
                model_source_status.set(format!("no saved source registry at {}", path.display()));
                return;
            };
            merge_missing_default_sources(&mut loaded);
            {
                let mut registry = source_registry.borrow_mut();
                *registry = loaded;
            }
            model_source_status.set(format!("source registry reloaded from {}", path.display()));
            persist_source_registry_with_notice(&source_registry, model_source_status);
        }
    };
    let enable_source_action = guarded_ui_action(
        "models.enable_source",
        Some(model_source_status),
        enable_source_action,
    );
    let disable_source_action = guarded_ui_action(
        "models.disable_source",
        Some(model_source_status),
        disable_source_action,
    );
    let set_role_default_action = guarded_ui_action(
        "models.set_role_default",
        Some(model_source_status),
        set_role_default_action,
    );
    let configure_confidential_source_action = guarded_ui_action(
        "models.configure_confidential",
        Some(model_source_status),
        configure_confidential_source_action,
    );
    let enable_confidential_source_action = guarded_ui_action(
        "models.enable_confidential",
        Some(model_source_status),
        enable_confidential_source_action,
    );
    let disable_confidential_source_action = guarded_ui_action(
        "models.disable_confidential",
        Some(model_source_status),
        disable_confidential_source_action,
    );
    let reset_sources_action = guarded_ui_action(
        "models.reset_sources",
        Some(model_source_status),
        reset_sources_action,
    );
    let reload_sources_action = guarded_ui_action(
        "models.reload_sources",
        Some(model_source_status),
        reload_sources_action,
    );

    v_stack((
        label(|| "Model Studio"),
        label(move || format!("llama.cpp version: {}", runtime_version.get())),
        label(move || format!("runtime health: {}", runtime_health.get())),
        label({
            let runtimes = runtimes.clone();
            move || {
                match runtimes.try_borrow() {
                    Ok(runtime_registry) => format!(
                        "openjarvis bridge mode a: {}",
                        format_openjarvis_mode_a_summary(&runtime_registry)
                    ),
                    Err(_) => "openjarvis bridge mode a: busy".to_string(),
                }
            }
        })
        .style(|s| s.color(theme::text_secondary())),
        label({
            let runtimes = runtimes.clone();
            move || {
                match runtimes.try_borrow() {
                    Ok(runtime_registry) => format!(
                        "openjarvis bridge mode b: {}",
                        format_openjarvis_mode_b_summary(&runtime_registry)
                    ),
                    Err(_) => "openjarvis bridge mode b: busy".to_string(),
                }
            }
        })
        .style(|s| s.color(theme::text_secondary())),
        label({
            let source_registry = source_registry.clone();
            move || {
                match source_registry.try_borrow() {
                    Ok(registry) => format!(
                        "source registry inventory: {}",
                        format_source_registry_inventory(&registry)
                    ),
                    Err(_) => "source registry inventory: busy".to_string(),
                }
            }
        })
        .style(|s| s.color(theme::text_secondary())),
        label({
            let source_registry = source_registry.clone();
            move || {
                match source_registry.try_borrow() {
                    Ok(registry) => format!(
                        "role defaults: chat={} coder={} codex={} image={} video={}",
                        format_source_role_default(&registry, SourceRole::Chat),
                        format_source_role_default(&registry, SourceRole::Coder),
                        format_source_role_default(&registry, SourceRole::CodexSpecialist),
                        format_source_role_default(&registry, SourceRole::ImageGeneration),
                        format_source_role_default(&registry, SourceRole::VideoGeneration),
                    ),
                    Err(_) => "role defaults: busy".to_string(),
                }
            }
        })
        .style(|s| s.color(theme::text_secondary())),
        v_stack((
            h_stack((
                label(|| "Source ID"),
                text_input(model_source_target).style(|s| s.min_width(320.0).padding(6.0).color(theme::input_text())),
                label(|| "Role"),
                text_input(model_source_role).style(|s| s.min_width(180.0).padding(6.0).color(theme::input_text())),
            ))
            .style(|s| s.items_center().gap(6.0)),
            h_stack((
                label(|| "Verifier endpoint"),
                text_input(model_confidential_verifier_endpoint)
                    .style(|s| s.min_width(360.0).padding(6.0).color(theme::input_text())),
            ))
            .style(|s| s.items_center().gap(6.0)),
            h_stack((
                label(|| "Expected provider"),
                text_input(model_confidential_expected_provider)
                    .style(|s| s.min_width(240.0).padding(6.0).color(theme::input_text())),
                label(|| "Measurement prefixes"),
                text_input(model_confidential_measurement_prefixes)
                    .style(|s| s.min_width(320.0).padding(6.0).color(theme::input_text())),
            ))
            .style(|s| s.items_center().gap(6.0)),
            h_stack((
                label(|| "Verifier timeout-ms"),
                text_input(model_confidential_timeout_ms)
                    .style(|s| s.min_width(120.0).padding(6.0).color(theme::input_text())),
                label(|| "API key env var"),
                text_input(model_confidential_api_key_env_var)
                    .style(|s| s.min_width(220.0).padding(6.0).color(theme::input_text())),
            ))
            .style(|s| s.items_center().gap(6.0)),
            h_stack((
                button("Enable Source").action(enable_source_action),
                button("Disable Source").action(disable_source_action),
                button("Set Role Default").action(set_role_default_action),
                button("Confidential Configure").action(configure_confidential_source_action),
                button("Confidential On").action(enable_confidential_source_action),
                button("Confidential Off").action(disable_confidential_source_action),
                button("Reset Sources").action(reset_sources_action),
                button("Reload Sources").action(reload_sources_action),
            ))
            .style(|s| s.items_center().gap(6.0)),
            v_stack((
                label(move || format!("source policy: {}", model_source_status.get()))
                    .style(|s| s.color(theme::text_secondary())),
                label({
                    let source_registry = source_registry.clone();
                    move || {
                        let target = model_source_target.get().trim().to_string();
                        if target.is_empty() {
                            return "confidential source status: select source id".to_string();
                        }
                        let registry = match source_registry.try_borrow() {
                            Ok(value) => value,
                            Err(_) => return "confidential source status: source registry busy".to_string(),
                        };
                        let Some(source) = registry.get(target.as_str()) else {
                            return format!("confidential source status: source {} not found", target);
                        };
                        match source.confidential_endpoint.as_ref() {
                            Some(metadata) => format!(
                                "confidential source status: enabled={} verifier={} timeout_ms={} api_key_env={} provider={} prefixes={} target_prefix={} encryption={:?} logging_policy={}",
                                if metadata.enabled { "yes" } else { "no" },
                                clip_text(metadata.attestation_verifier.endpoint.as_str(), 80),
                                metadata.attestation_verifier.timeout_ms,
                                metadata
                                    .attestation_verifier
                                    .api_key_env_var
                                    .as_deref()
                                    .unwrap_or("none"),
                                metadata
                                    .expected_attestation_provider
                                    .as_deref()
                                    .unwrap_or("any"),
                                if metadata.expected_measurement_prefixes.is_empty() {
                                    "any".to_string()
                                } else {
                                    clip_text(
                                        metadata.expected_measurement_prefixes.join(", ").as_str(),
                                        48,
                                    )
                                },
                                clip_text(metadata.expected_target_prefix.as_str(), 72),
                                metadata.encryption_mode,
                                clip_text(metadata.declared_logging_policy.as_str(), 48)
                            ),
                            None => format!(
                                "confidential source status: source {} has no confidential metadata",
                                source.id
                            ),
                        }
                    }
                })
                .style(|s| s.color(theme::text_secondary())),
                label(|| {
                    "role keys: chat, planner, coder, codex_specialist, debugger, verifier, image_generation, video_generation"
                })
                .style(|s| s.color(theme::text_secondary())),
            ))
            .style(|s| s.row_gap(4.0)),
        ))
        .style(|s| s.row_gap(6.0)),
        label({
            let runtimes = runtimes.clone();
            move || {
                match runtimes.try_borrow() {
                    Ok(runtime_registry) => match runtime_registry.get("llama.cpp") {
                        Some(entry) => format!(
                            "runtime card: backend={} | pinned={}",
                            format_runtime_backend_badge(entry.backend),
                            if entry.pinned_version { "yes" } else { "no" },
                        ),
                        None => "runtime card: unavailable".to_string(),
                    },
                    Err(_) => "runtime card: busy".to_string(),
                }
            }
        })
        .style(|s| s.color(theme::text_secondary())),
        label({
            let runtimes = runtimes.clone();
            move || {
                match runtimes.try_borrow() {
                    Ok(runtime_registry) => format!(
                        "runtime card rollback metadata: {}",
                        format_runtime_pin_rollback_summary(&runtime_registry, "llama.cpp")
                    ),
                    Err(_) => "runtime card rollback metadata: busy".to_string(),
                }
            }
        })
        .style(|s| s.color(theme::text_secondary())),
        label({
            let runtimes = runtimes.clone();
            move || {
                match runtimes.try_borrow() {
                    Ok(runtime_registry) => format!(
                        "runtime card benchmark history: {}",
                        format_runtime_benchmark_summary(&runtime_registry, "llama.cpp")
                    ),
                    Err(_) => "runtime card benchmark history: busy".to_string(),
                }
            }
        })
        .style(|s| s.color(theme::text_secondary())),
        label(move || format!("vulkan memory: {}", runtime_vulkan_memory_status.get()))
            .style(|s| s.color(theme::text_secondary())),
        label(move || {
            format!(
                "vulkan validation: {}",
                runtime_vulkan_validation_status.get()
            )
        })
        .style(|s| s.color(theme::text_secondary())),
    ))
    .style(|s| s.size_full().padding(12.0).row_gap(6.0))
}

