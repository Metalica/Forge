#[allow(clippy::too_many_arguments)]
fn settings_panel(
    workspace: Rc<WorkspaceHost>,
    feature_registry: Rc<RefCell<FeaturePolicyRegistry>>,
    feature_target: RwSignal<String>,
    feature_policy_status: RwSignal<String>,
    feature_fallback_visible: RwSignal<bool>,
    feature_policy_snapshot: RwSignal<String>,
    runtimes: Rc<RefCell<RuntimeRegistry>>,
    runtime_profile_status: RwSignal<String>,
    runtime_version: RwSignal<String>,
    runtime_health: RwSignal<String>,
    runtime_process_state: RwSignal<String>,
    runtime_process_pid: RwSignal<String>,
    runtime_processes: Rc<RefCell<RuntimeProcessManager>>,
    runtime_vulkan_memory_status: RwSignal<String>,
    runtime_vulkan_validation_status: RwSignal<String>,
    llama_model_path: RwSignal<String>,
    llama_host: RwSignal<String>,
    llama_port: RwSignal<String>,
    llama_ctx_size: RwSignal<String>,
    llama_threads: RwSignal<String>,
    llama_gpu_layers: RwSignal<String>,
    llama_batch_size: RwSignal<String>,
    settings_category: RwSignal<SettingsCategory>,
) -> impl IntoView {
    let topology_placement_status = {
        let registry_ref = feature_registry.borrow();
        RwSignal::new(format_topology_placement_status(&registry_ref))
    };
    let openvino_status = {
        let registry_ref = feature_registry.borrow();
        RwSignal::new(format_openvino_status(&registry_ref))
    };
    let linux_memory_tuning_status = {
        let registry_ref = feature_registry.borrow();
        RwSignal::new(format_linux_memory_tuning_status(&registry_ref))
    };
    let dense_math_status = {
        let registry_ref = feature_registry.borrow();
        RwSignal::new(format_dense_math_status(&registry_ref))
    };
    let allocator_mode_status = {
        let registry_ref = feature_registry.borrow();
        RwSignal::new(format_allocator_mode_status(&registry_ref))
    };
    let profiling_stack_status = {
        let registry_ref = feature_registry.borrow();
        RwSignal::new(format_profiling_stack_status(&registry_ref))
    };
    let release_optimization_status = {
        let registry_ref = feature_registry.borrow();
        RwSignal::new(format_release_optimization_status(&registry_ref))
    };
    let ispc_status = {
        let registry_ref = feature_registry.borrow();
        RwSignal::new(format_ispc_status(&registry_ref))
    };
    let highway_status = {
        let registry_ref = feature_registry.borrow();
        RwSignal::new(format_highway_status(&registry_ref))
    };
    let rust_arch_simd_status = {
        let registry_ref = feature_registry.borrow();
        RwSignal::new(format_rust_arch_simd_status(&registry_ref))
    };
    let rayon_parallelism_status = {
        let registry_ref = feature_registry.borrow();
        RwSignal::new(format_rayon_parallelism_status(&registry_ref))
    };
    let io_uring_status = {
        let registry_ref = feature_registry.borrow();
        RwSignal::new(format_io_uring_status(&registry_ref))
    };
    let lmdb_metadata_status = {
        let registry_ref = feature_registry.borrow();
        RwSignal::new(format_lmdb_metadata_status(&registry_ref))
    };
    let confidential_relay_feature_status = {
        let registry_ref = feature_registry.borrow();
        RwSignal::new(format_confidential_relay_feature_status(&registry_ref))
    };
    let gate_readiness = {
        let registry_ref = feature_registry.borrow();
        RwSignal::new(format_gate_readiness(&registry_ref))
    };
    let gate_artifact = Rc::new(RefCell::new(None::<ConditionalGateArtifact>));
    let gate_artifact_path = RwSignal::new(String::from("not loaded"));
    let gate_artifact_status = RwSignal::new(String::from(
        "gate artifact not loaded (use Load Gate Artifact)",
    ));
    let flag_parity_status = RwSignal::new(String::from("flag parity unavailable"));
    match load_latest_gate_artifact() {
        Ok((path, artifact)) => {
            let status = format_gate_artifact_status_with_validation(&path, &artifact);
            let parity = format_flag_parity(&artifact);
            gate_artifact_path.set(path.display().to_string());
            gate_artifact_status.set(status);
            flag_parity_status.set(parity);
            *gate_artifact.borrow_mut() = Some(artifact);
        }
        Err(error) => {
            gate_artifact_status.set(error);
        }
    }
    let refresh_gate_surface_statuses = move |registry: &FeaturePolicyRegistry| {
        openvino_status.set(format_openvino_status(registry));
        linux_memory_tuning_status.set(format_linux_memory_tuning_status(registry));
        dense_math_status.set(format_dense_math_status(registry));
        allocator_mode_status.set(format_allocator_mode_status(registry));
        profiling_stack_status.set(format_profiling_stack_status(registry));
        release_optimization_status.set(format_release_optimization_status(registry));
        ispc_status.set(format_ispc_status(registry));
        highway_status.set(format_highway_status(registry));
        rust_arch_simd_status.set(format_rust_arch_simd_status(registry));
        rayon_parallelism_status.set(format_rayon_parallelism_status(registry));
        io_uring_status.set(format_io_uring_status(registry));
        lmdb_metadata_status.set(format_lmdb_metadata_status(registry));
        confidential_relay_feature_status.set(format_confidential_relay_feature_status(registry));
        gate_readiness.set(format_gate_readiness(registry));
    };

    let apply_target_state = |target_state: FeatureState, label: &'static str| {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let feature_key = feature_target.get();
            let Some(feature_id) = parse_feature_id_key(&feature_key) else {
                feature_policy_status.set(format!("unknown feature key: {feature_key}"));
                return;
            };
            let mut registry_mut = feature_registry.borrow_mut();
            let set_result = registry_mut.set_requested_state(feature_id, target_state);
            if set_result.is_err() {
                feature_policy_status.set(format!("failed to set state for {feature_key}"));
                return;
            }
            evaluate_registry_with_default_checks(&mut registry_mut);
            let status = registry_mut.status(feature_id);
            let message = match status {
                Some(value) => format!(
                    "{label}: {} -> {:?} ({})",
                    feature_id_key(value.id),
                    value.effective_state,
                    value.reason
                ),
                None => format!("{label}: state applied"),
            };
            feature_policy_status.set(message);
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            topology_placement_status.set(format_topology_placement_status(&registry_mut));
            refresh_gate_surface_statuses(&registry_mut);
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
        }
    };

    let apply_topology_state = |target_state: FeatureState, label: &'static str| {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let mut registry_mut = feature_registry.borrow_mut();
            let result = apply_topology_mode(&mut registry_mut, target_state);
            if let Err(error) = result {
                feature_policy_status.set(format!("topology mode update failed: {error}"));
                return;
            }
            feature_policy_status.set(format!(
                "topology mode {label}: {}",
                format_topology_placement_status(&registry_mut)
            ));
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            topology_placement_status.set(format_topology_placement_status(&registry_mut));
            refresh_gate_surface_statuses(&registry_mut);
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
        }
    };

    let apply_openvino_state = |target_state: FeatureState, label: &'static str| {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let mut registry_mut = feature_registry.borrow_mut();
            let result = apply_openvino_mode(&mut registry_mut, target_state);
            if let Err(error) = result {
                feature_policy_status.set(format!("openvino mode update failed: {error}"));
                return;
            }
            feature_policy_status.set(format!(
                "openvino mode {label}: {}",
                format_openvino_status(&registry_mut)
            ));
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            topology_placement_status.set(format_topology_placement_status(&registry_mut));
            refresh_gate_surface_statuses(&registry_mut);
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
        }
    };

    let apply_linux_memory_tuning_state = |target_state: FeatureState, label: &'static str| {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let mut registry_mut = feature_registry.borrow_mut();
            let result = apply_linux_memory_tuning_mode(&mut registry_mut, target_state);
            if let Err(error) = result {
                feature_policy_status.set(format!("linux memory tuning update failed: {error}"));
                return;
            }
            feature_policy_status.set(format!(
                "linux memory tuning {label}: {}",
                format_linux_memory_tuning_status(&registry_mut)
            ));
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            topology_placement_status.set(format_topology_placement_status(&registry_mut));
            refresh_gate_surface_statuses(&registry_mut);
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
        }
    };

    let apply_dense_math_state = |target_state: FeatureState, label: &'static str| {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let mut registry_mut = feature_registry.borrow_mut();
            let result = apply_dense_math_mode(&mut registry_mut, target_state);
            if let Err(error) = result {
                feature_policy_status.set(format!("dense math backend update failed: {error}"));
                return;
            }
            feature_policy_status.set(format!(
                "dense math backend {label}: {}",
                format_dense_math_status(&registry_mut)
            ));
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            topology_placement_status.set(format_topology_placement_status(&registry_mut));
            refresh_gate_surface_statuses(&registry_mut);
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
        }
    };

    let apply_allocator_mode_state = |target_state: FeatureState, label: &'static str| {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let mut registry_mut = feature_registry.borrow_mut();
            let result = apply_allocator_mode(&mut registry_mut, target_state);
            if let Err(error) = result {
                feature_policy_status.set(format!("allocator mode update failed: {error}"));
                return;
            }
            feature_policy_status.set(format!(
                "allocator mode {label}: {}",
                format_allocator_mode_status(&registry_mut)
            ));
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            topology_placement_status.set(format_topology_placement_status(&registry_mut));
            refresh_gate_surface_statuses(&registry_mut);
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
        }
    };

    let apply_profiling_state = |target_state: FeatureState, label: &'static str| {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let mut registry_mut = feature_registry.borrow_mut();
            let result = apply_profiling_mode(&mut registry_mut, target_state);
            if let Err(error) = result {
                feature_policy_status.set(format!("profiling stack update failed: {error}"));
                return;
            }
            feature_policy_status.set(format!(
                "profiling stack {label}: {}",
                format_profiling_stack_status(&registry_mut)
            ));
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            topology_placement_status.set(format_topology_placement_status(&registry_mut));
            refresh_gate_surface_statuses(&registry_mut);
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
        }
    };

    let apply_release_optimization_state = |target_state: FeatureState, label: &'static str| {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let mut registry_mut = feature_registry.borrow_mut();
            let result = apply_release_optimization_mode(&mut registry_mut, target_state);
            if let Err(error) = result {
                feature_policy_status.set(format!("release optimization update failed: {error}"));
                return;
            }
            feature_policy_status.set(format!(
                "release optimization {label}: {}",
                format_release_optimization_status(&registry_mut)
            ));
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            topology_placement_status.set(format_topology_placement_status(&registry_mut));
            refresh_gate_surface_statuses(&registry_mut);
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
        }
    };

    let apply_ispc_state = |target_state: FeatureState, label: &'static str| {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let mut registry_mut = feature_registry.borrow_mut();
            let result = apply_ispc_mode(&mut registry_mut, target_state);
            if let Err(error) = result {
                feature_policy_status.set(format!("ispc kernel update failed: {error}"));
                return;
            }
            feature_policy_status.set(format!(
                "ispc kernels {label}: {}",
                format_ispc_status(&registry_mut)
            ));
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            topology_placement_status.set(format_topology_placement_status(&registry_mut));
            refresh_gate_surface_statuses(&registry_mut);
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
        }
    };

    let apply_highway_state = |target_state: FeatureState, label: &'static str| {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let mut registry_mut = feature_registry.borrow_mut();
            let result = apply_highway_mode(&mut registry_mut, target_state);
            if let Err(error) = result {
                feature_policy_status.set(format!("highway simd update failed: {error}"));
                return;
            }
            feature_policy_status.set(format!(
                "highway simd {label}: {}",
                format_highway_status(&registry_mut)
            ));
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            topology_placement_status.set(format_topology_placement_status(&registry_mut));
            refresh_gate_surface_statuses(&registry_mut);
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
        }
    };

    let apply_rust_arch_simd_state = |target_state: FeatureState, label: &'static str| {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let mut registry_mut = feature_registry.borrow_mut();
            let result = apply_rust_arch_simd_mode(&mut registry_mut, target_state);
            if let Err(error) = result {
                feature_policy_status.set(format!("rust arch simd update failed: {error}"));
                return;
            }
            feature_policy_status.set(format!(
                "rust arch simd {label}: {}",
                format_rust_arch_simd_status(&registry_mut)
            ));
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            topology_placement_status.set(format_topology_placement_status(&registry_mut));
            refresh_gate_surface_statuses(&registry_mut);
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
        }
    };

    let apply_rayon_state = |target_state: FeatureState, label: &'static str| {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let mut registry_mut = feature_registry.borrow_mut();
            let result = apply_rayon_mode(&mut registry_mut, target_state);
            if let Err(error) = result {
                feature_policy_status.set(format!("rayon parallelism update failed: {error}"));
                return;
            }
            feature_policy_status.set(format!(
                "rayon parallelism {label}: {}",
                format_rayon_parallelism_status(&registry_mut)
            ));
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            topology_placement_status.set(format_topology_placement_status(&registry_mut));
            refresh_gate_surface_statuses(&registry_mut);
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
        }
    };

    let apply_io_uring_state = |target_state: FeatureState, label: &'static str| {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let mut registry_mut = feature_registry.borrow_mut();
            let result = apply_io_uring_mode(&mut registry_mut, target_state);
            if let Err(error) = result {
                feature_policy_status.set(format!("io_uring update failed: {error}"));
                return;
            }
            feature_policy_status.set(format!(
                "io_uring {label}: {}",
                format_io_uring_status(&registry_mut)
            ));
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            topology_placement_status.set(format_topology_placement_status(&registry_mut));
            refresh_gate_surface_statuses(&registry_mut);
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
        }
    };

    let apply_lmdb_metadata_state = |target_state: FeatureState, label: &'static str| {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let mut registry_mut = feature_registry.borrow_mut();
            let result = apply_lmdb_metadata_mode(&mut registry_mut, target_state);
            if let Err(error) = result {
                feature_policy_status.set(format!("lmdb metadata update failed: {error}"));
                return;
            }
            feature_policy_status.set(format!(
                "lmdb metadata {label}: {}",
                format_lmdb_metadata_status(&registry_mut)
            ));
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            topology_placement_status.set(format_topology_placement_status(&registry_mut));
            refresh_gate_surface_statuses(&registry_mut);
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
        }
    };

    let apply_confidential_relay_feature_state =
        |target_state: FeatureState, label: &'static str| {
            let feature_registry = feature_registry.clone();
            let runtimes = runtimes.clone();
            move || {
                let mut registry_mut = feature_registry.borrow_mut();
                let result = apply_confidential_relay_feature_mode(&mut registry_mut, target_state);
                if let Err(error) = result {
                    feature_policy_status.set(format!("confidential relay update failed: {error}"));
                    return;
                }
                feature_policy_status.set(format!(
                    "confidential relay {label}: {}",
                    format_confidential_relay_feature_status(&registry_mut)
                ));
                feature_policy_snapshot.set(format_feature_policy_snapshot(
                    &registry_mut,
                    feature_fallback_visible.get(),
                ));
                topology_placement_status.set(format_topology_placement_status(&registry_mut));
                refresh_gate_surface_statuses(&registry_mut);
                let runtime_registry_ref = runtimes.borrow();
                sync_runtime_vulkan_card_status(
                    &runtime_registry_ref,
                    &registry_mut,
                    runtime_vulkan_memory_status,
                    runtime_vulkan_validation_status,
                );
            }
        };

    let load_gate_artifact_action = {
        let gate_artifact = gate_artifact.clone();
        move || match load_latest_gate_artifact() {
            Ok((path, artifact)) => {
                let status = format_gate_artifact_status_with_validation(&path, &artifact);
                let parity = format_flag_parity(&artifact);
                gate_artifact_path.set(path.display().to_string());
                gate_artifact_status.set(status.clone());
                flag_parity_status.set(parity.clone());
                *gate_artifact.borrow_mut() = Some(artifact);
                feature_policy_status.set(format!("gate artifact loaded: {status} | {parity}"));
            }
            Err(error) => {
                gate_artifact_status.set(error.clone());
                feature_policy_status.set(format!("gate artifact load failed: {error}"));
            }
        }
    };

    let run_gate_now_action = {
        let gate_artifact = gate_artifact.clone();
        let workspace = workspace.clone();
        move || {
            let command = gate_run_command();
            match workspace.run_terminal_command(command) {
                Ok(output) => {
                    if output.exit_code != 0 {
                        let stderr = clip_text(output.stderr.trim(), 180);
                        feature_policy_status.set(format!(
                            "gate run failed (exit {}): {}",
                            output.exit_code,
                            if stderr.is_empty() {
                                "see terminal output"
                            } else {
                                &stderr
                            }
                        ));
                        return;
                    }
                    match load_latest_gate_artifact() {
                        Ok((path, artifact)) => {
                            let status =
                                format_gate_artifact_status_with_validation(&path, &artifact);
                            let parity = format_flag_parity(&artifact);
                            gate_artifact_path.set(path.display().to_string());
                            gate_artifact_status.set(status.clone());
                            flag_parity_status.set(parity.clone());
                            *gate_artifact.borrow_mut() = Some(artifact);
                            let stdout = clip_text(output.stdout.trim(), 120);
                            feature_policy_status.set(format!(
                                "gate run complete: {} | {}{}",
                                status,
                                parity,
                                if stdout.is_empty() {
                                    String::new()
                                } else {
                                    format!(" | output={stdout}")
                                }
                            ));
                        }
                        Err(error) => {
                            feature_policy_status.set(format!(
                                "gate run finished but artifact refresh failed: {error}"
                            ));
                        }
                    }
                }
                Err(error) => {
                    feature_policy_status.set(format!(
                        "gate run command failed: {}",
                        clip_text(&format!("{error:?}"), 180)
                    ));
                }
            }
        }
    };

    let apply_gate_defaults_action = {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        let gate_artifact = gate_artifact.clone();
        move || {
            let artifact = if let Some(existing) = gate_artifact.borrow().clone() {
                existing
            } else {
                match load_latest_gate_artifact() {
                    Ok((path, loaded)) => {
                        let status = format_gate_artifact_status_with_validation(&path, &loaded);
                        let parity = format_flag_parity(&loaded);
                        gate_artifact_path.set(path.display().to_string());
                        gate_artifact_status.set(status);
                        flag_parity_status.set(parity);
                        *gate_artifact.borrow_mut() = Some(loaded.clone());
                        loaded
                    }
                    Err(error) => {
                        feature_policy_status.set(format!("gate defaults apply skipped: {error}"));
                        return;
                    }
                }
            };
            if let Err(error) = validate_gate_artifact_for_defaults(&artifact) {
                feature_policy_status.set(format!("gate defaults apply skipped: {error}"));
                return;
            }

            let openvino_state =
                match parse_selected_default_state(&artifact.selected_defaults.openvino_backend) {
                    Ok(value) => value,
                    Err(error) => {
                        feature_policy_status.set(format!("gate defaults apply skipped: {error}"));
                        return;
                    }
                };
            let memory_state = match parse_selected_default_state(
                &artifact.selected_defaults.linux_memory_tuning_profile,
            ) {
                Ok(value) => value,
                Err(error) => {
                    feature_policy_status.set(format!("gate defaults apply skipped: {error}"));
                    return;
                }
            };
            let openblas_state =
                match parse_selected_default_state(&artifact.selected_defaults.openblas_backend) {
                    Ok(value) => value,
                    Err(error) => {
                        feature_policy_status.set(format!("gate defaults apply skipped: {error}"));
                        return;
                    }
                };
            let blis_state =
                match parse_selected_default_state(&artifact.selected_defaults.blis_backend) {
                    Ok(value) => value,
                    Err(error) => {
                        feature_policy_status.set(format!("gate defaults apply skipped: {error}"));
                        return;
                    }
                };
            let profiling_state =
                match parse_selected_default_state(&artifact.selected_defaults.profiling_mode) {
                    Ok(value) => value,
                    Err(error) => {
                        feature_policy_status.set(format!("gate defaults apply skipped: {error}"));
                        return;
                    }
                };
            let release_optimization_state = match parse_selected_default_state(
                &artifact.selected_defaults.release_optimization_mode,
            ) {
                Ok(value) => value,
                Err(error) => {
                    feature_policy_status.set(format!("gate defaults apply skipped: {error}"));
                    return;
                }
            };
            let ispc_state =
                match parse_selected_default_state(&artifact.selected_defaults.ispc_kernels) {
                    Ok(value) => value,
                    Err(error) => {
                        feature_policy_status.set(format!("gate defaults apply skipped: {error}"));
                        return;
                    }
                };
            let highway_state =
                match parse_selected_default_state(&artifact.selected_defaults.highway_simd) {
                    Ok(value) => value,
                    Err(error) => {
                        feature_policy_status.set(format!("gate defaults apply skipped: {error}"));
                        return;
                    }
                };
            let rust_arch_simd_state =
                match parse_selected_default_state(&artifact.selected_defaults.rust_arch_simd) {
                    Ok(value) => value,
                    Err(error) => {
                        feature_policy_status.set(format!("gate defaults apply skipped: {error}"));
                        return;
                    }
                };
            let rayon_state =
                match parse_selected_default_state(&artifact.selected_defaults.rayon_parallelism) {
                    Ok(value) => value,
                    Err(error) => {
                        feature_policy_status.set(format!("gate defaults apply skipped: {error}"));
                        return;
                    }
                };

            let mut registry_mut = feature_registry.borrow_mut();
            if let Err(error) = apply_openvino_mode(&mut registry_mut, openvino_state) {
                feature_policy_status
                    .set(format!("gate defaults apply failed for openvino: {error}"));
                return;
            }
            if let Err(error) = apply_linux_memory_tuning_mode(&mut registry_mut, memory_state) {
                feature_policy_status.set(format!(
                    "gate defaults apply failed for linux memory profile: {error}"
                ));
                return;
            }
            if let Err(error) =
                registry_mut.set_requested_state(FeatureId::OpenBlasBackend, openblas_state)
            {
                feature_policy_status.set(format!(
                    "gate defaults apply failed for openblas backend: {error:?}"
                ));
                return;
            }
            if let Err(error) = registry_mut.set_requested_state(FeatureId::BlisBackend, blis_state)
            {
                feature_policy_status.set(format!(
                    "gate defaults apply failed for blis backend: {error:?}"
                ));
                return;
            }
            if let Err(error) = apply_profiling_mode(&mut registry_mut, profiling_state) {
                feature_policy_status.set(format!(
                    "gate defaults apply failed for profiling mode: {error}"
                ));
                return;
            }
            if let Err(error) =
                apply_release_optimization_mode(&mut registry_mut, release_optimization_state)
            {
                feature_policy_status.set(format!(
                    "gate defaults apply failed for release optimization mode: {error}"
                ));
                return;
            }
            if let Err(error) = apply_ispc_mode(&mut registry_mut, ispc_state) {
                feature_policy_status
                    .set(format!("gate defaults apply failed for ispc mode: {error}"));
                return;
            }
            if let Err(error) = apply_highway_mode(&mut registry_mut, highway_state) {
                feature_policy_status.set(format!(
                    "gate defaults apply failed for highway mode: {error}"
                ));
                return;
            }
            if let Err(error) = apply_rust_arch_simd_mode(&mut registry_mut, rust_arch_simd_state) {
                feature_policy_status.set(format!(
                    "gate defaults apply failed for rust arch simd mode: {error}"
                ));
                return;
            }
            if let Err(error) = apply_rayon_mode(&mut registry_mut, rayon_state) {
                feature_policy_status.set(format!(
                    "gate defaults apply failed for rayon mode: {error}"
                ));
                return;
            }
            evaluate_registry_with_default_checks(&mut registry_mut);

            let note = format!(
                "gate defaults applied: openvino={:?}, linux_memory_tuning={:?}, openblas={:?}, blis={:?}, profiling={:?}, release_opt={:?}, ispc={:?}, highway={:?}, rust_arch_simd={:?}, rayon={:?} (benchmark evidence flags remain explicit env controls)",
                openvino_state,
                memory_state,
                openblas_state,
                blis_state,
                profiling_state,
                release_optimization_state,
                ispc_state,
                highway_state,
                rust_arch_simd_state,
                rayon_state
            );
            feature_policy_status.set(note);
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            topology_placement_status.set(format_topology_placement_status(&registry_mut));
            refresh_gate_surface_statuses(&registry_mut);
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
        }
    };

    let show_gate_env_commands_action = {
        let gate_artifact = gate_artifact.clone();
        move || {
            let artifact = if let Some(existing) = gate_artifact.borrow().clone() {
                existing
            } else {
                match load_latest_gate_artifact() {
                    Ok((path, loaded)) => {
                        let status = format_gate_artifact_status_with_validation(&path, &loaded);
                        let parity = format_flag_parity(&loaded);
                        gate_artifact_path.set(path.display().to_string());
                        gate_artifact_status.set(status);
                        flag_parity_status.set(parity);
                        *gate_artifact.borrow_mut() = Some(loaded.clone());
                        loaded
                    }
                    Err(error) => {
                        feature_policy_status
                            .set(format!("env command preview unavailable: {error}"));
                        return;
                    }
                }
            };
            let commands = format_gate_env_commands(&artifact);
            feature_policy_status.set(format!("recommended benchmark flags: {commands}"));
        }
    };

    let apply_recommended_flags_action = {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        let gate_artifact = gate_artifact.clone();
        move || {
            let artifact = if let Some(existing) = gate_artifact.borrow().clone() {
                existing
            } else {
                match load_latest_gate_artifact() {
                    Ok((path, loaded)) => {
                        let status = format_gate_artifact_status_with_validation(&path, &loaded);
                        let parity = format_flag_parity(&loaded);
                        gate_artifact_path.set(path.display().to_string());
                        gate_artifact_status.set(status);
                        flag_parity_status.set(parity);
                        *gate_artifact.borrow_mut() = Some(loaded.clone());
                        loaded
                    }
                    Err(error) => {
                        feature_policy_status
                            .set(format!("apply recommended flags unavailable: {error}"));
                        return;
                    }
                }
            };

            let applied = match apply_recommended_flags(&artifact) {
                Ok(count) => count,
                Err(error) => {
                    feature_policy_status.set(format!("apply recommended flags failed: {error}"));
                    return;
                }
            };
            let parity = format_flag_parity(&artifact);
            flag_parity_status.set(parity.clone());

            let mut registry_mut = feature_registry.borrow_mut();
            evaluate_registry_with_default_checks(&mut registry_mut);
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            topology_placement_status.set(format_topology_placement_status(&registry_mut));
            refresh_gate_surface_statuses(&registry_mut);
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
            feature_policy_status.set(format!(
                "applied {applied} recommended benchmark flags in-process | {parity}"
            ));
        }
    };

    let clear_recommended_flags_action = {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        let gate_artifact = gate_artifact.clone();
        move || {
            let cleared = clear_recommended_flags();
            if let Some(artifact) = gate_artifact.borrow().clone() {
                flag_parity_status.set(format_flag_parity(&artifact));
            } else {
                flag_parity_status
                    .set("flag parity unavailable (load artifact to compare)".to_string());
            }

            let mut registry_mut = feature_registry.borrow_mut();
            evaluate_registry_with_default_checks(&mut registry_mut);
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            topology_placement_status.set(format_topology_placement_status(&registry_mut));
            refresh_gate_surface_statuses(&registry_mut);
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
            feature_policy_status.set(format!("cleared {cleared} benchmark evidence env flags"));
        }
    };

    let check_flag_parity_action = {
        let gate_artifact = gate_artifact.clone();
        move || {
            let artifact = if let Some(existing) = gate_artifact.borrow().clone() {
                existing
            } else {
                match load_latest_gate_artifact() {
                    Ok((path, loaded)) => {
                        let status = format_gate_artifact_status_with_validation(&path, &loaded);
                        gate_artifact_path.set(path.display().to_string());
                        gate_artifact_status.set(status);
                        *gate_artifact.borrow_mut() = Some(loaded.clone());
                        loaded
                    }
                    Err(error) => {
                        feature_policy_status
                            .set(format!("flag parity check unavailable: {error}"));
                        return;
                    }
                }
            };
            let parity = format_flag_parity(&artifact);
            flag_parity_status.set(parity.clone());
            feature_policy_status.set(format!("flag parity check: {parity}"));
        }
    };

    let mark_fallback = {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let feature_key = feature_target.get();
            let Some(feature_id) = parse_feature_id_key(&feature_key) else {
                feature_policy_status.set(format!("unknown feature key: {feature_key}"));
                return;
            };
            let mut registry_mut = feature_registry.borrow_mut();
            let result = registry_mut.report_runtime_failure(feature_id, "manual simulation");
            if result.is_err() {
                feature_policy_status.set(format!("failed to mark fallback for {feature_key}"));
                return;
            }
            feature_policy_status.set(format!(
                "fallback forced for {}",
                feature_id_key(feature_id)
            ));
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            topology_placement_status.set(format_topology_placement_status(&registry_mut));
            refresh_gate_surface_statuses(&registry_mut);
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
        }
    };

    let clear_fallback = {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let feature_key = feature_target.get();
            let Some(feature_id) = parse_feature_id_key(&feature_key) else {
                feature_policy_status.set(format!("unknown feature key: {feature_key}"));
                return;
            };
            let mut registry_mut = feature_registry.borrow_mut();
            if registry_mut.clear_session_fallback(feature_id).is_err() {
                feature_policy_status.set(format!("failed to clear fallback for {feature_key}"));
                return;
            }
            evaluate_registry_with_default_checks(&mut registry_mut);
            feature_policy_status.set(format!(
                "fallback cleared for {}",
                feature_id_key(feature_id)
            ));
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            topology_placement_status.set(format_topology_placement_status(&registry_mut));
            refresh_gate_surface_statuses(&registry_mut);
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
        }
    };

    let toggle_fallback_visibility = {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            feature_fallback_visible.update(|value| *value = !*value);
            let registry_ref = feature_registry.borrow();
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_ref,
                feature_fallback_visible.get(),
            ));
            topology_placement_status.set(format_topology_placement_status(&registry_ref));
            refresh_gate_surface_statuses(&registry_ref);
            feature_policy_status.set(format!(
                "fallback visibility: {}",
                if feature_fallback_visible.get() {
                    "shown"
                } else {
                    "hidden"
                }
            ));
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_ref,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
        }
    };

    let reset_safe_defaults = {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let mut registry_mut = feature_registry.borrow_mut();
            registry_mut.reset_to_safe_defaults();
            evaluate_registry_with_default_checks(&mut registry_mut);
            feature_policy_status.set(String::from("policy reset to safe defaults (auto)"));
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            topology_placement_status.set(format_topology_placement_status(&registry_mut));
            refresh_gate_surface_statuses(&registry_mut);
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
        }
    };

    let save_preferences = {
        let feature_registry = feature_registry.clone();
        move || {
            let registry_ref = feature_registry.borrow();
            let settings =
                collect_persisted_feature_settings(&registry_ref, feature_fallback_visible.get());
            let path = feature_policy_settings_path();
            match save_feature_policy_settings(&path, &settings) {
                Ok(()) => feature_policy_status
                    .set(format!("saved policy settings to {}", path.display())),
                Err(error) => feature_policy_status.set(format!("save failed: {error}")),
            }
        }
    };

    let reload_preferences = {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let path = feature_policy_settings_path();
            let Some(settings) = load_feature_policy_settings(&path) else {
                feature_policy_status.set(format!("no saved settings at {}", path.display()));
                return;
            };
            feature_fallback_visible.set(settings.fallback_visibility);
            let mut registry_mut = feature_registry.borrow_mut();
            registry_mut.reset_to_safe_defaults();
            for feature in settings.features {
                let _ = registry_mut.set_requested_state(feature.id, feature.requested_state);
            }
            evaluate_registry_with_default_checks(&mut registry_mut);
            feature_policy_status.set(format!("reloaded policy settings from {}", path.display()));
            feature_policy_snapshot.set(format_feature_policy_snapshot(
                &registry_mut,
                feature_fallback_visible.get(),
            ));
            topology_placement_status.set(format_topology_placement_status(&registry_mut));
            refresh_gate_surface_statuses(&registry_mut);
            let runtime_registry_ref = runtimes.borrow();
            sync_runtime_vulkan_card_status(
                &runtime_registry_ref,
                &registry_mut,
                runtime_vulkan_memory_status,
                runtime_vulkan_validation_status,
            );
        }
    };

    let apply_vulkan_memory_state = |target_state: FeatureState, label: &'static str| {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let mut registry_mut = feature_registry.borrow_mut();
            let result = registry_mut.set_requested_state(FeatureId::VulkanMemoryAllocator, target_state);
            if let Err(error) = result {
                feature_policy_status.set(format!("vulkan memory update failed: {error:?}"));
                return;
            }
            evaluate_registry_with_default_checks(&mut registry_mut);
            if matches!(target_state, FeatureState::Disabled) {
                llama_gpu_layers.set(String::from("0"));
            }
            let status = registry_mut.status(FeatureId::VulkanMemoryAllocator);
            let summary = match status {
                Some(value) => format!(
                    "vulkan memory {label}: requested={:?} effective={:?} ({})",
                    value.requested_state,
                    value.effective_state,
                    clip_text(&value.reason, 90)
                ),
                None => String::from("vulkan memory status unavailable"),
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
        }
    };

    let refresh_vulkan_policy_gate = {
        let feature_registry = feature_registry.clone();
        let runtimes = runtimes.clone();
        move || {
            let mut registry_mut = feature_registry.borrow_mut();
            let runtime_registry_ref = runtimes.borrow();
            let gate_note =
                apply_vulkan_benchmark_gate_from_registry(&runtime_registry_ref, &mut registry_mut);
            let status = registry_mut.status(FeatureId::VulkanMemoryAllocator);
            let summary = match status {
                Some(value) => format!(
                    "vulkan update: requested={:?} effective={:?} ({}) | gate={}",
                    value.requested_state,
                    value.effective_state,
                    clip_text(&value.reason, 90),
                    clip_text(&gate_note, 90)
                ),
                None => String::from("vulkan update: status unavailable"),
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
        }
    };

    let update_llama_runtime_action = {
        let runtimes = runtimes.clone();
        let feature_registry = feature_registry.clone();
        move || {
            let mut runtime_registry = runtimes.borrow_mut();
            let update_note = match runtime_registry.update_version("llama.cpp", "0.1.0-phase1") {
                UpdateResult::Updated => {
                    let _ = runtime_registry.set_health("llama.cpp", RuntimeHealth::Unknown);
                    String::from("llama.cpp metadata updated")
                }
                UpdateResult::AlreadyCurrent => String::from("llama.cpp metadata already current"),
                UpdateResult::BlockedByPin => String::from("llama.cpp update blocked by pin"),
                UpdateResult::RuntimeNotFound => String::from("llama.cpp runtime missing"),
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
            runtime_profile_status.set(update_note);
        }
    };

    let start_llama_runtime_action = {
        let runtimes = runtimes.clone();
        let runtime_processes = runtime_processes.clone();
        let feature_registry = feature_registry.clone();
        move || {
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
                runtime_profile_status
                    .set(String::from("llama.cpp start forced gpu-layers=0 (vulkan inactive)"));
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
                    runtime_profile_status.set(match start_result {
                        StartResult::Started | StartResult::AlreadyRunning => {
                            String::from("llama.cpp runtime start requested")
                        }
                        StartResult::LaunchFailed => {
                            String::from("llama.cpp runtime launch failed (check process state)")
                        }
                    });
                    drop(runtime_registry);
                    persist_runtime_registry_with_notice(&runtimes, runtime_profile_status);
                }
                Err(error) => {
                    runtime_process_state.set(String::from("launch aborted"));
                    runtime_profile_status.set(format!("llama.cpp profile invalid: {error}"));
                }
            }
        }
    };

    let stop_llama_runtime_action = {
        let runtimes = runtimes.clone();
        let runtime_processes = runtime_processes.clone();
        let feature_registry = feature_registry.clone();
        move || {
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
            runtime_profile_status.set(match stop_result {
                StopResult::Stopped => String::from("llama.cpp runtime stop requested"),
                StopResult::NotRunning => String::from("llama.cpp runtime already stopped"),
                StopResult::UnknownRuntime => String::from("llama.cpp runtime missing"),
            });
            drop(runtime_registry);
            persist_runtime_registry_with_notice(&runtimes, runtime_profile_status);
        }
    };

    let general_section = Stack::vertical((
        Label::derived(|| "General"),
        Stack::vertical((
            Label::derived(|| "Topology placement mode"),
            Stack::horizontal((
                Button::new("Topology Enable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_topology_state(FeatureState::Enabled, "enabled"),
                )),
                Button::new("Topology Auto").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_topology_state(FeatureState::Auto, "auto"),
                )),
                Button::new("Topology Disable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_topology_state(FeatureState::Disabled, "disabled"),
                )),
            ))
            .style(|s| s.gap(8.0)),
            Label::derived(move || format!("Placement status: {}", topology_placement_status.get()))
                .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
        Stack::vertical((
            Label::derived(|| "Confidential relay feature mode"),
            Stack::horizontal((
                Button::new("Confidential Enable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_confidential_relay_feature_state(FeatureState::Enabled, "enabled"),
                )),
                Button::new("Confidential Auto").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_confidential_relay_feature_state(FeatureState::Auto, "auto"),
                )),
                Button::new("Confidential Disable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_confidential_relay_feature_state(FeatureState::Disabled, "disabled"),
                )),
            ))
            .style(|s| s.gap(8.0)),
            Label::derived(move || {
                format!(
                    "Confidential feature status: {}",
                    confidential_relay_feature_status.get()
                )
            })
            .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
        Stack::vertical((
            Button::new("Feature policy states")
                .style(|s| s.padding_horiz(10.0).padding_vert(4.0).width(190.0)),
            Stack::horizontal((
                Button::new("Disabled").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_target_state(FeatureState::Disabled, "disabled"),
                )),
                Button::new("Available").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_target_state(FeatureState::Available, "available"),
                )),
                Button::new("Enabled").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_target_state(FeatureState::Enabled, "enabled"),
                )),
                Button::new("Auto").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_target_state(FeatureState::Auto, "auto"),
                )),
                Button::new("Fallback").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_target_state(FeatureState::Fallback, "fallback"),
                )),
            ))
            .style(|s| s.gap(12.0)),
            Stack::horizontal((
                Label::derived(|| "Feature key").style(|s| s.color(theme::text_secondary())),
                TextInput::new(feature_target)
                    .style(|s| s.min_width(220.0).padding(6.0).color(theme::input_text())),
                Button::new("Enable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_target_state(FeatureState::Enabled, "enabled"),
                )),
                Button::new("Disable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_target_state(FeatureState::Disabled, "disabled"),
                )),
                Button::new("Auto").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_target_state(FeatureState::Auto, "auto"),
                )),
                Button::new("Mark Fallback").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    mark_fallback,
                )),
                Button::new("Clear Fallback").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    clear_fallback,
                )),
            ))
            .style(|s| s.gap(8.0)),
            Stack::horizontal((
                Button::new("Toggle Fallback Visibility").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    toggle_fallback_visibility,
                )),
                Button::new("Reset Safe Defaults").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    reset_safe_defaults,
                )),
                Button::new("Save Preferences").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    save_preferences,
                )),
                Button::new("Reload Preferences").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    reload_preferences,
                )),
            ))
            .style(|s| s.gap(8.0)),
            Label::derived(|| {
                format!(
                    "Settings file: {}",
                    feature_policy_settings_path().display()
                )
            })
            .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| {
            s.row_gap(10.0)
                .padding(12.0)
                .background(theme::surface_2())
                .border(1.0)
        }),
        Stack::vertical((
            Label::derived(|| "Policy snapshot").style(|s| s.color(theme::text_secondary())),
            Scroll::new(
                Label::derived(move || feature_policy_snapshot.get())
                    .style(|s| s.color(theme::text_secondary())),
            )
            .style(|s| {
                s.width_full()
                    .height(260.0)
                    .padding(8.0)
                    .background(theme::surface_1())
            }),
        ))
        .style(|s| s.row_gap(8.0)),
        Stack::vertical((
            Label::derived(|| "Benchmark Evidence Artifact"),
            Stack::horizontal((
                Button::new("Run Gate Now").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    run_gate_now_action,
                )),
                Button::new("Load Gate Artifact").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    load_gate_artifact_action,
                )),
                Button::new("Apply Gate Defaults").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_gate_defaults_action,
                )),
                Button::new("Apply Recommended Flags").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_recommended_flags_action,
                )),
                Button::new("Clear Recommended Flags").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    clear_recommended_flags_action,
                )),
                Button::new("Show Env Commands").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    show_gate_env_commands_action,
                )),
                Button::new("Check Flag Parity").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    check_flag_parity_action,
                )),
            ))
            .style(|s| s.gap(8.0)),
            Label::derived(move || format!("Artifact path: {}", gate_artifact_path.get()))
                .style(|s| s.color(theme::text_secondary())),
            Label::derived(move || format!("Artifact status: {}", gate_artifact_status.get()))
                .style(|s| s.color(theme::text_secondary())),
            Label::derived(move || format!("Flag parity: {}", flag_parity_status.get()))
                .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
    ))
    .style(|s| s.row_gap(8.0).padding(8.0).background(theme::surface_1()));

    let ui_section = Stack::vertical((
        Label::derived(|| "UI"),
        Stack::vertical((
            Label::derived(|| "UI text color policy"),
            Label::derived(|| "Button text color: black (global override active)")
                .style(|s| s.color(theme::text_secondary())),
            Label::derived(|| "Input text color: black (global override active)")
                .style(|s| s.color(theme::text_secondary())),
            Label::derived(|| "Use this category for upcoming UI-only controls.")
                .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
    ))
    .style(|s| s.row_gap(8.0).padding(8.0).background(theme::surface_1()));

    let windows_section = Stack::vertical((
        Label::derived(|| "Windows").style(|s| s.color(theme::warning()).font_size(16.0)),
        Stack::vertical((
            Label::derived(|| "OpenVINO mode").style(|s| s.color(theme::warning())),
            Stack::horizontal((
                Button::new("OpenVINO Enable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_openvino_state(FeatureState::Enabled, "enabled"),
                )),
                Button::new("OpenVINO Auto").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_openvino_state(FeatureState::Auto, "auto"),
                )),
                Button::new("OpenVINO Disable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_openvino_state(FeatureState::Disabled, "disabled"),
                )),
            ))
            .style(|s| s.gap(8.0)),
            Label::derived(move || format!("OpenVINO status: {}", openvino_status.get()))
                .style(|s| s.color(theme::warning())),
        ))
        .style(|s| s.row_gap(8.0)),
    ))
    .style(|s| s.row_gap(12.0).padding(8.0).background(theme::surface_1()));

    let linux_section = Stack::vertical((
        Label::derived(|| "Linux"),
        Stack::vertical((
            Label::derived(|| "Linux memory tuning profile (THP + zswap + zram)"),
            Stack::horizontal((
                Button::new("Memory Enable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_linux_memory_tuning_state(FeatureState::Enabled, "enabled"),
                )),
                Button::new("Memory Auto").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_linux_memory_tuning_state(FeatureState::Auto, "auto"),
                )),
                Button::new("Memory Disable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_linux_memory_tuning_state(FeatureState::Disabled, "disabled"),
                )),
            ))
            .style(|s| s.gap(8.0)),
            Label::derived(move || format!("Linux memory status: {}", linux_memory_tuning_status.get()))
                .style(|s| s.color(theme::text_secondary())),
            Label::derived(move || format!("Readiness: {}", gate_readiness.get()))
                .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
        Stack::vertical((
            Label::derived(|| "Linux I/O mode (io_uring)"),
            Stack::horizontal((
                Button::new("io_uring Enable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_io_uring_state(FeatureState::Enabled, "enabled"),
                )),
                Button::new("io_uring Auto").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_io_uring_state(FeatureState::Auto, "auto"),
                )),
                Button::new("io_uring Disable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_io_uring_state(FeatureState::Disabled, "disabled"),
                )),
            ))
            .style(|s| s.gap(8.0)),
            Label::derived(move || format!("io_uring status: {}", io_uring_status.get()))
                .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
    ))
    .style(|s| s.row_gap(8.0).padding(8.0).background(theme::surface_1()));

    let cpu_section = Stack::vertical((
        Label::derived(|| "CPU"),
        Stack::vertical((
            Label::derived(|| "llama.cpp runtime controls"),
            Stack::horizontal((
                Button::new("Llama Start").action(guarded_ui_action(
                    "settings.llama_start",
                    Some(runtime_profile_status),
                    start_llama_runtime_action,
                )),
                Button::new("Llama Stop").action(guarded_ui_action(
                    "settings.llama_stop",
                    Some(runtime_profile_status),
                    stop_llama_runtime_action,
                )),
                Button::new("Llama Update").action(guarded_ui_action(
                    "settings.llama_update",
                    Some(runtime_profile_status),
                    update_llama_runtime_action,
                )),
            ))
            .style(|s| s.gap(8.0)),
            Label::derived(move || format!("Runtime version: {}", runtime_version.get()))
                .style(|s| s.color(theme::text_secondary())),
            Label::derived(move || format!("Runtime health: {}", runtime_health.get()))
                .style(|s| s.color(theme::text_secondary())),
            Label::derived(move || format!("Runtime state: {}", runtime_process_state.get()))
                .style(|s| s.color(theme::text_secondary())),
            Label::derived(move || format!("Runtime pid: {}", runtime_process_pid.get()))
                .style(|s| s.color(theme::text_secondary())),
            Label::derived(move || format!("Runtime status: {}", runtime_profile_status.get()))
                .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
        Stack::vertical((
            Label::derived(|| "Dense math backend profile (OpenBLAS + BLIS)"),
            Stack::horizontal((
                Button::new("Dense Math Enable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_dense_math_state(FeatureState::Enabled, "enabled"),
                )),
                Button::new("Dense Math Auto").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_dense_math_state(FeatureState::Auto, "auto"),
                )),
                Button::new("Dense Math Disable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_dense_math_state(FeatureState::Disabled, "disabled"),
                )),
            ))
            .style(|s| s.gap(8.0)),
            Label::derived(move || format!("Dense math status: {}", dense_math_status.get()))
                .style(|s| s.color(theme::text_secondary())),
            Label::derived(|| "Allocator mode (mimalloc + jemalloc + snmalloc)"),
            Stack::horizontal((
                Button::new("Allocator Enable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_allocator_mode_state(FeatureState::Enabled, "enabled"),
                )),
                Button::new("Allocator Auto").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_allocator_mode_state(FeatureState::Auto, "auto"),
                )),
                Button::new("Allocator Disable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_allocator_mode_state(FeatureState::Disabled, "disabled"),
                )),
            ))
            .style(|s| s.gap(8.0)),
            Label::derived(move || format!("Allocator status: {}", allocator_mode_status.get()))
                .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
        Stack::vertical((
            Label::derived(|| "Profiling stack mode (perf + Tracy)"),
            Stack::horizontal((
                Button::new("Profiling Enable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_profiling_state(FeatureState::Enabled, "enabled"),
                )),
                Button::new("Profiling Auto").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_profiling_state(FeatureState::Auto, "auto"),
                )),
                Button::new("Profiling Disable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_profiling_state(FeatureState::Disabled, "disabled"),
                )),
            ))
            .style(|s| s.gap(8.0)),
            Label::derived(move || format!("Profiling status: {}", profiling_stack_status.get()))
                .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
        Stack::vertical((
            Label::derived(|| "Release optimization mode (AutoFDO + BOLT)"),
            Stack::horizontal((
                Button::new("Release Opt Enable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_release_optimization_state(FeatureState::Enabled, "enabled"),
                )),
                Button::new("Release Opt Auto").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_release_optimization_state(FeatureState::Auto, "auto"),
                )),
                Button::new("Release Opt Disable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_release_optimization_state(FeatureState::Disabled, "disabled"),
                )),
            ))
            .style(|s| s.gap(8.0)),
            Label::derived(move || {
                format!(
                    "Release optimization status: {}",
                    release_optimization_status.get()
                )
            })
            .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
        Stack::vertical((
            Label::derived(|| "Kernel vectorization mode (ISPC)"),
            Stack::horizontal((
                Button::new("ISPC Enable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_ispc_state(FeatureState::Enabled, "enabled"),
                )),
                Button::new("ISPC Auto").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_ispc_state(FeatureState::Auto, "auto"),
                )),
                Button::new("ISPC Disable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_ispc_state(FeatureState::Disabled, "disabled"),
                )),
            ))
            .style(|s| s.gap(8.0)),
            Label::derived(move || format!("ISPC status: {}", ispc_status.get()))
                .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
        Stack::vertical((
            Label::derived(|| "Portable SIMD mode (Highway)"),
            Stack::horizontal((
                Button::new("Highway Enable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_highway_state(FeatureState::Enabled, "enabled"),
                )),
                Button::new("Highway Auto").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_highway_state(FeatureState::Auto, "auto"),
                )),
                Button::new("Highway Disable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_highway_state(FeatureState::Disabled, "disabled"),
                )),
            ))
            .style(|s| s.gap(8.0)),
            Label::derived(move || format!("Highway status: {}", highway_status.get()))
                .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
        Stack::vertical((
            Label::derived(|| "Rust SIMD mode (std::arch)"),
            Stack::horizontal((
                Button::new("Rust SIMD Enable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_rust_arch_simd_state(FeatureState::Enabled, "enabled"),
                )),
                Button::new("Rust SIMD Auto").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_rust_arch_simd_state(FeatureState::Auto, "auto"),
                )),
                Button::new("Rust SIMD Disable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_rust_arch_simd_state(FeatureState::Disabled, "disabled"),
                )),
            ))
            .style(|s| s.gap(8.0)),
            Label::derived(move || format!("Rust SIMD status: {}", rust_arch_simd_status.get()))
                .style(|s| s.color(theme::text_secondary())),
            Label::derived(|| "Rust-native parallelism mode (Rayon)"),
            Stack::horizontal((
                Button::new("Rayon Enable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_rayon_state(FeatureState::Enabled, "enabled"),
                )),
                Button::new("Rayon Auto").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_rayon_state(FeatureState::Auto, "auto"),
                )),
                Button::new("Rayon Disable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_rayon_state(FeatureState::Disabled, "disabled"),
                )),
            ))
            .style(|s| s.gap(8.0)),
            Label::derived(move || format!("Rayon status: {}", rayon_parallelism_status.get()))
                .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
        Stack::vertical((
            Label::derived(|| "Metadata mode (LMDB)"),
            Stack::horizontal((
                Button::new("LMDB Enable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_lmdb_metadata_state(FeatureState::Enabled, "enabled"),
                )),
                Button::new("LMDB Auto").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_lmdb_metadata_state(FeatureState::Auto, "auto"),
                )),
                Button::new("LMDB Disable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_lmdb_metadata_state(FeatureState::Disabled, "disabled"),
                )),
            ))
            .style(|s| s.gap(8.0)),
            Label::derived(move || format!("LMDB status: {}", lmdb_metadata_status.get()))
                .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
    ))
    .style(|s| s.row_gap(8.0).padding(8.0).background(theme::surface_1()));

    let gpu_section = Stack::vertical((
        Label::derived(|| "GPU"),
        Stack::vertical((
            Label::derived(|| "Vulkan llama.cpp policy"),
            Stack::horizontal((
                Button::new("Vulkan Enable").action(guarded_ui_action(
                    "settings.vulkan_on",
                    Some(feature_policy_status),
                    apply_vulkan_memory_state(FeatureState::Enabled, "enabled"),
                )),
                Button::new("Vulkan Auto").action(guarded_ui_action(
                    "settings.vulkan_auto",
                    Some(feature_policy_status),
                    apply_vulkan_memory_state(FeatureState::Auto, "auto"),
                )),
                Button::new("Vulkan Disable").action(guarded_ui_action(
                    "settings.vulkan_off",
                    Some(feature_policy_status),
                    apply_vulkan_memory_state(FeatureState::Disabled, "disabled"),
                )),
                Button::new("Vulkan Update Gate").action(guarded_ui_action(
                    "settings.vulkan_update",
                    Some(feature_policy_status),
                    refresh_vulkan_policy_gate,
                )),
            ))
            .style(|s| s.gap(8.0)),
            Label::derived(move || format!("Vulkan memory: {}", runtime_vulkan_memory_status.get()))
                .style(|s| s.color(theme::text_secondary())),
            Label::derived(move || format!("Vulkan validation: {}", runtime_vulkan_validation_status.get()))
                .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
    ))
    .style(|s| s.row_gap(8.0).padding(8.0).background(theme::surface_1()));

    Stack::vertical((
        general_section.style(move |s| {
            s.apply_if(settings_category.get() != SettingsCategory::General, |s| {
                s.display(floem::taffy::style::Display::None)
            })
        }),
        ui_section.style(move |s| {
            s.apply_if(settings_category.get() != SettingsCategory::Ui, |s| {
                s.display(floem::taffy::style::Display::None)
            })
        }),
        windows_section.style(move |s| {
            s.apply_if(settings_category.get() != SettingsCategory::Windows, |s| {
                s.display(floem::taffy::style::Display::None)
            })
        }),
        linux_section.style(move |s| {
            s.apply_if(settings_category.get() != SettingsCategory::Linux, |s| {
                s.display(floem::taffy::style::Display::None)
            })
        }),
        cpu_section.style(move |s| {
            s.apply_if(settings_category.get() != SettingsCategory::Cpu, |s| {
                s.display(floem::taffy::style::Display::None)
            })
        }),
        gpu_section.style(move |s| {
            s.apply_if(settings_category.get() != SettingsCategory::Gpu, |s| {
                s.display(floem::taffy::style::Display::None)
            })
        }),
        Label::derived(move || format!("Policy status: {}", feature_policy_status.get()))
            .style(|s| s.color(theme::text_secondary())),
    ))
    .style(|s| s.size_full().row_gap(8.0))
}

