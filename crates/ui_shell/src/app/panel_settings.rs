#[allow(clippy::too_many_arguments)]
fn settings_panel(
    workspace: Rc<WorkspaceHost>,
    feature_registry: Rc<RefCell<FeaturePolicyRegistry>>,
    feature_target: RwSignal<String>,
    feature_policy_status: RwSignal<String>,
    feature_fallback_visible: RwSignal<bool>,
    feature_policy_snapshot: RwSignal<String>,
    runtimes: Rc<RefCell<RuntimeRegistry>>,
    runtime_vulkan_memory_status: RwSignal<String>,
    runtime_vulkan_validation_status: RwSignal<String>,
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

    v_stack((
        label(|| "Feature policy states: Disabled / Available / Enabled / Auto / Fallback"),
        v_stack((
            label(|| "Topology placement mode"),
            h_stack((
                button("Topology Enable")
                    .action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_topology_state(FeatureState::Enabled, "enabled"))),
                button("Topology Auto").action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_topology_state(FeatureState::Auto, "auto"))),
                button("Topology Disable")
                    .action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_topology_state(FeatureState::Disabled, "disabled"))),
            ))
            .style(|s| s.gap(8.0)),
            label(move || format!("Placement status: {}", topology_placement_status.get()))
                .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
        v_stack((
            label(|| "OpenVINO mode"),
            h_stack((
                button("OpenVINO Enable")
                    .action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_openvino_state(FeatureState::Enabled, "enabled"))),
                button("OpenVINO Auto").action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_openvino_state(FeatureState::Auto, "auto"))),
                button("OpenVINO Disable")
                    .action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_openvino_state(FeatureState::Disabled, "disabled"))),
            ))
            .style(|s| s.gap(8.0)),
            label(move || format!("OpenVINO status: {}", openvino_status.get()))
                .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
        v_stack((
            label(|| "Linux memory tuning profile (THP + zswap + zram)"),
            h_stack((
                button("Memory Enable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_linux_memory_tuning_state(FeatureState::Enabled, "enabled"),
                )),
                button("Memory Auto")
                    .action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_linux_memory_tuning_state(FeatureState::Auto, "auto"))),
                button("Memory Disable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_linux_memory_tuning_state(FeatureState::Disabled, "disabled"),
                )),
            ))
            .style(|s| s.gap(8.0)),
            label(move || format!("Linux memory status: {}", linux_memory_tuning_status.get()))
                .style(|s| s.color(theme::text_secondary())),
            label(move || format!("Readiness: {}", gate_readiness.get()))
                .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
        v_stack((
            label(|| "Dense math backend profile (OpenBLAS + BLIS)"),
            h_stack((
                button("Dense Math Enable")
                    .action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_dense_math_state(FeatureState::Enabled, "enabled"))),
                button("Dense Math Auto")
                    .action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_dense_math_state(FeatureState::Auto, "auto"))),
                button("Dense Math Disable")
                    .action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_dense_math_state(FeatureState::Disabled, "disabled"))),
            ))
            .style(|s| s.gap(8.0)),
            label(move || format!("Dense math status: {}", dense_math_status.get()))
                .style(|s| s.color(theme::text_secondary())),
            label(|| "Allocator mode (mimalloc + jemalloc + snmalloc)"),
            h_stack((
                button("Allocator Enable")
                    .action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_allocator_mode_state(FeatureState::Enabled, "enabled"))),
                button("Allocator Auto")
                    .action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_allocator_mode_state(FeatureState::Auto, "auto"))),
                button("Allocator Disable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_allocator_mode_state(FeatureState::Disabled, "disabled"),
                )),
            ))
            .style(|s| s.gap(8.0)),
            label(move || format!("Allocator status: {}", allocator_mode_status.get()))
                .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
        v_stack((
            label(|| "Profiling stack mode (perf + Tracy)"),
            h_stack((
                button("Profiling Enable")
                    .action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_profiling_state(FeatureState::Enabled, "enabled"))),
                button("Profiling Auto").action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_profiling_state(FeatureState::Auto, "auto"))),
                button("Profiling Disable")
                    .action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_profiling_state(FeatureState::Disabled, "disabled"))),
            ))
            .style(|s| s.gap(8.0)),
            label(move || format!("Profiling status: {}", profiling_stack_status.get()))
                .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
        v_stack((
            label(|| "Release optimization mode (AutoFDO + BOLT)"),
            h_stack((
                button("Release Opt Enable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_release_optimization_state(FeatureState::Enabled, "enabled"),
                )),
                button("Release Opt Auto")
                    .action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_release_optimization_state(FeatureState::Auto, "auto"))),
                button("Release Opt Disable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_release_optimization_state(FeatureState::Disabled, "disabled"),
                )),
            ))
            .style(|s| s.gap(8.0)),
            label(move || {
                format!(
                    "Release optimization status: {}",
                    release_optimization_status.get()
                )
            })
            .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
        v_stack((
            label(|| "Kernel vectorization mode (ISPC)"),
            h_stack((
                button("ISPC Enable").action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_ispc_state(FeatureState::Enabled, "enabled"))),
                button("ISPC Auto").action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_ispc_state(FeatureState::Auto, "auto"))),
                button("ISPC Disable").action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_ispc_state(FeatureState::Disabled, "disabled"))),
            ))
            .style(|s| s.gap(8.0)),
            label(move || format!("ISPC status: {}", ispc_status.get()))
                .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
        v_stack((
            label(|| "Portable SIMD mode (Highway)"),
            h_stack((
                button("Highway Enable")
                    .action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_highway_state(FeatureState::Enabled, "enabled"))),
                button("Highway Auto").action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_highway_state(FeatureState::Auto, "auto"))),
                button("Highway Disable")
                    .action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_highway_state(FeatureState::Disabled, "disabled"))),
            ))
            .style(|s| s.gap(8.0)),
            label(move || format!("Highway status: {}", highway_status.get()))
                .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
        v_stack((
            label(|| "Rust SIMD mode (std::arch)"),
            h_stack((
                button("Rust SIMD Enable")
                    .action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_rust_arch_simd_state(FeatureState::Enabled, "enabled"))),
                button("Rust SIMD Auto")
                    .action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_rust_arch_simd_state(FeatureState::Auto, "auto"))),
                button("Rust SIMD Disable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_rust_arch_simd_state(FeatureState::Disabled, "disabled"),
                )),
            ))
            .style(|s| s.gap(8.0)),
            label(move || format!("Rust SIMD status: {}", rust_arch_simd_status.get()))
                .style(|s| s.color(theme::text_secondary())),
            label(|| "Rust-native parallelism mode (Rayon)"),
            h_stack((
                button("Rayon Enable").action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_rayon_state(FeatureState::Enabled, "enabled"))),
                button("Rayon Auto").action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_rayon_state(FeatureState::Auto, "auto"))),
                button("Rayon Disable")
                    .action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_rayon_state(FeatureState::Disabled, "disabled"))),
            ))
            .style(|s| s.gap(8.0)),
            label(move || format!("Rayon status: {}", rayon_parallelism_status.get()))
                .style(|s| s.color(theme::text_secondary())),
            label(|| "Linux I/O mode (io_uring)"),
            h_stack((
                button("io_uring Enable")
                    .action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_io_uring_state(FeatureState::Enabled, "enabled"))),
                button("io_uring Auto").action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_io_uring_state(FeatureState::Auto, "auto"))),
                button("io_uring Disable")
                    .action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_io_uring_state(FeatureState::Disabled, "disabled"))),
            ))
            .style(|s| s.gap(8.0)),
            label(move || format!("io_uring status: {}", io_uring_status.get()))
                .style(|s| s.color(theme::text_secondary())),
            label(|| "Metadata mode (LMDB)"),
            h_stack((
                button("LMDB Enable")
                    .action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_lmdb_metadata_state(FeatureState::Enabled, "enabled"))),
                button("LMDB Auto").action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_lmdb_metadata_state(FeatureState::Auto, "auto"))),
                button("LMDB Disable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_lmdb_metadata_state(FeatureState::Disabled, "disabled"),
                )),
            ))
            .style(|s| s.gap(8.0)),
            label(move || format!("LMDB status: {}", lmdb_metadata_status.get()))
                .style(|s| s.color(theme::text_secondary())),
            label(|| "Confidential relay feature mode"),
            h_stack((
                button("Confidential Enable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_confidential_relay_feature_state(FeatureState::Enabled, "enabled"),
                )),
                button("Confidential Auto").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_confidential_relay_feature_state(FeatureState::Auto, "auto"),
                )),
                button("Confidential Disable").action(guarded_ui_action(
                    "settings.action",
                    Some(feature_policy_status),
                    apply_confidential_relay_feature_state(FeatureState::Disabled, "disabled"),
                )),
            ))
            .style(|s| s.gap(8.0)),
            label(move || {
                format!(
                    "Confidential feature status: {}",
                    confidential_relay_feature_status.get()
                )
            })
            .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
        v_stack((
            label(|| "Benchmark Evidence Artifact"),
            h_stack((
                button("Run Gate Now").action(guarded_ui_action("settings.action", Some(feature_policy_status), run_gate_now_action)),
                button("Load Gate Artifact").action(guarded_ui_action("settings.action", Some(feature_policy_status), load_gate_artifact_action)),
                button("Apply Gate Defaults").action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_gate_defaults_action)),
                button("Apply Recommended Flags").action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_recommended_flags_action)),
                button("Clear Recommended Flags").action(guarded_ui_action("settings.action", Some(feature_policy_status), clear_recommended_flags_action)),
                button("Show Env Commands").action(guarded_ui_action("settings.action", Some(feature_policy_status), show_gate_env_commands_action)),
                button("Check Flag Parity").action(guarded_ui_action("settings.action", Some(feature_policy_status), check_flag_parity_action)),
            ))
            .style(|s| s.gap(8.0)),
            label(move || format!("Artifact path: {}", gate_artifact_path.get()))
                .style(|s| s.color(theme::text_secondary())),
            label(move || format!("Artifact status: {}", gate_artifact_status.get()))
                .style(|s| s.color(theme::text_secondary())),
            label(move || format!("Flag parity: {}", flag_parity_status.get()))
                .style(|s| s.color(theme::text_secondary())),
        ))
        .style(|s| s.row_gap(8.0)),
        label(|| {
            format!(
                "Settings file: {}",
                feature_policy_settings_path().display()
            )
        })
        .style(|s| s.color(theme::text_secondary())),
        h_stack((
            label(|| "Feature key"),
            text_input(feature_target).style(|s| s.min_width(220.0).padding(6.0).color(theme::input_text())),
            button("Enable").action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_target_state(FeatureState::Enabled, "enabled"))),
            button("Disable").action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_target_state(FeatureState::Disabled, "disabled"))),
            button("Auto").action(guarded_ui_action("settings.action", Some(feature_policy_status), apply_target_state(FeatureState::Auto, "auto"))),
            button("Mark Fallback").action(guarded_ui_action("settings.action", Some(feature_policy_status), mark_fallback)),
            button("Clear Fallback").action(guarded_ui_action("settings.action", Some(feature_policy_status), clear_fallback)),
        ))
        .style(|s| s.gap(8.0)),
        h_stack((
            button("Toggle Fallback Visibility").action(guarded_ui_action("settings.action", Some(feature_policy_status), toggle_fallback_visibility)),
            button("Reset Safe Defaults").action(guarded_ui_action("settings.action", Some(feature_policy_status), reset_safe_defaults)),
            button("Save Preferences").action(guarded_ui_action("settings.action", Some(feature_policy_status), save_preferences)),
            button("Reload Preferences").action(guarded_ui_action("settings.action", Some(feature_policy_status), reload_preferences)),
        ))
        .style(|s| s.gap(8.0)),
        label(move || format!("Policy status: {}", feature_policy_status.get()))
            .style(|s| s.color(theme::text_secondary())),
        scroll(label(move || feature_policy_snapshot.get())).style(|s| {
            s.width_full()
                .height_full()
                .padding(8.0)
                .background(theme::surface_1())
        }),
    ))
    .style(|s| s.size_full().row_gap(8.0))
}

