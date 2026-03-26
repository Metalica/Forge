#[cfg(test)]
mod tests {
    use super::{
        PersistedChatConfidentialState, PersistedDockLayoutState, PersistedMediaStudioState,
        VideoCheckpointState, append_workspace_provenance_to_prompt, apply_allocator_mode,
        apply_confidential_relay_feature_mode, apply_dense_math_mode, apply_highway_mode,
        apply_io_uring_mode, apply_ispc_mode, apply_linux_memory_tuning_mode,
        apply_lmdb_metadata_mode, apply_openvino_mode, apply_profiling_mode, apply_rayon_mode,
        apply_release_optimization_mode, apply_rust_arch_simd_mode, apply_topology_mode,
        apply_vulkan_benchmark_gate_from_registry, build_codex_specialist_prompt,
        build_workspace_input_provenance_block, create_default_agent_run,
        default_chat_confidential_allow_remote_fallback, default_chat_confidential_profile_window,
        evaluate_flag_parity_with_env, evaluate_registry_with_default_checks,
        find_latest_gate_artifact_path, format_agent_graph, format_agent_trace_filtered,
        format_allocator_mode_status, format_confidential_relay_feature_status,
        format_dense_math_status, format_extension_inventory_summary,
        format_extension_target_detail, format_feature_policy_snapshot, format_file_list,
        format_flag_parity, format_gate_artifact_status, format_gate_env_commands,
        format_gate_readiness, format_highway_status, format_io_uring_status, format_ispc_status,
        format_job_timeline, format_linux_memory_tuning_status, format_lmdb_metadata_status,
        format_openvino_status, format_profiling_stack_status, format_rayon_parallelism_status,
        format_release_optimization_status, format_runtime_benchmark_summary,
        format_runtime_pin_rollback_summary, format_rust_arch_simd_status,
        format_source_role_default, format_topology_placement_status, gate_run_command,
        load_agent_studio_state, load_chat_confidential_state, load_dock_layout_state,
        load_extension_host_state, load_gate_artifact, load_job_queue_state,
        load_media_studio_state, load_project_memory_state, load_runtime_registry_state,
        load_source_registry_state, parse_confidential_mode_input, parse_memory_scope_input,
        parse_profile_window_size_input, parse_selected_default_state, parse_source_role_input,
        queue_complete_tracked_job, queue_fail_tracked_job, queue_start_tracked_job,
        resolve_source_route_for_role, save_agent_studio_state, save_chat_confidential_state,
        save_dock_layout_state, save_extension_host_state, save_job_queue_state,
        save_media_studio_state, save_project_memory_state, save_runtime_registry_state,
        save_source_registry_state, should_auto_run_codex_for_started_step,
        should_auto_run_routed_for_started_step, source_role_for_agent_role,
        validate_gate_artifact_for_defaults,
    };
    use super::{RuntimeProcessState, sync_runtime_process_signals};
    use control_plane::agent_orchestrator::{AgentOrchestrator, AgentRole};
    use control_plane::extension_host::{
        ExtensionClass, ExtensionHost, ExtensionManifest, ExtensionPermission, ExtensionState,
        default_extension_host,
    };
    use control_plane::feature_policy::FeaturePolicyRegistry;
    use control_plane::project_memory::{MemoryScope, ProjectMemoryStore};
    use execution_plane::{
        jobs::{JobKind, JobPriority, JobQueue},
        workspace::WorkspaceHost,
    };
    use floem::reactive::{RwSignal, SignalGet, SignalUpdate};
    use runtime_registry::health::{RuntimeRegistry, UpdateResult, default_llama_runtime};
    use runtime_registry::process::{RuntimeLaunchRequest, RuntimeProcessManager, StartResult};
    use runtime_registry::source_registry::{SourceKind, SourceRole, default_source_registry};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::fs;
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::thread;
    use std::time::Duration;
    use urm::feature_policy::{FeatureDeclaration, FeatureId, FeatureState, Platform};

    struct RuntimeSyncSignals {
        runtime_process_state: RwSignal<String>,
        runtime_process_pid: RwSignal<String>,
        runtime_version: RwSignal<String>,
        runtime_health: RwSignal<String>,
        feature_policy_status: RwSignal<String>,
        feature_fallback_visible: RwSignal<bool>,
        feature_policy_snapshot: RwSignal<String>,
        runtime_vulkan_memory_status: RwSignal<String>,
        runtime_vulkan_validation_status: RwSignal<String>,
    }

    impl RuntimeSyncSignals {
        fn new() -> Self {
            Self {
                runtime_process_state: RwSignal::new(String::new()),
                runtime_process_pid: RwSignal::new(String::from("n/a")),
                runtime_version: RwSignal::new(String::new()),
                runtime_health: RwSignal::new(String::new()),
                feature_policy_status: RwSignal::new(String::from("policy idle")),
                feature_fallback_visible: RwSignal::new(true),
                feature_policy_snapshot: RwSignal::new(String::new()),
                runtime_vulkan_memory_status: RwSignal::new(String::new()),
                runtime_vulkan_validation_status: RwSignal::new(String::new()),
            }
        }
    }

    fn seeded_feature_registry() -> Rc<RefCell<FeaturePolicyRegistry>> {
        let mut registry = FeaturePolicyRegistry::with_defaults();
        let _ = registry.set_requested_state(FeatureId::VulkanMemoryAllocator, FeatureState::Auto);
        evaluate_registry_with_default_checks(&mut registry);
        Rc::new(RefCell::new(registry))
    }

    fn test_declaration(id: FeatureId, fallback_path: &str) -> FeatureDeclaration {
        FeatureDeclaration {
            id,
            supported_platforms: vec![Platform::current()],
            required_hardware: "test hardware".to_string(),
            expected_benefit: "test benefit".to_string(),
            known_risks: "test risks".to_string(),
            validation_method: "test validation".to_string(),
            fallback_path: fallback_path.to_string(),
            benchmark_requirement: "test benchmark".to_string(),
            present_on_system: true,
        }
    }

    fn topology_registry() -> FeaturePolicyRegistry {
        FeaturePolicyRegistry::new(vec![
            test_declaration(
                FeatureId::HwlocTopology,
                "Disable topology mode and use baseline scheduler",
            ),
            test_declaration(
                FeatureId::NumactlPlacement,
                "Fallback to OS default scheduler placement",
            ),
        ])
    }

    fn trio_registry() -> FeaturePolicyRegistry {
        FeaturePolicyRegistry::new(vec![
            test_declaration(
                FeatureId::OpenVinoBackend,
                "Fallback to primary local runtime backend",
            ),
            test_declaration(
                FeatureId::TransparentHugePages,
                "Revert to kernel baseline THP behavior",
            ),
            test_declaration(FeatureId::Zswap, "Disable zswap tuning profile"),
            test_declaration(FeatureId::Zram, "Disable zram profile"),
        ])
    }

    fn optimization_registry() -> FeaturePolicyRegistry {
        FeaturePolicyRegistry::new(vec![
            test_declaration(
                FeatureId::MimallocAllocator,
                "Switch to default allocator policy",
            ),
            test_declaration(
                FeatureId::JemallocAllocator,
                "Switch allocator to safe default",
            ),
            test_declaration(
                FeatureId::SnmallocAllocator,
                "Switch allocator to safe default",
            ),
            test_declaration(
                FeatureId::OpenBlasBackend,
                "Fallback to selected default backend",
            ),
            test_declaration(
                FeatureId::BlisBackend,
                "Fallback to selected default backend",
            ),
            test_declaration(FeatureId::PerfProfiler, "Disable perf capture for session"),
            test_declaration(FeatureId::TracyProfiler, "Disable Tracy instrumentation"),
            test_declaration(
                FeatureId::AutoFdoOptimizer,
                "Fallback to baseline release build path",
            ),
            test_declaration(
                FeatureId::BoltOptimizer,
                "Fallback to non-BOLT optimized binaries",
            ),
            test_declaration(
                FeatureId::IspcKernels,
                "Fallback to baseline kernel implementation",
            ),
            test_declaration(
                FeatureId::HighwaySimd,
                "Fallback to baseline/vector-specific implementation",
            ),
            test_declaration(FeatureId::RustArchSimd, "Fallback to scalar implementation"),
            test_declaration(
                FeatureId::RayonParallelism,
                "Fallback to sequential loop path",
            ),
            test_declaration(FeatureId::IoUring, "Fallback to baseline async I/O path"),
            test_declaration(FeatureId::LmdbMetadata, "Fallback to prior metadata store"),
            test_declaration(
                FeatureId::ConfidentialRelay,
                "Fallback to non-confidential routed or local execution",
            ),
        ])
    }

    fn nonzero_exit_request() -> RuntimeLaunchRequest {
        if cfg!(windows) {
            RuntimeLaunchRequest {
                program: "powershell".to_string(),
                args: vec![
                    "-NoProfile".to_string(),
                    "-Command".to_string(),
                    "exit 7".to_string(),
                ],
                working_dir: None,
                env: Vec::new(),
                health_probe: None,
                placement_hints: None,
            }
        } else {
            RuntimeLaunchRequest {
                program: "sh".to_string(),
                args: vec!["-c".to_string(), "exit 7".to_string()],
                working_dir: None,
                env: Vec::new(),
                health_probe: None,
                placement_hints: None,
            }
        }
    }

    #[test]
    fn topology_controls_mutate_policy_state() {
        let mut registry = topology_registry();
        let result = apply_topology_mode(&mut registry, FeatureState::Enabled);
        assert!(result.is_ok());

        let hwloc = registry.status(FeatureId::HwlocTopology);
        let numactl = registry.status(FeatureId::NumactlPlacement);
        assert!(hwloc.is_some());
        assert!(numactl.is_some());
        let hwloc = match hwloc {
            Some(value) => value,
            None => return,
        };
        let numactl = match numactl {
            Some(value) => value,
            None => return,
        };
        assert_eq!(hwloc.requested_state, FeatureState::Enabled);
        assert_eq!(numactl.requested_state, FeatureState::Enabled);
        assert_eq!(hwloc.effective_state, FeatureState::Enabled);
        assert_eq!(numactl.effective_state, FeatureState::Enabled);
    }

    #[test]
    fn topology_status_reflects_active_scheduler_mode() {
        let mut registry = topology_registry();
        let _ = apply_topology_mode(&mut registry, FeatureState::Enabled);
        let enabled_status = format_topology_placement_status(&registry);
        assert!(enabled_status.contains("scheduler=topology-aware"));
        assert!(enabled_status.contains("launch=numactl-affinity"));

        let _ = apply_topology_mode(&mut registry, FeatureState::Disabled);
        let disabled_status = format_topology_placement_status(&registry);
        assert!(disabled_status.contains("scheduler=baseline"));
        assert!(disabled_status.contains("launch=os-default"));
    }

    #[test]
    fn openvino_controls_mutate_policy_state() {
        let mut registry = trio_registry();
        let result = apply_openvino_mode(&mut registry, FeatureState::Enabled);
        assert!(result.is_ok());

        let status = registry.status(FeatureId::OpenVinoBackend);
        assert!(status.is_some());
        let status = match status {
            Some(value) => value,
            None => return,
        };
        assert_eq!(status.requested_state, FeatureState::Enabled);
        assert!(matches!(
            status.effective_state,
            FeatureState::Enabled | FeatureState::Fallback
        ));

        let summary = format_openvino_status(&registry);
        assert!(summary.contains("openvino_backend(req=Enabled"));
        assert!(summary.contains("eff="));
    }

    #[test]
    fn linux_memory_tuning_controls_mutate_grouped_policy_state() {
        let mut registry = trio_registry();
        let result = apply_linux_memory_tuning_mode(&mut registry, FeatureState::Enabled);
        assert!(result.is_ok());

        let thp = registry.status(FeatureId::TransparentHugePages);
        let zswap = registry.status(FeatureId::Zswap);
        let zram = registry.status(FeatureId::Zram);
        assert!(thp.is_some());
        assert!(zswap.is_some());
        assert!(zram.is_some());
        let thp = match thp {
            Some(value) => value,
            None => return,
        };
        let zswap = match zswap {
            Some(value) => value,
            None => return,
        };
        let zram = match zram {
            Some(value) => value,
            None => return,
        };
        assert_eq!(thp.requested_state, FeatureState::Enabled);
        assert_eq!(zswap.requested_state, FeatureState::Enabled);
        assert_eq!(zram.requested_state, FeatureState::Enabled);

        let summary = format_linux_memory_tuning_status(&registry);
        assert!(summary.contains("transparent_huge_pages(req=Enabled"));
        assert!(summary.contains("zswap(req=Enabled"));
        assert!(summary.contains("zram(req=Enabled"));
    }

    #[test]
    fn dense_math_controls_mutate_grouped_policy_state() {
        let mut registry = optimization_registry();
        let result = apply_dense_math_mode(&mut registry, FeatureState::Enabled);
        assert!(result.is_ok());

        let openblas = registry.status(FeatureId::OpenBlasBackend);
        let blis = registry.status(FeatureId::BlisBackend);
        assert!(openblas.is_some());
        assert!(blis.is_some());
        let openblas = match openblas {
            Some(value) => value,
            None => return,
        };
        let blis = match blis {
            Some(value) => value,
            None => return,
        };
        assert_eq!(openblas.requested_state, FeatureState::Enabled);
        assert_eq!(blis.requested_state, FeatureState::Enabled);

        let summary = format_dense_math_status(&registry);
        assert!(summary.contains("openblas_backend(req=Enabled"));
        assert!(summary.contains("blis_backend(req=Enabled"));
    }

    #[test]
    fn allocator_controls_mutate_grouped_policy_state() {
        let mut registry = optimization_registry();
        let result = apply_allocator_mode(&mut registry, FeatureState::Enabled);
        assert!(result.is_ok());

        let mimalloc = registry.status(FeatureId::MimallocAllocator);
        let jemalloc = registry.status(FeatureId::JemallocAllocator);
        let snmalloc = registry.status(FeatureId::SnmallocAllocator);
        assert!(mimalloc.is_some());
        assert!(jemalloc.is_some());
        assert!(snmalloc.is_some());
        let mimalloc = match mimalloc {
            Some(value) => value,
            None => return,
        };
        let jemalloc = match jemalloc {
            Some(value) => value,
            None => return,
        };
        let snmalloc = match snmalloc {
            Some(value) => value,
            None => return,
        };
        assert_eq!(mimalloc.requested_state, FeatureState::Enabled);
        assert_eq!(jemalloc.requested_state, FeatureState::Enabled);
        assert_eq!(snmalloc.requested_state, FeatureState::Enabled);

        let summary = format_allocator_mode_status(&registry);
        assert!(summary.contains("mimalloc_allocator(req=Enabled"));
        assert!(summary.contains("jemalloc_allocator(req=Enabled"));
        assert!(summary.contains("snmalloc_allocator(req=Enabled"));
    }

    #[test]
    fn profiling_stack_controls_mutate_grouped_policy_state() {
        let mut registry = optimization_registry();
        let result = apply_profiling_mode(&mut registry, FeatureState::Enabled);
        assert!(result.is_ok());

        let perf = registry.status(FeatureId::PerfProfiler);
        let tracy = registry.status(FeatureId::TracyProfiler);
        assert!(perf.is_some());
        assert!(tracy.is_some());
        let perf = match perf {
            Some(value) => value,
            None => return,
        };
        let tracy = match tracy {
            Some(value) => value,
            None => return,
        };
        assert_eq!(perf.requested_state, FeatureState::Enabled);
        assert_eq!(tracy.requested_state, FeatureState::Enabled);

        let summary = format_profiling_stack_status(&registry);
        assert!(summary.contains("perf_profiler(req=Enabled"));
        assert!(summary.contains("tracy_profiler(req=Enabled"));
    }

    #[test]
    fn release_optimization_controls_mutate_grouped_policy_state() {
        let mut registry = optimization_registry();
        let result = apply_release_optimization_mode(&mut registry, FeatureState::Enabled);
        assert!(result.is_ok());

        let autofdo = registry.status(FeatureId::AutoFdoOptimizer);
        let bolt = registry.status(FeatureId::BoltOptimizer);
        assert!(autofdo.is_some());
        assert!(bolt.is_some());
        let autofdo = match autofdo {
            Some(value) => value,
            None => return,
        };
        let bolt = match bolt {
            Some(value) => value,
            None => return,
        };
        assert_eq!(autofdo.requested_state, FeatureState::Enabled);
        assert_eq!(bolt.requested_state, FeatureState::Enabled);

        let summary = format_release_optimization_status(&registry);
        assert!(summary.contains("autofdo_optimizer(req=Enabled"));
        assert!(summary.contains("bolt_optimizer(req=Enabled"));
    }

    #[test]
    fn ispc_controls_mutate_policy_state() {
        let mut registry = optimization_registry();
        let result = apply_ispc_mode(&mut registry, FeatureState::Enabled);
        assert!(result.is_ok());

        let status = registry.status(FeatureId::IspcKernels);
        assert!(status.is_some());
        let status = match status {
            Some(value) => value,
            None => return,
        };
        assert_eq!(status.requested_state, FeatureState::Enabled);

        let summary = format_ispc_status(&registry);
        assert!(summary.contains("ispc_kernels(req=Enabled"));
    }

    #[test]
    fn highway_controls_mutate_policy_state() {
        let mut registry = optimization_registry();
        let result = apply_highway_mode(&mut registry, FeatureState::Enabled);
        assert!(result.is_ok());

        let status = registry.status(FeatureId::HighwaySimd);
        assert!(status.is_some());
        let status = match status {
            Some(value) => value,
            None => return,
        };
        assert_eq!(status.requested_state, FeatureState::Enabled);

        let summary = format_highway_status(&registry);
        assert!(summary.contains("highway_simd(req=Enabled"));
    }

    #[test]
    fn rust_arch_simd_controls_mutate_policy_state() {
        let mut registry = optimization_registry();
        let result = apply_rust_arch_simd_mode(&mut registry, FeatureState::Enabled);
        assert!(result.is_ok());

        let status = registry.status(FeatureId::RustArchSimd);
        assert!(status.is_some());
        let status = match status {
            Some(value) => value,
            None => return,
        };
        assert_eq!(status.requested_state, FeatureState::Enabled);

        let summary = format_rust_arch_simd_status(&registry);
        assert!(summary.contains("rust_arch_simd(req=Enabled"));
    }

    #[test]
    fn rayon_controls_mutate_policy_state() {
        let mut registry = optimization_registry();
        let result = apply_rayon_mode(&mut registry, FeatureState::Enabled);
        assert!(result.is_ok());

        let status = registry.status(FeatureId::RayonParallelism);
        assert!(status.is_some());
        let status = match status {
            Some(value) => value,
            None => return,
        };
        assert_eq!(status.requested_state, FeatureState::Enabled);

        let summary = format_rayon_parallelism_status(&registry);
        assert!(summary.contains("rayon_parallelism(req=Enabled"));
    }

    #[test]
    fn io_uring_controls_mutate_policy_state() {
        let mut registry = optimization_registry();
        let result = apply_io_uring_mode(&mut registry, FeatureState::Enabled);
        assert!(result.is_ok());

        let status = registry.status(FeatureId::IoUring);
        assert!(status.is_some());
        let status = match status {
            Some(value) => value,
            None => return,
        };
        assert_eq!(status.requested_state, FeatureState::Enabled);

        let summary = format_io_uring_status(&registry);
        assert!(summary.contains("io_uring(req=Enabled"));
    }

    #[test]
    fn lmdb_metadata_controls_mutate_policy_state() {
        let mut registry = optimization_registry();
        let result = apply_lmdb_metadata_mode(&mut registry, FeatureState::Enabled);
        assert!(result.is_ok());

        let status = registry.status(FeatureId::LmdbMetadata);
        assert!(status.is_some());
        let status = match status {
            Some(value) => value,
            None => return,
        };
        assert_eq!(status.requested_state, FeatureState::Enabled);

        let summary = format_lmdb_metadata_status(&registry);
        assert!(summary.contains("lmdb_metadata(req=Enabled"));
    }

    #[test]
    fn confidential_relay_controls_mutate_policy_state() {
        let mut registry = optimization_registry();
        let result = apply_confidential_relay_feature_mode(&mut registry, FeatureState::Enabled);
        assert!(result.is_ok());

        let status = registry.status(FeatureId::ConfidentialRelay);
        assert!(status.is_some());
        let status = match status {
            Some(value) => value,
            None => return,
        };
        assert_eq!(status.requested_state, FeatureState::Enabled);

        let summary = format_confidential_relay_feature_status(&registry);
        assert!(summary.contains("confidential_relay(req=Enabled"));
    }

    #[test]
    fn parse_selected_default_state_accepts_supported_values() {
        let auto = parse_selected_default_state("Auto");
        assert!(matches!(auto, Ok(FeatureState::Auto)));
        let disabled = parse_selected_default_state("disabled");
        assert!(matches!(disabled, Ok(FeatureState::Disabled)));
        let enabled = parse_selected_default_state("enabled");
        assert!(matches!(enabled, Ok(FeatureState::Enabled)));
        let unknown = parse_selected_default_state("invalid-default");
        assert!(unknown.is_err());
    }

    #[allow(clippy::too_many_arguments)]
    fn gate_artifact_for_test(
        gate_passed: bool,
        openvino_default: &str,
        memory_default: &str,
        openblas_default: &str,
        blis_default: &str,
        profiling_default: &str,
        release_optimization_default: &str,
        ispc_default: &str,
        highway_default: &str,
        rust_arch_simd_default: &str,
        rayon_default: &str,
    ) -> super::ConditionalGateArtifact {
        let mut recommended_env_flags = HashMap::new();
        recommended_env_flags.insert(super::OPENVINO_BENCHMARK_OK_ENV.to_string(), 1);
        recommended_env_flags.insert(super::THP_BENCHMARK_OK_ENV.to_string(), 1);
        recommended_env_flags.insert(super::ZSWAP_BENCHMARK_OK_ENV.to_string(), 1);
        recommended_env_flags.insert(super::ZRAM_BENCHMARK_OK_ENV.to_string(), 1);
        recommended_env_flags.insert(super::OPENBLAS_BENCHMARK_OK_ENV.to_string(), 1);
        recommended_env_flags.insert(super::BLIS_BENCHMARK_OK_ENV.to_string(), 1);
        recommended_env_flags.insert(super::PERF_BENCHMARK_OK_ENV.to_string(), 1);
        recommended_env_flags.insert(super::TRACY_BENCHMARK_OK_ENV.to_string(), 1);
        recommended_env_flags.insert(super::AUTOFDO_BENCHMARK_OK_ENV.to_string(), 1);
        recommended_env_flags.insert(super::BOLT_BENCHMARK_OK_ENV.to_string(), 1);
        recommended_env_flags.insert(super::ISPC_BENCHMARK_OK_ENV.to_string(), 1);
        recommended_env_flags.insert(super::HIGHWAY_BENCHMARK_OK_ENV.to_string(), 1);
        recommended_env_flags.insert(super::RUST_ARCH_SIMD_BENCHMARK_OK_ENV.to_string(), 1);
        recommended_env_flags.insert(super::RAYON_BENCHMARK_OK_ENV.to_string(), 1);
        super::ConditionalGateArtifact {
            generated_at_utc: "2026-03-19T00:00:00Z".to_string(),
            gate_passed,
            selected_defaults: super::GateSelectedDefaults {
                openvino_backend: openvino_default.to_string(),
                linux_memory_tuning_profile: memory_default.to_string(),
                openblas_backend: openblas_default.to_string(),
                blis_backend: blis_default.to_string(),
                profiling_mode: profiling_default.to_string(),
                release_optimization_mode: release_optimization_default.to_string(),
                ispc_kernels: ispc_default.to_string(),
                highway_simd: highway_default.to_string(),
                rust_arch_simd: rust_arch_simd_default.to_string(),
                rayon_parallelism: rayon_default.to_string(),
            },
            recommended_env_flags,
            decision: super::GateDecision {
                passed: gate_passed,
                reasons: vec!["test decision".to_string()],
            },
        }
    }

    #[test]
    fn gate_artifact_validation_rejects_non_fail_closed_defaults_when_gate_fails() {
        let artifact = gate_artifact_for_test(
            false, "Auto", "Disabled", "Disabled", "Disabled", "Disabled", "Disabled", "Disabled",
            "Disabled", "Disabled", "Disabled",
        );
        let validation = validate_gate_artifact_for_defaults(&artifact);
        assert!(validation.is_err());
        let message = validation.err().unwrap_or_default();
        assert!(message.contains("must remain Disabled"));
    }

    #[test]
    fn gate_artifact_validation_accepts_safe_defaults() {
        let artifact = gate_artifact_for_test(
            true, "Auto", "Disabled", "Auto", "Auto", "Auto", "Auto", "Auto", "Auto", "Auto",
            "Auto",
        );
        let validation = validate_gate_artifact_for_defaults(&artifact);
        assert!(validation.is_ok());
    }

    #[test]
    fn flag_parity_evaluator_reports_exact_mismatches() {
        let artifact = gate_artifact_for_test(
            true, "Auto", "Disabled", "Auto", "Disabled", "Auto", "Auto", "Auto", "Auto", "Auto",
            "Auto",
        );
        let (matched, mismatches) = evaluate_flag_parity_with_env(&artifact, |key| match key {
            "OPENVINO_BENCHMARK_OK" => Some("1".to_string()),
            "THP_BENCHMARK_OK" => Some("0".to_string()),
            "ZSWAP_BENCHMARK_OK" => Some("1".to_string()),
            "ZRAM_BENCHMARK_OK" => Some("unset".to_string()),
            "OPENBLAS_BENCHMARK_OK" => Some("0".to_string()),
            "BLIS_BENCHMARK_OK" => Some("1".to_string()),
            "PERF_BENCHMARK_OK" => Some("1".to_string()),
            "TRACY_BENCHMARK_OK" => Some("1".to_string()),
            "AUTOFDO_BENCHMARK_OK" => Some("1".to_string()),
            "BOLT_BENCHMARK_OK" => Some("1".to_string()),
            "ISPC_BENCHMARK_OK" => Some("1".to_string()),
            "HIGHWAY_BENCHMARK_OK" => Some("1".to_string()),
            "RUST_ARCH_SIMD_BENCHMARK_OK" => Some("1".to_string()),
            "RAYON_BENCHMARK_OK" => Some("1".to_string()),
            _ => None,
        });
        assert_eq!(matched, 11);
        assert_eq!(mismatches.len(), 3);
        assert!(
            mismatches
                .iter()
                .any(|item| item.contains("THP_BENCHMARK_OK"))
        );
        assert!(
            mismatches
                .iter()
                .any(|item| item.contains("ZRAM_BENCHMARK_OK"))
        );
        assert!(
            mismatches
                .iter()
                .any(|item| item.contains("OPENBLAS_BENCHMARK_OK"))
        );
    }

    #[test]
    fn flag_parity_format_includes_ratio() {
        let artifact = gate_artifact_for_test(
            true, "Auto", "Disabled", "Auto", "Disabled", "Auto", "Auto", "Auto", "Auto", "Auto",
            "Auto",
        );
        let text = format_flag_parity(&artifact);
        assert!(text.contains("flags "));
        assert!(text.contains("/14"));
    }

    #[test]
    fn gate_run_command_targets_adoption_gate_script() {
        let command = gate_run_command();
        assert!(command.contains("conditional_adoption_gate.ps1"));
        assert!(command.contains("-Iterations 8"));
    }

    #[test]
    fn gate_readiness_reports_blocked_for_missing_host_components() {
        let registry = FeaturePolicyRegistry::new(vec![
            FeatureDeclaration {
                id: FeatureId::OpenVinoBackend,
                supported_platforms: vec![Platform::current()],
                required_hardware: "test".to_string(),
                expected_benefit: "test".to_string(),
                known_risks: "test".to_string(),
                validation_method: "test".to_string(),
                fallback_path: "test".to_string(),
                benchmark_requirement: "test".to_string(),
                present_on_system: false,
            },
            FeatureDeclaration {
                id: FeatureId::TransparentHugePages,
                supported_platforms: vec![Platform::current()],
                required_hardware: "test".to_string(),
                expected_benefit: "test".to_string(),
                known_risks: "test".to_string(),
                validation_method: "test".to_string(),
                fallback_path: "test".to_string(),
                benchmark_requirement: "test".to_string(),
                present_on_system: false,
            },
            FeatureDeclaration {
                id: FeatureId::Zswap,
                supported_platforms: vec![Platform::current()],
                required_hardware: "test".to_string(),
                expected_benefit: "test".to_string(),
                known_risks: "test".to_string(),
                validation_method: "test".to_string(),
                fallback_path: "test".to_string(),
                benchmark_requirement: "test".to_string(),
                present_on_system: false,
            },
            FeatureDeclaration {
                id: FeatureId::Zram,
                supported_platforms: vec![Platform::current()],
                required_hardware: "test".to_string(),
                expected_benefit: "test".to_string(),
                known_risks: "test".to_string(),
                validation_method: "test".to_string(),
                fallback_path: "test".to_string(),
                benchmark_requirement: "test".to_string(),
                present_on_system: false,
            },
            FeatureDeclaration {
                id: FeatureId::OpenBlasBackend,
                supported_platforms: vec![Platform::current()],
                required_hardware: "test".to_string(),
                expected_benefit: "test".to_string(),
                known_risks: "test".to_string(),
                validation_method: "test".to_string(),
                fallback_path: "test".to_string(),
                benchmark_requirement: "test".to_string(),
                present_on_system: false,
            },
            FeatureDeclaration {
                id: FeatureId::BlisBackend,
                supported_platforms: vec![Platform::current()],
                required_hardware: "test".to_string(),
                expected_benefit: "test".to_string(),
                known_risks: "test".to_string(),
                validation_method: "test".to_string(),
                fallback_path: "test".to_string(),
                benchmark_requirement: "test".to_string(),
                present_on_system: false,
            },
            FeatureDeclaration {
                id: FeatureId::PerfProfiler,
                supported_platforms: vec![Platform::current()],
                required_hardware: "test".to_string(),
                expected_benefit: "test".to_string(),
                known_risks: "test".to_string(),
                validation_method: "test".to_string(),
                fallback_path: "test".to_string(),
                benchmark_requirement: "test".to_string(),
                present_on_system: false,
            },
            FeatureDeclaration {
                id: FeatureId::TracyProfiler,
                supported_platforms: vec![Platform::current()],
                required_hardware: "test".to_string(),
                expected_benefit: "test".to_string(),
                known_risks: "test".to_string(),
                validation_method: "test".to_string(),
                fallback_path: "test".to_string(),
                benchmark_requirement: "test".to_string(),
                present_on_system: false,
            },
            FeatureDeclaration {
                id: FeatureId::AutoFdoOptimizer,
                supported_platforms: vec![Platform::current()],
                required_hardware: "test".to_string(),
                expected_benefit: "test".to_string(),
                known_risks: "test".to_string(),
                validation_method: "test".to_string(),
                fallback_path: "test".to_string(),
                benchmark_requirement: "test".to_string(),
                present_on_system: false,
            },
            FeatureDeclaration {
                id: FeatureId::BoltOptimizer,
                supported_platforms: vec![Platform::current()],
                required_hardware: "test".to_string(),
                expected_benefit: "test".to_string(),
                known_risks: "test".to_string(),
                validation_method: "test".to_string(),
                fallback_path: "test".to_string(),
                benchmark_requirement: "test".to_string(),
                present_on_system: false,
            },
            FeatureDeclaration {
                id: FeatureId::IspcKernels,
                supported_platforms: vec![Platform::current()],
                required_hardware: "test".to_string(),
                expected_benefit: "test".to_string(),
                known_risks: "test".to_string(),
                validation_method: "test".to_string(),
                fallback_path: "test".to_string(),
                benchmark_requirement: "test".to_string(),
                present_on_system: false,
            },
            FeatureDeclaration {
                id: FeatureId::HighwaySimd,
                supported_platforms: vec![Platform::current()],
                required_hardware: "test".to_string(),
                expected_benefit: "test".to_string(),
                known_risks: "test".to_string(),
                validation_method: "test".to_string(),
                fallback_path: "test".to_string(),
                benchmark_requirement: "test".to_string(),
                present_on_system: false,
            },
            FeatureDeclaration {
                id: FeatureId::RustArchSimd,
                supported_platforms: vec![Platform::current()],
                required_hardware: "test".to_string(),
                expected_benefit: "test".to_string(),
                known_risks: "test".to_string(),
                validation_method: "test".to_string(),
                fallback_path: "test".to_string(),
                benchmark_requirement: "test".to_string(),
                present_on_system: false,
            },
            FeatureDeclaration {
                id: FeatureId::RayonParallelism,
                supported_platforms: vec![Platform::current()],
                required_hardware: "test".to_string(),
                expected_benefit: "test".to_string(),
                known_risks: "test".to_string(),
                validation_method: "test".to_string(),
                fallback_path: "test".to_string(),
                benchmark_requirement: "test".to_string(),
                present_on_system: false,
            },
        ]);
        let readiness = format_gate_readiness(&registry);
        assert!(readiness.contains("openvino=blocked"));
        assert!(readiness.contains("memory_profile=blocked"));
        assert!(readiness.contains("dense_math=blocked"));
        assert!(readiness.contains("profiling=blocked"));
        assert!(readiness.contains("release_opt=blocked"));
        assert!(readiness.contains("ispc=blocked"));
        assert!(readiness.contains("simd=blocked"));
        assert!(readiness.contains("rayon=blocked"));
    }

    #[test]
    fn find_latest_gate_artifact_path_prefers_latest_timestamp_name() {
        let mut root = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|value| value.as_nanos())
            .unwrap_or(0);
        root.push(format!("forge_gate_artifacts_{nanos}"));
        assert!(fs::create_dir_all(&root).is_ok());

        let older = root.join("conditional-adoption-gate-20260319-010101.json");
        let newer = root.join("conditional-adoption-gate-20260319-020202.json");
        let ignored = root.join("conditional-benchmark-20260319-030303.json");
        assert!(fs::write(&older, "{}").is_ok());
        assert!(fs::write(&newer, "{}").is_ok());
        assert!(fs::write(&ignored, "{}").is_ok());

        let latest = find_latest_gate_artifact_path(&root);
        assert!(latest.is_some());
        let latest = match latest {
            Some(value) => value,
            None => return,
        };
        assert_eq!(latest, newer);

        let _ = fs::remove_file(older);
        let _ = fs::remove_file(newer);
        let _ = fs::remove_file(ignored);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn gate_artifact_formatting_surfaces_recommended_flags() {
        let mut path = std::env::temp_dir();
        path.push("forge_gate_artifact_formatting.json");
        let _ = fs::remove_file(&path);

        let artifact_json = r#"{
            "generated_at_utc": "2026-03-19T00:00:00Z",
            "gate_passed": true,
            "selected_defaults": {
                "openvino_backend": "Auto",
                "linux_memory_tuning_profile": "Disabled",
                "openblas_backend": "Auto",
                "blis_backend": "Disabled",
                "profiling_mode": "Auto",
                "release_optimization_mode": "Auto",
                "ispc_kernels": "Auto",
                "highway_simd": "Auto",
                "rust_arch_simd": "Auto",
                "rayon_parallelism": "Auto"
            },
            "recommended_env_flags": {
                "OPENVINO_BENCHMARK_OK": 1,
                "THP_BENCHMARK_OK": 0,
                "ZSWAP_BENCHMARK_OK": 1,
                "ZRAM_BENCHMARK_OK": 0,
                "OPENBLAS_BENCHMARK_OK": 1,
                "BLIS_BENCHMARK_OK": 0,
                "PERF_BENCHMARK_OK": 1,
                "TRACY_BENCHMARK_OK": 1,
                "AUTOFDO_BENCHMARK_OK": 1,
                "BOLT_BENCHMARK_OK": 1,
                "ISPC_BENCHMARK_OK": 1,
                "HIGHWAY_BENCHMARK_OK": 1,
                "RUST_ARCH_SIMD_BENCHMARK_OK": 1,
                "RAYON_BENCHMARK_OK": 1
            },
            "decision": {
                "passed": true,
                "reasons": [
                    "openvino throughput met threshold"
                ]
            }
        }"#;
        assert!(fs::write(&path, artifact_json).is_ok());

        let artifact = load_gate_artifact(&path);
        assert!(artifact.is_ok());
        let artifact = match artifact {
            Ok(value) => value,
            Err(_) => return,
        };

        let status = format_gate_artifact_status(&path, &artifact);
        assert!(status.contains("gate_passed=true"));
        assert!(status.contains("defaults(openvino=Auto,memory=Disabled,openblas=Auto,blis=Disabled,profiling=Auto,release_opt=Auto,ispc=Auto,highway=Auto,rust_arch_simd=Auto,rayon=Auto)"));
        assert!(status.contains("OPENVINO_BENCHMARK_OK=1"));
        assert!(status.contains("THP_BENCHMARK_OK=0"));
        assert!(status.contains("OPENBLAS_BENCHMARK_OK=1"));
        assert!(status.contains("PERF_BENCHMARK_OK=1"));
        assert!(status.contains("RAYON_BENCHMARK_OK=1"));

        let commands = format_gate_env_commands(&artifact);
        assert!(commands.contains("set OPENVINO_BENCHMARK_OK=1"));
        assert!(commands.contains("export ZRAM_BENCHMARK_OK=0"));
        assert!(commands.contains("set BLIS_BENCHMARK_OK=0"));
        assert!(commands.contains("set PERF_BENCHMARK_OK=1"));
        assert!(commands.contains("export RAYON_BENCHMARK_OK=1"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn launch_failure_signal_forces_policy_fallback_and_user_status() {
        let mut runtime_registry = RuntimeRegistry::new();
        runtime_registry.register(default_llama_runtime());
        let mut process_manager = RuntimeProcessManager::new();
        let feature_registry = seeded_feature_registry();
        let signals = RuntimeSyncSignals::new();

        let request = RuntimeLaunchRequest::new("forge-nonexistent-runtime-binary");
        let start = process_manager.start("llama.cpp", &request);
        assert_eq!(start, StartResult::LaunchFailed);

        sync_runtime_process_signals(
            &mut process_manager,
            &mut runtime_registry,
            signals.runtime_process_state,
            signals.runtime_process_pid,
            signals.runtime_version,
            signals.runtime_health,
            feature_registry.clone(),
            signals.feature_policy_status,
            signals.feature_fallback_visible,
            signals.feature_policy_snapshot,
            signals.runtime_vulkan_memory_status,
            signals.runtime_vulkan_validation_status,
        );

        assert!(signals.runtime_process_state.get().contains("LaunchFailed"));
        assert_eq!(signals.runtime_health.get(), "Unavailable");
        assert!(
            signals
                .feature_policy_status
                .get()
                .contains("moved to Fallback")
        );
        assert!(
            signals
                .feature_policy_status
                .get()
                .contains("runtime launch failed")
        );

        let feature_status = feature_registry
            .borrow()
            .status(FeatureId::VulkanMemoryAllocator);
        assert!(feature_status.is_some());
        let feature_status = match feature_status {
            Some(value) => value,
            None => return,
        };
        assert_eq!(feature_status.effective_state, FeatureState::Fallback);
    }

    #[test]
    fn duplicate_signal_is_deduplicated_and_does_not_re_notify() {
        let mut runtime_registry = RuntimeRegistry::new();
        runtime_registry.register(default_llama_runtime());
        let mut process_manager = RuntimeProcessManager::new();
        let feature_registry = seeded_feature_registry();
        let signals = RuntimeSyncSignals::new();

        let request = RuntimeLaunchRequest::new("forge-nonexistent-runtime-binary");
        let start = process_manager.start("llama.cpp", &request);
        assert_eq!(start, StartResult::LaunchFailed);

        sync_runtime_process_signals(
            &mut process_manager,
            &mut runtime_registry,
            signals.runtime_process_state,
            signals.runtime_process_pid,
            signals.runtime_version,
            signals.runtime_health,
            feature_registry.clone(),
            signals.feature_policy_status,
            signals.feature_fallback_visible,
            signals.feature_policy_snapshot,
            signals.runtime_vulkan_memory_status,
            signals.runtime_vulkan_validation_status,
        );
        let first_note = signals.feature_policy_status.get();
        assert!(first_note.contains("moved to Fallback"));

        signals
            .feature_policy_status
            .set(String::from("policy status sentinel"));
        sync_runtime_process_signals(
            &mut process_manager,
            &mut runtime_registry,
            signals.runtime_process_state,
            signals.runtime_process_pid,
            signals.runtime_version,
            signals.runtime_health,
            feature_registry.clone(),
            signals.feature_policy_status,
            signals.feature_fallback_visible,
            signals.feature_policy_snapshot,
            signals.runtime_vulkan_memory_status,
            signals.runtime_vulkan_validation_status,
        );

        assert_eq!(
            signals.feature_policy_status.get(),
            "policy status sentinel"
        );
    }

    #[test]
    fn nonzero_exit_signal_forces_fallback_and_updates_status() {
        let mut runtime_registry = RuntimeRegistry::new();
        runtime_registry.register(default_llama_runtime());
        let mut process_manager = RuntimeProcessManager::new();
        let feature_registry = seeded_feature_registry();
        let signals = RuntimeSyncSignals::new();

        let start = process_manager.start("llama.cpp", &nonzero_exit_request());
        assert_eq!(start, StartResult::Started);

        for _ in 0..25 {
            sync_runtime_process_signals(
                &mut process_manager,
                &mut runtime_registry,
                signals.runtime_process_state,
                signals.runtime_process_pid,
                signals.runtime_version,
                signals.runtime_health,
                feature_registry.clone(),
                signals.feature_policy_status,
                signals.feature_fallback_visible,
                signals.feature_policy_snapshot,
                signals.runtime_vulkan_memory_status,
                signals.runtime_vulkan_validation_status,
            );

            let status = process_manager.status("llama.cpp");
            if matches!(
                status.map(|value| value.state),
                Some(RuntimeProcessState::Exited(7))
            ) && signals
                .feature_policy_status
                .get()
                .contains("runtime exited non-zero: 7")
            {
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }

        assert!(signals.runtime_process_state.get().contains("Exited (7)"));
        assert_eq!(signals.runtime_health.get(), "Unavailable");
        assert!(
            signals
                .feature_policy_status
                .get()
                .contains("runtime exited non-zero: 7")
        );

        let feature_status = feature_registry
            .borrow()
            .status(FeatureId::VulkanMemoryAllocator);
        assert!(feature_status.is_some());
        let feature_status = match feature_status {
            Some(value) => value,
            None => return,
        };
        assert_eq!(feature_status.effective_state, FeatureState::Fallback);
    }

    #[test]
    fn policy_snapshot_includes_fallback_after_runtime_signal() {
        let mut runtime_registry = RuntimeRegistry::new();
        runtime_registry.register(default_llama_runtime());
        let mut process_manager = RuntimeProcessManager::new();
        let feature_registry = seeded_feature_registry();
        let signals = RuntimeSyncSignals::new();

        let request = RuntimeLaunchRequest::new("forge-nonexistent-runtime-binary");
        let start = process_manager.start("llama.cpp", &request);
        assert_eq!(start, StartResult::LaunchFailed);

        sync_runtime_process_signals(
            &mut process_manager,
            &mut runtime_registry,
            signals.runtime_process_state,
            signals.runtime_process_pid,
            signals.runtime_version,
            signals.runtime_health,
            feature_registry.clone(),
            signals.feature_policy_status,
            signals.feature_fallback_visible,
            signals.feature_policy_snapshot,
            signals.runtime_vulkan_memory_status,
            signals.runtime_vulkan_validation_status,
        );

        let snapshot = signals.feature_policy_snapshot.get();
        assert!(snapshot.contains("vulkan_memory_allocator"));
        assert!(snapshot.contains("effective=Fallback"));

        let rebuilt_snapshot = {
            let registry_ref = feature_registry.borrow();
            format_feature_policy_snapshot(&registry_ref, true)
        };
        assert!(rebuilt_snapshot.contains("effective=Fallback"));
    }

    #[test]
    fn agent_graph_and_trace_filter_views_render_expected_data() {
        let mut orchestrator = AgentOrchestrator::new();
        let run_result = create_default_agent_run(&mut orchestrator, "ui-trace-filter");
        assert!(run_result.is_ok());
        let run_id = match run_result {
            Ok(value) => value,
            Err(_) => return,
        };

        let _ = orchestrator.start_next_step(run_id);
        let _ = orchestrator.complete_step(run_id, "planner", "plan complete");
        let _ = orchestrator.start_next_step(run_id);
        let _ = orchestrator.request_approval(run_id, "coder", "needs approval");

        let run = orchestrator.run(run_id);
        assert!(run.is_some());
        let run = match run {
            Some(value) => value,
            None => return,
        };

        let graph = format_agent_graph(run);
        assert!(graph.contains("planner [planner]"));
        assert!(graph.contains("coder [coder]"));

        let filtered = format_agent_trace_filtered(run, "approval", "approval", "coder");
        assert!(filtered.contains("approval-requested"));
    }

    #[test]
    fn agent_studio_state_round_trip_persists_runs() {
        let mut orchestrator = AgentOrchestrator::new();
        let run_result = create_default_agent_run(&mut orchestrator, "persist-roundtrip");
        assert!(run_result.is_ok());
        let run_id = match run_result {
            Ok(value) => value,
            Err(_) => return,
        };

        let mut path = std::env::temp_dir();
        path.push("forge_agent_state_round_trip_test.json");
        let _ = fs::remove_file(&path);

        let save = save_agent_studio_state(&path, &orchestrator, Some(run_id));
        assert!(save.is_ok());
        let loaded = load_agent_studio_state(&path);
        assert!(loaded.is_some());
        let loaded = match loaded {
            Some(value) => value,
            None => return,
        };
        assert_eq!(loaded.active_run_id, Some(run_id));
        assert_eq!(loaded.runs.len(), 1);
        let _ = fs::remove_file(PathBuf::from(&path));
    }

    #[test]
    fn runtime_registry_state_round_trip_persists_metadata() {
        let mut registry = RuntimeRegistry::new();
        registry.register(default_llama_runtime());
        assert!(registry.set_pinned_version("llama.cpp", true));
        assert_eq!(
            registry.update_version("llama.cpp", "0.3.0"),
            UpdateResult::BlockedByPin
        );
        assert!(registry.set_pinned_version("llama.cpp", false));
        assert_eq!(
            registry.update_version("llama.cpp", "0.3.0"),
            UpdateResult::Updated
        );
        assert!(registry.rollback("llama.cpp"));
        assert!(registry.record_benchmark(
            "llama.cpp",
            "vulkan_chat_completion_live",
            121,
            Some(33),
            true
        ));

        let mut path = std::env::temp_dir();
        path.push("forge_runtime_registry_state_roundtrip.json");
        let _ = fs::remove_file(&path);

        let saved = save_runtime_registry_state(&path, &registry);
        assert!(saved.is_ok());
        let loaded = load_runtime_registry_state(&path);
        assert!(loaded.is_some());
        let loaded = match loaded {
            Some(value) => value,
            None => return,
        };
        let loaded_entry = loaded.get("llama.cpp");
        assert!(loaded_entry.is_some());
        let loaded_entry = match loaded_entry {
            Some(value) => value,
            None => return,
        };
        assert_eq!(loaded_entry.rollback_history.len(), 1);
        assert_eq!(loaded_entry.benchmark_history.len(), 1);
        assert_eq!(
            loaded_entry.benchmark_history[0].workload,
            "vulkan_chat_completion_live"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn project_memory_state_round_trip_persists_entries() {
        let mut store = ProjectMemoryStore::new();
        assert!(
            store
                .upsert(
                    MemoryScope::Project,
                    "goal",
                    "finish backlog slice",
                    "agent"
                )
                .is_ok()
        );
        assert!(
            store
                .upsert(MemoryScope::Workspace, "repo", "E:/Forge", "agent")
                .is_ok()
        );
        let _ = store.recall(MemoryScope::Project, "backlog", 8);

        let mut path = std::env::temp_dir();
        path.push("forge_project_memory_state_roundtrip.json");
        let _ = fs::remove_file(&path);

        let saved = save_project_memory_state(&path, &store);
        assert!(saved.is_ok());
        let loaded = load_project_memory_state(&path);
        assert!(loaded.is_some());
        let loaded = match loaded {
            Some(value) => value,
            None => return,
        };
        let stats = loaded.stats();
        assert_eq!(stats.project_entries, 1);
        assert_eq!(stats.workspace_entries, 1);
        assert_eq!(stats.session_entries, 0);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn media_studio_state_round_trip_persists_gallery_and_checkpoints() {
        let state = PersistedMediaStudioState {
            schema_version: 1,
            media_prompt: String::from("render forged steel keyboard"),
            media_seed: String::from("41"),
            media_batch_size: String::from("3"),
            media_gallery: String::from("#1 queued | seed=41"),
            media_next_asset_id: 11,
            video_prompt: String::from("pan shot over workstation"),
            video_seed: String::from("77"),
            video_batch_size: String::from("2"),
            video_duration_seconds: String::from("8"),
            video_checkpoint_entries: vec![VideoCheckpointState {
                asset_id: 9,
                prompt_preview: String::from("pan shot over workstation"),
                seed: 77,
                duration_seconds: 8,
                source_id: String::from("video-sidecar"),
                source_display_name: String::from("Video Sidecar"),
                source_kind: SourceKind::SidecarBridge,
                progress_percent: 40,
                state: String::from("checkpointed"),
            }],
        };

        let mut path = std::env::temp_dir();
        path.push("forge_media_studio_state_roundtrip.json");
        let _ = fs::remove_file(&path);

        let saved = save_media_studio_state(&path, &state);
        assert!(saved.is_ok());
        let loaded = load_media_studio_state(&path);
        assert!(loaded.is_some());
        let loaded = match loaded {
            Some(value) => value,
            None => return,
        };
        assert_eq!(loaded.media_prompt, "render forged steel keyboard");
        assert_eq!(loaded.media_next_asset_id, 11);
        assert_eq!(loaded.video_checkpoint_entries.len(), 1);
        let checkpoint = &loaded.video_checkpoint_entries[0];
        assert_eq!(checkpoint.asset_id, 9);
        assert_eq!(checkpoint.source_id, "video-sidecar");
        assert_eq!(checkpoint.progress_percent, 40);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn chat_confidential_state_round_trip_persists_policy_controls() {
        let state = PersistedChatConfidentialState {
            schema_version: 1,
            measurement: String::from("sha256:trusted-chat"),
            policy_mode: String::from("enabled"),
            max_attestation_age_ms: String::from("120000"),
            profile_window_size: String::from("24"),
            require_confidential_cpu: false,
            require_confidential_gpu: true,
            allow_remote_fallback: true,
        };

        let mut path = std::env::temp_dir();
        path.push("forge_chat_confidential_state_roundtrip.json");
        let _ = fs::remove_file(&path);

        let saved = save_chat_confidential_state(&path, &state);
        assert!(saved.is_ok());
        let loaded = load_chat_confidential_state(&path);
        assert!(loaded.is_some());
        let loaded = match loaded {
            Some(value) => value,
            None => return,
        };
        assert_eq!(loaded.measurement, "sha256:trusted-chat");
        assert_eq!(loaded.policy_mode, "enabled");
        assert_eq!(loaded.max_attestation_age_ms, "120000");
        assert_eq!(loaded.profile_window_size, "24");
        assert!(!loaded.require_confidential_cpu);
        assert!(loaded.require_confidential_gpu);
        assert!(loaded.allow_remote_fallback);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn chat_confidential_state_load_accepts_legacy_without_profile_window_field() {
        let json = r#"{
  "schema_version": 1,
  "measurement": "sha256:legacy",
  "policy_mode": "required",
  "max_attestation_age_ms": "300000",
  "require_confidential_cpu": true,
  "require_confidential_gpu": true
}"#;
        let mut path = std::env::temp_dir();
        path.push("forge_chat_confidential_legacy_state.json");
        let _ = fs::remove_file(&path);
        assert!(fs::write(&path, json).is_ok());

        let loaded = load_chat_confidential_state(&path);
        assert!(loaded.is_some());
        let loaded = match loaded {
            Some(value) => value,
            None => return,
        };
        assert_eq!(
            loaded.profile_window_size,
            default_chat_confidential_profile_window()
        );
        assert_eq!(
            loaded.allow_remote_fallback,
            default_chat_confidential_allow_remote_fallback()
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn dock_layout_state_round_trip_persists_visibility_flags() {
        let state = PersistedDockLayoutState {
            schema_version: 1,
            sidebar_open: false,
            inspector_open: true,
            bottom_open: true,
        };

        let mut path = std::env::temp_dir();
        path.push("forge_dock_layout_state_roundtrip.json");
        let _ = fs::remove_file(&path);

        let saved = save_dock_layout_state(&path, &state);
        assert!(saved.is_ok());
        let loaded = load_dock_layout_state(&path);
        assert!(loaded.is_some());
        let loaded = match loaded {
            Some(value) => value,
            None => return,
        };
        assert!(!loaded.sidebar_open);
        assert!(loaded.inspector_open);
        assert!(loaded.bottom_open);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn parse_confidential_mode_input_accepts_aliases() {
        assert!(matches!(
            parse_confidential_mode_input("required"),
            Ok(runtime_registry::confidential_relay::ConfidentialRelayMode::Required)
        ));
        assert!(matches!(
            parse_confidential_mode_input("on"),
            Ok(runtime_registry::confidential_relay::ConfidentialRelayMode::Enabled)
        ));
        assert!(matches!(
            parse_confidential_mode_input("off"),
            Ok(runtime_registry::confidential_relay::ConfidentialRelayMode::Disabled)
        ));
        assert!(parse_confidential_mode_input("maybe").is_err());
    }

    #[test]
    fn parse_profile_window_size_input_validates_positive_integer() {
        let parsed = parse_profile_window_size_input("32");
        assert!(parsed.is_ok());
        assert_eq!(parsed.unwrap_or_default(), 32);
        assert!(parse_profile_window_size_input("0").is_err());
        assert!(parse_profile_window_size_input("abc").is_err());
    }

    #[test]
    fn extension_host_state_round_trip_persists_permissions_and_isolation() {
        let mut host = default_extension_host();
        assert!(host.grant_all_permissions("provider-openai").is_ok());
        assert!(host.set_enabled("provider-openai", true).is_ok());
        assert!(
            host.isolate_failure("provider-openai", "manual isolation from UI")
                .is_ok()
        );

        let mut path = std::env::temp_dir();
        path.push("forge_extension_host_state_roundtrip.json");
        let _ = fs::remove_file(&path);

        let saved = save_extension_host_state(&path, &host);
        assert!(saved.is_ok());
        let loaded = load_extension_host_state(&path);
        assert!(loaded.is_some());
        let loaded = match loaded {
            Some(value) => value,
            None => return,
        };
        let runtime = loaded.get("provider-openai");
        assert!(runtime.is_some());
        let runtime = match runtime {
            Some(value) => value,
            None => return,
        };
        assert_eq!(runtime.state, ExtensionState::FailedIsolated);
        assert_eq!(
            runtime.last_error.as_deref(),
            Some("manual isolation from UI")
        );
        let check = loaded.permission_check("provider-openai");
        assert!(check.is_ok());
        let check = match check {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(check.can_enable);
        assert!(check.missing_permissions.is_empty());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn job_queue_state_round_trip_restores_running_and_queued_jobs() {
        let mut queue = JobQueue::new();
        let _ = queue.enqueue("queued-code", JobKind::CodeBuild, JobPriority::Normal);
        let _ = queue.enqueue(
            "queued-image",
            JobKind::ImageGeneration,
            JobPriority::Foreground,
        );
        let running = queue.start_next();
        assert!(running.is_some());
        let running = match running {
            Some(value) => value,
            None => return,
        };
        let _ = queue.fail(running, "mock fail");
        let _ = queue.enqueue(
            "queued-video",
            JobKind::VideoGeneration,
            JobPriority::Background,
        );
        let _ = queue.start_next();

        let mut path = std::env::temp_dir();
        path.push("forge_job_queue_state_roundtrip.json");
        let _ = fs::remove_file(&path);

        let saved = save_job_queue_state(&path, &queue);
        assert!(saved.is_ok());
        let loaded = load_job_queue_state(&path);
        assert!(loaded.is_some());
        let loaded = match loaded {
            Some(value) => value,
            None => return,
        };
        let restored = JobQueue::restore_state(loaded.queue);
        assert!(restored.is_ok());
        let restored = match restored {
            Ok(value) => value,
            Err(_) => return,
        };
        let snapshot = restored.snapshot();
        assert!(snapshot.running >= 1);
        assert!(snapshot.queued >= 1);
        assert!(snapshot.failed >= 1);
        assert!(restored.first_running_job().is_some());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn tracked_queue_helpers_progress_llm_and_agent_jobs() {
        let queue = Rc::new(RefCell::new(JobQueue::new()));
        let queued_jobs = RwSignal::new(0_u32);
        let running_jobs = RwSignal::new(0_u32);
        let completed_jobs = RwSignal::new(0_u32);
        let failed_jobs = RwSignal::new(0_u32);
        let cancelled_jobs = RwSignal::new(0_u32);

        let llm_job = queue_start_tracked_job(
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
        assert_eq!(running_jobs.get(), 1);
        assert_eq!(queued_jobs.get(), 0);
        let running_timeline = format_job_timeline(&queue.borrow(), "running", 8);
        assert!(running_timeline.contains("kind=llm"));
        assert!(running_timeline.contains("state=running"));
        assert!(queue_complete_tracked_job(
            &queue,
            llm_job,
            queued_jobs,
            running_jobs,
            completed_jobs,
            failed_jobs,
            cancelled_jobs,
        ));
        assert_eq!(running_jobs.get(), 0);
        assert_eq!(completed_jobs.get(), 1);

        let agent_job = queue_start_tracked_job(
            &queue,
            "agent-codex-coder".to_string(),
            JobKind::AgentRun,
            JobPriority::Foreground,
            queued_jobs,
            running_jobs,
            completed_jobs,
            failed_jobs,
            cancelled_jobs,
        );
        assert_eq!(running_jobs.get(), 1);
        assert!(queue_fail_tracked_job(
            &queue,
            agent_job,
            "adapter timeout".to_string(),
            queued_jobs,
            running_jobs,
            completed_jobs,
            failed_jobs,
            cancelled_jobs,
        ));
        assert_eq!(running_jobs.get(), 0);
        assert_eq!(failed_jobs.get(), 1);

        let recent = queue.borrow().records_recent(2);
        assert_eq!(recent.len(), 2);
        assert!(matches!(recent[0].kind, JobKind::AgentRun));
        assert!(matches!(recent[1].kind, JobKind::LlmInference));
    }

    #[test]
    fn code_studio_refresh_files_action_tracks_queue_success() {
        let mut root = std::env::temp_dir();
        root.push("forge_code_studio_refresh_files_queue_test");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::create_dir_all(root.join("src"));
        let _ = fs::write(root.join("src").join("main.rs"), "fn main() {}\n");

        let workspace = WorkspaceHost::new(root.clone());
        let queue = Rc::new(RefCell::new(JobQueue::new()));
        let queued_jobs = RwSignal::new(0_u32);
        let running_jobs = RwSignal::new(0_u32);
        let completed_jobs = RwSignal::new(0_u32);
        let failed_jobs = RwSignal::new(0_u32);
        let cancelled_jobs = RwSignal::new(0_u32);
        let code_file_list = RwSignal::new(String::new());
        let code_queue_status = RwSignal::new(String::from("code queue idle"));

        let tracked_job_id = queue_start_tracked_job(
            &queue,
            "code-refresh-files".to_string(),
            JobKind::SystemTask,
            JobPriority::Normal,
            queued_jobs,
            running_jobs,
            completed_jobs,
            failed_jobs,
            cancelled_jobs,
        );
        match workspace.list_files(60) {
            Ok(files) => {
                code_file_list.set(format_file_list(&files));
                let _ = queue_complete_tracked_job(
                    &queue,
                    tracked_job_id,
                    queued_jobs,
                    running_jobs,
                    completed_jobs,
                    failed_jobs,
                    cancelled_jobs,
                );
                code_queue_status.set(format!("files refreshed [job #{}]", tracked_job_id.raw()));
            }
            Err(error) => {
                code_file_list.set(format!("Workspace files error: {error:?}"));
                let _ = queue_fail_tracked_job(
                    &queue,
                    tracked_job_id,
                    format!("workspace list failed: {error:?}"),
                    queued_jobs,
                    running_jobs,
                    completed_jobs,
                    failed_jobs,
                    cancelled_jobs,
                );
                code_queue_status.set(format!(
                    "files refresh failed [job #{}]",
                    tracked_job_id.raw()
                ));
            }
        }

        assert_eq!(running_jobs.get(), 0);
        assert_eq!(completed_jobs.get(), 1);
        assert_eq!(failed_jobs.get(), 0);
        assert!(code_queue_status.get().contains("files refreshed"));
        assert!(
            code_queue_status
                .get()
                .contains(&format!("[job #{}]", tracked_job_id.raw()))
        );
        assert!(code_file_list.get().contains("main.rs"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn code_studio_load_action_tracks_queue_failure() {
        let mut root = std::env::temp_dir();
        root.push("forge_code_studio_load_queue_failure_test");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::create_dir_all(&root);

        let workspace = WorkspaceHost::new(root.clone());
        let queue = Rc::new(RefCell::new(JobQueue::new()));
        let queued_jobs = RwSignal::new(0_u32);
        let running_jobs = RwSignal::new(0_u32);
        let completed_jobs = RwSignal::new(0_u32);
        let failed_jobs = RwSignal::new(0_u32);
        let cancelled_jobs = RwSignal::new(0_u32);
        let code_editor_preview = RwSignal::new(String::new());
        let code_queue_status = RwSignal::new(String::from("code queue idle"));
        let path = String::from("missing.rs");

        let tracked_job_id = queue_start_tracked_job(
            &queue,
            format!("code-load-{path}"),
            JobKind::CodeBuild,
            JobPriority::Normal,
            queued_jobs,
            running_jobs,
            completed_jobs,
            failed_jobs,
            cancelled_jobs,
        );
        match workspace.read_file_excerpt(&path, 80, 5000) {
            Ok(excerpt) => {
                code_editor_preview.set(excerpt);
                let _ = queue_complete_tracked_job(
                    &queue,
                    tracked_job_id,
                    queued_jobs,
                    running_jobs,
                    completed_jobs,
                    failed_jobs,
                    cancelled_jobs,
                );
                code_queue_status.set(format!("editor loaded [job #{}]", tracked_job_id.raw()));
            }
            Err(error) => {
                code_editor_preview.set(format!("Editor open failed: {error:?}"));
                let _ = queue_fail_tracked_job(
                    &queue,
                    tracked_job_id,
                    format!("editor load failed: {error:?}"),
                    queued_jobs,
                    running_jobs,
                    completed_jobs,
                    failed_jobs,
                    cancelled_jobs,
                );
                code_queue_status.set(format!(
                    "editor load failed [job #{}]",
                    tracked_job_id.raw()
                ));
            }
        }

        assert_eq!(running_jobs.get(), 0);
        assert_eq!(completed_jobs.get(), 0);
        assert_eq!(failed_jobs.get(), 1);
        assert!(code_queue_status.get().contains("editor load failed"));
        assert!(
            code_queue_status
                .get()
                .contains(&format!("[job #{}]", tracked_job_id.raw()))
        );
        assert!(code_editor_preview.get().contains("Editor open failed"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn jobs_timeline_filter_limits_to_matching_records() {
        let mut queue = JobQueue::new();
        let _ = queue.enqueue(
            "index workspace",
            JobKind::SystemTask,
            JobPriority::Background,
        );
        let image = queue.enqueue(
            "image-asset-42",
            JobKind::ImageGeneration,
            JobPriority::Normal,
        );
        let _ = queue.start_next();
        let _ = queue.start_next();
        assert!(queue.fail(image, "mock failure"));

        let failed_view = format_job_timeline(&queue, "failed", 8);
        assert!(failed_view.contains("state=failed"));
        assert!(failed_view.contains("kind=image"));
        assert!(!failed_view.contains("kind=system"));

        let system_view = format_job_timeline(&queue, "system", 8);
        assert!(system_view.contains("kind=system"));
        assert!(!system_view.contains("kind=image"));
    }

    #[test]
    fn vulkan_benchmark_history_drives_policy_gate_transition() {
        let mut runtime_registry = RuntimeRegistry::new();
        runtime_registry.register(default_llama_runtime());
        assert!(runtime_registry.record_benchmark(
            "llama.cpp",
            "vulkan_chat_completion_live",
            420,
            Some(7),
            false
        ));
        assert!(runtime_registry.record_benchmark(
            "llama.cpp",
            "vulkan_chat_completion_live",
            410,
            Some(8),
            false
        ));
        assert!(runtime_registry.record_benchmark(
            "llama.cpp",
            "vulkan_chat_completion_live",
            401,
            Some(9),
            true
        ));

        let mut feature_registry = FeaturePolicyRegistry::with_defaults();
        let _ = feature_registry
            .set_requested_state(FeatureId::VulkanMemoryAllocator, FeatureState::Auto);
        evaluate_registry_with_default_checks(&mut feature_registry);

        let note =
            apply_vulkan_benchmark_gate_from_registry(&runtime_registry, &mut feature_registry);
        assert!(note.contains("fail"));
        let status = feature_registry.status(FeatureId::VulkanMemoryAllocator);
        assert!(status.is_some());
        let status = match status {
            Some(value) => value,
            None => return,
        };
        assert_eq!(status.effective_state, FeatureState::Fallback);
    }

    #[test]
    fn runtime_registry_card_summaries_include_benchmark_and_rollback_metadata() {
        let mut registry = RuntimeRegistry::new();
        registry.register(default_llama_runtime());
        assert!(registry.set_pinned_version("llama.cpp", true));
        assert_eq!(
            registry.update_version("llama.cpp", "0.2.0"),
            UpdateResult::BlockedByPin
        );
        assert!(registry.set_pinned_version("llama.cpp", false));
        assert_eq!(
            registry.update_version("llama.cpp", "0.2.0"),
            UpdateResult::Updated
        );
        assert!(registry.rollback("llama.cpp"));
        assert!(registry.record_benchmark("llama.cpp", "chat_completion", 111, Some(39), true));

        let benchmark = format_runtime_benchmark_summary(&registry, "llama.cpp");
        assert!(benchmark.contains("runs=1"));
        assert!(benchmark.contains("111ms"));

        let rollback = format_runtime_pin_rollback_summary(&registry, "llama.cpp");
        assert!(rollback.contains("rollback_events=1"));
        assert!(rollback.contains("pinned=no"));
    }

    #[test]
    fn codex_prompt_builder_includes_goal_instruction_and_context() {
        let mut orchestrator = AgentOrchestrator::new();
        let run_result = create_default_agent_run(&mut orchestrator, "codex prompt test");
        assert!(run_result.is_ok());
        let run_id = match run_result {
            Ok(value) => value,
            Err(_) => return,
        };
        let _ = orchestrator.start_next_step(run_id);
        let _ = orchestrator.complete_step(run_id, "planner", "planner output");
        let run = orchestrator.run(run_id);
        assert!(run.is_some());
        let run = match run {
            Some(value) => value,
            None => return,
        };

        let prompt = build_codex_specialist_prompt(
            run,
            "coder",
            "apply patch safely",
            "prefer minimal diff",
        );
        assert!(prompt.contains("Goal: codex prompt test"));
        assert!(prompt.contains("Coder Step: coder"));
        assert!(prompt.contains("Instruction: apply patch safely"));
        assert!(prompt.contains("planner output"));
    }

    #[test]
    fn workspace_provenance_block_includes_trust_label_and_source_path() {
        let mut root = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|value| value.as_nanos())
            .unwrap_or(0);
        root.push(format!("forge_workspace_provenance_{nanos}"));
        assert!(fs::create_dir_all(root.join("src")).is_ok());
        assert!(fs::write(root.join("src/main.rs"), "fn main() {}\n").is_ok());

        let workspace = WorkspaceHost::new(root.clone());
        let block = build_workspace_input_provenance_block(&workspace, "src/main.rs");
        assert!(block.is_some());
        let block = match block {
            Some(value) => value,
            None => return,
        };
        assert!(block.contains("trust_label=trusted.workspace.local.canonical"));
        assert!(block.contains("provenance=workspace://src/main.rs"));
        assert!(block.contains("fn main() {}"));

        let prompt = append_workspace_provenance_to_prompt(
            "Base agent prompt".to_string(),
            &workspace,
            "src/main.rs",
        );
        assert!(prompt.contains("Base agent prompt"));
        assert!(prompt.contains("Workspace Input Provenance"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn source_registry_reports_codex_specialist_default() {
        let registry = default_source_registry();
        let summary = format_source_role_default(&registry, SourceRole::CodexSpecialist);
        assert!(summary.contains("Codex Specialist"));
    }

    #[test]
    fn planner_route_uses_local_default_source() {
        let registry = default_source_registry();
        let route = resolve_source_route_for_role(&registry, SourceRole::Planner);
        assert!(route.is_ok());
        let route = match route {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(matches!(route.source_kind, SourceKind::LocalModel));
    }

    #[test]
    fn debugger_route_uses_local_default_source() {
        let registry = default_source_registry();
        let route = resolve_source_route_for_role(&registry, SourceRole::Debugger);
        assert!(route.is_ok());
        let route = match route {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(matches!(route.source_kind, SourceKind::LocalModel));
    }

    #[test]
    fn verifier_route_uses_local_default_source() {
        let registry = default_source_registry();
        let route = resolve_source_route_for_role(&registry, SourceRole::Verifier);
        assert!(route.is_ok());
        let route = match route {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(matches!(route.source_kind, SourceKind::LocalModel));
    }

    #[test]
    fn planner_route_honors_remote_default_override() {
        let mut registry = default_source_registry();
        let set_default =
            registry.set_default_for_role(SourceRole::Planner, "openjarvis-mode-b-sidecar");
        assert!(set_default.is_ok());

        let route = resolve_source_route_for_role(&registry, SourceRole::Planner);
        assert!(route.is_ok());
        let route = match route {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(route.source_id, "openjarvis-mode-b-sidecar");
        assert!(matches!(route.source_kind, SourceKind::SidecarBridge));
    }

    #[test]
    fn debugger_route_honors_remote_default_override() {
        let mut registry = default_source_registry();
        let set_default =
            registry.set_default_for_role(SourceRole::Debugger, "openjarvis-mode-b-sidecar");
        assert!(set_default.is_ok());

        let route = resolve_source_route_for_role(&registry, SourceRole::Debugger);
        assert!(route.is_ok());
        let route = match route {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(route.source_id, "openjarvis-mode-b-sidecar");
        assert!(matches!(route.source_kind, SourceKind::SidecarBridge));
    }

    #[test]
    fn verifier_route_honors_remote_default_override() {
        let mut registry = default_source_registry();
        let set_default =
            registry.set_default_for_role(SourceRole::Verifier, "openjarvis-mode-b-sidecar");
        assert!(set_default.is_ok());

        let route = resolve_source_route_for_role(&registry, SourceRole::Verifier);
        assert!(route.is_ok());
        let route = match route {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(route.source_id, "openjarvis-mode-b-sidecar");
        assert!(matches!(route.source_kind, SourceKind::SidecarBridge));
    }

    #[test]
    fn agent_roles_map_to_source_roles_for_routed_execution() {
        assert_eq!(
            source_role_for_agent_role(AgentRole::Planner),
            Some(SourceRole::Planner)
        );
        assert_eq!(
            source_role_for_agent_role(AgentRole::Coder),
            Some(SourceRole::Coder)
        );
        assert_eq!(
            source_role_for_agent_role(AgentRole::Debugger),
            Some(SourceRole::Debugger)
        );
        assert_eq!(
            source_role_for_agent_role(AgentRole::Verifier),
            Some(SourceRole::Verifier)
        );
    }

    #[test]
    fn media_source_route_resolution_uses_current_role_default() {
        let mut registry = default_source_registry();
        let set_default = registry.set_default_for_role(SourceRole::ImageGeneration, "api-openai");
        assert!(set_default.is_ok());

        let route = resolve_source_route_for_role(&registry, SourceRole::ImageGeneration);
        assert!(route.is_ok());
        let route = match route {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(route.source_id, "api-openai");
    }

    #[test]
    fn media_source_route_resolution_fails_without_enabled_video_sources() {
        let mut registry = default_source_registry();
        assert!(registry.set_enabled("local-video-runtime", false));
        assert!(registry.set_enabled("api-openai", false));

        let route = resolve_source_route_for_role(&registry, SourceRole::VideoGeneration);
        assert!(route.is_err());
    }

    #[test]
    fn source_registry_state_round_trip_persists_default_override() {
        let mut registry = default_source_registry();
        let override_result =
            registry.set_default_for_role(SourceRole::Coder, "openjarvis-mode-b-sidecar");
        assert!(override_result.is_ok());

        let mut path = std::env::temp_dir();
        path.push("forge_source_registry_state_roundtrip.json");
        let _ = fs::remove_file(&path);

        let saved = save_source_registry_state(&path, &registry);
        assert!(saved.is_ok());
        let loaded = load_source_registry_state(&path);
        assert!(loaded.is_some());
        let loaded = match loaded {
            Some(value) => value,
            None => return,
        };
        let default_for_coder = loaded.default_for(SourceRole::Coder);
        assert!(default_for_coder.is_some());
        let default_for_coder = match default_for_coder {
            Some(value) => value,
            None => return,
        };
        assert_eq!(default_for_coder.id, "openjarvis-mode-b-sidecar");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn cross_surface_source_routing_and_queue_persistence_round_trip() {
        let mut registry = default_source_registry();
        assert!(
            registry
                .set_default_for_role(SourceRole::Chat, "api-openai")
                .is_ok()
        );
        assert!(
            registry
                .set_default_for_role(SourceRole::Planner, "openjarvis-mode-b-sidecar")
                .is_ok()
        );
        assert!(
            registry
                .set_default_for_role(SourceRole::ImageGeneration, "api-openai")
                .is_ok()
        );
        assert!(
            registry
                .set_default_for_role(SourceRole::VideoGeneration, "api-openai")
                .is_ok()
        );

        let mut source_path = std::env::temp_dir();
        source_path.push("forge_phase3_cross_surface_source_registry_roundtrip.json");
        let _ = fs::remove_file(&source_path);

        assert!(save_source_registry_state(&source_path, &registry).is_ok());
        let loaded_registry = load_source_registry_state(&source_path);
        assert!(loaded_registry.is_some());
        let loaded_registry = match loaded_registry {
            Some(value) => value,
            None => return,
        };

        let chat_route = resolve_source_route_for_role(&loaded_registry, SourceRole::Chat);
        assert!(chat_route.is_ok());
        let chat_route = match chat_route {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(chat_route.source_id, "api-openai");
        assert!(matches!(chat_route.source_kind, SourceKind::ApiModel));

        let planner_route = resolve_source_route_for_role(&loaded_registry, SourceRole::Planner);
        assert!(planner_route.is_ok());
        let planner_route = match planner_route {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(planner_route.source_id, "openjarvis-mode-b-sidecar");
        assert!(matches!(
            planner_route.source_kind,
            SourceKind::SidecarBridge
        ));

        let image_route =
            resolve_source_route_for_role(&loaded_registry, SourceRole::ImageGeneration);
        assert!(image_route.is_ok());
        let image_route = match image_route {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(image_route.source_id, "api-openai");
        assert!(matches!(image_route.source_kind, SourceKind::ApiModel));

        let video_route =
            resolve_source_route_for_role(&loaded_registry, SourceRole::VideoGeneration);
        assert!(video_route.is_ok());
        let video_route = match video_route {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(video_route.source_id, "api-openai");
        assert!(matches!(video_route.source_kind, SourceKind::ApiModel));

        let queue = Rc::new(RefCell::new(JobQueue::new()));
        let queued_jobs = RwSignal::new(0_u32);
        let running_jobs = RwSignal::new(0_u32);
        let completed_jobs = RwSignal::new(0_u32);
        let failed_jobs = RwSignal::new(0_u32);
        let cancelled_jobs = RwSignal::new(0_u32);

        let chat_job = queue_start_tracked_job(
            &queue,
            format!("chat-routed-{}", chat_route.source_id),
            JobKind::LlmInference,
            JobPriority::Foreground,
            queued_jobs,
            running_jobs,
            completed_jobs,
            failed_jobs,
            cancelled_jobs,
        );
        assert!(queue_complete_tracked_job(
            &queue,
            chat_job,
            queued_jobs,
            running_jobs,
            completed_jobs,
            failed_jobs,
            cancelled_jobs,
        ));

        let planner_job = queue_start_tracked_job(
            &queue,
            format!("planner-routed-{}", planner_route.source_id),
            JobKind::AgentRun,
            JobPriority::Foreground,
            queued_jobs,
            running_jobs,
            completed_jobs,
            failed_jobs,
            cancelled_jobs,
        );
        assert!(queue_complete_tracked_job(
            &queue,
            planner_job,
            queued_jobs,
            running_jobs,
            completed_jobs,
            failed_jobs,
            cancelled_jobs,
        ));

        let image_job = queue_start_tracked_job(
            &queue,
            format!("image-routed-{}", image_route.source_id),
            JobKind::ImageGeneration,
            JobPriority::Normal,
            queued_jobs,
            running_jobs,
            completed_jobs,
            failed_jobs,
            cancelled_jobs,
        );
        assert!(queue_complete_tracked_job(
            &queue,
            image_job,
            queued_jobs,
            running_jobs,
            completed_jobs,
            failed_jobs,
            cancelled_jobs,
        ));

        let video_job = queue_start_tracked_job(
            &queue,
            format!("video-routed-{}", video_route.source_id),
            JobKind::VideoGeneration,
            JobPriority::Normal,
            queued_jobs,
            running_jobs,
            completed_jobs,
            failed_jobs,
            cancelled_jobs,
        );
        assert!(queue_fail_tracked_job(
            &queue,
            video_job,
            "mock video timeout".to_string(),
            queued_jobs,
            running_jobs,
            completed_jobs,
            failed_jobs,
            cancelled_jobs,
        ));

        assert_eq!(running_jobs.get(), 0);
        assert_eq!(completed_jobs.get(), 3);
        assert_eq!(failed_jobs.get(), 1);

        let mut queue_path = std::env::temp_dir();
        queue_path.push("forge_phase3_cross_surface_queue_roundtrip.json");
        let _ = fs::remove_file(&queue_path);

        let queue_ref = queue.borrow();
        assert!(save_job_queue_state(&queue_path, &queue_ref).is_ok());
        drop(queue_ref);

        let loaded_queue = load_job_queue_state(&queue_path);
        assert!(loaded_queue.is_some());
        let loaded_queue = match loaded_queue {
            Some(value) => value,
            None => return,
        };
        let restored_queue = JobQueue::restore_state(loaded_queue.queue);
        assert!(restored_queue.is_ok());
        let restored_queue = match restored_queue {
            Ok(value) => value,
            Err(_) => return,
        };
        let snapshot = restored_queue.snapshot();
        assert_eq!(snapshot.running, 0);
        assert_eq!(snapshot.completed, 3);
        assert_eq!(snapshot.failed, 1);

        let timeline = format_job_timeline(&restored_queue, "all", 16);
        assert!(timeline.contains("chat-routed-api-openai"));
        assert!(timeline.contains("planner-routed-openjarvis-mode-b-sidecar"));
        assert!(timeline.contains("image-routed-api-openai"));
        assert!(timeline.contains("video-routed-api-openai"));

        let _ = fs::remove_file(source_path);
        let _ = fs::remove_file(queue_path);
    }

    #[test]
    fn auto_codex_policy_triggers_only_for_running_coder_step() {
        let mut orchestrator = AgentOrchestrator::new();
        let run_result = create_default_agent_run(&mut orchestrator, "auto-codex-policy");
        assert!(run_result.is_ok());
        let run_id = match run_result {
            Ok(value) => value,
            Err(_) => return,
        };

        let planner_start = orchestrator.start_next_step(run_id);
        assert!(planner_start.is_ok());
        let planner_step_id = match planner_start {
            Ok(Some(value)) => value,
            _ => return,
        };
        let run = orchestrator.run(run_id);
        assert!(run.is_some());
        let run = match run {
            Some(value) => value,
            None => return,
        };
        assert!(!should_auto_run_codex_for_started_step(
            run,
            &planner_step_id
        ));

        let _ = orchestrator.complete_step(run_id, "planner", "planner complete");
        let coder_start = orchestrator.start_next_step(run_id);
        assert!(coder_start.is_ok());
        let coder_step_id = match coder_start {
            Ok(Some(value)) => value,
            _ => return,
        };
        let run = orchestrator.run(run_id);
        assert!(run.is_some());
        let run = match run {
            Some(value) => value,
            None => return,
        };
        assert!(should_auto_run_codex_for_started_step(run, &coder_step_id));
    }

    #[test]
    fn auto_routed_policy_triggers_for_planner_debugger_and_verifier_steps() {
        let mut orchestrator = AgentOrchestrator::new();
        let run_result = create_default_agent_run(&mut orchestrator, "auto-routed-policy");
        assert!(run_result.is_ok());
        let run_id = match run_result {
            Ok(value) => value,
            Err(_) => return,
        };

        let planner_start = orchestrator.start_next_step(run_id);
        assert!(planner_start.is_ok());
        let planner_step_id = match planner_start {
            Ok(Some(value)) => value,
            _ => return,
        };
        let run = orchestrator.run(run_id);
        assert!(run.is_some());
        let run = match run {
            Some(value) => value,
            None => return,
        };
        assert!(should_auto_run_routed_for_started_step(
            run,
            &planner_step_id
        ));

        let _ = orchestrator.complete_step(run_id, "planner", "planner complete");
        let coder_start = orchestrator.start_next_step(run_id);
        assert!(coder_start.is_ok());
        let coder_step_id = match coder_start {
            Ok(Some(value)) => value,
            _ => return,
        };
        let run = orchestrator.run(run_id);
        assert!(run.is_some());
        let run = match run {
            Some(value) => value,
            None => return,
        };
        assert!(!should_auto_run_routed_for_started_step(
            run,
            &coder_step_id
        ));

        let _ = orchestrator.complete_step(run_id, "coder", "coder complete");
        let debugger_start = orchestrator.start_next_step(run_id);
        assert!(debugger_start.is_ok());
        let debugger_step_id = match debugger_start {
            Ok(Some(value)) => value,
            _ => return,
        };
        let run = orchestrator.run(run_id);
        assert!(run.is_some());
        let run = match run {
            Some(value) => value,
            None => return,
        };
        assert!(should_auto_run_routed_for_started_step(
            run,
            &debugger_step_id
        ));

        let _ = orchestrator.complete_step(run_id, "debugger", "debugger complete");
        let verifier_start = orchestrator.start_next_step(run_id);
        assert!(verifier_start.is_ok());
        let verifier_step_id = match verifier_start {
            Ok(Some(value)) => value,
            _ => return,
        };
        let run = orchestrator.run(run_id);
        assert!(run.is_some());
        let run = match run {
            Some(value) => value,
            None => return,
        };
        assert!(should_auto_run_routed_for_started_step(
            run,
            &verifier_step_id
        ));
    }

    #[test]
    fn extension_inventory_summary_reports_enabled_and_isolated_counts() {
        let mut host = default_extension_host();
        assert!(host.grant_all_permissions("provider-openai").is_ok());
        assert!(host.set_enabled("provider-openai", true).is_ok());
        assert!(
            host.isolate_failure("viewer-session-inspector", "crash")
                .is_ok()
        );

        let summary = format_extension_inventory_summary(&host);
        assert!(summary.contains("total=2"));
        assert!(summary.contains("enabled=1"));
        assert!(summary.contains("isolated=1"));
    }

    #[test]
    fn extension_target_detail_shows_permission_blocked_state() {
        let mut host = ExtensionHost::new();
        let register = host.register(ExtensionManifest {
            id: "provider-x".to_string(),
            display_name: "Provider X".to_string(),
            class: ExtensionClass::ModelProvider,
            idle_cost_mb: 20,
            startup_cost_ms: 30,
            memory_budget_mb: 128,
            cpu_budget_percent: 18,
            requires_network: true,
            background_activity: "request-response".to_string(),
            requested_permissions: vec![
                ExtensionPermission::Network,
                ExtensionPermission::ExternalApis,
            ],
        });
        assert!(register.is_ok());

        let detail = format_extension_target_detail(&host, "provider-x");
        assert!(detail.contains("permission-check=blocked"));
        assert!(detail.contains("network"));
        assert!(detail.contains("external_apis"));
        assert!(detail.contains("granted_permissions=[none]"));
    }

    #[test]
    fn extension_target_detail_reports_granted_permissions_after_grant() {
        let mut host = default_extension_host();
        assert!(host.grant_all_permissions("provider-openai").is_ok());

        let detail = format_extension_target_detail(&host, "provider-openai");
        assert!(detail.contains("permission-check=pass"));
        assert!(detail.contains("granted_permissions=[external_apis,network]"));
    }

    #[test]
    fn memory_scope_parser_accepts_supported_scope_keys() {
        assert_eq!(
            parse_memory_scope_input("session"),
            Some(MemoryScope::Session)
        );
        assert_eq!(
            parse_memory_scope_input("project"),
            Some(MemoryScope::Project)
        );
        assert_eq!(
            parse_memory_scope_input("work-space"),
            Some(MemoryScope::Workspace)
        );
        assert!(parse_memory_scope_input("global").is_none());
    }

    #[test]
    fn source_role_parser_accepts_supported_role_keys() {
        assert_eq!(parse_source_role_input("chat"), Some(SourceRole::Chat));
        assert_eq!(
            parse_source_role_input("planner"),
            Some(SourceRole::Planner)
        );
        assert_eq!(parse_source_role_input("coder"), Some(SourceRole::Coder));
        assert_eq!(
            parse_source_role_input("codex-specialist"),
            Some(SourceRole::CodexSpecialist)
        );
        assert_eq!(
            parse_source_role_input("image_generation"),
            Some(SourceRole::ImageGeneration)
        );
        assert_eq!(
            parse_source_role_input("video"),
            Some(SourceRole::VideoGeneration)
        );
        assert!(parse_source_role_input("global").is_none());
    }
}
