use std::{
    cell::RefCell,
    collections::HashMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    panic::{self, AssertUnwindSafe},
    rc::Rc,
    sync::{Mutex, OnceLock},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use control_plane::agent_orchestrator::{
    AgentGraphNode, AgentOrchestrator, AgentRole, AgentRun, AgentStepStatus, AgentTraceEventKind,
    RetryPolicy,
};
use control_plane::extension_host::{
    ExtensionHost, ExtensionHostError, ExtensionPermission, ExtensionResourceTotals,
    ExtensionRuntimeSnapshot, ExtensionState, default_extension_host,
};
use control_plane::feature_policy::{
    FeaturePolicyRegistry, RuntimeSafetyTrigger, VulkanBenchmarkGateConfig,
    VulkanBenchmarkGateDecision, VulkanBenchmarkSample, apply_vulkan_benchmark_gate,
    default_activation_checks_for_declaration_with_env, evaluate_vulkan_benchmark_gate,
};
use control_plane::lmdb_metadata::open_lmdb_metadata_store;
use control_plane::project_memory::{MemoryEntry, MemoryScope, ProjectMemoryStore};
use execution_plane::{
    jobs::{JobId, JobKind, JobPriority, JobQueue, JobQueueState, JobRecord, JobState},
    terminal::{TerminalSessionId, TerminalSessionManager, TerminalSessionState},
    workspace::{GitStatusSummary, TerminalCommandResult, WorkspaceHost},
};
use floem::AnyView;
use floem::Application;
use floem::prelude::*;
use floem::window::{Icon, WindowConfig};
use runtime_registry::{
    confidential_relay::{
        AttestationEvidence, AttestationVerifierConfig, ConfidentialEndpointMetadata,
        ConfidentialRelayMode, ConfidentialRelayPolicy, ConfidentialRelaySessionStore,
        RelayEncryptionMode, unix_time_ms_now,
    },
    health::{
        RuntimeBackend, RuntimeEntry, RuntimeHealth, RuntimeRegistry, UpdateResult,
        default_llama_runtime,
    },
    openjarvis_bridge::default_openjarvis_mode_a_runtime,
    openjarvis_mode_b::default_openjarvis_mode_b_runtime,
    process::{
        LlamaCppCompletionRequest, LlamaCppLaunchProfile, RuntimeLaunchRequest,
        RuntimeProcessManager, RuntimeProcessState, RuntimeSafetySignal, StartResult, StopResult,
        run_llama_cpp_completion,
    },
    provider_adapter::{
        ChatTaskRequest, CodexSpecialistTaskRequest, ConfidentialChatTaskRequest, RoleTaskRequest,
        run_chat_task_with_source, run_codex_specialist_task,
        run_confidential_chat_task_with_source, run_role_task_with_source,
    },
    source_registry::{
        SourceEntry, SourceKind, SourceRegistry, SourceRole, default_source_registry,
    },
};
use serde::{Deserialize, Serialize};
use urm::budget::{MemoryBudget, ResourceManager, SpillPolicy, TransferKind};
use urm::feature_policy::{ActivationChecks, FeatureId, FeatureState};
use urm::vulkan_memory::{
    VulkanMemoryAllocatorKind, VulkanMemoryPolicy, VulkanMemoryPolicyMode, VulkanMemoryState,
    resolve_vulkan_memory_status,
};

use crate::{api::PrimaryView, theme};

static FORGE_LOG_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static FORGE_PANIC_HOOK_INSTALLED: OnceLock<()> = OnceLock::new();

fn now_unix_ms() -> u128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis(),
        Err(_) => 0,
    }
}

fn forge_log_path() -> PathBuf {
    match std::env::current_dir() {
        Ok(path) => path.join("forge.exe.log"),
        Err(_) => PathBuf::from("E:/Forge/forge.exe.log"),
    }
}

fn append_forge_log_line(level: &str, scope: &str, message: &str) {
    let lock = FORGE_LOG_LOCK.get_or_init(|| Mutex::new(()));
    if let Ok(_guard) = lock.lock() {
        let log_path = forge_log_path();
        if let Ok(mut file) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
        {
            let _ = writeln!(
                file,
                "[{}] [{}] [{}] {}",
                now_unix_ms(),
                level,
                scope,
                message
            );
        }
    }
}

fn log_info(scope: &str, message: impl AsRef<str>) {
    append_forge_log_line("INFO", scope, message.as_ref());
}

fn log_warn(scope: &str, message: impl AsRef<str>) {
    append_forge_log_line("WARN", scope, message.as_ref());
}

fn log_error(scope: &str, message: impl AsRef<str>) {
    append_forge_log_line("ERROR", scope, message.as_ref());
}

fn log_startup_checkpoint(scope: &str, started: Instant) {
    log_info(
        "startup",
        format!("{scope} finished in {}ms", started.elapsed().as_millis()),
    );
}

fn install_forge_panic_hook() {
    if FORGE_PANIC_HOOK_INSTALLED.get().is_some() {
        return;
    }
    let previous_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        let location = panic_info
            .location()
            .map(|value| format!("{}:{}", value.file(), value.line()))
            .unwrap_or_else(|| "unknown-location".to_string());
        let payload = if let Some(message) = panic_info.payload().downcast_ref::<&str>() {
            (*message).to_string()
        } else if let Some(message) = panic_info.payload().downcast_ref::<String>() {
            message.clone()
        } else {
            "non-string panic payload".to_string()
        };
        let backtrace = std::backtrace::Backtrace::force_capture();
        log_error(
            "panic",
            format!(
                "ui panic at {} | {} | backtrace={:?}",
                location, payload, backtrace
            ),
        );
        previous_hook(panic_info);
    }));
    let _ = FORGE_PANIC_HOOK_INSTALLED.set(());
}

fn guarded_ui_action<F>(
    action_name: &'static str,
    status_signal: Option<RwSignal<String>>,
    action: F,
) -> impl Fn() + 'static
where
    F: Fn() + 'static,
{
    move || {
        let started = Instant::now();
        log_info("action", format!("{action_name} started"));
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            action();
        }));
        match result {
            Ok(()) => {
                log_info(
                    "action",
                    format!(
                        "{action_name} completed in {}ms",
                        started.elapsed().as_millis()
                    ),
                );
            }
            Err(_) => {
                log_error("action", format!("{action_name} panicked"));
                if let Some(status) = status_signal {
                    status.set(format!(
                        "{action_name} crashed; see {}",
                        forge_log_path().display()
                    ));
                }
            }
        }
    }
}

include!("app/shell_core.rs");
include!("app/panel_model.rs");
include!("app/panel_agent.rs");
include!("app/panel_settings.rs");
include!("app/panel_chat.rs");
include!("app/panel_media.rs");
include!("app/panel_code.rs");
include!("app/panel_inspector.rs");
include!("app/panel_jobs_bottom.rs");
include!("app/runtime_state_helpers.rs");
include!("app/feature_policy_gate.rs");
include!("app/tests.rs");
