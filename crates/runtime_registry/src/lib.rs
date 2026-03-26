#![forbid(unsafe_code)]

pub mod allocator_build;
pub mod confidential_relay;
pub mod io_routing;
pub mod local_api_hardening;
pub mod openjarvis_bridge;
pub mod openjarvis_mode_b;
pub mod provider_adapter;
pub mod source_registry;
pub mod vulkan_memory;
pub mod health {
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::error::Error;
    use std::fmt;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RuntimeRegistryStorageError {
        message: String,
    }

    impl RuntimeRegistryStorageError {
        fn new(message: impl Into<String>) -> Self {
            Self {
                message: message.into(),
            }
        }
    }

    impl fmt::Display for RuntimeRegistryStorageError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.message)
        }
    }

    impl Error for RuntimeRegistryStorageError {}

    impl From<RuntimeRegistryStorageError> for String {
        fn from(value: RuntimeRegistryStorageError) -> Self {
            value.to_string()
        }
    }

    /// Runtime health state used in Model Studio cards and routing policy.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub enum RuntimeHealth {
        Unknown,
        Healthy,
        Degraded,
        Unavailable,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub enum RuntimeType {
        LlamaCpp,
        ForgeNative,
        OpenJarvisManaged,
        ApiBacked,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub enum RuntimeBackend {
        Cpu,
        Vulkan,
        Cuda,
        Hip,
        Sycl,
        Hybrid,
        RemoteApi,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RuntimeEntry {
        pub id: String,
        pub display_name: String,
        pub runtime_type: RuntimeType,
        pub binary_or_endpoint: String,
        pub version: String,
        pub backend: RuntimeBackend,
        pub health: RuntimeHealth,
        pub pinned_version: bool,
        pub default_local_runtime: bool,
        pub last_benchmark_ms: Option<u64>,
        pub rollback_version: Option<String>,
        pub benchmark_history: Vec<RuntimeBenchmarkRecord>,
        pub rollback_history: Vec<RuntimeRollbackRecord>,
        pub updated_at: SystemTime,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RuntimeBenchmarkRecord {
        pub workload: String,
        pub latency_ms: u64,
        pub tokens_per_second: Option<u32>,
        pub success: bool,
        pub recorded_at: SystemTime,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RuntimeRollbackRecord {
        pub from_version: String,
        pub to_version: String,
        pub trigger: String,
        pub recorded_at: SystemTime,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum UpdateResult {
        Updated,
        AlreadyCurrent,
        BlockedByPin,
        RuntimeNotFound,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct PersistedRuntimeRegistryState {
        schema_version: u32,
        entries: Vec<PersistedRuntimeEntry>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct PersistedRuntimeEntry {
        id: String,
        display_name: String,
        runtime_type: RuntimeType,
        binary_or_endpoint: String,
        version: String,
        backend: RuntimeBackend,
        health: RuntimeHealth,
        pinned_version: bool,
        default_local_runtime: bool,
        last_benchmark_ms: Option<u64>,
        rollback_version: Option<String>,
        benchmark_history: Vec<PersistedRuntimeBenchmarkRecord>,
        rollback_history: Vec<PersistedRuntimeRollbackRecord>,
        updated_at_unix_ms: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct PersistedRuntimeBenchmarkRecord {
        workload: String,
        latency_ms: u64,
        tokens_per_second: Option<u32>,
        success: bool,
        recorded_at_unix_ms: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct PersistedRuntimeRollbackRecord {
        from_version: String,
        to_version: String,
        trigger: String,
        recorded_at_unix_ms: u64,
    }

    #[derive(Debug, Default)]
    pub struct RuntimeRegistry {
        entries: HashMap<String, RuntimeEntry>,
    }

    impl RuntimeRegistry {
        const PERSISTED_SCHEMA_VERSION: u32 = 1;

        pub fn new() -> Self {
            Self::default()
        }

        pub fn register(&mut self, entry: RuntimeEntry) {
            self.entries.insert(entry.id.clone(), entry);
        }

        pub fn get(&self, id: &str) -> Option<&RuntimeEntry> {
            self.entries.get(id)
        }

        pub fn list(&self) -> Vec<&RuntimeEntry> {
            let mut entries: Vec<&RuntimeEntry> = self.entries.values().collect();
            entries.sort_by_key(|entry| entry.display_name.as_str());
            entries
        }

        pub fn save_to_path(&self, path: &Path) -> Result<(), RuntimeRegistryStorageError> {
            let persisted = self.to_persisted_state();
            let encoded = serde_json::to_string_pretty(&persisted).map_err(|error| {
                RuntimeRegistryStorageError::new(format!(
                    "runtime metadata serialization failed: {error}"
                ))
            })?;
            fs::write(path, encoded).map_err(|error| {
                RuntimeRegistryStorageError::new(format!(
                    "runtime metadata write failed at {}: {error}",
                    path.display()
                ))
            })
        }

        pub fn load_from_path(path: &Path) -> Result<Self, String> {
            let contents = fs::read_to_string(path).map_err(|error| {
                format!(
                    "runtime metadata read failed at {}: {error}",
                    path.display()
                )
            })?;
            let persisted: PersistedRuntimeRegistryState = serde_json::from_str(&contents)
                .map_err(|error| format!("runtime metadata parse failed: {error}"))?;
            Self::from_persisted_state(persisted)
        }

        fn to_persisted_state(&self) -> PersistedRuntimeRegistryState {
            let mut entries = self
                .entries
                .values()
                .map(|entry| PersistedRuntimeEntry {
                    id: entry.id.clone(),
                    display_name: entry.display_name.clone(),
                    runtime_type: entry.runtime_type,
                    binary_or_endpoint: entry.binary_or_endpoint.clone(),
                    version: entry.version.clone(),
                    backend: entry.backend,
                    health: entry.health,
                    pinned_version: entry.pinned_version,
                    default_local_runtime: entry.default_local_runtime,
                    last_benchmark_ms: entry.last_benchmark_ms,
                    rollback_version: entry.rollback_version.clone(),
                    benchmark_history: entry
                        .benchmark_history
                        .iter()
                        .map(|record| PersistedRuntimeBenchmarkRecord {
                            workload: record.workload.clone(),
                            latency_ms: record.latency_ms,
                            tokens_per_second: record.tokens_per_second,
                            success: record.success,
                            recorded_at_unix_ms: system_time_to_unix_ms(record.recorded_at),
                        })
                        .collect(),
                    rollback_history: entry
                        .rollback_history
                        .iter()
                        .map(|record| PersistedRuntimeRollbackRecord {
                            from_version: record.from_version.clone(),
                            to_version: record.to_version.clone(),
                            trigger: record.trigger.clone(),
                            recorded_at_unix_ms: system_time_to_unix_ms(record.recorded_at),
                        })
                        .collect(),
                    updated_at_unix_ms: system_time_to_unix_ms(entry.updated_at),
                })
                .collect::<Vec<_>>();
            entries.sort_by(|left, right| left.id.cmp(&right.id));
            PersistedRuntimeRegistryState {
                schema_version: Self::PERSISTED_SCHEMA_VERSION,
                entries,
            }
        }

        fn from_persisted_state(state: PersistedRuntimeRegistryState) -> Result<Self, String> {
            if state.schema_version != Self::PERSISTED_SCHEMA_VERSION {
                return Err(format!(
                    "runtime metadata schema mismatch: expected {} got {}",
                    Self::PERSISTED_SCHEMA_VERSION,
                    state.schema_version
                ));
            }
            let mut entries = HashMap::new();
            for entry in state.entries {
                let runtime_entry = RuntimeEntry {
                    id: entry.id.clone(),
                    display_name: entry.display_name,
                    runtime_type: entry.runtime_type,
                    binary_or_endpoint: entry.binary_or_endpoint,
                    version: entry.version,
                    backend: entry.backend,
                    health: entry.health,
                    pinned_version: entry.pinned_version,
                    default_local_runtime: entry.default_local_runtime,
                    last_benchmark_ms: entry.last_benchmark_ms,
                    rollback_version: entry.rollback_version,
                    benchmark_history: entry
                        .benchmark_history
                        .into_iter()
                        .map(|record| RuntimeBenchmarkRecord {
                            workload: record.workload,
                            latency_ms: record.latency_ms,
                            tokens_per_second: record.tokens_per_second,
                            success: record.success,
                            recorded_at: unix_ms_to_system_time(record.recorded_at_unix_ms),
                        })
                        .collect(),
                    rollback_history: entry
                        .rollback_history
                        .into_iter()
                        .map(|record| RuntimeRollbackRecord {
                            from_version: record.from_version,
                            to_version: record.to_version,
                            trigger: record.trigger,
                            recorded_at: unix_ms_to_system_time(record.recorded_at_unix_ms),
                        })
                        .collect(),
                    updated_at: unix_ms_to_system_time(entry.updated_at_unix_ms),
                };
                entries.insert(runtime_entry.id.clone(), runtime_entry);
            }
            Ok(Self { entries })
        }

        pub fn set_health(&mut self, id: &str, health: RuntimeHealth) -> bool {
            let Some(entry) = self.entries.get_mut(id) else {
                return false;
            };
            entry.health = health;
            entry.updated_at = SystemTime::now();
            true
        }

        pub fn set_pinned_version(&mut self, id: &str, pinned: bool) -> bool {
            let Some(entry) = self.entries.get_mut(id) else {
                return false;
            };
            entry.pinned_version = pinned;
            entry.updated_at = SystemTime::now();
            true
        }

        pub fn update_version(&mut self, id: &str, new_version: impl Into<String>) -> UpdateResult {
            let Some(entry) = self.entries.get_mut(id) else {
                return UpdateResult::RuntimeNotFound;
            };
            if entry.pinned_version {
                return UpdateResult::BlockedByPin;
            }

            let new_version = new_version.into();
            if entry.version == new_version {
                return UpdateResult::AlreadyCurrent;
            }
            entry.rollback_version = Some(entry.version.clone());
            entry.version = new_version;
            entry.updated_at = SystemTime::now();
            UpdateResult::Updated
        }

        pub fn rollback(&mut self, id: &str) -> bool {
            let Some(entry) = self.entries.get_mut(id) else {
                return false;
            };
            let Some(previous) = entry.rollback_version.take() else {
                return false;
            };
            let current = std::mem::replace(&mut entry.version, previous);
            entry.rollback_version = Some(current);
            entry.rollback_history.push(RuntimeRollbackRecord {
                from_version: entry
                    .rollback_version
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                to_version: entry.version.clone(),
                trigger: "manual rollback".to_string(),
                recorded_at: SystemTime::now(),
            });
            cap_history(&mut entry.rollback_history, 24);
            entry.updated_at = SystemTime::now();
            true
        }

        pub fn record_benchmark(
            &mut self,
            id: &str,
            workload: impl Into<String>,
            latency_ms: u64,
            tokens_per_second: Option<u32>,
            success: bool,
        ) -> bool {
            let Some(entry) = self.entries.get_mut(id) else {
                return false;
            };
            entry.last_benchmark_ms = Some(latency_ms);
            entry.benchmark_history.push(RuntimeBenchmarkRecord {
                workload: workload.into(),
                latency_ms,
                tokens_per_second,
                success,
                recorded_at: SystemTime::now(),
            });
            cap_history(&mut entry.benchmark_history, 40);
            entry.updated_at = SystemTime::now();
            true
        }

        pub fn benchmark_history(&self, id: &str) -> Option<&[RuntimeBenchmarkRecord]> {
            self.entries
                .get(id)
                .map(|entry| entry.benchmark_history.as_slice())
        }

        pub fn rollback_history(&self, id: &str) -> Option<&[RuntimeRollbackRecord]> {
            self.entries
                .get(id)
                .map(|entry| entry.rollback_history.as_slice())
        }

        pub fn set_default_local_runtime(&mut self, id: &str) -> bool {
            if !self.entries.contains_key(id) {
                return false;
            }
            for entry in self.entries.values_mut() {
                entry.default_local_runtime = false;
            }
            if let Some(entry) = self.entries.get_mut(id) {
                entry.default_local_runtime = true;
            }
            true
        }
    }

    pub fn default_llama_runtime() -> RuntimeEntry {
        let binary_or_endpoint = resolve_default_llama_binary_path();
        let backend = resolve_llama_backend(&binary_or_endpoint);
        RuntimeEntry {
            id: "llama.cpp".to_string(),
            display_name: "llama.cpp".to_string(),
            runtime_type: RuntimeType::LlamaCpp,
            binary_or_endpoint,
            version: "0.0.0-bootstrap".to_string(),
            backend,
            health: RuntimeHealth::Unknown,
            pinned_version: false,
            default_local_runtime: true,
            last_benchmark_ms: None,
            rollback_version: None,
            benchmark_history: Vec::new(),
            rollback_history: Vec::new(),
            updated_at: SystemTime::now(),
        }
    }

    fn cap_history<T>(items: &mut Vec<T>, max_len: usize) {
        if items.len() > max_len {
            let remove_count = items.len() - max_len;
            items.drain(0..remove_count);
        }
    }

    fn system_time_to_unix_ms(value: SystemTime) -> u64 {
        value
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
            .unwrap_or(0)
    }

    fn unix_ms_to_system_time(value: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(value)
    }

    fn resolve_default_llama_binary_path() -> String {
        let candidates = [
            "E:/Forge/runtimes/llama.cpp/llama-server.exe",
            "E:/Forge/runtimes/llama.cpp/llama-server",
            "E:/Forge/runtimes/llama.cpp/bin/llama-server.exe",
            "E:/Forge/runtimes/llama.cpp/bin/llama-server",
        ];
        for candidate in candidates {
            if Path::new(candidate).exists() {
                return candidate.to_string();
            }
        }
        candidates[0].to_string()
    }

    fn resolve_llama_backend(binary_or_endpoint: &str) -> RuntimeBackend {
        let runtime_root = resolve_llama_runtime_root(Path::new(binary_or_endpoint));
        detect_llama_backend(runtime_root.as_deref())
    }

    fn resolve_llama_runtime_root(binary_or_endpoint: &Path) -> Option<PathBuf> {
        let mut root = if binary_or_endpoint.is_dir() {
            binary_or_endpoint.to_path_buf()
        } else {
            binary_or_endpoint.parent()?.to_path_buf()
        };
        if root
            .file_name()
            .map(|value| value.to_string_lossy().eq_ignore_ascii_case("bin"))
            .unwrap_or(false)
            && let Some(parent) = root.parent()
        {
            root = parent.to_path_buf();
        }
        Some(root)
    }

    fn detect_llama_backend(runtime_root: Option<&Path>) -> RuntimeBackend {
        let Some(runtime_root) = runtime_root else {
            return RuntimeBackend::Cpu;
        };

        let mut detected = Vec::new();

        if backend_marker_exists(
            runtime_root,
            &[
                "ggml-vulkan.dll",
                "libggml-vulkan.so",
                "libggml-vulkan.dylib",
            ],
        ) {
            detected.push(RuntimeBackend::Vulkan);
        }
        if backend_marker_exists(
            runtime_root,
            &["ggml-cuda.dll", "libggml-cuda.so", "libggml-cuda.dylib"],
        ) {
            detected.push(RuntimeBackend::Cuda);
        }
        if backend_marker_exists(
            runtime_root,
            &["ggml-hip.dll", "libggml-hip.so", "libggml-hip.dylib"],
        ) {
            detected.push(RuntimeBackend::Hip);
        }
        if backend_marker_exists(
            runtime_root,
            &["ggml-sycl.dll", "libggml-sycl.so", "libggml-sycl.dylib"],
        ) {
            detected.push(RuntimeBackend::Sycl);
        }

        match detected.len() {
            0 => RuntimeBackend::Cpu,
            1 => detected[0],
            _ => RuntimeBackend::Hybrid,
        }
    }

    fn backend_marker_exists(runtime_root: &Path, markers: &[&str]) -> bool {
        markers.iter().any(|marker| {
            runtime_root.join(marker).exists() || runtime_root.join("bin").join(marker).exists()
        })
    }

    #[cfg(test)]
    mod tests {
        use std::fs;
        use std::path::PathBuf;
        use std::time::{SystemTime, UNIX_EPOCH};

        use super::{
            RuntimeBackend, RuntimeHealth, RuntimeRegistry, UpdateResult, default_llama_runtime,
            resolve_llama_backend,
        };

        fn unique_test_root(label: &str) -> PathBuf {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            std::env::temp_dir().join(format!("forge_runtime_health_{label}_{nonce}"))
        }

        #[test]
        fn runtime_update_and_rollback_work() {
            let mut registry = RuntimeRegistry::new();
            registry.register(default_llama_runtime());

            let updated = registry.update_version("llama.cpp", "0.1.0");
            assert_eq!(updated, UpdateResult::Updated);
            assert_eq!(
                registry
                    .get("llama.cpp")
                    .map(|entry| entry.version.as_str()),
                Some("0.1.0")
            );

            assert!(registry.rollback("llama.cpp"));
            assert_eq!(
                registry
                    .get("llama.cpp")
                    .map(|entry| entry.version.as_str()),
                Some("0.0.0-bootstrap")
            );

            let rollback_history = registry.rollback_history("llama.cpp");
            assert!(rollback_history.is_some());
            let rollback_history = match rollback_history {
                Some(value) => value,
                None => return,
            };
            assert_eq!(rollback_history.len(), 1);
            assert_eq!(rollback_history[0].from_version, "0.1.0");
            assert_eq!(rollback_history[0].to_version, "0.0.0-bootstrap");
        }

        #[test]
        fn health_update_changes_runtime_state() {
            let mut registry = RuntimeRegistry::new();
            registry.register(default_llama_runtime());
            assert!(registry.set_health("llama.cpp", RuntimeHealth::Healthy));
            assert_eq!(
                registry.get("llama.cpp").map(|entry| entry.health),
                Some(RuntimeHealth::Healthy)
            );
        }

        #[test]
        fn pinned_runtime_blocks_update_until_unpinned() {
            let mut registry = RuntimeRegistry::new();
            registry.register(default_llama_runtime());
            assert!(registry.set_pinned_version("llama.cpp", true));

            let blocked = registry.update_version("llama.cpp", "0.2.0");
            assert_eq!(blocked, UpdateResult::BlockedByPin);
            assert_eq!(
                registry
                    .get("llama.cpp")
                    .map(|entry| entry.version.as_str()),
                Some("0.0.0-bootstrap")
            );

            assert!(registry.set_pinned_version("llama.cpp", false));
            let updated = registry.update_version("llama.cpp", "0.2.0");
            assert_eq!(updated, UpdateResult::Updated);
        }

        #[test]
        fn benchmark_records_are_captured_and_visible() {
            let mut registry = RuntimeRegistry::new();
            registry.register(default_llama_runtime());
            assert!(registry.record_benchmark("llama.cpp", "chat_completion", 143, Some(38), true));
            assert!(registry.record_benchmark(
                "llama.cpp",
                "chat_completion",
                151,
                Some(35),
                false
            ));

            let entry = registry.get("llama.cpp");
            assert!(entry.is_some());
            let entry = match entry {
                Some(value) => value,
                None => return,
            };
            assert_eq!(entry.last_benchmark_ms, Some(151));
            assert_eq!(entry.benchmark_history.len(), 2);
            assert_eq!(entry.benchmark_history[0].workload, "chat_completion");
            assert!(entry.benchmark_history[0].success);
            assert!(!entry.benchmark_history[1].success);
        }

        #[test]
        fn default_llama_runtime_path_uses_llama_server_naming() {
            let entry = default_llama_runtime();
            assert!(entry.binary_or_endpoint.contains("llama-server"));
        }

        #[test]
        fn runtime_metadata_persistence_round_trip_preserves_histories() {
            let mut registry = RuntimeRegistry::new();
            registry.register(default_llama_runtime());
            assert_eq!(
                registry.update_version("llama.cpp", "0.3.0"),
                UpdateResult::Updated
            );
            assert!(registry.rollback("llama.cpp"));
            assert!(registry.set_pinned_version("llama.cpp", true));
            assert!(registry.record_benchmark("llama.cpp", "chat_completion", 122, Some(34), true));

            let root = unique_test_root("persist");
            assert!(fs::create_dir_all(&root).is_ok());
            let state_path = root.join("runtime_registry_state.json");

            let saved = registry.save_to_path(&state_path);
            assert!(saved.is_ok());

            let loaded = RuntimeRegistry::load_from_path(&state_path);
            assert!(loaded.is_ok());
            let loaded = match loaded {
                Ok(value) => value,
                Err(_) => return,
            };
            let entry = loaded.get("llama.cpp");
            assert!(entry.is_some());
            let entry = match entry {
                Some(value) => value,
                None => return,
            };
            assert!(entry.pinned_version);
            assert_eq!(entry.rollback_history.len(), 1);
            assert_eq!(entry.benchmark_history.len(), 1);
            assert_eq!(entry.benchmark_history[0].latency_ms, 122);

            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn llama_backend_detection_reports_cuda_when_cuda_marker_exists() {
            let root = unique_test_root("cuda");
            assert!(fs::create_dir_all(&root).is_ok());
            let binary = root.join(if cfg!(windows) {
                "llama-server.exe"
            } else {
                "llama-server"
            });
            assert!(fs::write(&binary, "").is_ok());
            assert!(fs::write(root.join("ggml-cuda.dll"), "").is_ok());

            let backend = resolve_llama_backend(binary.to_string_lossy().as_ref());
            assert_eq!(backend, RuntimeBackend::Cuda);

            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn llama_backend_detection_reports_hybrid_when_multiple_accelerators_exist() {
            let root = unique_test_root("hybrid");
            assert!(fs::create_dir_all(&root).is_ok());
            let binary = root.join(if cfg!(windows) {
                "llama-server.exe"
            } else {
                "llama-server"
            });
            assert!(fs::write(&binary, "").is_ok());
            assert!(fs::write(root.join("ggml-cuda.dll"), "").is_ok());
            assert!(fs::write(root.join("ggml-vulkan.dll"), "").is_ok());

            let backend = resolve_llama_backend(binary.to_string_lossy().as_ref());
            assert_eq!(backend, RuntimeBackend::Hybrid);

            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn llama_backend_detection_supports_bin_layout() {
            let root = unique_test_root("bin_layout");
            let bin_dir = root.join("bin");
            assert!(fs::create_dir_all(&bin_dir).is_ok());
            let binary = bin_dir.join(if cfg!(windows) {
                "llama-server.exe"
            } else {
                "llama-server"
            });
            assert!(fs::write(&binary, "").is_ok());
            assert!(fs::write(root.join("ggml-hip.dll"), "").is_ok());

            let backend = resolve_llama_backend(binary.to_string_lossy().as_ref());
            assert_eq!(backend, RuntimeBackend::Hip);

            let _ = fs::remove_dir_all(root);
        }
    }
}

pub mod process {
    use forge_security::broker::resolve_secret_env_reference;
    use forge_security::command_guard::{
        validate_secret_free_command_line, validate_secret_free_environment,
    };
    use std::collections::HashMap;
    use std::error::Error;
    use std::fmt;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use urm::topology::{NumaPlacementPolicy, NumaPolicyMode};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RuntimeProcessValidationError {
        message: String,
    }

    impl RuntimeProcessValidationError {
        fn new(message: impl Into<String>) -> Self {
            Self {
                message: message.into(),
            }
        }
    }

    impl fmt::Display for RuntimeProcessValidationError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.message)
        }
    }

    impl Error for RuntimeProcessValidationError {}

    impl From<RuntimeProcessValidationError> for String {
        fn from(value: RuntimeProcessValidationError) -> Self {
            value.to_string()
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RuntimeLaunchRequest {
        pub program: String,
        pub args: Vec<String>,
        pub working_dir: Option<PathBuf>,
        pub env: Vec<(String, String)>,
        pub health_probe: Option<RuntimeHealthProbe>,
        pub placement_hints: Option<RuntimePlacementHints>,
    }

    impl RuntimeLaunchRequest {
        pub fn new(program: impl Into<String>) -> Self {
            Self {
                program: program.into(),
                args: Vec::new(),
                working_dir: None,
                env: Vec::new(),
                health_probe: None,
                placement_hints: None,
            }
        }

        pub fn validate(&self) -> Result<(), RuntimeProcessValidationError> {
            if self.program.trim().is_empty() {
                return Err(RuntimeProcessValidationError::new(
                    "program cannot be empty",
                ));
            }
            validate_secret_free_command_line(&self.program, &self.args)
                .map_err(|error| RuntimeProcessValidationError::new(error.to_string()))?;
            validate_secret_free_environment(&self.env)
                .map_err(|error| RuntimeProcessValidationError::new(error.to_string()))?;
            if let Some(hints) = &self.placement_hints {
                hints.validate()?;
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RuntimePlacementHints {
        pub preferred_numa_node_os_index: Option<u32>,
        pub preferred_socket_os_index: Option<u32>,
        pub preferred_processing_unit_os_index: Option<u32>,
        pub numa_policy: Option<NumaPlacementPolicy>,
    }

    impl RuntimePlacementHints {
        pub fn validate(&self) -> Result<(), RuntimeProcessValidationError> {
            let Some(policy) = self.numa_policy else {
                return Ok(());
            };

            match policy.mode {
                NumaPolicyMode::Disabled => {
                    if policy.numa_node_os_index.is_some() || policy.cpu_os_index.is_some() {
                        return Err(RuntimeProcessValidationError::new(
                            "disabled NUMA policy must not include node/cpu constraints",
                        ));
                    }
                }
                NumaPolicyMode::Prefer | NumaPolicyMode::Bind => {
                    let policy_node = match policy.numa_node_os_index {
                        Some(value) => value,
                        None => {
                            return Err(RuntimeProcessValidationError::new(
                                "NUMA policy in prefer/bind mode requires numa_node_os_index",
                            ));
                        }
                    };
                    if let Some(preferred_node) = self.preferred_numa_node_os_index
                        && preferred_node != policy_node
                    {
                        return Err(RuntimeProcessValidationError::new(format!(
                            "preferred NUMA node ({preferred_node}) does not match policy node ({policy_node})"
                        )));
                    }

                    if let (Some(policy_cpu), Some(preferred_cpu)) =
                        (policy.cpu_os_index, self.preferred_processing_unit_os_index)
                        && preferred_cpu != policy_cpu
                    {
                        return Err(RuntimeProcessValidationError::new(format!(
                            "preferred processing unit ({preferred_cpu}) does not match policy cpu ({policy_cpu})"
                        )));
                    }
                }
            }

            Ok(())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum RuntimeHealthProbe {
        Tcp { host: String, port: u16 },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RuntimeProbeStatus {
        pub healthy: bool,
        pub detail: String,
        pub checked_at: SystemTime,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct LlamaCppLaunchProfile {
        pub binary_path: PathBuf,
        pub model_path: PathBuf,
        pub host: String,
        pub port: u16,
        pub context_size: u32,
        pub threads: u16,
        pub gpu_layers: u16,
        pub batch_size: u32,
        pub embedding_mode: bool,
        pub extra_args: Vec<String>,
        pub placement_hints: Option<RuntimePlacementHints>,
    }

    impl LlamaCppLaunchProfile {
        pub fn new(binary_path: impl Into<PathBuf>, model_path: impl Into<PathBuf>) -> Self {
            Self {
                binary_path: binary_path.into(),
                model_path: model_path.into(),
                host: "127.0.0.1".to_string(),
                port: 8080,
                context_size: 8192,
                threads: 8,
                gpu_layers: 0,
                batch_size: 512,
                embedding_mode: false,
                extra_args: Vec::new(),
                placement_hints: None,
            }
        }

        pub fn validate(&self) -> Result<(), RuntimeProcessValidationError> {
            if self.host.trim().is_empty() {
                return Err(RuntimeProcessValidationError::new("host cannot be empty"));
            }
            if self.threads == 0 {
                return Err(RuntimeProcessValidationError::new(
                    "threads must be greater than zero",
                ));
            }
            if self.context_size == 0 {
                return Err(RuntimeProcessValidationError::new(
                    "context_size must be greater than zero",
                ));
            }
            if self.batch_size == 0 {
                return Err(RuntimeProcessValidationError::new(
                    "batch_size must be greater than zero",
                ));
            }
            if !self.binary_path.is_file() {
                return Err(RuntimeProcessValidationError::new(format!(
                    "binary not found: {}",
                    self.binary_path.to_string_lossy()
                )));
            }
            if !self.model_path.is_file() {
                return Err(RuntimeProcessValidationError::new(format!(
                    "model not found: {}",
                    self.model_path.to_string_lossy()
                )));
            }
            Ok(())
        }

        pub fn to_launch_request(&self) -> Result<RuntimeLaunchRequest, String> {
            self.validate()?;

            let mut args = vec![
                "--model".to_string(),
                self.model_path.to_string_lossy().into_owned(),
                "--host".to_string(),
                self.host.clone(),
                "--port".to_string(),
                self.port.to_string(),
                "--ctx-size".to_string(),
                self.context_size.to_string(),
                "--threads".to_string(),
                self.threads.to_string(),
                "--batch-size".to_string(),
                self.batch_size.to_string(),
            ];
            if self.gpu_layers > 0 {
                args.push("--n-gpu-layers".to_string());
                args.push(self.gpu_layers.to_string());
            }
            if self.embedding_mode {
                args.push("--embedding".to_string());
            }
            args.extend(self.extra_args.iter().cloned());

            let request = RuntimeLaunchRequest {
                program: self.binary_path.to_string_lossy().into_owned(),
                args,
                working_dir: self.binary_path.parent().map(|path| path.to_path_buf()),
                env: Vec::new(),
                health_probe: Some(RuntimeHealthProbe::Tcp {
                    host: self.host.clone(),
                    port: self.port,
                }),
                placement_hints: self.placement_hints.clone(),
            };
            request.validate()?;
            Ok(request)
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct LlamaCppCompletionRequest {
        pub host: String,
        pub port: u16,
        pub prompt: String,
        pub n_predict: u32,
    }

    impl LlamaCppCompletionRequest {
        pub fn validate(&self) -> Result<(), RuntimeProcessValidationError> {
            if self.host.trim().is_empty() {
                return Err(RuntimeProcessValidationError::new("host cannot be empty"));
            }
            if self.port == 0 {
                return Err(RuntimeProcessValidationError::new(
                    "port must be greater than zero",
                ));
            }
            if self.prompt.trim().is_empty() {
                return Err(RuntimeProcessValidationError::new("prompt cannot be empty"));
            }
            if self.n_predict == 0 {
                return Err(RuntimeProcessValidationError::new(
                    "n_predict must be greater than zero",
                ));
            }
            Ok(())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct LlamaCppCompletionResult {
        pub endpoint: String,
        pub text: String,
        pub raw_json: String,
        pub latency_ms: u128,
    }

    pub fn run_llama_cpp_completion(
        request: &LlamaCppCompletionRequest,
    ) -> Result<LlamaCppCompletionResult, String> {
        run_llama_cpp_completion_with_timeout(request, Duration::from_secs(30))
    }

    fn run_llama_cpp_completion_with_timeout(
        request: &LlamaCppCompletionRequest,
        timeout: Duration,
    ) -> Result<LlamaCppCompletionResult, String> {
        request.validate()?;
        let endpoint = format!("{}:{}", request.host.trim(), request.port);
        let start = Instant::now();

        let socket_address = match endpoint.to_socket_addrs() {
            Ok(mut addresses) => match addresses.next() {
                Some(address) => address,
                None => return Err(format!("unable to resolve runtime endpoint {endpoint}")),
            },
            Err(error) => {
                return Err(format!(
                    "failed to resolve runtime endpoint {endpoint}: {error}"
                ));
            }
        };

        let mut stream = match TcpStream::connect_timeout(&socket_address, timeout) {
            Ok(stream) => stream,
            Err(error) => {
                return Err(format!(
                    "failed to connect to runtime endpoint {endpoint}: {error}"
                ));
            }
        };
        if let Err(error) = stream.set_read_timeout(Some(timeout)) {
            return Err(format!(
                "failed to set read timeout for {endpoint}: {error}"
            ));
        }
        if let Err(error) = stream.set_write_timeout(Some(timeout)) {
            return Err(format!(
                "failed to set write timeout for {endpoint}: {error}"
            ));
        }

        let body_json = serde_json::json!({
            "prompt": request.prompt,
            "n_predict": request.n_predict,
            "stream": false
        })
        .to_string();
        let request_payload = format!(
            "POST /completion HTTP/1.1\r\nHost: {endpoint}\r\nContent-Type: application/json\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
            body_json.len(),
            body_json
        );
        if let Err(error) = stream.write_all(request_payload.as_bytes()) {
            return Err(format!(
                "failed to send generation request to {endpoint}: {error}"
            ));
        }
        if let Err(error) = stream.flush() {
            return Err(format!(
                "failed to flush generation request to {endpoint}: {error}"
            ));
        }

        let mut response_bytes = Vec::new();
        if let Err(error) = stream.read_to_end(&mut response_bytes) {
            return Err(format!(
                "failed to read generation response from {endpoint}: {error}"
            ));
        }
        let response_text = String::from_utf8_lossy(&response_bytes).into_owned();
        let (status_line, headers, body) = parse_http_response(&response_text)?;
        if !status_line.starts_with("HTTP/1.1 200") && !status_line.starts_with("HTTP/1.0 200") {
            return Err(format!(
                "generation request failed at {endpoint}: {status_line} | body: {}",
                clip_for_error(body, 240)
            ));
        }

        let decoded_body = if headers
            .iter()
            .any(|(key, value)| key == "transfer-encoding" && value.contains("chunked"))
        {
            decode_chunked_body(body)?
        } else {
            body.to_string()
        };

        let parsed: serde_json::Value = match serde_json::from_str(&decoded_body) {
            Ok(value) => value,
            Err(error) => {
                return Err(format!(
                    "invalid json response from {endpoint}: {error} | body: {}",
                    clip_for_error(&decoded_body, 240)
                ));
            }
        };
        let text = extract_generation_text(&parsed).ok_or_else(|| {
            format!(
                "generation response missing supported text fields at {endpoint}: {}",
                clip_for_error(&decoded_body, 240)
            )
        })?;

        Ok(LlamaCppCompletionResult {
            endpoint,
            text,
            raw_json: decoded_body,
            latency_ms: start.elapsed().as_millis(),
        })
    }

    type ParsedHttpResponse<'a> = (String, Vec<(String, String)>, &'a str);

    fn parse_http_response(response: &str) -> Result<ParsedHttpResponse<'_>, String> {
        let separator = "\r\n\r\n";
        let split_index = response
            .find(separator)
            .ok_or_else(|| "invalid http response: missing header/body separator".to_string())?;
        let (header_block, body) = response.split_at(split_index);
        let body = &body[separator.len()..];

        let mut header_lines = header_block.lines();
        let status_line = header_lines
            .next()
            .ok_or_else(|| "invalid http response: missing status line".to_string())?
            .to_string();
        let mut headers = Vec::new();
        for line in header_lines {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            headers.push((
                name.trim().to_lowercase(),
                value.trim().to_ascii_lowercase(),
            ));
        }
        Ok((status_line, headers, body))
    }

    fn decode_chunked_body(body: &str) -> Result<String, String> {
        let bytes = body.as_bytes();
        let mut cursor = 0usize;
        let mut decoded = Vec::new();

        while cursor < bytes.len() {
            let line_end = find_crlf(bytes, cursor).ok_or_else(|| {
                "invalid chunked response: missing chunk size terminator".to_string()
            })?;
            let size_line = String::from_utf8_lossy(&bytes[cursor..line_end]);
            let size_token = size_line.split(';').next().unwrap_or_default().trim();
            let size = match usize::from_str_radix(size_token, 16) {
                Ok(value) => value,
                Err(_) => return Err("invalid chunked response: invalid chunk size".to_string()),
            };
            cursor = line_end.saturating_add(2);
            if size == 0 {
                break;
            }
            let chunk_end = cursor.saturating_add(size);
            if chunk_end > bytes.len() {
                return Err("invalid chunked response: truncated chunk payload".to_string());
            }
            decoded.extend_from_slice(&bytes[cursor..chunk_end]);
            cursor = chunk_end;
            if cursor.saturating_add(2) > bytes.len() || &bytes[cursor..cursor + 2] != b"\r\n" {
                return Err("invalid chunked response: missing chunk terminator".to_string());
            }
            cursor = cursor.saturating_add(2);
        }

        Ok(String::from_utf8_lossy(&decoded).into_owned())
    }

    fn find_crlf(bytes: &[u8], start: usize) -> Option<usize> {
        let mut index = start;
        while index.saturating_add(1) < bytes.len() {
            if bytes[index] == b'\r' && bytes[index + 1] == b'\n' {
                return Some(index);
            }
            index = index.saturating_add(1);
        }
        None
    }

    fn extract_generation_text(parsed: &serde_json::Value) -> Option<String> {
        if let Some(text) = parsed.get("content").and_then(serde_json::Value::as_str) {
            return Some(text.to_string());
        }
        if let Some(text) = parsed.get("response").and_then(serde_json::Value::as_str) {
            return Some(text.to_string());
        }
        if let Some(text) = parsed
            .pointer("/choices/0/text")
            .and_then(serde_json::Value::as_str)
        {
            return Some(text.to_string());
        }
        if let Some(text) = parsed
            .pointer("/choices/0/message/content")
            .and_then(serde_json::Value::as_str)
        {
            return Some(text.to_string());
        }
        None
    }

    fn clip_for_error(input: &str, max_chars: usize) -> String {
        if input.chars().count() <= max_chars {
            return input.to_string();
        }
        let clipped: String = input.chars().take(max_chars).collect();
        format!("{clipped}...")
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum RuntimeProcessState {
        Stopped,
        Running,
        Exited(i32),
        LaunchFailed(String),
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RuntimeProcessStatus {
        pub runtime_id: String,
        pub state: RuntimeProcessState,
        pub pid: Option<u32>,
        pub started_at: Option<SystemTime>,
        pub probe_status: Option<RuntimeProbeStatus>,
        pub checked_at: SystemTime,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum RuntimeSafetySignal {
        LaunchFailed { runtime_id: String, reason: String },
        ProbeUnhealthy { runtime_id: String, detail: String },
        ExitedNonZero { runtime_id: String, exit_code: i32 },
    }

    impl RuntimeSafetySignal {
        fn marker(&self) -> String {
            match self {
                RuntimeSafetySignal::LaunchFailed { runtime_id, reason } => {
                    format!("launch_failed:{runtime_id}:{reason}")
                }
                RuntimeSafetySignal::ProbeUnhealthy { runtime_id, detail } => {
                    format!("probe_unhealthy:{runtime_id}:{detail}")
                }
                RuntimeSafetySignal::ExitedNonZero {
                    runtime_id,
                    exit_code,
                } => format!("exited_nonzero:{runtime_id}:{exit_code}"),
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum StartResult {
        Started,
        AlreadyRunning,
        LaunchFailed,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum StopResult {
        Stopped,
        NotRunning,
        UnknownRuntime,
    }

    #[derive(Debug, Default)]
    struct ManagedRuntimeProcess {
        child: Option<Child>,
        started_at: Option<SystemTime>,
        last_exit_code: Option<i32>,
        last_error: Option<String>,
        health_probe: Option<RuntimeHealthProbe>,
        last_safety_marker: Option<String>,
        isolated_temp_dir: Option<PathBuf>,
    }

    #[derive(Debug, Default)]
    pub struct RuntimeProcessManager {
        processes: HashMap<String, ManagedRuntimeProcess>,
    }

    impl RuntimeProcessManager {
        pub fn new() -> Self {
            Self::default()
        }

        fn minimal_inherited_environment() -> Vec<(String, String)> {
            Self::build_minimal_inherited_environment(std::env::vars())
        }

        fn build_minimal_inherited_environment<I>(variables: I) -> Vec<(String, String)>
        where
            I: IntoIterator<Item = (String, String)>,
        {
            variables
                .into_iter()
                .filter(|(key, _)| Self::is_minimal_inherited_env_key(key))
                .collect()
        }

        fn is_minimal_inherited_env_key(key: &str) -> bool {
            if cfg!(windows) {
                let normalized = key.to_ascii_uppercase();
                matches!(
                    normalized.as_str(),
                    "PATH" | "SYSTEMROOT" | "WINDIR" | "COMSPEC" | "PATHEXT" | "TEMP" | "TMP"
                )
            } else {
                matches!(
                    key,
                    "PATH"
                        | "HOME"
                        | "USER"
                        | "LOGNAME"
                        | "LANG"
                        | "LC_ALL"
                        | "LC_CTYPE"
                        | "TERM"
                        | "TMPDIR"
                )
            }
        }

        fn build_isolated_temp_dir(
            runtime_id: &str,
            working_dir: Option<&Path>,
        ) -> Result<PathBuf, RuntimeProcessValidationError> {
            let base_dir = match working_dir {
                Some(path) => path.to_path_buf(),
                None => std::env::current_dir().map_err(|error| {
                    RuntimeProcessValidationError::new(format!(
                        "runtime temp isolation failed to resolve current directory: {error}"
                    ))
                })?,
            };
            let canonical_base = fs::canonicalize(&base_dir).map_err(|error| {
                RuntimeProcessValidationError::new(format!(
                    "runtime temp isolation failed to canonicalize base directory {}: {error}",
                    base_dir.display()
                ))
            })?;
            let root = canonical_base.join(".forge").join("runtime_tmp");
            fs::create_dir_all(&root).map_err(|error| {
                RuntimeProcessValidationError::new(format!(
                    "runtime temp isolation failed to create root {}: {error}",
                    root.display()
                ))
            })?;
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let safe_runtime_id = Self::sanitize_runtime_id(runtime_id);
            let isolated = root.join(format!("{safe_runtime_id}_{nonce}"));
            fs::create_dir(&isolated).map_err(|error| {
                RuntimeProcessValidationError::new(format!(
                    "runtime temp isolation failed to create task directory {}: {error}",
                    isolated.display()
                ))
            })?;
            Ok(isolated)
        }

        fn sanitize_runtime_id(runtime_id: &str) -> String {
            let mut sanitized = runtime_id
                .chars()
                .map(|ch| {
                    if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                        ch
                    } else {
                        '_'
                    }
                })
                .collect::<String>();
            if sanitized.trim_matches('_').is_empty() {
                sanitized = "runtime".to_string();
            }
            sanitized
        }

        fn apply_isolated_temp_environment(command: &mut Command, isolated_temp_dir: &Path) {
            let value = isolated_temp_dir.to_string_lossy().to_string();
            command.env("TMPDIR", value.as_str());
            command.env("TMP", value.as_str());
            command.env("TEMP", value.as_str());
        }

        fn cleanup_process_temp_dir(process: &mut ManagedRuntimeProcess) {
            let Some(path) = process.isolated_temp_dir.take() else {
                return;
            };
            let _ = fs::remove_dir_all(path);
        }

        pub fn start(
            &mut self,
            runtime_id: impl Into<String>,
            request: &RuntimeLaunchRequest,
        ) -> StartResult {
            let runtime_id = runtime_id.into();
            let process = self.processes.entry(runtime_id.clone()).or_default();

            if let Err(error) = request.validate() {
                Self::cleanup_process_temp_dir(process);
                process.child = None;
                process.started_at = None;
                process.last_error = Some(format!("invalid launch request: {error}"));
                process.health_probe = request.health_probe.clone();
                return StartResult::LaunchFailed;
            }

            if let Some(child) = process.child.as_mut() {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        process.last_exit_code = status.code();
                        process.child = None;
                        process.started_at = None;
                        Self::cleanup_process_temp_dir(process);
                    }
                    Ok(None) => return StartResult::AlreadyRunning,
                    Err(error) => {
                        process.last_error = Some(error.to_string());
                        process.child = None;
                        process.started_at = None;
                        Self::cleanup_process_temp_dir(process);
                    }
                }
            }
            Self::cleanup_process_temp_dir(process);

            let isolated_temp_dir =
                match Self::build_isolated_temp_dir(&runtime_id, request.working_dir.as_deref()) {
                    Ok(path) => path,
                    Err(error) => {
                        Self::cleanup_process_temp_dir(process);
                        process.child = None;
                        process.started_at = None;
                        process.last_error = Some(error.to_string());
                        process.health_probe = request.health_probe.clone();
                        return StartResult::LaunchFailed;
                    }
                };

            let mut command = Command::new(&request.program);
            command.args(&request.args);
            if let Some(working_dir) = &request.working_dir {
                command.current_dir(working_dir);
            }
            command.env_clear();
            for (key, value) in Self::minimal_inherited_environment() {
                command.env(key, value);
            }
            let mut stdin_secret_env = Vec::new();
            for (key, value) in &request.env {
                let secret_value = match resolve_secret_env_reference(value) {
                    Ok(value) => value,
                    Err(error) => {
                        process.child = None;
                        process.started_at = None;
                        process.last_error = Some(format!(
                            "secret env resolution failed for key {key}: {error}"
                        ));
                        process.health_probe = request.health_probe.clone();
                        return StartResult::LaunchFailed;
                    }
                };
                if let Some(secret_value) = secret_value {
                    stdin_secret_env.push((key.clone(), secret_value));
                } else {
                    command.env(key, value);
                }
            }
            Self::apply_isolated_temp_environment(&mut command, isolated_temp_dir.as_path());
            if stdin_secret_env.is_empty() {
                command.stdin(Stdio::null());
            } else {
                command.stdin(Stdio::piped());
            }
            command.stdout(Stdio::null()).stderr(Stdio::null());

            match command.spawn() {
                Ok(mut child) => {
                    if !stdin_secret_env.is_empty()
                        && let Err(error) =
                            Self::inject_secret_env_via_stdin(&mut child, &stdin_secret_env)
                    {
                        let _ = child.kill();
                        let _ = child.wait();
                        let _ = fs::remove_dir_all(isolated_temp_dir.as_path());
                        Self::cleanup_process_temp_dir(process);
                        process.child = None;
                        process.started_at = None;
                        process.last_error = Some(error.to_string());
                        process.health_probe = request.health_probe.clone();
                        return StartResult::LaunchFailed;
                    }
                    process.child = Some(child);
                    process.started_at = Some(SystemTime::now());
                    process.last_exit_code = None;
                    process.last_error = None;
                    process.health_probe = request.health_probe.clone();
                    process.isolated_temp_dir = Some(isolated_temp_dir);
                    StartResult::Started
                }
                Err(error) => {
                    let _ = fs::remove_dir_all(isolated_temp_dir.as_path());
                    Self::cleanup_process_temp_dir(process);
                    process.child = None;
                    process.started_at = None;
                    process.last_error = Some(error.to_string());
                    process.health_probe = request.health_probe.clone();
                    StartResult::LaunchFailed
                }
            }
        }

        fn inject_secret_env_via_stdin(
            child: &mut Child,
            secret_env: &[(String, String)],
        ) -> Result<(), RuntimeProcessValidationError> {
            let mut stdin = child.stdin.take().ok_or_else(|| {
                RuntimeProcessValidationError::new(
                    "runtime secret injection failed: child stdin is unavailable",
                )
            })?;
            let mut payload = Self::render_secret_stdin_payload(secret_env)
                .map_err(RuntimeProcessValidationError::new)?;
            if let Err(error) = stdin.write_all(payload.as_slice()) {
                Self::clear_sensitive_bytes(&mut payload);
                return Err(RuntimeProcessValidationError::new(format!(
                    "runtime secret injection failed while writing stdin payload: {error}"
                )));
            }
            if let Err(error) = stdin.flush() {
                Self::clear_sensitive_bytes(&mut payload);
                return Err(RuntimeProcessValidationError::new(format!(
                    "runtime secret injection failed while flushing stdin payload: {error}"
                )));
            }
            Self::clear_sensitive_bytes(&mut payload);
            Ok(())
        }

        fn render_secret_stdin_payload(secret_env: &[(String, String)]) -> Result<Vec<u8>, String> {
            let entries = secret_env
                .iter()
                .map(|(key, value)| serde_json::json!({ "key": key, "value": value }))
                .collect::<Vec<_>>();
            let mut payload = serde_json::to_vec(&serde_json::json!({
                "forge_secret_env": entries,
                "delivery": "stdin-once"
            }))
            .map_err(|error| format!("runtime secret payload serialization failed: {error}"))?;
            payload.push(b'\n');
            Ok(payload)
        }

        fn clear_sensitive_bytes(bytes: &mut Vec<u8>) {
            bytes.fill(0);
            bytes.clear();
        }

        pub fn stop(&mut self, runtime_id: &str) -> StopResult {
            let Some(process) = self.processes.get_mut(runtime_id) else {
                return StopResult::UnknownRuntime;
            };
            let Some(mut child) = process.child.take() else {
                return StopResult::NotRunning;
            };

            if let Err(error) = child.kill() {
                process.last_error = Some(error.to_string());
            }

            match child.wait() {
                Ok(status) => {
                    process.last_exit_code = status.code();
                }
                Err(error) => {
                    process.last_error = Some(error.to_string());
                }
            }
            process.started_at = None;
            Self::cleanup_process_temp_dir(process);
            StopResult::Stopped
        }

        pub fn status(&mut self, runtime_id: &str) -> Option<RuntimeProcessStatus> {
            let process = self.processes.get_mut(runtime_id)?;

            if let Some(child) = process.child.as_mut() {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        process.last_exit_code = status.code();
                        process.child = None;
                        process.started_at = None;
                        Self::cleanup_process_temp_dir(process);
                    }
                    Ok(None) => {}
                    Err(error) => {
                        process.last_error = Some(error.to_string());
                        process.child = None;
                        process.started_at = None;
                        Self::cleanup_process_temp_dir(process);
                    }
                }
            }

            let pid = process.child.as_ref().map(std::process::Child::id);
            let probe_status = if process.child.is_some() {
                process.health_probe.as_ref().map(Self::evaluate_probe)
            } else {
                None
            };
            let state = if process.child.is_some() {
                RuntimeProcessState::Running
            } else if let Some(error) = &process.last_error {
                RuntimeProcessState::LaunchFailed(error.clone())
            } else if let Some(code) = process.last_exit_code {
                RuntimeProcessState::Exited(code)
            } else {
                RuntimeProcessState::Stopped
            };

            Some(RuntimeProcessStatus {
                runtime_id: runtime_id.to_string(),
                state,
                pid,
                started_at: process.started_at,
                probe_status,
                checked_at: SystemTime::now(),
            })
        }

        pub fn clear(&mut self, runtime_id: &str) -> bool {
            if let Some(mut process) = self.processes.remove(runtime_id) {
                if let Some(mut child) = process.child.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                Self::cleanup_process_temp_dir(&mut process);
                return true;
            }
            false
        }

        pub fn consume_safety_signal(&mut self, runtime_id: &str) -> Option<RuntimeSafetySignal> {
            let status = self.status(runtime_id)?;
            let signal = Self::build_safety_signal(&status);
            let process = self.processes.get_mut(runtime_id)?;
            match signal {
                Some(signal) => {
                    let marker = signal.marker();
                    if process.last_safety_marker.as_deref() == Some(marker.as_str()) {
                        None
                    } else {
                        process.last_safety_marker = Some(marker);
                        Some(signal)
                    }
                }
                None => {
                    process.last_safety_marker = None;
                    None
                }
            }
        }

        fn evaluate_probe(probe: &RuntimeHealthProbe) -> RuntimeProbeStatus {
            match probe {
                RuntimeHealthProbe::Tcp { host, port } => {
                    let endpoint = format!("{host}:{port}");
                    let address = match endpoint.to_socket_addrs() {
                        Ok(mut addresses) => addresses.next(),
                        Err(_) => None,
                    };
                    match address {
                        Some(socket_address) => {
                            match TcpStream::connect_timeout(
                                &socket_address,
                                Duration::from_millis(350),
                            ) {
                                Ok(_) => RuntimeProbeStatus {
                                    healthy: true,
                                    detail: format!("tcp reachable at {host}:{port}"),
                                    checked_at: SystemTime::now(),
                                },
                                Err(error) => RuntimeProbeStatus {
                                    healthy: false,
                                    detail: format!("tcp probe failed at {host}:{port}: {error}"),
                                    checked_at: SystemTime::now(),
                                },
                            }
                        }
                        None => RuntimeProbeStatus {
                            healthy: false,
                            detail: format!("unable to resolve tcp probe target {host}:{port}"),
                            checked_at: SystemTime::now(),
                        },
                    }
                }
            }
        }

        fn build_safety_signal(status: &RuntimeProcessStatus) -> Option<RuntimeSafetySignal> {
            match &status.state {
                RuntimeProcessState::LaunchFailed(reason) => {
                    Some(RuntimeSafetySignal::LaunchFailed {
                        runtime_id: status.runtime_id.clone(),
                        reason: reason.clone(),
                    })
                }
                RuntimeProcessState::Exited(code) if *code != 0 => {
                    Some(RuntimeSafetySignal::ExitedNonZero {
                        runtime_id: status.runtime_id.clone(),
                        exit_code: *code,
                    })
                }
                RuntimeProcessState::Running => {
                    if let Some(probe) = &status.probe_status
                        && !probe.healthy
                    {
                        return Some(RuntimeSafetySignal::ProbeUnhealthy {
                            runtime_id: status.runtime_id.clone(),
                            detail: probe.detail.clone(),
                        });
                    }
                    None
                }
                RuntimeProcessState::Stopped | RuntimeProcessState::Exited(_) => None,
            }
        }
    }

    impl Drop for RuntimeProcessManager {
        fn drop(&mut self) {
            let runtime_ids: Vec<String> = self.processes.keys().cloned().collect();
            for runtime_id in runtime_ids {
                let _ = self.clear(&runtime_id);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{
            LlamaCppCompletionRequest, LlamaCppLaunchProfile, RuntimeHealthProbe,
            RuntimeLaunchRequest, RuntimePlacementHints, RuntimeProcessManager,
            RuntimeProcessState, RuntimeSafetySignal, StartResult, StopResult,
            run_llama_cpp_completion_with_timeout,
        };
        use forge_security::broker::{render_secret_env_reference, with_global_secret_broker};
        use std::collections::HashMap;
        use std::fs;
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;
        use std::time::Duration;
        use std::time::{SystemTime, UNIX_EPOCH};
        use urm::topology::{NumaPlacementPolicy, NumaPolicyMode};

        fn unique_test_root(name: &str) -> std::path::PathBuf {
            let mut root = std::env::temp_dir();
            let nanos = match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(duration) => duration.as_nanos(),
                Err(_) => 0,
            };
            root.push(format!("forge_runtime_profile_{name}_{nanos}"));
            root
        }

        fn long_running_request() -> RuntimeLaunchRequest {
            if cfg!(windows) {
                RuntimeLaunchRequest {
                    program: "powershell".to_string(),
                    args: vec![
                        "-NoProfile".to_string(),
                        "-Command".to_string(),
                        "Start-Sleep -Seconds 10".to_string(),
                    ],
                    working_dir: None,
                    env: Vec::new(),
                    health_probe: None,
                    placement_hints: None,
                }
            } else {
                RuntimeLaunchRequest {
                    program: "sh".to_string(),
                    args: vec!["-c".to_string(), "sleep 10".to_string()],
                    working_dir: None,
                    env: Vec::new(),
                    health_probe: None,
                    placement_hints: None,
                }
            }
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

        fn stdin_secret_probe_request() -> RuntimeLaunchRequest {
            if cfg!(windows) {
                RuntimeLaunchRequest {
                    program: "powershell".to_string(),
                    args: vec![
                        "-NoProfile".to_string(),
                        "-Command".to_string(),
                        "if ($env:FORGE_RUNTIME_STDIN_ONLY_TOKEN_7A6) { exit 7 }; $payload = [Console]::In.ReadToEnd(); if ($payload -notmatch 'FORGE_RUNTIME_STDIN_ONLY_TOKEN_7A6') { exit 8 }; if ($payload -notmatch 'sk-stdin-secret') { exit 9 }; exit 0".to_string(),
                    ],
                    working_dir: None,
                    env: Vec::new(),
                    health_probe: None,
                    placement_hints: None,
                }
            } else {
                RuntimeLaunchRequest {
                    program: "sh".to_string(),
                    args: vec![
                        "-c".to_string(),
                        "if [ -n \"$FORGE_RUNTIME_STDIN_ONLY_TOKEN_7A6\" ]; then exit 7; fi; payload=$(cat); printf '%s' \"$payload\" | grep -q 'FORGE_RUNTIME_STDIN_ONLY_TOKEN_7A6' || exit 8; printf '%s' \"$payload\" | grep -q 'sk-stdin-secret' || exit 9; exit 0".to_string(),
                    ],
                    working_dir: None,
                    env: Vec::new(),
                    health_probe: None,
                    placement_hints: None,
                }
            }
        }

        fn temp_probe_request(
            output_path: &std::path::Path,
            working_dir: &std::path::Path,
        ) -> RuntimeLaunchRequest {
            if cfg!(windows) {
                let escaped_output = output_path.to_string_lossy().replace('\'', "''");
                RuntimeLaunchRequest {
                    program: "powershell".to_string(),
                    args: vec![
                        "-NoProfile".to_string(),
                        "-Command".to_string(),
                        format!(
                            "$temp = if ($env:TEMP) {{ $env:TEMP }} elseif ($env:TMP) {{ $env:TMP }} else {{ '' }}; Set-Content -LiteralPath '{escaped_output}' -Value $temp; exit 0"
                        ),
                    ],
                    working_dir: Some(working_dir.to_path_buf()),
                    env: Vec::new(),
                    health_probe: None,
                    placement_hints: None,
                }
            } else {
                let escaped_output = output_path
                    .to_string_lossy()
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"");
                RuntimeLaunchRequest {
                    program: "sh".to_string(),
                    args: vec![
                        "-c".to_string(),
                        format!("printf '%s' \"${{TMPDIR:-$TMP}}\" > \"{escaped_output}\"; exit 0"),
                    ],
                    working_dir: Some(working_dir.to_path_buf()),
                    env: Vec::new(),
                    health_probe: None,
                    placement_hints: None,
                }
            }
        }

        fn wait_for_exit_code(
            manager: &mut RuntimeProcessManager,
            runtime_id: &str,
        ) -> Option<i32> {
            for _ in 0..40 {
                if let Some(status) = manager.status(runtime_id)
                    && let RuntimeProcessState::Exited(code) = status.state
                {
                    return Some(code);
                }
                thread::sleep(Duration::from_millis(25));
            }
            None
        }

        #[test]
        fn launch_failure_is_reported() {
            let mut manager = RuntimeProcessManager::new();
            let request = RuntimeLaunchRequest::new("forge-nonexistent-runtime-binary");

            let result = manager.start("llama.cpp", &request);
            assert_eq!(result, StartResult::LaunchFailed);

            let status = manager.status("llama.cpp");
            assert!(matches!(
                status.map(|value| value.state),
                Some(RuntimeProcessState::LaunchFailed(_))
            ));

            let signal = manager.consume_safety_signal("llama.cpp");
            assert!(matches!(
                signal,
                Some(RuntimeSafetySignal::LaunchFailed { .. })
            ));
        }

        #[test]
        fn start_and_stop_runtime_process() {
            let mut manager = RuntimeProcessManager::new();
            let request = long_running_request();

            let result = manager.start("llama.cpp", &request);
            assert_eq!(result, StartResult::Started);

            let status = manager.status("llama.cpp");
            assert!(matches!(
                status.map(|value| value.state),
                Some(RuntimeProcessState::Running) | Some(RuntimeProcessState::Exited(_))
            ));

            let stop = manager.stop("llama.cpp");
            assert!(matches!(stop, StopResult::Stopped | StopResult::NotRunning));
        }

        #[test]
        fn runtime_launch_uses_isolated_temp_directory_and_cleans_it_up() {
            let root = unique_test_root("isolated_temp");
            assert!(fs::create_dir_all(&root).is_ok());
            let output_path = root.join("observed_temp.txt");
            let request = temp_probe_request(output_path.as_path(), root.as_path());

            let mut manager = RuntimeProcessManager::new();
            let started = manager.start("temp-probe", &request);
            assert_eq!(started, StartResult::Started);

            let exit_code = wait_for_exit_code(&mut manager, "temp-probe");
            assert_eq!(exit_code, Some(0));

            let contents = fs::read_to_string(output_path.as_path());
            assert!(contents.is_ok());
            let observed = match contents {
                Ok(value) => value.trim().to_string(),
                Err(_) => String::new(),
            };
            assert!(!observed.is_empty());

            let isolated_temp_path = std::path::PathBuf::from(observed);
            let observed_text = isolated_temp_path
                .to_string_lossy()
                .replace('\\', "/")
                .to_ascii_lowercase();
            assert!(
                observed_text.contains("/.forge/runtime_tmp/"),
                "observed temp path {observed_text} did not include /.forge/runtime_tmp/"
            );

            let _ = manager.status("temp-probe");
            assert!(!isolated_temp_path.exists());

            let _ = fs::remove_file(output_path.as_path());
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn tcp_probe_reports_reachable_endpoint() {
            let listener = TcpListener::bind("127.0.0.1:0");
            assert!(listener.is_ok());
            let listener = match listener {
                Ok(value) => value,
                Err(_) => return,
            };
            let local_addr = listener.local_addr();
            assert!(local_addr.is_ok());
            let local_addr = match local_addr {
                Ok(value) => value,
                Err(_) => return,
            };
            let mut request = long_running_request();
            request.health_probe = Some(RuntimeHealthProbe::Tcp {
                host: "127.0.0.1".to_string(),
                port: local_addr.port(),
            });

            let mut manager = RuntimeProcessManager::new();
            let started = manager.start("llama.cpp", &request);
            assert_eq!(started, StartResult::Started);

            let status = manager.status("llama.cpp");
            assert!(matches!(
                status.as_ref().and_then(|value| value.probe_status.as_ref()),
                Some(probe) if probe.healthy
            ));

            let _ = manager.stop("llama.cpp");
        }

        #[test]
        fn unhealthy_probe_emits_safety_signal_once_until_state_changes() {
            let mut request = long_running_request();
            request.health_probe = Some(RuntimeHealthProbe::Tcp {
                host: "127.0.0.1".to_string(),
                port: 6553,
            });

            let mut manager = RuntimeProcessManager::new();
            let started = manager.start("llama.cpp", &request);
            assert_eq!(started, StartResult::Started);

            let signal = manager.consume_safety_signal("llama.cpp");
            assert!(matches!(
                signal,
                Some(RuntimeSafetySignal::ProbeUnhealthy { .. })
            ));

            let duplicate = manager.consume_safety_signal("llama.cpp");
            assert!(duplicate.is_none());

            let _ = manager.stop("llama.cpp");
        }

        #[test]
        fn nonzero_exit_emits_safety_signal() {
            let mut manager = RuntimeProcessManager::new();
            let request = nonzero_exit_request();
            let started = manager.start("llama.cpp", &request);
            assert_eq!(started, StartResult::Started);

            let exit_code = wait_for_exit_code(&mut manager, "llama.cpp");
            assert_eq!(exit_code, Some(7));

            let mut signal = None;
            for _ in 0..40 {
                signal = manager.consume_safety_signal("llama.cpp");
                if signal.is_some() {
                    break;
                }
                thread::sleep(Duration::from_millis(25));
            }

            assert!(matches!(
                signal,
                Some(RuntimeSafetySignal::ExitedNonZero { exit_code: 7, .. })
            ));
        }

        fn spawn_mock_llama_server(response: String) -> Option<u16> {
            let listener = match TcpListener::bind("127.0.0.1:0") {
                Ok(value) => value,
                Err(_) => return None,
            };
            let port = match listener.local_addr() {
                Ok(address) => address.port(),
                Err(_) => return None,
            };

            thread::spawn(move || {
                let accepted = listener.accept();
                let (mut stream, _) = match accepted {
                    Ok(value) => value,
                    Err(_) => return,
                };
                let mut request_buffer = [0u8; 2048];
                let _ = stream.read(&mut request_buffer);
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            });

            Some(port)
        }

        #[test]
        fn llama_completion_parses_content_response() {
            let body = r#"{"content":"forge local response"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let port = spawn_mock_llama_server(response);
            assert!(port.is_some());
            let port = match port {
                Some(value) => value,
                None => return,
            };

            let request = LlamaCppCompletionRequest {
                host: "127.0.0.1".to_string(),
                port,
                prompt: "say hi".to_string(),
                n_predict: 32,
            };
            let result = run_llama_cpp_completion_with_timeout(&request, Duration::from_secs(2));
            assert!(result.is_ok());
            let result = match result {
                Ok(value) => value,
                Err(_) => return,
            };
            assert_eq!(result.text, "forge local response");
            assert_eq!(result.endpoint, format!("127.0.0.1:{port}"));
        }

        #[test]
        fn llama_completion_supports_chunked_http_body() {
            let json = r#"{"content":"chunked response ok"}"#;
            let chunk_1 = &json.as_bytes()[0..18];
            let chunk_2 = &json.as_bytes()[18..];
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:X}\r\n{}\r\n{:X}\r\n{}\r\n0\r\n\r\n",
                chunk_1.len(),
                String::from_utf8_lossy(chunk_1),
                chunk_2.len(),
                String::from_utf8_lossy(chunk_2)
            );
            let port = spawn_mock_llama_server(response);
            assert!(port.is_some());
            let port = match port {
                Some(value) => value,
                None => return,
            };

            let request = LlamaCppCompletionRequest {
                host: "127.0.0.1".to_string(),
                port,
                prompt: "say hi".to_string(),
                n_predict: 32,
            };
            let result = run_llama_cpp_completion_with_timeout(&request, Duration::from_secs(2));
            assert!(result.is_ok());
            let result = match result {
                Ok(value) => value,
                Err(_) => return,
            };
            assert_eq!(result.text, "chunked response ok");
        }

        #[test]
        fn llama_profile_builds_launch_request() {
            let root = unique_test_root("llama_profile");
            assert!(fs::create_dir_all(&root).is_ok());
            let binary = root.join(if cfg!(windows) {
                "llama-server.exe"
            } else {
                "llama-server"
            });
            let model = root.join("model.gguf");

            assert!(fs::write(&binary, "").is_ok());
            assert!(fs::write(&model, "").is_ok());

            let mut profile = LlamaCppLaunchProfile::new(&binary, &model);
            profile.host = "127.0.0.1".to_string();
            profile.port = 9090;
            profile.threads = 4;
            profile.gpu_layers = 12;
            profile.embedding_mode = true;

            let request = profile.to_launch_request();
            assert!(request.is_ok());
            let request = match request {
                Ok(value) => value,
                Err(_) => RuntimeLaunchRequest::new("invalid"),
            };
            assert!(request.args.iter().any(|value| value == "--model"));
            assert!(request.args.iter().any(|value| value == "--n-gpu-layers"));
            assert!(matches!(
                request.health_probe,
                Some(RuntimeHealthProbe::Tcp { .. })
            ));

            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn llama_profile_propagates_topology_numa_hints_to_launch_request() {
            let root = unique_test_root("llama_profile_hints");
            assert!(fs::create_dir_all(&root).is_ok());
            let binary = root.join(if cfg!(windows) {
                "llama-server.exe"
            } else {
                "llama-server"
            });
            let model = root.join("model.gguf");

            assert!(fs::write(&binary, "").is_ok());
            assert!(fs::write(&model, "").is_ok());

            let mut profile = LlamaCppLaunchProfile::new(&binary, &model);
            profile.placement_hints = Some(RuntimePlacementHints {
                preferred_numa_node_os_index: Some(1),
                preferred_socket_os_index: Some(1),
                preferred_processing_unit_os_index: Some(3),
                numa_policy: Some(NumaPlacementPolicy::bind_node(1, Some(3))),
            });

            let request = profile.to_launch_request();
            assert!(request.is_ok());
            let request = match request {
                Ok(value) => value,
                Err(_) => RuntimeLaunchRequest::new("invalid"),
            };
            assert_eq!(request.placement_hints, profile.placement_hints);

            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn invalid_numa_policy_is_rejected_before_launch() {
            let mut manager = RuntimeProcessManager::new();
            let mut request = RuntimeLaunchRequest::new("powershell");
            request.placement_hints = Some(RuntimePlacementHints {
                preferred_numa_node_os_index: Some(0),
                preferred_socket_os_index: None,
                preferred_processing_unit_os_index: None,
                numa_policy: Some(NumaPlacementPolicy {
                    mode: NumaPolicyMode::Bind,
                    numa_node_os_index: None,
                    cpu_os_index: None,
                }),
            });

            let result = manager.start("llama.cpp", &request);
            assert_eq!(result, StartResult::LaunchFailed);
            let status = manager.status("llama.cpp");
            assert!(matches!(
                status.map(|value| value.state),
                Some(RuntimeProcessState::LaunchFailed(_))
            ));
            let signal = manager.consume_safety_signal("llama.cpp");
            assert!(matches!(
                signal,
                Some(RuntimeSafetySignal::LaunchFailed { .. })
            ));
        }

        #[test]
        fn launch_request_with_cli_secret_material_is_rejected() {
            let mut manager = RuntimeProcessManager::new();
            let mut request = RuntimeLaunchRequest::new("powershell");
            request.args = vec![
                "-NoProfile".to_string(),
                "-Command".to_string(),
                "--api-key=sk-live-secret-material".to_string(),
            ];

            let result = manager.start("llama.cpp", &request);
            assert_eq!(result, StartResult::LaunchFailed);

            let status = manager.status("llama.cpp");
            assert!(matches!(
                status.map(|value| value.state),
                Some(RuntimeProcessState::LaunchFailed(_))
            ));
        }

        #[test]
        fn launch_request_with_secret_environment_variable_is_rejected() {
            let mut manager = RuntimeProcessManager::new();
            let mut request = RuntimeLaunchRequest::new("powershell");
            request.args = vec![
                "-NoProfile".to_string(),
                "-Command".to_string(),
                "echo ok".to_string(),
            ];
            request.env.push((
                "OPENAI_API_KEY".to_string(),
                "sk-live-secret-material".to_string(),
            ));

            let result = manager.start("llama.cpp", &request);
            assert_eq!(result, StartResult::LaunchFailed);

            let status = manager.status("llama.cpp");
            assert!(matches!(
                status.map(|value| value.state),
                Some(RuntimeProcessState::LaunchFailed(_))
            ));
        }

        #[test]
        fn launch_request_with_secret_handle_reference_is_allowed() {
            let reference = with_global_secret_broker(|broker| {
                let handle = broker.store_secret("OPENAI_API_KEY", "sk-runtime-env-reference")?;
                Ok(render_secret_env_reference(&handle))
            });
            assert!(reference.is_ok());
            let reference = match reference {
                Ok(value) => value,
                Err(_) => return,
            };

            let mut manager = RuntimeProcessManager::new();
            let mut request = long_running_request();
            request.env.push(("OPENAI_API_KEY".to_string(), reference));

            let result = manager.start("llama.cpp", &request);
            assert_eq!(result, StartResult::Started);
            let _ = manager.stop("llama.cpp");
        }

        #[test]
        fn launch_request_with_secret_handle_reference_is_injected_via_stdin_not_env() {
            let reference = with_global_secret_broker(|broker| {
                let handle =
                    broker.store_secret("FORGE_RUNTIME_STDIN_ONLY_TOKEN_7A6", "sk-stdin-secret")?;
                Ok(render_secret_env_reference(&handle))
            });
            assert!(reference.is_ok());
            let reference = match reference {
                Ok(value) => value,
                Err(_) => return,
            };

            let mut manager = RuntimeProcessManager::new();
            let mut request = stdin_secret_probe_request();
            request
                .env
                .push(("FORGE_RUNTIME_STDIN_ONLY_TOKEN_7A6".to_string(), reference));

            let result = manager.start("llama.cpp", &request);
            assert_eq!(result, StartResult::Started);
            assert_eq!(wait_for_exit_code(&mut manager, "llama.cpp"), Some(0));
        }

        #[test]
        fn render_secret_stdin_payload_serializes_expected_json_envelope() {
            let payload = RuntimeProcessManager::render_secret_stdin_payload(&[(
                "OPENAI_API_KEY".to_string(),
                "sk-live-secret".to_string(),
            )]);
            assert!(payload.is_ok());
            let payload = match payload {
                Ok(value) => value,
                Err(_) => return,
            };

            assert_eq!(payload.last(), Some(&b'\n'));
            let payload_text = String::from_utf8(payload);
            assert!(payload_text.is_ok());
            let payload_text = match payload_text {
                Ok(value) => value,
                Err(_) => return,
            };
            assert!(payload_text.contains("\"delivery\":\"stdin-once\""));
            assert!(payload_text.contains("\"key\":\"OPENAI_API_KEY\""));
            assert!(payload_text.contains("\"value\":\"sk-live-secret\""));
        }

        #[test]
        fn launch_request_with_unknown_secret_handle_reference_is_rejected() {
            let mut manager = RuntimeProcessManager::new();
            let mut request = RuntimeLaunchRequest::new("powershell");
            request.args = vec![
                "-NoProfile".to_string(),
                "-Command".to_string(),
                "echo ok".to_string(),
            ];
            request.env.push((
                "OPENAI_API_KEY".to_string(),
                "forge-secret-handle://missing-reference".to_string(),
            ));

            let result = manager.start("llama.cpp", &request);
            assert_eq!(result, StartResult::LaunchFailed);
        }

        #[cfg(windows)]
        #[test]
        fn minimal_inherited_environment_windows_allowlist_is_case_insensitive() {
            let filtered = RuntimeProcessManager::build_minimal_inherited_environment(vec![
                ("Path".to_string(), "C:\\Windows\\System32".to_string()),
                ("systemroot".to_string(), "C:\\Windows".to_string()),
                ("OPENAI_API_KEY".to_string(), "sk-live-secret".to_string()),
                ("FORGE_CUSTOM_ENV".to_string(), "1".to_string()),
            ]);
            let map: HashMap<String, String> = filtered.into_iter().collect();

            assert!(map.contains_key("Path"));
            assert!(map.contains_key("systemroot"));
            assert!(!map.contains_key("OPENAI_API_KEY"));
            assert!(!map.contains_key("FORGE_CUSTOM_ENV"));
        }

        #[cfg(not(windows))]
        #[test]
        fn minimal_inherited_environment_unix_allowlist_excludes_custom_keys() {
            let filtered = RuntimeProcessManager::build_minimal_inherited_environment(vec![
                ("PATH".to_string(), "/usr/bin".to_string()),
                ("HOME".to_string(), "/tmp/test-home".to_string()),
                ("OPENAI_API_KEY".to_string(), "sk-live-secret".to_string()),
                ("FORGE_CUSTOM_ENV".to_string(), "1".to_string()),
            ]);
            let map: HashMap<String, String> = filtered.into_iter().collect();

            assert!(map.contains_key("PATH"));
            assert!(map.contains_key("HOME"));
            assert!(!map.contains_key("OPENAI_API_KEY"));
            assert!(!map.contains_key("FORGE_CUSTOM_ENV"));
        }
    }
}
