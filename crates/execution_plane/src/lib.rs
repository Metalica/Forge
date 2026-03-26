#![forbid(unsafe_code)]

pub mod allocator_build;
pub mod benchmark;
pub mod io_path;
pub mod safety {
    use std::collections::HashMap;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SafetyEscalation {
        None,
        Degraded,
        FallbackRequired,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SafetyStatus {
        pub key: String,
        pub consecutive_failures: u32,
        pub escalation: SafetyEscalation,
        pub last_reason: Option<String>,
    }

    #[derive(Debug)]
    pub struct SessionSafetyMonitor {
        threshold_degraded: u32,
        threshold_fallback: u32,
        failures: HashMap<String, u32>,
        last_reason: HashMap<String, String>,
    }

    impl SessionSafetyMonitor {
        pub fn new(threshold_degraded: u32, threshold_fallback: u32) -> Self {
            let threshold_degraded = threshold_degraded.max(1);
            let threshold_fallback = threshold_fallback.max(threshold_degraded + 1);
            Self {
                threshold_degraded,
                threshold_fallback,
                failures: HashMap::new(),
                last_reason: HashMap::new(),
            }
        }

        pub fn default_runtime() -> Self {
            Self::new(2, 3)
        }

        pub fn record_failure(
            &mut self,
            key: impl Into<String>,
            reason: impl Into<String>,
        ) -> SafetyStatus {
            let key = key.into();
            let reason = reason.into();
            let failures = self
                .failures
                .entry(key.clone())
                .and_modify(|value| *value = value.saturating_add(1))
                .or_insert(1);
            let failure_count = *failures;
            self.last_reason.insert(key.clone(), reason.clone());
            SafetyStatus {
                key,
                consecutive_failures: failure_count,
                escalation: self.escalation_for(failure_count),
                last_reason: Some(reason),
            }
        }

        pub fn record_success(&mut self, key: &str) -> SafetyStatus {
            self.failures.remove(key);
            let reason = self.last_reason.remove(key);
            SafetyStatus {
                key: key.to_string(),
                consecutive_failures: 0,
                escalation: SafetyEscalation::None,
                last_reason: reason,
            }
        }

        pub fn status(&self, key: &str) -> SafetyStatus {
            let failures = *self.failures.get(key).unwrap_or(&0);
            SafetyStatus {
                key: key.to_string(),
                consecutive_failures: failures,
                escalation: self.escalation_for(failures),
                last_reason: self.last_reason.get(key).cloned(),
            }
        }

        fn escalation_for(&self, failures: u32) -> SafetyEscalation {
            if failures >= self.threshold_fallback {
                SafetyEscalation::FallbackRequired
            } else if failures >= self.threshold_degraded {
                SafetyEscalation::Degraded
            } else {
                SafetyEscalation::None
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{SafetyEscalation, SessionSafetyMonitor};

        #[test]
        fn escalation_progresses_with_repeated_failures() {
            let mut monitor = SessionSafetyMonitor::new(2, 4);
            let first = monitor.record_failure("runtime.launch", "launch failed");
            assert_eq!(first.escalation, SafetyEscalation::None);

            let second = monitor.record_failure("runtime.launch", "launch failed");
            assert_eq!(second.escalation, SafetyEscalation::Degraded);

            let third = monitor.record_failure("runtime.launch", "launch failed");
            assert_eq!(third.escalation, SafetyEscalation::Degraded);

            let fourth = monitor.record_failure("runtime.launch", "launch failed");
            assert_eq!(fourth.escalation, SafetyEscalation::FallbackRequired);
        }

        #[test]
        fn success_resets_failure_counter() {
            let mut monitor = SessionSafetyMonitor::default_runtime();
            let _ = monitor.record_failure("runtime.launch", "launch failed");
            let _ = monitor.record_failure("runtime.launch", "launch failed");
            let reset = monitor.record_success("runtime.launch");
            assert_eq!(reset.consecutive_failures, 0);
            assert_eq!(reset.escalation, SafetyEscalation::None);
            let after = monitor.status("runtime.launch");
            assert_eq!(after.consecutive_failures, 0);
        }
    }
}

pub mod numa {
    use urm::topology::{NumaPlacementPolicy, NumaPolicyMode};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HostPlatform {
        Linux,
        Other,
    }

    impl HostPlatform {
        fn current() -> Self {
            if cfg!(target_os = "linux") {
                Self::Linux
            } else {
                Self::Other
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct LaunchCommand {
        pub program: String,
        pub args: Vec<String>,
    }

    impl LaunchCommand {
        pub fn new(program: impl Into<String>, args: Vec<String>) -> Self {
            Self {
                program: program.into(),
                args,
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum NumaPolicyApplication {
        AppliedNumactl,
        SkippedDisabled,
        SkippedNonLinux,
        SkippedNumactlUnavailable,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct NumaLaunchOutcome {
        pub command: LaunchCommand,
        pub application: NumaPolicyApplication,
        pub reason: String,
    }

    pub fn apply_numa_policy(
        command: LaunchCommand,
        policy: NumaPlacementPolicy,
    ) -> NumaLaunchOutcome {
        apply_numa_policy_for_platform(
            command,
            policy,
            HostPlatform::current(),
            numactl_available_on_path(),
        )
    }

    fn apply_numa_policy_for_platform(
        command: LaunchCommand,
        policy: NumaPlacementPolicy,
        platform: HostPlatform,
        numactl_available: bool,
    ) -> NumaLaunchOutcome {
        if matches!(policy.mode, NumaPolicyMode::Disabled) {
            return NumaLaunchOutcome {
                command,
                application: NumaPolicyApplication::SkippedDisabled,
                reason: "NUMA policy disabled".to_string(),
            };
        }

        if !matches!(platform, HostPlatform::Linux) {
            return NumaLaunchOutcome {
                command,
                application: NumaPolicyApplication::SkippedNonLinux,
                reason: "numactl path skipped: host platform is not Linux".to_string(),
            };
        }

        if !numactl_available {
            return NumaLaunchOutcome {
                command,
                application: NumaPolicyApplication::SkippedNumactlUnavailable,
                reason: "numactl not available on PATH; using baseline launch path".to_string(),
            };
        }

        let base_program = command.program;
        let base_args = command.args;
        let mut args = Vec::new();
        if let Some(node) = policy.numa_node_os_index {
            match policy.mode {
                NumaPolicyMode::Bind => {
                    args.push(format!("--cpunodebind={node}"));
                    args.push(format!("--membind={node}"));
                }
                NumaPolicyMode::Prefer => {
                    args.push(format!("--preferred={node}"));
                }
                NumaPolicyMode::Disabled => {}
            }
        }
        if let Some(cpu) = policy.cpu_os_index {
            args.push(format!("--physcpubind={cpu}"));
        }
        args.push("--".to_string());
        args.push(base_program);
        args.extend(base_args);

        NumaLaunchOutcome {
            command: LaunchCommand {
                program: "numactl".to_string(),
                args,
            },
            application: NumaPolicyApplication::AppliedNumactl,
            reason: "numactl launch path applied".to_string(),
        }
    }

    fn numactl_available_on_path() -> bool {
        let path_var = std::env::var_os("PATH");
        let Some(path_var) = path_var else {
            return false;
        };
        for entry in std::env::split_paths(&path_var) {
            let executable = entry.join("numactl");
            if executable.is_file() {
                return true;
            }
            let executable_with_ext = entry.join("numactl.exe");
            if executable_with_ext.is_file() {
                return true;
            }
        }
        false
    }

    #[cfg(test)]
    mod tests {
        use super::{
            HostPlatform, LaunchCommand, NumaPolicyApplication, apply_numa_policy_for_platform,
        };
        use urm::topology::NumaPlacementPolicy;

        #[test]
        fn non_linux_falls_back_to_baseline_launch() {
            let command = LaunchCommand::new(
                "llama-server",
                vec!["--port".to_string(), "8080".to_string()],
            );
            let policy = NumaPlacementPolicy::bind_node(1, Some(2));
            let outcome =
                apply_numa_policy_for_platform(command.clone(), policy, HostPlatform::Other, true);

            assert_eq!(outcome.application, NumaPolicyApplication::SkippedNonLinux);
            assert_eq!(outcome.command, command);
        }

        #[test]
        fn linux_without_numactl_falls_back_to_baseline_launch() {
            let command = LaunchCommand::new(
                "llama-server",
                vec!["--port".to_string(), "8080".to_string()],
            );
            let policy = NumaPlacementPolicy::bind_node(1, Some(2));
            let outcome =
                apply_numa_policy_for_platform(command.clone(), policy, HostPlatform::Linux, false);

            assert_eq!(
                outcome.application,
                NumaPolicyApplication::SkippedNumactlUnavailable
            );
            assert_eq!(outcome.command, command);
            assert!(outcome.reason.contains("baseline launch path"));
        }

        #[test]
        fn linux_with_numactl_wraps_launch_command() {
            let command = LaunchCommand::new(
                "llama-server",
                vec!["--model".to_string(), "model.gguf".to_string()],
            );
            let policy = NumaPlacementPolicy::bind_node(1, Some(2));
            let outcome =
                apply_numa_policy_for_platform(command, policy, HostPlatform::Linux, true);

            assert_eq!(outcome.application, NumaPolicyApplication::AppliedNumactl);
            assert_eq!(outcome.command.program, "numactl");
            assert_eq!(
                outcome.command.args,
                vec![
                    "--cpunodebind=1".to_string(),
                    "--membind=1".to_string(),
                    "--physcpubind=2".to_string(),
                    "--".to_string(),
                    "llama-server".to_string(),
                    "--model".to_string(),
                    "model.gguf".to_string(),
                ]
            );
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn linux_integration_policy_application_path_is_constructed() {
            let command = LaunchCommand::new(
                "llama-server",
                vec!["--ctx-size".to_string(), "8192".to_string()],
            );
            let policy = NumaPlacementPolicy::prefer_node(0, None);
            let outcome =
                apply_numa_policy_for_platform(command, policy, HostPlatform::Linux, true);

            assert_eq!(outcome.application, NumaPolicyApplication::AppliedNumactl);
            assert_eq!(outcome.command.program, "numactl");
            assert!(outcome.command.args.contains(&"--preferred=0".to_string()));
        }

        #[cfg(not(target_os = "linux"))]
        #[test]
        fn non_linux_integration_path_keeps_baseline_request() {
            let command = LaunchCommand::new(
                "llama-server",
                vec!["--ctx-size".to_string(), "8192".to_string()],
            );
            let policy = NumaPlacementPolicy::prefer_node(0, None);
            let outcome =
                apply_numa_policy_for_platform(command.clone(), policy, HostPlatform::Other, true);

            assert_eq!(outcome.application, NumaPolicyApplication::SkippedNonLinux);
            assert_eq!(outcome.command, command);
        }
    }
}

pub mod jobs {
    use serde::{Deserialize, Serialize};
    use std::collections::{HashMap, VecDeque};
    use std::time::SystemTime;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct JobId(u64);

    impl JobId {
        pub fn raw(self) -> u64 {
            self.0
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub enum JobKind {
        CodeBuild,
        LlmInference,
        ImageGeneration,
        VideoGeneration,
        AgentRun,
        SystemTask,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    pub enum JobPriority {
        Background,
        Normal,
        Foreground,
    }

    /// High-level execution state for workload tracking.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub enum JobState {
        Queued,
        Running,
        Completed,
        Failed,
        Cancelled,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct JobQueueStateRecord {
        pub id: u64,
        pub name: String,
        pub kind: JobKind,
        pub priority: JobPriority,
        pub state: JobState,
        pub created_at_unix_ms: Option<u64>,
        pub started_at_unix_ms: Option<u64>,
        pub completed_at_unix_ms: Option<u64>,
        pub failure_reason: Option<String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct JobQueueState {
        pub next_id: u64,
        pub queued_ids: Vec<u64>,
        pub records: Vec<JobQueueStateRecord>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct JobRecord {
        pub id: JobId,
        pub name: String,
        pub kind: JobKind,
        pub priority: JobPriority,
        pub state: JobState,
        pub created_at: SystemTime,
        pub started_at: Option<SystemTime>,
        pub completed_at: Option<SystemTime>,
        pub failure_reason: Option<String>,
    }

    impl JobRecord {
        pub fn is_terminal(&self) -> bool {
            matches!(
                self.state,
                JobState::Completed | JobState::Failed | JobState::Cancelled
            )
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct QueueSnapshot {
        pub queued: usize,
        pub running: usize,
        pub completed: usize,
        pub failed: usize,
        pub cancelled: usize,
    }

    #[derive(Debug, Default)]
    pub struct JobQueue {
        next_id: u64,
        queued: VecDeque<JobId>,
        jobs: HashMap<JobId, JobRecord>,
    }

    impl JobQueue {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn enqueue(
            &mut self,
            name: impl Into<String>,
            kind: JobKind,
            priority: JobPriority,
        ) -> JobId {
            self.next_id += 1;
            let id = JobId(self.next_id);
            let now = SystemTime::now();
            let record = JobRecord {
                id,
                name: name.into(),
                kind,
                priority,
                state: JobState::Queued,
                created_at: now,
                started_at: None,
                completed_at: None,
                failure_reason: None,
            };
            self.jobs.insert(id, record);

            // Keep foreground jobs ahead of normal/background to reduce UI latency.
            if priority == JobPriority::Foreground {
                self.queued.push_front(id);
            } else {
                self.queued.push_back(id);
            }
            id
        }

        pub fn start_next(&mut self) -> Option<JobId> {
            let id = self.queued.pop_front()?;
            if let Some(record) = self.jobs.get_mut(&id) {
                record.state = JobState::Running;
                record.started_at = Some(SystemTime::now());
            }
            Some(id)
        }

        pub fn complete(&mut self, id: JobId) -> bool {
            self.transition_terminal(id, JobState::Completed, None)
        }

        pub fn fail(&mut self, id: JobId, reason: impl Into<String>) -> bool {
            self.transition_terminal(id, JobState::Failed, Some(reason.into()))
        }

        pub fn cancel(&mut self, id: JobId) -> bool {
            if self.remove_from_queue(id) {
                return self.transition_terminal(id, JobState::Cancelled, None);
            }
            self.transition_terminal(id, JobState::Cancelled, None)
        }

        pub fn get(&self, id: JobId) -> Option<&JobRecord> {
            self.jobs.get(&id)
        }

        pub fn snapshot(&self) -> QueueSnapshot {
            let mut running = 0usize;
            let mut completed = 0usize;
            let mut failed = 0usize;
            let mut cancelled = 0usize;
            for record in self.jobs.values() {
                match record.state {
                    JobState::Running => running += 1,
                    JobState::Completed => completed += 1,
                    JobState::Failed => failed += 1,
                    JobState::Cancelled => cancelled += 1,
                    JobState::Queued => {}
                }
            }
            QueueSnapshot {
                queued: self.queued.len(),
                running,
                completed,
                failed,
                cancelled,
            }
        }

        pub fn queued_depth(&self) -> usize {
            self.queued.len()
        }

        pub fn records_recent(&self, limit: usize) -> Vec<JobRecord> {
            if limit == 0 {
                return Vec::new();
            }
            let mut records = self.jobs.values().cloned().collect::<Vec<_>>();
            records.sort_by_key(|record| std::cmp::Reverse(record.id.0));
            records.truncate(limit);
            records
        }

        pub fn first_running_job(&self) -> Option<JobId> {
            self.jobs
                .values()
                .filter(|record| matches!(record.state, JobState::Running))
                .map(|record| record.id)
                .max_by_key(|id| id.0)
        }

        pub fn snapshot_state(&self) -> JobQueueState {
            let mut records = self
                .jobs
                .values()
                .map(|record| JobQueueStateRecord {
                    id: record.id.0,
                    name: record.name.clone(),
                    kind: record.kind,
                    priority: record.priority,
                    state: record.state,
                    created_at_unix_ms: system_time_to_unix_ms(record.created_at),
                    started_at_unix_ms: record.started_at.and_then(system_time_to_unix_ms),
                    completed_at_unix_ms: record.completed_at.and_then(system_time_to_unix_ms),
                    failure_reason: record.failure_reason.clone(),
                })
                .collect::<Vec<_>>();
            records.sort_by_key(|entry| entry.id);

            JobQueueState {
                next_id: self.next_id,
                queued_ids: self.queued.iter().map(|id| id.0).collect::<Vec<_>>(),
                records,
            }
        }

        pub fn restore_state(state: JobQueueState) -> Result<Self, String> {
            let mut jobs = HashMap::new();
            let mut max_id = 0_u64;
            for entry in state.records {
                if entry.id == 0 {
                    return Err("invalid job id 0 in persisted state".to_string());
                }
                max_id = max_id.max(entry.id);
                let job_id = JobId(entry.id);
                if jobs.contains_key(&job_id) {
                    return Err(format!("duplicate job id in persisted state: {}", entry.id));
                }
                jobs.insert(
                    job_id,
                    JobRecord {
                        id: job_id,
                        name: entry.name,
                        kind: entry.kind,
                        priority: entry.priority,
                        state: entry.state,
                        created_at: entry
                            .created_at_unix_ms
                            .map(unix_ms_to_system_time)
                            .unwrap_or(SystemTime::UNIX_EPOCH),
                        started_at: entry.started_at_unix_ms.map(unix_ms_to_system_time),
                        completed_at: entry.completed_at_unix_ms.map(unix_ms_to_system_time),
                        failure_reason: entry.failure_reason,
                    },
                );
            }

            let mut queued = VecDeque::new();
            for raw_id in state.queued_ids {
                let job_id = JobId(raw_id);
                if let Some(record) = jobs.get_mut(&job_id) {
                    record.state = JobState::Queued;
                    queued.push_back(job_id);
                }
            }

            let mut queued_ids = queued.iter().map(|id| id.0).collect::<Vec<_>>();
            queued_ids.sort_unstable();
            for record in jobs.values_mut() {
                if matches!(record.state, JobState::Queued) && !queued_ids.contains(&record.id.0) {
                    queued.push_back(record.id);
                }
            }

            let next_id = state.next_id.max(max_id);
            Ok(Self {
                next_id,
                queued,
                jobs,
            })
        }

        fn remove_from_queue(&mut self, id: JobId) -> bool {
            if let Some(position) = self.queued.iter().position(|candidate| *candidate == id) {
                self.queued.remove(position);
                return true;
            }
            false
        }

        fn transition_terminal(
            &mut self,
            id: JobId,
            state: JobState,
            failure_reason: Option<String>,
        ) -> bool {
            let Some(record) = self.jobs.get_mut(&id) else {
                return false;
            };
            record.state = state;
            record.failure_reason = failure_reason;
            record.completed_at = Some(SystemTime::now());
            true
        }
    }

    fn system_time_to_unix_ms(value: SystemTime) -> Option<u64> {
        value
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
    }

    fn unix_ms_to_system_time(millis: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH
            .checked_add(std::time::Duration::from_millis(millis))
            .unwrap_or(SystemTime::UNIX_EPOCH)
    }

    #[cfg(test)]
    mod tests {
        use super::{JobKind, JobPriority, JobQueue, JobState};

        #[test]
        fn foreground_jobs_start_first() {
            let mut queue = JobQueue::new();
            let normal = queue.enqueue("normal", JobKind::AgentRun, JobPriority::Normal);
            let foreground =
                queue.enqueue("foreground", JobKind::CodeBuild, JobPriority::Foreground);

            let started = queue.start_next();
            assert_eq!(started.map(|id| id.raw()), Some(foreground.raw()));
            assert_eq!(
                started
                    .and_then(|id| queue.get(id))
                    .map(|record| record.state),
                Some(JobState::Running)
            );
            assert!(queue.get(normal).is_some());
        }

        #[test]
        fn failures_are_recorded_with_reason() {
            let mut queue = JobQueue::new();
            let job = queue.enqueue("llm", JobKind::LlmInference, JobPriority::Normal);
            let started = queue.start_next();
            assert_eq!(started.map(|id| id.raw()), Some(job.raw()));

            assert!(queue.fail(job, "runtime unavailable"));
            assert_eq!(
                queue.get(job).map(|record| record.state),
                Some(JobState::Failed)
            );
            assert_eq!(
                queue
                    .get(job)
                    .and_then(|record| record.failure_reason.as_deref()),
                Some("runtime unavailable")
            );
        }

        #[test]
        fn records_recent_returns_newest_first_with_limit() {
            let mut queue = JobQueue::new();
            let first = queue.enqueue("first", JobKind::SystemTask, JobPriority::Background);
            let second = queue.enqueue("second", JobKind::CodeBuild, JobPriority::Normal);
            let third = queue.enqueue("third", JobKind::AgentRun, JobPriority::Foreground);

            let recent = queue.records_recent(2);
            assert_eq!(recent.len(), 2);
            assert_eq!(recent[0].id.raw(), third.raw());
            assert_eq!(recent[1].id.raw(), second.raw());
            assert_ne!(recent[1].id.raw(), first.raw());
        }

        #[test]
        fn snapshot_restore_round_trip_preserves_queue_state() {
            let mut queue = JobQueue::new();
            let _ = queue.enqueue("code-a", JobKind::CodeBuild, JobPriority::Normal);
            let _ = queue.enqueue("img-b", JobKind::ImageGeneration, JobPriority::Foreground);
            let running = queue.start_next();
            assert!(running.is_some());
            let running = match running {
                Some(value) => value,
                None => return,
            };
            assert!(queue.fail(running, "mock fail"));
            let queued =
                queue.enqueue("video-c", JobKind::VideoGeneration, JobPriority::Background);
            assert!(queue.cancel(queued));

            let state = queue.snapshot_state();
            let restored = JobQueue::restore_state(state.clone());
            assert!(restored.is_ok());
            let restored = match restored {
                Ok(value) => value,
                Err(_) => return,
            };
            assert_eq!(restored.snapshot(), queue.snapshot());
            assert_eq!(restored.snapshot_state().next_id, state.next_id);
            assert_eq!(restored.snapshot_state().queued_ids, state.queued_ids);
            assert_eq!(
                restored.records_recent(16).len(),
                queue.records_recent(16).len()
            );
        }
    }
}

pub mod workspace {
    use std::ffi::OsStr;
    use std::fs;
    use std::path::{Component, Path, PathBuf};
    use std::process::Command;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum WorkspaceError {
        InvalidPath(String),
        Io(String),
        Command(String),
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SearchHit {
        pub path: String,
        pub line_number: usize,
        pub line_excerpt: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct GitStatusSummary {
        pub branch: String,
        pub ahead: u32,
        pub behind: u32,
        pub staged: u32,
        pub modified: u32,
        pub untracked: u32,
    }

    impl Default for GitStatusSummary {
        fn default() -> Self {
            Self {
                branch: String::from("unknown"),
                ahead: 0,
                behind: 0,
                staged: 0,
                modified: 0,
                untracked: 0,
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TerminalCommandResult {
        pub command: String,
        pub stdout: String,
        pub stderr: String,
        pub exit_code: i32,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct WorkspaceHost {
        root: PathBuf,
        canonical_root: PathBuf,
    }

    impl WorkspaceHost {
        pub fn new(root: impl Into<PathBuf>) -> Self {
            let root = root.into();
            let canonical_root = fs::canonicalize(&root).unwrap_or_else(|_| root.clone());
            Self {
                root,
                canonical_root,
            }
        }

        pub fn root(&self) -> &Path {
            &self.root
        }

        pub fn list_files(&self, limit: usize) -> Result<Vec<String>, WorkspaceError> {
            if limit == 0 {
                return Ok(Vec::new());
            }

            let mut files = Vec::new();
            self.walk_files(&self.root, limit, &mut files)?;
            files.sort();
            Ok(files)
        }

        pub fn read_file(&self, relative_path: &str) -> Result<String, WorkspaceError> {
            let path = self.resolve_relative_path(relative_path)?;
            fs::read_to_string(path).map_err(Self::io_error)
        }

        pub fn read_file_excerpt(
            &self,
            relative_path: &str,
            max_lines: usize,
            max_chars: usize,
        ) -> Result<String, WorkspaceError> {
            let contents = self.read_file(relative_path)?;
            let mut excerpt = String::new();
            for (index, line) in contents.lines().enumerate() {
                if index >= max_lines {
                    break;
                }
                if !excerpt.is_empty() {
                    excerpt.push('\n');
                }
                excerpt.push_str(line);
            }
            if excerpt.chars().count() > max_chars {
                let truncated: String = excerpt.chars().take(max_chars).collect();
                return Ok(format!("{truncated}\n..."));
            }
            Ok(excerpt)
        }

        pub fn write_file(
            &self,
            relative_path: &str,
            contents: &str,
        ) -> Result<(), WorkspaceError> {
            let path = self.resolve_relative_path(relative_path)?;
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(Self::io_error)?;
            }
            fs::write(path, contents).map_err(Self::io_error)
        }

        pub fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchHit>, WorkspaceError> {
            if limit == 0 || query.trim().is_empty() {
                return Ok(Vec::new());
            }

            let query = query.to_lowercase();
            let mut hits = Vec::new();
            self.walk_search(&self.root, &query, limit, &mut hits)?;
            Ok(hits)
        }

        pub fn git_status(&self) -> Result<GitStatusSummary, WorkspaceError> {
            let output = Command::new("git")
                .arg("-C")
                .arg(&self.root)
                .arg("status")
                .arg("--porcelain=2")
                .arg("--branch")
                // Keep repo discovery scoped to the configured workspace root.
                .env("GIT_CEILING_DIRECTORIES", &self.root)
                .output()
                .map_err(Self::command_error)?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(WorkspaceError::Command(format!(
                    "git status failed: {}",
                    stderr.trim()
                )));
            }

            let mut summary = GitStatusSummary::default();
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Some(rest) = line.strip_prefix("# branch.head ") {
                    summary.branch = rest.trim().to_string();
                    continue;
                }
                if let Some(rest) = line.strip_prefix("# branch.ab ") {
                    let mut parts = rest.split_whitespace();
                    if let Some(ahead) = parts.next() {
                        summary.ahead = Self::parse_branch_delta(ahead, '+');
                    }
                    if let Some(behind) = parts.next() {
                        summary.behind = Self::parse_branch_delta(behind, '-');
                    }
                    continue;
                }
                if line.starts_with("? ") {
                    summary.untracked += 1;
                    continue;
                }
                if line.starts_with("1 ") || line.starts_with("2 ") {
                    let mut fields = line.split_whitespace();
                    let _kind = fields.next();
                    if let Some(xy) = fields.next() {
                        let mut chars = xy.chars();
                        if let Some(index_status) = chars.next()
                            && index_status != '.'
                        {
                            summary.staged += 1;
                        }
                        if let Some(worktree_status) = chars.next()
                            && worktree_status != '.'
                        {
                            summary.modified += 1;
                        }
                    }
                }
            }
            Ok(summary)
        }

        pub fn run_terminal_command(
            &self,
            command: &str,
        ) -> Result<TerminalCommandResult, WorkspaceError> {
            let command = command.trim();
            if command.is_empty() {
                return Err(WorkspaceError::Command(
                    "terminal command is empty".to_string(),
                ));
            }

            let mut process = if cfg!(windows) {
                let mut cmd = Command::new("powershell");
                cmd.arg("-NoProfile").arg("-Command").arg(command);
                cmd
            } else {
                let mut cmd = Command::new("sh");
                cmd.arg("-lc").arg(command);
                cmd
            };
            process.current_dir(&self.root);

            let output = process.output().map_err(Self::command_error)?;
            let exit_code = output.status.code().unwrap_or(-1);

            Ok(TerminalCommandResult {
                command: command.to_string(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                exit_code,
            })
        }

        fn walk_files(
            &self,
            current_dir: &Path,
            limit: usize,
            files: &mut Vec<String>,
        ) -> Result<(), WorkspaceError> {
            if files.len() >= limit {
                return Ok(());
            }

            let mut entries = Vec::new();
            for entry in fs::read_dir(current_dir).map_err(Self::io_error)? {
                entries.push(entry.map_err(Self::io_error)?);
            }
            entries.sort_by_key(|entry| entry.path());

            for entry in entries {
                if files.len() >= limit {
                    break;
                }

                let path = entry.path();
                self.ensure_existing_path_within_workspace(&path)?;
                let file_type = entry.file_type().map_err(Self::io_error)?;
                if file_type.is_dir() {
                    if Self::is_ignored_directory(entry.file_name().as_os_str()) {
                        continue;
                    }
                    self.walk_files(&path, limit, files)?;
                    continue;
                }
                if file_type.is_file() {
                    files.push(self.to_relative_display_path(&path)?);
                }
            }

            Ok(())
        }

        fn walk_search(
            &self,
            current_dir: &Path,
            query_lower: &str,
            limit: usize,
            hits: &mut Vec<SearchHit>,
        ) -> Result<(), WorkspaceError> {
            if hits.len() >= limit {
                return Ok(());
            }

            let mut entries = Vec::new();
            for entry in fs::read_dir(current_dir).map_err(Self::io_error)? {
                entries.push(entry.map_err(Self::io_error)?);
            }
            entries.sort_by_key(|entry| entry.path());

            for entry in entries {
                if hits.len() >= limit {
                    break;
                }

                let path = entry.path();
                self.ensure_existing_path_within_workspace(&path)?;
                let file_type = entry.file_type().map_err(Self::io_error)?;
                if file_type.is_dir() {
                    if Self::is_ignored_directory(entry.file_name().as_os_str()) {
                        continue;
                    }
                    self.walk_search(&path, query_lower, limit, hits)?;
                    continue;
                }

                if !file_type.is_file() {
                    continue;
                }

                let content = match fs::read_to_string(&path) {
                    Ok(content) => content,
                    Err(_) => continue,
                };
                let relative_path = self.to_relative_display_path(&path)?;
                for (index, line) in content.lines().enumerate() {
                    if !line.to_lowercase().contains(query_lower) {
                        continue;
                    }
                    let excerpt = Self::line_excerpt(line, 140);
                    hits.push(SearchHit {
                        path: relative_path.clone(),
                        line_number: index + 1,
                        line_excerpt: excerpt,
                    });
                    if hits.len() >= limit {
                        break;
                    }
                }
            }

            Ok(())
        }

        fn line_excerpt(line: &str, max_chars: usize) -> String {
            if line.chars().count() <= max_chars {
                return line.to_string();
            }
            let prefix: String = line.chars().take(max_chars).collect();
            format!("{prefix}...")
        }

        fn to_relative_display_path(&self, path: &Path) -> Result<String, WorkspaceError> {
            self.ensure_existing_path_within_workspace(path)?;
            let relative = path
                .strip_prefix(&self.root)
                .map_err(|_| WorkspaceError::InvalidPath(path.display().to_string()))?;
            Ok(relative.to_string_lossy().replace('\\', "/"))
        }

        fn resolve_relative_path(&self, relative_path: &str) -> Result<PathBuf, WorkspaceError> {
            let candidate = Path::new(relative_path);
            if relative_path.trim().is_empty() {
                return Err(WorkspaceError::InvalidPath(
                    "relative path is empty".to_string(),
                ));
            }
            for component in candidate.components() {
                match component {
                    Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                        return Err(WorkspaceError::InvalidPath(relative_path.to_string()));
                    }
                    Component::CurDir | Component::Normal(_) => {}
                }
            }
            let resolved = self.root.join(candidate);
            self.ensure_candidate_path_within_workspace(&resolved)?;
            Ok(resolved)
        }

        fn ensure_candidate_path_within_workspace(
            &self,
            candidate: &Path,
        ) -> Result<(), WorkspaceError> {
            self.reject_symlink_components(candidate)?;
            let existing = Self::nearest_existing_ancestor(candidate).ok_or_else(|| {
                WorkspaceError::InvalidPath(format!(
                    "workspace path has no existing ancestor: {}",
                    candidate.display()
                ))
            })?;
            let canonical_existing = fs::canonicalize(&existing).map_err(Self::io_error)?;
            if !canonical_existing.starts_with(&self.canonical_root) {
                return Err(WorkspaceError::InvalidPath(format!(
                    "workspace path escapes root boundary: {}",
                    candidate.display()
                )));
            }
            Ok(())
        }

        fn ensure_existing_path_within_workspace(&self, path: &Path) -> Result<(), WorkspaceError> {
            self.reject_symlink_components(path)?;
            let canonical = fs::canonicalize(path).map_err(Self::io_error)?;
            if !canonical.starts_with(&self.canonical_root) {
                return Err(WorkspaceError::InvalidPath(format!(
                    "workspace path escapes root boundary: {}",
                    path.display()
                )));
            }
            Ok(())
        }

        fn reject_symlink_components(&self, candidate: &Path) -> Result<(), WorkspaceError> {
            let relative = candidate
                .strip_prefix(&self.root)
                .map_err(|_| WorkspaceError::InvalidPath(candidate.display().to_string()))?;
            let mut cursor = self.root.clone();
            Self::reject_if_symlink(&cursor)?;
            for component in relative.components() {
                match component {
                    Component::Normal(segment) => {
                        cursor.push(segment);
                        if cursor.exists() {
                            Self::reject_if_symlink(&cursor)?;
                        }
                    }
                    Component::CurDir => {}
                    Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                        return Err(WorkspaceError::InvalidPath(candidate.display().to_string()));
                    }
                }
            }
            Ok(())
        }

        fn reject_if_symlink(path: &Path) -> Result<(), WorkspaceError> {
            let metadata = fs::symlink_metadata(path).map_err(Self::io_error)?;
            if metadata.file_type().is_symlink() {
                return Err(WorkspaceError::InvalidPath(format!(
                    "workspace path contains symlink component: {}",
                    path.display()
                )));
            }
            Ok(())
        }

        fn nearest_existing_ancestor(path: &Path) -> Option<PathBuf> {
            let mut current = path.to_path_buf();
            loop {
                if current.exists() {
                    return Some(current);
                }
                if !current.pop() {
                    return None;
                }
            }
        }

        fn is_ignored_directory(name: &OsStr) -> bool {
            matches!(name.to_str(), Some(".git") | Some("target") | Some(".tmp"))
        }

        fn parse_branch_delta(token: &str, expected_prefix: char) -> u32 {
            let Some(stripped) = token.strip_prefix(expected_prefix) else {
                return 0;
            };
            stripped.parse::<u32>().unwrap_or_default()
        }

        fn io_error(error: std::io::Error) -> WorkspaceError {
            WorkspaceError::Io(error.to_string())
        }

        fn command_error(error: std::io::Error) -> WorkspaceError {
            WorkspaceError::Command(error.to_string())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::WorkspaceHost;
        use std::fs;
        use std::path::PathBuf;
        use std::time::{SystemTime, UNIX_EPOCH};

        fn unique_test_root(name: &str) -> PathBuf {
            let mut root = std::env::temp_dir();
            let nanos = match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(duration) => duration.as_nanos(),
                Err(_) => 0,
            };
            root.push(format!("forge_workspace_host_{name}_{nanos}"));
            root
        }

        #[test]
        fn file_search_read_and_write_flow() {
            let root = unique_test_root("io");
            assert!(fs::create_dir_all(root.join("src")).is_ok());
            assert!(fs::write(root.join("src/main.rs"), "fn main() {}\n").is_ok());
            assert!(fs::write(root.join("README.md"), "phase 1 workspace host\n").is_ok());

            let host = WorkspaceHost::new(&root);

            let files = host.list_files(20);
            assert!(
                matches!(files, Ok(ref listed) if listed.iter().any(|entry| entry == "src/main.rs"))
            );

            let hits = host.search("phase 1", 10);
            assert!(
                matches!(hits, Ok(ref entries) if entries.iter().any(|entry| entry.path == "README.md"))
            );

            let excerpt = host.read_file_excerpt("README.md", 1, 40);
            assert!(matches!(excerpt, Ok(ref text) if text.contains("workspace host")));

            assert!(
                host.write_file("notes/todo.txt", "integrate terminal")
                    .is_ok()
            );
            let reloaded = host.read_file("notes/todo.txt");
            assert!(matches!(reloaded, Ok(ref text) if text == "integrate terminal"));

            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn git_status_returns_error_outside_git_repo() {
            let root = unique_test_root("git");
            assert!(fs::create_dir_all(&root).is_ok());
            // Force this test root to be treated as a non-functional git directory,
            // so parent repository discovery cannot mask the expected error path.
            assert!(fs::write(root.join(".git"), "gitdir: ./missing\n").is_ok());

            let host = WorkspaceHost::new(&root);
            assert!(host.git_status().is_err());

            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn terminal_command_executes() {
            let root = unique_test_root("terminal");
            assert!(fs::create_dir_all(&root).is_ok());

            let host = WorkspaceHost::new(&root);
            let command = if cfg!(windows) {
                "Write-Output forge-terminal-test"
            } else {
                "printf forge-terminal-test"
            };
            let result = host.run_terminal_command(command);

            assert!(
                matches!(result, Ok(ref output) if output.stdout.contains("forge-terminal-test"))
            );

            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn write_file_rejects_parent_escape() {
            let root = unique_test_root("escape_parent");
            assert!(fs::create_dir_all(&root).is_ok());
            let host = WorkspaceHost::new(&root);

            let result = host.write_file("../outside.txt", "blocked");
            assert!(result.is_err());

            let _ = fs::remove_dir_all(root);
        }

        #[cfg(unix)]
        #[test]
        fn read_file_rejects_symlink_escape() {
            use std::os::unix::fs::symlink;

            let root = unique_test_root("symlink_escape");
            let outside_root = unique_test_root("outside_root");
            assert!(fs::create_dir_all(&root).is_ok());
            assert!(fs::create_dir_all(&outside_root).is_ok());
            let outside_file = outside_root.join("secret.txt");
            assert!(fs::write(&outside_file, "top secret").is_ok());
            let link_path = root.join("secret-link.txt");
            assert!(symlink(&outside_file, &link_path).is_ok());

            let host = WorkspaceHost::new(&root);
            let result = host.read_file("secret-link.txt");
            assert!(result.is_err());

            let _ = fs::remove_dir_all(root);
            let _ = fs::remove_dir_all(outside_root);
        }
    }
}

pub mod terminal {
    use std::collections::{HashMap, VecDeque};
    use std::ffi::OsStr;
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::SystemTime;

    use portable_pty::{CommandBuilder, PtySize, native_pty_system};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum TerminalError {
        UnknownSession,
        Command(String),
        Io(String),
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TerminalSessionId(u64);

    impl TerminalSessionId {
        pub fn raw(self) -> u64 {
            self.0
        }

        pub fn from_raw(raw: u64) -> Self {
            Self(raw)
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum TerminalSessionState {
        Running,
        Exited(i32),
        FailedToStart(String),
        Stopped,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TerminalSessionStatus {
        pub id: TerminalSessionId,
        pub command: String,
        pub state: TerminalSessionState,
        pub started_at: Option<SystemTime>,
        pub ended_at: Option<SystemTime>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TerminalOutputLine {
        sequence: u64,
        text: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TerminalPollResult {
        pub lines: Vec<String>,
        pub dropped_since_last_poll: u64,
        pub total_buffered: usize,
    }

    #[derive(Debug)]
    struct OutputBuffer {
        lines: VecDeque<TerminalOutputLine>,
        next_sequence: u64,
        dropped_total: u64,
        line_limit: usize,
    }

    impl OutputBuffer {
        fn new(line_limit: usize) -> Self {
            Self {
                lines: VecDeque::new(),
                next_sequence: 0,
                dropped_total: 0,
                line_limit,
            }
        }

        fn push_line(&mut self, text: String) {
            self.next_sequence = self.next_sequence.saturating_add(1);
            self.lines.push_back(TerminalOutputLine {
                sequence: self.next_sequence,
                text,
            });
            while self.lines.len() > self.line_limit {
                let _ = self.lines.pop_front();
                self.dropped_total = self.dropped_total.saturating_add(1);
            }
        }
    }

    struct ManagedTerminalSession {
        command: String,
        child: Option<Box<dyn portable_pty::Child + Send + Sync>>,
        input: Option<Box<dyn Write + Send>>,
        state: TerminalSessionState,
        started_at: Option<SystemTime>,
        ended_at: Option<SystemTime>,
        output: Arc<Mutex<OutputBuffer>>,
        last_polled_sequence: u64,
        last_polled_dropped_total: u64,
    }

    pub struct TerminalSessionManager {
        root: PathBuf,
        next_id: u64,
        sessions: HashMap<TerminalSessionId, ManagedTerminalSession>,
        output_line_limit: usize,
    }

    impl TerminalSessionManager {
        pub fn new(root: impl Into<PathBuf>) -> Self {
            Self {
                root: root.into(),
                next_id: 0,
                sessions: HashMap::new(),
                output_line_limit: 2000,
            }
        }

        pub fn start_session(
            &mut self,
            command: impl Into<String>,
        ) -> Result<TerminalSessionId, TerminalError> {
            let command = command.into();
            if command.trim().is_empty() {
                return Err(TerminalError::Command(
                    "terminal command is empty".to_string(),
                ));
            }

            let output = Arc::new(Mutex::new(OutputBuffer::new(self.output_line_limit)));
            let pty_system = native_pty_system();
            let pair = pty_system
                .openpty(PtySize {
                    rows: 30,
                    cols: 120,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .map_err(|error| TerminalError::Io(error.to_string()))?;

            let mut cmd = Self::build_shell_command(&command);
            cmd.cwd(self.root.as_os_str());
            let child = pair
                .slave
                .spawn_command(cmd)
                .map_err(|error| TerminalError::Io(error.to_string()))?;

            let reader = pair
                .master
                .try_clone_reader()
                .map_err(|error| TerminalError::Io(error.to_string()))?;
            let writer = pair
                .master
                .take_writer()
                .map_err(|error| TerminalError::Io(error.to_string()))?;

            Self::spawn_reader_thread(reader, output.clone());

            self.next_id = self.next_id.saturating_add(1);
            let id = TerminalSessionId(self.next_id);
            let session = ManagedTerminalSession {
                command,
                child: Some(child),
                input: Some(writer),
                state: TerminalSessionState::Running,
                started_at: Some(SystemTime::now()),
                ended_at: None,
                output,
                last_polled_sequence: 0,
                last_polled_dropped_total: 0,
            };
            self.sessions.insert(id, session);
            Ok(id)
        }

        pub fn status(
            &mut self,
            session_id: TerminalSessionId,
        ) -> Result<TerminalSessionStatus, TerminalError> {
            self.refresh_session_state(session_id)?;
            let session = self
                .sessions
                .get(&session_id)
                .ok_or(TerminalError::UnknownSession)?;
            Ok(TerminalSessionStatus {
                id: session_id,
                command: session.command.clone(),
                state: session.state.clone(),
                started_at: session.started_at,
                ended_at: session.ended_at,
            })
        }

        pub fn poll_output(
            &mut self,
            session_id: TerminalSessionId,
            max_lines: usize,
        ) -> Result<TerminalPollResult, TerminalError> {
            if max_lines == 0 {
                return Ok(TerminalPollResult {
                    lines: Vec::new(),
                    dropped_since_last_poll: 0,
                    total_buffered: 0,
                });
            }

            self.refresh_session_state(session_id)?;
            let session = self
                .sessions
                .get_mut(&session_id)
                .ok_or(TerminalError::UnknownSession)?;

            let (lines, latest_sequence, dropped_total, total_buffered) = {
                let mut_guard = session
                    .output
                    .lock()
                    .map_err(|_| TerminalError::Io("terminal output lock poisoned".to_string()))?;
                let mut lines = Vec::new();
                let mut latest_sequence = session.last_polled_sequence;
                for line in &mut_guard.lines {
                    if line.sequence <= session.last_polled_sequence {
                        continue;
                    }
                    if lines.len() >= max_lines {
                        break;
                    }
                    latest_sequence = line.sequence;
                    lines.push(line.text.clone());
                }
                (
                    lines,
                    latest_sequence,
                    mut_guard.dropped_total,
                    mut_guard.lines.len(),
                )
            };

            let dropped_since_last_poll =
                dropped_total.saturating_sub(session.last_polled_dropped_total);
            session.last_polled_dropped_total = dropped_total;
            if latest_sequence > session.last_polled_sequence {
                session.last_polled_sequence = latest_sequence;
            }

            Ok(TerminalPollResult {
                lines,
                dropped_since_last_poll,
                total_buffered,
            })
        }

        pub fn send_input(
            &mut self,
            session_id: TerminalSessionId,
            input: &str,
        ) -> Result<usize, TerminalError> {
            self.refresh_session_state(session_id)?;
            let session = self
                .sessions
                .get_mut(&session_id)
                .ok_or(TerminalError::UnknownSession)?;
            if !matches!(session.state, TerminalSessionState::Running) {
                return Err(TerminalError::Command(
                    "terminal session is not running".to_string(),
                ));
            }
            if input.is_empty() {
                return Ok(0);
            }

            let writer = session.input.as_mut().ok_or_else(|| {
                TerminalError::Command("terminal session has no interactive input".to_string())
            })?;
            writer
                .write_all(input.as_bytes())
                .map_err(|error| TerminalError::Io(error.to_string()))?;
            writer
                .flush()
                .map_err(|error| TerminalError::Io(error.to_string()))?;
            Ok(input.len())
        }

        pub fn stop_session(
            &mut self,
            session_id: TerminalSessionId,
        ) -> Result<bool, TerminalError> {
            let session = self
                .sessions
                .get_mut(&session_id)
                .ok_or(TerminalError::UnknownSession)?;
            session.input = None;
            let Some(mut child) = session.child.take() else {
                return Ok(false);
            };

            if let Err(error) = child.kill() {
                session.state = TerminalSessionState::FailedToStart(error.to_string());
                session.ended_at = Some(SystemTime::now());
                return Ok(false);
            }
            if let Err(error) = child.wait() {
                session.state = TerminalSessionState::FailedToStart(error.to_string());
                session.ended_at = Some(SystemTime::now());
                return Ok(false);
            }

            session.state = TerminalSessionState::Stopped;
            session.ended_at = Some(SystemTime::now());
            Ok(true)
        }

        pub fn clear_session(
            &mut self,
            session_id: TerminalSessionId,
        ) -> Result<bool, TerminalError> {
            let Some(mut session) = self.sessions.remove(&session_id) else {
                return Ok(false);
            };
            session.input = None;
            if let Some(mut child) = session.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            Ok(true)
        }

        fn refresh_session_state(
            &mut self,
            session_id: TerminalSessionId,
        ) -> Result<(), TerminalError> {
            let session = self
                .sessions
                .get_mut(&session_id)
                .ok_or(TerminalError::UnknownSession)?;
            let Some(child) = session.child.as_mut() else {
                return Ok(());
            };
            match child.try_wait() {
                Ok(Some(status)) => {
                    let code = status.exit_code() as i32;
                    session.state = TerminalSessionState::Exited(code);
                    session.ended_at = Some(SystemTime::now());
                    session.child = None;
                    session.input = None;
                }
                Ok(None) => {}
                Err(error) => {
                    session.state = TerminalSessionState::FailedToStart(error.to_string());
                    session.ended_at = Some(SystemTime::now());
                    session.child = None;
                    session.input = None;
                }
            }
            Ok(())
        }

        fn build_shell_command(command: &str) -> CommandBuilder {
            if cfg!(windows) {
                let mut cmd = CommandBuilder::new(OsStr::new("cmd"));
                cmd.arg("/Q");
                cmd.arg("/D");
                cmd.arg("/C");
                cmd.arg(command);
                cmd
            } else {
                let mut cmd = CommandBuilder::new(OsStr::new("sh"));
                cmd.arg("-lc");
                cmd.arg(command);
                cmd
            }
        }

        fn spawn_reader_thread<R: Read + Send + 'static>(
            reader: R,
            output: Arc<Mutex<OutputBuffer>>,
        ) {
            thread::spawn(move || {
                let mut reader = reader;
                let mut carry = String::new();
                let mut bytes = [0u8; 2048];
                loop {
                    match reader.read(&mut bytes) {
                        Ok(0) => break,
                        Ok(read) => {
                            let chunk = String::from_utf8_lossy(&bytes[..read]).replace('\r', "");
                            carry.push_str(&chunk);
                            loop {
                                let newline_index = carry.find('\n');
                                let Some(newline_index) = newline_index else {
                                    break;
                                };
                                let line = carry[..newline_index].to_string();
                                carry = carry[(newline_index + 1)..].to_string();
                                if let Ok(mut buffer) = output.lock() {
                                    buffer.push_line(format!("pty> {line}"));
                                } else {
                                    return;
                                }
                            }

                            if !carry.is_empty() {
                                let partial = std::mem::take(&mut carry);
                                if let Ok(mut buffer) = output.lock() {
                                    buffer.push_line(format!("pty> {partial}"));
                                } else {
                                    return;
                                }
                            }
                        }
                        Err(error) => {
                            let payload = format!("pty> read error: {error}");
                            if let Ok(mut buffer) = output.lock() {
                                buffer.push_line(payload);
                            }
                            break;
                        }
                    }
                }
                if !carry.is_empty()
                    && let Ok(mut buffer) = output.lock()
                {
                    buffer.push_line(format!("pty> {carry}"));
                }
            });
        }
    }

    impl Drop for TerminalSessionManager {
        fn drop(&mut self) {
            let ids: Vec<TerminalSessionId> = self.sessions.keys().copied().collect();
            for id in ids {
                let _ = self.clear_session(id);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{TerminalSessionManager, TerminalSessionState};
        use std::fs;
        use std::thread;
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        fn unique_test_root(name: &str) -> std::path::PathBuf {
            let mut root = std::env::temp_dir();
            let nanos = match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(duration) => duration.as_nanos(),
                Err(_) => 0,
            };
            root.push(format!("forge_terminal_session_{name}_{nanos}"));
            root
        }

        fn streaming_command() -> &'static str {
            if cfg!(windows) {
                "echo alpha && ping -n 2 127.0.0.1 >NUL && echo beta && ping -n 2 127.0.0.1 >NUL && echo gamma"
            } else {
                "printf 'alpha\\n'; sleep 0.12; printf 'beta\\n'; sleep 0.12; printf 'gamma\\n'"
            }
        }

        #[test]
        fn streaming_terminal_emits_incremental_output() {
            if cfg!(windows) {
                return;
            }
            let root = unique_test_root("stream");
            assert!(fs::create_dir_all(&root).is_ok());
            let mut manager = TerminalSessionManager::new(&root);
            let session = manager.start_session(streaming_command());
            assert!(session.is_ok());
            let session = match session {
                Ok(value) => value,
                Err(_) => return,
            };

            let mut collected = String::new();
            for _ in 0..80 {
                let poll = manager.poll_output(session, 50);
                assert!(poll.is_ok());
                let poll = match poll {
                    Ok(value) => value,
                    Err(_) => return,
                };
                if !poll.lines.is_empty() {
                    collected.push_str(&poll.lines.join("\n"));
                    collected.push('\n');
                }
                if collected.contains("gamma") {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }

            assert!(collected.contains("alpha"));
            assert!(collected.contains("gamma"));

            let status = manager.status(session);
            assert!(status.is_ok());
            let status = match status {
                Ok(value) => value,
                Err(_) => return,
            };
            assert!(matches!(
                status.state,
                TerminalSessionState::Running | TerminalSessionState::Exited(_)
            ));

            let _ = manager.clear_session(session);
            let _ = fs::remove_dir_all(root);
        }

        fn interactive_command() -> &'static str {
            if cfg!(windows) {
                "set /p v=& echo echo:%v%"
            } else {
                "printf 'ready\\n'; IFS= read line; printf 'echo:%s\\n' \"$line\""
            }
        }

        #[test]
        fn interactive_input_is_forwarded_to_terminal_session() {
            if cfg!(windows) {
                return;
            }
            let root = unique_test_root("interactive");
            assert!(fs::create_dir_all(&root).is_ok());
            let mut manager = TerminalSessionManager::new(&root);
            let session = manager.start_session(interactive_command());
            assert!(session.is_ok());
            let session = match session {
                Ok(value) => value,
                Err(_) => return,
            };

            for _ in 0..10 {
                let status = manager.status(session);
                if matches!(
                    status.as_ref().map(|value| &value.state),
                    Ok(TerminalSessionState::Running)
                ) {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }

            let input = if cfg!(windows) {
                "forge-pty-input\r\n"
            } else {
                "forge-pty-input\n"
            };
            let sent = manager.send_input(session, input);
            assert!(matches!(sent, Ok(bytes) if bytes > 0));

            let mut collected = String::new();
            for _ in 0..30 {
                let poll = manager.poll_output(session, 80);
                assert!(poll.is_ok());
                let poll = match poll {
                    Ok(value) => value,
                    Err(_) => return,
                };
                if !poll.lines.is_empty() {
                    collected.push_str(&poll.lines.join("\n"));
                    collected.push('\n');
                }
                if collected.contains("echo:forge-pty-input") {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }

            assert!(collected.contains("echo:forge-pty-input"));

            let _ = manager.clear_session(session);
            let _ = fs::remove_dir_all(root);
        }

        #[test]
        fn empty_command_is_rejected() {
            let root = unique_test_root("reject");
            assert!(fs::create_dir_all(&root).is_ok());
            let mut manager = TerminalSessionManager::new(&root);
            assert!(manager.start_session("   ").is_err());
            let _ = fs::remove_dir_all(root);
        }
    }
}
