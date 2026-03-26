use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentRole {
    Planner,
    Coder,
    Debugger,
    Verifier,
}

impl AgentRole {
    pub const fn label(self) -> &'static str {
        match self {
            AgentRole::Planner => "planner",
            AgentRole::Coder => "coder",
            AgentRole::Debugger => "debugger",
            AgentRole::Verifier => "verifier",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentRunStatus {
    Active,
    WaitingApproval,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentStepStatus {
    Blocked,
    Queued,
    Running,
    WaitingApproval,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts_per_step: u8,
}

impl RetryPolicy {
    pub fn new(max_attempts_per_step: u8) -> Self {
        Self {
            max_attempts_per_step: max_attempts_per_step.max(1),
        }
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts_per_step: 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentGraphNode {
    pub step_id: String,
    pub title: String,
    pub role: AgentRole,
    pub instruction: String,
    pub depends_on: Vec<String>,
    pub requires_approval: bool,
}

impl AgentGraphNode {
    pub fn new(
        step_id: impl Into<String>,
        title: impl Into<String>,
        role: AgentRole,
        instruction: impl Into<String>,
    ) -> Self {
        Self {
            step_id: step_id.into(),
            title: title.into(),
            role,
            instruction: instruction.into(),
            depends_on: Vec::new(),
            requires_approval: false,
        }
    }

    pub fn with_dependencies(mut self, depends_on: Vec<String>) -> Self {
        self.depends_on = depends_on;
        self
    }

    pub fn with_approval(mut self, requires_approval: bool) -> Self {
        self.requires_approval = requires_approval;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentTraceEventKind {
    RunCreated {
        run_id: u64,
        goal: String,
    },
    StepQueued {
        step_id: String,
    },
    StepStarted {
        step_id: String,
        role: AgentRole,
        attempt: u8,
    },
    ApprovalRequested {
        step_id: String,
        reason: String,
    },
    ApprovalResolved {
        step_id: String,
        approved: bool,
        note: String,
    },
    StepCompleted {
        step_id: String,
    },
    StepFailed {
        step_id: String,
        error: String,
    },
    StepRetried {
        step_id: String,
        next_attempt: u8,
    },
    RunCompleted {
        run_id: u64,
    },
    RunFailed {
        run_id: u64,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTraceEvent {
    pub sequence: u64,
    pub recorded_at_unix_ms: u64,
    pub kind: AgentTraceEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStep {
    pub step_id: String,
    pub title: String,
    pub role: AgentRole,
    pub instruction: String,
    pub depends_on: Vec<String>,
    pub requires_approval: bool,
    pub status: AgentStepStatus,
    pub attempt_count: u8,
    pub max_attempts: u8,
    pub output: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRun {
    pub run_id: u64,
    pub goal: String,
    pub status: AgentRunStatus,
    pub steps: Vec<AgentStep>,
    pub trace: Vec<AgentTraceEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentOrchestrationError {
    EmptyGraph,
    DuplicateStepId(String),
    UnknownDependency {
        step_id: String,
        dependency: String,
    },
    CycleDetected(String),
    RunNotFound(u64),
    StepNotFound {
        run_id: u64,
        step_id: String,
    },
    InvalidTransition {
        step_id: String,
        from: AgentStepStatus,
        expected: &'static str,
    },
    DuplicateRunId(u64),
    InvalidRun(String),
}

#[derive(Debug, Default)]
pub struct AgentOrchestrator {
    runs: HashMap<u64, AgentRun>,
    next_run_id: u64,
    next_trace_sequence: u64,
}

impl AgentOrchestrator {
    pub fn new() -> Self {
        Self {
            runs: HashMap::new(),
            next_run_id: 1,
            next_trace_sequence: 1,
        }
    }

    pub fn create_run(
        &mut self,
        goal: impl Into<String>,
        graph: Vec<AgentGraphNode>,
        retry_policy: RetryPolicy,
    ) -> Result<u64, AgentOrchestrationError> {
        validate_graph(&graph)?;
        let run_id = self.next_run_id;
        self.next_run_id += 1;

        let steps = graph
            .into_iter()
            .map(|node| AgentStep {
                step_id: node.step_id,
                title: node.title,
                role: node.role,
                instruction: node.instruction,
                status: if node.depends_on.is_empty() {
                    AgentStepStatus::Queued
                } else {
                    AgentStepStatus::Blocked
                },
                depends_on: node.depends_on,
                requires_approval: node.requires_approval,
                attempt_count: 0,
                max_attempts: retry_policy.max_attempts_per_step,
                output: None,
                last_error: None,
            })
            .collect::<Vec<_>>();

        let run = AgentRun {
            run_id,
            goal: goal.into(),
            status: AgentRunStatus::Active,
            steps,
            trace: Vec::new(),
        };
        self.runs.insert(run_id, run);

        self.push_trace(
            run_id,
            AgentTraceEventKind::RunCreated {
                run_id,
                goal: self
                    .runs
                    .get(&run_id)
                    .map(|value| value.goal.clone())
                    .unwrap_or_default(),
            },
        )?;

        let queued_steps = self
            .runs
            .get(&run_id)
            .map(|run| {
                run.steps
                    .iter()
                    .filter(|step| matches!(step.status, AgentStepStatus::Queued))
                    .map(|step| step.step_id.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        for step_id in queued_steps {
            self.push_trace(run_id, AgentTraceEventKind::StepQueued { step_id })?;
        }

        self.recompute_run_status(run_id)?;
        Ok(run_id)
    }

    pub fn run(&self, run_id: u64) -> Option<&AgentRun> {
        self.runs.get(&run_id)
    }

    pub fn run_snapshot(&self, run_id: u64) -> Option<AgentRun> {
        self.runs.get(&run_id).cloned()
    }

    pub fn runs_snapshot(&self) -> Vec<AgentRun> {
        let mut runs = self.runs.values().cloned().collect::<Vec<_>>();
        runs.sort_by_key(|run| run.run_id);
        runs
    }

    pub fn restore_runs(&mut self, runs: Vec<AgentRun>) -> Result<(), AgentOrchestrationError> {
        let mut restored = HashMap::new();
        let mut max_run_id = 0u64;
        let mut max_trace_sequence = 0u64;

        for run in runs {
            if restored.contains_key(&run.run_id) {
                return Err(AgentOrchestrationError::DuplicateRunId(run.run_id));
            }
            validate_restored_run(&run)?;
            max_run_id = max_run_id.max(run.run_id);
            for event in &run.trace {
                max_trace_sequence = max_trace_sequence.max(event.sequence);
            }
            restored.insert(run.run_id, run);
        }

        self.runs = restored;
        self.next_run_id = max_run_id.saturating_add(1).max(1);
        self.next_trace_sequence = max_trace_sequence.saturating_add(1).max(1);
        Ok(())
    }

    pub fn start_next_step(
        &mut self,
        run_id: u64,
    ) -> Result<Option<String>, AgentOrchestrationError> {
        self.promote_ready_steps(run_id)?;

        let selected = {
            let run = self.run_mut(run_id)?;
            let step = run
                .steps
                .iter_mut()
                .find(|step| matches!(step.status, AgentStepStatus::Queued));
            let Some(step) = step else {
                return Ok(None);
            };
            step.status = AgentStepStatus::Running;
            step.attempt_count = step.attempt_count.saturating_add(1);
            (step.step_id.clone(), step.role, step.attempt_count)
        };

        self.push_trace(
            run_id,
            AgentTraceEventKind::StepStarted {
                step_id: selected.0.clone(),
                role: selected.1,
                attempt: selected.2,
            },
        )?;
        self.recompute_run_status(run_id)?;
        Ok(Some(selected.0))
    }

    pub fn request_approval(
        &mut self,
        run_id: u64,
        step_id: &str,
        reason: impl Into<String>,
    ) -> Result<(), AgentOrchestrationError> {
        let reason = reason.into();
        {
            let run = self.run_mut(run_id)?;
            let step = find_step_mut(run, step_id).ok_or_else(|| {
                AgentOrchestrationError::StepNotFound {
                    run_id,
                    step_id: step_id.to_string(),
                }
            })?;
            if !matches!(step.status, AgentStepStatus::Running) {
                return Err(AgentOrchestrationError::InvalidTransition {
                    step_id: step_id.to_string(),
                    from: step.status,
                    expected: "running",
                });
            }
            step.status = AgentStepStatus::WaitingApproval;
            if step.attempt_count > 0 {
                step.attempt_count -= 1;
            }
        }

        self.push_trace(
            run_id,
            AgentTraceEventKind::ApprovalRequested {
                step_id: step_id.to_string(),
                reason,
            },
        )?;
        self.recompute_run_status(run_id)
    }

    pub fn resolve_approval(
        &mut self,
        run_id: u64,
        step_id: &str,
        approved: bool,
        note: impl Into<String>,
    ) -> Result<(), AgentOrchestrationError> {
        let note = note.into();
        {
            let run = self.run_mut(run_id)?;
            let step = find_step_mut(run, step_id).ok_or_else(|| {
                AgentOrchestrationError::StepNotFound {
                    run_id,
                    step_id: step_id.to_string(),
                }
            })?;
            if !matches!(step.status, AgentStepStatus::WaitingApproval) {
                return Err(AgentOrchestrationError::InvalidTransition {
                    step_id: step_id.to_string(),
                    from: step.status,
                    expected: "waiting approval",
                });
            }
            if approved {
                step.status = AgentStepStatus::Queued;
            } else {
                step.status = AgentStepStatus::Failed;
                step.last_error = Some(format!("approval denied: {note}"));
            }
        }

        self.push_trace(
            run_id,
            AgentTraceEventKind::ApprovalResolved {
                step_id: step_id.to_string(),
                approved,
                note: note.clone(),
            },
        )?;

        if !approved {
            self.push_trace(
                run_id,
                AgentTraceEventKind::StepFailed {
                    step_id: step_id.to_string(),
                    error: format!("approval denied: {note}"),
                },
            )?;
        } else {
            self.push_trace(
                run_id,
                AgentTraceEventKind::StepQueued {
                    step_id: step_id.to_string(),
                },
            )?;
        }

        self.recompute_run_status(run_id)
    }

    pub fn complete_step(
        &mut self,
        run_id: u64,
        step_id: &str,
        output: impl Into<String>,
    ) -> Result<(), AgentOrchestrationError> {
        {
            let run = self.run_mut(run_id)?;
            let step = find_step_mut(run, step_id).ok_or_else(|| {
                AgentOrchestrationError::StepNotFound {
                    run_id,
                    step_id: step_id.to_string(),
                }
            })?;
            if !matches!(step.status, AgentStepStatus::Running) {
                return Err(AgentOrchestrationError::InvalidTransition {
                    step_id: step_id.to_string(),
                    from: step.status,
                    expected: "running",
                });
            }
            step.status = AgentStepStatus::Completed;
            step.output = Some(output.into());
            step.last_error = None;
        }

        self.push_trace(
            run_id,
            AgentTraceEventKind::StepCompleted {
                step_id: step_id.to_string(),
            },
        )?;
        self.promote_ready_steps(run_id)?;
        self.recompute_run_status(run_id)
    }

    pub fn fail_step(
        &mut self,
        run_id: u64,
        step_id: &str,
        error: impl Into<String>,
    ) -> Result<(), AgentOrchestrationError> {
        let error = error.into();
        let next_attempt = {
            let run = self.run_mut(run_id)?;
            let step = find_step_mut(run, step_id).ok_or_else(|| {
                AgentOrchestrationError::StepNotFound {
                    run_id,
                    step_id: step_id.to_string(),
                }
            })?;
            if !matches!(step.status, AgentStepStatus::Running) {
                return Err(AgentOrchestrationError::InvalidTransition {
                    step_id: step_id.to_string(),
                    from: step.status,
                    expected: "running",
                });
            }

            step.last_error = Some(error.clone());
            if step.attempt_count < step.max_attempts {
                step.status = AgentStepStatus::Queued;
                Some(step.attempt_count.saturating_add(1))
            } else {
                step.status = AgentStepStatus::Failed;
                None
            }
        };

        self.push_trace(
            run_id,
            AgentTraceEventKind::StepFailed {
                step_id: step_id.to_string(),
                error,
            },
        )?;
        if let Some(next_attempt) = next_attempt {
            self.push_trace(
                run_id,
                AgentTraceEventKind::StepRetried {
                    step_id: step_id.to_string(),
                    next_attempt,
                },
            )?;
            self.push_trace(
                run_id,
                AgentTraceEventKind::StepQueued {
                    step_id: step_id.to_string(),
                },
            )?;
        }

        self.recompute_run_status(run_id)
    }

    fn run_mut(&mut self, run_id: u64) -> Result<&mut AgentRun, AgentOrchestrationError> {
        self.runs
            .get_mut(&run_id)
            .ok_or(AgentOrchestrationError::RunNotFound(run_id))
    }

    fn push_trace(
        &mut self,
        run_id: u64,
        kind: AgentTraceEventKind,
    ) -> Result<(), AgentOrchestrationError> {
        let event = AgentTraceEvent {
            sequence: self.next_trace_sequence,
            recorded_at_unix_ms: unix_now_ms(),
            kind,
        };
        self.next_trace_sequence = self.next_trace_sequence.saturating_add(1);

        let run = self.run_mut(run_id)?;
        run.trace.push(event);
        Ok(())
    }

    fn promote_ready_steps(&mut self, run_id: u64) -> Result<(), AgentOrchestrationError> {
        let promoted = {
            let run = self.run_mut(run_id)?;
            let completed = run
                .steps
                .iter()
                .filter(|step| matches!(step.status, AgentStepStatus::Completed))
                .map(|step| step.step_id.clone())
                .collect::<HashSet<_>>();
            let mut promoted = Vec::new();
            for step in &mut run.steps {
                if !matches!(step.status, AgentStepStatus::Blocked) {
                    continue;
                }
                let ready = step.depends_on.iter().all(|dep| completed.contains(dep));
                if ready {
                    step.status = AgentStepStatus::Queued;
                    promoted.push(step.step_id.clone());
                }
            }
            promoted
        };

        for step_id in promoted {
            self.push_trace(run_id, AgentTraceEventKind::StepQueued { step_id })?;
        }
        Ok(())
    }

    fn recompute_run_status(&mut self, run_id: u64) -> Result<(), AgentOrchestrationError> {
        let transition = {
            let run = self.run_mut(run_id)?;
            let previous = run.status;
            let next = if run
                .steps
                .iter()
                .all(|step| matches!(step.status, AgentStepStatus::Completed))
            {
                AgentRunStatus::Completed
            } else if run
                .steps
                .iter()
                .any(|step| matches!(step.status, AgentStepStatus::Failed))
            {
                AgentRunStatus::Failed
            } else if run
                .steps
                .iter()
                .any(|step| matches!(step.status, AgentStepStatus::WaitingApproval))
            {
                AgentRunStatus::WaitingApproval
            } else {
                AgentRunStatus::Active
            };
            run.status = next;

            if previous != next {
                let failure_reason = run
                    .steps
                    .iter()
                    .find(|step| matches!(step.status, AgentStepStatus::Failed))
                    .and_then(|step| step.last_error.clone())
                    .unwrap_or_else(|| "unknown failure".to_string());
                Some((next, failure_reason))
            } else {
                None
            }
        };

        if let Some((next, failure_reason)) = transition {
            match next {
                AgentRunStatus::Completed => {
                    self.push_trace(run_id, AgentTraceEventKind::RunCompleted { run_id })?;
                }
                AgentRunStatus::Failed => {
                    self.push_trace(
                        run_id,
                        AgentTraceEventKind::RunFailed {
                            run_id,
                            reason: failure_reason,
                        },
                    )?;
                }
                AgentRunStatus::Active | AgentRunStatus::WaitingApproval => {}
            }
        }

        Ok(())
    }
}

fn find_step_mut<'a>(run: &'a mut AgentRun, step_id: &str) -> Option<&'a mut AgentStep> {
    run.steps.iter_mut().find(|step| step.step_id == step_id)
}

fn validate_graph(graph: &[AgentGraphNode]) -> Result<(), AgentOrchestrationError> {
    if graph.is_empty() {
        return Err(AgentOrchestrationError::EmptyGraph);
    }

    let mut ids = HashSet::new();
    for node in graph {
        if !ids.insert(node.step_id.clone()) {
            return Err(AgentOrchestrationError::DuplicateStepId(
                node.step_id.clone(),
            ));
        }
    }

    let id_set = graph
        .iter()
        .map(|node| node.step_id.clone())
        .collect::<HashSet<_>>();
    for node in graph {
        for dependency in &node.depends_on {
            if !id_set.contains(dependency) {
                return Err(AgentOrchestrationError::UnknownDependency {
                    step_id: node.step_id.clone(),
                    dependency: dependency.clone(),
                });
            }
        }
    }

    let adjacency = graph
        .iter()
        .map(|node| (node.step_id.clone(), node.depends_on.clone()))
        .collect::<HashMap<_, _>>();
    if let Some(step_id) = detect_cycle(&adjacency) {
        return Err(AgentOrchestrationError::CycleDetected(step_id));
    }

    Ok(())
}

fn validate_restored_run(run: &AgentRun) -> Result<(), AgentOrchestrationError> {
    if run.steps.is_empty() {
        return Err(AgentOrchestrationError::InvalidRun(format!(
            "run {} has no steps",
            run.run_id
        )));
    }

    let mut ids = HashSet::new();
    for step in &run.steps {
        if !ids.insert(step.step_id.clone()) {
            return Err(AgentOrchestrationError::InvalidRun(format!(
                "run {} duplicate step id: {}",
                run.run_id, step.step_id
            )));
        }
    }

    let id_set = run
        .steps
        .iter()
        .map(|step| step.step_id.clone())
        .collect::<HashSet<_>>();
    let mut adjacency = HashMap::new();
    for step in &run.steps {
        for dependency in &step.depends_on {
            if !id_set.contains(dependency) {
                return Err(AgentOrchestrationError::InvalidRun(format!(
                    "run {} step {} depends on unknown {}",
                    run.run_id, step.step_id, dependency
                )));
            }
        }
        adjacency.insert(step.step_id.clone(), step.depends_on.clone());
    }

    if let Some(cycle) = detect_cycle(&adjacency) {
        return Err(AgentOrchestrationError::InvalidRun(format!(
            "run {} contains dependency cycle at {}",
            run.run_id, cycle
        )));
    }

    Ok(())
}

fn detect_cycle(adjacency: &HashMap<String, Vec<String>>) -> Option<String> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Visit {
        Visiting,
        Visited,
    }

    fn dfs(
        node: &str,
        adjacency: &HashMap<String, Vec<String>>,
        marks: &mut HashMap<String, Visit>,
    ) -> Option<String> {
        if let Some(mark) = marks.get(node) {
            if *mark == Visit::Visiting {
                return Some(node.to_string());
            }
            return None;
        }

        marks.insert(node.to_string(), Visit::Visiting);
        if let Some(dependencies) = adjacency.get(node) {
            for dependency in dependencies {
                if let Some(cycle) = dfs(dependency, adjacency, marks) {
                    return Some(cycle);
                }
            }
        }
        marks.insert(node.to_string(), Visit::Visited);
        None
    }

    let mut marks = HashMap::new();
    for node in adjacency.keys() {
        if let Some(cycle) = dfs(node, adjacency, &mut marks) {
            return Some(cycle);
        }
    }
    None
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{
        AgentGraphNode, AgentOrchestrationError, AgentOrchestrator, AgentRole, AgentRunStatus,
        AgentStepStatus, AgentTraceEventKind, RetryPolicy,
    };

    fn build_linear_graph() -> Vec<AgentGraphNode> {
        vec![
            AgentGraphNode::new(
                "planner",
                "Plan work",
                AgentRole::Planner,
                "Create execution plan",
            ),
            AgentGraphNode::new(
                "coder",
                "Implement changes",
                AgentRole::Coder,
                "Write and test code",
            )
            .with_dependencies(vec!["planner".to_string()])
            .with_approval(true),
            AgentGraphNode::new(
                "verifier",
                "Verify outcome",
                AgentRole::Verifier,
                "Confirm behavior and quality gates",
            )
            .with_dependencies(vec!["coder".to_string()]),
        ]
    }

    #[test]
    fn create_run_rejects_duplicate_step_ids() {
        let mut orchestrator = AgentOrchestrator::new();
        let graph = vec![
            AgentGraphNode::new("planner", "Plan", AgentRole::Planner, "Plan"),
            AgentGraphNode::new("planner", "Duplicate", AgentRole::Coder, "Code"),
        ];

        let result = orchestrator.create_run("duplicate-step-check", graph, RetryPolicy::default());
        assert!(matches!(
            result,
            Err(AgentOrchestrationError::DuplicateStepId(_))
        ));
    }

    #[test]
    fn create_run_rejects_unknown_dependency() {
        let mut orchestrator = AgentOrchestrator::new();
        let graph = vec![
            AgentGraphNode::new("planner", "Plan", AgentRole::Planner, "Plan")
                .with_dependencies(vec!["missing".to_string()]),
        ];

        let result = orchestrator.create_run("unknown-dependency", graph, RetryPolicy::default());
        assert!(matches!(
            result,
            Err(AgentOrchestrationError::UnknownDependency { .. })
        ));
    }

    #[test]
    fn run_completes_with_approval_and_retry_flow() {
        let mut orchestrator = AgentOrchestrator::new();
        let run_result =
            orchestrator.create_run("phase2-agent-v1", build_linear_graph(), RetryPolicy::new(2));
        assert!(run_result.is_ok());
        let run_id = match run_result {
            Ok(value) => value,
            Err(_) => return,
        };

        let first = orchestrator.start_next_step(run_id);
        assert!(matches!(first, Ok(Some(ref step)) if step == "planner"));
        let planner_complete = orchestrator.complete_step(run_id, "planner", "plan ready");
        assert!(planner_complete.is_ok());

        let second = orchestrator.start_next_step(run_id);
        assert!(matches!(second, Ok(Some(ref step)) if step == "coder"));
        let approval_request =
            orchestrator.request_approval(run_id, "coder", "code touches runtime");
        assert!(approval_request.is_ok());
        let approval_resolve = orchestrator.resolve_approval(run_id, "coder", true, "approved");
        assert!(approval_resolve.is_ok());

        let restart = orchestrator.start_next_step(run_id);
        assert!(matches!(restart, Ok(Some(ref step)) if step == "coder"));
        let first_fail = orchestrator.fail_step(run_id, "coder", "transient compile failure");
        assert!(first_fail.is_ok());

        let retry_start = orchestrator.start_next_step(run_id);
        assert!(matches!(retry_start, Ok(Some(ref step)) if step == "coder"));
        let coder_complete = orchestrator.complete_step(run_id, "coder", "impl done");
        assert!(coder_complete.is_ok());

        let verifier_start = orchestrator.start_next_step(run_id);
        assert!(matches!(verifier_start, Ok(Some(ref step)) if step == "verifier"));
        let verifier_complete = orchestrator.complete_step(run_id, "verifier", "verified");
        assert!(verifier_complete.is_ok());

        let run = orchestrator.run(run_id);
        assert!(run.is_some());
        let run = match run {
            Some(value) => value,
            None => return,
        };
        assert_eq!(run.status, AgentRunStatus::Completed);

        let has_retry = run
            .trace
            .iter()
            .any(|event| matches!(event.kind, AgentTraceEventKind::StepRetried { .. }));
        assert!(has_retry);
        let has_approval = run.trace.iter().any(|event| {
            matches!(
                event.kind,
                AgentTraceEventKind::ApprovalRequested { .. }
                    | AgentTraceEventKind::ApprovalResolved { .. }
            )
        });
        assert!(has_approval);
        let has_completed = run
            .trace
            .iter()
            .any(|event| matches!(event.kind, AgentTraceEventKind::RunCompleted { .. }));
        assert!(has_completed);
    }

    #[test]
    fn approval_denial_fails_run() {
        let mut orchestrator = AgentOrchestrator::new();
        let run_result = orchestrator.create_run(
            "approval-denial",
            build_linear_graph(),
            RetryPolicy::default(),
        );
        assert!(run_result.is_ok());
        let run_id = match run_result {
            Ok(value) => value,
            Err(_) => return,
        };

        let _ = orchestrator.start_next_step(run_id);
        let _ = orchestrator.complete_step(run_id, "planner", "plan done");
        let _ = orchestrator.start_next_step(run_id);
        let _ = orchestrator.request_approval(run_id, "coder", "needs review");
        let deny = orchestrator.resolve_approval(run_id, "coder", false, "unsafe scope");
        assert!(deny.is_ok());

        let run = orchestrator.run(run_id);
        assert!(run.is_some());
        let run = match run {
            Some(value) => value,
            None => return,
        };
        assert_eq!(run.status, AgentRunStatus::Failed);

        let coder = run.steps.iter().find(|step| step.step_id == "coder");
        assert!(coder.is_some());
        let coder = match coder {
            Some(value) => value,
            None => return,
        };
        assert_eq!(coder.status, AgentStepStatus::Failed);
    }

    #[test]
    fn restore_runs_round_trip_preserves_trace_and_counters() {
        let mut orchestrator = AgentOrchestrator::new();
        let run_result = orchestrator.create_run(
            "restore-roundtrip",
            build_linear_graph(),
            RetryPolicy::new(2),
        );
        assert!(run_result.is_ok());
        let run_id = match run_result {
            Ok(value) => value,
            Err(_) => return,
        };

        let _ = orchestrator.start_next_step(run_id);
        let _ = orchestrator.complete_step(run_id, "planner", "plan done");
        let _ = orchestrator.start_next_step(run_id);
        let _ = orchestrator.fail_step(run_id, "coder", "retry me");

        let snapshot = orchestrator.runs_snapshot();
        let mut restored = AgentOrchestrator::new();
        let restore_result = restored.restore_runs(snapshot.clone());
        assert!(restore_result.is_ok());

        let restored_run = restored.run(run_id);
        assert!(restored_run.is_some());
        let restored_run = match restored_run {
            Some(value) => value,
            None => return,
        };
        let original_run = snapshot.iter().find(|run| run.run_id == run_id);
        assert!(original_run.is_some());
        let original_run = match original_run {
            Some(value) => value,
            None => return,
        };
        assert_eq!(restored_run.trace.len(), original_run.trace.len());

        let new_run = restored.create_run("new-run", build_linear_graph(), RetryPolicy::default());
        assert!(matches!(new_run, Ok(value) if value > run_id));
    }

    #[test]
    fn restore_runs_rejects_invalid_dependency() {
        let invalid_run = super::AgentRun {
            run_id: 7,
            goal: "invalid".to_string(),
            status: AgentRunStatus::Active,
            steps: vec![super::AgentStep {
                step_id: "coder".to_string(),
                title: "Code".to_string(),
                role: AgentRole::Coder,
                instruction: "Implement".to_string(),
                depends_on: vec!["missing".to_string()],
                requires_approval: false,
                status: AgentStepStatus::Blocked,
                attempt_count: 0,
                max_attempts: 2,
                output: None,
                last_error: None,
            }],
            trace: Vec::new(),
        };

        let mut orchestrator = AgentOrchestrator::new();
        let result = orchestrator.restore_runs(vec![invalid_run]);
        assert!(matches!(
            result,
            Err(AgentOrchestrationError::InvalidRun(_))
        ));
    }
}
