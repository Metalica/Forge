use urm::topology::{
    NumaPlacementPolicy, NumaPolicyMode, ProcessingUnitLocality, TopologySnapshot,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlacementMode {
    Baseline,
    TopologyAware,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WorkloadPlacementHint {
    pub preferred_numa_node_os_index: Option<u32>,
    pub preferred_socket_os_index: Option<u32>,
    pub preferred_processing_unit_os_index: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerCandidate {
    pub worker_id: String,
    pub processing_unit_os_index: u32,
    pub inflight_jobs: u32,
}

impl WorkerCandidate {
    pub fn new(
        worker_id: impl Into<String>,
        processing_unit_os_index: u32,
        inflight_jobs: u32,
    ) -> Self {
        Self {
            worker_id: worker_id.into(),
            processing_unit_os_index,
            inflight_jobs,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementDecision {
    pub worker_id: String,
    pub score: i64,
    pub locality: Option<ProcessingUnitLocality>,
    pub reason: String,
}

impl PlacementDecision {
    pub fn recommended_numa_policy(&self) -> NumaPlacementPolicy {
        let Some(locality) = self.locality else {
            return NumaPlacementPolicy::disabled();
        };
        let Some(numa_node_os_index) = locality.numa_node_os_index else {
            return NumaPlacementPolicy::disabled();
        };

        NumaPlacementPolicy {
            mode: NumaPolicyMode::Bind,
            numa_node_os_index: Some(numa_node_os_index),
            cpu_os_index: Some(locality.processing_unit_os_index),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SchedulerPlacementEngine {
    mode: PlacementMode,
    topology: Option<TopologySnapshot>,
}

impl SchedulerPlacementEngine {
    pub fn baseline() -> Self {
        Self {
            mode: PlacementMode::Baseline,
            topology: None,
        }
    }

    pub fn topology_aware(topology: TopologySnapshot) -> Self {
        Self {
            mode: PlacementMode::TopologyAware,
            topology: Some(topology),
        }
    }

    pub fn select_worker(
        &self,
        workers: &[WorkerCandidate],
        hint: WorkloadPlacementHint,
    ) -> Option<PlacementDecision> {
        let mut best: Option<PlacementDecision> = None;
        for worker in workers {
            let (score, locality, reason) = self.score_candidate(worker, hint);
            let decision = PlacementDecision {
                worker_id: worker.worker_id.clone(),
                score,
                locality,
                reason,
            };
            if is_better_decision(&decision, best.as_ref(), worker.inflight_jobs, workers) {
                best = Some(decision);
            }
        }
        best
    }

    fn score_candidate(
        &self,
        worker: &WorkerCandidate,
        hint: WorkloadPlacementHint,
    ) -> (i64, Option<ProcessingUnitLocality>, String) {
        let mut score = 1000i64 - (worker.inflight_jobs as i64 * 100);
        let mut reasons = vec!["least-load baseline".to_string()];

        if self.mode == PlacementMode::Baseline {
            return (score, None, reasons.join("; "));
        }

        let Some(topology) = &self.topology else {
            reasons.push("topology unavailable: baseline fallback".to_string());
            return (score, None, reasons.join("; "));
        };

        let locality = topology.processing_unit_locality(worker.processing_unit_os_index);

        if hint.preferred_processing_unit_os_index == Some(worker.processing_unit_os_index) {
            score += 180;
            reasons.push("matched preferred processing unit".to_string());
        }

        if let Some(locality) = locality {
            if hint.preferred_numa_node_os_index == locality.numa_node_os_index
                && hint.preferred_numa_node_os_index.is_some()
            {
                score += 80;
                reasons.push("matched preferred NUMA node".to_string());
            } else if hint.preferred_numa_node_os_index.is_some()
                && locality.numa_node_os_index.is_some()
            {
                score -= 30;
            }

            if hint.preferred_socket_os_index == locality.socket_os_index
                && hint.preferred_socket_os_index.is_some()
            {
                score += 40;
                reasons.push("matched preferred socket".to_string());
            } else if hint.preferred_socket_os_index.is_some() && locality.socket_os_index.is_some()
            {
                score -= 15;
            }

            return (score, Some(locality), reasons.join("; "));
        }

        reasons.push("worker locality unknown in topology snapshot".to_string());
        (score, None, reasons.join("; "))
    }
}

fn is_better_decision(
    candidate: &PlacementDecision,
    current: Option<&PlacementDecision>,
    candidate_inflight: u32,
    workers: &[WorkerCandidate],
) -> bool {
    let Some(current) = current else {
        return true;
    };
    if candidate.score > current.score {
        return true;
    }
    if candidate.score < current.score {
        return false;
    }

    let current_inflight = workers
        .iter()
        .find(|worker| worker.worker_id == current.worker_id)
        .map(|worker| worker.inflight_jobs)
        .unwrap_or(u32::MAX);
    if candidate_inflight < current_inflight {
        return true;
    }
    if candidate_inflight > current_inflight {
        return false;
    }

    candidate.worker_id < current.worker_id
}

#[cfg(test)]
mod tests {
    use super::{PlacementMode, SchedulerPlacementEngine, WorkerCandidate, WorkloadPlacementHint};
    use urm::topology::{
        NumaPolicyMode, TopologyObjectSnapshot, TopologySnapshot, TopologySource, TopologySummary,
    };

    fn sample_topology() -> TopologySnapshot {
        TopologySnapshot {
            schema_version: 1,
            source: TopologySource::Fallback,
            captured_at_unix_ms: 0,
            summary: TopologySummary {
                numa_node_count: 2,
                socket_count: 2,
                shared_cache_count: 0,
                core_count: 4,
                processing_unit_count: 4,
                smt_enabled: false,
            },
            numa_nodes: vec![
                TopologyObjectSnapshot {
                    object_type: "NUMANode".to_string(),
                    logical_index: 0,
                    os_index: 0,
                    depth: 0,
                    cpuset: Some("0-1".to_string()),
                    nodeset: None,
                },
                TopologyObjectSnapshot {
                    object_type: "NUMANode".to_string(),
                    logical_index: 1,
                    os_index: 1,
                    depth: 0,
                    cpuset: Some("2-3".to_string()),
                    nodeset: None,
                },
            ],
            sockets: vec![
                TopologyObjectSnapshot {
                    object_type: "Package".to_string(),
                    logical_index: 0,
                    os_index: 0,
                    depth: 0,
                    cpuset: Some("0-1".to_string()),
                    nodeset: None,
                },
                TopologyObjectSnapshot {
                    object_type: "Package".to_string(),
                    logical_index: 1,
                    os_index: 1,
                    depth: 0,
                    cpuset: Some("2-3".to_string()),
                    nodeset: None,
                },
            ],
            shared_caches: Vec::new(),
            cores: Vec::new(),
            processing_units: vec![
                TopologyObjectSnapshot {
                    object_type: "PU".to_string(),
                    logical_index: 0,
                    os_index: 0,
                    depth: 0,
                    cpuset: Some("0".to_string()),
                    nodeset: None,
                },
                TopologyObjectSnapshot {
                    object_type: "PU".to_string(),
                    logical_index: 1,
                    os_index: 1,
                    depth: 0,
                    cpuset: Some("1".to_string()),
                    nodeset: None,
                },
                TopologyObjectSnapshot {
                    object_type: "PU".to_string(),
                    logical_index: 2,
                    os_index: 2,
                    depth: 0,
                    cpuset: Some("2".to_string()),
                    nodeset: None,
                },
                TopologyObjectSnapshot {
                    object_type: "PU".to_string(),
                    logical_index: 3,
                    os_index: 3,
                    depth: 0,
                    cpuset: Some("3".to_string()),
                    nodeset: None,
                },
            ],
        }
    }

    #[test]
    fn baseline_prefers_least_loaded_worker() {
        let engine = SchedulerPlacementEngine::baseline();
        let workers = vec![
            WorkerCandidate::new("worker-a", 0, 2),
            WorkerCandidate::new("worker-b", 1, 0),
            WorkerCandidate::new("worker-c", 2, 1),
        ];
        let selected = engine.select_worker(&workers, WorkloadPlacementHint::default());
        assert!(selected.is_some());
        let selected = match selected {
            Some(value) => value,
            None => return,
        };
        assert_eq!(selected.worker_id, "worker-b");
    }

    #[test]
    fn topology_aware_prefers_locality_over_baseline_tie_break() {
        let topology = sample_topology();
        let workers = vec![
            WorkerCandidate::new("worker-a", 0, 1),
            WorkerCandidate::new("worker-b", 2, 1),
        ];

        let baseline = SchedulerPlacementEngine::baseline();
        let baseline_selected = baseline.select_worker(
            &workers,
            WorkloadPlacementHint {
                preferred_numa_node_os_index: Some(1),
                ..WorkloadPlacementHint::default()
            },
        );
        assert!(baseline_selected.is_some());
        let baseline_selected = match baseline_selected {
            Some(value) => value,
            None => return,
        };
        assert_eq!(baseline_selected.worker_id, "worker-a");

        let topology_aware = SchedulerPlacementEngine::topology_aware(topology);
        assert_eq!(topology_aware.mode, PlacementMode::TopologyAware);
        let topology_selected = topology_aware.select_worker(
            &workers,
            WorkloadPlacementHint {
                preferred_numa_node_os_index: Some(1),
                ..WorkloadPlacementHint::default()
            },
        );
        assert!(topology_selected.is_some());
        let topology_selected = match topology_selected {
            Some(value) => value,
            None => return,
        };
        assert_eq!(topology_selected.worker_id, "worker-b");
        assert!(topology_selected.reason.contains("NUMA"));
    }

    #[test]
    fn preferred_processing_unit_has_highest_weight() {
        let topology_aware = SchedulerPlacementEngine::topology_aware(sample_topology());
        let workers = vec![
            WorkerCandidate::new("worker-a", 0, 1),
            WorkerCandidate::new("worker-b", 1, 1),
        ];
        let selected = topology_aware.select_worker(
            &workers,
            WorkloadPlacementHint {
                preferred_processing_unit_os_index: Some(1),
                ..WorkloadPlacementHint::default()
            },
        );
        assert!(selected.is_some());
        let selected = match selected {
            Some(value) => value,
            None => return,
        };
        assert_eq!(selected.worker_id, "worker-b");
    }

    #[test]
    fn placement_decision_emits_bind_numa_policy_when_locality_is_known() {
        let topology_aware = SchedulerPlacementEngine::topology_aware(sample_topology());
        let workers = vec![
            WorkerCandidate::new("worker-a", 0, 1),
            WorkerCandidate::new("worker-b", 2, 1),
        ];
        let selected = topology_aware.select_worker(
            &workers,
            WorkloadPlacementHint {
                preferred_numa_node_os_index: Some(1),
                ..WorkloadPlacementHint::default()
            },
        );
        assert!(selected.is_some());
        let selected = match selected {
            Some(value) => value,
            None => return,
        };

        let policy = selected.recommended_numa_policy();
        assert_eq!(policy.mode, NumaPolicyMode::Bind);
        assert_eq!(policy.numa_node_os_index, Some(1));
        assert_eq!(policy.cpu_os_index, Some(2));
    }
}
