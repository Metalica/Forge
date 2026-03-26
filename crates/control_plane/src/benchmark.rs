use crate::scheduler::{SchedulerPlacementEngine, WorkerCandidate, WorkloadPlacementHint};
use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use urm::topology::{TopologyObjectSnapshot, TopologySnapshot, TopologySource, TopologySummary};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueBenchmarkConfig {
    pub iterations: usize,
    pub worker_count: usize,
    pub outstanding_window: usize,
}

impl Default for QueueBenchmarkConfig {
    fn default() -> Self {
        Self {
            iterations: 20_000,
            worker_count: 16,
            outstanding_window: 96,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct QueueBenchmarkMetrics {
    pub workload: &'static str,
    pub operations: u64,
    pub elapsed_ms: u128,
    pub throughput_ops_per_sec: f64,
    pub p50_latency_us: u64,
    pub p95_latency_us: u64,
    pub max_latency_us: u64,
    pub peak_live_bytes: usize,
    pub peak_reserved_bytes: usize,
    pub fragmentation_permille: u64,
}

pub fn run_queue_benchmark(config: QueueBenchmarkConfig) -> QueueBenchmarkMetrics {
    if config.iterations == 0 || config.worker_count == 0 {
        return QueueBenchmarkMetrics {
            workload: "queue",
            operations: 0,
            elapsed_ms: 0,
            throughput_ops_per_sec: 0.0,
            p50_latency_us: 0,
            p95_latency_us: 0,
            max_latency_us: 0,
            peak_live_bytes: 0,
            peak_reserved_bytes: 0,
            fragmentation_permille: 0,
        };
    }

    let topology = synthetic_topology(config.worker_count);
    let engine = SchedulerPlacementEngine::topology_aware(topology);
    let mut workers: Vec<WorkerCandidate> = (0..config.worker_count)
        .map(|index| WorkerCandidate::new(format!("worker-{index:02}"), index as u32, 0))
        .collect();
    let mut active_buffers: VecDeque<Vec<u8>> = VecDeque::with_capacity(config.outstanding_window);
    let mut latencies_us: Vec<u64> = Vec::with_capacity(config.iterations);
    let mut peak_live_bytes = 0usize;
    let mut peak_reserved_bytes = 0usize;

    let suite_start = Instant::now();
    for iteration in 0..config.iterations {
        let start = Instant::now();
        let hint = WorkloadPlacementHint {
            preferred_numa_node_os_index: Some((iteration % 2) as u32),
            preferred_socket_os_index: Some((iteration % 2) as u32),
            preferred_processing_unit_os_index: Some((iteration % config.worker_count) as u32),
        };

        let selected = engine.select_worker(&workers, hint);
        if let Some(selected) = selected {
            if let Some(worker) = workers
                .iter_mut()
                .find(|value| value.worker_id == selected.worker_id)
            {
                worker.inflight_jobs = worker.inflight_jobs.saturating_add(1);
            }

            // Allocation churn approximates queue payload pressure for allocator comparison.
            let payload_size = 512usize + ((iteration * 97) % 8192);
            let mut payload = vec![0u8; payload_size];
            for (index, byte) in payload.iter_mut().enumerate().step_by(97) {
                *byte = ((iteration + index) % 251) as u8;
            }
            active_buffers.push_back(payload);
            while active_buffers.len() > config.outstanding_window {
                let _ = active_buffers.pop_front();
            }

            if iteration % 2 == 0
                && let Some(worker) = workers
                    .iter_mut()
                    .find(|value| value.worker_id == selected.worker_id)
            {
                worker.inflight_jobs = worker.inflight_jobs.saturating_sub(1);
            }
        }

        let elapsed = start.elapsed();
        latencies_us.push(duration_to_us(elapsed));

        let (live_bytes, reserved_bytes) = buffer_bytes(&active_buffers);
        peak_live_bytes = peak_live_bytes.max(live_bytes);
        peak_reserved_bytes = peak_reserved_bytes.max(reserved_bytes);
    }
    let elapsed = suite_start.elapsed();

    let operations = config.iterations as u64;
    let throughput_ops_per_sec = if elapsed.is_zero() {
        0.0
    } else {
        operations as f64 / elapsed.as_secs_f64()
    };
    let (p50_latency_us, p95_latency_us, max_latency_us) = latency_summary_us(&latencies_us);
    let fragmentation_permille = fragmentation_permille(peak_live_bytes, peak_reserved_bytes);

    QueueBenchmarkMetrics {
        workload: "queue",
        operations,
        elapsed_ms: elapsed.as_millis(),
        throughput_ops_per_sec,
        p50_latency_us,
        p95_latency_us,
        max_latency_us,
        peak_live_bytes,
        peak_reserved_bytes,
        fragmentation_permille,
    }
}

fn buffer_bytes(buffers: &VecDeque<Vec<u8>>) -> (usize, usize) {
    buffers.iter().fold((0usize, 0usize), |acc, buffer| {
        (
            acc.0.saturating_add(buffer.len()),
            acc.1.saturating_add(buffer.capacity()),
        )
    })
}

fn duration_to_us(duration: Duration) -> u64 {
    duration.as_micros().min(u64::MAX as u128) as u64
}

fn latency_summary_us(latencies_us: &[u64]) -> (u64, u64, u64) {
    if latencies_us.is_empty() {
        return (0, 0, 0);
    }
    let mut sorted = latencies_us.to_vec();
    sorted.sort_unstable();
    let max_latency_us = *sorted.last().unwrap_or(&0);
    let p50 = percentile_u64(&sorted, 50);
    let p95 = percentile_u64(&sorted, 95);
    (p50, p95, max_latency_us)
}

fn percentile_u64(sorted_values: &[u64], percentile: usize) -> u64 {
    if sorted_values.is_empty() {
        return 0;
    }
    let last = sorted_values.len().saturating_sub(1);
    let index = (last.saturating_mul(percentile)) / 100;
    sorted_values[index]
}

fn fragmentation_permille(peak_live_bytes: usize, peak_reserved_bytes: usize) -> u64 {
    if peak_live_bytes == 0 || peak_reserved_bytes <= peak_live_bytes {
        return 0;
    }
    let slack = peak_reserved_bytes.saturating_sub(peak_live_bytes);
    ((slack as u128).saturating_mul(1000) / peak_live_bytes as u128) as u64
}

fn synthetic_topology(worker_count: usize) -> TopologySnapshot {
    let capped_workers = worker_count.max(1);
    let socket_count = if capped_workers > 1 { 2 } else { 1 };
    let workers_per_socket = capped_workers.div_ceil(socket_count);

    let sockets: Vec<TopologyObjectSnapshot> = (0..socket_count)
        .map(|socket| {
            let range_start = socket * workers_per_socket;
            let range_end = ((socket + 1) * workers_per_socket).min(capped_workers);
            let cpuset = if range_end > range_start {
                format!("{range_start}-{}", range_end - 1)
            } else {
                range_start.to_string()
            };
            TopologyObjectSnapshot {
                object_type: "Package".to_string(),
                logical_index: socket as u32,
                os_index: socket as u32,
                depth: 0,
                cpuset: Some(cpuset),
                nodeset: None,
            }
        })
        .collect();

    let numa_nodes: Vec<TopologyObjectSnapshot> = sockets
        .iter()
        .enumerate()
        .map(|(index, socket)| TopologyObjectSnapshot {
            object_type: "NUMANode".to_string(),
            logical_index: index as u32,
            os_index: index as u32,
            depth: 0,
            cpuset: socket.cpuset.clone(),
            nodeset: None,
        })
        .collect();

    let processing_units: Vec<TopologyObjectSnapshot> = (0..capped_workers)
        .map(|index| TopologyObjectSnapshot {
            object_type: "PU".to_string(),
            logical_index: index as u32,
            os_index: index as u32,
            depth: 0,
            cpuset: Some(index.to_string()),
            nodeset: None,
        })
        .collect();

    TopologySnapshot {
        schema_version: 1,
        source: TopologySource::Fallback,
        captured_at_unix_ms: current_time_unix_ms(),
        summary: TopologySummary {
            numa_node_count: numa_nodes.len() as u32,
            socket_count: sockets.len() as u32,
            shared_cache_count: 0,
            core_count: capped_workers as u32,
            processing_unit_count: processing_units.len() as u32,
            smt_enabled: false,
        },
        numa_nodes,
        sockets,
        shared_caches: Vec::new(),
        cores: Vec::new(),
        processing_units,
    }
}

fn current_time_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{QueueBenchmarkConfig, run_queue_benchmark};

    #[test]
    fn queue_benchmark_emits_nonzero_metrics() {
        let metrics = run_queue_benchmark(QueueBenchmarkConfig {
            iterations: 200,
            worker_count: 8,
            outstanding_window: 32,
        });
        assert_eq!(metrics.workload, "queue");
        assert_eq!(metrics.operations, 200);
        assert!(metrics.elapsed_ms <= 30_000);
        assert!(metrics.p95_latency_us >= metrics.p50_latency_us);
        assert!(metrics.max_latency_us >= metrics.p95_latency_us);
        assert!(metrics.peak_reserved_bytes >= metrics.peak_live_bytes);
    }
}
