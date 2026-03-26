use crate::jobs::{JobKind, JobPriority, JobQueue};
use crate::safety::SessionSafetyMonitor;
use control_plane::lmdb_metadata::open_lmdb_metadata_store;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::error::Error;
use std::fmt;
use std::fs;
use std::mem::size_of;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use urm::lmdb_metadata::LmdbMetadataStore;

#[derive(Debug, Clone, PartialEq, Eq)]
struct MetadataIndexStoreError {
    message: String,
}

impl MetadataIndexStoreError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for MetadataIndexStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for MetadataIndexStoreError {}

impl From<MetadataIndexStoreError> for String {
    fn from(value: MetadataIndexStoreError) -> Self {
        value.to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentBenchmarkConfig {
    pub iterations: usize,
    pub outstanding_window: usize,
}

impl Default for AgentBenchmarkConfig {
    fn default() -> Self {
        Self {
            iterations: 18_000,
            outstanding_window: 128,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexBenchmarkConfig {
    pub documents: usize,
    pub tokens_per_document: usize,
    pub retained_documents: usize,
}

impl Default for IndexBenchmarkConfig {
    fn default() -> Self {
        Self {
            documents: 1_200,
            tokens_per_document: 192,
            retained_documents: 96,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WorkloadMetrics {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IndexingStoreMode {
    Lmdb,
    LegacyInMemory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexBenchmarkBackend {
    Lmdb,
    LegacyInMemory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexedDocumentRecord {
    key: String,
    terms: Vec<String>,
    live_bytes: usize,
    reserved_bytes: usize,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexingParitySnapshot {
    retained_documents: Vec<String>,
    retained_payload_lengths: HashMap<String, usize>,
    term_postings: HashMap<String, Vec<String>>,
}

trait MetadataIndexStore {
    fn put_document(&mut self, key: &str, payload: &[u8]) -> Result<(), MetadataIndexStoreError>;
    fn get_document(&self, key: &str) -> Result<Option<Vec<u8>>, String>;
    fn delete_document(&mut self, key: &str) -> Result<bool, String>;
    fn add_term_document(
        &mut self,
        term: &str,
        document_id: &str,
    ) -> Result<(), MetadataIndexStoreError>;
    fn remove_term_document(&mut self, term: &str, document_id: &str) -> Result<bool, String>;
    fn lookup_term(&self, term: &str) -> Result<Vec<String>, String>;
}

#[derive(Debug, Default)]
struct InMemoryMetadataIndexStore {
    metadata: HashMap<String, Vec<u8>>,
    index: HashMap<String, BTreeSet<String>>,
}

impl MetadataIndexStore for InMemoryMetadataIndexStore {
    fn put_document(&mut self, key: &str, payload: &[u8]) -> Result<(), MetadataIndexStoreError> {
        self.metadata.insert(key.to_string(), payload.to_vec());
        Ok(())
    }

    fn get_document(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(self.metadata.get(key).cloned())
    }

    fn delete_document(&mut self, key: &str) -> Result<bool, String> {
        Ok(self.metadata.remove(key).is_some())
    }

    fn add_term_document(
        &mut self,
        term: &str,
        document_id: &str,
    ) -> Result<(), MetadataIndexStoreError> {
        self.index
            .entry(term.to_string())
            .or_default()
            .insert(document_id.to_string());
        Ok(())
    }

    fn remove_term_document(&mut self, term: &str, document_id: &str) -> Result<bool, String> {
        let Some(postings) = self.index.get_mut(term) else {
            return Ok(false);
        };
        let removed = postings.remove(document_id);
        if postings.is_empty() {
            self.index.remove(term);
        }
        Ok(removed)
    }

    fn lookup_term(&self, term: &str) -> Result<Vec<String>, String> {
        let postings = self
            .index
            .get(term)
            .map(|value| value.iter().cloned().collect())
            .unwrap_or_default();
        Ok(postings)
    }
}

struct LmdbMetadataIndexStore {
    root_dir: PathBuf,
    store: LmdbMetadataStore,
}

impl LmdbMetadataIndexStore {
    fn open_temporary() -> Result<Self, String> {
        let root_dir = unique_store_root("execution_plane_bench");
        let store = open_lmdb_metadata_store(&root_dir, false)
            .map_err(|error| format!("failed to open lmdb metadata store: {error}"))?;
        Ok(Self { root_dir, store })
    }
}

impl Drop for LmdbMetadataIndexStore {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root_dir);
    }
}

impl MetadataIndexStore for LmdbMetadataIndexStore {
    fn put_document(&mut self, key: &str, payload: &[u8]) -> Result<(), MetadataIndexStoreError> {
        self.store.put_metadata(key, payload).map_err(|error| {
            MetadataIndexStoreError::new(format!("lmdb put_metadata failed: {error}"))
        })
    }

    fn get_document(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        self.store
            .get_metadata(key)
            .map_err(|error| format!("lmdb get_metadata failed: {error}"))
    }

    fn delete_document(&mut self, key: &str) -> Result<bool, String> {
        self.store
            .delete_metadata(key)
            .map_err(|error| format!("lmdb delete_metadata failed: {error}"))
    }

    fn add_term_document(
        &mut self,
        term: &str,
        document_id: &str,
    ) -> Result<(), MetadataIndexStoreError> {
        self.store
            .add_index_entry(term, document_id)
            .map_err(|error| {
                MetadataIndexStoreError::new(format!("lmdb add_index_entry failed: {error}"))
            })
    }

    fn remove_term_document(&mut self, term: &str, document_id: &str) -> Result<bool, String> {
        self.store
            .remove_index_entry(term, document_id)
            .map_err(|error| format!("lmdb remove_index_entry failed: {error}"))
    }

    fn lookup_term(&self, term: &str) -> Result<Vec<String>, String> {
        self.store
            .lookup_index(term)
            .map_err(|error| format!("lmdb lookup_index failed: {error}"))
    }
}

pub fn run_agent_benchmark(config: AgentBenchmarkConfig) -> WorkloadMetrics {
    if config.iterations == 0 {
        return empty_metrics("agent");
    }

    let mut queue = JobQueue::new();
    let mut safety = SessionSafetyMonitor::default_runtime();
    let mut active_buffers: VecDeque<Vec<u8>> = VecDeque::with_capacity(config.outstanding_window);
    let mut latencies_us: Vec<u64> = Vec::with_capacity(config.iterations);
    let mut peak_live_bytes = 0usize;
    let mut peak_reserved_bytes = 0usize;

    let suite_start = Instant::now();
    for iteration in 0..config.iterations {
        let start = Instant::now();
        let priority = if iteration % 3 == 0 {
            JobPriority::Foreground
        } else {
            JobPriority::Normal
        };
        let job = queue.enqueue(
            format!("agent-step-{iteration:06}"),
            JobKind::AgentRun,
            priority,
        );
        let _ = queue.start_next();

        let key = format!("agent.{:02}", iteration % 12);
        if iteration % 9 == 0 {
            let _ = safety.record_failure(&key, "simulated transient tool failure");
            let _ = queue.fail(job, "simulated transient tool failure");
        } else {
            let _ = safety.record_success(&key);
            let _ = queue.complete(job);
        }

        let payload_size = 384usize + ((iteration * 131) % 7_168);
        let mut payload = Vec::with_capacity(payload_size + payload_size / 3);
        payload.resize(payload_size, 0u8);
        for (index, byte) in payload.iter_mut().enumerate().step_by(113) {
            *byte = ((iteration + index) % 251) as u8;
        }
        active_buffers.push_back(payload);
        while active_buffers.len() > config.outstanding_window {
            let _ = active_buffers.pop_front();
        }

        if iteration % 24 == 0 {
            let _ = queue.snapshot();
            let _ = safety.status("agent.00");
        }

        let elapsed = start.elapsed();
        latencies_us.push(duration_to_us(elapsed));
        let (live_bytes, reserved_bytes) = buffer_bytes(&active_buffers);
        peak_live_bytes = peak_live_bytes.max(live_bytes);
        peak_reserved_bytes = peak_reserved_bytes.max(reserved_bytes);
    }
    let elapsed = suite_start.elapsed();
    summarize_metrics(
        "agent",
        config.iterations as u64,
        elapsed,
        &latencies_us,
        peak_live_bytes,
        peak_reserved_bytes,
    )
}

pub fn run_indexing_benchmark(config: IndexBenchmarkConfig) -> WorkloadMetrics {
    run_indexing_benchmark_with_mode(config, IndexingStoreMode::Lmdb)
}

pub fn run_indexing_benchmark_with_backend(
    config: IndexBenchmarkConfig,
    backend: IndexBenchmarkBackend,
) -> WorkloadMetrics {
    let mode = match backend {
        IndexBenchmarkBackend::Lmdb => IndexingStoreMode::Lmdb,
        IndexBenchmarkBackend::LegacyInMemory => IndexingStoreMode::LegacyInMemory,
    };
    run_indexing_benchmark_with_mode(config, mode)
}

fn run_indexing_benchmark_with_mode(
    config: IndexBenchmarkConfig,
    mode: IndexingStoreMode,
) -> WorkloadMetrics {
    if config.documents == 0 || config.tokens_per_document == 0 {
        return empty_metrics("indexing");
    }

    let mut store = create_index_store(mode)
        .or_else(|_| create_index_store(IndexingStoreMode::LegacyInMemory))
        .unwrap_or_else(|_| Box::new(InMemoryMetadataIndexStore::default()) as Box<_>);
    let mut recent_documents: VecDeque<IndexedDocumentRecord> =
        VecDeque::with_capacity(config.retained_documents);
    let mut active_posting_counts: HashMap<String, usize> = HashMap::new();
    let mut latencies_us: Vec<u64> = Vec::with_capacity(config.documents);
    let mut peak_live_bytes = 0usize;
    let mut peak_reserved_bytes = 0usize;

    let suite_start = Instant::now();
    for doc_id in 0..config.documents {
        let start = Instant::now();
        let document_key = format!("doc:{doc_id:06}");
        let (document_payload, terms) = build_document(doc_id, config.tokens_per_document);

        let _ = store.put_document(&document_key, &document_payload);
        for term in &terms {
            let _ = store.add_term_document(term, &document_key);
            increment_term_count(&mut active_posting_counts, term);
        }

        recent_documents.push_back(IndexedDocumentRecord {
            key: document_key.clone(),
            terms,
            live_bytes: document_payload.len(),
            reserved_bytes: document_payload.capacity(),
        });

        while recent_documents.len() > config.retained_documents {
            let Some(evicted) = recent_documents.pop_front() else {
                break;
            };
            let _ = store.delete_document(&evicted.key);
            for term in &evicted.terms {
                let _ = store.remove_term_document(term, &evicted.key);
                decrement_term_count(&mut active_posting_counts, term);
            }
        }

        if doc_id % 16 == 0 {
            if let Some(term) = recent_documents
                .back()
                .and_then(|value| value.terms.first())
            {
                let _ = store.lookup_term(term);
            }
            let _ = store.get_document(&document_key);
        }

        let elapsed = start.elapsed();
        latencies_us.push(duration_to_us(elapsed));

        if doc_id % 8 == 0 || doc_id + 1 == config.documents {
            let (live_bytes, reserved_bytes) =
                estimate_index_memory(&active_posting_counts, &recent_documents);
            peak_live_bytes = peak_live_bytes.max(live_bytes);
            peak_reserved_bytes = peak_reserved_bytes.max(reserved_bytes);
        }
    }
    let elapsed = suite_start.elapsed();
    summarize_metrics(
        "indexing",
        config.documents as u64,
        elapsed,
        &latencies_us,
        peak_live_bytes,
        peak_reserved_bytes,
    )
}

#[cfg(test)]
fn collect_indexing_snapshot(
    config: IndexBenchmarkConfig,
    mode: IndexingStoreMode,
) -> Result<IndexingParitySnapshot, String> {
    let mut store = create_index_store(mode)?;
    let mut recent_documents: VecDeque<IndexedDocumentRecord> =
        VecDeque::with_capacity(config.retained_documents);
    let mut active_posting_counts: HashMap<String, usize> = HashMap::new();
    let mut evicted_document_keys = Vec::new();

    for doc_id in 0..config.documents {
        let document_key = format!("doc:{doc_id:06}");
        let (document_payload, terms) = build_document(doc_id, config.tokens_per_document);

        store.put_document(&document_key, &document_payload)?;
        for term in &terms {
            store.add_term_document(term, &document_key)?;
            increment_term_count(&mut active_posting_counts, term);
        }

        recent_documents.push_back(IndexedDocumentRecord {
            key: document_key.clone(),
            terms,
            live_bytes: document_payload.len(),
            reserved_bytes: document_payload.capacity(),
        });

        while recent_documents.len() > config.retained_documents {
            let Some(evicted) = recent_documents.pop_front() else {
                break;
            };
            let _ = store.delete_document(&evicted.key)?;
            for term in &evicted.terms {
                let _ = store.remove_term_document(term, &evicted.key)?;
                decrement_term_count(&mut active_posting_counts, term);
            }
            evicted_document_keys.push(evicted.key);
        }
    }

    for key in evicted_document_keys {
        if store.get_document(&key)?.is_some() {
            return Err(format!("evicted document still present in store: {key}"));
        }
    }

    let mut retained_documents = Vec::with_capacity(recent_documents.len());
    let mut retained_payload_lengths = HashMap::new();
    for record in &recent_documents {
        retained_documents.push(record.key.clone());
        let payload = store.get_document(&record.key)?;
        let Some(payload) = payload else {
            return Err(format!(
                "retained document missing from store: {}",
                record.key
            ));
        };
        retained_payload_lengths.insert(record.key.clone(), payload.len());
    }

    let mut term_postings = HashMap::new();
    for term in active_posting_counts.keys() {
        term_postings.insert(term.clone(), store.lookup_term(term)?);
    }

    Ok(IndexingParitySnapshot {
        retained_documents,
        retained_payload_lengths,
        term_postings,
    })
}

fn create_index_store(mode: IndexingStoreMode) -> Result<Box<dyn MetadataIndexStore>, String> {
    match mode {
        IndexingStoreMode::Lmdb => {
            let store = LmdbMetadataIndexStore::open_temporary()?;
            Ok(Box::new(store))
        }
        IndexingStoreMode::LegacyInMemory => Ok(Box::new(InMemoryMetadataIndexStore::default())),
    }
}

fn unique_store_root(label: &str) -> PathBuf {
    let mut root = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    root.push(format!("forge_indexing_lmdb_{label}_{nanos}"));
    root
}

fn build_document(doc_id: usize, tokens_per_document: usize) -> (Vec<u8>, Vec<String>) {
    let mut document_buffer =
        Vec::with_capacity(tokens_per_document.saturating_mul(10) + (doc_id % 64));
    let mut unique_terms = BTreeSet::new();
    for token_index in 0..tokens_per_document {
        let vocab = (token_index + doc_id * 7) % 4_096;
        let token = format!("tok_{vocab:04x}");
        unique_terms.insert(token);

        document_buffer.push(b'a' + (vocab % 26) as u8);
        if token_index % 21 == 0 {
            document_buffer.push(b' ');
        }
    }
    (document_buffer, unique_terms.into_iter().collect())
}

fn increment_term_count(term_counts: &mut HashMap<String, usize>, term: &str) {
    let count = term_counts.entry(term.to_string()).or_insert(0);
    *count = count.saturating_add(1);
}

fn decrement_term_count(term_counts: &mut HashMap<String, usize>, term: &str) {
    let Some(count) = term_counts.get_mut(term) else {
        return;
    };
    *count = count.saturating_sub(1);
    if *count == 0 {
        term_counts.remove(term);
    }
}

fn estimate_index_memory(
    active_posting_counts: &HashMap<String, usize>,
    recent_documents: &VecDeque<IndexedDocumentRecord>,
) -> (usize, usize) {
    let mut live_bytes = 0usize;
    let mut reserved_bytes = 0usize;
    for (term, posting_count) in active_posting_counts {
        let postings_bytes = posting_count.saturating_mul(size_of::<u32>());
        live_bytes = live_bytes
            .saturating_add(term.len())
            .saturating_add(postings_bytes);
        reserved_bytes = reserved_bytes
            .saturating_add(term.capacity())
            .saturating_add(postings_bytes);
    }
    for document in recent_documents {
        live_bytes = live_bytes.saturating_add(document.live_bytes);
        reserved_bytes = reserved_bytes.saturating_add(document.reserved_bytes);
    }
    (live_bytes, reserved_bytes)
}

fn buffer_bytes(buffers: &VecDeque<Vec<u8>>) -> (usize, usize) {
    buffers.iter().fold((0usize, 0usize), |acc, buffer| {
        (
            acc.0.saturating_add(buffer.len()),
            acc.1.saturating_add(buffer.capacity()),
        )
    })
}

fn summarize_metrics(
    workload: &'static str,
    operations: u64,
    elapsed: Duration,
    latencies_us: &[u64],
    peak_live_bytes: usize,
    peak_reserved_bytes: usize,
) -> WorkloadMetrics {
    let throughput_ops_per_sec = if elapsed.is_zero() {
        0.0
    } else {
        operations as f64 / elapsed.as_secs_f64()
    };
    let (p50_latency_us, p95_latency_us, max_latency_us) = latency_summary_us(latencies_us);
    WorkloadMetrics {
        workload,
        operations,
        elapsed_ms: elapsed.as_millis(),
        throughput_ops_per_sec,
        p50_latency_us,
        p95_latency_us,
        max_latency_us,
        peak_live_bytes,
        peak_reserved_bytes,
        fragmentation_permille: fragmentation_permille(peak_live_bytes, peak_reserved_bytes),
    }
}

fn empty_metrics(workload: &'static str) -> WorkloadMetrics {
    WorkloadMetrics {
        workload,
        operations: 0,
        elapsed_ms: 0,
        throughput_ops_per_sec: 0.0,
        p50_latency_us: 0,
        p95_latency_us: 0,
        max_latency_us: 0,
        peak_live_bytes: 0,
        peak_reserved_bytes: 0,
        fragmentation_permille: 0,
    }
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

#[cfg(test)]
mod tests {
    use super::{
        AgentBenchmarkConfig, IndexBenchmarkConfig, IndexingStoreMode, collect_indexing_snapshot,
        run_agent_benchmark, run_indexing_benchmark, run_indexing_benchmark_with_mode,
    };

    #[test]
    fn agent_benchmark_returns_expected_shape() {
        let metrics = run_agent_benchmark(AgentBenchmarkConfig {
            iterations: 240,
            outstanding_window: 32,
        });
        assert_eq!(metrics.workload, "agent");
        assert_eq!(metrics.operations, 240);
        assert!(metrics.p95_latency_us >= metrics.p50_latency_us);
        assert!(metrics.max_latency_us >= metrics.p95_latency_us);
    }

    #[test]
    fn indexing_benchmark_returns_expected_shape() {
        let metrics = run_indexing_benchmark(IndexBenchmarkConfig {
            documents: 120,
            tokens_per_document: 80,
            retained_documents: 24,
        });
        assert_eq!(metrics.workload, "indexing");
        assert_eq!(metrics.operations, 120);
        assert!(metrics.p95_latency_us >= metrics.p50_latency_us);
        assert!(metrics.peak_reserved_bytes >= metrics.peak_live_bytes);
    }

    #[test]
    fn lmdb_indexing_matches_legacy_in_memory_behavior() {
        let config = IndexBenchmarkConfig {
            documents: 64,
            tokens_per_document: 48,
            retained_documents: 12,
        };

        let legacy_snapshot = collect_indexing_snapshot(config, IndexingStoreMode::LegacyInMemory);
        assert!(legacy_snapshot.is_ok());
        let legacy_snapshot = match legacy_snapshot {
            Ok(value) => value,
            Err(_) => return,
        };

        let lmdb_snapshot = collect_indexing_snapshot(config, IndexingStoreMode::Lmdb);
        assert!(lmdb_snapshot.is_ok());
        let lmdb_snapshot = match lmdb_snapshot {
            Ok(value) => value,
            Err(_) => return,
        };

        assert_eq!(
            lmdb_snapshot.retained_documents,
            legacy_snapshot.retained_documents
        );
        assert_eq!(
            lmdb_snapshot.retained_payload_lengths,
            legacy_snapshot.retained_payload_lengths
        );
        assert_eq!(lmdb_snapshot.term_postings, legacy_snapshot.term_postings);
    }

    #[test]
    fn legacy_mode_benchmark_path_remains_available() {
        let metrics = run_indexing_benchmark_with_mode(
            IndexBenchmarkConfig {
                documents: 40,
                tokens_per_document: 32,
                retained_documents: 10,
            },
            IndexingStoreMode::LegacyInMemory,
        );
        assert_eq!(metrics.workload, "indexing");
        assert_eq!(metrics.operations, 40);
    }
}
