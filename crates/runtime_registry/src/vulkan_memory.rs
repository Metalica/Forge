use crate::health::RuntimeBackend;
use std::collections::HashMap;
use urm::vulkan_memory::{
    VulkanAllocationRecord, VulkanAllocationRequest, VulkanMemoryAllocatorKind, VulkanMemoryError,
    VulkanMemoryPolicy, VulkanMemoryStatus, resolve_vulkan_memory_status,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VulkanAllocatorSnapshot {
    pub live_allocations: usize,
    pub live_bytes: u64,
    pub reserved_bytes: u64,
    pub peak_reserved_bytes: u64,
}

impl VulkanAllocatorSnapshot {
    fn empty() -> Self {
        Self {
            live_allocations: 0,
            live_bytes: 0,
            reserved_bytes: 0,
            peak_reserved_bytes: 0,
        }
    }
}

#[derive(Debug, Default)]
struct SimulatedVmaAllocator {
    next_allocation_id: u64,
    next_offset_bytes: u64,
    live_bytes: u64,
    reserved_bytes: u64,
    peak_reserved_bytes: u64,
    allocations: HashMap<u64, VulkanAllocationRecord>,
    free_ranges: Vec<FreeRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FreeRange {
    offset_bytes: u64,
    size_bytes: u64,
}

impl SimulatedVmaAllocator {
    fn allocate(
        &mut self,
        request: VulkanAllocationRequest,
    ) -> Result<VulkanAllocationRecord, VulkanMemoryError> {
        request.validate()?;

        let alignment = request.normalized_alignment();
        let mut selected: Option<(usize, u64)> = None;
        for (index, range) in self.free_ranges.iter().enumerate() {
            let aligned_offset = align_up(range.offset_bytes, alignment);
            let padding = aligned_offset.saturating_sub(range.offset_bytes);
            let required = padding.saturating_add(request.size_bytes);
            if required <= range.size_bytes {
                selected = Some((index, aligned_offset));
                break;
            }
        }

        let offset_bytes = if let Some((range_index, aligned_offset)) = selected {
            let range = self.free_ranges.remove(range_index);
            let prefix = aligned_offset.saturating_sub(range.offset_bytes);
            let suffix_start = aligned_offset.saturating_add(request.size_bytes);
            let consumed = prefix.saturating_add(request.size_bytes);
            let suffix = range.size_bytes.saturating_sub(consumed);

            if prefix > 0 {
                self.free_ranges.push(FreeRange {
                    offset_bytes: range.offset_bytes,
                    size_bytes: prefix,
                });
            }
            if suffix > 0 {
                self.free_ranges.push(FreeRange {
                    offset_bytes: suffix_start,
                    size_bytes: suffix,
                });
            }
            self.free_ranges.sort_by_key(|value| value.offset_bytes);
            aligned_offset
        } else {
            let aligned_offset = align_up(self.next_offset_bytes, alignment);
            self.next_offset_bytes = aligned_offset.saturating_add(request.size_bytes);
            self.reserved_bytes = self.reserved_bytes.max(self.next_offset_bytes);
            self.peak_reserved_bytes = self.peak_reserved_bytes.max(self.reserved_bytes);
            aligned_offset
        };

        self.next_allocation_id = self.next_allocation_id.saturating_add(1);
        let allocation_id = self.next_allocation_id;
        self.live_bytes = self.live_bytes.saturating_add(request.size_bytes);
        let record = VulkanAllocationRecord {
            allocation_id,
            allocator: VulkanMemoryAllocatorKind::Vma,
            usage: request.usage,
            size_bytes: request.size_bytes,
            reserved_bytes: request.size_bytes,
            offset_bytes,
            mapped: request.mapped,
        };
        self.allocations.insert(allocation_id, record);
        Ok(record)
    }

    fn free(&mut self, allocation_id: u64) -> Result<(), VulkanMemoryError> {
        let Some(record) = self.allocations.remove(&allocation_id) else {
            return Err(VulkanMemoryError::AllocationNotFound(allocation_id));
        };
        self.live_bytes = self.live_bytes.saturating_sub(record.size_bytes);
        self.free_ranges.push(FreeRange {
            offset_bytes: record.offset_bytes,
            size_bytes: record.size_bytes,
        });
        self.merge_free_ranges();
        Ok(())
    }

    fn snapshot(&self) -> VulkanAllocatorSnapshot {
        VulkanAllocatorSnapshot {
            live_allocations: self.allocations.len(),
            live_bytes: self.live_bytes,
            reserved_bytes: self.reserved_bytes,
            peak_reserved_bytes: self.peak_reserved_bytes.max(self.reserved_bytes),
        }
    }

    fn merge_free_ranges(&mut self) {
        if self.free_ranges.len() < 2 {
            return;
        }
        self.free_ranges.sort_by_key(|value| value.offset_bytes);
        let mut merged: Vec<FreeRange> = Vec::with_capacity(self.free_ranges.len());
        for range in self.free_ranges.iter().copied() {
            if let Some(last) = merged.last_mut() {
                let last_end = last.offset_bytes.saturating_add(last.size_bytes);
                if range.offset_bytes <= last_end {
                    let range_end = range.offset_bytes.saturating_add(range.size_bytes);
                    let merged_end = last_end.max(range_end);
                    last.size_bytes = merged_end.saturating_sub(last.offset_bytes);
                    continue;
                }
            }
            merged.push(range);
        }
        self.free_ranges = merged;
    }
}

#[derive(Debug, Default)]
struct ConservativeAllocator {
    next_allocation_id: u64,
    live_bytes: u64,
    reserved_bytes: u64,
    peak_reserved_bytes: u64,
    allocations: HashMap<u64, VulkanAllocationRecord>,
}

impl ConservativeAllocator {
    const CHUNK_BYTES: u64 = 4 * 1024 * 1024;

    fn allocate(
        &mut self,
        request: VulkanAllocationRequest,
    ) -> Result<VulkanAllocationRecord, VulkanMemoryError> {
        request.validate()?;
        self.next_allocation_id = self.next_allocation_id.saturating_add(1);
        let allocation_id = self.next_allocation_id;
        let reserved_bytes = align_up(request.size_bytes, Self::CHUNK_BYTES);

        self.live_bytes = self.live_bytes.saturating_add(request.size_bytes);
        self.reserved_bytes = self.reserved_bytes.saturating_add(reserved_bytes);
        self.peak_reserved_bytes = self.peak_reserved_bytes.max(self.reserved_bytes);

        let record = VulkanAllocationRecord {
            allocation_id,
            allocator: VulkanMemoryAllocatorKind::Conservative,
            usage: request.usage,
            size_bytes: request.size_bytes,
            reserved_bytes,
            offset_bytes: 0,
            mapped: request.mapped,
        };
        self.allocations.insert(allocation_id, record);
        Ok(record)
    }

    fn free(&mut self, allocation_id: u64) -> Result<(), VulkanMemoryError> {
        let Some(record) = self.allocations.remove(&allocation_id) else {
            return Err(VulkanMemoryError::AllocationNotFound(allocation_id));
        };
        self.live_bytes = self.live_bytes.saturating_sub(record.size_bytes);
        self.reserved_bytes = self.reserved_bytes.saturating_sub(record.reserved_bytes);
        Ok(())
    }

    fn snapshot(&self) -> VulkanAllocatorSnapshot {
        VulkanAllocatorSnapshot {
            live_allocations: self.allocations.len(),
            live_bytes: self.live_bytes,
            reserved_bytes: self.reserved_bytes,
            peak_reserved_bytes: self.peak_reserved_bytes.max(self.reserved_bytes),
        }
    }
}

#[derive(Debug)]
enum RuntimeAllocatorEngine {
    Vma(SimulatedVmaAllocator),
    Conservative(ConservativeAllocator),
    None,
}

#[derive(Debug)]
struct RuntimeAllocatorSession {
    status: VulkanMemoryStatus,
    engine: RuntimeAllocatorEngine,
}

#[derive(Debug)]
pub struct VulkanRuntimeAllocatorManager {
    policy: VulkanMemoryPolicy,
    sessions: HashMap<String, RuntimeAllocatorSession>,
}

impl VulkanRuntimeAllocatorManager {
    pub fn new(policy: VulkanMemoryPolicy) -> Self {
        Self {
            policy,
            sessions: HashMap::new(),
        }
    }

    pub fn configure_runtime(
        &mut self,
        runtime_id: impl Into<String>,
        backend: RuntimeBackend,
        vma_available: bool,
    ) -> VulkanMemoryStatus {
        let runtime_id = runtime_id.into();
        let vulkan_backend = matches!(backend, RuntimeBackend::Vulkan | RuntimeBackend::Hybrid);
        let status = resolve_vulkan_memory_status(self.policy, vulkan_backend, vma_available);
        let engine = match status.allocator {
            Some(VulkanMemoryAllocatorKind::Vma) => {
                RuntimeAllocatorEngine::Vma(SimulatedVmaAllocator::default())
            }
            Some(VulkanMemoryAllocatorKind::Conservative) => {
                RuntimeAllocatorEngine::Conservative(ConservativeAllocator::default())
            }
            None => RuntimeAllocatorEngine::None,
        };
        self.sessions.insert(
            runtime_id,
            RuntimeAllocatorSession {
                status: status.clone(),
                engine,
            },
        );
        status
    }

    pub fn status(&self, runtime_id: &str) -> Option<VulkanMemoryStatus> {
        self.sessions
            .get(runtime_id)
            .map(|session| session.status.clone())
    }

    pub fn allocate(
        &mut self,
        runtime_id: &str,
        request: VulkanAllocationRequest,
    ) -> Result<VulkanAllocationRecord, VulkanMemoryError> {
        request.validate()?;
        let Some(session) = self.sessions.get_mut(runtime_id) else {
            return Err(VulkanMemoryError::RuntimeNotConfigured(
                runtime_id.to_string(),
            ));
        };

        if !session.status.is_active() {
            return Err(VulkanMemoryError::BackendUnavailable(
                session.status.reason.clone(),
            ));
        }

        match &mut session.engine {
            RuntimeAllocatorEngine::Vma(allocator) => allocator.allocate(request),
            RuntimeAllocatorEngine::Conservative(allocator) => allocator.allocate(request),
            RuntimeAllocatorEngine::None => Err(VulkanMemoryError::BackendUnavailable(
                session.status.reason.clone(),
            )),
        }
    }

    pub fn free(&mut self, runtime_id: &str, allocation_id: u64) -> Result<(), VulkanMemoryError> {
        let Some(session) = self.sessions.get_mut(runtime_id) else {
            return Err(VulkanMemoryError::RuntimeNotConfigured(
                runtime_id.to_string(),
            ));
        };
        match &mut session.engine {
            RuntimeAllocatorEngine::Vma(allocator) => allocator.free(allocation_id),
            RuntimeAllocatorEngine::Conservative(allocator) => allocator.free(allocation_id),
            RuntimeAllocatorEngine::None => Err(VulkanMemoryError::BackendUnavailable(
                session.status.reason.clone(),
            )),
        }
    }

    pub fn snapshot(&self, runtime_id: &str) -> Option<VulkanAllocatorSnapshot> {
        let session = self.sessions.get(runtime_id)?;
        let snapshot = match &session.engine {
            RuntimeAllocatorEngine::Vma(allocator) => allocator.snapshot(),
            RuntimeAllocatorEngine::Conservative(allocator) => allocator.snapshot(),
            RuntimeAllocatorEngine::None => VulkanAllocatorSnapshot::empty(),
        };
        Some(snapshot)
    }
}

fn align_up(value: u64, alignment: u64) -> u64 {
    let alignment = alignment.max(1);
    if alignment == 1 {
        return value;
    }
    let mask = alignment.saturating_sub(1);
    if value & mask == 0 {
        value
    } else {
        value.saturating_add(alignment.saturating_sub(value & mask))
    }
}

#[cfg(test)]
mod tests {
    use super::VulkanRuntimeAllocatorManager;
    use crate::health::RuntimeBackend;
    use urm::vulkan_memory::{
        VulkanAllocationRequest, VulkanMemoryAllocatorKind, VulkanMemoryError, VulkanMemoryPolicy,
        VulkanMemoryPolicyMode, VulkanMemoryState, VulkanMemoryUsage,
    };

    fn request(size_bytes: u64, alignment_bytes: u64) -> VulkanAllocationRequest {
        VulkanAllocationRequest {
            size_bytes,
            alignment_bytes,
            usage: VulkanMemoryUsage::Buffer,
            mapped: false,
        }
    }

    #[test]
    fn vma_suballocation_lifecycle_reuses_freed_range() {
        let mut manager = VulkanRuntimeAllocatorManager::new(VulkanMemoryPolicy::default());
        let status = manager.configure_runtime("rt-vulkan", RuntimeBackend::Vulkan, true);
        assert_eq!(status.state, VulkanMemoryState::Active);
        assert_eq!(status.allocator, Some(VulkanMemoryAllocatorKind::Vma));

        let first = manager.allocate("rt-vulkan", request(4096, 256));
        assert!(first.is_ok());
        let first = match first {
            Ok(value) => value,
            Err(_) => return,
        };
        let second = manager.allocate("rt-vulkan", request(8192, 256));
        assert!(second.is_ok());
        let second = match second {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(second.offset_bytes >= first.offset_bytes + first.size_bytes);

        let freed = manager.free("rt-vulkan", first.allocation_id);
        assert!(freed.is_ok());

        let reused = manager.allocate("rt-vulkan", request(1024, 256));
        assert!(reused.is_ok());
        let reused = match reused {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(reused.allocator, VulkanMemoryAllocatorKind::Vma);
        assert_eq!(reused.offset_bytes, first.offset_bytes);

        let snapshot = manager.snapshot("rt-vulkan");
        assert!(snapshot.is_some());
        let snapshot = match snapshot {
            Some(value) => value,
            None => return,
        };
        assert_eq!(snapshot.live_allocations, 2);
        assert!(snapshot.reserved_bytes >= snapshot.live_bytes);
    }

    #[test]
    fn vma_unavailable_falls_back_to_conservative_allocator_when_policy_allows() {
        let mut manager = VulkanRuntimeAllocatorManager::new(VulkanMemoryPolicy::default());
        let status = manager.configure_runtime("rt-vulkan", RuntimeBackend::Vulkan, false);
        assert_eq!(status.state, VulkanMemoryState::Fallback);
        assert_eq!(
            status.allocator,
            Some(VulkanMemoryAllocatorKind::Conservative)
        );

        let allocation = manager.allocate("rt-vulkan", request(8192, 256));
        assert!(allocation.is_ok());
        let allocation = match allocation {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(
            allocation.allocator,
            VulkanMemoryAllocatorKind::Conservative
        );
        assert!(allocation.reserved_bytes >= allocation.size_bytes);
        assert_eq!(allocation.offset_bytes, 0);
    }

    #[test]
    fn require_vma_policy_returns_unavailable_when_vma_cannot_be_loaded() {
        let mut manager = VulkanRuntimeAllocatorManager::new(VulkanMemoryPolicy {
            mode: VulkanMemoryPolicyMode::RequireVma,
        });
        let status = manager.configure_runtime("rt-vulkan", RuntimeBackend::Vulkan, false);
        assert_eq!(status.state, VulkanMemoryState::Unavailable);
        assert!(status.allocator.is_none());

        let allocation = manager.allocate("rt-vulkan", request(4096, 128));
        assert!(matches!(
            allocation,
            Err(VulkanMemoryError::BackendUnavailable(_))
        ));
    }

    #[test]
    fn non_vulkan_backend_stays_disabled() {
        let mut manager = VulkanRuntimeAllocatorManager::new(VulkanMemoryPolicy::default());
        let status = manager.configure_runtime("rt-cpu", RuntimeBackend::Cpu, true);
        assert_eq!(status.state, VulkanMemoryState::Disabled);

        let allocation = manager.allocate("rt-cpu", request(1024, 64));
        assert!(matches!(
            allocation,
            Err(VulkanMemoryError::BackendUnavailable(_))
        ));
    }
}
