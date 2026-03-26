use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulkanMemoryPolicyMode {
    Disabled,
    PreferVma,
    RequireVma,
    ForceConservative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulkanMemoryPolicy {
    pub mode: VulkanMemoryPolicyMode,
}

impl Default for VulkanMemoryPolicy {
    fn default() -> Self {
        Self {
            mode: VulkanMemoryPolicyMode::PreferVma,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulkanMemoryAllocatorKind {
    Vma,
    Conservative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulkanMemoryState {
    Disabled,
    Active,
    Fallback,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulkanMemoryStatus {
    pub state: VulkanMemoryState,
    pub allocator: Option<VulkanMemoryAllocatorKind>,
    pub vma_available: bool,
    pub reason: String,
}

impl VulkanMemoryStatus {
    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            VulkanMemoryState::Active | VulkanMemoryState::Fallback
        ) && self.allocator.is_some()
    }
}

pub fn resolve_vulkan_memory_status(
    policy: VulkanMemoryPolicy,
    vulkan_backend: bool,
    vma_available: bool,
) -> VulkanMemoryStatus {
    if !vulkan_backend {
        return VulkanMemoryStatus {
            state: VulkanMemoryState::Disabled,
            allocator: None,
            vma_available,
            reason: "runtime backend is not Vulkan-capable".to_string(),
        };
    }

    match policy.mode {
        VulkanMemoryPolicyMode::Disabled => VulkanMemoryStatus {
            state: VulkanMemoryState::Disabled,
            allocator: None,
            vma_available,
            reason: "vulkan memory policy disabled".to_string(),
        },
        VulkanMemoryPolicyMode::ForceConservative => VulkanMemoryStatus {
            state: VulkanMemoryState::Fallback,
            allocator: Some(VulkanMemoryAllocatorKind::Conservative),
            vma_available,
            reason: "forced conservative Vulkan memory path".to_string(),
        },
        VulkanMemoryPolicyMode::PreferVma => {
            if vma_available {
                VulkanMemoryStatus {
                    state: VulkanMemoryState::Active,
                    allocator: Some(VulkanMemoryAllocatorKind::Vma),
                    vma_available,
                    reason: "VMA allocator active".to_string(),
                }
            } else {
                VulkanMemoryStatus {
                    state: VulkanMemoryState::Fallback,
                    allocator: Some(VulkanMemoryAllocatorKind::Conservative),
                    vma_available,
                    reason: "VMA unavailable; using conservative Vulkan memory path".to_string(),
                }
            }
        }
        VulkanMemoryPolicyMode::RequireVma => {
            if vma_available {
                VulkanMemoryStatus {
                    state: VulkanMemoryState::Active,
                    allocator: Some(VulkanMemoryAllocatorKind::Vma),
                    vma_available,
                    reason: "VMA allocator active".to_string(),
                }
            } else {
                VulkanMemoryStatus {
                    state: VulkanMemoryState::Unavailable,
                    allocator: None,
                    vma_available,
                    reason: "VMA required by policy but unavailable".to_string(),
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulkanMemoryUsage {
    Buffer,
    Image,
    Staging,
    Scratch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulkanAllocationRequest {
    pub size_bytes: u64,
    pub alignment_bytes: u64,
    pub usage: VulkanMemoryUsage,
    pub mapped: bool,
}

impl VulkanAllocationRequest {
    pub fn validate(&self) -> Result<(), VulkanMemoryError> {
        if self.size_bytes == 0 {
            return Err(VulkanMemoryError::InvalidRequest(
                "size_bytes must be greater than zero".to_string(),
            ));
        }
        if self.alignment_bytes == 0 || !self.alignment_bytes.is_power_of_two() {
            return Err(VulkanMemoryError::InvalidRequest(
                "alignment_bytes must be a non-zero power of two".to_string(),
            ));
        }
        Ok(())
    }

    pub fn normalized_alignment(self) -> u64 {
        self.alignment_bytes.max(1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulkanAllocationRecord {
    pub allocation_id: u64,
    pub allocator: VulkanMemoryAllocatorKind,
    pub usage: VulkanMemoryUsage,
    pub size_bytes: u64,
    pub reserved_bytes: u64,
    pub offset_bytes: u64,
    pub mapped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulkanMemoryError {
    RuntimeNotConfigured(String),
    BackendUnavailable(String),
    InvalidRequest(String),
    AllocationNotFound(u64),
}

impl fmt::Display for VulkanMemoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VulkanMemoryError::RuntimeNotConfigured(runtime_id) => {
                write!(
                    formatter,
                    "runtime not configured for Vulkan allocator: {runtime_id}"
                )
            }
            VulkanMemoryError::BackendUnavailable(reason) => {
                write!(formatter, "Vulkan memory allocator unavailable: {reason}")
            }
            VulkanMemoryError::InvalidRequest(reason) => {
                write!(formatter, "invalid Vulkan memory request: {reason}")
            }
            VulkanMemoryError::AllocationNotFound(allocation_id) => {
                write!(
                    formatter,
                    "vulkan allocation handle not found: {allocation_id}"
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        VulkanAllocationRequest, VulkanMemoryPolicy, VulkanMemoryPolicyMode, VulkanMemoryState,
        VulkanMemoryUsage, resolve_vulkan_memory_status,
    };

    #[test]
    fn prefer_vma_falls_back_when_vma_unavailable() {
        let status = resolve_vulkan_memory_status(VulkanMemoryPolicy::default(), true, false);
        assert_eq!(status.state, VulkanMemoryState::Fallback);
        assert!(status.reason.contains("VMA unavailable"));
    }

    #[test]
    fn require_vma_without_vma_is_unavailable() {
        let status = resolve_vulkan_memory_status(
            VulkanMemoryPolicy {
                mode: VulkanMemoryPolicyMode::RequireVma,
            },
            true,
            false,
        );
        assert_eq!(status.state, VulkanMemoryState::Unavailable);
        assert!(!status.is_active());
    }

    #[test]
    fn allocation_request_requires_positive_size_and_power_of_two_alignment() {
        let invalid_size = VulkanAllocationRequest {
            size_bytes: 0,
            alignment_bytes: 256,
            usage: VulkanMemoryUsage::Buffer,
            mapped: false,
        };
        assert!(invalid_size.validate().is_err());

        let invalid_alignment = VulkanAllocationRequest {
            size_bytes: 1024,
            alignment_bytes: 300,
            usage: VulkanMemoryUsage::Buffer,
            mapped: true,
        };
        assert!(invalid_alignment.validate().is_err());

        let valid = VulkanAllocationRequest {
            size_bytes: 1024,
            alignment_bytes: 256,
            usage: VulkanMemoryUsage::Image,
            mapped: false,
        };
        assert!(valid.validate().is_ok());
    }
}
