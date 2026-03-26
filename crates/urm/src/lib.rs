#![forbid(unsafe_code)]

pub mod allocator_policy;
pub mod feature_policy;
pub mod io_policy;
pub mod lmdb_metadata;
pub mod topology;
pub mod vulkan_memory;

pub mod budget {
    use std::collections::VecDeque;
    use std::time::SystemTime;

    /// Memory budget contract used by the scheduler and runtime registry.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MemoryBudget {
        pub ram_mb: u32,
        pub vram_mb: u32,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SpillPolicy {
        Conservative,
        Balanced,
        Aggressive,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TransferKind {
        RamToVram,
        VramToRam,
        RamToDisk,
        DiskToRam,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TransferEvent {
        pub sequence: u64,
        pub kind: TransferKind,
        pub bytes: u64,
        pub reason: String,
        pub occurred_at: SystemTime,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct UsageSnapshot {
        pub ram_used_mb: u32,
        pub vram_used_mb: u32,
        pub ram_budget_mb: u32,
        pub vram_budget_mb: u32,
        pub cpu_used_percent: u32,
        pub cpu_budget_percent: u32,
        pub extension_ram_used_mb: u32,
        pub extension_cpu_used_percent: u32,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SpillDecision {
        None,
        SpillVramToRam,
        SpillRamToDisk,
    }

    #[derive(Debug)]
    pub struct ResourceManager {
        budget: MemoryBudget,
        policy: SpillPolicy,
        ram_used_mb: u32,
        vram_used_mb: u32,
        cpu_used_percent: u32,
        cpu_budget_percent: u32,
        extension_ram_used_mb: u32,
        extension_cpu_used_percent: u32,
        transfer_seq: u64,
        transfer_log: VecDeque<TransferEvent>,
        transfer_log_limit: usize,
    }

    impl ResourceManager {
        pub fn new(budget: MemoryBudget, policy: SpillPolicy) -> Self {
            Self {
                budget,
                policy,
                ram_used_mb: 0,
                vram_used_mb: 0,
                cpu_used_percent: 0,
                cpu_budget_percent: 100,
                extension_ram_used_mb: 0,
                extension_cpu_used_percent: 0,
                transfer_seq: 0,
                transfer_log: VecDeque::new(),
                transfer_log_limit: 256,
            }
        }

        pub fn budget(&self) -> MemoryBudget {
            self.budget
        }

        pub fn policy(&self) -> SpillPolicy {
            self.policy
        }

        pub fn set_policy(&mut self, policy: SpillPolicy) {
            self.policy = policy;
        }

        pub fn set_budget(&mut self, budget: MemoryBudget) {
            self.budget = budget;
        }

        pub fn cpu_budget_percent(&self) -> u32 {
            self.cpu_budget_percent
        }

        pub fn set_cpu_budget_percent(&mut self, cpu_budget_percent: u32) {
            self.cpu_budget_percent = cpu_budget_percent.clamp(1, 100);
            self.cpu_used_percent = self.cpu_used_percent.min(self.cpu_budget_percent);
        }

        pub fn set_cpu_used_percent(&mut self, cpu_used_percent: u32) {
            self.cpu_used_percent = cpu_used_percent.min(self.cpu_budget_percent);
        }

        pub fn set_extension_overhead(
            &mut self,
            extension_ram_used_mb: u32,
            extension_cpu_used_percent: u32,
        ) -> bool {
            if self.ram_used_mb.saturating_add(extension_ram_used_mb) > self.budget.ram_mb {
                return false;
            }
            if self
                .cpu_used_percent
                .saturating_add(extension_cpu_used_percent)
                > self.cpu_budget_percent
            {
                return false;
            }
            self.extension_ram_used_mb = extension_ram_used_mb;
            self.extension_cpu_used_percent = extension_cpu_used_percent;
            true
        }

        pub fn reserve_ram(&mut self, mb: u32) -> bool {
            if self
                .ram_used_mb
                .saturating_add(mb)
                .saturating_add(self.extension_ram_used_mb)
                > self.budget.ram_mb
            {
                return false;
            }
            self.ram_used_mb = self.ram_used_mb.saturating_add(mb);
            true
        }

        pub fn reserve_vram(&mut self, mb: u32) -> bool {
            if self.vram_used_mb.saturating_add(mb) > self.budget.vram_mb {
                return false;
            }
            self.vram_used_mb = self.vram_used_mb.saturating_add(mb);
            true
        }

        pub fn release_ram(&mut self, mb: u32) {
            self.ram_used_mb = self.ram_used_mb.saturating_sub(mb);
        }

        pub fn release_vram(&mut self, mb: u32) {
            self.vram_used_mb = self.vram_used_mb.saturating_sub(mb);
        }

        pub fn usage(&self) -> UsageSnapshot {
            UsageSnapshot {
                ram_used_mb: self.ram_used_mb.saturating_add(self.extension_ram_used_mb),
                vram_used_mb: self.vram_used_mb,
                ram_budget_mb: self.budget.ram_mb,
                vram_budget_mb: self.budget.vram_mb,
                cpu_used_percent: self
                    .cpu_used_percent
                    .saturating_add(self.extension_cpu_used_percent),
                cpu_budget_percent: self.cpu_budget_percent,
                extension_ram_used_mb: self.extension_ram_used_mb,
                extension_cpu_used_percent: self.extension_cpu_used_percent,
            }
        }

        pub fn recommended_spill(&self) -> SpillDecision {
            let total_ram_used = self.ram_used_mb.saturating_add(self.extension_ram_used_mb);
            let ram_pressure = total_ram_used as f64 / self.budget.ram_mb.max(1) as f64;
            let vram_pressure = self.vram_used_mb as f64 / self.budget.vram_mb.max(1) as f64;

            match self.policy {
                SpillPolicy::Conservative => {
                    if vram_pressure > 0.95 {
                        SpillDecision::SpillVramToRam
                    } else if ram_pressure > 0.95 {
                        SpillDecision::SpillRamToDisk
                    } else {
                        SpillDecision::None
                    }
                }
                SpillPolicy::Balanced => {
                    if vram_pressure > 0.85 {
                        SpillDecision::SpillVramToRam
                    } else if ram_pressure > 0.85 {
                        SpillDecision::SpillRamToDisk
                    } else {
                        SpillDecision::None
                    }
                }
                SpillPolicy::Aggressive => {
                    if vram_pressure > 0.75 {
                        SpillDecision::SpillVramToRam
                    } else if ram_pressure > 0.75 {
                        SpillDecision::SpillRamToDisk
                    } else {
                        SpillDecision::None
                    }
                }
            }
        }

        pub fn log_transfer(&mut self, kind: TransferKind, bytes: u64, reason: impl Into<String>) {
            self.transfer_seq += 1;
            self.transfer_log.push_back(TransferEvent {
                sequence: self.transfer_seq,
                kind,
                bytes,
                reason: reason.into(),
                occurred_at: SystemTime::now(),
            });
            while self.transfer_log.len() > self.transfer_log_limit {
                self.transfer_log.pop_front();
            }
        }

        pub fn transfer_log(&self) -> &VecDeque<TransferEvent> {
            &self.transfer_log
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{MemoryBudget, ResourceManager, SpillDecision, SpillPolicy, TransferKind};

        #[test]
        fn spill_decision_reflects_policy_thresholds() {
            let mut manager = ResourceManager::new(
                MemoryBudget {
                    ram_mb: 16000,
                    vram_mb: 8000,
                },
                SpillPolicy::Balanced,
            );

            assert!(manager.reserve_vram(7000));
            assert_eq!(manager.recommended_spill(), SpillDecision::SpillVramToRam);

            manager.release_vram(7000);
            assert!(manager.reserve_ram(14000));
            assert_eq!(manager.recommended_spill(), SpillDecision::SpillRamToDisk);
        }

        #[test]
        fn transfer_log_records_sequence() {
            let mut manager = ResourceManager::new(
                MemoryBudget {
                    ram_mb: 4000,
                    vram_mb: 4000,
                },
                SpillPolicy::Conservative,
            );

            manager.log_transfer(TransferKind::RamToVram, 1024, "prefetch weights");
            manager.log_transfer(TransferKind::VramToRam, 512, "evict cold cache");

            assert_eq!(
                manager.transfer_log().front().map(|event| event.sequence),
                Some(1)
            );
            assert_eq!(
                manager.transfer_log().back().map(|event| event.sequence),
                Some(2)
            );
        }

        #[test]
        fn extension_overhead_contributes_to_usage_and_enforces_budget() {
            let mut manager = ResourceManager::new(
                MemoryBudget {
                    ram_mb: 1000,
                    vram_mb: 800,
                },
                SpillPolicy::Balanced,
            );
            manager.set_cpu_budget_percent(40);
            manager.set_cpu_used_percent(10);
            assert!(manager.reserve_ram(700));

            let rejected = manager.set_extension_overhead(320, 10);
            assert!(!rejected);

            let accepted = manager.set_extension_overhead(200, 15);
            assert!(accepted);
            let usage = manager.usage();
            assert_eq!(usage.ram_used_mb, 900);
            assert_eq!(usage.extension_ram_used_mb, 200);
            assert_eq!(usage.cpu_used_percent, 25);
            assert_eq!(usage.cpu_budget_percent, 40);
            assert_eq!(usage.extension_cpu_used_percent, 15);

            assert!(!manager.reserve_ram(101));
            assert!(manager.reserve_ram(100));
        }
    }
}
