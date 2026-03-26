use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

pub const TOPOLOGY_SNAPSHOT_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TopologySource {
    Disabled,
    Hwloc,
    Fallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyCaptureOptions {
    pub enabled: bool,
}

impl Default for TopologyCaptureOptions {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologySnapshot {
    pub schema_version: u16,
    pub source: TopologySource,
    pub captured_at_unix_ms: u64,
    pub summary: TopologySummary,
    pub numa_nodes: Vec<TopologyObjectSnapshot>,
    pub sockets: Vec<TopologyObjectSnapshot>,
    pub shared_caches: Vec<CacheTopologySnapshot>,
    pub cores: Vec<TopologyObjectSnapshot>,
    pub processing_units: Vec<TopologyObjectSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologySummary {
    pub numa_node_count: u32,
    pub socket_count: u32,
    pub shared_cache_count: u32,
    pub core_count: u32,
    pub processing_unit_count: u32,
    pub smt_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyObjectSnapshot {
    pub object_type: String,
    pub logical_index: u32,
    pub os_index: u32,
    pub depth: u32,
    pub cpuset: Option<String>,
    pub nodeset: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheTopologySnapshot {
    pub object_type: String,
    pub logical_index: u32,
    pub os_index: u32,
    pub depth: u32,
    pub cpuset: Option<String>,
    pub nodeset: Option<String>,
    pub cache_level: u32,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopologyError {
    HwlocInitializationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessingUnitLocality {
    pub processing_unit_os_index: u32,
    pub numa_node_os_index: Option<u32>,
    pub socket_os_index: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NumaPolicyMode {
    Disabled,
    Prefer,
    Bind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumaPlacementPolicy {
    pub mode: NumaPolicyMode,
    pub numa_node_os_index: Option<u32>,
    pub cpu_os_index: Option<u32>,
}

impl NumaPlacementPolicy {
    pub fn disabled() -> Self {
        Self {
            mode: NumaPolicyMode::Disabled,
            numa_node_os_index: None,
            cpu_os_index: None,
        }
    }

    pub fn prefer_node(numa_node_os_index: u32, cpu_os_index: Option<u32>) -> Self {
        Self {
            mode: NumaPolicyMode::Prefer,
            numa_node_os_index: Some(numa_node_os_index),
            cpu_os_index,
        }
    }

    pub fn bind_node(numa_node_os_index: u32, cpu_os_index: Option<u32>) -> Self {
        Self {
            mode: NumaPolicyMode::Bind,
            numa_node_os_index: Some(numa_node_os_index),
            cpu_os_index,
        }
    }
}

impl fmt::Display for TopologyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TopologyError::HwlocInitializationFailed => {
                formatter.write_str("failed to initialize hwloc topology")
            }
        }
    }
}

impl TopologySnapshot {
    pub fn processing_unit_locality(
        &self,
        processing_unit_os_index: u32,
    ) -> Option<ProcessingUnitLocality> {
        let processing_unit = self
            .processing_units
            .iter()
            .find(|value| value.os_index == processing_unit_os_index)?;
        Some(ProcessingUnitLocality {
            processing_unit_os_index,
            numa_node_os_index: find_domain_os_index(&self.numa_nodes, processing_unit),
            socket_os_index: find_domain_os_index(&self.sockets, processing_unit),
        })
    }

    pub fn is_numa_aware(&self) -> bool {
        self.summary.numa_node_count > 1 && !self.numa_nodes.is_empty()
    }

    fn disabled() -> Self {
        Self {
            schema_version: TOPOLOGY_SNAPSHOT_SCHEMA_VERSION,
            source: TopologySource::Disabled,
            captured_at_unix_ms: current_time_unix_ms(),
            summary: TopologySummary {
                numa_node_count: 0,
                socket_count: 0,
                shared_cache_count: 0,
                core_count: 0,
                processing_unit_count: 0,
                smt_enabled: false,
            },
            numa_nodes: Vec::new(),
            sockets: Vec::new(),
            shared_caches: Vec::new(),
            cores: Vec::new(),
            processing_units: Vec::new(),
        }
    }

    fn fallback() -> Self {
        let pu_count = std::thread::available_parallelism()
            .ok()
            .map(|value| value.get() as u32)
            .unwrap_or(1);

        let mut processing_units = Vec::new();
        let mut cores = Vec::new();
        for index in 0..pu_count {
            let bit = index.to_string();
            processing_units.push(TopologyObjectSnapshot {
                object_type: "PU".to_string(),
                logical_index: index,
                os_index: index,
                depth: 0,
                cpuset: Some(bit.clone()),
                nodeset: None,
            });
            cores.push(TopologyObjectSnapshot {
                object_type: "Core".to_string(),
                logical_index: index,
                os_index: index,
                depth: 0,
                cpuset: Some(bit),
                nodeset: None,
            });
        }

        let sockets = vec![TopologyObjectSnapshot {
            object_type: "Package".to_string(),
            logical_index: 0,
            os_index: 0,
            depth: 0,
            cpuset: None,
            nodeset: None,
        }];

        let summary = TopologySummary {
            numa_node_count: 0,
            socket_count: sockets.len() as u32,
            shared_cache_count: 0,
            core_count: cores.len() as u32,
            processing_unit_count: processing_units.len() as u32,
            smt_enabled: false,
        };

        Self {
            schema_version: TOPOLOGY_SNAPSHOT_SCHEMA_VERSION,
            source: TopologySource::Fallback,
            captured_at_unix_ms: current_time_unix_ms(),
            summary,
            numa_nodes: Vec::new(),
            sockets,
            shared_caches: Vec::new(),
            cores,
            processing_units,
        }
    }
}

fn find_domain_os_index(
    domains: &[TopologyObjectSnapshot],
    processing_unit: &TopologyObjectSnapshot,
) -> Option<u32> {
    if domains.is_empty() {
        return None;
    }
    if domains.len() == 1 {
        return domains.first().map(|value| value.os_index);
    }
    domains
        .iter()
        .find(|domain| domain_contains_processing_unit(domain, processing_unit))
        .map(|value| value.os_index)
}

fn domain_contains_processing_unit(
    domain: &TopologyObjectSnapshot,
    processing_unit: &TopologyObjectSnapshot,
) -> bool {
    let Some(cpuset) = &domain.cpuset else {
        return false;
    };
    cpuset_contains_os_index(cpuset, processing_unit.os_index)
}

fn cpuset_contains_os_index(cpuset: &str, os_index: u32) -> bool {
    let trimmed = cpuset.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.contains("0x") || trimmed.contains("0X") {
        return hex_cpuset_contains_os_index(trimmed, os_index);
    }

    for token in trimmed
        .split([',', ' ', '\t', '\n', '\r'])
        .filter(|value| !value.is_empty())
    {
        if let Some((start, end)) = token.split_once('-') {
            let Ok(start) = start.parse::<u32>() else {
                continue;
            };
            let Ok(end) = end.parse::<u32>() else {
                continue;
            };
            if (start..=end).contains(&os_index) {
                return true;
            }
            continue;
        }
        if token.parse::<u32>().ok() == Some(os_index) {
            return true;
        }
    }
    false
}

fn hex_cpuset_contains_os_index(cpuset: &str, os_index: u32) -> bool {
    let segments: Vec<&str> = cpuset
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect();
    if segments.is_empty() {
        return false;
    }

    for (segment_offset, segment) in segments.iter().rev().enumerate() {
        let normalized = segment
            .trim_start_matches("0x")
            .trim_start_matches("0X")
            .replace('_', "");
        if normalized.is_empty() {
            continue;
        }
        let Ok(bits) = u32::from_str_radix(&normalized, 16) else {
            continue;
        };
        let bit_offset = segment_offset as u32 * 32;
        if os_index < bit_offset {
            continue;
        }
        let local_bit = os_index - bit_offset;
        if local_bit < 32 && (bits & (1u32 << local_bit)) != 0 {
            return true;
        }
    }
    false
}

pub fn capture_topology_snapshot() -> Result<TopologySnapshot, TopologyError> {
    capture_topology_snapshot_with_options(TopologyCaptureOptions::default())
}

pub fn capture_topology_snapshot_with_options(
    options: TopologyCaptureOptions,
) -> Result<TopologySnapshot, TopologyError> {
    if !options.enabled {
        return Ok(TopologySnapshot::disabled());
    }

    #[cfg(all(feature = "topology-hwloc", not(windows)))]
    {
        return capture_topology_snapshot_hwloc();
    }

    #[cfg(not(all(feature = "topology-hwloc", not(windows))))]
    {
        Ok(TopologySnapshot::fallback())
    }
}

#[cfg(all(feature = "topology-hwloc", not(windows)))]
fn capture_topology_snapshot_hwloc() -> Result<TopologySnapshot, TopologyError> {
    use hwloc::{ObjectType, Topology};

    let topology = match Topology::new() {
        Some(value) => value,
        None => return Err(TopologyError::HwlocInitializationFailed),
    };

    let mut numa_nodes = collect_objects(&topology, &ObjectType::NUMANode);
    let mut sockets = collect_objects(&topology, &ObjectType::Package);
    let mut cores = collect_objects(&topology, &ObjectType::Core);
    let mut processing_units = collect_objects(&topology, &ObjectType::PU);
    let mut shared_caches = collect_caches(&topology);

    sort_objects(&mut numa_nodes);
    sort_objects(&mut sockets);
    sort_objects(&mut cores);
    sort_objects(&mut processing_units);
    sort_caches(&mut shared_caches);

    let summary = TopologySummary {
        numa_node_count: numa_nodes.len() as u32,
        socket_count: sockets.len() as u32,
        shared_cache_count: shared_caches.len() as u32,
        core_count: cores.len() as u32,
        processing_unit_count: processing_units.len() as u32,
        smt_enabled: processing_units.len() > cores.len(),
    };

    Ok(TopologySnapshot {
        schema_version: TOPOLOGY_SNAPSHOT_SCHEMA_VERSION,
        source: TopologySource::Hwloc,
        captured_at_unix_ms: current_time_unix_ms(),
        summary,
        numa_nodes,
        sockets,
        shared_caches,
        cores,
        processing_units,
    })
}

#[cfg(all(feature = "topology-hwloc", not(windows)))]
fn collect_objects(
    topology: &hwloc::Topology,
    object_type: &hwloc::ObjectType,
) -> Vec<TopologyObjectSnapshot> {
    let objects_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        topology.objects_with_type(object_type)
    }));
    let objects = match objects_result {
        Ok(Ok(values)) => values,
        _ => return Vec::new(),
    };

    objects
        .iter()
        .map(|object| TopologyObjectSnapshot {
            object_type: object_type_name(&object.object_type()).to_string(),
            logical_index: object.logical_index(),
            os_index: object.os_index(),
            depth: object.depth(),
            cpuset: object.cpuset().map(|set| set.to_string()),
            nodeset: object.nodeset().map(|set| set.to_string()),
        })
        .collect()
}

#[cfg(all(feature = "topology-hwloc", not(windows)))]
fn collect_caches(topology: &hwloc::Topology) -> Vec<CacheTopologySnapshot> {
    use hwloc::ObjectType;

    const CACHE_TYPES: [ObjectType; 8] = [
        ObjectType::L1Cache,
        ObjectType::L2Cache,
        ObjectType::L3Cache,
        ObjectType::L4Cache,
        ObjectType::L5Cache,
        ObjectType::L1iCache,
        ObjectType::L2iCache,
        ObjectType::L3iCache,
    ];

    let mut caches = Vec::new();
    for cache_type in CACHE_TYPES {
        let objects_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            topology.objects_with_type(&cache_type)
        }));
        let objects = match objects_result {
            Ok(Ok(values)) => values,
            _ => continue,
        };
        for object in objects {
            let attributes = object.cache_attributes();
            caches.push(CacheTopologySnapshot {
                object_type: object_type_name(&object.object_type()).to_string(),
                logical_index: object.logical_index(),
                os_index: object.os_index(),
                depth: object.depth(),
                cpuset: object.cpuset().map(|set| set.to_string()),
                nodeset: object.nodeset().map(|set| set.to_string()),
                cache_level: attributes.map(|value| value.depth()).unwrap_or(0),
                size_bytes: attributes.map(|value| value.size()).unwrap_or(0),
            });
        }
    }
    caches
}

#[cfg(all(feature = "topology-hwloc", not(windows)))]
fn object_type_name(object_type: &hwloc::ObjectType) -> &'static str {
    use hwloc::ObjectType;

    match object_type {
        ObjectType::Machine => "Machine",
        ObjectType::Package => "Package",
        ObjectType::Core => "Core",
        ObjectType::PU => "PU",
        ObjectType::L1Cache => "L1Cache",
        ObjectType::L2Cache => "L2Cache",
        ObjectType::L3Cache => "L3Cache",
        ObjectType::L4Cache => "L4Cache",
        ObjectType::L5Cache => "L5Cache",
        ObjectType::L1iCache => "L1iCache",
        ObjectType::L2iCache => "L2iCache",
        ObjectType::L3iCache => "L3iCache",
        ObjectType::NUMANode => "NUMANode",
        ObjectType::Group => "Group",
        ObjectType::Bridge => "Bridge",
        ObjectType::PCIDevice => "PCIDevice",
        ObjectType::OSDevice => "OSDevice",
        ObjectType::Misc => "Misc",
        ObjectType::Memcache => "MemCache",
        ObjectType::Die => "Die",
        _ => "Other",
    }
}

#[cfg(all(feature = "topology-hwloc", not(windows)))]
fn sort_objects(values: &mut [TopologyObjectSnapshot]) {
    values.sort_by_key(|value| (value.depth, value.logical_index, value.os_index));
}

#[cfg(all(feature = "topology-hwloc", not(windows)))]
fn sort_caches(values: &mut [CacheTopologySnapshot]) {
    values.sort_by_key(|value| {
        (
            value.cache_level,
            value.depth,
            value.logical_index,
            value.os_index,
        )
    });
}

fn current_time_unix_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis() as u64,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        NumaPlacementPolicy, NumaPolicyMode, TOPOLOGY_SNAPSHOT_SCHEMA_VERSION,
        TopologyCaptureOptions, TopologyObjectSnapshot, TopologySnapshot, TopologySource,
        TopologySummary, capture_topology_snapshot, capture_topology_snapshot_with_options,
        cpuset_contains_os_index,
    };

    fn sample_topology() -> TopologySnapshot {
        TopologySnapshot {
            schema_version: TOPOLOGY_SNAPSHOT_SCHEMA_VERSION,
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
                    cpuset: Some("0x00000003".to_string()),
                    nodeset: None,
                },
                TopologyObjectSnapshot {
                    object_type: "Package".to_string(),
                    logical_index: 1,
                    os_index: 1,
                    depth: 0,
                    cpuset: Some("0x0000000c".to_string()),
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
    fn snapshot_shape_has_stable_counts() {
        let snapshot = capture_topology_snapshot();
        assert!(snapshot.is_ok());
        let snapshot = match snapshot {
            Ok(value) => value,
            Err(_) => return,
        };

        assert_eq!(snapshot.schema_version, TOPOLOGY_SNAPSHOT_SCHEMA_VERSION);
        assert_eq!(
            snapshot.summary.numa_node_count as usize,
            snapshot.numa_nodes.len()
        );
        assert_eq!(
            snapshot.summary.socket_count as usize,
            snapshot.sockets.len()
        );
        assert_eq!(
            snapshot.summary.shared_cache_count as usize,
            snapshot.shared_caches.len()
        );
        assert_eq!(snapshot.summary.core_count as usize, snapshot.cores.len());
        assert_eq!(
            snapshot.summary.processing_unit_count as usize,
            snapshot.processing_units.len()
        );
    }

    #[test]
    fn snapshot_is_serializable_to_and_from_json() {
        let snapshot = capture_topology_snapshot();
        assert!(snapshot.is_ok());
        let snapshot = match snapshot {
            Ok(value) => value,
            Err(_) => return,
        };

        let json = serde_json::to_string(&snapshot);
        assert!(json.is_ok());
        let json = match json {
            Ok(value) => value,
            Err(_) => return,
        };

        let decoded = serde_json::from_str::<super::TopologySnapshot>(&json);
        assert!(decoded.is_ok());
        let decoded = match decoded {
            Ok(value) => value,
            Err(_) => return,
        };

        assert_eq!(decoded.schema_version, TOPOLOGY_SNAPSHOT_SCHEMA_VERSION);
        assert_eq!(decoded.summary, snapshot.summary);
    }

    #[cfg(all(feature = "topology-hwloc", not(windows)))]
    #[test]
    fn hwloc_capture_contains_required_sections() {
        let snapshot = capture_topology_snapshot();
        assert!(snapshot.is_ok());
        let snapshot = match snapshot {
            Ok(value) => value,
            Err(_) => return,
        };

        assert_eq!(snapshot.source, TopologySource::Hwloc);
        assert!(snapshot.summary.processing_unit_count > 0);
        assert!(snapshot.summary.core_count > 0);
        assert_eq!(
            snapshot.summary.numa_node_count as usize,
            snapshot.numa_nodes.len()
        );
        assert_eq!(
            snapshot.summary.socket_count as usize,
            snapshot.sockets.len()
        );
        assert_eq!(
            snapshot.summary.shared_cache_count as usize,
            snapshot.shared_caches.len()
        );
        assert!(
            snapshot
                .numa_nodes
                .iter()
                .all(|value| value.object_type == "NUMANode")
        );
        assert!(
            snapshot
                .sockets
                .iter()
                .all(|value| value.object_type == "Package")
        );
        assert!(
            snapshot
                .cores
                .iter()
                .all(|value| value.object_type == "Core")
        );
        assert!(
            snapshot
                .processing_units
                .iter()
                .all(|value| value.object_type == "PU")
        );
        assert_eq!(
            snapshot.summary.smt_enabled,
            snapshot.summary.processing_unit_count > snapshot.summary.core_count
        );
    }

    #[cfg(not(all(feature = "topology-hwloc", not(windows))))]
    #[test]
    fn fallback_capture_is_used_without_hwloc_feature() {
        let snapshot = capture_topology_snapshot();
        assert!(snapshot.is_ok());
        let snapshot = match snapshot {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(snapshot.source, TopologySource::Fallback);
        assert!(snapshot.summary.processing_unit_count > 0);
    }

    #[test]
    fn capture_can_be_disabled_by_user_option() {
        let snapshot =
            capture_topology_snapshot_with_options(TopologyCaptureOptions { enabled: false });
        assert!(snapshot.is_ok());
        let snapshot = match snapshot {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(snapshot.source, TopologySource::Disabled);
        assert_eq!(snapshot.summary.processing_unit_count, 0);
    }

    #[test]
    fn processing_unit_locality_maps_numa_and_socket_domains() {
        let snapshot = sample_topology();
        let locality = snapshot.processing_unit_locality(2);
        assert!(locality.is_some());
        let locality = match locality {
            Some(value) => value,
            None => return,
        };
        assert_eq!(locality.processing_unit_os_index, 2);
        assert_eq!(locality.numa_node_os_index, Some(1));
        assert_eq!(locality.socket_os_index, Some(1));
        assert!(snapshot.is_numa_aware());
    }

    #[test]
    fn cpuset_matching_supports_hex_masks_and_ranges() {
        assert!(cpuset_contains_os_index("0x00000005", 0));
        assert!(cpuset_contains_os_index("0x00000005", 2));
        assert!(!cpuset_contains_os_index("0x00000005", 1));
        assert!(cpuset_contains_os_index("3-5", 4));
        assert!(!cpuset_contains_os_index("3-5", 6));
    }

    #[test]
    fn numa_policy_helpers_emit_expected_modes() {
        let disabled = NumaPlacementPolicy::disabled();
        assert_eq!(disabled.mode, NumaPolicyMode::Disabled);
        assert_eq!(disabled.numa_node_os_index, None);

        let preferred = NumaPlacementPolicy::prefer_node(0, Some(3));
        assert_eq!(preferred.mode, NumaPolicyMode::Prefer);
        assert_eq!(preferred.numa_node_os_index, Some(0));
        assert_eq!(preferred.cpu_os_index, Some(3));

        let bind = NumaPlacementPolicy::bind_node(1, Some(7));
        assert_eq!(bind.mode, NumaPolicyMode::Bind);
        assert_eq!(bind.numa_node_os_index, Some(1));
        assert_eq!(bind.cpu_os_index, Some(7));
    }
}
