use urm::allocator_policy::AllocatorPolicy;

#[cfg(not(any(
    feature = "allocator-mimalloc",
    feature = "allocator-jemalloc",
    feature = "allocator-snmalloc"
)))]
compile_error!(
    "execution_plane requires one allocator build mode feature: allocator-mimalloc, allocator-jemalloc, or allocator-snmalloc"
);

#[cfg(any(
    all(feature = "allocator-mimalloc", feature = "allocator-jemalloc"),
    all(feature = "allocator-mimalloc", feature = "allocator-snmalloc"),
    all(feature = "allocator-jemalloc", feature = "allocator-snmalloc")
))]
compile_error!(
    "execution_plane allocator build mode must be singular; use --no-default-features when selecting allocator-jemalloc or allocator-snmalloc"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocatorBuildMode {
    Mimalloc,
    Jemalloc,
    Snmalloc,
}

impl AllocatorBuildMode {
    pub const fn as_feature_name(self) -> &'static str {
        match self {
            AllocatorBuildMode::Mimalloc => "allocator-mimalloc",
            AllocatorBuildMode::Jemalloc => "allocator-jemalloc",
            AllocatorBuildMode::Snmalloc => "allocator-snmalloc",
        }
    }

    pub const fn as_policy(self) -> AllocatorPolicy {
        match self {
            AllocatorBuildMode::Mimalloc => AllocatorPolicy::Mimalloc,
            AllocatorBuildMode::Jemalloc => AllocatorPolicy::Jemalloc,
            AllocatorBuildMode::Snmalloc => AllocatorPolicy::Snmalloc,
        }
    }
}

pub const fn active_allocator_build_mode() -> AllocatorBuildMode {
    #[cfg(feature = "allocator-mimalloc")]
    {
        AllocatorBuildMode::Mimalloc
    }
    #[cfg(all(not(feature = "allocator-mimalloc"), feature = "allocator-jemalloc"))]
    {
        AllocatorBuildMode::Jemalloc
    }
    #[cfg(all(
        not(feature = "allocator-mimalloc"),
        not(feature = "allocator-jemalloc"),
        feature = "allocator-snmalloc"
    ))]
    {
        AllocatorBuildMode::Snmalloc
    }
}

pub const fn active_allocator_policy() -> AllocatorPolicy {
    active_allocator_build_mode().as_policy()
}

#[cfg(test)]
mod tests {
    use super::{AllocatorBuildMode, active_allocator_build_mode, active_allocator_policy};
    use urm::allocator_policy::AllocatorPolicy;

    #[test]
    fn build_mode_and_policy_are_supported_values() {
        assert!(matches!(
            active_allocator_build_mode(),
            AllocatorBuildMode::Mimalloc
                | AllocatorBuildMode::Jemalloc
                | AllocatorBuildMode::Snmalloc
        ));
        assert!(matches!(
            active_allocator_policy(),
            AllocatorPolicy::Mimalloc | AllocatorPolicy::Jemalloc | AllocatorPolicy::Snmalloc
        ));
    }

    #[cfg(feature = "allocator-mimalloc")]
    #[test]
    fn mimalloc_feature_maps_to_mimalloc_policy() {
        assert_eq!(active_allocator_build_mode(), AllocatorBuildMode::Mimalloc);
        assert_eq!(active_allocator_policy(), AllocatorPolicy::Mimalloc);
    }

    #[cfg(feature = "allocator-jemalloc")]
    #[test]
    fn jemalloc_feature_maps_to_jemalloc_policy() {
        assert_eq!(active_allocator_build_mode(), AllocatorBuildMode::Jemalloc);
        assert_eq!(active_allocator_policy(), AllocatorPolicy::Jemalloc);
    }

    #[cfg(feature = "allocator-snmalloc")]
    #[test]
    fn snmalloc_feature_maps_to_snmalloc_policy() {
        assert_eq!(active_allocator_build_mode(), AllocatorBuildMode::Snmalloc);
        assert_eq!(active_allocator_policy(), AllocatorPolicy::Snmalloc);
    }
}
