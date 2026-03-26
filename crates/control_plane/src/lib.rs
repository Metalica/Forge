#![forbid(unsafe_code)]

pub mod agent_orchestrator;
pub mod benchmark;
pub mod extension_host;
pub mod feature_policy;
pub mod io_policy;
pub mod lmdb_metadata;
pub mod mcp_bridge;
pub mod project_memory;
pub mod scheduler;

pub mod commands {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum CommandScope {
        Shell,
        Workspace,
        Editor,
        Runtime,
        Agent,
        Jobs,
        Extensions,
        System,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PermissionRequirement {
        None,
        UserApproval,
        Elevated,
    }

    /// Command envelope for cross-module coordination.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Command {
        pub id: &'static str,
        pub source: &'static str,
        pub scope: CommandScope,
        pub permission: PermissionRequirement,
    }

    impl Command {
        pub fn new(
            id: &'static str,
            source: &'static str,
            scope: CommandScope,
            permission: PermissionRequirement,
        ) -> Self {
            Self {
                id,
                source,
                scope,
                permission,
            }
        }
    }
}
