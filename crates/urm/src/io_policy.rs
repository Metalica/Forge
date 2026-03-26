use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IoWorkloadClass {
    Download,
    Indexing,
    LogStreaming,
    FileCopy,
}

impl IoWorkloadClass {
    pub fn key(self) -> &'static str {
        match self {
            IoWorkloadClass::Download => "download",
            IoWorkloadClass::Indexing => "indexing",
            IoWorkloadClass::LogStreaming => "log_streaming",
            IoWorkloadClass::FileCopy => "file_copy",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IoPolicyMode {
    Disabled,
    PreferIoUring,
    RequireIoUring,
}

impl IoPolicyMode {
    pub fn prefers_fast_path(self) -> bool {
        matches!(
            self,
            IoPolicyMode::PreferIoUring | IoPolicyMode::RequireIoUring
        )
    }

    pub fn requires_fast_path(self) -> bool {
        matches!(self, IoPolicyMode::RequireIoUring)
    }
}

#[cfg(test)]
mod tests {
    use super::{IoPolicyMode, IoWorkloadClass};

    #[test]
    fn workload_keys_are_stable() {
        assert_eq!(IoWorkloadClass::Download.key(), "download");
        assert_eq!(IoWorkloadClass::Indexing.key(), "indexing");
        assert_eq!(IoWorkloadClass::LogStreaming.key(), "log_streaming");
        assert_eq!(IoWorkloadClass::FileCopy.key(), "file_copy");
    }

    #[test]
    fn policy_mode_fast_path_intent_is_reported() {
        assert!(!IoPolicyMode::Disabled.prefers_fast_path());
        assert!(IoPolicyMode::PreferIoUring.prefers_fast_path());
        assert!(IoPolicyMode::RequireIoUring.prefers_fast_path());
        assert!(!IoPolicyMode::PreferIoUring.requires_fast_path());
        assert!(IoPolicyMode::RequireIoUring.requires_fast_path());
    }
}
