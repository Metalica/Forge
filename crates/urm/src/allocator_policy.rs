use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

pub const DEFAULT_ALLOCATOR_POLICY: AllocatorPolicy = AllocatorPolicy::Mimalloc;
pub const ALLOCATOR_CONTRACT_KEY: &str = "allocator";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllocatorPolicy {
    Mimalloc,
    Jemalloc,
    Snmalloc,
}

impl AllocatorPolicy {
    pub fn as_config_value(self) -> &'static str {
        match self {
            AllocatorPolicy::Mimalloc => "mimalloc",
            AllocatorPolicy::Jemalloc => "jemalloc",
            AllocatorPolicy::Snmalloc => "snmalloc",
        }
    }
}

impl Default for AllocatorPolicy {
    fn default() -> Self {
        DEFAULT_ALLOCATOR_POLICY
    }
}

impl FromStr for AllocatorPolicy {
    type Err = AllocatorPolicyConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim().to_lowercase().replace('-', "_");
        match normalized.as_str() {
            "mimalloc" => Ok(AllocatorPolicy::Mimalloc),
            "jemalloc" => Ok(AllocatorPolicy::Jemalloc),
            "snmalloc" => Ok(AllocatorPolicy::Snmalloc),
            _ => Err(AllocatorPolicyConfigError::UnsupportedAllocator(
                value.to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllocatorPolicyConfig {
    pub allocator: AllocatorPolicy,
}

impl Default for AllocatorPolicyConfig {
    fn default() -> Self {
        Self {
            allocator: DEFAULT_ALLOCATOR_POLICY,
        }
    }
}

impl AllocatorPolicyConfig {
    pub fn from_contract_str(input: &str) -> Result<Self, AllocatorPolicyConfigError> {
        let mut allocator = None;
        for raw_line in input.lines() {
            let line = strip_comments(raw_line).trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(AllocatorPolicyConfigError::InvalidLine(line.to_string()));
            };
            let key = key.trim().to_lowercase();
            let value = unquote(value.trim());
            if key == ALLOCATOR_CONTRACT_KEY {
                allocator = Some(AllocatorPolicy::from_str(value)?);
            }
        }

        let allocator = allocator.ok_or(AllocatorPolicyConfigError::MissingAllocator)?;
        Ok(Self { allocator })
    }

    pub fn to_contract_string(&self) -> String {
        format!("allocator = \"{}\"\n", self.allocator.as_config_value())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllocatorPolicyConfigError {
    MissingAllocator,
    UnsupportedAllocator(String),
    InvalidLine(String),
}

impl fmt::Display for AllocatorPolicyConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AllocatorPolicyConfigError::MissingAllocator => {
                formatter.write_str("allocator setting is required")
            }
            AllocatorPolicyConfigError::UnsupportedAllocator(value) => {
                write!(formatter, "unsupported allocator policy: {value}")
            }
            AllocatorPolicyConfigError::InvalidLine(line) => {
                write!(formatter, "invalid allocator config line: {line}")
            }
        }
    }
}

fn strip_comments(line: &str) -> &str {
    match line.split_once('#') {
        Some((value, _)) => value,
        None => line,
    }
}

fn unquote(value: &str) -> &str {
    if value.len() >= 2 {
        let bytes = value.as_bytes();
        if (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'')
        {
            return &value[1..value.len() - 1];
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::{AllocatorPolicy, AllocatorPolicyConfig, AllocatorPolicyConfigError};

    #[test]
    fn default_allocator_policy_is_explicit() {
        let config = AllocatorPolicyConfig::default();
        assert_eq!(config.allocator, AllocatorPolicy::Mimalloc);
    }

    #[test]
    fn parse_supported_allocator_values() {
        let config = AllocatorPolicyConfig::from_contract_str("allocator = \"mimalloc\"");
        assert!(config.is_ok());
        let config = match config {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(config.allocator, AllocatorPolicy::Mimalloc);

        let config = AllocatorPolicyConfig::from_contract_str("allocator = jemalloc");
        assert!(config.is_ok());
        let config = match config {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(config.allocator, AllocatorPolicy::Jemalloc);

        let config = AllocatorPolicyConfig::from_contract_str("allocator = snmalloc");
        assert!(config.is_ok());
        let config = match config {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(config.allocator, AllocatorPolicy::Snmalloc);
    }

    #[test]
    fn parse_rejects_unsupported_allocator_values() {
        let config = AllocatorPolicyConfig::from_contract_str("allocator = rpmalloc");
        assert!(matches!(
            config,
            Err(AllocatorPolicyConfigError::UnsupportedAllocator(_))
        ));
    }

    #[test]
    fn parse_requires_allocator_key() {
        let config = AllocatorPolicyConfig::from_contract_str("foo = \"mimalloc\"");
        assert!(matches!(
            config,
            Err(AllocatorPolicyConfigError::MissingAllocator)
        ));
    }

    #[test]
    fn contract_round_trip_is_stable() {
        let config = AllocatorPolicyConfig {
            allocator: AllocatorPolicy::Jemalloc,
        };
        let encoded = config.to_contract_string();
        assert_eq!(encoded, "allocator = \"jemalloc\"\n");
        let decoded = AllocatorPolicyConfig::from_contract_str(&encoded);
        assert!(decoded.is_ok());
        let decoded = match decoded {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(decoded, config);
    }
}
