use std::env;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequiredEnvError {
    Missing,
    Empty,
}

pub(crate) fn read_required(name: &str) -> Result<String, RequiredEnvError> {
    env::var(name).map_err(|_| RequiredEnvError::Missing)
}

pub(crate) fn read_required_non_empty(name: &str) -> Result<String, RequiredEnvError> {
    let value = read_required(name)?;
    if value.trim().is_empty() {
        return Err(RequiredEnvError::Empty);
    }
    Ok(value)
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn read_opt_in_flag(name: &str) -> bool {
    match env::var(name).ok() {
        Some(raw) => parse_opt_in_flag(raw.as_str()),
        None => false,
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_opt_in_flag(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}
