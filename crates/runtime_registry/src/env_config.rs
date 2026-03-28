use std::env;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequiredEnvError {
    Missing,
    Empty,
}

pub(crate) fn read_optional_non_empty(name: &str) -> Option<String> {
    env::var(name).ok().as_deref().and_then(trim_to_non_empty)
}

pub(crate) fn read_required_non_empty(name: &str) -> Result<String, RequiredEnvError> {
    let value = env::var(name).map_err(|_| RequiredEnvError::Missing)?;
    trim_to_non_empty(value.as_str()).ok_or(RequiredEnvError::Empty)
}

pub(crate) fn read_flexible_flag(name: &str) -> Option<bool> {
    parse_flexible_flag(env::var(name).ok()?.as_str())
}

pub(crate) fn read_strict_one_flag(name: &str) -> Option<bool> {
    env::var(name).ok().map(|value| value.trim() == "1")
}

pub(crate) fn read_positive_u32(name: &str) -> Option<u32> {
    env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|value| *value > 0)
}

pub(crate) fn parse_csv_list_lowercase(raw: &str) -> Vec<String> {
    raw.split([';', ','])
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
}

fn trim_to_non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

fn parse_flexible_flag(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}
