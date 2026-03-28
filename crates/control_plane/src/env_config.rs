use std::env;

pub(crate) fn read_optional(name: &str) -> Option<String> {
    env::var(name).ok()
}

pub(crate) fn read_strict_one_flag(name: &str) -> Option<bool> {
    env::var(name).ok().map(|value| value.trim() == "1")
}

pub(crate) fn read_flexible_flag(name: &str) -> Option<bool> {
    match env::var(name).ok()?.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}
