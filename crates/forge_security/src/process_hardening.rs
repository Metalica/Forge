#[cfg(any(target_os = "linux", test))]
use crate::env_config;
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessHardeningError {
    message: String,
}

impl fmt::Display for ProcessHardeningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ProcessHardeningError {}

pub fn enforce_process_dumpability_controls() -> Result<(), ProcessHardeningError> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::prctl;
        use nix::sys::resource::{Resource, setrlimit};
        use std::path::Path;

        setrlimit(Resource::RLIMIT_CORE, 0, 0).map_err(|error| ProcessHardeningError {
            message: format!("failed to disable process core dumps: {error}"),
        })?;
        prctl::set_dumpable(false).map_err(|error| ProcessHardeningError {
            message: format!("failed to set process non-dumpable: {error}"),
        })?;
        let dumpable = prctl::get_dumpable().map_err(|error| ProcessHardeningError {
            message: format!("failed to verify process non-dumpable status: {error}"),
        })?;
        if dumpable {
            return Err(ProcessHardeningError {
                message: "process remains dumpable after hardening controls".to_string(),
            });
        }

        prctl::set_no_new_privs().map_err(|error| ProcessHardeningError {
            message: format!("failed to set no_new_privs sandbox baseline: {error}"),
        })?;
        let no_new_privs = prctl::get_no_new_privs().map_err(|error| ProcessHardeningError {
            message: format!("failed to verify no_new_privs sandbox baseline: {error}"),
        })?;
        if !no_new_privs {
            return Err(ProcessHardeningError {
                message: "no_new_privs baseline was not enforced".to_string(),
            });
        }

        if env_flag_enabled("FORGE_REQUIRE_LINUX_SECCOMP_PROFILE") {
            let status = std::fs::read_to_string("/proc/self/status").map_err(|error| {
                ProcessHardeningError {
                    message: format!(
                        "failed to read /proc/self/status for strict sandbox checks: {error}"
                    ),
                }
            })?;
            let landlock_available = Path::new("/sys/kernel/security/landlock").exists();
            ensure_optional_linux_sandbox_requirements(
                status.as_str(),
                true,
                env_flag_enabled("FORGE_REQUIRE_LINUX_LANDLOCK"),
                landlock_available,
            )?;
        } else if env_flag_enabled("FORGE_REQUIRE_LINUX_LANDLOCK") {
            let status = std::fs::read_to_string("/proc/self/status").map_err(|error| {
                ProcessHardeningError {
                    message: format!(
                        "failed to read /proc/self/status for strict sandbox checks: {error}"
                    ),
                }
            })?;
            let landlock_available = Path::new("/sys/kernel/security/landlock").exists();
            ensure_optional_linux_sandbox_requirements(
                status.as_str(),
                false,
                true,
                landlock_available,
            )?;
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn parse_proc_status_numeric_field(status: &str, field: &str) -> Option<u32> {
    for line in status.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim() != field {
            continue;
        }
        return value.trim().parse::<u32>().ok();
    }
    None
}

#[cfg(any(target_os = "linux", test))]
fn env_flag_enabled(name: &str) -> bool {
    env_config::read_opt_in_flag(name)
}

#[cfg(any(target_os = "linux", test))]
fn parse_env_flag(raw: &str) -> bool {
    let normalized = raw.trim().to_ascii_lowercase();
    matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
}

#[cfg(any(target_os = "linux", test))]
fn ensure_optional_linux_sandbox_requirements(
    proc_status: &str,
    require_seccomp: bool,
    require_landlock: bool,
    landlock_available: bool,
) -> Result<(), ProcessHardeningError> {
    if require_seccomp {
        let seccomp_mode = parse_proc_status_numeric_field(proc_status, "Seccomp").unwrap_or(0);
        if seccomp_mode == 0 {
            return Err(ProcessHardeningError {
                message: "strict sandbox requires seccomp profile but /proc/self/status reports Seccomp=0".to_string(),
            });
        }
    }

    if require_landlock && !landlock_available {
        return Err(ProcessHardeningError {
            message:
                "strict sandbox requires landlock but kernel landlock interface is unavailable"
                    .to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_optional_linux_sandbox_requirements, env_flag_enabled, parse_env_flag,
        parse_proc_status_numeric_field,
    };

    #[test]
    fn parse_proc_status_numeric_field_extracts_value() {
        let status = "Name:\tforge\nPid:\t123\nSeccomp:\t2\nNoNewPrivs:\t1\n";
        assert_eq!(parse_proc_status_numeric_field(status, "Seccomp"), Some(2));
        assert_eq!(
            parse_proc_status_numeric_field(status, "NoNewPrivs"),
            Some(1)
        );
    }

    #[test]
    fn parse_proc_status_numeric_field_returns_none_for_missing_or_invalid_values() {
        let status = "Name:\tforge\nSeccomp:\tn/a\n";
        assert_eq!(parse_proc_status_numeric_field(status, "NoNewPrivs"), None);
        assert_eq!(parse_proc_status_numeric_field(status, "Seccomp"), None);
    }

    #[test]
    fn parse_env_flag_accepts_common_truthy_values() {
        assert!(parse_env_flag("1"));
        assert!(parse_env_flag("true"));
        assert!(parse_env_flag("yes"));
        assert!(parse_env_flag("ON"));
        assert!(!parse_env_flag("0"));
        assert!(!parse_env_flag("false"));
    }

    #[test]
    fn env_flag_enabled_returns_false_when_missing() {
        assert!(!env_flag_enabled("FORGE_TEST_TRUTHY_FLAG"));
    }

    #[test]
    fn strict_sandbox_requirements_fail_when_seccomp_is_required_but_disabled() {
        let status = "Name:\tforge\nSeccomp:\t0\nNoNewPrivs:\t1\n";
        let result = ensure_optional_linux_sandbox_requirements(status, true, false, true);
        assert!(result.is_err());
    }

    #[test]
    fn strict_sandbox_requirements_pass_when_seccomp_filter_is_active() {
        let status = "Name:\tforge\nSeccomp:\t2\nNoNewPrivs:\t1\n";
        let result = ensure_optional_linux_sandbox_requirements(status, true, false, true);
        assert!(result.is_ok());
    }

    #[test]
    fn strict_sandbox_requirements_fail_when_landlock_is_required_but_unavailable() {
        let status = "Name:\tforge\nSeccomp:\t2\nNoNewPrivs:\t1\n";
        let result = ensure_optional_linux_sandbox_requirements(status, false, true, false);
        assert!(result.is_err());
    }
}
