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
    }
    Ok(())
}
