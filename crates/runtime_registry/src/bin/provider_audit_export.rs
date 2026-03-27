use runtime_registry::local_api_hardening::save_redacted_provider_adapter_audit_events_to_path;
use std::env;
use std::error::Error;
use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExportArgs {
    out_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderAuditExportError {
    message: String,
}

impl ProviderAuditExportError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ProviderAuditExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ProviderAuditExportError {}

impl ExportArgs {
    fn parse() -> Result<Self, ProviderAuditExportError> {
        let mut out_path = None::<PathBuf>;
        let mut args = env::args().skip(1);
        while let Some(flag) = args.next() {
            if flag == "--help" || flag == "-h" {
                return Err(ProviderAuditExportError::new(Self::usage()));
            }
            let value = args.next().ok_or_else(|| {
                ProviderAuditExportError::new(format!(
                    "missing value for argument {flag}\n\n{}",
                    Self::usage()
                ))
            })?;
            match flag.as_str() {
                "--out" => out_path = Some(PathBuf::from(value)),
                _ => {
                    return Err(ProviderAuditExportError::new(format!(
                        "unknown argument {flag}\n\n{}",
                        Self::usage()
                    )));
                }
            }
        }

        let out_path = out_path.ok_or_else(|| {
            ProviderAuditExportError::new(format!("missing --out argument\n\n{}", Self::usage()))
        })?;
        Ok(Self { out_path })
    }

    fn usage() -> String {
        "Usage:\n  provider_audit_export --out <path>\n\nExample:\n  cargo run -p runtime_registry --bin provider_audit_export -- --out E:/Forge/.tmp/security/provider_adapter_audit_events.json".to_string()
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), ProviderAuditExportError> {
    let args = ExportArgs::parse()?;
    save_redacted_provider_adapter_audit_events_to_path(args.out_path.as_path())
        .map_err(ProviderAuditExportError::new)?;
    println!(
        "provider adapter redacted audit events exported to {}",
        args.out_path.display()
    );
    Ok(())
}
