use forge_security::broker::{
    KekAdapter, LinuxKekCustodyChainAdapter, LinuxKernelKeyringKekAdapter,
    LinuxSecretServiceKekAdapter, LinuxTpm2KekAdapter,
};
use serde::Serialize;
use std::env;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const REPORT_SCHEMA_VERSION: u32 = 1;
const DEFAULT_KEK_ID: &str = "forge-linux-kek";
const ENV_TPM2_CONTEXT: &str = "FORGE_LINUX_KEK_TPM2_CONTEXT";
const ENV_KEYRING_SERIAL: &str = "FORGE_LINUX_KEK_KEYRING_SERIAL";
const ENV_SECRET_SERVICE_REF: &str = "FORGE_LINUX_KEK_SECRET_SERVICE_REF";

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportArgs {
    out_path: PathBuf,
    kek_id: String,
    tpm2_context_path: Option<String>,
    keyring_serial: Option<String>,
    secret_service_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KekCustodyMatrixError {
    message: String,
}

impl KekCustodyMatrixError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for KekCustodyMatrixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for KekCustodyMatrixError {}

impl ReportArgs {
    fn parse() -> Result<Self, KekCustodyMatrixError> {
        let mut out_path = None::<PathBuf>;
        let mut kek_id = DEFAULT_KEK_ID.to_string();
        let mut tpm2_context_path = None::<String>;
        let mut keyring_serial = None::<String>;
        let mut secret_service_ref = None::<String>;

        let mut args = env::args().skip(1);
        while let Some(flag) = args.next() {
            if flag == "--help" || flag == "-h" {
                return Err(KekCustodyMatrixError::new(Self::usage()));
            }
            let value = args.next().ok_or_else(|| {
                KekCustodyMatrixError::new(format!(
                    "missing value for argument {flag}\n\n{}",
                    Self::usage()
                ))
            })?;
            match flag.as_str() {
                "--out" => out_path = Some(PathBuf::from(value)),
                "--kek-id" => kek_id = value,
                "--linux-tpm2-context-path" => tpm2_context_path = Some(value),
                "--linux-keyring-serial" => keyring_serial = Some(value),
                "--linux-secret-service-ref" => secret_service_ref = Some(value),
                _ => {
                    return Err(KekCustodyMatrixError::new(format!(
                        "unknown argument {flag}\n\n{}",
                        Self::usage()
                    )));
                }
            }
        }

        let out_path = out_path.ok_or_else(|| {
            KekCustodyMatrixError::new(format!("missing --out argument\n\n{}", Self::usage()))
        })?;
        if kek_id.trim().is_empty() {
            return Err(KekCustodyMatrixError::new("kek id cannot be empty"));
        }
        Ok(Self {
            out_path,
            kek_id,
            tpm2_context_path: tpm2_context_path
                .or_else(|| read_optional_non_empty_env(ENV_TPM2_CONTEXT)),
            keyring_serial: keyring_serial
                .or_else(|| read_optional_non_empty_env(ENV_KEYRING_SERIAL)),
            secret_service_ref: secret_service_ref
                .or_else(|| read_optional_non_empty_env(ENV_SECRET_SERVICE_REF)),
        })
    }

    fn usage() -> String {
        "Usage:
  kek_custody_matrix_report --out <path> [--kek-id <id>] [--linux-tpm2-context-path <path>] [--linux-keyring-serial <serial>] [--linux-secret-service-ref <lookup>]

Env fallback:
  FORGE_LINUX_KEK_TPM2_CONTEXT
  FORGE_LINUX_KEK_KEYRING_SERIAL
  FORGE_LINUX_KEK_SECRET_SERVICE_REF

Example:
  cargo run -p forge_security --bin kek_custody_matrix_report -- --out E:/Forge/.tmp/security/kek_custody_matrix.json".to_string()
    }
}

fn read_optional_non_empty_env(name: &str) -> Option<String> {
    env::var(name).ok().and_then(|value| {
        if value.trim().is_empty() {
            None
        } else {
            Some(value)
        }
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct AdapterProbe {
    adapter: String,
    configured: bool,
    status: String,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct LinuxKekCustodyReport {
    baseline_order: Vec<String>,
    configured_tpm2: bool,
    configured_keyring: bool,
    configured_secret_service: bool,
    adapters: Vec<AdapterProbe>,
    custody_chain_probe: AdapterProbe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct KekCustodyMatrixReport {
    schema_version: u32,
    generated_at_unix_ms: u64,
    target_os: String,
    argon2id_policy: String,
    linux: LinuxKekCustodyReport,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), KekCustodyMatrixError> {
    let args = ReportArgs::parse()?;
    let report = build_report(&args);
    if let Some(parent) = args.out_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| {
            KekCustodyMatrixError::new(format!(
                "failed to create report directory {}: {error}",
                parent.display()
            ))
        })?;
    }
    let encoded = serde_json::to_string_pretty(&report).map_err(|error| {
        KekCustodyMatrixError::new(format!("report serialization failed: {error}"))
    })?;
    fs::write(&args.out_path, encoded).map_err(|error| {
        KekCustodyMatrixError::new(format!(
            "report write failed at {}: {error}",
            args.out_path.display()
        ))
    })?;
    println!(
        "kek custody matrix report exported to {}",
        args.out_path.display()
    );
    Ok(())
}

fn build_report(args: &ReportArgs) -> KekCustodyMatrixReport {
    KekCustodyMatrixReport {
        schema_version: REPORT_SCHEMA_VERSION,
        generated_at_unix_ms: now_unix_ms(),
        target_os: env::consts::OS.to_string(),
        argon2id_policy: "fallback_unwrap_only_never_primary_storage".to_string(),
        linux: build_linux_report(args),
    }
}

fn build_linux_report(args: &ReportArgs) -> LinuxKekCustodyReport {
    let mut adapters = Vec::with_capacity(3);
    let mut chain_status = AdapterProbe {
        adapter: "linux-custody-chain".to_string(),
        configured: false,
        status: "skipped_unconfigured".to_string(),
        detail: "requires both tpm2 context path and keyring serial".to_string(),
    };

    let tpm2_probe = if let Some(context_path) = args.tpm2_context_path.clone() {
        probe_linux_adapter(
            "linux-tpm2",
            LinuxTpm2KekAdapter::new(args.kek_id.clone(), context_path)
                .map(|adapter| Box::new(adapter) as Box<dyn KekAdapter>),
        )
    } else {
        AdapterProbe {
            adapter: "linux-tpm2".to_string(),
            configured: false,
            status: "skipped_unconfigured".to_string(),
            detail: format!("set --linux-tpm2-context-path or {ENV_TPM2_CONTEXT}"),
        }
    };
    adapters.push(tpm2_probe);

    let keyring_probe = if let Some(serial) = args.keyring_serial.clone() {
        probe_linux_adapter(
            "linux-keyring",
            LinuxKernelKeyringKekAdapter::new(args.kek_id.clone(), serial)
                .map(|adapter| Box::new(adapter) as Box<dyn KekAdapter>),
        )
    } else {
        AdapterProbe {
            adapter: "linux-keyring".to_string(),
            configured: false,
            status: "skipped_unconfigured".to_string(),
            detail: format!("set --linux-keyring-serial or {ENV_KEYRING_SERIAL}"),
        }
    };
    adapters.push(keyring_probe);

    let secret_service_probe = if let Some(lookup) = args.secret_service_ref.clone() {
        probe_linux_adapter(
            "linux-secret-service",
            LinuxSecretServiceKekAdapter::new(args.kek_id.clone(), lookup)
                .map(|adapter| Box::new(adapter) as Box<dyn KekAdapter>),
        )
    } else {
        AdapterProbe {
            adapter: "linux-secret-service".to_string(),
            configured: false,
            status: "skipped_unconfigured".to_string(),
            detail: format!("optional; set --linux-secret-service-ref or {ENV_SECRET_SERVICE_REF}"),
        }
    };
    adapters.push(secret_service_probe);

    if let (Some(context_path), Some(keyring_serial)) =
        (args.tpm2_context_path.clone(), args.keyring_serial.clone())
    {
        chain_status = probe_linux_adapter(
            "linux-custody-chain",
            LinuxKekCustodyChainAdapter::new(
                args.kek_id.clone(),
                context_path,
                keyring_serial,
                args.secret_service_ref.clone(),
            )
            .map(|adapter| Box::new(adapter) as Box<dyn KekAdapter>),
        );
    }

    LinuxKekCustodyReport {
        baseline_order: vec![
            "linux-tpm2".to_string(),
            "linux-keyring".to_string(),
            "linux-secret-service".to_string(),
        ],
        configured_tpm2: args.tpm2_context_path.is_some(),
        configured_keyring: args.keyring_serial.is_some(),
        configured_secret_service: args.secret_service_ref.is_some(),
        adapters,
        custody_chain_probe: chain_status,
    }
}

fn probe_linux_adapter(
    adapter_name: &str,
    adapter: Result<Box<dyn KekAdapter>, forge_security::broker::SecretBrokerError>,
) -> AdapterProbe {
    let adapter = match adapter {
        Ok(value) => value,
        Err(error) => {
            return AdapterProbe {
                adapter: adapter_name.to_string(),
                configured: true,
                status: "configuration_error".to_string(),
                detail: error.to_string(),
            };
        }
    };
    let mut probe_dek = [0xAB_u8; 32];
    let wrapped = adapter.wrap_key(&probe_dek);
    probe_dek.fill(0);
    match wrapped {
        Ok(wrapped) => match adapter.unwrap_key(wrapped.as_slice()) {
            Ok(unwrapped) => {
                if unwrapped == [0xAB_u8; 32] {
                    AdapterProbe {
                        adapter: adapter_name.to_string(),
                        configured: true,
                        status: "ok".to_string(),
                        detail: "adapter wrap/unwrap probe passed".to_string(),
                    }
                } else {
                    AdapterProbe {
                        adapter: adapter_name.to_string(),
                        configured: true,
                        status: "probe_failed".to_string(),
                        detail: "adapter unwrap probe returned unexpected key bytes".to_string(),
                    }
                }
            }
            Err(error) => AdapterProbe {
                adapter: adapter_name.to_string(),
                configured: true,
                status: "probe_failed".to_string(),
                detail: format!("unwrap failed: {error}"),
            },
        },
        Err(error) => AdapterProbe {
            adapter: adapter_name.to_string(),
            configured: true,
            status: "probe_failed".to_string(),
            detail: format!("wrap failed: {error}"),
        },
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}
