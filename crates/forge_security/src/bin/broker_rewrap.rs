use forge_security::broker::{
    EnvAesKekAdapter, EnvArgon2idKekAdapter, KekAdapter, rotate_encrypted_store_kek,
};
use std::env;
use std::error::Error;
use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KekMode {
    EnvAes,
    EnvArgon2id,
}

impl KekMode {
    fn parse(value: &str) -> Result<Self, BrokerRewrapError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "env-aes" => Ok(Self::EnvAes),
            "env-argon2id" => Ok(Self::EnvArgon2id),
            _ => Err(BrokerRewrapError::new(format!(
                "invalid KEK mode {value}; expected one of: env-aes, env-argon2id"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RewrapArgs {
    store_path: PathBuf,
    from_kek_mode: KekMode,
    from_kek_id: String,
    from_kek_env: String,
    from_kek_salt_env: Option<String>,
    to_kek_mode: KekMode,
    to_kek_id: String,
    to_kek_env: String,
    to_kek_salt_env: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BrokerRewrapError {
    message: String,
}

impl BrokerRewrapError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for BrokerRewrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for BrokerRewrapError {}

impl From<String> for BrokerRewrapError {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl RewrapArgs {
    fn parse() -> Result<Self, BrokerRewrapError> {
        let mut store_path = None::<PathBuf>;
        let mut from_kek_mode = KekMode::EnvAes;
        let mut from_kek_id = None::<String>;
        let mut from_kek_env = None::<String>;
        let mut from_kek_salt_env = None::<String>;
        let mut to_kek_mode = KekMode::EnvAes;
        let mut to_kek_id = None::<String>;
        let mut to_kek_env = None::<String>;
        let mut to_kek_salt_env = None::<String>;

        let mut args = env::args().skip(1);
        while let Some(flag) = args.next() {
            if flag == "--help" || flag == "-h" {
                return Err(BrokerRewrapError::new(Self::usage()));
            }
            let value = args
                .next()
                .ok_or_else(|| format!("missing value for argument {flag}\n\n{}", Self::usage()))?;
            match flag.as_str() {
                "--store" => store_path = Some(PathBuf::from(value)),
                "--from-kek-mode" => from_kek_mode = KekMode::parse(&value)?,
                "--from-kek-id" => from_kek_id = Some(value),
                "--from-kek-env" => from_kek_env = Some(value),
                "--from-kek-salt-env" => from_kek_salt_env = Some(value),
                "--to-kek-mode" => to_kek_mode = KekMode::parse(&value)?,
                "--to-kek-id" => to_kek_id = Some(value),
                "--to-kek-env" => to_kek_env = Some(value),
                "--to-kek-salt-env" => to_kek_salt_env = Some(value),
                _ => {
                    return Err(BrokerRewrapError::new(format!(
                        "unknown argument {flag}\n\n{}",
                        Self::usage()
                    )));
                }
            }
        }

        let store_path = store_path.ok_or_else(|| {
            BrokerRewrapError::new(format!("missing --store argument\n\n{}", Self::usage()))
        })?;
        let from_kek_id = from_kek_id.ok_or_else(|| {
            BrokerRewrapError::new(format!(
                "missing --from-kek-id argument\n\n{}",
                Self::usage()
            ))
        })?;
        let from_kek_env = from_kek_env.ok_or_else(|| {
            BrokerRewrapError::new(format!(
                "missing --from-kek-env argument\n\n{}",
                Self::usage()
            ))
        })?;
        let to_kek_id = to_kek_id.ok_or_else(|| {
            BrokerRewrapError::new(format!("missing --to-kek-id argument\n\n{}", Self::usage()))
        })?;
        let to_kek_env = to_kek_env.ok_or_else(|| {
            BrokerRewrapError::new(format!(
                "missing --to-kek-env argument\n\n{}",
                Self::usage()
            ))
        })?;
        if from_kek_mode == KekMode::EnvArgon2id && from_kek_salt_env.is_none() {
            return Err(BrokerRewrapError::new(format!(
                "missing --from-kek-salt-env for --from-kek-mode env-argon2id\n\n{}",
                Self::usage()
            )));
        }
        if from_kek_mode == KekMode::EnvAes && from_kek_salt_env.is_some() {
            return Err(BrokerRewrapError::new(
                "--from-kek-salt-env is only valid when --from-kek-mode env-argon2id",
            ));
        }
        if to_kek_mode != KekMode::EnvAes {
            return Err(BrokerRewrapError::new(
                "destination KEK mode must be env-aes because wrapping to argon2id fallback is disallowed",
            ));
        }
        if to_kek_salt_env.is_some() {
            return Err(BrokerRewrapError::new(
                "--to-kek-salt-env is only valid when --to-kek-mode env-argon2id",
            ));
        }

        Ok(Self {
            store_path,
            from_kek_mode,
            from_kek_id,
            from_kek_env,
            from_kek_salt_env,
            to_kek_mode,
            to_kek_id,
            to_kek_env,
            to_kek_salt_env,
        })
    }

    fn usage() -> String {
        "Usage:
  broker_rewrap --store <path> --from-kek-mode <env-aes|env-argon2id> --from-kek-id <id> --from-kek-env <ENV_VAR> [--from-kek-salt-env <ENV_VAR>] --to-kek-mode <env-aes> --to-kek-id <id> --to-kek-env <ENV_VAR>

Examples:
  cargo run -p forge_security --bin broker_rewrap -- --store E:/Forge/.tmp/broker.json --from-kek-mode env-aes --from-kek-id kek-v1 --from-kek-env FORGE_KEK_OLD --to-kek-mode env-aes --to-kek-id kek-v2 --to-kek-env FORGE_KEK_NEW
  cargo run -p forge_security --bin broker_rewrap -- --store E:/Forge/.tmp/broker.json --from-kek-mode env-argon2id --from-kek-id legacy-argon --from-kek-env FORGE_KEK_PASSPHRASE --from-kek-salt-env FORGE_KEK_SALT --to-kek-mode env-aes --to-kek-id kek-v2 --to-kek-env FORGE_KEK_NEW".to_string()
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), BrokerRewrapError> {
    let args = RewrapArgs::parse()?;
    let from_adapter = build_source_kek_adapter(&args)?;
    let to_adapter = build_destination_kek_adapter(&args)?;
    rotate_encrypted_store_kek(
        args.store_path.as_path(),
        from_adapter.as_ref(),
        to_adapter.as_ref(),
    )
    .map_err(|error| BrokerRewrapError::new(error.to_string()))?;
    println!(
        "broker store rewrapped successfully at {}",
        args.store_path.display()
    );
    Ok(())
}

fn build_source_kek_adapter(args: &RewrapArgs) -> Result<Box<dyn KekAdapter>, BrokerRewrapError> {
    match args.from_kek_mode {
        KekMode::EnvAes => {
            EnvAesKekAdapter::new(args.from_kek_id.clone(), args.from_kek_env.clone())
                .map(|adapter| Box::new(adapter) as Box<dyn KekAdapter>)
                .map_err(|error| BrokerRewrapError::new(error.to_string()))
        }
        KekMode::EnvArgon2id => {
            let salt_env = args
                .from_kek_salt_env
                .clone()
                .ok_or_else(|| BrokerRewrapError::new("missing source argon2id salt env var"))?;
            EnvArgon2idKekAdapter::new(
                args.from_kek_id.clone(),
                args.from_kek_env.clone(),
                salt_env,
            )
            .map(|adapter| Box::new(adapter) as Box<dyn KekAdapter>)
            .map_err(|error| BrokerRewrapError::new(error.to_string()))
        }
    }
}

fn build_destination_kek_adapter(
    args: &RewrapArgs,
) -> Result<Box<dyn KekAdapter>, BrokerRewrapError> {
    if args.to_kek_mode != KekMode::EnvAes {
        return Err(BrokerRewrapError::new(
            "destination KEK mode must be env-aes",
        ));
    }
    if args.to_kek_salt_env.is_some() {
        return Err(BrokerRewrapError::new(
            "--to-kek-salt-env is unsupported for env-aes destination mode",
        ));
    }
    EnvAesKekAdapter::new(args.to_kek_id.clone(), args.to_kek_env.clone())
        .map(|adapter| Box::new(adapter) as Box<dyn KekAdapter>)
        .map_err(|error| BrokerRewrapError::new(error.to_string()))
}
