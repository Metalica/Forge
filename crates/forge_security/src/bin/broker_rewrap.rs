use forge_security::broker::{EnvAesKekAdapter, rotate_encrypted_store_kek};
use std::env;
use std::error::Error;
use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
struct RewrapArgs {
    store_path: PathBuf,
    from_kek_id: String,
    from_kek_env: String,
    to_kek_id: String,
    to_kek_env: String,
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
        let mut from_kek_id = None::<String>;
        let mut from_kek_env = None::<String>;
        let mut to_kek_id = None::<String>;
        let mut to_kek_env = None::<String>;

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
                "--from-kek-id" => from_kek_id = Some(value),
                "--from-kek-env" => from_kek_env = Some(value),
                "--to-kek-id" => to_kek_id = Some(value),
                "--to-kek-env" => to_kek_env = Some(value),
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

        Ok(Self {
            store_path,
            from_kek_id,
            from_kek_env,
            to_kek_id,
            to_kek_env,
        })
    }

    fn usage() -> String {
        "Usage:\n  broker_rewrap --store <path> --from-kek-id <id> --from-kek-env <ENV_VAR> --to-kek-id <id> --to-kek-env <ENV_VAR>\n\nExample:\n  cargo run -p forge_security --bin broker_rewrap -- --store E:/Forge/.tmp/broker.json --from-kek-id kek-v1 --from-kek-env FORGE_KEK_OLD --to-kek-id kek-v2 --to-kek-env FORGE_KEK_NEW".to_string()
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
    let from_adapter = EnvAesKekAdapter::new(args.from_kek_id, args.from_kek_env)
        .map_err(|error| BrokerRewrapError::new(error.to_string()))?;
    let to_adapter = EnvAesKekAdapter::new(args.to_kek_id, args.to_kek_env)
        .map_err(|error| BrokerRewrapError::new(error.to_string()))?;
    rotate_encrypted_store_kek(args.store_path.as_path(), &from_adapter, &to_adapter)
        .map_err(|error| BrokerRewrapError::new(error.to_string()))?;
    println!(
        "broker store rewrapped successfully at {}",
        args.store_path.display()
    );
    Ok(())
}
