use crate::broker::is_secret_env_reference;
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandGuardError {
    message: String,
}

impl CommandGuardError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for CommandGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for CommandGuardError {}

pub fn validate_secret_free_command_line(
    program: &str,
    args: &[String],
) -> Result<(), CommandGuardError> {
    if looks_like_secret_value(program) {
        return Err(CommandGuardError::new(
            "launch request rejected: program contains secret-like material",
        ));
    }
    for (index, arg) in args.iter().enumerate() {
        if looks_like_secret_cli_arg(arg) {
            return Err(CommandGuardError::new(format!(
                "launch request rejected: command-line argument at position {} appears to carry secret material",
                index + 1
            )));
        }
    }
    Ok(())
}

pub fn validate_secret_free_environment(env: &[(String, String)]) -> Result<(), CommandGuardError> {
    for (key, value) in env {
        if is_secret_env_reference(value) {
            continue;
        }
        if looks_like_sensitive_env_key(key) && !value.trim().is_empty() {
            return Err(CommandGuardError::new(
                "launch request rejected: sensitive environment key carries secret material",
            ));
        }
        if looks_like_secret_value(value) {
            return Err(CommandGuardError::new(
                "launch request rejected: environment value appears to contain secret material",
            ));
        }
    }
    Ok(())
}

fn looks_like_secret_cli_arg(arg: &str) -> bool {
    let trimmed = arg.trim();
    if trimmed.is_empty() {
        return false;
    }

    if let Some((key, _value)) = trimmed.split_once('=')
        && is_sensitive_key(key)
    {
        return true;
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("authorization:") && lower.contains("bearer ") {
        return true;
    }
    if lower.starts_with("bearer ") {
        return true;
    }
    false
}

fn is_sensitive_key(raw: &str) -> bool {
    let canonical = raw
        .trim()
        .trim_start_matches('-')
        .trim_start_matches('/')
        .replace('-', "_")
        .to_ascii_lowercase();
    matches!(
        canonical.as_str(),
        "api_key"
            | "apikey"
            | "token"
            | "secret"
            | "password"
            | "authorization"
            | "auth"
            | "bearer"
    )
}

fn looks_like_sensitive_env_key(raw: &str) -> bool {
    let normalized = raw.trim().replace('-', "_").to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    normalized.contains("api_key")
        || normalized.contains("token")
        || normalized.contains("secret")
        || normalized.contains("password")
        || normalized.contains("auth")
        || normalized == "openai_api_key"
}

fn looks_like_secret_value(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() < 24 {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    lower.starts_with("sk-") || lower.starts_with("bearer ")
}

#[cfg(test)]
mod tests {
    use crate::broker::{render_secret_env_reference, with_global_secret_broker};

    use super::{validate_secret_free_command_line, validate_secret_free_environment};

    #[test]
    fn rejects_sensitive_equals_argument() {
        let result = validate_secret_free_command_line(
            "llama-server",
            &[String::from("--api-key=sk-live-secret-value")],
        );
        assert!(result.is_err());
        let result = match result {
            Ok(_) => return,
            Err(value) => value,
        };
        let rendered = result.to_string();
        assert!(!rendered.contains("sk-live-secret-value"));
        assert!(!rendered.contains("api-key"));
    }

    #[test]
    fn rejects_authorization_bearer_header_arg() {
        let result = validate_secret_free_command_line(
            "curl",
            &[String::from("Authorization: Bearer sk-live-secret-value")],
        );
        assert!(result.is_err());
    }

    #[test]
    fn accepts_non_secret_runtime_args() {
        let result = validate_secret_free_command_line(
            "llama-server",
            &[
                String::from("--model"),
                String::from("E:/Forge/models/default.gguf"),
                String::from("--host"),
                String::from("127.0.0.1"),
            ],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_sensitive_environment_key() {
        let result = validate_secret_free_environment(&[(
            String::from("OPENAI_API_KEY"),
            String::from("sk-live-secret-value"),
        )]);
        assert!(result.is_err());
        let result = match result {
            Ok(_) => return,
            Err(value) => value,
        };
        let rendered = result.to_string();
        assert!(!rendered.contains("OPENAI_API_KEY"));
        assert!(!rendered.contains("sk-live-secret-value"));
    }

    #[test]
    fn accepts_non_secret_environment() {
        let result = validate_secret_free_environment(&[
            (String::from("RUST_LOG"), String::from("info")),
            (String::from("FORGE_MODE"), String::from("local")),
        ]);
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_secret_handle_reference_in_environment() {
        let reference = with_global_secret_broker(|broker| {
            let handle = broker.store_secret("OPENAI_API_KEY", "sk-env-ref-secret")?;
            Ok(render_secret_env_reference(&handle))
        });
        assert!(reference.is_ok());
        let reference = match reference {
            Ok(value) => value,
            Err(_) => return,
        };

        let result =
            validate_secret_free_environment(&[(String::from("OPENAI_API_KEY"), reference)]);
        assert!(result.is_ok());
    }
}
