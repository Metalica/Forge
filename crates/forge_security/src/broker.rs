use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const BROKER_PERSISTED_SCHEMA_VERSION: u32 = 1;
const BROKER_AUDIT_SCHEMA_VERSION: u32 = 1;
const BROKER_KEY_WRAP_AAD: &[u8] = b"forge-security-broker-key-wrap-v1";
const SECRET_ENV_REFERENCE_PREFIX: &str = "forge-secret-handle://";
const MAX_AUDIT_EVENTS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretBrokerError {
    message: String,
}

impl SecretBrokerError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for SecretBrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for SecretBrokerError {}

impl From<SecretBrokerError> for String {
    fn from(value: SecretBrokerError) -> Self {
        value.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretHandle(String);

impl SecretHandle {
    fn new(value: String) -> Self {
        Self(value)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn render_secret_env_reference(handle: &SecretHandle) -> String {
    format!("{SECRET_ENV_REFERENCE_PREFIX}{}", handle.as_str())
}

pub fn is_secret_env_reference(value: &str) -> bool {
    value.trim().starts_with(SECRET_ENV_REFERENCE_PREFIX)
}

pub fn resolve_secret_env_reference(value: &str) -> Result<Option<String>, SecretBrokerError> {
    let trimmed = value.trim();
    let Some(handle) = parse_secret_env_reference(trimmed) else {
        return Ok(None);
    };
    with_global_secret_broker(|broker| {
        let injected = broker.inject_secret(&handle, SecretInjectionTarget::Raw)?;
        broker.rotate_or_revoke_secret(&handle, None)?;
        Ok(Some(injected))
    })
}

fn parse_secret_env_reference(value: &str) -> Option<SecretHandle> {
    let handle = value.strip_prefix(SECRET_ENV_REFERENCE_PREFIX)?.trim();
    if handle.is_empty() {
        return None;
    }
    Some(SecretHandle::new(handle.to_string()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretInjectionTarget {
    HttpAuthorizationBearer,
    Raw,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSecret {
    pub handle: SecretHandle,
    pub label: String,
    value: String,
}

impl ResolvedSecret {
    pub fn expose(&self) -> &str {
        &self.value
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SecretRecord {
    label: String,
    secret_bytes: Vec<u8>,
    memory_locked: bool,
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
    access_count: u64,
    revoked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretAuditAction {
    StoreSecret,
    ResolveSecretHandle,
    InjectSecret,
    RotateSecret,
    RevokeSecret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretAuditDecision {
    Allowed,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretAuditEvent {
    pub action: SecretAuditAction,
    pub decision: SecretAuditDecision,
    pub at_unix_ms: u64,
    pub handle: Option<String>,
    pub label: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedSecretAuditLog {
    schema_version: u32,
    events: Vec<SecretAuditEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedSecretStore {
    schema_version: u32,
    records: Vec<PersistedSecretRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedSecretRecord {
    handle: String,
    label: String,
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
    access_count: u64,
    revoked: bool,
    kek_id: Option<String>,
    wrapped_dek_b64: Option<String>,
    nonce_b64: Option<String>,
    ciphertext_b64: Option<String>,
}

pub trait KekAdapter {
    fn kek_id(&self) -> &str;
    fn wrap_key(&self, dek: &[u8; 32]) -> Result<Vec<u8>, SecretBrokerError>;
    fn unwrap_key(&self, wrapped_dek: &[u8]) -> Result<[u8; 32], SecretBrokerError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticAesKekAdapter {
    key_id: String,
    key_bytes: [u8; 32],
}

impl StaticAesKekAdapter {
    pub fn new(key_id: impl Into<String>, key_bytes: [u8; 32]) -> Result<Self, SecretBrokerError> {
        let key_id = key_id.into();
        if key_id.trim().is_empty() {
            return Err(SecretBrokerError::new("kek key_id cannot be empty"));
        }
        Ok(Self { key_id, key_bytes })
    }
}

impl KekAdapter for StaticAesKekAdapter {
    fn kek_id(&self) -> &str {
        &self.key_id
    }

    fn wrap_key(&self, dek: &[u8; 32]) -> Result<Vec<u8>, SecretBrokerError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key_bytes)
            .map_err(|_| SecretBrokerError::new("kek cipher initialization failed"))?;
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: dek.as_slice(),
                    aad: BROKER_KEY_WRAP_AAD,
                },
            )
            .map_err(|_| SecretBrokerError::new("kek wrap operation failed"))?;
        let mut output = Vec::with_capacity(nonce.len() + ciphertext.len());
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    fn unwrap_key(&self, wrapped_dek: &[u8]) -> Result<[u8; 32], SecretBrokerError> {
        if wrapped_dek.len() <= 12 {
            return Err(SecretBrokerError::new(
                "wrapped key payload is shorter than minimum envelope size",
            ));
        }
        let (nonce, ciphertext) = wrapped_dek.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(&self.key_bytes)
            .map_err(|_| SecretBrokerError::new("kek cipher initialization failed"))?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: BROKER_KEY_WRAP_AAD,
                },
            )
            .map_err(|_| SecretBrokerError::new("kek unwrap operation failed"))?;
        if plaintext.len() != 32 {
            return Err(SecretBrokerError::new(
                "unwrapped key length is invalid; expected 32 bytes",
            ));
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&plaintext);
        Ok(dek)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvAesKekAdapter {
    key_id: String,
    env_key: String,
}

impl EnvAesKekAdapter {
    pub fn new(
        key_id: impl Into<String>,
        env_key: impl Into<String>,
    ) -> Result<Self, SecretBrokerError> {
        let key_id = key_id.into();
        let env_key = env_key.into();
        if key_id.trim().is_empty() {
            return Err(SecretBrokerError::new("kek key_id cannot be empty"));
        }
        if env_key.trim().is_empty() {
            return Err(SecretBrokerError::new("kek env key cannot be empty"));
        }
        Ok(Self { key_id, env_key })
    }

    fn resolve_delegate(&self) -> Result<StaticAesKekAdapter, SecretBrokerError> {
        let raw = std::env::var(&self.env_key)
            .map_err(|_| SecretBrokerError::new(format!("missing KEK env var {}", self.env_key)))?;
        let key_bytes = parse_kek_bytes(&raw)?;
        StaticAesKekAdapter::new(self.key_id.clone(), key_bytes)
    }
}

impl KekAdapter for EnvAesKekAdapter {
    fn kek_id(&self) -> &str {
        &self.key_id
    }

    fn wrap_key(&self, dek: &[u8; 32]) -> Result<Vec<u8>, SecretBrokerError> {
        self.resolve_delegate()?.wrap_key(dek)
    }

    fn unwrap_key(&self, wrapped_dek: &[u8]) -> Result<[u8; 32], SecretBrokerError> {
        self.resolve_delegate()?.unwrap_key(wrapped_dek)
    }
}

#[derive(Debug, Default)]
pub struct SecretBroker {
    records: HashMap<SecretHandle, SecretRecord>,
    next_id: u64,
    audit_events: Vec<SecretAuditEvent>,
}

impl SecretBroker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn store_secret(
        &mut self,
        label: impl Into<String>,
        secret: impl Into<String>,
    ) -> Result<SecretHandle, SecretBrokerError> {
        let label = label.into();
        if label.trim().is_empty() {
            let error = SecretBrokerError::new("secret label cannot be empty");
            self.record_audit_event(
                SecretAuditAction::StoreSecret,
                SecretAuditDecision::Denied,
                None,
                None,
                error.to_string(),
            );
            return Err(error);
        }

        let secret = secret.into();
        if secret.trim().is_empty() {
            let error = SecretBrokerError::new("secret value cannot be empty");
            self.record_audit_event(
                SecretAuditAction::StoreSecret,
                SecretAuditDecision::Denied,
                None,
                Some(label.as_str()),
                error.to_string(),
            );
            return Err(error);
        }

        let now_unix_ms = now_unix_ms();
        let handle = SecretHandle::new(format!(
            "secret-{}-{}",
            now_unix_ms,
            self.allocate_handle_suffix()
        ));
        let label_for_audit = label.clone();
        let mut secret_bytes = secret.into_bytes();
        let memory_locked = try_lock_secret_bytes(secret_bytes.as_mut_slice());

        let record = SecretRecord {
            label,
            secret_bytes,
            memory_locked,
            created_at_unix_ms: now_unix_ms,
            updated_at_unix_ms: now_unix_ms,
            access_count: 0,
            revoked: false,
        };
        self.records.insert(handle.clone(), record);
        self.record_audit_event(
            SecretAuditAction::StoreSecret,
            SecretAuditDecision::Allowed,
            Some(handle.as_str()),
            Some(label_for_audit.as_str()),
            "secret stored",
        );
        Ok(handle)
    }

    pub fn resolve_secret_handle(
        &mut self,
        handle: &SecretHandle,
    ) -> Result<ResolvedSecret, SecretBrokerError> {
        let (label, value) = {
            let record = match self.lookup_active_record_mut(handle) {
                Ok(record) => record,
                Err(error) => {
                    self.record_audit_event(
                        SecretAuditAction::ResolveSecretHandle,
                        SecretAuditDecision::Denied,
                        Some(handle.as_str()),
                        None,
                        error.to_string(),
                    );
                    return Err(error);
                }
            };
            record.access_count = record.access_count.saturating_add(1);
            record.updated_at_unix_ms = now_unix_ms();
            let value = String::from_utf8(record.secret_bytes.clone())
                .map_err(|_| SecretBrokerError::new("secret bytes are not valid UTF-8"))?;
            (record.label.clone(), value)
        };
        self.record_audit_event(
            SecretAuditAction::ResolveSecretHandle,
            SecretAuditDecision::Allowed,
            Some(handle.as_str()),
            Some(label.as_str()),
            "secret resolved",
        );
        Ok(ResolvedSecret {
            handle: handle.clone(),
            label,
            value,
        })
    }

    pub fn inject_secret(
        &mut self,
        handle: &SecretHandle,
        target: SecretInjectionTarget,
    ) -> Result<String, SecretBrokerError> {
        let resolved = match self.resolve_secret_handle(handle) {
            Ok(resolved) => resolved,
            Err(error) => {
                self.record_audit_event(
                    SecretAuditAction::InjectSecret,
                    SecretAuditDecision::Denied,
                    Some(handle.as_str()),
                    None,
                    error.to_string(),
                );
                return Err(error);
            }
        };
        let rendered = match target {
            SecretInjectionTarget::HttpAuthorizationBearer => {
                format!("Bearer {}", resolved.expose())
            }
            SecretInjectionTarget::Raw => resolved.expose().to_string(),
        };
        self.record_audit_event(
            SecretAuditAction::InjectSecret,
            SecretAuditDecision::Allowed,
            Some(handle.as_str()),
            Some(resolved.label.as_str()),
            "secret injected",
        );
        Ok(rendered)
    }

    pub fn rotate_or_revoke_secret(
        &mut self,
        handle: &SecretHandle,
        replacement_secret: Option<String>,
    ) -> Result<(), SecretBrokerError> {
        if let Some(secret) = replacement_secret.as_deref()
            && secret.trim().is_empty()
        {
            let error = SecretBrokerError::new("replacement secret cannot be empty");
            self.record_audit_event(
                SecretAuditAction::RotateSecret,
                SecretAuditDecision::Denied,
                Some(handle.as_str()),
                None,
                error.to_string(),
            );
            return Err(error);
        }

        let record = match self
            .records
            .get_mut(handle)
            .ok_or_else(|| SecretBrokerError::new("unknown secret handle"))
        {
            Ok(record) => record,
            Err(error) => {
                let action = if replacement_secret.is_some() {
                    SecretAuditAction::RotateSecret
                } else {
                    SecretAuditAction::RevokeSecret
                };
                self.record_audit_event(
                    action,
                    SecretAuditDecision::Denied,
                    Some(handle.as_str()),
                    None,
                    error.to_string(),
                );
                return Err(error);
            }
        };

        let label_for_audit = record.label.clone();
        let (action, detail) = match replacement_secret {
            Some(secret) => {
                if record.memory_locked {
                    let _ = try_unlock_secret_bytes(record.secret_bytes.as_mut_slice());
                }
                clear_bytes(&mut record.secret_bytes);
                let mut next_secret = secret.into_bytes();
                record.memory_locked = try_lock_secret_bytes(next_secret.as_mut_slice());
                record.secret_bytes = next_secret;
                record.revoked = false;
                (SecretAuditAction::RotateSecret, "secret rotated")
            }
            None => {
                if record.memory_locked {
                    let _ = try_unlock_secret_bytes(record.secret_bytes.as_mut_slice());
                    record.memory_locked = false;
                }
                clear_bytes(&mut record.secret_bytes);
                record.secret_bytes.clear();
                record.revoked = true;
                (SecretAuditAction::RevokeSecret, "secret revoked")
            }
        };
        record.updated_at_unix_ms = now_unix_ms();
        self.record_audit_event(
            action,
            SecretAuditDecision::Allowed,
            Some(handle.as_str()),
            Some(label_for_audit.as_str()),
            detail,
        );
        Ok(())
    }

    pub fn latest_audit_events(&self, limit: usize) -> Vec<SecretAuditEvent> {
        if limit == 0 || self.audit_events.is_empty() {
            return Vec::new();
        }
        let start = self.audit_events.len().saturating_sub(limit);
        self.audit_events[start..].to_vec()
    }

    pub fn save_redacted_audit_events_to_path(&self, path: &Path) -> Result<(), SecretBrokerError> {
        let payload = PersistedSecretAuditLog {
            schema_version: BROKER_AUDIT_SCHEMA_VERSION,
            events: self.audit_events.clone(),
        };
        let encoded = serde_json::to_string_pretty(&payload).map_err(|error| {
            SecretBrokerError::new(format!("broker audit serialization failed: {error}"))
        })?;
        fs::write(path, encoded).map_err(|error| {
            SecretBrokerError::new(format!(
                "broker audit write failed at {}: {error}",
                path.display()
            ))
        })
    }

    pub fn save_encrypted_to_path(
        &self,
        path: &Path,
        kek: &dyn KekAdapter,
    ) -> Result<(), SecretBrokerError> {
        let mut persisted_records = Vec::with_capacity(self.records.len());
        for (handle, record) in &self.records {
            let persisted = to_persisted_record(handle, record, kek)?;
            persisted_records.push(persisted);
        }
        persisted_records.sort_by(|left, right| left.handle.cmp(&right.handle));
        let payload = PersistedSecretStore {
            schema_version: BROKER_PERSISTED_SCHEMA_VERSION,
            records: persisted_records,
        };
        let encoded = serde_json::to_string_pretty(&payload).map_err(|error| {
            SecretBrokerError::new(format!("broker serialization failed: {error}"))
        })?;
        fs::write(path, encoded).map_err(|error| {
            SecretBrokerError::new(format!(
                "broker encrypted write failed at {}: {error}",
                path.display()
            ))
        })
    }

    pub fn load_encrypted_from_path(
        path: &Path,
        kek: &dyn KekAdapter,
    ) -> Result<Self, SecretBrokerError> {
        let contents = fs::read_to_string(path).map_err(|error| {
            SecretBrokerError::new(format!(
                "broker encrypted read failed at {}: {error}",
                path.display()
            ))
        })?;
        let payload: PersistedSecretStore = serde_json::from_str(&contents)
            .map_err(|error| SecretBrokerError::new(format!("broker parse failed: {error}")))?;
        if payload.schema_version != BROKER_PERSISTED_SCHEMA_VERSION {
            return Err(SecretBrokerError::new(format!(
                "broker schema mismatch: expected {} got {}",
                BROKER_PERSISTED_SCHEMA_VERSION, payload.schema_version
            )));
        }
        from_persisted_store(payload, kek)
    }

    fn lookup_active_record_mut(
        &mut self,
        handle: &SecretHandle,
    ) -> Result<&mut SecretRecord, SecretBrokerError> {
        let record = self
            .records
            .get_mut(handle)
            .ok_or_else(|| SecretBrokerError::new("unknown secret handle"))?;
        if record.revoked {
            return Err(SecretBrokerError::new("secret handle has been revoked"));
        }
        Ok(record)
    }

    fn allocate_handle_suffix(&mut self) -> u64 {
        self.next_id = self.next_id.saturating_add(1);
        self.next_id
    }

    fn record_audit_event(
        &mut self,
        action: SecretAuditAction,
        decision: SecretAuditDecision,
        handle: Option<&str>,
        label: Option<&str>,
        detail: impl Into<String>,
    ) {
        let event = SecretAuditEvent {
            action,
            decision,
            at_unix_ms: now_unix_ms(),
            handle: handle.map(redact_sensitive_text),
            label: label.map(redact_sensitive_text),
            detail: redact_sensitive_text(detail.into()),
        };
        self.audit_events.push(event);
        if self.audit_events.len() > MAX_AUDIT_EVENTS {
            let overflow = self.audit_events.len().saturating_sub(MAX_AUDIT_EVENTS);
            self.audit_events.drain(0..overflow);
        }
    }
}

impl Drop for SecretBroker {
    fn drop(&mut self) {
        for record in self.records.values_mut() {
            if record.memory_locked {
                let _ = try_unlock_secret_bytes(record.secret_bytes.as_mut_slice());
                record.memory_locked = false;
            }
            clear_bytes(record.secret_bytes.as_mut_slice());
            record.secret_bytes.clear();
        }
    }
}

static GLOBAL_SECRET_BROKER: OnceLock<Mutex<SecretBroker>> = OnceLock::new();

pub fn with_global_secret_broker<T>(
    action: impl FnOnce(&mut SecretBroker) -> Result<T, SecretBrokerError>,
) -> Result<T, SecretBrokerError> {
    let lock = GLOBAL_SECRET_BROKER.get_or_init(|| Mutex::new(SecretBroker::new()));
    let mut broker = lock
        .lock()
        .map_err(|_| SecretBrokerError::new("global secret broker mutex was poisoned"))?;
    action(&mut broker)
}

pub fn rotate_encrypted_store_kek(
    path: &Path,
    current_kek: &dyn KekAdapter,
    next_kek: &dyn KekAdapter,
) -> Result<(), SecretBrokerError> {
    let broker = SecretBroker::load_encrypted_from_path(path, current_kek)?;
    let temp_path = build_rewrap_temp_path(path);
    broker.save_encrypted_to_path(temp_path.as_path(), next_kek)?;

    match fs::rename(&temp_path, path) {
        Ok(()) => Ok(()),
        Err(rename_error) => {
            fs::copy(&temp_path, path).map_err(|copy_error| {
                SecretBrokerError::new(format!(
                    "broker KEK rotation failed while replacing store (rename failed: {rename_error}; copy failed: {copy_error})"
                ))
            })?;
            fs::remove_file(&temp_path).map_err(|cleanup_error| {
                SecretBrokerError::new(format!(
                    "broker KEK rotation completed but temporary file cleanup failed at {}: {cleanup_error}",
                    temp_path.display()
                ))
            })?;
            Ok(())
        }
    }
}

pub fn save_global_redacted_audit_events_to_path(path: &Path) -> Result<(), SecretBrokerError> {
    with_global_secret_broker(|broker| broker.save_redacted_audit_events_to_path(path))
}

fn build_rewrap_temp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "forge_secret_store.json".to_string());
    let temp_name = format!("{file_name}.rewrap.tmp");
    match path.parent() {
        Some(parent) => parent.join(temp_name),
        None => PathBuf::from(temp_name),
    }
}

fn to_persisted_record(
    handle: &SecretHandle,
    record: &SecretRecord,
    kek: &dyn KekAdapter,
) -> Result<PersistedSecretRecord, SecretBrokerError> {
    if record.revoked {
        return Ok(PersistedSecretRecord {
            handle: handle.as_str().to_string(),
            label: record.label.clone(),
            created_at_unix_ms: record.created_at_unix_ms,
            updated_at_unix_ms: record.updated_at_unix_ms,
            access_count: record.access_count,
            revoked: true,
            kek_id: None,
            wrapped_dek_b64: None,
            nonce_b64: None,
            ciphertext_b64: None,
        });
    }

    let mut dek = [0u8; 32];
    OsRng.fill_bytes(&mut dek);

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let aad = build_secret_aad(handle, record);
    let cipher = Aes256Gcm::new_from_slice(&dek)
        .map_err(|_| SecretBrokerError::new("secret cipher initialization failed"))?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: record.secret_bytes.as_slice(),
                aad: aad.as_slice(),
            },
        )
        .map_err(|_| SecretBrokerError::new("secret encryption failed"))?;

    let wrapped_dek = kek.wrap_key(&dek)?;
    clear_bytes(&mut dek);

    Ok(PersistedSecretRecord {
        handle: handle.as_str().to_string(),
        label: record.label.clone(),
        created_at_unix_ms: record.created_at_unix_ms,
        updated_at_unix_ms: record.updated_at_unix_ms,
        access_count: record.access_count,
        revoked: false,
        kek_id: Some(kek.kek_id().to_string()),
        wrapped_dek_b64: Some(B64.encode(wrapped_dek)),
        nonce_b64: Some(B64.encode(nonce)),
        ciphertext_b64: Some(B64.encode(ciphertext)),
    })
}

fn from_persisted_store(
    payload: PersistedSecretStore,
    kek: &dyn KekAdapter,
) -> Result<SecretBroker, SecretBrokerError> {
    let mut records = HashMap::new();
    let mut highest_id = 0_u64;

    for entry in payload.records {
        let handle = SecretHandle::new(entry.handle);
        highest_id = highest_id.max(extract_handle_suffix(handle.as_str()).unwrap_or(0));

        let mut secret_bytes = Vec::new();
        if !entry.revoked {
            let key_id = entry.kek_id.as_deref().ok_or_else(|| {
                SecretBrokerError::new("persisted active secret is missing kek_id")
            })?;
            if key_id != kek.kek_id() {
                return Err(SecretBrokerError::new(format!(
                    "persisted secret key id mismatch: expected {} got {}",
                    kek.kek_id(),
                    key_id
                )));
            }
            let wrapped_dek = decode_b64_required(
                entry.wrapped_dek_b64.as_deref(),
                "persisted active secret is missing wrapped DEK",
            )?;
            let mut dek = kek.unwrap_key(&wrapped_dek)?;
            let nonce = decode_b64_required(
                entry.nonce_b64.as_deref(),
                "persisted active secret is missing nonce",
            )?;
            if nonce.len() != 12 {
                return Err(SecretBrokerError::new("persisted nonce has invalid length"));
            }
            let ciphertext = decode_b64_required(
                entry.ciphertext_b64.as_deref(),
                "persisted active secret is missing ciphertext",
            )?;

            let probe_record = SecretRecord {
                label: entry.label.clone(),
                secret_bytes: Vec::new(),
                memory_locked: false,
                created_at_unix_ms: entry.created_at_unix_ms,
                updated_at_unix_ms: entry.updated_at_unix_ms,
                access_count: entry.access_count,
                revoked: false,
            };
            let aad = build_secret_aad(&handle, &probe_record);
            let cipher = Aes256Gcm::new_from_slice(&dek)
                .map_err(|_| SecretBrokerError::new("secret cipher initialization failed"))?;
            let plaintext = cipher
                .decrypt(
                    Nonce::from_slice(nonce.as_slice()),
                    Payload {
                        msg: ciphertext.as_slice(),
                        aad: aad.as_slice(),
                    },
                )
                .map_err(|_| {
                    SecretBrokerError::new("secret decryption failed; wrong KEK or tampered store")
                })?;
            clear_bytes(&mut dek);
            secret_bytes = plaintext;
        }
        let memory_locked = try_lock_secret_bytes(secret_bytes.as_mut_slice());

        records.insert(
            handle,
            SecretRecord {
                label: entry.label,
                secret_bytes,
                memory_locked,
                created_at_unix_ms: entry.created_at_unix_ms,
                updated_at_unix_ms: entry.updated_at_unix_ms,
                access_count: entry.access_count,
                revoked: entry.revoked,
            },
        );
    }

    Ok(SecretBroker {
        records,
        next_id: highest_id,
        audit_events: Vec::new(),
    })
}

fn parse_kek_bytes(raw: &str) -> Result<[u8; 32], SecretBrokerError> {
    let trimmed = raw.trim();
    if trimmed.len() == 64 && trimmed.chars().all(|char| char.is_ascii_hexdigit()) {
        let mut bytes = [0u8; 32];
        let mut index = 0_usize;
        while index < 32 {
            let from = index * 2;
            let to = from + 2;
            let pair = &trimmed[from..to];
            let byte = u8::from_str_radix(pair, 16)
                .map_err(|_| SecretBrokerError::new("invalid hex KEK bytes"))?;
            bytes[index] = byte;
            index += 1;
        }
        return Ok(bytes);
    }

    let decoded = B64
        .decode(trimmed.as_bytes())
        .map_err(|_| SecretBrokerError::new("invalid base64 KEK bytes"))?;
    if decoded.len() != 32 {
        return Err(SecretBrokerError::new(
            "KEK must decode to exactly 32 bytes",
        ));
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(decoded.as_slice());
    Ok(bytes)
}

fn decode_b64_required(
    value: Option<&str>,
    missing_message: &str,
) -> Result<Vec<u8>, SecretBrokerError> {
    let value = value.ok_or_else(|| SecretBrokerError::new(missing_message))?;
    B64.decode(value.as_bytes())
        .map_err(|_| SecretBrokerError::new("invalid base64 payload in persisted secret store"))
}

fn build_secret_aad(handle: &SecretHandle, record: &SecretRecord) -> Vec<u8> {
    format!(
        "forge-secret-v1|{}|{}|{}|{}|{}|{}",
        handle.as_str(),
        record.label,
        record.created_at_unix_ms,
        record.updated_at_unix_ms,
        record.access_count,
        record.revoked
    )
    .into_bytes()
}

fn extract_handle_suffix(handle: &str) -> Option<u64> {
    handle.rsplit('-').next()?.parse::<u64>().ok()
}

fn clear_bytes(bytes: &mut [u8]) {
    for item in bytes {
        *item = 0;
    }
}

fn try_lock_secret_bytes(bytes: &mut [u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let _ = bytes;
    false
}

fn try_unlock_secret_bytes(bytes: &mut [u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let _ = bytes;
    false
}

fn redact_sensitive_text(input: impl AsRef<str>) -> String {
    let mut output = input.as_ref().to_string();
    output = redact_sk_tokens(output.as_str());
    output = redact_bearer_tokens(output.as_str());
    output
}

fn redact_sk_tokens(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut index = 0usize;

    while index < chars.len() {
        if chars[index] == 's'
            && index + 2 < chars.len()
            && chars[index + 1] == 'k'
            && chars[index + 2] == '-'
        {
            let mut end = index + 3;
            while end < chars.len() {
                let candidate = chars[end];
                if candidate.is_ascii_alphanumeric()
                    || candidate == '-'
                    || candidate == '_'
                    || candidate == '.'
                {
                    end = end.saturating_add(1);
                } else {
                    break;
                }
            }
            let token_len = end.saturating_sub(index);
            if token_len >= 12 {
                output.push_str("sk-[REDACTED]");
                index = end;
                continue;
            }
        }
        output.push(chars[index]);
        index = index.saturating_add(1);
    }

    output
}

fn redact_bearer_tokens(input: &str) -> String {
    let mut output = String::new();
    for token in input.split_whitespace() {
        if token.eq_ignore_ascii_case("bearer") {
            output.push_str("Bearer ");
            continue;
        }
        if output.ends_with("Bearer ")
            && token.len() >= 16
            && token
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            output.push_str("[REDACTED] ");
            continue;
        }
        output.push_str(token);
        output.push(' ');
    }
    output.trim_end().to_string()
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .unwrap_or(Duration::from_millis(0))
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::{
        EnvAesKekAdapter, SecretAuditAction, SecretAuditDecision, SecretBroker, SecretHandle,
        SecretInjectionTarget, StaticAesKekAdapter, is_secret_env_reference,
        render_secret_env_reference, resolve_secret_env_reference, rotate_encrypted_store_kek,
        with_global_secret_broker,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_path(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|value| value.as_nanos())
            .unwrap_or(0);
        path.push(format!("forge_security_{label}_{nanos}.json"));
        path
    }

    fn sample_static_kek() -> Option<StaticAesKekAdapter> {
        StaticAesKekAdapter::new("unit-test-kek", [7u8; 32]).ok()
    }

    #[test]
    fn store_and_resolve_secret_roundtrip() {
        let mut broker = SecretBroker::new();
        let handle = broker.store_secret("OPENAI_API_KEY", "sk-live-abc");
        assert!(handle.is_ok());
        let handle = match handle {
            Ok(value) => value,
            Err(_) => return,
        };
        let resolved = broker.resolve_secret_handle(&handle);
        assert!(resolved.is_ok());
        let resolved = match resolved {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(resolved.label, "OPENAI_API_KEY");
        assert_eq!(resolved.expose(), "sk-live-abc");
    }

    #[test]
    fn inject_secret_formats_bearer_header() {
        let mut broker = SecretBroker::new();
        let handle = broker.store_secret("OPENAI_API_KEY", "sk-test-xyz");
        assert!(handle.is_ok());
        let handle = match handle {
            Ok(value) => value,
            Err(_) => return,
        };
        let injected =
            broker.inject_secret(&handle, SecretInjectionTarget::HttpAuthorizationBearer);
        assert!(injected.is_ok());
        let injected = match injected {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(injected, "Bearer sk-test-xyz");
    }

    #[test]
    fn rotate_secret_replaces_old_value() {
        let mut broker = SecretBroker::new();
        let handle = broker.store_secret("OPENAI_API_KEY", "sk-old");
        assert!(handle.is_ok());
        let handle = match handle {
            Ok(value) => value,
            Err(_) => return,
        };
        let rotated = broker.rotate_or_revoke_secret(&handle, Some("sk-new".to_string()));
        assert!(rotated.is_ok());
        let resolved = broker.resolve_secret_handle(&handle);
        assert!(resolved.is_ok());
        let resolved = match resolved {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(resolved.expose(), "sk-new");
    }

    #[test]
    fn revoked_secret_cannot_be_resolved() {
        let mut broker = SecretBroker::new();
        let handle = broker.store_secret("OPENAI_API_KEY", "sk-revoke");
        assert!(handle.is_ok());
        let handle = match handle {
            Ok(value) => value,
            Err(_) => return,
        };
        let revoked = broker.rotate_or_revoke_secret(&handle, None);
        assert!(revoked.is_ok());
        let resolved = broker.resolve_secret_handle(&handle);
        assert!(resolved.is_err());
    }

    #[test]
    fn global_secret_broker_runs_store_resolve_flow() {
        let value = with_global_secret_broker(|broker| {
            let handle = broker.store_secret("GLOBAL_TEST", "value-1")?;
            let rendered = broker.inject_secret(&handle, SecretInjectionTarget::Raw)?;
            broker.rotate_or_revoke_secret(&handle, None)?;
            Ok(rendered)
        });
        assert!(value.is_ok());
        let value = match value {
            Ok(v) => v,
            Err(_) => return,
        };
        assert_eq!(value, "value-1");
    }

    #[test]
    fn unknown_handle_returns_error() {
        let mut broker = SecretBroker::new();
        let missing_handle = SecretHandle("missing".to_string());
        let result = broker.resolve_secret_handle(&missing_handle);
        assert!(result.is_err());
    }

    #[test]
    fn encrypted_persistence_round_trip_hides_plaintext() {
        let mut broker = SecretBroker::new();
        let handle = broker.store_secret("OPENAI_API_KEY", "sk-super-secret-123");
        assert!(handle.is_ok());
        let handle = match handle {
            Ok(value) => value,
            Err(_) => return,
        };
        let kek = sample_static_kek();
        assert!(kek.is_some());
        let kek = match kek {
            Some(value) => value,
            None => return,
        };
        let path = unique_temp_path("broker_encrypted");

        let saved = broker.save_encrypted_to_path(path.as_path(), &kek);
        assert!(saved.is_ok());
        let persisted = fs::read_to_string(path.as_path());
        assert!(persisted.is_ok());
        let persisted = match persisted {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(!persisted.contains("sk-super-secret-123"));
        assert!(!persisted.contains("\"secret_bytes\""));

        let loaded = SecretBroker::load_encrypted_from_path(path.as_path(), &kek);
        assert!(loaded.is_ok());
        let mut loaded = match loaded {
            Ok(value) => value,
            Err(_) => return,
        };
        let resolved = loaded.resolve_secret_handle(&handle);
        assert!(resolved.is_ok());
        let resolved = match resolved {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(resolved.expose(), "sk-super-secret-123");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn encrypted_store_rejects_wrong_kek() {
        let mut broker = SecretBroker::new();
        let handle = broker.store_secret("OPENAI_API_KEY", "sk-super-secret-123");
        assert!(handle.is_ok());
        let kek_a = StaticAesKekAdapter::new("unit-test-kek", [7u8; 32]);
        assert!(kek_a.is_ok());
        let kek_a = match kek_a {
            Ok(value) => value,
            Err(_) => return,
        };
        let kek_b = StaticAesKekAdapter::new("unit-test-kek", [8u8; 32]);
        assert!(kek_b.is_ok());
        let kek_b = match kek_b {
            Ok(value) => value,
            Err(_) => return,
        };
        let path = unique_temp_path("broker_wrong_kek");
        let saved = broker.save_encrypted_to_path(path.as_path(), &kek_a);
        assert!(saved.is_ok());
        let loaded = SecretBroker::load_encrypted_from_path(path.as_path(), &kek_b);
        assert!(loaded.is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn env_kek_adapter_fails_closed_when_env_key_is_missing() {
        let env_name = "FORGE_SECURITY_TEST_MISSING_KEK_7A6C1";
        let adapter = EnvAesKekAdapter::new("env-kek", env_name);
        assert!(adapter.is_ok());
        let adapter = match adapter {
            Ok(value) => value,
            Err(_) => return,
        };

        let mut broker = SecretBroker::new();
        let handle = broker.store_secret("OPENAI_API_KEY", "sk-env-secret");
        assert!(handle.is_ok());
        let _handle = match handle {
            Ok(value) => value,
            Err(_) => return,
        };
        let path = unique_temp_path("broker_env_kek");
        let saved = broker.save_encrypted_to_path(path.as_path(), &adapter);
        assert!(saved.is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn resolve_secret_env_reference_injects_and_revokes() {
        let setup = with_global_secret_broker(|broker| {
            let handle = broker.store_secret("OPENAI_API_KEY", "sk-runtime-secret")?;
            Ok(render_secret_env_reference(&handle))
        });
        assert!(setup.is_ok());
        let reference = match setup {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(is_secret_env_reference(&reference));

        let resolved = resolve_secret_env_reference(&reference);
        assert!(resolved.is_ok());
        let resolved = match resolved {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(resolved.as_deref(), Some("sk-runtime-secret"));

        let second = resolve_secret_env_reference(&reference);
        assert!(second.is_err());
    }

    #[test]
    fn non_reference_env_value_is_ignored() {
        let resolved = resolve_secret_env_reference("not-a-reference");
        assert!(resolved.is_ok());
        let resolved = match resolved {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(resolved.is_none());
    }

    #[test]
    fn rotate_encrypted_store_kek_rewraps_store_and_requires_new_kek() {
        let mut broker = SecretBroker::new();
        let handle = broker.store_secret("OPENAI_API_KEY", "sk-rotate-secret");
        assert!(handle.is_ok());
        let handle = match handle {
            Ok(value) => value,
            Err(_) => return,
        };

        let old_kek = StaticAesKekAdapter::new("kek-old", [3u8; 32]);
        assert!(old_kek.is_ok());
        let old_kek = match old_kek {
            Ok(value) => value,
            Err(_) => return,
        };
        let new_kek = StaticAesKekAdapter::new("kek-new", [4u8; 32]);
        assert!(new_kek.is_ok());
        let new_kek = match new_kek {
            Ok(value) => value,
            Err(_) => return,
        };

        let path = unique_temp_path("broker_rewrap");
        let saved = broker.save_encrypted_to_path(path.as_path(), &old_kek);
        assert!(saved.is_ok());

        let rotated = rotate_encrypted_store_kek(path.as_path(), &old_kek, &new_kek);
        assert!(rotated.is_ok());

        let old_load = SecretBroker::load_encrypted_from_path(path.as_path(), &old_kek);
        assert!(old_load.is_err());

        let loaded = SecretBroker::load_encrypted_from_path(path.as_path(), &new_kek);
        assert!(loaded.is_ok());
        let mut loaded = match loaded {
            Ok(value) => value,
            Err(_) => return,
        };
        let resolved = loaded.resolve_secret_handle(&handle);
        assert!(resolved.is_ok());
        let resolved = match resolved {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(resolved.expose(), "sk-rotate-secret");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn broker_audit_events_capture_allow_and_deny_decisions() {
        let mut broker = SecretBroker::new();
        let handle = broker.store_secret("OPENAI_API_KEY", "sk-audit-secret-value");
        assert!(handle.is_ok());
        let handle = match handle {
            Ok(value) => value,
            Err(_) => return,
        };

        let resolved = broker.resolve_secret_handle(&handle);
        assert!(resolved.is_ok());

        let revoked = broker.rotate_or_revoke_secret(&handle, None);
        assert!(revoked.is_ok());

        let denied = broker.resolve_secret_handle(&handle);
        assert!(denied.is_err());

        let events = broker.latest_audit_events(16);
        assert!(!events.is_empty());
        assert!(events.iter().any(|event| {
            event.action == SecretAuditAction::StoreSecret
                && event.decision == SecretAuditDecision::Allowed
        }));
        assert!(events.iter().any(|event| {
            event.action == SecretAuditAction::ResolveSecretHandle
                && event.decision == SecretAuditDecision::Denied
        }));
        for event in events {
            assert!(!event.detail.contains("sk-audit-secret-value"));
        }
    }

    #[test]
    fn exported_audit_log_redacts_secret_like_tokens() {
        let mut broker = SecretBroker::new();
        let handle = broker.store_secret("sk-live-label-value-12345", "sk-live-plain-secret-12345");
        assert!(handle.is_ok());
        let handle = match handle {
            Ok(value) => value,
            Err(_) => return,
        };
        let injected =
            broker.inject_secret(&handle, SecretInjectionTarget::HttpAuthorizationBearer);
        assert!(injected.is_ok());

        let path = unique_temp_path("broker_audit_log");
        let saved = broker.save_redacted_audit_events_to_path(path.as_path());
        assert!(saved.is_ok());

        let contents = fs::read_to_string(path.as_path());
        assert!(contents.is_ok());
        let contents = match contents {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(contents.contains("schema_version"));
        assert!(contents.contains("[REDACTED]"));
        assert!(!contents.contains("sk-live-plain-secret-12345"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn revoke_clears_secret_bytes_and_releases_lock_state() {
        let mut broker = SecretBroker::new();
        let handle = broker.store_secret("OPENAI_API_KEY", "sk-clear-me");
        assert!(handle.is_ok());
        let handle = match handle {
            Ok(value) => value,
            Err(_) => return,
        };

        let revoked = broker.rotate_or_revoke_secret(&handle, None);
        assert!(revoked.is_ok());

        let record = broker.records.get(&handle);
        assert!(record.is_some());
        let record = match record {
            Some(value) => value,
            None => return,
        };
        assert!(record.secret_bytes.is_empty());
        assert!(record.revoked);
        assert!(!record.memory_locked);
    }
}
