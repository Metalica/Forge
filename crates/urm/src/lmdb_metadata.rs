use lmdb::{Database, DatabaseFlags, Environment, Transaction, WriteFlags};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};

const METADATA_DB_NAME: &str = "forge_metadata";
const INDEX_DB_NAME: &str = "forge_index";
const SYSTEM_DB_NAME: &str = "forge_system";
const SCHEMA_VERSION_KEY: &[u8] = b"schema_version";

pub const LMDB_METADATA_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LmdbMetadataStoreOptions {
    pub map_size_bytes: usize,
    pub max_databases: u32,
    pub allow_schema_migration: bool,
}

impl Default for LmdbMetadataStoreOptions {
    fn default() -> Self {
        Self {
            map_size_bytes: 64 * 1024 * 1024,
            max_databases: 8,
            allow_schema_migration: false,
        }
    }
}

#[derive(Debug)]
pub enum LmdbMetadataStoreError {
    Io(std::io::Error),
    Lmdb(lmdb::Error),
    InvalidSchemaEncoding,
    UnsupportedFutureSchema { found: u16, current: u16 },
    MigrationRequired { found: u16, current: u16 },
    UnsupportedMigration { from: u16, to: u16 },
}

impl Display for LmdbMetadataStoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LmdbMetadataStoreError::Io(error) => write!(f, "I/O error: {error}"),
            LmdbMetadataStoreError::Lmdb(error) => write!(f, "LMDB error: {error}"),
            LmdbMetadataStoreError::InvalidSchemaEncoding => {
                write!(f, "invalid LMDB schema_version encoding")
            }
            LmdbMetadataStoreError::UnsupportedFutureSchema { found, current } => write!(
                f,
                "LMDB schema version {found} is newer than supported version {current}"
            ),
            LmdbMetadataStoreError::MigrationRequired { found, current } => write!(
                f,
                "LMDB schema migration required (found {found}, current {current})"
            ),
            LmdbMetadataStoreError::UnsupportedMigration { from, to } => {
                write!(f, "unsupported LMDB schema migration from {from} to {to}")
            }
        }
    }
}

impl Error for LmdbMetadataStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            LmdbMetadataStoreError::Io(error) => Some(error),
            LmdbMetadataStoreError::Lmdb(error) => Some(error),
            LmdbMetadataStoreError::InvalidSchemaEncoding
            | LmdbMetadataStoreError::UnsupportedFutureSchema { .. }
            | LmdbMetadataStoreError::MigrationRequired { .. }
            | LmdbMetadataStoreError::UnsupportedMigration { .. } => None,
        }
    }
}

impl From<std::io::Error> for LmdbMetadataStoreError {
    fn from(value: std::io::Error) -> Self {
        LmdbMetadataStoreError::Io(value)
    }
}

impl From<lmdb::Error> for LmdbMetadataStoreError {
    fn from(value: lmdb::Error) -> Self {
        LmdbMetadataStoreError::Lmdb(value)
    }
}

pub struct LmdbMetadataStore {
    root_dir: PathBuf,
    env: Environment,
    metadata_db: Database,
    index_db: Database,
    system_db: Database,
    schema_version: u16,
}

impl LmdbMetadataStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LmdbMetadataStoreError> {
        Self::open_with_options(path, LmdbMetadataStoreOptions::default())
    }

    pub fn open_with_options(
        path: impl AsRef<Path>,
        options: LmdbMetadataStoreOptions,
    ) -> Result<Self, LmdbMetadataStoreError> {
        let root_dir = path.as_ref().to_path_buf();
        fs::create_dir_all(&root_dir)?;

        let mut builder = Environment::new();
        builder.set_max_dbs(options.max_databases);
        builder.set_map_size(options.map_size_bytes);
        let env = builder.open(&root_dir)?;

        let metadata_db = env.create_db(Some(METADATA_DB_NAME), DatabaseFlags::empty())?;
        let index_db = env.create_db(Some(INDEX_DB_NAME), DatabaseFlags::empty())?;
        let system_db = env.create_db(Some(SYSTEM_DB_NAME), DatabaseFlags::empty())?;

        let mut store = Self {
            root_dir,
            env,
            metadata_db,
            index_db,
            system_db,
            schema_version: 0,
        };
        let schema_version = store.ensure_schema_version(options.allow_schema_migration)?;
        store.schema_version = schema_version;
        Ok(store)
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn put_metadata(
        &self,
        key: impl AsRef<str>,
        value: impl AsRef<[u8]>,
    ) -> Result<(), LmdbMetadataStoreError> {
        let mut txn = self.env.begin_rw_txn()?;
        txn.put(
            self.metadata_db,
            &key.as_ref().as_bytes(),
            &value.as_ref(),
            WriteFlags::empty(),
        )?;
        txn.commit()?;
        Ok(())
    }

    pub fn get_metadata(
        &self,
        key: impl AsRef<str>,
    ) -> Result<Option<Vec<u8>>, LmdbMetadataStoreError> {
        let txn = self.env.begin_ro_txn()?;
        match txn.get(self.metadata_db, &key.as_ref().as_bytes()) {
            Ok(bytes) => Ok(Some(bytes.to_vec())),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn delete_metadata(&self, key: impl AsRef<str>) -> Result<bool, LmdbMetadataStoreError> {
        let mut txn = self.env.begin_rw_txn()?;
        match txn.del(self.metadata_db, &key.as_ref().as_bytes(), None) {
            Ok(()) => {
                txn.commit()?;
                Ok(true)
            }
            Err(lmdb::Error::NotFound) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub fn add_index_entry(
        &self,
        term: impl AsRef<str>,
        document_id: impl AsRef<str>,
    ) -> Result<(), LmdbMetadataStoreError> {
        let term = term.as_ref();
        let document_id = document_id.as_ref();
        let mut entries = self.lookup_index(term)?;
        if !entries.iter().any(|value| value == document_id) {
            entries.push(document_id.to_string());
            entries.sort();
        }

        let encoded = encode_index_entries(&entries);
        let mut txn = self.env.begin_rw_txn()?;
        txn.put(
            self.index_db,
            &term.as_bytes(),
            &encoded.as_bytes(),
            WriteFlags::empty(),
        )?;
        txn.commit()?;
        Ok(())
    }

    pub fn remove_index_entry(
        &self,
        term: impl AsRef<str>,
        document_id: impl AsRef<str>,
    ) -> Result<bool, LmdbMetadataStoreError> {
        let term = term.as_ref();
        let document_id = document_id.as_ref();
        let mut entries = self.lookup_index(term)?;
        let original_len = entries.len();
        entries.retain(|value| value != document_id);
        if entries.len() == original_len {
            return Ok(false);
        }

        let mut txn = self.env.begin_rw_txn()?;
        if entries.is_empty() {
            match txn.del(self.index_db, &term.as_bytes(), None) {
                Ok(()) | Err(lmdb::Error::NotFound) => {}
                Err(error) => return Err(error.into()),
            }
        } else {
            let encoded = encode_index_entries(&entries);
            txn.put(
                self.index_db,
                &term.as_bytes(),
                &encoded.as_bytes(),
                WriteFlags::empty(),
            )?;
        }
        txn.commit()?;
        Ok(true)
    }

    pub fn lookup_index(
        &self,
        term: impl AsRef<str>,
    ) -> Result<Vec<String>, LmdbMetadataStoreError> {
        let txn = self.env.begin_ro_txn()?;
        let term = term.as_ref();
        match txn.get(self.index_db, &term.as_bytes()) {
            Ok(bytes) => Ok(decode_index_entries(bytes)),
            Err(lmdb::Error::NotFound) => Ok(Vec::new()),
            Err(error) => Err(error.into()),
        }
    }

    fn ensure_schema_version(
        &mut self,
        allow_schema_migration: bool,
    ) -> Result<u16, LmdbMetadataStoreError> {
        let stored_version = self.read_schema_version()?;
        let Some(stored_version) = stored_version else {
            self.write_schema_version(LMDB_METADATA_SCHEMA_VERSION)?;
            return Ok(LMDB_METADATA_SCHEMA_VERSION);
        };

        if stored_version == LMDB_METADATA_SCHEMA_VERSION {
            return Ok(stored_version);
        }
        if stored_version > LMDB_METADATA_SCHEMA_VERSION {
            return Err(LmdbMetadataStoreError::UnsupportedFutureSchema {
                found: stored_version,
                current: LMDB_METADATA_SCHEMA_VERSION,
            });
        }
        if !allow_schema_migration {
            return Err(LmdbMetadataStoreError::MigrationRequired {
                found: stored_version,
                current: LMDB_METADATA_SCHEMA_VERSION,
            });
        }

        self.migrate_schema(stored_version, LMDB_METADATA_SCHEMA_VERSION)?;
        self.write_schema_version(LMDB_METADATA_SCHEMA_VERSION)?;
        Ok(LMDB_METADATA_SCHEMA_VERSION)
    }

    fn read_schema_version(&self) -> Result<Option<u16>, LmdbMetadataStoreError> {
        let txn = self.env.begin_ro_txn()?;
        match txn.get(self.system_db, &SCHEMA_VERSION_KEY) {
            Ok(bytes) => decode_u16(bytes).map(Some),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn write_schema_version(&self, version: u16) -> Result<(), LmdbMetadataStoreError> {
        let mut txn = self.env.begin_rw_txn()?;
        let bytes = encode_u16(version);
        txn.put(
            self.system_db,
            &SCHEMA_VERSION_KEY,
            &bytes,
            WriteFlags::empty(),
        )?;
        txn.commit()?;
        Ok(())
    }

    fn migrate_schema(&self, from: u16, to: u16) -> Result<(), LmdbMetadataStoreError> {
        let mut version = from;
        while version < to {
            match version {
                0 => {
                    version = 1;
                }
                _ => {
                    return Err(LmdbMetadataStoreError::UnsupportedMigration { from: version, to });
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn set_schema_version_for_tests(&self, version: u16) -> Result<(), LmdbMetadataStoreError> {
        self.write_schema_version(version)
    }
}

fn encode_u16(value: u16) -> [u8; 2] {
    value.to_le_bytes()
}

fn decode_u16(bytes: &[u8]) -> Result<u16, LmdbMetadataStoreError> {
    if bytes.len() != 2 {
        return Err(LmdbMetadataStoreError::InvalidSchemaEncoding);
    }
    let mut value = [0u8; 2];
    value.copy_from_slice(bytes);
    Ok(u16::from_le_bytes(value))
}

fn encode_index_entries(entries: &[String]) -> String {
    entries.join("\n")
}

fn decode_index_entries(bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    let mut unique = BTreeSet::new();
    for line in text.lines() {
        let candidate = line.trim();
        if !candidate.is_empty() {
            unique.insert(candidate.to_string());
        }
    }
    unique.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::{LMDB_METADATA_SCHEMA_VERSION, LmdbMetadataStore, LmdbMetadataStoreOptions};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_store_root(label: &str) -> PathBuf {
        let mut root = std::env::temp_dir();
        let nanos = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(value) => value.as_nanos(),
            Err(_) => 0,
        };
        root.push(format!("forge_lmdb_metadata_{label}_{nanos}"));
        root
    }

    #[test]
    fn open_initializes_schema_version() {
        let root = unique_store_root("open_init");
        let store = LmdbMetadataStore::open(&root);
        assert!(store.is_ok());
        let store = match store {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(store.schema_version(), LMDB_METADATA_SCHEMA_VERSION);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn metadata_round_trip_persists_after_reopen() {
        let root = unique_store_root("metadata_reopen");
        let store = LmdbMetadataStore::open(&root);
        assert!(store.is_ok());
        let store = match store {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(
            store
                .put_metadata("doc:42", b"{\"title\":\"Forge\"}")
                .is_ok()
        );

        let first_read = store.get_metadata("doc:42");
        assert!(first_read.is_ok());
        assert_eq!(
            first_read.ok().flatten(),
            Some(b"{\"title\":\"Forge\"}".to_vec())
        );

        drop(store);

        let reopened = LmdbMetadataStore::open(&root);
        assert!(reopened.is_ok());
        let reopened = match reopened {
            Ok(value) => value,
            Err(_) => return,
        };
        let second_read = reopened.get_metadata("doc:42");
        assert!(second_read.is_ok());
        assert_eq!(
            second_read.ok().flatten(),
            Some(b"{\"title\":\"Forge\"}".to_vec())
        );

        assert!(reopened.delete_metadata("doc:42").ok() == Some(true));
        assert!(reopened.get_metadata("doc:42").ok().flatten().is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn index_read_write_and_remove_behaves_stably() {
        let root = unique_store_root("index_round_trip");
        let store = LmdbMetadataStore::open(&root);
        assert!(store.is_ok());
        let store = match store {
            Ok(value) => value,
            Err(_) => return,
        };

        assert!(store.add_index_entry("token:forge", "doc-a").is_ok());
        assert!(store.add_index_entry("token:forge", "doc-b").is_ok());
        assert!(store.add_index_entry("token:forge", "doc-a").is_ok());
        let lookup = store.lookup_index("token:forge");
        assert!(lookup.is_ok());
        assert_eq!(
            lookup.ok(),
            Some(vec!["doc-a".to_string(), "doc-b".to_string()])
        );

        let removed = store.remove_index_entry("token:forge", "doc-a");
        assert!(removed.ok() == Some(true));
        let after_remove = store.lookup_index("token:forge");
        assert!(after_remove.is_ok());
        assert_eq!(after_remove.ok(), Some(vec!["doc-b".to_string()]));

        let removed_last = store.remove_index_entry("token:forge", "doc-b");
        assert!(removed_last.ok() == Some(true));
        assert_eq!(store.lookup_index("token:forge").ok(), Some(Vec::new()));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_schema_requires_migration_unless_opted_in() {
        let root = unique_store_root("migration_guard");
        let store = LmdbMetadataStore::open(&root);
        assert!(store.is_ok());
        let store = match store {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(store.set_schema_version_for_tests(0).is_ok());
        drop(store);

        let reopen_without_migration = LmdbMetadataStore::open(&root);
        assert!(reopen_without_migration.is_err());

        let reopen_with_migration = LmdbMetadataStore::open_with_options(
            &root,
            LmdbMetadataStoreOptions {
                allow_schema_migration: true,
                ..LmdbMetadataStoreOptions::default()
            },
        );
        assert!(reopen_with_migration.is_ok());
        let reopen_with_migration = match reopen_with_migration {
            Ok(value) => value,
            Err(_) => return,
        };
        assert_eq!(
            reopen_with_migration.schema_version(),
            LMDB_METADATA_SCHEMA_VERSION
        );

        let _ = fs::remove_dir_all(root);
    }
}
