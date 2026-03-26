use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MemoryScope {
    Session,
    Project,
    Workspace,
}

impl MemoryScope {
    pub const fn label(self) -> &'static str {
        match self {
            MemoryScope::Session => "session",
            MemoryScope::Project => "project",
            MemoryScope::Workspace => "workspace",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub id: u64,
    pub scope: MemoryScope,
    pub key: String,
    pub value: String,
    pub source: String,
    pub hit_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryUpsertResult {
    pub id: u64,
    pub created: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRecallResult {
    pub id: u64,
    pub scope: MemoryScope,
    pub key: String,
    pub value: String,
    pub source: String,
    pub hit_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryScopeStats {
    pub session_entries: usize,
    pub project_entries: usize,
    pub workspace_entries: usize,
}

#[derive(Debug, Default)]
pub struct ProjectMemoryStore {
    entries: HashMap<u64, MemoryEntry>,
    lookup_by_scope_key: HashMap<(MemoryScope, String), u64>,
    next_id: u64,
}

impl ProjectMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(
        &mut self,
        scope: MemoryScope,
        key: impl Into<String>,
        value: impl Into<String>,
        source: impl Into<String>,
    ) -> Result<MemoryUpsertResult, String> {
        let key = key.into().trim().to_string();
        if key.is_empty() {
            return Err("memory key cannot be empty".to_string());
        }
        let value = value.into().trim().to_string();
        if value.is_empty() {
            return Err("memory value cannot be empty".to_string());
        }
        let source = source.into().trim().to_string();
        if source.is_empty() {
            return Err("memory source cannot be empty".to_string());
        }

        if let Some(id) = self.lookup_by_scope_key.get(&(scope, key.clone())).copied() {
            if let Some(entry) = self.entries.get_mut(&id) {
                entry.value = value;
                entry.source = source;
                return Ok(MemoryUpsertResult { id, created: false });
            }
        }

        self.next_id = self.next_id.saturating_add(1);
        let id = self.next_id;
        self.entries.insert(
            id,
            MemoryEntry {
                id,
                scope,
                key: key.clone(),
                value,
                source,
                hit_count: 0,
            },
        );
        self.lookup_by_scope_key.insert((scope, key), id);
        Ok(MemoryUpsertResult { id, created: true })
    }

    pub fn recall(
        &mut self,
        scope: MemoryScope,
        query: &str,
        limit: usize,
    ) -> Vec<MemoryRecallResult> {
        let normalized_query = query.trim().to_lowercase();
        let mut matches = self
            .entries
            .values_mut()
            .filter(|entry| entry.scope == scope)
            .filter(|entry| {
                if normalized_query.is_empty() {
                    return true;
                }
                entry.key.to_lowercase().contains(&normalized_query)
                    || entry.value.to_lowercase().contains(&normalized_query)
            })
            .collect::<Vec<_>>();

        matches.sort_by(|left, right| {
            right
                .hit_count
                .cmp(&left.hit_count)
                .then(left.key.cmp(&right.key))
        });

        let target_len = limit.max(1);
        let mut results = Vec::new();
        for entry in matches.into_iter().take(target_len) {
            entry.hit_count = entry.hit_count.saturating_add(1);
            results.push(MemoryRecallResult {
                id: entry.id,
                scope: entry.scope,
                key: entry.key.clone(),
                value: entry.value.clone(),
                source: entry.source.clone(),
                hit_count: entry.hit_count,
            });
        }
        results
    }

    pub fn clear_scope(&mut self, scope: MemoryScope) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| entry.scope != scope);
        self.lookup_by_scope_key
            .retain(|(entry_scope, _), _| *entry_scope != scope);
        before.saturating_sub(self.entries.len())
    }

    pub fn snapshot(&self) -> Vec<MemoryEntry> {
        let mut entries = self.entries.values().cloned().collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.id);
        entries
    }

    pub fn restore(entries: Vec<MemoryEntry>) -> Self {
        let mut store = Self::new();
        for mut entry in entries {
            if entry.key.trim().is_empty()
                || entry.value.trim().is_empty()
                || entry.source.trim().is_empty()
            {
                continue;
            }
            entry.key = entry.key.trim().to_string();
            entry.value = entry.value.trim().to_string();
            entry.source = entry.source.trim().to_string();
            store.next_id = store.next_id.max(entry.id);
            store
                .lookup_by_scope_key
                .insert((entry.scope, entry.key.clone()), entry.id);
            store.entries.insert(entry.id, entry);
        }
        store
    }

    pub fn stats(&self) -> MemoryScopeStats {
        let mut stats = MemoryScopeStats {
            session_entries: 0,
            project_entries: 0,
            workspace_entries: 0,
        };
        for entry in self.entries.values() {
            match entry.scope {
                MemoryScope::Session => {
                    stats.session_entries = stats.session_entries.saturating_add(1);
                }
                MemoryScope::Project => {
                    stats.project_entries = stats.project_entries.saturating_add(1);
                }
                MemoryScope::Workspace => {
                    stats.workspace_entries = stats.workspace_entries.saturating_add(1);
                }
            }
        }
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::{MemoryScope, ProjectMemoryStore};

    #[test]
    fn upsert_creates_then_updates_same_scope_key() {
        let mut store = ProjectMemoryStore::new();
        let created = store.upsert(MemoryScope::Project, "repo", "forge", "ui");
        assert!(created.is_ok());
        let created = match created {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(created.created);

        let updated = store.upsert(MemoryScope::Project, "repo", "forge-v2", "agent");
        assert!(updated.is_ok());
        let updated = match updated {
            Ok(value) => value,
            Err(_) => return,
        };
        assert!(!updated.created);
        assert_eq!(created.id, updated.id);
    }

    #[test]
    fn recall_filters_by_scope_and_query() {
        let mut store = ProjectMemoryStore::new();
        assert!(
            store
                .upsert(MemoryScope::Project, "runtime", "llama.cpp", "models")
                .is_ok()
        );
        assert!(
            store
                .upsert(MemoryScope::Session, "runtime", "session-only", "chat")
                .is_ok()
        );

        let project_hits = store.recall(MemoryScope::Project, "llama", 8);
        assert_eq!(project_hits.len(), 1);
        assert_eq!(project_hits[0].scope, MemoryScope::Project);
        assert_eq!(project_hits[0].key, "runtime");
        assert_eq!(project_hits[0].value, "llama.cpp");
    }

    #[test]
    fn clear_scope_removes_only_target_scope() {
        let mut store = ProjectMemoryStore::new();
        assert!(
            store
                .upsert(MemoryScope::Project, "a", "1", "source")
                .is_ok()
        );
        assert!(
            store
                .upsert(MemoryScope::Workspace, "b", "2", "source")
                .is_ok()
        );
        let removed = store.clear_scope(MemoryScope::Project);
        assert_eq!(removed, 1);

        let stats = store.stats();
        assert_eq!(stats.project_entries, 0);
        assert_eq!(stats.workspace_entries, 1);
    }

    #[test]
    fn snapshot_restore_round_trip_preserves_entries() {
        let mut store = ProjectMemoryStore::new();
        assert!(
            store
                .upsert(MemoryScope::Session, "scope", "session-value", "seed")
                .is_ok()
        );
        assert!(
            store
                .upsert(MemoryScope::Project, "goal", "ship", "seed")
                .is_ok()
        );
        let _ = store.recall(MemoryScope::Project, "", 8);
        let snapshot = store.snapshot();
        let restored = ProjectMemoryStore::restore(snapshot);
        let stats = restored.stats();
        assert_eq!(stats.session_entries, 1);
        assert_eq!(stats.project_entries, 1);
        assert_eq!(stats.workspace_entries, 0);
    }
}
