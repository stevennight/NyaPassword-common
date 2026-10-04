//! The local replica. Only ciphertext and non-secret metadata are stored; the
//! host picks the backend (SQLite on desktop and Android, an in-memory store
//! persisted as one blob in the browser extension).
//!
//! Writes go through [`Store::apply`], which must be atomic: a crash leaves
//! either all of a batch or none of it.

use std::collections::BTreeMap;
use std::sync::Mutex;

use npw_api::ItemRecord;
use serde::{Deserialize, Serialize};

use crate::{CoreError, Result};

/// An edit that has not reached the server yet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PendingEdit {
    pub op_id: String,
    /// The server revision this edit is based on (0: new item).
    pub base_revision: i64,
    pub deleted: bool,
    pub format_major: u16,
    pub wrapped_key: String,
    pub ciphertext: String,
    pub created_at: i64,
    /// Set when the server rejected the edit; it stays here (never dropped) until the user decides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejected: Option<String>,
}

/// One item in the replica: the last revision known to be on the server (the
/// merge base) and, possibly, a local edit on top of it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LocalItem {
    pub vault_id: String,
    pub item_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<ItemRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<PendingEdit>,
}

#[derive(Debug, Clone)]
pub enum StoreOp {
    PutMeta(String, Vec<u8>),
    DeleteMeta(String),
    PutItem(LocalItem),
    DeleteItem { vault_id: String, item_id: String },
    PutBlob(String, Vec<u8>),
    DeleteBlob(String),
    /// Removes every item of a vault (vault deleted or full resync rebuild).
    ClearVault(String),
}

pub trait Store: Send + Sync {
    fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn get_item(&self, vault_id: &str, item_id: &str) -> Result<Option<LocalItem>>;
    fn list_items(&self, vault_id: &str) -> Result<Vec<LocalItem>>;
    fn list_all_items(&self) -> Result<Vec<LocalItem>>;
    fn get_blob(&self, key: &str) -> Result<Option<Vec<u8>>>;
    /// Applies all operations atomically.
    fn apply(&self, ops: Vec<StoreOp>) -> Result<()>;
}

/// A store in memory. The browser extension serializes it with [`MemoryStore::snapshot`].
#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<MemInner>,
}

#[derive(Default, Serialize, Deserialize, Clone)]
struct MemInner {
    meta: BTreeMap<String, Vec<u8>>,
    items: BTreeMap<(String, String), LocalItem>,
    #[serde(default)]
    blobs: BTreeMap<String, Vec<u8>>,
    #[serde(skip)]
    generation: u64,
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    v: u32,
    meta: Vec<(String, String)>,
    items: Vec<LocalItem>,
    blobs: Vec<(String, String)>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything as JSON bytes (ciphertext only; safe to persist as is).
    pub fn snapshot(&self) -> Vec<u8> {
        let g = self.inner.lock().expect("store lock");
        let snap = Snapshot {
            v: 1,
            meta: g.meta.iter().map(|(k, v)| (k.clone(), npw_crypto::b64(v))).collect(),
            items: g.items.values().cloned().collect(),
            blobs: g.blobs.iter().map(|(k, v)| (k.clone(), npw_crypto::b64(v))).collect(),
        };
        serde_json::to_vec(&snap).expect("snapshot serializes")
    }

    pub fn from_snapshot(bytes: &[u8]) -> Result<Self> {
        let snap: Snapshot = serde_json::from_slice(bytes).map_err(|e| CoreError::Store(format!("bad snapshot: {e}")))?;
        let mut inner = MemInner::default();
        for (k, v) in snap.meta {
            inner.meta.insert(k, npw_crypto::unb64(&v).ok_or_else(|| CoreError::Store("bad snapshot meta".into()))?);
        }
        for it in snap.items {
            inner.items.insert((it.vault_id.clone(), it.item_id.clone()), it);
        }
        for (k, v) in snap.blobs {
            inner.blobs.insert(k, npw_crypto::unb64(&v).ok_or_else(|| CoreError::Store("bad snapshot blob".into()))?);
        }
        Ok(Self { inner: Mutex::new(inner) })
    }

    /// Increases with every write; hosts persist the snapshot when it changes.
    pub fn generation(&self) -> u64 {
        self.inner.lock().expect("store lock").generation
    }
}

impl Store for MemoryStore {
    fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.inner.lock().expect("store lock").meta.get(key).cloned())
    }

    fn get_item(&self, vault_id: &str, item_id: &str) -> Result<Option<LocalItem>> {
        Ok(self.inner.lock().expect("store lock").items.get(&(vault_id.to_string(), item_id.to_string())).cloned())
    }

    fn list_items(&self, vault_id: &str) -> Result<Vec<LocalItem>> {
        Ok(self.inner.lock().expect("store lock").items.values().filter(|i| i.vault_id == vault_id).cloned().collect())
    }

    fn list_all_items(&self) -> Result<Vec<LocalItem>> {
        Ok(self.inner.lock().expect("store lock").items.values().cloned().collect())
    }

    fn get_blob(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.inner.lock().expect("store lock").blobs.get(key).cloned())
    }

    fn apply(&self, ops: Vec<StoreOp>) -> Result<()> {
        let mut g = self.inner.lock().expect("store lock");
        // apply to a copy, swap in at the end: all or nothing
        let mut next = g.clone();
        for op in ops {
            match op {
                StoreOp::PutMeta(k, v) => {
                    next.meta.insert(k, v);
                }
                StoreOp::DeleteMeta(k) => {
                    next.meta.remove(&k);
                }
                StoreOp::PutItem(it) => {
                    next.items.insert((it.vault_id.clone(), it.item_id.clone()), it);
                }
                StoreOp::DeleteItem { vault_id, item_id } => {
                    next.items.remove(&(vault_id, item_id));
                }
                StoreOp::PutBlob(k, v) => {
                    next.blobs.insert(k, v);
                }
                StoreOp::DeleteBlob(k) => {
                    next.blobs.remove(&k);
                }
                StoreOp::ClearVault(v) => next.items.retain(|(vid, _), _| *vid != v),
            }
        }
        next.generation = g.generation + 1;
        *g = next;
        Ok(())
    }
}
