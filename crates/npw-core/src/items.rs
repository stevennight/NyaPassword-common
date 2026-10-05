//! Items: the decrypted cache and local edits. Every edit is written to the
//! replica first (as a pending edit) and pushed by the next sync, so editing
//! works offline and nothing is lost if the app is killed.

use std::collections::HashMap;

use npw_api::ItemRecord;
use npw_crypto::{aad, b64, envelope, Key32};
use npw_model::format::format_major_of;
use npw_model::{decode_item, encode_item, ItemContent};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::{d64, uuid_bytes, AccountState, Client, Keyring};
use crate::store::{LocalItem, PendingEdit, Store, StoreOp};
use crate::{search, CoreError, Result};

/// One decrypted item.
#[derive(Clone)]
pub(crate) struct CachedItem {
    pub vault_id: String,
    pub item_id: String,
    pub content: ItemContent,
    pub read_only: bool,
    pub deleted: bool,
    pub pending: bool,
    pub rejected: Option<String>,
    pub revision: i64,
    pub ik: Key32,
    /// Lower-case search text including pinyin.
    pub index: search::SearchIndex,
}

#[derive(Default)]
pub(crate) struct Cache {
    pub items: HashMap<(String, String), CachedItem>,
    /// Items that could not be decrypted: (vault, item, reason).
    pub broken: Vec<(String, String, String)>,
}

pub(crate) struct Decrypted {
    pub content: ItemContent,
    pub read_only: bool,
    pub ik: Key32,
}

pub(crate) fn open_item(
    vk: &Key32,
    vault_id: &str,
    item_id: &str,
    wrapped_key: &str,
    ciphertext: &str,
    format_major: u16,
) -> Result<Decrypted> {
    let v = uuid_bytes(vault_id)?;
    let i = uuid_bytes(item_id)?;
    let ik = envelope::unwrap_key(vk, &d64(wrapped_key)?, &aad::item_key(&v, &i))?;
    let plain = envelope::open(
        &ik,
        &d64(ciphertext)?,
        &aad::item_content(&v, &i, format_major),
    )?;
    let d = decode_item(&plain).map_err(|e| CoreError::Invalid(e.to_string()))?;
    Ok(Decrypted {
        content: d.content,
        read_only: d.read_only,
        ik,
    })
}

/// Seals content: returns (wrapped item key, ciphertext, format major).
pub(crate) fn seal_item(
    vk: &Key32,
    vault_id: &str,
    item_id: &str,
    ik: &Key32,
    content: &ItemContent,
) -> Result<(String, String, u16)> {
    let v = uuid_bytes(vault_id)?;
    let i = uuid_bytes(item_id)?;
    let major = format_major_of(content);
    let wrapped = envelope::wrap_key(vk, ik, &aad::item_key(&v, &i));
    let ct = envelope::seal(ik, &encode_item(content), &aad::item_content(&v, &i, major));
    Ok((b64(&wrapped), b64(&ct), major))
}

pub(crate) fn decrypt_record(vk: &Key32, vault_id: &str, r: &ItemRecord) -> Result<Decrypted> {
    open_item(
        vk,
        vault_id,
        &r.item_id,
        &r.wrapped_key,
        &r.ciphertext,
        r.format_major,
    )
}

pub(crate) fn decrypt_pending(
    vk: &Key32,
    vault_id: &str,
    item_id: &str,
    p: &PendingEdit,
) -> Result<Decrypted> {
    open_item(
        vk,
        vault_id,
        item_id,
        &p.wrapped_key,
        &p.ciphertext,
        p.format_major,
    )
}

impl Cache {
    pub fn build(store: &dyn Store, keys: &Keyring, acc: &AccountState) -> Result<Self> {
        let mut cache = Cache::default();
        for v in &acc.vaults {
            let Some(vk) = keys.vault_keys.get(&v.id) else {
                continue;
            };
            for li in store.list_items(&v.id)? {
                cache.refresh_item(vk, &li);
            }
        }
        Ok(cache)
    }

    /// Re-decrypts one item from its replica state.
    pub fn refresh_item(&mut self, vk: &Key32, li: &LocalItem) {
        let key = (li.vault_id.clone(), li.item_id.clone());
        self.broken
            .retain(|(v, i, _)| !(v == &li.vault_id && i == &li.item_id));
        let (dec, deleted, revision) = match (&li.pending, &li.server) {
            (Some(p), s) => (
                decrypt_pending(vk, &li.vault_id, &li.item_id, p),
                p.deleted,
                s.as_ref().map(|r| r.revision).unwrap_or(0),
            ),
            (None, Some(r)) => (decrypt_record(vk, &li.vault_id, r), r.deleted, r.revision),
            (None, None) => {
                self.items.remove(&key);
                return;
            }
        };
        match dec {
            Ok(d) => {
                let index = search::index(&d.content);
                self.items.insert(
                    key,
                    CachedItem {
                        vault_id: li.vault_id.clone(),
                        item_id: li.item_id.clone(),
                        content: d.content,
                        read_only: d.read_only,
                        deleted,
                        pending: li.pending.is_some(),
                        rejected: li.pending.as_ref().and_then(|p| p.rejected.clone()),
                        revision,
                        ik: d.ik,
                        index,
                    },
                );
            }
            Err(e) => {
                self.items.remove(&key);
                self.broken
                    .push((li.vault_id.clone(), li.item_id.clone(), e.to_string()));
            }
        }
    }
}

/// What hosts show for an item.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ItemView {
    pub vault_id: String,
    pub item_id: String,
    pub template: String,
    pub title: String,
    pub subtitle: String,
    pub favorite: bool,
    pub archived: bool,
    /// Secrets need the user to verify again (master password / biometrics)
    /// before they are shown, copied or filled. Enforced by the hosts.
    #[serde(default)]
    pub reprompt: bool,
    /// In the trash.
    pub deleted: bool,
    pub tags: Vec<String>,
    pub urls: Vec<String>,
    pub has_totp: bool,
    pub passkeys: usize,
    pub attachments: usize,
    pub conflicts: usize,
    pub read_only: bool,
    /// Has a local edit the server has not confirmed yet.
    pub pending: bool,
    /// The server refused the pending edit (the edit is kept).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejected: Option<String>,
    pub revision: i64,
    pub created_at: i64,
    pub updated_at: i64,
    /// Full content: only from [`Client::item`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<ItemContent>,
}

impl CachedItem {
    pub fn view(&self, with_content: bool) -> ItemView {
        let c = &self.content;
        ItemView {
            vault_id: self.vault_id.clone(),
            item_id: self.item_id.clone(),
            template: c.template.clone(),
            title: c.title.clone(),
            subtitle: c.subtitle(),
            favorite: c.favorite,
            archived: c.archived,
            reprompt: c.reprompt,
            deleted: self.deleted,
            tags: c.tags.clone(),
            urls: c.urls.iter().map(|u| u.url.clone()).collect(),
            has_totp: c.totp().is_some(),
            passkeys: c.passkeys.len(),
            attachments: c.attachments.len(),
            conflicts: c.conflicts.len(),
            read_only: self.read_only,
            pending: self.pending,
            rejected: self.rejected.clone(),
            revision: self.revision,
            created_at: c.created_at,
            updated_at: c.updated_at,
            content: with_content.then(|| c.clone()),
        }
    }
}

/// Which items [`Client::list_items`] returns.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ItemFilter {
    #[serde(default)]
    pub vault_id: Option<String>,
    #[serde(default)]
    pub template: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub favorites: bool,
    /// Only items with unresolved conflicts.
    #[serde(default)]
    pub conflicts: bool,
    /// `false`: hide archived (default); `true`: only archived.
    #[serde(default)]
    pub archived: bool,
    /// Only items in the trash.
    #[serde(default)]
    pub trash: bool,
    #[serde(default)]
    pub query: String,
}

impl Client {
    pub(crate) fn vault_key(&self, vault_id: &str) -> Result<Key32> {
        let st = self.state.lock().expect("state");
        st.keys
            .as_ref()
            .ok_or(CoreError::Locked)?
            .vault_keys
            .get(vault_id)
            .cloned()
            .ok_or(CoreError::NotFound)
    }

    pub fn list_items(&self, filter: &ItemFilter) -> Result<Vec<ItemView>> {
        let st = self.state.lock().expect("state");
        if st.keys.is_none() {
            return Err(CoreError::Locked);
        }
        let q = search::Query::parse(&filter.query);
        let mut out: Vec<(i64, ItemView)> = st
            .cache
            .items
            .values()
            .filter(|c| {
                if filter.trash != c.deleted {
                    return false;
                }
                if !filter.trash
                    && filter.archived != c.content.archived
                    && !filter.conflicts
                    && !filter.favorites
                {
                    return false;
                }
                filter.vault_id.as_ref().is_none_or(|v| &c.vault_id == v)
                    && filter
                        .template
                        .as_ref()
                        .is_none_or(|t| &c.content.template == t)
                    && filter.tag.as_ref().is_none_or(|t| {
                        c.content
                            .tags
                            .iter()
                            .any(|x| x == t || x.starts_with(&format!("{t}/")))
                    })
                    && (!filter.favorites || c.content.favorite)
                    && (!filter.conflicts || !c.content.conflicts.is_empty())
                    && q.matches(&c.index)
            })
            .map(|c| (q.score(&c.index, &c.content.title), c.view(false)))
            .collect();
        out.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| a.1.title.to_lowercase().cmp(&b.1.title.to_lowercase()))
        });
        Ok(out.into_iter().map(|(_, v)| v).collect())
    }

    pub fn item(&self, vault_id: &str, item_id: &str) -> Result<ItemView> {
        let st = self.state.lock().expect("state");
        if st.keys.is_none() {
            return Err(CoreError::Locked);
        }
        st.cache
            .items
            .get(&(vault_id.to_string(), item_id.to_string()))
            .map(|c| c.view(true))
            .ok_or(CoreError::NotFound)
    }

    /// All tags in use, sorted.
    pub fn tags(&self) -> Result<Vec<String>> {
        let st = self.state.lock().expect("state");
        let mut tags: Vec<String> = st
            .cache
            .items
            .values()
            .filter(|c| !c.deleted)
            .flat_map(|c| c.content.tags.clone())
            .collect();
        tags.sort();
        tags.dedup();
        Ok(tags)
    }

    /// Creates (`item_id = None`) or updates an item. Local first; the next sync pushes it.
    pub fn save_item(
        &self,
        vault_id: &str,
        item_id: Option<&str>,
        mut content: ItemContent,
    ) -> Result<String> {
        let vk = self.vault_key(vault_id)?;
        let (item_id, ik, deleted) = match item_id {
            Some(id) => {
                let st = self.state.lock().expect("state");
                let cur = st
                    .cache
                    .items
                    .get(&(vault_id.to_string(), id.to_string()))
                    .ok_or(CoreError::NotFound)?;
                if cur.read_only {
                    return Err(CoreError::ReadOnly);
                }
                content.record_changes_from(&cur.content);
                (id.to_string(), cur.ik.clone(), cur.deleted)
            }
            None => {
                let now = npw_model::now_ms();
                if content.created_at == 0 {
                    content.created_at = now;
                }
                content.updated_at = now;
                (npw_model::new_id(), Key32::generate(), false)
            }
        };
        self.write_pending(vault_id, &item_id, &vk, &ik, &content, deleted)?;
        Ok(item_id)
    }

    /// Writes a pending edit for an item and refreshes the cache.
    pub(crate) fn write_pending(
        &self,
        vault_id: &str,
        item_id: &str,
        vk: &Key32,
        ik: &Key32,
        content: &ItemContent,
        deleted: bool,
    ) -> Result<()> {
        let (wrapped_key, ciphertext, format_major) =
            seal_item(vk, vault_id, item_id, ik, content)?;
        let existing = self.store.get_item(vault_id, item_id)?;
        let base_revision = existing
            .as_ref()
            .and_then(|li| li.server.as_ref())
            .map(|r| r.revision)
            .unwrap_or(0);
        let (server, seen) = existing.map(|li| (li.server, li.seen)).unwrap_or_default();
        let li = LocalItem {
            vault_id: vault_id.to_string(),
            item_id: item_id.to_string(),
            server,
            seen,
            pending: Some(PendingEdit {
                op_id: uuid::Uuid::new_v4().to_string(),
                base_revision,
                deleted,
                format_major,
                wrapped_key,
                ciphertext,
                created_at: npw_model::now_ms(),
                rejected: None,
            }),
        };
        self.store.apply(vec![StoreOp::PutItem(li.clone())])?;
        self.state
            .lock()
            .expect("state")
            .cache
            .refresh_item(vk, &li);
        Ok(())
    }

    fn set_deleted(&self, vault_id: &str, item_id: &str, deleted: bool) -> Result<()> {
        let vk = self.vault_key(vault_id)?;
        let (content, ik) = {
            let st = self.state.lock().expect("state");
            let cur = st
                .cache
                .items
                .get(&(vault_id.to_string(), item_id.to_string()))
                .ok_or(CoreError::NotFound)?;
            if cur.deleted == deleted {
                return Ok(());
            }
            (cur.content.clone(), cur.ik.clone())
        };
        self.write_pending(vault_id, item_id, &vk, &ik, &content, deleted)
    }

    /// Moves an item to the trash.
    pub fn delete_item(&self, vault_id: &str, item_id: &str) -> Result<()> {
        self.set_deleted(vault_id, item_id, true)
    }

    /// Takes an item out of the trash.
    pub fn restore_item(&self, vault_id: &str, item_id: &str) -> Result<()> {
        self.set_deleted(vault_id, item_id, false)
    }

    /// Resolves a sync conflict: `use_conflict_value` puts the value that lost back in place.
    pub fn resolve_conflict(
        &self,
        vault_id: &str,
        item_id: &str,
        conflict_id: &str,
        use_conflict_value: bool,
    ) -> Result<()> {
        let mut content = self
            .item(vault_id, item_id)?
            .content
            .ok_or(CoreError::NotFound)?;
        let idx = content
            .conflicts
            .iter()
            .position(|c| c.id == conflict_id)
            .ok_or(CoreError::NotFound)?;
        let conflict = content.conflicts.remove(idx);
        if use_conflict_value {
            let mut tree =
                serde_json::to_value(&content).map_err(|e| CoreError::Invalid(e.to_string()))?;
            set_path(&mut tree, &conflict.path, conflict.value.clone())?;
            content =
                serde_json::from_value(tree).map_err(|e| CoreError::Invalid(e.to_string()))?;
        }
        self.save_item(vault_id, Some(item_id), content)?;
        Ok(())
    }

    /// Items whose conflicts or pending edits need attention.
    pub fn attention(&self) -> Result<(usize, usize, usize)> {
        let st = self.state.lock().expect("state");
        let conflicts = st
            .cache
            .items
            .values()
            .filter(|c| !c.content.conflicts.is_empty())
            .count();
        let pending = st.cache.items.values().filter(|c| c.pending).count();
        let rejected = st
            .cache
            .items
            .values()
            .filter(|c| c.rejected.is_some())
            .count();
        Ok((conflicts, pending, rejected))
    }

    /// Every live item, decrypted, with its vault name. For exports.
    pub fn export_items(&self) -> Result<Vec<(String, ItemContent)>> {
        let vaults: HashMap<String, String> =
            self.vaults()?.into_iter().map(|v| (v.id, v.name)).collect();
        let st = self.state.lock().expect("state");
        let mut out: Vec<(String, ItemContent)> = st
            .cache
            .items
            .values()
            .filter(|c| !c.deleted)
            .map(|c| {
                (
                    vaults.get(&c.vault_id).cloned().unwrap_or_default(),
                    c.content.clone(),
                )
            })
            .collect();
        out.sort_by_key(|a| a.1.created_at);
        Ok(out)
    }

    /// Items whose URLs match a page or app, best match first.
    pub fn autofill_candidates(&self, target: &str) -> Result<Vec<ItemView>> {
        let Some(t) = npw_match::parse(target) else {
            return Ok(vec![]);
        };
        let eq = npw_match::Equivalents::with_builtin(&[]);
        let st = self.state.lock().expect("state");
        if st.keys.is_none() {
            return Err(CoreError::Locked);
        }
        let mut hits: Vec<(npw_match::Quality, i64, ItemView)> = st
            .cache
            .items
            .values()
            .filter(|c| !c.deleted && !c.content.autofill.never)
            .filter_map(|c| {
                let q = npw_match::best_match(
                    c.content
                        .urls
                        .iter()
                        .map(|u| (u.url.as_str(), u.match_mode.as_str())),
                    &t,
                    &eq,
                )?;
                Some((q, c.content.updated_at, c.view(false)))
            })
            .collect();
        hits.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));
        Ok(hits.into_iter().map(|h| h.2).collect())
    }

    /// Items that could not be decrypted (shown by the health check).
    pub fn broken_items(&self) -> Vec<(String, String, String)> {
        self.state.lock().expect("state").cache.broken.clone()
    }

    pub(crate) fn cached_content(
        &self,
        vault_id: &str,
        item_id: &str,
    ) -> Option<(ItemContent, Key32)> {
        let st = self.state.lock().expect("state");
        st.cache
            .items
            .get(&(vault_id.to_string(), item_id.to_string()))
            .map(|c| (c.content.clone(), c.ik.clone()))
    }
}

/// Sets the value at a merge path like `fields/<id>/value`, `title` or `notes`.
fn set_path(tree: &mut Value, path: &str, value: Value) -> Result<()> {
    if path.is_empty() {
        return Err(CoreError::Invalid(
            "cannot restore a whole-item conflict automatically".into(),
        ));
    }
    let segs: Vec<&str> = path.split('/').collect();
    let mut cur = tree;
    for (i, seg) in segs.iter().enumerate() {
        let last = i + 1 == segs.len();
        let next = match cur {
            Value::Object(m) => {
                if last {
                    m.insert(seg.to_string(), value);
                    return Ok(());
                }
                m.entry(seg.to_string()).or_insert(Value::Null)
            }
            Value::Array(a) => {
                let pos = a
                    .iter()
                    .position(|e| e.get("id").and_then(Value::as_str) == Some(seg));
                match pos {
                    Some(p) if last => {
                        a[p] = value;
                        return Ok(());
                    }
                    Some(p) => &mut a[p],
                    None if last => {
                        a.push(value);
                        return Ok(());
                    }
                    None => return Err(CoreError::NotFound),
                }
            }
            _ => return Err(CoreError::NotFound),
        };
        cur = next;
    }
    Ok(())
}
