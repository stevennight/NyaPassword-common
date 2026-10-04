//! Operations that need the server: revision history, emptying the trash,
//! attachments, and atomic imports.

use npw_api::{self as api_t, ItemRecord, PushItem, PushStatus};
use npw_crypto::{aad, b64, stream, Key32};
use npw_model::{Attachment, ItemContent};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::client::{d64, uuid_bytes, Client};
use crate::items::{decrypt_record, seal_item};
use crate::store::{LocalItem, StoreOp};
use crate::{api, CoreError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImportResult {
    pub batch_id: String,
    pub imported: usize,
}

/// Imported items carry `"import": {"batch", "source", "at"}` (unknown to older
/// clients, preserved by them) so a whole import can be undone.
pub const IMPORT_KEY: &str = "import";

impl Client {
    /// Every saved revision of an item, newest first.
    pub async fn item_history(
        &self,
        vault_id: &str,
        item_id: &str,
    ) -> Result<Vec<api_t::RevisionInfo>> {
        let r: api_t::RevisionsResp = self
            .authed::<api::Empty, _>(
                "GET",
                &format!("/v1/vaults/{vault_id}/items/{item_id}/revisions"),
                None,
            )
            .await?;
        Ok(r.revisions)
    }

    /// The content of one revision.
    pub async fn item_revision(
        &self,
        vault_id: &str,
        item_id: &str,
        revision: i64,
    ) -> Result<ItemContent> {
        let rec: ItemRecord = self
            .authed::<api::Empty, _>(
                "GET",
                &format!("/v1/vaults/{vault_id}/items/{item_id}/revisions/{revision}"),
                None,
            )
            .await?;
        let vk = self.vault_key(vault_id)?;
        Ok(decrypt_record(&vk, vault_id, &rec)?.content)
    }

    /// Makes an old revision the current content (as a new revision: history is never rewritten).
    pub async fn restore_revision(
        &self,
        vault_id: &str,
        item_id: &str,
        revision: i64,
    ) -> Result<()> {
        let mut old = self.item_revision(vault_id, item_id, revision).await?;
        let cur = self
            .item(vault_id, item_id)?
            .content
            .ok_or(CoreError::NotFound)?;
        // keep the password history and conflicts collected since
        for h in cur.history {
            if !old.history.iter().any(|x| x.id == h.id) {
                old.history.push(h);
            }
        }
        old.conflicts = cur.conflicts;
        self.save_item(vault_id, Some(item_id), old)?;
        Ok(())
    }

    /// Permanently deletes items that are in the trash (synced first).
    pub async fn purge(&self, vault_id: &str, item_ids: &[String]) -> Result<Vec<String>> {
        self.sync().await?;
        let mut ids = vec![];
        for id in item_ids {
            let li = self
                .store
                .get_item(vault_id, id)?
                .ok_or(CoreError::NotFound)?;
            let in_trash = li.pending.is_none() && li.server.as_ref().is_some_and(|s| s.deleted);
            if !in_trash {
                return Err(CoreError::Invalid(
                    "only items in the trash can be deleted permanently".into(),
                ));
            }
            ids.push(id.clone());
        }
        let r: api_t::PurgeResp = self
            .authed(
                "POST",
                &format!("/v1/vaults/{vault_id}/purge"),
                Some(&api_t::PurgeReq { item_ids: ids }),
            )
            .await?;
        let ops = r
            .purged
            .iter()
            .map(|id| StoreOp::DeleteItem {
                vault_id: vault_id.to_string(),
                item_id: id.clone(),
            })
            .collect();
        self.store.apply(ops)?;
        let mut st = self.state.lock().expect("state");
        for id in &r.purged {
            st.cache.items.remove(&(vault_id.to_string(), id.clone()));
        }
        Ok(r.purged)
    }

    /// Encrypts and uploads a file, then adds it to the item (a local edit, synced next).
    pub async fn add_attachment(
        &self,
        vault_id: &str,
        item_id: &str,
        name: &str,
        mime: &str,
        data: &[u8],
    ) -> Result<String> {
        let (_, _) = self
            .cached_content(vault_id, item_id)
            .ok_or(CoreError::NotFound)?;
        let att_id = uuid::Uuid::new_v4().to_string();
        let fk = Key32::generate();
        let blob = stream::encrypt(&fk, &aad::attachment(&uuid_bytes(&att_id)?), data);
        let sha = npw_crypto::sha256_hex(&blob);
        let info: api_t::AttachmentInfo = serde_json::from_slice(
            &self
                .authed_raw(
                    "PUT",
                    &format!("/v1/vaults/{vault_id}/attachments/{att_id}?item={item_id}"),
                    Some(blob.clone()),
                )
                .await?,
        )
        .map_err(|e| CoreError::Network(e.to_string()))?;
        if info.sha256 != sha {
            return Err(CoreError::Network("attachment upload corrupted".into()));
        }
        self.store
            .apply(vec![StoreOp::PutBlob(format!("att/{att_id}"), blob)])?;
        let (mut content, _) = self
            .cached_content(vault_id, item_id)
            .ok_or(CoreError::NotFound)?;
        content.attachments.push(Attachment {
            id: att_id.clone(),
            name: name.to_string(),
            size: data.len() as u64,
            mime: mime.to_string(),
            key: b64(fk.as_bytes()),
            blob_sha256: sha,
            created_at: npw_model::now_ms(),
            extra: Default::default(),
        });
        self.save_item(vault_id, Some(item_id), content)?;
        Ok(att_id)
    }

    /// Decrypted attachment content (downloaded once, then cached encrypted).
    pub async fn attachment(
        &self,
        vault_id: &str,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<Vec<u8>> {
        let (content, _) = self
            .cached_content(vault_id, item_id)
            .ok_or(CoreError::NotFound)?;
        let att = content
            .attachments
            .iter()
            .find(|a| a.id == attachment_id)
            .ok_or(CoreError::NotFound)?
            .clone();
        let key = format!("att/{attachment_id}");
        let blob = match self.store.get_blob(&key)? {
            Some(b) => b,
            None => {
                let b = self
                    .authed_raw(
                        "GET",
                        &format!("/v1/vaults/{vault_id}/attachments/{attachment_id}"),
                        None,
                    )
                    .await?;
                self.store.apply(vec![StoreOp::PutBlob(key, b.clone())])?;
                b
            }
        };
        if !att.blob_sha256.is_empty() && npw_crypto::sha256_hex(&blob) != att.blob_sha256 {
            return Err(CoreError::Invalid(
                "attachment does not match its checksum".into(),
            ));
        }
        let fk = Key32::from_slice(&d64(&att.key)?)?;
        Ok(stream::decrypt(
            &fk,
            &aad::attachment(&uuid_bytes(attachment_id)?),
            &blob,
        )?)
    }

    /// Removes an attachment from the item (the blob stays on the server for history).
    pub fn remove_attachment(
        &self,
        vault_id: &str,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<()> {
        let (mut content, _) = self
            .cached_content(vault_id, item_id)
            .ok_or(CoreError::NotFound)?;
        content.attachments.retain(|a| a.id != attachment_id);
        self.save_item(vault_id, Some(item_id), content)?;
        Ok(())
    }

    /// Imports items in one all-or-nothing request (online). Each item is
    /// tagged with the batch so the import can be undone as a whole.
    pub async fn import_items(
        &self,
        vault_id: &str,
        items: Vec<ItemContent>,
        source: &str,
    ) -> Result<ImportResult> {
        let items = items
            .into_iter()
            .map(|c| (npw_model::new_id(), c))
            .collect();
        self.import_items_with_ids(vault_id, items, source).await
    }

    /// Same, with item ids chosen by the caller.
    pub async fn import_items_with_ids(
        &self,
        vault_id: &str,
        items: Vec<(String, ItemContent)>,
        source: &str,
    ) -> Result<ImportResult> {
        let vk = self.vault_key(vault_id)?;
        let batch_id = uuid::Uuid::now_v7().to_string();
        let now = npw_model::now_ms();
        let mut push = vec![];
        let mut locals = vec![];
        for (item_id, mut c) in items {
            c.extra.insert(
                IMPORT_KEY.into(),
                json!({ "batch": batch_id, "source": source, "at": now }),
            );
            if c.created_at == 0 {
                c.created_at = now;
            }
            if c.updated_at == 0 {
                c.updated_at = now;
            }
            let ik = Key32::generate();
            let (wrapped_key, ciphertext, format_major) =
                seal_item(&vk, vault_id, &item_id, &ik, &c)?;
            push.push(PushItem {
                op_id: uuid::Uuid::new_v4().to_string(),
                item_id: item_id.clone(),
                base_revision: 0,
                deleted: false,
                format_major,
                wrapped_key,
                ciphertext,
            });
        }
        let device_id = self.account()?.device_id;
        let mut imported = 0;
        // one atomic request per 500 items keeps requests a sane size
        for chunk in push.chunks(500) {
            let resp: api_t::PushResp = self
                .authed(
                    "POST",
                    &format!("/v1/vaults/{vault_id}/items/batch"),
                    Some(&api_t::PushReq {
                        items: chunk.to_vec(),
                        atomic: true,
                    }),
                )
                .await?;
            for (r, p) in resp.results.iter().zip(chunk) {
                if r.status != PushStatus::Ok {
                    return Err(CoreError::Invalid(format!(
                        "import refused by the server: {}",
                        r.reason.clone().unwrap_or_default()
                    )));
                }
                let rec = ItemRecord {
                    item_id: p.item_id.clone(),
                    revision: r.revision.unwrap_or(1),
                    seq: r.seq.unwrap_or(0),
                    deleted: false,
                    format_major: p.format_major,
                    wrapped_key: p.wrapped_key.clone(),
                    ciphertext: p.ciphertext.clone(),
                    hash: api_t::item_hash(&d64(&p.wrapped_key)?, &d64(&p.ciphertext)?),
                    updated_at: now,
                    device_id: device_id.clone(),
                };
                let mut li = LocalItem::new(vault_id, &p.item_id);
                li.set_server(rec);
                locals.push(li);
                imported += 1;
            }
        }
        self.store
            .apply(locals.iter().cloned().map(StoreOp::PutItem).collect())?;
        let mut st = self.state.lock().expect("state");
        for li in &locals {
            st.cache.refresh_item(&vk, li);
        }
        Ok(ImportResult { batch_id, imported })
    }

    /// Import batches present in the vault: (batch id, source, time, item count).
    pub fn import_batches(&self) -> Result<Vec<(String, String, i64, usize)>> {
        let st = self.state.lock().expect("state");
        let mut map: std::collections::BTreeMap<String, (String, i64, usize)> = Default::default();
        for c in st.cache.items.values().filter(|c| !c.deleted) {
            if let Some(imp) = c.content.extra.get(IMPORT_KEY) {
                let batch = imp
                    .get("batch")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let e = map.entry(batch).or_insert((
                    imp.get("source")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    imp.get("at").and_then(|v| v.as_i64()).unwrap_or(0),
                    0,
                ));
                e.2 += 1;
            }
        }
        Ok(map
            .into_iter()
            .map(|(b, (s, at, n))| (b, s, at, n))
            .collect())
    }

    /// Moves every item of an import batch to the trash.
    pub fn undo_import(&self, batch_id: &str) -> Result<usize> {
        let targets: Vec<(String, String)> = {
            let st = self.state.lock().expect("state");
            st.cache
                .items
                .values()
                .filter(|c| {
                    !c.deleted
                        && c.content
                            .extra
                            .get(IMPORT_KEY)
                            .and_then(|i| i.get("batch"))
                            .and_then(|b| b.as_str())
                            == Some(batch_id)
                })
                .map(|c| (c.vault_id.clone(), c.item_id.clone()))
                .collect()
        };
        for (v, i) in &targets {
            self.delete_item(v, i)?;
        }
        Ok(targets.len())
    }
}
