//! Sync (design doc §7).
//!
//! For each vault: pull the server's changes since the last known sequence
//! number (merging them into local pending edits), push the pending edits
//! with optimistic concurrency, repeat until nothing conflicts, then compare
//! digests (pulling again first when the server moved on meanwhile). A digest
//! mismatch, a server whose sequence went backwards, or a changed server epoch
//! (restored from a backup) triggers a full reconciliation, which re-uploads
//! anything the server lost. Vaults the server stops listing are kept locally
//! and skipped (reported in [`SyncReport::vaults_missing_on_server`]).
//!
//! Invariants:
//! - a pending edit is removed only once the server acknowledged exactly that edit;
//! - a merge never discards a value (see npw-model's merge);
//! - a record that fails to decrypt is stored as is and reported, never merged or overwritten.

use std::collections::{HashMap, HashSet};

use npw_api::{self as api_t, ItemRecord, PushItem, PushStatus};
use npw_crypto::Key32;
use npw_model::{merge_items, ItemContent};
use serde::{Deserialize, Serialize};

use crate::client::{d64, Client};
use crate::items::{decrypt_pending, decrypt_record, seal_item};
use crate::store::{LocalItem, PendingEdit, StoreOp};
use crate::{api, CoreError, Result};

const PAGE: usize = 500;
const PUSH_BATCH: usize = 100;
const MAX_ROUNDS: usize = 8;
/// Digest comparisons per vault and sync before a mismatch means a full reconciliation.
const DIGEST_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SyncReport {
    pub pulled: usize,
    pub pushed: usize,
    /// Remote changes merged into local edits.
    pub merged: usize,
    /// New conflicts recorded in items.
    pub conflicts: usize,
    /// Edits the server refused (kept locally).
    pub rejected: usize,
    /// Items re-uploaded because the server had lost them (restored from a backup).
    pub restored_to_server: usize,
    /// Server records that could not be decrypted (kept, not merged).
    pub undecryptable: usize,
    /// The server sent an older revision than one already seen.
    pub rollbacks_detected: usize,
    pub full_resyncs: usize,
    pub finished_at: i64,
    /// Vaults the server no longer lists. Their local copies (and unsynced
    /// edits) are kept but not synced; the server may have lost them.
    #[serde(default)]
    pub vaults_missing_on_server: usize,
    /// The server sent new unlock material (wrapped account key, KDF parameters,
    /// salt) that failed validation; this device keeps using its own.
    #[serde(default)]
    pub account_key_update_refused: bool,
}

impl Client {
    /// Pulls, merges and pushes every vault. Safe to call any time; concurrent calls run one after another.
    pub async fn sync(&self) -> Result<SyncReport> {
        let _guard = self.sync_lock.lock().await;
        if !self.is_unlocked() {
            return Err(CoreError::Locked);
        }
        let mut report = SyncReport::default();

        let info: api_t::ServerInfo =
            api::call::<api::Empty, _>(&*self.transport()?, "GET", "/v1/server-info", None, None)
                .await?;
        let epoch = info.epoch;
        let acct: api_t::AccountResp = self
            .authed::<api::Empty, _>("GET", "/v1/account", None)
            .await?;
        let server_seqs: HashMap<String, i64> =
            acct.vaults.iter().map(|v| (v.id.clone(), v.seq)).collect();
        let update = self.apply_account_resp(acct)?;
        report.vaults_missing_on_server = update.missing_vaults;
        report.account_key_update_refused = update.unlock_refused;

        let mut acc = self.account()?;
        let epoch_changed = !acc.epoch.is_empty() && !epoch.is_empty() && acc.epoch != epoch;

        let vault_ids: Vec<String> = acc
            .vaults
            .iter()
            .filter(|v| !v.missing_on_server)
            .map(|v| v.id.clone())
            .collect();
        for vault_id in vault_ids {
            let vk = self.vault_key(&vault_id)?;
            let server_seq = server_seqs.get(&vault_id).copied().unwrap_or(0);
            let full = epoch_changed || server_seq < self.local_seq(&vault_id)?;
            self.exchange(&vault_id, &vk, full, &mut report).await?;

            // Compare digests. While the server is ahead of what was pulled, a mismatch
            // can come from writes after the pull (other devices, our own push): pull,
            // push and compare again. A mismatch at the pulled sequence number, or one
            // that persists, means the histories differ: reconcile everything.
            let mut agreed = false;
            for attempt in 1..=DIGEST_ATTEMPTS {
                let d: api_t::DigestResp = self
                    .authed::<api::Empty, _>("GET", &format!("/v1/vaults/{vault_id}/digest"), None)
                    .await?;
                if d.digest == self.local_digest(&vault_id)? {
                    agreed = true;
                    break;
                }
                if attempt == DIGEST_ATTEMPTS || d.vault_seq <= self.local_seq(&vault_id)? {
                    break;
                }
                self.exchange(&vault_id, &vk, false, &mut report).await?;
            }
            if !agreed {
                self.reconcile(&vault_id, &vk, &mut report).await?;
                report.full_resyncs += 1;
                self.push(&vault_id, &mut report).await?;
            }
        }

        acc = self.account()?;
        acc.epoch = epoch;
        acc.last_sync_at = npw_model::now_ms();
        self.save_account(acc)?;
        report.finished_at = npw_model::now_ms();
        Ok(report)
    }

    /// Pull (or fully reconcile) and push until nothing conflicts (at most `MAX_ROUNDS`).
    async fn exchange(
        &self,
        vault_id: &str,
        vk: &Key32,
        mut full: bool,
        report: &mut SyncReport,
    ) -> Result<()> {
        for _ in 0..MAX_ROUNDS {
            if full {
                self.reconcile(vault_id, vk, report).await?;
                report.full_resyncs += 1;
                full = false;
            } else {
                self.pull(vault_id, vk, report).await?;
            }
            let conflicts = self.push(vault_id, report).await?;
            if conflicts == 0 {
                break;
            }
        }
        Ok(())
    }

    /// Changes up to this sequence number are in the replica.
    fn local_seq(&self, vault_id: &str) -> Result<i64> {
        Ok(self
            .account()?
            .vaults
            .iter()
            .find(|v| v.id == vault_id)
            .map(|v| v.seq)
            .unwrap_or(0))
    }

    fn local_digest(&self, vault_id: &str) -> Result<String> {
        let items = self.store.list_items(vault_id)?;
        let heads: Vec<&ItemRecord> = items.iter().filter_map(|i| i.server.as_ref()).collect();
        Ok(api_t::vault_digest(heads.iter().map(|r| {
            (r.item_id.as_str(), r.revision, r.deleted, r.hash.as_str())
        })))
    }

    fn set_vault_seq(&self, vault_id: &str, seq: i64) -> Result<StoreOp> {
        let mut acc = self.account()?;
        if let Some(v) = acc.vaults.iter_mut().find(|v| v.id == vault_id) {
            v.seq = seq;
        }
        let op = self.persist_account(&acc)?;
        self.state.lock().expect("state").account = Some(acc);
        Ok(op)
    }

    async fn pull(&self, vault_id: &str, vk: &Key32, report: &mut SyncReport) -> Result<()> {
        let mut since = self.local_seq(vault_id)?;
        loop {
            let page: api_t::ChangesResp = self
                .authed::<api::Empty, _>(
                    "GET",
                    &format!("/v1/vaults/{vault_id}/changes?since={since}&limit={PAGE}"),
                    None,
                )
                .await?;
            let mut ops = vec![];
            let mut touched = vec![];
            let mut touched_purged: Vec<String> = vec![];
            for rec in page.items {
                if let Some(li) = self.apply_remote(vault_id, vk, rec, report)? {
                    touched.push(li.clone());
                    ops.push(StoreOp::PutItem(li));
                }
            }
            for id in &page.purged {
                match self.apply_purge(vault_id, id)? {
                    Some(op) => ops.push(op),
                    None => continue,
                }
                touched_purged.push(id.clone());
            }
            since = page.next_seq;
            ops.push(self.set_vault_seq(vault_id, since)?);
            self.store.apply(ops)?;
            {
                let mut st = self.state.lock().expect("state");
                for li in &touched {
                    st.cache.refresh_item(vk, li);
                }
                for id in &touched_purged {
                    if let Ok(Some(li)) = self.store.get_item(vault_id, id) {
                        st.cache.refresh_item(vk, &li);
                    } else {
                        st.cache.items.remove(&(vault_id.to_string(), id.clone()));
                    }
                }
            }
            if !page.has_more {
                return Ok(());
            }
        }
    }

    /// Folds one server record into the replica. Returns the new local state, if it changed.
    fn apply_remote(
        &self,
        vault_id: &str,
        vk: &Key32,
        rec: ItemRecord,
        report: &mut SyncReport,
    ) -> Result<Option<LocalItem>> {
        let wk = d64(&rec.wrapped_key)?;
        let ct = d64(&rec.ciphertext)?;
        if api_t::item_hash(&wk, &ct) != rec.hash {
            return Err(CoreError::Network(format!(
                "item {} arrived corrupted (hash mismatch)",
                rec.item_id
            )));
        }
        let local = self.store.get_item(vault_id, &rec.item_id)?;
        let mut li = local
            .clone()
            .unwrap_or_else(|| LocalItem::new(vault_id, &rec.item_id));

        if let Some(s) = &li.server {
            if rec.revision < s.revision {
                report.rollbacks_detected += 1;
                return Ok(None);
            }
            if rec.revision == s.revision && rec.hash == s.hash {
                return Ok(None);
            }
        }
        report.pulled += 1;

        let Some(pending) = li.pending.clone() else {
            li.set_server(rec);
            return Ok(Some(li));
        };
        if pending.base_revision == rec.revision
            && li.server.as_ref().is_some_and(|s| s.hash == rec.hash)
        {
            li.set_server(rec);
            return Ok(Some(li));
        }

        // The item changed on the server while this device has an unsynced edit: merge.
        let remote = match decrypt_record(vk, vault_id, &rec) {
            Ok(d) => d,
            Err(_) => {
                // Keep both untouched: the record becomes the base, our edit stays pending (and
                // will be refused as a conflict until a client that can read the record merges).
                report.undecryptable += 1;
                li.set_server(rec);
                return Ok(Some(li));
            }
        };
        let mine = decrypt_pending(vk, vault_id, &li.item_id, &pending)?;
        let base: Option<ItemContent> = li
            .server
            .as_ref()
            .and_then(|s| decrypt_record(vk, vault_id, s).ok())
            .map(|d| d.content);
        let device = self.account()?.device_id;
        let outcome = merge_items(base.as_ref(), &mine.content, &remote.content, &device);
        report.merged += 1;
        report.conflicts += outcome.new_conflicts;

        // Deletion: an edit on either side beats a deletion on the other.
        let base_deleted = li.server.as_ref().is_some_and(|s| s.deleted);
        let mine_changed = base.as_ref() != Some(&mine.content);
        let remote_changed = base.as_ref() != Some(&remote.content);
        let deleted = if pending.deleted == rec.deleted {
            rec.deleted
        } else if pending.deleted != base_deleted {
            // this device moved it to / out of the trash; a deletion loses to a remote edit
            pending.deleted && !remote_changed
        } else {
            // the server side moved it to / out of the trash; a deletion loses to our edit
            rec.deleted && !mine_changed
        };

        let merged = outcome.content;
        let ik = if remote.read_only || mine.read_only {
            None
        } else {
            Some(remote.ik.clone())
        };
        li.set_server(rec.clone());
        if merged == remote.content && deleted == rec.deleted {
            li.pending = None;
        } else if let Some(ik) = ik {
            let (wrapped_key, ciphertext, format_major) =
                seal_item(vk, vault_id, &li.item_id, &ik, &merged)?;
            li.pending = Some(PendingEdit {
                op_id: uuid::Uuid::new_v4().to_string(),
                base_revision: rec.revision,
                deleted,
                format_major,
                wrapped_key,
                ciphertext,
                created_at: npw_model::now_ms(),
                rejected: None,
            });
        } else {
            // A newer client wrote the remote revision: we must not rewrite it. Keep our
            // edit (visible, not lost) but stop pushing it.
            if let Some(p) = &mut li.pending {
                p.rejected = Some(
                    "the item was changed by a newer version of NyaPassword; update this app"
                        .into(),
                );
            }
            report.rejected += 1;
        }
        Ok(Some(li))
    }

    /// An item was permanently deleted on the server. Drop it, unless this
    /// device has an unsynced edit: then the edit re-creates it (an edit is
    /// never lost).
    fn apply_purge(&self, vault_id: &str, item_id: &str) -> Result<Option<StoreOp>> {
        let Some(mut li) = self.store.get_item(vault_id, item_id)? else {
            return Ok(None);
        };
        match &mut li.pending {
            Some(p) => {
                p.base_revision = 0;
                li.server = None;
                Ok(Some(StoreOp::PutItem(li)))
            }
            None => Ok(Some(StoreOp::DeleteItem {
                vault_id: vault_id.to_string(),
                item_id: item_id.to_string(),
            })),
        }
    }

    /// Pushes pending edits. Returns how many came back as conflicts.
    async fn push(&self, vault_id: &str, report: &mut SyncReport) -> Result<usize> {
        let pending: Vec<LocalItem> = self
            .store
            .list_items(vault_id)?
            .into_iter()
            .filter(|li| li.pending.as_ref().is_some_and(|p| p.rejected.is_none()))
            .collect();
        let vk = self.vault_key(vault_id)?;
        let mut conflicts = 0;
        for chunk in pending.chunks(PUSH_BATCH) {
            let items: Vec<PushItem> = chunk
                .iter()
                .map(|li| {
                    let p = li.pending.as_ref().expect("filtered");
                    PushItem {
                        op_id: p.op_id.clone(),
                        item_id: li.item_id.clone(),
                        base_revision: p.base_revision,
                        deleted: p.deleted,
                        format_major: p.format_major,
                        wrapped_key: p.wrapped_key.clone(),
                        ciphertext: p.ciphertext.clone(),
                    }
                })
                .collect();
            let sent: HashMap<String, PushItem> = items
                .iter()
                .map(|i| (i.item_id.clone(), i.clone()))
                .collect();
            let resp: api_t::PushResp = self
                .authed(
                    "POST",
                    &format!("/v1/vaults/{vault_id}/items/batch"),
                    Some(&api_t::PushReq {
                        items,
                        atomic: false,
                    }),
                )
                .await?;
            let device_id = self.account()?.device_id;
            let mut ops = vec![];
            let mut touched = vec![];
            for r in resp.results {
                let Some(sent_item) = sent.get(&r.item_id) else {
                    continue;
                };
                // Re-read: the user may have edited again while the request was in flight.
                let Some(mut li) = self.store.get_item(vault_id, &r.item_id)? else {
                    continue;
                };
                match r.status {
                    PushStatus::Ok => {
                        let revision = r.revision.ok_or_else(|| {
                            CoreError::Network("push result without revision".into())
                        })?;
                        let wk = d64(&sent_item.wrapped_key)?;
                        let ct = d64(&sent_item.ciphertext)?;
                        li.set_server(ItemRecord {
                            item_id: r.item_id.clone(),
                            revision,
                            seq: r.seq.unwrap_or(0),
                            deleted: sent_item.deleted,
                            format_major: sent_item.format_major,
                            wrapped_key: sent_item.wrapped_key.clone(),
                            ciphertext: sent_item.ciphertext.clone(),
                            hash: api_t::item_hash(&wk, &ct),
                            updated_at: npw_model::now_ms(),
                            device_id: device_id.clone(),
                        });
                        match &mut li.pending {
                            Some(p) if p.op_id == sent_item.op_id => li.pending = None,
                            // edited again meanwhile: that edit now builds on the acknowledged revision
                            Some(p) => p.base_revision = revision,
                            None => {}
                        }
                        report.pushed += 1;
                    }
                    PushStatus::Conflict => {
                        conflicts += 1;
                        continue;
                    }
                    PushStatus::Rejected => {
                        if let Some(p) = &mut li.pending {
                            if p.op_id == sent_item.op_id {
                                p.rejected =
                                    Some(r.reason.clone().unwrap_or_else(|| "rejected".into()));
                            }
                        }
                        report.rejected += 1;
                    }
                }
                touched.push(li.clone());
                ops.push(StoreOp::PutItem(li));
            }
            self.store.apply(ops)?;
            let mut st = self.state.lock().expect("state");
            for li in &touched {
                st.cache.refresh_item(&vk, li);
            }
        }
        Ok(conflicts)
    }

    /// Full reconciliation against every item head on the server.
    async fn reconcile(&self, vault_id: &str, vk: &Key32, report: &mut SyncReport) -> Result<()> {
        let mut server: HashMap<String, ItemRecord> = HashMap::new();
        let mut since = 0;
        let vault_seq;
        // Tombstones come with the page whose sequence range holds them (older
        // servers: only with the last page), so collect them from every page.
        let mut purged: HashSet<String> = HashSet::new();
        loop {
            let page: api_t::ChangesResp = self
                .authed::<api::Empty, _>(
                    "GET",
                    &format!("/v1/vaults/{vault_id}/changes?since={since}&limit={PAGE}"),
                    None,
                )
                .await?;
            for r in page.items {
                server.insert(r.item_id.clone(), r);
            }
            purged.extend(page.purged);
            since = page.next_seq;
            if !page.has_more {
                vault_seq = page.vault_seq;
                break;
            }
        }
        let locals = self.store.list_items(vault_id)?;
        let local_ids: HashSet<String> = locals.iter().map(|l| l.item_id.clone()).collect();
        let mut ops = vec![];
        let mut touched = vec![];

        let mut dropped = vec![];
        for mut li in locals {
            let srv = server.remove(&li.item_id);
            if srv.is_none() && purged.contains(&li.item_id) {
                match self.apply_purge(vault_id, &li.item_id)? {
                    Some(StoreOp::PutItem(kept)) => li = kept,
                    Some(op) => {
                        ops.push(op);
                        dropped.push(li.item_id.clone());
                        continue;
                    }
                    None => continue,
                }
                touched.push(li.clone());
                ops.push(StoreOp::PutItem(li));
                continue;
            }
            match (srv, li.server.clone()) {
                (Some(rec), Some(mine)) if rec.hash == mine.hash => li.set_server(rec),
                (Some(rec), Some(_)) if li.seen.contains(&rec.hash) => {
                    // The server is at a revision this device had already seen: it lost the
                    // newer ones (restored from an older backup). Put ours back on top.
                    if self.restore_onto(vault_id, vk, &mut li, Some(rec), false, report)? {
                        report.restored_to_server += 1;
                    }
                }
                (Some(rec), Some(mine)) => {
                    // A state this device never saw. If the server's history contains our head,
                    // it is simply newer; otherwise the histories diverged: merge, keep both.
                    let newer = rec.revision > mine.revision
                        && self.server_has(vault_id, &rec.item_id, &mine.hash).await?;
                    if newer {
                        let mut tmp = SyncReport::default();
                        if let Some(new_li) = self.apply_remote(vault_id, vk, rec, &mut tmp)? {
                            li = new_li;
                        }
                        report.pulled += tmp.pulled;
                        report.merged += tmp.merged;
                        report.conflicts += tmp.conflicts;
                        report.undecryptable += tmp.undecryptable;
                    } else if self.restore_onto(vault_id, vk, &mut li, Some(rec), true, report)? {
                        report.restored_to_server += 1;
                    }
                }
                (Some(rec), None) => {
                    let mut tmp_report = SyncReport::default();
                    if let Some(new_li) = self.apply_remote(vault_id, vk, rec, &mut tmp_report)? {
                        li = new_li;
                    }
                    report.pulled += tmp_report.pulled;
                    report.merged += tmp_report.merged;
                    report.conflicts += tmp_report.conflicts;
                    report.undecryptable += tmp_report.undecryptable;
                }
                (None, Some(_)) => {
                    // The server does not have this item at all any more.
                    if self.restore_onto(vault_id, vk, &mut li, None, false, report)? {
                        report.restored_to_server += 1;
                    }
                }
                (None, None) => {} // created locally, not pushed yet
            }
            touched.push(li.clone());
            ops.push(StoreOp::PutItem(li));
        }
        for (_, rec) in server {
            if local_ids.contains(&rec.item_id) {
                continue;
            }
            let mut tmp = SyncReport::default();
            if let Some(li) = self.apply_remote(vault_id, vk, rec, &mut tmp)? {
                report.pulled += 1;
                touched.push(li.clone());
                ops.push(StoreOp::PutItem(li));
            }
        }
        ops.push(self.set_vault_seq(vault_id, vault_seq)?);
        self.store.apply(ops)?;
        let mut st = self.state.lock().expect("state");
        for li in &touched {
            st.cache.refresh_item(vk, li);
        }
        for id in dropped {
            st.cache.items.remove(&(vault_id.to_string(), id));
        }
        Ok(())
    }

    /// Does the server's history of an item contain a revision with this hash?
    async fn server_has(&self, vault_id: &str, item_id: &str, hash: &str) -> Result<bool> {
        let r: api_t::RevisionsResp = self
            .authed::<api::Empty, _>(
                "GET",
                &format!("/v1/vaults/{vault_id}/items/{item_id}/revisions"),
                None,
            )
            .await?;
        Ok(r.revisions.iter().any(|x| x.hash == hash))
    }

    /// Makes this device's newest state of an item a pending edit on top of the
    /// server's (older or missing) record. `diverged`: the server's record is not
    /// an ancestor of ours, so merge without a base (both sides' values survive).
    fn restore_onto(
        &self,
        vault_id: &str,
        vk: &Key32,
        li: &mut LocalItem,
        server: Option<ItemRecord>,
        diverged: bool,
        report: &mut SyncReport,
    ) -> Result<bool> {
        let base_revision = server.as_ref().map(|r| r.revision).unwrap_or(0);
        // Newest local state: the pending edit if any, else the last server head we saw.
        let (wrapped_key, ciphertext, format_major, deleted) = match (&li.pending, &li.server) {
            (Some(p), _) => (
                p.wrapped_key.clone(),
                p.ciphertext.clone(),
                p.format_major,
                p.deleted,
            ),
            (None, Some(s)) => (
                s.wrapped_key.clone(),
                s.ciphertext.clone(),
                s.format_major,
                s.deleted,
            ),
            (None, None) => return Ok(false),
        };
        let mut new_pending = PendingEdit {
            op_id: uuid::Uuid::new_v4().to_string(),
            base_revision,
            deleted,
            format_major,
            wrapped_key,
            ciphertext,
            created_at: npw_model::now_ms(),
            rejected: None,
        };
        if let Some(rec) = server.as_ref().filter(|_| diverged) {
            // Same item, diverged history: merge without a base so both sides' values survive.
            if let (Ok(theirs), Ok(mine)) = (
                decrypt_record(vk, vault_id, rec),
                decrypt_pending(vk, vault_id, &li.item_id, &new_pending),
            ) {
                if theirs.content != mine.content {
                    let device = self.account()?.device_id;
                    let out = merge_items(None, &mine.content, &theirs.content, &device);
                    report.conflicts += out.new_conflicts;
                    let (wk, ct, fm) =
                        seal_item(vk, vault_id, &li.item_id, &theirs.ik, &out.content)?;
                    new_pending.wrapped_key = wk;
                    new_pending.ciphertext = ct;
                    new_pending.format_major = fm;
                    new_pending.deleted = deleted && rec.deleted;
                }
            }
        }
        match server {
            Some(r) => li.set_server(r),
            None => li.server = None,
        }
        li.pending = Some(new_pending);
        Ok(true)
    }
}
