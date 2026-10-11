//! Tidying up: bulk edits of many items, renaming and deleting tags, and
//! finding and merging duplicate items. Every change is an ordinary local edit
//! (a new revision, synced next) and nothing is deleted for good: merged items
//! go to the trash and earlier contents stay in the revision history.

use std::collections::{BTreeMap, HashMap, HashSet};

use npw_model::{new_short_id, Field, HistoryEntry, ItemContent};
use serde::{Deserialize, Serialize};

use crate::client::Client;
use crate::items::{CachedItem, ItemView, PendingWrite};
use crate::remote::IMPORT_KEY;
use crate::{CoreError, Result};

/// An item, by vault and ID.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ItemRef {
    pub vault_id: String,
    pub item_id: String,
}

impl ItemRef {
    pub fn new(vault_id: impl Into<String>, item_id: impl Into<String>) -> Self {
        Self {
            vault_id: vault_id.into(),
            item_id: item_id.into(),
        }
    }

    fn key(&self) -> (String, String) {
        (self.vault_id.clone(), self.item_id.clone())
    }
}

/// What [`Client::bulk_update`] does to each item.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BulkAction {
    AddTags {
        tags: Vec<String>,
    },
    RemoveTags {
        tags: Vec<String>,
    },
    Favorite {
        on: bool,
    },
    Archive {
        on: bool,
    },
    /// Move to the trash.
    Trash,
    /// Take out of the trash.
    Restore,
}

/// An item a bulk edit left alone.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Skipped {
    pub vault_id: String,
    pub item_id: String,
    pub title: String,
    /// `read_only` (written by a newer version) or `not_found`.
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BulkReport {
    /// Items written (one new revision each).
    pub changed: usize,
    /// Items that already were as asked.
    pub unchanged: usize,
    pub skipped: Vec<Skipped>,
}

/// A tag in use and how many items carry it or one of its sub-tags.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TagCount {
    pub tag: String,
    pub items: usize,
}

/// Items that look like the same thing saved more than once.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DuplicateGroup {
    /// The site (registrable domain) the items share; empty when they were
    /// grouped by title or content.
    pub site: String,
    /// The username they share (as saved in the newest item); may be empty.
    pub username: String,
    /// Newest first: the first one is the suggested item to keep.
    pub items: Vec<ItemView>,
    /// Every item has the same password (or none has one).
    pub same_password: bool,
    /// The items have the same content (ignoring tags, dates and history).
    pub identical: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MergeReport {
    pub kept: Option<ItemRef>,
    /// Items moved to the trash.
    pub trashed: usize,
    /// Attachments copied to the kept item.
    pub attachments_copied: usize,
    /// Differing passwords and other secrets, kept in the password history.
    pub secrets_to_history: usize,
}

/// `" 工作 / 开发/ "` → `工作/开发`; `None` when nothing is left.
pub fn normalize_tag(tag: &str) -> Option<String> {
    let parts: Vec<&str> = tag
        .split('/')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    (!parts.is_empty()).then(|| parts.join("/"))
}

fn normalize_tags(tags: &[String]) -> Result<Vec<String>> {
    let mut out: Vec<String> = vec![];
    for t in tags {
        if let Some(t) = normalize_tag(t) {
            if !out.contains(&t) {
                out.push(t);
            }
        }
    }
    if out.is_empty() {
        return Err(CoreError::Invalid("no tag given".into()));
    }
    Ok(out)
}

/// `tag` is `of` or one of its sub-tags (`of/…`).
fn under(tag: &str, of: &str) -> bool {
    tag == of
        || tag
            .strip_prefix(of)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn dedup_keep_order(tags: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    tags.into_iter()
        .filter(|t| seen.insert(t.clone()))
        .collect()
}

/// Applies a content action; `true` when the content changed.
fn apply_action(c: &mut ItemContent, a: &BulkAction) -> bool {
    match a {
        BulkAction::AddTags { tags } => {
            let before = c.tags.len();
            for t in tags {
                if !c.tags.contains(t) {
                    c.tags.push(t.clone());
                }
            }
            c.tags.len() != before
        }
        BulkAction::RemoveTags { tags } => {
            let before = c.tags.len();
            c.tags.retain(|t| !tags.contains(t));
            c.tags.len() != before
        }
        BulkAction::Favorite { on } => std::mem::replace(&mut c.favorite, *on) != *on,
        BulkAction::Archive { on } => std::mem::replace(&mut c.archived, *on) != *on,
        BulkAction::Trash | BulkAction::Restore => false,
    }
}

/// Renames tag `from` (and its sub-tags) to `to`; `true` when anything changed.
fn rename_in(tags: &mut Vec<String>, from: &str, to: &str) -> bool {
    if !tags.iter().any(|t| under(t, from)) {
        return false;
    }
    let renamed = tags
        .iter()
        .map(|t| {
            if under(t, from) {
                format!("{to}{}", &t[from.len()..])
            } else {
                t.clone()
            }
        })
        .collect();
    let next = dedup_keep_order(renamed);
    let changed = &next != tags;
    *tags = next;
    changed
}

// ------------------------------------------------------------- duplicates

/// What makes two items "the same content": everything the user typed in,
/// without IDs, labels, dates, tags, flags or history.
fn fingerprint(c: &ItemContent) -> String {
    let mut fields: Vec<(String, String, String)> = c
        .fields
        .iter()
        .filter(|f| !f.is_empty())
        .map(|f| {
            (
                f.kind.clone(),
                f.purpose.clone().unwrap_or_default(),
                f.text(),
            )
        })
        .collect();
    fields.sort();
    let mut urls: Vec<String> = c.urls.iter().map(|u| u.url.trim().to_lowercase()).collect();
    urls.sort();
    urls.dedup();
    let mut passkeys: Vec<&str> = c
        .passkeys
        .iter()
        .map(|p| p.credential_id.as_str())
        .collect();
    passkeys.sort();
    let mut files: Vec<(&str, u64)> = c
        .attachments
        .iter()
        .map(|a| (a.name.as_str(), a.size))
        .collect();
    files.sort();
    serde_json::json!([
        c.template,
        c.title.trim().to_lowercase(),
        fields,
        urls,
        c.notes.trim(),
        passkeys,
        files
    ])
    .to_string()
}

struct UnionFind(Vec<usize>);

impl UnionFind {
    fn find(&mut self, i: usize) -> usize {
        let mut r = i;
        while self.0[r] != r {
            r = self.0[r];
        }
        let mut i = i;
        while self.0[i] != r {
            let next = self.0[i];
            self.0[i] = r;
            i = next;
        }
        r
    }

    fn union(&mut self, a: usize, b: usize) {
        let (a, b) = (self.find(a), self.find(b));
        if a != b {
            self.0[b] = a;
        }
    }
}

/// Groups items that look like duplicates: the same username on the same site
/// (or, without URLs, under the same title), or the same content.
fn find_duplicates(items: &[&CachedItem]) -> Vec<DuplicateGroup> {
    let mut uf = UnionFind((0..items.len()).collect());
    let mut first: HashMap<String, usize> = HashMap::new();
    let mut link = |key: String, i: usize, uf: &mut UnionFind| match first.get(&key) {
        Some(&j) => uf.union(j, i),
        None => {
            first.insert(key, i);
        }
    };
    let prints: Vec<String> = items.iter().map(|c| fingerprint(&c.content)).collect();
    for (i, c) in items.iter().enumerate() {
        link(format!("c\n{}", prints[i]), i, &mut uf);
        let Some(user) = c.content.username() else {
            continue;
        };
        let user = user.trim().to_lowercase();
        if c.content.urls.is_empty() {
            let title = c.content.title.trim().to_lowercase();
            if !title.is_empty() {
                link(format!("t\n{title}\n{user}"), i, &mut uf);
            }
        }
        for u in &c.content.urls {
            let site = npw_match::site(&u.url);
            if !site.is_empty() {
                link(format!("s\n{site}\n{user}"), i, &mut uf);
            }
        }
    }

    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..items.len() {
        groups.entry(uf.find(i)).or_default().push(i);
    }
    let mut out: Vec<DuplicateGroup> = groups
        .into_values()
        .filter(|g| g.len() > 1)
        .map(|mut g| {
            g.sort_by(|&a, &b| {
                items[b]
                    .content
                    .updated_at
                    .cmp(&items[a].content.updated_at)
                    .then_with(|| items[a].item_id.cmp(&items[b].item_id))
            });
            let newest = &items[g[0]].content;
            let username = newest.username().unwrap_or_default().trim().to_string();
            let user_l = username.to_lowercase();
            // the site every item has (with this username), if any
            let site = newest
                .urls
                .iter()
                .map(|u| npw_match::site(&u.url))
                .find(|s| {
                    !s.is_empty()
                        && g.iter().all(|&i| {
                            let c = &items[i].content;
                            c.username().map(|u| u.trim().to_lowercase()).as_deref()
                                == Some(user_l.as_str())
                                && c.urls.iter().any(|u| &npw_match::site(&u.url) == s)
                        })
                })
                .unwrap_or_default();
            let pw = newest.password();
            DuplicateGroup {
                site,
                username,
                same_password: g.iter().all(|&i| items[i].content.password() == pw),
                identical: g.iter().all(|&i| prints[i] == prints[g[0]]),
                items: g.iter().map(|&i| items[i].view(false)).collect(),
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.identical
            .cmp(&a.identical)
            .then_with(|| {
                let la = if a.site.is_empty() {
                    &a.items[0].title
                } else {
                    &a.site
                };
                let lb = if b.site.is_empty() {
                    &b.items[0].title
                } else {
                    &b.site
                };
                la.to_lowercase().cmp(&lb.to_lowercase())
            })
            .then_with(|| a.username.cmp(&b.username))
    });
    out
}

// ------------------------------------------------------------------ merge

/// The field of `out` that `f` (from another item) corresponds to.
fn target_field(out: &ItemContent, f: &Field) -> Option<usize> {
    if let Some(i) = out
        .fields
        .iter()
        .position(|x| x.id == f.id && x.kind == f.kind)
    {
        return Some(i);
    }
    if let Some(p) = &f.purpose {
        if let Some(i) = out
            .fields
            .iter()
            .position(|x| x.purpose.as_ref() == Some(p))
        {
            return Some(i);
        }
    }
    let label = f.label.trim().to_lowercase();
    if label.is_empty() {
        return None;
    }
    out.fields
        .iter()
        .position(|x| x.kind == f.kind && x.label.trim().to_lowercase() == label)
}

/// The section of `out` to put a copied field into (copying the section from
/// `other` when `out` has none like it).
fn map_section(out: &mut ItemContent, other: &ItemContent, sid: &str) -> Option<String> {
    let s = other.sections.iter().find(|s| s.id == sid)?;
    let label = s.label.trim();
    if let Some(x) = out
        .sections
        .iter()
        .find(|x| x.id == s.id || (!label.is_empty() && x.label.trim() == label))
    {
        return Some(x.id.clone());
    }
    let mut copy = s.clone();
    copy.id = new_short_id("s");
    let id = copy.id.clone();
    out.sections.push(copy);
    Some(id)
}

/// Appends a copy of `f` to `out` (fresh ID; no autofill purpose when `out`
/// already has a field for it).
fn append_field(out: &mut ItemContent, other: &ItemContent, f: &Field) -> String {
    let mut copy = f.clone();
    if out.fields.iter().any(|x| x.id == copy.id) {
        copy.id = new_short_id("f");
    }
    if copy
        .purpose
        .as_ref()
        .is_some_and(|p| out.fields.iter().any(|x| x.purpose.as_ref() == Some(p)))
    {
        copy.purpose = None;
    }
    copy.section = match &f.section {
        Some(sid) => map_section(out, other, sid),
        None => None,
    };
    let id = copy.id.clone();
    out.fields.push(copy);
    id
}

/// Merges the contents of `others` into `keep` without losing a value: empty
/// fields are filled in, differing secrets go to the password history,
/// other differing fields are added as extra fields; URLs, tags, passkeys,
/// history and notes are combined. Attachments are not touched (they must be
/// copied with new keys, see [`Client::merge_items`]). Returns the merged
/// content and how many secrets went to the history.
pub fn merge_contents(keep: &ItemContent, others: &[ItemContent]) -> (ItemContent, usize) {
    let mut out = keep.clone();
    let mut to_history = 0;
    let now = npw_model::now_ms();
    for other in others {
        // other field ID → field ID in `out`, for the password history
        let mut ids: HashMap<String, String> = HashMap::new();
        for f in &other.fields {
            if f.is_empty() {
                continue;
            }
            if let Some(i) = target_field(&out, f) {
                ids.insert(f.id.clone(), out.fields[i].id.clone());
                let t = &out.fields[i];
                if t.is_empty() {
                    out.fields[i].value = f.value.clone();
                    continue;
                }
                if t.value == f.value {
                    continue;
                }
                if t.is_secret() || f.is_secret() {
                    let (field, label) = (t.id.clone(), t.label.clone());
                    let known = out
                        .history
                        .iter()
                        .any(|h| h.field == field && h.value == f.value);
                    if !known {
                        out.history.push(HistoryEntry {
                            id: new_short_id("h"),
                            field,
                            label,
                            value: f.value.clone(),
                            until: if other.updated_at > 0 {
                                other.updated_at
                            } else {
                                now
                            },
                            extra: Default::default(),
                        });
                        to_history += 1;
                    }
                    continue;
                }
            }
            // no counterpart, or a different non-secret value: keep it as its own field
            if let Some(x) = out
                .fields
                .iter()
                .find(|x| x.kind == f.kind && x.value == f.value)
            {
                ids.entry(f.id.clone()).or_insert_with(|| x.id.clone());
                continue;
            }
            let id = append_field(&mut out, other, f);
            ids.entry(f.id.clone()).or_insert(id);
        }

        for h in &other.history {
            let field = ids
                .get(&h.field)
                .cloned()
                .unwrap_or_else(|| h.field.clone());
            let known = out
                .history
                .iter()
                .any(|x| x.id == h.id || (x.field == field && x.value == h.value));
            if !known {
                let mut copy = h.clone();
                copy.field = field;
                out.history.push(copy);
            }
        }

        for u in &other.urls {
            let url = u.url.trim();
            if url.is_empty()
                || out
                    .urls
                    .iter()
                    .any(|x| x.url.trim().eq_ignore_ascii_case(url))
            {
                continue;
            }
            let mut copy = u.clone();
            if out.urls.iter().any(|x| x.id == copy.id) {
                copy.id = new_short_id("u");
            }
            out.urls.push(copy);
        }

        for p in &other.passkeys {
            if out
                .passkeys
                .iter()
                .any(|x| x.credential_id == p.credential_id)
            {
                continue;
            }
            let mut copy = p.clone();
            if out.passkeys.iter().any(|x| x.id == copy.id) {
                copy.id = new_short_id("pk");
            }
            out.passkeys.push(copy);
        }

        for t in &other.tags {
            if !out.tags.contains(t) {
                out.tags.push(t.clone());
            }
        }

        let notes = other.notes.trim();
        if !notes.is_empty() && !out.notes.contains(notes) {
            out.notes = if out.notes.trim().is_empty() {
                notes.to_string()
            } else {
                format!("{}\n\n{notes}", out.notes.trim_end())
            };
        }

        if out.title.trim().is_empty() {
            out.title = other.title.clone();
        }
        out.favorite |= other.favorite;
        out.reprompt |= other.reprompt;
        // archived only when every merged item was
        out.archived &= other.archived;
        if out.ssh.is_none() {
            out.ssh = other.ssh.clone();
        }
        if other.created_at > 0 && (out.created_at == 0 || other.created_at < out.created_at) {
            out.created_at = other.created_at;
        }
        for (k, v) in &other.extra {
            // the import marker stays the kept item's own: undoing another
            // item's import must not trash the merged result
            if k != IMPORT_KEY && !out.extra.contains_key(k) {
                out.extra.insert(k.clone(), v.clone());
            }
        }
    }
    (out, to_history)
}

impl Client {
    /// Applies one action to many items in one local transaction.
    pub fn bulk_update(&self, items: &[ItemRef], action: &BulkAction) -> Result<BulkReport> {
        let action = match action {
            BulkAction::AddTags { tags } => BulkAction::AddTags {
                tags: normalize_tags(tags)?,
            },
            BulkAction::RemoveTags { tags } => BulkAction::RemoveTags {
                tags: tags.iter().filter_map(|t| normalize_tag(t)).collect(),
            },
            a => a.clone(),
        };
        let mut report = BulkReport::default();
        let mut writes = vec![];
        {
            let st = self.state.lock().expect("state");
            let keys = st.keys.as_ref().ok_or(CoreError::Locked)?;
            let mut seen = HashSet::new();
            for r in items {
                if !seen.insert(r.key()) {
                    continue;
                }
                let (Some(cur), Some(vk)) = (
                    st.cache.items.get(&r.key()),
                    keys.vault_keys.get(&r.vault_id),
                ) else {
                    report.skipped.push(Skipped {
                        vault_id: r.vault_id.clone(),
                        item_id: r.item_id.clone(),
                        title: String::new(),
                        reason: "not_found".into(),
                    });
                    continue;
                };
                let mut content = cur.content.clone();
                let mut deleted = cur.deleted;
                let changed = match action {
                    BulkAction::Trash | BulkAction::Restore => {
                        deleted = action == BulkAction::Trash;
                        deleted != cur.deleted
                    }
                    _ if cur.read_only => {
                        report.skipped.push(Skipped {
                            vault_id: r.vault_id.clone(),
                            item_id: r.item_id.clone(),
                            title: cur.content.title.clone(),
                            reason: "read_only".into(),
                        });
                        continue;
                    }
                    _ => {
                        let changed = apply_action(&mut content, &action);
                        if changed {
                            content.record_changes_from(&cur.content);
                        }
                        changed
                    }
                };
                if !changed {
                    report.unchanged += 1;
                    continue;
                }
                writes.push(PendingWrite {
                    vault_id: r.vault_id.clone(),
                    item_id: r.item_id.clone(),
                    vk: vk.clone(),
                    ik: cur.ik.clone(),
                    content,
                    deleted,
                });
            }
        }
        report.changed = writes.len();
        self.write_pending_many(writes)?;
        Ok(report)
    }

    /// Every tag in use (live items), with the parents of nested tags, and
    /// how many items carry the tag or one of its sub-tags.
    pub fn tag_counts(&self) -> Result<Vec<TagCount>> {
        let st = self.state.lock().expect("state");
        if st.keys.is_none() {
            return Err(CoreError::Locked);
        }
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for c in st.cache.items.values().filter(|c| !c.deleted) {
            let mut mine: HashSet<String> = HashSet::new();
            for t in &c.content.tags {
                let mut prefix = String::new();
                for part in t.split('/') {
                    if !prefix.is_empty() {
                        prefix.push('/');
                    }
                    prefix.push_str(part);
                    mine.insert(prefix.clone());
                }
            }
            for t in mine {
                *counts.entry(t).or_default() += 1;
            }
        }
        Ok(counts
            .into_iter()
            .map(|(tag, items)| TagCount { tag, items })
            .collect())
    }

    /// Renames a tag and its sub-tags on every item, the trash included (so
    /// a restored item does not bring the old name back). Renaming to a tag
    /// that exists merges the two.
    pub fn rename_tag(&self, from: &str, to: &str) -> Result<BulkReport> {
        let from = normalize_tag(from).ok_or_else(|| CoreError::Invalid("no tag given".into()))?;
        let to = normalize_tag(to).ok_or_else(|| CoreError::Invalid("no tag given".into()))?;
        if from == to {
            return Ok(BulkReport::default());
        }
        self.edit_tags(&from, |tags| rename_in(tags, &from, &to))
    }

    /// Removes a tag and its sub-tags from every item (the items stay).
    pub fn delete_tag(&self, tag: &str) -> Result<BulkReport> {
        let tag = normalize_tag(tag).ok_or_else(|| CoreError::Invalid("no tag given".into()))?;
        self.edit_tags(&tag, |tags| {
            let before = tags.len();
            tags.retain(|t| !under(t, &tag));
            tags.len() != before
        })
    }

    fn edit_tags(&self, tag: &str, edit: impl Fn(&mut Vec<String>) -> bool) -> Result<BulkReport> {
        let mut report = BulkReport::default();
        let mut writes = vec![];
        {
            let st = self.state.lock().expect("state");
            let keys = st.keys.as_ref().ok_or(CoreError::Locked)?;
            for c in st.cache.items.values() {
                if !c.content.tags.iter().any(|t| under(t, tag)) {
                    continue;
                }
                let Some(vk) = keys.vault_keys.get(&c.vault_id) else {
                    continue;
                };
                if c.read_only {
                    report.skipped.push(Skipped {
                        vault_id: c.vault_id.clone(),
                        item_id: c.item_id.clone(),
                        title: c.content.title.clone(),
                        reason: "read_only".into(),
                    });
                    continue;
                }
                let mut content = c.content.clone();
                if !edit(&mut content.tags) {
                    report.unchanged += 1;
                    continue;
                }
                content.record_changes_from(&c.content);
                writes.push(PendingWrite {
                    vault_id: c.vault_id.clone(),
                    item_id: c.item_id.clone(),
                    vk: vk.clone(),
                    ik: c.ik.clone(),
                    content,
                    deleted: c.deleted,
                });
            }
        }
        report.changed = writes.len();
        self.write_pending_many(writes)?;
        Ok(report)
    }

    /// Groups of items that look like duplicates (not in the trash, archived
    /// included; items written by a newer version are left out).
    pub fn duplicates(&self) -> Result<Vec<DuplicateGroup>> {
        let st = self.state.lock().expect("state");
        if st.keys.is_none() {
            return Err(CoreError::Locked);
        }
        let mut items: Vec<&CachedItem> = st
            .cache
            .items
            .values()
            .filter(|c| !c.deleted && !c.read_only)
            .collect();
        items.sort_by(|a, b| (&a.vault_id, &a.item_id).cmp(&(&b.vault_id, &b.item_id)));
        Ok(find_duplicates(&items))
    }

    /// Merges `others` into `keep` ([`merge_contents`]) and moves them to the
    /// trash, in one local transaction. Attachments of the other items are
    /// copied to the kept item first (re-encrypted, which needs the server).
    pub async fn merge_items(&self, keep: &ItemRef, others: &[ItemRef]) -> Result<MergeReport> {
        let mut others_u: Vec<ItemRef> = vec![];
        for o in others {
            if o != keep && !others_u.contains(o) {
                others_u.push(o.clone());
            }
        }
        if others_u.is_empty() {
            return Err(CoreError::Invalid("nothing to merge".into()));
        }
        let ((keep_before, _), others_before) = self.merge_inputs(keep, &others_u)?;

        // copy the other items' attachments, skipping files the kept item already has
        let mut copied = vec![];
        // SHA-256 of the kept item's files (fetched when first needed) and of those copied
        let mut known: Option<Vec<String>> = None;
        for (o, (content, _)) in others_u.iter().zip(&others_before) {
            for a in &content.attachments {
                let data = self.attachment(&o.vault_id, &o.item_id, &a.id).await?;
                let sha = npw_crypto::sha256_hex(&data);
                if known.is_none() {
                    let mut k = vec![];
                    for x in &keep_before.attachments {
                        let d = self
                            .attachment(&keep.vault_id, &keep.item_id, &x.id)
                            .await?;
                        k.push(npw_crypto::sha256_hex(&d));
                    }
                    known = Some(k);
                }
                let known = known.as_mut().expect("filled above");
                if known.contains(&sha) {
                    continue;
                }
                let att = self
                    .upload_attachment(&keep.vault_id, &keep.item_id, &a.name, &a.mime, &data)
                    .await?;
                known.push(sha);
                copied.push(att);
            }
        }

        // the items may have changed (a sync) while uploading: merge what is there now
        let ((keep_now, keep_ik), others_now) = self.merge_inputs(keep, &others_u)?;
        let others_content: Vec<ItemContent> = others_now.iter().map(|(c, _)| c.clone()).collect();
        let (mut merged, to_history) = merge_contents(&keep_now, &others_content);
        merged.attachments.extend(copied.iter().cloned());
        merged.record_changes_from(&keep_now);

        let mut writes = vec![PendingWrite {
            vault_id: keep.vault_id.clone(),
            item_id: keep.item_id.clone(),
            vk: self.vault_key(&keep.vault_id)?,
            ik: keep_ik,
            content: merged,
            deleted: false,
        }];
        for (o, (content, ik)) in others_u.iter().zip(others_now) {
            writes.push(PendingWrite {
                vault_id: o.vault_id.clone(),
                item_id: o.item_id.clone(),
                vk: self.vault_key(&o.vault_id)?,
                ik,
                content,
                deleted: true,
            });
        }
        self.write_pending_many(writes)?;
        Ok(MergeReport {
            kept: Some(keep.clone()),
            trashed: others_u.len(),
            attachments_copied: copied.len(),
            secrets_to_history: to_history,
        })
    }

    /// The current contents and item keys of the items to merge, checked.
    #[allow(clippy::type_complexity)]
    fn merge_inputs(
        &self,
        keep: &ItemRef,
        others: &[ItemRef],
    ) -> Result<(
        (ItemContent, npw_crypto::Key32),
        Vec<(ItemContent, npw_crypto::Key32)>,
    )> {
        let st = self.state.lock().expect("state");
        if st.keys.is_none() {
            return Err(CoreError::Locked);
        }
        let get = |r: &ItemRef| -> Result<(ItemContent, npw_crypto::Key32)> {
            let c = st.cache.items.get(&r.key()).ok_or(CoreError::NotFound)?;
            if c.read_only {
                return Err(CoreError::ReadOnly);
            }
            if c.deleted {
                return Err(CoreError::Invalid(
                    "an item to merge is in the trash".into(),
                ));
            }
            if !c.content.conflicts.is_empty() {
                return Err(CoreError::Invalid(
                    "resolve the sync conflicts of these items first".into(),
                ));
            }
            Ok((c.content.clone(), c.ik.clone()))
        };
        let k = get(keep)?;
        let o = others.iter().map(get).collect::<Result<Vec<_>>>()?;
        Ok((k, o))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use npw_model::item::{kind, purpose};
    use npw_model::{Attachment, Passkey, Section, UrlEntry};

    fn login(title: &str, user: &str, pw: &str, url: &str) -> ItemContent {
        let mut it = npw_model::template("login").unwrap().new_item("zh-CN");
        it.title = title.into();
        it.field_mut("username").unwrap().value = user.into();
        it.field_mut("password").unwrap().value = pw.into();
        if !url.is_empty() {
            it.urls.push(UrlEntry::new(url));
        }
        it
    }

    fn cached(vault: &str, id: &str, content: ItemContent) -> CachedItem {
        CachedItem {
            vault_id: vault.into(),
            item_id: id.into(),
            index: crate::search::index(&content),
            content,
            read_only: false,
            deleted: false,
            pending: false,
            rejected: None,
            revision: 1,
            ik: npw_crypto::Key32::from_bytes([1; 32]),
        }
    }

    #[test]
    fn tags_are_normalized() {
        assert_eq!(
            normalize_tag(" 工作 / 开发/ ").as_deref(),
            Some("工作/开发")
        );
        assert_eq!(normalize_tag("a//b").as_deref(), Some("a/b"));
        assert_eq!(normalize_tag(" / "), None);
        assert!(normalize_tags(&["".into(), " ".into()]).is_err());
        assert_eq!(
            normalize_tags(&["a".into(), " a ".into(), "b".into()]).unwrap(),
            vec!["a", "b"]
        );
    }

    #[test]
    fn under_matches_whole_segments_only() {
        assert!(under("工作", "工作"));
        assert!(under("工作/开发", "工作"));
        assert!(!under("工作室", "工作"));
        assert!(!under("工", "工作"));
    }

    #[test]
    fn rename_moves_sub_tags_and_merges_with_existing() {
        let mut t = vec![
            "工作".to_string(),
            "工作/开发".into(),
            "工作室".into(),
            "公司".into(),
        ];
        assert!(rename_in(&mut t, "工作", "公司"));
        assert_eq!(t, vec!["公司", "公司/开发", "工作室"]);
        let mut t = vec!["x".to_string()];
        assert!(!rename_in(&mut t, "y", "z"));
        // into its own sub-tag
        let mut t = vec!["a".to_string(), "a/b".into()];
        assert!(rename_in(&mut t, "a", "a/old"));
        assert_eq!(t, vec!["a/old", "a/old/b"]);
    }

    #[test]
    fn bulk_actions_report_changes() {
        let mut c = login("A", "u", "p", "");
        c.tags = vec!["x".into()];
        assert!(apply_action(
            &mut c,
            &BulkAction::AddTags {
                tags: vec!["x".into(), "y".into()]
            }
        ));
        assert_eq!(c.tags, vec!["x", "y"]);
        assert!(!apply_action(
            &mut c,
            &BulkAction::AddTags {
                tags: vec!["y".into()]
            }
        ));
        assert!(apply_action(
            &mut c,
            &BulkAction::RemoveTags {
                tags: vec!["x".into()]
            }
        ));
        assert_eq!(c.tags, vec!["y"]);
        assert!(apply_action(&mut c, &BulkAction::Favorite { on: true }));
        assert!(!apply_action(&mut c, &BulkAction::Favorite { on: true }));
        assert!(apply_action(&mut c, &BulkAction::Archive { on: true }));
        assert!(c.archived && c.favorite);
    }

    #[test]
    fn bulk_action_json_shape() {
        let a: BulkAction = serde_json::from_str(r#"{"kind":"add_tags","tags":["a"]}"#).unwrap();
        assert_eq!(
            a,
            BulkAction::AddTags {
                tags: vec!["a".into()]
            }
        );
        let a: BulkAction = serde_json::from_str(r#"{"kind":"archive","on":true}"#).unwrap();
        assert_eq!(a, BulkAction::Archive { on: true });
        let a: BulkAction = serde_json::from_str(r#"{"kind":"trash"}"#).unwrap();
        assert_eq!(a, BulkAction::Trash);
    }

    #[test]
    fn duplicates_by_site_and_username() {
        let mut a = login("GitHub", "Me@Example.com", "p1", "https://github.com/login");
        a.updated_at = 10;
        let mut b = login(
            "github.com",
            "me@example.com ",
            "p2",
            "https://www.github.com/",
        );
        b.updated_at = 20;
        let c = login("GitHub", "other", "p1", "https://github.com/");
        let d = login("Gitee", "me@example.com", "p1", "https://gitee.com/");
        let items = [
            cached("v", "a", a),
            cached("v", "b", b),
            cached("v", "c", c),
            cached("v", "d", d),
        ];
        let refs: Vec<&CachedItem> = items.iter().collect();
        let g = find_duplicates(&refs);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].site, "github.com");
        assert_eq!(g[0].username, "me@example.com");
        assert_eq!(
            g[0].items
                .iter()
                .map(|v| v.item_id.as_str())
                .collect::<Vec<_>>(),
            vec!["b", "a"]
        );
        assert!(!g[0].same_password);
        assert!(!g[0].identical);
    }

    #[test]
    fn duplicates_without_urls_and_identical_notes() {
        let a = login("Router", "admin", "x", "");
        let b = login(" router ", "ADMIN", "x", "");
        let mut n1 = npw_model::template("secure_note")
            .unwrap()
            .new_item("zh-CN");
        n1.title = "Recovery codes".into();
        n1.notes = "1111 2222".into();
        let mut n2 = n1.clone();
        n2.tags = vec!["imported".into()];
        n2.favorite = true;
        let mut n3 = n1.clone();
        n3.notes = "3333".into();
        let items = [
            cached("v", "a", a),
            cached("v", "b", b),
            cached("v", "n1", n1),
            cached("v", "n2", n2),
            cached("w", "n3", n3),
        ];
        let refs: Vec<&CachedItem> = items.iter().collect();
        let g = find_duplicates(&refs);
        assert_eq!(g.len(), 2);
        // identical groups first
        assert!(g[0].identical && g[0].same_password);
        assert_eq!(g[0].site, "");
        let mut ids: Vec<&str> = g[0].items.iter().map(|v| v.item_id.as_str()).collect();
        ids.sort();
        assert_eq!(ids, vec!["n1", "n2"]);
        // same title and username (case and spaces aside), no URL: grouped, but not identical
        assert!(!g[1].identical && g[1].same_password);
        assert_eq!(g[1].items.len(), 2);
    }

    #[test]
    fn different_sites_stay_apart() {
        let a = login("A", "me", "p", "https://a.example.com");
        let b = login("B", "me", "p", "https://b.example.org");
        let items = [cached("v", "a", a), cached("v", "b", b)];
        let refs: Vec<&CachedItem> = items.iter().collect();
        assert!(find_duplicates(&refs).is_empty());
    }

    #[test]
    fn merge_keeps_every_value() {
        let mut keep = login("GitHub", "me", "new-pw", "https://github.com/login");
        keep.tags = vec!["dev".into()];
        keep.notes = "main account".into();
        keep.updated_at = 200;
        keep.created_at = 150;
        keep.history.push(HistoryEntry {
            id: "h_1".into(),
            field: "password".into(),
            label: "密码".into(),
            value: "older-pw".into(),
            until: 100,
            extra: Default::default(),
        });

        let mut other = login("github", "me", "old-pw", "https://github.com/");
        other.updated_at = 120;
        other.created_at = 50;
        other.tags = vec!["imported".into(), "dev".into()];
        other.favorite = true;
        other.notes = "recovery: 1234".into();
        other.field_mut("otp").unwrap().value = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".into();
        other.sections.push(Section {
            id: "s_a".into(),
            label: "Extra".into(),
            extra: Default::default(),
        });
        let mut f = Field::new("f_email", "Email", kind::EMAIL).with_value("me@example.com");
        f.section = Some("s_a".into());
        other.fields.push(f);
        other.urls.push(UrlEntry::new("https://gist.github.com"));
        other.history.push(HistoryEntry {
            id: "h_2".into(),
            field: "password".into(),
            label: "Password".into(),
            value: "ancient-pw".into(),
            until: 10,
            extra: Default::default(),
        });
        other.passkeys.push(Passkey {
            id: "pk_1".into(),
            rp_id: "github.com".into(),
            credential_id: "cred".into(),
            user_handle: "h".into(),
            user_name: "me".into(),
            user_display_name: String::new(),
            rp_name: String::new(),
            alg: -7,
            private_key: "k".into(),
            counter: 0,
            discoverable: true,
            created_at: 0,
            extra: Default::default(),
        });
        other
            .extra
            .insert(IMPORT_KEY.into(), serde_json::json!({"batch": "b1"}));
        other.extra.insert("x_future".into(), serde_json::json!(1));

        let (m, n) = merge_contents(&keep, &[other.clone()]);
        assert_eq!(n, 1);
        assert_eq!(m.title, "GitHub");
        assert_eq!(m.field("password").unwrap().value, "new-pw");
        let old: Vec<&serde_json::Value> = m
            .history
            .iter()
            .filter(|h| h.field == "password")
            .map(|h| &h.value)
            .collect();
        assert_eq!(old, vec!["older-pw", "old-pw", "ancient-pw"]);
        let added = m.history.iter().find(|h| h.value == "old-pw").unwrap();
        assert_eq!(added.until, 120);
        // empty field filled in
        assert!(m.field("otp").unwrap().text().starts_with("otpauth://"));
        // extra field with its section
        let email = m
            .fields
            .iter()
            .find(|f| f.text() == "me@example.com")
            .unwrap();
        let sec = m
            .sections
            .iter()
            .find(|s| Some(&s.id) == email.section.as_ref())
            .unwrap();
        assert_eq!(sec.label, "Extra");
        assert_eq!(m.urls.len(), 3, "github.com/login, github.com/, gist");
        assert_eq!(m.tags, vec!["dev", "imported"]);
        assert!(m.favorite);
        assert_eq!(m.notes, "main account\n\nrecovery: 1234");
        assert_eq!(m.passkeys.len(), 1);
        assert_eq!(m.created_at, 50);
        assert!(!m.extra.contains_key(IMPORT_KEY));
        assert_eq!(m.extra["x_future"], 1);

        // merging the same again adds nothing new
        let (m2, n2) = merge_contents(&m, &[other]);
        assert_eq!(n2, 0);
        assert_eq!(m2.history.len(), m.history.len());
        assert_eq!(m2.fields.len(), m.fields.len());
        assert_eq!(m2.urls.len(), m.urls.len());
        assert_eq!(m2.notes, m.notes);
    }

    #[test]
    fn merge_keeps_differing_plain_fields_as_extra_fields() {
        let mut keep = login("Bank", "me", "p", "https://bank.example.com");
        keep.fields
            .push(Field::new("f_phone", "电话", kind::PHONE).with_value("111"));
        let mut other = login("Bank", "me", "p", "https://bank.example.com");
        other
            .fields
            .push(Field::new("f_x", "电话", kind::PHONE).with_value("222"));
        other.fields.push(
            Field::new("f_u2", "Login name", kind::TEXT)
                .with_purpose(purpose::USERNAME)
                .with_value("me-too"),
        );
        let (m, n) = merge_contents(&keep, &[other]);
        assert_eq!(n, 0);
        let phones: Vec<String> = m
            .fields
            .iter()
            .filter(|f| f.kind == kind::PHONE)
            .map(Field::text)
            .collect();
        assert_eq!(phones, vec!["111", "222"]);
        // a second username keeps its value but not the autofill purpose
        let u2 = m.fields.iter().find(|f| f.text() == "me-too").unwrap();
        assert_eq!(u2.purpose, None);
        assert_eq!(m.username().as_deref(), Some("me"));
        // field IDs stay unique
        let mut ids: Vec<&str> = m.fields.iter().map(|f| f.id.as_str()).collect();
        let n = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), n);
    }

    #[test]
    fn merge_flags() {
        let mut keep = login("A", "u", "p", "");
        keep.archived = true;
        let mut other = keep.clone();
        other.archived = false;
        other.reprompt = true;
        let (m, _) = merge_contents(&keep, &[other]);
        assert!(!m.archived, "an active item keeps the result active");
        assert!(m.reprompt, "the stricter setting wins");
        let mut keep = login("", "u", "p", "");
        keep.archived = true;
        let mut other = login("Named", "u", "p", "");
        other.archived = true;
        let (m, _) = merge_contents(&keep, &[other.clone(), other]);
        assert!(m.archived, "archived when every item was");
        assert_eq!(m.title, "Named");
    }

    #[test]
    fn merge_does_not_touch_attachments() {
        let keep = login("A", "u", "p", "");
        let mut other = keep.clone();
        other.attachments.push(Attachment {
            id: "att".into(),
            name: "f.txt".into(),
            size: 1,
            mime: String::new(),
            key: "k".into(),
            blob_sha256: String::new(),
            created_at: 0,
            extra: Default::default(),
        });
        let (m, _) = merge_contents(&keep, &[other]);
        assert!(m.attachments.is_empty());
    }
}
