//! KDBX 4 export, opens in KeePassXC / KeePass / KeePassDX / Strongbox.
//!
//! Mapping:
//!
//! - one group per vault under the root group `NyaPassword`; deleted items go to
//!   the recycle bin group `回收站` (marked as the database's recycle bin), in a
//!   sub-group per vault;
//! - `Title` ← title; `UserName` ← first field with purpose `username`;
//!   `Password` ← first field with purpose `password`; `URL` ← first URL, further
//!   URLs as `KP2A_URL_1`, `KP2A_URL_2`, … (read by KeePassXC and KeePass2Android);
//!   `Notes` ← notes;
//! - first TOTP field → `otp` as an `otpauth://` URI (bare base32 secrets are
//!   converted), which is where KeePassXC looks for it;
//! - passkeys → KeePassXC's `KPEX_PASSKEY_USERNAME`, `KPEX_PASSKEY_CREDENTIAL_ID`,
//!   `KPEX_PASSKEY_PRIVATE_KEY_PEM` (PKCS#8 PEM), `KPEX_PASSKEY_RELYING_PARTY`,
//!   `KPEX_PASSKEY_USER_HANDLE`. KeePassXC supports one passkey per entry, so
//!   every further passkey gets a copy of the entry titled `Title (passkey N)`
//!   (fields and URLs copied; attachments and history only on the original);
//! - every other field → a custom string field named by its label (`Section:
//!   Label` inside a section, ` (2)`, ` (3)` … appended when a name repeats),
//!   protected when the field is secret (`concealed`, `pin`, `totp`). Empty
//!   fields are skipped. This covers every template (cards, identities, SSH keys…);
//! - attachments → entry attachments (binaries), duplicate names made unique;
//! - history (previous values of secret fields) → KeePass entry history: one
//!   snapshot per previous value, oldest first, dated when the value stopped
//!   being current;
//! - tags → KeePass tags (`;` `,` and tabs in a tag become spaces); `favorite` and
//!   `archived` are added as tags;
//! - `created_at` / `updated_at` → creation / modification times (whole seconds);
//! - the template ID is kept in the entry custom data `NyaPassword/template`.
//!
//! Not representable in KDBX (use the native export to keep them): URL match
//! modes and Android certificate pins, field kinds and generator recipes, section
//! structure, autofill / SSH agent settings, unresolved sync conflicts, passkey
//! counters and display names, unknown keys from newer clients.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use keepass::config::{DatabaseConfig, KdfConfig};
use keepass::db::{
    fields, CustomDataItem, CustomDataValue, Entry, EntryMut, GroupId, Times, Value,
};
use keepass::{Database, DatabaseKey};
use npw_model::{ItemContent, Passkey};

use crate::mapping::{display_label, field_text, split, totp_uri};
use crate::{ExportError, ExportItem, ExportVault};

/// Name of the recycle bin group holding deleted items.
pub const RECYCLE_BIN: &str = "回收站";
/// Root group and database name.
pub const ROOT_NAME: &str = "NyaPassword";
/// Entry custom data key holding the NyaPassword template ID.
pub const TEMPLATE_KEY: &str = "NyaPassword/template";

pub const PASSKEY_USERNAME: &str = "KPEX_PASSKEY_USERNAME";
pub const PASSKEY_CREDENTIAL_ID: &str = "KPEX_PASSKEY_CREDENTIAL_ID";
pub const PASSKEY_PRIVATE_KEY_PEM: &str = "KPEX_PASSKEY_PRIVATE_KEY_PEM";
pub const PASSKEY_RELYING_PARTY: &str = "KPEX_PASSKEY_RELYING_PARTY";
pub const PASSKEY_USER_HANDLE: &str = "KPEX_PASSKEY_USER_HANDLE";

/// KDF settings of the written database (Argon2id).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdbxOptions {
    /// Memory in KiB.
    pub memory_kib: u64,
    pub iterations: u64,
    pub parallelism: u32,
}

impl Default for KdbxOptions {
    /// Argon2id, 64 MiB, 10 passes, 2 lanes: about a second on a desktop, and the
    /// same memory as KeePassXC's default.
    fn default() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 10,
            parallelism: 2,
        }
    }
}

impl KdbxOptions {
    /// Tiny parameters for tests only.
    pub fn insecure_for_tests() -> Self {
        Self {
            memory_kib: 64,
            iterations: 1,
            parallelism: 1,
        }
    }
}

/// Writes all vaults as one KDBX 4 database protected by `password`, with
/// [`KdbxOptions::default`].
pub fn export_kdbx(vaults: &[ExportVault], password: &str) -> Result<Vec<u8>, ExportError> {
    export_kdbx_with(vaults, password, &KdbxOptions::default())
}

/// [`export_kdbx`] with explicit KDF settings.
pub fn export_kdbx_with(
    vaults: &[ExportVault],
    password: &str,
    options: &KdbxOptions,
) -> Result<Vec<u8>, ExportError> {
    let mut db = Database::new();
    db.config = config(options);
    db.meta.generator = Some(ROOT_NAME.to_string());
    db.meta.database_name = Some(ROOT_NAME.to_string());
    db.root_mut().name = ROOT_NAME.to_string();

    let mut vault_groups: Vec<GroupId> = Vec::with_capacity(vaults.len());
    for v in vaults {
        let mut root = db.root_mut();
        let mut g = root.add_group();
        g.name = v.name.clone();
        vault_groups.push(g.id());
    }

    let mut recycle: Option<(GroupId, HashMap<usize, GroupId>)> = None;
    for (vi, v) in vaults.iter().enumerate() {
        for item in &v.items {
            let group = if item.deleted {
                let (bin, subgroups) = recycle.get_or_insert_with(|| {
                    let mut root = db.root_mut();
                    let mut g = root.add_group();
                    g.name = RECYCLE_BIN.to_string();
                    g.enable_searching = Some(false);
                    (g.id(), HashMap::new())
                });
                let bin = *bin;
                *subgroups.entry(vi).or_insert_with(|| {
                    let mut binm = db.group_mut(bin).expect("recycle bin exists");
                    let mut g = binm.add_group();
                    g.name = v.name.clone();
                    g.id()
                })
            } else {
                vault_groups[vi]
            };
            add_item(&mut db, group, item);
        }
    }
    if let Some((bin, _)) = recycle {
        db.meta.recyclebin_enabled = Some(true);
        db.meta.recyclebin_uuid = Some(bin.uuid());
        db.meta.recyclebin_changed = Some(Times::now());
    }

    let mut out = Vec::new();
    db.save(&mut out, DatabaseKey::new().with_password(password))
        .map_err(|e| ExportError::Kdbx(e.to_string()))?;
    Ok(out)
}

fn config(options: &KdbxOptions) -> DatabaseConfig {
    let mut config = DatabaseConfig::default();
    // The Argon2 version type lives in a crate we do not depend on: take it from the default.
    if let KdfConfig::Argon2 { version, .. } = config.kdf_config.clone() {
        config.kdf_config = KdfConfig::Argon2id {
            iterations: options.iterations.max(1),
            memory: options.memory_kib.max(8) * 1024,
            parallelism: options.parallelism.max(1),
            version,
        };
    }
    config
}

/// Unique attribute names within one entry.
#[derive(Default)]
struct Names(HashSet<String>);

impl Names {
    fn claim(&mut self, base: &str) -> String {
        let base = if base.trim().is_empty() {
            "Field"
        } else {
            base
        };
        if self.0.insert(base.to_string()) {
            return base.to_string();
        }
        let mut n = 2;
        loop {
            let candidate = format!("{base} ({n})");
            if self.0.insert(candidate.clone()) {
                return candidate;
            }
            n += 1;
        }
    }
}

/// Time since the Unix epoch for a KeePass timestamp (whole seconds; years 1970 ..= 9999).
fn since_epoch(ms: i64) -> Option<Duration> {
    if ms <= 0 || ms > 253_402_300_799_000 {
        return None;
    }
    Some(Duration::from_secs((ms / 1000) as u64))
}

fn clean_tag(t: &str) -> String {
    t.chars()
        .map(|c| {
            if matches!(c, ';' | ',' | '\t') {
                ' '
            } else {
                c
            }
        })
        .collect::<String>()
        .trim()
        .to_string()
}

fn pem(private_key_b64url: &str) -> String {
    use base64::Engine;
    let Some(der) = npw_crypto::unb64(private_key_b64url) else {
        return private_key_b64url.to_string();
    };
    let b = base64::engine::general_purpose::STANDARD.encode(der);
    let mut s = String::from("-----BEGIN PRIVATE KEY-----\n");
    for line in b.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        s.push('\n');
    }
    s.push_str("-----END PRIVATE KEY-----");
    s
}

fn passkey_fields(pk: &Passkey) -> Vec<(&'static str, Value<String>)> {
    vec![
        (PASSKEY_USERNAME, Value::unprotected(pk.user_name.clone())),
        (
            PASSKEY_CREDENTIAL_ID,
            Value::protected(pk.credential_id.clone()),
        ),
        (
            PASSKEY_PRIVATE_KEY_PEM,
            Value::protected(pem(&pk.private_key)),
        ),
        (PASSKEY_RELYING_PARTY, Value::unprotected(pk.rp_id.clone())),
        (
            PASSKEY_USER_HANDLE,
            Value::protected(pk.user_handle.clone()),
        ),
    ]
}

fn add_item(db: &mut Database, group: GroupId, item: &ExportItem) {
    let c: &ItemContent = &item.content;
    let s = split(c);
    let mut names = Names::default();
    for n in [
        fields::TITLE,
        fields::USERNAME,
        fields::PASSWORD,
        fields::URL,
        fields::NOTES,
        fields::OTP,
    ] {
        names.claim(n);
    }

    // Field ID → attribute name, for history snapshots.
    let mut by_id: HashMap<&str, String> = HashMap::new();
    let mut base: Vec<(String, Value<String>)> = Vec::new();

    let username = s.username.map(|f| field_text(c, f)).unwrap_or_default();
    base.push((fields::TITLE.into(), Value::unprotected(c.title.clone())));
    base.push((
        fields::USERNAME.into(),
        Value::unprotected(username.clone()),
    ));
    base.push((
        fields::PASSWORD.into(),
        Value::protected(s.password.map(|f| field_text(c, f)).unwrap_or_default()),
    ));
    base.push((fields::NOTES.into(), Value::unprotected(c.notes.clone())));
    if let Some(f) = s.username {
        by_id.insert(&f.id, fields::USERNAME.into());
    }
    if let Some(f) = s.password {
        by_id.insert(&f.id, fields::PASSWORD.into());
    }
    if let Some(f) = s.totp {
        by_id.insert(&f.id, fields::OTP.into());
        let uri = totp_uri(&f.text(), &c.title, &username);
        if !uri.is_empty() {
            base.push((fields::OTP.into(), Value::protected(uri)));
        }
    }

    let mut urls = c.urls.iter();
    base.push((
        fields::URL.into(),
        Value::unprotected(urls.next().map(|u| u.url.clone()).unwrap_or_default()),
    ));
    for (i, u) in urls.enumerate() {
        let name = names.claim(&format!("KP2A_URL_{}", i + 1));
        base.push((name, Value::unprotected(u.url.clone())));
    }
    if !c.passkeys.is_empty() {
        for n in [
            PASSKEY_USERNAME,
            PASSKEY_CREDENTIAL_ID,
            PASSKEY_PRIVATE_KEY_PEM,
            PASSKEY_RELYING_PARTY,
            PASSKEY_USER_HANDLE,
        ] {
            names.claim(n);
        }
    }

    for f in &s.others {
        let name = names.claim(&display_label(c, f));
        by_id.insert(&f.id, name.clone());
        if f.is_empty() {
            continue;
        }
        let text = field_text(c, f);
        let v = if f.is_secret() {
            Value::protected(text)
        } else {
            Value::unprotected(text)
        };
        base.push((name, v));
    }

    let mut tags: Vec<String> = c
        .tags
        .iter()
        .map(|t| clean_tag(t))
        .filter(|t| !t.is_empty())
        .collect();
    if c.favorite {
        tags.push("favorite".into());
    }
    if c.archived {
        tags.push("archived".into());
    }

    let fill = |e: &mut EntryMut<'_>,
                extra: &[(&'static str, Value<String>)],
                title_suffix: Option<String>| {
        for (k, v) in &base {
            e.set(k.clone(), v.clone());
        }
        for (k, v) in extra {
            e.set(*k, v.clone());
        }
        if let Some(suffix) = title_suffix {
            e.set_unprotected(fields::TITLE, format!("{}{suffix}", c.title));
        }
        // An entry with a passkey but no URL: point it at the relying party.
        if let Some((_, rp)) = extra.iter().find(|(k, _)| *k == PASSKEY_RELYING_PARTY) {
            if c.urls.is_empty() && !rp.is_empty() {
                e.set_unprotected(fields::URL, format!("https://{}", rp.get()));
            }
        }
        e.tags = tags.clone();
        if let Some(d) = since_epoch(c.created_at) {
            e.times.creation = Some(Times::epoch() + d);
        }
        if let Some(d) = since_epoch(c.updated_at) {
            e.times.last_modification = Some(Times::epoch() + d);
            e.times.last_access = Some(Times::epoch() + d);
        }
        e.custom_data.insert(
            TEMPLATE_KEY.to_string(),
            CustomDataItem {
                value: Some(CustomDataValue::String(c.template.clone())),
                last_modification_time: None,
            },
        );
    };

    // The item itself (with the first passkey, attachments and history).
    let first_pk = c.passkeys.first().map(passkey_fields).unwrap_or_default();
    let mut grp = db.group_mut(group).expect("group exists");
    let mut e = grp.add_entry();
    fill(&mut e, &first_pk, None);

    let mut att_names = HashSet::new();
    for (meta, data) in &item.attachments {
        let name = attachment_name(&mut att_names, &meta.name, &meta.id);
        e.add_attachment(name, Value::protected(data.clone()));
    }

    if !c.history.is_empty() {
        let snapshot: Entry = (*e).clone();
        let mut hist: Vec<_> = c.history.iter().collect();
        // History::add_entry prepends: add newest first so the file lists oldest first.
        hist.sort_by_key(|h| std::cmp::Reverse(h.until));
        for h in hist {
            let mut snap = snapshot.clone();
            snap.history = None;
            let key = by_id.get(h.field.as_str()).cloned().unwrap_or_else(|| {
                let label = if h.label.is_empty() {
                    h.field.as_str()
                } else {
                    h.label.as_str()
                };
                label.to_string()
            });
            let text = match &h.value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null => String::new(),
                other => other.to_string(),
            };
            let text = if key == fields::OTP {
                totp_uri(&text, &c.title, &username)
            } else {
                text
            };
            snap.fields.insert(key, Value::protected(text));
            if let Some(d) = since_epoch(h.until) {
                snap.times.last_modification = Some(Times::epoch() + d);
            }
            e.history
                .get_or_insert_with(Default::default)
                .add_entry(snap);
        }
    }

    for (i, pk) in c.passkeys.iter().enumerate().skip(1) {
        let mut grp = db.group_mut(group).expect("group exists");
        let mut e = grp.add_entry();
        fill(
            &mut e,
            &passkey_fields(pk),
            Some(format!(" (passkey {})", i + 1)),
        );
    }
}

/// A unique attachment name: `name.ext`, then `name (2).ext`, … (the ID if unnamed).
fn attachment_name(taken: &mut HashSet<String>, name: &str, id: &str) -> String {
    let name = if name.trim().is_empty() { id } else { name };
    if taken.insert(name.to_string()) {
        return name.to_string();
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    let mut n = 2;
    loop {
        let candidate = format!("{stem} ({n}){ext}");
        if taken.insert(candidate.clone()) {
            return candidate;
        }
        n += 1;
    }
}
