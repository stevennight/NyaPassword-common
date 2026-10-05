//! Bitwarden / Vaultwarden exports: JSON, password-protected JSON, ".zip (with
//! attachments)" and CSV. Mapping rules follow the `bw2op` migration tool.
//!
//! Mapping decisions:
//! - folders (nested `a/b` names) become tags; collections become `集合/<name>`
//!   (`Collections/<name>`) tags; an organization item without a known collection
//!   gets `组织/<organizationId>` (`Organization/<id>`);
//! - identity SSN / passport / driver's licence numbers are split into separate
//!   `document` items (the identity keeps name, contacts and address);
//! - custom fields go into the "Other fields" section; linked fields become text
//!   describing the link (with a warning);
//! - items in the trash are skipped (listed in the report); unknown item types are
//!   imported as secure notes holding every value (`Mapping::Fallback`).

use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};

use base64::alphabet;
use base64::engine::{general_purpose::GeneralPurpose, DecodePaddingMode, GeneralPurposeConfig};
use base64::Engine;
use npw_model::{kind, match_mode, HistoryEntry, Passkey, UrlEntry};
use serde_json::{Map, Value};

use crate::{
    mime_for, parse_rfc3339_ms, strip_bom, tr, Draft, ImportError, ImportResult,
    ImportedAttachment, ImportedItem, Mapping, Skipped,
};

const LOGIN: i64 = 1;
const NOTE: i64 = 2;
const CARD: i64 = 3;
const IDENTITY: i64 = 4;
const SSH_KEY: i64 = 5;

/// Largest attachment read from a zip export (guards against zip bombs).
const MAX_ENTRY_BYTES: u64 = 2 << 30;

/// Whether a zip entry name is the export's JSON (not an attachment).
pub fn is_data_json(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with(".json") && !n.starts_with("attachments/") && !n.contains("/attachments/")
}

/// Imports a JSON export; password-protected exports need `password`.
pub fn import_json(
    bytes: &[u8],
    password: Option<&str>,
    locale: &str,
) -> Result<ImportResult, ImportError> {
    let doc = parse_doc(bytes, password)?;
    Ok(convert(&doc, Vec::new(), Vec::new(), locale))
}

/// Imports a ".zip (with attachments)" export: `data.json` plus `attachments/<itemId>/<file>`.
pub fn import_zip(
    bytes: &[u8],
    password: Option<&str>,
    locale: &str,
) -> Result<ImportResult, ImportError> {
    let fmt = |e: zip::result::ZipError| ImportError::Format(format!("zip: {e}"));
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).map_err(fmt)?;
    let names: Vec<String> = zip.file_names().map(str::to_string).collect();
    let json_name = names
        .iter()
        .filter(|n| is_data_json(n))
        .min_by_key(|n| n.len())
        .cloned()
        .ok_or_else(|| ImportError::Format("no data.json in the zip".into()))?;
    let mut files = Vec::new();
    let mut skipped = Vec::new();
    let mut json = None;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(fmt)?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_string();
        if entry.size() > MAX_ENTRY_BYTES {
            skipped.push(Skipped::new(name, "file too large"));
            continue;
        }
        let mut data = Vec::new();
        (&mut entry)
            .take(MAX_ENTRY_BYTES)
            .read_to_end(&mut data)
            .map_err(|e| ImportError::Format(format!("zip entry {name}: {e}")))?;
        if name == json_name {
            json = Some(data);
        } else {
            files.push((name, data));
        }
    }
    let json = json.ok_or_else(|| ImportError::Format("no data.json in the zip".into()))?;
    let doc = parse_doc(&json, password)?;
    Ok(convert(&doc, files, skipped, locale))
}

fn parse_doc(bytes: &[u8], password: Option<&str>) -> Result<Value, ImportError> {
    let text = std::str::from_utf8(strip_bom(bytes))
        .map_err(|_| ImportError::Format("not UTF-8 text".into()))?;
    let doc: Value =
        serde_json::from_str(text).map_err(|e| ImportError::Format(format!("JSON: {e}")))?;
    let doc = if doc.get("encrypted").and_then(Value::as_bool) == Some(true) {
        decrypt_export(&doc, password)?
    } else {
        doc
    };
    let ok = doc.get("items").is_some_and(Value::is_array)
        || doc.get("folders").is_some_and(Value::is_array);
    if !ok {
        return Err(ImportError::Format(
            "not a Bitwarden export (no items)".into(),
        ));
    }
    Ok(doc)
}

// ───────────────────────── password-protected exports ─────────────────────────

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// Key derivation settings of a password-protected export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    Pbkdf2 {
        iterations: u32,
    },
    /// `memory` in MiB.
    Argon2id {
        iterations: u32,
        memory: u32,
        parallelism: u32,
    },
}

impl Kdf {
    fn from_doc(doc: &Value) -> Result<Self, ImportError> {
        let num = |k: &str| {
            doc.get(k)
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok())
        };
        let bad = |what: &str| ImportError::Format(format!("invalid KDF setting: {what}"));
        let iterations = num("kdfIterations")
            .filter(|&n| n >= 1)
            .ok_or_else(|| bad("kdfIterations"))?;
        match doc.get("kdfType").and_then(Value::as_u64) {
            Some(0) if iterations <= 10_000_000 => Ok(Kdf::Pbkdf2 { iterations }),
            Some(1) if iterations <= 100 => Ok(Kdf::Argon2id {
                iterations,
                memory: num("kdfMemory")
                    .filter(|m| (1..=4096).contains(m))
                    .ok_or_else(|| bad("kdfMemory"))?,
                parallelism: num("kdfParallelism")
                    .filter(|p| (1..=64).contains(p))
                    .ok_or_else(|| bad("kdfParallelism"))?,
            }),
            Some(0 | 1) => Err(bad("kdfIterations")),
            other => Err(ImportError::Unsupported(format!("KDF type {other:?}"))),
        }
    }
}

/// The export's AES-256 and HMAC-SHA256 keys.
pub struct ExportKeys {
    pub enc: [u8; 32],
    pub mac: [u8; 32],
}

/// Derives the export keys like Bitwarden's `makePinKey`: PBKDF2-SHA256(password,
/// salt) or Argon2id(password, SHA-256(salt)) gives a 32-byte key, which HKDF-expand
/// stretches into `enc` and `mac` keys. The salt is the base64 *text* from the file.
pub fn derive_keys(password: &str, salt: &str, kdf: Kdf) -> Result<ExportKeys, ImportError> {
    use sha2::Digest;
    let mut master = [0u8; 32];
    match kdf {
        Kdf::Pbkdf2 { iterations } => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
                password.as_bytes(),
                salt.as_bytes(),
                iterations,
                &mut master,
            );
        }
        Kdf::Argon2id {
            iterations,
            memory,
            parallelism,
        } => {
            let params = argon2::Params::new(memory * 1024, iterations, parallelism, Some(32))
                .map_err(|e| ImportError::Format(format!("Argon2 parameters: {e}")))?;
            let salt_hash = sha2::Sha256::digest(salt.as_bytes());
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                .hash_password_into(password.as_bytes(), &salt_hash, &mut master)
                .map_err(|e| ImportError::Format(format!("Argon2: {e}")))?;
        }
    }
    let hk = hkdf::Hkdf::<sha2::Sha256>::from_prk(&master)
        .map_err(|_| ImportError::Format("HKDF".into()))?;
    let mut keys = ExportKeys {
        enc: [0; 32],
        mac: [0; 32],
    };
    hk.expand(b"enc", &mut keys.enc)
        .map_err(|_| ImportError::Format("HKDF".into()))?;
    hk.expand(b"mac", &mut keys.mac)
        .map_err(|_| ImportError::Format("HKDF".into()))?;
    Ok(keys)
}

/// Decrypts a Bitwarden `EncString` of type 2 (`2.iv|ct|mac`: AES-256-CBC with
/// PKCS#7, HMAC-SHA256 over iv‖ct). A bad MAC means the key is wrong.
pub fn decrypt_enc_string(s: &str, keys: &ExportKeys) -> Result<Vec<u8>, ImportError> {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    use hmac::Mac;
    let body = s.trim().strip_prefix("2.").ok_or_else(|| {
        ImportError::Unsupported("encryption type other than AES-CBC-256 + HMAC-SHA256".into())
    })?;
    let parts: Vec<&str> = body.split('|').collect();
    let [iv, ct, mac] = parts[..] else {
        return Err(ImportError::Format("malformed encrypted string".into()));
    };
    let b64 = |p: &str| {
        b64_decode(p).ok_or_else(|| ImportError::Format("malformed encrypted string".into()))
    };
    let (iv, ct, mac) = (b64(iv)?, b64(ct)?, b64(mac)?);
    let iv: [u8; 16] = iv
        .try_into()
        .map_err(|_| ImportError::Format("bad IV length".into()))?;
    let mut h = <HmacSha256 as Mac>::new_from_slice(&keys.mac)
        .map_err(|_| ImportError::Format("HMAC".into()))?;
    h.update(&iv);
    h.update(&ct);
    h.verify_slice(&mac)
        .map_err(|_| ImportError::WrongPassword)?;
    cbc::Decryptor::<aes::Aes256>::new(&keys.enc.into(), &iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(&ct)
        .map_err(|_| ImportError::Format("bad padding".into()))
}

/// Decrypts a password-protected export into the plain export JSON.
pub fn decrypt_export(doc: &Value, password: Option<&str>) -> Result<Value, ImportError> {
    if doc.get("passwordProtected").and_then(Value::as_bool) != Some(true) {
        return Err(ImportError::Unsupported(
            "this export is encrypted with the account key; export again as \"password protected\" or unencrypted".into(),
        ));
    }
    let field = |k: &str| {
        doc.get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| ImportError::Format(format!("missing {k}")))
    };
    let salt = field("salt")?;
    let validation = field("encKeyValidation_DO_NOT_EDIT")?;
    let data = field("data")?;
    let kdf = Kdf::from_doc(doc)?;
    let password = password.ok_or(ImportError::NeedPassword)?;
    let keys = derive_keys(password, salt, kdf)?;
    decrypt_enc_string(validation, &keys)?;
    let plain = decrypt_enc_string(data, &keys).map_err(|e| match e {
        // The key checked out against the validation string, so the data itself is damaged.
        ImportError::WrongPassword => {
            ImportError::Format("encrypted data is damaged (MAC mismatch)".into())
        }
        e => e,
    })?;
    let text = String::from_utf8(plain)
        .map_err(|_| ImportError::Format("decrypted data is not UTF-8".into()))?;
    serde_json::from_str(strip_bom_str(&text))
        .map_err(|e| ImportError::Format(format!("decrypted JSON: {e}")))
}

fn strip_bom_str(s: &str) -> &str {
    s.strip_prefix('\u{feff}').unwrap_or(s)
}

const LENIENT: GeneralPurposeConfig =
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);
const B64_STD: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, LENIENT);
const B64_URL: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, LENIENT);

/// Decodes standard or URL-safe base64, padded or not.
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    B64_STD.decode(s).or_else(|_| B64_URL.decode(s)).ok()
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

// ───────────────────────── JSON → items ─────────────────────────

/// A JSON value as text: strings as is, numbers and booleans printed, null empty.
fn text(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

fn get(v: &Value, k: &str) -> String {
    text(v.get(k))
}

fn is_blank(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.values().all(is_blank),
        _ => false,
    }
}

fn as_int(v: Option<&Value>) -> Option<i64> {
    match v? {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn as_bool(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => {
            matches!(s.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes")
        }
        Some(Value::Number(n)) => n.as_i64() == Some(1),
        _ => false,
    }
}

/// Top-level item keys handled for every type (or deliberately ignored).
const COMMON_KEYS: &[&str] = &[
    "id",
    "organizationId",
    "folderId",
    "type",
    "reprompt",
    "name",
    "notes",
    "favorite",
    "fields",
    "collectionIds",
    "passwordHistory",
    "revisionDate",
    "creationDate",
    "deletedDate",
    "archivedDate",
    "key",
    "attachments",
    "object",
    "edit",
    "viewPassword",
    "permissions",
    "organizationUseTotp",
    "localData",
    "secureNote",
];
const TYPED_KEYS: &[&str] = &["login", "card", "identity", "sshKey"];

struct Ctx<'a> {
    locale: &'a str,
    folders: HashMap<String, String>,
    collections: HashMap<String, String>,
}

fn id_name_map(doc: &Value, key: &str) -> HashMap<String, String> {
    doc.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|f| (get(f, "id"), get(f, "name")))
                .filter(|(id, _)| !id.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Converts a decrypted export plus zip files (`(path, bytes)`) into items.
fn convert(
    doc: &Value,
    files: Vec<(String, Vec<u8>)>,
    mut skipped: Vec<Skipped>,
    locale: &str,
) -> ImportResult {
    let ctx = Ctx {
        locale,
        folders: id_name_map(doc, "folders"),
        collections: id_name_map(doc, "collections"),
    };
    let mut items: Vec<ImportedItem> = Vec::new();
    let raw_items = doc
        .get("items")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for (i, raw) in raw_items.iter().enumerate() {
        if !raw.is_object() {
            skipped.push(Skipped::new(
                format!("#{}", i + 1),
                tr(locale, "无法识别的条目", "unrecognised entry"),
            ));
            continue;
        }
        let title = item_title(raw, locale);
        if !is_blank(raw.get("deletedDate").unwrap_or(&Value::Null)) {
            skipped.push(Skipped::new(
                title,
                tr(locale, "在回收站中", "in the trash"),
            ));
            continue;
        }
        items.extend(convert_item(raw, &title, &ctx));
    }
    attach_files(&mut items, files, raw_items, locale);
    ImportResult::new(items, skipped)
}

fn item_title(raw: &Value, locale: &str) -> String {
    let t = get(raw, "name").trim().to_string();
    if t.is_empty() {
        tr(locale, "（无标题）", "(untitled)").to_string()
    } else {
        t
    }
}

fn convert_item(raw: &Value, title: &str, ctx: &Ctx) -> Vec<ImportedItem> {
    let locale = ctx.locale;
    let id = get(raw, "id");
    let ty = as_int(raw.get("type"));
    let template = match ty {
        Some(LOGIN) => "login",
        Some(NOTE) => "secure_note",
        Some(CARD) => "credit_card",
        Some(IDENTITY) => "identity",
        Some(SSH_KEY) => "ssh_key",
        _ => "secure_note",
    };
    let mut d = Draft::new(template, title, &id, locale);
    let mut extra_items = Vec::new();
    let own_key = match ty {
        Some(LOGIN) => login(&mut d, raw),
        Some(NOTE) => None,
        Some(CARD) => card(&mut d, raw),
        Some(IDENTITY) => {
            extra_items = identity(&mut d, raw);
            Some("identity")
        }
        Some(SSH_KEY) => ssh_key(&mut d, raw),
        _ => {
            d.item.mapping = Mapping::Fallback;
            d.warn(match ty {
                Some(t) => format!(
                    "{} {t}",
                    tr(
                        locale,
                        "未知的 Bitwarden 条目类型",
                        "unknown Bitwarden item type"
                    )
                ),
                None => tr(locale, "缺少条目类型", "missing item type").to_string(),
            });
            for (k, v) in raw.as_object().into_iter().flatten() {
                if !COMMON_KEYS.contains(&k.as_str()) {
                    flatten(&mut d, k, v);
                }
            }
            None
        }
    };
    if ty.is_some_and(|t| (LOGIN..=SSH_KEY).contains(&t)) {
        // Data in keys this type does not use (e.g. a `card` object on a login).
        for (k, v) in raw.as_object().into_iter().flatten() {
            let typed_elsewhere = TYPED_KEYS.contains(&k.as_str()) && Some(k.as_str()) != own_key;
            let unknown = !COMMON_KEYS.contains(&k.as_str()) && !TYPED_KEYS.contains(&k.as_str());
            if (typed_elsewhere || unknown) && !is_blank(v) {
                flatten(&mut d, k, v);
                d.warn(format!(
                    "{k}: {}",
                    tr(
                        locale,
                        "无法对应的数据，已放入其他字段",
                        "unmapped data, kept in Other fields"
                    )
                ));
                d.partial();
            }
        }
    }
    common(&mut d, raw, ctx);
    for doc_item in &mut extra_items {
        doc_item.content.tags = d.item.content.tags.clone();
        doc_item.content.created_at = d.item.content.created_at;
        doc_item.content.updated_at = d.item.content.updated_at;
        doc_item.content.archived = d.item.content.archived;
    }
    let mut out = vec![d.finish()];
    out.extend(extra_items);
    out
}

/// Stores every scalar under `v` as "Other fields" entries labelled with its path.
fn flatten(d: &mut Draft, path: &str, v: &Value) {
    match v {
        Value::Null => {}
        Value::Object(o) => o
            .iter()
            .for_each(|(k, v)| flatten(d, &format!("{path}.{k}"), v)),
        Value::Array(a) => a
            .iter()
            .enumerate()
            .for_each(|(i, v)| flatten(d, &format!("{path}[{i}]"), v)),
        other => {
            let value = text(Some(other));
            if value.is_empty() {
                return;
            }
            let last = path
                .rsplit(['.', '['])
                .next()
                .unwrap_or(path)
                .to_ascii_lowercase();
            let secret = [
                "password",
                "totp",
                "number",
                "code",
                "ssn",
                "privatekey",
                "keyvalue",
                "secret",
            ]
            .iter()
            .any(|s| last.contains(s));
            d.other(
                path,
                if secret { kind::CONCEALED } else { kind::TEXT },
                &value,
            );
        }
    }
}

/// Reports keys of a typed object (`login`, `card`…) that the mapping did not use.
fn leftovers(d: &mut Draft, group: &str, obj: &Value, known: &[&str]) {
    for (k, v) in obj.as_object().into_iter().flatten() {
        if !known.contains(&k.as_str()) && !is_blank(v) {
            flatten(d, &format!("{group}.{k}"), v);
            let w = format!(
                "{group}.{k}: {}",
                tr(
                    d.locale(),
                    "无法对应的数据，已放入其他字段",
                    "unmapped data, kept in Other fields"
                )
            );
            d.warn(w);
            d.partial();
        }
    }
}

/// Notes, favorite, tags, timestamps, custom fields and password history.
fn common(d: &mut Draft, raw: &Value, ctx: &Ctx) {
    let locale = ctx.locale;
    let c = d.content();
    c.notes = get(raw, "notes");
    c.favorite = as_bool(raw.get("favorite"));
    if let Some(folder) = ctx.folders.get(&get(raw, "folderId")) {
        c.tags.push(folder.trim_matches('/').to_string());
    }
    let mut has_collection = false;
    for cid in raw
        .get("collectionIds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let cid = text(Some(cid));
        let name = ctx.collections.get(&cid).cloned().unwrap_or(cid);
        c.tags
            .push(format!("{}/{name}", tr(locale, "集合", "Collections")));
        has_collection = true;
    }
    let org = get(raw, "organizationId");
    if !org.is_empty() && !has_collection {
        c.tags
            .push(format!("{}/{org}", tr(locale, "组织", "Organization")));
    }
    if let Some(t) = parse_rfc3339_ms(&get(raw, "creationDate")) {
        c.created_at = t;
    }
    if let Some(t) = parse_rfc3339_ms(&get(raw, "revisionDate")) {
        c.updated_at = t;
    }
    if !get(raw, "creationDate").is_empty() && get(raw, "revisionDate").is_empty() {
        c.updated_at = c.created_at;
    }
    c.archived = !is_blank(raw.get("archivedDate").unwrap_or(&Value::Null));
    // Bitwarden's "master password re-prompt" (1 = password); any non-zero value asks.
    c.reprompt = match as_int(raw.get("reprompt")) {
        Some(n) => n != 0,
        None => as_bool(raw.get("reprompt")),
    };
    custom_fields(d, raw);
    for h in raw
        .get("passwordHistory")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let value = get(h, "password");
        if value.is_empty() {
            continue;
        }
        let until = parse_rfc3339_ms(&get(h, "lastUsedDate")).unwrap_or(0);
        d.content().history.push(HistoryEntry {
            id: npw_model::new_short_id("h"),
            field: "password".into(),
            label: tr(locale, "密码", "Password").into(),
            value: Value::String(value),
            until,
            extra: Map::new(),
        });
    }
}

fn custom_fields(d: &mut Draft, raw: &Value) {
    let locale = d.locale().to_string();
    for cf in raw
        .get("fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let mut label = get(cf, "name");
        if label.is_empty() {
            label = tr(&locale, "（未命名字段）", "(unnamed field)").into();
        }
        let value = get(cf, "value");
        match as_int(cf.get("type")) {
            None | Some(0) => {
                d.other(&label, kind::TEXT, &value);
            }
            Some(1) => {
                d.other(&label, kind::CONCEALED, &value);
            }
            Some(2) => match value.trim().to_ascii_lowercase().as_str() {
                b @ ("true" | "false") => {
                    d.other(&label, kind::BOOLEAN, b);
                }
                "" => {
                    d.other(&label, kind::BOOLEAN, "false");
                }
                _ => d.unmapped(
                    &label,
                    kind::TEXT,
                    &value,
                    tr(
                        &locale,
                        "布尔字段的值不是 true/false",
                        "boolean field value is not true/false",
                    ),
                ),
            },
            Some(3) => {
                let linked = as_int(cf.get("linkedId"));
                let target = linked
                    .and_then(|n| linked_name(n, &locale))
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("#{}", linked.unwrap_or(0)));
                let why = tr(
                    &locale,
                    "Bitwarden 链接字段，已存为说明文字",
                    "Bitwarden linked field, stored as text",
                );
                d.unmapped(&label, kind::TEXT, &format!("→ {target}"), why);
            }
            Some(n) => d.unmapped(
                &label,
                kind::TEXT,
                &value,
                &format!(
                    "{} {n}",
                    tr(&locale, "未知的自定义字段类型", "unknown custom field type")
                ),
            ),
        }
    }
}

/// What a linked custom field (`linkedId`) points at (Bitwarden `LinkedIdType`;
/// note `bw2op`'s identity table is shifted by one from 401 on).
fn linked_name(id: i64, locale: &str) -> Option<&'static str> {
    let (zh, en) = match id {
        100 => ("用户名", "Username"),
        101 => ("密码", "Password"),
        300 => ("持卡人", "Cardholder name"),
        301 => ("有效期月", "Expiration month"),
        302 => ("有效期年", "Expiration year"),
        303 => ("安全码", "Security code"),
        304 => ("卡组织", "Brand"),
        305 => ("卡号", "Number"),
        400 => ("称谓", "Title"),
        401 => ("中间名", "Middle name"),
        402 => ("地址1", "Address 1"),
        403 => ("地址2", "Address 2"),
        404 => ("地址3", "Address 3"),
        405 => ("城市", "City"),
        406 => ("州/省", "State / province"),
        407 => ("邮编", "Postal code"),
        408 => ("国家", "Country"),
        409 => ("公司", "Company"),
        410 => ("邮箱", "Email"),
        411 => ("电话", "Phone"),
        412 => ("SSN", "SSN"),
        413 => ("用户名", "Username"),
        414 => ("护照号", "Passport number"),
        415 => ("驾照号", "License number"),
        416 => ("名", "First name"),
        417 => ("姓", "Last name"),
        418 => ("全名", "Full name"),
        _ => return None,
    };
    Some(if crate::is_zh(locale) { zh } else { en })
}

/// Returns the typed key it consumed.
fn login(d: &mut Draft, raw: &Value) -> Option<&'static str> {
    let l = raw.get("login").cloned().unwrap_or(Value::Null);
    d.set("username", &get(&l, "username"));
    d.set("password", &get(&l, "password"));
    d.set("otp", &get(&l, "totp"));
    for u in l
        .get("uris")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let url = get(u, "uri");
        if url.trim().is_empty() {
            continue;
        }
        let m = match u.get("match") {
            None | Some(Value::Null) => Some(match_mode::DOMAIN),
            v => match as_int(v) {
                Some(0) => Some(match_mode::DOMAIN),
                Some(1) => Some(match_mode::HOST),
                Some(2) => Some(match_mode::STARTS_WITH),
                Some(3) => Some(match_mode::EXACT),
                Some(4) => Some(match_mode::REGEX),
                Some(5) => Some(match_mode::NEVER),
                _ => None,
            },
        };
        let mut entry = UrlEntry::new(url.clone());
        match m {
            Some(m) => entry.match_mode = m.into(),
            None => {
                let w = format!(
                    "{url}: {} {}",
                    tr(d.locale(), "未知的网址匹配方式", "unknown URL match type"),
                    text(u.get("match"))
                );
                d.warn(w);
                d.partial();
            }
        }
        d.content().urls.push(entry);
    }
    let fallback_created = parse_rfc3339_ms(&get(raw, "creationDate")).unwrap_or(0);
    for p in l
        .get("fido2Credentials")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(pk) = passkey(d, p, fallback_created) {
            d.content().passkeys.push(pk);
        }
    }
    if as_bool(l.get("autofillOnPageLoad")) {
        let w = tr(
            d.locale(),
            "“页面加载时自动填充”设置未导入",
            "\"autofill on page load\" setting was not imported",
        );
        d.warn(w);
    }
    let known = [
        "uris",
        "username",
        "password",
        "totp",
        "passwordRevisionDate",
        "fido2Credentials",
        "autofillOnPageLoad",
    ];
    leftovers(d, "login", &l, &known);
    Some("login")
}

/// Converts a `fido2Credentials` entry. Bitwarden stores the credential ID as a
/// GUID string (the raw ID is its 16 bytes) or `b64.<base64url>`, and the private
/// key as base64url PKCS#8.
fn passkey(d: &mut Draft, p: &Value, fallback_created: i64) -> Option<Passkey> {
    let locale = d.locale().to_string();
    let rp_id = get(p, "rpId");
    let cred = get(p, "credentialId");
    let raw_id = if let Some(rest) = cred.strip_prefix("b64.") {
        b64_decode(rest)
    } else if let Ok(u) = uuid::Uuid::parse_str(&cred) {
        Some(u.as_bytes().to_vec())
    } else {
        b64_decode(&cred)
    };
    let credential_id = match raw_id {
        Some(b) if !b.is_empty() => b64url(&b),
        _ => {
            if cred.is_empty() && get(p, "keyValue").is_empty() {
                return None;
            }
            d.warn(format!(
                "{rp_id}: {}",
                tr(
                    &locale,
                    "passkey 的凭据 ID 格式无法识别，已原样保存",
                    "passkey credential ID not recognised, kept as is"
                )
            ));
            d.partial();
            cred.clone()
        }
    };
    let key = get(p, "keyValue");
    let private_key = match b64_decode(&key) {
        Some(b) if !b.is_empty() => b64url(&b),
        _ => {
            d.warn(format!(
                "{rp_id}: {}",
                tr(
                    &locale,
                    "passkey 私钥无法识别，已原样保存",
                    "passkey private key not recognised, kept as is"
                )
            ));
            d.partial();
            key.clone()
        }
    };
    let user_handle = get(p, "userHandle");
    let user_handle = b64_decode(&user_handle)
        .map(|b| b64url(&b))
        .unwrap_or(user_handle);
    let mut extra = Map::new();
    let (algo, curve) = (get(p, "keyAlgorithm"), get(p, "keyCurve"));
    let alg = match (
        algo.to_ascii_uppercase().as_str(),
        curve.to_ascii_uppercase().as_str(),
    ) {
        ("ECDSA" | "", "P-256" | "") => -7,
        ("EDDSA", _) => -8,
        _ => {
            d.warn(format!(
                "{rp_id}: {} {algo} {curve}",
                tr(&locale, "未知的 passkey 算法", "unknown passkey algorithm")
            ));
            d.partial();
            -7
        }
    };
    for k in ["keyType", "keyAlgorithm", "keyCurve"] {
        let v = get(p, k);
        let default = matches!(
            (k, v.as_str()),
            ("keyType", "public-key") | ("keyAlgorithm", "ECDSA") | ("keyCurve", "P-256") | (_, "")
        );
        if !default {
            extra.insert(k.to_string(), Value::String(v));
        }
    }
    let counter = match as_int(p.get("counter")) {
        Some(n) => u32::try_from(n).unwrap_or(0),
        None => {
            if !get(p, "counter").is_empty() {
                d.warn(format!(
                    "{rp_id}: {}",
                    tr(
                        &locale,
                        "passkey 计数器无法识别，已设为 0",
                        "passkey counter not recognised, set to 0"
                    )
                ));
            }
            0
        }
    };
    let discoverable = match p.get("discoverable") {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) if s.is_empty() => true,
        v => as_bool(v),
    };
    Some(Passkey {
        id: npw_model::new_short_id("pk"),
        rp_id,
        credential_id,
        user_handle,
        user_name: get(p, "userName"),
        user_display_name: get(p, "userDisplayName"),
        rp_name: get(p, "rpName"),
        alg,
        private_key,
        counter,
        discoverable,
        created_at: parse_rfc3339_ms(&get(p, "creationDate")).unwrap_or(fallback_created),
        extra,
    })
}

/// `YYYY-MM` from a month (`1`–`12`, `01`) and a 2- or 4-digit year.
fn expiry(month: &str, year: &str) -> Option<String> {
    let m: u32 = month.trim().parse().ok()?;
    let mut y: u32 = year.trim().parse().ok()?;
    if y < 100 {
        y += 2000;
    }
    ((1..=12).contains(&m) && (1000..=9999).contains(&y)).then(|| format!("{y:04}-{m:02}"))
}

fn card(d: &mut Draft, raw: &Value) -> Option<&'static str> {
    let c = raw.get("card").cloned().unwrap_or(Value::Null);
    d.set("cardholder", &get(&c, "cardholderName"));
    d.set("number", &get(&c, "number"));
    d.set("cvv", &get(&c, "code"));
    d.set("card_type", &get(&c, "brand"));
    let (m, y) = (get(&c, "expMonth"), get(&c, "expYear"));
    if !m.is_empty() || !y.is_empty() {
        match expiry(&m, &y) {
            Some(e) => d.set("expiry", &e),
            None => {
                let label = tr(d.locale(), "有效期（原始）", "Expiry (original)").to_string();
                let why =
                    tr(d.locale(), "有效期无法识别", "expiry date not recognised").to_string();
                d.unmapped(&label, kind::TEXT, &format!("{m}/{y}"), &why);
            }
        }
    }
    leftovers(
        d,
        "card",
        &c,
        &[
            "cardholderName",
            "brand",
            "number",
            "expMonth",
            "expYear",
            "code",
        ],
    );
    Some("card")
}

/// Fills the identity and returns the split-off document items.
fn identity(d: &mut Draft, raw: &Value) -> Vec<ImportedItem> {
    let locale = d.locale().to_string();
    let idn = raw.get("identity").cloned().unwrap_or(Value::Null);
    let g = |k: &str| get(&idn, k).trim().to_string();
    let full_name = ["title", "firstName", "middleName", "lastName"]
        .map(g)
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    d.set("full_name", &full_name);
    d.set("phone", &get(&idn, "phone"));
    d.set("email", &get(&idn, "email"));
    d.set("company", &get(&idn, "company"));
    let street = ["address1", "address2", "address3"]
        .map(|k| get(&idn, k))
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    let addr = serde_json::json!({
        "country": get(&idn, "country"),
        "province": get(&idn, "state"),
        "city": get(&idn, "city"),
        "district": "",
        "street": street,
        "postal_code": get(&idn, "postalCode"),
    });
    if !is_blank(&addr) {
        d.set_value("address", addr);
    }
    let username = get(&idn, "username");
    if !username.is_empty() {
        d.other(tr(&locale, "用户名", "Username"), kind::TEXT, &username);
    }
    let mut docs = Vec::new();
    let title = d.item.content.title.clone();
    for (key, zh, en) in [
        ("ssn", "社会保障号", "SSN"),
        ("passportNumber", "护照", "Passport"),
        ("licenseNumber", "驾照", "Driver's license"),
    ] {
        let number = get(&idn, key);
        if number.is_empty() {
            continue;
        }
        let label = tr(&locale, zh, en);
        let mut doc = Draft::new(
            "document",
            &format!("{title} - {label}"),
            &format!("{}#{key}", d.item.source_id),
            &locale,
        );
        doc.set("doc_type", label);
        doc.set("number", &number);
        doc.set("full_name", &full_name);
        doc.content().favorite = as_bool(raw.get("favorite"));
        doc.warn(format!(
            "{}: {title}",
            tr(&locale, "从身份条目拆分出的证件", "split from identity")
        ));
        docs.push(doc.finish());
    }
    let known = [
        "title",
        "firstName",
        "middleName",
        "lastName",
        "address1",
        "address2",
        "address3",
        "city",
        "state",
        "postalCode",
        "country",
        "company",
        "email",
        "phone",
        "ssn",
        "username",
        "passportNumber",
        "licenseNumber",
    ];
    leftovers(d, "identity", &idn, &known);
    docs
}

/// A readable key type from an OpenSSH public key line.
fn ssh_key_type(public_key: &str) -> String {
    let algo = public_key.split_whitespace().next().unwrap_or("");
    match algo {
        "ssh-ed25519" => "Ed25519",
        "ssh-rsa" => "RSA",
        "ecdsa-sha2-nistp256" => "ECDSA P-256",
        "ecdsa-sha2-nistp384" => "ECDSA P-384",
        "ecdsa-sha2-nistp521" => "ECDSA P-521",
        "sk-ssh-ed25519@openssh.com" => "Ed25519-SK",
        "sk-ecdsa-sha2-nistp256@openssh.com" => "ECDSA-SK",
        "ssh-dss" => "DSA",
        other => other,
    }
    .to_string()
}

fn ssh_key(d: &mut Draft, raw: &Value) -> Option<&'static str> {
    let s = raw.get("sshKey").cloned().unwrap_or(Value::Null);
    let public_key = get(&s, "publicKey");
    d.set("private_key", &get(&s, "privateKey"));
    d.set("public_key", &public_key);
    d.set("fingerprint", &get(&s, "keyFingerprint"));
    d.set("key_type", &ssh_key_type(&public_key));
    leftovers(
        d,
        "sshKey",
        &s,
        &["privateKey", "publicKey", "keyFingerprint"],
    );
    Some("sshKey")
}

/// Assigns `attachments/<itemId or item name>/<file>` to items; files without an
/// owner are collected in one secure note so nothing is lost.
fn attach_files(
    items: &mut Vec<ImportedItem>,
    files: Vec<(String, Vec<u8>)>,
    raw_items: &[Value],
    locale: &str,
) {
    if files.is_empty() {
        return;
    }
    let by_id: HashMap<String, usize> = items
        .iter()
        .enumerate()
        .rev()
        .map(|(i, it)| (it.source_id.clone(), i))
        .collect();
    // Item names that are unique among the exported items (Bitwarden may use names as folder names).
    let mut name_count: HashMap<String, usize> = HashMap::new();
    for r in raw_items {
        *name_count.entry(get(r, "name")).or_default() += 1;
    }
    let by_name: HashMap<String, usize> = items
        .iter()
        .enumerate()
        .filter(|(_, it)| !it.source_id.contains('#'))
        .filter_map(|(i, it)| {
            let name = raw_items
                .iter()
                .find(|r| get(r, "id") == it.source_id)
                .map(|r| get(r, "name"))?;
            (name_count.get(&name) == Some(&1)).then_some((name, i))
        })
        .collect();
    let mut orphans = Vec::new();
    let mut seen = HashSet::new();
    for (path, data) in files {
        let parts: Vec<&str> = path.split(['/', '\\']).filter(|p| !p.is_empty()).collect();
        let Some((file_name, dirs)) = parts.split_last() else {
            continue;
        };
        let owner = dirs
            .iter()
            .find_map(|p| by_id.get(*p))
            .or_else(|| dirs.iter().find_map(|p| by_name.get(*p)))
            .copied();
        let att = ImportedAttachment {
            name: file_name.to_string(),
            mime: mime_for(file_name),
            data,
        };
        match owner {
            Some(i) if seen.insert((i, att.name.clone())) => items[i].attachments.push(att),
            _ => orphans.push((path, att)),
        }
    }
    if orphans.is_empty() {
        return;
    }
    let title = tr(
        locale,
        "Bitwarden 未归属的附件",
        "Bitwarden unassigned attachments",
    );
    let mut d = Draft::new("secure_note", title, "attachments", locale);
    for (path, att) in orphans {
        d.other(tr(locale, "原路径", "Original path"), kind::TEXT, &path);
        d.item.attachments.push(att);
    }
    d.warn(tr(
        locale,
        "这些附件找不到所属条目，已放在这条笔记里",
        "these attachments had no matching item; kept in this note",
    ));
    d.partial();
    items.push(d.finish());
}

// ───────────────────────── CSV ─────────────────────────

/// Imports Bitwarden's CSV export (personal or organization).
pub fn import_csv(bytes: &[u8], locale: &str) -> Result<ImportResult, ImportError> {
    let text = std::str::from_utf8(strip_bom(bytes))
        .map_err(|_| ImportError::Format("not UTF-8 text".into()))?;
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());
    let headers: Vec<String> = rdr
        .headers()
        .map_err(|e| ImportError::Format(format!("CSV: {e}")))?
        .iter()
        .map(|h| h.trim().to_string())
        .collect();
    let col = |name: &str| headers.iter().position(|h| h.eq_ignore_ascii_case(name));
    if col("login_uri").is_none()
        && col("login_username").is_none()
        && col("login_password").is_none()
    {
        return Err(ImportError::Format("not a Bitwarden CSV export".into()));
    }
    const KNOWN: &[&str] = &[
        "folder",
        "favorite",
        "type",
        "name",
        "notes",
        "fields",
        "reprompt",
        "login_uri",
        "login_username",
        "login_password",
        "login_totp",
        "collections",
    ];
    let mut items = Vec::new();
    let mut skipped = Vec::new();
    for (row, rec) in rdr.records().enumerate() {
        let rec = rec.map_err(|e| ImportError::Format(format!("CSV row {}: {e}", row + 2)))?;
        if rec.iter().all(|f| f.trim().is_empty()) {
            continue;
        }
        let get = |name: &str| col(name).and_then(|i| rec.get(i)).unwrap_or("").to_string();
        let mut title = get("name").trim().to_string();
        if title.is_empty() {
            title = tr(locale, "（无标题）", "(untitled)").into();
        }
        let ty = get("type").trim().to_ascii_lowercase();
        let template = match ty.as_str() {
            "login" | "" => "login",
            "note" | "securenote" => "secure_note",
            other => {
                skipped.push(Skipped::new(
                    title,
                    format!(
                        "{} {other}",
                        tr(
                            locale,
                            "CSV 中不支持的条目类型",
                            "unsupported item type in CSV"
                        )
                    ),
                ));
                continue;
            }
        };
        let mut d = Draft::new(template, &title, &format!("row{}", row + 2), locale);
        if template == "login" {
            d.set("username", &get("login_username"));
            d.set("password", &get("login_password"));
            d.set("otp", &get("login_totp"));
            for u in get("login_uri")
                .split(',')
                .map(str::trim)
                .filter(|u| !u.is_empty())
            {
                d.content().urls.push(UrlEntry::new(u));
            }
        } else {
            for k in [
                "login_username",
                "login_password",
                "login_totp",
                "login_uri",
            ] {
                let v = get(k);
                if !v.is_empty() {
                    let why =
                        tr(locale, "笔记条目中的登录数据", "login data on a note").to_string();
                    d.unmapped(
                        k,
                        if k == "login_password" || k == "login_totp" {
                            kind::CONCEALED
                        } else {
                            kind::TEXT
                        },
                        &v,
                        &why,
                    );
                }
            }
        }
        d.content().notes = get("notes");
        d.content().favorite = matches!(get("favorite").trim(), "1" | "true" | "TRUE" | "True");
        let folder = get("folder");
        if !folder.trim().is_empty() {
            d.content()
                .tags
                .push(folder.trim().trim_matches('/').to_string());
        }
        for c in get("collections")
            .split(',')
            .map(str::trim)
            .filter(|c| !c.is_empty())
        {
            let tag = format!("{}/{c}", tr(locale, "集合", "Collections"));
            d.content().tags.push(tag);
        }
        d.content().reprompt = !matches!(get("reprompt").trim(), "" | "0");
        csv_fields(&mut d, &get("fields"));
        for (i, h) in headers.iter().enumerate() {
            let v = rec.get(i).unwrap_or("");
            if !KNOWN.iter().any(|k| h.eq_ignore_ascii_case(k)) && !v.is_empty() {
                let why = tr(
                    locale,
                    "无法对应的列，已放入其他字段",
                    "unmapped column, kept in Other fields",
                )
                .to_string();
                d.unmapped(h, kind::TEXT, v, &why);
            }
        }
        for (i, v) in rec.iter().enumerate().skip(headers.len()) {
            if !v.is_empty() {
                let why = tr(
                    locale,
                    "多出的列，已放入其他字段",
                    "extra column, kept in Other fields",
                )
                .to_string();
                d.unmapped(&format!("#{}", i + 1), kind::TEXT, v, &why);
            }
        }
        items.push(d.finish());
    }
    Ok(ImportResult::new(items, skipped))
}

/// Bitwarden CSV custom fields: one `name: value` per line. A line without
/// `": "` continues the previous value (keeps multi-line values).
fn csv_fields(d: &mut Draft, fields: &str) {
    let mut parsed: Vec<(String, String)> = Vec::new();
    for line in fields.lines() {
        match line.split_once(": ") {
            Some((name, value)) => parsed.push((name.to_string(), value.to_string())),
            None => match parsed.last_mut() {
                Some((_, v)) => {
                    v.push('\n');
                    v.push_str(line);
                }
                None if !line.trim().is_empty() => {
                    parsed.push((line.trim_end_matches(':').to_string(), String::new()))
                }
                None => {}
            },
        }
    }
    for (name, value) in parsed {
        d.other(&name, kind::TEXT, &value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_formats() {
        assert_eq!(expiry("3", "2027").as_deref(), Some("2027-03"));
        assert_eq!(expiry("12", "29").as_deref(), Some("2029-12"));
        assert_eq!(expiry("13", "2027"), None);
        assert_eq!(expiry("", "2027"), None);
    }

    #[test]
    fn credential_id_guid_to_base64url() {
        let mut d = Draft::new("login", "t", "1", "en");
        let p = serde_json::json!({"credentialId": "00112233-4455-6677-8899-aabbccddeeff", "keyValue": "AAEC", "rpId": "example.com"});
        let pk = passkey(&mut d, &p, 0).unwrap();
        assert_eq!(pk.credential_id, "ABEiM0RVZneImaq7zN3u_w");
        assert_eq!(pk.private_key, "AAEC");
        assert!(d.item.warnings.is_empty());
    }
}
