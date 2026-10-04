//! KeePass / KeePassXC importers: KDBX (3.1 and 4, also KeePass 1 `.kdb`) via the
//! `keepass` crate, and the KeePassXC (or KeePass 2) CSV export.
//!
//! - groups become nested tags (`Parent/Child`; the root group's name is skipped),
//!   the recycle bin is not imported (listed as skipped);
//! - Title / UserName / Password / URL / Notes fill the login template; entries
//!   with none of username, password, URL, OTP or passkey become secure notes;
//! - OTP: the `otp` attribute (otpauth URI or KeeOtp `key=…&step=…`), the older
//!   `TOTP Seed` / `TOTP Settings` pair and KeePass 2.47+ `TimeOtp-*` attributes;
//! - KeePassXC passkeys (`KPEX_PASSKEY_*`) become passkeys (PEM PKCS#8 → base64url DER);
//! - `KP2A_URL*` attributes become extra URLs, all other attributes go to
//!   "Other fields" (protected → concealed);
//! - binaries become attachments, earlier passwords from the entry history become
//!   password history, the expiry date becomes an "Expires" field.
//!
//! Only password-protected databases are supported (no key files / challenge-response).

use std::collections::HashSet;

use base64::Engine;
use keepass::db::{fields, Entry, EntryRef, GroupRef};
use keepass::error::{DatabaseKeyError, DatabaseOpenError};
use keepass::{Database, DatabaseKey};
use npw_model::{kind, HistoryEntry, Passkey, UrlEntry};
use serde_json::{Map, Value};

use crate::{
    mime_for, parse_rfc3339_ms, strip_bom, tr, Draft, ImportError, ImportResult,
    ImportedAttachment, ImportedItem, Skipped,
};

const KDBX_SIG1: [u8; 4] = [0x03, 0xD9, 0xA2, 0x9A];

// ───────────────────────────────────────── KDBX ─────────────────────────────────────────

/// Imports a KeePass database (KDBX 3.1 / 4, or KeePass 1.x KDB) protected by `password`.
pub fn import_kdbx(
    bytes: &[u8],
    password: Option<&str>,
    locale: &str,
) -> Result<ImportResult, ImportError> {
    if bytes.len() < 12 || bytes[..4] != KDBX_SIG1 {
        return Err(ImportError::Format("not a KeePass database".into()));
    }
    let Some(password) = password else {
        return Err(ImportError::NeedPassword);
    };
    let db =
        Database::parse(bytes, DatabaseKey::new().with_password(password)).map_err(open_error)?;

    let recycle_bin = db.recycle_bin().map(|g| g.id());
    let mut out = Out {
        items: Vec::new(),
        skipped: Vec::new(),
        locale: locale.to_string(),
    };
    let root = db.root();
    walk(&root, &[], recycle_bin, &mut out);
    Ok(ImportResult::new(out.items, out.skipped))
}

fn open_error(e: DatabaseOpenError) -> ImportError {
    match e {
        DatabaseOpenError::Key(DatabaseKeyError::IncorrectKey) => ImportError::WrongPassword,
        DatabaseOpenError::Key(DatabaseKeyError::EmptyKey) => ImportError::NeedPassword,
        DatabaseOpenError::UnsupportedVersion => {
            ImportError::Unsupported("this KeePass database version".into())
        }
        other => ImportError::Format(format!("cannot open the KeePass database: {other}")),
    }
}

struct Out {
    items: Vec<ImportedItem>,
    skipped: Vec<Skipped>,
    locale: String,
}

fn walk(
    group: &GroupRef<'_>,
    path: &[String],
    recycle_bin: Option<keepass::db::GroupId>,
    out: &mut Out,
) {
    if Some(group.id()) == recycle_bin {
        skip_all(group, out);
        return;
    }
    let tag = path.join("/");
    for entry in group.entries() {
        if is_kdb_meta_stream(&entry) {
            continue;
        }
        out.items.push(convert_entry(&entry, &tag, &out.locale));
    }
    for child in group.groups() {
        let mut p = path.to_vec();
        p.push(child.name.clone());
        walk(&child, &p, recycle_bin, out);
    }
}

fn skip_all(group: &GroupRef<'_>, out: &mut Out) {
    for entry in group.entries() {
        out.skipped.push(Skipped::new(
            entry.get_title().unwrap_or_default(),
            "in the KeePass recycle bin",
        ));
    }
    for child in group.groups() {
        skip_all(&child, out);
    }
}

/// KeePass 1.x stores metadata as fake entries.
fn is_kdb_meta_stream(e: &Entry) -> bool {
    e.get_title() == Some("Meta-Info")
        && e.get_username() == Some("SYSTEM")
        && e.get_url() == Some("$")
}

const STANDARD: [&str; 5] = [
    fields::TITLE,
    fields::USERNAME,
    fields::PASSWORD,
    fields::URL,
    fields::NOTES,
];
const PK_USERNAME: &str = "KPEX_PASSKEY_USERNAME";
const PK_CREDENTIAL_ID: &str = "KPEX_PASSKEY_CREDENTIAL_ID";
const PK_GENERATED_USER_ID: &str = "KPEX_PASSKEY_GENERATED_USER_ID";
const PK_PRIVATE_KEY: &str = "KPEX_PASSKEY_PRIVATE_KEY_PEM";
const PK_RP: &str = "KPEX_PASSKEY_RELYING_PARTY";
const PK_USER_HANDLE: &str = "KPEX_PASSKEY_USER_HANDLE";
const PK_FLAG_BE: &str = "KPEX_PASSKEY_FLAG_BE";
const PK_FLAG_BS: &str = "KPEX_PASSKEY_FLAG_BS";

/// UTC milliseconds of an optional `NaiveDateTime` (the `keepass` crate's chrono type).
macro_rules! ms {
    ($t:expr) => {
        $t.map(|t| t.and_utc().timestamp_millis())
    };
}

fn convert_entry(entry: &EntryRef<'_>, group_tag: &str, locale: &str) -> ImportedItem {
    let get = |k: &str| entry.get(k).unwrap_or_default();
    let title = get(fields::TITLE);
    let (user, pass, url) = (
        get(fields::USERNAME),
        get(fields::PASSWORD),
        get(fields::URL).trim(),
    );
    let mut consumed: HashSet<&str> = STANDARD.into_iter().collect();

    let (otp, otp_keys) = entry_otp(entry, title);
    consumed.extend(otp_keys);
    let has_passkey = entry.fields.contains_key(PK_PRIVATE_KEY);

    let is_login =
        !(user.is_empty() && pass.is_empty() && url.is_empty() && otp.is_empty() && !has_passkey);
    let mut d = Draft::new(
        if is_login { "login" } else { "secure_note" },
        title,
        &entry.id().to_string(),
        locale,
    );
    if is_login {
        d.set("username", user);
        d.set("password", pass);
        d.set("otp", &otp);
        if !url.is_empty() {
            d.content().urls.push(UrlEntry::new(url));
        }
    }
    {
        let c = d.content();
        c.notes = get(fields::NOTES).to_string();
        if !group_tag.is_empty() {
            c.tags.push(group_tag.to_string());
        }
        c.tags.extend(
            entry
                .tags
                .iter()
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty()),
        );
        if let Some(t) = ms!(entry.times.creation) {
            c.created_at = t;
        }
        if let Some(t) = ms!(entry.times.last_modification) {
            c.updated_at = t;
        }
    }

    // Passkey.
    if has_passkey {
        match passkey(entry) {
            Ok(mut pk) => {
                pk.created_at = ms!(entry.times.creation).unwrap_or(0);
                d.content().passkeys.push(pk);
                consumed.extend([
                    PK_USERNAME,
                    PK_CREDENTIAL_ID,
                    PK_GENERATED_USER_ID,
                    PK_PRIVATE_KEY,
                    PK_RP,
                    PK_USER_HANDLE,
                    PK_FLAG_BE,
                    PK_FLAG_BS,
                ]);
            }
            Err(why) => {
                d.warn(format!(
                    "passkey not imported ({why}); its attributes are kept in Other fields"
                ));
                d.partial();
            }
        }
    }

    // Extra URLs (Keepass2Android / KeePassXC `KP2A_URL*`).
    let mut keys: Vec<&String> = entry.fields.keys().collect();
    keys.sort();
    for k in &keys {
        if k.starts_with("KP2A_URL") {
            let u = get(k).trim();
            if !u.is_empty() {
                if !d.item.content.urls.iter().any(|e| e.url == u) {
                    d.content().urls.push(UrlEntry::new(u));
                }
                consumed.insert(k.as_str());
            }
        }
    }

    // Other attributes.
    for k in keys {
        if consumed.contains(k.as_str()) {
            continue;
        }
        let Some(v) = entry.fields.get(k) else {
            continue;
        };
        if v.get().is_empty() {
            continue;
        }
        let kind_ = if v.is_protected() {
            kind::CONCEALED
        } else {
            kind::TEXT
        };
        d.other(k, kind_, v.get());
    }

    // Expiry.
    if entry.times.expires == Some(true) {
        if let Some(exp) = entry.times.expiry {
            let label = tr(locale, "过期时间", "Expires").to_string();
            d.other(&label, kind::DATE, &exp.date().to_string());
        }
    }

    // Attachments.
    let mut atts: Vec<(&str, Vec<u8>)> = entry
        .attachments_named()
        .map(|(n, a)| (n, a.data.get().clone()))
        .collect();
    atts.sort_by(|a, b| a.0.cmp(b.0));
    for (name, data) in atts {
        d.item.attachments.push(ImportedAttachment {
            name: name.to_string(),
            mime: mime_for(name),
            data,
        });
    }

    // Password history: older passwords that differ from the current one.
    if let Some(h) = &entry.history {
        let mut versions: Vec<&Entry> = h.get_entries().iter().collect();
        versions.sort_by_key(|e| e.times.last_modification);
        let label = d
            .item
            .content
            .field("password")
            .map(|f| f.label.clone())
            .unwrap_or_else(|| tr(locale, "密码", "Password").to_string());
        let mut seen: HashSet<&str> = HashSet::new();
        for (i, v) in versions.iter().enumerate() {
            let old = v.get(fields::PASSWORD).unwrap_or_default();
            if old.is_empty() || old == pass || !seen.insert(old) {
                continue;
            }
            let until = versions
                .get(i + 1)
                .and_then(|n| ms!(n.times.last_modification))
                .or_else(|| ms!(entry.times.last_modification))
                .unwrap_or(0);
            d.content().history.push(HistoryEntry {
                id: npw_model::new_short_id("h"),
                field: "password".into(),
                label: label.clone(),
                value: Value::String(old.to_string()),
                until,
                extra: Map::new(),
            });
        }
    }

    d.finish()
}

/// The entry's TOTP as an `otpauth://` URI (or bare secret), and the attributes it used.
fn entry_otp<'a>(entry: &'a Entry, title: &str) -> (String, Vec<&'a str>) {
    let get = |k: &str| entry.get(k).map(str::trim).filter(|s| !s.is_empty());
    let key_of = |k: &str| entry.fields.get_key_value(k).map(|(k, _)| k.as_str());

    if let Some(v) = get(fields::OTP) {
        return (otp_uri(v, title), key_of(fields::OTP).into_iter().collect());
    }
    if let Some(seed) = get("TOTP Seed") {
        let settings = get("TOTP Settings").unwrap_or("30;6");
        let mut parts = settings.split(';');
        let period = parts.next().unwrap_or("30").trim().to_string();
        let size = parts.next().unwrap_or("6").trim().to_string();
        let mut params = vec![("secret", seed.replace(' ', "").to_ascii_uppercase())];
        if period != "30" && !period.is_empty() {
            params.push(("period", period));
        }
        if size == "S" {
            params.push(("digits", "5".into()));
            params.push(("encoder", "steam".into()));
        } else if size != "6" && !size.is_empty() {
            params.push(("digits", size));
        }
        let used = ["TOTP Seed", "TOTP Settings"]
            .into_iter()
            .filter_map(key_of)
            .collect();
        return (build_uri(title, &params), used);
    }
    // KeePass 2.47+ built-in TOTP.
    let secret = if let Some(s) = get("TimeOtp-Secret-Base32") {
        Some(s.replace(' ', "").to_ascii_uppercase())
    } else if let Some(s) = get("TimeOtp-Secret") {
        Some(base32(s.as_bytes()))
    } else if let Some(s) = get("TimeOtp-Secret-Hex") {
        from_hex(s).map(|b| base32(&b))
    } else if let Some(s) = get("TimeOtp-Secret-Base64") {
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .ok()
            .map(|b| base32(&b))
    } else {
        None
    };
    if let Some(secret) = secret {
        let mut params = vec![("secret", secret)];
        if let Some(p) = get("TimeOtp-Period").filter(|p| *p != "30") {
            params.push(("period", p.to_string()));
        }
        if let Some(n) = get("TimeOtp-Length").filter(|n| *n != "6") {
            params.push(("digits", n.to_string()));
        }
        match get("TimeOtp-Algorithm") {
            Some("HMAC-SHA-256") => params.push(("algorithm", "SHA256".into())),
            Some("HMAC-SHA-512") => params.push(("algorithm", "SHA512".into())),
            _ => {}
        }
        let used = [
            "TimeOtp-Secret-Base32",
            "TimeOtp-Secret",
            "TimeOtp-Secret-Hex",
            "TimeOtp-Secret-Base64",
            "TimeOtp-Period",
            "TimeOtp-Length",
            "TimeOtp-Algorithm",
        ]
        .into_iter()
        .filter_map(key_of)
        .collect();
        return (build_uri(title, &params), used);
    }
    (String::new(), vec![])
}

/// Normalises an OTP value: `otpauth://` URIs and bare secrets stay as they are,
/// KeeOtp's `key=…&step=…&size=…&otpHashMode=…` becomes an `otpauth://` URI.
fn otp_uri(raw: &str, title: &str) -> String {
    let raw = raw.trim();
    if raw.to_ascii_lowercase().starts_with("otpauth://") || !raw.contains("key=") {
        return raw.to_string();
    }
    let mut params = Vec::new();
    for pair in raw.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "key" => params.insert(0, ("secret", v.replace(' ', "").to_ascii_uppercase())),
            "step" if v != "30" => params.push(("period", v.to_string())),
            "size" if v != "6" => params.push(("digits", v.to_string())),
            "otphashmode" => match v.to_ascii_lowercase().as_str() {
                "sha256" => params.push(("algorithm", "SHA256".into())),
                "sha512" => params.push(("algorithm", "SHA512".into())),
                _ => {}
            },
            _ => {}
        }
    }
    if params.first().is_none_or(|(k, _)| *k != "secret") {
        return raw.to_string();
    }
    build_uri(title, &params)
}

fn build_uri(title: &str, params: &[(&str, String)]) -> String {
    let label = if title.is_empty() {
        "KeePass".to_string()
    } else {
        pct(title)
    };
    let query: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{k}={}", pct(v)))
        .collect();
    format!("otpauth://totp/{label}?{}", query.join("&"))
}

fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn base32(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if s.len() & 1 == 1 {
        return None;
    }
    s.chunks(2)
        .map(|p| {
            let h = (p[0] as char).to_digit(16)?;
            let l = (p[1] as char).to_digit(16)?;
            Some((h * 16 + l) as u8)
        })
        .collect()
}

/// base64 or base64url (with or without padding) → base64url without padding.
fn to_b64url(s: &str) -> Option<String> {
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
    let t: String = s
        .trim()
        .trim_end_matches('=')
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let bytes = URL_SAFE_NO_PAD
        .decode(&t)
        .or_else(|_| STANDARD_NO_PAD.decode(&t))
        .ok()?;
    Some(URL_SAFE_NO_PAD.encode(bytes))
}

/// A KeePassXC passkey from the entry's `KPEX_PASSKEY_*` attributes.
fn passkey(entry: &Entry) -> Result<Passkey, String> {
    let get = |k: &str| entry.get(k).map(str::trim).unwrap_or_default();
    let rp_id = get(PK_RP);
    if rp_id.is_empty() {
        return Err("no relying party".into());
    }
    let cred = [get(PK_CREDENTIAL_ID), get(PK_GENERATED_USER_ID)]
        .into_iter()
        .find(|s| !s.is_empty())
        .ok_or("no credential ID")?;
    let credential_id = to_b64url(cred).ok_or("credential ID is not base64")?;
    let user_handle = match get(PK_USER_HANDLE) {
        "" => String::new(),
        h => to_b64url(h).ok_or("user handle is not base64")?,
    };
    let der = pem_pkcs8_der(get(PK_PRIVATE_KEY))?;
    let alg = cose_alg(&der).ok_or("unsupported private key algorithm")?;
    let mut extra = Map::new();
    for (k, name) in [
        (PK_FLAG_BE, "backup_eligible"),
        (PK_FLAG_BS, "backup_state"),
    ] {
        match get(k).to_ascii_lowercase().as_str() {
            "" => {}
            "1" | "true" => {
                extra.insert(name.into(), Value::Bool(true));
            }
            _ => {
                extra.insert(name.into(), Value::Bool(false));
            }
        }
    }
    Ok(Passkey {
        id: npw_model::new_short_id("pk"),
        rp_id: rp_id.to_string(),
        credential_id,
        user_handle,
        user_name: get(PK_USERNAME).to_string(),
        user_display_name: String::new(),
        rp_name: String::new(),
        alg,
        private_key: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(der),
        counter: 0,
        discoverable: true,
        created_at: 0,
        extra,
    })
}

/// The DER bytes of a `-----BEGIN PRIVATE KEY-----` (PKCS#8) PEM block.
fn pem_pkcs8_der(pem: &str) -> Result<Vec<u8>, String> {
    let pem = pem.trim();
    if pem.is_empty() {
        return Err("no private key".into());
    }
    let begin = pem.find("-----BEGIN ").ok_or("private key is not PEM")?;
    let rest = &pem[begin + 11..];
    let label_end = rest.find("-----").ok_or("private key is not PEM")?;
    let label = &rest[..label_end];
    if label != "PRIVATE KEY" {
        return Err(format!("private key is '{label}', not PKCS#8"));
    }
    let body = &rest[label_end + 5..];
    let end = body
        .find("-----END")
        .ok_or("private key PEM is truncated")?;
    let b64: String = body[..end].chars().filter(|c| !c.is_whitespace()).collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| "private key PEM is not base64".to_string())?;
    if der.first() != Some(&0x30) {
        return Err("private key is not DER".into());
    }
    Ok(der)
}

/// COSE algorithm from the PKCS#8 algorithm OID.
fn cose_alg(der: &[u8]) -> Option<i64> {
    const EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    const ED25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];
    const RSA: &[u8] = &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
    ];
    // The OID sits in the first few dozen bytes; don't scan the whole key.
    let head = &der[..der.len().min(40)];
    let has = |oid: &[u8]| head.windows(oid.len()).any(|w| w == oid);
    if has(EC_PUBLIC_KEY) {
        Some(-7)
    } else if has(ED25519) {
        Some(-8)
    } else if has(RSA) {
        Some(-257)
    } else {
        None
    }
}

// ───────────────────────────────────────── CSV ─────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Col {
    Group,
    Title,
    Username,
    Password,
    Url,
    Notes,
    Totp,
    Icon,
    Modified,
    Created,
    Other,
}

fn col(h: &str) -> Col {
    match h.trim().to_ascii_lowercase().as_str() {
        "group" => Col::Group,
        "title" | "account" => Col::Title,
        "username" | "user name" | "login name" => Col::Username,
        "password" => Col::Password,
        "url" | "web site" | "website" => Col::Url,
        "notes" | "comments" => Col::Notes,
        "totp" | "otp" => Col::Totp,
        "icon" => Col::Icon,
        "last modified" | "last modification" => Col::Modified,
        "created" | "creation" => Col::Created,
        _ => Col::Other,
    }
}

/// Imports a KeePassXC CSV export (`Group,Title,Username,Password,URL,Notes,TOTP,Icon,Last Modified,Created`)
/// or a KeePass 2 CSV export (`Account,Login Name,Password,Web Site,Comments`).
pub fn import_keepass_csv(bytes: &[u8], locale: &str) -> Result<ImportResult, ImportError> {
    let text = std::str::from_utf8(strip_bom(bytes))
        .map_err(|_| ImportError::Format("the CSV file is not UTF-8 text".into()))?;
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());
    let headers: Vec<String> = rdr
        .headers()
        .map_err(|e| ImportError::Format(format!("cannot read the CSV header: {e}")))?
        .iter()
        .map(|h| h.trim().to_string())
        .collect();
    let cols: Vec<Col> = headers.iter().map(|h| col(h)).collect();
    let has = |c: Col| cols.contains(&c);
    if !has(Col::Title) || !(has(Col::Username) || has(Col::Password) || has(Col::Url)) {
        return Err(ImportError::Format(
            "not a KeePass CSV export: expected Title, Username, Password and URL columns".into(),
        ));
    }

    let mut items = Vec::new();
    let skipped = Vec::new();
    for (row, rec) in rdr.records().enumerate() {
        let rec = rec.map_err(|e| ImportError::Format(format!("CSV row {}: {e}", row + 2)))?;
        if rec.iter().all(|v| v.trim().is_empty()) {
            continue;
        }
        let get = |c: Col| {
            cols.iter()
                .position(|&x| x == c)
                .and_then(|i| rec.get(i))
                .unwrap_or_default()
        };
        let title = get(Col::Title);
        let (user, pass, url) = (get(Col::Username), get(Col::Password), get(Col::Url).trim());
        let otp = otp_uri(get(Col::Totp), title);
        let is_login = !(user.is_empty() && pass.is_empty() && url.is_empty() && otp.is_empty());
        let mut d = Draft::new(
            if is_login { "login" } else { "secure_note" },
            title,
            &format!("row {}", row + 2),
            locale,
        );
        if is_login {
            d.set("username", user);
            d.set("password", pass);
            d.set("otp", &otp);
            if !url.is_empty() {
                d.content().urls.push(UrlEntry::new(url));
            }
        }
        {
            let c = d.content();
            c.notes = get(Col::Notes).to_string();
            // `Root/Sub/Leaf` → `Sub/Leaf` (the root group's name is not a tag).
            let group: Vec<&str> = get(Col::Group)
                .split('/')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            if group.len() > 1 {
                c.tags.push(group[1..].join("/"));
            }
            if let Some(t) = parse_rfc3339_ms(get(Col::Created)) {
                c.created_at = t;
            }
            if let Some(t) = parse_rfc3339_ms(get(Col::Modified)) {
                c.updated_at = t;
            }
        }
        for (i, value) in rec.iter().enumerate() {
            if cols.get(i).copied().unwrap_or(Col::Other) != Col::Other || value.is_empty() {
                continue;
            }
            let label = headers
                .get(i)
                .map(String::as_str)
                .filter(|h| !h.is_empty())
                .unwrap_or("field")
                .to_string();
            d.other(&label, kind::TEXT, value);
            d.partial();
        }
        items.push(d.finish());
    }
    Ok(ImportResult::new(items, skipped))
}

/// Alias of [`import_keepass_csv`].
pub fn import_csv(bytes: &[u8], locale: &str) -> Result<ImportResult, ImportError> {
    import_keepass_csv(bytes, locale)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_rfc4648() {
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn keeotp() {
        assert_eq!(
            otp_uri(
                "key=JBSWY3DPEHPK3PXP&step=60&size=8&otpHashMode=Sha256",
                "A b"
            ),
            "otpauth://totp/A%20b?secret=JBSWY3DPEHPK3PXP&period=60&digits=8&algorithm=SHA256"
        );
        assert_eq!(otp_uri("JBSWY3DPEHPK3PXP", "x"), "JBSWY3DPEHPK3PXP");
    }
}
