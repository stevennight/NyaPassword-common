//! 1Password importers: `.1pux` (a zip with `export.data` JSON and the
//! attachments under `files/`) and the 1Password CSV export.
//!
//! Mapping rules:
//! - categories map onto our templates (driver licence / passport / SSN become
//!   `document` with a document type; categories without a close template keep
//!   all their data in sections and are marked `Partial`; unknown ones become a
//!   secure note marked `Fallback`);
//! - well-known 1Password field IDs fill the template fields; every other field
//!   keeps its label and its 1Password section (`s_1p_<name>`), untitled sections
//!   go to "Other fields";
//! - values of unknown types are kept as text with a warning, nothing is dropped;
//! - references to other items keep the 1Password item UUID as their value,
//!   which is the referenced item's [`ImportedItem::source_id`].

use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};

use npw_model::{kind, match_mode, purpose, Field, HistoryEntry, Section, UrlEntry};
use serde_json::{json, Map, Value};
use zip::ZipArchive;

use crate::{
    mime_for, strip_bom, tr, Draft, ImportError, ImportResult, ImportedAttachment, ImportedItem,
    Mapping, Skipped,
};

/// Upper bound for `export.data` (decompressed).
const MAX_EXPORT_DATA: u64 = 512 << 20;
/// Upper bound for one attachment (decompressed).
const MAX_ATTACHMENT: u64 = 1 << 30;

type Zip<'a> = ZipArchive<Cursor<&'a [u8]>>;

// ───────────────────────────────────────── .1pux ─────────────────────────────────────────

/// Imports a 1Password `.1pux` export.
pub fn import_pux(bytes: &[u8], locale: &str) -> Result<ImportResult, ImportError> {
    let mut zip = ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| ImportError::Format(format!("not a zip archive: {e}")))?;

    // Attachments: `files/<documentId>__<fileName>`.
    let mut files: HashMap<String, usize> = HashMap::new();
    let mut files_by_name: HashMap<String, usize> = HashMap::new();
    let mut export_idx = None;
    for i in 0..zip.len() {
        let Ok(f) = zip.by_index_raw(i) else { continue };
        if f.is_dir() {
            continue;
        }
        let name = f.name().replace('\\', "/");
        if name == "export.data" {
            export_idx = Some(i);
        } else if let Some(rest) = name.strip_prefix("files/") {
            match rest.split_once("__") {
                Some((doc_id, file_name)) => {
                    files.insert(doc_id.to_string(), i);
                    files_by_name.entry(file_name.to_string()).or_insert(i);
                }
                None => {
                    files.insert(rest.to_string(), i);
                    files_by_name.entry(rest.to_string()).or_insert(i);
                }
            }
        }
    }
    let idx = export_idx.ok_or_else(|| {
        ImportError::Format("export.data is missing: not a 1Password .1pux export".into())
    })?;
    let data = read_entry(&mut zip, idx, MAX_EXPORT_DATA)
        .map_err(|e| ImportError::Format(format!("cannot read export.data: {e}")))?;
    let root: Value = serde_json::from_slice(strip_bom(&data))
        .map_err(|e| ImportError::Format(format!("export.data is not valid JSON: {e}")))?;
    let accounts = root
        .get("accounts")
        .and_then(Value::as_array)
        .ok_or_else(|| ImportError::Format("export.data has no accounts".into()))?;

    let vault_count: usize = accounts
        .iter()
        .map(|a| {
            a.get("vaults")
                .and_then(Value::as_array)
                .map_or(0, Vec::len)
        })
        .sum();
    let mut ctx = Ctx {
        zip,
        files,
        files_by_name,
        locale: locale.to_string(),
    };
    let mut items = Vec::new();
    let mut skipped = Vec::new();
    for account in accounts {
        for vault in account
            .get("vaults")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let vault_name = vault
                .pointer("/attrs/name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            for item in vault
                .get("items")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if !item.is_object() {
                    skipped.push(Skipped::new("", "item is not a JSON object"));
                    continue;
                }
                let mut it = ctx.item(item);
                if vault_count > 1
                    && !vault_name.is_empty()
                    && !it.content.tags.iter().any(|t| t == vault_name)
                {
                    it.content.tags.push(vault_name.to_string());
                }
                items.push(it);
            }
        }
    }

    // References keep the 1Password UUID (the referenced item's `source_id`).
    let ids: HashSet<String> = items.iter().map(|i| i.source_id.clone()).collect();
    for it in &mut items {
        let missing: Vec<String> = it
            .content
            .fields
            .iter()
            .filter(|f| f.kind == kind::REFERENCE && !f.is_empty() && !ids.contains(&f.text()))
            .map(|f| f.label.clone())
            .collect();
        for label in missing {
            it.warnings.push(format!(
                "{label}: the referenced item is not in this export"
            ));
        }
    }
    Ok(ImportResult::new(items, skipped))
}

fn read_entry(zip: &mut Zip<'_>, idx: usize, limit: u64) -> Result<Vec<u8>, String> {
    let f = zip.by_index(idx).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    f.take(limit + 1)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.len() as u64 > limit {
        return Err("entry too large".into());
    }
    Ok(buf)
}

struct Ctx<'a> {
    zip: Zip<'a>,
    files: HashMap<String, usize>,
    files_by_name: HashMap<String, usize>,
    locale: String,
}

/// How a 1Password category maps onto a template.
struct Category {
    template: &'static str,
    /// For `document`: the document type (zh, en).
    doc_type: Option<(&'static str, &'static str)>,
    /// Name of the 1Password category when our template is only an approximation.
    approx: Option<&'static str>,
    /// 1Password field ID → our template field ID.
    map: &'static [(&'static str, &'static str)],
}

const fn cat(template: &'static str, map: &'static [(&'static str, &'static str)]) -> Category {
    Category {
        template,
        doc_type: None,
        approx: None,
        map,
    }
}

const fn doc(
    zh: &'static str,
    en: &'static str,
    approx: Option<&'static str>,
    map: &'static [(&'static str, &'static str)],
) -> Category {
    Category {
        template: "document",
        doc_type: Some((zh, en)),
        approx,
        map,
    }
}

fn category(uuid: &str) -> Option<Category> {
    Some(match uuid {
        "001" => cat(
            "login",
            &[("username", "username"), ("password", "password")],
        ),
        "002" => cat(
            "credit_card",
            &[
                ("cardholder", "cardholder"),
                ("ccnum", "number"),
                ("expiry", "expiry"),
                ("cvv", "cvv"),
                ("pin", "pin"),
                ("type", "card_type"),
                ("bank", "bank"),
                ("phoneLocal", "phone"),
            ],
        ),
        "003" => cat("secure_note", &[]),
        "004" => cat(
            "identity",
            &[
                ("defphone", "phone"),
                ("cellphone", "phone"),
                ("email", "email"),
                ("address", "address"),
                ("birthdate", "birthday"),
                ("company", "company"),
            ],
        ),
        "005" => cat("password", &[("password", "password")]),
        "006" => cat("secure_note", &[]),
        "100" => cat(
            "software_license",
            &[
                ("product_version", "version"),
                ("reg_code", "license_key"),
                ("reg_name", "licensed_to"),
                ("reg_email", "email"),
                ("order_number", "order_number"),
                ("order_date", "purchased_on"),
            ],
        ),
        "101" => cat(
            "bank_account",
            &[
                ("bankName", "bank"),
                ("accountNo", "account_number"),
                ("owner", "account_name"),
                ("swift", "swift"),
            ],
        ),
        "102" => cat(
            "database",
            &[
                ("database_type", "db_type"),
                ("hostname", "host"),
                ("port", "port"),
                ("database", "database"),
                ("username", "username"),
                ("password", "password"),
                ("options", "options"),
            ],
        ),
        "103" => doc(
            "驾驶证",
            "Driver license",
            None,
            &[
                ("number", "number"),
                ("fullname", "full_name"),
                ("expiry_date", "expires_on"),
                ("issue_date", "issued_on"),
            ],
        ),
        "104" => doc(
            "户外许可证",
            "Outdoor license",
            Some("Outdoor License"),
            &[
                ("name", "full_name"),
                ("valid_from", "issued_on"),
                ("expires", "expires_on"),
            ],
        ),
        "105" => doc(
            "会员卡",
            "Membership",
            Some("Membership"),
            &[
                ("member_name", "full_name"),
                ("membership_no", "number"),
                ("org_name", "issuer"),
                ("expiry_date", "expires_on"),
            ],
        ),
        "106" => doc(
            "护照",
            "Passport",
            None,
            &[
                ("number", "number"),
                ("fullname", "full_name"),
                ("issuing_authority", "issuer"),
                ("issue_date", "issued_on"),
                ("expiry_date", "expires_on"),
            ],
        ),
        "107" => doc(
            "积分计划",
            "Reward program",
            Some("Reward Program"),
            &[
                ("member_name", "full_name"),
                ("membership_no", "number"),
                ("company_name", "issuer"),
            ],
        ),
        "108" => doc(
            "社会安全号",
            "Social Security Number",
            None,
            &[("name", "full_name"), ("number", "number")],
        ),
        "109" => cat(
            "wifi",
            &[
                ("network_name", "ssid"),
                ("wireless_password", "password"),
                ("wireless_security", "security"),
            ],
        ),
        "110" => cat(
            "server",
            &[
                ("url", "host"),
                ("username", "username"),
                ("password", "password"),
            ],
        ),
        "111" => Category {
            template: "login",
            doc_type: None,
            approx: Some("Email Account"),
            map: &[("pop_username", "username"), ("pop_password", "password")],
        },
        "112" => cat(
            "api_credential",
            &[
                ("username", "username"),
                ("credential", "credential"),
                ("hostname", "endpoint"),
                ("expires", "expires_on"),
            ],
        ),
        "113" => Category {
            template: "secure_note",
            doc_type: None,
            approx: Some("Medical Record"),
            map: &[],
        },
        "114" => cat("ssh_key", &[]),
        "115" => cat(
            "crypto_wallet",
            &[
                ("recoveryPhrase", "recovery_phrase"),
                ("password", "password"),
                ("walletAddress", "address"),
            ],
        ),
        _ => return None,
    })
}

/// A 1Password field value converted to our model.
enum Conv {
    Simple {
        kind: &'static str,
        value: Value,
    },
    Ssh {
        private_key: String,
        public_key: String,
        fingerprint: String,
        key_type: String,
    },
    File {
        name: String,
        doc_id: String,
    },
    Unknown {
        type_name: String,
        text: String,
    },
}

impl Conv {
    fn is_empty(&self) -> bool {
        match self {
            Conv::Simple { value, .. } => match value {
                Value::Null => true,
                Value::String(s) => s.is_empty(),
                Value::Object(o) => o.values().all(|v| v.as_str().is_none_or(str::is_empty)),
                _ => false,
            },
            Conv::Ssh {
                private_key,
                public_key,
                ..
            } => private_key.is_empty() && public_key.is_empty(),
            Conv::File { name, doc_id } => name.is_empty() && doc_id.is_empty(),
            Conv::Unknown { text, .. } => text.is_empty(),
        }
    }
}

fn as_text(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn str_at<'v>(v: &'v Value, key: &str) -> &'v str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn convert(value: &Value, multiline_hint: bool) -> Conv {
    let (ty, inner) = match value {
        Value::Object(o) => match o.iter().next() {
            Some((k, v)) => (k.as_str(), v),
            None => {
                return Conv::Simple {
                    kind: kind::TEXT,
                    value: Value::String(String::new()),
                }
            }
        },
        Value::String(_) => ("string", value),
        Value::Null => {
            return Conv::Simple {
                kind: kind::TEXT,
                value: Value::String(String::new()),
            }
        }
        other => {
            return Conv::Unknown {
                type_name: "value".into(),
                text: other.to_string(),
            }
        }
    };
    let text = || as_text(inner);
    let simple = |kind: &'static str, s: String| Conv::Simple {
        kind,
        value: Value::String(s),
    };
    match ty {
        "string" | "menu" | "creditCardType" | "gender" => {
            let s = text();
            let k = if multiline_hint || s.contains('\n') {
                kind::MULTILINE
            } else {
                kind::TEXT
            };
            simple(k, s)
        }
        "concealed" | "creditCardNumber" => simple(kind::CONCEALED, text()),
        "totp" => simple(kind::TOTP, text()),
        "email" => {
            let s = match inner {
                Value::Object(_) => str_at(inner, "email_address").to_string(),
                _ => text(),
            };
            simple(kind::EMAIL, s)
        }
        "phone" => simple(kind::PHONE, text()),
        "url" => simple(kind::URL, text()),
        "date" => match inner {
            Value::Number(n) => match n.as_i64() {
                Some(0) | None => simple(kind::DATE, String::new()),
                Some(secs) => simple(kind::DATE, ymd_from_secs(secs)),
            },
            Value::Null => simple(kind::DATE, String::new()),
            _ => simple(kind::TEXT, text()),
        },
        "monthYear" => match inner.as_i64() {
            Some(0) => simple(kind::MONTH_YEAR, String::new()),
            Some(n) if (1..=12).contains(&(n % 100)) && n / 100 > 0 => {
                simple(kind::MONTH_YEAR, format!("{:04}-{:02}", n / 100, n % 100))
            }
            _ if inner.is_null() => simple(kind::MONTH_YEAR, String::new()),
            _ => simple(kind::TEXT, text()),
        },
        "address" => match inner {
            Value::Object(_) => Conv::Simple {
                kind: kind::ADDRESS,
                value: json!({
                    "country": str_at(inner, "country"),
                    "province": str_at(inner, "state"),
                    "city": str_at(inner, "city"),
                    "district": "",
                    "street": str_at(inner, "street"),
                    "postal_code": str_at(inner, "zip"),
                }),
            },
            _ => simple(kind::MULTILINE, text()),
        },
        "sshKey" => {
            let meta = inner.get("metadata").unwrap_or(&Value::Null);
            let openssh = str_at(meta, "privateKey");
            let private_key = if openssh.is_empty() {
                str_at(inner, "privateKey")
            } else {
                openssh
            };
            Conv::Ssh {
                private_key: private_key.to_string(),
                public_key: str_at(meta, "publicKey").to_string(),
                fingerprint: str_at(meta, "fingerprint").to_string(),
                key_type: str_at(meta, "keyType").to_string(),
            }
        }
        "file" => Conv::File {
            name: str_at(inner, "fileName").to_string(),
            doc_id: str_at(inner, "documentId").to_string(),
        },
        "reference" => simple(kind::REFERENCE, text()),
        _ => Conv::Unknown {
            type_name: ty.to_string(),
            text: text(),
        },
    }
}

/// Whether a value of kind `value_kind` may go into a template field of kind `field_kind`.
fn compatible(field_kind: &str, value_kind: &str) -> bool {
    const STRUCTURED: [&str; 5] = [
        kind::DATE,
        kind::MONTH_YEAR,
        kind::ADDRESS,
        kind::REFERENCE,
        kind::TOTP,
    ];
    if STRUCTURED.contains(&field_kind) || STRUCTURED.contains(&value_kind) {
        return field_kind == value_kind;
    }
    true
}

impl Ctx<'_> {
    fn item(&mut self, item: &Value) -> ImportedItem {
        let overview = item.get("overview").unwrap_or(&Value::Null);
        let details = item.get("details").unwrap_or(&Value::Null);
        let title = str_at(overview, "title");
        let uuid = str_at(item, "uuid");
        let cat_id = item.get("categoryUuid").map(as_text).unwrap_or_default();
        let locale = self.locale.clone();

        let category = category(&cat_id);
        let mut d = Draft::new(
            category.as_ref().map_or("secure_note", |c| c.template),
            title,
            uuid,
            &locale,
        );
        match &category {
            None => {
                d.item.mapping = Mapping::Fallback;
                d.warn(format!(
                    "unknown 1Password category '{cat_id}': stored as a secure note"
                ));
            }
            Some(c) => {
                if let Some((zh, en)) = c.doc_type {
                    d.set("doc_type", tr(&locale, zh, en));
                }
                if let Some(name) = c.approx {
                    d.partial();
                    d.warn(format!(
                        "1Password category '{name}' has no matching template: stored as {}",
                        c.template
                    ));
                }
            }
        }
        let map = category.as_ref().map_or(&[][..], |c| c.map);

        // Item-level attributes.
        {
            let c = d.content();
            c.favorite = item
                .get("favIndex")
                .and_then(Value::as_i64)
                .is_some_and(|n| n > 0);
            if let Some(t) = item
                .get("createdAt")
                .and_then(Value::as_i64)
                .filter(|&t| t > 0)
            {
                c.created_at = t.saturating_mul(1000);
            }
            if let Some(t) = item
                .get("updatedAt")
                .and_then(Value::as_i64)
                .filter(|&t| t > 0)
            {
                c.updated_at = t.saturating_mul(1000);
            }
            for t in overview
                .get("tags")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(t) = t.as_str() {
                    c.tags.push(t.to_string());
                }
            }
            c.notes = str_at(details, "notesPlain").to_string();
        }
        match str_at(item, "state") {
            "archived" => d.content().archived = true,
            "deleted" => {
                d.content().archived = true;
                d.warn("item was in the 1Password trash: imported as archived");
            }
            _ => {}
        }
        self.urls(&mut d, overview);

        // Login form fields.
        for lf in details
            .get("loginFields")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let value = as_text(lf.get("value").unwrap_or(&Value::Null));
            if value.is_empty() {
                continue;
            }
            let designation = str_at(lf, "designation");
            let target = match designation {
                "username" => Some(("username", purpose::USERNAME, kind::TEXT)),
                "password" => Some(("password", purpose::PASSWORD, kind::CONCEALED)),
                _ => None,
            };
            let label = [str_at(lf, "name"), str_at(lf, "id"), designation]
                .into_iter()
                .find(|s| !s.is_empty())
                .unwrap_or("field")
                .to_string();
            match target {
                Some((id, _, _)) if d.item.content.field(id).is_some_and(Field::is_empty) => {
                    d.set(id, &value)
                }
                Some((_, p, k)) => {
                    // A second username / password, or a template without one.
                    let free = d.item.content.by_purpose(p).is_none_or(Field::is_empty);
                    let f = d.other(&label, k, &value);
                    if free {
                        f.purpose = Some(p.to_string());
                    }
                }
                None => {
                    let k = match str_at(lf, "fieldType") {
                        "P" => kind::CONCEALED,
                        "E" => kind::EMAIL,
                        "U" => kind::URL,
                        "N" => kind::NUMBER,
                        _ => kind::TEXT,
                    };
                    d.other(&label, k, &value);
                }
            }
        }

        // A stand-alone password (Password category, some routers…).
        if let Some(pw) = details
            .get("password")
            .map(as_text)
            .filter(|s| !s.is_empty())
        {
            if d.item
                .content
                .field("password")
                .is_some_and(Field::is_empty)
            {
                d.set("password", &pw);
            } else {
                let label = tr(&locale, "密码", "Password").to_string();
                d.other(&label, kind::CONCEALED, &pw);
            }
        }

        // Sections.
        let mut name_parts: Vec<(usize, String)> = Vec::new();
        let mut used_section_ids = HashSet::new();
        for (si, sec) in details
            .get("sections")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            let sec_title = str_at(sec, "title");
            let sec_name = str_at(sec, "name");
            let mut sec_id: Option<String> = None;
            for fld in sec
                .get("fields")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let fid = str_at(fld, "id");
                let ftitle = str_at(fld, "title");
                let multiline = fld
                    .get("multiline")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let conv = convert(fld.get("value").unwrap_or(&Value::Null), multiline);
                if conv.is_empty() {
                    continue;
                }
                // Identity name parts are combined into the full name.
                if cat_id == "004" {
                    let order = match fid {
                        "firstname" => Some(0),
                        "initial" => Some(1),
                        "lastname" => Some(2),
                        _ => None,
                    };
                    if let (
                        Some(o),
                        Conv::Simple {
                            value: Value::String(s),
                            ..
                        },
                    ) = (order, &conv)
                    {
                        name_parts.push((o, s.clone()));
                        continue;
                    }
                }
                // Template field?
                if let Conv::Simple { kind: vk, value } = &conv {
                    let target = map
                        .iter()
                        .find(|(from, _)| *from == fid)
                        .map(|(_, to)| *to)
                        .or_else(|| {
                            // A TOTP anywhere fills the login's one-time password field.
                            (*vk == kind::TOTP).then_some("otp")
                        });
                    if let Some(to) = target {
                        let fits = d
                            .item
                            .content
                            .field(to)
                            .is_some_and(|f| f.is_empty() && compatible(&f.kind, vk));
                        if fits {
                            d.set_value(to, value.clone());
                            continue;
                        }
                    }
                }
                if let Conv::Ssh {
                    private_key,
                    public_key,
                    fingerprint,
                    key_type,
                } = &conv
                {
                    if d.item.content.template == "ssh_key"
                        && d.item
                            .content
                            .field("private_key")
                            .is_some_and(Field::is_empty)
                    {
                        d.set("private_key", private_key);
                        d.set("public_key", public_key);
                        d.set("fingerprint", fingerprint);
                        d.set("key_type", key_type);
                        continue;
                    }
                }
                if let Conv::File { name, doc_id } = &conv {
                    self.attach(&mut d, doc_id, name);
                    continue;
                }

                // A custom field in its section.
                let section = match &sec_id {
                    Some(id) => id.clone(),
                    None => {
                        let id = if sec_title.is_empty() {
                            d.other_section()
                        } else {
                            let base = format!(
                                "s_1p_{}",
                                slug(
                                    if sec_name.is_empty() {
                                        sec_title
                                    } else {
                                        sec_name
                                    },
                                    si
                                )
                            );
                            let mut id = base.clone();
                            let mut n = 2;
                            while !used_section_ids.insert(id.clone()) {
                                id = format!("{base}_{n}");
                                n += 1;
                            }
                            d.content().sections.push(Section {
                                id: id.clone(),
                                label: sec_title.to_string(),
                                extra: Map::new(),
                            });
                            id
                        };
                        sec_id = Some(id.clone());
                        id
                    }
                };
                let label = [ftitle, fid]
                    .into_iter()
                    .find(|s| !s.is_empty())
                    .unwrap_or("field")
                    .to_string();
                match conv {
                    Conv::Simple { kind: k, value } => {
                        push_field(&mut d, &label, k, value, &section)
                    }
                    Conv::Ssh {
                        private_key,
                        public_key,
                        fingerprint,
                        key_type,
                    } => {
                        push_field(
                            &mut d,
                            &label,
                            kind::CONCEALED,
                            Value::String(private_key),
                            &section,
                        );
                        for (l, k, v) in [
                            (
                                tr(&locale, "公钥", "Public key"),
                                kind::MULTILINE,
                                public_key,
                            ),
                            (tr(&locale, "指纹", "Fingerprint"), kind::TEXT, fingerprint),
                            (tr(&locale, "类型", "Key type"), kind::TEXT, key_type),
                        ] {
                            if !v.is_empty() {
                                push_field(
                                    &mut d,
                                    &format!("{label} – {l}"),
                                    k,
                                    Value::String(v),
                                    &section,
                                );
                            }
                        }
                    }
                    Conv::Unknown { type_name, text } => {
                        push_field(&mut d, &label, kind::TEXT, Value::String(text), &section);
                        d.warn(format!(
                            "{label}: unknown 1Password value type '{type_name}' kept as text"
                        ));
                        d.partial();
                    }
                    Conv::File { .. } => {}
                }
            }
        }
        if !name_parts.is_empty() {
            name_parts.sort_by_key(|(o, _)| *o);
            let full: Vec<&str> = name_parts
                .iter()
                .map(|(_, s)| s.as_str())
                .filter(|s| !s.is_empty())
                .collect();
            d.set("full_name", &full.join(" "));
        }

        // Password history.
        let pw_label = d
            .item
            .content
            .field("password")
            .map(|f| f.label.clone())
            .unwrap_or_default();
        for h in details
            .get("passwordHistory")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let value = as_text(h.get("value").unwrap_or(&Value::Null));
            if value.is_empty() {
                continue;
            }
            let until = h
                .get("time")
                .and_then(Value::as_i64)
                .unwrap_or(0)
                .saturating_mul(1000);
            d.content().history.push(HistoryEntry {
                id: npw_model::new_short_id("h"),
                field: "password".into(),
                label: pw_label.clone(),
                value: Value::String(value),
                until,
                extra: Map::new(),
            });
        }

        // The Document category's file.
        if let Some(da) = details.get("documentAttributes").filter(|v| v.is_object()) {
            let name = str_at(da, "fileName").to_string();
            let doc_id = str_at(da, "documentId").to_string();
            self.attach(&mut d, &doc_id, &name);
        }

        // Anything else in `details` is kept, too.
        if let Some(obj) = details.as_object() {
            const KNOWN: [&str; 7] = [
                "loginFields",
                "notesPlain",
                "sections",
                "passwordHistory",
                "documentAttributes",
                "password",
                "htmlForm",
            ];
            for (k, v) in obj {
                if KNOWN.contains(&k.as_str()) || is_blank(v) {
                    continue;
                }
                d.unmapped(
                    k,
                    kind::TEXT,
                    &as_text(v),
                    "unrecognised 1Password data kept as text",
                );
            }
        }
        d.finish()
    }

    fn urls(&mut self, d: &mut Draft, overview: &Value) {
        let mut seen = HashSet::new();
        for u in overview
            .get("urls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let url = str_at(u, "url").trim();
            if url.is_empty() || !seen.insert(url.to_string()) {
                continue;
            }
            let mut e = UrlEntry::new(url);
            e.match_mode = match str_at(u, "mode") {
                "never" => match_mode::NEVER,
                "exact" | "exactHost" | "host" => match_mode::HOST,
                _ => match_mode::DOMAIN,
            }
            .to_string();
            let label = str_at(u, "label");
            if !label.is_empty() {
                e.extra
                    .insert("label".into(), Value::String(label.to_string()));
            }
            d.content().urls.push(e);
        }
        let url = str_at(overview, "url").trim();
        if !url.is_empty() && seen.insert(url.to_string()) {
            d.content().urls.push(UrlEntry::new(url));
        }
    }

    fn attach(&mut self, d: &mut Draft, doc_id: &str, name: &str) {
        let idx = self
            .files
            .get(doc_id)
            .or_else(|| self.files_by_name.get(name))
            .copied();
        let display = if name.is_empty() { doc_id } else { name };
        let Some(idx) = idx else {
            d.warn(format!("attachment '{display}' is missing from the export"));
            d.partial();
            return;
        };
        match read_entry(&mut self.zip, idx, MAX_ATTACHMENT) {
            Ok(data) => {
                if d.item
                    .attachments
                    .iter()
                    .any(|a| a.name == display && a.data == data)
                {
                    return;
                }
                d.item.attachments.push(ImportedAttachment {
                    name: display.to_string(),
                    mime: mime_for(display),
                    data,
                });
            }
            Err(e) => {
                d.warn(format!("attachment '{display}' could not be read: {e}"));
                d.partial();
            }
        }
    }
}

fn is_blank(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.iter().all(is_blank),
        Value::Object(o) => o.values().all(is_blank),
        _ => false,
    }
}

fn push_field(d: &mut Draft, label: &str, k: &'static str, value: Value, section: &str) {
    let mut f = Field::new(npw_model::new_short_id("f"), label, k);
    if let Value::String(s) = &value {
        if s.contains('\n') && k != kind::MULTILINE {
            f.multiline = true;
        }
    }
    f.value = value;
    f.section = Some(section.to_string());
    d.content().fields.push(f);
}

fn slug(s: &str, fallback: usize) -> String {
    let out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .split('_')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("_");
    let out: String = out.chars().take(32).collect();
    if out.is_empty() {
        format!("{fallback}")
    } else {
        out
    }
}

/// `YYYY-MM-DD` (UTC) for Unix seconds.
fn ymd_from_secs(secs: i64) -> String {
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ───────────────────────────────────────── CSV ─────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Col {
    Title,
    Url,
    Username,
    Password,
    Otp,
    Favorite,
    Archived,
    Tags,
    Notes,
    Other,
}

fn col(header: &str) -> Col {
    match header.trim().to_ascii_lowercase().as_str() {
        "title" | "name" => Col::Title,
        "url" | "urls" | "website" | "login url" => Col::Url,
        "username" | "login username" => Col::Username,
        "password" | "login password" => Col::Password,
        "otpauth" | "one-time password" | "otp" | "totp" => Col::Otp,
        "favorite" | "favourite" => Col::Favorite,
        "archived" => Col::Archived,
        "tags" => Col::Tags,
        "notes" | "notesplain" => Col::Notes,
        _ => Col::Other,
    }
}

fn truthy(s: &str) -> bool {
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes" | "y"
    )
}

/// Imports a 1Password CSV export (`Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes`;
/// other columns become fields in "Other fields").
pub fn import_csv(bytes: &[u8], locale: &str) -> Result<ImportResult, ImportError> {
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
    if !has(Col::Title)
        || !(has(Col::Username) || has(Col::Password) || has(Col::Url) || has(Col::Otp))
    {
        return Err(ImportError::Format(
            "not a 1Password CSV export: expected Title, Username, Password and Url columns".into(),
        ));
    }

    let mut items = Vec::new();
    let mut skipped = Vec::new();
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
        let (user, pass, url, otp) = (
            get(Col::Username),
            get(Col::Password),
            get(Col::Url).trim(),
            get(Col::Otp).trim(),
        );
        let is_login = !(user.is_empty() && pass.is_empty() && url.is_empty() && otp.is_empty());
        let mut title = get(Col::Title).to_string();
        if title.trim().is_empty() {
            title = if url.is_empty() {
                tr(locale, "未命名", "Untitled").to_string()
            } else {
                url.to_string()
            };
        }
        let mut d = Draft::new(
            if is_login { "login" } else { "secure_note" },
            &title,
            &format!("row {}", row + 2),
            locale,
        );
        if is_login {
            d.set("username", user);
            d.set("password", pass);
            d.set("otp", otp);
            if !url.is_empty() {
                d.content().urls.push(UrlEntry::new(url));
            }
        }
        {
            let c = d.content();
            c.favorite = truthy(get(Col::Favorite));
            c.archived = truthy(get(Col::Archived));
            let tags = get(Col::Tags);
            let sep = if tags.contains(';') { ';' } else { ',' };
            c.tags.extend(
                tags.split(sep)
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .map(str::to_string),
            );
            c.notes = get(Col::Notes).to_string();
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
        let item = d.finish();
        if item.content.fields.iter().all(Field::is_empty)
            && item.content.notes.is_empty()
            && item.content.urls.is_empty()
            && get(Col::Title).is_empty()
        {
            skipped.push(Skipped::new(title, "empty row"));
            continue;
        }
        items.push(item);
    }
    Ok(ImportResult::new(items, skipped))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(ymd_from_secs(0), "1970-01-01");
        assert_eq!(ymd_from_secs(1_705_314_600), "2024-01-15");
        assert_eq!(ymd_from_secs(-1), "1969-12-31");
        assert_eq!(ymd_from_secs(951_782_400), "2000-02-29");
    }

    #[test]
    fn slugs() {
        assert_eq!(slug("Linked Items!", 0), "linked_items");
        assert_eq!(slug("帐户", 3), "3");
    }
}
