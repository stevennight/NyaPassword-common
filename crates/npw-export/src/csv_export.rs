//! CSV export.
//!
//! **WARNING: the output is plaintext.** Every password, card number, recovery
//! code and TOTP secret is readable by anyone and anything that can read the
//! file (sync clients, backups, antivirus uploads, the recycle bin). Clients must
//! ask for the master password again and show this warning before calling it
//! (design doc §9.3), and should suggest deleting the file after use.
//!
//! Format: UTF-8 with BOM, CRLF line endings, RFC 4180 quoting (opens correctly
//! in Excel / WPS / LibreOffice; multi-line values stay in one cell). Columns:
//!
//! `vault,title,username,password,url,totp,notes,tags,template,fields`
//!
//! - `username` / `password`: the first field with that purpose;
//! - `url`: the first URL; `totp`: the first TOTP field as stored;
//! - `tags`: joined with `;`;
//! - `fields`: a JSON array of every other non-empty field and every further URL,
//!   `[{"label", "section"?, "kind", "value"}]` (addresses as JSON objects).
//!
//! Not included: deleted items (recycle bin), attachments, passkeys (their
//! private keys do not belong in a spreadsheet), history, settings. Use the
//! native or KDBX export for those.

use npw_model::kind;
use serde_json::{json, Value};

use crate::mapping::{field_text, section_label, split};
use crate::ExportVault;

/// Column headers, in order.
pub const COLUMNS: [&str; 10] = [
    "vault", "title", "username", "password", "url", "totp", "notes", "tags", "template", "fields",
];

/// Writes all non-deleted items as CSV. **Plaintext** — see the module docs.
pub fn export_csv(vaults: &[ExportVault]) -> Vec<u8> {
    let mut out = Vec::from(&b"\xEF\xBB\xBF"[..]);
    {
        let mut w = csv::WriterBuilder::new()
            .terminator(csv::Terminator::CRLF)
            .from_writer(&mut out);
        w.write_record(COLUMNS)
            .expect("writing to a Vec cannot fail");
        for v in vaults {
            for item in v.items.iter().filter(|i| !i.deleted) {
                let c = &item.content;
                let s = split(c);
                let mut extra: Vec<Value> = Vec::new();
                for f in &s.others {
                    if f.is_empty() {
                        continue;
                    }
                    let mut o = serde_json::Map::new();
                    o.insert(
                        "label".into(),
                        Value::String(if f.label.is_empty() {
                            f.id.clone()
                        } else {
                            f.label.clone()
                        }),
                    );
                    if let Some(sec) = section_label(c, f) {
                        o.insert("section".into(), Value::String(sec.to_string()));
                    }
                    o.insert("kind".into(), Value::String(f.kind.clone()));
                    let value = if f.value.is_object() {
                        f.value.clone()
                    } else {
                        Value::String(field_text(c, f))
                    };
                    o.insert("value".into(), value);
                    extra.push(Value::Object(o));
                }
                for u in c.urls.iter().skip(1) {
                    extra.push(json!({"label": "URL", "kind": kind::URL, "value": u.url}));
                }
                let text =
                    |f: Option<&npw_model::Field>| f.map(|f| field_text(c, f)).unwrap_or_default();
                let fields_json = if extra.is_empty() {
                    String::new()
                } else {
                    Value::Array(extra).to_string()
                };
                let record = [
                    v.name.clone(),
                    c.title.clone(),
                    text(s.username),
                    text(s.password),
                    c.urls.first().map(|u| u.url.clone()).unwrap_or_default(),
                    text(s.totp),
                    c.notes.clone(),
                    c.tags.join(";"),
                    c.template.clone(),
                    fields_json,
                ];
                w.write_record(&record)
                    .expect("writing to a Vec cannot fail");
            }
        }
        w.flush().expect("writing to a Vec cannot fail");
    }
    out
}
