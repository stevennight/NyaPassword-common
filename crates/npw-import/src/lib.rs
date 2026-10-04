//! Importers for other password managers' exports (design doc §9).
//!
//! Every importer turns an export file into [`ImportedItem`]s (NyaPassword item
//! content plus attachment bytes) and an [`ImportReport`] for the preview.
//! Nothing is dropped: data without a matching template field goes into the
//! "Other fields" section (or the notes) and is listed as a warning.
//! Library code never touches the filesystem, so it also builds for WASM.

pub mod bitwarden;
pub mod csv_generic;
pub mod keepass;
pub mod onepassword;
pub mod report;

use std::collections::HashSet;

use npw_model::{kind, Field, ItemContent, Section};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;

pub use report::{ImportReport, ItemWarning, Skipped};

/// Why an import failed. Item-level problems are warnings in the report, not errors.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// The file is password protected and no password was given.
    #[error("this export is password protected")]
    NeedPassword,
    #[error("wrong password")]
    WrongPassword,
    /// The file is damaged or not what the chosen source expects.
    #[error("invalid export file: {0}")]
    Format(String),
    #[error("unsupported export: {0}")]
    Unsupported(String),
}

/// How faithfully an item was mapped onto a template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mapping {
    /// Every value landed in a template field (or an expected custom field).
    Full,
    /// Mapped onto a template, but some values had to go into "Other fields" / notes.
    Partial,
    /// Unknown kind of entry: everything was stored as fields of a secure note.
    Fallback,
}

/// An attachment to upload (encrypted) together with its item.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImportedAttachment {
    pub name: String,
    pub mime: String,
    /// Serialized as standard base64.
    #[serde(serialize_with = "ser_base64")]
    pub data: Vec<u8>,
}

fn ser_base64<S: Serializer>(data: &[u8], s: S) -> Result<S::Ok, S::Error> {
    use base64::Engine;
    s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(data))
}

/// One item ready to be written to the vault.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImportedItem {
    pub content: ItemContent,
    pub attachments: Vec<ImportedAttachment>,
    /// The entry's ID in the source (derived IDs such as `<id>#passport` for split items).
    pub source_id: String,
    pub mapping: Mapping,
    pub warnings: Vec<String>,
}

/// Items plus the preview report.
#[derive(Debug, Clone, Serialize)]
pub struct ImportResult {
    pub items: Vec<ImportedItem>,
    pub report: ImportReport,
}

impl ImportResult {
    /// Builds the result and computes its report.
    pub fn new(items: Vec<ImportedItem>, skipped: Vec<Skipped>) -> Self {
        let report = ImportReport::build(&items, skipped);
        Self { items, report }
    }
}

/// Export formats this crate reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    BitwardenJson,
    /// Password-protected (or account-key encrypted) Bitwarden JSON.
    BitwardenEncryptedJson,
    /// Bitwarden / Vaultwarden ".zip (with attachments)".
    BitwardenZip,
    BitwardenCsv,
    /// Chrome / Edge / Google Password Manager CSV, and other CSVs with recognisable headers.
    ChromeCsv,
    OnePasswordPux,
    OnePasswordCsv,
    KeepassKdbx,
    KeepassCsv,
}

const KDBX_MAGIC: [u8; 8] = [0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5];

/// Guesses the export format from the file name and content.
pub fn detect(file_name: &str, bytes: &[u8]) -> Option<Source> {
    let name = file_name.to_ascii_lowercase();
    if bytes.starts_with(&KDBX_MAGIC) {
        return Some(Source::KeepassKdbx);
    }
    if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        let names = zip_names(bytes)?;
        if names.iter().any(|n| n == "export.data") || name.ends_with(".1pux") {
            return Some(Source::OnePasswordPux);
        }
        return names
            .iter()
            .any(|n| bitwarden::is_data_json(n))
            .then_some(Source::BitwardenZip);
    }
    let text = std::str::from_utf8(strip_bom(bytes)).ok()?;
    if text.trim_start().starts_with('{') {
        let v: Value = serde_json::from_str(text).ok()?;
        if v.get("encrypted").and_then(Value::as_bool) == Some(true) {
            return Some(Source::BitwardenEncryptedJson);
        }
        return (v.get("items").is_some() || v.get("folders").is_some())
            .then_some(Source::BitwardenJson);
    }
    let headers: Vec<String> = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes())
        .headers()
        .ok()?
        .iter()
        .map(|h| h.trim().to_lowercase())
        .collect();
    let has = |h: &str| headers.iter().any(|x| x == h);
    if has("login_uri") || has("login_username") || has("login_password") {
        Some(Source::BitwardenCsv)
    } else if (has("group") && has("title")) || (has("account") && has("login name")) {
        Some(Source::KeepassCsv)
    } else if has("otpauth") || name.contains("1password") || (has("title") && has("archived")) {
        Some(Source::OnePasswordCsv)
    } else if csv_generic::recognises(&headers) {
        Some(Source::ChromeCsv)
    } else {
        None
    }
}

fn zip_names(bytes: &[u8]) -> Option<Vec<String>> {
    let zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).ok()?;
    Some(zip.file_names().map(str::to_string).collect())
}

/// Imports an export file. `locale` (e.g. `zh-CN`, `en`) picks field and section labels.
pub fn import(
    source: Source,
    bytes: &[u8],
    password: Option<&str>,
    locale: &str,
) -> Result<ImportResult, ImportError> {
    match source {
        Source::BitwardenJson | Source::BitwardenEncryptedJson => {
            bitwarden::import_json(bytes, password, locale)
        }
        Source::BitwardenZip => bitwarden::import_zip(bytes, password, locale),
        Source::BitwardenCsv => bitwarden::import_csv(bytes, locale),
        Source::ChromeCsv => csv_generic::import_csv(bytes, locale),
        Source::OnePasswordPux => onepassword::import_pux(bytes, locale),
        Source::OnePasswordCsv => onepassword::import_csv(bytes, locale),
        Source::KeepassKdbx => keepass::import_kdbx(bytes, password, locale),
        Source::KeepassCsv => keepass::import_csv(bytes, locale),
    }
}

/// Checks that everything imported ended up in the decrypted vault items: every
/// non-empty field value, URL (with match mode), passkey, attachment name,
/// password-history value, tag, notes, title and favorite flag. Returns the problems
/// found (titles and field labels only, never values); empty means a 100% match.
pub fn compare(source_items: &[ImportedItem], decrypted: &[ItemContent]) -> Vec<String> {
    let mut problems = Vec::new();
    if source_items.len() != decrypted.len() {
        problems.push(format!(
            "item count differs: imported {}, found {}",
            source_items.len(),
            decrypted.len()
        ));
    }
    let mut used = vec![false; decrypted.len()];
    for (i, src) in source_items.iter().enumerate() {
        let c = &src.content;
        // Prefer the item at the same position, then any unused one with the same title and template.
        let order = std::iter::once(i).chain((0..decrypted.len()).filter(move |&j| j != i));
        let mut best: Option<(usize, Vec<String>)> = None;
        for j in order {
            let Some(d) = decrypted.get(j) else { continue };
            if used[j] || d.title != c.title || d.template != c.template {
                continue;
            }
            let diff = diff_item(src, d);
            let better = best.as_ref().is_none_or(|(_, b)| diff.len() < b.len());
            if better {
                let done = diff.is_empty();
                best = Some((j, diff));
                if done {
                    break;
                }
            }
        }
        match best {
            Some((j, diff)) => {
                used[j] = true;
                problems.extend(
                    diff.into_iter()
                        .map(|p| format!("{} [{}]: {p}", c.title, src.source_id)),
                );
            }
            None => problems.push(format!("{} [{}]: item missing", c.title, src.source_id)),
        }
    }
    problems
}

fn section_label<'a>(item: &'a ItemContent, f: &Field) -> Option<&'a str> {
    let id = f.section.as_deref()?;
    item.sections
        .iter()
        .find(|s| s.id == id)
        .map(|s| s.label.as_str())
}

fn diff_item(src: &ImportedItem, d: &ItemContent) -> Vec<String> {
    let c = &src.content;
    let mut p = Vec::new();
    if c.favorite != d.favorite {
        p.push("favorite flag differs".into());
    }
    if c.archived != d.archived {
        p.push("archived flag differs".into());
    }
    if c.notes != d.notes {
        p.push("notes differ".into());
    }
    for t in &c.tags {
        if !d.tags.contains(t) {
            p.push(format!("tag '{t}' missing"));
        }
    }
    for f in c.fields.iter().filter(|f| !f.is_empty()) {
        match d.field(&f.id) {
            None => p.push(format!("field '{}' missing", f.label)),
            Some(g) if g.value != f.value => p.push(format!("field '{}' value differs", f.label)),
            Some(g) if g.kind != f.kind => p.push(format!("field '{}' kind differs", f.label)),
            Some(g) if section_label(c, f) != section_label(d, g) => {
                p.push(format!("field '{}' section differs", f.label))
            }
            _ => {}
        }
    }
    for u in &c.urls {
        if !d
            .urls
            .iter()
            .any(|v| v.url == u.url && v.match_mode == u.match_mode)
        {
            p.push(format!("url '{}' missing or match mode differs", u.url));
        }
    }
    for k in &c.passkeys {
        let ok = d.passkeys.iter().any(|q| {
            q.credential_id == k.credential_id
                && q.private_key == k.private_key
                && q.rp_id == k.rp_id
                && q.user_handle == k.user_handle
                && q.user_name == k.user_name
        });
        if !ok {
            p.push(format!("passkey for '{}' missing or differs", k.rp_id));
        }
    }
    for a in &src.attachments {
        if !d
            .attachments
            .iter()
            .any(|b| b.name == a.name && b.size == a.data.len() as u64)
        {
            p.push(format!("attachment '{}' missing or size differs", a.name));
        }
    }
    for h in &c.history {
        if !d
            .history
            .iter()
            .any(|g| g.field == h.field && g.value == h.value)
        {
            p.push(format!("history entry of '{}' missing", h.field));
        }
    }
    p
}

// ───────────────────────── helpers shared by the importers ─────────────────────────

/// Whether labels should be Chinese.
pub fn is_zh(locale: &str) -> bool {
    locale.to_ascii_lowercase().starts_with("zh")
}

/// Picks the Chinese or English text for `locale`.
pub fn tr<'a>(locale: &str, zh: &'a str, en: &'a str) -> &'a str {
    if is_zh(locale) {
        zh
    } else {
        en
    }
}

/// Removes a UTF-8 byte order mark.
pub fn strip_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes)
}

/// A MIME type guessed from a file name's extension.
pub fn mime_for(name: &str) -> String {
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "txt" | "log" | "md" => "text/plain",
        "csv" => "text/csv",
        "json" => "application/json",
        "xml" => "application/xml",
        "html" | "htm" => "text/html",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "heic" => "image/heic",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "7z" => "application/x-7z-compressed",
        "pem" | "crt" | "cer" => "application/x-pem-file",
        "p12" | "pfx" => "application/x-pkcs12",
        "kdbx" => "application/x-keepass2",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "mp4" => "video/mp4",
        "mp3" => "audio/mpeg",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// Parses an RFC 3339 / ISO 8601 timestamp (`2024-01-15T10:30:00.123Z`,
/// `+08:00` offsets, a space instead of `T`, or a bare date) into UTC milliseconds.
pub fn parse_rfc3339_ms(s: &str) -> Option<i64> {
    let s = s.trim();
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = s.get(r)?;
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())?
    };
    if b.len() < 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    let days = days_from_civil(y, mo, d);
    if b.len() == 10 {
        return Some(days * 86_400_000);
    }
    if !matches!(b[10], b'T' | b't' | b' ') || b.len() < 19 || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut i = 19;
    let mut ms = 0i64;
    if b.get(i) == Some(&b'.') {
        let start = i + 1;
        i = start;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        let frac = s.get(start..i)?;
        if frac.is_empty() {
            return None;
        }
        let first3: String = frac.chars().chain("000".chars()).take(3).collect();
        ms = first3.parse().ok()?;
    }
    let offset_min = match b.get(i) {
        None | Some(b'Z') | Some(b'z') if i + 1 >= b.len() => 0,
        Some(&c @ (b'+' | b'-')) if b.len() == i + 6 && b[i + 3] == b':' => {
            let m = num(i + 1..i + 3)? * 60 + num(i + 4..i + 6)?;
            if c == b'+' {
                m
            } else {
                -m
            }
        }
        _ => return None,
    };
    Some(((days * 24 + h) * 60 + mi - offset_min) * 60_000 + sec * 1000 + ms)
}

/// Days since 1970-01-01 (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Builds one [`ImportedItem`]: fills template fields, collects everything else
/// in the "Other fields" section, and tracks warnings and the mapping quality.
#[derive(Debug)]
pub struct Draft {
    pub item: ImportedItem,
    locale: String,
    other_section: Option<String>,
}

impl Draft {
    /// A new item of `template` (its template fields start empty; an unknown
    /// template gives an item without fields).
    pub fn new(template: &str, title: &str, source_id: &str, locale: &str) -> Self {
        let content = match npw_model::template(template) {
            Some(t) => {
                let mut c = t.new_item(locale);
                c.title = title.to_string();
                c
            }
            None => ItemContent::new(template, title),
        };
        Self {
            item: ImportedItem {
                content,
                attachments: vec![],
                source_id: source_id.to_string(),
                mapping: Mapping::Full,
                warnings: vec![],
            },
            locale: locale.to_string(),
            other_section: None,
        }
    }

    pub fn content(&mut self) -> &mut ItemContent {
        &mut self.item.content
    }

    /// Sets a template field's value; when the template has no such field the
    /// value goes to "Other fields" with a warning. Empty values are ignored.
    pub fn set(&mut self, id: &str, value: &str) {
        self.set_value(id, Value::String(value.to_string()));
    }

    /// Like [`Draft::set`] for structured values (addresses).
    pub fn set_value(&mut self, id: &str, value: Value) {
        if value.as_str().is_some_and(str::is_empty) || value.is_null() {
            return;
        }
        match self.item.content.field_mut(id) {
            Some(f) => {
                if f.kind == kind::TEXT && value.as_str().is_some_and(|s| s.contains('\n')) {
                    f.multiline = true;
                }
                f.value = value;
            }
            None => {
                let text = value
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| value.to_string());
                self.unmapped(id, kind::TEXT, &text, &format!("no template field '{id}'"));
            }
        }
    }

    /// The "Other fields" section's ID, created on first use.
    pub fn other_section(&mut self) -> String {
        if let Some(id) = &self.other_section {
            return id.clone();
        }
        let id = npw_model::new_short_id("s");
        let label = tr(&self.locale, "其他字段", "Other fields").to_string();
        self.item.content.sections.push(Section {
            id: id.clone(),
            label,
            extra: Default::default(),
        });
        self.other_section = Some(id.clone());
        id
    }

    /// Adds a field (random ID) to "Other fields". Multi-line text keeps its
    /// line breaks: `text` becomes `multiline`, secrets get `multiline: true`.
    pub fn other(&mut self, label: &str, kind_: &str, value: &str) -> &mut Field {
        let section = self.other_section();
        let multiline = value.contains('\n');
        let kind_ = if kind_ == kind::TEXT && multiline {
            kind::MULTILINE
        } else {
            kind_
        };
        let mut f = Field::new(npw_model::new_short_id("f"), label, kind_).with_value(value);
        f.section = Some(section);
        f.multiline = multiline && kind_ != kind::MULTILINE;
        self.item.content.fields.push(f);
        let last = self.item.content.fields.len() - 1;
        &mut self.item.content.fields[last]
    }

    /// Stores a value that has no proper place: "Other fields", a warning, `Partial`.
    pub fn unmapped(&mut self, label: &str, kind_: &str, value: &str, why: &str) {
        self.other(label, kind_, value);
        self.warn(format!("{label}: {why}"));
        self.partial();
    }

    pub fn warn(&mut self, w: impl Into<String>) {
        self.item.warnings.push(w.into());
    }

    /// Downgrades the mapping to `Partial` (never upgrades `Fallback`).
    pub fn partial(&mut self) {
        if self.item.mapping == Mapping::Full {
            self.item.mapping = Mapping::Partial;
        }
    }

    pub fn locale(&self) -> &str {
        &self.locale
    }

    pub fn finish(mut self) -> ImportedItem {
        let mut seen = HashSet::new();
        self.item
            .content
            .tags
            .retain(|t| !t.is_empty() && seen.insert(t.clone()));
        self.item
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339() {
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_ms("2024-01-15T10:30:00.123Z"),
            Some(1_705_314_600_123)
        );
        assert_eq!(
            parse_rfc3339_ms("2024-01-15T18:30:00.1234567+08:00"),
            Some(1_705_314_600_123)
        );
        assert_eq!(parse_rfc3339_ms("2024-01-15"), Some(1_705_276_800_000));
        assert_eq!(parse_rfc3339_ms("1969-12-31T23:59:59Z"), Some(-1000));
        for bad in [
            "",
            "2024",
            "2024-13-01",
            "2024-01-15T25:00:00Z",
            "2024-01-15T10:30:00+0800",
            "2024-01-15T10:30:00Zx",
            "２０２４-01-01",
        ] {
            assert_eq!(parse_rfc3339_ms(bad), None, "{bad}");
        }
    }
}
