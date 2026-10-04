//! Field classification shared by the KDBX and CSV exports.

use npw_model::{kind, purpose, Field, ItemContent};

/// How an item's fields split into the standard columns and the rest.
pub(crate) struct Split<'a> {
    pub username: Option<&'a Field>,
    pub password: Option<&'a Field>,
    pub totp: Option<&'a Field>,
    /// Every other field, in item order.
    pub others: Vec<&'a Field>,
}

pub(crate) fn split(item: &ItemContent) -> Split<'_> {
    let username = item
        .fields
        .iter()
        .find(|f| f.purpose.as_deref() == Some(purpose::USERNAME));
    let password = item
        .fields
        .iter()
        .find(|f| f.purpose.as_deref() == Some(purpose::PASSWORD));
    let totp = item
        .fields
        .iter()
        .find(|f| f.kind == kind::TOTP && !f.is_empty())
        .or_else(|| item.fields.iter().find(|f| f.kind == kind::TOTP));
    let taken = |f: &Field| {
        [username, password, totp]
            .iter()
            .any(|t| t.is_some_and(|t| std::ptr::eq(t, f)))
    };
    let others = item.fields.iter().filter(|f| !taken(f)).collect();
    Split {
        username,
        password,
        totp,
        others,
    }
}

/// The section's label, if the field is in a section.
pub(crate) fn section_label<'a>(item: &'a ItemContent, field: &'a Field) -> Option<&'a str> {
    let sid = field.section.as_deref()?;
    let label = item
        .sections
        .iter()
        .find(|s| s.id == sid)
        .map(|s| s.label.as_str())
        .unwrap_or("");
    Some(if label.is_empty() { sid } else { label })
}

/// `Label`, or `Section: Label` for fields inside a section; the field ID if unlabelled.
pub(crate) fn display_label(item: &ItemContent, field: &Field) -> String {
    let label = if field.label.trim().is_empty() {
        field.id.as_str()
    } else {
        field.label.as_str()
    };
    match section_label(item, field) {
        Some(s) => format!("{s}: {label}"),
        None => label.to_string(),
    }
}

/// The value as text; `file` fields show the attachment's name rather than its ID.
pub(crate) fn field_text(item: &ItemContent, field: &Field) -> String {
    let text = field.text();
    if field.kind == kind::FILE {
        if let Some(a) = item.attachments.iter().find(|a| a.id == text) {
            return a.name.clone();
        }
    }
    text
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// An `otpauth://` URI for a TOTP field value. URIs (`otpauth://`, `steam://`, ...)
/// are kept as they are; a bare base32 secret becomes
/// `otpauth://totp/<issuer>:<account>?secret=…&issuer=…` (SHA1, 6 digits, 30 s).
pub(crate) fn totp_uri(value: &str, issuer: &str, account: &str) -> String {
    let v = value.trim();
    if v.is_empty() || v.contains("://") {
        return v.to_string();
    }
    let secret: String = v
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase();
    let secret = secret.trim_end_matches('=');
    let issuer = if issuer.trim().is_empty() {
        "NyaPassword"
    } else {
        issuer.trim()
    };
    let label = if account.is_empty() {
        percent_encode(issuer)
    } else {
        format!("{}:{}", percent_encode(issuer), percent_encode(account))
    };
    format!(
        "otpauth://totp/{label}?secret={secret}&period=30&digits=6&algorithm=SHA1&issuer={}",
        percent_encode(issuer)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totp_uri_forms() {
        assert_eq!(
            totp_uri("otpauth://totp/x?secret=A", "i", "a"),
            "otpauth://totp/x?secret=A"
        );
        assert_eq!(
            totp_uri("jbsw y3dp ehpk 3pxp", "Example 站", "me@example.com"),
            "otpauth://totp/Example%20%E7%AB%99:me%40example.com?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&algorithm=SHA1&issuer=Example%20%E7%AB%99"
        );
        assert_eq!(totp_uri("", "i", "a"), "");
    }
}
