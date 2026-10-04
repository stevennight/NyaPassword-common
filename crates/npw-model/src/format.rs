//! Format versions (design doc §5.6).
//!
//! - MINOR adds optional keys only. Keys are never renamed, retyped or reused.
//! - A client reading a newer MINOR may edit the item: unknown keys are kept.
//! - A client reading a newer MAJOR shows the item read-only and never writes it.
//! - Items are not rewritten on upgrade; they move to the new format when next saved.
//!
//! Every released version is frozen: `format/history/vX.Y/schema.json` plus the
//! encrypted samples in `tests/compat/vX.Y/` (tests/compat.rs decrypts them).

use serde_json::Value;

use crate::ItemContent;

pub const FORMAT_MAJOR: u16 = 1;
pub const FORMAT_MINOR: u16 = 0;
pub const FORMAT_VERSION: &str = "1.0";

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("item is not valid JSON: {0}")]
    Json(String),
    #[error("item has no valid format version")]
    NoVersion,
}

pub fn parse_version(v: &str) -> Option<(u16, u16)> {
    let (a, b) = v.split_once('.')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

/// A decrypted item, possibly from a newer client.
#[derive(Debug, Clone)]
pub struct DecodedItem {
    /// Typed view. For a newer MAJOR whose shape no longer parses, a minimal
    /// view (title only) built from `raw`.
    pub content: ItemContent,
    /// Exactly what was decrypted.
    pub raw: Value,
    /// `(major, minor)` the item was written with.
    pub version: (u16, u16),
    /// True when this client must not write the item (newer MAJOR, or unparsable).
    pub read_only: bool,
}

pub fn decode_item(bytes: &[u8]) -> Result<DecodedItem, FormatError> {
    let raw: Value = serde_json::from_slice(bytes).map_err(|e| FormatError::Json(e.to_string()))?;
    let version = raw
        .get("format")
        .and_then(Value::as_str)
        .and_then(parse_version)
        .ok_or(FormatError::NoVersion)?;
    let typed: Result<ItemContent, _> = serde_json::from_value(raw.clone());
    match typed {
        Ok(content) if version.0 <= FORMAT_MAJOR => Ok(DecodedItem {
            content,
            raw,
            version,
            read_only: false,
        }),
        Ok(content) => Ok(DecodedItem {
            content,
            raw,
            version,
            read_only: true,
        }),
        Err(_) => {
            // Never guess at an item we cannot parse: show what we can, refuse to edit.
            let mut content = ItemContent::new(
                raw.get("template")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
                raw.get("title").and_then(Value::as_str).unwrap_or("?"),
            );
            content.format = raw
                .get("format")
                .and_then(Value::as_str)
                .unwrap_or("?")
                .to_string();
            Ok(DecodedItem {
                content,
                raw,
                version,
                read_only: true,
            })
        }
    }
}

/// Serializes an item for encryption. The written format is raised to this
/// client's version, never lowered (a newer MINOR's extra keys are still inside).
pub fn encode_item(content: &ItemContent) -> Vec<u8> {
    let mut c = content.clone();
    let current = (FORMAT_MAJOR, FORMAT_MINOR);
    let written = parse_version(&c.format).unwrap_or(current);
    if written < current {
        c.format = FORMAT_VERSION.to_string();
    }
    serde_json::to_vec(&c).expect("item content always serializes")
}

/// The major version an item will be written with (bound into the encryption's associated data).
pub fn format_major_of(content: &ItemContent) -> u16 {
    parse_version(&content.format)
        .map(|v| v.0.max(FORMAT_MAJOR))
        .unwrap_or(FORMAT_MAJOR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_minor_is_editable_newer_major_is_not() {
        let minor = br#"{"format":"1.7","template":"login","title":"a","new_key":1}"#;
        let d = decode_item(minor).unwrap();
        assert!(!d.read_only);
        let out: Value = serde_json::from_slice(&encode_item(&d.content)).unwrap();
        assert_eq!(out["format"], "1.7");
        assert_eq!(out["new_key"], 1);

        let major = br#"{"format":"2.0","template":"login","title":"b","fields":"now a string"}"#;
        let d = decode_item(major).unwrap();
        assert!(d.read_only);
        assert_eq!(d.content.title, "b");

        let old = br#"{"format":"0.9","template":"login","title":"c"}"#;
        let out: Value =
            serde_json::from_slice(&encode_item(&decode_item(old).unwrap().content)).unwrap();
        assert_eq!(out["format"], FORMAT_VERSION);
    }

    #[test]
    fn rejects_garbage() {
        assert!(decode_item(b"not json").is_err());
        assert!(decode_item(br#"{"title":"no version"}"#).is_err());
    }
}
