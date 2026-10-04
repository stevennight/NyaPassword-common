//! The NyaPassword item format (design doc §5).
//!
//! Item content is JSON, encrypted as a whole. Rules that keep data safe across
//! client versions:
//! - every struct keeps the keys it does not know (`extra`) and writes them back;
//! - `format` is `MAJOR.MINOR`: a newer MINOR is editable, a newer MAJOR is read-only;
//! - fields, sections, URLs, passkeys, attachments, history and conflicts carry
//!   stable IDs, which is what the three-way merge ([`merge`]) works on.

pub mod format;
pub mod item;
pub mod merge;
pub mod template;

pub use format::{
    decode_item, encode_item, DecodedItem, FORMAT_MAJOR, FORMAT_MINOR, FORMAT_VERSION,
};
pub use item::*;
pub use merge::{merge_items, MergeOutcome};
pub use template::{template, templates, Template, TemplateField};

/// Current time in milliseconds since the Unix epoch (UTC).
pub fn now_ms() -> i64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_now()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }
}

#[cfg(target_arch = "wasm32")]
fn js_now() -> i64 {
    js_sys::Date::now() as i64
}

/// A new random ID for items, fields and the like (UUIDv7: time-ordered, so new
/// items sort naturally and IDs from different devices never collide).
pub fn new_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// A short random ID for fields, sections and other in-item entries.
pub fn new_short_id(prefix: &str) -> String {
    let u = uuid::Uuid::new_v4();
    format!("{prefix}_{}", &u.simple().to_string()[..12])
}
