//! NyaPassword exports (design doc §8.6, §9.3; file format in `docs/导出格式.md`).
//!
//! - [`native`]: the native encrypted export. Lossless: every item, field,
//!   unknown key, passkey, history entry and attachment comes back exactly.
//!   Opening it needs the master password **and** the Secret Key.
//! - [`kdbx`]: KDBX 4, opens directly in KeePassXC (TOTP, passkeys, attachments,
//!   SSH keys and every template's fields included). Lossy in structure only:
//!   sections become label prefixes, NyaPassword-only settings are dropped.
//! - [`csv_export`]: **plaintext** CSV for spreadsheets and other managers.
//!
//! The library does no file I/O (it also builds for `wasm32-unknown-unknown`):
//! callers pass decrypted vaults in and get bytes out.

pub mod csv_export;
pub mod kdbx;
mod mapping;
pub mod native;

pub use csv_export::export_csv;
pub use kdbx::{export_kdbx, export_kdbx_with, KdbxOptions};
pub use native::{export_native, open_native};

use npw_model::{Attachment, ItemContent};

/// One vault to export, already decrypted.
#[derive(Debug, Clone, PartialEq)]
pub struct ExportVault {
    pub name: String,
    pub items: Vec<ExportItem>,
}

/// One item: its decrypted content and the plaintext of its attachments.
#[derive(Debug, Clone, PartialEq)]
pub struct ExportItem {
    pub content: ItemContent,
    /// Attachment metadata (normally the matching entry of `content.attachments`)
    /// and the decrypted bytes.
    pub attachments: Vec<(Attachment, Vec<u8>)>,
    /// The item is in the recycle bin.
    pub deleted: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// Wrong master password or wrong Secret Key (the two cannot be told apart),
    /// or the key-wrapping part of the header was altered.
    #[error("wrong master password or Secret Key")]
    WrongPassword,
    #[error("not a NyaPassword export file")]
    NotAnExport,
    #[error("unsupported export format version {0}")]
    UnsupportedVersion(u32),
    /// The payload failed authentication: the file was damaged or tampered with.
    #[error("the export file is damaged or has been tampered with")]
    Corrupted,
    #[error("malformed export file: {0}")]
    Malformed(String),
    #[error("cryptography error: {0}")]
    Crypto(#[from] npw_crypto::CryptoError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("KDBX error: {0}")]
    Kdbx(String),
}
