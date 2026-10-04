//! Native encrypted export: lossless, opened with the master password and the
//! Secret Key, independent of the server.
//!
//! # File layout
//!
//! ```text
//! NYAPASSWORD-EXPORT\n                 magic line (19 bytes)
//! {"format":1,...}\n                   header: one line of compact UTF-8 JSON
//! <payload>                            binary, to end of file
//! ```
//!
//! Header fields:
//!
//! | key | value |
//! |---|---|
//! | `format` | `1` |
//! | `created_at` | UTC milliseconds |
//! | `export_id` | random UUID (hyphenated); bound into every AAD |
//! | `account_login` | the account's login name (shown before unlocking) |
//! | `kdf` | Argon2id parameters `{alg, m, t, p}` (same shape as the account's) |
//! | `salt` | 16 random bytes, base64url (a fresh salt per export) |
//! | `secret_key_required` | always `true` |
//! | `wrapped_key` | the export key EK sealed (npw-crypto envelope) under AUK |
//!
//! Keys:
//!
//! ```text
//! AUK = kdf::derive_master(password, Secret Key, salt, kdf).auk
//! wrapped_key = envelope::seal(AUK, EK, aad::export(export_id))
//! payload     = stream::encrypt(EK, aad::export(export_id) ‖ SHA-256(header line), JSON)
//! ```
//!
//! The payload AAD includes the SHA-256 of the exact header line bytes (without
//! the trailing `\n`), so changing any header byte (login, time, ...) makes the
//! payload fail authentication. The payload is the JSON document
//!
//! ```json
//! {"vaults":[{"name":"…","items":[{"content":{ItemContent},"deleted":false,
//!     "attachments":[{"meta":{Attachment},"data_b64":"…"}]}]}]}
//! ```
//!
//! with attachment bytes in base64url (no padding). No compression (pure Rust,
//! WASM-friendly, and avoids compression side channels). The header contains
//! nothing about the items: not even their number.

use npw_crypto::{aad, b64, envelope, kdf, stream, unb64, KdfParams, Key32, SecretKey};
use npw_model::{Attachment, ItemContent};
use serde::{Deserialize, Serialize};

use crate::{ExportError, ExportItem, ExportVault};

/// First line of every native export file (including the `\n`).
pub const MAGIC: &[u8] = b"NYAPASSWORD-EXPORT\n";
/// Current file format version.
pub const FORMAT: u32 = 1;
/// Suggested file extension.
pub const EXTENSION: &str = "npwexport";

const MAX_HEADER: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub format: u32,
    pub created_at: i64,
    pub export_id: String,
    pub account_login: String,
    pub kdf: KdfParams,
    pub salt: String,
    pub secret_key_required: bool,
    pub wrapped_key: String,
}

#[derive(Serialize)]
struct PayloadOut<'a> {
    vaults: Vec<VaultOut<'a>>,
}
#[derive(Serialize)]
struct VaultOut<'a> {
    name: &'a str,
    items: Vec<ItemOut<'a>>,
}
#[derive(Serialize)]
struct ItemOut<'a> {
    content: &'a ItemContent,
    deleted: bool,
    attachments: Vec<AttachmentOut<'a>>,
}
#[derive(Serialize)]
struct AttachmentOut<'a> {
    meta: &'a Attachment,
    data_b64: String,
}

#[derive(Deserialize)]
struct PayloadIn {
    vaults: Vec<VaultIn>,
}
#[derive(Deserialize)]
struct VaultIn {
    name: String,
    #[serde(default)]
    items: Vec<ItemIn>,
}
#[derive(Deserialize)]
struct ItemIn {
    content: ItemContent,
    #[serde(default)]
    deleted: bool,
    #[serde(default)]
    attachments: Vec<AttachmentIn>,
}
#[derive(Deserialize)]
struct AttachmentIn {
    meta: Attachment,
    data_b64: String,
}

fn payload_aad(export_id: &[u8; 16], header_line: &[u8]) -> Vec<u8> {
    let mut a = aad::export(export_id);
    a.extend_from_slice(&npw_crypto::sha256(header_line));
    a
}

/// Writes a native encrypted export.
///
/// `params` are normally the account's KDF parameters; they are not checked
/// against the minimums here (tests use `KdfParams::insecure_for_tests()`).
pub fn export_native(
    vaults: &[ExportVault],
    login: &str,
    password: &str,
    secret_key: &SecretKey,
    params: KdfParams,
) -> Result<Vec<u8>, ExportError> {
    let export_id = *uuid::Uuid::new_v4().as_bytes();
    let salt = npw_crypto::random_bytes::<16>();
    let master = kdf::derive_master(password, secret_key, &salt, &params)?;
    let ek = Key32::generate();
    let wrapped = envelope::wrap_key(&master.auk, &ek, &aad::export(&export_id));

    let header = Header {
        format: FORMAT,
        created_at: npw_model::now_ms(),
        export_id: uuid::Uuid::from_bytes(export_id).hyphenated().to_string(),
        account_login: login.to_string(),
        kdf: params,
        salt: b64(&salt),
        secret_key_required: true,
        wrapped_key: b64(&wrapped),
    };
    let header_line = serde_json::to_vec(&header)?;
    debug_assert!(!header_line.contains(&b'\n'));

    let payload = PayloadOut {
        vaults: vaults
            .iter()
            .map(|v| VaultOut {
                name: &v.name,
                items: v
                    .items
                    .iter()
                    .map(|it| ItemOut {
                        content: &it.content,
                        deleted: it.deleted,
                        attachments: it
                            .attachments
                            .iter()
                            .map(|(meta, data)| AttachmentOut {
                                meta,
                                data_b64: b64(data),
                            })
                            .collect(),
                    })
                    .collect(),
            })
            .collect(),
    };
    let mut json = serde_json::to_vec(&payload)?;
    let body = stream::encrypt(&ek, &payload_aad(&export_id, &header_line), &json);
    zeroize_vec(&mut json);

    let mut out = Vec::with_capacity(MAGIC.len() + header_line.len() + 1 + body.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&header_line);
    out.push(b'\n');
    out.extend_from_slice(&body);
    Ok(out)
}

/// Reads the header without decrypting anything (e.g. to show the account
/// login before asking for the password).
pub fn read_header(bytes: &[u8]) -> Result<Header, ExportError> {
    split(bytes).map(|(h, _, _)| h)
}

fn split(bytes: &[u8]) -> Result<(Header, &[u8], &[u8]), ExportError> {
    let rest = bytes.strip_prefix(MAGIC).ok_or(ExportError::NotAnExport)?;
    let end = rest
        .iter()
        .take(MAX_HEADER)
        .position(|&b| b == b'\n')
        .ok_or_else(|| ExportError::Malformed("header line not terminated".into()))?;
    let header_line = &rest[..end];
    let body = &rest[end + 1..];
    let header: Header = serde_json::from_slice(header_line)
        .map_err(|e| ExportError::Malformed(format!("header: {e}")))?;
    if header.format != FORMAT {
        return Err(ExportError::UnsupportedVersion(header.format));
    }
    Ok((header, header_line, body))
}

/// Opens a native export. A wrong password or Secret Key gives
/// [`ExportError::WrongPassword`]; a damaged or altered file gives
/// [`ExportError::Corrupted`] (or `WrongPassword` if the key-wrapping part was hit).
pub fn open_native(
    bytes: &[u8],
    password: &str,
    secret_key: &SecretKey,
) -> Result<Vec<ExportVault>, ExportError> {
    let (header, header_line, body) = split(bytes)?;
    let export_id = *uuid::Uuid::parse_str(&header.export_id)
        .map_err(|_| ExportError::Malformed("export_id".into()))?
        .as_bytes();
    let salt = unb64(&header.salt).ok_or_else(|| ExportError::Malformed("salt".into()))?;
    let wrapped =
        unb64(&header.wrapped_key).ok_or_else(|| ExportError::Malformed("wrapped_key".into()))?;
    let p = header.kdf;
    // Upper bounds only: refuse a file that would make us allocate gigabytes.
    if p.m > 1024 * 1024
        || p.t > 64
        || p.p > 16
        || p.m == 0
        || p.t == 0
        || p.p == 0
        || salt.len() < 16
    {
        return Err(ExportError::Malformed(
            "key derivation parameters out of range".into(),
        ));
    }

    let master = kdf::derive_master(password, secret_key, &salt, &p)?;
    let ek = envelope::unwrap_key(&master.auk, &wrapped, &aad::export(&export_id)).map_err(
        |e| match e {
            npw_crypto::CryptoError::Decrypt => ExportError::WrongPassword,
            other => ExportError::Crypto(other),
        },
    )?;
    // Any failure here (authentication, layout, version byte) means the payload
    // is not what was written: the key is right, so the file was altered.
    let mut json = stream::decrypt(&ek, &payload_aad(&export_id, header_line), body)
        .map_err(|_| ExportError::Corrupted)?;
    let parsed: Result<PayloadIn, _> = serde_json::from_slice(&json);
    zeroize_vec(&mut json);
    let payload = parsed.map_err(|e| ExportError::Malformed(format!("payload: {e}")))?;

    payload
        .vaults
        .into_iter()
        .map(|v| {
            let items = v
                .items
                .into_iter()
                .map(|it| {
                    let attachments = it
                        .attachments
                        .into_iter()
                        .map(|a| {
                            let data = if a.data_b64.is_empty() {
                                Vec::new()
                            } else {
                                unb64(&a.data_b64).ok_or_else(|| {
                                    ExportError::Malformed(format!("attachment {}", a.meta.id))
                                })?
                            };
                            Ok((a.meta, data))
                        })
                        .collect::<Result<Vec<_>, ExportError>>()?;
                    Ok(ExportItem {
                        content: it.content,
                        attachments,
                        deleted: it.deleted,
                    })
                })
                .collect::<Result<Vec<_>, ExportError>>()?;
            Ok(ExportVault {
                name: v.name,
                items,
            })
        })
        .collect()
}

/// Best-effort wipe of a plaintext buffer before it is freed.
fn zeroize_vec(v: &mut [u8]) {
    v.fill(0);
    std::hint::black_box(v);
}
