//! The NyaPassword HTTP API, version 1 (design doc §7, docs/API.md).
//!
//! JSON over HTTPS; binary values are base64url without padding; times are
//! milliseconds since the Unix epoch (UTC); IDs are UUID strings.
//!
//! Compatibility: within API major 1, requests and responses only gain
//! optional fields. New behaviour is switched on by the feature list in
//! [`ServerInfo`], never by comparing versions.

use serde::{Deserialize, Serialize};

pub use npw_crypto::KdfParams;

pub mod admin;

pub const API_MAJOR: u16 = 1;
pub const API_MINOR: u16 = 0;

/// Feature names a server can announce.
pub mod feature {
    pub const EVENTS: &str = "events";
    pub const ATTACHMENTS: &str = "attachments";
    pub const REVISIONS: &str = "revisions";
    pub const RECOVERY_CODE: &str = "recovery-code";
    pub const ATOMIC_BATCH: &str = "atomic-batch";
}

/// base64url without padding.
pub type B64 = String;

fn is_false(b: &bool) -> bool {
    !*b
}

// ---------------------------------------------------------------- errors

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

pub mod code {
    pub const UNAUTHORIZED: &str = "unauthorized";
    pub const FORBIDDEN: &str = "forbidden";
    pub const NOT_FOUND: &str = "not_found";
    pub const CONFLICT: &str = "conflict";
    pub const INVALID: &str = "invalid_request";
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const REGISTRATION_CLOSED: &str = "registration_closed";
    pub const LOGIN_FAILED: &str = "login_failed";
    pub const TOO_LARGE: &str = "too_large";
    pub const DEVICE_REVOKED: &str = "device_revoked";
    pub const SERVER: &str = "server_error";
}

// ---------------------------------------------------------------- server

/// `GET /v1/server-info`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    /// `MAJOR.MINOR`
    pub api: String,
    pub server_version: String,
    pub features: Vec<String>,
    pub registration_open: bool,
    /// Server clock, for TOTP clock-skew warnings.
    pub time: i64,
    /// Identifies the server's database. Changes when the server is restored
    /// from a backup, which makes clients reconcile everything (and re-upload
    /// what the server lost).
    #[serde(default)]
    pub epoch: String,
}

// ---------------------------------------------------------------- auth

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Reuse this device ID when the device logs in again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    /// `windows`, `macos`, `linux`, `android`, `chrome`, `web`, `cli`
    pub platform: String,
    pub client_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewVault {
    pub id: String,
    /// VK sealed under AK.
    pub wrapped_key: B64,
    /// Vault metadata JSON sealed under VK.
    pub encrypted_meta: B64,
}

/// `POST /v1/auth/register/start`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterStartReq {
    pub login: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite: Option<String>,
    pub account_id: String,
    pub opaque_request: B64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaqueResp {
    pub opaque_response: B64,
}

/// `POST /v1/auth/register/finish`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterFinishReq {
    pub login: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite: Option<String>,
    pub account_id: String,
    pub opaque_upload: B64,
    pub kdf: KdfParams,
    pub account_salt: B64,
    pub encrypted_account_key: B64,
    pub public_key: B64,
    pub encrypted_private_key: B64,
    pub vault: NewVault,
    pub device: DeviceInfo,
}

/// `POST /v1/auth/prelogin`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreloginReq {
    pub login: String,
}

/// Unknown logins get a consistent made-up answer, so this does not reveal which accounts exist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreloginResp {
    pub account_id: String,
    pub kdf: KdfParams,
    pub account_salt: B64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoginMethod {
    #[default]
    Password,
    RecoveryCode,
}

/// `POST /v1/auth/login/start`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginStartReq {
    pub login: String,
    #[serde(default)]
    pub method: LoginMethod,
    pub opaque_request: B64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginStartResp {
    pub login_id: String,
    pub opaque_response: B64,
}

/// `POST /v1/auth/login/finish`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFinishReq {
    pub login_id: String,
    pub opaque_finalization: B64,
    pub device: DeviceInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub account_id: String,
    pub device_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: i64,
}

/// `POST /v1/auth/refresh`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshReq {
    pub refresh_token: String,
}

/// `POST /v1/account/password/start` and `.../recovery/start`: a new OPAQUE registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReRegisterStartReq {
    pub opaque_request: B64,
}

/// `POST /v1/account/password/finish`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePasswordFinishReq {
    pub opaque_upload: B64,
    pub kdf: KdfParams,
    pub account_salt: B64,
    pub encrypted_account_key: B64,
}

/// `POST /v1/account/recovery/finish`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetRecoveryFinishReq {
    pub opaque_upload: B64,
    /// AK sealed under the recovery code's key.
    pub encrypted_account_key_recovery: B64,
}

// ---------------------------------------------------------------- account & vaults

/// `GET /v1/account`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountResp {
    pub account_id: String,
    pub login: String,
    pub kdf: KdfParams,
    pub account_salt: B64,
    pub encrypted_account_key: B64,
    pub public_key: B64,
    pub encrypted_private_key: B64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_account_key_recovery: Option<B64>,
    pub vaults: Vec<VaultInfo>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultInfo {
    pub id: String,
    pub wrapped_key: B64,
    pub encrypted_meta: B64,
    pub meta_revision: i64,
    /// Latest change sequence number in the vault.
    pub seq: i64,
    /// `owner` (v1); `member`, `reader` reserved for sharing.
    pub role: String,
    pub created_at: i64,
}

/// `POST /v1/vaults`
pub type CreateVaultReq = NewVault;

/// `PUT /v1/vaults/{id}/meta`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateVaultMetaReq {
    pub encrypted_meta: B64,
    pub base_revision: i64,
}

// ---------------------------------------------------------------- items

/// One revision of an item as stored by the server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ItemRecord {
    pub item_id: String,
    pub revision: i64,
    pub seq: i64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub deleted: bool,
    pub format_major: u16,
    /// IK sealed under VK.
    pub wrapped_key: B64,
    /// Item content sealed under IK.
    pub ciphertext: B64,
    /// hex SHA-256 of the decoded wrapped_key followed by the decoded ciphertext.
    pub hash: String,
    pub updated_at: i64,
    pub device_id: String,
}

/// `GET /v1/vaults/{id}/changes?since=<seq>&limit=<n>`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangesResp {
    /// The newest revision of every item changed after `since`, in `seq` order.
    pub items: Vec<ItemRecord>,
    pub next_seq: i64,
    pub has_more: bool,
    pub vault_seq: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PushItem {
    /// Client-chosen ID; retrying the same op is harmless.
    pub op_id: String,
    pub item_id: String,
    /// The revision this edit is based on; 0 creates the item.
    pub base_revision: i64,
    #[serde(default)]
    pub deleted: bool,
    pub format_major: u16,
    pub wrapped_key: B64,
    pub ciphertext: B64,
}

/// `POST /v1/vaults/{id}/items/batch`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushReq {
    pub items: Vec<PushItem>,
    /// All or nothing (imports).
    #[serde(default)]
    pub atomic: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PushStatus {
    Ok,
    /// `base_revision` is not the current revision: pull, merge, retry.
    Conflict,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PushResult {
    pub op_id: String,
    pub item_id: String,
    pub status: PushStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_revision: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushResp {
    pub results: Vec<PushResult>,
    pub vault_seq: i64,
}

/// `GET /v1/vaults/{id}/digest`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DigestResp {
    /// See [`vault_digest`].
    pub digest: String,
    pub count: i64,
    pub vault_seq: i64,
}

/// The vault digest both sides compute: hex SHA-256 over every item, sorted by
/// item ID, of `item_id ‖ 0x00 ‖ revision (8 bytes BE) ‖ deleted (1 byte) ‖ hash (hex ASCII)`.
pub fn vault_digest<'a>(items: impl IntoIterator<Item = (&'a str, i64, bool, &'a str)>) -> String {
    let mut v: Vec<(&str, i64, bool, &str)> = items.into_iter().collect();
    v.sort_by(|a, b| a.0.cmp(b.0));
    let mut buf = Vec::with_capacity(v.len() * 110);
    for (id, rev, deleted, hash) in v {
        buf.extend_from_slice(id.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&rev.to_be_bytes());
        buf.push(deleted as u8);
        buf.extend_from_slice(hash.as_bytes());
    }
    npw_crypto::sha256_hex(&buf)
}

/// The item hash: hex SHA-256 of `wrapped_key ‖ ciphertext` (decoded bytes).
pub fn item_hash(wrapped_key: &[u8], ciphertext: &[u8]) -> String {
    let mut buf = Vec::with_capacity(wrapped_key.len() + ciphertext.len());
    buf.extend_from_slice(wrapped_key);
    buf.extend_from_slice(ciphertext);
    npw_crypto::sha256_hex(&buf)
}

/// `GET /v1/vaults/{id}/items/{item}/revisions`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevisionInfo {
    pub revision: i64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub deleted: bool,
    pub created_at: i64,
    pub device_id: String,
    pub size: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevisionsResp {
    pub revisions: Vec<RevisionInfo>,
}

/// `POST /v1/vaults/{id}/purge`: permanently deletes items that are in the trash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurgeReq {
    pub item_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurgeResp {
    pub purged: Vec<String>,
}

/// `PUT /v1/vaults/{v}/attachments/{id}` (body: the encrypted blob) answers this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentInfo {
    pub id: String,
    pub size: i64,
    pub sha256: String,
}

// ---------------------------------------------------------------- devices, audit, events

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub client_version: String,
    pub created_at: i64,
    pub last_seen_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<i64>,
    #[serde(default)]
    pub current: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub at: i64,
    pub action: String,
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub detail: String,
}

/// Messages on the WebSocket `GET /v1/events`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    VaultChanged { vault_id: String, seq: i64 },
    AccountChanged,
    DeviceRevoked { device_id: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_order_independent() {
        let a = vault_digest([("b", 2, false, "h2"), ("a", 1, true, "h1")]);
        let b = vault_digest([("a", 1, true, "h1"), ("b", 2, false, "h2")]);
        assert_eq!(a, b);
        assert_ne!(a, vault_digest([("a", 1, false, "h1"), ("b", 2, false, "h2")]));
    }

    #[test]
    fn event_json() {
        let e = Event::VaultChanged { vault_id: "v".into(), seq: 3 };
        assert_eq!(serde_json::to_string(&e).unwrap(), r#"{"kind":"vault_changed","vault_id":"v","seq":3}"#);
    }
}
