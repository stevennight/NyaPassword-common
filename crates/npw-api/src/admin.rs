//! The admin API (`/v1/admin/...`), used by the management console.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminLoginReq {
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSession {
    pub token: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    /// Aliyun OSS.
    Oss,
    Webdav,
    /// A directory on the server (e.g. a NAS mount); `endpoint` is the path.
    Fs,
}

/// A backup destination. Secrets are write-only: responses only say whether one is set.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BackupTarget {
    pub id: String,
    pub kind: TargetKind,
    pub name: String,
    pub enabled: bool,
    /// The credentials cannot delete (OSS write-only policy + retention):
    /// the server never prunes this target, bucket lifecycle rules do.
    #[serde(default)]
    pub protect_mode: bool,
    /// OSS: `https://oss-cn-hangzhou.aliyuncs.com`; WebDAV: the server URL; Fs: an absolute path.
    pub endpoint: String,
    /// OSS only.
    #[serde(default)]
    pub bucket: String,
    /// Directory inside the bucket / WebDAV server.
    #[serde(default)]
    pub root: String,
    /// OSS access key ID / WebDAV user name.
    #[serde(default)]
    pub username: String,
    /// OSS access key secret / WebDAV password. Only in requests; empty keeps the stored one.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret: String,
    #[serde(default)]
    pub has_secret: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Retention {
    pub recent: u32,
    pub daily: u32,
    pub weekly: u32,
    pub monthly: u32,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            recent: 48,
            daily: 30,
            weekly: 12,
            monthly: 24,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct NotifyConfig {
    #[serde(default)]
    pub webhook_url: String,
    #[serde(default)]
    pub telegram_bot_token: String,
    #[serde(default)]
    pub telegram_chat_id: String,
    #[serde(default)]
    pub bark_url: String,
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default)]
    pub smtp_port: u16,
    #[serde(default)]
    pub smtp_username: String,
    #[serde(default)]
    pub smtp_password: String,
    #[serde(default)]
    pub smtp_from: String,
    #[serde(default)]
    pub smtp_to: String,
}

/// Everything the backup page edits in one go.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BackupSettings {
    pub retention: Retention,
    /// age recipients (`age1...`) besides the server's own key. At least one
    /// offline key is strongly recommended (the Emergency Kit holds it).
    pub recipients: Vec<String>,
    /// Minutes to wait after the last change before backing up.
    pub debounce_minutes: u32,
    /// Daily backup time (UTC hour) even without changes.
    pub daily_hour_utc: u32,
    pub notify: NotifyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TargetResult {
    pub target_id: String,
    pub ok: bool,
    #[serde(default)]
    pub object: String,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BackupRun {
    pub id: String,
    pub started_at: i64,
    pub finished_at: i64,
    /// `change`, `daily`, `manual`
    pub trigger: String,
    pub size: i64,
    pub items: i64,
    pub max_seq: i64,
    pub results: Vec<TargetResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DrillRun {
    pub id: String,
    pub at: i64,
    pub target_id: String,
    pub object: String,
    pub ok: bool,
    pub detail: String,
    pub duration_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TargetStatus {
    pub target: BackupTarget,
    #[serde(default)]
    pub last_success_at: Option<i64>,
    #[serde(default)]
    pub last_attempt_at: Option<i64>,
    #[serde(default)]
    pub last_error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupStatus {
    pub settings: BackupSettings,
    pub server_recipient: String,
    pub targets: Vec<TargetStatus>,
    pub runs: Vec<BackupRun>,
    pub drills: Vec<DrillRun>,
    #[serde(default)]
    pub last_success_at: Option<i64>,
    /// When the user last confirmed a manual restore drill (offline key).
    #[serde(default)]
    pub last_manual_drill_at: Option<i64>,
    pub pending_changes: bool,
}

/// One backup object a target holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupObject {
    pub name: String,
    pub size: i64,
    pub modified_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Health {
    pub version: String,
    pub started_at: i64,
    pub db_ok: bool,
    pub integrity_checked_at: i64,
    pub accounts: i64,
    pub devices: i64,
    pub items: i64,
    pub revisions: i64,
    pub attachments: i64,
    pub attachment_bytes: i64,
    pub db_bytes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAccount {
    pub account_id: String,
    pub login: String,
    pub created_at: i64,
    pub items: i64,
    pub devices: Vec<super::DeviceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteReq {
    /// Hours until the invite expires.
    pub hours: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    pub code: String,
    pub expires_at: i64,
    #[serde(default)]
    pub used_at: Option<i64>,
}
