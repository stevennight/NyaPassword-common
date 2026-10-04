//! The NyaPassword client core, shared by every client (desktop via Tauri,
//! Android via UniFFI, the extension and the web vault via WASM).
//!
//! - [`Client`]: registration, login, unlock / lock, the decrypted item cache,
//!   item edits (always local first, then synced), sync, attachments, history.
//! - [`store`]: the local replica (ciphertext only).
//! - [`transport`]: HTTP.
//! - [`search`], [`generator`], [`security`]: search with pinyin, password
//!   generator, security report.

mod api;
pub mod client;
pub mod generator;
pub mod health;
mod items;
mod remote;
pub mod search;
pub mod security;
pub mod store;
mod sync;
pub mod transport;

pub use client::{AccountSummary, Client, ClientConfig, EmergencyKit, ItemView, LockState, VaultView};
pub use health::HealthReport;
pub use items::ItemFilter;
pub use remote::{ImportResult, IMPORT_KEY};
pub use security::{Finding, Issue, SecurityReport};
pub use store::{LocalItem, MemoryStore, PendingEdit, Store, StoreOp};
pub use sync::SyncReport;
pub use transport::{HttpRequest, HttpResponse, Transport};

pub use npw_crypto::{Key32, SecretKey};
pub use npw_model as model;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("locked")]
    Locked,
    #[error("not signed in on this device")]
    NotSignedIn,
    #[error("wrong master password or Secret Key")]
    WrongPassword,
    #[error("session expired, sign in again")]
    SessionExpired,
    #[error("this device was removed from the account")]
    DeviceRevoked,
    #[error("network error: {0}")]
    Network(String),
    #[error("server error {status} {code}: {message}")]
    Api { status: u16, code: String, message: String },
    #[error("cryptography error: {0}")]
    Crypto(#[from] npw_crypto::CryptoError),
    #[error("local storage error: {0}")]
    Store(String),
    #[error("{0}")]
    Invalid(String),
    #[error("item was written by a newer version of NyaPassword; update this app to edit it")]
    ReadOnly,
    #[error("not found")]
    NotFound,
    #[error("needs a connection to the server")]
    Offline,
}

impl CoreError {
    /// Stable machine-readable code for hosts (UI messages are localized there).
    pub fn code(&self) -> &'static str {
        match self {
            CoreError::Locked => "locked",
            CoreError::NotSignedIn => "not_signed_in",
            CoreError::WrongPassword => "wrong_password",
            CoreError::SessionExpired => "session_expired",
            CoreError::DeviceRevoked => "device_revoked",
            CoreError::Network(_) => "network",
            CoreError::Api { .. } => "api",
            CoreError::Crypto(_) => "crypto",
            CoreError::Store(_) => "store",
            CoreError::Invalid(_) => "invalid",
            CoreError::ReadOnly => "read_only",
            CoreError::NotFound => "not_found",
            CoreError::Offline => "offline",
        }
    }
}

pub type Result<T> = std::result::Result<T, CoreError>;
