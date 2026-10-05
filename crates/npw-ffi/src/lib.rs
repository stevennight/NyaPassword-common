//! The client core for native apps, through UniFFI (Android now; iOS / macOS
//! native later). One [`NpwClient`] per account on a device, over a SQLite
//! replica (ciphertext and non-secret metadata only).
//!
//! The surface is deliberately small and forward-compatible: structured
//! values (item views, item content, reports, filters) cross the boundary as
//! JSON strings in the same shapes the WASM build (`npw-wasm`) hands to
//! JavaScript. Hosts must edit item content as a JSON tree and send it back
//! whole, so keys added by newer clients survive (the core keeps unknown keys
//! too, see `npw-model`).
//!
//! Every call blocks; hosts call from a background thread. Network calls run
//! on the client's own tokio runtime. Errors carry the stable
//! [`CoreError::code`] (`locked`, `wrong_password`, `network`, ...); passkey
//! errors are `invalid` with a message `passkey:<DOMException name>:<text>`.

use std::path::PathBuf;
use std::sync::Arc;

use npw_core::passkeys::PasskeyCaller;
use npw_core::{Client, ClientConfig, CoreError, ItemFilter};
use npw_crypto::Key32;
use npw_model::{ItemContent, UrlEntry};
use npw_store_sqlite::SqliteStore;
use serde::de::DeserializeOwned;
use serde::Serialize;

uniffi::setup_scaffolding!();

/// An error from the core: `code` is stable (see `CoreError::code`), `detail` is for logs.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum NpwError {
    #[error("{code}: {detail}")]
    Core { code: String, detail: String },
}

impl From<CoreError> for NpwError {
    fn from(e: CoreError) -> Self {
        NpwError::Core {
            code: e.code().to_string(),
            detail: e.to_string(),
        }
    }
}

fn invalid(msg: impl std::fmt::Display) -> NpwError {
    NpwError::Core {
        code: "invalid".into(),
        detail: msg.to_string(),
    }
}

type Res<T> = Result<T, NpwError>;

fn to_json<T: Serialize>(v: &T) -> Res<String> {
    serde_json::to_string(v).map_err(invalid)
}

fn from_json<T: DeserializeOwned>(s: &str) -> Res<T> {
    serde_json::from_str(s).map_err(invalid)
}

/// The scheme Android apps are stored under in item URLs.
pub const ANDROID_APP_SCHEME: &str = "androidapp://";

/// Normalizes a certificate fingerprint to lower-case hex without separators
/// (`AB:CD:..` and `abcd..` compare equal).
pub fn normalize_cert(c: &str) -> String {
    c.chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

/// Whether an app with signing certificates `certs` may use an item that
/// matched `androidapp://<package>`: if any of the item's entries for that
/// package records certificates, one of the app's must be among them
/// (another app installed under the same package name is not offered the
/// login). Entries without certificates accept any signer (older items,
/// imports).
pub fn app_cert_allowed(urls: &[UrlEntry], package: &str, certs: &[String]) -> bool {
    let pinned: Vec<String> = urls
        .iter()
        .filter(|u| app_package(&u.url).as_deref() == Some(package))
        .flat_map(|u| u.cert_sha256.iter().map(|c| normalize_cert(c)))
        .filter(|c| !c.is_empty())
        .collect();
    if pinned.is_empty() {
        return true;
    }
    certs
        .iter()
        .map(|c| normalize_cert(c))
        .any(|c| pinned.contains(&c))
}

fn app_package(url: &str) -> Option<String> {
    match npw_match::parse(url) {
        Some(npw_match::Target::App { package }) => Some(package),
        _ => None,
    }
}

/// Adds `androidapp://<package>` with the app's signing certificate to an
/// item's URLs (or the certificate to an existing entry for that package).
/// Returns whether anything changed.
pub fn link_app_url(content: &mut ItemContent, package: &str, cert_sha256: &str) -> bool {
    let cert = normalize_cert(cert_sha256);
    if let Some(u) = content
        .urls
        .iter_mut()
        .find(|u| app_package(&u.url).as_deref() == Some(package))
    {
        if cert.is_empty() || u.cert_sha256.iter().any(|c| normalize_cert(c) == cert) {
            return false;
        }
        u.cert_sha256.push(cert);
        return true;
    }
    let mut u = UrlEntry::new(format!("{ANDROID_APP_SCHEME}{package}"));
    u.match_mode = npw_model::item::match_mode::EXACT.to_string();
    if !cert.is_empty() {
        u.cert_sha256.push(cert);
    }
    content.urls.push(u);
    true
}

#[derive(uniffi::Object)]
pub struct NpwClient {
    inner: Arc<Client>,
    rt: tokio::runtime::Runtime,
}

impl NpwClient {
    fn block<F: std::future::Future>(&self, f: F) -> F::Output {
        self.rt.block_on(f)
    }

    fn caller(json: &str) -> Res<PasskeyCaller> {
        from_json(json)
    }
}

#[uniffi::export]
impl NpwClient {
    /// Opens (or creates) the replica at `db_path`. `device_key`: 32 bytes the
    /// host keeps in the OS key store; it seals the Secret Key and the session.
    #[uniffi::constructor]
    pub fn new(
        db_path: String,
        device_key: Vec<u8>,
        device_name: String,
        client_version: String,
        locale: String,
    ) -> Res<Arc<Self>> {
        let store = Arc::new(SqliteStore::open(&PathBuf::from(db_path))?);
        let mut cfg = ClientConfig::new(&device_name, "android", &client_version);
        cfg.locale = locale;
        let key =
            Key32::from_slice(&device_key).map_err(|_| invalid("device key must be 32 bytes"))?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("npw-core")
            .enable_all()
            .build()
            .map_err(invalid)?;
        let client = {
            // reqwest wants a runtime context when its client is built
            let _g = rt.enter();
            Client::new(cfg, store, key)?
        };
        Ok(Arc::new(Self {
            inner: Arc::new(client),
            rt,
        }))
    }

    // ------------------------------------------------------------ account and unlock

    /// `LockState` JSON: `{signed_in, unlocked, login, server_url, account_id, device_id, last_sync_at}`.
    pub fn lock_state(&self) -> Res<String> {
        to_json(&self.inner.lock_state())
    }

    pub fn is_unlocked(&self) -> bool {
        self.inner.is_unlocked()
    }

    /// Creates an account, signs in and unlocks. Returns the `EmergencyKit` JSON.
    pub fn register(
        &self,
        server_url: String,
        login: String,
        password: String,
        invite: Option<String>,
    ) -> Res<String> {
        let kit =
            self.block(
                self.inner
                    .register(&server_url, &login, &password, invite.as_deref()),
            )?;
        to_json(&kit)
    }

    /// Signs this device in (needs the Secret Key once) and unlocks.
    pub fn sign_in(
        &self,
        server_url: String,
        login: String,
        password: String,
        secret_key: String,
    ) -> Res<()> {
        Ok(self.block(
            self.inner
                .sign_in(&server_url, &login, &password, &secret_key),
        )?)
    }

    /// Unlocks with the master password (works offline).
    pub fn unlock(&self, password: String) -> Res<()> {
        Ok(self.inner.unlock(&password)?)
    }

    /// Checks the master password without changing the lock state (user verification).
    pub fn verify_password(&self, password: String) -> Res<()> {
        self.inner.verify_password(&password)?;
        Ok(())
    }

    /// The key a host may keep behind biometrics. Only while unlocked.
    pub fn quick_unlock_key(&self) -> Res<Vec<u8>> {
        Ok(self.inner.quick_unlock_key()?)
    }

    pub fn unlock_with_key(&self, key: Vec<u8>) -> Res<()> {
        Ok(self.inner.unlock_with_key(&key)?)
    }

    /// Checks a key from [`NpwClient::quick_unlock_key`] (released by biometrics)
    /// without changing the lock state: user verification before using an item
    /// marked `reprompt`. Only while unlocked.
    pub fn verify_key(&self, key: Vec<u8>) -> Res<()> {
        Ok(self.inner.verify_key(&key)?)
    }

    /// Forgets all keys and decrypted data.
    pub fn lock(&self) {
        self.inner.lock();
    }

    /// Removes the account from this device; refuses while edits are unsynced unless `force`.
    pub fn sign_out(&self, force: bool) -> Res<()> {
        Ok(self.block(self.inner.sign_out(force))?)
    }

    pub fn emergency_kit(&self) -> Res<String> {
        to_json(&self.inner.emergency_kit()?)
    }

    pub fn change_password(&self, current: String, new_password: String) -> Res<()> {
        Ok(self.block(self.inner.change_password(&current, &new_password))?)
    }

    /// `DeviceRecord[]` JSON.
    pub fn devices(&self) -> Res<String> {
        to_json(&self.block(self.inner.devices())?)
    }

    pub fn revoke_device(&self, device_id: String) -> Res<()> {
        Ok(self.block(self.inner.revoke_device(&device_id))?)
    }

    /// `AuditEntry[]` JSON.
    pub fn audit_log(&self) -> Res<String> {
        to_json(&self.block(self.inner.audit_log())?)
    }

    /// `ServerInfo` JSON.
    pub fn server_info(&self) -> Res<String> {
        to_json(&self.block(self.inner.server_info())?)
    }

    // ------------------------------------------------------------ sync

    /// Pull, merge, push. `SyncReport` JSON.
    pub fn sync(&self) -> Res<String> {
        to_json(&self.block(self.inner.sync())?)
    }

    /// A short-lived token for the events WebSocket (`wss://<server>/v1/events?token=`).
    pub fn events_token(&self) -> Res<String> {
        Ok(self.block(self.inner.events_token())?)
    }

    /// `[conflicts, pending, rejected]` JSON.
    pub fn attention(&self) -> Res<String> {
        to_json(&self.inner.attention()?)
    }

    // ------------------------------------------------------------ vaults and items

    /// `VaultView[]` JSON.
    pub fn vaults(&self) -> Res<String> {
        to_json(&self.inner.vaults()?)
    }

    pub fn create_vault(&self, name: String) -> Res<String> {
        Ok(self.block(self.inner.create_vault(&name))?)
    }

    pub fn rename_vault(&self, vault_id: String, name: String) -> Res<()> {
        Ok(self.block(self.inner.rename_vault(&vault_id, &name))?)
    }

    /// `ItemView[]` JSON (without content). `filter_json`: an `ItemFilter` (`{}` = all).
    pub fn list_items(&self, filter_json: String) -> Res<String> {
        let f: ItemFilter = if filter_json.trim().is_empty() {
            ItemFilter::default()
        } else {
            from_json(&filter_json)?
        };
        to_json(&self.inner.list_items(&f)?)
    }

    /// `ItemView` JSON with `content`.
    pub fn item(&self, vault_id: String, item_id: String) -> Res<String> {
        to_json(&self.inner.item(&vault_id, &item_id)?)
    }

    /// Tags in use, sorted. JSON array.
    pub fn tags(&self) -> Res<String> {
        to_json(&self.inner.tags()?)
    }

    /// A new, unsaved item of a template (`ItemContent` JSON).
    pub fn new_item(&self, template: String) -> Res<String> {
        let t = npw_model::template(&template).ok_or_else(|| invalid("unknown template"))?;
        to_json(&t.new_item(&self.inner.config().locale))
    }

    /// Creates (`item_id` = null) or updates an item from `ItemContent` JSON. Returns the item id.
    pub fn save_item(
        &self,
        vault_id: String,
        item_id: Option<String>,
        content_json: String,
    ) -> Res<String> {
        let c: ItemContent = from_json(&content_json)?;
        Ok(self.inner.save_item(&vault_id, item_id.as_deref(), c)?)
    }

    /// Moves an item to the trash.
    pub fn delete_item(&self, vault_id: String, item_id: String) -> Res<()> {
        Ok(self.inner.delete_item(&vault_id, &item_id)?)
    }

    pub fn restore_item(&self, vault_id: String, item_id: String) -> Res<()> {
        Ok(self.inner.restore_item(&vault_id, &item_id)?)
    }

    /// Permanently deletes items in the trash (online). Returns the purged ids.
    pub fn purge(&self, vault_id: String, item_ids: Vec<String>) -> Res<Vec<String>> {
        Ok(self.block(self.inner.purge(&vault_id, &item_ids))?)
    }

    pub fn resolve_conflict(
        &self,
        vault_id: String,
        item_id: String,
        conflict_id: String,
        use_conflict_value: bool,
    ) -> Res<()> {
        Ok(self
            .inner
            .resolve_conflict(&vault_id, &item_id, &conflict_id, use_conflict_value)?)
    }

    /// `RevisionInfo[]` JSON, newest first (online).
    pub fn item_history(&self, vault_id: String, item_id: String) -> Res<String> {
        to_json(&self.block(self.inner.item_history(&vault_id, &item_id))?)
    }

    /// `ItemContent` JSON of one revision (online).
    pub fn item_revision(&self, vault_id: String, item_id: String, revision: i64) -> Res<String> {
        to_json(&self.block(self.inner.item_revision(&vault_id, &item_id, revision))?)
    }

    pub fn restore_revision(&self, vault_id: String, item_id: String, revision: i64) -> Res<()> {
        Ok(self.block(self.inner.restore_revision(&vault_id, &item_id, revision))?)
    }

    /// Encrypts and uploads a file and adds it to the item. Returns the attachment id.
    pub fn add_attachment(
        &self,
        vault_id: String,
        item_id: String,
        name: String,
        mime: String,
        data: Vec<u8>,
    ) -> Res<String> {
        Ok(self.block(
            self.inner
                .add_attachment(&vault_id, &item_id, &name, &mime, &data),
        )?)
    }

    /// Decrypted attachment content (downloaded once, then cached encrypted).
    pub fn attachment(
        &self,
        vault_id: String,
        item_id: String,
        attachment_id: String,
    ) -> Res<Vec<u8>> {
        Ok(self.block(self.inner.attachment(&vault_id, &item_id, &attachment_id))?)
    }

    pub fn remove_attachment(
        &self,
        vault_id: String,
        item_id: String,
        attachment_id: String,
    ) -> Res<()> {
        Ok(self
            .inner
            .remove_attachment(&vault_id, &item_id, &attachment_id)?)
    }

    /// `SecurityReport` JSON.
    pub fn security_report(&self) -> Res<String> {
        to_json(&self.inner.security_report()?)
    }

    /// `HealthReport` JSON.
    pub fn health_check(&self) -> Res<String> {
        to_json(&self.inner.health_check()?)
    }

    // ------------------------------------------------------------ autofill

    /// Items whose URLs match `target` (a URL, a host, or `androidapp://<package>`),
    /// best first; `ItemView[]` JSON. For an app target, `app_certs` are the
    /// calling app's signing certificates (SHA-256 hex): items that pinned
    /// other certificates for that package are left out.
    pub fn autofill_candidates(&self, target: String, app_certs: Vec<String>) -> Res<String> {
        let mut views = self.inner.autofill_candidates(&target)?;
        if let Some(package) = app_package(&target) {
            views.retain(|v| {
                self.inner
                    .item(&v.vault_id, &v.item_id)
                    .ok()
                    .and_then(|full| full.content)
                    .is_some_and(|c| app_cert_allowed(&c.urls, &package, &app_certs))
            });
        }
        to_json(&views)
    }

    /// Remembers that an app uses an item: adds `androidapp://<package>` with
    /// the app's signing certificate (SHA-256 hex). Saved locally, synced next.
    pub fn link_app(
        &self,
        vault_id: String,
        item_id: String,
        package: String,
        cert_sha256: String,
    ) -> Res<bool> {
        let mut c = self
            .inner
            .item(&vault_id, &item_id)?
            .content
            .ok_or(CoreError::NotFound)?;
        if !link_app_url(&mut c, &package, &cert_sha256) {
            return Ok(false);
        }
        self.inner.save_item(&vault_id, Some(&item_id), c)?;
        Ok(true)
    }

    // ------------------------------------------------------------ passkeys

    /// Passkeys that can answer a get request (`PasskeyCandidate[]` JSON).
    /// `caller_json`: `{"kind":"web","origin":..}` | `{"kind":"android_app","origin":"android:apk-key-hash:.."}`
    /// | `{"kind":"client_data_hash","hash":<base64url>}`.
    pub fn passkey_candidates(&self, caller_json: String, request_json: String) -> Res<String> {
        let caller = Self::caller(&caller_json)?;
        to_json(&self.inner.passkey_candidates(&caller, &request_json)?)
    }

    /// Creates a passkey and stores it in the target item (when both ids are
    /// given) or in a new login in `vault_id`. Returns `PasskeyCreated` JSON
    /// (`{vault_id, item_id, response}`; `response` is the PublicKeyCredential JSON).
    /// The host must have verified the user first.
    pub fn passkey_create(
        &self,
        caller_json: String,
        request_json: String,
        target_vault_id: Option<String>,
        target_item_id: Option<String>,
        vault_id: String,
    ) -> Res<String> {
        let caller = Self::caller(&caller_json)?;
        let target = match (&target_vault_id, &target_item_id) {
            (Some(v), Some(i)) => Some((v.as_str(), i.as_str())),
            _ => None,
        };
        to_json(
            &self
                .inner
                .passkey_create(&caller, &request_json, target, &vault_id)?,
        )
    }

    /// Signs a get request with one stored passkey. Returns the PublicKeyCredential JSON.
    /// The host must have verified the user first.
    pub fn passkey_get(
        &self,
        caller_json: String,
        request_json: String,
        vault_id: String,
        item_id: String,
        passkey_id: String,
    ) -> Res<String> {
        let caller = Self::caller(&caller_json)?;
        to_json(&self.inner.passkey_get(
            &caller,
            &request_json,
            &vault_id,
            &item_id,
            &passkey_id,
        )?)
    }
}

// ------------------------------------------------------------------ free functions

/// Current code of an `otpauth://` URI or base32 secret:
/// `{code, remaining, period, issuer, account}` JSON.
#[uniffi::export]
pub fn otp_code(uri: String, unix_secs: i64) -> Res<String> {
    let spec = npw_otp::OtpSpec::parse(&uri).map_err(invalid)?;
    let t = unix_secs.max(0) as u64;
    to_json(&serde_json::json!({
        "code": spec.code(t),
        "remaining": spec.remaining(t),
        "period": spec.period,
        "issuer": spec.issuer,
        "account": spec.account,
    }))
}

/// Generates a password from a `Recipe` JSON (empty = default). `{password, bits}` JSON.
#[uniffi::export]
pub fn generate(recipe_json: String) -> Res<String> {
    let r: npw_core::generator::Recipe = if recipe_json.trim().is_empty() {
        Default::default()
    } else {
        from_json(&recipe_json)?
    };
    to_json(&npw_core::generator::generate(&r))
}

/// 0 (very weak) to 4 (very strong).
#[uniffi::export]
pub fn password_strength(password: String) -> u8 {
    npw_core::generator::strength(&password)
}

/// All templates with their fields, labelled for `locale` (JSON, same shape as npw-wasm).
#[uniffi::export]
pub fn templates(locale: String) -> Res<String> {
    let list: Vec<serde_json::Value> = npw_model::templates()
        .iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id,
                "label": t.label(&locale),
                "icon": t.icon,
                "fields": t.fields.iter().map(|f| serde_json::json!({
                    "id": f.id, "kind": f.kind, "purpose": f.purpose,
                    "multiline": f.multiline, "label": f.label(&locale),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    to_json(&list)
}

/// Field presets for "add field" (`Field[]` JSON).
#[uniffi::export]
pub fn field_presets(locale: String) -> Res<String> {
    let list: Vec<_> = npw_model::template::EXTRA_FIELD_PRESETS
        .iter()
        .map(|f| f.to_field(&locale))
        .collect();
    to_json(&list)
}

/// A short random id for fields, sections, URLs (`f_…`, `s_…`, `u_…`).
#[uniffi::export]
pub fn new_short_id(prefix: String) -> String {
    npw_model::new_short_id(&prefix)
}

/// The host (or package) shown for a URL.
#[uniffi::export]
pub fn display_host(url: String) -> String {
    npw_match::display_host(&url)
}

/// Parses a Secret Key, returning its canonical text form (fails on typos).
#[uniffi::export]
pub fn normalize_secret_key(text: String) -> Res<String> {
    npw_crypto::SecretKey::parse(&text)
        .map(|k| k.to_text())
        .map_err(|e| CoreError::from(e).into())
}

/// 32 random bytes from the OS (device keys).
#[uniffi::export]
pub fn random_key() -> Vec<u8> {
    npw_crypto::random_bytes::<32>().to_vec()
}

/// Whether a web origin (from a privileged browser) may use `rp_id`
/// (WebAuthn: the RP ID must be the origin's host or a registrable parent).
#[uniffi::export]
pub fn passkey_origin_allows_rp(origin: String, rp_id: String) -> bool {
    npw_passkey::parse_origin(&origin)
        .and_then(|o| npw_passkey::effective_rp_id(Some(&rp_id), &o))
        .is_ok()
}

/// The npw-ffi crate version (the common revision the app was built with is in its about page).
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg(test)]
mod tests;
