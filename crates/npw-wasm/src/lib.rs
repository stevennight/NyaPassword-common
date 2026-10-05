//! The client core for JavaScript. One `NpwClient` per account on a device;
//! the replica lives in memory and the host persists [`NpwClient::snapshot`]
//! (ciphertext only) in IndexedDB / storage. Errors are thrown as
//! `{code, message}` objects (codes from `CoreError::code`).

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use npw_core::{Client, ClientConfig, CoreError, ItemFilter, MemoryStore};
use npw_crypto::Key32;
use npw_model::ItemContent;
use serde::Serialize;
use wasm_bindgen::prelude::*;

fn js_err(e: CoreError) -> JsValue {
    let o = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&o, &"code".into(), &e.code().into());
    let _ = js_sys::Reflect::set(&o, &"message".into(), &e.to_string().into());
    o.into()
}

fn bad(msg: impl std::fmt::Display) -> JsValue {
    js_err(CoreError::Invalid(msg.to_string()))
}

fn to_js<T: Serialize>(v: &T) -> Result<JsValue, JsValue> {
    v.serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(bad)
}

fn from_js<T: serde::de::DeserializeOwned>(v: JsValue) -> Result<T, JsValue> {
    serde_wasm_bindgen::from_value(v).map_err(bad)
}

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub struct NpwClient {
    inner: Rc<Client>,
    store: Arc<MemoryStore>,
    /// Parsed imports waiting for the user's confirmation, by token.
    imports: Rc<RefCell<HashMap<String, (String, npw_import::ImportResult)>>>,
}

#[wasm_bindgen]
impl NpwClient {
    /// `device_key`: 32 random bytes the host keeps for this browser profile.
    /// `snapshot`: a previous [`NpwClient::snapshot`], or empty for a new device.
    #[wasm_bindgen(constructor)]
    pub fn new(
        device_name: &str,
        platform: &str,
        version: &str,
        locale: &str,
        device_key: &[u8],
        snapshot: &[u8],
    ) -> Result<NpwClient, JsValue> {
        let store = Arc::new(if snapshot.is_empty() {
            MemoryStore::new()
        } else {
            MemoryStore::from_snapshot(snapshot).map_err(js_err)?
        });
        let mut cfg = ClientConfig::new(device_name, platform, version);
        cfg.locale = locale.to_string();
        let key = Key32::from_slice(device_key).map_err(|_| bad("device key must be 32 bytes"))?;
        let client = Client::new(cfg, store.clone(), key).map_err(js_err)?;
        Ok(NpwClient {
            inner: Rc::new(client),
            store,
            imports: Default::default(),
        })
    }

    /// The replica as bytes (ciphertext and non-secret metadata only).
    pub fn snapshot(&self) -> Vec<u8> {
        self.store.snapshot()
    }

    /// Increases on every change of the replica; persist the snapshot when it moves.
    pub fn generation(&self) -> f64 {
        self.store.generation() as f64
    }

    #[wasm_bindgen(js_name = lockState)]
    pub fn lock_state(&self) -> Result<JsValue, JsValue> {
        to_js(&self.inner.lock_state())
    }

    pub async fn register(
        &self,
        server: String,
        login: String,
        password: String,
        invite: Option<String>,
    ) -> Result<JsValue, JsValue> {
        let c = self.inner.clone();
        to_js(
            &c.register(&server, &login, &password, invite.as_deref())
                .await
                .map_err(js_err)?,
        )
    }

    #[wasm_bindgen(js_name = signIn)]
    pub async fn sign_in(
        &self,
        server: String,
        login: String,
        password: String,
        secret_key: String,
    ) -> Result<(), JsValue> {
        let c = self.inner.clone();
        c.sign_in(&server, &login, &password, &secret_key)
            .await
            .map_err(js_err)
    }

    pub fn unlock(&self, password: &str) -> Result<(), JsValue> {
        self.inner.unlock(password).map_err(js_err)
    }

    #[wasm_bindgen(js_name = quickUnlockKey)]
    pub fn quick_unlock_key(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.quick_unlock_key().map_err(js_err)
    }

    #[wasm_bindgen(js_name = unlockWithKey)]
    pub fn unlock_with_key(&self, key: &[u8]) -> Result<(), JsValue> {
        self.inner.unlock_with_key(key).map_err(js_err)
    }

    /// Checks the master password without changing the lock state (user
    /// verification before using an item marked `reprompt`).
    #[wasm_bindgen(js_name = verifyPassword)]
    pub fn verify_password(&self, password: &str) -> Result<(), JsValue> {
        self.inner
            .verify_password(password)
            .map(drop)
            .map_err(js_err)
    }

    /// Checks a key from [`NpwClient::quick_unlock_key`] without changing the
    /// lock state. Only while unlocked.
    #[wasm_bindgen(js_name = verifyKey)]
    pub fn verify_key(&self, key: &[u8]) -> Result<(), JsValue> {
        self.inner.verify_key(key).map_err(js_err)
    }

    pub fn lock(&self) {
        self.inner.lock();
    }

    #[wasm_bindgen(js_name = signOut)]
    pub async fn sign_out(&self, force: bool) -> Result<(), JsValue> {
        let c = self.inner.clone();
        c.sign_out(force).await.map_err(js_err)
    }

    #[wasm_bindgen(js_name = emergencyKit)]
    pub fn emergency_kit(&self) -> Result<JsValue, JsValue> {
        to_js(&self.inner.emergency_kit().map_err(js_err)?)
    }

    pub async fn sync(&self) -> Result<JsValue, JsValue> {
        let c = self.inner.clone();
        to_js(&c.sync().await.map_err(js_err)?)
    }

    #[wasm_bindgen(js_name = eventsToken)]
    pub async fn events_token(&self) -> Result<String, JsValue> {
        let c = self.inner.clone();
        c.events_token().await.map_err(js_err)
    }

    pub fn vaults(&self) -> Result<JsValue, JsValue> {
        to_js(&self.inner.vaults().map_err(js_err)?)
    }

    #[wasm_bindgen(js_name = createVault)]
    pub async fn create_vault(&self, name: String) -> Result<String, JsValue> {
        let c = self.inner.clone();
        c.create_vault(&name).await.map_err(js_err)
    }

    #[wasm_bindgen(js_name = renameVault)]
    pub async fn rename_vault(&self, vault_id: String, name: String) -> Result<(), JsValue> {
        let c = self.inner.clone();
        c.rename_vault(&vault_id, &name).await.map_err(js_err)
    }

    #[wasm_bindgen(js_name = listItems)]
    pub fn list_items(&self, filter: JsValue) -> Result<JsValue, JsValue> {
        let f: ItemFilter = if filter.is_undefined() || filter.is_null() {
            ItemFilter::default()
        } else {
            from_js(filter)?
        };
        to_js(&self.inner.list_items(&f).map_err(js_err)?)
    }

    pub fn item(&self, vault_id: &str, item_id: &str) -> Result<JsValue, JsValue> {
        to_js(&self.inner.item(vault_id, item_id).map_err(js_err)?)
    }

    pub fn tags(&self) -> Result<JsValue, JsValue> {
        to_js(&self.inner.tags().map_err(js_err)?)
    }

    /// A new item of a template (not saved).
    #[wasm_bindgen(js_name = newItem)]
    pub fn new_item(&self, template: &str, locale: &str) -> Result<JsValue, JsValue> {
        let t = npw_model::template(template).ok_or_else(|| bad("unknown template"))?;
        to_js(&t.new_item(locale))
    }

    #[wasm_bindgen(js_name = saveItem)]
    pub fn save_item(
        &self,
        vault_id: &str,
        item_id: Option<String>,
        content: JsValue,
    ) -> Result<String, JsValue> {
        let c: ItemContent = from_js(content)?;
        self.inner
            .save_item(vault_id, item_id.as_deref(), c)
            .map_err(js_err)
    }

    #[wasm_bindgen(js_name = deleteItem)]
    pub fn delete_item(&self, vault_id: &str, item_id: &str) -> Result<(), JsValue> {
        self.inner.delete_item(vault_id, item_id).map_err(js_err)
    }

    #[wasm_bindgen(js_name = restoreItem)]
    pub fn restore_item(&self, vault_id: &str, item_id: &str) -> Result<(), JsValue> {
        self.inner.restore_item(vault_id, item_id).map_err(js_err)
    }

    #[wasm_bindgen(js_name = resolveConflict)]
    pub fn resolve_conflict(
        &self,
        vault_id: &str,
        item_id: &str,
        conflict_id: &str,
        use_conflict_value: bool,
    ) -> Result<(), JsValue> {
        self.inner
            .resolve_conflict(vault_id, item_id, conflict_id, use_conflict_value)
            .map_err(js_err)
    }

    pub fn attention(&self) -> Result<JsValue, JsValue> {
        to_js(&self.inner.attention().map_err(js_err)?)
    }

    #[wasm_bindgen(js_name = autofillCandidates)]
    pub fn autofill_candidates(&self, target: &str) -> Result<JsValue, JsValue> {
        to_js(&self.inner.autofill_candidates(target).map_err(js_err)?)
    }

    /// `caller`: `{kind: "web", origin}` — the origin as the browser reported it for the frame.
    #[wasm_bindgen(js_name = passkeyCandidates)]
    pub fn passkey_candidates(
        &self,
        caller: JsValue,
        request_json: &str,
    ) -> Result<JsValue, JsValue> {
        let caller: npw_core::passkeys::PasskeyCaller = from_js(caller)?;
        to_js(
            &self
                .inner
                .passkey_candidates(&caller, request_json)
                .map_err(js_err)?,
        )
    }

    #[wasm_bindgen(js_name = passkeyCreate)]
    pub fn passkey_create(
        &self,
        caller: JsValue,
        request_json: &str,
        target_vault: Option<String>,
        target_item: Option<String>,
        vault_id: &str,
    ) -> Result<JsValue, JsValue> {
        let caller: npw_core::passkeys::PasskeyCaller = from_js(caller)?;
        let target = match (&target_vault, &target_item) {
            (Some(v), Some(i)) => Some((v.as_str(), i.as_str())),
            _ => None,
        };
        to_js(
            &self
                .inner
                .passkey_create(&caller, request_json, target, vault_id)
                .map_err(js_err)?,
        )
    }

    #[wasm_bindgen(js_name = passkeyGet)]
    pub fn passkey_get(
        &self,
        caller: JsValue,
        request_json: &str,
        vault_id: &str,
        item_id: &str,
        passkey_id: &str,
    ) -> Result<JsValue, JsValue> {
        let caller: npw_core::passkeys::PasskeyCaller = from_js(caller)?;
        to_js(
            &self
                .inner
                .passkey_get(&caller, request_json, vault_id, item_id, passkey_id)
                .map_err(js_err)?,
        )
    }

    #[wasm_bindgen(js_name = itemHistory)]
    pub async fn item_history(
        &self,
        vault_id: String,
        item_id: String,
    ) -> Result<JsValue, JsValue> {
        let c = self.inner.clone();
        to_js(&c.item_history(&vault_id, &item_id).await.map_err(js_err)?)
    }

    #[wasm_bindgen(js_name = itemRevision)]
    pub async fn item_revision(
        &self,
        vault_id: String,
        item_id: String,
        revision: f64,
    ) -> Result<JsValue, JsValue> {
        let c = self.inner.clone();
        to_js(
            &c.item_revision(&vault_id, &item_id, revision as i64)
                .await
                .map_err(js_err)?,
        )
    }

    #[wasm_bindgen(js_name = restoreRevision)]
    pub async fn restore_revision(
        &self,
        vault_id: String,
        item_id: String,
        revision: f64,
    ) -> Result<(), JsValue> {
        let c = self.inner.clone();
        c.restore_revision(&vault_id, &item_id, revision as i64)
            .await
            .map_err(js_err)
    }

    pub async fn purge(&self, vault_id: String, item_ids: JsValue) -> Result<JsValue, JsValue> {
        let ids: Vec<String> = from_js(item_ids)?;
        let c = self.inner.clone();
        to_js(&c.purge(&vault_id, &ids).await.map_err(js_err)?)
    }

    #[wasm_bindgen(js_name = addAttachment)]
    pub async fn add_attachment(
        &self,
        vault_id: String,
        item_id: String,
        name: String,
        mime: String,
        data: Vec<u8>,
    ) -> Result<String, JsValue> {
        let c = self.inner.clone();
        c.add_attachment(&vault_id, &item_id, &name, &mime, &data)
            .await
            .map_err(js_err)
    }

    pub async fn attachment(
        &self,
        vault_id: String,
        item_id: String,
        attachment_id: String,
    ) -> Result<Vec<u8>, JsValue> {
        let c = self.inner.clone();
        c.attachment(&vault_id, &item_id, &attachment_id)
            .await
            .map_err(js_err)
    }

    #[wasm_bindgen(js_name = removeAttachment)]
    pub fn remove_attachment(
        &self,
        vault_id: &str,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<(), JsValue> {
        self.inner
            .remove_attachment(vault_id, item_id, attachment_id)
            .map_err(js_err)
    }

    /// Imports already-parsed items (an array of item contents) atomically.
    #[wasm_bindgen(js_name = importItems)]
    pub async fn import_items(
        &self,
        vault_id: String,
        items: JsValue,
        source: String,
    ) -> Result<JsValue, JsValue> {
        let items: Vec<ItemContent> = from_js(items)?;
        let c = self.inner.clone();
        to_js(
            &c.import_items(&vault_id, items, &source)
                .await
                .map_err(js_err)?,
        )
    }

    /// Parses an export file of another manager; returns a preview with a `token` for [`Self::import_commit`].
    #[wasm_bindgen(js_name = importParse)]
    pub fn import_parse(
        &self,
        file_name: &str,
        data: &[u8],
        password: Option<String>,
        locale: &str,
    ) -> Result<JsValue, JsValue> {
        let (source, parsed) =
            npw_core::transfer::parse_import(file_name, data, password.as_deref(), locale)
                .map_err(js_err)?;
        let preview = npw_core::transfer::preview(&source, &parsed);
        let token = npw_model::new_id();
        self.imports
            .borrow_mut()
            .insert(token.clone(), (source, parsed));
        let mut v = serde_json::to_value(&preview).map_err(bad)?;
        v["token"] = token.into();
        to_js(&v)
    }

    #[wasm_bindgen(js_name = importCommit)]
    pub async fn import_commit(&self, token: String, vault_id: String) -> Result<JsValue, JsValue> {
        let (source, parsed) = self
            .imports
            .borrow_mut()
            .remove(&token)
            .ok_or_else(|| bad("this import expired; choose the file again"))?;
        let c = self.inner.clone();
        to_js(
            &c.import_parsed(&vault_id, parsed, &source.to_lowercase())
                .await
                .map_err(js_err)?,
        )
    }

    /// `native`, `kdbx` or `csv`; needs the master password.
    #[wasm_bindgen(js_name = exportVault)]
    pub async fn export_vault(&self, format: String, password: String) -> Result<Vec<u8>, JsValue> {
        let c = self.inner.clone();
        c.export_vault(&format, &password).await.map_err(js_err)
    }

    #[wasm_bindgen(js_name = importBatches)]
    pub fn import_batches(&self) -> Result<JsValue, JsValue> {
        to_js(&self.inner.import_batches().map_err(js_err)?)
    }

    #[wasm_bindgen(js_name = undoImport)]
    pub fn undo_import(&self, batch_id: &str) -> Result<u32, JsValue> {
        self.inner
            .undo_import(batch_id)
            .map(|n| n as u32)
            .map_err(js_err)
    }

    #[wasm_bindgen(js_name = exportItems)]
    pub fn export_items(&self) -> Result<JsValue, JsValue> {
        to_js(&self.inner.export_items().map_err(js_err)?)
    }

    #[wasm_bindgen(js_name = securityReport)]
    pub fn security_report(&self) -> Result<JsValue, JsValue> {
        to_js(&self.inner.security_report().map_err(js_err)?)
    }

    #[wasm_bindgen(js_name = healthCheck)]
    pub fn health_check(&self) -> Result<JsValue, JsValue> {
        to_js(&self.inner.health_check().map_err(js_err)?)
    }

    #[wasm_bindgen(js_name = changePassword)]
    pub async fn change_password(
        &self,
        current: String,
        new_password: String,
    ) -> Result<(), JsValue> {
        let c = self.inner.clone();
        c.change_password(&current, &new_password)
            .await
            .map_err(js_err)
    }

    pub async fn devices(&self) -> Result<JsValue, JsValue> {
        let c = self.inner.clone();
        to_js(&c.devices().await.map_err(js_err)?)
    }

    #[wasm_bindgen(js_name = revokeDevice)]
    pub async fn revoke_device(&self, device_id: String) -> Result<(), JsValue> {
        let c = self.inner.clone();
        c.revoke_device(&device_id).await.map_err(js_err)
    }

    #[wasm_bindgen(js_name = auditLog)]
    pub async fn audit_log(&self) -> Result<JsValue, JsValue> {
        let c = self.inner.clone();
        to_js(&c.audit_log().await.map_err(js_err)?)
    }

    #[wasm_bindgen(js_name = serverInfo)]
    pub async fn server_info(&self) -> Result<JsValue, JsValue> {
        let c = self.inner.clone();
        to_js(&c.server_info().await.map_err(js_err)?)
    }
}

// ------------------------------------------------------------------ free functions

/// Current code of an `otpauth://` URI or base32 secret: `{code, remaining, period}`.
#[wasm_bindgen(js_name = otpCode)]
pub fn otp_code(uri: &str, unix_secs: f64) -> Result<JsValue, JsValue> {
    let spec = npw_otp::OtpSpec::parse(uri).map_err(bad)?;
    let t = unix_secs as u64;
    to_js(
        &serde_json::json!({ "code": spec.code(t), "remaining": spec.remaining(t), "period": spec.period, "issuer": spec.issuer, "account": spec.account }),
    )
}

/// Generates a password from a recipe (see npw_core::generator::Recipe).
#[wasm_bindgen]
pub fn generate(recipe: JsValue) -> Result<JsValue, JsValue> {
    let r: npw_core::generator::Recipe = if recipe.is_undefined() {
        Default::default()
    } else {
        from_js(recipe)?
    };
    to_js(&npw_core::generator::generate(&r))
}

/// 0 (very weak) to 4 (very strong).
#[wasm_bindgen(js_name = passwordStrength)]
pub fn password_strength(password: &str) -> u8 {
    npw_core::generator::strength(password)
}

/// All templates with their fields, labelled for `locale`.
#[wasm_bindgen]
pub fn templates(locale: &str) -> Result<JsValue, JsValue> {
    let list: Vec<serde_json::Value> = npw_model::templates()
        .iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id,
                "label": t.label(locale),
                "icon": t.icon,
                "fields": t.fields.iter().map(|f| serde_json::json!({"id": f.id, "kind": f.kind, "purpose": f.purpose, "multiline": f.multiline, "label": f.label(locale)})).collect::<Vec<_>>(),
            })
        })
        .collect();
    to_js(&list)
}

/// Field presets for "add field" (recovery codes and the like).
#[wasm_bindgen(js_name = fieldPresets)]
pub fn field_presets(locale: &str) -> Result<JsValue, JsValue> {
    let list: Vec<_> = npw_model::template::EXTRA_FIELD_PRESETS
        .iter()
        .map(|f| f.to_field(locale))
        .collect();
    to_js(&list)
}

#[wasm_bindgen(js_name = newShortId)]
pub fn new_short_id(prefix: &str) -> String {
    npw_model::new_short_id(prefix)
}

/// The host shown for a URL.
#[wasm_bindgen(js_name = displayHost)]
pub fn display_host(url: &str) -> String {
    npw_match::display_host(url)
}

/// The site (registrable domain) of a URL; equal sites may share prompts and fills.
#[wasm_bindgen(js_name = siteOf)]
pub fn site_of(url: &str) -> String {
    npw_match::site(url)
}

/// Parses a Secret Key, returning its canonical text form (throws on typos).
#[wasm_bindgen(js_name = normalizeSecretKey)]
pub fn normalize_secret_key(text: &str) -> Result<String, JsValue> {
    npw_crypto::SecretKey::parse(text)
        .map(|k| k.to_text())
        .map_err(|e| js_err(e.into()))
}

/// 32 random bytes (device keys).
#[wasm_bindgen(js_name = randomKey)]
pub fn random_key() -> Vec<u8> {
    npw_crypto::random_bytes::<32>().to_vec()
}
