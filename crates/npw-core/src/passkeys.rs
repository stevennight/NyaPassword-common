//! Passkeys stored in items (design doc §5.2, §10.4, §10.5). The browser
//! extension, Android's credential provider and the desktop app all go through
//! these functions, so a passkey created on one client works on every other.
//!
//! Callers must have verified the user (master password, biometrics) before
//! calling create / get: the authenticator data always carries the UV flag.

use npw_model::{ItemContent, Passkey, UrlEntry};
use npw_passkey::{CreateRequest, CredentialDescriptor, GetRequest, PasskeyError};
use serde::{Deserialize, Serialize};

use crate::client::Client;
use crate::{CoreError, Result};

/// Who is asking.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PasskeyCaller {
    /// A web page; the origin comes from the browser, never from the page.
    Web { origin: String },
    /// An Android app verified against the RP's Digital Asset Links: `android:apk-key-hash:...`.
    AndroidApp { origin: String },
    /// A privileged caller (an Android browser) that supplies clientDataHash and checked the origin itself.
    ClientDataHash { hash: String },
}

/// A passkey that can answer a request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PasskeyCandidate {
    pub vault_id: String,
    pub item_id: String,
    pub passkey_id: String,
    pub title: String,
    pub rp_id: String,
    pub user_name: String,
    pub user_display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyCreated {
    pub vault_id: String,
    pub item_id: String,
    /// The PublicKeyCredential JSON for the page / app.
    pub response: serde_json::Value,
}

fn perr(e: PasskeyError) -> CoreError {
    CoreError::Invalid(format!("passkey:{}:{e}", e.dom_exception_name()))
}

fn hash32(b64: &str) -> Result<[u8; 32]> {
    let v = npw_passkey::b64url_decode(b64)
        .ok_or_else(|| CoreError::Invalid("bad clientDataHash".into()))?;
    v.try_into()
        .map_err(|_| CoreError::Invalid("clientDataHash must be 32 bytes".into()))
}

/// The RP ID a request is for, as the caller may use it.
fn rp_id_for(caller: &PasskeyCaller, requested: Option<&str>) -> Result<String> {
    match caller {
        PasskeyCaller::Web { origin } => {
            let o = npw_passkey::parse_origin(origin).map_err(perr)?;
            npw_passkey::effective_rp_id(requested, &o).map_err(perr)
        }
        _ => requested
            .map(|r| r.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|r| !r.is_empty())
            .ok_or_else(|| CoreError::Invalid("rp id is required".into())),
    }
}

impl Client {
    fn all_passkeys(&self) -> Result<Vec<(String, String, String, Passkey)>> {
        let st = self.state.lock().expect("state");
        if st.keys.is_none() {
            return Err(CoreError::Locked);
        }
        Ok(st
            .cache
            .items
            .values()
            .filter(|c| !c.deleted)
            .flat_map(|c| {
                c.content.passkeys.iter().map(move |p| {
                    (
                        c.vault_id.clone(),
                        c.item_id.clone(),
                        c.content.title.clone(),
                        p.clone(),
                    )
                })
            })
            .collect())
    }

    /// Passkeys that can answer a `navigator.credentials.get` request.
    pub fn passkey_candidates(
        &self,
        caller: &PasskeyCaller,
        request_json: &str,
    ) -> Result<Vec<PasskeyCandidate>> {
        let req: GetRequest =
            serde_json::from_str(request_json).map_err(|e| CoreError::Invalid(e.to_string()))?;
        let rp_id = rp_id_for(caller, req.rp_id.as_deref())?;
        let all = self.all_passkeys()?;
        let chosen = npw_passkey::matching(
            all.iter().map(|(_, _, _, p)| p),
            &rp_id,
            &req.allow_credentials,
        );
        Ok(all
            .iter()
            .filter(|(_, _, _, p)| {
                chosen
                    .iter()
                    .any(|c| c.id == p.id && c.credential_id == p.credential_id)
            })
            .map(|(v, i, t, p)| PasskeyCandidate {
                vault_id: v.clone(),
                item_id: i.clone(),
                passkey_id: p.id.clone(),
                title: t.clone(),
                rp_id: p.rp_id.clone(),
                user_name: p.user_name.clone(),
                user_display_name: p.user_display_name.clone(),
            })
            .collect())
    }

    /// Creates a passkey and stores it: in `target` (vault, item) when given,
    /// otherwise in a new login item in `vault_id`. Saved locally first,
    /// pushed by the next sync.
    pub fn passkey_create(
        &self,
        caller: &PasskeyCaller,
        request_json: &str,
        target: Option<(&str, &str)>,
        vault_id: &str,
    ) -> Result<PasskeyCreated> {
        let req: CreateRequest =
            serde_json::from_str(request_json).map_err(|e| CoreError::Invalid(e.to_string()))?;
        let rp_id = rp_id_for(caller, req.rp.id.as_deref())?;
        let all = self.all_passkeys()?;
        npw_passkey::check_excluded(&req, &rp_id, all.iter().map(|(_, _, _, p)| p))
            .map_err(perr)?;
        let (mut passkey, response) = match caller {
            PasskeyCaller::Web { origin } => npw_passkey::create(&req, origin),
            PasskeyCaller::AndroidApp { origin } => {
                npw_passkey::create_for_android_app(&req, origin)
            }
            PasskeyCaller::ClientDataHash { hash } => {
                npw_passkey::create_with_client_data_hash(&req, &hash32(hash)?)
            }
        }
        .map_err(perr)?;
        passkey.id = npw_model::new_short_id("pk");
        passkey.created_at = npw_model::now_ms();

        let (vault, item_id) = match target {
            Some((v, i)) => {
                let mut content = self.item(v, i)?.content.ok_or(CoreError::NotFound)?;
                content.passkeys.push(passkey);
                self.save_item(v, Some(i), content)?;
                (v.to_string(), i.to_string())
            }
            None => {
                let mut content: ItemContent = npw_model::template("login")
                    .expect("login template")
                    .new_item(&self.cfg.locale);
                content.title = if req.rp.name.trim().is_empty() {
                    rp_id.clone()
                } else {
                    req.rp.name.clone()
                };
                if let Some(f) = content.field_mut("username") {
                    f.value = req.user.name.clone().into();
                }
                content.urls.push(UrlEntry::new(format!("https://{rp_id}")));
                content.passkeys.push(passkey);
                let id = self.save_item(vault_id, None, content)?;
                (vault_id.to_string(), id)
            }
        };
        Ok(PasskeyCreated {
            vault_id: vault,
            item_id,
            response: serde_json::to_value(&response)
                .map_err(|e| CoreError::Invalid(e.to_string()))?,
        })
    }

    /// Signs a `get` request with one stored passkey. Returns the PublicKeyCredential JSON.
    pub fn passkey_get(
        &self,
        caller: &PasskeyCaller,
        request_json: &str,
        vault_id: &str,
        item_id: &str,
        passkey_id: &str,
    ) -> Result<serde_json::Value> {
        let req: GetRequest =
            serde_json::from_str(request_json).map_err(|e| CoreError::Invalid(e.to_string()))?;
        let mut content = self
            .item(vault_id, item_id)?
            .content
            .ok_or(CoreError::NotFound)?;
        let pk = content
            .passkeys
            .iter_mut()
            .find(|p| p.id == passkey_id)
            .ok_or(CoreError::NotFound)?;
        let before = pk.counter;
        let response = match caller {
            PasskeyCaller::Web { origin } => npw_passkey::get(&req, origin, pk),
            PasskeyCaller::AndroidApp { origin } => {
                npw_passkey::get_for_android_app(&req, origin, pk)
            }
            PasskeyCaller::ClientDataHash { hash } => {
                npw_passkey::get_with_client_data_hash(&req, &hash32(hash)?, pk)
            }
        }
        .map_err(perr)?;
        if pk.counter != before {
            self.save_item(vault_id, Some(item_id), content)?;
        }
        serde_json::to_value(&response).map_err(|e| CoreError::Invalid(e.to_string()))
    }
}

/// The candidates' allow-list helper for hosts that already parsed requests.
pub fn allow_list(request_json: &str) -> Vec<CredentialDescriptor> {
    serde_json::from_str::<GetRequest>(request_json)
        .map(|r| r.allow_credentials)
        .unwrap_or_default()
}
