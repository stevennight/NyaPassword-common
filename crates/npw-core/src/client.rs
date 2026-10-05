//! The client: account state, keys, sessions. Item operations live in
//! `items.rs`, sync in `sync.rs`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use npw_api as api_t;
use npw_crypto::{
    aad, b64, envelope, kdf, opaque, unb64, AccountKeyPair, KdfParams, Key32, SecretKey,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::api::{self, is_unauthorized};
use crate::items::Cache;
use crate::store::{Store, StoreOp};
use crate::transport::Transport;
use crate::{CoreError, Result};

pub(crate) const META_ACCOUNT: &str = "account";
pub(crate) const META_SECRET_KEY: &str = "secret_key";
pub(crate) const META_SESSION: &str = "session";
/// How long signing out waits for the server to acknowledge the logout.
const SIGN_OUT_TIMEOUT_MS: u32 = 5_000;

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub device_name: String,
    /// `windows`, `macos`, `linux`, `android`, `chrome`, `web`, `cli`
    pub platform: String,
    pub client_version: String,
    /// `zh-CN`, `en`: labels of new template fields.
    pub locale: String,
    /// Accept key-derivation parameters below the minimum. Tests only.
    pub allow_weak_kdf: bool,
    /// KDF parameters for new accounts (tests use tiny ones).
    pub new_account_kdf: KdfParams,
}

impl ClientConfig {
    pub fn new(device_name: &str, platform: &str, client_version: &str) -> Self {
        Self {
            device_name: device_name.into(),
            platform: platform.into(),
            client_version: client_version.into(),
            locale: "zh-CN".into(),
            allow_weak_kdf: false,
            new_account_kdf: KdfParams::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct VaultState {
    pub id: String,
    pub wrapped_key: String,
    pub encrypted_meta: String,
    pub meta_revision: i64,
    pub role: String,
    /// Changes up to this sequence number are in the replica.
    pub seq: i64,
    pub created_at: i64,
    /// The server stopped listing this vault. Its local copy (with unsynced
    /// edits) is kept, never cleared, and it is not synced until it is back.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub missing_on_server: bool,
}

/// What unlocks the account key offline: AK wrapped under AUK, and the KDF
/// parameters and salt that derive AUK from the master password.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct UnlockMaterial {
    pub kdf: KdfParams,
    pub account_salt: String,
    pub encrypted_account_key: String,
}

/// Non-secret account data persisted on the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AccountState {
    pub server_url: String,
    pub login: String,
    pub account_id: String,
    pub device_id: String,
    pub kdf: KdfParams,
    pub account_salt: String,
    pub encrypted_account_key: String,
    pub public_key: String,
    pub encrypted_private_key: String,
    pub vaults: Vec<VaultState>,
    /// The server's database epoch: changes when the server is restored from a backup.
    #[serde(default)]
    pub epoch: String,
    #[serde(default)]
    pub last_sync_at: i64,
    /// The unlock material in use before the server announced a different one
    /// (a password change on another device). Offline unlock tries the current
    /// material, then this one, so a server that sends garbage cannot lock this
    /// device out. Dropped once the current material has unlocked this device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_unlock: Option<UnlockMaterial>,
    /// The current material came from the server and has not unlocked this device yet.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unlock_unverified: bool,
}

impl AccountState {
    pub(crate) fn unlock_material(&self) -> UnlockMaterial {
        UnlockMaterial {
            kdf: self.kdf,
            account_salt: self.account_salt.clone(),
            encrypted_account_key: self.encrypted_account_key.clone(),
        }
    }

    fn set_unlock_material(&mut self, m: UnlockMaterial) {
        self.kdf = m.kdf;
        self.account_salt = m.account_salt;
        self.encrypted_account_key = m.encrypted_account_key;
    }
}

/// What [`Client::apply_account_resp`] kept from the local state instead of
/// taking the server's word.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct AccountUpdate {
    /// Vaults the server no longer lists (kept locally, not synced).
    pub missing_vaults: usize,
    /// The server's unlock material failed validation and was not adopted.
    pub unlock_refused: bool,
}

pub(crate) struct Keyring {
    pub ak: Key32,
    /// The OPAQUE login key, kept while unlocked with the password so an expired session can be renewed silently.
    pub login: Option<Key32>,
    pub vault_keys: HashMap<String, Key32>,
}

pub(crate) struct State {
    pub account: Option<AccountState>,
    pub session: Option<api_t::Session>,
    pub keys: Option<Keyring>,
    pub cache: Cache,
}

type TransportFactory = Box<dyn Fn(&str) -> Result<Arc<dyn Transport>> + Send + Sync>;

pub struct Client {
    pub(crate) cfg: ClientConfig,
    pub(crate) store: Arc<dyn Store>,
    device_key: Key32,
    transport: RwLock<Option<Arc<dyn Transport>>>,
    factory: TransportFactory,
    pub(crate) state: Mutex<State>,
    pub(crate) sync_lock: async_lock::Mutex<()>,
}

/// What the user must keep: shown once after registration, printable as the Emergency Kit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyKit {
    pub server_url: String,
    pub login: String,
    pub account_id: String,
    pub secret_key: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LockState {
    pub signed_in: bool,
    pub unlocked: bool,
    pub login: String,
    pub server_url: String,
    pub account_id: String,
    pub device_id: String,
    pub last_sync_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountSummary {
    pub login: String,
    pub server_url: String,
    pub account_id: String,
    pub vaults: Vec<VaultView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultView {
    pub id: String,
    pub name: String,
    pub role: String,
    pub items: usize,
}

/// Vault metadata, sealed under the vault key.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct VaultMeta {
    pub name: String,
    #[serde(default)]
    pub icon: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

pub use crate::items::ItemView;

pub(crate) fn uuid_bytes(id: &str) -> Result<[u8; 16]> {
    uuid::Uuid::parse_str(id)
        .map(|u| *u.as_bytes())
        .map_err(|_| CoreError::Invalid(format!("bad id {id}")))
}

pub(crate) fn d64(s: &str) -> Result<Vec<u8>> {
    unb64(s).ok_or_else(|| CoreError::Invalid("bad base64".into()))
}

fn json<T: Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).expect("serializable")
}

impl Client {
    /// Opens the client over a local store. `device_key` protects the Secret
    /// Key and the session on this device; hosts keep it in the OS key store
    /// (DPAPI, Android Keystore, ...).
    pub fn new(cfg: ClientConfig, store: Arc<dyn Store>, device_key: Key32) -> Result<Self> {
        #[cfg(feature = "http")]
        let factory: TransportFactory = Box::new(|url| {
            Ok(Arc::new(crate::transport::ReqwestTransport::new(url)?) as Arc<dyn Transport>)
        });
        #[cfg(not(feature = "http"))]
        let factory: TransportFactory =
            Box::new(|_| Err(CoreError::Invalid("no HTTP transport configured".into())));
        Self::with_transport_factory(cfg, store, device_key, factory)
    }

    pub fn with_transport_factory(
        cfg: ClientConfig,
        store: Arc<dyn Store>,
        device_key: Key32,
        factory: TransportFactory,
    ) -> Result<Self> {
        let account: Option<AccountState> = match store.get_meta(META_ACCOUNT)? {
            Some(b) => Some(
                serde_json::from_slice(&b)
                    .map_err(|e| CoreError::Store(format!("account state: {e}")))?,
            ),
            None => None,
        };
        let client = Self {
            cfg,
            store,
            device_key,
            transport: RwLock::new(None),
            factory,
            state: Mutex::new(State {
                account: None,
                session: None,
                keys: None,
                cache: Cache::default(),
            }),
            sync_lock: async_lock::Mutex::new(()),
        };
        if let Some(acc) = account {
            *client.transport.write().expect("lock") = Some((client.factory)(&acc.server_url)?);
            let session = client.load_sealed::<api_t::Session>(META_SESSION)?;
            let mut st = client.state.lock().expect("state");
            st.account = Some(acc);
            st.session = session;
        }
        Ok(client)
    }

    pub fn config(&self) -> &ClientConfig {
        &self.cfg
    }

    pub(crate) fn transport(&self) -> Result<Arc<dyn Transport>> {
        self.transport
            .read()
            .expect("lock")
            .clone()
            .ok_or(CoreError::NotSignedIn)
    }

    fn seal_device(&self, name: &str, data: &[u8]) -> Vec<u8> {
        envelope::seal(&self.device_key, data, &aad::device_secret(name))
    }

    fn load_sealed<T: for<'de> Deserialize<'de>>(&self, name: &str) -> Result<Option<T>> {
        match self.store.get_meta(name)? {
            None => Ok(None),
            Some(b) => {
                let mut plain = envelope::open(&self.device_key, &b, &aad::device_secret(name))
                    .map_err(|_| CoreError::Store(format!("{name}: wrong device key")))?;
                let v = serde_json::from_slice(&plain).map_err(|e| CoreError::Store(e.to_string()));
                plain.zeroize();
                v.map(Some)
            }
        }
    }

    pub(crate) fn secret_key(&self) -> Result<SecretKey> {
        let b = self
            .store
            .get_meta(META_SECRET_KEY)?
            .ok_or(CoreError::NotSignedIn)?;
        let mut raw = envelope::open(&self.device_key, &b, &aad::device_secret(META_SECRET_KEY))
            .map_err(|_| CoreError::Store("secret key: wrong device key".into()))?;
        let arr: [u8; 16] = raw
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::Store("secret key length".into()))?;
        raw.zeroize();
        Ok(SecretKey::from_raw(arr))
    }

    pub(crate) fn account(&self) -> Result<AccountState> {
        self.state
            .lock()
            .expect("state")
            .account
            .clone()
            .ok_or(CoreError::NotSignedIn)
    }

    pub(crate) fn persist_account(&self, acc: &AccountState) -> Result<StoreOp> {
        Ok(StoreOp::PutMeta(META_ACCOUNT.into(), json(acc)))
    }

    pub(crate) fn save_account(&self, acc: AccountState) -> Result<()> {
        self.store.apply(vec![self.persist_account(&acc)?])?;
        self.state.lock().expect("state").account = Some(acc);
        Ok(())
    }

    fn save_session(&self, s: &api_t::Session) -> Result<()> {
        self.store.apply(vec![StoreOp::PutMeta(
            META_SESSION.into(),
            self.seal_device(META_SESSION, &json(s)),
        )])?;
        self.state.lock().expect("state").session = Some(s.clone());
        Ok(())
    }

    fn check_kdf(&self, p: &KdfParams) -> Result<()> {
        if self.cfg.allow_weak_kdf {
            return Ok(());
        }
        p.validate().map_err(CoreError::from)
    }

    fn device_info(&self, id: Option<String>) -> api_t::DeviceInfo {
        api_t::DeviceInfo {
            id,
            name: self.cfg.device_name.clone(),
            platform: self.cfg.platform.clone(),
            client_version: self.cfg.client_version.clone(),
        }
    }

    // ------------------------------------------------------------ status

    pub fn lock_state(&self) -> LockState {
        let st = self.state.lock().expect("state");
        match &st.account {
            None => LockState {
                signed_in: false,
                unlocked: false,
                login: String::new(),
                server_url: String::new(),
                account_id: String::new(),
                device_id: String::new(),
                last_sync_at: 0,
            },
            Some(a) => LockState {
                signed_in: true,
                unlocked: st.keys.is_some(),
                login: a.login.clone(),
                server_url: a.server_url.clone(),
                account_id: a.account_id.clone(),
                device_id: a.device_id.clone(),
                last_sync_at: a.last_sync_at,
            },
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.state.lock().expect("state").keys.is_some()
    }

    // ------------------------------------------------------------ registration

    /// Creates an account on `server_url`, signs this device in and unlocks.
    /// Returns the Emergency Kit data (the Secret Key exists nowhere else yet).
    pub async fn register(
        &self,
        server_url: &str,
        login: &str,
        password: &str,
        invite: Option<&str>,
    ) -> Result<EmergencyKit> {
        if self.state.lock().expect("state").account.is_some() {
            return Err(CoreError::Invalid(
                "already signed in on this device".into(),
            ));
        }
        let login = login.trim().to_string();
        if login.is_empty() || password.is_empty() {
            return Err(CoreError::Invalid("login and password are required".into()));
        }
        let t = (self.factory)(server_url)?;
        let account_id = uuid::Uuid::now_v7().to_string();
        let acc_bytes = uuid_bytes(&account_id)?;
        let sk = SecretKey::generate();
        let salt = npw_crypto::random_bytes::<16>();
        let kdf_params = self.cfg.new_account_kdf;
        let mk = kdf::derive_master(password, &sk, &salt, &kdf_params)?;

        let ak = Key32::generate();
        let enc_ak = envelope::wrap_key(&mk.auk, &ak, &aad::account_key(&acc_bytes));
        let kp = AccountKeyPair::generate();
        let enc_priv = envelope::seal(
            &ak,
            kp.secret.as_bytes(),
            &aad::account_private_key(&acc_bytes),
        );

        let vault_id = uuid::Uuid::now_v7().to_string();
        let vk = Key32::generate();
        let vbytes = uuid_bytes(&vault_id)?;
        let wrapped_vk = envelope::wrap_key(&ak, &vk, &aad::vault_key(&vbytes));
        let meta = VaultMeta {
            name: if self.cfg.locale.starts_with("zh") {
                "个人".into()
            } else {
                "Personal".into()
            },
            ..Default::default()
        };
        let enc_meta = envelope::seal(&vk, &json(&meta), &aad::vault_meta(&vbytes));

        let (ostate, oreq) = opaque::client_register_start(&mk.login)?;
        let r: api_t::OpaqueResp = api::call(
            &*t,
            "POST",
            "/v1/auth/register/start",
            Some(&api_t::RegisterStartReq {
                login: login.clone(),
                invite: invite.map(str::to_string),
                account_id: account_id.clone(),
                opaque_request: b64(&oreq),
            }),
            None,
        )
        .await?;
        let upload = opaque::client_register_finish(ostate, &mk.login, &d64(&r.opaque_response)?)?;
        let session: api_t::Session = api::call(
            &*t,
            "POST",
            "/v1/auth/register/finish",
            Some(&api_t::RegisterFinishReq {
                login: login.clone(),
                invite: invite.map(str::to_string),
                account_id: account_id.clone(),
                opaque_upload: b64(&upload),
                kdf: kdf_params,
                account_salt: b64(&salt),
                encrypted_account_key: b64(&enc_ak),
                public_key: b64(&kp.public),
                encrypted_private_key: b64(&enc_priv),
                vault: api_t::NewVault {
                    id: vault_id.clone(),
                    wrapped_key: b64(&wrapped_vk),
                    encrypted_meta: b64(&enc_meta),
                },
                device: self.device_info(None),
            }),
            None,
        )
        .await?;

        let acc = AccountState {
            server_url: server_url.trim_end_matches('/').to_string(),
            login: login.clone(),
            account_id: account_id.clone(),
            device_id: session.device_id.clone(),
            kdf: kdf_params,
            account_salt: b64(&salt),
            encrypted_account_key: b64(&enc_ak),
            public_key: b64(&kp.public),
            encrypted_private_key: b64(&enc_priv),
            vaults: vec![VaultState {
                id: vault_id.clone(),
                wrapped_key: b64(&wrapped_vk),
                encrypted_meta: b64(&enc_meta),
                meta_revision: 1,
                role: "owner".into(),
                seq: 0,
                created_at: npw_model::now_ms(),
                missing_on_server: false,
            }],
            epoch: String::new(),
            last_sync_at: 0,
            previous_unlock: None,
            unlock_unverified: false,
        };
        self.store.apply(vec![
            self.persist_account(&acc)?,
            StoreOp::PutMeta(
                META_SECRET_KEY.into(),
                self.seal_device(META_SECRET_KEY, sk.raw()),
            ),
            StoreOp::PutMeta(
                META_SESSION.into(),
                self.seal_device(META_SESSION, &json(&session)),
            ),
        ])?;
        *self.transport.write().expect("lock") = Some(t);
        {
            let mut st = self.state.lock().expect("state");
            st.account = Some(acc.clone());
            st.session = Some(session);
            let mut vault_keys = HashMap::new();
            vault_keys.insert(vault_id, vk);
            st.keys = Some(Keyring {
                ak,
                login: Some(mk.login),
                vault_keys,
            });
            st.cache = Cache::default();
        }
        Ok(EmergencyKit {
            server_url: acc.server_url,
            login,
            account_id,
            secret_key: sk.to_text(),
            created_at: npw_model::now_ms(),
        })
    }

    // ------------------------------------------------------------ sign-in

    async fn opaque_login(
        t: &dyn Transport,
        login: &str,
        login_key: &Key32,
        method: api_t::LoginMethod,
        device: api_t::DeviceInfo,
    ) -> Result<api_t::Session> {
        let (ostate, oreq) = opaque::client_login_start(login_key)?;
        let r: api_t::LoginStartResp = api::call(
            t,
            "POST",
            "/v1/auth/login/start",
            Some(&api_t::LoginStartReq {
                login: login.to_string(),
                method,
                opaque_request: b64(&oreq),
            }),
            None,
        )
        .await?;
        let fin = opaque::client_login_finish(ostate, login_key, &d64(&r.opaque_response)?)
            .map_err(|_| CoreError::WrongPassword)?;
        let res: Result<api_t::Session> = api::call(
            t,
            "POST",
            "/v1/auth/login/finish",
            Some(&api_t::LoginFinishReq {
                login_id: r.login_id,
                opaque_finalization: b64(&fin),
                device,
            }),
            None,
        )
        .await;
        match res {
            Err(CoreError::Api { code, .. }) if code == api_t::code::LOGIN_FAILED => {
                Err(CoreError::WrongPassword)
            }
            other => other,
        }
    }

    /// Signs this device in to an existing account (needs the Secret Key once).
    pub async fn sign_in(
        &self,
        server_url: &str,
        login: &str,
        password: &str,
        secret_key: &str,
    ) -> Result<()> {
        if self.state.lock().expect("state").account.is_some() {
            return Err(CoreError::Invalid(
                "already signed in on this device".into(),
            ));
        }
        let sk = SecretKey::parse(secret_key)?;
        let login = login.trim().to_string();
        let t = (self.factory)(server_url)?;
        let pre: api_t::PreloginResp = api::call(
            &*t,
            "POST",
            "/v1/auth/prelogin",
            Some(&api_t::PreloginReq {
                login: login.clone(),
            }),
            None,
        )
        .await?;
        self.check_kdf(&pre.kdf)?;
        let salt = d64(&pre.account_salt)?;
        let mk = kdf::derive_master(password, &sk, &salt, &pre.kdf)?;
        let session = Self::opaque_login(
            &*t,
            &login,
            &mk.login,
            api_t::LoginMethod::Password,
            self.device_info(None),
        )
        .await?;
        let acct: api_t::AccountResp = api::call::<api::Empty, _>(
            &*t,
            "GET",
            "/v1/account",
            None,
            Some(&session.access_token),
        )
        .await?;
        let acc_bytes = uuid_bytes(&acct.account_id)?;
        let ak = envelope::unwrap_key(
            &mk.auk,
            &d64(&acct.encrypted_account_key)?,
            &aad::account_key(&acc_bytes),
        )
        .map_err(|_| CoreError::WrongPassword)?;

        let acc = AccountState {
            server_url: server_url.trim_end_matches('/').to_string(),
            login: acct.login.clone(),
            account_id: acct.account_id.clone(),
            device_id: session.device_id.clone(),
            // the parameters that just derived the key which opened AK
            kdf: pre.kdf,
            account_salt: pre.account_salt.clone(),
            encrypted_account_key: acct.encrypted_account_key.clone(),
            public_key: acct.public_key.clone(),
            encrypted_private_key: acct.encrypted_private_key.clone(),
            vaults: vec![],
            epoch: String::new(),
            last_sync_at: 0,
            previous_unlock: None,
            unlock_unverified: false,
        };
        self.store.apply(vec![
            self.persist_account(&acc)?,
            StoreOp::PutMeta(
                META_SECRET_KEY.into(),
                self.seal_device(META_SECRET_KEY, sk.raw()),
            ),
            StoreOp::PutMeta(
                META_SESSION.into(),
                self.seal_device(META_SESSION, &json(&session)),
            ),
        ])?;
        *self.transport.write().expect("lock") = Some(t);
        {
            let mut st = self.state.lock().expect("state");
            st.account = Some(acc);
            st.session = Some(session);
            st.keys = Some(Keyring {
                ak,
                login: Some(mk.login),
                vault_keys: HashMap::new(),
            });
            st.cache = Cache::default();
        }
        self.apply_account_resp(acct)?;
        Ok(())
    }

    /// Checks unlock material from the server before it replaces what this device has.
    fn check_unlock_material(&self, m: &UnlockMaterial) -> Result<()> {
        self.check_kdf(&m.kdf)?;
        if !(16..=64).contains(&d64(&m.account_salt)?.len()) {
            return Err(CoreError::Invalid("bad account salt".into()));
        }
        if d64(&m.encrypted_account_key)?.is_empty() {
            return Err(CoreError::Invalid("empty wrapped account key".into()));
        }
        Ok(())
    }

    /// Updates vaults (keys, metadata) and the unlock material from `GET /v1/account`.
    ///
    /// The server is not trusted with what this device needs to work offline:
    /// - a vault it stops listing keeps its local copy (never cleared; vaults
    ///   cannot be deleted through the API) and is skipped by sync;
    /// - new unlock material (another device changed the master password) must
    ///   pass validation, and the last material known to work is kept as a
    ///   fallback for offline unlock.
    pub(crate) fn apply_account_resp(&self, r: api_t::AccountResp) -> Result<AccountUpdate> {
        let mut acc = self.account()?;
        if r.account_id != acc.account_id {
            return Err(CoreError::Invalid(
                "the server returned another account".into(),
            ));
        }
        let mut update = AccountUpdate::default();
        let offered = UnlockMaterial {
            kdf: r.kdf,
            account_salt: r.account_salt,
            encrypted_account_key: r.encrypted_account_key,
        };
        let current = acc.unlock_material();
        if offered != current {
            match self.check_unlock_material(&offered) {
                Ok(()) => {
                    // keep the material that last worked; an unverified one is just replaced
                    if !acc.unlock_unverified {
                        acc.previous_unlock = Some(current);
                    }
                    acc.set_unlock_material(offered);
                    acc.unlock_unverified = true;
                }
                Err(e) => {
                    tracing::warn!("ignoring the account key update from the server: {e}");
                    update.unlock_refused = true;
                }
            }
        }
        let mut vaults = vec![];
        for v in r.vaults {
            let seq = acc
                .vaults
                .iter()
                .find(|x| x.id == v.id)
                .map(|x| x.seq)
                .unwrap_or(0);
            vaults.push(VaultState {
                id: v.id,
                wrapped_key: v.wrapped_key,
                encrypted_meta: v.encrypted_meta,
                meta_revision: v.meta_revision,
                role: v.role,
                seq,
                created_at: v.created_at,
                missing_on_server: false,
            });
        }
        for old in &acc.vaults {
            if !vaults.iter().any(|n| n.id == old.id) {
                vaults.push(VaultState {
                    missing_on_server: true,
                    ..old.clone()
                });
                update.missing_vaults += 1;
            }
        }
        acc.vaults = vaults;
        self.store.apply(vec![self.persist_account(&acc)?])?;
        let mut st = self.state.lock().expect("state");
        st.account = Some(acc.clone());
        if let Some(keys) = st.keys.as_mut() {
            for v in &acc.vaults {
                if !keys.vault_keys.contains_key(&v.id) {
                    let vk = envelope::unwrap_key(
                        &keys.ak,
                        &d64(&v.wrapped_key)?,
                        &aad::vault_key(&uuid_bytes(&v.id)?),
                    )?;
                    keys.vault_keys.insert(v.id.clone(), vk);
                }
            }
        }
        Ok(update)
    }

    // ------------------------------------------------------------ unlock / lock

    /// Opens AK with the master password: the current unlock material first,
    /// then the previous one (see [`AccountState::previous_unlock`]).
    /// Returns AK, the master keys and whether the current material worked.
    pub(crate) fn open_account_key(
        &self,
        acc: &AccountState,
        password: &str,
    ) -> Result<(Key32, kdf::MasterKeys, bool)> {
        let sk = self.secret_key()?;
        let acc_bytes = uuid_bytes(&acc.account_id)?;
        let mut first_err = None;
        let mut tried = false;
        let candidates = std::iter::once(acc.unlock_material()).chain(acc.previous_unlock.clone());
        for (i, m) in candidates.enumerate() {
            let attempt = (|| -> Result<(Key32, kdf::MasterKeys)> {
                self.check_kdf(&m.kdf)?;
                let mk = kdf::derive_master(password, &sk, &d64(&m.account_salt)?, &m.kdf)?;
                tried = true;
                let ak = envelope::unwrap_key(
                    &mk.auk,
                    &d64(&m.encrypted_account_key)?,
                    &aad::account_key(&acc_bytes),
                )
                .map_err(|_| CoreError::WrongPassword)?;
                Ok((ak, mk))
            })();
            match attempt {
                Ok((ak, mk)) => return Ok((ak, mk, i == 0)),
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        Err(if tried {
            CoreError::WrongPassword
        } else {
            first_err.unwrap_or(CoreError::WrongPassword)
        })
    }

    /// Unlocks with the master password. Works offline.
    pub fn unlock(&self, password: &str) -> Result<()> {
        let acc = self.account()?;
        let (ak, mk, current) = self.open_account_key(&acc, password)?;
        if current && (acc.unlock_unverified || acc.previous_unlock.is_some()) {
            // the current material works here: the fallback is no longer needed
            self.update_account(|a| {
                if a.unlock_material() == acc.unlock_material() {
                    a.unlock_unverified = false;
                    a.previous_unlock = None;
                }
            })?;
        }
        self.finish_unlock(ak, Some(mk.login))
    }

    /// Changes the persisted account state in one step.
    pub(crate) fn update_account(&self, f: impl FnOnce(&mut AccountState)) -> Result<()> {
        let mut st = self.state.lock().expect("state");
        let mut acc = st.account.clone().ok_or(CoreError::NotSignedIn)?;
        f(&mut acc);
        self.store.apply(vec![self.persist_account(&acc)?])?;
        st.account = Some(acc);
        Ok(())
    }

    /// The key a host may store behind biometrics for quick unlock. Only while unlocked.
    pub fn quick_unlock_key(&self) -> Result<Vec<u8>> {
        let st = self.state.lock().expect("state");
        let keys = st.keys.as_ref().ok_or(CoreError::Locked)?;
        Ok(keys.ak.as_bytes().to_vec())
    }

    /// Unlocks with a key from [`Client::quick_unlock_key`].
    pub fn unlock_with_key(&self, key: &[u8]) -> Result<()> {
        let acc = self.account()?;
        let ak = Key32::from_slice(key)?;
        // prove the key is right: it must open the account's private key
        envelope::open(
            &ak,
            &d64(&acc.encrypted_private_key)?,
            &aad::account_private_key(&uuid_bytes(&acc.account_id)?),
        )
        .map_err(|_| CoreError::WrongPassword)?;
        self.finish_unlock(ak, None)
    }

    /// Checks that `key` (from a host's biometric quick-unlock store) is this
    /// account's key, without changing the lock state. Only while unlocked:
    /// hosts use it to re-verify the user before using an item marked
    /// `reprompt` (see also [`Client::verify_password`]).
    pub fn verify_key(&self, key: &[u8]) -> Result<()> {
        if !self.is_unlocked() {
            return Err(CoreError::Locked);
        }
        let acc = self.account()?;
        let ak = Key32::from_slice(key)?;
        envelope::open(
            &ak,
            &d64(&acc.encrypted_private_key)?,
            &aad::account_private_key(&uuid_bytes(&acc.account_id)?),
        )
        .map(|mut plain| plain.zeroize())
        .map_err(|_| CoreError::WrongPassword)
    }

    fn finish_unlock(&self, ak: Key32, login: Option<Key32>) -> Result<()> {
        let acc = self.account()?;
        let mut vault_keys = HashMap::new();
        for v in &acc.vaults {
            let vk = envelope::unwrap_key(
                &ak,
                &d64(&v.wrapped_key)?,
                &aad::vault_key(&uuid_bytes(&v.id)?),
            )?;
            vault_keys.insert(v.id.clone(), vk);
        }
        let keys = Keyring {
            ak,
            login,
            vault_keys,
        };
        let cache = Cache::build(&*self.store, &keys, &acc)?;
        let mut st = self.state.lock().expect("state");
        st.keys = Some(keys);
        st.cache = cache;
        Ok(())
    }

    /// Forgets all keys and decrypted data.
    pub fn lock(&self) {
        let mut st = self.state.lock().expect("state");
        st.keys = None;
        st.cache = Cache::default();
    }

    /// The Secret Key in its printable form (for re-showing the Emergency Kit). Only while unlocked.
    pub fn emergency_kit(&self) -> Result<EmergencyKit> {
        if !self.is_unlocked() {
            return Err(CoreError::Locked);
        }
        let acc = self.account()?;
        Ok(EmergencyKit {
            server_url: acc.server_url,
            login: acc.login,
            account_id: acc.account_id,
            secret_key: self.secret_key()?.to_text(),
            created_at: npw_model::now_ms(),
        })
    }

    /// Removes the account from this device. Refuses while edits are unsynced, unless `force`.
    /// Signing out when already signed out (e.g. after the device was revoked) succeeds.
    pub async fn sign_out(&self, force: bool) -> Result<()> {
        if self.state.lock().expect("state").account.is_none() {
            return self.wipe_local();
        }
        let pending = self
            .store
            .list_all_items()?
            .iter()
            .filter(|i| i.pending.is_some())
            .count();
        if pending > 0 && !force {
            return Err(CoreError::Invalid(format!(
                "{pending} edits have not been synced yet"
            )));
        }
        // Tell the server, best effort: only with a still-valid access token
        // (never refresh or sign in again just to sign out) and with a short
        // timeout, so an unreachable or slow server cannot hold up signing
        // out. An unused session simply expires on the server.
        let token = {
            let st = self.state.lock().expect("state");
            st.session
                .as_ref()
                .filter(|s| s.access_expires_at > npw_model::now_ms() + 5_000)
                .map(|s| s.access_token.clone())
        };
        if let (Some(token), Ok(t)) = (token, self.transport()) {
            let _ = api::call_with_timeout::<api::Empty, api::Empty>(
                &*t,
                "POST",
                "/v1/auth/logout",
                Some(&api::Empty {}),
                Some(&token),
                Some(SIGN_OUT_TIMEOUT_MS),
            )
            .await;
        }
        self.wipe_local()
    }

    /// Deletes the account, the Secret Key, the session, the whole replica and
    /// cached attachments from this device, without asking the server.
    fn wipe_local(&self) -> Result<()> {
        let mut ops = vec![
            StoreOp::DeleteMeta(META_ACCOUNT.into()),
            StoreOp::DeleteMeta(META_SECRET_KEY.into()),
            StoreOp::DeleteMeta(META_SESSION.into()),
        ];
        let mut vaults: std::collections::BTreeSet<String> = self
            .store
            .list_all_items()?
            .into_iter()
            .map(|i| i.vault_id)
            .collect();
        if let Ok(acc) = self.account() {
            vaults.extend(acc.vaults.into_iter().map(|v| v.id));
        }
        ops.extend(vaults.into_iter().map(StoreOp::ClearVault));
        {
            // cached attachment blobs are named in the (decrypted) item contents
            let st = self.state.lock().expect("state");
            for c in st.cache.items.values() {
                for a in &c.content.attachments {
                    ops.push(StoreOp::DeleteBlob(format!("att/{}", a.id)));
                }
            }
        }
        self.store.apply(ops)?;
        let mut st = self.state.lock().expect("state");
        st.account = None;
        st.session = None;
        st.keys = None;
        st.cache = Cache::default();
        *self.transport.write().expect("lock") = None;
        Ok(())
    }

    /// The server says this device was revoked: it is treated as lost. Sign out
    /// and wipe everything of the account here (no silent sign-in again).
    fn on_revoked<T>(&self, r: Result<T>) -> Result<T> {
        if let Err(CoreError::DeviceRevoked) = &r {
            if let Err(e) = self.wipe_local() {
                tracing::error!("wiping the revoked device failed: {e}");
            }
        }
        r
    }

    // ------------------------------------------------------------ sessions

    /// A valid access token, refreshing (or silently re-logging in) when needed.
    pub(crate) async fn bearer(&self) -> Result<String> {
        let session = self.state.lock().expect("state").session.clone();
        let now = npw_model::now_ms();
        match session {
            Some(s) if s.access_expires_at > now + 60_000 => Ok(s.access_token),
            Some(s) => self.refresh(&s.refresh_token).await,
            None => self.relogin().await,
        }
    }

    async fn refresh(&self, refresh_token: &str) -> Result<String> {
        let t = self.transport()?;
        let r: Result<api_t::Session> = api::call(
            &*t,
            "POST",
            "/v1/auth/refresh",
            Some(&api_t::RefreshReq {
                refresh_token: refresh_token.to_string(),
            }),
            None,
        )
        .await;
        match r {
            Ok(s) => {
                self.save_session(&s)?;
                Ok(s.access_token)
            }
            Err(e) if is_unauthorized(&e) => self.relogin().await,
            Err(e) => Err(e),
        }
    }

    async fn relogin(&self) -> Result<String> {
        let login_key = {
            let st = self.state.lock().expect("state");
            st.keys.as_ref().and_then(|k| k.login.clone())
        };
        let Some(login_key) = login_key else {
            return Err(CoreError::SessionExpired);
        };
        let acc = self.account()?;
        let t = self.transport()?;
        let s = Self::opaque_login(
            &*t,
            &acc.login,
            &login_key,
            api_t::LoginMethod::Password,
            self.device_info(Some(acc.device_id.clone())),
        )
        .await?;
        self.save_session(&s)?;
        Ok(s.access_token)
    }

    /// An authenticated call, retried once after renewing the session on 401
    /// `unauthorized`. `device_revoked` is final: the device wipes its local copy.
    pub(crate) async fn authed<Req: Serialize, Resp: for<'de> Deserialize<'de>>(
        &self,
        method: &'static str,
        path: &str,
        body: Option<&Req>,
    ) -> Result<Resp> {
        let r = self.authed_once(method, path, body).await;
        self.on_revoked(r)
    }

    async fn authed_once<Req: Serialize, Resp: for<'de> Deserialize<'de>>(
        &self,
        method: &'static str,
        path: &str,
        body: Option<&Req>,
    ) -> Result<Resp> {
        let t = self.transport()?;
        let token = self.bearer().await?;
        match api::call(&*t, method, path, body, Some(&token)).await {
            Err(e) if is_unauthorized(&e) => {
                self.state.lock().expect("state").session = None;
                let token = self.relogin().await?;
                api::call(&*t, method, path, body, Some(&token)).await
            }
            other => other,
        }
    }

    pub(crate) async fn authed_raw(
        &self,
        method: &'static str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let r = self.authed_raw_once(method, path, body).await;
        self.on_revoked(r)
    }

    async fn authed_raw_once(
        &self,
        method: &'static str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let t = self.transport()?;
        let token = self.bearer().await?;
        match api::call_raw(&*t, method, path, body.clone(), Some(&token)).await {
            Err(e) if is_unauthorized(&e) => {
                self.state.lock().expect("state").session = None;
                let token = self.relogin().await?;
                api::call_raw(&*t, method, path, body, Some(&token)).await
            }
            other => other,
        }
    }

    /// A short-lived token for the events WebSocket (`wss://.../v1/events?token=`).
    pub async fn events_token(&self) -> Result<String> {
        let r = self.bearer().await;
        self.on_revoked(r)
    }

    // ------------------------------------------------------------ account management

    /// Changes the master password (online). The Secret Key stays the same.
    pub async fn change_password(&self, current: &str, new_password: &str) -> Result<()> {
        if new_password.is_empty() {
            return Err(CoreError::Invalid("the new password is empty".into()));
        }
        let acc = self.account()?;
        let sk = self.secret_key()?;
        let (ak, _, _) = self.open_account_key(&acc, current)?;
        let acc_bytes = uuid_bytes(&acc.account_id)?;
        let new_salt = npw_crypto::random_bytes::<16>();
        let params = if self.cfg.allow_weak_kdf {
            acc.kdf
        } else {
            KdfParams::default()
        };
        let mk = kdf::derive_master(new_password, &sk, &new_salt, &params)?;
        let enc_ak = envelope::wrap_key(&mk.auk, &ak, &aad::account_key(&acc_bytes));
        let (ostate, oreq) = opaque::client_register_start(&mk.login)?;
        let r: api_t::OpaqueResp = self
            .authed(
                "POST",
                "/v1/account/password/start",
                Some(&api_t::ReRegisterStartReq {
                    opaque_request: b64(&oreq),
                }),
            )
            .await?;
        let upload = opaque::client_register_finish(ostate, &mk.login, &d64(&r.opaque_response)?)?;
        let _: api::Empty = self
            .authed(
                "POST",
                "/v1/account/password/finish",
                Some(&api_t::ChangePasswordFinishReq {
                    opaque_upload: b64(&upload),
                    kdf: params,
                    account_salt: b64(&new_salt),
                    encrypted_account_key: b64(&enc_ak),
                }),
            )
            .await?;
        self.update_account(|a| {
            a.set_unlock_material(UnlockMaterial {
                kdf: params,
                account_salt: b64(&new_salt),
                encrypted_account_key: b64(&enc_ak),
            });
            // made (and so verified) here
            a.unlock_unverified = false;
            a.previous_unlock = None;
        })?;
        if let Some(keys) = self.state.lock().expect("state").keys.as_mut() {
            keys.login = Some(mk.login);
        }
        Ok(())
    }

    pub async fn devices(&self) -> Result<Vec<api_t::DeviceRecord>> {
        self.authed::<api::Empty, _>("GET", "/v1/devices", None)
            .await
    }

    pub async fn revoke_device(&self, device_id: &str) -> Result<()> {
        let _: api::Empty = self
            .authed::<api::Empty, _>("DELETE", &format!("/v1/devices/{device_id}"), None)
            .await?;
        Ok(())
    }

    pub async fn audit_log(&self) -> Result<Vec<api_t::AuditEntry>> {
        self.authed::<api::Empty, _>("GET", "/v1/account/audit", None)
            .await
    }

    pub async fn server_info(&self) -> Result<api_t::ServerInfo> {
        api::call::<api::Empty, _>(&*self.transport()?, "GET", "/v1/server-info", None, None).await
    }

    /// Creates another vault (online).
    pub async fn create_vault(&self, name: &str) -> Result<String> {
        let vault_id = uuid::Uuid::now_v7().to_string();
        let vbytes = uuid_bytes(&vault_id)?;
        let vk = Key32::generate();
        let (wrapped, meta) = {
            let st = self.state.lock().expect("state");
            let keys = st.keys.as_ref().ok_or(CoreError::Locked)?;
            let m = VaultMeta {
                name: name.to_string(),
                ..Default::default()
            };
            (
                envelope::wrap_key(&keys.ak, &vk, &aad::vault_key(&vbytes)),
                envelope::seal(&vk, &json(&m), &aad::vault_meta(&vbytes)),
            )
        };
        let _: api::Empty = self
            .authed(
                "POST",
                "/v1/vaults",
                Some(&api_t::NewVault {
                    id: vault_id.clone(),
                    wrapped_key: b64(&wrapped),
                    encrypted_meta: b64(&meta),
                }),
            )
            .await?;
        let acct: api_t::AccountResp = self
            .authed::<api::Empty, _>("GET", "/v1/account", None)
            .await?;
        self.apply_account_resp(acct)?;
        Ok(vault_id)
    }

    /// Renames a vault (online).
    pub async fn rename_vault(&self, vault_id: &str, name: &str) -> Result<()> {
        let acc = self.account()?;
        let v = acc
            .vaults
            .iter()
            .find(|v| v.id == vault_id)
            .ok_or(CoreError::NotFound)?
            .clone();
        let enc = {
            let st = self.state.lock().expect("state");
            let vk = st
                .keys
                .as_ref()
                .ok_or(CoreError::Locked)?
                .vault_keys
                .get(vault_id)
                .ok_or(CoreError::NotFound)?
                .clone();
            let mut meta = self.vault_meta(&v, &vk).unwrap_or_default();
            meta.name = name.to_string();
            envelope::seal(&vk, &json(&meta), &aad::vault_meta(&uuid_bytes(vault_id)?))
        };
        let _: api::Empty = self
            .authed(
                "PUT",
                &format!("/v1/vaults/{vault_id}/meta"),
                Some(&api_t::UpdateVaultMetaReq {
                    encrypted_meta: b64(&enc),
                    base_revision: v.meta_revision,
                }),
            )
            .await?;
        let acct: api_t::AccountResp = self
            .authed::<api::Empty, _>("GET", "/v1/account", None)
            .await?;
        self.apply_account_resp(acct)?;
        Ok(())
    }

    pub(crate) fn vault_meta(&self, v: &VaultState, vk: &Key32) -> Result<VaultMeta> {
        let plain = envelope::open(
            vk,
            &d64(&v.encrypted_meta)?,
            &aad::vault_meta(&uuid_bytes(&v.id)?),
        )?;
        serde_json::from_slice(&plain).map_err(|e| CoreError::Invalid(e.to_string()))
    }

    pub fn vaults(&self) -> Result<Vec<VaultView>> {
        let st = self.state.lock().expect("state");
        let keys = st.keys.as_ref().ok_or(CoreError::Locked)?;
        let acc = st.account.as_ref().ok_or(CoreError::NotSignedIn)?;
        let mut out = vec![];
        for v in &acc.vaults {
            let name = keys
                .vault_keys
                .get(&v.id)
                .and_then(|vk| self.vault_meta(v, vk).ok())
                .map(|m| m.name)
                .unwrap_or_else(|| "?".into());
            let items = st
                .cache
                .items
                .values()
                .filter(|c| c.vault_id == v.id && !c.deleted)
                .count();
            out.push(VaultView {
                id: v.id.clone(),
                name,
                role: v.role.clone(),
                items,
            });
        }
        Ok(out)
    }

    pub fn account_summary(&self) -> Result<AccountSummary> {
        let acc = self.account()?;
        Ok(AccountSummary {
            login: acc.login,
            server_url: acc.server_url,
            account_id: acc.account_id,
            vaults: self.vaults()?,
        })
    }
}
