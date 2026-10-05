//! PIN unlock (desktop and Android; docs/加密规格.md §4.4).
//!
//! The core only wraps and opens the account key: [`Client::pin_wrap`] gives
//! the host a [`PinBlob`] (AK under `Argon2id(NFKD(PIN), random salt)`), and
//! [`Client::unlock_with_pin`] / [`Client::verify_pin`] open it and check the
//! key against the account like [`Client::unlock_with_key`]. The host keeps
//! the blob behind the platform's key store (never on the server), counts
//! wrong tries and wipes it after a few (a PIN alone is easy to guess
//! offline), and applies the 14-day rule.

use npw_crypto::{b64, pin, KdfParams, Key32};
use serde::{Deserialize, Serialize};

use crate::client::{d64, uuid_bytes};
use crate::{Client, CoreError, Result};

/// A PIN has at least this many characters (any characters).
pub const MIN_PIN_CHARS: usize = 4;
pub const PIN_BLOB_VERSION: u32 = 1;

/// The account key wrapped under a PIN key. Device-local: hosts store it
/// encrypted by the platform's key store and never send it anywhere.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PinBlob {
    /// [`PIN_BLOB_VERSION`].
    pub version: u32,
    pub account_id: String,
    /// base64url of the random salt ([`pin::SALT_LEN`] bytes).
    pub salt: String,
    /// The Argon2id parameters of the PIN key (the account's at the time).
    pub kdf: KdfParams,
    /// base64url envelope of AK under the PIN key, AAD `aad::pin_unlock(account_id)`.
    pub wrapped: String,
}

/// Checks the PIN rules (at least [`MIN_PIN_CHARS`] characters).
pub fn check_pin(pin: &str) -> Result<()> {
    if pin.chars().count() < MIN_PIN_CHARS {
        return Err(CoreError::Invalid(format!(
            "the PIN must have at least {MIN_PIN_CHARS} characters"
        )));
    }
    Ok(())
}

impl Client {
    /// Wraps the account key under a new PIN. Only while unlocked. The PIN
    /// key uses the account's current KDF parameters and a fresh salt.
    pub fn pin_wrap(&self, pin_text: &str) -> Result<PinBlob> {
        check_pin(pin_text)?;
        let acc = self.account()?;
        let ak = {
            let st = self.state.lock().expect("state");
            st.keys.as_ref().ok_or(CoreError::Locked)?.ak.clone()
        };
        let params = acc.unlock_material().kdf;
        let salt = npw_crypto::random_bytes::<{ pin::SALT_LEN }>();
        let key = pin::derive_key(pin_text, &salt, &params)?;
        let wrapped = pin::wrap(&key, &ak, &uuid_bytes(&acc.account_id)?);
        Ok(PinBlob {
            version: PIN_BLOB_VERSION,
            account_id: acc.account_id,
            salt: b64(&salt),
            kdf: params,
            wrapped: b64(&wrapped),
        })
    }

    /// Opens a PIN blob: the account key, checked against the account.
    /// A wrong PIN is [`CoreError::WrongPassword`].
    fn open_pin(&self, blob: &PinBlob, pin_text: &str) -> Result<Key32> {
        let acc = self.account()?;
        if blob.version != PIN_BLOB_VERSION {
            return Err(CoreError::Invalid(format!(
                "unsupported PIN blob version {}",
                blob.version
            )));
        }
        if blob.account_id != acc.account_id {
            return Err(CoreError::Invalid(
                "the PIN belongs to another account".into(),
            ));
        }
        // the blob comes from the host's storage: the same limits as server parameters
        self.check_kdf(&blob.kdf)?;
        let salt = d64(&blob.salt)?;
        if salt.len() < pin::SALT_LEN {
            return Err(CoreError::Invalid("bad PIN salt".into()));
        }
        let key = pin::derive_key(pin_text, &salt, &blob.kdf)?;
        let ak = pin::unwrap(&key, &d64(&blob.wrapped)?, &uuid_bytes(&acc.account_id)?)
            .map_err(|_| CoreError::WrongPassword)?;
        self.check_account_key(&acc, &ak)?;
        Ok(ak)
    }

    /// Unlocks with the PIN. Works offline.
    pub fn unlock_with_pin(&self, blob: &PinBlob, pin_text: &str) -> Result<()> {
        let ak = self.open_pin(blob, pin_text)?;
        self.finish_unlock(ak, None)
    }

    /// Checks the PIN without changing the lock state (verifying the user
    /// again before an item marked `reprompt` is used). Only while unlocked.
    pub fn verify_pin(&self, blob: &PinBlob, pin_text: &str) -> Result<()> {
        if !self.is_unlocked() {
            return Err(CoreError::Locked);
        }
        self.open_pin(blob, pin_text).map(drop)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use npw_crypto::{aad, envelope, kdf, AccountKeyPair, SecretKey};

    use super::*;
    use crate::client::{AccountState, META_ACCOUNT, META_SECRET_KEY};
    use crate::store::StoreOp;
    use crate::transport::{HttpRequest, HttpResponse, Transport};
    use crate::{ClientConfig, MemoryStore, Store};

    const ACCOUNT: &str = "0192f0c0-0000-7000-8000-000000000001";

    struct NoNetwork;

    #[async_trait::async_trait]
    impl Transport for NoNetwork {
        async fn send(&self, _: HttpRequest) -> Result<HttpResponse> {
            Err(CoreError::Offline)
        }
    }

    fn client(store: Arc<MemoryStore>, weak_ok: bool) -> Client {
        let mut cfg = ClientConfig::new("test", "cli", "0.0.0");
        cfg.allow_weak_kdf = weak_ok;
        Client::with_transport_factory(
            cfg,
            store,
            Key32::from_bytes([9; 32]),
            Box::new(|_| Ok(Arc::new(NoNetwork) as Arc<dyn Transport>)),
        )
        .unwrap()
    }

    /// A signed-in device (no server needed): password "correct horse".
    fn signed_in() -> (Arc<MemoryStore>, Client, Key32) {
        let store = Arc::new(MemoryStore::new());
        let c = client(store.clone(), true);
        let sk = SecretKey::from_raw([5; 16]);
        let salt = [6u8; 16];
        let params = KdfParams::insecure_for_tests();
        let mk = kdf::derive_master("correct horse", &sk, &salt, &params).unwrap();
        let ak = Key32::generate();
        let id = uuid_bytes(ACCOUNT).unwrap();
        let kp = AccountKeyPair::generate();
        let acc = AccountState {
            server_url: "https://vault.example.com".into(),
            login: "me@example.com".into(),
            account_id: ACCOUNT.into(),
            device_id: "d".into(),
            kdf: params,
            account_salt: b64(&salt),
            encrypted_account_key: b64(&envelope::wrap_key(&mk.auk, &ak, &aad::account_key(&id))),
            public_key: b64(&kp.public),
            encrypted_private_key: b64(&envelope::seal(
                &ak,
                kp.secret.as_bytes(),
                &aad::account_private_key(&id),
            )),
            vaults: vec![],
            epoch: String::new(),
            last_sync_at: 0,
            previous_unlock: None,
            unlock_unverified: false,
        };
        store
            .apply(vec![
                StoreOp::PutMeta(META_ACCOUNT.into(), serde_json::to_vec(&acc).unwrap()),
                StoreOp::PutMeta(
                    META_SECRET_KEY.into(),
                    c.seal_device(META_SECRET_KEY, sk.raw()),
                ),
            ])
            .unwrap();
        // reopen over the store, as an app start does
        let c = client(store.clone(), true);
        c.unlock("correct horse").unwrap();
        (store, c, ak)
    }

    #[test]
    fn wrap_unlock_and_verify() {
        let (_, c, ak) = signed_in();
        assert!(matches!(c.pin_wrap("123"), Err(CoreError::Invalid(_))));
        let blob = c.pin_wrap("1234").unwrap();
        assert_eq!(blob.account_id, ACCOUNT);
        assert_eq!(blob.kdf, KdfParams::insecure_for_tests());
        assert_eq!(d64(&blob.salt).unwrap().len(), pin::SALT_LEN);
        // a new salt every time
        assert_ne!(c.pin_wrap("1234").unwrap().salt, blob.salt);

        // verification keeps the lock state
        c.verify_pin(&blob, "1234").unwrap();
        assert!(matches!(
            c.verify_pin(&blob, "0000"),
            Err(CoreError::WrongPassword)
        ));
        assert!(c.is_unlocked());

        c.lock();
        assert!(matches!(
            c.verify_pin(&blob, "1234"),
            Err(CoreError::Locked)
        ));
        assert!(matches!(c.pin_wrap("1234"), Err(CoreError::Locked)));
        assert!(matches!(
            c.unlock_with_pin(&blob, "4321"),
            Err(CoreError::WrongPassword)
        ));
        assert!(!c.is_unlocked());
        // full-width digits are the same PIN (NFKD)
        c.unlock_with_pin(&blob, "\u{ff11}\u{ff12}\u{ff13}\u{ff14}")
            .unwrap();
        assert!(c.is_unlocked());
        assert_eq!(c.quick_unlock_key().unwrap(), ak.as_bytes().to_vec());
    }

    #[test]
    fn tampered_or_foreign_blobs_are_refused() {
        let (store, c, _) = signed_in();
        let blob = c.pin_wrap("2580").unwrap();
        c.lock();

        let mut other = blob.clone();
        other.account_id = "0192f0c0-0000-7000-8000-000000000002".into();
        assert!(matches!(
            c.unlock_with_pin(&other, "2580"),
            Err(CoreError::Invalid(_))
        ));
        let mut v2 = blob.clone();
        v2.version = 2;
        assert!(matches!(
            c.unlock_with_pin(&v2, "2580"),
            Err(CoreError::Invalid(_))
        ));
        let mut flipped = blob.clone();
        let mut w = d64(&flipped.wrapped).unwrap();
        *w.last_mut().unwrap() ^= 1;
        flipped.wrapped = b64(&w);
        assert!(matches!(
            c.unlock_with_pin(&flipped, "2580"),
            Err(CoreError::WrongPassword)
        ));
        let mut short_salt = blob.clone();
        short_salt.salt = b64(&[1u8; 8]);
        assert!(c.unlock_with_pin(&short_salt, "2580").is_err());

        // a well-formed blob that opens to some other key: the account check refuses it
        let salt = [4u8; pin::SALT_LEN];
        let key = pin::derive_key("2580", &salt, &blob.kdf).unwrap();
        let forged = PinBlob {
            salt: b64(&salt),
            wrapped: b64(&pin::wrap(
                &key,
                &Key32::generate(),
                &uuid_bytes(ACCOUNT).unwrap(),
            )),
            ..blob.clone()
        };
        assert!(matches!(
            c.unlock_with_pin(&forged, "2580"),
            Err(CoreError::WrongPassword)
        ));
        assert!(!c.is_unlocked());

        // weak parameters in the blob are refused unless the client allows them (tests)
        let strict = client(store, false);
        assert!(matches!(
            strict.unlock_with_pin(&blob, "2580"),
            Err(CoreError::Crypto(npw_crypto::CryptoError::InvalidKdfParams))
        ));
        c.unlock_with_pin(&blob, "2580").unwrap();
    }

    #[test]
    fn blob_json_shape() {
        let (_, c, _) = signed_in();
        let blob = c.pin_wrap("abcd").unwrap();
        let v: serde_json::Value = serde_json::to_value(&blob).unwrap();
        assert_eq!(v["version"], 1);
        assert_eq!(v["kdf"]["alg"], "argon2id");
        let back: PinBlob = serde_json::from_value(v).unwrap();
        assert_eq!(back, blob);
    }
}
