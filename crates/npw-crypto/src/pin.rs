//! PIN unlock on one device (desktop and Android; docs/加密规格.md §4.4).
//!
//! ```text
//! pin_key = Argon2id(NFKD(PIN), salt = 16 random bytes, m, t, p) → 32 bytes
//! wrapped = envelope(pin_key, AK, AAD = "npw/pin-unlock/v1" ‖ account_id)
//! ```
//!
//! A PIN has little entropy: this layer alone does not stop an offline guess.
//! Hosts keep the result behind the platform's key store (DPAPI / the OS
//! credential store, a non-exportable Android Keystore key) and wipe it after
//! a few wrong tries; the wrapped key never leaves the device.

use crate::kdf::argon2id_nfkd;
use crate::{aad, envelope, KdfParams, Key32, Result};

/// Length of the random salt of a PIN key.
pub const SALT_LEN: usize = 16;

/// `pin_key = Argon2id(NFKD(pin), salt, params)`. The salt must be at least 16
/// bytes; `params` are not checked against the minimums (see
/// [`KdfParams::validate`]).
pub fn derive_key(pin: &str, salt: &[u8], params: &KdfParams) -> Result<Key32> {
    let mut out = argon2id_nfkd(pin, salt, params)?;
    let key = Key32::from_bytes(out);
    zeroize::Zeroize::zeroize(&mut out);
    Ok(key)
}

/// Wraps the account key under a PIN key, bound to the account.
pub fn wrap(pin_key: &Key32, account_key: &Key32, account_id: &[u8; 16]) -> Vec<u8> {
    envelope::wrap_key(pin_key, account_key, &aad::pin_unlock(account_id))
}

/// The account key, or [`crate::CryptoError::Decrypt`] for a wrong PIN key
/// (or another account, or tampered bytes).
pub fn unwrap(pin_key: &Key32, wrapped: &[u8], account_id: &[u8; 16]) -> Result<Key32> {
    envelope::unwrap_key(pin_key, wrapped, &aad::pin_unlock(account_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CryptoError;

    const ACCOUNT: [u8; 16] = [7u8; 16];

    #[test]
    fn round_trip_and_bindings() {
        let p = KdfParams::insecure_for_tests();
        let salt = [1u8; SALT_LEN];
        let ak = Key32::generate();
        let k = derive_key("1234", &salt, &p).unwrap();
        let w = wrap(&k, &ak, &ACCOUNT);
        assert_eq!(unwrap(&k, &w, &ACCOUNT).unwrap(), ak);
        // another PIN, salt or account: nothing
        let other = derive_key("1235", &salt, &p).unwrap();
        assert_eq!(unwrap(&other, &w, &ACCOUNT), Err(CryptoError::Decrypt));
        let resalted = derive_key("1234", &[2u8; SALT_LEN], &p).unwrap();
        assert_eq!(unwrap(&resalted, &w, &ACCOUNT), Err(CryptoError::Decrypt));
        assert_eq!(unwrap(&k, &w, &[8u8; 16]), Err(CryptoError::Decrypt));
        // the quick-unlock label is a different domain
        let as_quick = envelope::wrap_key(&k, &ak, &aad::quick_unlock(&ACCOUNT));
        assert_eq!(unwrap(&k, &as_quick, &ACCOUNT), Err(CryptoError::Decrypt));
    }

    #[test]
    fn nfkd_and_salt_rules() {
        let p = KdfParams::insecure_for_tests();
        let salt = [3u8; SALT_LEN];
        // full-width digits fold to ASCII digits
        assert_eq!(
            derive_key("\u{ff11}\u{ff12}\u{ff13}\u{ff14}", &salt, &p).unwrap(),
            derive_key("1234", &salt, &p).unwrap()
        );
        assert_ne!(
            derive_key("1234 ", &salt, &p).unwrap(),
            derive_key("1234", &salt, &p).unwrap()
        );
        assert_eq!(
            derive_key("1234", &[0u8; 15], &p).err(),
            Some(CryptoError::InvalidKdfParams)
        );
    }
}
