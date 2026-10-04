//! Two-secret key derivation (design doc §4.2).
//!
//! ```text
//! K_pw  = Argon2id(NFKD(password), salt = account_salt, m, t, p) → 32 bytes
//! K_sk  = HKDF-SHA256(ikm = Secret Key, salt = account_salt, info = "npw/sk/v1")
//! M     = K_pw XOR K_sk
//! AUK   = HKDF-SHA256(ikm = M, salt = "", info = "npw/auk/v1")      account unlock key
//! LOGIN = HKDF-SHA256(ikm = M, salt = "", info = "npw/opaque/v1")   OPAQUE password
//! ```
//!
//! Without the Secret Key (128 random bits that never leave the user's devices),
//! a stolen server database or backup gives an attacker nothing to brute-force.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

use crate::{CryptoError, Key32, Result, SecretKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Always "argon2id" in v1.
    pub alg: KdfAlg,
    /// Memory in KiB.
    pub m: u32,
    /// Iterations.
    pub t: u32,
    /// Parallelism.
    pub p: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KdfAlg {
    Argon2id,
}

impl Default for KdfParams {
    /// 64 MiB, 3 passes, 4 lanes.
    fn default() -> Self {
        Self {
            alg: KdfAlg::Argon2id,
            m: 64 * 1024,
            t: 3,
            p: 4,
        }
    }
}

impl KdfParams {
    /// Refuses parameters a malicious server could use to weaken the derivation.
    pub fn validate(&self) -> Result<()> {
        if self.m < 16 * 1024
            || self.m > 1024 * 1024
            || self.t < 1
            || self.t > 64
            || self.p < 1
            || self.p > 16
        {
            return Err(CryptoError::InvalidKdfParams);
        }
        Ok(())
    }

    /// Small parameters for tests only (never accepted by `validate`).
    pub fn insecure_for_tests() -> Self {
        Self {
            alg: KdfAlg::Argon2id,
            m: 64,
            t: 1,
            p: 1,
        }
    }
}

/// Keys derived from the master password and the Secret Key.
pub struct MasterKeys {
    pub auk: Key32,
    pub login: Key32,
}

/// Unicode NFKD, nothing trimmed: the same password typed on any platform or
/// input method gives the same bytes.
pub fn normalize_password(password: &str) -> String {
    password.nfkd().collect()
}

/// Derives the master keys. Does not check `params` against the minimums: callers
/// that got the parameters from a server must call [`KdfParams::validate`] first
/// (npw-core always does, unless a test configuration turns it off).
pub fn derive_master(
    password: &str,
    secret_key: &SecretKey,
    account_salt: &[u8],
    params: &KdfParams,
) -> Result<MasterKeys> {
    if account_salt.len() < 16 {
        return Err(CryptoError::InvalidKdfParams);
    }
    let mut pw = normalize_password(password).into_bytes();
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(params.m, params.t, params.p, Some(32))
            .map_err(|_| CryptoError::InvalidKdfParams)?,
    );
    let mut k_pw = [0u8; 32];
    argon
        .hash_password_into(&pw, account_salt, &mut k_pw)
        .map_err(|_| CryptoError::InvalidKdfParams)?;
    pw.zeroize();

    let mut k_sk = [0u8; 32];
    Hkdf::<Sha256>::new(Some(account_salt), secret_key.raw())
        .expand(b"npw/sk/v1", &mut k_sk)
        .expect("32 bytes is a valid HKDF-SHA256 length");

    let mut m = [0u8; 32];
    for i in 0..32 {
        m[i] = k_pw[i] ^ k_sk[i];
    }
    k_pw.zeroize();
    k_sk.zeroize();

    let hk = Hkdf::<Sha256>::new(None, &m);
    let mut auk = [0u8; 32];
    let mut login = [0u8; 32];
    hk.expand(b"npw/auk/v1", &mut auk).expect("valid length");
    hk.expand(b"npw/opaque/v1", &mut login)
        .expect("valid length");
    m.zeroize();
    Ok(MasterKeys {
        auk: Key32::from_bytes(auk),
        login: Key32::from_bytes(login),
    })
}

/// Key for a recovery code (256 random bits, so plain HKDF suffices).
pub fn derive_recovery(code: &[u8; 32], account_salt: &[u8]) -> MasterKeys {
    let hk = Hkdf::<Sha256>::new(Some(account_salt), code);
    let mut auk = [0u8; 32];
    let mut login = [0u8; 32];
    hk.expand(b"npw/recovery-auk/v1", &mut auk)
        .expect("valid length");
    hk.expand(b"npw/recovery-opaque/v1", &mut login)
        .expect("valid length");
    MasterKeys {
        auk: Key32::from_bytes(auk),
        login: Key32::from_bytes(login),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_secret_key_matters() {
        let sk1 = SecretKey::from_raw([7u8; 16]);
        let sk2 = SecretKey::from_raw([8u8; 16]);
        let salt = [1u8; 16];
        let p = KdfParams::insecure_for_tests();
        let a = derive_master("pässwörd", &sk1, &salt, &p).unwrap();
        let b = derive_master("pässwörd", &sk1, &salt, &p).unwrap();
        let c = derive_master("pässwörd", &sk2, &salt, &p).unwrap();
        assert_eq!(a.auk, b.auk);
        assert_ne!(a.auk, c.auk);
        assert_ne!(a.auk, a.login);
    }

    #[test]
    fn nfkd_composed_and_decomposed_agree() {
        let sk = SecretKey::from_raw([7u8; 16]);
        let salt = [1u8; 16];
        let p = KdfParams::insecure_for_tests();
        let composed = derive_master("caf\u{e9}", &sk, &salt, &p).unwrap();
        let decomposed = derive_master("cafe\u{301}", &sk, &salt, &p).unwrap();
        assert_eq!(composed.auk, decomposed.auk);
        let spaced = derive_master("café ", &sk, &salt, &p).unwrap();
        assert_ne!(composed.auk, spaced.auk, "whitespace is significant");
    }

    #[test]
    fn rejects_weak_params() {
        let sk = SecretKey::from_raw([7u8; 16]);
        assert!(KdfParams {
            alg: KdfAlg::Argon2id,
            m: 16 * 1024,
            t: 0,
            p: 1
        }
        .validate()
        .is_err());
        assert!(KdfParams::insecure_for_tests().validate().is_err());
        assert!(KdfParams::default().validate().is_ok());
        assert!(derive_master("x", &sk, &[0u8; 8], &KdfParams::insecure_for_tests()).is_err());
    }
}
