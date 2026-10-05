//! NyaPassword cryptography. Every primitive comes from an audited RustCrypto /
//! dalek / opaque-ke crate; this crate only fixes the parameters, the byte
//! layouts and the domain separation (see docs/加密规格.md in this repository).
//!
//! Key hierarchy (design doc §4.2):
//!
//! ```text
//! master password ─NFKD─► Argon2id ─┐
//!                                    ├─ XOR ─► HKDF ─┬─► AUK   (decrypts the account key)
//! Secret Key ──────────────► HKDF ───┘               └─► OPAQUE password (login)
//! AUK ─► account key AK ─► vault keys VK ─► item keys IK ─► item content / attachment keys
//! ```

pub mod aad;
pub mod envelope;
pub mod kdf;
pub mod keys;
pub mod opaque;
pub mod pin;
pub mod secret_key;
pub mod stream;

pub use envelope::{open, seal};
pub use kdf::{derive_master, KdfParams, MasterKeys};
pub use keys::{random_bytes, AccountKeyPair, Key32};
pub use secret_key::SecretKey;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    /// Wrong key, wrong associated data or tampered ciphertext. Deliberately carries no detail.
    #[error("decryption failed")]
    Decrypt,
    #[error("unsupported envelope version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported algorithm {0}")]
    UnsupportedAlgorithm(u8),
    #[error("malformed ciphertext")]
    Malformed,
    #[error("invalid Secret Key: {0}")]
    InvalidSecretKey(&'static str),
    #[error("invalid key derivation parameters")]
    InvalidKdfParams,
    #[error("OPAQUE protocol error")]
    Opaque,
    #[error("invalid key length")]
    KeyLength,
}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// URL-safe base64 without padding: the encoding of every binary value in the API and item JSON.
pub fn b64(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Decodes [`b64`]; also accepts standard-alphabet and padded input (imported data).
pub fn unb64(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let t = text.trim().trim_end_matches('=');
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(t)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(t))
        .ok()
}

/// SHA-256, hex encoded.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}
