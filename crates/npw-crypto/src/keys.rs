use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, Result};

/// A 256-bit symmetric key, wiped from memory when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct Key32([u8; 32]);

impl Key32 {
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut k);
        Self(k)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::KeyLength)?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for Key32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key32(..)")
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

/// The account's X25519 key pair. v1 is single-account and does not share vaults,
/// but every account gets one at registration so that sharing (HPKE-wrapping a
/// vault key to another member) needs no data migration later.
pub struct AccountKeyPair {
    pub secret: Key32,
    pub public: [u8; 32],
}

impl AccountKeyPair {
    pub fn generate() -> Self {
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        Self {
            secret: Key32::from_bytes(secret.to_bytes()),
            public,
        }
    }

    pub fn from_secret(secret: Key32) -> Self {
        let s = x25519_dalek::StaticSecret::from(*secret.as_bytes());
        let public = x25519_dalek::PublicKey::from(&s).to_bytes();
        Self { secret, public }
    }
}
