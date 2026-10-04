//! The ciphertext envelope:
//!
//! ```text
//! [version: 1 byte = 1][algorithm: 1 byte = 1][nonce: 24 bytes][ciphertext ‖ tag: n + 16 bytes]
//! ```
//!
//! Algorithm 1 is XChaCha20-Poly1305 with a random 192-bit nonce (safe to pick
//! at random for any number of messages under one key). New algorithms only
//! ever get new numbers; old ones stay decryptable forever.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::{random_bytes, CryptoError, Key32, Result};

pub const VERSION: u8 = 1;
pub const ALG_XCHACHA20POLY1305: u8 = 1;
pub const HEADER_LEN: usize = 2 + 24;
pub const OVERHEAD: usize = HEADER_LEN + 16;

pub fn seal(key: &Key32, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let nonce = random_bytes::<24>();
    seal_with_nonce(key, &nonce, plaintext, aad)
}

/// Deterministic sealing for test vectors only.
pub fn seal_with_nonce(key: &Key32, nonce: &[u8; 24], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let ct = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption cannot fail for in-memory buffers");
    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.push(VERSION);
    out.push(ALG_XCHACHA20POLY1305);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    out
}

pub fn open(key: &Key32, envelope: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if envelope.len() < OVERHEAD {
        return Err(CryptoError::Malformed);
    }
    match envelope[0] {
        VERSION => {}
        v => return Err(CryptoError::UnsupportedVersion(v)),
    }
    match envelope[1] {
        ALG_XCHACHA20POLY1305 => {}
        a => return Err(CryptoError::UnsupportedAlgorithm(a)),
    }
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .decrypt(
            XNonce::from_slice(&envelope[2..HEADER_LEN]),
            Payload {
                msg: &envelope[HEADER_LEN..],
                aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)
}

/// Seals a 32-byte key under another key.
pub fn wrap_key(kek: &Key32, key: &Key32, aad: &[u8]) -> Vec<u8> {
    seal(kek, key.as_bytes(), aad)
}

pub fn unwrap_key(kek: &Key32, wrapped: &[u8], aad: &[u8]) -> Result<Key32> {
    let mut raw = open(kek, wrapped, aad)?;
    let k = Key32::from_slice(&raw);
    zeroize::Zeroize::zeroize(&mut raw);
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tamper() {
        let k = Key32::generate();
        let env = seal(&k, b"hello", b"aad");
        assert_eq!(open(&k, &env, b"aad").unwrap(), b"hello");
        assert_eq!(open(&k, &env, b"other"), Err(CryptoError::Decrypt));
        assert_eq!(
            open(&Key32::generate(), &env, b"aad"),
            Err(CryptoError::Decrypt)
        );
        for i in 0..env.len() {
            let mut bad = env.clone();
            bad[i] ^= 1;
            assert!(
                open(&k, &bad, b"aad").is_err(),
                "flipping byte {i} must fail"
            );
        }
        assert_eq!(open(&k, &env[..10], b"aad"), Err(CryptoError::Malformed));
    }

    #[test]
    fn empty_plaintext() {
        let k = Key32::generate();
        let env = seal(&k, b"", b"");
        assert_eq!(env.len(), OVERHEAD);
        assert_eq!(open(&k, &env, b"").unwrap(), b"");
    }

    #[test]
    fn nonces_differ() {
        let k = Key32::generate();
        assert_ne!(seal(&k, b"x", b""), seal(&k, b"x", b""));
    }
}
