//! Chunked encryption for attachments (the STREAM construction):
//!
//! ```text
//! header:  [version = 1][algorithm = 2][nonce prefix: 19 bytes]
//! chunks:  XChaCha20-Poly1305(chunk_i), nonce = prefix ‖ u32 BE i ‖ last-flag byte
//! ```
//!
//! Every chunk is 1 MiB of plaintext except the last (which may be empty). The
//! counter stops reordering, the last-flag stops truncation, and the associated
//! data binds the stream to its attachment ID.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::{random_bytes, CryptoError, Key32, Result};

pub const VERSION: u8 = 1;
pub const ALG_XCHACHA20POLY1305_STREAM: u8 = 2;
pub const CHUNK: usize = 1024 * 1024;
const TAG: usize = 16;
pub const HEADER_LEN: usize = 2 + 19;

fn nonce(prefix: &[u8; 19], counter: u32, last: bool) -> [u8; 24] {
    let mut n = [0u8; 24];
    n[..19].copy_from_slice(prefix);
    n[19..23].copy_from_slice(&counter.to_be_bytes());
    n[23] = last as u8;
    n
}

/// Size of the encrypted stream for a plaintext of `len` bytes.
pub fn encrypted_len(len: usize) -> usize {
    let chunks = if len == 0 { 1 } else { len.div_ceil(CHUNK) };
    HEADER_LEN + len + chunks * TAG
}

pub fn encrypt(key: &Key32, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let prefix = random_bytes::<19>();
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let mut out = Vec::with_capacity(encrypted_len(plaintext.len()));
    out.push(VERSION);
    out.push(ALG_XCHACHA20POLY1305_STREAM);
    out.extend_from_slice(&prefix);
    let chunks: Vec<&[u8]> = if plaintext.is_empty() { vec![&[][..]] } else { plaintext.chunks(CHUNK).collect() };
    let n = chunks.len();
    for (i, chunk) in chunks.into_iter().enumerate() {
        let counter = u32::try_from(i).expect("attachments are far below 4 PiB");
        let ct = cipher
            .encrypt(XNonce::from_slice(&nonce(&prefix, counter, i + 1 == n)), Payload { msg: chunk, aad })
            .expect("in-memory encryption cannot fail");
        out.extend_from_slice(&ct);
    }
    out
}

pub fn decrypt(key: &Key32, aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < HEADER_LEN + TAG {
        return Err(CryptoError::Malformed);
    }
    if data[0] != VERSION {
        return Err(CryptoError::UnsupportedVersion(data[0]));
    }
    if data[1] != ALG_XCHACHA20POLY1305_STREAM {
        return Err(CryptoError::UnsupportedAlgorithm(data[1]));
    }
    let prefix: [u8; 19] = data[2..HEADER_LEN].try_into().expect("length checked");
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let body = &data[HEADER_LEN..];
    let mut out = Vec::with_capacity(body.len());
    let chunks: Vec<&[u8]> = body.chunks(CHUNK + TAG).collect();
    let n = chunks.len();
    for (i, chunk) in chunks.into_iter().enumerate() {
        if chunk.len() < TAG {
            return Err(CryptoError::Malformed);
        }
        let counter = u32::try_from(i).map_err(|_| CryptoError::Malformed)?;
        let pt = cipher
            .decrypt(XNonce::from_slice(&nonce(&prefix, counter, i + 1 == n)), Payload { msg: chunk, aad })
            .map_err(|_| CryptoError::Decrypt)?;
        out.extend_from_slice(&pt);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_at_chunk_boundaries() {
        let k = Key32::generate();
        for len in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 2 * CHUNK + 5] {
            let data: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
            let enc = encrypt(&k, b"att", &data);
            assert_eq!(enc.len(), encrypted_len(len), "len {len}");
            assert_eq!(decrypt(&k, b"att", &enc).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn detects_truncation_reordering_and_wrong_aad() {
        let k = Key32::generate();
        let data = vec![9u8; 2 * CHUNK + 10];
        let enc = encrypt(&k, b"att", &data);
        // drop the last chunk: the new last chunk was not sealed as last
        assert!(decrypt(&k, b"att", &enc[..HEADER_LEN + 2 * (CHUNK + TAG)]).is_err());
        // swap the first two chunks
        let mut swapped = enc[..HEADER_LEN].to_vec();
        swapped.extend_from_slice(&enc[HEADER_LEN + CHUNK + TAG..HEADER_LEN + 2 * (CHUNK + TAG)]);
        swapped.extend_from_slice(&enc[HEADER_LEN..HEADER_LEN + CHUNK + TAG]);
        swapped.extend_from_slice(&enc[HEADER_LEN + 2 * (CHUNK + TAG)..]);
        assert!(decrypt(&k, b"att", &swapped).is_err());
        assert!(decrypt(&k, b"other", &enc).is_err());
    }
}
