//! The Secret Key: 128 random bits generated on the user's device at
//! registration, never sent to the server, printed in the Emergency Kit.
//!
//! Text form: `A1-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX-C`
//! - `A1`: format version;
//! - 26 Crockford base32 characters: the 128 bits, big-endian, padded with 2 zero bits;
//! - `C`: one check character, `SHA-256("A1" ‖ raw)[0] & 31`, catching typos.
//!
//! Parsing ignores dashes, spaces and case, and accepts O for 0 and I / L for 1.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{random_bytes, sha256, CryptoError, Result};

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const PREFIX: &str = "A1";

#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct SecretKey([u8; 16]);

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

fn check_char(raw: &[u8; 16]) -> u8 {
    let mut data = Vec::with_capacity(18);
    data.extend_from_slice(PREFIX.as_bytes());
    data.extend_from_slice(raw);
    ALPHABET[(sha256(&data)[0] & 31) as usize]
}

fn decode_char(c: char) -> Option<u8> {
    let c = match c.to_ascii_uppercase() {
        'O' => '0',
        'I' | 'L' => '1',
        c => c,
    };
    ALPHABET.iter().position(|&a| a as char == c).map(|p| p as u8)
}

impl SecretKey {
    pub fn generate() -> Self {
        Self(random_bytes::<16>())
    }

    pub fn from_raw(raw: [u8; 16]) -> Self {
        Self(raw)
    }

    pub fn raw(&self) -> &[u8; 16] {
        &self.0
    }

    /// `A1-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX-C`.
    pub fn to_text(&self) -> String {
        // 26 × 5 = 130 bits: the 128-bit value followed by 2 zero bits. The last
        // character carries the lowest 3 value bits and the padding.
        let mut bits: u128 = u128::from_be_bytes(self.0);
        let mut chars = [0u8; 26];
        chars[25] = ALPHABET[((bits & 0b111) << 2) as usize];
        bits >>= 3;
        for c in chars[..25].iter_mut().rev() {
            *c = ALPHABET[(bits & 31) as usize];
            bits >>= 5;
        }
        let body = std::str::from_utf8(&chars).expect("alphabet is ASCII");
        format!(
            "{PREFIX}-{}-{}-{}-{}-{}-{}",
            &body[0..6],
            &body[6..11],
            &body[11..16],
            &body[16..21],
            &body[21..26],
            check_char(&self.0) as char
        )
    }

    pub fn parse(text: &str) -> Result<Self> {
        let cleaned: String = text.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
        let upper = cleaned.to_ascii_uppercase();
        let rest = upper.strip_prefix(PREFIX).ok_or(CryptoError::InvalidSecretKey("must start with A1"))?;
        let chars: Vec<char> = rest.chars().collect();
        if chars.len() != 27 {
            return Err(CryptoError::InvalidSecretKey("wrong length"));
        }
        let mut value: u128 = 0;
        for (i, c) in chars[..26].iter().enumerate() {
            let d = decode_char(*c).ok_or(CryptoError::InvalidSecretKey("invalid character"))? as u128;
            if i == 25 {
                if d & 0b11 != 0 {
                    return Err(CryptoError::InvalidSecretKey("invalid last character"));
                }
                value = (value << 3) | (d >> 2);
            } else {
                value = (value << 5) | d;
            }
        }
        let raw = value.to_be_bytes();
        let check = decode_char(chars[26]).ok_or(CryptoError::InvalidSecretKey("invalid check character"))?;
        if ALPHABET[check as usize] != check_char(&raw) {
            return Err(CryptoError::InvalidSecretKey("check character does not match (typo?)"));
        }
        Ok(Self(raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_many() {
        for _ in 0..2000 {
            let k = SecretKey::generate();
            let t = k.to_text();
            assert_eq!(t.len(), 35, "{t}"); // A1- + 6 + 4×5 + check + 5 dashes
            assert_eq!(SecretKey::parse(&t).unwrap(), k);
            assert_eq!(SecretKey::parse(&t.to_lowercase().replace('-', " ")).unwrap(), k);
        }
        for raw in [[0u8; 16], [0xff; 16]] {
            let k = SecretKey::from_raw(raw);
            assert_eq!(SecretKey::parse(&k.to_text()).unwrap(), k);
        }
    }

    #[test]
    fn detects_typos() {
        let k = SecretKey::from_raw(*b"0123456789abcdef");
        let t = k.to_text();
        let mut detected = 0;
        let mut total = 0;
        for (i, c) in t.char_indices().skip(3) {
            if c == '-' {
                continue;
            }
            let replacement = if c == 'Z' { 'Y' } else { 'Z' };
            let mut bad = t.clone();
            bad.replace_range(i..i + 1, &replacement.to_string());
            total += 1;
            if SecretKey::parse(&bad).is_err() {
                detected += 1;
            }
        }
        // a 5-bit check misses about 1 in 32 single-character typos
        assert!(detected * 10 >= total * 8, "{detected}/{total}");
    }

    #[test]
    fn confusable_characters() {
        let k = SecretKey::from_raw([0u8; 16]);
        let t = k.to_text().replace('0', "O");
        assert_eq!(SecretKey::parse(&t).unwrap(), k);
    }
}
