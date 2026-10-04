//! PEM text handling, including the legacy OpenSSL encryption headers
//! (`Proc-Type: 4,ENCRYPTED` / `DEK-Info: AES-128-CBC,<iv>`) that strict
//! RFC 7468 parsers reject. `ssh-keygen` before OpenSSH 7.8 wrote RSA/EC keys
//! this way, so plenty of old `id_rsa` files look like this.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use md5::{Digest, Md5};
use zeroize::Zeroizing;

use crate::SshError;

pub(crate) struct Pem {
    pub label: String,
    pub headers: Vec<(String, String)>,
    pub der: Zeroizing<Vec<u8>>,
}

impl Pem {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Whether the body is encrypted with the legacy OpenSSL scheme.
    pub fn legacy_encrypted(&self) -> bool {
        self.header("Proc-Type")
            .is_some_and(|v| v.replace(' ', "").eq_ignore_ascii_case("4,ENCRYPTED"))
    }

    /// Decrypts a legacy-encrypted body (EVP_BytesToKey with MD5, AES-CBC).
    pub fn legacy_decrypt(&self, passphrase: &str) -> Result<Zeroizing<Vec<u8>>, SshError> {
        let dek = self
            .header("DEK-Info")
            .ok_or_else(|| SshError::InvalidKey("encrypted PEM without DEK-Info".into()))?;
        let (cipher, iv_hex) = dek
            .split_once(',')
            .ok_or_else(|| SshError::InvalidKey("malformed DEK-Info".into()))?;
        let iv = hex::decode(iv_hex.trim())
            .map_err(|_| SshError::InvalidKey("malformed DEK-Info IV".into()))?;
        let key_len = match cipher.trim().to_ascii_uppercase().as_str() {
            "AES-128-CBC" => 16,
            "AES-192-CBC" => 24,
            "AES-256-CBC" => 32,
            other => return Err(SshError::Unsupported(format!("legacy PEM cipher {other}"))),
        };
        if iv.len() != 16 {
            return Err(SshError::InvalidKey("DEK-Info IV must be 16 bytes".into()));
        }
        let key = evp_bytes_to_key(passphrase.as_bytes(), &iv[..8], key_len);
        let out = match key_len {
            16 => cbc::Decryptor::<aes::Aes128>::new_from_slices(&key, &iv)
                .ok()
                .and_then(|d| d.decrypt_padded_vec_mut::<Pkcs7>(&self.der).ok()),
            24 => cbc::Decryptor::<aes::Aes192>::new_from_slices(&key, &iv)
                .ok()
                .and_then(|d| d.decrypt_padded_vec_mut::<Pkcs7>(&self.der).ok()),
            _ => cbc::Decryptor::<aes::Aes256>::new_from_slices(&key, &iv)
                .ok()
                .and_then(|d| d.decrypt_padded_vec_mut::<Pkcs7>(&self.der).ok()),
        };
        out.map(Zeroizing::new).ok_or(SshError::WrongPassphrase)
    }
}

/// OpenSSL `EVP_BytesToKey(cipher, MD5, salt, pass, count = 1)`, key part only.
pub(crate) fn evp_bytes_to_key(pass: &[u8], salt: &[u8], key_len: usize) -> Zeroizing<Vec<u8>> {
    let mut key = Zeroizing::new(Vec::with_capacity(key_len + 16));
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(pass);
        h.update(salt);
        prev = h.finalize().to_vec();
        key.extend_from_slice(&prev);
    }
    key.truncate(key_len);
    key
}

/// Finds the first PEM block in `text` (surrounding text is ignored).
pub(crate) fn parse(text: &str) -> Result<Pem, SshError> {
    let mut lines = text.lines().map(str::trim);
    let label = loop {
        let line = lines.next().ok_or(SshError::UnrecognizedFormat)?;
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            if let Some(label) = rest.strip_suffix("-----") {
                break label.to_string();
            }
        }
    };
    let end = format!("-----END {label}-----");
    let mut headers = Vec::new();
    let mut body = String::new();
    let mut in_headers = true;
    let mut closed = false;
    for line in lines {
        if line == end {
            closed = true;
            break;
        }
        if in_headers {
            if let Some((k, v)) = line.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
                continue;
            }
            in_headers = false;
        }
        body.push_str(line);
    }
    if !closed {
        return Err(SshError::InvalidKey(format!("missing {end}")));
    }
    let der = STANDARD
        .decode(body.trim_end_matches('=').as_bytes())
        .or_else(|_| STANDARD.decode(body.as_bytes()));
    let der = der.map_err(|_| SshError::InvalidKey("PEM body is not base64".into()))?;
    Ok(Pem {
        label,
        headers,
        der: Zeroizing::new(der),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evp_bytes_to_key_matches_openssl() {
        // `openssl enc -aes-{128,256}-cbc -k password -S 0102030405060708 -P -md md5`
        let salt = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(
            hex::encode(&*evp_bytes_to_key(b"password", &salt, 16)),
            "e7b0971e52ca5cc8d0539fb3412f6316"
        );
        assert_eq!(
            hex::encode(&*evp_bytes_to_key(b"password", &salt, 32)),
            "e7b0971e52ca5cc8d0539fb3412f6316f7ba2e6ee293d9f3457b99436b51ce02"
        );
    }

    #[test]
    fn parse_ignores_surrounding_text() {
        let text = "garbage\n-----BEGIN TEST-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAEC\n-----END TEST-----\ntrailer";
        let pem = parse(text).unwrap();
        assert_eq!(pem.label, "TEST");
        assert!(pem.legacy_encrypted());
        assert_eq!(&*pem.der, &[0, 1, 2]);
        assert!(parse("-----BEGIN X-----\nAAAA\n").is_err());
        assert!(parse("nothing here").is_err());
    }
}
