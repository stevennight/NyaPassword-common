//! Private/public key parsing, generation, export and raw signing.

use pkcs8::DecodePrivateKey;
use rand_core::OsRng;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, KeypairData, RsaKeypair};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, LineEnding, Mpint, PrivateKey, PublicKey};
use zeroize::Zeroizing;

use crate::{pem, SshError};

/// Key types [`generate`] can create.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyKind {
    #[default]
    Ed25519,
    EcdsaP256,
    Rsa3072,
    Rsa4096,
}

/// The container a private key was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    /// `-----BEGIN OPENSSH PRIVATE KEY-----` (optionally bcrypt-pbkdf encrypted).
    OpenSsh,
    /// `-----BEGIN PRIVATE KEY-----`.
    Pkcs8,
    /// `-----BEGIN ENCRYPTED PRIVATE KEY-----` (PBES2).
    Pkcs8Encrypted,
    /// `-----BEGIN RSA PRIVATE KEY-----` (optionally legacy-encrypted).
    Pkcs1,
    /// `-----BEGIN EC PRIVATE KEY-----` (optionally legacy-encrypted).
    Sec1,
}

/// What the vault shows for a private key (template `ssh_key` fields
/// `public_key`, `fingerprint`, `key_type`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    /// SSH algorithm name: `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`, ...
    pub algorithm: String,
    /// Human label: `Ed25519`, `ECDSA P-256`, `RSA 3072`, ...
    pub key_type: String,
    pub bits: u32,
    /// `<algorithm> <base64> [comment]`
    pub public_openssh: String,
    /// `SHA256:<base64 without padding>`, as `ssh-keygen -l` prints it.
    pub fingerprint: String,
    pub comment: String,
    /// The stored key text is passphrase-protected.
    pub encrypted: bool,
    pub format: KeyFormat,
}

/// A public key, e.g. from the item's `public_key` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyInfo {
    pub algorithm: String,
    pub key_type: String,
    pub bits: u32,
    pub public_openssh: String,
    pub fingerprint: String,
    pub comment: String,
    /// The SSH wire-format key blob (what the agent protocol uses).
    pub blob: Vec<u8>,
}

/// A freshly generated key pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedKey {
    /// Unencrypted `-----BEGIN OPENSSH PRIVATE KEY-----` text (LF line endings).
    pub private_openssh: String,
    pub public_openssh: String,
    pub fingerprint: String,
    pub algorithm: String,
    pub key_type: String,
}

fn none_if_empty(p: Option<&str>) -> Option<&str> {
    p.filter(|p| !p.is_empty())
}

/// Describes a key from its public half.
fn describe(public: &PublicKey) -> Result<(String, String, u32), SshError> {
    let algorithm = public.algorithm().as_str().to_string();
    let (label, bits) = match public.key_data() {
        KeyData::Ed25519(_) => ("Ed25519".to_string(), 256),
        KeyData::Ecdsa(k) => match k.curve() {
            EcdsaCurve::NistP256 => ("ECDSA P-256".to_string(), 256),
            EcdsaCurve::NistP384 => ("ECDSA P-384".to_string(), 384),
            EcdsaCurve::NistP521 => ("ECDSA P-521".to_string(), 521),
        },
        KeyData::Rsa(k) => {
            let bits = mpint_len_bits(&k.n);
            (format!("RSA {bits}"), bits)
        }
        KeyData::Dsa(_) => ("DSA".to_string(), 1024),
        KeyData::SkEd25519(_) => ("Ed25519-SK".to_string(), 256),
        KeyData::SkEcdsaSha2NistP256(_) => ("ECDSA-SK".to_string(), 256),
        _ => (algorithm.clone(), 0),
    };
    Ok((algorithm, label, bits))
}

fn mpint_len_bits(m: &Mpint) -> u32 {
    let bytes = m.as_positive_bytes().unwrap_or_default();
    match bytes.first() {
        None => 0,
        Some(&top) => (bytes.len() as u32 - 1) * 8 + (8 - top.leading_zeros()),
    }
}

fn fingerprint(public: &PublicKey) -> String {
    public.fingerprint(HashAlg::Sha256).to_string()
}

fn ecdsa_p256(secret: p256::SecretKey) -> KeypairData {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let public = secret.public_key().to_encoded_point(false);
    KeypairData::Ecdsa(EcdsaKeypair::NistP256 {
        public,
        private: secret.into(),
    })
}

fn ecdsa_p384(secret: p384::SecretKey) -> KeypairData {
    use p384::elliptic_curve::sec1::ToEncodedPoint;
    let public = secret.public_key().to_encoded_point(false);
    KeypairData::Ecdsa(EcdsaKeypair::NistP384 {
        public,
        private: secret.into(),
    })
}

fn rsa_keypair(key: &rsa::RsaPrivateKey) -> Result<KeypairData, SshError> {
    RsaKeypair::try_from(key)
        .map(KeypairData::Rsa)
        .map_err(|e| SshError::Unsupported(format!("RSA key: {e}")))
}

fn from_pkcs8_der(der: &[u8]) -> Result<KeypairData, SshError> {
    if let Ok(k) = ed25519_dalek::SigningKey::from_pkcs8_der(der) {
        return Ok(KeypairData::Ed25519(Ed25519Keypair::from(k)));
    }
    if let Ok(k) = p256::SecretKey::from_pkcs8_der(der) {
        return Ok(ecdsa_p256(k));
    }
    if let Ok(k) = p384::SecretKey::from_pkcs8_der(der) {
        return Ok(ecdsa_p384(k));
    }
    if let Ok(k) = rsa::RsaPrivateKey::from_pkcs8_der(der) {
        return rsa_keypair(&k);
    }
    match pkcs8::PrivateKeyInfo::try_from(der) {
        Ok(info) => Err(SshError::Unsupported(format!(
            "PKCS#8 key algorithm {}",
            info.algorithm.oid
        ))),
        Err(e) => Err(SshError::InvalidKey(format!("PKCS#8: {e}"))),
    }
}

fn from_sec1_der(der: &[u8]) -> Result<KeypairData, SshError> {
    if let Ok(k) = p256::SecretKey::from_sec1_der(der) {
        return Ok(ecdsa_p256(k));
    }
    if let Ok(k) = p384::SecretKey::from_sec1_der(der) {
        return Ok(ecdsa_p384(k));
    }
    Err(SshError::Unsupported(
        "EC key on an unsupported curve (P-256 and P-384 are supported)".into(),
    ))
}

/// Reads any supported private key. An OpenSSH key without a passphrase is
/// returned still encrypted (its public half is readable); every other
/// encrypted format needs the passphrase.
fn read(text: &str, passphrase: Option<&str>) -> Result<(PrivateKey, KeyFormat, bool), SshError> {
    let passphrase = none_if_empty(passphrase);
    let pem = pem::parse(text)?;
    let legacy = pem.legacy_encrypted();
    let legacy_body = || -> Result<Zeroizing<Vec<u8>>, SshError> {
        if !legacy {
            return Ok(pem.der.clone());
        }
        pem.legacy_decrypt(passphrase.ok_or(SshError::PassphraseRequired)?)
    };
    let (data, format, encrypted) = match pem.label.as_str() {
        "OPENSSH PRIVATE KEY" => {
            let key = PrivateKey::from_bytes(&pem.der)?;
            if !key.is_encrypted() {
                return Ok((key, KeyFormat::OpenSsh, false));
            }
            let Some(pass) = passphrase else {
                return Ok((key, KeyFormat::OpenSsh, true));
            };
            let key = key.decrypt(pass).map_err(|e| match e {
                ssh_key::Error::Crypto | ssh_key::Error::Encoding(_) => SshError::WrongPassphrase,
                other => SshError::from(other),
            })?;
            return Ok((key, KeyFormat::OpenSsh, true));
        }
        "PRIVATE KEY" => (from_pkcs8_der(&pem.der)?, KeyFormat::Pkcs8, false),
        "ENCRYPTED PRIVATE KEY" => {
            let pass = passphrase.ok_or(SshError::PassphraseRequired)?;
            let info = pkcs8::EncryptedPrivateKeyInfo::try_from(pem.der.as_slice())
                .map_err(|e| SshError::InvalidKey(format!("PKCS#8: {e}")))?;
            let doc = info.decrypt(pass).map_err(|_| SshError::WrongPassphrase)?;
            (
                from_pkcs8_der(doc.as_bytes())?,
                KeyFormat::Pkcs8Encrypted,
                true,
            )
        }
        "RSA PRIVATE KEY" => {
            let der = legacy_body()?;
            let key = rsa::RsaPrivateKey::from_pkcs1_der(&der).map_err(|e| {
                if legacy {
                    SshError::WrongPassphrase
                } else {
                    SshError::InvalidKey(format!("PKCS#1: {e}"))
                }
            })?;
            (rsa_keypair(&key)?, KeyFormat::Pkcs1, legacy)
        }
        "EC PRIVATE KEY" => {
            let der = legacy_body()?;
            let data =
                from_sec1_der(&der)
                    .map_err(|e| if legacy { SshError::WrongPassphrase } else { e })?;
            (data, KeyFormat::Sec1, legacy)
        }
        "OPENSSH PUBLIC KEY" | "PUBLIC KEY" | "RSA PUBLIC KEY" | "SSH2 PUBLIC KEY" => {
            return Err(SshError::NotAPrivateKey);
        }
        other => return Err(SshError::Unsupported(format!("PEM type {other:?}"))),
    };
    Ok((PrivateKey::new(data, "")?, format, encrypted))
}

/// Loads a private key in any supported format and returns it decrypted.
pub fn load_private_key(text: &str, passphrase: Option<&str>) -> Result<PrivateKey, SshError> {
    let (key, _, _) = read(text, passphrase)?;
    if key.is_encrypted() {
        return Err(SshError::PassphraseRequired);
    }
    Ok(key)
}

/// Parses a private key (OpenSSH, PKCS#8, encrypted PKCS#8, PKCS#1 RSA, SEC1 EC;
/// legacy-encrypted PEM too) and describes it.
///
/// An encrypted OpenSSH key can be described without the passphrase (its
/// public half is stored in clear); when a passphrase is given it is checked
/// and a wrong one fails with [`SshError::WrongPassphrase`]. Other encrypted
/// formats need the passphrase. An empty passphrase counts as none.
pub fn parse_private_key(text: &str, passphrase: Option<&str>) -> Result<KeyInfo, SshError> {
    let (key, format, encrypted) = read(text, passphrase)?;
    let public = key.public_key();
    let (algorithm, key_type, bits) = describe(public)?;
    Ok(KeyInfo {
        algorithm,
        key_type,
        bits,
        public_openssh: public.to_openssh()?,
        fingerprint: fingerprint(public),
        comment: public.comment().to_string(),
        encrypted,
        format,
    })
}

/// Parses an OpenSSH public key line (`ssh-ed25519 AAAA... comment`).
pub fn parse_public_key(text: &str) -> Result<PublicKeyInfo, SshError> {
    let line = text.trim();
    let public = PublicKey::from_openssh(line)
        .map_err(|e| SshError::InvalidKey(format!("public key: {e}")))?;
    public_info(&public)
}

/// Describes a public key given as an SSH wire-format blob.
pub fn parse_public_key_blob(blob: &[u8]) -> Result<PublicKeyInfo, SshError> {
    let public = PublicKey::from_bytes(blob)
        .map_err(|e| SshError::InvalidKey(format!("public key blob: {e}")))?;
    public_info(&public)
}

fn public_info(public: &PublicKey) -> Result<PublicKeyInfo, SshError> {
    let (algorithm, key_type, bits) = describe(public)?;
    Ok(PublicKeyInfo {
        algorithm,
        key_type,
        bits,
        public_openssh: public.to_openssh()?,
        fingerprint: fingerprint(public),
        comment: public.comment().to_string(),
        blob: public.to_bytes()?,
    })
}

/// Generates a new key pair; the private key is returned unencrypted in
/// OpenSSH format (the vault encrypts it; use [`export_openssh`] to add a
/// passphrase for a file on disk).
pub fn generate(kind: KeyKind, comment: &str) -> Result<GeneratedKey, SshError> {
    let mut rng = OsRng;
    let data = match kind {
        KeyKind::Ed25519 => KeypairData::Ed25519(Ed25519Keypair::random(&mut rng)),
        KeyKind::EcdsaP256 => {
            KeypairData::Ecdsa(EcdsaKeypair::random(&mut rng, EcdsaCurve::NistP256)?)
        }
        KeyKind::Rsa3072 => KeypairData::Rsa(RsaKeypair::random(&mut rng, 3072)?),
        KeyKind::Rsa4096 => KeypairData::Rsa(RsaKeypair::random(&mut rng, 4096)?),
    };
    let key = PrivateKey::new(data, comment)?;
    let public = key.public_key();
    let (algorithm, key_type, _) = describe(public)?;
    Ok(GeneratedKey {
        private_openssh: key.to_openssh(LineEnding::LF)?.to_string(),
        public_openssh: public.to_openssh()?,
        fingerprint: fingerprint(public),
        algorithm,
        key_type,
    })
}

/// Re-encodes any supported private key as OpenSSH text, optionally
/// encrypted with `new_passphrase` (bcrypt-pbkdf + aes256-ctr, as
/// `ssh-keygen` does) and with a new comment.
pub fn export_openssh(
    text: &str,
    passphrase: Option<&str>,
    new_passphrase: Option<&str>,
    comment: Option<&str>,
) -> Result<String, SshError> {
    let mut key = load_private_key(text, passphrase)?;
    if let Some(c) = comment {
        key.set_comment(c);
    }
    let key = match none_if_empty(new_passphrase) {
        Some(p) => key.encrypt(&mut OsRng, p)?,
        None => key,
    };
    Ok(key.to_openssh(LineEnding::LF)?.to_string())
}

/// Hash for RSA signatures (`ssh-rsa` = SHA-1, `rsa-sha2-256`, `rsa-sha2-512`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RsaHash {
    Sha1,
    Sha256,
    Sha512,
}

/// Builds an `rsa` private key from OpenSSH key material.
///
/// Not `rsa::RsaPrivateKey::try_from(&RsaKeypair)`: ssh-key 0.6.7 passes the
/// primes as `[p, p]` there, which fails key validation, so its own RSA
/// signing does not work. This builds it from `[p, q]`.
fn rsa_private(kp: &RsaKeypair) -> Result<rsa::RsaPrivateKey, SshError> {
    let big = |m: &Mpint| -> Result<rsa::BigUint, SshError> {
        m.as_positive_bytes()
            .map(rsa::BigUint::from_bytes_be)
            .ok_or_else(|| SshError::InvalidKey("negative RSA parameter".into()))
    };
    rsa::RsaPrivateKey::from_components(
        big(&kp.public.n)?,
        big(&kp.public.e)?,
        big(&kp.private.d)?,
        vec![big(&kp.private.p)?, big(&kp.private.q)?],
    )
    .map_err(|e| SshError::InvalidKey(format!("RSA key: {e}")))
}

/// Signs `data` and returns `(signature algorithm name, signature bytes)` as
/// they go into an SSH signature blob.
pub(crate) fn sign_raw(
    key: &PrivateKey,
    data: &[u8],
    rsa_hash: RsaHash,
) -> Result<(String, Vec<u8>), SshError> {
    match key.key_data() {
        KeypairData::Rsa(kp) => {
            let private = rsa_private(kp)?;
            if private.n().bits() < 1024 {
                return Err(SshError::Unsupported("RSA keys under 1024 bits".into()));
            }
            let mut rng = OsRng;
            let (name, sig) = match rsa_hash {
                RsaHash::Sha1 => (
                    "ssh-rsa",
                    rsa::pkcs1v15::SigningKey::<sha1::Sha1>::new(private)
                        .try_sign_with_rng(&mut rng, data),
                ),
                RsaHash::Sha256 => (
                    "rsa-sha2-256",
                    rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private)
                        .try_sign_with_rng(&mut rng, data),
                ),
                RsaHash::Sha512 => (
                    "rsa-sha2-512",
                    rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(private)
                        .try_sign_with_rng(&mut rng, data),
                ),
            };
            let sig = sig.map_err(|e| SshError::Signing(e.to_string()))?;
            Ok((name.to_string(), sig.to_vec()))
        }
        KeypairData::Ed25519(_) | KeypairData::Ecdsa(_) => {
            let sig: ssh_key::Signature = key
                .key_data()
                .try_sign(data)
                .map_err(|e| SshError::Signing(e.to_string()))?;
            Ok((
                sig.algorithm().as_str().to_string(),
                sig.as_bytes().to_vec(),
            ))
        }
        _ => Err(SshError::Unsupported(format!(
            "signing with {}",
            key.algorithm().as_str()
        ))),
    }
}

/// `string algorithm ‖ string signature` (RFC 4253 §6.6).
pub(crate) fn signature_blob(algorithm: &str, sig: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + algorithm.len() + sig.len());
    crate::wire::put_string(&mut out, algorithm.as_bytes());
    crate::wire::put_string(&mut out, sig);
    out
}

/// Signs SSHSIG data (`ssh-keygen -Y sign` / git commit signing).
pub(crate) fn sshsig(
    key: &PrivateKey,
    namespace: &str,
    data: &[u8],
) -> Result<ssh_key::SshSig, SshError> {
    let hash = HashAlg::Sha512;
    let signed = ssh_key::SshSig::signed_data(namespace, hash, data)?;
    let (alg, sig) = sign_raw(key, &signed, RsaHash::Sha512)?;
    let signature = ssh_key::Signature::new(Algorithm::new(&alg)?, sig)?;
    Ok(ssh_key::SshSig::new(
        key.public_key().key_data().clone(),
        namespace,
        hash,
        signature,
    )?)
}
