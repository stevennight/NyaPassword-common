//! SSH keys and the ssh-agent protocol (design doc §10.3).
//!
//! Pure logic, no I/O, so it also builds for `wasm32-unknown-unknown`:
//! - keys: parse OpenSSH (incl. bcrypt-pbkdf + aes256-ctr / aes256-gcm
//!   encryption), PKCS#8 (plain and PBES2-encrypted), PKCS#1 RSA and SEC1 EC
//!   PEM (incl. legacy OpenSSL `Proc-Type: 4,ENCRYPTED`); generate Ed25519,
//!   ECDSA P-256 and RSA 3072/4096; OpenSSH public keys and SHA256 fingerprints;
//! - [`agent`]: the ssh-agent message handler the desktop app plugs into its
//!   named pipe (`\\.\pipe\openssh-ssh-agent`) or Unix socket;
//! - SSHSIG signing / verification for git commit signing.

pub mod agent;
mod keys;
mod pem;
mod wire;

pub use agent::{
    deframe, frame, Agent, FrameError, Identity, KeySource, PrivateKeyText, SignPurpose,
    SignRequest,
};
pub use keys::{
    export_openssh, generate, load_private_key, parse_private_key, parse_public_key,
    parse_public_key_blob, GeneratedKey, KeyFormat, KeyInfo, KeyKind, PublicKeyInfo,
};
/// The underlying RustCrypto `ssh-key` crate (0.6), for callers that need more.
pub use ssh_key;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SshError {
    #[error("not a recognized private key")]
    UnrecognizedFormat,
    #[error("this is a public key, not a private key")]
    NotAPrivateKey,
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("the private key is encrypted; a passphrase is required")]
    PassphraseRequired,
    #[error("wrong passphrase")]
    WrongPassphrase,
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("signing failed: {0}")]
    Signing(String),
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
}

impl From<ssh_key::Error> for SshError {
    fn from(e: ssh_key::Error) -> Self {
        match e {
            ssh_key::Error::AlgorithmUnknown | ssh_key::Error::AlgorithmUnsupported { .. } => {
                SshError::Unsupported(e.to_string())
            }
            ssh_key::Error::Encrypted => SshError::PassphraseRequired,
            other => SshError::InvalidKey(other.to_string()),
        }
    }
}

/// Signs `data` as SSHSIG (what `ssh-keygen -Y sign -n <namespace>` and git's
/// `gpg.format = ssh` produce), with SHA-512. Returns the armored
/// `-----BEGIN SSH SIGNATURE-----` text.
pub fn sshsig_sign(
    private_openssh: &str,
    namespace: &str,
    data: &[u8],
) -> Result<String, SshError> {
    sshsig_sign_with_passphrase(private_openssh, None, namespace, data)
}

/// [`sshsig_sign`] for a passphrase-protected key.
pub fn sshsig_sign_with_passphrase(
    private_key: &str,
    passphrase: Option<&str>,
    namespace: &str,
    data: &[u8],
) -> Result<String, SshError> {
    if namespace.is_empty() {
        return Err(SshError::Signing(
            "SSHSIG namespace must not be empty".into(),
        ));
    }
    let key = load_private_key(private_key, passphrase)?;
    let sig = keys::sshsig(&key, namespace, data)?;
    Ok(sig.to_pem(ssh_key::LineEnding::LF)?)
}

/// Verifies an armored SSHSIG over `data` against an OpenSSH public key and namespace.
pub fn sshsig_verify(
    public_openssh: &str,
    namespace: &str,
    data: &[u8],
    armored: &str,
) -> Result<(), SshError> {
    let public = ssh_key::PublicKey::from_openssh(public_openssh.trim())
        .map_err(|e| SshError::InvalidKey(e.to_string()))?;
    let sig = ssh_key::SshSig::from_pem(armored.trim())
        .map_err(|e| SshError::InvalidSignature(e.to_string()))?;
    public
        .verify(namespace, data, &sig)
        .map_err(|e| SshError::InvalidSignature(e.to_string()))
}
