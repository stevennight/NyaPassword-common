//! The ssh-agent protocol (draft-miller-ssh-agent), without any I/O.
//!
//! The desktop app owns the socket / named pipe: it reads bytes, splits them
//! into messages with [`deframe`], passes each message body to
//! [`Agent::handle`] and writes the reply back with [`frame`]. Keys come only
//! from the vault (through [`KeySource`]); adding or removing identities over
//! the protocol is refused.

use zeroize::Zeroizing;

use crate::keys::{self, RsaHash};
use crate::wire::{put_string, put_u32, Reader};

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
pub const SSH_AGENTC_EXTENSION: u8 = 27;

/// Sign request flag: RSA signature with SHA-256 (`rsa-sha2-256`).
pub const SSH_AGENT_RSA_SHA2_256: u32 = 2;
/// Sign request flag: RSA signature with SHA-512 (`rsa-sha2-512`).
pub const SSH_AGENT_RSA_SHA2_512: u32 = 4;

/// Largest message accepted (OpenSSH's `AGENT_MAX_LEN`).
pub const MAX_MESSAGE_LEN: usize = 256 * 1024;

/// One identity offered to clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// SSH wire-format public key blob (see [`crate::parse_public_key`]).
    pub key_blob: Vec<u8>,
    /// Usually the item title or the key comment.
    pub comment: String,
}

/// Private key material for one identity.
pub struct PrivateKeyText {
    /// The item's `private_key` field (any format [`crate::parse_private_key`] reads).
    pub private_key: Zeroizing<String>,
    /// The item's `passphrase` field, if the key text is encrypted.
    pub passphrase: Option<Zeroizing<String>>,
}

/// Where the agent's keys come from (the unlocked vault).
pub trait KeySource {
    /// Public keys to offer, in order.
    fn identities(&self) -> Vec<Identity>;

    /// The private key for `key_blob`. Called only after the user approved
    /// the signature, so the vault can decrypt the item lazily.
    fn private_key(&self, key_blob: &[u8]) -> Option<PrivateKeyText>;
}

/// What a signature is going to be used for, parsed from the data to sign so
/// the confirmation prompt can say "log in as git to ..." or "sign a git commit".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignPurpose {
    /// SSH user authentication (RFC 4252 §7).
    UserAuth {
        user: String,
        service: String,
        /// `publickey` or `publickey-hostbound-v00@openssh.com`.
        method: String,
        /// Fingerprint of the server host key, if the client bound it
        /// (OpenSSH 8.9+ `publickey-hostbound`).
        host_key_fingerprint: Option<String>,
    },
    /// An SSHSIG signature (`ssh-keygen -Y sign`), e.g. namespace `git`.
    SshSig {
        namespace: String,
    },
    Unknown,
}

/// A pending signature, shown to the user before signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    pub key_blob: Vec<u8>,
    /// The identity's comment.
    pub comment: String,
    pub fingerprint: String,
    /// Signature algorithm that will be used (`ssh-ed25519`, `rsa-sha2-256`, ...).
    pub algorithm: String,
    pub data: Vec<u8>,
    pub flags: u32,
    pub purpose: SignPurpose,
}

/// Adds the `u32` length prefix to a message body.
pub fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    put_u32(&mut out, body.len() as u32);
    out.extend_from_slice(body);
    out
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("agent message of {0} bytes exceeds the limit")]
    TooLong(usize),
}

/// Splits the first complete message off `buf`.
///
/// Returns `Ok(None)` if more bytes are needed, or `Ok(Some((body, consumed)))`.
/// A message longer than [`MAX_MESSAGE_LEN`] is an error; the connection
/// should then be closed, as OpenSSH's agent does.
pub fn deframe(buf: &[u8]) -> Result<Option<(&[u8], usize)>, FrameError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_MESSAGE_LEN {
        return Err(FrameError::TooLong(len));
    }
    if buf.len() - 4 < len {
        return Ok(None);
    }
    Ok(Some((&buf[4..4 + len], 4 + len)))
}

/// The protocol state machine. Holds configuration only; no keys, no I/O.
#[derive(Debug, Clone, Default)]
pub struct Agent {
    /// Allow legacy `ssh-rsa` (SHA-1) signatures when a client asks for an
    /// RSA signature without a SHA-2 flag. Off by default: OpenSSH 8.8+ never
    /// needs it, and it only matters for very old servers.
    pub allow_rsa_sha1: bool,
}

fn failure() -> Vec<u8> {
    vec![SSH_AGENT_FAILURE]
}

impl Agent {
    pub fn new() -> Self {
        Self::default()
    }

    /// Handles one message body (without the length prefix) and returns the
    /// reply body (frame it with [`frame`]). Never panics on malformed input;
    /// anything unsupported or invalid gets `SSH_AGENT_FAILURE`.
    ///
    /// `approve` is called for every sign request whose key is known, before
    /// the private key is read; returning `false` denies it.
    pub fn handle(
        &self,
        request: &[u8],
        keys: &dyn KeySource,
        approve: &mut dyn FnMut(&SignRequest) -> bool,
    ) -> Vec<u8> {
        let mut r = Reader::new(request);
        match r.u8() {
            Some(SSH_AGENTC_REQUEST_IDENTITIES) if r.is_empty() => identities_answer(keys),
            Some(SSH_AGENTC_SIGN_REQUEST) => {
                self.sign(&mut r, keys, approve).unwrap_or_else(failure)
            }
            // Add/remove/lock/smartcard/extension requests: keys come only
            // from the vault. (OpenSSH treats a failed `session-bind@openssh.com`
            // extension as non-fatal.)
            _ => failure(),
        }
    }

    fn sign(
        &self,
        r: &mut Reader<'_>,
        keys: &dyn KeySource,
        approve: &mut dyn FnMut(&SignRequest) -> bool,
    ) -> Option<Vec<u8>> {
        let key_blob = r.string()?;
        let data = r.string()?;
        let flags = r.u32()?;

        let identity = keys
            .identities()
            .into_iter()
            .find(|i| i.key_blob == key_blob)?;
        let public = keys::parse_public_key_blob(key_blob).ok()?;
        let is_rsa = public.algorithm == "ssh-rsa";
        let rsa_hash = if flags & SSH_AGENT_RSA_SHA2_512 != 0 {
            RsaHash::Sha512
        } else if flags & SSH_AGENT_RSA_SHA2_256 != 0 {
            RsaHash::Sha256
        } else {
            RsaHash::Sha1
        };
        if is_rsa && rsa_hash == RsaHash::Sha1 && !self.allow_rsa_sha1 {
            return None;
        }
        let algorithm = match (is_rsa, rsa_hash) {
            (true, RsaHash::Sha512) => "rsa-sha2-512".to_string(),
            (true, RsaHash::Sha256) => "rsa-sha2-256".to_string(),
            (true, RsaHash::Sha1) => "ssh-rsa".to_string(),
            (false, _) => public.algorithm.clone(),
        };

        let request = SignRequest {
            key_blob: key_blob.to_vec(),
            comment: identity.comment,
            fingerprint: public.fingerprint,
            algorithm,
            data: data.to_vec(),
            flags,
            purpose: parse_purpose(data),
        };
        if !approve(&request) {
            return None;
        }

        let material = keys.private_key(key_blob)?;
        let key = keys::load_private_key(
            &material.private_key,
            material.passphrase.as_deref().map(|s| s.as_str()),
        )
        .ok()?;
        // The vault entry must really be the key that was offered.
        if key.public_key().to_bytes().ok()? != key_blob {
            return None;
        }
        let (alg, sig) = keys::sign_raw(&key, data, rsa_hash).ok()?;

        let mut out = vec![SSH_AGENT_SIGN_RESPONSE];
        put_string(&mut out, &keys::signature_blob(&alg, &sig));
        Some(out)
    }
}

fn identities_answer(keys: &dyn KeySource) -> Vec<u8> {
    let ids = keys.identities();
    let mut out = vec![SSH_AGENT_IDENTITIES_ANSWER];
    put_u32(&mut out, ids.len() as u32);
    for id in &ids {
        put_string(&mut out, &id.key_blob);
        put_string(&mut out, id.comment.as_bytes());
    }
    out
}

/// Recognizes SSH user-authentication data and SSHSIG data.
pub fn parse_purpose(data: &[u8]) -> SignPurpose {
    if let Some(rest) = data.strip_prefix(b"SSHSIG") {
        let mut r = Reader::new(rest);
        if let Some(ns) = r.utf8() {
            return SignPurpose::SshSig {
                namespace: ns.to_string(),
            };
        }
        return SignPurpose::Unknown;
    }
    parse_userauth(data).unwrap_or(SignPurpose::Unknown)
}

fn parse_userauth(data: &[u8]) -> Option<SignPurpose> {
    const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
    let mut r = Reader::new(data);
    let session_id = r.string()?;
    if session_id.is_empty() || r.u8()? != SSH_MSG_USERAUTH_REQUEST {
        return None;
    }
    let user = r.utf8()?.to_string();
    let service = r.utf8()?.to_string();
    let method = r.utf8()?.to_string();
    if !method.starts_with("publickey") || r.u8()? != 1 {
        return None;
    }
    let _alg = r.string()?;
    let _key = r.string()?;
    let host_key_fingerprint = if method == "publickey-hostbound-v00@openssh.com" {
        keys::parse_public_key_blob(r.string()?)
            .ok()
            .map(|k| k.fingerprint)
    } else {
        None
    };
    Some(SignPurpose::UserAuth {
        user,
        service,
        method,
        host_key_fingerprint,
    })
}
