//! A software WebAuthn authenticator (design doc §10.4, §10.5).
//!
//! The browser extension intercepts `navigator.credentials.create/get` and the
//! Android `CredentialProviderService` receives the same JSON options; both
//! hand them to this crate together with the caller's origin. There is no CTAP
//! transport: this crate plays authenticator *and* the client half of the
//! browser (it builds `clientDataJSON`), and returns the JSON a browser's
//! `PublicKeyCredential.toJSON()` produces.
//!
//! Credentials are ES256 (P-256) only, use `none` attestation, and are
//! *synced* passkeys: the BE (backup eligible) and BS (backed up) flags are
//! set and the signature counter stays 0 (see [`get`]).
//!
//! User verification: every response sets UP and UV. Callers must only call
//! [`create`]/[`get`] after the user has been verified for this operation
//! (unlocked vault plus an explicit confirmation, biometric or master
//! password) — the same contract as other password-manager passkey providers.

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod cbor;
pub mod rp;

pub use npw_model::Passkey;
pub use rp::{effective_rp_id, is_registrable_suffix_or_equal, parse_origin, WebOrigin};

use cbor::Value;

/// COSE algorithm identifier for ES256 (ECDSA P-256 with SHA-256).
pub const COSE_ES256: i64 = -7;

/// The AAGUID NyaPassword reports in attestedCredentialData
/// (`d2f8a7c1-4b3e-4f6a-9c5d-1e0b7a3f9c24`). Lets RPs show "NyaPassword" in
/// their passkey list once registered with the community AAGUID list.
pub const AAGUID: [u8; 16] = [
    0xd2, 0xf8, 0xa7, 0xc1, 0x4b, 0x3e, 0x4f, 0x6a, 0x9c, 0x5d, 0x1e, 0x0b, 0x7a, 0x3f, 0x9c, 0x24,
];

/// Length of newly generated credential IDs.
pub const CREDENTIAL_ID_LEN: usize = 16;

/// Authenticator data flags (WebAuthn §6.1).
pub mod flags {
    /// User present.
    pub const UP: u8 = 0x01;
    /// User verified.
    pub const UV: u8 = 0x04;
    /// Backup eligible.
    pub const BE: u8 = 0x08;
    /// Backup state (currently backed up).
    pub const BS: u8 = 0x10;
    /// Attested credential data included.
    pub const AT: u8 = 0x40;
    /// Extension data included.
    pub const ED: u8 = 0x80;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PasskeyError {
    /// No supported algorithm in `pubKeyCredParams`, or an unsupported stored key.
    #[error("not supported: {0}")]
    NotSupported(String),
    /// The origin may not use this RP ID, or the passkey belongs to another RP.
    #[error("security error: {0}")]
    Security(String),
    /// The credential is not allowed for this request.
    #[error("not allowed: {0}")]
    NotAllowed(String),
    /// A credential in `excludeCredentials` already exists in the vault.
    #[error("invalid state: {0}")]
    InvalidState(String),
    /// Malformed options (bad base64url, missing fields, ...).
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// The stored private key cannot be used.
    #[error("invalid stored key: {0}")]
    InvalidKey(String),
}

impl PasskeyError {
    /// The `DOMException` name a browser would reject the promise with.
    pub fn dom_exception_name(&self) -> &'static str {
        match self {
            PasskeyError::NotSupported(_) => "NotSupportedError",
            PasskeyError::Security(_) => "SecurityError",
            PasskeyError::NotAllowed(_) | PasskeyError::InvalidKey(_) => "NotAllowedError",
            PasskeyError::InvalidState(_) => "InvalidStateError",
            PasskeyError::InvalidRequest(_) => "TypeError",
        }
    }
}

// ---------------------------------------------------------------------------
// Request / response JSON (WebAuthn Level 3 JSON serialization, all binary
// values base64url without padding).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpEntity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserEntity {
    /// base64url user handle (1..=64 bytes).
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub kind: String,
    pub alg: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDescriptor {
    #[serde(rename = "type", default = "public_key_type")]
    pub kind: String,
    /// base64url credential ID.
    pub id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transports: Vec<String>,
}

fn public_key_type() -> String {
    "public-key".into()
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
}

/// `PublicKeyCredentialCreationOptions` (JSON form).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest {
    pub rp: RpEntity,
    pub user: UserEntity,
    /// base64url
    pub challenge: String,
    #[serde(default)]
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub exclude_credentials: Vec<CredentialDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// `PublicKeyCredentialRequestOptions` (JSON form).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRequest {
    /// base64url
    pub challenge: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(default)]
    pub allow_credentials: Vec<CredentialDescriptor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    pub transports: Vec<String>,
    #[serde(rename = "publicKeyAlgorithm")]
    pub public_key_algorithm: i64,
    /// SubjectPublicKeyInfo DER, base64url.
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredProps {
    pub rk: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClientExtensionResults {
    #[serde(rename = "credProps", default, skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<CredProps>,
}

/// `PublicKeyCredential.toJSON()` of a registration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateResponse {
    pub id: String,
    pub raw_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub response: AttestationResponse,
    pub authenticator_attachment: String,
    pub client_extension_results: ClientExtensionResults,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    /// DER-encoded ECDSA signature, base64url.
    pub signature: String,
    /// base64url; `None` (JSON null) if the passkey has no user handle.
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
}

/// `PublicKeyCredential.toJSON()` of an authentication.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetResponse {
    pub id: String,
    pub raw_id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub response: AssertionResponse,
    pub authenticator_attachment: String,
    pub client_extension_results: ClientExtensionResults,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// base64url without padding (the encoding of every binary value in the JSON).
pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes base64url, tolerating padding and the standard alphabet (some
/// importers and sites send either).
pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim().trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(s)
        .ok()
        .or_else(|| STANDARD_NO_PAD.decode(s).ok())
}

fn decode_field(name: &str, s: &str) -> Result<Vec<u8>, PasskeyError> {
    b64url_decode(s).ok_or_else(|| PasskeyError::InvalidRequest(format!("{name} is not base64url")))
}

/// Builds `clientDataJSON` byte-for-byte the way browsers serialize it
/// (WebAuthn §5.8.1.1: type, challenge, origin, crossOrigin, in that order).
pub fn client_data_json(kind: &str, challenge: &[u8], origin: &str) -> String {
    format!(
        "{{\"type\":{},\"challenge\":{},\"origin\":{},\"crossOrigin\":false}}",
        json_str(kind),
        json_str(&b64url(challenge)),
        json_str(origin),
    )
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).expect("string serialization cannot fail")
}

fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    Sha256::digest(rp_id.as_bytes()).into()
}

/// COSE_Key (RFC 9053) for an EC2 P-256 public key, canonical CBOR.
pub fn cose_key_es256(public: &p256::PublicKey) -> Vec<u8> {
    let point = public.to_encoded_point(false);
    let (x, y) = (
        point.x().expect("uncompressed"),
        point.y().expect("uncompressed"),
    );
    Value::Map(vec![
        (Value::Int(1), Value::Int(2)),          // kty: EC2
        (Value::Int(3), Value::Int(COSE_ES256)), // alg: ES256
        (Value::Int(-1), Value::Int(1)),         // crv: P-256
        (Value::Int(-2), Value::Bytes(x.to_vec())),
        (Value::Int(-3), Value::Bytes(y.to_vec())),
    ])
    .to_vec()
}

fn signing_key(passkey: &Passkey) -> Result<SigningKey, PasskeyError> {
    if passkey.alg != COSE_ES256 {
        return Err(PasskeyError::NotSupported(format!(
            "COSE algorithm {}",
            passkey.alg
        )));
    }
    let der = b64url_decode(&passkey.private_key)
        .ok_or_else(|| PasskeyError::InvalidKey("private key is not base64url".into()))?;
    let secret = p256::SecretKey::from_pkcs8_der(&der)
        .map_err(|e| PasskeyError::InvalidKey(format!("PKCS#8: {e}")))?;
    Ok(SigningKey::from(secret))
}

/// The SubjectPublicKeyInfo (DER) of a stored passkey, e.g. to show or export it.
pub fn public_key_spki(passkey: &Passkey) -> Result<Vec<u8>, PasskeyError> {
    let key = signing_key(passkey)?;
    let spki = key
        .verifying_key()
        .to_public_key_der()
        .map_err(|e| PasskeyError::InvalidKey(e.to_string()))?;
    Ok(spki.as_bytes().to_vec())
}

fn same_credential(stored_b64: &str, wanted: &[u8]) -> bool {
    b64url_decode(stored_b64).is_some_and(|id| id == wanted)
}

fn allowed_ids(list: &[CredentialDescriptor]) -> Vec<Vec<u8>> {
    list.iter()
        .filter(|d| d.kind == "public-key")
        .filter_map(|d| b64url_decode(&d.id))
        .collect()
}

/// Chooses the passkeys that can answer a `get` for `rp_id`.
///
/// With a non-empty allow list, the passkeys whose credential ID is listed
/// (discoverable or not); with an empty one, the discoverable passkeys of the
/// RP. RP IDs compare case-insensitively.
pub fn matching<'a>(
    passkeys: impl Iterator<Item = &'a Passkey>,
    rp_id: &str,
    allow: &[CredentialDescriptor],
) -> Vec<&'a Passkey> {
    let rp_id = rp::normalize_rp_id(rp_id).unwrap_or_else(|| rp_id.to_ascii_lowercase());
    let ids = allowed_ids(allow);
    passkeys
        .filter(|p| p.rp_id.eq_ignore_ascii_case(&rp_id))
        .filter(|p| {
            if allow.is_empty() {
                p.discoverable
            } else {
                ids.iter().any(|id| same_credential(&p.credential_id, id))
            }
        })
        .collect()
}

/// Fails with [`PasskeyError::InvalidState`] if the vault already holds one of
/// the request's `excludeCredentials` for this RP. Call before [`create`]
/// (the extension then reports `InvalidStateError` as browsers do).
pub fn check_excluded<'a>(
    req: &CreateRequest,
    rp_id: &str,
    passkeys: impl Iterator<Item = &'a Passkey>,
) -> Result<(), PasskeyError> {
    if req.exclude_credentials.is_empty() {
        return Ok(());
    }
    if matching(passkeys, rp_id, &req.exclude_credentials).is_empty() {
        Ok(())
    } else {
        Err(PasskeyError::InvalidState(
            "a credential for this account already exists".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

enum ClientData {
    /// Build clientDataJSON with this origin serialization.
    Origin(String),
    /// The caller (Android privileged app / browser) built it already.
    Hash([u8; 32]),
}

impl ClientData {
    fn resolve(&self, kind: &str, challenge: &[u8]) -> (String, [u8; 32]) {
        match self {
            ClientData::Origin(origin) => {
                let json = client_data_json(kind, challenge, origin);
                let hash = Sha256::digest(json.as_bytes()).into();
                (json, hash)
            }
            ClientData::Hash(h) => (String::new(), *h),
        }
    }
}

fn check_alg(req: &CreateRequest) -> Result<(), PasskeyError> {
    // An empty list means "ES256 or RS256" (WebAuthn §5.1.3 step 10).
    if req.pub_key_cred_params.is_empty()
        || req
            .pub_key_cred_params
            .iter()
            .any(|p| p.kind == "public-key" && p.alg == COSE_ES256)
    {
        Ok(())
    } else {
        Err(PasskeyError::NotSupported(
            "only ES256 (-7) credentials can be created".into(),
        ))
    }
}

/// Registers a new passkey for a web origin (`navigator.credentials.create`).
///
/// Validates the RP ID against `origin`, generates a P-256 key and a random
/// credential ID, and returns the passkey to store in the item plus the
/// browser-format response for the page. `excludeCredentials` is checked by
/// [`check_excluded`], since only the caller can see the vault.
pub fn create(
    req: &CreateRequest,
    origin: &str,
) -> Result<(Passkey, CreateResponse), PasskeyError> {
    let origin = parse_origin(origin)?;
    let rp_id = effective_rp_id(req.rp.id.as_deref(), &origin)?;
    make_credential(req, &rp_id, ClientData::Origin(origin.serialized))
}

/// Registration for an Android app whose origin is
/// `android:apk-key-hash:<base64url sha256 of the signing cert>`.
///
/// The caller must already have verified the app against the RP's Digital
/// Asset Links; `rp.id` is required and used as is (after normalization).
pub fn create_for_android_app(
    req: &CreateRequest,
    app_origin: &str,
) -> Result<(Passkey, CreateResponse), PasskeyError> {
    if !app_origin.starts_with("android:apk-key-hash:") {
        return Err(PasskeyError::Security(format!(
            "not an Android app origin: {app_origin:?}"
        )));
    }
    let rp_id = required_rp_id(req.rp.id.as_deref())?;
    make_credential(req, &rp_id, ClientData::Origin(app_origin.to_string()))
}

/// Registration when the caller supplies `clientDataHash` (Android privileged
/// callers such as browsers). The caller is responsible for the origin/RP ID
/// check; `rp.id` is required. `response.clientDataJSON` is empty.
pub fn create_with_client_data_hash(
    req: &CreateRequest,
    client_data_hash: &[u8; 32],
) -> Result<(Passkey, CreateResponse), PasskeyError> {
    let rp_id = required_rp_id(req.rp.id.as_deref())?;
    make_credential(req, &rp_id, ClientData::Hash(*client_data_hash))
}

fn required_rp_id(rp_id: Option<&str>) -> Result<String, PasskeyError> {
    let rp_id = rp_id.ok_or_else(|| PasskeyError::InvalidRequest("rp id is required".into()))?;
    rp::normalize_rp_id(rp_id)
        .ok_or_else(|| PasskeyError::Security(format!("invalid RP ID {rp_id:?}")))
}

fn make_credential(
    req: &CreateRequest,
    rp_id: &str,
    client: ClientData,
) -> Result<(Passkey, CreateResponse), PasskeyError> {
    check_alg(req)?;
    let challenge = decode_field("challenge", &req.challenge)?;
    let user_handle = decode_field("user.id", &req.user.id)?;
    if user_handle.is_empty() || user_handle.len() > 64 {
        return Err(PasskeyError::InvalidRequest(
            "user.id must be 1 to 64 bytes".into(),
        ));
    }

    let secret = p256::SecretKey::random(&mut OsRng);
    let public = secret.public_key();
    let pkcs8 = secret
        .to_pkcs8_der()
        .map_err(|e| PasskeyError::InvalidKey(e.to_string()))?;
    let spki = public
        .to_public_key_der()
        .map_err(|e| PasskeyError::InvalidKey(e.to_string()))?;
    let mut credential_id = [0u8; CREDENTIAL_ID_LEN];
    OsRng.fill_bytes(&mut credential_id);

    let (client_json, client_hash) = client.resolve("webauthn.create", &challenge);
    let _ = client_hash; // "none" attestation signs nothing at registration.

    let mut auth_data = Vec::with_capacity(37 + 16 + 2 + CREDENTIAL_ID_LEN + 77);
    auth_data.extend_from_slice(&rp_id_hash(rp_id));
    auth_data.push(flags::UP | flags::UV | flags::BE | flags::BS | flags::AT);
    auth_data.extend_from_slice(&0u32.to_be_bytes());
    auth_data.extend_from_slice(&AAGUID);
    auth_data.extend_from_slice(&(CREDENTIAL_ID_LEN as u16).to_be_bytes());
    auth_data.extend_from_slice(&credential_id);
    auth_data.extend_from_slice(&cose_key_es256(&public));

    let attestation_object = Value::Map(vec![
        (Value::text("fmt"), Value::text("none")),
        (Value::text("attStmt"), Value::Map(vec![])),
        (Value::text("authData"), Value::Bytes(auth_data.clone())),
    ])
    .to_vec();

    let id = b64url(&credential_id);
    let passkey = Passkey {
        id: npw_model::new_short_id("pk"),
        rp_id: rp_id.to_string(),
        credential_id: id.clone(),
        user_handle: b64url(&user_handle),
        user_name: req.user.name.clone(),
        user_display_name: req.user.display_name.clone(),
        rp_name: req.rp.name.clone(),
        alg: COSE_ES256,
        private_key: b64url(pkcs8.as_bytes()),
        counter: 0,
        // Always discoverable: the vault can list credentials per RP anyway,
        // and it makes username-less sign-in work on every device.
        discoverable: true,
        created_at: npw_model::now_ms(),
        extra: Default::default(),
    };
    let response = CreateResponse {
        id: id.clone(),
        raw_id: id,
        kind: "public-key".into(),
        response: AttestationResponse {
            client_data_json: b64url(client_json.as_bytes()),
            attestation_object: b64url(&attestation_object),
            transports: vec!["internal".into(), "hybrid".into()],
            public_key_algorithm: COSE_ES256,
            public_key: b64url(spki.as_bytes()),
            authenticator_data: b64url(&auth_data),
        },
        authenticator_attachment: "platform".into(),
        client_extension_results: ClientExtensionResults {
            cred_props: Some(CredProps { rk: true }),
        },
    };
    Ok((passkey, response))
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/// Signs an assertion with `passkey` for a web origin (`navigator.credentials.get`).
///
/// Checks the RP ID against the origin, that the passkey belongs to that RP
/// and (if `allowCredentials` is non-empty) that it is listed.
///
/// Signature counter: synced passkeys report 0 and never increment it. One
/// credential lives on several devices that cannot agree on a monotonic
/// value, and an RP that sees a counter go backwards may flag the credential
/// as cloned; 0 tells the RP "no counter". A passkey imported with a non-zero
/// counter (from an authenticator that did count) keeps counting upwards
/// from there, written back into `passkey.counter`, so the RP never sees a
/// drop; the caller must save the item afterwards in that case.
pub fn get(
    req: &GetRequest,
    origin: &str,
    passkey: &mut Passkey,
) -> Result<GetResponse, PasskeyError> {
    let origin = parse_origin(origin)?;
    let rp_id = effective_rp_id(req.rp_id.as_deref(), &origin)?;
    get_assertion(req, &rp_id, ClientData::Origin(origin.serialized), passkey)
}

/// Assertion for a verified Android app origin (`android:apk-key-hash:...`);
/// `rpId` is required. See [`create_for_android_app`].
pub fn get_for_android_app(
    req: &GetRequest,
    app_origin: &str,
    passkey: &mut Passkey,
) -> Result<GetResponse, PasskeyError> {
    if !app_origin.starts_with("android:apk-key-hash:") {
        return Err(PasskeyError::Security(format!(
            "not an Android app origin: {app_origin:?}"
        )));
    }
    let rp_id = required_rp_id(req.rp_id.as_deref())?;
    get_assertion(
        req,
        &rp_id,
        ClientData::Origin(app_origin.to_string()),
        passkey,
    )
}

/// Assertion over a caller-supplied `clientDataHash` (Android privileged
/// callers); `rpId` is required and `response.clientDataJSON` is empty.
pub fn get_with_client_data_hash(
    req: &GetRequest,
    client_data_hash: &[u8; 32],
    passkey: &mut Passkey,
) -> Result<GetResponse, PasskeyError> {
    let rp_id = required_rp_id(req.rp_id.as_deref())?;
    get_assertion(req, &rp_id, ClientData::Hash(*client_data_hash), passkey)
}

fn get_assertion(
    req: &GetRequest,
    rp_id: &str,
    client: ClientData,
    passkey: &mut Passkey,
) -> Result<GetResponse, PasskeyError> {
    let stored_rp =
        rp::normalize_rp_id(&passkey.rp_id).unwrap_or_else(|| passkey.rp_id.to_ascii_lowercase());
    if stored_rp != rp_id {
        return Err(PasskeyError::Security(format!(
            "passkey is for {:?}, not {rp_id:?}",
            passkey.rp_id
        )));
    }
    let credential_id = b64url_decode(&passkey.credential_id)
        .ok_or_else(|| PasskeyError::InvalidKey("credential ID is not base64url".into()))?;
    if !req.allow_credentials.is_empty()
        && !allowed_ids(&req.allow_credentials).contains(&credential_id)
    {
        return Err(PasskeyError::NotAllowed(
            "credential is not in allowCredentials".into(),
        ));
    }
    let challenge = decode_field("challenge", &req.challenge)?;
    let key = signing_key(passkey)?;

    let counter = if passkey.counter == 0 {
        0
    } else {
        passkey.counter.saturating_add(1)
    };
    let (client_json, client_hash) = client.resolve("webauthn.get", &challenge);

    let mut auth_data = Vec::with_capacity(37);
    auth_data.extend_from_slice(&rp_id_hash(rp_id));
    auth_data.push(flags::UP | flags::UV | flags::BE | flags::BS);
    auth_data.extend_from_slice(&counter.to_be_bytes());

    let mut signed = auth_data.clone();
    signed.extend_from_slice(&client_hash);
    let signature: Signature = key.sign(&signed);
    passkey.counter = counter;

    let user_handle = b64url_decode(&passkey.user_handle)
        .filter(|h| !h.is_empty())
        .map(|h| b64url(&h));
    let id = b64url(&credential_id);
    Ok(GetResponse {
        id: id.clone(),
        raw_id: id,
        kind: "public-key".into(),
        response: AssertionResponse {
            client_data_json: b64url(client_json.as_bytes()),
            authenticator_data: b64url(&auth_data),
            signature: b64url(signature.to_der().as_bytes()),
            user_handle,
        },
        authenticator_attachment: "platform".into(),
        client_extension_results: ClientExtensionResults::default(),
    })
}
