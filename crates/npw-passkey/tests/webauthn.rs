//! End-to-end checks of the authenticator from the relying party's side: the
//! RP verification steps of WebAuthn §7.1 / §7.2, done independently with a
//! tiny CBOR decoder and p256's verifier.

use npw_passkey::*;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};

// --- a tiny CBOR decoder (test only) ---------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Cbor {
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Bool(bool),
}

impl Cbor {
    fn get(&self, key: &Cbor) -> Option<&Cbor> {
        match self {
            Cbor::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    fn text_key(&self, key: &str) -> Option<&Cbor> {
        self.get(&Cbor::Text(key.into()))
    }
    fn int_key(&self, key: i128) -> Option<&Cbor> {
        self.get(&Cbor::Int(key))
    }
    fn bytes(&self) -> &[u8] {
        match self {
            Cbor::Bytes(b) => b,
            other => panic!("not bytes: {other:?}"),
        }
    }
}

/// Decodes one item from the front of `input`, returning the rest. Rejects
/// indefinite lengths and non-shortest heads, i.e. checks canonical form too.
fn decode(input: &[u8]) -> (Cbor, &[u8]) {
    let (first, mut rest) = (input[0], &input[1..]);
    let major = first >> 5;
    let info = first & 0x1f;
    if major == 7 {
        return match info {
            20 => (Cbor::Bool(false), rest),
            21 => (Cbor::Bool(true), rest),
            _ => panic!("unsupported simple value {info}"),
        };
    }
    let n: u64 = match info {
        0..=23 => info as u64,
        24 => {
            let v = rest[0] as u64;
            rest = &rest[1..];
            assert!(v >= 24, "non-canonical 1-byte head");
            v
        }
        25 => {
            let v = u16::from_be_bytes(rest[..2].try_into().unwrap()) as u64;
            rest = &rest[2..];
            assert!(v > 0xff, "non-canonical 2-byte head");
            v
        }
        26 => {
            let v = u32::from_be_bytes(rest[..4].try_into().unwrap()) as u64;
            rest = &rest[4..];
            assert!(v > 0xffff, "non-canonical 4-byte head");
            v
        }
        27 => {
            let v = u64::from_be_bytes(rest[..8].try_into().unwrap());
            rest = &rest[8..];
            assert!(v > 0xffff_ffff, "non-canonical 8-byte head");
            v
        }
        _ => panic!("indefinite or reserved length"),
    };
    match major {
        0 => (Cbor::Int(n as i128), rest),
        1 => (Cbor::Int(-1 - n as i128), rest),
        2 => (
            Cbor::Bytes(rest[..n as usize].to_vec()),
            &rest[n as usize..],
        ),
        3 => (
            Cbor::Text(String::from_utf8(rest[..n as usize].to_vec()).unwrap()),
            &rest[n as usize..],
        ),
        4 => {
            let mut items = vec![];
            for _ in 0..n {
                let (item, r) = decode(rest);
                items.push(item);
                rest = r;
            }
            (Cbor::Array(items), rest)
        }
        5 => {
            let mut entries = vec![];
            let mut last_key: Option<Vec<u8>> = None;
            for _ in 0..n {
                let before = rest;
                let (k, r) = decode(rest);
                let key_bytes = before[..before.len() - r.len()].to_vec();
                if let Some(prev) = &last_key {
                    let ordered = (prev.len(), prev) < (key_bytes.len(), &key_bytes);
                    assert!(ordered, "map keys not in canonical order");
                }
                last_key = Some(key_bytes);
                let (v, r) = decode(r);
                entries.push((k, v));
                rest = r;
            }
            (Cbor::Map(entries), rest)
        }
        _ => panic!("unsupported major type {major}"),
    }
}

fn decode_all(input: &[u8]) -> Cbor {
    let (v, rest) = decode(input);
    assert!(rest.is_empty(), "trailing bytes after CBOR item");
    v
}

// --- helpers -----------------------------------------------------------------

fn d(s: &str) -> Vec<u8> {
    b64url_decode(s).expect("base64url")
}

fn create_request(rp_id: Option<&str>) -> CreateRequest {
    let mut json = serde_json::json!({
        "rp": { "name": "Example" },
        "user": { "id": b64url(b"user-1234"), "name": "alice@example.com", "displayName": "Alice" },
        "challenge": b64url(b"registration-challenge-0123456789"),
        "pubKeyCredParams": [ { "type": "public-key", "alg": -8 }, { "type": "public-key", "alg": -7 }, { "type": "public-key", "alg": -257 } ],
        "timeout": 60000,
        "excludeCredentials": [],
        "authenticatorSelection": { "residentKey": "required", "requireResidentKey": true, "userVerification": "preferred" },
        "attestation": "none",
        "extensions": { "credProps": true }
    });
    if let Some(id) = rp_id {
        json["rp"]["id"] = id.into();
    }
    serde_json::from_value(json).unwrap()
}

fn get_request(rp_id: Option<&str>, allow: &[&str]) -> GetRequest {
    let mut json = serde_json::json!({
        "challenge": b64url(b"assertion-challenge-abcdefghijklmn"),
        "allowCredentials": allow.iter().map(|id| serde_json::json!({ "type": "public-key", "id": id })).collect::<Vec<_>>(),
        "userVerification": "required"
    });
    if let Some(id) = rp_id {
        json["rpId"] = id.into();
    }
    serde_json::from_value(json).unwrap()
}

struct AuthData {
    rp_id_hash: [u8; 32],
    flags: u8,
    counter: u32,
    attested: Option<(Vec<u8>, Vec<u8>, Cbor)>, // aaguid, credential id, COSE key
}

fn parse_auth_data(bytes: &[u8]) -> AuthData {
    assert!(bytes.len() >= 37);
    let rp_id_hash = bytes[..32].try_into().unwrap();
    let flags = bytes[32];
    let counter = u32::from_be_bytes(bytes[33..37].try_into().unwrap());
    let attested = if flags & flags::AT != 0 {
        let aaguid = bytes[37..53].to_vec();
        let len = u16::from_be_bytes(bytes[53..55].try_into().unwrap()) as usize;
        let cred_id = bytes[55..55 + len].to_vec();
        let (cose, rest) = decode(&bytes[55 + len..]);
        assert!(rest.is_empty(), "no extensions expected after the COSE key");
        Some((aaguid, cred_id, cose))
    } else {
        assert_eq!(bytes.len(), 37);
        None
    };
    AuthData {
        rp_id_hash,
        flags,
        counter,
        attested,
    }
}

fn verifying_key_from_cose(cose: &Cbor) -> VerifyingKey {
    assert_eq!(cose.int_key(1), Some(&Cbor::Int(2)), "kty EC2");
    assert_eq!(cose.int_key(3), Some(&Cbor::Int(-7)), "alg ES256");
    assert_eq!(cose.int_key(-1), Some(&Cbor::Int(1)), "crv P-256");
    let x = cose.int_key(-2).unwrap().bytes();
    let y = cose.int_key(-3).unwrap().bytes();
    assert_eq!((x.len(), y.len()), (32, 32));
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    VerifyingKey::from_sec1_bytes(&sec1).unwrap()
}

/// RP-side registration verification (WebAuthn §7.1, "none" attestation).
fn verify_registration(
    resp: &CreateResponse,
    rp_id: &str,
    origin: &str,
    challenge: &[u8],
) -> VerifyingKey {
    assert_eq!(resp.kind, "public-key");
    assert_eq!(resp.id, resp.raw_id);
    assert_eq!(resp.authenticator_attachment, "platform");
    assert_eq!(
        resp.client_extension_results.cred_props,
        Some(CredProps { rk: true })
    );

    let cdj = d(&resp.response.client_data_json);
    let client: serde_json::Value = serde_json::from_slice(&cdj).unwrap();
    assert_eq!(client["type"], "webauthn.create");
    assert_eq!(d(client["challenge"].as_str().unwrap()), challenge);
    assert_eq!(client["origin"], origin);
    assert_eq!(client["crossOrigin"], false);

    let att = decode_all(&d(&resp.response.attestation_object));
    assert_eq!(att.text_key("fmt"), Some(&Cbor::Text("none".into())));
    assert_eq!(att.text_key("attStmt"), Some(&Cbor::Map(vec![])));
    let auth_bytes = att.text_key("authData").unwrap().bytes().to_vec();
    assert_eq!(auth_bytes, d(&resp.response.authenticator_data));

    let ad = parse_auth_data(&auth_bytes);
    assert_eq!(
        ad.rp_id_hash,
        <[u8; 32]>::from(Sha256::digest(rp_id.as_bytes()))
    );
    assert_eq!(
        ad.flags,
        flags::UP | flags::UV | flags::BE | flags::BS | flags::AT
    );
    assert_eq!(ad.counter, 0);
    let (aaguid, cred_id, cose) = ad.attested.unwrap();
    assert_eq!(aaguid, AAGUID);
    assert_eq!(cred_id.len(), CREDENTIAL_ID_LEN);
    assert_eq!(cred_id, d(&resp.raw_id));

    let from_cose = verifying_key_from_cose(&cose);
    let from_spki = VerifyingKey::from_public_key_der(&d(&resp.response.public_key)).unwrap();
    assert_eq!(from_cose, from_spki);
    assert_eq!(resp.response.public_key_algorithm, -7);
    from_spki
}

/// RP-side assertion verification (WebAuthn §7.2).
fn verify_assertion(
    resp: &GetResponse,
    key: &VerifyingKey,
    rp_id: &str,
    origin: &str,
    challenge: &[u8],
) -> AuthData {
    let cdj = d(&resp.response.client_data_json);
    let client: serde_json::Value = serde_json::from_slice(&cdj).unwrap();
    assert_eq!(client["type"], "webauthn.get");
    assert_eq!(d(client["challenge"].as_str().unwrap()), challenge);
    assert_eq!(client["origin"], origin);

    let auth = d(&resp.response.authenticator_data);
    let ad = parse_auth_data(&auth);
    assert_eq!(
        ad.rp_id_hash,
        <[u8; 32]>::from(Sha256::digest(rp_id.as_bytes()))
    );
    assert_eq!(ad.flags, flags::UP | flags::UV | flags::BE | flags::BS);

    let mut signed = auth.clone();
    signed.extend_from_slice(&Sha256::digest(&cdj));
    let sig = Signature::from_der(&d(&resp.response.signature)).unwrap();
    key.verify(&signed, &sig)
        .expect("assertion signature verifies");
    ad
}

// --- tests -------------------------------------------------------------------

#[test]
fn register_then_authenticate() {
    let origin = "https://login.example.com";
    let req = create_request(Some("example.com"));
    let (mut passkey, resp) = create(&req, "https://login.example.com/signup?x=1").unwrap();

    let key = verify_registration(
        &resp,
        "example.com",
        origin,
        b"registration-challenge-0123456789",
    );
    assert_eq!(passkey.rp_id, "example.com");
    assert_eq!(passkey.rp_name, "Example");
    assert_eq!(passkey.user_name, "alice@example.com");
    assert_eq!(passkey.user_display_name, "Alice");
    assert_eq!(d(&passkey.user_handle), b"user-1234");
    assert_eq!(passkey.credential_id, resp.id);
    assert_eq!(passkey.alg, -7);
    assert!(passkey.discoverable);
    assert_eq!(passkey.counter, 0);
    assert_eq!(
        public_key_spki(&passkey).unwrap(),
        d(&resp.response.public_key)
    );

    // Discoverable flow (empty allow list) on another subdomain of the RP.
    let greq = get_request(Some("example.com"), &[]);
    let gresp = get(&greq, "https://www.example.com", &mut passkey).unwrap();
    let ad = verify_assertion(
        &gresp,
        &key,
        "example.com",
        "https://www.example.com",
        b"assertion-challenge-abcdefghijklmn",
    );
    assert_eq!(ad.counter, 0);
    assert_eq!(passkey.counter, 0, "synced passkeys keep the counter at 0");
    assert_eq!(gresp.id, passkey.credential_id);
    assert_eq!(
        gresp.response.user_handle.as_deref().map(d),
        Some(b"user-1234".to_vec())
    );
    assert_eq!(gresp.authenticator_attachment, "platform");

    // Allow-list flow.
    let greq = get_request(
        Some("example.com"),
        &[&b64url(b"someone-else"), &passkey.credential_id],
    );
    let gresp = get(&greq, origin, &mut passkey).unwrap();
    verify_assertion(
        &gresp,
        &key,
        "example.com",
        origin,
        b"assertion-challenge-abcdefghijklmn",
    );

    // Not in the allow list.
    let greq = get_request(Some("example.com"), &[&b64url(b"someone-else")]);
    assert!(matches!(
        get(&greq, origin, &mut passkey),
        Err(PasskeyError::NotAllowed(_))
    ));

    // Wrong RP: valid for the origin, but the passkey belongs to example.com.
    let greq = get_request(None, &[]);
    assert!(matches!(
        get(&greq, "https://other.org", &mut passkey),
        Err(PasskeyError::Security(_))
    ));
    // RP ID not valid for the origin.
    let greq = get_request(Some("example.com"), &[]);
    assert!(matches!(
        get(&greq, "https://example.org", &mut passkey),
        Err(PasskeyError::Security(_))
    ));
}

#[test]
fn default_rp_id_is_origin_host() {
    let req = create_request(None);
    let (passkey, resp) = create(&req, "https://Accounts.Example.com:8443").unwrap();
    assert_eq!(passkey.rp_id, "accounts.example.com");
    verify_registration(
        &resp,
        "accounts.example.com",
        "https://accounts.example.com:8443",
        b"registration-challenge-0123456789",
    );
}

#[test]
fn json_shape_matches_browsers() {
    let (_, resp) = create(&create_request(Some("example.com")), "https://example.com").unwrap();
    let v = serde_json::to_value(&resp).unwrap();
    for key in [
        "id",
        "rawId",
        "type",
        "response",
        "authenticatorAttachment",
        "clientExtensionResults",
    ] {
        assert!(v.get(key).is_some(), "missing {key}");
    }
    let r = &v["response"];
    for key in [
        "clientDataJSON",
        "attestationObject",
        "transports",
        "publicKeyAlgorithm",
        "publicKey",
        "authenticatorData",
    ] {
        assert!(r.get(key).is_some(), "missing response.{key}");
    }
    assert_eq!(r["transports"], serde_json::json!(["internal", "hybrid"]));
    assert_eq!(
        v["clientExtensionResults"],
        serde_json::json!({ "credProps": { "rk": true } })
    );
    // No padding, URL-safe alphabet.
    for s in [
        &resp.id,
        &resp.response.client_data_json,
        &resp.response.attestation_object,
        &resp.response.public_key,
    ] {
        assert!(!s.contains(['=', '+', '/']), "{s}");
    }
    // clientDataJSON is exactly the browser serialization (key order, no spaces).
    let cdj = String::from_utf8(d(&resp.response.client_data_json)).unwrap();
    assert_eq!(
        cdj,
        format!(
            "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"https://example.com\",\"crossOrigin\":false}}",
            b64url(b"registration-challenge-0123456789")
        )
    );

    let mut pk = create(&create_request(Some("example.com")), "https://example.com")
        .unwrap()
        .0;
    let g =
        serde_json::to_value(get(&get_request(None, &[]), "https://example.com", &mut pk).unwrap())
            .unwrap();
    for key in [
        "clientDataJSON",
        "authenticatorData",
        "signature",
        "userHandle",
    ] {
        assert!(g["response"].get(key).is_some(), "missing response.{key}");
    }
    assert_eq!(g["type"], "public-key");
}

#[test]
fn rp_id_validation_matrix() {
    let ok =
        |rp: Option<&str>, origin: &str| create(&create_request(rp), origin).map(|(p, _)| p.rp_id);
    assert_eq!(
        ok(Some("example.com"), "https://sub.example.com").unwrap(),
        "example.com"
    );
    assert!(matches!(
        ok(Some("other.com"), "https://example.com"),
        Err(PasskeyError::Security(_))
    ));
    assert!(matches!(
        ok(Some("com"), "https://example.com"),
        Err(PasskeyError::Security(_))
    ));
    assert!(matches!(
        ok(Some("github.io"), "https://octocat.github.io"),
        Err(PasskeyError::Security(_))
    ));
    assert_eq!(
        ok(Some("octocat.github.io"), "https://octocat.github.io").unwrap(),
        "octocat.github.io"
    );
    assert_eq!(
        ok(Some("localhost"), "http://localhost:5173").unwrap(),
        "localhost"
    );
    assert!(matches!(
        ok(Some("example.com"), "http://example.com"),
        Err(PasskeyError::Security(_))
    ));
    assert!(matches!(
        ok(None, "https://10.0.0.1"),
        Err(PasskeyError::Security(_))
    ));
}

#[test]
fn unsupported_algorithms_and_bad_input() {
    let mut req = create_request(Some("example.com"));
    req.pub_key_cred_params = vec![
        PubKeyCredParam {
            kind: "public-key".into(),
            alg: -257,
        },
        PubKeyCredParam {
            kind: "public-key".into(),
            alg: -8,
        },
    ];
    let err = create(&req, "https://example.com").unwrap_err();
    assert!(matches!(err, PasskeyError::NotSupported(_)));
    assert_eq!(err.dom_exception_name(), "NotSupportedError");

    // Empty list = defaults (ES256 included).
    req.pub_key_cred_params.clear();
    assert!(create(&req, "https://example.com").is_ok());

    let mut req = create_request(Some("example.com"));
    req.challenge = "not base64!".into();
    assert!(matches!(
        create(&req, "https://example.com"),
        Err(PasskeyError::InvalidRequest(_))
    ));
    let mut req = create_request(Some("example.com"));
    req.user.id = b64url(&[0u8; 65]);
    assert!(matches!(
        create(&req, "https://example.com"),
        Err(PasskeyError::InvalidRequest(_))
    ));
    req.user.id = String::new();
    assert!(matches!(
        create(&req, "https://example.com"),
        Err(PasskeyError::InvalidRequest(_))
    ));

    // A stored key that is not ES256 / not a valid PKCS#8.
    let (mut pk, _) = create(&create_request(Some("example.com")), "https://example.com").unwrap();
    pk.private_key = b64url(b"garbage");
    assert!(matches!(
        get(&get_request(None, &[]), "https://example.com", &mut pk),
        Err(PasskeyError::InvalidKey(_))
    ));
    pk.alg = -8;
    assert!(matches!(
        get(&get_request(None, &[]), "https://example.com", &mut pk),
        Err(PasskeyError::NotSupported(_))
    ));
}

#[test]
fn passkey_round_trips_through_item_json() {
    let (passkey, resp) =
        create(&create_request(Some("example.com")), "https://example.com").unwrap();
    let key = VerifyingKey::from_public_key_der(&d(&resp.response.public_key)).unwrap();

    let mut item = npw_model::ItemContent::new("login", "Example");
    item.passkeys.push(passkey.clone());
    let json = serde_json::to_string(&item).unwrap();
    let back: npw_model::ItemContent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.passkeys, vec![passkey.clone()]);
    let raw: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(raw["passkeys"][0]["alg"], -7);
    assert_eq!(raw["passkeys"][0]["rp_id"], "example.com");

    let mut restored = back.passkeys[0].clone();
    let gresp = get(
        &get_request(Some("example.com"), &[]),
        "https://example.com",
        &mut restored,
    )
    .unwrap();
    verify_assertion(
        &gresp,
        &key,
        "example.com",
        "https://example.com",
        b"assertion-challenge-abcdefghijklmn",
    );
}

#[test]
fn imported_counter_keeps_increasing() {
    let (mut pk, resp) =
        create(&create_request(Some("example.com")), "https://example.com").unwrap();
    let key = VerifyingKey::from_public_key_der(&d(&resp.response.public_key)).unwrap();
    pk.counter = 41;
    let gresp = get(&get_request(None, &[]), "https://example.com", &mut pk).unwrap();
    let ad = verify_assertion(
        &gresp,
        &key,
        "example.com",
        "https://example.com",
        b"assertion-challenge-abcdefghijklmn",
    );
    assert_eq!(ad.counter, 42);
    assert_eq!(pk.counter, 42);
}

#[test]
fn client_data_hash_variants() {
    let hash: [u8; 32] = Sha256::digest(b"{\"type\":\"webauthn.create\",...}").into();
    let req = create_request(Some("Example.com"));
    let (mut pk, resp) = create_with_client_data_hash(&req, &hash).unwrap();
    assert_eq!(pk.rp_id, "example.com");
    assert_eq!(resp.response.client_data_json, "");
    let key = VerifyingKey::from_public_key_der(&d(&resp.response.public_key)).unwrap();

    // rp.id is required without an origin.
    assert!(matches!(
        create_with_client_data_hash(&create_request(None), &hash),
        Err(PasskeyError::InvalidRequest(_))
    ));

    let get_hash: [u8; 32] = Sha256::digest(b"browser-built client data").into();
    let greq = get_request(Some("example.com"), &[]);
    let gresp = get_with_client_data_hash(&greq, &get_hash, &mut pk).unwrap();
    assert_eq!(gresp.response.client_data_json, "");
    let mut signed = d(&gresp.response.authenticator_data);
    signed.extend_from_slice(&get_hash);
    key.verify(
        &signed,
        &Signature::from_der(&d(&gresp.response.signature)).unwrap(),
    )
    .unwrap();

    // Wrong RP for the passkey.
    let greq = get_request(Some("other.com"), &[]);
    assert!(matches!(
        get_with_client_data_hash(&greq, &get_hash, &mut pk),
        Err(PasskeyError::Security(_))
    ));
}

#[test]
fn android_app_origin() {
    let app = "android:apk-key-hash:3kQ2e9nW6Hc5Yd0lPZ1pXj2l8tPq9xG4Z8kq0YcA1Bs";
    let (mut pk, resp) = create_for_android_app(&create_request(Some("example.com")), app).unwrap();
    let key = verify_registration(
        &resp,
        "example.com",
        app,
        b"registration-challenge-0123456789",
    );
    let gresp = get_for_android_app(&get_request(Some("example.com"), &[]), app, &mut pk).unwrap();
    verify_assertion(
        &gresp,
        &key,
        "example.com",
        app,
        b"assertion-challenge-abcdefghijklmn",
    );
    assert!(
        create_for_android_app(&create_request(Some("example.com")), "https://example.com")
            .is_err()
    );
}

#[test]
fn matching_and_exclusion() {
    let (a, _) = create(&create_request(Some("example.com")), "https://example.com").unwrap();
    let (mut b, _) = create(&create_request(Some("example.com")), "https://example.com").unwrap();
    b.discoverable = false;
    let (c, _) = create(&create_request(Some("other.org")), "https://other.org").unwrap();
    let all = [a.clone(), b.clone(), c.clone()];

    let m = matching(all.iter(), "EXAMPLE.com", &[]);
    assert_eq!(
        m,
        vec![&a],
        "empty allow list: discoverable passkeys of the RP only"
    );
    let allow = [CredentialDescriptor {
        kind: "public-key".into(),
        id: b.credential_id.clone(),
        transports: vec![],
    }];
    assert_eq!(matching(all.iter(), "example.com", &allow), vec![&b]);
    assert!(matching(all.iter(), "other.org", &allow).is_empty());

    let mut req = create_request(Some("example.com"));
    assert!(check_excluded(&req, "example.com", all.iter()).is_ok());
    req.exclude_credentials = vec![CredentialDescriptor {
        kind: "public-key".into(),
        id: a.credential_id.clone(),
        transports: vec![],
    }];
    let err = check_excluded(&req, "example.com", all.iter()).unwrap_err();
    assert_eq!(err.dom_exception_name(), "InvalidStateError");
    req.exclude_credentials[0].id = b64url(b"unknown");
    assert!(check_excluded(&req, "example.com", all.iter()).is_ok());
}

#[test]
fn credentials_are_unique() {
    let req = create_request(Some("example.com"));
    let (a, ra) = create(&req, "https://example.com").unwrap();
    let (b, rb) = create(&req, "https://example.com").unwrap();
    assert_ne!(a.credential_id, b.credential_id);
    assert_ne!(a.private_key, b.private_key);
    assert_ne!(ra.response.public_key, rb.response.public_key);
}
