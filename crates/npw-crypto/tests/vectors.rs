//! Frozen test vectors for the NyaPassword cryptography (docs/加密规格.md §12).
//!
//! `tests/vectors/v1.json` holds fixed inputs and the outputs they must give,
//! forever and on every target (native, WASM, Android). Every vector is checked
//! twice: against this crate, and against the small re-implementation of the
//! specification at the bottom of this file, which uses the underlying
//! primitives (argon2, hkdf, chacha20poly1305, sha2) directly. A change in the
//! code or a misreading of the specification both show up as a failure.
//!
//! The file was generated once from the code. Regenerating it is only allowed
//! while format v1 is unreleased:
//!   $env:NPW_BLESS=1; cargo test -p npw-crypto --test vectors
//!
//! OPAQUE has no vectors here: its messages are randomized, and opaque-ke
//! carries the RFC 9807 vectors for the cipher suite itself.

use std::path::PathBuf;

use npw_crypto::kdf::{self, KdfAlg};
use npw_crypto::{aad, envelope, stream, CryptoError, KdfParams, Key32, SecretKey};
use serde::{Deserialize, Serialize};

// ------------------------------------------------------------------ file format

#[derive(Serialize, Deserialize)]
struct Vectors {
    version: u32,
    note: String,
    kdf: Vec<KdfVector>,
    recovery: Vec<RecoveryVector>,
    kdf_params: Vec<ParamsVector>,
    secret_key: Vec<SecretKeyVector>,
    secret_key_invalid: Vec<InvalidText>,
    aad: Vec<AadVector>,
    envelope: Vec<EnvelopeVector>,
    envelope_invalid: Vec<InvalidCiphertext>,
    stream: Vec<StreamVector>,
    stream_invalid: Vec<InvalidCiphertext>,
}

#[derive(Serialize, Deserialize)]
struct KdfVector {
    name: String,
    password: String,
    /// UTF-8 bytes of NFKD(password): what Argon2id actually hashes.
    password_nfkd_hex: String,
    secret_key: String,
    account_salt_hex: String,
    params: KdfParams,
    /// Argon2id output.
    k_pw_hex: String,
    /// HKDF of the Secret Key.
    k_sk_hex: String,
    /// k_pw XOR k_sk.
    master_hex: String,
    auk_hex: String,
    login_hex: String,
}

#[derive(Serialize, Deserialize)]
struct RecoveryVector {
    code_hex: String,
    account_salt_hex: String,
    auk_hex: String,
    login_hex: String,
}

#[derive(Serialize, Deserialize)]
struct ParamsVector {
    params: KdfParams,
    valid: bool,
}

#[derive(Serialize, Deserialize)]
struct SecretKeyVector {
    raw_hex: String,
    text: String,
    check_char: String,
    /// Other spellings that must parse to the same key.
    also_accepted: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct InvalidText {
    name: String,
    text: String,
    error: String,
}

#[derive(Serialize, Deserialize)]
struct AadVector {
    function: String,
    label: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    format_major: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    hex: String,
}

#[derive(Serialize, Deserialize)]
struct EnvelopeVector {
    name: String,
    key_hex: String,
    nonce_hex: String,
    aad_hex: String,
    plaintext_hex: String,
    envelope_hex: String,
}

#[derive(Serialize, Deserialize)]
struct InvalidCiphertext {
    name: String,
    key_hex: String,
    aad_hex: String,
    data_hex: String,
    error: String,
}

#[derive(Serialize, Deserialize)]
struct StreamVector {
    name: String,
    key_hex: String,
    nonce_prefix_hex: String,
    aad_hex: String,
    /// Plaintext byte i is `(i * 31) % 251`.
    plaintext_len: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ciphertext_hex: Option<String>,
    ciphertext_sha256: String,
    encrypted_len: usize,
}

// ------------------------------------------------------------------ fixed inputs

const ACCOUNT_ID: &str = "0192f0c0-0000-7000-8000-000000000001";
const VAULT_ID: &str = "0192f0c0-0000-7000-8000-000000000002";
const ITEM_ID: &str = "0192f0c0-0000-7000-8000-000000000064";
const ATTACHMENT_ID: &str = "0192f0c0-0000-7000-8000-0000000000a1";
const EXPORT_ID: &str = "0192f0c0-0000-7000-8000-0000000000e1";

fn uuid16(s: &str) -> [u8; 16] {
    let h: String = s.chars().filter(|c| *c != '-').collect();
    hex::decode(h).unwrap().try_into().unwrap()
}

fn seq(start: u8, n: usize) -> Vec<u8> {
    (0..n).map(|i| start.wrapping_add(i as u8)).collect()
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

fn params(m: u32, t: u32, p: u32) -> KdfParams {
    KdfParams {
        alg: KdfAlg::Argon2id,
        m,
        t,
        p,
    }
}

fn h(b: &[u8]) -> String {
    hex::encode(b)
}

fn unh(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn key(s: &str) -> Key32 {
    Key32::from_slice(&unh(s)).unwrap()
}

fn error_kind(e: &CryptoError) -> String {
    match e {
        CryptoError::Decrypt => "decrypt".into(),
        CryptoError::UnsupportedVersion(v) => format!("unsupported_version({v})"),
        CryptoError::UnsupportedAlgorithm(a) => format!("unsupported_algorithm({a})"),
        CryptoError::Malformed => "malformed".into(),
        CryptoError::InvalidSecretKey(_) => "invalid_secret_key".into(),
        CryptoError::InvalidKdfParams => "invalid_kdf_params".into(),
        CryptoError::Opaque => "opaque".into(),
        CryptoError::KeyLength => "key_length".into(),
    }
}

/// The AAD functions by name, as the vectors call them.
fn aad_of(
    function: &str,
    ids: &[String],
    format_major: Option<u16>,
    name: Option<&str>,
) -> Vec<u8> {
    let id = |i: usize| uuid16(&ids[i]);
    match function {
        "account_key" => aad::account_key(&id(0)),
        "account_private_key" => aad::account_private_key(&id(0)),
        "recovery_account_key" => aad::recovery_account_key(&id(0)),
        "vault_key" => aad::vault_key(&id(0)),
        "vault_meta" => aad::vault_meta(&id(0)),
        "item_key" => aad::item_key(&id(0), &id(1)),
        "item_content" => aad::item_content(&id(0), &id(1), format_major.unwrap()),
        "attachment" => aad::attachment(&id(0)),
        "device_secret" => aad::device_secret(name.unwrap()),
        "quick_unlock" => aad::quick_unlock(&id(0)),
        "export" => aad::export(&id(0)),
        other => panic!("unknown AAD function {other}"),
    }
}

// ------------------------------------------------------------------ generation (from the code)

fn gen_kdf() -> Vec<KdfVector> {
    let sk_compat = SecretKey::from_raw(*b"NyaPassword-SK-1");
    let sk_seq = SecretKey::from_raw(seq(0, 16).try_into().unwrap());
    let salt5a = vec![0x5au8; 16];
    let cases: Vec<(&str, &str, &SecretKey, Vec<u8>, KdfParams)> = vec![
        (
            "ascii, test parameters (same as npw-core compat v1.0)",
            "correct horse battery staple",
            &sk_compat,
            salt5a.clone(),
            KdfParams::insecure_for_tests(),
        ),
        (
            "unicode, composed é",
            "caf\u{e9} 密码 🐱",
            &sk_compat,
            salt5a.clone(),
            params(1024, 2, 2),
        ),
        (
            "unicode, decomposed e + U+0301 (same keys as the composed form)",
            "cafe\u{301} 密码 🐱",
            &sk_compat,
            salt5a.clone(),
            params(1024, 2, 2),
        ),
        (
            "compatibility characters: ligature and full-width letters fold",
            "\u{fb01}ne \u{ff30}\u{ff41}\u{ff53}\u{ff53}",
            &sk_seq,
            salt5a.clone(),
            params(256, 1, 1),
        ),
        (
            "leading and trailing spaces are kept",
            "  pass word  ",
            &sk_seq,
            salt5a,
            params(256, 1, 1),
        ),
        (
            "empty password, 32-byte salt",
            "",
            &sk_seq,
            seq(0x80, 32),
            params(256, 1, 1),
        ),
        (
            "default parameters (64 MiB, t=3, p=4)",
            "correct horse battery staple",
            &sk_seq,
            seq(0, 16),
            KdfParams::default(),
        ),
    ];
    cases
        .into_iter()
        .map(|(name, pw, sk, salt, p)| {
            let mk = kdf::derive_master(pw, sk, &salt, &p).unwrap();
            let (k_pw, k_sk, m) = reference::kdf_parts(pw, sk.raw(), &salt, &p);
            KdfVector {
                name: name.into(),
                password: pw.into(),
                password_nfkd_hex: h(kdf::normalize_password(pw).as_bytes()),
                secret_key: sk.to_text(),
                account_salt_hex: h(&salt),
                params: p,
                k_pw_hex: h(&k_pw),
                k_sk_hex: h(&k_sk),
                master_hex: h(&m),
                auk_hex: h(mk.auk.as_bytes()),
                login_hex: h(mk.login.as_bytes()),
            }
        })
        .collect()
}

fn gen_recovery() -> Vec<RecoveryVector> {
    [
        ([0x11u8; 32], vec![0x5au8; 16]),
        (seq(0, 32).try_into().unwrap(), seq(0x80, 32)),
    ]
    .into_iter()
    .map(|(code, salt)| {
        let mk = kdf::derive_recovery(&code, &salt);
        RecoveryVector {
            code_hex: h(&code),
            account_salt_hex: h(&salt),
            auk_hex: h(mk.auk.as_bytes()),
            login_hex: h(mk.login.as_bytes()),
        }
    })
    .collect()
}

fn gen_params() -> Vec<ParamsVector> {
    [
        KdfParams::default(),
        params(16 * 1024, 1, 1),
        params(16 * 1024 - 1, 1, 1),
        params(1024 * 1024, 64, 16),
        params(1024 * 1024 + 1, 3, 4),
        params(64 * 1024, 0, 4),
        params(64 * 1024, 65, 4),
        params(64 * 1024, 3, 0),
        params(64 * 1024, 3, 17),
        KdfParams::insecure_for_tests(),
    ]
    .into_iter()
    .map(|p| ParamsVector {
        params: p,
        valid: p.validate().is_ok(),
    })
    .collect()
}

fn gen_secret_keys() -> (Vec<SecretKeyVector>, Vec<InvalidText>) {
    let raws: Vec<[u8; 16]> = vec![
        [0u8; 16],
        [0xffu8; 16],
        *b"NyaPassword-SK-1",
        seq(0, 16).try_into().unwrap(),
        unh("a35f0c9e71d24b88e6103fd25c7a91b4").try_into().unwrap(),
    ];
    let valid = raws
        .iter()
        .map(|raw| {
            let text = SecretKey::from_raw(*raw).to_text();
            let mut also = vec![
                text.to_lowercase(),
                text.replace('-', " "),
                text.replace('-', ""),
                format!("  {}\n", text.replace('-', "").to_lowercase()),
            ];
            let body = &text[3..];
            if body.contains('0') || body.contains('1') {
                also.push(format!(
                    "A1-{}",
                    body.replace('0', "O")
                        .replacen('1', "I", 1)
                        .replace('1', "l")
                ));
            }
            SecretKeyVector {
                raw_hex: h(raw),
                check_char: text[text.len() - 1..].to_string(),
                text,
                also_accepted: also,
            }
        })
        .collect::<Vec<_>>();

    let zero = valid[0].text.clone(); // A1-000000-00000-00000-00000-00000-<check>
    let check = zero.chars().last().unwrap();
    let other_check = if check == 'Z' { 'Y' } else { 'Z' };
    let mut bad_padding = zero.clone();
    // last body character: its 2 lowest bits are padding and must be zero
    bad_padding.replace_range(32..33, "1");
    let invalid = vec![
        (
            "wrong check character",
            format!("{}{other_check}", &zero[..zero.len() - 1]),
        ),
        ("wrong prefix", format!("B1{}", &zero[2..])),
        ("no prefix", zero[3..].to_string()),
        (
            "one character missing",
            format!("{}{}", &zero[..4], &zero[5..]),
        ),
        (
            "one character too many",
            format!("{}0{}", &zero[..4], &zero[4..]),
        ),
        (
            "U is not in the alphabet",
            format!("{}U{}", &zero[..4], &zero[5..]),
        ),
        ("non-zero padding bits", bad_padding),
        ("empty", String::new()),
    ]
    .into_iter()
    .map(|(name, text)| InvalidText {
        name: name.into(),
        error: error_kind(&SecretKey::parse(&text).expect_err(name)),
        text,
    })
    .collect();
    (valid, invalid)
}

/// (function, label, ids, format_major, name)
type AadCase = (
    &'static str,
    &'static str,
    Vec<String>,
    Option<u16>,
    Option<&'static str>,
);

/// (name, key, nonce, aad, plaintext)
type EnvelopeCase = (&'static str, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn gen_aad() -> Vec<AadVector> {
    let a = || vec![ACCOUNT_ID.to_string()];
    let v = || vec![VAULT_ID.to_string()];
    let vi = || vec![VAULT_ID.to_string(), ITEM_ID.to_string()];
    let cases: Vec<AadCase> = vec![
        ("account_key", "npw/account-key/v1", a(), None, None),
        (
            "account_private_key",
            "npw/account-x25519/v1",
            a(),
            None,
            None,
        ),
        (
            "recovery_account_key",
            "npw/recovery-account-key/v1",
            a(),
            None,
            None,
        ),
        ("vault_key", "npw/vault-key/v1", v(), None, None),
        ("vault_meta", "npw/vault-meta/v1", v(), None, None),
        ("item_key", "npw/item-key/v1", vi(), None, None),
        ("item_content", "npw/item/v1", vi(), Some(1), None),
        ("item_content", "npw/item/v1", vi(), Some(2), None),
        (
            "attachment",
            "npw/attachment/v1",
            vec![ATTACHMENT_ID.into()],
            None,
            None,
        ),
        (
            "device_secret",
            "npw/device-secret/v1/",
            vec![],
            None,
            Some("secret_key"),
        ),
        (
            "device_secret",
            "npw/device-secret/v1/",
            vec![],
            None,
            Some("session"),
        ),
        ("quick_unlock", "npw/quick-unlock/v1", a(), None, None),
        (
            "export",
            "npw/export/v1",
            vec![EXPORT_ID.into()],
            None,
            None,
        ),
    ];
    cases
        .into_iter()
        .map(|(function, label, ids, fm, name)| AadVector {
            hex: h(&aad_of(function, &ids, fm, name)),
            function: function.into(),
            label: label.into(),
            ids,
            format_major: fm,
            name: name.map(str::to_string),
        })
        .collect()
}

fn item_json() -> Vec<u8> {
    r#"{"format":"1.0","template":"password","title":"示例","fields":[{"id":"password","label":"密码","kind":"concealed","purpose":"password","value":"pässwörd"}]}"#
        .as_bytes()
        .to_vec()
}

fn gen_envelopes() -> (Vec<EnvelopeVector>, Vec<InvalidCiphertext>) {
    let k0 = seq(0, 32);
    let cases: Vec<EnvelopeCase> = vec![
        (
            "empty plaintext, empty AAD",
            k0.clone(),
            seq(0x40, 24),
            vec![],
            vec![],
        ),
        (
            "short message with AAD",
            k0.clone(),
            vec![1; 24],
            b"npw/test".to_vec(),
            b"hello".to_vec(),
        ),
        (
            "AK wrapped under AUK (= npw-core compat v1.0 encrypted_account_key)",
            vec![1; 32],
            vec![1; 24],
            aad::account_key(&uuid16(ACCOUNT_ID)),
            vec![2; 32],
        ),
        (
            "IK wrapped under VK",
            vec![3; 32],
            vec![0x14; 24],
            aad::item_key(&uuid16(VAULT_ID), &uuid16(ITEM_ID)),
            vec![0x0a; 32],
        ),
        (
            "item content JSON under IK",
            vec![0x0a; 32],
            vec![0x64; 24],
            aad::item_content(&uuid16(VAULT_ID), &uuid16(ITEM_ID), 1),
            item_json(),
        ),
        (
            "300 bytes (several ChaCha20 blocks)",
            k0.clone(),
            seq(0xa0, 24),
            vec![],
            pattern(300),
        ),
    ];
    let valid: Vec<EnvelopeVector> = cases
        .into_iter()
        .map(|(name, k, n, a, pt)| {
            let env = envelope::seal_with_nonce(
                &Key32::from_slice(&k).unwrap(),
                &n.clone().try_into().unwrap(),
                &pt,
                &a,
            );
            EnvelopeVector {
                name: name.into(),
                key_hex: h(&k),
                nonce_hex: h(&n),
                aad_hex: h(&a),
                plaintext_hex: h(&pt),
                envelope_hex: h(&env),
            }
        })
        .collect();

    let base = &valid[1];
    let env = unh(&base.envelope_hex);
    let with = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut e = env.clone();
        f(&mut e);
        e
    };
    let bad: Vec<(&str, String, String, Vec<u8>)> = vec![
        (
            "version byte 2",
            base.key_hex.clone(),
            base.aad_hex.clone(),
            with(&|e| e[0] = 2),
        ),
        (
            "version byte 0",
            base.key_hex.clone(),
            base.aad_hex.clone(),
            with(&|e| e[0] = 0),
        ),
        (
            "algorithm 2 (the attachment stream id) is not an envelope algorithm",
            base.key_hex.clone(),
            base.aad_hex.clone(),
            with(&|e| e[1] = 2),
        ),
        (
            "shorter than header + tag",
            base.key_hex.clone(),
            base.aad_hex.clone(),
            env[..envelope::OVERHEAD - 1].to_vec(),
        ),
        (
            "last tag byte flipped",
            base.key_hex.clone(),
            base.aad_hex.clone(),
            with(&|e| *e.last_mut().unwrap() ^= 1),
        ),
        (
            "nonce byte flipped",
            base.key_hex.clone(),
            base.aad_hex.clone(),
            with(&|e| e[2] ^= 0x80),
        ),
        (
            "wrong AAD",
            base.key_hex.clone(),
            h(b"npw/test2"),
            env.clone(),
        ),
        (
            "wrong key",
            h(&[0xff; 32]),
            base.aad_hex.clone(),
            env.clone(),
        ),
    ];
    let invalid = bad
        .into_iter()
        .map(|(name, k, a, data)| InvalidCiphertext {
            error: error_kind(&envelope::open(&key(&k), &data, &unh(&a)).expect_err(name)),
            name: name.into(),
            key_hex: k,
            aad_hex: a,
            data_hex: h(&data),
        })
        .collect();
    (valid, invalid)
}

/// `stream::encrypt` picks a random nonce prefix, so the stream vectors are
/// built by the reference implementation with a fixed prefix and checked by
/// decrypting them with the crate.
fn gen_streams() -> (Vec<StreamVector>, Vec<InvalidCiphertext>) {
    let k = seq(0x20, 32);
    let prefix: [u8; 19] = seq(0xc0, 19).try_into().unwrap();
    let a = aad::attachment(&uuid16(ATTACHMENT_ID));
    let lens: Vec<(&str, usize)> = vec![
        ("empty file: one empty chunk", 0),
        ("100 bytes: one short chunk", 100),
        (
            "exactly 1 MiB: one full chunk, no empty chunk after it",
            stream::CHUNK,
        ),
        (
            "1 MiB + 5: a full chunk and a 5-byte last chunk",
            stream::CHUNK + 5,
        ),
        ("exactly 2 MiB: two full chunks", 2 * stream::CHUNK),
    ];
    let valid: Vec<StreamVector> = lens
        .into_iter()
        .map(|(name, len)| {
            let pt = pattern(len);
            let ct = reference::stream_encrypt(&k, &prefix, &a, &pt);
            assert_eq!(
                stream::decrypt(&key(&h(&k)), &a, &ct).unwrap(),
                pt,
                "{name}"
            );
            StreamVector {
                name: name.into(),
                key_hex: h(&k),
                nonce_prefix_hex: h(&prefix),
                aad_hex: h(&a),
                plaintext_len: len,
                ciphertext_hex: (ct.len() <= 1024).then(|| h(&ct)),
                ciphertext_sha256: npw_crypto::sha256_hex(&ct),
                encrypted_len: stream::encrypted_len(len),
            }
        })
        .collect();

    let pt = pattern(100);
    let good = reference::stream_encrypt(&k, &prefix, &a, &pt);
    let with = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut e = good.clone();
        f(&mut e);
        e
    };
    let bad: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        ("version byte 2", a.clone(), with(&|e| e[0] = 2)),
        (
            "algorithm 1 (the envelope id)",
            a.clone(),
            with(&|e| e[1] = 1),
        ),
        (
            "shorter than header + tag",
            a.clone(),
            good[..stream::HEADER_LEN + 15].to_vec(),
        ),
        (
            "truncated: the only chunk was sealed as not-last",
            a.clone(),
            reference::stream_chunks(&k, &prefix, &a, &[(&pt, 0, false)]),
        ),
        (
            "reordered: the first chunk carries counter 1",
            a.clone(),
            reference::stream_chunks(&k, &prefix, &a, &[(&pt, 1, true)]),
        ),
        (
            "chunk byte flipped",
            a.clone(),
            with(&|e| e[stream::HEADER_LEN] ^= 1),
        ),
        (
            "other attachment id",
            aad::attachment(&uuid16(EXPORT_ID)),
            good.clone(),
        ),
    ];
    let invalid = bad
        .into_iter()
        .map(|(name, aad_bytes, data)| InvalidCiphertext {
            error: error_kind(&stream::decrypt(&key(&h(&k)), &aad_bytes, &data).expect_err(name)),
            name: name.into(),
            key_hex: h(&k),
            aad_hex: h(&aad_bytes),
            data_hex: h(&data),
        })
        .collect();
    (valid, invalid)
}

fn generate() -> Vectors {
    let (secret_key, secret_key_invalid) = gen_secret_keys();
    let (envelope, envelope_invalid) = gen_envelopes();
    let (stream, stream_invalid) = gen_streams();
    Vectors {
        version: 1,
        note: "NyaPassword crypto test vectors v1 (docs/加密规格.md). Binary values are hex. \
               Stream plaintext byte i is (i * 31) % 251. Frozen: never edit, only add a new file."
            .into(),
        kdf: gen_kdf(),
        recovery: gen_recovery(),
        kdf_params: gen_params(),
        secret_key,
        secret_key_invalid,
        aad: gen_aad(),
        envelope,
        envelope_invalid,
        stream,
        stream_invalid,
    }
}

// ------------------------------------------------------------------ checks

fn check(v: &Vectors) {
    assert_eq!(v.version, 1);

    for k in &v.kdf {
        let sk = SecretKey::parse(&k.secret_key).unwrap();
        let salt = unh(&k.account_salt_hex);
        assert_eq!(
            h(kdf::normalize_password(&k.password).as_bytes()),
            k.password_nfkd_hex,
            "{}",
            k.name
        );
        let mk = kdf::derive_master(&k.password, &sk, &salt, &k.params).unwrap();
        assert_eq!(h(mk.auk.as_bytes()), k.auk_hex, "AUK: {}", k.name);
        assert_eq!(h(mk.login.as_bytes()), k.login_hex, "LOGIN: {}", k.name);
        // the specification, step by step
        let (k_pw, k_sk, m) = reference::kdf_parts(&k.password, sk.raw(), &salt, &k.params);
        assert_eq!(h(&k_pw), k.k_pw_hex, "K_pw: {}", k.name);
        assert_eq!(h(&k_sk), k.k_sk_hex, "K_sk: {}", k.name);
        assert_eq!(h(&m), k.master_hex, "M: {}", k.name);
        let (auk, login) = reference::split(&m);
        assert_eq!(
            (h(&auk), h(&login)),
            (k.auk_hex.clone(), k.login_hex.clone()),
            "{}",
            k.name
        );
    }
    // composed and decomposed spellings of one password give the same keys
    assert_eq!(v.kdf[1].auk_hex, v.kdf[2].auk_hex);
    assert_ne!(v.kdf[1].password, v.kdf[2].password);
    // short salts are refused
    assert_eq!(
        kdf::derive_master(
            "x",
            &SecretKey::from_raw([0; 16]),
            &[0; 15],
            &KdfParams::insecure_for_tests()
        )
        .err(),
        Some(CryptoError::InvalidKdfParams)
    );

    for r in &v.recovery {
        let code: [u8; 32] = unh(&r.code_hex).try_into().unwrap();
        let salt = unh(&r.account_salt_hex);
        let mk = kdf::derive_recovery(&code, &salt);
        assert_eq!(h(mk.auk.as_bytes()), r.auk_hex);
        assert_eq!(h(mk.login.as_bytes()), r.login_hex);
        let (auk, login) = reference::recovery(&code, &salt);
        assert_eq!(
            (h(&auk), h(&login)),
            (r.auk_hex.clone(), r.login_hex.clone())
        );
    }

    for p in &v.kdf_params {
        assert_eq!(p.params.validate().is_ok(), p.valid, "{:?}", p.params);
        assert_eq!(
            reference::params_valid(&p.params),
            p.valid,
            "{:?}",
            p.params
        );
    }

    for s in &v.secret_key {
        let raw: [u8; 16] = unh(&s.raw_hex).try_into().unwrap();
        assert_eq!(SecretKey::from_raw(raw).to_text(), s.text);
        assert_eq!(reference::secret_key_text(&raw), s.text);
        assert_eq!(s.text.chars().last().unwrap().to_string(), s.check_char);
        assert_eq!(SecretKey::parse(&s.text).unwrap().raw(), &raw);
        for alt in &s.also_accepted {
            assert_eq!(SecretKey::parse(alt).unwrap().raw(), &raw, "{alt:?}");
        }
    }
    for s in &v.secret_key_invalid {
        let e = SecretKey::parse(&s.text).expect_err(&s.name);
        assert_eq!(error_kind(&e), s.error, "{}", s.name);
    }

    for a in &v.aad {
        let got = aad_of(&a.function, &a.ids, a.format_major, a.name.as_deref());
        assert_eq!(h(&got), a.hex, "{}", a.function);
        // label ‖ raw 16-byte ids ‖ tail
        let mut want = a.label.as_bytes().to_vec();
        for id in &a.ids {
            want.extend_from_slice(&uuid16(id));
        }
        if let Some(fm) = a.format_major {
            want.extend_from_slice(&fm.to_be_bytes());
        }
        if let Some(n) = &a.name {
            want.extend_from_slice(n.as_bytes());
        }
        assert_eq!(h(&want), a.hex, "{}", a.function);
    }

    for e in &v.envelope {
        let k = key(&e.key_hex);
        let nonce: [u8; 24] = unh(&e.nonce_hex).try_into().unwrap();
        let (a, pt, env) = (unh(&e.aad_hex), unh(&e.plaintext_hex), unh(&e.envelope_hex));
        assert_eq!(
            envelope::seal_with_nonce(&k, &nonce, &pt, &a),
            env,
            "{}",
            e.name
        );
        assert_eq!(
            reference::envelope_seal(&unh(&e.key_hex), &nonce, &a, &pt),
            env,
            "{}",
            e.name
        );
        assert_eq!(envelope::open(&k, &env, &a).unwrap(), pt, "{}", e.name);
        assert_eq!(env.len(), pt.len() + envelope::OVERHEAD);
        if pt.len() == 32 {
            assert_eq!(
                envelope::unwrap_key(&k, &env, &a).unwrap().as_bytes()[..],
                pt[..]
            );
        }
    }
    for e in &v.envelope_invalid {
        let r = envelope::open(&key(&e.key_hex), &unh(&e.data_hex), &unh(&e.aad_hex));
        assert_eq!(error_kind(&r.expect_err(&e.name)), e.error, "{}", e.name);
    }

    for s in &v.stream {
        let k = unh(&s.key_hex);
        let prefix: [u8; 19] = unh(&s.nonce_prefix_hex).try_into().unwrap();
        let a = unh(&s.aad_hex);
        let pt = pattern(s.plaintext_len);
        let ct = reference::stream_encrypt(&k, &prefix, &a, &pt);
        assert_eq!(
            npw_crypto::sha256_hex(&ct),
            s.ciphertext_sha256,
            "{}",
            s.name
        );
        if let Some(c) = &s.ciphertext_hex {
            assert_eq!(&h(&ct), c, "{}", s.name);
        }
        assert_eq!(ct.len(), s.encrypted_len, "{}", s.name);
        assert_eq!(
            stream::encrypted_len(s.plaintext_len),
            s.encrypted_len,
            "{}",
            s.name
        );
        assert_eq!(
            stream::decrypt(&key(&s.key_hex), &a, &ct).unwrap(),
            pt,
            "{}",
            s.name
        );
    }
    for s in &v.stream_invalid {
        let r = stream::decrypt(&key(&s.key_hex), &unh(&s.aad_hex), &unh(&s.data_hex));
        assert_eq!(error_kind(&r.expect_err(&s.name)), s.error, "{}", s.name);
    }
}

#[test]
fn frozen_crypto_vectors() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("v1.json");
    if std::env::var("NPW_BLESS").is_ok() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let json = serde_json::to_string_pretty(&generate()).unwrap() + "\n";
        std::fs::write(&path, json).unwrap();
    }
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("{} missing (NPW_BLESS=1 generates it)", path.display()));
    let v: Vectors = serde_json::from_str(&text).unwrap();
    check(&v);
}

// ------------------------------------------------------------------ the specification, re-implemented

mod reference {
    use argon2::{Algorithm, Argon2, Params, Version};
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    use hkdf::Hkdf;
    use npw_crypto::KdfParams;
    use sha2::{Digest, Sha256};
    use unicode_normalization::UnicodeNormalization;

    const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    const CHUNK: usize = 1 << 20;

    fn hkdf32(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        Hkdf::<Sha256>::new(salt, ikm)
            .expand(info, &mut out)
            .unwrap();
        out
    }

    /// (K_pw, K_sk, M) of §2.
    pub fn kdf_parts(
        password: &str,
        sk: &[u8; 16],
        salt: &[u8],
        p: &KdfParams,
    ) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let pw: String = password.nfkd().collect();
        let argon = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(p.m, p.t, p.p, Some(32)).unwrap(),
        );
        let mut k_pw = [0u8; 32];
        argon
            .hash_password_into(pw.as_bytes(), salt, &mut k_pw)
            .unwrap();
        let k_sk = hkdf32(Some(salt), sk, b"npw/sk/v1");
        let m: [u8; 32] = std::array::from_fn(|i| k_pw[i] ^ k_sk[i]);
        (k_pw, k_sk, m)
    }

    /// (AUK, LOGIN) from M: HKDF with an empty salt.
    pub fn split(m: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        (
            hkdf32(None, m, b"npw/auk/v1"),
            hkdf32(None, m, b"npw/opaque/v1"),
        )
    }

    pub fn recovery(code: &[u8; 32], salt: &[u8]) -> ([u8; 32], [u8; 32]) {
        (
            hkdf32(Some(salt), code, b"npw/recovery-auk/v1"),
            hkdf32(Some(salt), code, b"npw/recovery-opaque/v1"),
        )
    }

    pub fn params_valid(p: &KdfParams) -> bool {
        (16 * 1024..=1024 * 1024).contains(&p.m)
            && (1..=64).contains(&p.t)
            && (1..=16).contains(&p.p)
    }

    /// `A1-` + 26 Crockford characters of (128 bits ‖ 00), grouped 6-5-5-5-5, `-` + check character.
    pub fn secret_key_text(raw: &[u8; 16]) -> String {
        let mut bits = String::new();
        for b in raw {
            bits.push_str(&format!("{b:08b}"));
        }
        bits.push_str("00");
        let body: String = bits
            .as_bytes()
            .chunks(5)
            .map(|c| {
                CROCKFORD[usize::from_str_radix(std::str::from_utf8(c).unwrap(), 2).unwrap()]
                    as char
            })
            .collect();
        let mut data = b"A1".to_vec();
        data.extend_from_slice(raw);
        let check = CROCKFORD[(Sha256::digest(&data)[0] & 31) as usize] as char;
        format!(
            "A1-{}-{}-{}-{}-{}-{check}",
            &body[0..6],
            &body[6..11],
            &body[11..16],
            &body[16..21],
            &body[21..26]
        )
    }

    pub fn envelope_seal(key: &[u8], nonce: &[u8; 24], aad: &[u8], pt: &[u8]) -> Vec<u8> {
        let ct = XChaCha20Poly1305::new(key.into())
            .encrypt(XNonce::from_slice(nonce), Payload { msg: pt, aad })
            .unwrap();
        let mut out = vec![1u8, 1u8];
        out.extend_from_slice(nonce);
        out.extend_from_slice(&ct);
        out
    }

    /// Header, then each (plaintext, counter, last) chunk sealed as specified.
    pub fn stream_chunks(
        key: &[u8],
        prefix: &[u8; 19],
        aad: &[u8],
        chunks: &[(&[u8], u32, bool)],
    ) -> Vec<u8> {
        let cipher = XChaCha20Poly1305::new(key.into());
        let mut out = vec![1u8, 2u8];
        out.extend_from_slice(prefix);
        for (pt, counter, last) in chunks {
            let mut nonce = [0u8; 24];
            nonce[..19].copy_from_slice(prefix);
            nonce[19..23].copy_from_slice(&counter.to_be_bytes());
            nonce[23] = u8::from(*last);
            out.extend_from_slice(
                &cipher
                    .encrypt(XNonce::from_slice(&nonce), Payload { msg: pt, aad })
                    .unwrap(),
            );
        }
        out
    }

    pub fn stream_encrypt(key: &[u8], prefix: &[u8; 19], aad: &[u8], pt: &[u8]) -> Vec<u8> {
        let parts: Vec<&[u8]> = if pt.is_empty() {
            vec![&[][..]]
        } else {
            pt.chunks(CHUNK).collect()
        };
        let n = parts.len();
        let chunks: Vec<(&[u8], u32, bool)> = parts
            .into_iter()
            .enumerate()
            .map(|(i, c)| (c, i as u32, i + 1 == n))
            .collect();
        stream_chunks(key, prefix, aad, &chunks)
    }
}
