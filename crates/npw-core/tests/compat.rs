//! Frozen format test vectors (design doc §5.6). For every released item
//! format `tests/compat/vX.Y/vectors.json` holds key-derivation vectors and
//! encrypted items made with fixed keys and nonces. Every build on every
//! target must keep deriving the same keys and decrypting these items to the
//! same content — forever.
//!
//! Regenerate the current version's vectors (only before it is released!):
//!   $env:NPW_BLESS=1; cargo test -p npw-core --test compat

use std::path::PathBuf;

use npw_crypto::{aad, b64, envelope, kdf, unb64, KdfParams, Key32, SecretKey};
use npw_model::{decode_item, encode_item, template, templates, ItemContent};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Serialize, Deserialize)]
struct KdfVector {
    password: String,
    secret_key: String,
    account_salt: String,
    params: KdfParams,
    auk_hex: String,
    login_hex: String,
}

#[derive(Serialize, Deserialize)]
struct ItemVector {
    name: String,
    item_id: String,
    format_major: u16,
    wrapped_key: String,
    ciphertext: String,
    plaintext: Value,
}

#[derive(Serialize, Deserialize)]
struct Vectors {
    format: String,
    kdf: Vec<KdfVector>,
    account_id: String,
    vault_id: String,
    account_key_hex: String,
    auk_hex: String,
    encrypted_account_key: String,
    vault_key_hex: String,
    wrapped_vault_key: String,
    items: Vec<ItemVector>,
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("compat")
}

fn uuid16(s: &str) -> [u8; 16] {
    *uuid::Uuid::parse_str(s).unwrap().as_bytes()
}

fn nonce(n: u8) -> [u8; 24] {
    [n; 24]
}

fn sample_items() -> Vec<(String, ItemContent)> {
    let mut out = vec![];
    for (i, t) in templates().iter().enumerate() {
        let mut it = t.new_item(if i % 2 == 0 { "zh-CN" } else { "en" });
        it.title = format!("{} 示例 {i}", t.zh);
        it.created_at = 1_759_536_000_000 + i as i64;
        it.updated_at = it.created_at + 1000;
        for f in &mut it.fields {
            f.value = match f.kind.as_str() {
                "address" => {
                    json!({ "country": "中国", "province": "浙江省", "city": "杭州市", "district": "西湖区", "street": "示例路 1 号", "postal_code": "310000" })
                }
                "date" => "2030-01-31".into(),
                "month_year" => "2030-08".into(),
                "boolean" => "true".into(),
                "totp" => "otpauth://totp/Example:me?secret=JBSWY3DPEHPK3PXP&issuer=Example".into(),
                _ if f.multiline => "line 1\nline 2\n第三行".into(),
                _ => format!("{}-value", f.id).into(),
            };
        }
        out.push((t.id.to_string(), it));
    }
    // a login with everything the format has
    let mut full = template("login").unwrap().new_item("zh-CN");
    full.title = "Full".into();
    full.favorite = true;
    full.archived = true;
    full.tags = vec!["工作/开发".into(), "a".into()];
    full.notes = "多行\n备注".into();
    full.created_at = 1_759_536_000_000;
    full.updated_at = 1_759_536_000_500;
    full.fields[0].value = "octocat".into();
    full.fields[1].value = "pässwörd".into();
    let mut rec = npw_model::Field::new("f_rc", "恢复码", "concealed");
    rec.multiline = true;
    rec.section = Some("s_rec".into());
    rec.value = "aaaa-bbbb\ncccc-dddd".into();
    full.fields.push(rec);
    full.sections.push(npw_model::Section {
        id: "s_rec".into(),
        label: "恢复".into(),
        extra: Default::default(),
    });
    full.urls.push(npw_model::UrlEntry {
        id: "u1".into(),
        url: "https://github.com/login".into(),
        match_mode: "domain".into(),
        cert_sha256: vec![],
        extra: Default::default(),
    });
    full.urls.push(npw_model::UrlEntry {
        id: "u2".into(),
        url: "androidapp://com.github.android".into(),
        match_mode: "exact".into(),
        cert_sha256: vec!["ab".repeat(32)],
        extra: Default::default(),
    });
    full.passkeys.push(npw_model::Passkey {
        id: "pk1".into(),
        rp_id: "github.com".into(),
        credential_id: "Y3JlZA".into(),
        user_handle: "dXNlcg".into(),
        user_name: "octocat".into(),
        user_display_name: "Octo Cat".into(),
        rp_name: "GitHub".into(),
        alg: -7,
        private_key: "cGtjczg".into(),
        counter: 0,
        discoverable: true,
        created_at: 1_759_536_000_000,
        extra: Default::default(),
    });
    full.attachments.push(npw_model::Attachment {
        id: "a1".into(),
        name: "扫描件.pdf".into(),
        size: 12345,
        mime: "application/pdf".into(),
        key: b64(&[9u8; 32]),
        blob_sha256: "00".repeat(32),
        created_at: 1_759_536_000_000,
        extra: Default::default(),
    });
    full.history.push(npw_model::HistoryEntry {
        id: "h1".into(),
        field: "password".into(),
        label: "密码".into(),
        value: "old".into(),
        until: 1_759_536_000_100,
        extra: Default::default(),
    });
    full.conflicts.push(npw_model::Conflict {
        id: "c1".into(),
        path: "fields/password/value".into(),
        label: "密码".into(),
        value: "theirs".into(),
        kept: "pässwörd".into(),
        device: "dev".into(),
        at: 1_759_536_000_200,
        extra: Default::default(),
    });
    full.autofill.auto_submit = true;
    full.extra.insert(
        "import".into(),
        json!({ "batch": "b", "source": "bitwarden", "at": 1 }),
    );
    full.extra
        .insert("x_future_key".into(), json!({ "kept": [1, 2, 3] }));
    out.push(("login_full".into(), full));
    out
}

fn generate() -> Vectors {
    let account_id = "0192f0c0-0000-7000-8000-000000000001".to_string();
    let vault_id = "0192f0c0-0000-7000-8000-000000000002".to_string();
    let sk = SecretKey::from_raw(*b"NyaPassword-SK-1");
    let salt = [0x5au8; 16];
    let mut kdfs = vec![];
    for (pw, params) in [
        (
            "correct horse battery staple",
            KdfParams::insecure_for_tests(),
        ),
        (
            "café 密码 🐱",
            KdfParams {
                alg: npw_crypto::kdf::KdfAlg::Argon2id,
                m: 1024,
                t: 2,
                p: 2,
            },
        ),
    ] {
        let mk = kdf::derive_master(pw, &sk, &salt, &params).unwrap();
        kdfs.push(KdfVector {
            password: pw.into(),
            secret_key: sk.to_text(),
            account_salt: b64(&salt),
            params,
            auk_hex: hex::encode(mk.auk.as_bytes()),
            login_hex: hex::encode(mk.login.as_bytes()),
        });
    }
    let auk = Key32::from_bytes([1u8; 32]);
    let ak = Key32::from_bytes([2u8; 32]);
    let vk = Key32::from_bytes([3u8; 32]);
    let enc_ak = envelope::seal_with_nonce(
        &auk,
        &nonce(1),
        ak.as_bytes(),
        &aad::account_key(&uuid16(&account_id)),
    );
    let wrapped_vk = envelope::seal_with_nonce(
        &ak,
        &nonce(2),
        vk.as_bytes(),
        &aad::vault_key(&uuid16(&vault_id)),
    );
    let mut items = vec![];
    for (i, (name, content)) in sample_items().into_iter().enumerate() {
        let item_id = format!("0192f0c0-0000-7000-8000-{:012x}", 100 + i);
        let ik = Key32::from_bytes([10 + i as u8; 32]);
        let major = 1;
        let wk = envelope::seal_with_nonce(
            &vk,
            &nonce(20 + i as u8),
            ik.as_bytes(),
            &aad::item_key(&uuid16(&vault_id), &uuid16(&item_id)),
        );
        let plain = encode_item(&content);
        let ct = envelope::seal_with_nonce(
            &ik,
            &nonce(100 + i as u8),
            &plain,
            &aad::item_content(&uuid16(&vault_id), &uuid16(&item_id), major),
        );
        items.push(ItemVector {
            name,
            item_id,
            format_major: major,
            wrapped_key: b64(&wk),
            ciphertext: b64(&ct),
            plaintext: serde_json::from_slice(&plain).unwrap(),
        });
    }
    Vectors {
        format: npw_model::FORMAT_VERSION.into(),
        kdf: kdfs,
        account_id,
        vault_id,
        account_key_hex: hex::encode(ak.as_bytes()),
        auk_hex: hex::encode(auk.as_bytes()),
        encrypted_account_key: b64(&enc_ak),
        vault_key_hex: hex::encode(vk.as_bytes()),
        wrapped_vault_key: b64(&wrapped_vk),
        items,
    }
}

fn check(v: &Vectors) {
    for k in &v.kdf {
        let sk = SecretKey::parse(&k.secret_key).unwrap();
        let mk = kdf::derive_master(
            &k.password,
            &sk,
            &unb64(&k.account_salt).unwrap(),
            &k.params,
        )
        .unwrap();
        assert_eq!(
            hex::encode(mk.auk.as_bytes()),
            k.auk_hex,
            "AUK for {:?}",
            k.password
        );
        assert_eq!(hex::encode(mk.login.as_bytes()), k.login_hex);
    }
    let auk = Key32::from_slice(&hex::decode(&v.auk_hex).unwrap()).unwrap();
    let ak = envelope::unwrap_key(
        &auk,
        &unb64(&v.encrypted_account_key).unwrap(),
        &aad::account_key(&uuid16(&v.account_id)),
    )
    .unwrap();
    assert_eq!(hex::encode(ak.as_bytes()), v.account_key_hex);
    let vk = envelope::unwrap_key(
        &ak,
        &unb64(&v.wrapped_vault_key).unwrap(),
        &aad::vault_key(&uuid16(&v.vault_id)),
    )
    .unwrap();
    assert_eq!(hex::encode(vk.as_bytes()), v.vault_key_hex);
    for it in &v.items {
        let ik = envelope::unwrap_key(
            &vk,
            &unb64(&it.wrapped_key).unwrap(),
            &aad::item_key(&uuid16(&v.vault_id), &uuid16(&it.item_id)),
        )
        .unwrap();
        let plain = envelope::open(
            &ik,
            &unb64(&it.ciphertext).unwrap(),
            &aad::item_content(&uuid16(&v.vault_id), &uuid16(&it.item_id), it.format_major),
        )
        .unwrap_or_else(|e| panic!("{}: {e}", it.name));
        let decoded = decode_item(&plain).unwrap();
        assert!(!decoded.read_only, "{}", it.name);
        assert_eq!(decoded.raw, it.plaintext, "{}: plaintext changed", it.name);
        // writing it back must not lose or change anything
        let again: Value = serde_json::from_slice(&encode_item(&decoded.content)).unwrap();
        assert_eq!(
            again, it.plaintext,
            "{}: re-encoding changed the item",
            it.name
        );
    }
}

#[test]
fn frozen_vectors_still_decrypt() {
    let root = dir();
    let current = root.join(format!("v{}", npw_model::FORMAT_VERSION));
    if std::env::var("NPW_BLESS").is_ok() {
        std::fs::create_dir_all(&current).unwrap();
        let v = generate();
        std::fs::write(
            current.join("vectors.json"),
            serde_json::to_string_pretty(&v).unwrap() + "\n",
        )
        .unwrap();
    }
    let mut checked = 0;
    for entry in std::fs::read_dir(&root).expect("tests/compat exists") {
        let p = entry.unwrap().path().join("vectors.json");
        if p.exists() {
            let v: Vectors = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
            check(&v);
            checked += 1;
        }
    }
    assert!(checked >= 1, "no frozen vectors found");
}

#[test]
fn schema_is_frozen_for_this_version() {
    let model = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("npw-model")
        .join("format");
    let current = std::fs::read_to_string(model.join("schema.json"))
        .unwrap()
        .replace("\r\n", "\n");
    let frozen = model
        .join("history")
        .join(format!("v{}", npw_model::FORMAT_VERSION))
        .join("schema.json");
    let frozen = std::fs::read_to_string(&frozen)
        .unwrap_or_else(|_| panic!("{} missing: freeze the format", frozen.display()))
        .replace("\r\n", "\n");
    assert_eq!(current, frozen, "format/schema.json changed: bump FORMAT_MINOR (only additions!) and freeze the new version");
}
