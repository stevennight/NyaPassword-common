//! KeePass importer tests: a fake KDBX 4 database written in the test with the
//! `keepass` crate, the KeePassXC CSV fixture, and garbage / truncated input.

use std::time::Duration;

use base64::Engine;
use keepass::config::KdfConfig;
use keepass::db::{fields, Entry, History, Times, Value};
use keepass::{Database, DatabaseKey};
use npw_import::keepass::{import_csv, import_kdbx, import_keepass_csv};
use npw_import::{ImportError, ImportedItem, Mapping};
use npw_model::kind;
use rand::{rngs::StdRng, Rng, SeedableRng};

const PASSWORD: &str = "fake-master-password";

/// A fake (structurally PKCS#8-shaped) P-256 private key.
fn fake_p256_der() -> Vec<u8> {
    let mut der = vec![
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
        0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x04, 0x6D, 0x30,
        0x6B, 0x02, 0x01, 0x01, 0x04, 0x20,
    ];
    der.extend((0..32u8).map(|i| i.wrapping_mul(7)));
    der
}

fn pem(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<String> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8(c.to_vec()).unwrap())
        .collect();
    format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        lines.join("\n")
    )
}

/// `Some(NaiveDateTime)` at Unix `secs` (a macro so the test needs no chrono dependency).
macro_rules! at {
    ($secs:expr) => {
        Some(Times::epoch() + Duration::from_secs($secs))
    };
}

fn build_kdbx() -> Vec<u8> {
    let mut db = Database::new();
    db.config.kdf_config = KdfConfig::Aes { rounds: 100 };
    db.root_mut().name = "Root".into();

    let mut root = db.root_mut();
    // Root/Personal/Banking: a login with otp, attachment, history, custom fields, expiry.
    let mut personal = root.add_group();
    personal.name = "Personal".into();
    let mut banking = personal.add_group();
    banking.name = "Banking".into();
    {
        let mut e = banking.add_entry();
        e.set_unprotected(fields::TITLE, "Example Bank");
        e.set_unprotected(fields::USERNAME, "alice");
        e.set_protected(fields::PASSWORD, "old-1");
        e.times.last_modification = at!(1_600_000_000);
        let v1: Entry = (*e).clone();
        e.set_protected(fields::PASSWORD, "old-2");
        e.times.last_modification = at!(1_650_000_000);
        let v2: Entry = (*e).clone();
        e.set_protected(fields::PASSWORD, "current-pass");
        e.times.last_modification = at!(1_700_000_000);
        e.times.creation = at!(1_500_000_000);
        e.times.expires = Some(true);
        e.times.expiry = at!(1_893_456_000);
        let mut h = History::default();
        h.add_entry(v1);
        h.add_entry(v2);
        e.history = Some(h);
        e.set_unprotected(fields::URL, "https://bank.example.com");
        e.set_unprotected(fields::NOTES, "bank notes\nsecond line");
        e.set_protected(
            fields::OTP,
            "otpauth://totp/Bank:alice?secret=JBSWY3DPEHPK3PXP",
        );
        e.set_protected("PIN", "1234");
        e.set_unprotected("Branch", "Main St");
        e.set_unprotected("KP2A_URL_1", "https://m.bank.example.com");
        e.tags.push("finance".into());
        e.add_attachment(
            "readme.txt",
            Value::unprotected(b"hello attachment".to_vec()),
        );
    }
    // Root/Web: a KeePassXC passkey and a KeePass-2 style TOTP.
    let mut web = root.add_group();
    web.name = "Web".into();
    {
        let mut e = web.add_entry();
        e.set_unprotected(fields::TITLE, "Passkey site");
        e.set_unprotected(fields::USERNAME, "alice");
        e.set_unprotected(fields::URL, "https://passkey.example.com");
        e.set_unprotected("KPEX_PASSKEY_USERNAME", "alice");
        e.set_unprotected("KPEX_PASSKEY_CREDENTIAL_ID", "AAECAwQFBgcICQ-_");
        e.set_protected("KPEX_PASSKEY_PRIVATE_KEY_PEM", pem(&fake_p256_der()));
        e.set_unprotected("KPEX_PASSKEY_RELYING_PARTY", "passkey.example.com");
        e.set_protected("KPEX_PASSKEY_USER_HANDLE", "dXNlci1oYW5kbGU");
        e.set_unprotected("KPEX_PASSKEY_FLAG_BE", "1");
    }
    {
        let mut e = web.add_entry();
        e.set_unprotected(fields::TITLE, "Old TOTP");
        e.set_unprotected(fields::USERNAME, "bob");
        e.set_protected("TOTP Seed", "JBSW Y3DP EHPK 3PXP");
        e.set_unprotected("TOTP Settings", "60;8");
    }
    {
        let mut e = web.add_entry();
        e.set_unprotected(fields::TITLE, "Broken passkey");
        e.set_unprotected(fields::USERNAME, "carol");
        e.set_protected("KPEX_PASSKEY_PRIVATE_KEY_PEM", "not a pem");
        e.set_unprotected("KPEX_PASSKEY_RELYING_PARTY", "broken.example.com");
    }
    // A note directly in the root group.
    {
        let mut e = root.add_entry();
        e.set_unprotected(fields::TITLE, "Plain note");
        e.set_unprotected(fields::NOTES, "just text");
    }
    // Recycle bin.
    let mut bin = root.add_group();
    bin.name = "Recycle Bin".into();
    let bin_id = bin.id().uuid();
    bin.add_entry()
        .set_unprotected(fields::TITLE, "Deleted thing");
    db.meta.recyclebin_uuid = Some(bin_id);

    let mut out = Vec::new();
    db.save(&mut out, DatabaseKey::new().with_password(PASSWORD))
        .unwrap();
    out
}

fn by_title<'a>(items: &'a [ImportedItem], title: &str) -> &'a ImportedItem {
    items
        .iter()
        .find(|i| i.content.title == title)
        .unwrap_or_else(|| panic!("no item {title}"))
}

fn field_by_label<'a>(it: &'a ImportedItem, label: &str) -> &'a npw_model::Field {
    it.content
        .fields
        .iter()
        .find(|f| f.label == label)
        .unwrap_or_else(|| panic!("no field {label} in {}", it.content.title))
}

#[test]
fn kdbx4_maps_entries() {
    let bytes = build_kdbx();
    let r = import_kdbx(&bytes, Some(PASSWORD), "en").unwrap();
    assert_eq!(r.items.len(), 5);
    assert_eq!(r.report.skipped.len(), 1);
    assert_eq!(r.report.skipped[0].title, "Deleted thing");

    let bank = by_title(&r.items, "Example Bank");
    let c = &bank.content;
    assert_eq!(c.template, "login");
    assert_eq!(
        c.tags,
        vec!["Personal/Banking".to_string(), "finance".to_string()]
    );
    assert_eq!(c.username().as_deref(), Some("alice"));
    assert_eq!(c.password().as_deref(), Some("current-pass"));
    assert_eq!(
        c.totp().as_deref(),
        Some("otpauth://totp/Bank:alice?secret=JBSWY3DPEHPK3PXP")
    );
    assert_eq!(c.notes, "bank notes\nsecond line");
    let urls: Vec<&str> = c.urls.iter().map(|u| u.url.as_str()).collect();
    assert_eq!(
        urls,
        vec!["https://bank.example.com", "https://m.bank.example.com"]
    );
    assert_eq!(c.created_at, 1_500_000_000_000);
    assert_eq!(c.updated_at, 1_700_000_000_000);
    let pin = field_by_label(bank, "PIN");
    assert_eq!(
        (pin.kind.as_str(), pin.text().as_str()),
        (kind::CONCEALED, "1234")
    );
    assert_eq!(field_by_label(bank, "Branch").kind, kind::TEXT);
    let exp = field_by_label(bank, "Expires");
    assert_eq!(
        (exp.kind.as_str(), exp.text().as_str()),
        (kind::DATE, "2030-01-01")
    );
    assert!(!c.fields.iter().any(|f| f.label.starts_with("KP2A_URL")));
    assert_eq!(bank.attachments.len(), 1);
    assert_eq!(bank.attachments[0].name, "readme.txt");
    assert_eq!(bank.attachments[0].mime, "text/plain");
    assert_eq!(bank.attachments[0].data, b"hello attachment");
    let hist: Vec<(&str, i64)> = c
        .history
        .iter()
        .map(|h| (h.value.as_str().unwrap(), h.until))
        .collect();
    assert_eq!(
        hist,
        vec![("old-1", 1_650_000_000_000), ("old-2", 1_700_000_000_000)]
    );
    assert!(c.history.iter().all(|h| h.field == "password"));
    assert_eq!(bank.mapping, Mapping::Full);

    let pk_item = by_title(&r.items, "Passkey site");
    assert_eq!(pk_item.content.passkeys.len(), 1);
    let pk = &pk_item.content.passkeys[0];
    assert_eq!(pk.rp_id, "passkey.example.com");
    assert_eq!(pk.credential_id, "AAECAwQFBgcICQ-_");
    assert_eq!(pk.user_handle, "dXNlci1oYW5kbGU");
    assert_eq!(pk.user_name, "alice");
    assert_eq!(pk.alg, -7);
    assert_eq!(
        pk.private_key,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(fake_p256_der())
    );
    assert_eq!(
        pk.extra.get("backup_eligible"),
        Some(&serde_json::Value::Bool(true))
    );
    assert!(!pk_item
        .content
        .fields
        .iter()
        .any(|f| f.label.starts_with("KPEX_")));
    assert_eq!(pk_item.mapping, Mapping::Full);
    assert_eq!(r.report.passkeys, 1);

    let old = by_title(&r.items, "Old TOTP");
    assert_eq!(
        old.content.totp().as_deref(),
        Some("otpauth://totp/Old%20TOTP?secret=JBSWY3DPEHPK3PXP&period=60&digits=8")
    );
    assert!(!old
        .content
        .fields
        .iter()
        .any(|f| f.label.starts_with("TOTP ")));
    assert_eq!(old.content.tags, vec!["Web".to_string()]);

    let broken = by_title(&r.items, "Broken passkey");
    assert!(broken.content.passkeys.is_empty());
    assert_eq!(broken.mapping, Mapping::Partial);
    assert!(broken.warnings.iter().any(|w| w.contains("passkey")));
    assert_eq!(
        field_by_label(broken, "KPEX_PASSKEY_PRIVATE_KEY_PEM").kind,
        kind::CONCEALED
    );

    let note = by_title(&r.items, "Plain note");
    assert_eq!(note.content.template, "secure_note");
    assert!(note.content.tags.is_empty());
    assert_eq!(note.content.notes, "just text");
}

#[test]
fn kdbx_password_errors() {
    let bytes = build_kdbx();
    assert!(matches!(
        import_kdbx(&bytes, None, "en"),
        Err(ImportError::NeedPassword)
    ));
    assert!(matches!(
        import_kdbx(&bytes, Some("wrong"), "en"),
        Err(ImportError::WrongPassword)
    ));
    assert!(matches!(
        import_kdbx(b"not a database at all", Some("x"), "en"),
        Err(ImportError::Format(_))
    ));
}

#[test]
fn keepassxc_csv() {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/keepass/keepassxc.csv"
    ))
    .unwrap();
    let r = import_keepass_csv(&bytes, "en").unwrap();
    assert_eq!(r.items.len(), 3);
    assert_eq!(import_csv(&bytes, "en").unwrap().items.len(), 3);

    let router = by_title(&r.items, "Example Router");
    assert!(router.content.tags.is_empty());
    assert_eq!(router.content.urls[0].url, "http://203.0.113.1");
    assert_eq!(router.content.updated_at, 1_704_164_645_000);
    assert_eq!(router.content.created_at, 1_685_577_600_000);

    let bank = by_title(&r.items, "Example Bank");
    assert_eq!(bank.content.tags, vec!["Personal/Banking".to_string()]);
    assert_eq!(bank.content.password().as_deref(), Some("fake-bank-pass"));
    assert_eq!(
        bank.content.totp().as_deref(),
        Some("otpauth://totp/Bank:alice?secret=JBSWY3DPEHPK3PXP&period=30&digits=6")
    );
    assert_eq!(bank.content.notes, "account notes");
    assert_eq!(bank.mapping, Mapping::Full);

    let note = by_title(&r.items, "Door code note");
    assert_eq!(note.content.template, "secure_note");
    assert_eq!(note.content.tags, vec!["Notes".to_string()]);
}

#[test]
fn keepass2_csv_headers() {
    let csv = "\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\",\"Extra\"\n\"Site\",\"u\",\"p\",\"https://example.com\",\"c\",\"x\"\n";
    let r = import_keepass_csv(csv.as_bytes(), "zh-CN").unwrap();
    let it = &r.items[0];
    assert_eq!(it.content.username().as_deref(), Some("u"));
    assert_eq!(it.content.notes, "c");
    assert_eq!(field_by_label(it, "Extra").text(), "x");
    assert_eq!(it.content.sections[0].label, "其他字段");
    assert_eq!(it.mapping, Mapping::Partial);
}

#[test]
fn garbage_and_truncated_input_never_panics() {
    let mut rng = StdRng::seed_from_u64(0x06ee_9a55);
    let kdbx = build_kdbx();
    let csv = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/keepass/keepassxc.csv"
    ))
    .unwrap();
    const CHARS: &[u8] = b"abcXYZ019 ,;\"'\n\r\t";

    for i in 0..3000 {
        let len = rng.gen_range(0..2048);
        let mut junk: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
        if i % 2 == 0 && junk.len() >= 12 {
            // A valid signature with a random header behind it.
            junk[..8].copy_from_slice(&kdbx[..8]);
        }
        assert!(
            import_kdbx(&junk, Some("x"), "en").is_err(),
            "garbage accepted as KDBX"
        );
        let text: Vec<u8> = (0..len)
            .map(|_| CHARS[rng.gen_range(0..CHARS.len())])
            .collect();
        assert!(
            import_keepass_csv(&text, "en").is_err(),
            "garbage accepted as KeePass CSV"
        );
        assert!(import_keepass_csv(&junk, "en").is_err());
    }
    for _ in 0..1000 {
        let cut = rng.gen_range(0..kdbx.len());
        // Cutting off only the end-of-stream marker still leaves the whole, authenticated payload.
        if let Ok(r) = import_kdbx(&kdbx[..cut], Some(PASSWORD), "en") {
            assert!(
                cut + 64 > kdbx.len(),
                "a truncated database was accepted at {cut} of {}",
                kdbx.len()
            );
            assert_eq!(r.items.len(), 5);
        }
        // Flip bytes in the encrypted payload only: a mutated header could ask
        // for billions of KDF rounds, which is slow rather than wrong.
        let mut flipped = kdbx.clone();
        let half = flipped.len() / 2;
        for _ in 0..rng.gen_range(1..8) {
            let at = rng.gen_range(half..flipped.len());
            flipped[at] ^= rng.gen_range(1..=255u8);
        }
        assert!(import_kdbx(&flipped, Some(PASSWORD), "en").is_err());
        let cut = rng.gen_range(0..csv.len());
        let _ = import_keepass_csv(&csv[..cut], "en");
    }
}
