mod common;

use keepass::db::{fields, EntryRef};
use keepass::{Database, DatabaseKey};
use npw_export::kdbx::{self, KdbxOptions};
use npw_export::{export_kdbx_with, ExportVault};
use npw_model::kind;

const PW: &str = "kdbx 密码 test";

fn export() -> (Vec<ExportVault>, Database) {
    let vaults = common::vaults();
    let bytes = export_kdbx_with(&vaults, PW, &KdbxOptions::insecure_for_tests()).unwrap();
    assert_eq!(&bytes[..4], &[0x03, 0xD9, 0xA2, 0x9A], "KeePass signature");
    let db = Database::parse(&bytes, DatabaseKey::new().with_password(PW)).unwrap();
    (vaults, db)
}

fn entry<'a>(db: &'a Database, title: &str) -> EntryRef<'a> {
    db.iter_all_entries()
        .find(|e| e.get_title() == Some(title))
        .unwrap_or_else(|| panic!("no entry {title:?}"))
}

fn protected(e: &EntryRef<'_>, key: &str) -> bool {
    e.fields
        .get(key)
        .unwrap_or_else(|| panic!("no field {key:?}"))
        .is_protected()
}

#[test]
fn wrong_password_fails() {
    let bytes =
        export_kdbx_with(&common::vaults(), PW, &KdbxOptions::insecure_for_tests()).unwrap();
    assert!(Database::parse(&bytes, DatabaseKey::new().with_password("nope")).is_err());
}

#[test]
fn groups_and_recycle_bin() {
    let (_, db) = export();
    let root = db.root();
    assert_eq!(root.name, "NyaPassword");
    let names: Vec<String> = root.groups().map(|g| g.name.clone()).collect();
    for n in ["个人", "Work", "Empty vault", kdbx::RECYCLE_BIN] {
        assert!(names.contains(&n.to_string()), "{names:?}");
    }
    let bin = db.recycle_bin().expect("recycle bin set in meta");
    assert_eq!(bin.name, kdbx::RECYCLE_BIN);
    let work_bin = bin
        .group_by_name("Work")
        .expect("per-vault group in the bin");
    let deleted: Vec<_> = work_bin.entries().collect();
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].get_title(), Some("已删除的笔记"));
    assert_eq!(deleted[0].get(fields::NOTES), Some("deleted but kept"));
    assert!(deleted[0].tags.contains(&"archived".to_string()));
    assert_eq!(root.group_by_name("Work").unwrap().entries().count(), 0);
}

#[test]
fn login_fields() {
    let (_, db) = export();
    let e = entry(&db, common::LOGIN_TITLE);
    assert_eq!(e.parent().name, "个人");
    assert_eq!(e.get_username(), Some("user@example.com"));
    assert_eq!(e.get_password(), Some(common::PASSWORD));
    assert!(protected(&e, fields::PASSWORD));
    assert_eq!(e.get_url(), Some("https://example.com/login"));
    assert_eq!(e.get("KP2A_URL_1"), Some("https://accounts.example.com"));
    assert_eq!(e.get("KP2A_URL_2"), Some("androidapp://com.example.app"));
    assert_eq!(e.get(fields::NOTES), Some(common::NOTES));

    let otp = e.get(fields::OTP).unwrap();
    assert!(otp.starts_with("otpauth://totp/Example%20%E7%99%BB%E5%BD%95:user%40example.com?secret=JBSWY3DPEHPK3PXP"), "{otp}");
    assert!(protected(&e, fields::OTP));

    // section prefix, multiline concealed value kept byte for byte, protected
    assert_eq!(e.get("恢复: 恢复码"), Some(common::RECOVERY));
    assert!(protected(&e, "恢复: 恢复码"));
    assert_eq!(e.get("PIN"), Some("123456"));
    assert!(protected(&e, "PIN"));
    // a custom field labelled like a standard one does not overwrite it
    assert_eq!(e.get("密码"), Some("a field labelled like the password"));
    assert!(!protected(&e, "密码"));
    assert!(e.get("空字段").is_none(), "empty fields are skipped");

    let tags = &e.tags;
    for t in ["工作/开发", "a b", "favorite"] {
        assert!(tags.contains(&t.to_string()), "{tags:?}");
    }
    assert!(!tags.contains(&"archived".to_string()));

    assert_eq!(
        e.times.creation.unwrap().and_utc().timestamp(),
        1_700_000_000
    );
    assert_eq!(
        e.times.last_modification.unwrap().and_utc().timestamp(),
        1_759_536_000
    );
}

#[test]
fn passkeys() {
    let (_, db) = export();
    let e = entry(&db, common::LOGIN_TITLE);
    assert_eq!(e.get(kdbx::PASSKEY_USERNAME), Some("user@example.com"));
    assert_eq!(e.get(kdbx::PASSKEY_RELYING_PARTY), Some("example.com"));
    assert_eq!(
        e.get(kdbx::PASSKEY_CREDENTIAL_ID),
        Some(common::b64url(&[1u8; 16]).as_str())
    );
    assert_eq!(
        e.get(kdbx::PASSKEY_USER_HANDLE),
        Some(common::b64url(&[101u8; 32]).as_str())
    );
    let pem = e.get(kdbx::PASSKEY_PRIVATE_KEY_PEM).unwrap();
    assert!(
        pem.starts_with("-----BEGIN PRIVATE KEY-----\n")
            && pem.ends_with("\n-----END PRIVATE KEY-----"),
        "{pem}"
    );
    assert!(protected(&e, kdbx::PASSKEY_PRIVATE_KEY_PEM));
    // the PEM body decodes back to the PKCS#8 DER
    use base64::Engine;
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    assert!(pem.lines().all(|l| l.len() <= 64));
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(body)
            .unwrap(),
        common::fake_pkcs8(1)
    );

    let e2 = entry(&db, &format!("{} (passkey 2)", common::LOGIN_TITLE));
    assert_eq!(e2.get(kdbx::PASSKEY_USERNAME), Some("second@example.com"));
    assert_eq!(
        e2.get(kdbx::PASSKEY_CREDENTIAL_ID),
        Some(common::b64url(&[2u8; 16]).as_str())
    );
    assert_eq!(
        e2.get_password(),
        Some(common::PASSWORD),
        "the copy keeps the login fields"
    );
    assert_eq!(e2.attachments().count(), 0);
}

#[test]
fn attachments() {
    let (vaults, db) = export();
    let e = entry(&db, common::LOGIN_TITLE);
    let src = &vaults[0].items[0].attachments;
    assert_eq!(e.attachments().count(), 3);
    let a = e.attachment_by_name("recovery.txt").unwrap();
    assert_eq!(a.data.get(), &src[0].1);
    let big = e.attachment_by_name("big.bin").unwrap();
    assert_eq!(big.data.get().len(), common::BIG);
    assert_eq!(big.data.get(), &src[1].1);
    let dup = e
        .attachment_by_name("recovery (2).txt")
        .expect("duplicate name made unique");
    assert!(dup.data.get().is_empty());
}

#[test]
fn password_history() {
    let (_, db) = export();
    let e = entry(&db, common::LOGIN_TITLE);
    let h = e.history.as_ref().expect("history");
    assert_eq!(h.get_entries().len(), 2);
    // oldest first, as KeePass writes it
    let old: Vec<&str> = h
        .get_entries()
        .iter()
        .map(|x| x.get_password().unwrap())
        .collect();
    assert_eq!(old, common::OLD_PASSWORDS);
    assert_eq!(
        h.get_entries()[0]
            .times
            .last_modification
            .unwrap()
            .and_utc()
            .timestamp(),
        1_740_000_000
    );
    assert!(h.get_entries()[0].fields[fields::PASSWORD].is_protected());
    // the current entry is unchanged
    assert_eq!(e.get_password(), Some(common::PASSWORD));
}

#[test]
fn every_template_keeps_every_field() {
    let (vaults, db) = export();
    for item in common::template_items() {
        let c = &item.content;
        let e = entry(&db, &c.title);
        assert_eq!(e.get(fields::NOTES), Some(c.notes.as_str()));
        let values: Vec<&str> = e.fields.values().map(|v| v.get().as_str()).collect();
        for f in &c.fields {
            if f.kind == kind::TOTP {
                assert_eq!(e.get(fields::OTP), Some(f.text().as_str()), "{}", c.title);
                continue;
            }
            assert!(
                values.contains(&f.text().as_str()),
                "{}: field {} ({}) missing; have {values:?}",
                c.title,
                f.id,
                f.text()
            );
            // secret fields are protected wherever they landed
            if f.is_secret() {
                let (_, v) = e.fields.iter().find(|(_, v)| v.get() == &f.text()).unwrap();
                assert!(v.is_protected(), "{}: {} not protected", c.title, f.id);
            }
        }
        match &e.custom_data[kdbx::TEMPLATE_KEY].value {
            Some(keepass::db::CustomDataValue::String(s)) => assert_eq!(s, &c.template),
            // The keepass crate reads any XML text that happens to be valid base64
            // (e.g. "password") back as binary; the file itself holds the text.
            Some(keepass::db::CustomDataValue::Binary(b)) => {
                use base64::Engine;
                assert_eq!(
                    base64::engine::general_purpose::STANDARD_NO_PAD.encode(b),
                    c.template
                )
            }
            other => panic!("{other:?}"),
        }
    }
    // spot checks on how names are chosen
    let card = entry(&db, "银行卡 示例");
    assert_eq!(card.get("卡号"), Some("number 值 value"));
    assert!(card.get_username().unwrap().is_empty());
    let server = entry(&db, "服务器 示例");
    assert_eq!(server.get_username(), Some("username 值 value"));
    assert_eq!(server.get_password(), Some("password 值 value"));
    let ssh = entry(&db, "SSH 密钥 示例");
    assert_eq!(
        ssh.get("私钥"),
        Some("private_key 第一行\nprivate_key line 2\n-----END-----")
    );
    let id = entry(&db, "身份 示例");
    assert!(id.get("地址").unwrap().contains("杭州"));
    let _ = vaults;
}
