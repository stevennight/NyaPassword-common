mod common;

use npw_crypto::{KdfParams, SecretKey};
use npw_export::native::{read_header, MAGIC};
use npw_export::{export_native, open_native, ExportError};

const PW: &str = "correct horse 电池 staple";

fn sk() -> SecretKey {
    SecretKey::from_raw(*b"0123456789abcdef")
}

fn export() -> (Vec<npw_export::ExportVault>, Vec<u8>) {
    let vaults = common::vaults();
    let bytes =
        export_native(&vaults, "alice", PW, &sk(), KdfParams::insecure_for_tests()).unwrap();
    (vaults, bytes)
}

fn header_len(bytes: &[u8]) -> usize {
    MAGIC.len()
        + bytes[MAGIC.len()..]
            .iter()
            .position(|&b| b == b'\n')
            .unwrap()
        + 1
}

#[test]
fn round_trip_is_lossless() {
    let (vaults, bytes) = export();
    let opened = open_native(&bytes, PW, &sk()).unwrap();
    assert_eq!(opened, vaults);
    // spot checks on the parts most likely to go wrong
    let login = &opened[0].items[0];
    assert_eq!(login.attachments[1].1.len(), common::BIG);
    assert_eq!(
        login.content.field("f_rec").unwrap().text(),
        common::RECOVERY
    );
    assert_eq!(login.content.extra["future_key"]["n"][2], 3);
    assert!(opened[1].items[0].deleted);
    assert!(opened[2].items.is_empty());
}

#[test]
fn empty_export_round_trips() {
    let bytes = export_native(&[], "alice", PW, &sk(), KdfParams::insecure_for_tests()).unwrap();
    assert!(open_native(&bytes, PW, &sk()).unwrap().is_empty());
}

#[test]
fn header_is_readable_and_leaks_nothing() {
    let (_, bytes) = export();
    assert!(bytes.starts_with(b"NYAPASSWORD-EXPORT\n"));
    let h = read_header(&bytes).unwrap();
    assert_eq!(h.format, 1);
    assert_eq!(h.account_login, "alice");
    assert!(h.secret_key_required);
    assert_eq!(h.kdf, KdfParams::insecure_for_tests());

    let header = std::str::from_utf8(&bytes[..header_len(&bytes)]).unwrap();
    for secret in [
        common::LOGIN_TITLE,
        "example.com",
        "个人",
        "Work",
        common::PASSWORD,
        "recovery.txt",
    ] {
        assert!(!header.contains(secret), "header leaks {secret:?}");
    }
    // nor anywhere else in the file
    let hay = String::from_utf8_lossy(&bytes);
    for secret in [common::LOGIN_TITLE, "user@example.com", "JBSW", "code-1111"] {
        assert!(!hay.contains(secret), "file leaks {secret:?}");
    }
}

#[test]
fn wrong_password_or_secret_key_fails() {
    let (_, bytes) = export();
    assert!(matches!(
        open_native(&bytes, "wrong", &sk()),
        Err(ExportError::WrongPassword)
    ));
    assert!(matches!(
        open_native(&bytes, &format!("{PW} "), &sk()),
        Err(ExportError::WrongPassword)
    ));
    let other = SecretKey::from_raw(*b"0123456789abcdeF");
    assert!(matches!(
        open_native(&bytes, PW, &other),
        Err(ExportError::WrongPassword)
    ));
}

#[test]
fn tampering_fails() {
    let (_, bytes) = export();
    let hl = header_len(&bytes);

    // payload bytes: start, middle (inside the big attachment), last byte
    for i in [hl, hl + 5, hl + 30, (hl + bytes.len()) / 2, bytes.len() - 1] {
        let mut bad = bytes.clone();
        bad[i] ^= 0x01;
        assert!(
            matches!(open_native(&bad, PW, &sk()), Err(ExportError::Corrupted)),
            "byte {i}"
        );
    }

    // a header byte outside the key material: the account login
    let pos = bytes.windows(5).position(|w| w == b"alice").unwrap();
    let mut bad = bytes.clone();
    bad[pos] = b'b';
    assert!(open_native(&bad, PW, &sk()).is_err());

    // wrapped key / salt / kdf
    for key in [&b"wrapped_key"[..], b"salt"] {
        let at = bytes.windows(key.len()).position(|w| w == key).unwrap() + key.len() + 5;
        let mut bad = bytes.clone();
        bad[at] = if bad[at] == b'A' { b'B' } else { b'A' };
        assert!(open_native(&bad, PW, &sk()).is_err());
    }

    // truncation and appended data
    assert!(open_native(&bytes[..bytes.len() - 1], PW, &sk()).is_err());
    assert!(open_native(&bytes[..hl + 10], PW, &sk()).is_err());
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(open_native(&longer, PW, &sk()).is_err());
}

#[test]
fn rejects_other_files() {
    assert!(matches!(
        open_native(b"hello", PW, &sk()),
        Err(ExportError::NotAnExport)
    ));
    assert!(matches!(
        open_native(b"NYAPASSWORD-EXPORT\n{\"format\":", PW, &sk()),
        Err(ExportError::Malformed(_))
    ));
    let (_, bytes) = export();
    let text = String::from_utf8_lossy(&bytes[..header_len(&bytes)])
        .replace("\"format\":1", "\"format\":2");
    let mut v = text.into_bytes();
    v.extend_from_slice(&bytes[header_len(&bytes)..]);
    assert!(matches!(
        open_native(&v, PW, &sk()),
        Err(ExportError::UnsupportedVersion(2))
    ));
}

#[test]
fn every_export_uses_fresh_keys() {
    let (_, a) = export();
    let (_, b) = export();
    let (ha, hb) = (read_header(&a).unwrap(), read_header(&b).unwrap());
    assert_ne!(ha.export_id, hb.export_id);
    assert_ne!(ha.salt, hb.salt);
    assert_ne!(ha.wrapped_key, hb.wrapped_key);
}
