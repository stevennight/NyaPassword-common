//! Key parsing / generation, checked against fixtures made by `ssh-keygen`
//! (OpenSSH_9.x) and `openssl` 3.x; the expected fingerprints are what
//! `ssh-keygen -lf` printed for them.

use npw_ssh::*;

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// `<alg> <base64>` of an OpenSSH public key line (without the comment).
fn key_part(line: &str) -> String {
    line.split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ")
}

const ED25519_FP: &str = "SHA256:I0R6L2Yw9yq24U/4GAAec2QGP7AfZmDYlOinqEGNFLA";
const ECDSA_FP: &str = "SHA256:HjMWUIgD3+B2EIOg+RaAgOrT4vxTjhfnBkd/3DWjuiI";
const RSA_OPENSSH_FP: &str = "SHA256:vwf9K97wpd+ylOKF0eNwgYZbC6j/rmzsGlP2GiZH2Jc";
const RSA_PEM_FP: &str = "SHA256:iaXeaci7lGwqzdCvjHzg9IHVjUhszgqyP5I8d9SKptc";
const EC_PEM_FP: &str = "SHA256:M3rcEzR1P0NV6ilcuZ+DrNOt8sAogqEsdL/tiy+JGdE";
const EC384_PEM_FP: &str = "SHA256:0GJInGus02tTQEenQXQg3tLahS6O7JZ+NJUVJ+4c2uA";
const ED25519_PEM_FP: &str = "SHA256:EwBape8A9Fs60yJJ+gLmuJkGk25X+xE4zBFL7+8L0pA";

#[test]
fn openssh_encrypted_aes256_ctr() {
    let text = fixture("ed25519_aes256ctr");
    let pub_line = fixture("ed25519_aes256ctr.pub");

    // Public half is readable without the passphrase.
    let info = parse_private_key(&text, None).unwrap();
    assert!(info.encrypted);
    assert_eq!(info.format, KeyFormat::OpenSsh);
    assert_eq!(info.fingerprint, ED25519_FP);
    assert_eq!(info.algorithm, "ssh-ed25519");
    assert_eq!(info.key_type, "Ed25519");
    // The comment lives inside the encrypted section.
    assert_eq!(info.comment, "");
    assert_eq!(key_part(&info.public_openssh), key_part(&pub_line));

    assert_eq!(
        parse_private_key(&text, Some("wrong")).unwrap_err(),
        SshError::WrongPassphrase
    );
    let ok = parse_private_key(&text, Some("correct horse")).unwrap();
    assert_eq!(ok.fingerprint, ED25519_FP);
    assert!(ok.encrypted);
    assert_eq!(ok.comment, "fixture-ed25519@example.com");
    assert_eq!(ok.public_openssh.trim(), pub_line.trim());

    assert_eq!(
        load_private_key(&text, None).unwrap_err(),
        SshError::PassphraseRequired
    );
    assert_eq!(
        load_private_key(&text, Some("")).unwrap_err(),
        SshError::PassphraseRequired
    );
    assert!(load_private_key(&text, Some("correct horse")).is_ok());
}

#[test]
fn openssh_encrypted_aes256_gcm() {
    let text = fixture("ecdsa_aes256gcm");
    let info = parse_private_key(&text, None).unwrap();
    assert!(info.encrypted);
    assert_eq!(info.fingerprint, ECDSA_FP);
    assert_eq!(info.algorithm, "ecdsa-sha2-nistp256");
    assert_eq!(info.key_type, "ECDSA P-256");
    assert_eq!(info.bits, 256);
    assert_eq!(
        parse_private_key(&text, Some("Correct horse")).unwrap_err(),
        SshError::WrongPassphrase
    );
    assert_eq!(
        parse_private_key(&text, Some("correct horse"))
            .unwrap()
            .fingerprint,
        ECDSA_FP
    );
}

#[test]
fn openssh_rsa() {
    let info = parse_private_key(&fixture("rsa_openssh"), None).unwrap();
    assert!(!info.encrypted);
    assert_eq!(info.fingerprint, RSA_OPENSSH_FP);
    assert_eq!(info.algorithm, "ssh-rsa");
    assert_eq!(info.key_type, "RSA 2048");
    assert_eq!(info.bits, 2048);
    assert_eq!(
        info.public_openssh.trim(),
        fixture("rsa_openssh.pub").trim()
    );
}

/// (file, passphrase, format, encrypted, fingerprint, .pub file)
type PemCase = (
    &'static str,
    Option<&'static str>,
    KeyFormat,
    bool,
    &'static str,
    &'static str,
);

#[test]
fn pem_formats() {
    let cases: &[PemCase] = &[
        (
            "rsa_pkcs8.pem",
            None,
            KeyFormat::Pkcs8,
            false,
            RSA_PEM_FP,
            "rsa_pkcs8.pub",
        ),
        (
            "rsa_pkcs1.pem",
            None,
            KeyFormat::Pkcs1,
            false,
            RSA_PEM_FP,
            "rsa_pkcs8.pub",
        ),
        (
            "rsa_pkcs1_enc.pem",
            Some("legacy-pass"),
            KeyFormat::Pkcs1,
            true,
            RSA_PEM_FP,
            "rsa_pkcs8.pub",
        ),
        (
            "rsa_pkcs8_enc.pem",
            Some("pkcs8-pass"),
            KeyFormat::Pkcs8Encrypted,
            true,
            RSA_PEM_FP,
            "rsa_pkcs8.pub",
        ),
        (
            "ec_pkcs8.pem",
            None,
            KeyFormat::Pkcs8,
            false,
            EC_PEM_FP,
            "ec_pkcs8.pub",
        ),
        (
            "ec_sec1.pem",
            None,
            KeyFormat::Sec1,
            false,
            EC_PEM_FP,
            "ec_pkcs8.pub",
        ),
        (
            "ec384_pkcs8.pem",
            None,
            KeyFormat::Pkcs8,
            false,
            EC384_PEM_FP,
            "ec384_pkcs8.pub",
        ),
        (
            "ed25519_pkcs8.pem",
            None,
            KeyFormat::Pkcs8,
            false,
            ED25519_PEM_FP,
            "ed25519_pkcs8.pub",
        ),
    ];
    for (file, pass, format, encrypted, fp, pub_file) in cases {
        let info =
            parse_private_key(&fixture(file), *pass).unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!(info.format, *format, "{file}");
        assert_eq!(info.encrypted, *encrypted, "{file}");
        assert_eq!(info.fingerprint, *fp, "{file}");
        assert_eq!(
            key_part(&info.public_openssh),
            key_part(&fixture(pub_file)),
            "{file}"
        );
    }
    assert_eq!(
        parse_private_key(&fixture("ec384_pkcs8.pem"), None)
            .unwrap()
            .key_type,
        "ECDSA P-384"
    );

    // Encrypted PEM needs the passphrase, and a wrong one is reported as such.
    for (file, good) in [
        ("rsa_pkcs1_enc.pem", "legacy-pass"),
        ("rsa_pkcs8_enc.pem", "pkcs8-pass"),
    ] {
        let text = fixture(file);
        assert_eq!(
            parse_private_key(&text, None).unwrap_err(),
            SshError::PassphraseRequired,
            "{file}"
        );
        assert_eq!(
            parse_private_key(&text, Some("nope")).unwrap_err(),
            SshError::WrongPassphrase,
            "{file}"
        );
        assert!(parse_private_key(&text, Some(good)).is_ok());
    }
}

#[test]
fn rejects_non_keys() {
    assert_eq!(
        parse_private_key("hello", None).unwrap_err(),
        SshError::UnrecognizedFormat
    );
    assert_eq!(
        parse_private_key("", None).unwrap_err(),
        SshError::UnrecognizedFormat
    );
    assert!(matches!(
        parse_private_key(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----",
            None
        ),
        Err(SshError::InvalidKey(_))
    ));
    assert!(matches!(
        parse_private_key(
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
            None
        ),
        Err(SshError::Unsupported(_))
    ));
    assert_eq!(
        parse_private_key(
            "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
            None
        )
        .unwrap_err(),
        SshError::NotAPrivateKey
    );
    assert!(parse_public_key("ssh-ed25519 notbase64").is_err());
}

#[test]
fn crlf_and_surrounding_whitespace() {
    let text = format!(
        "\r\n  {}  \r\n",
        fixture("rsa_openssh").replace('\n', "\r\n")
    );
    assert_eq!(
        parse_private_key(&text, None).unwrap().fingerprint,
        RSA_OPENSSH_FP
    );
}

#[test]
fn public_keys() {
    let info = parse_public_key(&fixture("ed25519_aes256ctr.pub")).unwrap();
    assert_eq!(info.fingerprint, ED25519_FP);
    assert_eq!(info.comment, "fixture-ed25519@example.com");
    assert_eq!(info.blob.len(), 4 + 11 + 4 + 32);
    let again = parse_public_key_blob(&info.blob).unwrap();
    assert_eq!(again.fingerprint, ED25519_FP);
    assert_eq!(again.comment, "");
}

fn check_generated(kind: KeyKind, algorithm: &str, key_type: &str) {
    let g = generate(kind, "nya@example.com").unwrap();
    assert!(g
        .private_openssh
        .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
    assert!(!g.private_openssh.contains('\r'));
    assert_eq!(g.algorithm, algorithm);
    assert_eq!(g.key_type, key_type);
    assert!(g.public_openssh.starts_with(&format!("{algorithm} AAAA")));
    assert!(g.public_openssh.ends_with(" nya@example.com"));
    // "SHA256:" + 43 base64 characters (32 bytes, unpadded).
    assert!(
        g.fingerprint.starts_with("SHA256:") && g.fingerprint.len() == 7 + 43,
        "{}",
        g.fingerprint
    );

    let info = parse_private_key(&g.private_openssh, None).unwrap();
    assert!(!info.encrypted);
    assert_eq!(info.fingerprint, g.fingerprint);
    assert_eq!(info.public_openssh, g.public_openssh);
    assert_eq!(info.comment, "nya@example.com");
    assert_eq!(
        parse_public_key(&g.public_openssh).unwrap().fingerprint,
        g.fingerprint
    );

    // Encrypt for a file on disk, parse back with / without the passphrase.
    let enc = export_openssh(&g.private_openssh, None, Some("s3cret"), None).unwrap();
    assert_ne!(enc, g.private_openssh);
    let info = parse_private_key(&enc, None).unwrap();
    assert!(info.encrypted);
    assert_eq!(info.fingerprint, g.fingerprint);
    assert_eq!(
        parse_private_key(&enc, Some("wrong")).unwrap_err(),
        SshError::WrongPassphrase
    );
    assert_eq!(
        parse_private_key(&enc, Some("s3cret")).unwrap().fingerprint,
        g.fingerprint
    );
    // And remove the passphrase again.
    let plain = export_openssh(&enc, Some("s3cret"), None, Some("renamed")).unwrap();
    let info = parse_private_key(&plain, None).unwrap();
    assert!(!info.encrypted);
    assert_eq!(info.comment, "renamed");
}

#[test]
fn generate_ed25519() {
    check_generated(KeyKind::default(), "ssh-ed25519", "Ed25519");
}

#[test]
fn generate_ecdsa_p256() {
    check_generated(KeyKind::EcdsaP256, "ecdsa-sha2-nistp256", "ECDSA P-256");
}

#[test]
fn generate_rsa() {
    check_generated(KeyKind::Rsa3072, "ssh-rsa", "RSA 3072");
    check_generated(KeyKind::Rsa4096, "ssh-rsa", "RSA 4096");
}

#[test]
fn pkcs8_import_converts_to_openssh() {
    let out = export_openssh(
        &fixture("rsa_pkcs1_enc.pem"),
        Some("legacy-pass"),
        None,
        Some("imported"),
    )
    .unwrap();
    let info = parse_private_key(&out, None).unwrap();
    assert_eq!(info.format, KeyFormat::OpenSsh);
    assert_eq!(info.fingerprint, RSA_PEM_FP);
    assert_eq!(info.comment, "imported");
}
