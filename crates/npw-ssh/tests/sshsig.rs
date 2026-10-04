//! SSHSIG (git commit signing) for every key type, verified with ssh-key.

use npw_ssh::*;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn check(private: &str, passphrase: Option<&str>, public: &str) {
    let data = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor Nya <nya@example.com> 1759536000 +0800\n\ncommit\n";
    let armored = sshsig_sign_with_passphrase(private, passphrase, "git", data).unwrap();
    assert!(armored.starts_with("-----BEGIN SSH SIGNATURE-----\n"));
    assert!(armored.trim_end().ends_with("-----END SSH SIGNATURE-----"));

    sshsig_verify(public, "git", data, &armored).unwrap();
    assert!(matches!(
        sshsig_verify(public, "file", data, &armored),
        Err(SshError::InvalidSignature(_))
    ));
    assert!(matches!(
        sshsig_verify(public, "git", b"tampered", &armored),
        Err(SshError::InvalidSignature(_))
    ));

    let sig = ssh_key::SshSig::from_pem(&armored).unwrap();
    assert_eq!(sig.namespace(), "git");
    assert_eq!(sig.hash_alg(), ssh_key::HashAlg::Sha512);
}

#[test]
fn ed25519() {
    let g = generate(KeyKind::Ed25519, "git").unwrap();
    check(&g.private_openssh, None, &g.public_openssh);
    assert!(sshsig_sign(&g.private_openssh, "git", b"x").unwrap().len() > 100);
}

#[test]
fn ecdsa() {
    let g = generate(KeyKind::EcdsaP256, "git").unwrap();
    check(&g.private_openssh, None, &g.public_openssh);
    check(
        &fixture("ecdsa_aes256gcm"),
        Some("correct horse"),
        &fixture("ecdsa_aes256gcm.pub"),
    );
}

#[test]
fn rsa() {
    check(&fixture("rsa_openssh"), None, &fixture("rsa_openssh.pub"));
    let sig = sshsig_sign(&fixture("rsa_openssh"), "git", b"x").unwrap();
    assert_eq!(
        ssh_key::SshSig::from_pem(&sig)
            .unwrap()
            .algorithm()
            .as_str(),
        "rsa-sha2-512"
    );
}

#[test]
fn errors() {
    let g = generate(KeyKind::Ed25519, "git").unwrap();
    assert!(sshsig_sign(&g.private_openssh, "", b"x").is_err());
    assert_eq!(
        sshsig_sign(&fixture("ed25519_aes256ctr"), "git", b"x").unwrap_err(),
        SshError::PassphraseRequired
    );
    assert!(sshsig_verify(&g.public_openssh, "git", b"x", "not a signature").is_err());
    // Signature from another key.
    let other = generate(KeyKind::Ed25519, "other").unwrap();
    let sig = sshsig_sign(&other.private_openssh, "git", b"x").unwrap();
    assert!(sshsig_verify(&g.public_openssh, "git", b"x", &sig).is_err());
}
