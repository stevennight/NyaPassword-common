//! ssh-agent round trips: identities, signing (verified independently with
//! ed25519-dalek / p256 / rsa), denial, and a seeded fuzz loop.

use npw_ssh::agent::*;
use npw_ssh::*;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rsa::signature::Verifier;
use zeroize::Zeroizing;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

struct Entry {
    blob: Vec<u8>,
    comment: String,
    private: String,
    passphrase: Option<String>,
}

#[derive(Default)]
struct Vault {
    entries: Vec<Entry>,
}

impl Vault {
    fn add(&mut self, private: &str, passphrase: Option<&str>, comment: &str) -> Vec<u8> {
        let info = parse_private_key(private, None).unwrap();
        let blob = parse_public_key(&info.public_openssh).unwrap().blob;
        self.entries.push(Entry {
            blob: blob.clone(),
            comment: comment.into(),
            private: private.into(),
            passphrase: passphrase.map(Into::into),
        });
        blob
    }
}

impl KeySource for Vault {
    fn identities(&self) -> Vec<Identity> {
        self.entries
            .iter()
            .map(|e| Identity {
                key_blob: e.blob.clone(),
                comment: e.comment.clone(),
            })
            .collect()
    }
    fn private_key(&self, key_blob: &[u8]) -> Option<PrivateKeyText> {
        let e = self.entries.iter().find(|e| e.blob == key_blob)?;
        Some(PrivateKeyText {
            private_key: Zeroizing::new(e.private.clone()),
            passphrase: e.passphrase.clone().map(Zeroizing::new),
        })
    }
}

fn put_string(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

fn read_string(buf: &mut &[u8]) -> Vec<u8> {
    let len = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
    let s = buf[4..4 + len].to_vec();
    *buf = &buf[4 + len..];
    s
}

fn sign_request(blob: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
    let mut m = vec![SSH_AGENTC_SIGN_REQUEST];
    put_string(&mut m, blob);
    put_string(&mut m, data);
    m.extend_from_slice(&flags.to_be_bytes());
    m
}

/// A realistic SSH_MSG_USERAUTH_REQUEST signature payload.
fn userauth_data(blob: &[u8], alg: &str) -> Vec<u8> {
    let mut d = vec![];
    put_string(&mut d, &[0x42; 32]); // session id
    d.push(50);
    put_string(&mut d, b"git");
    put_string(&mut d, b"ssh-connection");
    put_string(&mut d, b"publickey");
    d.push(1);
    put_string(&mut d, alg.as_bytes());
    put_string(&mut d, blob);
    d
}

/// Parses SSH_AGENT_SIGN_RESPONSE into (algorithm, raw signature).
fn parse_sign_response(resp: &[u8]) -> (String, Vec<u8>) {
    assert_eq!(
        resp[0],
        SSH_AGENT_SIGN_RESPONSE,
        "response {:?}",
        &resp[..resp.len().min(8)]
    );
    let mut r = &resp[1..];
    let blob = read_string(&mut r);
    assert!(r.is_empty());
    let mut b = &blob[..];
    let alg = String::from_utf8(read_string(&mut b)).unwrap();
    let sig = read_string(&mut b);
    assert!(b.is_empty());
    (alg, sig)
}

fn rsa_public(blob: &[u8]) -> rsa::RsaPublicKey {
    let mut b = blob;
    assert_eq!(read_string(&mut b), b"ssh-rsa");
    let e = read_string(&mut b);
    let n = read_string(&mut b);
    rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&n),
        rsa::BigUint::from_bytes_be(&e),
    )
    .unwrap()
}

fn approve_all() -> impl FnMut(&SignRequest) -> bool {
    |_| true
}

#[test]
fn request_identities() {
    let mut vault = Vault::default();
    let a = vault.add(
        &generate(KeyKind::Ed25519, "a").unwrap().private_openssh,
        None,
        "GitHub",
    );
    let b = vault.add(&fixture("rsa_openssh"), None, "Server");
    let resp = Agent::new().handle(&[SSH_AGENTC_REQUEST_IDENTITIES], &vault, &mut approve_all());
    assert_eq!(resp[0], SSH_AGENT_IDENTITIES_ANSWER);
    let mut r = &resp[1..];
    assert_eq!(u32::from_be_bytes(r[..4].try_into().unwrap()), 2);
    r = &r[4..];
    assert_eq!(read_string(&mut r), a);
    assert_eq!(read_string(&mut r), b"GitHub");
    assert_eq!(read_string(&mut r), b);
    assert_eq!(read_string(&mut r), b"Server");
    assert!(r.is_empty());

    // Empty vault.
    let resp = Agent::new().handle(
        &[SSH_AGENTC_REQUEST_IDENTITIES],
        &Vault::default(),
        &mut approve_all(),
    );
    assert_eq!(resp, [SSH_AGENT_IDENTITIES_ANSWER, 0, 0, 0, 0]);
}

#[test]
fn sign_ed25519() {
    let mut vault = Vault::default();
    let blob = vault.add(
        &generate(KeyKind::Ed25519, "me").unwrap().private_openssh,
        None,
        "GitHub",
    );
    let data = userauth_data(&blob, "ssh-ed25519");

    let mut seen = vec![];
    let resp = Agent::new().handle(
        &sign_request(&blob, &data, 0),
        &vault,
        &mut |req: &SignRequest| {
            seen.push(req.clone());
            true
        },
    );
    let (alg, sig) = parse_sign_response(&resp);
    assert_eq!(alg, "ssh-ed25519");

    let req = &seen[0];
    assert_eq!(req.comment, "GitHub");
    assert_eq!(req.algorithm, "ssh-ed25519");
    assert_eq!(req.data, data);
    assert!(req.fingerprint.starts_with("SHA256:"));
    assert_eq!(
        req.purpose,
        SignPurpose::UserAuth {
            user: "git".into(),
            service: "ssh-connection".into(),
            method: "publickey".into(),
            host_key_fingerprint: None
        }
    );

    let pk: [u8; 32] = blob[blob.len() - 32..].try_into().unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();
    vk.verify_strict(&data, &ed25519_dalek::Signature::from_slice(&sig).unwrap())
        .unwrap();
}

#[test]
fn sign_ecdsa_from_encrypted_key() {
    let mut vault = Vault::default();
    let blob = vault.add(
        &fixture("ecdsa_aes256gcm"),
        Some("correct horse"),
        "Encrypted ECDSA",
    );
    let data = b"arbitrary data";
    let (alg, sig) = parse_sign_response(&Agent::new().handle(
        &sign_request(&blob, data, 0),
        &vault,
        &mut approve_all(),
    ));
    assert_eq!(alg, "ecdsa-sha2-nistp256");

    // Signature is `mpint r ‖ mpint s`; public key blob ends with the SEC1 point.
    let mut s = &sig[..];
    let r_bytes = read_string(&mut s);
    let s_bytes = read_string(&mut s);
    let to32 = |m: &[u8]| {
        let m = if m.len() == 33 { &m[1..] } else { m };
        let mut out = [0u8; 32];
        out[32 - m.len()..].copy_from_slice(m);
        out
    };
    let sig = p256::ecdsa::Signature::from_scalars(to32(&r_bytes), to32(&s_bytes)).unwrap();
    let mut b = &blob[..];
    read_string(&mut b);
    read_string(&mut b);
    let point = read_string(&mut b);
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).unwrap();
    vk.verify(data, &sig).unwrap();

    // Wrong passphrase stored in the vault: failure, no panic.
    let mut bad = Vault::default();
    let blob = bad.add(&fixture("ecdsa_aes256gcm"), Some("nope"), "x");
    assert_eq!(
        Agent::new().handle(&sign_request(&blob, data, 0), &bad, &mut approve_all()),
        [SSH_AGENT_FAILURE]
    );
}

#[test]
fn sign_rsa_sha2() {
    let mut vault = Vault::default();
    let blob = vault.add(&fixture("rsa_openssh"), None, "RSA");
    let public = rsa_public(&blob);
    let data = userauth_data(&blob, "rsa-sha2-256");
    let agent = Agent::new();

    let (alg, sig) = parse_sign_response(&agent.handle(
        &sign_request(&blob, &data, SSH_AGENT_RSA_SHA2_256),
        &vault,
        &mut approve_all(),
    ));
    assert_eq!(alg, "rsa-sha2-256");
    assert_eq!(sig.len(), 256);
    let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(public.clone());
    vk.verify(
        &data,
        &rsa::pkcs1v15::Signature::try_from(sig.as_slice()).unwrap(),
    )
    .unwrap();

    let (alg, sig) = parse_sign_response(&agent.handle(
        &sign_request(&blob, &data, SSH_AGENT_RSA_SHA2_512),
        &vault,
        &mut approve_all(),
    ));
    assert_eq!(alg, "rsa-sha2-512");
    let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(public.clone());
    vk.verify(
        &data,
        &rsa::pkcs1v15::Signature::try_from(sig.as_slice()).unwrap(),
    )
    .unwrap();

    // Legacy SHA-1 only when enabled.
    assert_eq!(
        agent.handle(&sign_request(&blob, &data, 0), &vault, &mut approve_all()),
        [SSH_AGENT_FAILURE]
    );
    let legacy = Agent {
        allow_rsa_sha1: true,
    };
    let (alg, sig) = parse_sign_response(&legacy.handle(
        &sign_request(&blob, &data, 0),
        &vault,
        &mut approve_all(),
    ));
    assert_eq!(alg, "ssh-rsa");
    let vk = rsa::pkcs1v15::VerifyingKey::<sha1::Sha1>::new(public);
    vk.verify(
        &data,
        &rsa::pkcs1v15::Signature::try_from(sig.as_slice()).unwrap(),
    )
    .unwrap();

    // Also check with ssh-key's verifier (the path OpenSSH-compatible tools use).
    let (alg, sig) = parse_sign_response(&agent.handle(
        &sign_request(&blob, &data, SSH_AGENT_RSA_SHA2_256),
        &vault,
        &mut approve_all(),
    ));
    let sig = ssh_key::Signature::new(ssh_key::Algorithm::new(&alg).unwrap(), sig).unwrap();
    let pk = ssh_key::PublicKey::from_bytes(&blob).unwrap();
    pk.key_data().verify(&data, &sig).unwrap();
}

#[test]
fn sign_rsa_from_legacy_pem() {
    let mut vault = Vault::default();
    let text = fixture("rsa_pkcs1_enc.pem");
    let info = parse_private_key(&text, Some("legacy-pass")).unwrap();
    let blob = parse_public_key(&info.public_openssh).unwrap().blob;
    vault.entries.push(Entry {
        blob: blob.clone(),
        comment: "old".into(),
        private: text,
        passphrase: Some("legacy-pass".into()),
    });
    let (alg, sig) = parse_sign_response(&Agent::new().handle(
        &sign_request(&blob, b"x", SSH_AGENT_RSA_SHA2_256),
        &vault,
        &mut approve_all(),
    ));
    assert_eq!(alg, "rsa-sha2-256");
    let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(rsa_public(&blob));
    vk.verify(
        b"x",
        &rsa::pkcs1v15::Signature::try_from(sig.as_slice()).unwrap(),
    )
    .unwrap();
}

#[test]
fn denied_and_unknown_keys_fail() {
    let mut vault = Vault::default();
    let blob = vault.add(
        &generate(KeyKind::Ed25519, "me").unwrap().private_openssh,
        None,
        "GitHub",
    );
    let agent = Agent::new();

    let mut asked = 0;
    let resp = agent.handle(
        &sign_request(&blob, b"data", 0),
        &vault,
        &mut |_: &SignRequest| {
            asked += 1;
            false
        },
    );
    assert_eq!(resp, [SSH_AGENT_FAILURE]);
    assert_eq!(asked, 1);

    // Unknown key: refused without asking the user.
    let other = parse_public_key(&generate(KeyKind::Ed25519, "x").unwrap().public_openssh)
        .unwrap()
        .blob;
    let mut asked = 0;
    let resp = agent.handle(
        &sign_request(&other, b"data", 0),
        &vault,
        &mut |_: &SignRequest| {
            asked += 1;
            true
        },
    );
    assert_eq!(resp, [SSH_AGENT_FAILURE]);
    assert_eq!(asked, 0);

    // The vault returns a different private key than the offered public key.
    let mut mismatched = Vault::default();
    mismatched.entries.push(Entry {
        blob: blob.clone(),
        comment: "lying".into(),
        private: generate(KeyKind::Ed25519, "other").unwrap().private_openssh,
        passphrase: None,
    });
    assert_eq!(
        agent.handle(
            &sign_request(&blob, b"data", 0),
            &mismatched,
            &mut approve_all()
        ),
        [SSH_AGENT_FAILURE]
    );
}

#[test]
fn unsupported_messages_fail() {
    let vault = Vault::default();
    let agent = Agent::new();
    for msg in [
        vec![],
        vec![17], // ADD_IDENTITY
        vec![18], // REMOVE_IDENTITY
        vec![19], // REMOVE_ALL_IDENTITIES
        vec![22], // LOCK
        vec![SSH_AGENTC_EXTENSION, 0, 0, 0, 4, b'q', b'u', b'e', b'r'],
        vec![SSH_AGENTC_REQUEST_IDENTITIES, 0], // trailing junk
        vec![SSH_AGENTC_SIGN_REQUEST],
        vec![SSH_AGENTC_SIGN_REQUEST, 0xff, 0xff, 0xff, 0xff],
    ] {
        assert_eq!(
            agent.handle(&msg, &vault, &mut approve_all()),
            [SSH_AGENT_FAILURE],
            "{msg:?}"
        );
    }
}

#[test]
fn purposes() {
    let mut data = b"SSHSIG".to_vec();
    put_string(&mut data, b"git");
    put_string(&mut data, b"");
    put_string(&mut data, b"sha512");
    put_string(&mut data, &[0; 64]);
    assert_eq!(
        parse_purpose(&data),
        SignPurpose::SshSig {
            namespace: "git".into()
        }
    );

    let host =
        parse_public_key(&generate(KeyKind::Ed25519, "host").unwrap().public_openssh).unwrap();
    let mut d = vec![];
    put_string(&mut d, &[1; 32]);
    d.push(50);
    put_string(&mut d, b"root");
    put_string(&mut d, b"ssh-connection");
    put_string(&mut d, b"publickey-hostbound-v00@openssh.com");
    d.push(1);
    put_string(&mut d, b"ssh-ed25519");
    put_string(&mut d, b"blob");
    put_string(&mut d, &host.blob);
    assert_eq!(
        parse_purpose(&d),
        SignPurpose::UserAuth {
            user: "root".into(),
            service: "ssh-connection".into(),
            method: "publickey-hostbound-v00@openssh.com".into(),
            host_key_fingerprint: Some(host.fingerprint),
        }
    );
    assert_eq!(parse_purpose(b"random"), SignPurpose::Unknown);
    assert_eq!(parse_purpose(b""), SignPurpose::Unknown);
}

#[test]
fn framing() {
    let body = [SSH_AGENTC_REQUEST_IDENTITIES];
    let framed = frame(&body);
    assert_eq!(framed, [0, 0, 0, 1, 11]);
    assert_eq!(deframe(&framed[..3]).unwrap(), None);
    assert_eq!(deframe(&framed[..4]).unwrap(), None);
    assert_eq!(deframe(&framed).unwrap(), Some((&body[..], 5)));

    let mut two = frame(&[1, 2, 3]);
    two.extend(frame(&[]));
    two.extend([0, 0]);
    let (a, n) = deframe(&two).unwrap().unwrap();
    assert_eq!((a, n), (&[1u8, 2, 3][..], 7));
    let (b, m) = deframe(&two[n..]).unwrap().unwrap();
    assert_eq!((b, m), (&[][..], 4));
    assert_eq!(deframe(&two[n + m..]).unwrap(), None);

    assert_eq!(
        deframe(&[0xff, 0xff, 0xff, 0xff]).unwrap_err(),
        FrameError::TooLong(u32::MAX as usize)
    );
    assert!(deframe(&frame(&vec![0; MAX_MESSAGE_LEN]))
        .unwrap()
        .is_some());
    assert!(deframe(&((MAX_MESSAGE_LEN + 1) as u32).to_be_bytes()).is_err());
}

#[test]
fn fuzz_never_panics() {
    let mut vault = Vault::default();
    let ed = vault.add(
        &generate(KeyKind::Ed25519, "fuzz").unwrap().private_openssh,
        None,
        "ed",
    );
    let rsa = vault.add(&fixture("rsa_openssh"), None, "rsa");
    let agent = Agent {
        allow_rsa_sha1: true,
    };
    let mut rng = StdRng::seed_from_u64(0x6e79_6170_6173_7377);

    let valid = [
        vec![SSH_AGENTC_REQUEST_IDENTITIES],
        sign_request(&ed, b"hello", 0),
        sign_request(&rsa, b"hello", SSH_AGENT_RSA_SHA2_256),
        sign_request(&ed, &userauth_data(&ed, "ssh-ed25519"), 0),
    ];

    for i in 0..20_000 {
        let msg: Vec<u8> = match i % 4 {
            // Pure noise with an interesting type byte.
            0 => {
                let len = rng.gen_range(0..64);
                let mut m: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
                if let Some(first) = m.first_mut() {
                    *first = [11, 13, 17, 27, rng.gen()][rng.gen_range(0..5)];
                }
                m
            }
            // Bit flips in a valid message.
            1 | 2 => {
                let mut m = valid[rng.gen_range(0..valid.len())].clone();
                for _ in 0..rng.gen_range(1..4) {
                    let at = rng.gen_range(0..m.len());
                    m[at] ^= 1 << rng.gen_range(0..8);
                }
                m
            }
            // Truncated / extended valid message.
            _ => {
                let mut m = valid[rng.gen_range(0..valid.len())].clone();
                if rng.gen_bool(0.5) {
                    m.truncate(rng.gen_range(0..m.len()));
                } else {
                    m.extend((0..rng.gen_range(1..16)).map(|_| rng.gen::<u8>()));
                }
                m
            }
        };
        let resp = agent.handle(&msg, &vault, &mut |_: &SignRequest| (i >> 2) & 1 == 0);
        assert!(matches!(
            resp.first(),
            Some(&SSH_AGENT_FAILURE | &SSH_AGENT_IDENTITIES_ANSWER | &SSH_AGENT_SIGN_RESPONSE)
        ));

        // The deframer on the same noise.
        let _ = deframe(&msg);
    }
}
