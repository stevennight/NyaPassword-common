//! Bitwarden / CSV importer tests. All fixtures are fake (example.com).

use std::io::Write;

use npw_import::{
    bitwarden, compare, detect, import, ImportError, ImportResult, ImportedItem, Mapping, Source,
};
use npw_model::{kind, Attachment, ItemContent};
use serde_json::{json, Value};

const JSON: &str = include_str!("fixtures/bitwarden_export.json");

fn bw(locale: &str) -> ImportResult {
    import(Source::BitwardenJson, JSON.as_bytes(), None, locale).expect("import")
}

fn item<'a>(r: &'a ImportResult, title: &str) -> &'a ImportedItem {
    r.items
        .iter()
        .find(|i| i.content.title == title)
        .unwrap_or_else(|| panic!("no item {title}"))
}

fn val(it: &ImportedItem, id: &str) -> String {
    it.content.field(id).map(|f| f.text()).unwrap_or_default()
}

fn other<'a>(it: &'a ImportedItem, label: &str) -> &'a npw_model::Field {
    it.content
        .fields
        .iter()
        .find(|f| f.label == label)
        .unwrap_or_else(|| panic!("no field {label}"))
}

/// What the vault would hold after writing and decrypting the items: the
/// content as JSON round trip, plus attachment records for the uploaded files.
fn stored(items: &[ImportedItem]) -> Vec<ItemContent> {
    items
        .iter()
        .map(|it| {
            let mut c: ItemContent =
                serde_json::from_slice(&npw_model::encode_item(&it.content)).unwrap();
            for a in &it.attachments {
                c.attachments.push(Attachment {
                    id: npw_model::new_short_id("a"),
                    name: a.name.clone(),
                    size: a.data.len() as u64,
                    mime: a.mime.clone(),
                    key: "k".into(),
                    blob_sha256: String::new(),
                    created_at: 0,
                    extra: Default::default(),
                });
            }
            c
        })
        .collect()
}

#[test]
fn json_report_counts() {
    let r = bw("en");
    let t = &r.report.by_template;
    assert_eq!(r.report.total, 12);
    assert_eq!(t["login"], 3);
    assert_eq!(t["secure_note"], 2);
    assert_eq!(t["credit_card"], 2);
    assert_eq!(t["identity"], 1);
    assert_eq!(t["document"], 3);
    assert_eq!(t["ssh_key"], 1);
    assert_eq!(r.report.passkeys, 2);
    assert_eq!(r.report.fallback, 1);
    assert_eq!(r.report.skipped.len(), 1);
    assert_eq!(r.report.skipped[0].title, "Trashed login");
    let _ = serde_json::to_string(&r).unwrap();
}

#[test]
fn login_full_mapping() {
    let r = bw("en");
    let it = item(&r, "Example Dev Portal");
    assert_eq!(it.mapping, Mapping::Full, "{:?}", it.warnings);
    assert!(it.warnings.is_empty());
    let c = &it.content;
    assert_eq!(c.template, "login");
    assert_eq!(val(it, "username"), "alice@example.com");
    assert_eq!(val(it, "password"), "Corr3ct-Horse-Battery-Staple!");
    assert_eq!(
        val(it, "otp"),
        "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
    );
    assert_eq!(c.field("otp").unwrap().kind, kind::TOTP);
    assert!(c.favorite);
    assert_eq!(c.tags, ["Work/Dev"]);
    assert_eq!(c.notes, "line one\nline two\n\n  indented line");
    assert_eq!(c.created_at, 1_673_778_600_123);
    assert_eq!(
        c.updated_at,
        npw_import::parse_rfc3339_ms("2024-07-01T12:00:00Z").unwrap()
    );

    let modes: Vec<(&str, &str)> = c
        .urls
        .iter()
        .map(|u| (u.url.as_str(), u.match_mode.as_str()))
        .collect();
    assert_eq!(
        modes,
        [
            ("https://dev.example.com/login", "domain"),
            ("https://example.com", "domain"),
            ("https://host.example.com:8443", "host"),
            ("https://example.com/start", "starts_with"),
            ("https://example.com/exact?x=1", "exact"),
            ("^https://.*\\.example\\.net/", "regex"),
            ("https://never.example.org", "never"),
            ("androidapp://com.example.app", "domain"),
        ]
    );

    let h: Vec<&str> = c
        .history
        .iter()
        .map(|h| h.value.as_str().unwrap())
        .collect();
    assert_eq!(h, ["old-pass-1", "old-pass-2"]);
    assert!(c
        .history
        .iter()
        .all(|h| h.field == "password" && h.until > 0));

    // Custom fields: one "Other fields" section, random IDs, kinds, multi-line intact.
    assert_eq!(c.sections.len(), 1);
    assert_eq!(c.sections[0].label, "Other fields");
    let rc = other(it, "Recovery codes");
    assert_eq!((rc.kind.as_str(), rc.multiline), (kind::CONCEALED, true));
    assert_eq!(rc.text(), "aaaa-bbbb\ncccc-dddd\neeee-ffff");
    assert!(rc.id.starts_with("f_"));
    assert_eq!(rc.section.as_deref(), Some(c.sections[0].id.as_str()));
    assert_eq!(other(it, "Account ID").kind, kind::TEXT);
    assert_eq!(other(it, "Address\nmulti").kind, kind::MULTILINE);
    assert_eq!(
        other(it, "Address\nmulti").text(),
        "1 Example Road\nSample City"
    );
    assert_eq!(
        (
            other(it, "Newsletter").kind.as_str(),
            other(it, "Newsletter").text().as_str()
        ),
        (kind::BOOLEAN, "true")
    );
    assert_eq!(other(it, "Beta").text(), "false");
    assert_eq!(other(it, "(unnamed field)").text(), "no name");

    let pk = &c.passkeys[0];
    assert_eq!(pk.credential_id, "ABEiM0RVZneImaq7zN3u_w");
    assert_eq!(pk.rp_id, "dev.example.com");
    assert_eq!(pk.user_handle, "dXNlci1oYW5kbGUtMDAwMQ");
    assert_eq!(
        (
            pk.user_name.as_str(),
            pk.user_display_name.as_str(),
            pk.rp_name.as_str()
        ),
        ("alice@example.com", "Alice Example", "Example Dev")
    );
    assert_eq!((pk.alg, pk.counter, pk.discoverable), (-7, 7, true));
    assert!(pk.private_key.starts_with("MIGHAgEAMBMGByqGSM49") && !pk.private_key.contains('='));
    assert_eq!(
        pk.created_at,
        npw_import::parse_rfc3339_ms("2024-02-02T02:02:02Z").unwrap()
    );
    let pk2 = &c.passkeys[1];
    assert_eq!(pk2.credential_id, "AQIDBAUGBwgJCgsMDQ4PEA");
    assert_eq!(
        pk2.private_key, "ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4CBgoM",
        "standard base64 normalised to base64url"
    );
    assert!(!pk2.discoverable);
    assert_eq!(
        pk2.created_at, c.created_at,
        "missing creationDate falls back to the item's"
    );
}

#[test]
fn linked_steam_reprompt() {
    let r = bw("zh-CN");
    let it = item(&r, "Linked & Steam");
    assert_eq!(it.mapping, Mapping::Partial);
    assert_eq!(it.warnings.len(), 2, "{:?}", it.warnings);
    assert_eq!(val(it, "otp"), "steam://JBSWY3DPEHPK3PXP");
    assert_eq!(other(it, "Pass alias").text(), "→ 密码");
    assert_eq!(it.content.sections[0].label, "其他字段");
}

#[test]
fn note_card_identity_ssh() {
    let r = bw("en");
    let note = item(&r, "Wi-Fi notes");
    assert_eq!(note.content.template, "secure_note");
    assert_eq!(
        note.content.notes, "SSID: example-net\r\nKey: not-a-real-key\r\n",
        "line endings kept"
    );
    assert_eq!(note.content.tags, ["Work"]);

    let card = item(&r, "Example Visa");
    assert_eq!(card.mapping, Mapping::Full);
    assert_eq!(val(card, "cardholder"), "Alice Example");
    assert_eq!(val(card, "number"), "4111111111111111");
    assert_eq!(val(card, "expiry"), "2029-03");
    assert_eq!(val(card, "cvv"), "123");
    assert_eq!(val(card, "card_type"), "Visa");
    assert_eq!(card.content.tags, ["个人/银行"]);

    let odd = item(&r, "Odd expiry card");
    assert_eq!(odd.mapping, Mapping::Partial);
    assert_eq!(other(odd, "Expiry (original)").text(), "13/soon");
    assert_eq!(val(odd, "expiry"), "");

    let id = item(&r, "Alice identity");
    assert_eq!(id.mapping, Mapping::Full);
    assert_eq!(val(id, "full_name"), "Ms Alice Q Example");
    assert_eq!(val(id, "phone"), "+1 555 0100");
    assert_eq!(val(id, "email"), "alice@example.com");
    assert_eq!(val(id, "company"), "Example Corp");
    assert_eq!(
        id.content.field("address").unwrap().value,
        json!({"country": "XX", "province": "Sample State", "city": "Sample City", "district": "", "street": "1 Example Road\nUnit 2", "postal_code": "00000"})
    );
    assert_eq!(other(id, "Username").text(), "alice-id");
    assert!(
        id.content.fields.iter().all(|f| f.text() != "X0000000"),
        "passport moved to a document"
    );
    let docs: Vec<&ImportedItem> = r
        .items
        .iter()
        .filter(|i| i.content.template == "document")
        .collect();
    let got: Vec<(String, String, String)> = docs
        .iter()
        .map(|d| (val(d, "doc_type"), val(d, "number"), val(d, "full_name")))
        .collect();
    assert_eq!(
        got,
        [
            (
                "SSN".into(),
                "000-00-0000".into(),
                "Ms Alice Q Example".into()
            ),
            (
                "Passport".into(),
                "X0000000".into(),
                "Ms Alice Q Example".into()
            ),
            (
                "Driver's license".into(),
                "D000-0000".into(),
                "Ms Alice Q Example".into()
            ),
        ]
    );
    assert_eq!(
        docs[1].source_id,
        "a0000000-0000-4000-8000-000000000006#passportNumber"
    );
    assert_eq!(docs[1].content.title, "Alice identity - Passport");

    let ssh = item(&r, "Deploy key");
    assert_eq!(ssh.content.template, "ssh_key");
    assert!(
        val(ssh, "private_key").starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n")
            && val(ssh, "private_key").ends_with("-----\n")
    );
    assert!(val(ssh, "public_key").starts_with("ssh-ed25519 "));
    assert_eq!(
        val(ssh, "fingerprint"),
        "SHA256:ZmFrZWZpbmdlcnByaW50Zm9ydGVzdHNvbmx5MDAwMDA"
    );
    assert_eq!(val(ssh, "key_type"), "Ed25519");
    assert!(ssh.content.ssh.is_some());
    assert_eq!(ssh.content.tags, ["Work/Dev"]);
}

#[test]
fn org_unknown_and_fallback() {
    let r = bw("en");
    let team = item(&r, "Team shared");
    assert_eq!(team.content.tags, ["Collections/Ops"]);
    assert_eq!(team.mapping, Mapping::Partial);
    assert_eq!(team.content.urls[0].match_mode, "domain");
    assert_eq!(other(team, "login.futureLoginKey").text(), "kept");
    assert_eq!(other(team, "futureTopLevel.nested").text(), "1");
    assert_eq!(team.warnings.len(), 3, "{:?}", team.warnings);

    let fut = item(&r, "From the future");
    assert_eq!(
        (fut.content.template.as_str(), fut.mapping),
        ("secure_note", Mapping::Fallback)
    );
    assert_eq!(fut.content.notes, "future notes");
    let acct = other(fut, "bankAccount.accountNumber");
    assert_eq!(
        (acct.kind.as_str(), acct.text().as_str()),
        (kind::CONCEALED, "000111222")
    );
    assert_eq!(other(fut, "bankAccount.bankName").text(), "Example Bank");
}

#[test]
fn compare_detects_loss() {
    let r = bw("en");
    let mut vault = stored(&r.items);
    assert_eq!(compare(&r.items, &vault), Vec::<String>::new());
    // Order does not matter.
    vault.reverse();
    assert!(compare(&r.items, &vault).is_empty());
    // Any lost value is reported.
    let i = vault
        .iter()
        .position(|c| c.title == "Example Dev Portal")
        .unwrap();
    vault[i].urls.pop();
    vault[i].passkeys.pop();
    vault[i].field_mut("password").unwrap().value = "changed".into();
    vault[i].history.clear();
    let problems = compare(&r.items, &vault);
    assert_eq!(problems.len(), 5, "{problems:#?}");
    assert!(
        problems.iter().all(|p| !p.contains("Corr3ct")),
        "no secret values in problems"
    );
    vault.remove(0);
    assert!(compare(&r.items, &vault)
        .iter()
        .any(|p| p.contains("item count")));
}

fn build_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, data) in files {
        w.start_file(*name, opts).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

#[test]
fn zip_with_attachments() {
    let big: Vec<u8> = (0..200_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let bytes = build_zip(&[
        ("data.json", JSON.as_bytes()),
        (
            "attachments/a0000000-0000-4000-8000-000000000001/recovery.txt",
            b"codes\n",
        ),
        (
            "attachments/a0000000-0000-4000-8000-000000000001/scan.pdf",
            &big,
        ),
        (
            "attachments/Deploy key/id_ed25519.pub",
            b"ssh-ed25519 AAAA fake",
        ),
        (
            "attachments/ffffffff-0000-4000-8000-000000000000/lost.bin",
            b"\x00\x01",
        ),
    ]);
    assert_eq!(
        detect("bitwarden_export_20240101.zip", &bytes),
        Some(Source::BitwardenZip)
    );
    let r = import(Source::BitwardenZip, &bytes, None, "en").unwrap();
    let login = item(&r, "Example Dev Portal");
    let names: Vec<(&str, &str, usize)> = login
        .attachments
        .iter()
        .map(|a| (a.name.as_str(), a.mime.as_str(), a.data.len()))
        .collect();
    assert_eq!(
        names,
        [
            ("recovery.txt", "text/plain", 6),
            ("scan.pdf", "application/pdf", 200_000)
        ]
    );
    assert_eq!(login.attachments[1].data, big);
    assert_eq!(
        item(&r, "Deploy key").attachments[0].name,
        "id_ed25519.pub",
        "matched by unique item name"
    );
    let orphans = item(&r, "Bitwarden unassigned attachments");
    assert_eq!(orphans.attachments[0].name, "lost.bin");
    assert_eq!(
        other(orphans, "Original path").text(),
        "attachments/ffffffff-0000-4000-8000-000000000000/lost.bin"
    );
    assert_eq!(r.report.attachments, 4);
    assert_eq!(r.report.attachment_bytes, 6 + 200_000 + 21 + 2);
    assert!(compare(&r.items, &stored(&r.items)).is_empty());
    assert!(matches!(
        import(
            Source::BitwardenZip,
            &build_zip(&[("x.txt", b"x")]),
            None,
            "en"
        ),
        Err(ImportError::Format(_))
    ));
}

// ───────────────────── password-protected export (encryption side) ─────────────────────

mod enc {
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use hmac::Mac;
    use rand::RngCore;
    use serde_json::{json, Value};
    use sha2::Digest;

    pub enum Kdf {
        Pbkdf2(u32),
        Argon2id {
            iterations: u32,
            memory_mib: u32,
            parallelism: u32,
        },
    }

    /// Independent implementation of Bitwarden's `makePinKey` + `stretchKey`.
    fn keys(password: &str, salt: &str, kdf: &Kdf) -> ([u8; 32], [u8; 32]) {
        let mut master = [0u8; 32];
        match kdf {
            Kdf::Pbkdf2(it) => pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
                password.as_bytes(),
                salt.as_bytes(),
                *it,
                &mut master,
            ),
            Kdf::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => {
                let params =
                    argon2::Params::new(memory_mib * 1024, *iterations, *parallelism, Some(32))
                        .unwrap();
                argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                    .hash_password_into(
                        password.as_bytes(),
                        &sha2::Sha256::digest(salt.as_bytes()),
                        &mut master,
                    )
                    .unwrap();
            }
        }
        let hk = hkdf::Hkdf::<sha2::Sha256>::from_prk(&master).unwrap();
        let (mut e, mut m) = ([0u8; 32], [0u8; 32]);
        hk.expand(b"enc", &mut e).unwrap();
        hk.expand(b"mac", &mut m).unwrap();
        (e, m)
    }

    fn enc_string(plain: &[u8], enc: &[u8; 32], mac: &[u8; 32]) -> String {
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);
        let ct = cbc::Encryptor::<aes::Aes256>::new(enc.into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(plain);
        let mut h = <hmac::Hmac<sha2::Sha256> as Mac>::new_from_slice(mac).unwrap();
        h.update(&iv);
        h.update(&ct);
        let tag = h.finalize().into_bytes();
        format!(
            "2.{}|{}|{}",
            STANDARD.encode(iv),
            STANDARD.encode(ct),
            STANDARD.encode(tag)
        )
    }

    pub fn export(plain_json: &str, password: &str, kdf: Kdf) -> String {
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        let salt = STANDARD.encode(salt);
        let (e, m) = keys(password, &salt, &kdf);
        let (kdf_type, iterations, memory, parallelism) = match kdf {
            Kdf::Pbkdf2(i) => (0, i, Value::Null, Value::Null),
            Kdf::Argon2id {
                iterations,
                memory_mib,
                parallelism,
            } => (1, iterations, json!(memory_mib), json!(parallelism)),
        };
        json!({
            "encrypted": true,
            "passwordProtected": true,
            "salt": salt,
            "kdfType": kdf_type,
            "kdfIterations": iterations,
            "kdfMemory": memory,
            "kdfParallelism": parallelism,
            "encKeyValidation_DO_NOT_EDIT": enc_string(uuid::Uuid::new_v4().to_string().as_bytes(), &e, &m),
            "data": enc_string(plain_json.as_bytes(), &e, &m),
        })
        .to_string()
    }
}

/// Title, template, sorted (label, value) pairs, URL count, passkey count.
type Summary = (String, String, Vec<(String, String)>, usize, usize);

/// What two imports of the same data share (IDs of "Other fields" are random per import).
fn summary(r: &ImportResult) -> Vec<Summary> {
    r.items
        .iter()
        .map(|i| {
            let mut f: Vec<(String, String)> = i
                .content
                .fields
                .iter()
                .map(|f| (f.label.clone(), f.text()))
                .collect();
            f.sort();
            (
                i.content.title.clone(),
                i.content.template.clone(),
                f,
                i.content.urls.len(),
                i.content.passkeys.len(),
            )
        })
        .collect()
}

#[test]
fn encrypted_round_trip() {
    let plain = bw("en");
    for kdf in [
        enc::Kdf::Pbkdf2(5_000),
        enc::Kdf::Argon2id {
            iterations: 2,
            memory_mib: 8,
            parallelism: 2,
        },
    ] {
        let file = enc::export(JSON, "correct horse 电池", kdf);
        assert_eq!(
            detect("export.json", file.as_bytes()),
            Some(Source::BitwardenEncryptedJson)
        );
        let r = import(
            Source::BitwardenEncryptedJson,
            file.as_bytes(),
            Some("correct horse 电池"),
            "en",
        )
        .unwrap();
        assert_eq!(summary(&r), summary(&plain));
        assert!(matches!(
            import(
                Source::BitwardenEncryptedJson,
                file.as_bytes(),
                Some("wrong"),
                "en"
            ),
            Err(ImportError::WrongPassword)
        ));
        assert!(matches!(
            import(Source::BitwardenEncryptedJson, file.as_bytes(), None, "en"),
            Err(ImportError::NeedPassword)
        ));
        // The zip may carry a password-protected data.json too.
        let z = build_zip(&[("data.json", file.as_bytes())]);
        assert_eq!(
            import(Source::BitwardenZip, &z, Some("correct horse 电池"), "en")
                .unwrap()
                .items
                .len(),
            plain.items.len()
        );
    }
    // Tampered ciphertext fails the MAC (reported as damage, not as a wrong password).
    let file = enc::export(JSON, "pw", enc::Kdf::Pbkdf2(1_000));
    let mut doc: Value = serde_json::from_str(&file).unwrap();
    let data = doc["data"].as_str().unwrap().to_string();
    let (head, tail) = data.split_once('|').unwrap();
    let mut ct: Vec<char> = tail.chars().collect();
    ct[3] = if ct[3] == 'A' { 'B' } else { 'A' };
    doc["data"] = Value::String(format!("{head}|{}", ct.into_iter().collect::<String>()));
    assert!(matches!(
        bitwarden::decrypt_export(&doc, Some("pw")),
        Err(ImportError::Format(_))
    ));
    // Account-key encrypted exports cannot be read.
    let acct = json!({"encrypted": true, "encKeyValidation_DO_NOT_EDIT": "2.a|b|c", "data": "2.a|b|c", "items": []});
    assert!(matches!(
        import(
            Source::BitwardenEncryptedJson,
            acct.to_string().as_bytes(),
            Some("pw"),
            "en"
        ),
        Err(ImportError::Unsupported(_))
    ));
}

// ───────────────────── CSV ─────────────────────

#[test]
fn bitwarden_csv() {
    let bytes = include_bytes!("fixtures/bitwarden_export.csv");
    assert_eq!(detect("bitwarden.csv", bytes), Some(Source::BitwardenCsv));
    let r = import(Source::BitwardenCsv, bytes, None, "en").unwrap();
    assert_eq!(r.items.len(), 3);
    let m = &r.items[0];
    assert_eq!(
        (m.content.title.as_str(), m.content.favorite),
        ("Example Mail", true)
    );
    assert_eq!(m.content.tags, ["Work/Dev"]);
    assert_eq!(m.content.notes, "note line 1\nnote line 2");
    assert_eq!(val(m, "otp"), "JBSWY3DPEHPK3PXP");
    let urls: Vec<&str> = m.content.urls.iter().map(|u| u.url.as_str()).collect();
    assert_eq!(
        urls,
        ["https://mail.example.com", "androidapp://com.example.mail"]
    );
    assert_eq!(other(m, "Account ID").text(), "ACC-1");
    assert_eq!(other(m, "Recovery").text(), "line a\nline b");
    assert_eq!(r.items[1].content.template, "secure_note");
    assert_eq!(r.items[1].warnings.len(), 1, "reprompt");
    assert_eq!(r.items[2].content.title, "(untitled)");
    assert!(compare(&r.items, &stored(&r.items)).is_empty());
}

#[test]
fn chrome_and_generic_csv() {
    let bytes = include_bytes!("fixtures/chrome_passwords.csv");
    assert_eq!(
        detect("Chrome Passwords.csv", bytes),
        Some(Source::ChromeCsv)
    );
    let r = import(Source::ChromeCsv, bytes, None, "en").unwrap();
    assert_eq!(r.items.len(), 3, "empty row ignored");
    let a = &r.items[0];
    assert_eq!(a.content.title, "example.com");
    assert_eq!(val(a, "password"), "pa,ss\"word");
    assert_eq!(a.content.notes, "multi\r\nline note", "quoted CRLF kept");
    assert_eq!(a.mapping, Mapping::Full);
    assert_eq!(
        r.items[1].content.title, "shop.example.net",
        "title from URL host"
    );
    assert_eq!(r.items[2].content.template, "secure_note");
    assert_eq!(r.items[2].content.notes, "secret recipe");

    let ff = include_bytes!("fixtures/firefox_passwords.csv");
    assert_eq!(detect("logins.csv", ff), Some(Source::ChromeCsv));
    let r = import(Source::ChromeCsv, ff, None, "en").unwrap();
    let c = &r.items[0];
    assert_eq!(
        (c.content.title.as_str(), val(c, "username").as_str()),
        ("login.example.com", "carol")
    );
    assert_eq!(c.content.created_at, 1_700_000_000_000);
    assert_eq!(c.content.updated_at, 1_700_000_400_000);
    assert_eq!(c.mapping, Mapping::Partial);
    assert_eq!(
        other(c, "guid").text(),
        "{00000000-0000-4000-8000-000000000001}"
    );
    assert!(compare(&r.items, &stored(&r.items)).is_empty());

    assert!(matches!(
        import(Source::ChromeCsv, b"a,b,c\n1,2,3\n", None, "en"),
        Err(ImportError::Format(_))
    ));
}

#[test]
fn detection() {
    assert_eq!(
        detect("x.json", JSON.as_bytes()),
        Some(Source::BitwardenJson)
    );
    let bom: Vec<u8> = [b"\xEF\xBB\xBF".as_slice(), JSON.as_bytes()].concat();
    assert_eq!(detect("x.json", &bom), Some(Source::BitwardenJson));
    assert_eq!(
        detect(
            "x.kdbx",
            &[0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5, 0, 0]
        ),
        Some(Source::KeepassKdbx)
    );
    assert_eq!(
        detect("x.1pux", &build_zip(&[("export.data", b"{}")])),
        Some(Source::OnePasswordPux)
    );
    assert_eq!(
        detect(
            "x.csv",
            b"\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\"\n"
        ),
        Some(Source::KeepassCsv)
    );
    assert_eq!(
        detect(
            "x.csv",
            b"Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n"
        ),
        Some(Source::OnePasswordCsv)
    );
    assert_eq!(detect("x.txt", b"hello world"), None);
    assert_eq!(detect("x.bin", &[0xff, 0xfe, 0x00]), None);
    assert_eq!(detect("x.json", b"{\"a\": 1}"), None);
}
