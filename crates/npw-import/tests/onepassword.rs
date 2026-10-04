//! 1Password importer tests: a fake `.1pux` built in the test, the CSV fixture,
//! and garbage / truncated input.

use std::io::{Cursor, Write};

use npw_import::onepassword::{import_csv, import_pux};
use npw_import::{ImportError, ImportedItem, Mapping};
use npw_model::{kind, match_mode};
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde_json::{json, Value};

const LOGIN_UUID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaa";

fn export_data() -> Value {
    let personal = json!([
        {
            "uuid": LOGIN_UUID,
            "favIndex": 1,
            "createdAt": 1_600_000_000,
            "updatedAt": 1_700_000_000,
            "state": "active",
            "categoryUuid": "001",
            "details": {
                "loginFields": [
                    {"value": "alice@example.com", "id": "", "name": "email", "fieldType": "E", "designation": "username"},
                    {"value": "fake-password", "id": "", "name": "password", "fieldType": "P", "designation": "password"},
                    {"value": "remember", "id": "", "name": "remember_me", "fieldType": "C"}
                ],
                "notesPlain": "login notes",
                "sections": [
                    {"title": "Security", "name": "security", "fields": [
                        {"title": "one-time password", "id": "TOTP_x1", "value": {"totp": "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP"}},
                        {"title": "Recovery codes", "id": "rc", "value": {"concealed": "code-1\ncode-2"}},
                        {"title": "Hologram", "id": "holo", "value": {"hologram": "shiny"}},
                        {"title": "Empty", "id": "empty", "value": {"string": ""}}
                    ]}
                ],
                "passwordHistory": [{"value": "older-password", "time": 1_650_000_000}],
                "htmlForm": {"htmlAction": "https://example.com/login"}
            },
            "overview": {
                "title": "Example Login",
                "url": "https://example.com/login",
                "urls": [
                    {"label": "website", "url": "https://example.com/login", "mode": "default"},
                    {"label": "", "url": "https://admin.example.com", "mode": "never"},
                    {"label": "", "url": "https://exact.example.com", "mode": "exact"}
                ],
                "tags": ["Work/Dev"]
            }
        },
        {
            "uuid": "bbbbbbbbbbbbbbbbbbbbbbbbbb",
            "state": "archived",
            "categoryUuid": "002",
            "details": {"sections": [
                {"title": "", "name": "", "fields": [
                    {"title": "cardholder name", "id": "cardholder", "value": {"string": "Alice Example"}},
                    {"title": "type", "id": "type", "value": {"creditCardType": "visa"}},
                    {"title": "number", "id": "ccnum", "value": {"creditCardNumber": "4111111111111111"}},
                    {"title": "verification number", "id": "cvv", "value": {"concealed": "123"}},
                    {"title": "expiry date", "id": "expiry", "value": {"monthYear": 202_612}},
                    {"title": "valid from", "id": "validFrom", "value": {"monthYear": 202_001}}
                ]},
                {"title": "Contact Information", "name": "contactInfo", "fields": [
                    {"title": "issuing bank", "id": "bank", "value": {"string": "Example Bank"}},
                    {"title": "phone (intl)", "id": "phoneIntl", "value": {"phone": "+1 555 0100"}}
                ]}
            ]},
            "overview": {"title": "Example Card"}
        },
        {
            "uuid": "cccccccccccccccccccccccccc",
            "categoryUuid": "004",
            "details": {"sections": [
                {"title": "Identification", "name": "name", "fields": [
                    {"title": "first name", "id": "firstname", "value": {"string": "Jane"}},
                    {"title": "last name", "id": "lastname", "value": {"string": "Doe"}},
                    {"title": "birth date", "id": "birthdate", "value": {"date": 946_684_800}},
                    {"title": "occupation", "id": "occupation", "value": {"string": "Tester"}}
                ]},
                {"title": "Address", "name": "address", "fields": [
                    {"title": "address", "id": "address", "value": {"address": {"street": "1 Example St", "city": "Example City", "state": "EX", "zip": "00000", "country": "us"}}},
                    {"title": "default phone", "id": "defphone", "value": {"phone": "555-0100"}}
                ]},
                {"title": "Internet Details", "name": "internet", "fields": [
                    {"title": "email", "id": "email", "value": {"email": {"email_address": "jane@example.com", "provider": null}}},
                    {"title": "website", "id": "website", "value": {"url": "https://jane.example.com"}}
                ]}
            ]},
            "overview": {"title": "Jane Doe"}
        },
        {
            "uuid": "dddddddddddddddddddddddddd",
            "categoryUuid": "106",
            "details": {"sections": [{"title": "", "name": "", "fields": [
                {"title": "number", "id": "number", "value": {"string": "X1234567"}},
                {"title": "full name", "id": "fullname", "value": {"string": "Jane Doe"}},
                {"title": "issuing authority", "id": "issuing_authority", "value": {"string": "Example Office"}},
                {"title": "expiry date", "id": "expiry_date", "value": {"date": 1_893_456_000}},
                {"title": "nationality", "id": "nationality", "value": {"string": "Exampleland"}}
            ]}]},
            "overview": {"title": "Passport"}
        },
        {
            "uuid": "eeeeeeeeeeeeeeeeeeeeeeeeee",
            "categoryUuid": "114",
            "details": {"sections": [{"title": "", "name": "", "fields": [
                {"title": "private key", "id": "private_key", "value": {"sshKey": {
                    "privateKey": "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n",
                    "metadata": {
                        "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZQ==\n-----END OPENSSH PRIVATE KEY-----\n",
                        "publicKey": "ssh-ed25519 AAAAfake test@example.com",
                        "fingerprint": "SHA256:fakefingerprint",
                        "keyType": "ed25519"
                    }
                }}}
            ]}]},
            "overview": {"title": "Deploy key"}
        },
        {
            "uuid": "ffffffffffffffffffffffffff",
            "categoryUuid": "006",
            "details": {"documentAttributes": {"fileName": "scan.pdf", "documentId": "doc1", "decryptedSize": 9}},
            "overview": {"title": "Scanned document"}
        }
    ]);
    let shared = json!([
        {
            "uuid": "gggggggggggggggggggggggggg",
            "categoryUuid": "003",
            "details": {
                "notesPlain": "a note",
                "sections": [{"title": "Linked", "name": "linked items", "fields": [
                    {"title": "manual", "id": "f1", "value": {"file": {"fileName": "manual.txt", "documentId": "doc2", "decryptedSize": 5}}},
                    {"title": "login", "id": "f2", "value": {"reference": LOGIN_UUID}},
                    {"title": "gone", "id": "f3", "value": {"reference": "zzzzzzzzzzzzzzzzzzzzzzzzzz"}}
                ]}]
            },
            "overview": {"title": "Note with files"}
        },
        {
            "uuid": "hhhhhhhhhhhhhhhhhhhhhhhhhh",
            "categoryUuid": "999",
            "details": {"sections": [{"title": "Data", "name": "data", "fields": [
                {"title": "thing", "id": "t", "value": {"string": "value"}}
            ]}]},
            "overview": {"title": "Future category"}
        },
        {
            "uuid": "iiiiiiiiiiiiiiiiiiiiiiiiii",
            "categoryUuid": "005",
            "details": {"password": "standalone-pass"},
            "overview": {"title": "Just a password"}
        },
        {
            "uuid": "jjjjjjjjjjjjjjjjjjjjjjjjjj",
            "categoryUuid": "105",
            "details": {"sections": [{"title": "", "name": "", "fields": [
                {"title": "member name", "id": "member_name", "value": {"string": "Alice"}},
                {"title": "member ID", "id": "membership_no", "value": {"string": "M-1"}}
            ]}]},
            "overview": {"title": "Gym"}
        }
    ]);
    json!({
        "accounts": [{
            "attrs": {"accountName": "Example", "name": "Alice", "email": "alice@example.com", "uuid": "acc", "domain": "https://example.1password.com/"},
            "vaults": [
                {"attrs": {"uuid": "v1", "name": "Personal", "type": "P"}, "items": personal},
                {"attrs": {"uuid": "v2", "name": "Shared", "type": "U"}, "items": shared}
            ]
        }]
    })
}

fn build_pux() -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    w.start_file("export.attributes", opts).unwrap();
    w.write_all(
        br#"{"version":3,"description":"1Password Unencrypted Export","createdAt":1700000000}"#,
    )
    .unwrap();
    w.start_file("export.data", opts).unwrap();
    w.write_all(serde_json::to_string(&export_data()).unwrap().as_bytes())
        .unwrap();
    w.add_directory("files/", opts).unwrap();
    w.start_file("files/doc1__scan.pdf", opts).unwrap();
    w.write_all(b"%PDF-fake").unwrap();
    w.start_file("files/doc2__manual.txt", opts).unwrap();
    w.write_all(b"hello").unwrap();
    w.finish().unwrap().into_inner()
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

fn section_label(it: &ImportedItem, f: &npw_model::Field) -> String {
    let id = f.section.as_deref().unwrap();
    it.content
        .sections
        .iter()
        .find(|s| s.id == id)
        .unwrap()
        .label
        .clone()
}

#[test]
fn pux_maps_categories_fields_and_files() {
    let r = import_pux(&build_pux(), "en").unwrap();
    assert_eq!(r.items.len(), 10);
    assert!(r.report.skipped.is_empty());

    // Login.
    let login = by_title(&r.items, "Example Login");
    let c = &login.content;
    assert_eq!(c.template, "login");
    assert_eq!(login.source_id, LOGIN_UUID);
    assert!(c.favorite && !c.archived);
    assert_eq!(c.tags, vec!["Work/Dev".to_string(), "Personal".to_string()]);
    assert_eq!(c.created_at, 1_600_000_000_000);
    assert_eq!(c.updated_at, 1_700_000_000_000);
    assert_eq!(c.notes, "login notes");
    assert_eq!(c.field("username").unwrap().text(), "alice@example.com");
    assert_eq!(c.field("password").unwrap().text(), "fake-password");
    assert_eq!(
        c.field("otp").unwrap().text(),
        "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP"
    );
    let urls: Vec<(&str, &str)> = c
        .urls
        .iter()
        .map(|u| (u.url.as_str(), u.match_mode.as_str()))
        .collect();
    assert_eq!(
        urls,
        vec![
            ("https://example.com/login", match_mode::DOMAIN),
            ("https://admin.example.com", match_mode::NEVER),
            ("https://exact.example.com", match_mode::HOST)
        ]
    );
    let rc = field_by_label(login, "Recovery codes");
    assert_eq!(rc.kind, kind::CONCEALED);
    assert!(rc.multiline);
    assert_eq!(section_label(login, rc), "Security");
    assert!(c.sections.iter().any(|s| s.id == "s_1p_security"));
    let holo = field_by_label(login, "Hologram");
    assert_eq!(
        (holo.kind.as_str(), holo.text().as_str()),
        (kind::TEXT, "shiny")
    );
    assert!(login.warnings.iter().any(|w| w.contains("hologram")));
    assert_eq!(login.mapping, Mapping::Partial);
    assert!(!c.fields.iter().any(|f| f.label == "Empty"));
    assert_eq!(field_by_label(login, "remember_me").text(), "remember");
    assert_eq!(c.history.len(), 1);
    assert_eq!(
        (
            c.history[0].field.as_str(),
            c.history[0].value.as_str().unwrap(),
            c.history[0].until
        ),
        ("password", "older-password", 1_650_000_000_000)
    );

    // Credit card, archived.
    let card = by_title(&r.items, "Example Card");
    let c = &card.content;
    assert_eq!(c.template, "credit_card");
    assert!(c.archived);
    assert_eq!(c.field("cardholder").unwrap().text(), "Alice Example");
    assert_eq!(c.field("number").unwrap().text(), "4111111111111111");
    assert_eq!(c.field("cvv").unwrap().text(), "123");
    assert_eq!(c.field("expiry").unwrap().text(), "2026-12");
    assert_eq!(c.field("card_type").unwrap().text(), "visa");
    assert_eq!(c.field("bank").unwrap().text(), "Example Bank");
    let vf = field_by_label(card, "valid from");
    assert_eq!(
        (vf.kind.as_str(), vf.text().as_str()),
        (kind::MONTH_YEAR, "2020-01")
    );
    assert_eq!(section_label(card, vf), "Other fields");
    let ph = field_by_label(card, "phone (intl)");
    assert_eq!(ph.kind, kind::PHONE);
    assert_eq!(section_label(card, ph), "Contact Information");
    assert_eq!(card.mapping, Mapping::Full);

    // Identity.
    let id = by_title(&r.items, "Jane Doe");
    let c = &id.content;
    assert_eq!(c.template, "identity");
    assert_eq!(c.field("full_name").unwrap().text(), "Jane Doe");
    assert_eq!(c.field("birthday").unwrap().text(), "2000-01-01");
    assert_eq!(c.field("email").unwrap().text(), "jane@example.com");
    assert_eq!(c.field("phone").unwrap().text(), "555-0100");
    let addr = &c.field("address").unwrap().value;
    assert_eq!(addr["street"], "1 Example St");
    assert_eq!(addr["province"], "EX");
    assert_eq!(addr["postal_code"], "00000");
    assert_eq!(addr["country"], "us");
    assert_eq!(field_by_label(id, "occupation").text(), "Tester");
    assert_eq!(field_by_label(id, "website").kind, kind::URL);

    // Passport → ID document.
    let pp = by_title(&r.items, "Passport");
    let c = &pp.content;
    assert_eq!(c.template, "document");
    assert_eq!(c.field("doc_type").unwrap().text(), "Passport");
    assert_eq!(c.field("number").unwrap().text(), "X1234567");
    assert_eq!(c.field("issuer").unwrap().text(), "Example Office");
    assert_eq!(c.field("expires_on").unwrap().text(), "2030-01-01");
    assert_eq!(field_by_label(pp, "nationality").text(), "Exampleland");
    assert_eq!(pp.mapping, Mapping::Full);

    // SSH key.
    let ssh = by_title(&r.items, "Deploy key");
    let c = &ssh.content;
    assert_eq!(c.template, "ssh_key");
    assert!(c
        .field("private_key")
        .unwrap()
        .text()
        .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    assert_eq!(
        c.field("public_key").unwrap().text(),
        "ssh-ed25519 AAAAfake test@example.com"
    );
    assert_eq!(
        c.field("fingerprint").unwrap().text(),
        "SHA256:fakefingerprint"
    );
    assert_eq!(c.field("key_type").unwrap().text(), "ed25519");

    // Document category → note with its file.
    let docu = by_title(&r.items, "Scanned document");
    assert_eq!(docu.content.template, "secure_note");
    assert_eq!(docu.attachments.len(), 1);
    assert_eq!(docu.attachments[0].name, "scan.pdf");
    assert_eq!(docu.attachments[0].mime, "application/pdf");
    assert_eq!(docu.attachments[0].data, b"%PDF-fake");

    // File field and references.
    let note = by_title(&r.items, "Note with files");
    assert_eq!(note.content.tags, vec!["Shared".to_string()]);
    assert_eq!(note.attachments.len(), 1);
    assert_eq!(note.attachments[0].data, b"hello");
    let rf = field_by_label(note, "login");
    assert_eq!(
        (rf.kind.as_str(), rf.text().as_str()),
        (kind::REFERENCE, LOGIN_UUID)
    );
    assert_eq!(section_label(note, rf), "Linked");
    assert!(note
        .warnings
        .iter()
        .any(|w| w.contains("gone") && w.contains("not in this export")));

    // Unknown category → fallback secure note keeping its data.
    let fut = by_title(&r.items, "Future category");
    assert_eq!(fut.content.template, "secure_note");
    assert_eq!(fut.mapping, Mapping::Fallback);
    assert_eq!(field_by_label(fut, "thing").text(), "value");

    // Password category.
    let pw = by_title(&r.items, "Just a password");
    assert_eq!(pw.content.template, "password");
    assert_eq!(
        pw.content.field("password").unwrap().text(),
        "standalone-pass"
    );

    // Approximate category.
    let gym = by_title(&r.items, "Gym");
    assert_eq!(gym.content.template, "document");
    assert_eq!(gym.mapping, Mapping::Partial);
    assert_eq!(gym.content.field("number").unwrap().text(), "M-1");

    assert_eq!(r.report.total, 10);
    assert_eq!(r.report.fallback, 1);
    assert_eq!(r.report.attachments, 2);
    assert_eq!(r.report.by_template.get("document"), Some(&2));
}

#[test]
fn pux_chinese_labels() {
    let r = import_pux(&build_pux(), "zh-CN").unwrap();
    let pp = by_title(&r.items, "Passport");
    assert_eq!(pp.content.field("doc_type").unwrap().text(), "护照");
    let card = by_title(&r.items, "Example Card");
    assert_eq!(
        section_label(card, field_by_label(card, "valid from")),
        "其他字段"
    );
}

#[test]
fn pux_rejects_other_zips_and_json() {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    w.start_file("data.json", zip::write::SimpleFileOptions::default())
        .unwrap();
    w.write_all(b"{}").unwrap();
    let z = w.finish().unwrap().into_inner();
    assert!(matches!(import_pux(&z, "en"), Err(ImportError::Format(_))));

    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    w.start_file("export.data", zip::write::SimpleFileOptions::default())
        .unwrap();
    w.write_all(b"{\"accounts\": 5").unwrap();
    let z = w.finish().unwrap().into_inner();
    assert!(matches!(import_pux(&z, "en"), Err(ImportError::Format(_))));
}

#[test]
fn csv_export() {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/onepassword/export.csv"
    ))
    .unwrap();
    let r = import_csv(&bytes, "en").unwrap();
    assert_eq!(r.items.len(), 3);

    let mail = by_title(&r.items, "Example Mail");
    let c = &mail.content;
    assert_eq!(c.template, "login");
    assert_eq!(c.username().as_deref(), Some("alice@example.com"));
    assert_eq!(c.password().as_deref(), Some("fake-pass-1"));
    assert_eq!(
        c.totp().as_deref(),
        Some("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP")
    );
    assert_eq!(c.urls[0].url, "https://mail.example.com");
    assert!(c.favorite && !c.archived);
    assert_eq!(c.tags, vec!["Work".to_string(), "Mail".to_string()]);
    assert_eq!(c.notes, "line 1\nline 2");
    assert_eq!(mail.mapping, Mapping::Full);

    let forum = by_title(&r.items, "Old Forum");
    assert!(forum.content.archived);
    let q = field_by_label(forum, "Security Question");
    assert_eq!(q.text(), "blue");
    assert_eq!(forum.mapping, Mapping::Partial);

    let note = by_title(&r.items, "Shopping List");
    assert_eq!(note.content.template, "secure_note");
    assert_eq!(note.content.notes, "milk, eggs");
}

#[test]
fn csv_rejects_unrelated() {
    assert!(matches!(
        import_csv(b"a,b,c\n1,2,3\n", "en"),
        Err(ImportError::Format(_))
    ));
    assert!(matches!(
        import_csv(&[0xff, 0xfe, 0x00, 0x41], "en"),
        Err(ImportError::Format(_))
    ));
}

#[test]
fn garbage_and_truncated_input_never_panics() {
    let mut rng = StdRng::seed_from_u64(0x1a55_70ad);
    let pux = build_pux();
    let csv = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/onepassword/export.csv"
    ))
    .unwrap();

    for i in 0..3000 {
        let len = rng.gen_range(0..2048);
        let mut junk: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
        if i % 3 == 0 && junk.len() >= 4 {
            junk[..4].copy_from_slice(b"PK\x03\x04");
        }
        assert!(
            import_pux(&junk, "en").is_err(),
            "garbage accepted as .1pux"
        );
        // Printable junk with CSV punctuation.
        const CHARS: &[u8] = b"abcXYZ019 ,;\"'\n\r\t";
        let text: Vec<u8> = (0..len)
            .map(|_| CHARS[rng.gen_range(0..CHARS.len())])
            .collect();
        assert!(
            import_csv(&text, "en").is_err(),
            "garbage accepted as 1Password CSV"
        );
        assert!(import_csv(&junk, "en").is_err());
    }
    for _ in 0..1000 {
        let cut = rng.gen_range(0..pux.len());
        let _ = import_pux(&pux[..cut], "en");
        let mut flipped = pux.clone();
        for _ in 0..rng.gen_range(1..8) {
            let at = rng.gen_range(0..flipped.len());
            flipped[at] ^= rng.gen_range(1..=255u8);
        }
        let _ = import_pux(&flipped, "en");
        let cut = rng.gen_range(0..csv.len());
        let _ = import_csv(&csv[..cut], "en");
    }
}
