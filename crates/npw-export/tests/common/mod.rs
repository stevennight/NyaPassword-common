//! Fake data for the export tests (example.com only).
#![allow(dead_code)]

use npw_export::{ExportItem, ExportVault};
use npw_model::{
    kind, purpose, templates, Attachment, Field, HistoryEntry, ItemContent, Passkey, Section,
    UrlEntry,
};
use serde_json::{json, Map, Value};

pub const LOGIN_TITLE: &str = "Example 登录";
pub const PASSWORD: &str = "p@ss wörd 中文 \"quoted\", comma";
pub const OLD_PASSWORDS: [&str; 2] = ["oldest-密码-1", "older-密码-2"];
pub const RECOVERY: &str = "code-1111\ncode-2222\r\ncode-3333\n";
pub const NOTES: &str = "第一行\n second line, with comma\n\"quoted\"";
pub const TOTP_SECRET: &str = "JBSW Y3DP EHPK 3PXP";
pub const BIG: usize = 2 * 1024 * 1024 + 123;

/// Fake PKCS#8 DER bytes (not a real key; the exporters do not parse it).
pub fn fake_pkcs8(seed: u8) -> Vec<u8> {
    let mut v = vec![0x30, 0x81, 0x87, 0x02, 0x01, 0x00];
    v.extend((0..132u8).map(|i| i.wrapping_mul(7).wrapping_add(seed)));
    v
}

pub fn b64url(d: &[u8]) -> String {
    npw_crypto::b64(d)
}

fn attachment(id: &str, name: &str, data: &[u8], mime: &str) -> Attachment {
    Attachment {
        id: id.into(),
        name: name.into(),
        size: data.len() as u64,
        mime: mime.into(),
        key: b64url(&[9u8; 32]),
        blob_sha256: npw_crypto::sha256_hex(data),
        created_at: 1_759_536_000_000,
        extra: Map::new(),
    }
}

fn passkey(n: u8, user: &str) -> Passkey {
    Passkey {
        id: format!("pk{n}"),
        rp_id: "example.com".into(),
        credential_id: b64url(&[n; 16]),
        user_handle: b64url(&[n + 100; 32]),
        user_name: user.into(),
        user_display_name: format!("显示名 {n}"),
        rp_name: "Example".into(),
        alg: -7,
        private_key: b64url(&fake_pkcs8(n)),
        counter: 3,
        discoverable: true,
        created_at: 1_759_536_000_000,
        extra: Map::new(),
    }
}

pub fn login_item() -> ExportItem {
    let mut c = ItemContent::new("login", LOGIN_TITLE);
    c.created_at = 1_700_000_000_123;
    c.updated_at = 1_759_536_000_456;
    c.favorite = true;
    c.tags = vec!["工作/开发".into(), "a;b".into()];
    c.fields = vec![
        Field::new("username", "用户名", kind::TEXT)
            .with_purpose(purpose::USERNAME)
            .with_value("user@example.com"),
        Field::new("password", "密码", kind::CONCEALED)
            .with_purpose(purpose::PASSWORD)
            .with_value(PASSWORD),
        Field::new("otp", "一次性密码", kind::TOTP)
            .with_purpose(purpose::OTP)
            .with_value(TOTP_SECRET),
        {
            let mut f = Field::new("f_rec", "恢复码", kind::CONCEALED).with_value(RECOVERY);
            f.multiline = true;
            f.section = Some("s_rec".into());
            f
        },
        Field::new("f_pin", "PIN", kind::PIN).with_value("123456"),
        Field::new("f_dup", "密码", kind::TEXT).with_value("a field labelled like the password"),
        Field::new("f_empty", "空字段", kind::TEXT),
    ];
    c.fields[1].generator =
        Some(json!({"length": 24, "sets": ["upper", "lower", "digit", "symbol"]}));
    c.sections = vec![Section {
        id: "s_rec".into(),
        label: "恢复".into(),
        extra: Map::new(),
    }];
    c.urls = vec![
        UrlEntry::new("https://example.com/login"),
        UrlEntry::new("https://accounts.example.com"),
        UrlEntry {
            match_mode: "exact".into(),
            cert_sha256: vec!["ab".repeat(32)],
            ..UrlEntry::new("androidapp://com.example.app")
        },
    ];
    c.passkeys = vec![
        passkey(1, "user@example.com"),
        passkey(2, "second@example.com"),
    ];
    c.notes = NOTES.into();
    c.history = vec![
        HistoryEntry {
            id: "h2".into(),
            field: "password".into(),
            label: "密码".into(),
            value: OLD_PASSWORDS[1].into(),
            until: 1_750_000_000_000,
            extra: Map::new(),
        },
        HistoryEntry {
            id: "h1".into(),
            field: "password".into(),
            label: "密码".into(),
            value: OLD_PASSWORDS[0].into(),
            until: 1_740_000_000_000,
            extra: Map::new(),
        },
    ];
    c.extra.insert(
        "future_key".into(),
        json!({"from": "a newer client", "n": [1, 2, 3]}),
    );
    c.fields[0]
        .extra
        .insert("future_field_key".into(), json!(true));

    let small = "恢复码文件\r\nline 2\n".as_bytes().to_vec();
    let big: Vec<u8> = (0..BIG).map(|i| (i * 31 % 251) as u8).collect();
    let empty: Vec<u8> = Vec::new();
    let a1 = attachment("a1", "recovery.txt", &small, "text/plain");
    let a2 = attachment("a2", "big.bin", &big, "application/octet-stream");
    let a3 = attachment("a3", "recovery.txt", &empty, "text/plain"); // duplicate name, empty
    c.attachments = vec![a1.clone(), a2.clone(), a3.clone()];
    ExportItem {
        content: c,
        attachments: vec![(a1, small), (a2, big), (a3, empty)],
        deleted: false,
    }
}

/// A value for a template field of this kind.
pub fn sample_value(id: &str, k: &str, multiline: bool) -> Value {
    match k {
        kind::ADDRESS => {
            json!({"country": "中国", "province": "浙江", "city": "杭州", "street": "示例路 1 号", "postal_code": "310000"})
        }
        kind::DATE => "2030-01-31".into(),
        kind::MONTH_YEAR => "2030-01".into(),
        kind::NUMBER => "22".into(),
        kind::PIN => "654321".into(),
        kind::BOOLEAN => "true".into(),
        kind::REFERENCE => "0190a1b2-0000-7000-8000-000000000000".into(),
        kind::TOTP => "otpauth://totp/Example:me?secret=GEZDGNBVGY3TQOJQ&issuer=Example".into(),
        kind::EMAIL => format!("{id}@example.com").into(),
        kind::URL => "https://api.example.com/v1".into(),
        kind::PHONE => "+86 138 0000 0000".into(),
        _ if multiline => format!("{id} 第一行\n{id} line 2\n-----END-----").into(),
        _ => format!("{id} 值 value").into(),
    }
}

/// One filled item per built-in template except `login`.
pub fn template_items() -> Vec<ExportItem> {
    templates()
        .iter()
        .filter(|t| t.id != "login")
        .map(|t| {
            let mut c = t.new_item("zh");
            c.title = format!("{} 示例", t.zh);
            c.created_at = 1_700_000_000_000;
            c.updated_at = 1_700_000_100_000;
            for f in &mut c.fields {
                f.value = sample_value(&f.id, &f.kind, f.multiline);
            }
            c.notes = format!("{} notes 备注", t.en);
            ExportItem {
                content: c,
                attachments: vec![],
                deleted: false,
            }
        })
        .collect()
}

pub fn deleted_item() -> ExportItem {
    let mut c = ItemContent::new("secure_note", "已删除的笔记");
    c.notes = "deleted but kept".into();
    c.archived = true;
    ExportItem {
        content: c,
        attachments: vec![],
        deleted: true,
    }
}

pub fn vaults() -> Vec<ExportVault> {
    let mut personal = vec![login_item()];
    personal.extend(template_items());
    let mut archived = ItemContent::new("password", "Archived 归档");
    archived.archived = true;
    archived.fields.push(
        Field::new("password", "密码", kind::CONCEALED)
            .with_purpose(purpose::PASSWORD)
            .with_value("x"),
    );
    personal.push(ExportItem {
        content: archived,
        attachments: vec![],
        deleted: false,
    });
    vec![
        ExportVault {
            name: "个人".into(),
            items: personal,
        },
        ExportVault {
            name: "Work".into(),
            items: vec![deleted_item()],
        },
        ExportVault {
            name: "Empty vault".into(),
            items: vec![],
        },
    ]
}
