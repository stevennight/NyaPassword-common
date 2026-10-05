use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{new_short_id, now_ms, FORMAT_VERSION};

fn is_false(b: &bool) -> bool {
    !*b
}
fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// Field kinds (`Field::kind`). Strings rather than an enum so that kinds added
/// by newer clients survive a round trip through older ones.
pub mod kind {
    pub const TEXT: &str = "text";
    pub const MULTILINE: &str = "multiline";
    /// Hidden by default. With `multiline: true`: recovery codes, private keys, seed phrases.
    pub const CONCEALED: &str = "concealed";
    /// Digits only, e.g. a 6-digit payment password.
    pub const PIN: &str = "pin";
    pub const EMAIL: &str = "email";
    pub const PHONE: &str = "phone";
    pub const URL: &str = "url";
    /// `YYYY-MM-DD`
    pub const DATE: &str = "date";
    /// `YYYY-MM`, e.g. a card's expiry.
    pub const MONTH_YEAR: &str = "month_year";
    pub const NUMBER: &str = "number";
    /// An `otpauth://` URI (or a bare base32 secret).
    pub const TOTP: &str = "totp";
    /// Structured: `{country, province, city, district, street, postal_code}`.
    pub const ADDRESS: &str = "address";
    /// The ID of another item in the same vault.
    pub const REFERENCE: &str = "reference";
    /// The ID of an attachment of this item.
    pub const FILE: &str = "file";
    /// `"true"` / `"false"`.
    pub const BOOLEAN: &str = "boolean";

    /// Kinds whose values are secret: hidden in the UI, recorded in history when changed.
    pub fn is_secret(kind: &str) -> bool {
        matches!(kind, CONCEALED | PIN | TOTP)
    }
}

/// What a field means for autofill (`Field::purpose`), independent of its kind:
/// a phone number can be the username.
pub mod purpose {
    pub const USERNAME: &str = "username";
    pub const PASSWORD: &str = "password";
    pub const OTP: &str = "otp";
    pub const EMAIL: &str = "email";
    pub const PHONE: &str = "phone";
    pub const NAME: &str = "name";
    pub const CC_NAME: &str = "cc-name";
    pub const CC_NUMBER: &str = "cc-number";
    pub const CC_EXP: &str = "cc-exp";
    pub const CC_CSC: &str = "cc-csc";
    pub const ADDRESS: &str = "address";
    pub const SSH_PRIVATE_KEY: &str = "ssh-private-key";
    pub const SSH_PUBLIC_KEY: &str = "ssh-public-key";
}

/// URL match modes (`UrlEntry::match_mode`).
pub mod match_mode {
    /// Same registrable domain (eTLD+1). The default.
    pub const DOMAIN: &str = "domain";
    /// Same host name (and port, if the stored URL has one).
    pub const HOST: &str = "host";
    pub const STARTS_WITH: &str = "starts_with";
    pub const EXACT: &str = "exact";
    pub const REGEX: &str = "regex";
    pub const NEVER: &str = "never";
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Field {
    pub id: String,
    #[serde(default)]
    pub label: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// A string for every kind except `address` (an object).
    #[serde(default)]
    pub value: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub multiline: bool,
    /// The generator recipe last used for this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generator: Option<Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Field {
    pub fn new(id: impl Into<String>, label: impl Into<String>, kind: &str) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            kind: kind.to_string(),
            purpose: None,
            value: Value::String(String::new()),
            section: None,
            multiline: false,
            generator: None,
            extra: Map::new(),
        }
    }

    pub fn with_purpose(mut self, p: &str) -> Self {
        self.purpose = Some(p.to_string());
        self
    }

    pub fn with_value(mut self, v: impl Into<String>) -> Self {
        self.value = Value::String(v.into());
        self
    }

    /// The value as text (objects such as addresses are rendered as JSON).
    pub fn text(&self) -> String {
        match &self.value {
            Value::String(s) => s.clone(),
            Value::Null => String::new(),
            other => other.to_string(),
        }
    }

    pub fn is_secret(&self) -> bool {
        kind::is_secret(&self.kind)
    }

    pub fn is_empty(&self) -> bool {
        match &self.value {
            Value::Null => true,
            Value::String(s) => s.is_empty(),
            Value::Object(o) => o
                .values()
                .all(|v| v.as_str().map(str::is_empty).unwrap_or(v.is_null())),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Section {
    pub id: String,
    #[serde(default)]
    pub label: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UrlEntry {
    pub id: String,
    /// A web URL, or `androidapp://<package>` for an Android app.
    pub url: String,
    #[serde(rename = "match", default = "default_match")]
    pub match_mode: String,
    /// Android apps: accepted signing certificate SHA-256 fingerprints (hex).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cert_sha256: Vec<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

fn default_match() -> String {
    match_mode::DOMAIN.to_string()
}

impl UrlEntry {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            id: new_short_id("u"),
            url: url.into(),
            match_mode: default_match(),
            cert_sha256: vec![],
            extra: Map::new(),
        }
    }
}

/// A WebAuthn credential this item can sign with.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Passkey {
    pub id: String,
    pub rp_id: String,
    /// base64url
    pub credential_id: String,
    /// base64url
    #[serde(default)]
    pub user_handle: String,
    #[serde(default)]
    pub user_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user_display_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rp_name: String,
    /// COSE algorithm, -7 = ES256.
    #[serde(default = "default_alg")]
    pub alg: i64,
    /// PKCS#8 DER, base64url.
    pub private_key: String,
    #[serde(default)]
    pub counter: u32,
    #[serde(default = "default_true")]
    pub discoverable: bool,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub created_at: i64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

fn default_alg() -> i64 {
    -7
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attachment {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mime: String,
    /// The attachment's own key (base64url); the blob is stream-encrypted with it.
    pub key: String,
    /// SHA-256 (hex) of the encrypted blob, checked after download.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub blob_sha256: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub created_at: i64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A previous value of a secret field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub id: String,
    pub field: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    pub value: Value,
    /// When the value stopped being current.
    pub until: i64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A value that lost a sync conflict. Kept until the user resolves it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Conflict {
    pub id: String,
    /// What conflicted, e.g. `fields/password/value`, `title`, `notes`.
    pub path: String,
    #[serde(default)]
    pub label: String,
    /// The value that was not kept.
    pub value: Value,
    /// The value that was kept, when the conflict was recorded.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub kept: Value,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device: String,
    pub at: i64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AutofillSettings {
    #[serde(default, skip_serializing_if = "is_false")]
    pub auto_submit: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub never: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl AutofillSettings {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SshSettings {
    /// Ask before every signature (default) instead of once per session.
    #[serde(default = "default_true")]
    pub confirm_each_use: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub git_signing: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The decrypted content of one item revision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ItemContent {
    pub format: String,
    pub template: String,
    #[serde(default)]
    pub title: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub favorite: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub archived: bool,
    /// Ask the user to verify (master password, Windows Hello, biometrics)
    /// before showing, copying or filling this item's secrets. A UI guard, not
    /// encryption: the item is encrypted like any other.
    #[serde(default, skip_serializing_if = "is_false")]
    pub reprompt: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default)]
    pub fields: Vec<Field>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<Section>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<UrlEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passkeys: Vec<Passkey>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<HistoryEntry>,
    #[serde(default, skip_serializing_if = "AutofillSettings::is_default")]
    pub autofill: AutofillSettings,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<SshSettings>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<Conflict>,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub updated_at: i64,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl ItemContent {
    pub fn new(template: &str, title: impl Into<String>) -> Self {
        let now = now_ms();
        Self {
            format: FORMAT_VERSION.to_string(),
            template: template.to_string(),
            title: title.into(),
            favorite: false,
            archived: false,
            reprompt: false,
            tags: vec![],
            fields: vec![],
            sections: vec![],
            urls: vec![],
            passkeys: vec![],
            notes: String::new(),
            attachments: vec![],
            history: vec![],
            autofill: AutofillSettings::default(),
            ssh: None,
            conflicts: vec![],
            created_at: now,
            updated_at: now,
            extra: Map::new(),
        }
    }

    pub fn field(&self, id: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.id == id)
    }

    pub fn field_mut(&mut self, id: &str) -> Option<&mut Field> {
        self.fields.iter_mut().find(|f| f.id == id)
    }

    /// The first field with this autofill purpose.
    pub fn by_purpose(&self, p: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.purpose.as_deref() == Some(p))
    }

    pub fn username(&self) -> Option<String> {
        self.by_purpose(purpose::USERNAME)
            .map(Field::text)
            .filter(|s| !s.is_empty())
    }

    pub fn password(&self) -> Option<String> {
        self.by_purpose(purpose::PASSWORD)
            .map(Field::text)
            .filter(|s| !s.is_empty())
    }

    pub fn totp(&self) -> Option<String> {
        self.fields
            .iter()
            .find(|f| f.kind == kind::TOTP)
            .map(Field::text)
            .filter(|s| !s.is_empty())
    }

    /// Short line shown under the title in lists.
    pub fn subtitle(&self) -> String {
        if let Some(u) = self.username() {
            return u;
        }
        self.fields
            .iter()
            .find(|f| !f.is_secret() && !f.is_empty() && f.kind != kind::MULTILINE)
            .map(Field::text)
            .unwrap_or_default()
    }

    /// Records the old values of secret fields that `self` changed relative to
    /// `previous` (password history), and bumps `updated_at`. Call before saving.
    pub fn record_changes_from(&mut self, previous: &ItemContent) {
        let now = now_ms();
        for old in &previous.fields {
            if !old.is_secret() || old.is_empty() {
                continue;
            }
            let changed = match self.field(&old.id) {
                Some(new) => new.value != old.value,
                None => true,
            };
            if changed {
                self.history.push(HistoryEntry {
                    id: new_short_id("h"),
                    field: old.id.clone(),
                    label: old.label.clone(),
                    value: old.value.clone(),
                    until: now,
                    extra: Map::new(),
                });
            }
        }
        self.updated_at = now.max(previous.updated_at + 1);
    }

    /// Lower-cased text the search index uses: title, subtitle, URLs, tags, non-secret fields, notes.
    pub fn search_text(&self) -> String {
        let mut s = String::new();
        s.push_str(&self.title);
        for t in &self.tags {
            s.push(' ');
            s.push_str(t);
        }
        for u in &self.urls {
            s.push(' ');
            s.push_str(&u.url);
        }
        for f in &self.fields {
            if !f.is_secret() {
                s.push(' ');
                s.push_str(&f.text());
            }
        }
        s.push(' ');
        s.push_str(&self.notes);
        s.to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_keys_survive_round_trip() {
        let json = r#"{
            "format": "1.4", "template": "login", "title": "X", "future_top": {"a": 1},
            "fields": [{"id": "password", "kind": "concealed", "value": "p", "future_field": [1, 2]},
                       {"id": "f1", "kind": "hologram", "value": "?"}],
            "urls": [{"id": "u1", "url": "https://example.com", "match": "domain", "future_url": true}],
            "autofill": {"never": true, "future_af": "x"}
        }"#;
        let item: ItemContent = serde_json::from_str(json).unwrap();
        assert_eq!(item.fields[1].kind, "hologram");
        let back: Value = serde_json::to_value(&item).unwrap();
        let orig: Value = serde_json::from_str(json).unwrap();
        assert_eq!(back["future_top"], orig["future_top"]);
        assert_eq!(
            back["fields"][0]["future_field"],
            orig["fields"][0]["future_field"]
        );
        assert_eq!(back["urls"][0]["future_url"], orig["urls"][0]["future_url"]);
        assert_eq!(back["autofill"]["future_af"], orig["autofill"]["future_af"]);
    }

    #[test]
    fn history_records_changed_secrets_only() {
        let mut a = ItemContent::new("login", "Site");
        a.fields.push(
            Field::new("username", "用户名", kind::TEXT)
                .with_purpose(purpose::USERNAME)
                .with_value("me"),
        );
        a.fields.push(
            Field::new("password", "密码", kind::CONCEALED)
                .with_purpose(purpose::PASSWORD)
                .with_value("old"),
        );
        let mut b = a.clone();
        b.field_mut("username").unwrap().value = "me2".into();
        b.field_mut("password").unwrap().value = "new".into();
        b.record_changes_from(&a);
        assert_eq!(b.history.len(), 1);
        assert_eq!(b.history[0].value, "old");
        assert!(b.updated_at > a.updated_at);
    }

    #[test]
    fn reprompt_is_omitted_when_false() {
        let mut a = ItemContent::new("login", "Site");
        let v = serde_json::to_value(&a).unwrap();
        assert!(v.get("reprompt").is_none());
        a.reprompt = true;
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(v["reprompt"], Value::Bool(true));
        let back: ItemContent = serde_json::from_value(v).unwrap();
        assert!(back.reprompt);
        assert!(back.extra.is_empty());
    }
}
