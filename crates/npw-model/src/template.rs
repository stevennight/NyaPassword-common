//! Built-in templates (design doc §5.4). A template only decides which fields a
//! new item starts with and how they are labelled; items can add and remove
//! fields freely. Field IDs are fixed per template so merges, imports and
//! autofill can rely on them.

use crate::item::{kind, purpose};
use crate::{Field, ItemContent, SshSettings};

#[derive(Debug, Clone, Copy)]
pub struct TemplateField {
    pub id: &'static str,
    pub kind: &'static str,
    pub purpose: Option<&'static str>,
    pub multiline: bool,
    pub zh: &'static str,
    pub en: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct Template {
    pub id: &'static str,
    pub zh: &'static str,
    pub en: &'static str,
    /// Icon name the UIs map to their icon sets.
    pub icon: &'static str,
    pub fields: &'static [TemplateField],
}

const fn f(id: &'static str, kind: &'static str, purpose: Option<&'static str>, zh: &'static str, en: &'static str) -> TemplateField {
    TemplateField { id, kind, purpose, multiline: false, zh, en }
}

const fn ml(id: &'static str, kind: &'static str, purpose: Option<&'static str>, zh: &'static str, en: &'static str) -> TemplateField {
    TemplateField { id, kind, purpose, multiline: true, zh, en }
}

use kind::*;
use purpose as p;

pub const TEMPLATES: &[Template] = &[
    Template {
        id: "login",
        zh: "登录",
        en: "Login",
        icon: "login",
        fields: &[
            f("username", TEXT, Some(p::USERNAME), "用户名", "Username"),
            f("password", CONCEALED, Some(p::PASSWORD), "密码", "Password"),
            f("otp", TOTP, Some(p::OTP), "一次性密码", "One-time password"),
        ],
    },
    Template { id: "password", zh: "密码", en: "Password", icon: "password", fields: &[f("password", CONCEALED, Some(p::PASSWORD), "密码", "Password")] },
    Template { id: "secure_note", zh: "安全笔记", en: "Secure note", icon: "note", fields: &[] },
    Template {
        id: "credit_card",
        zh: "银行卡",
        en: "Card",
        icon: "card",
        fields: &[
            f("cardholder", TEXT, Some(p::CC_NAME), "持卡人", "Cardholder"),
            f("number", CONCEALED, Some(p::CC_NUMBER), "卡号", "Number"),
            f("expiry", MONTH_YEAR, Some(p::CC_EXP), "有效期", "Expiry"),
            f("cvv", CONCEALED, Some(p::CC_CSC), "CVV", "Verification number"),
            f("pin", PIN, None, "交易密码", "PIN"),
            f("card_type", TEXT, None, "卡类型", "Type"),
            f("bank", TEXT, None, "开户行", "Issuing bank"),
            f("phone", PHONE, None, "预留手机号", "Phone on file"),
        ],
    },
    Template {
        id: "bank_account",
        zh: "银行账户",
        en: "Bank account",
        icon: "bank",
        fields: &[
            f("bank", TEXT, None, "开户行 / 支行", "Bank / branch"),
            f("account_number", CONCEALED, None, "账号", "Account number"),
            f("account_name", TEXT, Some(p::NAME), "户名", "Account holder"),
            f("online_login", TEXT, Some(p::USERNAME), "网银登录名", "Online banking login"),
            f("online_password", CONCEALED, Some(p::PASSWORD), "登录密码", "Online banking password"),
            f("payment_password", PIN, None, "支付密码", "Payment password"),
            f("ukey_password", CONCEALED, None, "U 盾 / 证书密码", "Security key password"),
            f("phone", PHONE, None, "预留手机号", "Phone on file"),
            f("swift", TEXT, None, "SWIFT / 联行号", "SWIFT / routing"),
        ],
    },
    Template {
        id: "identity",
        zh: "身份",
        en: "Identity",
        icon: "identity",
        fields: &[
            f("full_name", TEXT, Some(p::NAME), "姓名", "Full name"),
            f("phone", PHONE, Some(p::PHONE), "手机", "Phone"),
            f("email", EMAIL, Some(p::EMAIL), "邮箱", "Email"),
            f("address", ADDRESS, Some(p::ADDRESS), "地址", "Address"),
            f("birthday", DATE, None, "生日", "Birthday"),
            f("company", TEXT, None, "公司", "Company"),
        ],
    },
    Template {
        id: "document",
        zh: "证件",
        en: "ID document",
        icon: "document",
        fields: &[
            f("doc_type", TEXT, None, "证件类型", "Document type"),
            f("number", CONCEALED, None, "号码", "Number"),
            f("full_name", TEXT, Some(p::NAME), "姓名", "Full name"),
            f("issuer", TEXT, None, "签发机关", "Issued by"),
            f("issued_on", DATE, None, "签发日期", "Issued on"),
            f("expires_on", DATE, None, "有效期至", "Expires on"),
        ],
    },
    Template {
        id: "ssh_key",
        zh: "SSH 密钥",
        en: "SSH key",
        icon: "ssh",
        fields: &[
            ml("private_key", CONCEALED, Some(p::SSH_PRIVATE_KEY), "私钥", "Private key"),
            ml("public_key", MULTILINE, Some(p::SSH_PUBLIC_KEY), "公钥", "Public key"),
            f("fingerprint", TEXT, None, "指纹", "Fingerprint"),
            f("key_type", TEXT, None, "类型", "Key type"),
            f("passphrase", CONCEALED, None, "私钥口令", "Passphrase"),
        ],
    },
    Template {
        id: "server",
        zh: "服务器",
        en: "Server",
        icon: "server",
        fields: &[
            f("host", TEXT, None, "地址", "Host"),
            f("port", NUMBER, None, "端口", "Port"),
            f("username", TEXT, Some(p::USERNAME), "用户名", "Username"),
            f("password", CONCEALED, Some(p::PASSWORD), "密码", "Password"),
            f("ssh_key", REFERENCE, None, "SSH 密钥", "SSH key"),
        ],
    },
    Template {
        id: "database",
        zh: "数据库",
        en: "Database",
        icon: "database",
        fields: &[
            f("db_type", TEXT, None, "类型", "Type"),
            f("host", TEXT, None, "地址", "Host"),
            f("port", NUMBER, None, "端口", "Port"),
            f("database", TEXT, None, "数据库", "Database"),
            f("username", TEXT, Some(p::USERNAME), "用户名", "Username"),
            f("password", CONCEALED, Some(p::PASSWORD), "密码", "Password"),
            f("options", TEXT, None, "连接参数", "Connection options"),
        ],
    },
    Template {
        id: "api_credential",
        zh: "API 凭据",
        en: "API credential",
        icon: "api",
        fields: &[
            f("username", TEXT, Some(p::USERNAME), "用户名 / Key ID", "Username / key ID"),
            ml("credential", CONCEALED, Some(p::PASSWORD), "凭据", "Credential"),
            f("endpoint", URL, None, "地址", "Endpoint"),
            f("expires_on", DATE, None, "过期时间", "Expires on"),
        ],
    },
    Template {
        id: "wifi",
        zh: "Wi-Fi",
        en: "Wi-Fi",
        icon: "wifi",
        fields: &[
            f("ssid", TEXT, None, "网络名称", "Network name"),
            f("password", CONCEALED, Some(p::PASSWORD), "密码", "Password"),
            f("security", TEXT, None, "加密方式", "Security"),
        ],
    },
    Template {
        id: "software_license",
        zh: "软件许可",
        en: "Software license",
        icon: "license",
        fields: &[
            f("version", TEXT, None, "版本", "Version"),
            ml("license_key", CONCEALED, None, "许可证密钥", "License key"),
            f("licensed_to", TEXT, None, "授权给", "Licensed to"),
            f("email", EMAIL, None, "注册邮箱", "Registered email"),
            f("order_number", TEXT, None, "订单号", "Order number"),
            f("purchased_on", DATE, None, "购买日期", "Purchase date"),
        ],
    },
    Template {
        id: "crypto_wallet",
        zh: "加密钱包",
        en: "Crypto wallet",
        icon: "wallet",
        fields: &[
            ml("recovery_phrase", CONCEALED, None, "助记词", "Recovery phrase"),
            f("password", CONCEALED, Some(p::PASSWORD), "钱包密码", "Wallet password"),
            f("address", TEXT, None, "地址", "Address"),
        ],
    },
];

/// Field presets the "add field" menu offers on every template.
pub const EXTRA_FIELD_PRESETS: &[TemplateField] = &[
    ml("recovery_codes", CONCEALED, None, "恢复码", "Recovery codes"),
    f("security_question", CONCEALED, None, "密保问题答案", "Security answer"),
    f("phone", PHONE, None, "手机号", "Phone"),
    f("email", EMAIL, None, "邮箱", "Email"),
];

pub fn templates() -> &'static [Template] {
    TEMPLATES
}

pub fn template(id: &str) -> Option<&'static Template> {
    TEMPLATES.iter().find(|t| t.id == id)
}

impl TemplateField {
    pub fn label(&self, locale: &str) -> &'static str {
        if locale.starts_with("zh") {
            self.zh
        } else {
            self.en
        }
    }

    pub fn to_field(&self, locale: &str) -> Field {
        let mut fld = Field::new(self.id, self.label(locale), self.kind);
        fld.purpose = self.purpose.map(str::to_string);
        fld.multiline = self.multiline;
        if self.kind == ADDRESS {
            fld.value = serde_json::json!({});
        }
        fld
    }
}

impl Template {
    pub fn label(&self, locale: &str) -> &'static str {
        if locale.starts_with("zh") {
            self.zh
        } else {
            self.en
        }
    }

    /// A new, empty item of this template.
    pub fn new_item(&self, locale: &str) -> ItemContent {
        let mut item = ItemContent::new(self.id, "");
        item.fields = self.fields.iter().map(|tf| tf.to_field(locale)).collect();
        if self.id == "ssh_key" {
            item.ssh = Some(SshSettings { confirm_each_use: true, ..Default::default() });
        }
        item
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_unique_within_templates() {
        let mut seen = std::collections::HashSet::new();
        for t in TEMPLATES {
            assert!(seen.insert(t.id), "duplicate template {}", t.id);
            let mut ids = std::collections::HashSet::new();
            for f in t.fields {
                assert!(ids.insert(f.id), "duplicate field {} in {}", f.id, t.id);
            }
        }
    }

    #[test]
    fn new_item_has_template_fields() {
        let item = template("bank_account").unwrap().new_item("zh-CN");
        assert_eq!(item.field("payment_password").unwrap().label, "支付密码");
        assert_eq!(item.field("payment_password").unwrap().kind, kind::PIN);
        let ssh = template("ssh_key").unwrap().new_item("en");
        assert!(ssh.field("private_key").unwrap().multiline);
    }
}
