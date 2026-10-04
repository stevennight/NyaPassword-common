//! Security report (like 1Password Watchtower): weak, reused and old
//! passwords, sites that support two-step verification but have no TOTP
//! saved, and logins on plain http. Computed locally; nothing leaves the device.

use std::collections::HashMap;

use npw_model::item::kind;
use serde::{Deserialize, Serialize};

use crate::client::Client;
use crate::generator::strength;
use crate::{CoreError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Issue {
    Weak,
    Reused,
    Old,
    TotpAvailable,
    Insecure,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub issue: Issue,
    pub vault_id: String,
    pub item_id: String,
    pub title: String,
    /// Weak: strength 0–4. Reused: how many items share it. Old: days. Others: the URL.
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SecurityReport {
    pub findings: Vec<Finding>,
    pub weak: usize,
    pub reused: usize,
    pub old: usize,
    pub totp_available: usize,
    pub insecure: usize,
}

/// Sites known to offer TOTP two-step verification (registrable domains).
const TOTP_SITES: &[&str] = &[
    "github.com", "gitlab.com", "google.com", "microsoft.com", "live.com", "apple.com", "amazon.com", "aws.amazon.com", "cloudflare.com",
    "dropbox.com", "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com", "discord.com", "slack.com", "reddit.com",
    "paypal.com", "binance.com", "coinbase.com", "okx.com", "docker.com", "npmjs.com", "pypi.org", "atlassian.net", "atlassian.com",
    "bitbucket.org", "digitalocean.com", "linode.com", "vultr.com", "hetzner.com", "ovh.com", "namecheap.com", "godaddy.com", "porkbun.com",
    "aliyun.com", "alibabacloud.com", "cloud.tencent.com", "tencentcloud.com", "huaweicloud.com", "qiniu.com", "upyun.com", "jdcloud.com",
    "ucloud.cn", "volcengine.com", "baidubce.com", "gitee.com", "coding.net", "steampowered.com", "epicgames.com", "ea.com", "ubisoft.com",
    "battle.net", "nintendo.com", "playstation.com", "proton.me", "protonmail.com", "fastmail.com", "zoho.com", "notion.so", "figma.com",
    "openai.com", "anthropic.com", "heroku.com", "vercel.com", "netlify.com", "stripe.com", "twilio.com", "sentry.io", "mega.nz", "tailscale.com",
];

impl Client {
    pub fn security_report(&self) -> Result<SecurityReport> {
        let st = self.state.lock().expect("state");
        if st.keys.is_none() {
            return Err(CoreError::Locked);
        }
        let now = npw_model::now_ms();
        let mut report = SecurityReport::default();
        let mut by_password: HashMap<String, Vec<(String, String, String)>> = HashMap::new();

        for c in st.cache.items.values().filter(|c| !c.deleted && !c.content.archived) {
            let it = &c.content;
            let push = |r: &mut SecurityReport, issue: Issue, detail: String| {
                r.findings.push(Finding { issue, vault_id: c.vault_id.clone(), item_id: c.item_id.clone(), title: it.title.clone(), detail });
            };
            if let Some(pw) = it.password() {
                let s = strength(&pw);
                if s <= 1 {
                    push(&mut report, Issue::Weak, s.to_string());
                    report.weak += 1;
                }
                by_password.entry(npw_crypto::sha256_hex(pw.as_bytes())).or_default().push((c.vault_id.clone(), c.item_id.clone(), it.title.clone()));
                let pw_field = it.by_purpose(npw_model::item::purpose::PASSWORD).map(|f| f.id.clone()).unwrap_or_default();
                let since = it.history.iter().filter(|h| h.field == pw_field).map(|h| h.until).max().unwrap_or(it.created_at);
                let days = (now - since) / 86_400_000;
                if since > 0 && days >= 365 {
                    push(&mut report, Issue::Old, days.to_string());
                    report.old += 1;
                }
            }
            let has_totp = it.fields.iter().any(|f| f.kind == kind::TOTP && !f.is_empty());
            for u in &it.urls {
                if let Some(npw_match::Target::Web { scheme, domain, host, .. }) = npw_match::parse(&u.url) {
                    if !has_totp && it.password().is_some() && (TOTP_SITES.contains(&domain.as_str()) || TOTP_SITES.contains(&host.as_str())) {
                        push(&mut report, Issue::TotpAvailable, u.url.clone());
                        report.totp_available += 1;
                        break;
                    }
                    let local = host == "localhost" || host.parse::<std::net::IpAddr>().is_ok() || !host.contains('.');
                    if scheme == "http" && !local && it.password().is_some() {
                        push(&mut report, Issue::Insecure, u.url.clone());
                        report.insecure += 1;
                        break;
                    }
                }
            }
        }
        for group in by_password.values().filter(|g| g.len() > 1) {
            for (v, i, t) in group {
                report.findings.push(Finding { issue: Issue::Reused, vault_id: v.clone(), item_id: i.clone(), title: t.clone(), detail: group.len().to_string() });
                report.reused += 1;
            }
        }
        Ok(report)
    }
}
