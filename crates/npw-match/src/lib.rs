//! URL and app matching (design doc §5.5). Every client asks this crate, so a
//! login matches the same pages on Windows, in the extension and on Android.
//!
//! Modes: `domain` (registrable domain, the default), `host` (host and port),
//! `starts_with`, `exact`, `regex`, `never`. Android apps are stored as
//! `androidapp://<package>`; whether the app's signing certificate is accepted
//! is checked by the Android client against the item's `cert_sha256` list.

use std::collections::HashMap;

/// Where autofill is happening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Web {
        /// `https`, `http`, ...
        scheme: String,
        /// Lower-case host without the trailing dot; IPv6 without brackets.
        host: String,
        /// Explicit port only (`None` for the scheme's default).
        port: Option<u16>,
        /// The full URL as normalized by the `url` crate.
        full: String,
        /// Registrable domain (eTLD+1), or the host itself for IPs, `localhost` and single labels.
        domain: String,
    },
    App {
        package: String,
    },
}

/// How well a stored URL matches; higher is better. Used to sort suggestions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Quality {
    Equivalent = 1,
    Domain = 2,
    Host = 3,
    StartsWith = 4,
    Exact = 5,
}

fn registrable(host: &str) -> String {
    if host.parse::<std::net::IpAddr>().is_ok() || !host.contains('.') {
        return host.to_string();
    }
    match psl::domain_str(host) {
        Some(d) => d.to_string(),
        None => host.to_string(),
    }
}

/// Parses what a user may have typed or a site may report: full URLs, bare
/// hosts (`example.com`, `192.168.1.1:8080`), `androidapp://` URIs.
pub fn parse(input: &str) -> Option<Target> {
    let s = input.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(pkg) = s.strip_prefix("androidapp://") {
        let pkg = pkg.trim_end_matches('/').to_string();
        return (!pkg.is_empty()).then_some(Target::App { package: pkg });
    }
    let with_scheme = if s.contains("://") {
        s.to_string()
    } else {
        format!("https://{s}")
    };
    let u = url::Url::parse(&with_scheme).ok()?;
    let host = match u.host()? {
        url::Host::Domain(d) => d.trim_end_matches('.').to_lowercase(),
        url::Host::Ipv4(ip) => ip.to_string(),
        url::Host::Ipv6(ip) => ip.to_string(),
    };
    if host.is_empty() {
        return None;
    }
    let domain = registrable(&host);
    Some(Target::Web {
        scheme: u.scheme().to_string(),
        port: u.port(),
        full: u.to_string(),
        domain,
        host,
    })
}

/// User-defined and built-in groups of domains that share logins.
#[derive(Debug, Clone, Default)]
pub struct Equivalents {
    group_of: HashMap<String, usize>,
}

impl Equivalents {
    pub fn new(groups: &[Vec<String>]) -> Self {
        let mut group_of = HashMap::new();
        for (i, g) in groups.iter().enumerate() {
            for d in g {
                group_of.insert(d.to_lowercase(), i);
            }
        }
        Self { group_of }
    }

    /// The built-in groups plus `custom`.
    pub fn with_builtin(custom: &[Vec<String>]) -> Self {
        let mut all: Vec<Vec<String>> = BUILTIN_EQUIVALENTS
            .iter()
            .map(|g| g.iter().map(|d| d.to_string()).collect())
            .collect();
        all.extend_from_slice(custom);
        Self::new(&all)
    }

    pub fn equivalent(&self, a: &str, b: &str) -> bool {
        match (self.group_of.get(a), self.group_of.get(b)) {
            (Some(x), Some(y)) => x == y,
            _ => false,
        }
    }
}

/// Domains that are known to share one account system.
pub const BUILTIN_EQUIVALENTS: &[&[&str]] = &[
    &[
        "taobao.com",
        "tmall.com",
        "alipay.com",
        "1688.com",
        "aliyun.com",
        "alibabacloud.com",
        "fliggy.com",
    ],
    &[
        "qq.com",
        "tencent.com",
        "weixin.qq.com",
        "wechat.com",
        "tenpay.com",
    ],
    &["baidu.com", "hao123.com"],
    &["jd.com", "jd.hk", "jdpay.com"],
    &["163.com", "126.com", "yeah.net", "netease.com"],
    &["bilibili.com", "b23.tv"],
    &["weibo.com", "weibo.cn", "sina.com.cn"],
    &["mi.com", "xiaomi.com"],
    &["huawei.com", "huaweicloud.com", "vmall.com"],
    &["google.com", "google.com.hk", "youtube.com", "gmail.com"],
    &[
        "microsoft.com",
        "live.com",
        "outlook.com",
        "office.com",
        "microsoftonline.com",
        "xbox.com",
        "bing.com",
    ],
    &["apple.com", "icloud.com", "icloud.com.cn"],
    &["amazon.com", "amazon.cn", "amazon.co.jp"],
    &["github.com", "githubusercontent.com"],
    &["atlassian.com", "atlassian.net", "bitbucket.org"],
];

/// Does a stored URL (with its match mode) match the target? `None` = no.
pub fn matches(stored: &str, mode: &str, target: &Target, eq: &Equivalents) -> Option<Quality> {
    if mode == "never" {
        return None;
    }
    if mode == "regex" {
        let full = match target {
            Target::Web { full, .. } => full.clone(),
            Target::App { package } => format!("androidapp://{package}"),
        };
        let re = regex_lite::Regex::new(stored).ok()?;
        return re.is_match(&full).then_some(Quality::Exact);
    }
    let s = parse(stored)?;
    match (&s, target) {
        (Target::App { package: a }, Target::App { package: b }) => {
            (a == b).then_some(Quality::Exact)
        }
        (
            Target::Web {
                scheme: ss,
                host: sh,
                port: sp,
                full: sf,
                domain: sd,
            },
            Target::Web {
                scheme: ts,
                host: th,
                port: tp,
                full: tf,
                domain: td,
            },
        ) => {
            // Never fill a password saved for https into plain http on another host.
            match mode {
                "exact" => (sf == tf).then_some(Quality::Exact),
                "starts_with" => tf.starts_with(sf.as_str()).then_some(Quality::StartsWith),
                "host" => (sh == th && (sp.is_none() || sp == tp)).then_some(Quality::Host),
                _ => {
                    if sh == th && (sp.is_none() || sp == tp) {
                        return Some(Quality::Host);
                    }
                    // IPs and single-label hosts only ever match themselves.
                    if sd == sh && !sh.contains('.') || sh.parse::<std::net::IpAddr>().is_ok() {
                        return None;
                    }
                    if ss == "https" && ts == "http" {
                        return None; // also for equivalent domains
                    }
                    if sd == td {
                        return Some(Quality::Domain);
                    }
                    if eq.equivalent(sd, td) {
                        return Some(Quality::Equivalent);
                    }
                    None
                }
            }
        }
        _ => None,
    }
}

/// Best match among an item's URLs.
pub fn best_match<'a>(
    urls: impl IntoIterator<Item = (&'a str, &'a str)>,
    target: &Target,
    eq: &Equivalents,
) -> Option<Quality> {
    urls.into_iter()
        .filter_map(|(u, m)| matches(u, m, target, eq))
        .max()
}

/// The text shown for a URL in lists: the host (or package).
/// The site a URL belongs to: its registrable domain (eTLD+1 from the public
/// suffix list), or the host for IPs, `localhost` and single labels; the
/// package for apps. Two pages are "the same site" when this is equal.
pub fn site(input: &str) -> String {
    match parse(input) {
        Some(Target::Web { domain, .. }) => domain,
        Some(Target::App { package }) => package,
        None => input.trim().to_lowercase(),
    }
}

#[cfg(test)]
mod site_tests {
    use super::site;

    #[test]
    fn site_uses_the_public_suffix_list() {
        assert_eq!(site("https://a.b.example.com.cn/x"), "example.com.cn");
        assert_eq!(site("https://user.github.io/"), "user.github.io");
        assert_eq!(site("https://login.example.co.uk"), "example.co.uk");
        assert_eq!(site("http://192.168.1.1:8080/"), "192.168.1.1");
        assert_eq!(site("http://localhost:3000"), "localhost");
        assert_ne!(
            site("https://evil-example.com.cn"),
            site("https://example.com.cn")
        );
    }
}

pub fn display_host(input: &str) -> String {
    match parse(input) {
        Some(Target::Web {
            host,
            port: Some(p),
            ..
        }) => format!("{host}:{p}"),
        Some(Target::Web { host, .. }) => host,
        Some(Target::App { package }) => package,
        None => input.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(u: &str) -> Target {
        parse(u).unwrap()
    }

    #[test]
    fn domain_mode() {
        let eq = Equivalents::with_builtin(&[]);
        assert_eq!(
            matches(
                "https://github.com/login",
                "domain",
                &t("https://gist.github.com/x"),
                &eq
            ),
            Some(Quality::Domain)
        );
        assert_eq!(
            matches(
                "https://github.com",
                "domain",
                &t("https://github.com/a"),
                &eq
            ),
            Some(Quality::Host)
        );
        assert_eq!(
            matches(
                "https://github.com",
                "domain",
                &t("https://github.com.evil.example/"),
                &eq
            ),
            None
        );
        assert_eq!(
            matches(
                "https://github.com",
                "domain",
                &t("https://githuh.com"),
                &eq
            ),
            None
        );
        // public suffixes: two different sites under the same suffix never match
        assert_eq!(
            matches(
                "https://alice.github.io",
                "domain",
                &t("https://bob.github.io"),
                &eq
            ),
            None
        );
        assert_eq!(
            matches(
                "https://a.example.com.cn",
                "domain",
                &t("https://b.example.com.cn"),
                &eq
            ),
            Some(Quality::Domain)
        );
        // no downgrade from https to http
        assert_eq!(
            matches(
                "https://www.example.com",
                "domain",
                &t("http://login.example.com"),
                &eq
            ),
            None
        );
    }

    #[test]
    fn ips_ports_and_bare_hosts() {
        let eq = Equivalents::default();
        assert_eq!(
            matches(
                "192.168.1.1:8080",
                "domain",
                &t("http://192.168.1.1:8080/login"),
                &eq
            ),
            Some(Quality::Host)
        );
        assert_eq!(
            matches(
                "192.168.1.1:8080",
                "domain",
                &t("http://192.168.1.1:9090/"),
                &eq
            ),
            None
        );
        assert_eq!(
            matches("192.168.1.1", "domain", &t("http://192.168.1.2/"), &eq),
            None
        );
        assert_eq!(
            matches("http://nas:5000", "domain", &t("http://nas:5000/x"), &eq),
            Some(Quality::Host)
        );
        assert_eq!(
            matches(
                "https://vault.example.com:8443",
                "host",
                &t("https://vault.example.com/"),
                &eq
            ),
            None
        );
    }

    #[test]
    fn equivalent_domains_keep_the_https_rule() {
        let eq = Equivalents::with_builtin(&[vec!["example.com".into(), "example.org".into()]]);
        // a login saved for https is never suggested on a plain http page of another host
        for (stored, target) in [
            ("https://taobao.com", "http://tmall.com"),
            ("https://www.taobao.com", "http://login.tmall.com/"),
            ("https://example.com", "http://example.org"),
        ] {
            assert_eq!(
                matches(stored, "domain", &t(target), &eq),
                None,
                "{stored} on {target}"
            );
        }
        // http → https is fine (an upgrade)
        assert_eq!(
            matches("http://taobao.com", "domain", &t("https://tmall.com"), &eq),
            Some(Quality::Equivalent)
        );
        // same host stays a host match regardless of scheme (documented)
        assert_eq!(
            matches("https://taobao.com", "domain", &t("http://taobao.com"), &eq),
            Some(Quality::Host)
        );
    }

    #[test]
    fn other_modes_and_equivalents() {
        let eq = Equivalents::with_builtin(&[vec!["example.com".into(), "example.org".into()]]);
        assert_eq!(
            matches(
                "https://www.taobao.com",
                "domain",
                &t("https://login.tmall.com"),
                &eq
            ),
            Some(Quality::Equivalent)
        );
        assert_eq!(
            matches(
                "https://example.com",
                "domain",
                &t("https://example.org"),
                &eq
            ),
            Some(Quality::Equivalent)
        );
        assert_eq!(
            matches(
                "http://www.taobao.com",
                "domain",
                &t("http://login.tmall.com"),
                &eq
            ),
            Some(Quality::Equivalent)
        );
        assert_eq!(
            matches(
                "https://a.com/x",
                "starts_with",
                &t("https://a.com/x/y"),
                &eq
            ),
            Some(Quality::StartsWith)
        );
        assert_eq!(
            matches("https://a.com/x", "starts_with", &t("https://a.com/y"), &eq),
            None
        );
        assert_eq!(
            matches("https://a.com/x", "exact", &t("https://a.com/x"), &eq),
            Some(Quality::Exact)
        );
        assert_eq!(
            matches(
                r"^https://[a-z]+\.a\.com/",
                "regex",
                &t("https://x.a.com/p"),
                &eq
            ),
            Some(Quality::Exact)
        );
        assert_eq!(
            matches("https://a.com", "never", &t("https://a.com"), &eq),
            None
        );
        assert_eq!(
            matches(
                "androidapp://com.github.android",
                "domain",
                &t("androidapp://com.github.android"),
                &eq
            ),
            Some(Quality::Exact)
        );
        assert_eq!(
            matches(
                "https://github.com",
                "domain",
                &t("androidapp://com.github.android"),
                &eq
            ),
            None
        );
    }

    #[test]
    fn display() {
        assert_eq!(display_host("https://Example.COM/login"), "example.com");
        assert_eq!(display_host("192.168.1.1:8080"), "192.168.1.1:8080");
    }
}
