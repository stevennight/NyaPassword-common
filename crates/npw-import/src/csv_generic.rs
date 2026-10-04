//! Chrome / Edge / Google Password Manager CSV (`name,url,username,password,note`)
//! and other CSVs whose headers can be recognised (Firefox, Safari, generic
//! `title,url,username,password,notes`). Columns without a meaning go into
//! "Other fields" with a warning.

use npw_model::{kind, UrlEntry};

use crate::{strip_bom, tr, Draft, ImportError, ImportResult, Skipped};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Title,
    Url,
    Username,
    Email,
    Password,
    Notes,
    Otp,
    Tags,
    Favorite,
    Created,
    Updated,
}

fn role(header: &str) -> Option<Role> {
    let h: String = header
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| !matches!(c, ' ' | '_' | '-'))
        .collect();
    Some(match h.as_str() {
        "name" | "title" | "account" | "item" | "itemname" | "entry" | "名称" | "标题" => {
            Role::Title
        }
        "url" | "uri" | "urls" | "website" | "site" | "loginuri" | "loginurl" | "hostname"
        | "originurl" | "网址" => Role::Url,
        "username" | "user" | "login" | "loginname" | "loginusername" | "用户名" | "账号" => {
            Role::Username
        }
        "email" | "emailaddress" | "邮箱" => Role::Email,
        "password" | "pass" | "pwd" | "loginpassword" | "密码" => Role::Password,
        "note" | "notes" | "comment" | "comments" | "extra" | "备注" => Role::Notes,
        "totp" | "otp" | "otpauth" | "onetimepassword" | "2fa" | "logintotp" => Role::Otp,
        "folder" | "group" | "tags" | "tag" | "category" | "grouping" | "文件夹" | "标签" => {
            Role::Tags
        }
        "favorite" | "favourite" | "fav" => Role::Favorite,
        "timecreated" | "created" => Role::Created,
        "timepasswordchanged" | "lastmodified" | "modified" => Role::Updated,
        _ => return None,
    })
}

/// Whether the (lower-cased) headers look like a password CSV this module can read.
pub fn recognises(headers: &[String]) -> bool {
    let roles: Vec<Role> = headers.iter().filter_map(|h| role(h)).collect();
    roles.contains(&Role::Password)
        && (roles.contains(&Role::Url)
            || roles.contains(&Role::Username)
            || roles.contains(&Role::Title))
}

/// A timestamp column: Unix milliseconds (Firefox), seconds, or RFC 3339.
fn timestamp(v: &str) -> Option<i64> {
    let v = v.trim();
    match v.parse::<i64>() {
        Ok(n) if n > 100_000_000_000 => Some(n),
        Ok(n) if n > 0 => Some(n * 1000),
        _ => crate::parse_rfc3339_ms(v),
    }
}

fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    host.rsplit_once('@').map(|(_, h)| h).unwrap_or(host)
}

/// Imports a browser / generic password CSV as login items.
pub fn import_csv(bytes: &[u8], locale: &str) -> Result<ImportResult, ImportError> {
    let text = std::str::from_utf8(strip_bom(bytes))
        .map_err(|_| ImportError::Format("not UTF-8 text".into()))?;
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());
    let headers: Vec<String> = rdr
        .headers()
        .map_err(|e| ImportError::Format(format!("CSV: {e}")))?
        .iter()
        .map(|h| h.trim().to_string())
        .collect();
    if !recognises(&headers) {
        return Err(ImportError::Format("CSV headers not recognised (need a password column and a name, URL or username column)".into()));
    }
    let mut roles: Vec<Option<Role>> = headers.iter().map(|h| role(h)).collect();
    // The first column of each role wins; later duplicates are kept as other fields.
    for i in 0..roles.len() {
        if roles[..i].contains(&roles[i]) && roles[i] != Some(Role::Url) {
            roles[i] = None;
        }
    }
    let email_is_username = !roles.contains(&Some(Role::Username));
    let mut items = Vec::new();
    let mut skipped = Vec::new();
    for (row, rec) in rdr.records().enumerate() {
        let line = row + 2;
        let rec = match rec {
            Ok(r) => r,
            Err(e) => {
                skipped.push(Skipped::new(format!("#{line}"), format!("CSV: {e}")));
                continue;
            }
        };
        if rec.iter().all(|f| f.trim().is_empty()) {
            continue;
        }
        let val = |r: Role| {
            roles
                .iter()
                .position(|x| *x == Some(r))
                .and_then(|i| rec.get(i))
                .unwrap_or("")
        };
        let urls: Vec<&str> = roles
            .iter()
            .zip(rec.iter())
            .filter(|(r, v)| **r == Some(Role::Url) && !v.trim().is_empty())
            .map(|(_, v)| v.trim())
            .collect();
        let username = if email_is_username {
            val(Role::Email)
        } else {
            val(Role::Username)
        };
        let mut title = val(Role::Title).trim().to_string();
        if title.is_empty() {
            title = urls
                .first()
                .map(|u| host_of(u).to_string())
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| username.to_string());
        }
        if title.is_empty() {
            title = tr(locale, "（无标题）", "(untitled)").into();
        }
        let is_note = urls.is_empty()
            && username.is_empty()
            && val(Role::Password).is_empty()
            && val(Role::Otp).is_empty();
        let mut d = Draft::new(
            if is_note { "secure_note" } else { "login" },
            &title,
            &format!("row{line}"),
            locale,
        );
        if !is_note {
            d.set("username", username);
            d.set("password", val(Role::Password));
            d.set("otp", val(Role::Otp));
            for u in &urls {
                d.content().urls.push(UrlEntry::new(*u));
            }
        }
        d.content().notes = val(Role::Notes).to_string();
        let tag = val(Role::Tags).trim().trim_matches('/');
        if !tag.is_empty() {
            d.content().tags.push(tag.to_string());
        }
        d.content().favorite = matches!(
            val(Role::Favorite).trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "y" | "x"
        );
        if let Some(t) = timestamp(val(Role::Created)) {
            d.content().created_at = t;
            d.content().updated_at = t;
        }
        if let Some(t) = timestamp(val(Role::Updated)) {
            d.content().updated_at = t;
        }
        if !email_is_username && !val(Role::Email).is_empty() {
            d.other(tr(locale, "邮箱", "Email"), kind::EMAIL, val(Role::Email));
        }
        for (i, v) in rec.iter().enumerate() {
            if roles.get(i).copied().flatten().is_some() || v.is_empty() {
                continue;
            }
            let label = headers
                .get(i)
                .cloned()
                .unwrap_or_else(|| format!("#{}", i + 1));
            let why = tr(
                locale,
                "无法对应的列，已放入其他字段",
                "unmapped column, kept in Other fields",
            )
            .to_string();
            d.unmapped(&label, kind::TEXT, v, &why);
        }
        // Columns used for nothing but read anyway (unparseable timestamps).
        for r in [Role::Created, Role::Updated] {
            let v = val(r);
            if !v.trim().is_empty() && timestamp(v).is_none() {
                let label = roles
                    .iter()
                    .position(|x| *x == Some(r))
                    .and_then(|i| headers.get(i))
                    .cloned()
                    .unwrap_or_default();
                let why = tr(locale, "无法识别的时间", "unrecognised timestamp").to_string();
                d.unmapped(&label, kind::TEXT, v, &why);
            }
        }
        items.push(d.finish());
    }
    Ok(ImportResult::new(items, skipped))
}
