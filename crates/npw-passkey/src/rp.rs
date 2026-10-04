//! Origin and RP ID validation (WebAuthn §5.1.3 step 7/8, §5.1.4 step 7/8 and
//! HTML's "is a registrable domain suffix of or is equal to").

use url::{Host, Url};

use crate::PasskeyError;

/// A caller origin that may use WebAuthn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebOrigin {
    /// ASCII serialization as browsers put it in clientDataJSON, e.g.
    /// `https://login.example.com` or `http://localhost:8080`.
    pub serialized: String,
    /// The effective domain: lower-case ASCII (punycode) host, no trailing dot.
    pub host: String,
}

fn is_localhost(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost")
}

/// Parses an origin (or any URL of the page; only its origin is used).
///
/// `https` is required, except `http://localhost` and `http://*.localhost`,
/// which browsers treat as secure contexts. IP-address origins are rejected
/// because an RP ID must be a domain.
pub fn parse_origin(origin: &str) -> Result<WebOrigin, PasskeyError> {
    let url = Url::parse(origin.trim())
        .map_err(|_| PasskeyError::Security(format!("invalid origin {origin:?}")))?;
    let host = match url.host() {
        Some(Host::Domain(d)) => d.trim_end_matches('.').to_ascii_lowercase(),
        Some(_) => {
            return Err(PasskeyError::Security(
                "an IP address origin cannot use WebAuthn".into(),
            ))
        }
        None => {
            return Err(PasskeyError::Security(format!(
                "origin {origin:?} has no host"
            )))
        }
    };
    match url.scheme() {
        "https" => {}
        "http" if is_localhost(&host) => {}
        s => {
            return Err(PasskeyError::Security(format!(
                "WebAuthn requires a secure origin, got scheme {s:?}"
            )))
        }
    }
    if host.is_empty() {
        return Err(PasskeyError::Security(format!(
            "origin {origin:?} has no host"
        )));
    }
    Ok(WebOrigin {
        serialized: url.origin().ascii_serialization(),
        host,
    })
}

/// Normalizes an RP ID the way the URL host parser does (IDNA to punycode,
/// lower case). Returns `None` if it is not a domain.
pub fn normalize_rp_id(rp_id: &str) -> Option<String> {
    let rp_id = rp_id.trim();
    if rp_id.is_empty() || rp_id.ends_with('.') || rp_id.contains(['/', ':', '@', '?', '#']) {
        return None;
    }
    match Host::parse(rp_id) {
        Ok(Host::Domain(d)) if !d.is_empty() => Some(d.to_ascii_lowercase()),
        _ => None,
    }
}

/// Returns the effective RP ID for `requested` (or the origin's host when the
/// request has none), if the origin may use it.
pub fn effective_rp_id(
    requested: Option<&str>,
    origin: &WebOrigin,
) -> Result<String, PasskeyError> {
    let Some(requested) = requested else {
        return Ok(origin.host.clone());
    };
    let rp = normalize_rp_id(requested)
        .ok_or_else(|| PasskeyError::Security(format!("invalid RP ID {requested:?}")))?;
    if is_registrable_suffix_or_equal(&rp, &origin.host) {
        Ok(rp)
    } else {
        Err(PasskeyError::Security(format!(
            "RP ID {rp:?} is not valid for origin {}",
            origin.serialized
        )))
    }
}

/// HTML "is a registrable domain suffix of or is equal to": `suffix` must be
/// `host` itself, or a parent domain of it that is not a public suffix (per
/// the Public Suffix List, including its private section such as `github.io`).
pub fn is_registrable_suffix_or_equal(suffix: &str, host: &str) -> bool {
    if suffix.is_empty() {
        return false;
    }
    if suffix == host {
        return true;
    }
    if !host.ends_with(&format!(".{suffix}")) {
        return false;
    }
    // The suffix may not be a public suffix itself ...
    if psl::suffix_str(suffix).is_none_or(|ps| ps == suffix) {
        return false;
    }
    // ... nor a label sequence inside the host's public suffix.
    if let Some(host_ps) = psl::suffix_str(host) {
        if host_ps == suffix || host_ps.ends_with(&format!(".{suffix}")) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rp(origin: &str, rp_id: Option<&str>) -> Result<String, PasskeyError> {
        effective_rp_id(rp_id, &parse_origin(origin)?)
    }

    #[test]
    fn matrix() {
        assert_eq!(
            rp("https://sub.example.com", Some("example.com")).unwrap(),
            "example.com"
        );
        assert_eq!(
            rp("https://sub.example.com", Some("sub.example.com")).unwrap(),
            "sub.example.com"
        );
        assert_eq!(
            rp("https://Sub.Example.com:8443/path?q", None).unwrap(),
            "sub.example.com"
        );
        assert_eq!(
            rp("https://a.b.example.co.uk", Some("Example.CO.uk")).unwrap(),
            "example.co.uk"
        );
        assert!(rp("https://example.com", Some("other.com")).is_err());
        assert!(rp("https://example.com", Some("sub.example.com")).is_err());
        assert!(rp("https://notexample.com", Some("example.com")).is_err());
        assert!(rp("https://example.com", Some("com")).is_err());
        assert!(rp("https://user.github.io", Some("github.io")).is_err());
        assert!(rp("https://a.example.co.uk", Some("co.uk")).is_err());
        assert!(rp("https://example.com", Some("")).is_err());
        assert!(rp("https://example.com", Some("example.com.")).is_err());
        assert!(rp("https://example.com", Some("https://example.com")).is_err());
        assert_eq!(
            rp("http://localhost:3000", Some("localhost")).unwrap(),
            "localhost"
        );
        assert_eq!(rp("http://localhost", None).unwrap(), "localhost");
        assert!(rp("http://example.com", Some("example.com")).is_err());
        assert!(rp("https://192.168.1.1", None).is_err());
        assert!(rp("https://[::1]", None).is_err());
        assert!(rp("ftp://example.com", None).is_err());
        assert!(rp("not a url", None).is_err());
        // IDN RP IDs are compared in punycode.
        assert_eq!(
            rp("https://www.bücher.example", Some("bücher.example")).unwrap(),
            "xn--bcher-kva.example"
        );
    }

    #[test]
    fn origin_serialization() {
        assert_eq!(
            parse_origin("https://example.com/login")
                .unwrap()
                .serialized,
            "https://example.com"
        );
        assert_eq!(
            parse_origin("https://example.com:443").unwrap().serialized,
            "https://example.com"
        );
        assert_eq!(
            parse_origin("https://example.com:8443/")
                .unwrap()
                .serialized,
            "https://example.com:8443"
        );
        assert_eq!(
            parse_origin("http://localhost:8080").unwrap().serialized,
            "http://localhost:8080"
        );
    }
}
