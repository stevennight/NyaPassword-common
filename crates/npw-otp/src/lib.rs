//! One-time passwords: TOTP (RFC 6238), HOTP (RFC 4226), Steam Guard, and
//! `otpauth://` URIs (or bare base32 secrets, as many sites show them).

use hmac::{Hmac, Mac};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OtpError {
    #[error("not a valid otpauth URI or base32 secret")]
    Invalid,
    #[error("unsupported algorithm")]
    Algorithm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Totp,
    Hotp,
    Steam,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpSpec {
    pub kind: Kind,
    pub secret: Vec<u8>,
    pub algorithm: Algorithm,
    pub digits: u32,
    /// Seconds (TOTP / Steam).
    pub period: u64,
    /// HOTP counter.
    pub counter: u64,
    pub issuer: String,
    pub account: String,
}

/// RFC 4648 base32, case-insensitive, ignoring spaces, dashes and padding.
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut buf: u64 = 0;
    let mut bits = 0;
    for c in s.chars() {
        if c == ' ' || c == '-' || c == '=' {
            continue;
        }
        let v = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u64 - 'A' as u64,
            c @ '2'..='7' => c as u64 - '2' as u64 + 26,
            _ => return None,
        };
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    (!out.is_empty()).then_some(out)
}

pub fn base32_encode(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[((buf >> bits) & 31) as usize] as char);
        }
        buf &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(A[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

impl OtpSpec {
    /// Parses an `otpauth://totp/...`, `otpauth://hotp/...`, `steam://SECRET`
    /// URI, or a bare base32 secret (TOTP, SHA-1, 6 digits, 30 s).
    pub fn parse(input: &str) -> Result<Self, OtpError> {
        let s = input.trim();
        let blank = |kind, secret, digits| Self {
            kind,
            secret,
            algorithm: Algorithm::Sha1,
            digits,
            period: 30,
            counter: 0,
            issuer: String::new(),
            account: String::new(),
        };
        if let Some(secret) = s.strip_prefix("steam://") {
            let mut spec = blank(Kind::Steam, base32_decode(secret).ok_or(OtpError::Invalid)?, 5);
            spec.issuer = "Steam".into();
            return Ok(spec);
        }
        if !s.to_ascii_lowercase().starts_with("otpauth://") {
            return Ok(blank(Kind::Totp, base32_decode(s).ok_or(OtpError::Invalid)?, 6));
        }
        let u = url::Url::parse(s).map_err(|_| OtpError::Invalid)?;
        let mut kind = match u.host_str().map(str::to_ascii_lowercase).as_deref() {
            Some("totp") => Kind::Totp,
            Some("hotp") => Kind::Hotp,
            Some("steam") => Kind::Steam,
            _ => return Err(OtpError::Invalid),
        };
        let label = percent_decode(u.path().trim_start_matches('/'));
        let (mut issuer, account) = match label.split_once(':') {
            Some((i, a)) => (i.trim().to_string(), a.trim().to_string()),
            None => (String::new(), label.trim().to_string()),
        };
        let mut secret = None;
        let mut algorithm = Algorithm::Sha1;
        let mut digits = 6;
        let mut period = 30;
        let mut counter = 0;
        for (k, v) in u.query_pairs() {
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = base32_decode(&v),
                "algorithm" => {
                    algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => return Err(OtpError::Algorithm),
                    }
                }
                "digits" => digits = v.parse().map_err(|_| OtpError::Invalid)?,
                "period" => period = v.parse().map_err(|_| OtpError::Invalid)?,
                "counter" => counter = v.parse().map_err(|_| OtpError::Invalid)?,
                "issuer" => issuer = v.to_string(),
                "encoder" if v.eq_ignore_ascii_case("steam") => kind = Kind::Steam,
                _ => {}
            }
        }
        if kind == Kind::Steam {
            digits = 5;
        }
        if !(1..=10).contains(&digits) || period == 0 {
            return Err(OtpError::Invalid);
        }
        Ok(Self { kind, secret: secret.ok_or(OtpError::Invalid)?, algorithm, digits, period, counter, issuer, account })
    }

    /// The code at `unix_secs` (TOTP / Steam) or for the stored counter (HOTP).
    pub fn code(&self, unix_secs: u64) -> String {
        let counter = match self.kind {
            Kind::Hotp => self.counter,
            _ => unix_secs / self.period,
        };
        let v = hotp_value(&self.secret, counter, self.algorithm);
        if self.kind == Kind::Steam {
            const CHARS: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";
            let mut n = v as usize;
            let mut s = String::new();
            for _ in 0..5 {
                s.push(CHARS[n % CHARS.len()] as char);
                n /= CHARS.len();
            }
            return s;
        }
        let m = 10u64.pow(self.digits);
        format!("{:0width$}", v as u64 % m, width = self.digits as usize)
    }

    /// Seconds until the current code changes (TOTP / Steam).
    pub fn remaining(&self, unix_secs: u64) -> u64 {
        self.period - unix_secs % self.period
    }

    pub fn to_uri(&self) -> String {
        let kind = if self.kind == Kind::Hotp { "hotp" } else { "totp" };
        let label = if self.issuer.is_empty() { self.account.clone() } else { format!("{}:{}", self.issuer, self.account) };
        let alg = match self.algorithm {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        };
        let mut u = format!(
            "otpauth://{kind}/{}?secret={}&algorithm={alg}&digits={}&period={}",
            percent_encode(&label),
            base32_encode(&self.secret),
            self.digits,
            self.period
        );
        if self.kind == Kind::Hotp {
            u.push_str(&format!("&counter={}", self.counter));
        }
        if self.kind == Kind::Steam {
            u.push_str("&encoder=steam");
        }
        if !self.issuer.is_empty() {
            u.push_str(&format!("&issuer={}", percent_encode(&self.issuer)));
        }
        u
    }
}

fn hotp_value(secret: &[u8], counter: u64, alg: Algorithm) -> u32 {
    let msg = counter.to_be_bytes();
    let h: Vec<u8> = match alg {
        Algorithm::Sha1 => {
            let mut m = Hmac::<sha1::Sha1>::new_from_slice(secret).expect("any key length");
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha256 => {
            let mut m = Hmac::<sha2::Sha256>::new_from_slice(secret).expect("any key length");
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha512 => {
            let mut m = Hmac::<sha2::Sha512>::new_from_slice(secret).expect("any key length");
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
    };
    let off = (h[h.len() - 1] & 0x0f) as usize;
    u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]])
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn percent_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~@".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(alg: Algorithm, secret: &[u8], kind: Kind, digits: u32, counter: u64) -> OtpSpec {
        OtpSpec { kind, secret: secret.to_vec(), algorithm: alg, digits, period: 30, counter, issuer: String::new(), account: String::new() }
    }

    // RFC 6238 appendix B.
    #[test]
    fn rfc6238() {
        let sha1 = spec(Algorithm::Sha1, b"12345678901234567890", Kind::Totp, 8, 0);
        let sha256 = spec(Algorithm::Sha256, b"12345678901234567890123456789012", Kind::Totp, 8, 0);
        let sha512 = spec(Algorithm::Sha512, b"1234567890123456789012345678901234567890123456789012345678901234", Kind::Totp, 8, 0);
        for (s, t, code) in [
            (&sha1, 59u64, "94287082"),
            (&sha1, 1111111109, "07081804"),
            (&sha1, 20000000000, "65353130"),
            (&sha256, 59, "46119246"),
            (&sha256, 1111111109, "68084774"),
            (&sha256, 20000000000, "77737706"),
            (&sha512, 59, "90693936"),
            (&sha512, 1111111109, "25091201"),
            (&sha512, 20000000000, "47863826"),
        ] {
            assert_eq!(s.code(t), code, "{:?} at {t}", s.algorithm);
        }
    }

    // RFC 4226 appendix D.
    #[test]
    fn rfc4226() {
        for (c, e) in ["755224", "287082", "359152", "969429", "338314"].iter().enumerate() {
            assert_eq!(spec(Algorithm::Sha1, b"12345678901234567890", Kind::Hotp, 6, c as u64).code(0), *e);
        }
    }

    #[test]
    fn parse_uris() {
        let s = OtpSpec::parse("otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub").unwrap();
        assert_eq!((s.issuer.as_str(), s.account.as_str(), s.digits, s.period), ("GitHub", "octocat", 6, 30));
        assert_eq!(s.secret, b"Hello!\xde\xad\xbe\xef");
        assert_eq!(OtpSpec::parse(&s.to_uri()).unwrap(), s);
        assert_eq!(OtpSpec::parse("jbsw y3dp ehpk 3pxp").unwrap().secret, s.secret);
        let label = OtpSpec::parse("otpauth://totp/%E7%A4%BA%E4%BE%8B:me%40example.com?secret=JBSWY3DP").unwrap();
        assert_eq!((label.issuer.as_str(), label.account.as_str()), ("示例", "me@example.com"));
        assert!(OtpSpec::parse("otpauth://totp/x?secret=").is_err());
        assert!(OtpSpec::parse("hello world!").is_err());
        assert_eq!(OtpSpec::parse("steam://JBSWY3DPEHPK3PXP").unwrap().code(0).len(), 5);
        assert_eq!(base32_decode(&base32_encode(b"any bytes \x00\xff")).unwrap(), b"any bytes \x00\xff");
    }
}
