//! Server backup archives (design doc §8.2):
//!
//! ```text
//! nyapassword-<UTC time>-s<max seq>.tar.zst.age
//!   manifest.json   format, times, counts, per-vault sequence numbers, SHA-256 of every file
//!   db.sqlite3      consistent snapshot of the server database
//!   server.key      the server's own secrets (target credentials key, OPAQUE setup lives in the db)
//! ```
//!
//! Encrypted with age to every recipient: the server's own key (automatic
//! restore drills) plus the user's offline key(s) from the Emergency Kit.
//! Attachments are uploaded separately as `attachments/<id>`; they are already
//! end-to-end encrypted.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;

use age::secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

pub const FORMAT: u32 = 1;
pub const PREFIX: &str = "backups/";
pub const ATTACHMENT_PREFIX: &str = "attachments/";

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("age: {0}")]
    Age(String),
    #[error("archive: {0}")]
    Archive(String),
    #[error("archive file {0} does not match the manifest")]
    Checksum(String),
    #[error("archive has no manifest")]
    NoManifest,
    #[error("unsupported archive format {0}")]
    Format(u32),
}

pub type Result<T> = std::result::Result<T, BackupError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    pub format: u32,
    pub created_at: i64,
    pub server_version: String,
    /// The server database epoch at backup time.
    pub epoch: String,
    pub accounts: i64,
    pub items: i64,
    pub revisions: i64,
    pub attachments: i64,
    /// vault id → sequence number.
    pub vaults: BTreeMap<String, i64>,
    /// file name → hex SHA-256.
    pub files: BTreeMap<String, String>,
}

impl Manifest {
    pub fn max_seq(&self) -> i64 {
        self.vaults.values().copied().max().unwrap_or(0)
    }
}

/// An age X25519 key pair: (identity `AGE-SECRET-KEY-1...`, recipient `age1...`).
pub fn generate_identity() -> (String, String) {
    let id = age::x25519::Identity::generate();
    (id.to_string().expose_secret().to_string(), id.to_public().to_string())
}

pub fn recipient_of(identity: &str) -> Result<String> {
    let id: age::x25519::Identity = identity.trim().parse().map_err(|e: &str| BackupError::Age(e.to_string()))?;
    Ok(id.to_public().to_string())
}

pub fn valid_recipient(r: &str) -> bool {
    r.trim().parse::<age::x25519::Recipient>().is_ok()
}

/// Builds the archive and encrypts it. `files`: (name, content); the manifest's
/// `files` map is filled in here.
pub fn seal(mut manifest: Manifest, files: &[(&str, &[u8])], recipients: &[String]) -> Result<Vec<u8>> {
    manifest.format = FORMAT;
    manifest.files = files.iter().map(|(n, d)| (n.to_string(), npw_crypto::sha256_hex(d))).collect();
    let manifest_json = serde_json::to_vec_pretty(&manifest).map_err(|e| BackupError::Archive(e.to_string()))?;

    let mut tar_buf = Vec::new();
    {
        let mut b = tar::Builder::new(&mut tar_buf);
        let add = |b: &mut tar::Builder<&mut Vec<u8>>, name: &str, data: &[u8]| -> Result<()> {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o600);
            h.set_mtime((manifest.created_at / 1000).max(0) as u64);
            h.set_cksum();
            b.append_data(&mut h, name, data).map_err(|e| BackupError::Archive(e.to_string()))
        };
        add(&mut b, "manifest.json", &manifest_json)?;
        for (name, data) in files {
            add(&mut b, name, data)?;
        }
        b.finish().map_err(|e| BackupError::Archive(e.to_string()))?;
    }
    let compressed = zstd::encode_all(&tar_buf[..], 9).map_err(|e| BackupError::Archive(e.to_string()))?;

    let parsed: Vec<age::x25519::Recipient> = recipients
        .iter()
        .map(|r| r.trim().parse::<age::x25519::Recipient>().map_err(|e| BackupError::Age(format!("bad recipient {r}: {e}"))))
        .collect::<Result<_>>()?;
    if parsed.is_empty() {
        return Err(BackupError::Age("no recipients".into()));
    }
    let enc = age::Encryptor::with_recipients(parsed.iter().map(|r| r as &dyn age::Recipient)).map_err(|e| BackupError::Age(e.to_string()))?;
    let mut out = vec![];
    let mut w = enc.wrap_output(&mut out).map_err(|e| BackupError::Age(e.to_string()))?;
    w.write_all(&compressed).map_err(|e| BackupError::Age(e.to_string()))?;
    w.finish().map_err(|e| BackupError::Age(e.to_string()))?;
    Ok(out)
}

/// Decrypts and unpacks an archive in memory, verifying every file against the manifest.
pub fn open(data: &[u8], identities: &[String]) -> Result<(Manifest, BTreeMap<String, Vec<u8>>)> {
    let ids: Vec<age::x25519::Identity> =
        identities.iter().map(|i| i.trim().parse::<age::x25519::Identity>().map_err(|e: &str| BackupError::Age(e.to_string()))).collect::<Result<_>>()?;
    let dec = age::Decryptor::new_buffered(data).map_err(|e| BackupError::Age(e.to_string()))?;
    let mut r = dec.decrypt(ids.iter().map(|i| i as &dyn age::Identity)).map_err(|e| BackupError::Age(e.to_string()))?;
    let mut compressed = vec![];
    r.read_to_end(&mut compressed).map_err(|e| BackupError::Age(e.to_string()))?;
    let tar_bytes = zstd::decode_all(&compressed[..]).map_err(|e| BackupError::Archive(e.to_string()))?;

    let mut files = BTreeMap::new();
    let mut a = tar::Archive::new(&tar_bytes[..]);
    for entry in a.entries().map_err(|e| BackupError::Archive(e.to_string()))? {
        let mut entry = entry.map_err(|e| BackupError::Archive(e.to_string()))?;
        let name = entry.path().map_err(|e| BackupError::Archive(e.to_string()))?.to_string_lossy().to_string();
        let mut buf = vec![];
        entry.read_to_end(&mut buf).map_err(|e| BackupError::Archive(e.to_string()))?;
        files.insert(name, buf);
    }
    let manifest: Manifest = serde_json::from_slice(files.get("manifest.json").ok_or(BackupError::NoManifest)?).map_err(|e| BackupError::Archive(e.to_string()))?;
    if manifest.format != FORMAT {
        return Err(BackupError::Format(manifest.format));
    }
    for (name, sum) in &manifest.files {
        let data = files.get(name).ok_or_else(|| BackupError::Checksum(name.clone()))?;
        if &npw_crypto::sha256_hex(data) != sum {
            return Err(BackupError::Checksum(name.clone()));
        }
    }
    files.remove("manifest.json");
    Ok((manifest, files))
}

/// Writes the files of an opened archive into `dir` (which must not contain them yet).
pub fn extract_to(files: &BTreeMap<String, Vec<u8>>, dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| BackupError::Archive(e.to_string()))?;
    for (name, data) in files {
        if name.contains("..") || name.contains('/') || name.contains('\\') {
            return Err(BackupError::Archive(format!("unexpected file name {name}")));
        }
        let p = dir.join(name);
        if p.exists() {
            return Err(BackupError::Archive(format!("{} already exists", p.display())));
        }
        std::fs::write(&p, data).map_err(|e| BackupError::Archive(e.to_string()))?;
    }
    Ok(())
}

/// `backups/nyapassword-20261004T120000Z-s000123.tar.zst.age`
pub fn object_name(created_at_ms: i64, max_seq: i64) -> String {
    format!("{PREFIX}nyapassword-{}-s{max_seq:09}.tar.zst.age", utc_stamp(created_at_ms))
}

/// Parses the time back out of an object name (for retention).
pub fn object_time(name: &str) -> Option<i64> {
    let base = name.rsplit('/').next()?;
    let stamp = base.strip_prefix("nyapassword-")?.get(..16)?;
    parse_stamp(stamp)
}

/// `YYYYMMDDTHHMMSSZ`
pub fn utc_stamp(ms: i64) -> String {
    let (y, mo, d, h, mi, s) = civil(ms.div_euclid(1000));
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

fn civil(secs: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Howard Hinnant's days-to-civil
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d, rem / 3600, rem % 3600 / 60, rem % 60)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn parse_stamp(s: &str) -> Option<i64> {
    if s.len() != 16 || &s[8..9] != "T" || &s[15..16] != "Z" {
        return None;
    }
    let n = |a: usize, b: usize| s.get(a..b)?.parse::<i64>().ok();
    let days = days_from_civil(n(0, 4)?, n(4, 6)?, n(6, 8)?);
    Some((days * 86_400 + n(9, 11)? * 3600 + n(11, 13)? * 60 + n(13, 15)?) * 1000)
}

/// Grandfather-father-son retention: which of `times` (ms, any order) to keep.
/// Keeps the newest `recent`, plus the newest backup of each of the last
/// `daily` days, `weekly` weeks and `monthly` months. Never returns an empty
/// set when `times` is not empty.
pub fn retain(times: &[i64], recent: usize, daily: usize, weekly: usize, monthly: usize) -> Vec<i64> {
    let mut sorted: Vec<i64> = times.to_vec();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    sorted.dedup();
    let mut keep: std::collections::BTreeSet<i64> = sorted.iter().take(recent.max(1)).copied().collect();
    let mut bucket = |key: &dyn Fn(i64) -> i64, n: usize| {
        let mut seen = std::collections::BTreeSet::new();
        for &t in &sorted {
            if seen.len() >= n {
                break;
            }
            if seen.insert(key(t)) {
                keep.insert(t);
            }
        }
    };
    bucket(&|t| t.div_euclid(86_400_000), daily);
    // weeks starting Monday (1970-01-01 was a Thursday)
    bucket(&|t| (t.div_euclid(86_400_000) + 3).div_euclid(7), weekly);
    bucket(
        &|t| {
            let (y, m, ..) = civil(t.div_euclid(1000));
            y * 12 + m
        },
        monthly,
    );
    keep.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let (srv_id, srv_pub) = generate_identity();
        let (off_id, off_pub) = generate_identity();
        let m = Manifest {
            format: 0,
            created_at: 1_759_536_000_000,
            server_version: "0.1.0".into(),
            epoch: "e".into(),
            accounts: 1,
            items: 2,
            revisions: 3,
            attachments: 0,
            vaults: [("v".to_string(), 7)].into(),
            files: Default::default(),
        };
        let data = seal(m.clone(), &[("db.sqlite3", b"db bytes"), ("server.key", b"key")], &[srv_pub, off_pub]).unwrap();
        for id in [srv_id, off_id] {
            let (got, files) = open(&data, &[id]).unwrap();
            assert_eq!(got.items, 2);
            assert_eq!(got.max_seq(), 7);
            assert_eq!(files["db.sqlite3"], b"db bytes");
        }
        let (wrong, _) = generate_identity();
        assert!(open(&data, &[wrong]).is_err());
    }

    #[test]
    fn names_and_times() {
        let t = 1_759_579_445_000; // 2025-10-04T12:04:05Z
        assert_eq!(utc_stamp(t), "20251004T120405Z");
        let name = object_name(t, 42);
        assert_eq!(name, "backups/nyapassword-20251004T120405Z-s000000042.tar.zst.age");
        assert_eq!(object_time(&name), Some(t));
        assert_eq!(utc_stamp(0), "19700101T000000Z");
        assert_eq!(parse_stamp("20240229T235959Z"), Some(1_709_251_199_000));
    }

    #[test]
    fn gfs_retention() {
        let hour = 3_600_000;
        let start = 1_759_536_000_000;
        // one backup every 6 hours for 400 days
        let times: Vec<i64> = (0..1600).map(|i| start + i * 6 * hour).collect();
        let keep = retain(&times, 4, 7, 4, 12);
        assert!(keep.contains(times.last().unwrap()));
        assert!(keep.len() <= 4 + 7 + 4 + 12);
        assert!(keep.len() >= 12);
        assert_eq!(retain(&[5], 0, 0, 0, 0), vec![5]);
        assert!(retain(&[], 1, 1, 1, 1).is_empty());
    }
}
