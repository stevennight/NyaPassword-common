//! A profile: one device's local replica in a directory.
//!
//! - `replica.sqlite3`: the local replica (ciphertext only).
//! - `device.key`: the device key, hex. Real clients keep it in the OS key
//!   store; this developer tool keeps it next to the replica.
//! - `unlock.key`: the account key, hex, while the profile is unlocked, so
//!   later commands need no password. Written by `register`, `login` and
//!   `unlock`, removed by `lock`. Whoever can read it can decrypt the vault:
//!   development only.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use npw_core::{Client, ClientConfig, CoreError, Key32};
use npw_store_sqlite::SqliteStore;

const REPLICA: &str = "replica.sqlite3";
const DEVICE_KEY: &str = "device.key";
const UNLOCK_KEY: &str = "unlock.key";

pub struct Profile {
    pub dir: PathBuf,
}

pub struct Opened {
    pub client: Client,
    pub store: Arc<SqliteStore>,
}

impl Profile {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// The device key of this profile, created on first use.
    fn device_key(&self) -> Result<Key32> {
        let p = self.path(DEVICE_KEY);
        if p.exists() {
            let text = std::fs::read_to_string(&p).with_context(|| p.display().to_string())?;
            let raw = hex::decode(text.trim()).context("device.key is not hex")?;
            return Ok(Key32::from_slice(&raw)?);
        }
        std::fs::create_dir_all(&self.dir).with_context(|| self.dir.display().to_string())?;
        let k = Key32::generate();
        std::fs::write(&p, hex::encode(k.as_bytes())).with_context(|| p.display().to_string())?;
        Ok(k)
    }

    /// Opens the replica and the client over it (locked).
    pub fn open(&self, device_name: &str) -> Result<Opened> {
        let key = self.device_key()?;
        let store = Arc::new(SqliteStore::open(&self.path(REPLICA))?);
        let mut cfg = ClientConfig::new(device_name, "cli", env!("CARGO_PKG_VERSION"));
        cfg.locale = "en".into();
        let client = Client::new(cfg, store.clone(), key)?;
        Ok(Opened { client, store })
    }

    /// Remembers the account key so later commands start unlocked.
    pub fn save_unlock(&self, c: &Client) -> Result<()> {
        let p = self.path(UNLOCK_KEY);
        std::fs::write(&p, hex::encode(c.quick_unlock_key()?))
            .with_context(|| p.display().to_string())
    }

    pub fn unlock_key(&self) -> Result<Option<Vec<u8>>> {
        let p = self.path(UNLOCK_KEY);
        if !p.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&p).with_context(|| p.display().to_string())?;
        Ok(Some(
            hex::decode(text.trim()).context("unlock.key is not hex")?,
        ))
    }

    /// Forgets the remembered account key. Returns whether there was one.
    pub fn clear_unlock(&self) -> Result<bool> {
        let p = self.path(UNLOCK_KEY);
        if !p.exists() {
            return Ok(false);
        }
        std::fs::remove_file(&p).with_context(|| p.display().to_string())?;
        Ok(true)
    }

    pub fn is_unlocked(&self) -> bool {
        self.path(UNLOCK_KEY).exists()
    }
}

/// Where the master password comes from: `--master-password` (insecure), the
/// environment variable named by `--password-env`, or a prompt.
pub struct PasswordSource {
    pub explicit: Option<String>,
    pub env: String,
}

impl PasswordSource {
    /// A password given without asking (flag or environment variable).
    pub fn given(&self) -> Option<String> {
        if let Some(p) = &self.explicit {
            return Some(p.clone());
        }
        std::env::var(&self.env).ok().filter(|p| !p.is_empty())
    }

    pub fn get(&self, prompt: &str) -> Result<String> {
        match self.given() {
            Some(p) => Ok(p),
            None => prompt_password(prompt),
        }
    }

    /// For a new password: asks twice when prompting.
    pub fn get_new(&self) -> Result<String> {
        if let Some(p) = self.given() {
            return Ok(p);
        }
        let a = prompt_password("New master password: ")?;
        let b = prompt_password("Repeat it: ")?;
        if a != b {
            bail!("the passwords differ");
        }
        Ok(a)
    }
}

/// Asks on the terminal without echo; with stdin redirected, reads one line from it.
pub fn prompt_password(prompt: &str) -> Result<String> {
    use std::io::IsTerminal;
    let p = if std::io::stdin().is_terminal() {
        rpassword::prompt_password(prompt).context("reading the password")?
    } else {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("reading the password from stdin")?;
        line.trim_end_matches(['\r', '\n']).to_string()
    };
    if p.is_empty() {
        bail!("empty password");
    }
    Ok(p)
}

/// Opens a signed-in profile and unlocks it: with a given password, else with
/// the remembered key, else with a prompted password.
pub fn open_unlocked(profile: &Profile, device_name: &str, pw: &PasswordSource) -> Result<Opened> {
    let o = profile.open(device_name)?;
    if !o.client.lock_state().signed_in {
        bail!(
            "profile {} is not signed in: run `register` or `login` first",
            profile.dir.display()
        );
    }
    if let Some(p) = pw.given() {
        o.client.unlock(&p)?;
        return Ok(o);
    }
    if let Some(k) = profile.unlock_key()? {
        match o.client.unlock_with_key(&k) {
            Ok(()) => return Ok(o),
            Err(CoreError::WrongPassword) => {
                eprintln!("the remembered key no longer works; forgetting it");
                profile.clear_unlock()?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    o.client.unlock(&prompt_password("Master password: ")?)?;
    Ok(o)
}
