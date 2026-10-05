//! Multi-device tests against a real server over HTTP.
//!
//! `stress`: N devices (one account, the others signed in with the Secret
//! Key) run random operations concurrently: create, edit, delete, restore,
//! offline stretches, app restarts, syncs (some cancelled half-way).
//! `kill-test`: the same devices push while a server process is killed and
//! restarted.
//!
//! Afterwards both check that
//! - every value a device held when it started a sync that then completed is
//!   on the server (in an item, its conflicts or password history, or an older
//!   revision). Values held only during a cancelled or failed sync may have been
//!   overwritten locally before ever leaving the device; they are counted, not checked;
//! - every device's replica digest equals the server's, all devices hold the
//!   same content, nothing is left pending and every item decrypts.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use npw_core::{Client, CoreError, ItemFilter, Store, SyncReport};
use npw_model::{Field, ItemContent};
use npw_store_sqlite::SqliteStore;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::profile::Profile;

#[derive(Args)]
pub struct StressArgs {
    /// Server URL, e.g. http://127.0.0.1:8087
    #[arg(long)]
    server: String,
    #[arg(long, default_value_t = 3)]
    devices: usize,
    /// Operations in total, spread over the devices.
    #[arg(long, default_value_t = 300)]
    ops: usize,
    /// Random seed (default: from the clock; printed).
    #[arg(long)]
    seed: Option<u64>,
    /// Directory for the device profiles (default: a new one under the temp directory).
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Invite code, when the server only registers accounts with one.
    #[arg(long)]
    invite: Option<String>,
    /// Keep the temporary profile directory after a successful run (kept on failure, and a --dir is never deleted).
    #[arg(long)]
    keep: bool,
}

#[derive(Args)]
pub struct KillArgs {
    /// The server executable. Copy it out of the target directory first: a
    /// running executable cannot be rebuilt on Windows.
    #[arg(long)]
    server_bin: PathBuf,
    /// The server's data directory (default: <dir>/server-data). Use a throwaway one.
    #[arg(long)]
    data: Option<PathBuf>,
    #[arg(long, default_value_t = 3)]
    devices: usize,
    /// Kill-and-restart rounds.
    #[arg(long, default_value_t = 15)]
    rounds: usize,
    /// Local edits per device before each round's sync.
    #[arg(long, default_value_t = 8)]
    edits: usize,
    #[arg(long)]
    seed: Option<u64>,
    /// Directory for the device profiles and the server log (default: a new one under the temp directory).
    #[arg(long)]
    dir: Option<PathBuf>,
    /// Keep the temporary directory after a successful run (kept on failure, and a --dir is never deleted).
    #[arg(long)]
    keep: bool,
}

// ------------------------------------------------------------------ devices

struct Device {
    idx: usize,
    name: String,
    profile: Profile,
    client: Client,
    store: Arc<SqliteStore>,
    password: String,
    counter: u64,
}

impl Device {
    fn tok(&mut self) -> String {
        self.counter += 1;
        format!("tok-{}-{}", self.idx, self.counter)
    }

    /// The app is killed and started again: a new client over the replica on disk.
    fn restart(&mut self) -> Result<()> {
        let o = self.profile.open(&self.name)?;
        o.client.unlock(&self.password)?;
        self.client = o.client;
        self.store = o.store;
        Ok(())
    }
}

#[derive(Default, Clone)]
struct Stats {
    creates: usize,
    edits: usize,
    deletes: usize,
    restores: usize,
    restarts: usize,
    offline: usize,
    syncs: usize,
    cancelled: usize,
    failed_syncs: usize,
    pushed: usize,
    pulled: usize,
    merged: usize,
    conflicts: usize,
    rejected: usize,
    full_resyncs: usize,
}

impl Stats {
    fn add(&mut self, o: &Stats) {
        self.creates += o.creates;
        self.edits += o.edits;
        self.deletes += o.deletes;
        self.restores += o.restores;
        self.restarts += o.restarts;
        self.offline += o.offline;
        self.syncs += o.syncs;
        self.cancelled += o.cancelled;
        self.failed_syncs += o.failed_syncs;
        self.pushed += o.pushed;
        self.pulled += o.pulled;
        self.merged += o.merged;
        self.conflicts += o.conflicts;
        self.rejected += o.rejected;
        self.full_resyncs += o.full_resyncs;
    }

    fn sync_done(&mut self, r: &SyncReport) {
        self.syncs += 1;
        self.pushed += r.pushed;
        self.pulled += r.pulled;
        self.merged += r.merged;
        self.conflicts += r.conflicts;
        self.rejected += r.rejected;
        self.full_resyncs += r.full_resyncs;
    }

    fn print(&self) {
        println!(
            "  ops:    {} creates, {} edits, {} deletes, {} restores, {} restarts, {} offline stretches",
            self.creates, self.edits, self.deletes, self.restores, self.restarts, self.offline
        );
        println!(
            "  syncs:  {} completed, {} cancelled, {} failed; pushed {}, pulled {}, merged {}, conflicts {}, rejected {}, full resyncs {}",
            self.syncs,
            self.cancelled,
            self.failed_syncs,
            self.pushed,
            self.pulled,
            self.merged,
            self.conflicts,
            self.rejected,
            self.full_resyncs
        );
    }
}

/// Which written values must survive.
#[derive(Default)]
struct Ledger {
    /// Tokens a device held when a sync began that then completed: they must be on the server.
    committed: HashSet<String>,
    /// Tokens a device held when a sync began that was cancelled or failed. A later
    /// local edit may overwrite them before they ever reach the server, which is
    /// not a loss; reported, not checked.
    unconfirmed: HashSet<String>,
}

type Committed = Arc<Mutex<Ledger>>;

fn confirm(ledger: &Committed, tokens: HashSet<String>, synced: bool) {
    let mut l = ledger.lock().expect("ledger");
    if synced {
        l.committed.extend(tokens);
    } else {
        l.unconfirmed.extend(tokens);
    }
}

/// The directory for the device profiles, and whether it is a temporary one to delete after success.
fn work_dir(dir: Option<PathBuf>, kind: &str, seed: u64) -> Result<(PathBuf, bool)> {
    let temporary = dir.is_none();
    let d = dir.unwrap_or_else(|| {
        std::env::temp_dir().join(format!("npw-dev-{kind}-{seed}-{}", npw_model::now_ms()))
    });
    std::fs::create_dir_all(&d).with_context(|| d.display().to_string())?;
    Ok((d, temporary))
}

/// Registers an account on the first device and signs the others in with its Secret Key.
async fn setup_devices(
    server: &str,
    n: usize,
    dir: &Path,
    seed: u64,
    invite: Option<&str>,
) -> Result<(Vec<Device>, String)> {
    if n == 0 {
        bail!("need at least one device");
    }
    let email = format!("stress-{seed}-{}@example.com", npw_model::now_ms());
    let password = format!("pw-{}", hex::encode(npw_core::Key32::generate().as_bytes()));
    let mut devices = vec![];
    let mut secret_key = String::new();
    for idx in 0..n {
        let name = format!("dev{idx}");
        let profile = Profile::new(dir.join(&name));
        let o = profile.open(&name)?;
        if idx == 0 {
            let kit = o
                .client
                .register(server, &email, &password, invite)
                .await
                .context("register")?;
            secret_key = kit.secret_key;
        } else {
            o.client
                .sign_in(server, &email, &password, &secret_key)
                .await
                .with_context(|| format!("sign in {name}"))?;
        }
        // lets `npw-dev --profile <dir>/devN ...` inspect the replica afterwards
        profile.save_unlock(&o.client)?;
        o.client
            .sync()
            .await
            .with_context(|| format!("first sync of {name}"))?;
        devices.push(Device {
            idx,
            name,
            profile,
            client: o.client,
            store: o.store,
            password: password.clone(),
            counter: 0,
        });
    }
    let vault = devices[0]
        .client
        .vaults()?
        .first()
        .map(|v| v.id.clone())
        .ok_or_else(|| anyhow!("no vault"))?;
    println!(
        "  account {email}, vault {vault}, profiles in {}",
        dir.display()
    );
    Ok((devices, vault))
}

fn login_item(dev: &mut Device) -> ItemContent {
    let t = dev.tok();
    let mut it = npw_model::template("login")
        .expect("login template")
        .new_item("en");
    it.title = format!("Item {t}");
    let user = dev.tok();
    let pw = dev.tok();
    if let Some(f) = it.field_mut("username") {
        f.value = user.into();
    }
    if let Some(f) = it.field_mut("password") {
        f.value = pw.into();
    }
    it.urls
        .push(npw_model::UrlEntry::new("https://item.example.com/login"));
    it
}

/// One random local edit. `roll` in 0..68 picks the kind (create 15, edit 45, delete 5, restore 3).
fn random_edit(
    dev: &mut Device,
    vault: &str,
    roll: u32,
    rng: &mut StdRng,
    st: &mut Stats,
) -> Result<()> {
    let items = dev.client.list_items(&ItemFilter {
        vault_id: Some(vault.into()),
        ..Default::default()
    })?;
    let trash = dev.client.list_items(&ItemFilter {
        vault_id: Some(vault.into()),
        trash: true,
        ..Default::default()
    })?;
    match roll {
        15..=59 if !items.is_empty() => {
            let id = items[rng.gen_range(0..items.len())].item_id.clone();
            let mut c = dev
                .client
                .item(vault, &id)?
                .content
                .ok_or_else(|| anyhow!("no content"))?;
            match rng.gen_range(0..5) {
                0 => {
                    let t = dev.tok();
                    if let Some(f) = c.field_mut("password") {
                        f.value = t.into();
                    }
                }
                1 => {
                    let t = dev.tok();
                    if let Some(f) = c.field_mut("username") {
                        f.value = t.into();
                    }
                }
                2 => c.notes = format!("{}{}\n", c.notes, dev.tok()),
                3 => {
                    let t = dev.tok();
                    c.fields.push(
                        Field::new(npw_model::new_short_id("f"), "extra", "text").with_value(t),
                    );
                }
                _ => c.tags.push(dev.tok()),
            }
            dev.client
                .save_item(vault, Some(&id), c)
                .with_context(|| format!("{} edit {id}", dev.name))?;
            st.edits += 1;
        }
        60..=64 if !items.is_empty() => {
            let id = &items[rng.gen_range(0..items.len())].item_id;
            dev.client.delete_item(vault, id)?;
            st.deletes += 1;
        }
        65..=67 if !trash.is_empty() => {
            let id = &trash[rng.gen_range(0..trash.len())].item_id;
            dev.client.restore_item(vault, id)?;
            st.restores += 1;
        }
        _ => {
            let it = login_item(dev);
            dev.client.save_item(vault, None, it)?;
            st.creates += 1;
        }
    }
    Ok(())
}

fn all_strings(v: &serde_json::Value, out: &mut HashSet<String>) {
    match v {
        serde_json::Value::String(s) => {
            out.insert(s.clone());
            for line in s.lines() {
                out.insert(line.to_string());
            }
            for word in s.split_whitespace() {
                out.insert(word.to_string());
            }
        }
        serde_json::Value::Array(a) => a.iter().for_each(|x| all_strings(x, out)),
        serde_json::Value::Object(o) => o.values().for_each(|x| all_strings(x, out)),
        _ => {}
    }
}

fn tokens_of(c: &ItemContent) -> HashSet<String> {
    let mut s = HashSet::new();
    all_strings(&serde_json::to_value(c).expect("serializable"), &mut s);
    s.into_iter().filter(|t| t.starts_with("tok-")).collect()
}

/// Every token in the device's items (current content, conflicts, password history).
fn device_tokens(c: &Client) -> Result<HashSet<String>> {
    let mut out = HashSet::new();
    for v in crate::all_items(c)? {
        if let Some(content) = c.item(&v.vault_id, &v.item_id)?.content {
            out.extend(tokens_of(&content));
        }
    }
    Ok(out)
}

/// A sync, retried on network errors (pooled connections die when the server restarts).
async fn sync_retry(dev: &Device, st: &mut Stats) -> Result<()> {
    let mut last = None;
    for attempt in 0..5 {
        match dev.client.sync().await {
            Ok(r) => {
                st.sync_done(&r);
                return Ok(());
            }
            Err(e @ CoreError::Network(_)) => {
                last = Some(e);
                tokio::time::sleep(Duration::from_millis(200 * (attempt + 1))).await;
            }
            Err(e) => return Err(anyhow!("{}: sync failed: {e}", dev.name)),
        }
    }
    Err(anyhow!(
        "{}: sync failed: {}",
        dev.name,
        last.map(|e| e.to_string()).unwrap_or_default()
    ))
}

/// Everyone syncs until nothing changes.
async fn settle(devices: &[Device], committed: &Committed, st: &mut Stats) -> Result<()> {
    for _ in 0..3 {
        for dev in devices {
            let t = device_tokens(&dev.client)?;
            sync_retry(dev, st).await?;
            confirm(committed, t, true);
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ digests (also used by `check`)

pub fn http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?)
}

/// The digest of the server heads in a replica, computed like the client core does.
pub fn local_digest(store: &dyn Store, vault_id: &str) -> Result<String> {
    let items = store.list_items(vault_id)?;
    Ok(npw_api::vault_digest(items.iter().filter_map(|i| {
        i.server
            .as_ref()
            .map(|r| (r.item_id.as_str(), r.revision, r.deleted, r.hash.as_str()))
    })))
}

pub async fn server_digest(
    http: &reqwest::Client,
    c: &Client,
    vault_id: &str,
) -> Result<npw_api::DigestResp> {
    let base = c.lock_state().server_url;
    let token = c.events_token().await?;
    let resp = http
        .get(format!("{base}/v1/vaults/{vault_id}/digest"))
        .bearer_auth(token)
        .send()
        .await?;
    let status = resp.status();
    let body = resp.bytes().await?;
    if !status.is_success() {
        bail!("digest: HTTP {status}: {}", String::from_utf8_lossy(&body));
    }
    Ok(serde_json::from_slice(&body)?)
}

// ------------------------------------------------------------------ verification

async fn verify(devices: &[Device], vault: &str, ledger: &Committed) -> Result<Vec<String>> {
    let mut failures = vec![];
    let (committed, unconfirmed) = {
        let l = ledger.lock().expect("ledger");
        let unconfirmed: HashSet<String> =
            l.unconfirmed.difference(&l.committed).cloned().collect();
        (l.committed.clone(), unconfirmed)
    };
    let reference = &devices[0].client;

    // 1. nothing lost
    let current = device_tokens(reference)?;
    let missing: Vec<&String> = committed.iter().filter(|t| !current.contains(*t)).collect();
    let unconfirmed_missing: Vec<&String> = unconfirmed
        .iter()
        .filter(|t| !current.contains(*t))
        .collect();
    let mut on_server: HashSet<String> = HashSet::new();
    if !missing.is_empty() || !unconfirmed_missing.is_empty() {
        for v in crate::all_items(reference)? {
            for r in reference.item_history(vault, &v.item_id).await? {
                on_server.extend(tokens_of(
                    &reference
                        .item_revision(vault, &v.item_id, r.revision)
                        .await?,
                ));
            }
        }
    }
    let lost: Vec<&&String> = missing
        .iter()
        .filter(|t| !on_server.contains(**t))
        .collect();
    let in_history = missing.len() - lost.len();
    if !lost.is_empty() {
        failures.push(format!(
            "{} of {} committed values are missing on the server, e.g. {:?}",
            lost.len(),
            committed.len(),
            lost.iter().take(10).collect::<Vec<_>>()
        ));
    }
    let overwritten = unconfirmed_missing
        .iter()
        .filter(|t| !on_server.contains(**t))
        .count();

    // 2. everyone agrees with the server and with each other
    let http = http_client()?;
    let server = server_digest(&http, reference, vault).await?;
    let snapshot = |c: &Client| -> Result<HashMap<String, (bool, ItemContent)>> {
        let mut m = HashMap::new();
        for v in crate::all_items(c)? {
            let content = c
                .item(&v.vault_id, &v.item_id)?
                .content
                .ok_or_else(|| anyhow!("no content"))?;
            m.insert(v.item_id.clone(), (v.deleted, content));
        }
        Ok(m)
    };
    let base = snapshot(reference)?;
    for dev in devices {
        let local = local_digest(&*dev.store, vault)?;
        if local != server.digest {
            failures.push(format!(
                "{}: replica digest {} differs from the server's {}",
                dev.name,
                &local[..12],
                &server.digest[..12]
            ));
        }
        let other = snapshot(&dev.client)?;
        if other.len() != base.len() {
            failures.push(format!(
                "{} sees {} items, {} sees {}",
                devices[0].name,
                base.len(),
                dev.name,
                other.len()
            ));
        }
        for (id, v) in &base {
            if other.get(id) != Some(v) {
                failures.push(format!(
                    "{} differs from {} on item {id}",
                    dev.name, devices[0].name
                ));
            }
        }
        let (_, pending, rejected) = dev.client.attention()?;
        if pending + rejected > 0 {
            failures.push(format!(
                "{} still has {pending} pending and {rejected} rejected edits",
                dev.name
            ));
        }
        let h = dev.client.health_check()?;
        for p in h.problems {
            failures.push(format!("{} health: {p:?}", dev.name));
        }
    }

    let trash = base.values().filter(|(d, _)| *d).count();
    let conflicts: usize = base.values().map(|(_, c)| c.conflicts.len()).sum();
    // both sides of the conflict written by one device: typically an edit whose
    // push reached the server while the acknowledgement was lost
    let self_conflicts = base
        .values()
        .flat_map(|(_, c)| &c.conflicts)
        .filter(|c| {
            let mut toks = HashSet::new();
            all_strings(&c.value, &mut toks);
            all_strings(&c.kept, &mut toks);
            let devs: HashSet<&str> = toks
                .iter()
                .filter(|t| t.starts_with("tok-"))
                .filter_map(|t| t.split('-').nth(1))
                .collect();
            devs.len() == 1
        })
        .count();
    println!(
        "  result: {} items ({} in the trash, {} open conflicts, {} of them between values of one device), server count {}, digest {}",
        base.len(),
        trash,
        conflicts,
        self_conflicts,
        server.count,
        &server.digest[..12]
    );
    println!(
        "  values: {} committed: {} in current items (incl. conflicts and password history), {} only in older revisions, {} lost",
        committed.len(),
        committed.len() - missing.len(),
        in_history,
        lost.len()
    );
    if !unconfirmed.is_empty() {
        println!(
            "          {} more were only held during cancelled or failed syncs: {} of them were overwritten locally before reaching the server (not a loss)",
            unconfirmed.len(),
            overwritten
        );
    }
    Ok(failures)
}

fn finish(
    name: &str,
    failures: Vec<String>,
    dir: &Path,
    keep: bool,
    started: Instant,
) -> Result<()> {
    let secs = started.elapsed().as_secs_f64();
    if failures.is_empty() {
        println!("{name}: OK in {secs:.1} s");
        if keep {
            println!("  profiles kept in {}", dir.display());
        } else {
            let _ = std::fs::remove_dir_all(dir);
        }
        return Ok(());
    }
    for f in &failures {
        println!("  FAIL: {f}");
    }
    println!("  profiles kept in {}", dir.display());
    bail!(
        "{name} failed after {secs:.1} s: {} problems",
        failures.len()
    )
}

// ------------------------------------------------------------------ stress

async fn run_device(
    mut dev: Device,
    vault: String,
    ops: usize,
    seed: u64,
    committed: Committed,
) -> Result<(Device, Stats)> {
    let mut rng =
        StdRng::seed_from_u64(seed ^ (dev.idx as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let mut st = Stats::default();
    let mut offline_left = 0usize;
    for step in 0..ops {
        let roll = rng.gen_range(0..100);
        match roll {
            0..=67 => random_edit(&mut dev, &vault, roll, &mut rng, &mut st)
                .with_context(|| format!("{} step {step}", dev.name))?,
            68..=70 => {
                dev.restart()?;
                st.restarts += 1;
            }
            71..=73 if offline_left == 0 => {
                // a stretch without network: edits pile up locally
                offline_left = rng.gen_range(5..20);
                st.offline += 1;
            }
            _ if offline_left > 0 => {}
            _ => {
                let held = device_tokens(&dev.client)?;
                if rng.gen_bool(0.15) {
                    // cancel the sync part-way, as if the process died mid-request
                    let ms = rng.gen_range(0..40);
                    match tokio::time::timeout(Duration::from_millis(ms), dev.client.sync()).await {
                        Err(_) => {
                            st.cancelled += 1;
                            confirm(&committed, held, false);
                        }
                        Ok(Ok(r)) => {
                            st.sync_done(&r);
                            confirm(&committed, held, true);
                        }
                        Ok(Err(e)) => bail!("{} step {step}: sync failed: {e}", dev.name),
                    }
                } else {
                    let r = dev
                        .client
                        .sync()
                        .await
                        .map_err(|e| anyhow!("{} step {step}: sync failed: {e}", dev.name))?;
                    st.sync_done(&r);
                    confirm(&committed, held, true);
                }
            }
        }
        offline_left = offline_left.saturating_sub(1);
    }
    Ok((dev, st))
}

pub async fn run_stress(a: StressArgs) -> Result<()> {
    let started = Instant::now();
    let seed = a.seed.unwrap_or_else(|| npw_model::now_ms() as u64);
    let (dir, temporary) = work_dir(a.dir, "stress", seed)?;
    println!(
        "stress: {} devices, {} ops, seed {seed}, server {}",
        a.devices, a.ops, a.server
    );
    let (devices, vault) =
        setup_devices(&a.server, a.devices, &dir, seed, a.invite.as_deref()).await?;
    let committed: Committed = Arc::default();

    let n = devices.len();
    let mut tasks = vec![];
    for (i, dev) in devices.into_iter().enumerate() {
        let ops = a.ops / n + usize::from(i < a.ops % n);
        tasks.push(tokio::spawn(run_device(
            dev,
            vault.clone(),
            ops,
            seed,
            committed.clone(),
        )));
    }
    let mut devices = vec![];
    let mut st = Stats::default();
    let mut errors = vec![];
    for t in tasks {
        match t.await? {
            Ok((d, s)) => {
                st.add(&s);
                devices.push(d);
            }
            Err(e) => errors.push(format!("{e:#}")),
        }
    }
    if !errors.is_empty() {
        st.print();
        return finish("stress", errors, &dir, true, started);
    }
    devices.sort_by_key(|d| d.idx);
    settle(&devices, &committed, &mut st).await?;
    st.print();
    let failures = verify(&devices, &vault, &committed).await?;
    finish("stress", failures, &dir, a.keep || !temporary, started)
}

// ------------------------------------------------------------------ kill-test

struct ServerProc {
    bin: PathBuf,
    data: PathBuf,
    addr: String,
    log: PathBuf,
    child: Option<Child>,
}

impl ServerProc {
    async fn start(&mut self) -> Result<()> {
        let http = http_client()?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let log = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log)?;
            let mut child = Command::new(&self.bin)
                .arg("--data")
                .arg(&self.data)
                .env("NYAPASSWORD_LISTEN", &self.addr)
                .env("NYAPASSWORD_LOG", "warn")
                .stdin(Stdio::null())
                .stdout(log.try_clone()?)
                .stderr(log)
                .spawn()
                .with_context(|| format!("starting {}", self.bin.display()))?;
            // wait until it answers, or exits (port still in use after the kill)
            loop {
                if let Some(status) = child.try_wait()? {
                    if Instant::now() > deadline {
                        bail!(
                            "the server keeps exiting ({status}); see {}",
                            self.log.display()
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    break;
                }
                let ok = http
                    .get(format!("http://{}/v1/server-info", self.addr))
                    .send()
                    .await
                    .is_ok_and(|r| r.status().is_success());
                if ok {
                    self.child = Some(child);
                    return Ok(());
                }
                if Instant::now() > deadline {
                    let _ = child.kill();
                    bail!("the server did not come up; see {}", self.log.display());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }

    /// Hard kill (TerminateProcess / SIGKILL), no shutdown.
    fn kill(&mut self) -> Result<()> {
        if let Some(mut c) = self.child.take() {
            c.kill()?;
            c.wait()?;
        }
        Ok(())
    }
}

impl Drop for ServerProc {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}

pub async fn run_kill_test(a: KillArgs) -> Result<()> {
    let started = Instant::now();
    let seed = a.seed.unwrap_or_else(|| npw_model::now_ms() as u64);
    let (dir, temporary) = work_dir(a.dir, "kill", seed)?;
    let data = a.data.unwrap_or_else(|| dir.join("server-data"));
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let addr = format!("127.0.0.1:{port}");
    let url = format!("http://{addr}");
    println!(
        "kill-test: {} devices, {} rounds x {} edits, seed {seed}, server {} on {url}",
        a.devices,
        a.rounds,
        a.edits,
        a.server_bin.display()
    );
    let mut srv = ServerProc {
        bin: a.server_bin,
        data,
        addr,
        log: dir.join("server.log"),
        child: None,
    };
    srv.start().await?;
    let (mut devices, vault) = setup_devices(&url, a.devices, &dir, seed, None).await?;
    let committed: Committed = Arc::default();
    let mut rng = StdRng::seed_from_u64(seed);
    let mut st = Stats::default();
    let mut kills = 0;

    for _round in 0..a.rounds {
        for dev in devices.iter_mut() {
            for _ in 0..a.edits {
                let roll = rng.gen_range(0..68);
                random_edit(dev, &vault, roll, &mut rng, &mut st)?;
            }
        }
        // everyone pushes at once; the server dies somewhere in the middle
        let tasks: Vec<_> = devices
            .drain(..)
            .map(|dev| {
                tokio::spawn(async move {
                    let held = device_tokens(&dev.client);
                    let r = dev.client.sync().await;
                    (dev, held, r)
                })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(rng.gen_range(0..60))).await;
        srv.kill()?;
        kills += 1;
        for t in tasks {
            let (dev, held, r) = t.await?;
            let held = held?;
            match r {
                Ok(r) => {
                    st.sync_done(&r);
                    confirm(&committed, held, true);
                }
                Err(CoreError::Network(_)) => {
                    st.failed_syncs += 1;
                    confirm(&committed, held, false);
                }
                Err(e) => bail!("{}: sync failed with a non-network error: {e}", dev.name),
            }
            devices.push(dev);
        }
        devices.sort_by_key(|d| d.idx);
        // sometimes the app dies too
        for dev in devices.iter_mut() {
            if rng.gen_bool(0.2) {
                dev.restart()?;
                st.restarts += 1;
            }
        }
        srv.start().await?;
    }

    settle(&devices, &committed, &mut st).await?;
    println!("  server killed {kills} times during pushes");
    st.print();
    let failures = verify(&devices, &vault, &committed).await?;
    srv.kill()?;
    finish("kill-test", failures, &dir, a.keep || !temporary, started)
}
