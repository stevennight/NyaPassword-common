//! npw-dev: the developer command line. Drives a running NyaPassword server
//! over HTTP with the client core, one local replica per profile directory.

mod profile;
mod stress;

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use npw_core::{Client, ItemFilter, ItemView, Store};

use profile::{open_unlocked, PasswordSource, Profile};

#[derive(Parser)]
#[command(
    name = "npw-dev",
    version,
    about = "NyaPassword developer CLI (talks to a running server)"
)]
struct Cli {
    /// Profile directory: one device's local replica.
    #[arg(
        long,
        global = true,
        env = "NPW_PROFILE",
        default_value = "npw-dev-profile"
    )]
    profile: PathBuf,
    /// Environment variable that holds the master password (prompted when unset).
    #[arg(long, global = true, default_value = "NPW_PASSWORD")]
    password_env: String,
    /// The master password on the command line. INSECURE (shell history,
    /// process list): only for throwaway test accounts.
    #[arg(long, global = true)]
    master_password: Option<String>,
    /// Device name shown in the account's device list.
    #[arg(long, global = true, default_value = "npw-dev")]
    device_name: String,
    /// Keep edits local (pending) instead of syncing right after them.
    #[arg(long, global = true)]
    no_sync: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create an account and sign this profile in; prints the Emergency Kit.
    Register {
        #[arg(long)]
        server: String,
        #[arg(long)]
        email: String,
        #[arg(long)]
        invite: Option<String>,
    },
    /// Sign this profile in to an existing account (a new device).
    Login {
        #[arg(long)]
        server: String,
        #[arg(long)]
        email: String,
        /// The Secret Key from the Emergency Kit.
        #[arg(long, env = "NPW_SECRET_KEY", hide_env_values = true)]
        secret_key: String,
    },
    /// Unlock with the master password and remember the account key in the profile.
    Unlock,
    /// Forget the remembered account key.
    Lock,
    /// Account, device and replica state.
    Status,
    /// Sign this profile out and clear its replica.
    Logout {
        /// Also when edits have not been synced yet (they are lost).
        #[arg(long)]
        force: bool,
    },
    /// Pull, merge and push every vault.
    Sync,
    /// Health check and digest comparison with the server.
    Check,
    /// List the vaults.
    Vaults,
    /// List items.
    List {
        /// Vault name or id.
        #[arg(long)]
        vault: Option<String>,
        /// Search text.
        #[arg(long, short)]
        query: Option<String>,
        /// Only items in the trash.
        #[arg(long)]
        trash: bool,
        /// Only archived items.
        #[arg(long)]
        archived: bool,
    },
    /// Print an item with its content as JSON.
    Get {
        /// Item id, id prefix or title.
        item: String,
    },
    /// Create a login item.
    AddLogin {
        #[arg(long)]
        title: String,
        #[arg(long)]
        username: Option<String>,
        /// The item's password (not the master password).
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        url: Vec<String>,
        /// Vault name or id (default: the first vault).
        #[arg(long)]
        vault: Option<String>,
    },
    /// Change an item.
    Edit {
        /// Item id, id prefix or title.
        item: String,
        /// Set a field by id, e.g. `--field password=s3cret`; unknown ids add a text field.
        #[arg(long = "field", value_name = "ID=VALUE")]
        fields: Vec<String>,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long)]
        add_url: Vec<String>,
    },
    /// Move an item to the trash.
    Delete {
        /// Item id, id prefix or title.
        item: String,
    },
    /// Take an item out of the trash.
    Restore {
        /// Item id, id prefix or title.
        item: String,
    },
    /// Import another password manager's export (online, all or nothing).
    Import {
        file: PathBuf,
        /// Format (default: detected from the file).
        #[arg(long, value_enum)]
        source: Option<ImportSource>,
        /// Vault name or id (default: the first vault).
        #[arg(long)]
        vault: Option<String>,
        /// Environment variable with the export file's password (encrypted Bitwarden, KDBX).
        #[arg(long)]
        file_password_env: Option<String>,
        /// The export file's password on the command line. INSECURE: tests only.
        #[arg(long)]
        file_password: Option<String>,
    },
    /// Export every vault (needs the master password).
    Export {
        #[arg(long, value_enum, default_value_t = ExportFormat::Native)]
        format: ExportFormat,
        #[arg(long)]
        out: PathBuf,
    },
    /// Random concurrent edits from several devices against the server, then verify nothing was lost.
    Stress(stress::StressArgs),
    /// Kill and restart a server process while devices push, then verify nothing was lost.
    KillTest(stress::KillArgs),
}

#[derive(Clone, Copy, ValueEnum)]
enum ImportSource {
    /// Bitwarden JSON (plain or encrypted) or ZIP with attachments.
    Bitwarden,
    BitwardenCsv,
    /// 1Password 1PUX.
    #[value(name = "1pux")]
    OnePux,
    #[value(name = "1password-csv")]
    OnePasswordCsv,
    /// KeePass / KeePassXC KDBX 4.
    Kdbx,
    KeepassCsv,
    /// Chrome / Edge / Firefox and other CSVs with recognisable headers.
    Csv,
}

#[derive(Clone, Copy, ValueEnum)]
enum ExportFormat {
    /// Lossless, encrypted; opens with the master password and the Secret Key.
    Native,
    /// KeePassXC, encrypted with the master password.
    Kdbx,
    /// Plaintext.
    Csv,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let profile = Profile::new(&cli.profile);
    let pw = PasswordSource {
        explicit: cli.master_password.clone(),
        env: cli.password_env.clone(),
    };
    let ctx = Ctx {
        profile,
        pw,
        device: cli.device_name.clone(),
        no_sync: cli.no_sync,
    };
    match cli.cmd {
        Cmd::Register {
            server,
            email,
            invite,
        } => ctx.register(&server, &email, invite.as_deref()).await,
        Cmd::Login {
            server,
            email,
            secret_key,
        } => ctx.login(&server, &email, &secret_key).await,
        Cmd::Unlock => {
            let o = ctx.profile.open(&ctx.device)?;
            if !o.client.lock_state().signed_in {
                bail!("not signed in");
            }
            o.client.unlock(&ctx.pw.get("Master password: ")?)?;
            ctx.profile.save_unlock(&o.client)?;
            println!("unlocked");
            Ok(())
        }
        Cmd::Lock => {
            if ctx.profile.clear_unlock()? {
                println!("locked");
            } else {
                println!("was not unlocked");
            }
            Ok(())
        }
        Cmd::Status => ctx.status(),
        Cmd::Logout { force } => {
            let o = ctx.profile.open(&ctx.device)?;
            o.client.sign_out(force).await?;
            ctx.profile.clear_unlock()?;
            println!("signed out");
            Ok(())
        }
        Cmd::Sync => {
            let c = ctx.unlocked()?;
            let r = c.sync().await?;
            println!("{}", serde_json::to_string_pretty(&r)?);
            Ok(())
        }
        Cmd::Check => ctx.check().await,
        Cmd::Vaults => {
            let c = ctx.unlocked()?;
            for v in c.vaults()? {
                println!("{}  {}  ({}, {} items)", v.id, v.name, v.role, v.items);
            }
            Ok(())
        }
        Cmd::List {
            vault,
            query,
            trash,
            archived,
        } => {
            let c = ctx.unlocked()?;
            let vault_id = vault.map(|v| resolve_vault(&c, &v)).transpose()?;
            let items = c.list_items(&ItemFilter {
                vault_id,
                query: query.unwrap_or_default(),
                trash,
                archived,
                ..Default::default()
            })?;
            for v in &items {
                println!("{}", list_line(v));
            }
            eprintln!("{} items", items.len());
            Ok(())
        }
        Cmd::Get { item } => {
            let c = ctx.unlocked()?;
            let v = resolve_item(&c, &item)?;
            let full = c.item(&v.vault_id, &v.item_id)?;
            println!("{}", serde_json::to_string_pretty(&full)?);
            Ok(())
        }
        Cmd::AddLogin {
            title,
            username,
            password,
            url,
            vault,
        } => {
            let c = ctx.unlocked()?;
            let vault_id = match vault {
                Some(v) => resolve_vault(&c, &v)?,
                None => first_vault(&c)?,
            };
            let mut it = npw_model::template("login")
                .ok_or_else(|| anyhow!("no login template"))?
                .new_item("en");
            it.title = title;
            if let Some(u) = username {
                set_field(&mut it, "username", &u);
            }
            if let Some(p) = password {
                set_field(&mut it, "password", &p);
            }
            for u in url {
                it.urls.push(npw_model::UrlEntry::new(u));
            }
            let id = c.save_item(&vault_id, None, it)?;
            println!("{id}");
            ctx.after_edit(&c).await
        }
        Cmd::Edit {
            item,
            fields,
            title,
            notes,
            add_url,
        } => {
            let c = ctx.unlocked()?;
            let v = resolve_item(&c, &item)?;
            let mut content = c
                .item(&v.vault_id, &v.item_id)?
                .content
                .ok_or_else(|| anyhow!("item has no content"))?;
            if let Some(t) = title {
                content.title = t;
            }
            if let Some(n) = notes {
                content.notes = n;
            }
            for f in &fields {
                let (id, value) = f
                    .split_once('=')
                    .ok_or_else(|| anyhow!("--field wants ID=VALUE, got {f:?}"))?;
                set_field(&mut content, id, value);
            }
            for u in add_url {
                content.urls.push(npw_model::UrlEntry::new(u));
            }
            c.save_item(&v.vault_id, Some(&v.item_id), content)?;
            println!("{}", v.item_id);
            ctx.after_edit(&c).await
        }
        Cmd::Delete { item } => {
            let c = ctx.unlocked()?;
            let v = resolve_item(&c, &item)?;
            c.delete_item(&v.vault_id, &v.item_id)?;
            println!("{} moved to the trash", v.item_id);
            ctx.after_edit(&c).await
        }
        Cmd::Restore { item } => {
            let c = ctx.unlocked()?;
            let v = resolve_item(&c, &item)?;
            c.restore_item(&v.vault_id, &v.item_id)?;
            println!("{} restored", v.item_id);
            ctx.after_edit(&c).await
        }
        Cmd::Import {
            file,
            source,
            vault,
            file_password_env,
            file_password,
        } => {
            let file_pw = file_password.or_else(|| {
                file_password_env
                    .and_then(|v| std::env::var(v).ok())
                    .filter(|p| !p.is_empty())
            });
            ctx.import(&file, source, vault.as_deref(), file_pw).await
        }
        Cmd::Export { format, out } => {
            let c = ctx.unlocked()?;
            let password = ctx.pw.get("Master password: ")?;
            let fmt = match format {
                ExportFormat::Native => "native",
                ExportFormat::Kdbx => "kdbx",
                ExportFormat::Csv => "csv",
            };
            let items = c.export_items()?.len();
            let bytes = c.export_vault(fmt, &password).await?;
            std::fs::write(&out, &bytes).with_context(|| out.display().to_string())?;
            println!(
                "{fmt}: {items} items, {} bytes -> {}",
                bytes.len(),
                out.display()
            );
            if fmt == "csv" {
                eprintln!("warning: the CSV file is plaintext; delete it when done");
            }
            Ok(())
        }
        Cmd::Stress(args) => stress::run_stress(args).await,
        Cmd::KillTest(args) => stress::run_kill_test(args).await,
    }
}

struct Ctx {
    profile: Profile,
    pw: PasswordSource,
    device: String,
    no_sync: bool,
}

impl Ctx {
    fn unlocked(&self) -> Result<Client> {
        Ok(open_unlocked(&self.profile, &self.device, &self.pw)?.client)
    }

    async fn after_edit(&self, c: &Client) -> Result<()> {
        if self.no_sync {
            eprintln!("saved locally (pending until the next sync)");
            return Ok(());
        }
        let r = c.sync().await?;
        eprintln!(
            "synced: pushed {}, pulled {}, merged {}, conflicts {}, rejected {}",
            r.pushed, r.pulled, r.merged, r.conflicts, r.rejected
        );
        Ok(())
    }

    async fn register(&self, server: &str, email: &str, invite: Option<&str>) -> Result<()> {
        let o = self.profile.open(&self.device)?;
        if o.client.lock_state().signed_in {
            bail!(
                "profile {} is already signed in; use another --profile",
                self.profile.dir.display()
            );
        }
        let password = self.pw.get_new()?;
        let kit = o.client.register(server, email, &password, invite).await?;
        self.profile.save_unlock(&o.client)?;
        println!("NyaPassword Emergency Kit");
        println!("  server:     {}", kit.server_url);
        println!("  login:      {}", kit.login);
        println!("  account id: {}", kit.account_id);
        println!("  Secret Key: {}", kit.secret_key);
        eprintln!(
            "keep the Secret Key: every new device needs it together with the master password"
        );
        Ok(())
    }

    async fn login(&self, server: &str, email: &str, secret_key: &str) -> Result<()> {
        let o = self.profile.open(&self.device)?;
        if o.client.lock_state().signed_in {
            bail!(
                "profile {} is already signed in; use another --profile",
                self.profile.dir.display()
            );
        }
        let password = self.pw.get("Master password: ")?;
        o.client
            .sign_in(server, email, &password, secret_key)
            .await?;
        self.profile.save_unlock(&o.client)?;
        let r = o.client.sync().await?;
        println!(
            "signed in as {} (device {}); pulled {} items",
            email,
            o.client.lock_state().device_id,
            r.pulled
        );
        Ok(())
    }

    fn status(&self) -> Result<()> {
        let o = self.profile.open(&self.device)?;
        let s = o.client.lock_state();
        println!("profile:   {}", self.profile.dir.display());
        if !s.signed_in {
            println!("signed in: no");
            return Ok(());
        }
        println!("signed in: {} on {}", s.login, s.server_url);
        println!("account:   {}", s.account_id);
        println!("device:    {}", s.device_id);
        println!(
            "unlocked:  {}",
            if self.profile.is_unlocked() {
                "yes (key remembered in the profile)"
            } else {
                "no"
            }
        );
        if s.last_sync_at > 0 {
            let ago = (npw_model::now_ms() - s.last_sync_at) / 1000;
            println!("last sync: {ago} s ago");
        } else {
            println!("last sync: never");
        }
        let items = o.store.list_all_items()?;
        let pending = items.iter().filter(|i| i.pending.is_some()).count();
        let rejected = items
            .iter()
            .filter(|i| i.pending.as_ref().is_some_and(|p| p.rejected.is_some()))
            .count();
        println!(
            "replica:   {} records, {pending} pending edits, {rejected} rejected",
            items.len()
        );
        Ok(())
    }

    async fn check(&self) -> Result<()> {
        let o = open_unlocked(&self.profile, &self.device, &self.pw)?;
        let h = o.client.health_check()?;
        println!(
            "health: {} checked, {} ok, {} pending, {} rejected, {} conflicts, {} problems",
            h.checked,
            h.ok,
            h.pending,
            h.rejected,
            h.conflicts,
            h.problems.len()
        );
        for (v, i, p) in &h.problems {
            println!("  {v}/{i}: {p}");
        }
        let mut bad = !h.problems.is_empty();
        let http = stress::http_client()?;
        for v in o.client.vaults()? {
            let local = stress::local_digest(&*o.store, &v.id)?;
            let remote = stress::server_digest(&http, &o.client, &v.id).await?;
            let same = local == remote.digest;
            bad |= !same;
            println!(
                "vault {} ({}): local {} server {} (server count {}) {}",
                v.name,
                v.id,
                &local[..12],
                &remote.digest[..12],
                remote.count,
                if same { "same" } else { "DIFFERENT (run sync)" }
            );
        }
        if bad {
            bail!("check found problems");
        }
        Ok(())
    }

    async fn import(
        &self,
        file: &std::path::Path,
        source: Option<ImportSource>,
        vault: Option<&str>,
        file_pw: Option<String>,
    ) -> Result<()> {
        let c = self.unlocked()?;
        let vault_id = match vault {
            Some(v) => resolve_vault(&c, v)?,
            None => first_vault(&c)?,
        };
        let data = std::fs::read(file).with_context(|| file.display().to_string())?;
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let detected = npw_import::detect(&name, &data);
        let src = match source {
            None => detected.ok_or_else(|| anyhow!("unrecognized file format; pass --source"))?,
            Some(s) => explicit_source(s, detected),
        };
        let mut file_pw = file_pw;
        let parsed = loop {
            match npw_import::import(src, &data, file_pw.as_deref(), "en") {
                Ok(p) => break p,
                Err(npw_import::ImportError::NeedPassword) if file_pw.is_none() => {
                    file_pw = Some(profile::prompt_password("Export file password: ")?);
                }
                Err(e) => bail!("cannot read {}: {e}", file.display()),
            }
        };
        let source_name = format!("{src:?}").to_lowercase();
        let preview = npw_core::transfer::preview(&source_name, &parsed);
        println!(
            "{}: {} items {:?}, {} warnings, {} passkeys, {} skipped",
            source_name,
            preview.items.len(),
            preview.counts,
            preview.warnings,
            preview.passkeys,
            preview.skipped.len()
        );
        for (title, reason) in &preview.skipped {
            println!("  skipped {title}: {reason}");
        }
        let report = c.import_parsed(&vault_id, parsed, &source_name).await?;
        println!(
            "imported {} items and {} attachments (batch {})",
            report.imported, report.attachments, report.batch_id
        );
        if !self.no_sync {
            c.sync().await?;
        }
        if !report.problems.is_empty() {
            for p in &report.problems {
                println!("  problem: {p}");
            }
            bail!("the vault does not match the source file");
        }
        println!("verified: every imported value is in the vault");
        Ok(())
    }
}

/// Maps the `--source` choice to a parser, letting detection pick the variant of a family.
fn explicit_source(s: ImportSource, detected: Option<npw_import::Source>) -> npw_import::Source {
    use npw_import::Source as S;
    match s {
        ImportSource::Bitwarden => match detected {
            Some(d @ (S::BitwardenJson | S::BitwardenEncryptedJson | S::BitwardenZip)) => d,
            _ => S::BitwardenJson,
        },
        ImportSource::BitwardenCsv => S::BitwardenCsv,
        ImportSource::OnePux => S::OnePasswordPux,
        ImportSource::OnePasswordCsv => S::OnePasswordCsv,
        ImportSource::Kdbx => S::KeepassKdbx,
        ImportSource::KeepassCsv => S::KeepassCsv,
        ImportSource::Csv => S::ChromeCsv,
    }
}

fn set_field(c: &mut npw_model::ItemContent, id: &str, value: &str) {
    match c.field_mut(id) {
        Some(f) => f.value = value.into(),
        None => c
            .fields
            .push(npw_model::Field::new(id, id, "text").with_value(value)),
    }
}

fn list_line(v: &ItemView) -> String {
    let mut flags = vec![];
    if v.pending {
        flags.push("pending".to_string());
    }
    if v.rejected.is_some() {
        flags.push("rejected".into());
    }
    if v.conflicts > 0 {
        flags.push(format!("{} conflicts", v.conflicts));
    }
    if v.deleted {
        flags.push("trash".into());
    }
    if v.archived {
        flags.push("archived".into());
    }
    let flags = if flags.is_empty() {
        String::new()
    } else {
        format!("  [{}]", flags.join(", "))
    };
    format!(
        "{}  {:<10} {}  {}{}",
        v.item_id, v.template, v.title, v.subtitle, flags
    )
}

/// Every item: live, archived and in the trash.
pub(crate) fn all_items(c: &Client) -> Result<Vec<ItemView>> {
    let mut out = c.list_items(&ItemFilter::default())?;
    out.extend(c.list_items(&ItemFilter {
        archived: true,
        ..Default::default()
    })?);
    out.extend(c.list_items(&ItemFilter {
        trash: true,
        ..Default::default()
    })?);
    Ok(out)
}

/// Finds an item by id, unique id prefix or title (case-insensitive).
fn resolve_item(c: &Client, r: &str) -> Result<ItemView> {
    let all = all_items(c)?;
    if let Some(v) = all.iter().find(|v| v.item_id == r) {
        return Ok(v.clone());
    }
    let by_prefix: Vec<&ItemView> = all.iter().filter(|v| v.item_id.starts_with(r)).collect();
    if r.len() >= 4 && by_prefix.len() == 1 {
        return Ok(by_prefix[0].clone());
    }
    let by_title: Vec<&ItemView> = all
        .iter()
        .filter(|v| v.title.eq_ignore_ascii_case(r))
        .collect();
    match by_title.len() {
        1 => Ok(by_title[0].clone()),
        0 if by_prefix.len() > 1 => bail!("{} items start with {r:?}", by_prefix.len()),
        0 => bail!("no item {r:?}"),
        n => {
            for v in by_title {
                eprintln!("  {}", list_line(v));
            }
            bail!("{n} items are titled {r:?}; use the id")
        }
    }
}

/// Finds a vault by id, unique id prefix or name (case-insensitive).
fn resolve_vault(c: &Client, r: &str) -> Result<String> {
    let vaults = c.vaults()?;
    if let Some(v) = vaults
        .iter()
        .find(|v| v.id == r || v.name.eq_ignore_ascii_case(r))
    {
        return Ok(v.id.clone());
    }
    let m: Vec<_> = vaults.iter().filter(|v| v.id.starts_with(r)).collect();
    match m.len() {
        1 => Ok(m[0].id.clone()),
        0 => bail!("no vault {r:?}"),
        n => bail!("{n} vaults start with {r:?}"),
    }
}

fn first_vault(c: &Client) -> Result<String> {
    c.vaults()?
        .into_iter()
        .next()
        .map(|v| v.id)
        .ok_or_else(|| anyhow!("the account has no vault"))
}
