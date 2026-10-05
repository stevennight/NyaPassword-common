//! Imports and exports (design doc §9). Parsing lives in npw-import, file
//! formats in npw-export; this module writes imports into a vault and gathers
//! a vault for export, the same way on every client.

use std::collections::HashMap;

use npw_crypto::{KdfParams, SecretKey};
use npw_export::{ExportItem, ExportVault};
use npw_import::ImportResult;
use npw_model::ItemContent;
use serde::{Deserialize, Serialize};

use crate::client::Client;
use crate::{CoreError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportCommitReport {
    pub batch_id: String,
    pub imported: usize,
    pub attachments: usize,
    /// Differences between the source and what is now in the vault (empty = everything arrived).
    pub problems: Vec<String>,
}

/// A short, value-free summary of a parsed import for the preview screen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportPreview {
    pub source: String,
    pub items: Vec<PreviewItem>,
    pub counts: std::collections::BTreeMap<String, usize>,
    pub warnings: usize,
    pub attachment_bytes: u64,
    pub passkeys: usize,
    pub skipped: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewItem {
    pub title: String,
    pub template: String,
    pub mapping: String,
    pub warnings: Vec<String>,
    pub attachments: usize,
    pub passkeys: usize,
}

/// Detects the format and parses an export file of another password manager.
pub fn parse_import(
    file_name: &str,
    data: &[u8],
    password: Option<&str>,
    locale: &str,
) -> Result<(String, ImportResult)> {
    let source = npw_import::detect(file_name, data)
        .ok_or_else(|| CoreError::Invalid("unrecognized file format".into()))?;
    let res = npw_import::import(source, data, password, locale).map_err(|e| match e {
        npw_import::ImportError::NeedPassword => CoreError::Invalid("need_password".into()),
        npw_import::ImportError::WrongPassword => CoreError::WrongPassword,
        other => CoreError::Invalid(other.to_string()),
    })?;
    Ok((format!("{source:?}"), res))
}

pub fn preview(source: &str, r: &ImportResult) -> ImportPreview {
    ImportPreview {
        source: source.to_string(),
        items: r
            .items
            .iter()
            .map(|i| PreviewItem {
                title: i.content.title.clone(),
                template: i.content.template.clone(),
                mapping: format!("{:?}", i.mapping).to_lowercase(),
                warnings: i.warnings.clone(),
                attachments: i.attachments.len(),
                passkeys: i.content.passkeys.len(),
            })
            .collect(),
        counts: r.report.by_template.clone(),
        warnings: r.report.warnings.len(),
        attachment_bytes: r.report.attachment_bytes,
        passkeys: r.report.passkeys,
        skipped: r
            .report
            .skipped
            .iter()
            .map(|s| (s.title.clone(), s.reason.clone()))
            .collect(),
    }
}

impl Client {
    /// Writes a parsed import into a vault: one atomic batch, then the
    /// attachments, then a field-by-field comparison with the source.
    pub async fn import_parsed(
        &self,
        vault_id: &str,
        parsed: ImportResult,
        source: &str,
    ) -> Result<ImportCommitReport> {
        // Item ids are chosen first, so reference fields (1Password) can point at the new items.
        let ids: Vec<String> = parsed.items.iter().map(|_| npw_model::new_id()).collect();
        let by_source: HashMap<&str, &str> = parsed
            .items
            .iter()
            .zip(&ids)
            .filter(|(i, _)| !i.source_id.is_empty())
            .map(|(i, id)| (i.source_id.as_str(), id.as_str()))
            .collect();
        let mut contents = vec![];
        for (it, id) in parsed.items.iter().zip(&ids) {
            let mut c = it.content.clone();
            for f in &mut c.fields {
                if f.kind == npw_model::item::kind::REFERENCE {
                    if let Some(s) = f.value.as_str() {
                        if let Some(new) = by_source.get(s) {
                            f.value = (*new).into();
                        }
                    }
                }
            }
            contents.push((id.clone(), c));
        }
        let res = self
            .import_items_with_ids(vault_id, contents, source)
            .await?;

        let mut attachments = 0;
        for (it, id) in parsed.items.iter().zip(&ids) {
            for a in &it.attachments {
                self.add_attachment(vault_id, id, &a.name, &a.mime, &a.data)
                    .await?;
                attachments += 1;
            }
        }

        // prove nothing was lost: decrypt what is now in the vault and compare
        let decrypted: Vec<ItemContent> = ids
            .iter()
            .filter_map(|id| self.item(vault_id, id).ok().and_then(|v| v.content))
            .collect();
        let problems = npw_import::compare(&parsed.items, &decrypted);
        Ok(ImportCommitReport {
            batch_id: res.batch_id,
            imported: res.imported,
            attachments,
            problems,
        })
    }

    /// Checks the master password and returns the Secret Key (for exports that need both).
    pub fn verify_password(&self, password: &str) -> Result<SecretKey> {
        let acc = self.account()?;
        self.open_account_key(&acc, password)?;
        self.secret_key()
    }

    /// Every vault with its items (also those in the trash) and decrypted attachments.
    pub async fn export_bundle(&self) -> Result<Vec<ExportVault>> {
        let vaults = self.vaults()?;
        let mut out = vec![];
        for v in vaults {
            let mut items = vec![];
            for trash in [false, true] {
                let list = self.list_items(&crate::ItemFilter {
                    vault_id: Some(v.id.clone()),
                    trash,
                    ..Default::default()
                })?;
                let archived = self.list_items(&crate::ItemFilter {
                    vault_id: Some(v.id.clone()),
                    trash,
                    archived: true,
                    ..Default::default()
                })?;
                for view in list
                    .into_iter()
                    .chain(archived.into_iter().filter(|_| !trash))
                {
                    let content = self
                        .item(&v.id, &view.item_id)?
                        .content
                        .ok_or(CoreError::NotFound)?;
                    let mut atts = vec![];
                    for a in &content.attachments {
                        let data = self.attachment(&v.id, &view.item_id, &a.id).await?;
                        atts.push((a.clone(), data));
                    }
                    items.push(ExportItem {
                        content,
                        attachments: atts,
                        deleted: view.deleted,
                    });
                }
            }
            out.push(ExportVault {
                name: v.name,
                items,
            });
        }
        Ok(out)
    }

    /// `native`: lossless, opens with password + Secret Key; `kdbx`: KeePassXC; `csv`: plaintext.
    pub async fn export_vault(&self, format: &str, password: &str) -> Result<Vec<u8>> {
        let sk = self.verify_password(password)?;
        let bundle = self.export_bundle().await?;
        let ex = |e: npw_export::ExportError| CoreError::Invalid(e.to_string());
        match format {
            "native" => {
                let params = if self.cfg.allow_weak_kdf {
                    KdfParams::insecure_for_tests()
                } else {
                    KdfParams::default()
                };
                npw_export::native::export_native(
                    &bundle,
                    &self.account()?.login,
                    password,
                    &sk,
                    params,
                )
                .map_err(ex)
            }
            "kdbx" => npw_export::kdbx::export_kdbx(&bundle, password).map_err(ex),
            "csv" => Ok(npw_export::csv_export::export_csv(&bundle)),
            _ => Err(CoreError::Invalid(format!(
                "unknown export format {format}"
            ))),
        }
    }
}
