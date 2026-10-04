//! The import preview / result report (design doc §9.1).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{ImportedItem, Mapping};

/// A warning about one item. Never contains secret values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemWarning {
    pub title: String,
    pub warning: String,
}

/// A source entry that was not imported, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Skipped {
    pub title: String,
    pub reason: String,
}

impl Skipped {
    pub fn new(title: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            reason: reason.into(),
        }
    }
}

/// Counts and lists for the import preview.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ImportReport {
    /// Items to be written.
    pub total: usize,
    /// Template ID → item count.
    pub by_template: BTreeMap<String, usize>,
    pub full: usize,
    pub partial: usize,
    pub fallback: usize,
    pub warnings: Vec<ItemWarning>,
    pub passkeys: usize,
    pub attachments: usize,
    pub attachment_bytes: u64,
    /// Largest single attachment, so the UI can warn about oversized files.
    pub largest_attachment: u64,
    pub skipped: Vec<Skipped>,
}

impl ImportReport {
    pub fn build(items: &[ImportedItem], skipped: Vec<Skipped>) -> Self {
        let mut r = ImportReport {
            total: items.len(),
            skipped,
            ..Default::default()
        };
        for it in items {
            *r.by_template
                .entry(it.content.template.clone())
                .or_default() += 1;
            match it.mapping {
                Mapping::Full => r.full += 1,
                Mapping::Partial => r.partial += 1,
                Mapping::Fallback => r.fallback += 1,
            }
            r.passkeys += it.content.passkeys.len();
            for a in &it.attachments {
                r.attachments += 1;
                r.attachment_bytes += a.data.len() as u64;
                r.largest_attachment = r.largest_attachment.max(a.data.len() as u64);
            }
            r.warnings.extend(it.warnings.iter().map(|w| ItemWarning {
                title: it.content.title.clone(),
                warning: w.clone(),
            }));
        }
        r
    }
}
