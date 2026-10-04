//! Vault health check (design doc §7.5): every item in the replica must
//! decrypt and parse, both its server revision and its pending edit.

use serde::{Deserialize, Serialize};

use crate::client::Client;
use crate::items::{decrypt_pending, decrypt_record};
use crate::{CoreError, Result};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct HealthReport {
    pub checked: usize,
    pub ok: usize,
    pub pending: usize,
    pub rejected: usize,
    pub read_only: usize,
    pub conflicts: usize,
    /// (vault, item, problem)
    pub problems: Vec<(String, String, String)>,
    pub checked_at: i64,
}

impl Client {
    pub fn health_check(&self) -> Result<HealthReport> {
        if !self.is_unlocked() {
            return Err(CoreError::Locked);
        }
        let mut r = HealthReport { checked_at: npw_model::now_ms(), ..Default::default() };
        let acc = self.account()?;
        for v in &acc.vaults {
            let vk = self.vault_key(&v.id)?;
            for li in self.store.list_items(&v.id)? {
                r.checked += 1;
                let mut fine = true;
                if let Some(s) = &li.server {
                    match decrypt_record(&vk, &v.id, s) {
                        Ok(d) => {
                            if d.read_only {
                                r.read_only += 1;
                            }
                            if !d.content.conflicts.is_empty() && li.pending.is_none() {
                                r.conflicts += 1;
                            }
                        }
                        Err(e) => {
                            fine = false;
                            r.problems.push((v.id.clone(), li.item_id.clone(), format!("server revision {}: {e}", s.revision)));
                        }
                    }
                }
                if let Some(p) = &li.pending {
                    r.pending += 1;
                    if let Some(reason) = &p.rejected {
                        r.rejected += 1;
                        r.problems.push((v.id.clone(), li.item_id.clone(), format!("edit refused by the server: {reason}")));
                    }
                    match decrypt_pending(&vk, &v.id, &li.item_id, p) {
                        Ok(d) => {
                            if !d.content.conflicts.is_empty() {
                                r.conflicts += 1;
                            }
                        }
                        Err(e) => {
                            fine = false;
                            r.problems.push((v.id.clone(), li.item_id.clone(), format!("local edit: {e}")));
                        }
                    }
                }
                if fine {
                    r.ok += 1;
                }
            }
        }
        Ok(r)
    }
}
