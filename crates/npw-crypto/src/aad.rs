//! Associated data for every envelope. Binding ciphertexts to their identity
//! means a malicious server cannot swap one item's ciphertext for another's,
//! move it to another vault, or present an account key as an item key.
//!
//! Layout: ASCII domain label, then the raw 16-byte UUIDs, then any integers big-endian.

fn build(label: &str, ids: &[&[u8; 16]], tail: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(label.len() + ids.len() * 16 + tail.len());
    v.extend_from_slice(label.as_bytes());
    for id in ids {
        v.extend_from_slice(&id[..]);
    }
    v.extend_from_slice(tail);
    v
}

/// The account key AK, sealed under the account unlock key AUK.
pub fn account_key(account_id: &[u8; 16]) -> Vec<u8> {
    build("npw/account-key/v1", &[account_id], &[])
}

/// The account X25519 secret key, sealed under AK.
pub fn account_private_key(account_id: &[u8; 16]) -> Vec<u8> {
    build("npw/account-x25519/v1", &[account_id], &[])
}

/// The account key sealed under a recovery code's key.
pub fn recovery_account_key(account_id: &[u8; 16]) -> Vec<u8> {
    build("npw/recovery-account-key/v1", &[account_id], &[])
}

/// A vault key VK, sealed under AK (own vaults; shared vaults will use HPKE).
pub fn vault_key(vault_id: &[u8; 16]) -> Vec<u8> {
    build("npw/vault-key/v1", &[vault_id], &[])
}

/// Vault metadata (name, icon), sealed under VK.
pub fn vault_meta(vault_id: &[u8; 16]) -> Vec<u8> {
    build("npw/vault-meta/v1", &[vault_id], &[])
}

/// An item key IK, sealed under VK.
pub fn item_key(vault_id: &[u8; 16], item_id: &[u8; 16]) -> Vec<u8> {
    build("npw/item-key/v1", &[vault_id, item_id], &[])
}

/// Item content, sealed under IK. The format major version is bound too, so a
/// ciphertext cannot be relabelled as an older format.
pub fn item_content(vault_id: &[u8; 16], item_id: &[u8; 16], format_major: u16) -> Vec<u8> {
    build(
        "npw/item/v1",
        &[vault_id, item_id],
        &format_major.to_be_bytes(),
    )
}

/// Attachment chunks, sealed under the attachment's own key.
pub fn attachment(attachment_id: &[u8; 16]) -> Vec<u8> {
    build("npw/attachment/v1", &[attachment_id], &[])
}

/// The Secret Key and other device secrets stored locally under a device key.
pub fn device_secret(name: &str) -> Vec<u8> {
    build("npw/device-secret/v1/", &[], name.as_bytes())
}

/// The account key wrapped for quick (biometric / PIN) unlock on one device.
pub fn quick_unlock(account_id: &[u8; 16]) -> Vec<u8> {
    build("npw/quick-unlock/v1", &[account_id], &[])
}

/// The account key wrapped under a PIN key on one device (`pin.rs`).
pub fn pin_unlock(account_id: &[u8; 16]) -> Vec<u8> {
    build("npw/pin-unlock/v1", &[account_id], &[])
}

/// Native encrypted exports.
pub fn export(export_id: &[u8; 16]) -> Vec<u8> {
    build("npw/export/v1", &[export_id], &[])
}
