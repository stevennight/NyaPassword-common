// "使用前需要验证" (item `reprompt`, like Bitwarden's master password
// re-prompt). A UI guard against someone at an unlocked, unattended screen:
// the item is encrypted like any other. The verification is for one item and
// lasts while that item stays open; selecting another item or locking ends it.

export interface ItemRef {
  vault_id: string;
  item_id: string;
  reprompt?: boolean;
}

export function itemKey(vaultId: string, itemId: string): string {
  return `${vaultId}/${itemId}`;
}

/** The item's secrets stay hidden: it asks for verification and was not verified since it was opened. */
export function gated(item: ItemRef | null | undefined, verified: string | null): boolean {
  if (!item?.reprompt) return false;
  return verified !== itemKey(item.vault_id, item.item_id);
}

/** The verification that survives opening an item: kept for the same item, dropped for any other. */
export function afterOpen(verified: string | null, vaultId: string, itemId: string): string | null {
  return verified === itemKey(vaultId, itemId) ? verified : null;
}

/** A message for a failed verification. */
export function verifyError(code: string, message: string): string {
  if (code === 'wrong_password') return '主密码不正确';
  if (code === 'locked') return '已锁定，请先解锁';
  return message || code || '验证失败';
}
