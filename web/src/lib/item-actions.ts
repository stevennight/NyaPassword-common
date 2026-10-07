// Item actions shared by the detail view and the item list's right-click menu.

import { webUrl, openExternal } from './links';
import type { MenuEntry } from './menu.svelte';
import type { Field, ItemView } from './types';
import { confirm, toast } from './ui.svelte';
import { vault } from './vault.svelte';

/** `view` must carry its content (`bridge.item`). */
export async function toggleFlag(view: ItemView, key: 'favorite' | 'archived') {
  const c = view.content;
  if (!c) return;
  const next = { ...c, [key]: !c[key] };
  try {
    await vault.bridge.saveItem(view.vault_id, view.item_id, next);
    toast(key === 'favorite' ? (next.favorite ? '已收藏' : '已取消收藏') : next.archived ? '已归档' : '已取消归档');
    await vault.edited();
  } catch (e) {
    vault.fail(e);
  }
}

export async function moveToTrash(view: ItemView) {
  if (!(await confirm('移到回收站？', `“${view.title}”会移到回收站，可以随时恢复。`, '移到回收站', true))) return;
  try {
    await vault.bridge.deleteItem(view.vault_id, view.item_id);
    await vault.edited();
  } catch (e) {
    vault.fail(e);
  }
}

export async function restoreFromTrash(view: ItemView) {
  try {
    await vault.bridge.restoreItem(view.vault_id, view.item_id);
    toast('已从回收站恢复');
    await vault.edited();
  } catch (e) {
    vault.fail(e);
  }
}

export async function purgeItem(view: ItemView) {
  if (!(await confirm('永久删除？', `“${view.title}”及其全部历史版本和附件会从服务器上删除，无法恢复（备份里还有）。`, '永久删除', true))) return;
  try {
    await vault.bridge.purge(view.vault_id, [view.item_id]);
    toast('已永久删除');
    if (vault.selected?.item_id === view.item_id) vault.selected = null;
    await vault.reload();
  } catch (e) {
    vault.fail(e);
  }
}

export function isSecret(f: Field): boolean {
  return f.kind === 'concealed' || f.kind === 'pin';
}

/** Copies a field's value (a TOTP field: the current code); secrets are cleared from the clipboard later. */
export async function copyValue(f: Field, value: string, label = f.label) {
  let text = value;
  if (f.kind === 'totp') text = vault.bridge.otpCode(value, Math.floor(Date.now() / 1000))?.code ?? '';
  const secret = isSecret(f) || f.kind === 'totp';
  try {
    await vault.bridge.copy(text, secret);
    toast(secret ? `已复制${label}，90 秒后清除` : `已复制${label}`);
  } catch (e) {
    vault.fail(e);
  }
}

function filled(f: Field | undefined): f is Field & { value: string } {
  return !!f && typeof f.value === 'string' && f.value !== '';
}

/** The right-click menu of an item in the list. `view` must carry its content. */
export function itemMenu(view: ItemView): MenuEntry[] {
  if (view.deleted) {
    return [
      { label: '恢复', run: () => restoreFromTrash(view) },
      null,
      { label: '永久删除', danger: true, run: () => purgeItem(view) },
    ];
  }
  const c = view.content;
  // "使用前需要验证": nothing to copy and no editing until the user verifies in the detail view
  const locked = vault.gated(view);
  const fields = c?.fields ?? [];
  const user = fields.find((f) => f.purpose === 'username');
  const pass = fields.find((f) => f.purpose === 'password');
  const totp = fields.find((f) => f.kind === 'totp');
  const site = view.urls.map(webUrl).find((u) => u !== null);
  const out: MenuEntry[] = [];
  if (!locked) {
    if (filled(user)) out.push({ label: `复制${user.label || '用户名'}`, run: () => copyValue(user, user.value) });
    if (filled(pass)) out.push({ label: `复制${pass.label || '密码'}`, run: () => copyValue(pass, pass.value) });
    if (filled(totp)) out.push({ label: '复制验证码', run: () => copyValue(totp, totp.value, '验证码') });
  }
  if (site) out.push({ label: '打开网站', run: () => openExternal(site).catch(vault.fail.bind(vault)) });
  out.push(null);
  if (!locked && !view.read_only) out.push({ label: '编辑', run: () => (vault.editing = { vault_id: view.vault_id, item_id: view.item_id }) });
  if (c) {
    out.push({ label: c.favorite ? '取消收藏' : '收藏', run: () => toggleFlag(view, 'favorite') });
    out.push({ label: c.archived ? '取消归档' : '归档', run: () => toggleFlag(view, 'archived') });
  }
  out.push(null, { label: '删除', danger: true, run: () => moveToTrash(view) });
  return out;
}
