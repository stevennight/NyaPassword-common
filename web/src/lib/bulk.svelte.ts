// Tidying up: bulk actions on the items picked in the list, renaming and
// deleting tags, and merging items. The work is done by the core
// (npw-core organize.rs); this is the UI around it.

import type { MenuEntry } from './menu.svelte';
import type { BulkAction, BulkReport, ItemRef, ItemView, MergeReport } from './types';
import { chooseMany, confirm, promptText, toast } from './ui.svelte';
import { vault } from './vault.svelte';

/** Same as the core's `normalize_tag`: `" 工作 / 开发/ "` → `工作/开发`. */
export function normalizeTag(tag: string): string {
  return tag
    .split('/')
    .map((p) => p.trim())
    .filter(Boolean)
    .join('/');
}

/** Comma-separated tags (as in the item editor), normalized, without repeats. */
export function parseTags(text: string): string[] {
  const out: string[] = [];
  for (const t of text.split(/[,，]/)) {
    const n = normalizeTag(t);
    if (n && !out.includes(n)) out.push(n);
  }
  return out;
}

const refs = (items: ItemView[]): ItemRef[] => items.map((i) => ({ vault_id: i.vault_id, item_id: i.item_id }));

function reportText(r: BulkReport, verb = '更新'): string {
  let s = r.changed ? `已${verb} ${r.changed} 个条目` : '没有需要修改的条目';
  const readOnly = r.skipped.filter((x) => x.reason === 'read_only').length;
  if (readOnly) s += `；${readOnly} 个由更新版本的 NyaPassword 写入，已跳过`;
  return s;
}

async function run(action: BulkAction, verb?: string) {
  const items = vault.pickedItems();
  if (!items.length) return;
  try {
    const r = await vault.bridge.bulkUpdate(refs(items), action);
    toast(reportText(r, verb), r.skipped.length ? 'info' : 'ok', r.skipped.length ? 5000 : 2600);
    await vault.edited();
  } catch (e) {
    vault.fail(e);
  }
}

export async function bulkAddTags() {
  const n = vault.pickedItems().length;
  const text = await promptText('添加标签', `给选中的 ${n} 个条目加上标签。多个标签用逗号分隔，“工作/开发”表示嵌套。`, {
    suggestions: vault.tags,
    placeholder: '例如：工作, 家庭/水电',
    ok: '添加',
  });
  if (text === null) return;
  const tags = parseTags(text);
  if (tags.length) await run({ kind: 'add_tags', tags });
}

export async function bulkRemoveTags() {
  const items = vault.pickedItems();
  const present = [...new Set(items.flatMap((i) => i.tags))].sort((a, b) => a.localeCompare(b, 'zh-CN'));
  if (!present.length) {
    toast('选中的条目都没有标签');
    return;
  }
  const tags = await chooseMany('移除标签', `从选中的 ${items.length} 个条目上去掉这些标签：`, present, '移除');
  if (tags?.length) await run({ kind: 'remove_tags', tags });
}

export async function bulkTrash() {
  const n = vault.pickedItems().length;
  if (!(await confirm('移到回收站？', `选中的 ${n} 个条目会移到回收站，可以随时恢复。`, '移到回收站', true))) return;
  await run({ kind: 'trash' }, '移到回收站');
}

export async function bulkPurge() {
  const items = vault.pickedItems().filter((i) => i.deleted);
  if (!items.length) return;
  if (!(await confirm('永久删除？', `选中的 ${items.length} 个条目及其全部历史版本和附件会从服务器上删除，无法恢复（备份里还有）。`, '永久删除', true))) return;
  const byVault = new Map<string, string[]>();
  for (const i of items) byVault.set(i.vault_id, [...(byVault.get(i.vault_id) ?? []), i.item_id]);
  try {
    let n = 0;
    for (const [v, ids] of byVault) n += (await vault.bridge.purge(v, ids)).length;
    toast(`已永久删除 ${n} 个条目`, 'ok');
    vault.selected = null;
    await vault.reload();
  } catch (e) {
    vault.fail(e);
  }
}

/** The merge dialog over the picked items (`MergeDialog`, shown by `Shell`). */
export const mergeState = $state<{ items: ItemView[] | null }>({ items: null });

export function bulkMerge() {
  const items = vault.pickedItems();
  if (items.length < 2) {
    toast('至少选择两个条目才能合并');
    return;
  }
  mergeState.items = items;
}

/** What the bulk action menu offers for the picked items. */
export function bulkMenu(): MenuEntry[] {
  const items = vault.pickedItems();
  if (!items.length) return [];
  if (vault.nav.kind === 'trash') {
    return [
      { label: `恢复 ${items.length} 个条目`, run: () => run({ kind: 'restore' }, '恢复') },
      null,
      { label: '永久删除…', danger: true, run: bulkPurge },
    ];
  }
  const out: MenuEntry[] = [];
  if (items.some((i) => !i.favorite)) out.push({ label: '加入收藏', run: () => run({ kind: 'favorite', on: true }) });
  if (items.some((i) => i.favorite)) out.push({ label: '取消收藏', run: () => run({ kind: 'favorite', on: false }) });
  if (items.some((i) => !i.archived)) out.push({ label: '归档', run: () => run({ kind: 'archive', on: true }, '归档') });
  if (items.some((i) => i.archived)) out.push({ label: '取消归档', run: () => run({ kind: 'archive', on: false }) });
  out.push(null, { label: '添加标签…', run: bulkAddTags });
  if (items.some((i) => i.tags.length)) out.push({ label: '移除标签…', run: bulkRemoveTags });
  out.push(null, { label: '合并为一个条目…', disabled: items.length < 2, run: bulkMerge });
  out.push(null, { label: '移到回收站…', danger: true, run: bulkTrash });
  return out;
}

// ------------------------------------------------------------------ tags

export async function renameTag(tag: string) {
  const text = await promptText('重命名标签', `“${tag}”及其子标签会在所有条目上改名（回收站里的也会改）。用“/”表示嵌套，如“工作/开发”。`, {
    value: tag,
    ok: '重命名',
  });
  if (text === null) return;
  const to = normalizeTag(text);
  if (!to || to === tag) return;
  if (vault.tags.some((t) => t === to || t.startsWith(`${to}/`))) {
    if (!(await confirm('合并标签？', `已经有标签“${to}”，“${tag}”会并入其中。`, '合并'))) return;
  }
  try {
    const r = await vault.bridge.renameTag(tag, to);
    toast(reportText(r), 'ok');
    // the sidebar filters by top-level tags: follow a renamed one
    if (vault.nav.kind === 'tag' && vault.nav.id === tag) await vault.setNav({ kind: 'tag', id: to.split('/')[0] ?? to });
    await vault.edited();
  } catch (e) {
    vault.fail(e);
  }
}

export async function deleteTag(tag: string, items?: number) {
  const n = items === undefined ? '' : ` ${items} 个`;
  if (!(await confirm('删除标签？', `会从${n}条目上去掉“${tag}”及其子标签，条目本身不受影响。`, '删除标签', true))) return;
  try {
    const r = await vault.bridge.deleteTag(tag);
    toast(reportText(r), 'ok');
    if (vault.nav.kind === 'tag' && vault.nav.id === tag) await vault.setNav({ kind: 'all' });
    await vault.edited();
  } catch (e) {
    vault.fail(e);
  }
}

// ----------------------------------------------------------------- merge

/** Why these items cannot be merged as they are (empty: they can). */
export function mergeBlocker(items: ItemView[]): string {
  if (items.some((i) => i.conflicts > 0)) return '其中有条目存在同步冲突，请先处理冲突再合并';
  if (items.some((i) => i.read_only)) return '其中有条目由更新版本的 NyaPassword 写入，请先更新本应用';
  if (items.some((i) => i.deleted)) return '回收站里的条目不能合并';
  return '';
}

export function mergeText(r: MergeReport): string {
  let s = `已合并，${r.trashed} 个条目移到了回收站`;
  if (r.secrets_to_history) s += `，${r.secrets_to_history} 个不同的密码存入了密码历史`;
  if (r.attachments_copied) s += `，复制了 ${r.attachments_copied} 个附件`;
  return s;
}

/** Merges `others` into `keep`; true when done. */
export async function mergeItems(keep: ItemView, others: ItemView[]): Promise<boolean> {
  try {
    const r = await vault.bridge.mergeItems(
      { vault_id: keep.vault_id, item_id: keep.item_id },
      others.map((o) => ({ vault_id: o.vault_id, item_id: o.item_id })),
    );
    toast(mergeText(r), 'ok', 5000);
    await vault.edited();
    return true;
  } catch (e) {
    vault.fail(e);
    return false;
  }
}
