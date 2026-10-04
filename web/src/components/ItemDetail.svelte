<script lang="ts">
  import { vault } from '$lib/vault.svelte';
  import { avatar, confirm, toast, TEMPLATE_ICONS } from '$lib/ui.svelte';
  import { bytes, dateTime, relativeTime } from '$lib/i18n';
  import type { Field, ItemView } from '$lib/types';
  import FieldRow from './FieldRow.svelte';
  import HistoryModal from './HistoryModal.svelte';
  import Modal from './Modal.svelte';

  let { vaultId, itemId }: { vaultId: string; itemId: string } = $props();
  let view = $state<ItemView | null>(null);
  let showHistory = $state(false);
  let compare = $state(false);

  $effect(() => {
    void vault.version;
    vault.bridge.item(vaultId, itemId).then((v) => (view = v)).catch(() => (view = null));
  });

  const c = $derived(view?.content);
  const tpl = $derived(vault.templates.find((t) => t.id === view?.template));
  const groups = $derived.by(() => {
    if (!c) return [] as { label: string; fields: Field[] }[];
    const visible = c.fields.filter((f) => !isEmpty(f));
    const out: { label: string; fields: Field[] }[] = [{ label: '', fields: visible.filter((f) => !f.section) }];
    for (const s of c.sections ?? []) out.push({ label: s.label, fields: visible.filter((f) => f.section === s.id) });
    const known = new Set((c.sections ?? []).map((s) => s.id));
    const orphans = visible.filter((f) => f.section && !known.has(f.section));
    if (orphans.length) out.push({ label: '其他', fields: orphans });
    return out.filter((g) => g.fields.length);
  });

  function isEmpty(f: Field) {
    if (f.value == null) return true;
    if (typeof f.value === 'string') return f.value === '';
    if (typeof f.value === 'object') return Object.values(f.value as object).every((v) => !v);
    return false;
  }

  async function toggle(key: 'favorite' | 'archived') {
    if (!c || !view) return;
    const next = { ...c, [key]: !c[key] };
    try {
      await vault.bridge.saveItem(vaultId, itemId, next);
      toast(key === 'favorite' ? (next.favorite ? '已收藏' : '已取消收藏') : next.archived ? '已归档' : '已取消归档');
      await vault.edited();
    } catch (e) {
      vault.fail(e);
    }
  }

  async function remove() {
    if (!view) return;
    if (!(await confirm('移到回收站？', `“${view.title}”会移到回收站，可以随时恢复。`, '移到回收站', true))) return;
    try {
      await vault.bridge.deleteItem(vaultId, itemId);
      await vault.edited();
    } catch (e) {
      vault.fail(e);
    }
  }

  async function restore() {
    try {
      await vault.bridge.restoreItem(vaultId, itemId);
      toast('已从回收站恢复');
      await vault.edited();
    } catch (e) {
      vault.fail(e);
    }
  }

  async function purge() {
    if (!view) return;
    if (!(await confirm('永久删除？', `“${view.title}”及其全部历史版本和附件会从服务器上删除，无法恢复（备份里还有）。`, '永久删除', true))) return;
    try {
      await vault.bridge.purge(vaultId, [itemId]);
      toast('已永久删除');
      vault.selected = null;
      await vault.reload();
    } catch (e) {
      vault.fail(e);
    }
  }

  async function resolve(conflictId: string, useOther: boolean) {
    try {
      await vault.bridge.resolveConflict(vaultId, itemId, conflictId, useOther);
      toast(useOther ? '已改用另一个值' : '已保留当前值');
      await vault.edited();
    } catch (e) {
      vault.fail(e);
    }
  }

  async function openAttachment(id: string, name: string, mime?: string) {
    try {
      const data = await vault.bridge.attachment(vaultId, itemId, id);
      await vault.bridge.saveFile(name, data, mime || 'application/octet-stream');
    } catch (e) {
      vault.fail(e);
    }
  }

  function show(v: unknown): string {
    if (v == null) return '（空）';
    return typeof v === 'string' ? v : JSON.stringify(v);
  }
</script>

{#if view && c}
  {@const a = avatar(view.title, view.template)}
  <div class="detail">
    <div class="head">
      <div class="ico big" style="background:{a.color}">{a.letter}</div>
      <div class="grow">
        <h2>{view.title || '（无标题）'}</h2>
        <div class="muted small">
          {TEMPLATE_ICONS[view.template] ?? ''} {tpl?.label ?? view.template} · {vault.vaults.find((v) => v.id === vaultId)?.name}
          {#each c.tags ?? [] as t (t)}<span class="chip">#{t}</span>{/each}
        </div>
      </div>
      <div class="acts">
        {#if view.deleted}
          <button class="btn sm" onclick={restore}>恢复</button>
          <button class="btn sm danger" onclick={purge}>永久删除</button>
        {:else}
          <button class="btn sm" title="收藏" onclick={() => toggle('favorite')}>{c.favorite ? '★' : '☆'}</button>
          <button class="btn sm primary" disabled={view.read_only} onclick={() => (vault.editing = { vault_id: vaultId, item_id: itemId })}>编辑</button>
          <button class="btn sm" onclick={() => toggle('archived')}>{c.archived ? '取消归档' : '归档'}</button>
          <button class="btn sm danger" onclick={remove}>删除</button>
        {/if}
      </div>
    </div>

    {#if view.read_only}
      <div class="banner small">这个条目由更新版本的 NyaPassword 写入，此版本只能查看。更新应用后即可编辑。</div>
    {/if}
    {#if view.rejected}
      <div class="banner bad small">服务器拒绝了对这个条目的修改：{view.rejected}。你的修改仍保存在本设备上。</div>
    {/if}
    {#if c.conflicts?.length}
      <div class="banner">
        <span>⚠</span>
        <div class="grow">
          <b>同步冲突</b>：{c.conflicts.length} 处在不同设备上被改成了不同的值。两个值都已保留，请选择要用哪个。
          <div style="margin-top:8px"><button class="btn sm" onclick={() => (compare = true)}>逐项处理</button></div>
        </div>
      </div>
    {/if}

    {#each groups as g, gi (gi)}
      <div class="card sec">
        {#if g.label}<div class="sec-h">{g.label}</div>{/if}
        {#each g.fields as f (f.id)}<FieldRow field={f} />{/each}
      </div>
    {/each}

    {#if c.passkeys?.length}
      <div class="card sec">
        <div class="sec-h">通行密钥</div>
        {#each c.passkeys as p (p.id)}
          <div class="row line"><span class="badge acc">passkey</span><span class="grow">{p.rp_id} · {p.user_name || p.user_display_name}</span><span class="faint small">{p.created_at ? relativeTime(p.created_at) : ''}</span></div>
        {/each}
      </div>
    {/if}

    {#if c.urls?.length}
      <div class="card sec">
        <div class="sec-h">网站与应用</div>
        {#each c.urls as u (u.id)}
          <div class="row line">
            {#if u.url.startsWith('androidapp://')}
              <span class="grow">📱 {u.url.slice(13)}</span>{#if u.cert_sha256?.length}<span class="badge ok">签名已记录</span>{/if}
            {:else}
              <a class="grow" href={/^https?:/.test(u.url) ? u.url : `https://${u.url}`} target="_blank" rel="noreferrer noopener">{u.url}</a>
            {/if}
            <span class="badge">{({ domain: '域名匹配', host: '主机匹配', starts_with: '前缀匹配', exact: '完全匹配', regex: '正则', never: '从不填写' } as Record<string, string>)[u.match] ?? u.match}</span>
          </div>
        {/each}
      </div>
    {/if}

    {#if c.notes}
      <div class="card sec"><div class="sec-h">备注</div><div class="notes">{c.notes}</div></div>
    {/if}

    {#if c.attachments?.length}
      <div class="card sec">
        <div class="sec-h">附件</div>
        {#each c.attachments as at (at.id)}
          <div class="row line"><span class="grow">📎 {at.name}</span><span class="faint small">{bytes(at.size)}</span><button class="btn sm" onclick={() => openAttachment(at.id, at.name, at.mime)}>下载</button></div>
        {/each}
      </div>
    {/if}

    <div class="meta">
      <span>修改于 {dateTime(c.updated_at)}</span>
      <span>创建于 {dateTime(c.created_at)}</span>
      {#if view.pending}<span class="badge">尚未同步</span>{/if}
      <button class="link" onclick={() => (showHistory = true)}>历史版本{view.revision ? `（${view.revision}）` : ''}</button>
      {#if c.history?.length}<span>密码历史 {c.history.length} 条</span>{/if}
      <span>格式 {c.format}</span>
    </div>
  </div>

  {#if showHistory}<HistoryModal {vaultId} {itemId} current={c} onclose={() => (showHistory = false)} />{/if}

  {#if compare}
    <Modal title="处理同步冲突" onclose={() => (compare = false)} width={640}>
      <p class="muted small">左边是现在保留的值，右边是另一台设备上的值。选了哪个都不会丢：另一个值仍在历史版本里。</p>
      {#each c.conflicts ?? [] as cf (cf.id)}
        <div class="card cf">
          <div class="sec-h">{cf.label || cf.path} · {relativeTime(cf.at)}</div>
          <div class="cmp">
            <div><div class="faint small">当前</div><div class="mono pre">{show(cf.kept)}</div><button class="btn sm primary" onclick={() => resolve(cf.id, false)}>保留当前值</button></div>
            <div><div class="faint small">另一台设备</div><div class="mono pre">{show(cf.value)}</div><button class="btn sm" onclick={() => resolve(cf.id, true)}>改用这个</button></div>
          </div>
        </div>
      {/each}
    </Modal>
  {/if}
{:else}
  <div class="empty faint">选择一个条目</div>
{/if}

<style>
  .detail { padding: 22px 28px 40px; max-width: 860px; }
  .head { display: flex; align-items: center; gap: 14px; margin-bottom: 16px; }
  .ico.big { width: 52px; height: 52px; border-radius: 13px; font-size: 22px; }
  h2 { margin: 0; font-size: 20px; word-break: break-word; }
  .acts { display: flex; gap: 6px; flex-wrap: wrap; justify-content: flex-end; }
  .chip { margin-left: 6px; font-size: 12px; padding: 1px 8px; border-radius: 999px; background: var(--surface-3); }
  .banner { margin-bottom: 14px; }
  .sec { margin-bottom: 14px; }
  .sec-h { padding: 7px 14px; font-size: 11.5px; font-weight: 600; color: var(--text-3); background: var(--surface-2); border-bottom: 1px solid var(--border); letter-spacing: .04em; }
  .line { padding: 9px 14px; border-bottom: 1px solid var(--border); }
  .line:last-child { border-bottom: 0; }
  .line a { color: var(--accent); word-break: break-all; }
  .notes { padding: 10px 14px; white-space: pre-wrap; }
  .meta { font-size: 12px; color: var(--text-3); display: flex; gap: 14px; flex-wrap: wrap; align-items: center; }
  .link { border: 0; background: none; color: var(--accent); padding: 0; font-size: 12px; }
  .empty { height: 100%; display: grid; place-items: center; }
  .cf { margin-bottom: 12px; }
  .cmp { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; padding: 10px 14px; }
  .pre { white-space: pre-wrap; word-break: break-all; margin: 4px 0 8px; padding: 6px 8px; background: var(--surface-2); border-radius: 6px; min-height: 30px; }
</style>
