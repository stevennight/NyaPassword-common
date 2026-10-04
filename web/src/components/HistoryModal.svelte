<script lang="ts">
  import { onMount } from 'svelte';
  import { vault } from '$lib/vault.svelte';
  import { confirm, toast } from '$lib/ui.svelte';
  import { dateTime } from '$lib/i18n';
  import type { ItemContent, RevisionInfo } from '$lib/types';
  import Modal from './Modal.svelte';

  let { vaultId, itemId, current, onclose }: { vaultId: string; itemId: string; current: ItemContent; onclose: () => void } = $props();
  let revisions = $state<RevisionInfo[]>([]);
  let error = $state('');
  let open = $state<{ rev: number; content: ItemContent } | null>(null);
  let devices = $state<Record<string, string>>({});
  let showPw = $state(false);

  onMount(async () => {
    try {
      revisions = await vault.bridge.itemHistory(vaultId, itemId);
      const ds = await vault.bridge.devices().catch(() => []);
      devices = Object.fromEntries(ds.map((d) => [d.id, d.name]));
    } catch (e) {
      error = '需要联网才能查看历史版本';
    }
  });

  async function view(rev: number) {
    try {
      open = { rev, content: await vault.bridge.itemRevision(vaultId, itemId, rev) };
    } catch (e) {
      vault.fail(e);
    }
  }

  async function restore(rev: number) {
    if (!(await confirm('恢复到这个版本？', '会作为一个新版本保存，当前内容仍保留在历史里。', '恢复'))) return;
    try {
      await vault.bridge.restoreRevision(vaultId, itemId, rev);
      toast('已恢复（作为新版本保存）');
      await vault.edited();
      onclose();
    } catch (e) {
      vault.fail(e);
    }
  }

  function diff(a: ItemContent, b: ItemContent): string[] {
    const out: string[] = [];
    if (a.title !== b.title) out.push('标题');
    const fa = new Map(a.fields.map((f) => [f.id, JSON.stringify(f.value)]));
    for (const f of b.fields) if (fa.get(f.id) !== JSON.stringify(f.value)) out.push(f.label || f.id);
    if ((a.notes ?? '') !== (b.notes ?? '')) out.push('备注');
    if (JSON.stringify(a.urls ?? []) !== JSON.stringify(b.urls ?? [])) out.push('网址');
    return out;
  }
</script>

<Modal title="历史版本" {onclose} width={620}>
  <p class="muted small">服务器只追加不改写：每次保存都是一个版本，都可以查看和恢复。</p>
  {#if error}<div class="banner small">{error}</div>{/if}
  {#each revisions as r, i (r.revision)}
    <div class="rev">
      <span class="badge" class:acc={i === 0}>r{r.revision}</span>
      <div class="grow">
        <div>{dateTime(r.created_at)}{r.deleted ? ' · 移到回收站' : ''}</div>
        <div class="faint small">{devices[r.device_id] ?? r.device_id.slice(0, 8)}</div>
      </div>
      <button class="btn sm" onclick={() => view(r.revision)}>查看</button>
      {#if i > 0}<button class="btn sm" onclick={() => restore(r.revision)}>恢复</button>{:else}<span class="badge">当前</span>{/if}
    </div>
  {/each}

  {#if current.history?.length}
    <h4>密码历史 <button class="btn ghost sm" onclick={() => (showPw = !showPw)}>{showPw ? '隐藏' : '显示'}</button></h4>
    {#each [...current.history].reverse() as h (h.id)}
      <div class="rev"><span class="grow mono">{showPw ? String(h.value) : '••••••••'}</span><span class="faint small">{h.label || h.field} · 用到 {dateTime(h.until)}</span>
        <button class="btn sm" onclick={async () => { await vault.bridge.copy(String(h.value), true); toast('已复制，90 秒后清除'); }}>复制</button></div>
    {/each}
  {/if}

  {#if open}
    <h4>版本 r{open.rev}</h4>
    <div class="card prev">
      <div><b>{open.content.title}</b></div>
      {#each open.content.fields.filter((f) => f.value) as f (f.id)}
        <div class="small"><span class="faint">{f.label}：</span><span class="mono">{['concealed', 'pin'].includes(f.kind) && !showPw ? '••••••' : typeof f.value === 'string' ? f.value : JSON.stringify(f.value)}</span></div>
      {/each}
      {#if open.content.notes}<div class="small faint" style="white-space:pre-wrap">{open.content.notes}</div>{/if}
      {#if diff(open.content, current).length}<div class="small" style="margin-top:6px">与当前不同：{diff(open.content, current).join('、')}</div>{/if}
    </div>
  {/if}
</Modal>

<style>
  .rev { display: flex; gap: 10px; align-items: center; padding: 8px 0; border-bottom: 1px solid var(--border); }
  h4 { margin: 16px 0 4px; font-size: 13px; }
  .prev { padding: 10px 12px; }
</style>
