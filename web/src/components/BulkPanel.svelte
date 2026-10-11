<script lang="ts">
  import { vault } from '$lib/vault.svelte';
  import { avatar } from '$lib/ui.svelte';
  import { bulkMenu } from '$lib/bulk.svelte';
  import type { MenuItem } from '$lib/menu.svelte';

  const items = $derived(vault.pickedItems());
  const actions = $derived.by(() => {
    void items;
    return bulkMenu().filter((e): e is MenuItem => e !== null);
  });
  const SHOWN = 40;
</script>

<div class="page">
  <h2>已选择 {items.length} 个条目</h2>
  <p class="muted small">按住 Ctrl（Mac 为 ⌘）点击可多选，按住 Shift 点击可连续选择；Esc 取消选择。</p>
  <div class="acts">
    {#each actions as a (a.label)}
      <button class="btn {a.danger ? 'danger' : ''}" disabled={a.disabled} onclick={() => a.run()}>{a.label}</button>
    {/each}
    <button class="btn ghost" onclick={() => vault.clearPicks()}>取消选择</button>
  </div>
  <div class="card">
    {#each items.slice(0, SHOWN) as it (it.vault_id + it.item_id)}
      {@const a = avatar(it.title, it.template)}
      <div class="line">
        <div class="ico" style="background:{a.color}">{a.letter}</div>
        <div class="grow">
          <div class="t">{it.title || '（无标题）'}</div>
          <div class="s">{it.subtitle || (it.urls[0] ? vault.bridge.displayHost(it.urls[0]) : '')}</div>
        </div>
        {#each it.tags.slice(0, 3) as t (t)}<span class="chip">#{t}</span>{/each}
        <button class="btn ghost sm" aria-label="不选这个" title="不选这个" onclick={() => vault.togglePick(it)}>✕</button>
      </div>
    {/each}
    {#if items.length > SHOWN}<div class="line faint">还有 {items.length - SHOWN} 个…</div>{/if}
  </div>
</div>

<style>
  .page { padding: 22px 28px 40px; max-width: 860px; }
  h2 { margin: 0 0 4px; }
  .acts { display: flex; flex-wrap: wrap; gap: 8px; margin: 14px 0 18px; }
  .line { display: flex; align-items: center; gap: 10px; padding: 8px 12px; border-bottom: 1px solid var(--border); }
  .line:last-child { border-bottom: 0; }
  .grow { min-width: 0; }
  .t { font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .s { font-size: 12.5px; color: var(--text-2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .chip { font-size: 12px; padding: 1px 8px; border-radius: 999px; background: var(--surface-3); white-space: nowrap; }
</style>
