<script lang="ts">
  import { vault } from '$lib/vault.svelte';
  import { avatar } from '$lib/ui.svelte';
  import NewItemMenu from './NewItemMenu.svelte';

  let q = $state(vault.query);
  let timer: ReturnType<typeof setTimeout>;
  let showNew = $state(false);

  function onInput() {
    clearTimeout(timer);
    timer = setTimeout(() => vault.search(q), 120);
  }

  function select(v: string, i: string) {
    vault.editing = null;
    vault.selected = { vault_id: v, item_id: i };
  }

  function keys(e: KeyboardEvent) {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    const idx = vault.items.findIndex((x) => x.item_id === vault.selected?.item_id);
    const next = vault.items[Math.max(0, Math.min(vault.items.length - 1, idx + (e.key === 'ArrowDown' ? 1 : -1)))];
    if (next) {
      e.preventDefault();
      select(next.vault_id, next.item_id);
      document.getElementById(`it-${next.item_id}`)?.scrollIntoView({ block: 'nearest' });
    }
  }

  const title = $derived.by(() => {
    const n = vault.nav;
    if (n.kind === 'trash') return '回收站';
    if (n.kind === 'archived') return '归档';
    if (n.kind === 'conflicts') return '待处理冲突';
    return '';
  });
</script>

<svelte:window onkeydown={(e) => { if ((e.ctrlKey || e.metaKey) && e.key === 'f') { e.preventDefault(); document.getElementById('search')?.focus(); } }} />

<section class="list">
  <div class="search">
    <input id="search" class="input" bind:value={q} oninput={onInput} onkeydown={keys} placeholder="搜索，支持拼音首字母（Ctrl+F）" autocomplete="off" />
    {#if vault.nav.kind !== 'trash'}
      <button class="btn primary" onclick={() => (showNew = true)}>＋ 新建</button>
    {/if}
  </div>
  {#if title}<div class="sub">{title} · {vault.items.length}</div>{/if}
  <div class="items">
    {#each vault.items as it (it.vault_id + it.item_id)}
      {@const a = avatar(it.title, it.template)}
      <button id="it-{it.item_id}" class="item" class:on={it.item_id === vault.selected?.item_id} onclick={() => select(it.vault_id, it.item_id)}>
        <div class="ico" style="background:{a.color}">{a.letter}</div>
        <div class="grow">
          <div class="t">{it.title || '（无标题）'}</div>
          <div class="s">{it.subtitle || (it.urls[0] ? vault.bridge.displayHost(it.urls[0]) : '')}</div>
        </div>
        {#if it.conflicts > 0}<span class="badge warn">冲突</span>
        {:else if it.rejected}<span class="badge bad">未同步</span>
        {:else if it.pending}<span class="badge" title="尚未同步到服务器">⇡</span>
        {:else if it.favorite}<span class="star">★</span>{/if}
      </button>
    {:else}
      <div class="empty">{vault.query ? '没有匹配的条目' : '这里还没有条目'}</div>
    {/each}
  </div>
</section>

{#if showNew}<NewItemMenu onclose={() => (showNew = false)} />{/if}

<style>
  .list { border-right: 1px solid var(--border); display: flex; flex-direction: column; min-width: 0; background: var(--surface); }
  .search { padding: 12px; border-bottom: 1px solid var(--border); display: flex; gap: 8px; }
  .sub { padding: 6px 14px; font-size: 12px; color: var(--text-3); border-bottom: 1px solid var(--border); }
  .items { overflow: auto; flex: 1; }
  .item { display: flex; gap: 10px; align-items: center; padding: 9px 12px; border: 0; border-bottom: 1px solid var(--border); width: 100%; background: transparent; text-align: left; }
  .item:hover { background: var(--surface-2); }
  .item.on { background: var(--sel); }
  .t { font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .s { font-size: 12.5px; color: var(--text-2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-height: 18px; }
  .star { color: var(--warn); font-size: 12px; }
  .empty { padding: 40px 16px; text-align: center; color: var(--text-3); }
</style>
