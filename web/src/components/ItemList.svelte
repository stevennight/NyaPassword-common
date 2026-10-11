<script lang="ts">
  import { vault } from '$lib/vault.svelte';
  import { avatar } from '$lib/ui.svelte';
  import { itemMenu } from '$lib/item-actions';
  import { bulkMenu } from '$lib/bulk.svelte';
  import { openMenu } from '$lib/menu.svelte';
  import type { ItemView } from '$lib/types';
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

  // where a Shift+click range starts
  let anchor: ItemView | null = null;

  function onClick(e: MouseEvent, it: ItemView) {
    if (e.shiftKey && (vault.selecting || vault.selected)) {
      const from = anchor ?? vault.items.find((x) => x.item_id === vault.selected?.item_id) ?? it;
      vault.pickRange(from, it);
      anchor = from;
      return;
    }
    if (e.ctrlKey || e.metaKey) {
      // the item open so far joins the selection
      if (!vault.selecting && vault.selected && vault.selected.item_id !== it.item_id) {
        const cur = vault.items.find((x) => x.item_id === vault.selected?.item_id);
        if (cur) vault.togglePick(cur);
      }
      vault.togglePick(it);
      anchor = it;
      return;
    }
    if (vault.selecting) {
      vault.togglePick(it);
      anchor = it;
      return;
    }
    anchor = it;
    select(it.vault_id, it.item_id);
  }

  function actionsMenu(e: MouseEvent) {
    const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
    openMenu(new MouseEvent('contextmenu', { clientX: r.left, clientY: r.bottom + 4 }), bulkMenu());
  }

  function onKey(e: KeyboardEvent) {
    const t = e.target as HTMLElement | null;
    const typing = !!t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable);
    if (vault.page !== 'items' || vault.editing || e.defaultPrevented) return;
    if (e.key === 'Escape' && vault.selecting && !document.querySelector('[aria-modal="true"]')) {
      vault.clearPicks();
    } else if ((e.ctrlKey || e.metaKey) && e.key === 'a' && !typing && vault.items.length) {
      e.preventDefault();
      vault.pickAll();
    }
  }

  async function contextMenu(e: MouseEvent, it: ItemView) {
    e.preventDefault();
    if (vault.selecting && vault.picked.length > 1 && vault.isPicked(it)) {
      openMenu(e, bulkMenu());
      return;
    }
    if (vault.selecting) vault.clearPicks();
    select(it.vault_id, it.item_id);
    try {
      openMenu(e, itemMenu(await vault.bridge.item(it.vault_id, it.item_id)));
    } catch (err) {
      vault.fail(err);
    }
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

<svelte:window onkeydown={(e) => { if ((e.ctrlKey || e.metaKey) && e.key === 'f') { e.preventDefault(); document.getElementById('search')?.focus(); } else onKey(e); }} />

<section class="list">
  <div class="search">
    <input id="search" class="input" bind:value={q} oninput={onInput} onkeydown={keys} placeholder="搜索，支持拼音首字母（Ctrl+F）" autocomplete="off" />
    {#if !vault.selecting}
      <button class="btn ghost" title="多选（Ctrl / Shift + 点击）" onclick={() => (vault.selecting = true)} disabled={!vault.items.length}>选择</button>
    {/if}
    {#if vault.nav.kind !== 'trash' && !vault.selecting}
      <button class="btn primary" onclick={() => (showNew = true)}>＋ 新建</button>
    {/if}
  </div>
  {#if vault.selecting}
    {@const all = vault.picked.length === vault.items.length && vault.items.length > 0}
    <div class="selbar">
      <label class="all"><input type="checkbox" checked={all} onchange={() => (all ? (vault.picked = []) : vault.pickAll())} /> 全选</label>
      <span class="grow faint">已选 {vault.picked.length} 项</span>
      <button class="btn sm primary" disabled={!vault.picked.length} onclick={actionsMenu}>操作 ▾</button>
      <button class="btn sm ghost" onclick={() => vault.clearPicks()}>完成</button>
    </div>
  {/if}
  {#if title}<div class="sub">{title} · {vault.items.length}</div>{/if}
  <div class="items">
    {#each vault.items as it (it.vault_id + it.item_id)}
      {@const a = avatar(it.title, it.template)}
      {@const picked = vault.selecting && vault.isPicked(it)}
      <button id="it-{it.item_id}" class="item" class:on={vault.selecting ? picked : it.item_id === vault.selected?.item_id} aria-pressed={vault.selecting ? picked : undefined} onmousedown={(e) => e.shiftKey && e.preventDefault()} onclick={(e) => onClick(e, it)} oncontextmenu={(e) => contextMenu(e, it)}>
        {#if vault.selecting}<input class="pick" type="checkbox" tabindex="-1" checked={picked} aria-hidden="true" />{/if}
        <div class="ico" style="background:{a.color}">{a.letter}</div>
        <div class="grow">
          <div class="t">{it.title || '（无标题）'}</div>
          <div class="s">{it.subtitle || (it.urls[0] ? vault.bridge.displayHost(it.urls[0]) : '')}</div>
        </div>
        {#if it.reprompt}<span class="lock" title="使用前需要验证">🔒</span>{/if}
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
  .selbar { display: flex; align-items: center; gap: 8px; padding: 6px 12px; border-bottom: 1px solid var(--border); background: var(--surface-2); font-size: 13px; }
  .all { display: flex; align-items: center; gap: 6px; cursor: pointer; }
  .pick { pointer-events: none; margin: 0; flex: none; }
  .sub { padding: 6px 14px; font-size: 12px; color: var(--text-3); border-bottom: 1px solid var(--border); }
  .items { overflow: auto; flex: 1; }
  .item { display: flex; gap: 10px; align-items: center; padding: 9px 12px; border: 0; border-bottom: 1px solid var(--border); width: 100%; background: transparent; text-align: left; }
  .item:hover { background: var(--surface-2); }
  .item.on { background: var(--sel); }
  .t { font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .s { font-size: 12.5px; color: var(--text-2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-height: 18px; }
  .star { color: var(--warn); font-size: 12px; }
  .lock { font-size: 11px; opacity: .7; }
  .empty { padding: 40px 16px; text-align: center; color: var(--text-3); }
</style>
