<script lang="ts">
  import { vault } from '$lib/vault.svelte';
  import { relativeTime } from '$lib/i18n';
  import Sidebar from './Sidebar.svelte';
  import ItemList from './ItemList.svelte';
  import ItemDetail from './ItemDetail.svelte';
  import ItemEditor from './ItemEditor.svelte';
  import SecurityPage from './SecurityPage.svelte';
  import SettingsPage from './SettingsPage.svelte';
  import ImportPage from './ImportPage.svelte';
  import Generator from './Generator.svelte';

  let navOpen = $state(false);
  let now = $state(Date.now());
  setInterval(() => (now = Date.now()), 30_000);

  const editKey = $derived(vault.editing ? vault.editing.vault_id + (vault.editing.item_id ?? 'new' + vault.newTemplate) : '');
  const selKey = $derived(vault.selected?.item_id ?? '');
  const showingDetail = $derived(vault.page !== 'items' || !!vault.editing || !!vault.selected);

  // close the drawer whenever the user navigates
  $effect(() => {
    void vault.nav;
    void vault.page;
    navOpen = false;
  });

  function back() {
    if (vault.page !== 'items') vault.page = 'items';
    else if (vault.editing) vault.editing = null;
    else vault.selected = null;
  }
</script>

<svelte:window onkeydown={(e) => { if ((e.ctrlKey || e.metaKey) && e.key === 'l') { e.preventDefault(); void vault.doLock(); } }} />

<div class="shell" class:detail={showingDetail} class:wide-page={vault.page !== 'items'}>
  <header class="top">
    <button class="btn ghost sm menu" onclick={() => (navOpen = !navOpen)} aria-label="菜单">☰</button>
    <button class="btn ghost sm backbtn" onclick={back}>‹ 返回</button>
    <span class="grow"></span>
    {#if vault.attention[1] > 0}<span class="badge" title="尚未同步到服务器的修改">⇡ {vault.attention[1]}</span>{/if}
    <button class="sync btn ghost sm" class:err={!!vault.syncError} title={vault.syncError || '同步'} onclick={() => vault.sync(false)}>
      <span class:spin={vault.syncing}>⟳</span>
      <span class="synctext">{vault.syncError ? '同步失败' : vault.syncing ? '同步中' : `已同步 ${relativeTime(vault.lastSync?.finished_at ?? vault.lock?.last_sync_at ?? 0, now)}`}</span>
    </button>
    <button class="btn ghost sm" onclick={() => vault.doLock()} title="锁定（Ctrl+L）">🔒 锁定</button>
  </header>

  <div class="navcol" class:open={navOpen}><Sidebar /></div>
  {#if navOpen}<button class="scrim" aria-label="关闭菜单" onclick={() => (navOpen = false)}></button>{/if}

  {#if vault.page === 'items'}
    <div class="listcol"><ItemList /></div>
  {/if}
  <main class="main">
    {#if vault.page === 'items'}
      {#if vault.editing}
        {@const ed = vault.editing}
        {#key editKey}<ItemEditor vaultId={ed.vault_id} itemId={ed.item_id} />{/key}
      {:else if vault.selected}
        {@const sel = vault.selected}
        {#key selKey}<ItemDetail vaultId={sel.vault_id} itemId={sel.item_id} />{/key}
      {:else}
        <div class="empty faint">选择或新建一个条目</div>
      {/if}
    {:else if vault.page === 'security'}<SecurityPage />
    {:else if vault.page === 'settings'}<SettingsPage />
    {:else if vault.page === 'import'}<ImportPage />
    {:else if vault.page === 'generator'}<h2 class="gh">密码生成器</h2><Generator inline />{/if}
  </main>
</div>

<style>
  .shell {
    display: grid; height: 100%;
    grid-template-columns: 230px 330px 1fr; grid-template-rows: 44px 1fr;
    grid-template-areas: 'top top top' 'nav list main';
  }
  .shell.wide-page { grid-template-areas: 'top top top' 'nav main main'; }
  .top { grid-area: top; display: flex; align-items: center; gap: 8px; padding: 0 12px; border-bottom: 1px solid var(--border); background: var(--surface); }
  .navcol { grid-area: nav; min-height: 0; display: flex; }
  .navcol :global(nav) { flex: 1; }
  .listcol { grid-area: list; min-height: 0; display: flex; }
  .listcol :global(section) { flex: 1; }
  .main { grid-area: main; overflow: auto; min-width: 0; background: var(--bg); }
  .menu, .backbtn, .scrim { display: none; }
  .empty { height: 100%; display: grid; place-items: center; }
  .sync.err { color: var(--bad); }
  .spin { display: inline-block; animation: spin 1s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .gh { margin: 22px 28px 0; }

  /* tablet: the sidebar becomes a drawer */
  @media (max-width: 1100px) {
    .shell { grid-template-columns: 300px 1fr; grid-template-areas: 'top top' 'list main'; }
    .shell.wide-page { grid-template-areas: 'top top' 'main main'; }
    .menu { display: inline-flex; }
    .navcol { position: fixed; top: 44px; bottom: 0; left: 0; width: 260px; z-index: 20; transform: translateX(-100%); transition: transform .18s; box-shadow: var(--shadow); }
    .navcol.open { transform: none; }
    .scrim { display: block; position: fixed; inset: 44px 0 0 0; background: rgba(0, 0, 0, .25); border: 0; z-index: 19; }
  }
  /* phone: list or detail */
  @media (max-width: 700px) {
    .shell, .shell.wide-page { grid-template-columns: 1fr; grid-template-areas: 'top' 'list'; }
    .shell.detail { grid-template-areas: 'top' 'main'; }
    .shell:not(.detail) .main { display: none; }
    .shell.detail .listcol { display: none; }
    .shell.detail .backbtn { display: inline-flex; }
    .synctext { display: none; }
  }
</style>
