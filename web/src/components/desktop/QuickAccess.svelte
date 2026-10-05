<script lang="ts">
  // Quick Access (desktop only, desktop.html#quick): opened by the global
  // shortcut over another program's window. Enter types the chosen login into
  // that window (its auto-type sequence); buttons copy username / password / code.
  import { onMount, tick } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import { listen } from '@tauri-apps/api/event';
  import type { ItemView } from '$lib/types';
  import { avatar } from '$lib/ui.svelte';

  interface QuickContext {
    signed_in: boolean;
    unlocked: boolean;
    target: { title: string; process: string } | null;
    matches: ItemView[];
    can_type: boolean;
    shortcut: string;
  }

  let ctx = $state<QuickContext | null>(null);
  let q = $state('');
  let results = $state<ItemView[]>([]);
  let sel = $state(0);
  let busy = $state(false);
  let msg = $state('');
  let input = $state<HTMLInputElement | null>(null);
  let timer: ReturnType<typeof setTimeout> | undefined;

  const list = $derived(q.trim() ? results : (ctx?.matches ?? []));
  const current = $derived(list[Math.min(sel, list.length - 1)] ?? null);

  const errText = (e: unknown) => (e && typeof e === 'object' && 'message' in e ? String((e as { message: unknown }).message) : String(e));

  async function load() {
    msg = '';
    q = '';
    results = [];
    sel = 0;
    busy = false;
    ctx = await invoke<QuickContext>('quick_context');
    await tick();
    input?.focus();
  }

  onMount(() => {
    void load();
    const off = listen('npw:quick-open', () => void load());
    return () => void off.then((f) => f());
  });

  function search() {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      results = q.trim() ? await invoke<ItemView[]>('quick_search', { query: q }) : [];
      sel = 0;
    }, 100);
  }

  const hide = () => invoke('quick_hide');

  async function autotype(it: ItemView | null) {
    if (!it || busy) return;
    if (!ctx?.can_type) {
      msg = ctx?.target ? '此平台不支持自动输入，请用复制' : '没有目标窗口：先切换到要登录的窗口，再按快捷键';
      return;
    }
    busy = true;
    try {
      await invoke('quick_autotype', { vaultId: it.vault_id, itemId: it.item_id });
    } catch (e) {
      // the app shows this window again to tell what went wrong
      msg = errText(e);
    } finally {
      busy = false;
    }
  }

  async function copy(it: ItemView | null, what: 'username' | 'password' | 'totp') {
    if (!it) return;
    try {
      await invoke('quick_copy', { vaultId: it.vault_id, itemId: it.item_id, what });
      await hide();
    } catch (e) {
      msg = errText(e);
    }
  }

  function onkey(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      void hide();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      sel = Math.min(sel + 1, Math.max(list.length - 1, 0));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      sel = Math.max(sel - 1, 0);
    } else if (e.key === 'Enter' && !e.isComposing) {
      e.preventDefault();
      void autotype(current);
    } else if (e.ctrlKey && !e.shiftKey && !e.altKey) {
      const what = ({ u: 'username', p: 'password', t: 'totp' } as const)[e.key.toLowerCase() as 'u' | 'p' | 't'];
      if (what) {
        e.preventDefault();
        void copy(current, what);
      }
    }
  }
</script>

<svelte:window onkeydown={onkey} onblur={() => { if (!busy) void hide(); }} />

<div class="qa">
  {#if !ctx}
    <div class="center faint">…</div>
  {:else if !ctx.unlocked}
    <div class="center">
      <p class="muted">{ctx.signed_in ? 'NyaPassword 已锁定' : '还没有登录账户'}</p>
      <button class="btn primary" onclick={() => invoke('quick_show_main')}>打开 NyaPassword{ctx.signed_in ? ' 解锁' : ''}</button>
      <p class="faint small">解锁后再按 {ctx.shortcut}</p>
    </div>
  {:else}
    <input class="search" bind:this={input} bind:value={q} oninput={search} placeholder="搜索全部条目（支持拼音）" spellcheck="false" autocomplete="off" />
    <div class="target small" title={ctx.target?.title}>
      {#if ctx.target}输入到：<b>{ctx.target.title || '（无标题）'}</b> <span class="faint">{ctx.target.process}</span>
      {:else}<span class="faint">没有目标窗口，只能复制</span>{/if}
    </div>
    <div class="list">
      {#if !q.trim() && ctx.target}<div class="grp">匹配这个窗口</div>{/if}
      {#each list as it, i (it.vault_id + it.item_id)}
        {@const a = avatar(it.title, it.template)}
        <button class="it" class:sel={i === sel} onmouseenter={() => (sel = i)} onclick={() => autotype(it)}>
          <span class="ico" style="background:{a.color}">{a.letter}</span>
          <span class="grow txt"><span class="t">{it.title || '（无标题）'}</span><span class="s">{it.subtitle}</span></span>
        </button>
      {:else}
        <div class="faint small pad">{q.trim() ? '没有匹配的条目' : '没有匹配这个窗口的条目，输入关键词搜索'}</div>
      {/each}
    </div>
    {#if msg}<div class="banner bad small">{msg}</div>{/if}
    <footer class="row small">
      <button class="btn sm primary" disabled={!current || busy} onclick={() => autotype(current)}>自动输入 Enter</button>
      <button class="btn sm" disabled={!current} onclick={() => copy(current, 'username')}>用户名 Ctrl+U</button>
      <button class="btn sm" disabled={!current} onclick={() => copy(current, 'password')}>密码 Ctrl+P</button>
      {#if current?.has_totp}<button class="btn sm" onclick={() => copy(current, 'totp')}>验证码 Ctrl+T</button>{/if}
      <span class="spacer"></span><span class="faint">Esc 关闭</span>
    </footer>
  {/if}
</div>

<style>
  .qa { height: 100vh; display: flex; flex-direction: column; gap: 8px; padding: 12px; background: var(--surface); border: 1px solid var(--border); }
  .center { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 10px; }
  .search { font-size: 17px; padding: 10px 12px; border: 1px solid var(--border); border-radius: 10px; background: var(--surface-2); outline: none; }
  .search:focus { border-color: var(--accent); }
  .target { color: var(--text-2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .list { flex: 1; overflow: auto; display: flex; flex-direction: column; }
  .grp { font-size: 11.5px; color: var(--text-3); font-weight: 600; padding: 2px 4px; }
  .it { display: flex; align-items: center; gap: 10px; padding: 6px 8px; border: 0; background: none; border-radius: 8px; text-align: left; }
  .it.sel { background: var(--sel); }
  .ico { width: 30px; height: 30px; border-radius: 8px; color: #fff; display: grid; place-items: center; font-weight: 600; flex: none; }
  .txt { display: flex; flex-direction: column; min-width: 0; }
  .t { font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .s { font-size: 12px; color: var(--text-2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .pad { padding: 8px; }
  footer { border-top: 1px solid var(--border); padding-top: 8px; flex-wrap: wrap; }
</style>
