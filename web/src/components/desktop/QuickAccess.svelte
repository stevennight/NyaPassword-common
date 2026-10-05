<script lang="ts">
  // Quick Access (desktop only, desktop.html#quick): opened by the global
  // shortcut over another program's window. Enter types the chosen login into
  // that window (its auto-type sequence); buttons copy username / password / code.
  // Items marked "使用前需要验证" first ask for the master password (or Windows
  // Hello) here; the app releases one secret per verification (quick_verify).
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
  /** An action waiting for the user to verify (a "使用前需要验证" item). */
  let pending = $state<{ it: ItemView; what: 'type' | 'password' | 'totp' } | null>(null);
  let vpw = $state('');
  let vinput = $state<HTMLInputElement | null>(null);
  let bio = $state<{ biometric: boolean; label: string; pin?: boolean }>({ biometric: false, label: '' });
  /** The field takes the PIN instead of the master password. */
  let usePin = $state(false);

  const list = $derived(q.trim() ? results : (ctx?.matches ?? []));
  const current = $derived(list[Math.min(sel, list.length - 1)] ?? null);

  const errText = (e: unknown) => (e && typeof e === 'object' && 'message' in e ? String((e as { message: unknown }).message) : String(e));

  async function load() {
    msg = '';
    q = '';
    results = [];
    sel = 0;
    busy = false;
    pending = null;
    vpw = '';
    usePin = false;
    ctx = await invoke<QuickContext>('quick_context');
    bio = ctx.unlocked
      ? await invoke<{ biometric: boolean; label: string; pin?: boolean }>('verify_user_options').catch(() => ({ biometric: false, label: '' }))
      : { biometric: false, label: '' };
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

  async function ask(it: ItemView, what: 'type' | 'password' | 'totp') {
    msg = '';
    vpw = '';
    pending = { it, what };
    await tick();
    vinput?.focus();
  }

  /** Verifies for the pending item (password or PIN, or Windows Hello without one), then runs its action. */
  async function verify(pw?: string) {
    if (!pending || busy) return;
    const { it, what } = pending;
    busy = true;
    msg = '';
    try {
      const secret = usePin ? { password: null, pin: pw || null } : { password: pw || null, pin: null };
      await invoke('quick_verify', { vaultId: it.vault_id, itemId: it.item_id, ...secret });
    } catch (e) {
      const o = e as { code?: string } | null;
      msg = o?.code === 'wrong_password' ? '主密码不正确' : errText(e);
      if (usePin && (o?.code === 'pin_wiped' || o?.code === 'password_required')) {
        usePin = false;
        bio = { ...bio, pin: false };
      }
      busy = false;
      vinput?.select();
      return;
    }
    busy = false;
    pending = null;
    vpw = '';
    if (what === 'type') await autotype(it, true);
    else await copy(it, what, true);
  }

  async function autotype(it: ItemView | null, verified = false) {
    if (!it || busy) return;
    if (it.reprompt && !verified) return ask(it, 'type');
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

  async function copy(it: ItemView | null, what: 'username' | 'password' | 'totp', verified = false) {
    if (!it) return;
    if (it.reprompt && what !== 'username' && !verified) return ask(it, what);
    try {
      await invoke('quick_copy', { vaultId: it.vault_id, itemId: it.item_id, what });
      await hide();
    } catch (e) {
      msg = errText(e);
    }
  }

  function onkey(e: KeyboardEvent) {
    if (pending) {
      if (e.key === 'Escape') {
        e.preventDefault();
        pending = null;
        msg = '';
        void tick().then(() => input?.focus());
      } else if (e.key === 'Enter' && !e.isComposing && vpw) {
        e.preventDefault();
        void verify(vpw);
      }
      return;
    }
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
  {:else if pending}
    <div class="verify">
      <div class="row"><span>🔒</span><b class="grow">{pending.it.title || '（无标题）'}</b></div>
      <p class="muted small">这个条目设置了“使用前需要验证”。{pending.what === 'type' ? '自动输入' : pending.what === 'password' ? '复制密码' : '复制验证码'}前，请输入主密码{bio.pin ? '或 PIN' : ''}{bio.biometric ? `或使用 ${bio.label}` : ''}。</p>
      <input class="search" type="password" bind:this={vinput} bind:value={vpw} placeholder={usePin ? 'PIN（Enter 验证，Esc 返回）' : '主密码（Enter 验证，Esc 返回）'} autocomplete="off" disabled={busy} />
      <div class="row">
        <button class="btn sm primary" disabled={busy || !vpw} onclick={() => verify(vpw)}>{busy ? '验证中…' : '验证'}</button>
        {#if bio.pin}<button class="btn sm" disabled={busy} onclick={() => { usePin = !usePin; vpw = ''; msg = ''; vinput?.focus(); }}>{usePin ? '改用主密码' : '使用 PIN'}</button>{/if}
        {#if bio.biometric}<button class="btn sm" disabled={busy} onclick={() => verify()}>使用 {bio.label}</button>{/if}
        <span class="spacer"></span>
        <button class="btn sm" disabled={busy} onclick={() => { pending = null; msg = ''; }}>返回</button>
      </div>
      {#if msg}<div class="banner bad small">{msg}</div>{/if}
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
          {#if it.reprompt}<span class="lock" title="使用前需要验证">🔒</span>{/if}
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
  .lock { font-size: 12px; opacity: .7; }
  .verify { flex: 1; display: flex; flex-direction: column; gap: 10px; padding: 8px 4px; }
  .verify p { margin: 0; }
  footer { border-top: 1px solid var(--border); padding-top: 8px; flex-wrap: wrap; }
</style>
