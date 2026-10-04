<script lang="ts">
  import { onMount } from 'svelte';
  import { vault } from '$lib/vault.svelte';
  import { errorCode, errorMessage } from '$lib/bridge';
  import { errorText, relativeTime } from '$lib/i18n';
  import { confirm } from '$lib/ui.svelte';
  import Logo from './Logo.svelte';

  let password = $state('');
  let busy = $state(false);
  let error = $state('');
  let quick = $state({ available: false, enabled: false, label: '' });
  let input: HTMLInputElement | undefined = $state();

  onMount(async () => {
    quick = await vault.bridge.quickUnlockStatus().catch(() => ({ available: false, enabled: false, label: '' }));
    input?.focus();
  });

  async function unlock(e: Event) {
    e.preventDefault();
    busy = true;
    error = '';
    // let the button repaint before the key derivation blocks the thread
    await new Promise((r) => setTimeout(r, 30));
    try {
      await vault.bridge.unlock(password);
      password = '';
      await vault.onUnlocked();
    } catch (e) {
      error = errorText(errorCode(e), errorMessage(e));
      input?.select();
    } finally {
      busy = false;
    }
  }

  async function quickUnlock() {
    error = '';
    try {
      await vault.bridge.quickUnlock();
      await vault.onUnlocked();
    } catch (e) {
      error = errorText(errorCode(e), errorMessage(e));
    }
  }

  async function signOut() {
    if (!(await confirm('退出此设备上的账户？', '会删除此设备上的本地副本。尚未同步的修改会丢失。下次登录需要 Secret Key。', '退出', true))) return;
    await vault.bridge.signOut(true);
    await vault.refreshLock();
  }
</script>

<div class="wrap">
  <form class="box" onsubmit={unlock}>
    <Logo size={64} />
    <h2>已锁定</h2>
    <p class="muted small">{vault.lock?.login} · {vault.lock?.server_url}</p>
    <div class="pw">
      <input bind:this={input} type="password" bind:value={password} placeholder="主密码" autocomplete="current-password" disabled={busy} />
      <button class="go" disabled={busy || !password}>{busy ? '…' : '解锁'}</button>
    </div>
    {#if quick.available && quick.enabled}
      <button type="button" class="btn hello" onclick={quickUnlock}>使用 {quick.label} 解锁</button>
    {/if}
    {#if error}<div class="banner bad small" style="margin-top:12px">{error}</div>{/if}
    <p class="faint small foot">离线也能解锁 · 上次同步 {relativeTime(vault.lock?.last_sync_at ?? 0)}</p>
    <button type="button" class="btn ghost sm" onclick={signOut}>退出此设备上的账户</button>
  </form>
</div>

<style>
  .wrap { height: 100%; display: grid; place-items: center; background: radial-gradient(circle at 50% 30%, var(--accent-2), var(--bg) 60%); padding: 16px; }
  .box { width: min(340px, 100%); text-align: center; }
  h2 { margin: 10px 0 2px; }
  .pw { display: flex; border: 1px solid var(--border); border-radius: 10px; background: var(--surface); overflow: hidden; margin-top: 16px; }
  .pw input { flex: 1; border: 0; padding: 11px 12px; outline: none; background: transparent; min-width: 0; }
  .pw .go { border: 0; background: var(--accent); color: var(--accent-text); padding: 0 18px; font-weight: 600; }
  .pw .go:disabled { opacity: .6; }
  .hello { width: 100%; justify-content: center; margin-top: 12px; padding: 10px; }
  .foot { margin: 16px 0 6px; }
</style>
