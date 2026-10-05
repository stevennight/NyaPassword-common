<script lang="ts">
  import { onMount } from 'svelte';
  import { vault } from '$lib/vault.svelte';
  import { errorCode, errorMessage, type QuickUnlockStatus } from '$lib/bridge';
  import { desktopApi } from '$lib/desktop';
  import { errorText, relativeTime } from '$lib/i18n';
  import { confirm } from '$lib/ui.svelte';
  import Logo from './Logo.svelte';

  let password = $state('');
  let busy = $state(false);
  let signingOut = $state(false);
  let error = $state('');
  let quick = $state<QuickUnlockStatus>({ available: false, enabled: false, label: '' });
  /** Desktop: the PIN field instead of the master password. */
  let usePin = $state(false);
  let input: HTMLInputElement | undefined = $state();
  const desk = desktopApi(vault.bridge);

  async function loadStatus() {
    quick = await vault.bridge.quickUnlockStatus().catch(() => ({ available: false, enabled: false, label: '' }));
    if (!quick.pin || !desk) usePin = false;
  }

  onMount(async () => {
    await loadStatus();
    // the PIN is the quickest choice when it is set (the master password stays one click away)
    if (quick.pin && desk) usePin = true;
    input?.focus();
  });

  function switchTo(pin: boolean) {
    usePin = pin;
    password = '';
    error = '';
    setTimeout(() => input?.focus(), 0);
  }

  async function unlock(e: Event) {
    e.preventDefault();
    busy = true;
    error = '';
    // let the button repaint before the key derivation blocks the thread
    await new Promise((r) => setTimeout(r, 30));
    try {
      if (usePin && desk) await desk.pinUnlock(password);
      else await vault.bridge.unlock(password);
      password = '';
      vault.unlockRequest = '';
      await vault.onUnlocked();
    } catch (e) {
      // wrong_pin carries the tries left; pin_wiped / password_required say why
      error = errorText(errorCode(e), errorMessage(e));
      if (usePin) {
        // the tries left, or the PIN was deleted / suspended: back to the master password
        await loadStatus();
        if (!usePin) password = '';
      }
      input?.select();
    } finally {
      busy = false;
    }
  }

  async function quickUnlock() {
    error = '';
    try {
      await vault.bridge.quickUnlock();
      vault.unlockRequest = '';
      await vault.onUnlocked();
    } catch (e) {
      error = errorText(errorCode(e), errorMessage(e));
      await loadStatus();
    }
  }

  async function signOut() {
    if (!(await confirm('退出此设备上的账户？', '会删除此设备上的本地副本。尚未同步的修改会丢失。下次登录需要 Secret Key。', '退出', true))) return;
    signingOut = true;
    error = '';
    try {
      await vault.bridge.signOut(true);
      await vault.refreshLock();
    } catch (e) {
      error = errorText(errorCode(e), errorMessage(e));
    } finally {
      signingOut = false;
    }
  }
</script>

<div class="wrap">
  <form class="box" onsubmit={unlock}>
    <Logo size={64} />
    <h2>已锁定</h2>
    <p class="muted small">{vault.lock?.login} · {vault.lock?.server_url}</p>
    {#if vault.unlockRequest}
      <div class="banner small ask">浏览器扩展（{vault.unlockRequest}）正在请求解锁：在这里解锁后，扩展也会解锁。</div>
    {/if}
    <div class="pw">
      {#if usePin}
        <input bind:this={input} type="password" bind:value={password} placeholder="PIN" autocomplete="off" inputmode="text" disabled={busy} />
      {:else}
        <input bind:this={input} type="password" bind:value={password} placeholder="主密码" autocomplete="current-password" disabled={busy} />
      {/if}
      <button class="go" disabled={busy || !password}>{busy ? '…' : '解锁'}</button>
    </div>
    {#if usePin && quick.pin_tries_left !== undefined && quick.pin_tries_left < 5}
      <p class="faint small tries">还可以再试 {quick.pin_tries_left} 次，之后 PIN 作废</p>
    {/if}
    <div class="ways">
      {#if quick.available && quick.enabled}
        <button type="button" class="btn hello" onclick={quickUnlock}>使用 {quick.label} 解锁</button>
      {/if}
      {#if quick.pin && desk}
        {#if usePin}
          <button type="button" class="btn ghost sm" onclick={() => switchTo(false)}>改用主密码</button>
        {:else}
          <button type="button" class="btn ghost sm" onclick={() => switchTo(true)}>使用 PIN 解锁</button>
        {/if}
      {/if}
    </div>
    {#if quick.password_reason && !usePin}<p class="faint small">{quick.password_reason}</p>{/if}
    {#if error}<div class="banner bad small" style="margin-top:12px">{error}</div>{/if}
    <p class="faint small foot">离线也能解锁 · 上次同步 {relativeTime(vault.lock?.last_sync_at ?? 0)}</p>
    <button type="button" class="btn ghost sm" onclick={signOut} disabled={signingOut || busy}>{signingOut ? '正在退出…' : '退出此设备上的账户'}</button>
  </form>
</div>

<style>
  .wrap { height: 100%; display: grid; place-items: center; background: radial-gradient(circle at 50% 30%, var(--accent-2), var(--bg) 60%); padding: 16px; }
  .box { width: min(340px, 100%); text-align: center; }
  h2 { margin: 10px 0 2px; }
  .ask { margin-top: 12px; text-align: left; }
  .pw { display: flex; border: 1px solid var(--border); border-radius: 10px; background: var(--surface); overflow: hidden; margin-top: 16px; }
  .pw input { flex: 1; border: 0; padding: 11px 12px; outline: none; background: transparent; min-width: 0; }
  .pw .go { border: 0; background: var(--accent); color: var(--accent-text); padding: 0 18px; font-weight: 600; }
  .pw .go:disabled { opacity: .6; }
  .tries { margin: 6px 0 0; }
  .ways { display: flex; flex-direction: column; align-items: center; gap: 6px; margin-top: 12px; }
  .hello { width: 100%; justify-content: center; padding: 10px; }
  .foot { margin: 16px 0 6px; }
</style>
