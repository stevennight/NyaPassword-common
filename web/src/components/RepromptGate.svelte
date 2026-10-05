<script lang="ts">
  // "此条目需要验证": shown instead of an item's secrets until the user types
  // the master password again (or, in the desktop app, uses Windows Hello).
  // The verification is for this item only and ends when another item is
  // selected or the app locks (vault.verified).
  import { onMount } from 'svelte';
  import { vault } from '$lib/vault.svelte';
  import { errorCode, errorMessage } from '$lib/bridge';
  import { verifyError } from '$lib/reprompt';

  let { vaultId, itemId, what = '查看或复制这个条目的密码等内容' }: { vaultId: string; itemId: string; what?: string } = $props();
  let password = $state('');
  let busy = $state(false);
  let error = $state('');
  let biometric = $state({ biometric: false, label: '' });
  let input: HTMLInputElement | undefined = $state();

  onMount(async () => {
    biometric = await vault.bridge.verifyUserOptions().catch(() => ({ biometric: false, label: '' }));
    input?.focus();
  });

  async function run(pw?: string) {
    busy = true;
    error = '';
    // let the button repaint before the key derivation blocks the thread
    await new Promise((r) => setTimeout(r, 30));
    try {
      await vault.verify(vaultId, itemId, pw);
      password = '';
    } catch (e) {
      error = verifyError(errorCode(e), errorMessage(e));
      input?.select();
    } finally {
      busy = false;
    }
  }

  function submit(e: Event) {
    e.preventDefault();
    if (password) void run(password);
  }
</script>

<form class="card gate" onsubmit={submit}>
  <div class="row"><span class="lock">🔒</span><b>此条目需要验证</b></div>
  <p class="muted small">{what}前，请再次输入主密码{biometric.biometric ? `或使用 ${biometric.label}` : ''}。</p>
  <div class="row">
    <input class="input" type="password" bind:this={input} bind:value={password} placeholder="主密码" autocomplete="current-password" disabled={busy} />
    <button class="btn primary" type="submit" disabled={busy || !password}>{busy ? '验证中…' : '验证'}</button>
  </div>
  {#if biometric.biometric}
    <button class="btn" type="button" disabled={busy} onclick={() => run()}>使用 {biometric.label}</button>
  {/if}
  {#if error}<div class="err small">{error}</div>{/if}
</form>

<style>
  .gate { padding: 14px; display: flex; flex-direction: column; gap: 10px; margin-bottom: 14px; align-items: flex-start; }
  .gate .row { width: 100%; }
  .lock { font-size: 16px; }
  p { margin: 0; }
  .err { color: var(--bad); }
</style>
