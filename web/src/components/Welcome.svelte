<script lang="ts">
  import { vault } from '$lib/vault.svelte';
  import { errorCode, errorMessage } from '$lib/bridge';
  import { errorText } from '$lib/i18n';
  import type { EmergencyKit as Kit } from '$lib/types';
  import Logo from './Logo.svelte';
  import EmergencyKit from './EmergencyKit.svelte';

  let mode = $state<'signin' | 'register'>('signin');
  let server = $state(vault.bridge.defaultServer());
  let login = $state('');
  let password = $state('');
  let password2 = $state('');
  let secretKey = $state('');
  let invite = $state('');
  let remember = $state(true);
  let busy = $state(false);
  let error = $state('');
  let kit = $state<Kit | null>(null);

  const strength = $derived(password ? vault.bridge.passwordStrength(password) : 0);
  const strengthText = ['很弱', '弱', '一般', '强', '很强'];

  // Paste the whole QR payload or a Secret Key.
  function onSecretInput(v: string) {
    secretKey = v;
    const t = v.trim();
    if (t.startsWith('{')) {
      try {
        const o = JSON.parse(t);
        if (o.secret_key) secretKey = o.secret_key;
        if (o.server) server = o.server;
        if (o.login) login = o.login;
      } catch {
        /* not the QR payload */
      }
    }
  }

  async function submit(e: Event) {
    e.preventDefault();
    error = '';
    if (mode === 'register') {
      if (password !== password2) return (error = '两次输入的主密码不一致');
      if (password.length < 10) return (error = '主密码至少 10 个字符（建议用一句话）');
    }
    busy = true;
    try {
      if (mode === 'register') {
        kit = await vault.bridge.register(server.trim(), login.trim(), password, invite.trim() || undefined);
      } else {
        const sk = vault.bridge.normalizeSecretKey(secretKey);
        await vault.bridge.signIn(server.trim(), login.trim(), password, sk, remember);
        password = '';
        await vault.onUnlocked();
      }
    } catch (e) {
      error = errorText(errorCode(e), errorMessage(e));
    } finally {
      busy = false;
    }
  }
</script>

<div class="wrap">
  {#if kit}
    <div class="panel wide">
      <h2>账户已创建</h2>
      <p class="muted">这是唯一一次显示完整的紧急恢复包（之后可以在“设置”里重新查看）。请现在打印或保存。</p>
      <EmergencyKit {kit} ondone={async () => { kit = null; password = ''; await vault.onUnlocked(); }} />
    </div>
  {:else}
    <form class="panel" onsubmit={submit}>
      <div class="brand"><Logo size={44} /><h1>NyaPassword</h1></div>
      <div class="tabs">
        <button type="button" class:on={mode === 'signin'} onclick={() => (mode = 'signin')}>登录已有账户</button>
        <button type="button" class:on={mode === 'register'} onclick={() => (mode = 'register')}>创建账户</button>
      </div>

      <label class="lbl" for="srv">服务器</label>
      <input id="srv" class="input" bind:value={server} placeholder="https://vault.example.com" required />
      <label class="lbl" for="login">账号（邮箱或用户名）</label>
      <input id="login" class="input" bind:value={login} autocomplete="username" required />
      <label class="lbl" for="pw">主密码</label>
      <input id="pw" class="input" type="password" bind:value={password} autocomplete={mode === 'register' ? 'new-password' : 'current-password'} required />
      {#if mode === 'register'}
        {#if password}<div class="small" class:weak={strength < 3}>强度：{strengthText[strength]}{strength < 3 ? '（建议更长，用一句只有你知道的话）' : ''}</div>{/if}
        <label class="lbl" for="pw2">再输一次主密码</label>
        <input id="pw2" class="input" type="password" bind:value={password2} autocomplete="new-password" required />
        <label class="lbl" for="inv">邀请码（第一个账户不需要）</label>
        <input id="inv" class="input" bind:value={invite} />
        <p class="hint">注册时会在本设备生成一串 <b>Secret Key</b>，和主密码一起加密你的数据；它不会发给服务器。新设备第一次登录需要它，请务必保存紧急恢复包。</p>
      {:else}
        <label class="lbl" for="sk">Secret Key（紧急恢复包上的 A1-…；也可以粘贴二维码内容）</label>
        <input id="sk" class="input mono" value={secretKey} oninput={(e) => onSecretInput((e.target as HTMLInputElement).value)} placeholder="A1-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX-X" autocomplete="off" spellcheck="false" required />
        {#if vault.bridge.kind === 'web'}
          <label class="check"><input type="checkbox" bind:checked={remember} /> 在此浏览器上记住（只在自己的电脑上勾选）</label>
        {/if}
      {/if}

      {#if error}<div class="banner bad small" style="margin-top:12px">{error}</div>{/if}
      <button class="btn primary submit" disabled={busy}>{busy ? '请稍候…' : mode === 'register' ? '创建账户' : '登录'}</button>
    </form>
  {/if}
</div>

<style>
  .wrap { min-height: 100%; display: grid; place-items: center; padding: 24px 16px; background: radial-gradient(circle at 50% 20%, var(--accent-2), var(--bg) 60%); }
  .panel { width: min(420px, 100%); background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 24px; box-shadow: var(--shadow); }
  .panel.wide { width: min(640px, 100%); }
  .brand { display: flex; align-items: center; gap: 10px; justify-content: center; margin-bottom: 14px; }
  h1 { margin: 0; font-size: 22px; }
  h2 { margin: 0 0 6px; }
  .tabs { display: grid; grid-template-columns: 1fr 1fr; background: var(--surface-2); border-radius: 10px; padding: 3px; margin-bottom: 6px; }
  .tabs button { border: 0; background: transparent; padding: 7px; border-radius: 8px; color: var(--text-2); }
  .tabs button.on { background: var(--surface); color: var(--text); font-weight: 600; box-shadow: 0 1px 3px rgba(0, 0, 0, .08); }
  .hint { font-size: 12.5px; color: var(--text-2); background: var(--surface-2); border-radius: 8px; padding: 8px 10px; }
  .check { display: flex; gap: 8px; align-items: center; margin-top: 10px; font-size: 13px; color: var(--text-2); }
  .submit { width: 100%; justify-content: center; margin-top: 16px; padding: 10px; }
  .weak { color: var(--warn); }
</style>
