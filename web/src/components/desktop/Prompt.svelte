<script lang="ts">
  // A confirmation window (desktop only, desktop.html#prompt): an SSH
  // signature or a browser extension asking to pair. The window's label is the
  // prompt's id; closing it denies. Approving needs a click: the window may
  // pop up while the user is typing elsewhere, so keys never approve, and the
  // buttons only work after a short moment. A key whose item is marked
  // "使用前需要验证" needs the master password (or Windows Hello) every time;
  // the app refuses the approval until this window verified the user.
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';

  type Info =
    | { kind: 'ssh_sign'; key: string; fingerprint: string; algorithm: string; purpose: string; process: string; confirm_each_use: boolean; reprompt?: boolean }
    | { kind: 'pair'; browser: string; extension_id: string; code: string };

  let info = $state<Info | null | undefined>(undefined);
  let armed = $state(false);
  let password = $state('');
  let busy = $state(false);
  let error = $state('');
  let bio = $state({ biometric: false, label: '' });

  onMount(async () => {
    info = await invoke<Info | null>('prompt_info').catch(() => null);
    setTimeout(() => (armed = true), 700);
    if (info?.kind === 'ssh_sign' && info.reprompt) {
      bio = await invoke<{ biometric: boolean; label: string }>('verify_user_options').catch(() => ({ biometric: false, label: '' }));
    }
  });

  const answer = (decision: 'once' | 'session' | 'deny') => invoke('prompt_respond', { decision });

  const errText = (e: unknown) => {
    const o = e as { code?: string; message?: string } | null;
    if (o?.code === 'wrong_password') return '主密码不正确';
    return o?.message ?? String(e);
  };

  /** Verifies (password, or Windows Hello without one), then allows this one signature. */
  async function verifyAndAllow(pw?: string) {
    if (busy) return;
    busy = true;
    error = '';
    try {
      await invoke('prompt_verify', { password: pw || null });
      password = '';
      await answer('once');
    } catch (e) {
      error = errText(e);
    } finally {
      busy = false;
    }
  }
</script>

<svelte:window onkeydown={(e) => { if (e.key === 'Escape') void answer('deny'); }} />

<div class="pr">
  {#if info === undefined}
    <div class="faint">…</div>
  {:else if info === null}
    <p class="muted">这个请求已经结束。</p>
  {:else if info.kind === 'ssh_sign'}
    <h2>SSH 签名请求</h2>
    <p class="muted">有程序请求用 NyaPassword 中的 SSH 密钥签名：</p>
    <dl>
      <dt>密钥</dt><dd><b>{info.key}</b></dd>
      <dt>用途</dt><dd>{info.purpose}</dd>
      <dt>程序</dt><dd>{info.process || '未知'}</dd>
      <dt>指纹</dt><dd class="mono small">{info.fingerprint}</dd>
      <dt>算法</dt><dd class="mono small">{info.algorithm}</dd>
    </dl>
    {#if info.reprompt}
      <p class="small">🔒 这个密钥的条目设置了“使用前需要验证”：每次签名都要输入主密码{bio.biometric ? `或使用 ${bio.label}` : ''}。</p>
      <!-- typing the password does not approve: the button needs a click -->
      <input class="input" type="password" bind:value={password} placeholder="主密码" autocomplete="off" disabled={busy}
        onkeydown={(e) => { if (e.key === 'Enter') e.preventDefault(); }} />
      {#if error}<p class="err small">{error}</p>{/if}
      <div class="row acts">
        <button class="btn" onclick={() => answer('deny')}>拒绝</button>
        <span class="spacer"></span>
        {#if bio.biometric}<button class="btn" disabled={!armed || busy} onclick={() => verifyAndAllow()}>使用 {bio.label} 并允许</button>{/if}
        <button class="btn primary" disabled={!armed || busy || !password} onclick={() => verifyAndAllow(password)}>验证并允许一次</button>
      </div>
    {:else}
      {#if !info.confirm_each_use}<p class="faint small">这个密钥设置为“每次解锁只确认一次”：允许后，到锁定前不再询问。</p>{/if}
      <div class="row acts">
        <button class="btn" onclick={() => answer('deny')}>拒绝</button>
        <span class="spacer"></span>
        <button class="btn" disabled={!armed} onclick={() => answer('session')}>锁定前都允许</button>
        <button class="btn primary" disabled={!armed} onclick={() => answer('once')}>允许一次</button>
      </div>
    {/if}
  {:else}
    <h2>浏览器扩展请求配对</h2>
    <p class="muted">{info.browser} 中的 NyaPassword 扩展请求与桌面端配对。配对后，桌面端解锁时扩展可以直接解锁，桌面端锁定时扩展也会锁定。</p>
    <div class="code mono">{info.code}</div>
    <p class="small">请确认扩展弹窗里显示的是<b>同一个数字</b>；如果你没有在扩展里点“配对”，请拒绝。</p>
    <p class="faint small mono">扩展 ID：{info.extension_id}</p>
    <div class="row acts">
      <button class="btn" onclick={() => answer('deny')}>拒绝</button>
      <span class="spacer"></span>
      <button class="btn primary" disabled={!armed} onclick={() => answer('once')}>允许配对</button>
    </div>
  {/if}
</div>

<style>
  .pr { height: 100vh; padding: 16px 18px; display: flex; flex-direction: column; gap: 8px; background: var(--surface); overflow: auto; }
  h2 { margin: 0; font-size: 16px; }
  p { margin: 0; }
  dl { display: grid; grid-template-columns: 44px 1fr; gap: 4px 10px; margin: 4px 0; }
  dt { color: var(--text-3); font-size: 12.5px; }
  dd { margin: 0; word-break: break-all; }
  .code { font-size: 34px; letter-spacing: 6px; text-align: center; padding: 6px; background: var(--surface-2); border-radius: 10px; }
  .acts { margin-top: auto; }
  .err { color: var(--bad); }
</style>
