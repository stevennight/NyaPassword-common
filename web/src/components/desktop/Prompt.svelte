<script lang="ts">
  // A confirmation window (desktop only, desktop.html#prompt): an SSH
  // signature or a browser extension asking to pair. The window's label is the
  // prompt's id; closing it denies. Approving needs a click: the window may
  // pop up while the user is typing elsewhere, so keys never approve, and the
  // buttons only work after a short moment.
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';

  type Info =
    | { kind: 'ssh_sign'; key: string; fingerprint: string; algorithm: string; purpose: string; process: string; confirm_each_use: boolean }
    | { kind: 'pair'; browser: string; extension_id: string; code: string };

  let info = $state<Info | null | undefined>(undefined);
  let armed = $state(false);

  onMount(async () => {
    info = await invoke<Info | null>('prompt_info').catch(() => null);
    setTimeout(() => (armed = true), 700);
  });

  const answer = (decision: 'once' | 'session' | 'deny') => invoke('prompt_respond', { decision });
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
    {#if !info.confirm_each_use}<p class="faint small">这个密钥设置为“每次解锁只确认一次”：允许后，到锁定前不再询问。</p>{/if}
    <div class="row acts">
      <button class="btn" onclick={() => answer('deny')}>拒绝</button>
      <span class="spacer"></span>
      <button class="btn" disabled={!armed} onclick={() => answer('session')}>锁定前都允许</button>
      <button class="btn primary" disabled={!armed} onclick={() => answer('once')}>允许一次</button>
    </div>
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
</style>
