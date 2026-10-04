<script lang="ts">
  import qrcode from 'qrcode-generator';
  import type { EmergencyKit } from '$lib/types';
  import { dateTime } from '$lib/i18n';
  import Logo from './Logo.svelte';

  let { kit, ondone }: { kit: EmergencyKit; ondone?: () => void } = $props();

  // The QR code carries what a new device needs besides the master password.
  const qr = $derived.by(() => {
    const q = qrcode(0, 'M');
    q.addData(JSON.stringify({ v: 1, server: kit.server_url, login: kit.login, secret_key: kit.secret_key }));
    q.make();
    return q.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
  });
</script>

<div class="kit">
  <div class="sheet" id="emergency-kit">
    <div class="row head"><Logo size={36} /><div><h2>NyaPassword 紧急恢复包</h2><div class="faint small">创建于 {dateTime(kit.created_at)}</div></div></div>
    <p class="warn">打印两份分开存放（例如家里和另一个可信的地方）。没有 Secret Key 和主密码，任何人（包括服务器管理员）都无法恢复你的数据。<b>不要只把它存在这个密码库里。</b></p>
    <dl>
      <dt>服务器</dt><dd class="mono">{kit.server_url}</dd>
      <dt>账号</dt><dd class="mono">{kit.login}</dd>
      <dt>Secret Key</dt><dd class="mono sk">{kit.secret_key}</dd>
      <dt>主密码</dt><dd class="blank">（手写在这里，或者记在心里）</dd>
      <dt>备份解密私钥</dt><dd class="blank">（服务端备份用的离线 age 私钥 AGE-SECRET-KEY-…，见管理后台“备份与恢复”）</dd>
    </dl>
    <div class="qr">{@html qr}<div class="faint small">新设备登录时扫描此码填入服务器、账号和 Secret Key</div></div>
  </div>
  <div class="row actions">
    <button class="btn" onclick={() => window.print()}>打印 / 存为 PDF</button>
    <span class="spacer"></span>
    {#if ondone}<button class="btn primary" onclick={ondone}>我已保存好，继续</button>{/if}
  </div>
</div>

<style>
  .sheet { border: 1px solid var(--border); border-radius: 12px; padding: 18px 20px; background: var(--surface); }
  .head { gap: 12px; margin-bottom: 8px; }
  h2 { margin: 0; font-size: 18px; }
  .warn { background: var(--warn-bg); border-radius: 8px; padding: 8px 10px; font-size: 13px; }
  dl { display: grid; grid-template-columns: 110px 1fr; gap: 8px 12px; margin: 14px 0; }
  dt { color: var(--text-2); font-size: 13px; }
  dd { margin: 0; word-break: break-all; }
  .sk { font-size: 17px; letter-spacing: .04em; color: var(--accent); }
  .blank { color: var(--text-3); border-bottom: 1px dashed var(--border); min-height: 24px; font-size: 12.5px; }
  .qr { display: flex; align-items: center; gap: 14px; }
  .qr :global(svg) { width: 128px; height: 128px; background: #fff; border-radius: 6px; }
  .actions { margin-top: 12px; }
  @media print {
    :global(body *) { visibility: hidden; }
    #emergency-kit, #emergency-kit :global(*) { visibility: visible; }
    #emergency-kit { position: absolute; left: 0; top: 0; width: 100%; border: none; color: #000; background: #fff; }
  }
</style>
