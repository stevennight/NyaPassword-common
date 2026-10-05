<script lang="ts">
  import { api, type TotpSetup } from './api';
  import { toast } from '$lib/ui.svelte';
  import { admin, errMsg, loadSecurity } from './store.svelte';

  let { onsignedout }: { onsignedout: () => void } = $props();

  // ---- password
  let cur = $state('');
  let next = $state('');
  let next2 = $state('');
  let pwMsg = $state('');
  let pwBusy = $state(false);

  async function changePassword(e: Event) {
    e.preventDefault();
    pwMsg = '';
    if (next !== next2) return (pwMsg = '两次输入的新密码不一致');
    if ([...next].length < 12) return (pwMsg = '新密码至少 12 个字符');
    pwBusy = true;
    try {
      await api('POST', '/password', { current: cur, new: next });
      cur = next = next2 = '';
      toast('管理员密码已修改；其他已登录的管理后台会话已退出', 'ok', 6000);
    } catch (err) {
      pwMsg = errMsg(err);
    } finally {
      pwBusy = false;
    }
  }

  // ---- TOTP
  let totpPw = $state('');
  let setup = $state<TotpSetup | null>(null);
  let code = $state('');
  let totpMsg = $state('');
  let totpBusy = $state(false);
  let qr = $state('');

  // the QR code library is only loaded when TOTP is being set up
  async function makeQr(uri: string) {
    const { default: qrcode } = await import('qrcode-generator');
    const q = qrcode(0, 'M');
    q.addData(uri);
    q.make();
    qr = q.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
  }

  async function totpAction(e: Event) {
    e.preventDefault();
    totpMsg = '';
    totpBusy = true;
    try {
      if (admin.security?.totp_enabled) {
        await api('POST', '/totp/disable', { password: totpPw });
        toast('两步验证已关闭', 'ok');
        totpPw = '';
      } else if (!setup) {
        setup = await api<TotpSetup>('POST', '/totp/setup', { password: totpPw });
        await makeQr(setup.uri);
      } else {
        await api('POST', '/totp/enable', { password: totpPw, secret: setup.secret, code });
        toast('两步验证已开启：下次登录需要验证码', 'ok', 5000);
        setup = null;
        totpPw = code = '';
      }
      await loadSecurity();
    } catch (err) {
      totpMsg = errMsg(err);
    } finally {
      totpBusy = false;
    }
  }
</script>

<h2>管理员</h2>

<section class="card">
  <h3>两步验证（TOTP）</h3>
  {#if !admin.securityLoaded}
    <p class="faint small">读取中…</p>
  {:else if admin.security === null}
    <p class="faint small">这台服务器不支持在后台设置两步验证；请用命令 <span class="mono">nyapassword-server admin-totp</span>。</p>
  {:else if admin.security.totp_enabled}
    <p><span class="badge ok">已开启</span> 登录管理后台需要密码和验证器 App 上的 6 位验证码。</p>
    <form onsubmit={totpAction}>
      <input class="input" type="password" bind:value={totpPw} placeholder="管理员密码（确认身份）" autocomplete="current-password" />
      {#if totpMsg}<div class="banner bad small">{totpMsg}</div>{/if}
      <button class="btn danger" disabled={!totpPw || totpBusy}>关闭两步验证</button>
    </form>
  {:else}
    <p><span class="badge warn">未开启</span> 开启后，即使管理员密码泄露，没有手机上的验证码也登录不了。</p>
    <form onsubmit={totpAction}>
      {#if !setup}
        <input class="input" type="password" bind:value={totpPw} placeholder="管理员密码（确认身份）" autocomplete="current-password" />
        {#if totpMsg}<div class="banner bad small">{totpMsg}</div>{/if}
        <button class="btn primary" disabled={!totpPw || totpBusy}>开始设置</button>
      {:else}
        <ol class="small steps">
          <li>用验证器 App（Google Authenticator、Microsoft Authenticator、NyaPassword 条目里的一次性密码等）扫描二维码，或手动输入密钥。</li>
          <li>输入 App 上显示的 6 位验证码，确认能对上。</li>
        </ol>
        <div class="qrrow">
          <div class="qr">{@html qr}</div>
          <div class="grow"><div class="faint small">密钥</div><div class="mono brk">{setup.secret}</div></div>
        </div>
        <input class="input mono" bind:value={code} placeholder="6 位验证码" inputmode="numeric" autocomplete="one-time-code" />
        {#if totpMsg}<div class="banner bad small">{totpMsg}</div>{/if}
        <div class="row"><button type="button" class="btn ghost" onclick={() => (setup = null)}>取消</button>
          <button class="btn primary" disabled={code.trim().length < 6 || totpBusy}>验证并开启</button></div>
      {/if}
    </form>
  {/if}
  <p class="faint small">手机丢了进不去后台时，在服务器上运行 <span class="mono">nyapassword-server admin-totp --off</span> 关闭。</p>
</section>

<section class="card">
  <h3>修改管理员密码</h3>
  <form onsubmit={changePassword}>
    <input class="input" type="password" bind:value={cur} placeholder="当前密码" autocomplete="current-password" />
    <input class="input" type="password" bind:value={next} placeholder="新密码（至少 12 个字符）" autocomplete="new-password" />
    <input class="input" type="password" bind:value={next2} placeholder="再输一次新密码" autocomplete="new-password" />
    {#if pwMsg}<div class="banner bad small">{pwMsg}</div>{/if}
    <button class="btn primary" disabled={!cur || !next || pwBusy}>修改</button>
  </form>
  <p class="faint small">管理员密码只用于这个后台，和任何用户的主密码无关。忘记时在服务器上运行 <span class="mono">nyapassword-server admin-password</span> 重设。</p>
</section>

<section class="card">
  <h3>本次登录</h3>
  <p class="small muted">会话保存在服务器内存中，12 小时后或服务器重启后失效。</p>
  <div><button class="btn" onclick={onsignedout}>退出管理后台</button></div>
</section>

<style>
  section { padding: 12px 14px; margin-bottom: 14px; display: flex; flex-direction: column; gap: 10px; max-width: 640px; }
  h3 { margin: 0; font-size: 14px; }
  p { margin: 0; }
  form { display: flex; flex-direction: column; gap: 8px; max-width: 380px; }
  form .btn { align-self: flex-start; }
  .steps { padding-left: 18px; margin: 0; }
  .qrrow { display: flex; gap: 12px; align-items: center; }
  .qr :global(svg) { width: 150px; height: 150px; background: #fff; border-radius: 6px; display: block; }
  .brk { word-break: break-all; }
</style>
