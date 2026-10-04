<script lang="ts">
  import { onMount } from 'svelte';
  import { api, setToken, token, type AdminAccount, type AuditEntry, type Health, type Invite } from './api';
  import { bytes, dateTime, relativeTime } from '$lib/i18n';
  import { confirm, toast } from '$lib/ui.svelte';
  import Logo from '$components/Logo.svelte';
  import Overlays from '$components/Overlays.svelte';
  import BackupPage from './BackupPage.svelte';

  type Tab = 'overview' | 'backup' | 'accounts' | 'invites' | 'audit';
  let signedIn = $state(!!token());
  let tab = $state<Tab>((location.hash.slice(1) as Tab) || 'overview');
  let password = $state('');
  let totp = $state('');
  let error = $state('');
  let health = $state<Health | null>(null);
  let accounts = $state<AdminAccount[]>([]);
  let invites = $state<Invite[]>([]);
  let newInvite = $state<Invite | null>(null);
  let audit = $state<AuditEntry[]>([]);

  async function login(e: Event) {
    e.preventDefault();
    error = '';
    try {
      const s = await api<{ token: string }>('POST', '/login', { password, totp: totp || undefined });
      setToken(s.token);
      signedIn = true;
      password = totp = '';
      await load();
    } catch (err) {
      error = (err as Error).message;
    }
  }

  async function load() {
    if (!signedIn) return;
    try {
      if (tab === 'overview') health = await api<Health>('GET', '/health');
      if (tab === 'accounts') accounts = await api<AdminAccount[]>('GET', '/accounts');
      if (tab === 'invites') invites = await api<Invite[]>('GET', '/invites');
      if (tab === 'audit') audit = await api<AuditEntry[]>('GET', '/audit');
    } catch (err) {
      if (!token()) signedIn = false;
      else toast((err as Error).message, 'error');
    }
  }

  function go(t: Tab) {
    tab = t;
    location.hash = t;
    void load();
  }

  async function invite() {
    newInvite = await api<Invite>('POST', '/invites', { hours: 72 });
    invites = await api<Invite[]>('GET', '/invites');
  }

  async function revoke(id: string, name: string) {
    if (!(await confirm('移除设备？', `“${name}”会立即退出登录。`, '移除', true))) return;
    await api('DELETE', `/devices/${id}`);
    accounts = await api<AdminAccount[]>('GET', '/accounts');
  }

  onMount(load);
</script>

{#if !signedIn}
  <div class="center">
    <form class="login" onsubmit={login}>
      <div class="row brand"><Logo size={36} /><h2>NyaPassword 管理后台</h2></div>
      <label class="lbl" for="ap">管理员密码</label>
      <input id="ap" class="input" type="password" bind:value={password} autocomplete="current-password" required />
      <label class="lbl" for="at">TOTP（如已开启）</label>
      <input id="at" class="input mono" bind:value={totp} inputmode="numeric" autocomplete="one-time-code" />
      {#if error}<div class="banner bad small" style="margin-top:10px">{error}</div>{/if}
      <button class="btn primary" style="width:100%;justify-content:center;margin-top:14px">登录</button>
      <p class="faint small">管理后台不能查看任何密码：服务器只有密文。</p>
    </form>
  </div>
{:else}
  <div class="layout">
    <nav class="side">
      <div class="row brand"><Logo size={26} /><b>管理后台</b></div>
      {#each [['overview', '概览'], ['backup', '备份与恢复'], ['accounts', '账户与设备'], ['invites', '邀请码'], ['audit', '审计日志']] as [k, l] (k)}
        <button class="nav" class:on={tab === k} onclick={() => go(k as Tab)}>{l}</button>
      {/each}
      <span class="spacer"></span>
      <a class="nav" href="/">打开网页版</a>
      <button class="nav" onclick={() => { setToken(null); signedIn = false; }}>退出</button>
    </nav>
    <main>
      {#if tab === 'overview' && health}
        <h2>概览</h2>
        <div class="stats">
          <div class="card stat"><b class:bad={!health.db_ok}>{health.db_ok ? '正常' : '异常'}</b><span>数据库检查</span></div>
          <div class="card stat"><b>{health.accounts}</b><span>账户</span></div>
          <div class="card stat"><b>{health.devices}</b><span>设备</span></div>
          <div class="card stat"><b>{health.items}</b><span>条目</span></div>
          <div class="card stat"><b>{health.revisions}</b><span>历史版本</span></div>
          <div class="card stat"><b>{health.attachments}</b><span>附件 · {bytes(health.attachment_bytes)}</span></div>
          <div class="card stat"><b>{bytes(health.db_bytes)}</b><span>数据库大小</span></div>
          <div class="card stat"><b>{health.version}</b><span>版本 · 启动于 {relativeTime(health.started_at)}</span></div>
        </div>
      {:else if tab === 'backup'}
        <BackupPage />
      {:else if tab === 'accounts'}
        <h2>账户与设备</h2>
        {#each accounts as a (a.account_id)}
          <div class="card acc">
            <div class="row"><b>{a.login}</b><span class="faint small">{a.items} 个条目 · 注册于 {dateTime(a.created_at)}</span></div>
            <table class="tbl">
              <thead><tr><th>设备</th><th>平台</th><th>版本</th><th>最近活动</th><th></th></tr></thead>
              <tbody>
                {#each a.devices as d (d.id)}
                  <tr><td>{d.name}</td><td>{d.platform}</td><td>{d.client_version}</td><td>{relativeTime(d.last_seen_at)}</td>
                    <td>{#if d.revoked_at}<span class="badge">已移除</span>{:else}<button class="btn sm danger" onclick={() => revoke(d.id, d.name)}>移除</button>{/if}</td></tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/each}
      {:else if tab === 'invites'}
        <h2>邀请码</h2>
        <p class="muted">第一个账户注册后，新账户需要邀请码。</p>
        <button class="btn primary" onclick={invite}>生成邀请码（72 小时有效）</button>
        {#if newInvite}<div class="banner ok" style="margin-top:12px">邀请码：<b class="mono">{newInvite.code}</b>（只显示这一次）</div>{/if}
        <div class="card" style="margin-top:14px">
          {#each invites as i, k (k)}<div class="row line"><span class="grow">到期 {dateTime(i.expires_at)}</span>{#if i.used_at}<span class="badge">已使用 {dateTime(i.used_at)}</span>{:else if i.expires_at < Date.now()}<span class="badge">已过期</span>{:else}<span class="badge ok">可用</span>{/if}</div>{/each}
        </div>
      {:else if tab === 'audit'}
        <h2>审计日志</h2>
        <div class="card"><table class="tbl"><thead><tr><th>时间</th><th>操作</th><th>详情</th><th>IP</th></tr></thead><tbody>
          {#each audit as a, k (k)}<tr><td>{dateTime(a.at)}</td><td>{a.action}</td><td>{a.detail}</td><td class="mono">{a.ip}</td></tr>{/each}
        </tbody></table></div>
      {/if}
    </main>
  </div>
{/if}
<Overlays />

<style>
  .center { height: 100%; display: grid; place-items: center; padding: 16px; }
  .login { width: min(380px, 100%); background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 22px; box-shadow: var(--shadow); }
  .brand { gap: 8px; margin-bottom: 10px; }
  .brand h2 { margin: 0; font-size: 18px; }
  .layout { display: grid; grid-template-columns: 200px 1fr; height: 100%; }
  .side { background: var(--sidebar); border-right: 1px solid var(--border); padding: 14px 10px; display: flex; flex-direction: column; gap: 2px; }
  .nav { border: 0; background: transparent; text-align: left; padding: 7px 10px; border-radius: 7px; color: var(--text); text-decoration: none; font-size: 14px; }
  .nav:hover { background: var(--surface-3); }
  .nav.on { background: var(--sel); color: var(--accent); font-weight: 600; }
  main { padding: 22px 26px; overflow: auto; }
  h2 { margin: 0 0 12px; font-size: 18px; }
  .stats { display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: 12px; }
  .stat { padding: 12px 14px; display: flex; flex-direction: column; }
  .stat b { font-size: 22px; }
  .stat b.bad { color: var(--bad); }
  .stat span { color: var(--text-2); font-size: 12.5px; }
  .acc { padding: 12px 14px; margin-bottom: 12px; }
  .line { padding: 8px 14px; border-bottom: 1px solid var(--border); }
  @media (max-width: 760px) { .layout { grid-template-columns: 1fr; } .side { flex-direction: row; flex-wrap: wrap; } }
</style>
