<script lang="ts">
  import { onMount } from 'svelte';
  import { api, setToken, token, type AdminAccount, type AuditEntry, type Health, type Invite } from './api';
  import { bytes, dateTime, relativeTime } from '$lib/i18n';
  import { confirm, toast } from '$lib/ui.svelte';
  import Logo from '$components/Logo.svelte';
  import Overlays from '$components/Overlays.svelte';
  import BackupPage from './BackupPage.svelte';
  import RecoveryKeys from './RecoveryKeys.svelte';
  import VerifyPage from './VerifyPage.svelte';
  import NotifyPage from './NotifyPage.svelte';
  import SchedulePage from './SchedulePage.svelte';
  import AdminPage from './AdminPage.svelte';
  import { admin, loadBackup, loadSecurity } from './store.svelte';
  import { todos, type Page } from './checks';

  const NAV: { group: string; items: [Page, string][] }[] = [
    { group: '', items: [['overview', '概览']] },
    { group: '备份', items: [['backup', '备份'], ['keys', '恢复密钥'], ['verify', '备份校验'], ['notify', '告警通知'], ['schedule', '计划与保留']] },
    { group: '用户', items: [['accounts', '账户与设备'], ['invites', '邀请码'], ['audit', '审计日志']] },
    { group: '', items: [['admin', '管理员']] },
  ];
  const PAGES = NAV.flatMap((g) => g.items.map(([k]) => k));
  const title = (p: Page) => NAV.flatMap((g) => g.items).find(([k]) => k === p)?.[1] ?? '';
  // old links (#backup with the settings modal) still land somewhere sensible
  const fromHash = (): Page => {
    const h = location.hash.slice(1) as Page;
    return PAGES.includes(h) ? h : 'overview';
  };

  let signedIn = $state(!!token());
  let page = $state<Page>(fromHash());
  let navOpen = $state(false);
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
      // the backup status and the admin's TOTP feed the overview and the nav badges
      if (!admin.backup || page === 'overview') await Promise.all([loadBackup(), loadSecurity()]);
      if (page === 'overview') health = await api<Health>('GET', '/health');
      if (page === 'accounts') accounts = await api<AdminAccount[]>('GET', '/accounts');
      if (page === 'invites') invites = await api<Invite[]>('GET', '/invites');
      if (page === 'audit') audit = await api<AuditEntry[]>('GET', '/audit');
    } catch (err) {
      if (!token()) signedIn = false;
      else toast((err as Error).message, 'error');
    }
    if (!token()) signedIn = false;
  }

  function go(p: Page) {
    page = p;
    navOpen = false;
    if (location.hash.slice(1) !== p) location.hash = p;
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

  function signOut() {
    setToken(null);
    signedIn = false;
    admin.backup = null;
    admin.security = null;
    admin.securityLoaded = false;
  }

  const list = $derived(admin.backup ? todos(admin.backup, admin.security) : []);
  const pageTodos = (p: Page) => list.filter((t) => t.page === p);

  onMount(() => {
    void load();
    const onHash = () => {
      const p = fromHash();
      if (p !== page) go(p);
    };
    addEventListener('hashchange', onHash);
    return () => removeEventListener('hashchange', onHash);
  });
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
    <header class="mtop">
      <button class="btn ghost sm" onclick={() => (navOpen = !navOpen)} aria-label="菜单" aria-expanded={navOpen}>☰</button>
      <Logo size={22} /><b class="grow">{title(page)}</b>
      {#if list.length}<button class="badge {list.some((t) => t.level === 'bad') ? 'bad' : 'warn'}" onclick={() => go('overview')}>{list.length} 项待处理</button>{/if}
    </header>
    <nav class="side" class:open={navOpen}>
      <div class="row brand"><Logo size={26} /><b>管理后台</b></div>
      {#each NAV as g, gi (gi)}
        {#if g.group}<div class="group faint">{g.group}</div>{/if}
        {#each g.items as [k, l] (k)}
          {@const n = k === 'overview' ? 0 : pageTodos(k).length}
          <button class="nav" class:on={page === k} onclick={() => go(k)}>
            <span class="grow">{l}</span>
            {#if n}<span class="dot" class:bad={pageTodos(k).some((t) => t.level === 'bad')} title="{n} 项待处理"></span>{/if}
          </button>
        {/each}
      {/each}
      <span class="spacer"></span>
      <a class="nav" href="/">打开网页版</a>
      <button class="nav" onclick={signOut}>退出</button>
    </nav>
    {#if navOpen}<button class="scrim" aria-label="关闭菜单" onclick={() => (navOpen = false)}></button>{/if}
    <main>
      {#if page === 'overview'}
        <h2>概览</h2>
        {#if admin.backup}
          <section class="card todo">
            <h3>待处理</h3>
            {#each list as t (t.id)}
              <button class="todoline" onclick={() => go(t.page)}>
                <span class="mark {t.level}">!</span>
                <span class="grow">{t.text}</span>
                <span class="faint small">去{title(t.page)} ›</span>
              </button>
            {:else}
              <div class="allgood"><span class="mark ok">✓</span> 一切正常：有备份目标、离线恢复密钥、告警通道，备份和校验都成功。</div>
            {/each}
          </section>
        {/if}
        {#if health}
          <div class="stats">
            <div class="card stat"><b class:bad={!health.db_ok}>{health.db_ok ? '正常' : '异常'}</b><span>数据库检查</span></div>
            <div class="card stat"><b>{admin.backup?.last_success_at ? relativeTime(admin.backup.last_success_at) : '从未'}</b><span>上次成功备份</span></div>
            <div class="card stat"><b>{health.accounts}</b><span>账户</span></div>
            <div class="card stat"><b>{health.devices}</b><span>设备</span></div>
            <div class="card stat"><b>{health.items}</b><span>条目</span></div>
            <div class="card stat"><b>{health.revisions}</b><span>历史版本</span></div>
            <div class="card stat"><b>{health.attachments}</b><span>附件 · {bytes(health.attachment_bytes)}</span></div>
            <div class="card stat"><b>{bytes(health.db_bytes)}</b><span>数据库大小</span></div>
            <div class="card stat"><b>{health.version}</b><span>版本 · 启动于 {relativeTime(health.started_at)}</span></div>
          </div>
        {/if}
      {:else if page === 'backup'}
        <BackupPage onnavigate={go} />
      {:else if page === 'keys'}
        <RecoveryKeys />
      {:else if page === 'verify'}
        <VerifyPage onnavigate={go} />
      {:else if page === 'notify'}
        <NotifyPage />
      {:else if page === 'schedule'}
        <SchedulePage />
      {:else if page === 'accounts'}
        <h2>账户与设备</h2>
        {#each accounts as a (a.account_id)}
          <div class="card acc">
            <div class="row wrap"><b>{a.login}</b><span class="faint small">{a.items} 个条目 · 注册于 {dateTime(a.created_at)}</span></div>
            <div class="tblwrap">
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
          </div>
        {:else}<p class="faint">还没有账户。</p>{/each}
      {:else if page === 'invites'}
        <h2>邀请码</h2>
        <p class="muted">第一个账户注册后，新账户需要邀请码。</p>
        <button class="btn primary" onclick={invite}>生成邀请码（72 小时有效）</button>
        {#if newInvite}<div class="banner ok" style="margin-top:12px">邀请码：<b class="mono">{newInvite.code}</b>（只显示这一次）</div>{/if}
        <div class="card" style="margin-top:14px">
          {#each invites as i, k (k)}<div class="row line"><span class="grow">到期 {dateTime(i.expires_at)}</span>{#if i.used_at}<span class="badge">已使用 {dateTime(i.used_at)}</span>{:else if i.expires_at < Date.now()}<span class="badge">已过期</span>{:else}<span class="badge ok">可用</span>{/if}</div>
          {:else}<div class="line faint small">还没有邀请码</div>{/each}
        </div>
      {:else if page === 'audit'}
        <h2>审计日志</h2>
        <div class="card tblwrap"><table class="tbl audit"><thead><tr><th>时间</th><th>操作</th><th>详情</th><th>IP</th></tr></thead><tbody>
          {#each audit as a, k (k)}<tr><td class="nowrap">{dateTime(a.at)}</td><td>{a.action}</td><td class="brk">{a.detail}</td><td class="mono">{a.ip}</td></tr>{/each}
        </tbody></table></div>
      {:else if page === 'admin'}
        <AdminPage onsignedout={signOut} />
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
  .layout { display: grid; grid-template-columns: 210px 1fr; height: 100%; }
  .mtop { display: none; }
  .side { background: var(--sidebar); border-right: 1px solid var(--border); padding: 14px 10px; display: flex; flex-direction: column; gap: 2px; overflow: auto; }
  .group { font-size: 11.5px; padding: 10px 10px 2px; letter-spacing: .04em; }
  .nav { border: 0; background: transparent; text-align: left; padding: 7px 10px; border-radius: 7px; color: var(--text); text-decoration: none; font-size: 14px; display: flex; align-items: center; gap: 6px; }
  .nav:hover { background: var(--surface-3); }
  .nav.on { background: var(--sel); color: var(--accent); font-weight: 600; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--warn); flex: none; }
  .dot.bad { background: var(--bad); }
  .scrim { display: none; }
  main { padding: 22px 26px 40px; overflow: auto; min-width: 0; }
  main :global(h2) { margin: 0 0 12px; font-size: 18px; }
  .stats { display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: 12px; }
  .stat { padding: 12px 14px; display: flex; flex-direction: column; }
  .stat b { font-size: 22px; }
  .stat b.bad { color: var(--bad); }
  .stat span { color: var(--text-2); font-size: 12.5px; }
  .todo { margin-bottom: 16px; }
  .todo h3 { margin: 0; padding: 12px 14px 6px; font-size: 14px; }
  .todoline { display: flex; align-items: center; gap: 10px; width: 100%; padding: 9px 14px; border: 0; border-top: 1px solid var(--border); background: transparent; text-align: left; }
  .todoline:hover { background: var(--surface-2); }
  .mark { width: 20px; height: 20px; border-radius: 50%; display: grid; place-items: center; font-weight: 700; font-size: 12px; flex: none; }
  .mark.bad { background: var(--bad-bg); color: var(--bad); }
  .mark.warn { background: var(--warn-bg); color: var(--warn); }
  .mark.ok { background: var(--ok-bg); color: var(--ok); }
  .allgood { display: flex; gap: 10px; align-items: center; padding: 9px 14px 12px; color: var(--text-2); }
  .acc { padding: 12px 14px; margin-bottom: 12px; }
  .wrap { flex-wrap: wrap; }
  .tblwrap { overflow-x: auto; }
  .tblwrap table { min-width: 560px; }
  .audit td.brk { min-width: 220px; }
  .nowrap { white-space: nowrap; }
  .brk { word-break: break-all; }
  .line { padding: 8px 14px; border-bottom: 1px solid var(--border); }
  button.badge { border: 0; cursor: pointer; }

  /* phone / narrow: the navigation becomes a drawer under a top bar */
  @media (max-width: 760px) {
    .layout { grid-template-columns: 1fr; grid-template-rows: 46px 1fr; }
    .mtop { display: flex; align-items: center; gap: 8px; padding: 0 10px; border-bottom: 1px solid var(--border); background: var(--surface); }
    .side { position: fixed; top: 46px; bottom: 0; left: 0; width: 240px; z-index: 30; transform: translateX(-100%); transition: transform .18s; box-shadow: var(--shadow); }
    .side.open { transform: none; }
    .side .brand { display: none; }
    .scrim { display: block; position: fixed; inset: 46px 0 0 0; background: rgba(0, 0, 0, .25); border: 0; z-index: 29; }
    main { padding: 16px 16px 40px; }
    .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
    .stat b { font-size: 18px; }
  }
</style>
