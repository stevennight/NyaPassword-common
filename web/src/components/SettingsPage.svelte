<script lang="ts" module>
  /** The last category, kept while the app runs (leaving settings and coming back). */
  let lastCategory: string | null = null;
</script>

<script lang="ts">
  import { onMount } from 'svelte';
  import { vault } from '$lib/vault.svelte';
  import { errorCode, errorMessage } from '$lib/bridge';
  import { dateTime, errorText, relativeTime } from '$lib/i18n';
  import { confirm, toast } from '$lib/ui.svelte';
  import { desktopApi } from '$lib/desktop';
  import type { QuickUnlockStatus } from '$lib/bridge';
  import type { AuditEntry, DeviceRecord, EmergencyKit as Kit } from '$lib/types';
  import EmergencyKit from './EmergencyKit.svelte';
  import ExportPanel from './ExportPanel.svelte';
  import Modal from './Modal.svelte';

  type Cat = 'general' | 'security' | 'account' | 'vaults' | 'devices' | 'extension' | 'quick' | 'ssh' | 'export';
  const desktop = vault.bridge.kind === 'desktop';
  // categories of the current client: the desktop app adds four
  const CATS: { id: Cat; title: string; sub: string; desktop?: boolean }[] = [
    { id: 'general', title: '通用', sub: desktop ? '外观、开机启动、更新' : '外观' },
    { id: 'security', title: '安全与解锁', sub: desktop ? 'PIN、Windows Hello、自动锁定' : '解锁方式、自动锁定' },
    { id: 'account', title: '账户', sub: '紧急恢复包、主密码、退出' },
    { id: 'vaults', title: '保险库', sub: '新建、改名' },
    { id: 'devices', title: '设备与日志', sub: '登录的设备、账户日志' },
    { id: 'extension', title: '浏览器扩展', sub: '由桌面端解锁扩展、配对', desktop: true },
    { id: 'quick', title: '快速搜索与自动输入', sub: '全局快捷键、自动输入', desktop: true },
    { id: 'ssh', title: 'SSH 与 Git', sub: 'SSH agent、Git 提交签名', desktop: true },
    { id: 'export', title: '导出与备份', sub: desktop ? '定期离线导出、立即导出' : '立即导出' },
  ];
  const cats = CATS.filter((c) => desktop || !c.desktop);

  let cat = $state<Cat>(cats.find((c) => c.id === lastCategory)?.id ?? 'general');
  /** Phones: the list is showing until a category is picked. */
  let picked = $state(lastCategory !== null);
  const title = $derived(cats.find((c) => c.id === cat)?.title ?? '');

  function open(c: Cat) {
    cat = c;
    picked = true;
    lastCategory = c;
    if (c === 'devices') void loadDevices();
  }

  let devices = $state<DeviceRecord[]>([]);
  let audit = $state<AuditEntry[]>([]);
  let kit = $state<Kit | null>(null);
  let quick = $state<QuickUnlockStatus>({ available: false, enabled: false, label: '' });
  const desk = desktopApi(vault.bridge);
  // PIN (desktop only): set / change
  let pinOpen = $state(false);
  let pin1 = $state('');
  let pin2 = $state('');
  let pinMsg = $state('');
  let pinBusy = $state(false);
  let cur = $state('');
  let next = $state('');
  let next2 = $state('');
  let pwMsg = $state('');
  let signingOut = $state(false);
  let newVault = $state('');
  let theme = $state(document.documentElement.dataset.theme ?? 'auto');

  async function loadDevices() {
    devices = await vault.bridge.devices().catch(() => []);
    audit = await vault.bridge.auditLog().catch(() => []);
  }

  onMount(async () => {
    quick = await vault.bridge.quickUnlockStatus().catch(() => quick);
    await loadDevices();
  });

  async function changePassword(e: Event) {
    e.preventDefault();
    pwMsg = '';
    if (next !== next2) return (pwMsg = '两次输入的新密码不一致');
    if (next.length < 10) return (pwMsg = '新主密码至少 10 个字符');
    try {
      await vault.bridge.changePassword(cur, next);
      cur = next = next2 = '';
      const cleared = quick.quick_set || quick.pin_set;
      toast(`主密码已修改；其他设备需要用新密码重新登录${cleared ? `。本机的 ${quick.label || '生物识别'} / PIN 解锁已清除，请重新设置` : ''}`, 'ok', 6000);
      quick = await vault.bridge.quickUnlockStatus().catch(() => quick);
    } catch (err) {
      pwMsg = errorText(errorCode(err), errorMessage(err));
    }
  }

  async function revoke(d: DeviceRecord) {
    if (!(await confirm('移除设备？', `“${d.name}”会立即退出，需要主密码和 Secret Key 才能重新登录。`, '移除', true))) return;
    await vault.bridge.revokeDevice(d.id).catch(vault.fail.bind(vault));
    await loadDevices();
  }

  /** Set up (the web vault: usable) right now. */
  const quickOn = $derived(quick.quick_set ?? quick.enabled);

  async function toggleQuick() {
    try {
      await vault.bridge.setQuickUnlock(!quickOn);
      quick = await vault.bridge.quickUnlockStatus();
    } catch (e) {
      vault.fail(e);
    }
  }

  async function setAtStart(on: boolean) {
    if (!desk) return;
    await desk.setBiometricAtStart(on).catch(vault.fail.bind(vault));
    quick = await vault.bridge.quickUnlockStatus().catch(() => quick);
  }

  async function savePin(e: Event) {
    e.preventDefault();
    if (!desk) return;
    pinMsg = '';
    if ([...pin1].length < 4) return (pinMsg = 'PIN 至少 4 个字符（任意字符）');
    if (pin1 !== pin2) return (pinMsg = '两次输入的 PIN 不一致');
    pinBusy = true;
    // let the button repaint before the key derivation blocks
    await new Promise((r) => setTimeout(r, 30));
    try {
      await desk.setPin(pin1);
      pin1 = pin2 = '';
      pinOpen = false;
      toast(quick.pin_set ? 'PIN 已修改' : 'PIN 已设置', 'ok');
      quick = await vault.bridge.quickUnlockStatus().catch(() => quick);
    } catch (err) {
      pinMsg = errorText(errorCode(err), errorMessage(err));
    } finally {
      pinBusy = false;
    }
  }

  async function removePin() {
    if (!desk || !(await confirm('删除 PIN？', '之后只能用主密码或生物识别解锁。', '删除', true))) return;
    await desk.removePin().catch(vault.fail.bind(vault));
    quick = await vault.bridge.quickUnlockStatus().catch(() => quick);
  }

  async function createVault() {
    if (!newVault.trim()) return;
    try {
      await vault.bridge.createVault(newVault.trim());
      newVault = '';
      await vault.reload();
      toast('保险库已创建');
    } catch (e) {
      vault.fail(e);
    }
  }

  async function rename(id: string, old: string) {
    const name = prompt('新名称', old);
    if (!name || name === old) return;
    await vault.bridge.renameVault(id, name).catch(vault.fail.bind(vault));
    await vault.reload();
  }

  function setTheme(t: string) {
    theme = t;
    if (t === 'auto') delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = t;
    try {
      localStorage.setItem('npw.theme', t);
    } catch {
      /* ignore */
    }
  }

  async function signOut() {
    const [, pending] = vault.attention;
    const warn = pending ? `还有 ${pending} 处修改没有同步到服务器，退出会丢失它们！` : '会删除此设备上的本地副本。';
    if (!(await confirm('退出此设备上的账户？', `${warn}\n下次登录需要 Secret Key。`, '退出', true))) return;
    signingOut = true;
    try {
      await vault.bridge.signOut(true);
      await vault.refreshLock();
    } catch (e) {
      toast(errorText(errorCode(e), errorMessage(e)), 'error');
    } finally {
      signingOut = false;
    }
  }

  const ACTIONS: Record<string, string> = {
    register: '注册', login: '登录', login_failed: '登录失败', password_change: '修改主密码', device_revoke: '移除设备', vault_create: '新建保险库', import: '导入', purge: '永久删除',
  };
  const LOCK_MINUTES = [1, 5, 10, 30, 60, 240];
</script>

<div class="sizer">
<div class="settings" class:picked>
  <nav class="cats" aria-label="设置分类">
    <h2 class="navtitle">设置</h2>
    {#each cats as c (c.id)}
      <button class="cat" class:on={cat === c.id} onclick={() => open(c.id)} aria-current={cat === c.id ? 'page' : undefined}>
        <span class="ct">{c.title}</span><span class="cs">{c.sub}</span><span class="chev">›</span>
      </button>
    {/each}
  </nav>

  <div class="content">
    <div class="row chead">
      <button class="btn ghost sm back" onclick={() => (picked = false)}>‹ 设置</button>
      <h2>{title}</h2>
    </div>

    {#if cat === 'general'}
      <section class="card">
        <h3>外观</h3>
        <div class="row"><span class="grow">主题</span>
          <select class="select" style="width:auto" value={theme} onchange={(e) => setTheme((e.target as HTMLSelectElement).value)}><option value="auto">跟随系统</option><option value="light">浅色</option><option value="dark">深色</option></select></div>
      </section>
      {#if desktop}{#await import('./desktop/DesktopSettings.svelte') then m}<m.default section="general" />{/await}{/if}
    {:else if cat === 'security'}
      <section class="card">
        <h3>解锁方式</h3>
        <div class="row"><span class="grow">主密码<span class="faint small">（始终可用；生物识别和 PIN 每 14 天仍需输入一次主密码）</span></span><span class="badge ok">已开启</span></div>
        {#if quick.available}
          <div class="row"><span class="grow">使用 {quick.label} 解锁<span class="faint small">（重置 {quick.label} 后失效）</span></span><button class="btn" onclick={toggleQuick}>{quickOn ? '关闭' : '开启'}</button></div>
          {#if desk && quickOn}
            <label class="row"><input type="checkbox" checked={quick.biometric_at_start ?? true} onchange={(e) => setAtStart((e.target as HTMLInputElement).checked)} />
              <span class="grow">启动时可直接用生物识别解锁（{quick.label}）<span class="faint small">（关闭后，每次启动后第一次解锁需要主密码）</span></span></label>
          {/if}
        {:else if desk}
          <div class="row"><span class="grow faint small">这台电脑没有可用的 Windows Hello / 生物识别</span></div>
        {/if}
        {#if desk && quick.pin_supported}
          <div class="row">
            <span class="grow">PIN 解锁<span class="faint small">（至少 4 个字符；连续输错 5 次作废；也可用于“使用前需要验证”）</span></span>
            {#if quick.pin_set}<button class="btn" onclick={() => (pinOpen = !pinOpen)}>修改</button><button class="btn danger" onclick={removePin}>删除</button>
            {:else}<button class="btn" onclick={() => (pinOpen = !pinOpen)}>设置</button>{/if}
          </div>
          {#if pinOpen}
            <form class="pinform" onsubmit={savePin}>
              <input class="input" type="password" bind:value={pin1} placeholder="新 PIN" autocomplete="off" disabled={pinBusy} />
              <input class="input" type="password" bind:value={pin2} placeholder="再输一次 PIN" autocomplete="off" disabled={pinBusy} />
              {#if pinMsg}<div class="banner bad small">{pinMsg}</div>{/if}
              <button class="btn primary" disabled={pinBusy || !pin1}>{pinBusy ? '请稍候…' : '保存 PIN'}</button>
              <p class="faint small">PIN 只保存在这台电脑上（Windows 凭据管理器保护），不会上传。忘记 PIN 时用主密码解锁即可。</p>
            </form>
          {/if}
        {:else if desk && quick.pin_supported === false && vault.lock?.signed_in}
          <div class="row"><span class="grow faint small">PIN 解锁不可用：设备密钥没有保存在系统凭据存储中</span></div>
        {/if}
        {#if quick.password_reason}<div class="faint small">{quick.password_reason}</div>{/if}
      </section>
      <section class="card">
        <h3>自动锁定</h3>
        <div class="row">
          <span class="grow">空闲后自动锁定</span>
          <select class="select" style="width:auto" value={vault.autoLockMinutes} onchange={(e) => vault.setAutoLock(Number((e.target as HTMLSelectElement).value))}>
            {#each LOCK_MINUTES as m (m)}<option value={m}>{m < 60 ? `${m} 分钟` : `${m / 60} 小时`}</option>{/each}
          </select>
        </div>
        {#if !desktop}<p class="faint small">复制的密码 90 秒后从剪贴板清除（浏览器允许读取剪贴板时，只清除还没被替换的内容）。</p>{/if}
      </section>
      {#if desktop}{#await import('./desktop/DesktopSettings.svelte') then m}<m.default section="security" />{/await}{/if}
    {:else if cat === 'account'}
      <section class="card">
        <h3>账户信息</h3>
        <div class="kv"><span>账号</span><b>{vault.lock?.login}</b><span>服务器</span><span class="mono brk">{vault.lock?.server_url}</span><span>上次同步</span><span>{relativeTime(vault.lock?.last_sync_at ?? 0)}{vault.syncError ? ` · ${vault.syncError}` : ''}</span></div>
        <div class="row wrap"><button class="btn" onclick={async () => (kit = await vault.bridge.emergencyKit())}>查看紧急恢复包</button><button class="btn" onclick={() => vault.sync(false)}>立即同步</button></div>
      </section>
      <section class="card">
        <h3>修改主密码</h3>
        <form onsubmit={changePassword}>
          <input class="input" type="password" bind:value={cur} placeholder="当前主密码" autocomplete="current-password" />
          <input class="input" type="password" bind:value={next} placeholder="新主密码" autocomplete="new-password" />
          <input class="input" type="password" bind:value={next2} placeholder="再输一次新主密码" autocomplete="new-password" />
          {#if pwMsg}<div class="banner bad small">{pwMsg}</div>{/if}
          <button class="btn primary" disabled={!cur || !next}>修改</button>
          <p class="faint small">Secret Key 不变；紧急恢复包上的主密码记得一起更新。</p>
        </form>
      </section>
      <section class="card">
        <h3>退出</h3>
        <p class="faint small">删除此设备上的本地副本；下次登录需要主密码和 Secret Key。</p>
        <div><button class="btn danger" onclick={signOut} disabled={signingOut}>{signingOut ? '正在退出…' : '退出此设备上的账户'}</button></div>
      </section>
    {:else if cat === 'vaults'}
      <section class="card">
        <h3>保险库</h3>
        {#each vault.vaults as v (v.id)}
          <div class="row line"><span class="grow">{v.name}</span><span class="faint small">{v.items} 个条目</span><button class="btn sm" onclick={() => rename(v.id, v.name)}>改名</button></div>
        {/each}
        <form class="row" onsubmit={(e) => { e.preventDefault(); void createVault(); }}><input class="input" bind:value={newVault} placeholder="新保险库名称" /><button class="btn" disabled={!newVault.trim()}>新建</button></form>
      </section>
    {:else if cat === 'devices'}
      <section class="card">
        <h3>设备</h3>
        {#each devices as d (d.id)}
          <div class="row line">
            <span class="grow">{d.name} {#if d.current}<span class="badge acc">本机</span>{/if}{#if d.revoked_at}<span class="badge bad">已移除</span>{/if}
              <div class="faint small">{d.platform} · {d.client_version} · 最近活动 {relativeTime(d.last_seen_at)}</div></span>
            {#if !d.current && !d.revoked_at}<button class="btn sm danger" onclick={() => revoke(d)}>移除</button>{/if}
          </div>
        {:else}<p class="faint small">读取中…（离线时不可用）</p>{/each}
      </section>
      <section class="card">
        <h3>账户日志</h3>
        <div class="log">
          {#each audit.slice(0, 50) as a, i (i)}
            <div class="row small line logline"><span class="faint">{dateTime(a.at)}</span><span>{ACTIONS[a.action] ?? a.action}</span><span class="faint grow">{a.detail}</span><span class="faint mono">{a.ip}</span></div>
          {:else}<p class="faint small">没有记录</p>{/each}
        </div>
      </section>
    {:else if cat === 'export'}
      {#if desktop}{#await import('./desktop/DesktopSettings.svelte') then m}<m.default section="export" />{/await}{/if}
      <section class="card">
        <h3>立即导出到文件</h3>
        <p class="faint small">把整个账户导出成一个文件，下载到这台设备。与服务器无关：服务器和它的备份都没了，这个文件仍然能打开。</p>
        <ExportPanel />
      </section>
    {:else if desktop && (cat === 'extension' || cat === 'quick' || cat === 'ssh')}
      {#await import('./desktop/DesktopSettings.svelte') then m}<m.default section={cat} />{/await}
    {/if}
  </div>
</div>

</div>

{#if kit}
  <Modal title="紧急恢复包" onclose={() => (kit = null)} width={680}><EmergencyKit {kit} /></Modal>
{/if}

<style>
  /* wide: categories on the left; narrow: tabs; phone: the list, then one category */
  .sizer { container-type: inline-size; min-height: 100%; display: flex; flex-direction: column; }
  .settings { flex: 1; display: grid; grid-template-columns: 210px minmax(0, 1fr); min-height: 100%; }
  .cats { border-right: 1px solid var(--border); padding: 22px 10px; display: flex; flex-direction: column; gap: 2px; background: var(--surface); }
  .navtitle { margin: 0 10px 10px; font-size: 20px; }
  .cat { display: grid; grid-template-columns: 1fr auto; text-align: left; border: 0; background: transparent; padding: 7px 10px; border-radius: 8px; color: var(--text); }
  .cat:hover { background: var(--surface-3); }
  .cat.on { background: var(--sel); color: var(--accent); }
  .cat.on .ct { font-weight: 600; }
  .cs { display: none; grid-column: 1; font-size: 12px; color: var(--text-3); }
  .chev { display: none; grid-row: 1 / span 2; grid-column: 2; align-self: center; color: var(--text-3); font-size: 18px; }
  .content { padding: 22px 28px 40px; max-width: 800px; min-width: 0; }
  .chead { margin-bottom: 12px; }
  .chead h2 { margin: 0; }
  .back { display: none; }
  section { padding: 14px 16px; margin-bottom: 14px; display: flex; flex-direction: column; gap: 10px; }
  h3 { margin: 0; font-size: 14px; }
  p { margin: 0; }
  form { display: flex; flex-direction: column; gap: 8px; }
  form.row { flex-direction: row; }
  .pinform { max-width: 360px; }
  form:not(.row) .btn { align-self: flex-start; }
  .kv { display: grid; grid-template-columns: 80px 1fr; gap: 4px 12px; font-size: 13.5px; }
  .kv span:nth-child(odd) { color: var(--text-2); }
  .brk { word-break: break-all; }
  .wrap { flex-wrap: wrap; }
  .line { padding: 6px 0; border-bottom: 1px solid var(--border); }
  .log { max-height: 420px; overflow: auto; }

  /* narrow: the categories become tabs above the content */
  @container (max-width: 760px) {
    .settings { grid-template-columns: 1fr; grid-template-rows: auto 1fr; }
    .cats { flex-direction: row; overflow-x: auto; border-right: 0; border-bottom: 1px solid var(--border); padding: 8px 10px 0; gap: 0; scrollbar-width: none; }
    .navtitle { display: none; }
    .cat { white-space: nowrap; border-radius: 0; padding: 8px 12px; border-bottom: 2px solid transparent; }
    .cat.on { background: transparent; border-bottom-color: var(--accent); }
    .content { padding: 16px 18px 40px; }
    .logline { flex-wrap: wrap; }
  }
  /* phone: a list of categories, then one category with a back button */
  @container (max-width: 520px) {
    .settings { display: block; }
    .cats { flex-direction: column; overflow: visible; border-bottom: 0; padding: 16px 12px; gap: 6px; background: transparent; }
    .navtitle { display: block; margin: 0 4px 6px; }
    .cat { white-space: normal; border: 1px solid var(--border); border-radius: 11px; background: var(--surface); padding: 10px 14px; }
    .cat.on { background: var(--surface); border-color: var(--border); color: var(--text); }
    .cat.on .ct { font-weight: 400; }
    .cs, .chev { display: block; }
    .settings:not(.picked) .content { display: none; }
    .settings.picked .cats { display: none; }
    .back { display: inline-flex; }
    .content { padding: 12px 12px 40px; }
    .kv { grid-template-columns: 64px 1fr; }
  }
</style>
