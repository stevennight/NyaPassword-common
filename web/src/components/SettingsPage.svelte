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
  import Modal from './Modal.svelte';

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

  onMount(async () => {
    quick = await vault.bridge.quickUnlockStatus().catch(() => quick);
    devices = await vault.bridge.devices().catch(() => []);
    audit = await vault.bridge.auditLog().catch(() => []);
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
    devices = await vault.bridge.devices();
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
</script>

<div class="page">
  <h2>设置</h2>

  <section class="card">
    <h3>账户</h3>
    <div class="kv"><span>账号</span><b>{vault.lock?.login}</b><span>服务器</span><span class="mono">{vault.lock?.server_url}</span><span>上次同步</span><span>{relativeTime(vault.lock?.last_sync_at ?? 0)}{vault.syncError ? ` · ${vault.syncError}` : ''}</span></div>
    <div class="row"><button class="btn" onclick={async () => (kit = await vault.bridge.emergencyKit())}>查看紧急恢复包</button><button class="btn" onclick={() => vault.sync(false)}>立即同步</button></div>
  </section>

  <section class="card">
    <h3>解锁与锁定</h3>
    <div class="row">
      <span class="grow">空闲后自动锁定</span>
      <select class="select" style="width:auto" value={vault.autoLockMinutes} onchange={(e) => vault.setAutoLock(Number((e.target as HTMLSelectElement).value))}>
        {#each [1, 5, 10, 30, 60, 240] as m (m)}<option value={m}>{m < 60 ? `${m} 分钟` : `${m / 60} 小时`}</option>{/each}
      </select>
    </div>
    {#if quick.available}
      <div class="row"><span class="grow">使用 {quick.label} 解锁<span class="faint small">（每 14 天仍需输入一次主密码；重置 {quick.label} 后失效）</span></span><button class="btn" onclick={toggleQuick}>{quickOn ? '关闭' : '开启'}</button></div>
      {#if desk && quickOn}
        <label class="row"><input type="checkbox" checked={quick.biometric_at_start ?? true} onchange={(e) => setAtStart((e.target as HTMLInputElement).checked)} />
          <span class="grow">启动时可直接用生物识别解锁（{quick.label}）<span class="faint small">（关闭后，每次启动后第一次解锁需要主密码）</span></span></label>
      {/if}
    {/if}
    {#if desk && quick.pin_supported}
      <div class="row">
        <span class="grow">PIN 解锁<span class="faint small">（至少 4 个字符；连续输错 5 次作废；每 14 天仍需输入一次主密码；也可用于“使用前需要验证”）</span></span>
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
    <div class="row"><span class="grow">外观</span>
      <select class="select" style="width:auto" value={theme} onchange={(e) => setTheme((e.target as HTMLSelectElement).value)}><option value="auto">跟随系统</option><option value="light">浅色</option><option value="dark">深色</option></select></div>
  </section>

  {#if vault.bridge.kind === 'desktop'}
    {#await import('./desktop/DesktopSettings.svelte') then m}<m.default />{/await}
  {/if}

  <section class="card">
    <h3>保险库</h3>
    {#each vault.vaults as v (v.id)}
      <div class="row line"><span class="grow">{v.name}</span><span class="faint small">{v.items} 个条目</span><button class="btn sm" onclick={() => rename(v.id, v.name)}>改名</button></div>
    {/each}
    <div class="row"><input class="input" bind:value={newVault} placeholder="新保险库名称" /><button class="btn" onclick={createVault}>新建</button></div>
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
    <h3>设备</h3>
    {#each devices as d (d.id)}
      <div class="row line">
        <span class="grow">{d.name} {#if d.current}<span class="badge acc">本机</span>{/if}{#if d.revoked_at}<span class="badge bad">已移除</span>{/if}
          <div class="faint small">{d.platform} · {d.client_version} · 最近活动 {relativeTime(d.last_seen_at)}</div></span>
        {#if !d.current && !d.revoked_at}<button class="btn sm danger" onclick={() => revoke(d)}>移除</button>{/if}
      </div>
    {/each}
  </section>

  <section class="card">
    <h3>账户日志</h3>
    <div class="log">
      {#each audit.slice(0, 50) as a, i (i)}
        <div class="row small line"><span class="faint">{dateTime(a.at)}</span><span>{ACTIONS[a.action] ?? a.action}</span><span class="faint grow">{a.detail}</span><span class="faint mono">{a.ip}</span></div>
      {/each}
    </div>
  </section>

  <section class="card">
    <h3>退出</h3>
    <button class="btn danger" onclick={signOut} disabled={signingOut}>{signingOut ? '正在退出…' : '退出此设备上的账户'}</button>
  </section>
</div>

{#if kit}
  <Modal title="紧急恢复包" onclose={() => (kit = null)} width={680}><EmergencyKit {kit} /></Modal>
{/if}

<style>
  .page { padding: 22px 28px 40px; max-width: 760px; }
  h2 { margin: 0 0 12px; }
  section { padding: 14px 16px; margin-bottom: 14px; display: flex; flex-direction: column; gap: 10px; }
  h3 { margin: 0; font-size: 14px; }
  form { display: flex; flex-direction: column; gap: 8px; }
  .pinform { max-width: 360px; }
  form .btn { align-self: flex-start; }
  .kv { display: grid; grid-template-columns: 80px 1fr; gap: 4px 12px; font-size: 13.5px; }
  .kv span:nth-child(odd) { color: var(--text-2); }
  .line { padding: 6px 0; border-bottom: 1px solid var(--border); }
  .log { max-height: 280px; overflow: auto; }
</style>
