<script lang="ts">
  import { onMount } from 'svelte';
  import { vault } from '$lib/vault.svelte';
  import { errorCode, errorMessage } from '$lib/bridge';
  import { dateTime, errorText, relativeTime } from '$lib/i18n';
  import { confirm, toast } from '$lib/ui.svelte';
  import type { AuditEntry, DeviceRecord, EmergencyKit as Kit } from '$lib/types';
  import EmergencyKit from './EmergencyKit.svelte';
  import Modal from './Modal.svelte';

  let devices = $state<DeviceRecord[]>([]);
  let audit = $state<AuditEntry[]>([]);
  let kit = $state<Kit | null>(null);
  let quick = $state({ available: false, enabled: false, label: '' });
  let cur = $state('');
  let next = $state('');
  let next2 = $state('');
  let pwMsg = $state('');
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
      toast('主密码已修改；其他设备需要用新密码重新登录', 'ok', 5000);
    } catch (err) {
      pwMsg = errorText(errorCode(err), errorMessage(err));
    }
  }

  async function revoke(d: DeviceRecord) {
    if (!(await confirm('移除设备？', `“${d.name}”会立即退出，需要主密码和 Secret Key 才能重新登录。`, '移除', true))) return;
    await vault.bridge.revokeDevice(d.id).catch(vault.fail.bind(vault));
    devices = await vault.bridge.devices();
  }

  async function toggleQuick() {
    try {
      await vault.bridge.setQuickUnlock(!quick.enabled);
      quick = await vault.bridge.quickUnlockStatus();
    } catch (e) {
      vault.fail(e);
    }
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
    await vault.bridge.signOut(true);
    await vault.refreshLock();
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
      <div class="row"><span class="grow">使用 {quick.label} 解锁（重启后或每 14 天仍需主密码）</span><button class="btn" onclick={toggleQuick}>{quick.enabled ? '关闭' : '开启'}</button></div>
    {/if}
    <div class="row"><span class="grow">外观</span>
      <select class="select" style="width:auto" value={theme} onchange={(e) => setTheme((e.target as HTMLSelectElement).value)}><option value="auto">跟随系统</option><option value="light">浅色</option><option value="dark">深色</option></select></div>
  </section>

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
    <button class="btn danger" onclick={signOut}>退出此设备上的账户</button>
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
  form .btn { align-self: flex-start; }
  .kv { display: grid; grid-template-columns: 80px 1fr; gap: 4px 12px; font-size: 13.5px; }
  .kv span:nth-child(odd) { color: var(--text-2); }
  .line { padding: 6px 0; border-bottom: 1px solid var(--border); }
  .log { max-height: 280px; overflow: auto; }
</style>
