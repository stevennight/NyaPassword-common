<script lang="ts">
  // Desktop-only part of the settings page (rendered by SettingsPage when bridge.kind === 'desktop').
  import { onMount } from 'svelte';
  import { vault } from '$lib/vault.svelte';
  import { errorCode, errorMessage } from '$lib/bridge';
  import { dateTime, errorText, relativeTime } from '$lib/i18n';
  import { confirm, toast } from '$lib/ui.svelte';
  import { desktopApi, type DesktopInfo, type DesktopSettings, type UpdateCheck } from '$lib/desktop';

  const api = desktopApi(vault.bridge)!;
  let info = $state<DesktopInfo | null>(null);
  let s = $state<DesktopSettings | null>(null);
  let password = $state('');
  let exporting = $state(false);
  let update = $state<UpdateCheck | null>(null);
  let checking = $state(false);
  let installing = $state(false);

  const msg = (e: unknown) => errorText(errorCode(e), errorMessage(e));

  onMount(async () => {
    [info, s] = await Promise.all([api.info(), api.settings()]).catch((e) => {
      vault.fail(e);
      return [null, null];
    });
  });

  async function save() {
    if (!s) return;
    const { last_export_at: _a, last_error: _b, ...exp } = $state.snapshot(s.export);
    try {
      s = await api.setSettings(exp, s.check_updates);
    } catch (e) {
      toast(msg(e), 'error', 5000);
      s = await api.settings();
    }
  }

  async function autostart(on: boolean) {
    try {
      await api.setAutostart(on);
    } catch (e) {
      vault.fail(e);
    }
    s = await api.settings();
  }

  async function pick() {
    const folder = await api.pickFolder().catch(() => null);
    if (folder && s) {
      s.export.folder = folder;
      await save();
    }
  }

  async function exportNow(e: Event) {
    e.preventDefault();
    if (!password) return;
    exporting = true;
    try {
      const r = await api.exportNow(password);
      toast(`已导出 ${r.files.length} 个文件${r.pruned.length ? `，清理旧导出 ${r.pruned.length} 个` : ''}`, 'ok', 5000);
    } catch (err) {
      toast(msg(err), 'error', 6000);
    } finally {
      password = '';
      exporting = false;
      s = await api.settings();
    }
  }

  async function check() {
    checking = true;
    try {
      update = await api.checkUpdate();
      if (!update.latest) toast('已是最新版本', 'ok');
    } catch (e) {
      toast(msg(e), 'error', 6000);
    } finally {
      checking = false;
    }
  }

  async function install() {
    if (!update?.latest) return;
    if (!(await confirm(`安装 ${update.latest}？`, '会下载安装包、校验签名和 SHA-256，然后关闭 NyaPassword 并静默安装，完成后自动重新打开。', '安装'))) return;
    installing = true;
    try {
      await api.installUpdate(update.latest);
    } catch (e) {
      toast(msg(e), 'error', 8000);
      installing = false;
    }
  }
</script>

{#if s && info}
  <section class="card">
    <h3>桌面端</h3>
    <label class="row"><span class="grow">开机时启动（最小化到托盘）</span>
      <input type="checkbox" checked={s.autostart} onchange={(e) => autostart((e.target as HTMLInputElement).checked)} /></label>
    <p class="faint small">关闭窗口时 NyaPassword 留在托盘；系统锁屏、注销、休眠时自动锁定。剪贴板中的密码 90 秒后清除，并且不进入剪贴板历史和云剪贴板。</p>
    {#if info.key_storage === 'file'}
      <div class="banner warn small">系统凭据存储不可用，设备密钥保存在本地文件中（{info.data_dir}）。它只受系统账户的文件权限保护。</div>
    {:else}
      <p class="faint small">设备密钥保存在{info.key_store_name}。</p>
    {/if}
  </section>

  <section class="card">
    <h3>定期离线导出</h3>
    <p class="faint small">把整个账户定期导出到本机文件夹，作为与服务器无关的逃生通道。导出需要主密码，而本应用从不保存主密码：到期后，下一次用主密码解锁时自动导出；也可以在这里立即导出。</p>
    <label class="row"><span class="grow">启用</span>
      <input type="checkbox" bind:checked={s.export.enabled} onchange={save} disabled={!s.export.folder} /></label>
    <div class="row">
      <span>文件夹</span><span class="mono small grow path" title={s.export.folder}>{s.export.folder || '未选择'}</span>
      <button class="btn sm" onclick={pick}>选择…</button>
    </div>
    <div class="row wrap">
      <span>每</span>
      <select class="select" style="width:auto" bind:value={s.export.interval_days} onchange={save}>
        {#each [1, 3, 7, 14, 30] as d (d)}<option value={d}>{d} 天</option>{/each}
      </select>
      <label class="row"><input type="checkbox" bind:checked={s.export.native} onchange={save} />原生加密（.npwexport）</label>
      <label class="row"><input type="checkbox" bind:checked={s.export.kdbx} onchange={save} />KDBX（KeePassXC）</label>
      <span>保留最近</span>
      <input class="input num" type="number" min="1" max="100" bind:value={s.export.keep} onchange={save} /><span>份</span>
    </div>
    <p class="faint small">原生格式需要主密码 + Secret Key 才能打开；KDBX 只用主密码保护，可直接用 KeePassXC 打开。文件名为 NyaPassword-日期.npwexport / .kdbx，只清理这种文件名的旧导出。</p>
    <div class="small">上次导出：{s.export.last_export_at ? `${dateTime(s.export.last_export_at)}（${relativeTime(s.export.last_export_at)}）` : '从未'}</div>
    {#if s.export.last_error}<div class="banner bad small">上次导出失败：{s.export.last_error}</div>{/if}
    <form class="row" onsubmit={exportNow}>
      <input class="input" type="password" bind:value={password} placeholder="主密码" autocomplete="current-password" disabled={exporting || !s.export.folder} />
      <button class="btn" disabled={exporting || !password || !s.export.folder}>{exporting ? '导出中…' : '立即导出'}</button>
    </form>
  </section>

  <section class="card">
    <h3>更新</h3>
    <div class="row"><span class="grow">当前版本 {info.version}</span>
      <button class="btn" onclick={check} disabled={checking}>{checking ? '检查中…' : '检查更新'}</button></div>
    <label class="row"><span class="grow">每天自动检查新版本</span>
      <input type="checkbox" bind:checked={s.check_updates} onchange={save} /></label>
    {#if update?.latest}
      <div class="banner ok small">新版本 {update.latest} 已发布。{update.reason}</div>
      {#if update.notes}<pre class="notes small">{update.notes}</pre>{/if}
      <div class="row">
        {#if update.can_install}<button class="btn primary" onclick={install} disabled={installing}>{installing ? '正在下载并校验…' : '下载并安装'}</button>{/if}
        <button class="btn" onclick={() => api.openReleasePage(update!.url).catch(vault.fail.bind(vault))}>打开发布页</button>
      </div>
    {/if}
    {#if !info.update_signed}<p class="faint small">此版本没有内置更新签名公钥，不会自动安装更新。</p>{/if}
  </section>
{/if}

<style>
  section { padding: 14px 16px; margin-bottom: 14px; display: flex; flex-direction: column; gap: 10px; }
  h3 { margin: 0; font-size: 14px; }
  p { margin: 0; }
  .wrap { flex-wrap: wrap; }
  .path { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text-2); }
  .num { width: 64px; }
  form .input { flex: 1; }
  .notes { max-height: 160px; overflow: auto; white-space: pre-wrap; margin: 0; padding: 8px; background: var(--surface-2); border-radius: 8px; }
</style>
