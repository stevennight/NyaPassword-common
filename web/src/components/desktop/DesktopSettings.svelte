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

  // ---- ssh-agent, Quick Access, browser bridge
  let pipe = $state('');
  let shortcut = $state('');
  let extIds = $state('');
  let busyAgent = $state(false);

  $effect(() => {
    if (s && !busyAgent) {
      pipe = s.ssh_agent.endpoint_setting;
      shortcut = s.quick_access.shortcut;
      extIds = s.browser_bridge.extension_ids.join('\n');
    }
  });

  async function apply(f: () => Promise<DesktopSettings>) {
    busyAgent = true;
    try {
      s = await f();
    } catch (e) {
      toast(msg(e), 'error', 6000);
      s = await api.settings();
    } finally {
      busyAgent = false;
    }
  }

  const sshAgent = (enabled: boolean) => apply(() => api.setSshAgent(enabled, pipe));
  const quickAccess = (enabled: boolean) => apply(() => api.setQuickAccess(enabled, shortcut));
  const ids = () => extIds.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);
  const browserBridge = (enabled: boolean) => apply(() => api.setBrowserBridge(enabled, ids()));

  async function unpair(id: string, name: string) {
    if (!(await confirm('取消配对？', `${name} 中的扩展将不能再由桌面端解锁，需要时可以重新配对。`, '取消配对', true))) return;
    await apply(() => api.removePairing(id));
  }

  const serviceText: Record<string, string> = { running: '正在运行', stopped: '已停止', not_installed: '未安装' };
  const startText: Record<string, string> = { auto: '自动启动', manual: '手动启动', disabled: '已禁用' };

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
    <h3>快捷搜索与自动输入</h3>
    <label class="row"><span class="grow">全局快捷键打开快捷搜索</span>
      <input type="checkbox" checked={s.quick_access.enabled} disabled={busyAgent} onchange={(e) => quickAccess((e.target as HTMLInputElement).checked)} /></label>
    <div class="row">
      <span>快捷键</span>
      <input class="input mono grow" bind:value={shortcut} placeholder="Ctrl+Shift+Space" spellcheck="false" />
      <button class="btn sm" disabled={busyAgent || shortcut === s.quick_access.shortcut} onclick={() => quickAccess(s!.quick_access.enabled)}>应用</button>
    </div>
    {#if s.quick_access.error}<div class="banner bad small">{s.quick_access.error}</div>{/if}
    <p class="faint small">在任意程序里按快捷键，搜索条目（支持拼音），回车把用户名、Tab、密码、回车输入到刚才的窗口（每个条目可在编辑页设置“自动输入序列”）；也可以复制用户名 / 密码 / 验证码。会优先列出标题或网址与当前窗口标题、程序名匹配的条目。快捷键写法如 Ctrl+Shift+Space、Alt+K。</p>
    {#if !s.quick_access.auto_type_supported}<div class="banner warn small">此平台暂不支持自动输入（目前只支持 Windows），快捷搜索里只能复制。</div>{/if}
  </section>

  <section class="card">
    <h3>SSH agent</h3>
    <label class="row"><span class="grow">启用 SSH agent（提供保险库中的 SSH 密钥）</span>
      <input type="checkbox" checked={s.ssh_agent.enabled} disabled={busyAgent} onchange={(e) => sshAgent((e.target as HTMLInputElement).checked)} /></label>
    {#if s.ssh_agent.running}
      <div class="banner ok small">正在监听 <span class="mono">{s.ssh_agent.auth_sock}</span></div>
    {:else if s.ssh_agent.error}
      <div class="banner bad small">{s.ssh_agent.error}</div>
    {/if}
    {#if info.platform === 'windows' && s.ssh_agent.system_agent.state}
      <p class="small">Windows OpenSSH Authentication Agent 服务：{serviceText[s.ssh_agent.system_agent.state] ?? s.ssh_agent.system_agent.state}{s.ssh_agent.system_agent.start_type ? `（${startText[s.ssh_agent.system_agent.start_type] ?? s.ssh_agent.system_agent.start_type}）` : ''}{s.ssh_agent.system_agent.state === 'running' ? '。它占用默认管道时，请停用它或改用其他管道名。' : ''}</p>
    {/if}
    <div class="row">
      <span>{info.platform === 'windows' ? '管道名' : 'Socket 路径'}</span>
      <input class="input mono grow" bind:value={pipe} placeholder={s.ssh_agent.default_endpoint} spellcheck="false" />
      <button class="btn sm" disabled={busyAgent || pipe === s.ssh_agent.endpoint_setting} onclick={() => sshAgent(s!.ssh_agent.enabled)}>应用</button>
    </div>
    <p class="faint small">
      {#if info.platform === 'windows'}
        默认使用 <span class="mono">\\.\pipe\openssh-ssh-agent</span>，Windows 自带的 ssh、Git for Windows（设置 core.sshCommand 为 Windows 的 ssh）直接可用。改用其他管道名时，设置环境变量 <span class="mono">SSH_AUTH_SOCK={s.ssh_agent.auth_sock}</span>，或在 ~/.ssh/config 里写 <span class="mono">IdentityAgent {s.ssh_agent.auth_sock.replaceAll('\\', '/')}</span>。
      {:else}
        设置 <span class="mono">export SSH_AUTH_SOCK="{s.ssh_agent.auth_sock}"</span>，或在 ~/.ssh/config 里写 IdentityAgent。（实验性）
      {/if}
      每次签名都会弹窗确认（可选“锁定前都允许”）；锁定时请求会先提示解锁。Git 提交签名（gpg.format = ssh）同样可用。WSL 的接法见桌面端 README。
    </p>
  </section>

  <section class="card">
    <h3>浏览器扩展联动</h3>
    <label class="row"><span class="grow">允许浏览器扩展由桌面端解锁（Native Messaging）</span>
      <input type="checkbox" checked={s.browser_bridge.enabled} disabled={busyAgent} onchange={(e) => browserBridge((e.target as HTMLInputElement).checked)} /></label>
    <label class="lbl small" for="ext-ids">扩展 ID（每行一个；在扩展弹窗的 ⚙ 里可以看到）</label>
    <textarea id="ext-ids" class="textarea mono small" rows="2" bind:value={extIds} spellcheck="false"></textarea>
    <div class="row">
      <span class="grow faint small">配对后：桌面端已解锁时，扩展打开即可解锁；桌面端锁定时，已连接的扩展也会锁定。</span>
      <button class="btn sm" disabled={busyAgent || extIds.trim() === s.browser_bridge.extension_ids.join('\n')} onclick={() => browserBridge(s!.browser_bridge.enabled)}>应用</button>
    </div>
    {#if s.browser_bridge.error}<div class="banner bad small">{s.browser_bridge.error}</div>
    {:else if s.browser_bridge.enabled && s.browser_bridge.running}<div class="banner ok small">已注册到 Chrome / Edge / Chromium</div>{/if}
    {#each s.browser_bridge.pairings as p (p.id)}
      <div class="row small">
        <span class="grow">{p.name} · <span class="mono">{p.extension_id.slice(0, 8)}…</span> · 配对于 {dateTime(p.created_at)}{p.last_used_at ? ` · 上次解锁 ${relativeTime(p.last_used_at)}` : ''}</span>
        <button class="btn ghost sm danger" onclick={() => unpair(p.id, p.name)}>取消配对</button>
      </div>
    {/each}
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
  .lbl { color: var(--text-2); }
  textarea { resize: vertical; }
  form .input { flex: 1; }
  .notes { max-height: 160px; overflow: auto; white-space: pre-wrap; margin: 0; padding: 8px; background: var(--surface-2); border-radius: 8px; }
</style>
