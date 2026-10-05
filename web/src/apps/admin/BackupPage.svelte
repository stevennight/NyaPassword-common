<script lang="ts">
  import { api, type BackupTarget, type TestStep } from './api';
  import { bytes, dateTime, relativeTime } from '$lib/i18n';
  import { confirm, toast } from '$lib/ui.svelte';
  import { admin, errMsg, loadBackup } from './store.svelte';
  import { nextDailyAt, STALE_AFTER, type Page } from './checks';
  import TargetWizard from './TargetWizard.svelte';
  import TestResult from './TestResult.svelte';

  let { onnavigate }: { onnavigate: (p: Page) => void } = $props();

  let busy = $state('');
  /** The wizard: a new target (null id) or an existing one. */
  let wizard = $state<{ target: BackupTarget | null } | null>(null);
  let testResult = $state<TestStep[] | null>(null);

  const b = $derived(admin.backup);
  const stale = $derived(!!b && (!b.last_success_at || Date.now() - b.last_success_at > STALE_AFTER));
  const KIND: Record<BackupTarget['kind'], string> = { oss: '阿里云 OSS', webdav: 'WebDAV', fs: '服务器上的目录' };
  const TRIGGER: Record<string, string> = { change: '变更后', daily: '每日', manual: '手动' };
  const targetName = (id: string) => b?.targets.find((t) => t.target.id === id)?.target.name ?? id;

  async function runNow() {
    busy = 'run';
    try {
      const r = await api<{ results: { ok: boolean }[] }>('POST', '/backup/run');
      const ok = r.results.length > 0 && r.results.every((x) => x.ok);
      toast(ok ? '备份完成，已读回校验' : '部分目标备份失败，见下方记录', ok ? 'ok' : 'error', 5000);
      await loadBackup();
    } catch (e) {
      toast(errMsg(e), 'error', 6000);
    } finally {
      busy = '';
    }
  }

  async function test(t: BackupTarget) {
    busy = `test-${t.id}`;
    try {
      testResult = (await api<{ steps: TestStep[] }>('POST', `/backup/targets/${t.id}/test`)).steps;
    } catch (e) {
      toast(errMsg(e), 'error');
    } finally {
      busy = '';
    }
  }

  async function toggle(t: BackupTarget) {
    try {
      await api('PUT', `/backup/targets/${t.id}`, { ...t, enabled: !t.enabled, secret: '' });
      await loadBackup();
    } catch (e) {
      toast(errMsg(e), 'error');
    }
  }

  async function remove(t: BackupTarget) {
    if (!(await confirm('删除备份目标？', `只删除配置，“${t.name}”上已有的备份不会被删除。`, '删除', true))) return;
    await api('DELETE', `/backup/targets/${t.id}`).catch((e) => toast(errMsg(e), 'error'));
    await loadBackup();
  }

  function where(t: BackupTarget): string {
    if (t.kind === 'oss') return `${t.bucket}/${t.root}`;
    if (t.kind === 'fs') return `${t.endpoint.replace(/[\\/]+$/, '')}/${t.root}`;
    return `${t.endpoint} ${t.root}`;
  }
</script>

<h2>备份</h2>
{#if b}
  <section class="card summary">
    <div class="sum">
      <span class="faint small">上次成功</span>
      <b class:bad={stale}>{b.last_success_at ? relativeTime(b.last_success_at) : '从未'}</b>
      {#if b.last_success_at}<span class="faint small">{dateTime(b.last_success_at)}</span>{/if}
    </div>
    <div class="sum">
      <span class="faint small">下次计划</span>
      <b>{b.targets.some((t) => t.target.enabled) ? dateTime(nextDailyAt(b.settings.daily_hour_utc)) : '—'}</b>
      <span class="faint small">每日定时{b.pending_changes ? `；有变更时约 ${b.settings.debounce_minutes} 分钟后` : ''}</span>
    </div>
    <div class="sum">
      <span class="faint small">未备份的变更</span>
      <b>{b.pending_changes ? '有' : '没有'}</b>
      <span class="faint small">{b.pending_changes ? '变更停止后自动备份（每小时最多一次）' : '最近一次备份已包含全部数据'}</span>
    </div>
    <div class="act">
      <button class="btn primary" disabled={!!busy || !b.targets.some((t) => t.target.enabled)} onclick={runNow}>{busy === 'run' ? '备份中…' : '立即备份'}</button>
      <button class="btn ghost sm" onclick={() => onnavigate('schedule')}>计划与保留 ›</button>
    </div>
  </section>

  {#if !b.settings.recipients.length}
    <div class="banner small"><span class="grow">还没有登记离线恢复密钥：服务器整个丢失时，备份解不开。</span><button class="btn sm" onclick={() => onnavigate('keys')}>去生成</button></div>
  {/if}

  <div class="row head"><h3 class="grow">备份目标</h3><button class="btn" onclick={() => (wizard = { target: null })}>＋ 添加目标</button></div>
  {#each b.targets as ts (ts.target.id)}
    {@const t = ts.target}
    <div class="card tgt">
      <div class="row wrap">
        <b>{t.name}</b><span class="badge">{KIND[t.kind]}</span>
        {#if !t.enabled}<span class="badge">已停用</span>{:else if ts.last_error}<span class="badge bad">上次失败</span>{:else if ts.last_success_at}<span class="badge ok">正常</span>{:else}<span class="badge warn">还没有成功过</span>{/if}
        {#if t.protect_mode}<span class="badge acc" title="凭据只能写不能删，旧备份由存储端生命周期规则清理">防删模式</span>{/if}
      </div>
      <div class="kv small">
        <span>位置</span><span class="mono">{where(t)}</span>
        <span>上次成功</span><span>{ts.last_success_at ? `${relativeTime(ts.last_success_at)}（${dateTime(ts.last_success_at)}）` : '从未'}</span>
        {#if ts.last_error}<span>错误</span><span class="err">{ts.last_error}</span>{/if}
      </div>
      <div class="row acts wrap">
        <button class="btn sm" disabled={!!busy} onclick={() => test(t)}>{busy === `test-${t.id}` ? '测试中…' : '测试连接'}</button>
        <button class="btn sm" onclick={() => (wizard = { target: { ...t, secret: '' } })}>编辑</button>
        <button class="btn sm" onclick={() => toggle(t)}>{t.enabled ? '停用' : '启用'}</button>
        <span class="spacer"></span>
        <button class="btn sm ghost danger" onclick={() => remove(t)}>删除</button>
      </div>
    </div>
  {:else}
    <div class="card empty">
      <p>还没有备份目标。建议配两个，放在不同的地方：</p>
      <ul class="small muted">
        <li><b>阿里云 OSS</b>（开防删模式：服务器被入侵也删不掉历史备份）</li>
        <li><b>WebDAV</b>（坚果云、NAS 自带的 WebDAV）或<b>服务器上的目录</b>（如挂载的 NAS）</li>
      </ul>
      <button class="btn primary" onclick={() => (wizard = { target: null })}>＋ 添加第一个目标</button>
    </div>
  {/each}

  <h3>最近备份</h3>
  <div class="card tblwrap">
    <table class="tbl">
      <thead><tr><th>时间</th><th>触发</th><th>大小</th><th>条目</th><th>结果</th></tr></thead>
      <tbody>
        {#each b.runs as r (r.id)}
          <tr>
            <td class="nowrap">{dateTime(r.started_at)}</td>
            <td>{TRIGGER[r.trigger] ?? r.trigger}</td>
            <td class="nowrap">{bytes(r.size)}</td>
            <td>{r.items}</td>
            <td>
              {#each r.results as x (x.target_id)}
                <div><span class="badge {x.ok ? 'ok' : 'bad'}">{targetName(x.target_id)}：{x.ok ? (x.verified ? '成功，已读回校验' : '成功') : '失败'}</span>{#if x.error}<div class="err small">{x.error}</div>{/if}</div>
              {:else}<span class="faint small">没有启用的目标</span>{/each}
            </td>
          </tr>
        {:else}<tr><td colspan="5" class="faint">还没有备份</td></tr>{/each}
      </tbody>
    </table>
  </div>
{/if}

{#if wizard}
  <TargetWizard target={wizard.target} onclose={() => (wizard = null)} />
{/if}
{#if testResult}
  <TestResult steps={testResult} onclose={() => (testResult = null)} />
{/if}

<style>
  h3 { margin: 18px 0 8px; font-size: 14px; }
  .head { margin: 18px 0 8px; }
  .head h3 { margin: 0; }
  .summary { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)) auto; gap: 14px; padding: 14px 16px; margin-bottom: 12px; align-items: start; }
  .sum { display: flex; flex-direction: column; gap: 1px; min-width: 0; }
  .sum b { font-size: 17px; }
  .sum b.bad { color: var(--bad); }
  .act { display: flex; flex-direction: column; gap: 6px; align-items: flex-end; }
  .banner { align-items: center; }
  .tgt { padding: 12px 14px; display: flex; flex-direction: column; gap: 8px; margin-bottom: 10px; }
  .kv { display: grid; grid-template-columns: 70px 1fr; gap: 3px 8px; color: var(--text-2); }
  .kv span:nth-child(even) { color: var(--text); word-break: break-all; }
  .wrap { flex-wrap: wrap; }
  .err { color: var(--bad); word-break: break-word; }
  .empty { padding: 14px 16px; }
  .empty p { margin: 0 0 6px; }
  .empty ul { margin: 0 0 12px; padding-left: 18px; }
  .tblwrap { overflow-x: auto; }
  .tblwrap table { min-width: 560px; }
  .nowrap { white-space: nowrap; }
  @media (max-width: 900px) {
    .summary { grid-template-columns: 1fr 1fr; }
    .act { grid-column: 1 / -1; flex-direction: row; justify-content: flex-start; align-items: center; }
  }
  @media (max-width: 480px) {
    .summary { grid-template-columns: 1fr; }
  }
</style>
