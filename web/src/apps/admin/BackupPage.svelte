<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type BackupStatus, type BackupTarget } from './api';
  import { bytes, dateTime, relativeTime } from '$lib/i18n';
  import { confirm, toast } from '$lib/ui.svelte';
  import Modal from '$components/Modal.svelte';

  let status = $state<BackupStatus | null>(null);
  let busy = $state('');
  let editing = $state<BackupTarget | null>(null);
  let testResult = $state<{ step: string; ok: boolean; expected_to_fail?: boolean; error?: string }[] | null>(null);
  let settingsOpen = $state(false);
  let recipientsText = $state('');

  onMount(load);
  async function load() {
    try {
      status = await api<BackupStatus>('GET', '/backup');
      recipientsText = status.settings.recipients.join('\n');
    } catch (e) {
      toast(String((e as Error).message), 'error');
    }
  }

  async function run(what: 'run' | 'drill') {
    busy = what;
    try {
      if (what === 'run') {
        const r = await api<{ results: { ok: boolean }[] }>('POST', '/backup/run');
        toast(r.results.every((x) => x.ok) ? '备份完成，已读回校验' : '部分目标备份失败', r.results.every((x) => x.ok) ? 'ok' : 'error');
      } else {
        const r = await api<{ ok: boolean; detail: string }>('POST', '/backup/drill', {});
        toast(r.ok ? '恢复演练通过' : `恢复演练失败：${r.detail}`, r.ok ? 'ok' : 'error', 6000);
      }
      await load();
    } catch (e) {
      toast(String((e as Error).message), 'error', 6000);
    } finally {
      busy = '';
    }
  }

  function newTarget(kind: BackupTarget['kind']) {
    editing = {
      id: crypto.randomUUID(),
      kind,
      name: kind === 'oss' ? '阿里云 OSS' : kind === 'webdav' ? 'WebDAV' : '本地目录',
      enabled: true,
      protect_mode: kind === 'oss',
      endpoint: kind === 'oss' ? 'https://oss-cn-hangzhou.aliyuncs.com' : kind === 'webdav' ? 'https://dav.example.com/dav/' : '/backup',
      bucket: '',
      root: 'nyapassword',
      username: '',
      secret: '',
      has_secret: false,
    };
  }

  async function saveTarget() {
    if (!editing) return;
    try {
      await api('PUT', `/backup/targets/${editing.id}`, editing);
      editing = null;
      toast('已保存');
      await load();
    } catch (e) {
      toast(String((e as Error).message), 'error');
    }
  }

  async function removeTarget(t: BackupTarget) {
    if (!(await confirm('删除备份目标？', `只删除配置，“${t.name}”上已有的备份不会被删除。`, '删除', true))) return;
    await api('DELETE', `/backup/targets/${t.id}`);
    await load();
  }

  async function test(t: BackupTarget) {
    busy = `test-${t.id}`;
    try {
      testResult = (await api<{ steps: typeof testResult }>('POST', `/backup/targets/${t.id}/test`)).steps;
    } catch (e) {
      toast(String((e as Error).message), 'error');
    } finally {
      busy = '';
    }
  }

  async function saveSettings() {
    if (!status) return;
    const s = { ...status.settings, recipients: recipientsText.split(/\s+/).map((r) => r.trim()).filter(Boolean) };
    try {
      await api('PUT', '/backup/settings', s);
      settingsOpen = false;
      toast('已保存');
      await load();
    } catch (e) {
      toast(String((e as Error).message), 'error');
    }
  }

  async function testNotify() {
    const r = await api<{ failed: string[] }>('POST', '/notify/test');
    toast(r.failed.length ? `失败：${r.failed.join('；')}` : '已发送测试通知', r.failed.length ? 'error' : 'ok', 6000);
  }

  async function manualDone() {
    await api('POST', '/backup/manual-drill');
    toast('已记录');
    await load();
  }

  const stale = $derived(status && (!status.last_success_at || Date.now() - status.last_success_at > 26 * 3600_000));
  const manualDays = $derived(status?.last_manual_drill_at ? Math.floor((Date.now() - status.last_manual_drill_at) / 86_400_000) : null);
  const targetName = (id: string) => status?.targets.find((t) => t.target.id === id)?.target.name ?? id;
</script>

{#if status}
  <div class="row head">
    <h2>备份与恢复</h2>
    {#if status.targets.length === 0}<span class="badge bad">未配置备份目标</span>
    {:else if stale}<span class="badge bad">超过 26 小时没有成功备份</span>
    {:else}<span class="badge ok">正常 · 上次成功 {relativeTime(status.last_success_at ?? 0)}</span>{/if}
    {#if status.pending_changes}<span class="badge">有未备份的变更</span>{/if}
    <span class="spacer"></span>
    <button class="btn" onclick={() => (settingsOpen = true)}>设置</button>
    <button class="btn" disabled={!!busy || !status.targets.length} onclick={() => run('drill')}>{busy === 'drill' ? '演练中…' : '恢复演练'}</button>
    <button class="btn primary" disabled={!!busy || !status.targets.length} onclick={() => run('run')}>{busy === 'run' ? '备份中…' : '立即备份'}</button>
  </div>

  {#if !status.settings.recipients.length}
    <div class="banner small">还没有设置<b>离线密钥</b>：服务器整个丢失时，只靠服务器自己的密钥解不开备份。请在自己电脑上运行 <span class="mono">nyapassword-server age-keygen</span>，把公钥填进“设置 → 备份接收者”，私钥打印进紧急恢复包。</div>
  {/if}

  <div class="targets">
    {#each status.targets as ts (ts.target.id)}
      {@const t = ts.target}
      <div class="card tgt">
        <div class="row"><b>{t.name}</b><span class="spacer"></span>
          {#if !t.enabled}<span class="badge">已停用</span>{:else if ts.last_error}<span class="badge bad">失败</span>{:else if t.protect_mode}<span class="badge ok">防删模式</span>{:else}<span class="badge ok">正常</span>{/if}</div>
        <div class="kv small">
          <span>类型</span><span>{t.kind === 'oss' ? '阿里云 OSS' : t.kind === 'webdav' ? 'WebDAV' : '本地目录'}</span>
          <span>位置</span><span class="mono">{t.kind === 'oss' ? `${t.bucket}/${t.root}` : `${t.endpoint} ${t.root}`}</span>
          <span>上次成功</span><span>{ts.last_success_at ? relativeTime(ts.last_success_at) : '从未'}</span>
          {#if ts.last_error}<span>错误</span><span class="err">{ts.last_error}</span>{/if}
        </div>
        <div class="row acts">
          <button class="btn sm" disabled={!!busy} onclick={() => test(t)}>{busy === `test-${t.id}` ? '测试中…' : '测试'}</button>
          <button class="btn sm" onclick={() => (editing = { ...t, secret: '' })}>编辑</button>
          <button class="btn sm danger" onclick={() => removeTarget(t)}>删除</button>
        </div>
      </div>
    {/each}
    <div class="card tgt add">
      <b>添加备份目标</b>
      <button class="btn" onclick={() => newTarget('oss')}>阿里云 OSS</button>
      <button class="btn" onclick={() => newTarget('webdav')}>WebDAV（坚果云、NAS）</button>
      <button class="btn ghost sm" onclick={() => newTarget('fs')}>服务器上的目录（NAS 挂载）</button>
    </div>
  </div>

  <div class="two">
    <div class="card">
      <h3>最近备份</h3>
      <table class="tbl">
        <thead><tr><th>时间</th><th>触发</th><th>大小</th><th>条目</th><th>结果</th></tr></thead>
        <tbody>
          {#each status.runs as r (r.id)}
            <tr>
              <td>{dateTime(r.started_at)}</td>
              <td>{({ change: '变更', daily: '每日', manual: '手动' } as Record<string, string>)[r.trigger] ?? r.trigger}</td>
              <td>{bytes(r.size)}</td>
              <td>{r.items}</td>
              <td>
                {#each r.results as x (x.target_id)}
                  <div><span class="badge {x.ok ? 'ok' : 'bad'}">{targetName(x.target_id)}：{x.ok ? (x.verified ? '已校验' : '成功') : '失败'}</span>{#if x.error}<div class="err small">{x.error}</div>{/if}</div>
                {/each}
              </td>
            </tr>
          {:else}<tr><td colspan="5" class="faint">还没有备份</td></tr>{/each}
        </tbody>
      </table>
    </div>
    <div class="card pad">
      <h3>恢复演练</h3>
      {#each status.drills.slice(0, 5) as d (d.id)}
        <div class="drill"><span class:ok={d.ok} class:err={!d.ok}>{d.ok ? '✓' : '✗'}</span><div><div class="small">{dateTime(d.at)} · {targetName(d.target_id)} · {d.duration_ms} ms</div><div class="faint small">{d.detail}</div></div></div>
      {:else}<div class="faint small">还没有演练（每周自动一次）</div>{/each}
      <div class="manual">
        <div class="small">上次<b>手动</b>演练（用离线私钥 <span class="mono">restore --dry-run</span>）：{manualDays === null ? '从未' : `${manualDays} 天前`}{manualDays === null || manualDays > 90 ? ' — 建议每季度一次' : ''}</div>
        <button class="btn sm" onclick={manualDone}>我刚做完一次手动演练</button>
      </div>
      <h3>保留策略</h3>
      <div class="ret">
        <div><b>{status.settings.retention.recent}</b>最近</div><div><b>{status.settings.retention.daily}</b>每日</div>
        <div><b>{status.settings.retention.weekly}</b>每周</div><div><b>{status.settings.retention.monthly}</b>每月</div>
      </div>
      <h3>加密</h3>
      <div class="faint small">age 接收者：服务端密钥（自动演练用）{status.settings.recipients.map((r) => ` + ${r.slice(0, 10)}…${r.slice(-4)}`).join('')}</div>
    </div>
  </div>
{/if}

{#if editing}
  <Modal title="备份目标" onclose={() => (editing = null)}>
    <label class="lbl" for="tn">名称</label><input id="tn" class="input" bind:value={editing.name} />
    <label class="lbl" for="te">{editing.kind === 'oss' ? 'Endpoint（如 https://oss-cn-hangzhou.aliyuncs.com）' : editing.kind === 'webdav' ? 'WebDAV 地址' : '目录（绝对路径）'}</label>
    <input id="te" class="input" bind:value={editing.endpoint} />
    {#if editing.kind === 'oss'}<label class="lbl" for="tb">Bucket</label><input id="tb" class="input" bind:value={editing.bucket} />{/if}
    <label class="lbl" for="tr">子目录</label><input id="tr" class="input" bind:value={editing.root} />
    {#if editing.kind !== 'fs'}
      <label class="lbl" for="tu">{editing.kind === 'oss' ? 'AccessKey ID' : '用户名'}</label><input id="tu" class="input" bind:value={editing.username} autocomplete="off" />
      <label class="lbl" for="ts">{editing.kind === 'oss' ? 'AccessKey Secret' : '密码 / 应用密码'}</label>
      <input id="ts" class="input" type="password" bind:value={editing.secret} placeholder={editing.has_secret ? '已设置，留空则不修改' : ''} autocomplete="new-password" />
    {/if}
    <label class="chk"><input type="checkbox" bind:checked={editing.enabled} /> 启用</label>
    <label class="chk"><input type="checkbox" bind:checked={editing.protect_mode} /> 防删模式（凭据只能写不能删，旧备份由存储端生命周期规则清理；服务端不做清理）</label>
    {#if editing.kind === 'oss'}<p class="faint small">建议给这个 AccessKey 只授 oss:PutObject、oss:GetObject、oss:ListObjects，桶开版本控制或合规保留。</p>{/if}
    <div class="row" style="justify-content:flex-end;margin-top:12px"><button class="btn" onclick={() => (editing = null)}>取消</button><button class="btn primary" onclick={saveTarget}>保存</button></div>
  </Modal>
{/if}

{#if testResult}
  <Modal title="测试结果" onclose={() => (testResult = null)} width={480}>
    {#each testResult as s (s.step)}
      <div class="row line"><span class="grow">{({ write: '写入探测文件', read: '读回并比对', delete: '删除探测文件' } as Record<string, string>)[s.step] ?? s.step}</span>
        {#if s.ok}<span class="badge ok">成功</span>{:else if s.expected_to_fail}<span class="badge ok">失败（防删模式下符合预期）</span>{:else}<span class="badge bad">失败</span>{/if}</div>
      {#if s.error && !s.expected_to_fail}<div class="err small">{s.error}</div>{/if}
    {/each}
    {#if testResult.find((s) => s.step === 'delete' && s.ok && s.expected_to_fail)}<div class="banner small" style="margin-top:8px">防删模式下删除竟然成功了：这个凭据能删除备份，服务器被入侵时历史备份也可能被删。建议收紧权限。</div>{/if}
  </Modal>
{/if}

{#if settingsOpen && status}
  <Modal title="备份设置" onclose={() => (settingsOpen = false)} width={620}>
    <label class="lbl" for="rc">备份接收者（离线 age 公钥 age1…，每行一个）</label>
    <textarea id="rc" class="textarea mono" bind:value={recipientsText} rows="3"></textarea>
    <div class="grid4">
      <label class="lbl">最近<input class="input" type="number" min="1" bind:value={status.settings.retention.recent} /></label>
      <label class="lbl">每日<input class="input" type="number" min="0" bind:value={status.settings.retention.daily} /></label>
      <label class="lbl">每周<input class="input" type="number" min="0" bind:value={status.settings.retention.weekly} /></label>
      <label class="lbl">每月<input class="input" type="number" min="0" bind:value={status.settings.retention.monthly} /></label>
    </div>
    <div class="grid4">
      <label class="lbl">变更后等待（分钟）<input class="input" type="number" min="1" bind:value={status.settings.debounce_minutes} /></label>
      <label class="lbl">每日备份（UTC 小时）<input class="input" type="number" min="0" max="23" bind:value={status.settings.daily_hour_utc} /></label>
    </div>
    <h3>告警通知</h3>
    <label class="lbl">Webhook URL（POST JSON）<input class="input" bind:value={status.settings.notify.webhook_url} /></label>
    <div class="grid4">
      <label class="lbl">Telegram Bot Token<input class="input" type="password" bind:value={status.settings.notify.telegram_bot_token} /></label>
      <label class="lbl">Telegram Chat ID<input class="input" bind:value={status.settings.notify.telegram_chat_id} /></label>
    </div>
    <label class="lbl">Bark 地址（https://api.day.app/你的key）<input class="input" bind:value={status.settings.notify.bark_url} /></label>
    <div class="grid4">
      <label class="lbl">SMTP 服务器<input class="input" bind:value={status.settings.notify.smtp_host} /></label>
      <label class="lbl">端口<input class="input" type="number" bind:value={status.settings.notify.smtp_port} /></label>
      <label class="lbl">用户名<input class="input" bind:value={status.settings.notify.smtp_username} /></label>
      <label class="lbl">密码<input class="input" type="password" bind:value={status.settings.notify.smtp_password} /></label>
      <label class="lbl">发件人<input class="input" bind:value={status.settings.notify.smtp_from} /></label>
      <label class="lbl">收件人<input class="input" bind:value={status.settings.notify.smtp_to} /></label>
    </div>
    <div class="row" style="margin-top:12px"><button class="btn" onclick={testNotify}>发送测试通知（先保存）</button><span class="spacer"></span><button class="btn primary" onclick={saveSettings}>保存</button></div>
  </Modal>
{/if}

<style>
  .head { margin-bottom: 12px; flex-wrap: wrap; }
  h2 { margin: 0; font-size: 18px; }
  h3 { margin: 12px 0 8px; font-size: 14px; }
  .targets { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; margin: 12px 0 18px; }
  .tgt { padding: 14px; display: flex; flex-direction: column; gap: 8px; }
  .tgt.add { border-style: dashed; align-items: flex-start; }
  .kv { display: grid; grid-template-columns: 70px 1fr; gap: 3px 8px; color: var(--text-2); }
  .kv span:nth-child(even) { color: var(--text); word-break: break-all; }
  .acts { margin-top: auto; }
  .err { color: var(--bad); }
  .ok { color: var(--ok); }
  .two { display: grid; grid-template-columns: 1.4fr 1fr; gap: 14px; }
  .two > .card:first-child { overflow: auto; }
  .two h3 { padding: 0 12px; }
  .pad { padding: 2px 14px 14px; }
  .drill { display: flex; gap: 8px; padding: 4px 0; }
  .manual { margin: 10px 0; padding: 8px 10px; background: var(--surface-2); border-radius: 8px; display: flex; flex-direction: column; gap: 6px; align-items: flex-start; }
  .ret { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; }
  .ret div { background: var(--surface-2); border-radius: 9px; padding: 8px; text-align: center; font-size: 12px; color: var(--text-2); }
  .ret b { display: block; font-size: 17px; color: var(--text); }
  .grid4 { display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 0 10px; }
  .chk { display: flex; gap: 8px; align-items: flex-start; margin-top: 10px; font-size: 13px; }
  .line { padding: 6px 0; border-bottom: 1px solid var(--border); }
  @media (max-width: 900px) { .two { grid-template-columns: 1fr; } }
</style>
