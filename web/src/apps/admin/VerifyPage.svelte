<script lang="ts">
  import { api, type DrillRun } from './api';
  import { dateTime, relativeTime } from '$lib/i18n';
  import { toast } from '$lib/ui.svelte';
  import { admin, errMsg, loadBackup } from './store.svelte';
  import { CHECK_EVERY, DAY, MANUAL_DRILL_DUE, type Page } from './checks';
  import { restoreCommand, type RestoreTarget } from './agekey';

  let { onnavigate }: { onnavigate: (p: Page) => void } = $props();

  let busy = $state(false);
  const b = $derived(admin.backup);
  const last = $derived<DrillRun | undefined>(b?.drills[0]);
  const targetName = (id: string) => b?.targets.find((t) => t.target.id === id)?.target.name ?? id;
  const manual = $derived(b?.last_manual_drill_at ?? 0);
  const manualDays = $derived(manual ? Math.floor((Date.now() - manual) / DAY) : null);
  const overdue = $derived(!manual || Date.now() - manual > MANUAL_DRILL_DUE);
  const firstTarget = $derived<RestoreTarget | null>(
    b?.targets.find((t) => t.target.enabled)?.target ?? b?.targets[0]?.target ?? null,
  );

  async function checkNow() {
    busy = true;
    try {
      const r = await api<DrillRun>('POST', '/backup/drill', {});
      toast(r.ok ? '校验通过：最新备份能解开，数据完整' : `校验失败：${r.detail}`, r.ok ? 'ok' : 'error', 6000);
      await loadBackup();
    } catch (e) {
      toast(errMsg(e), 'error', 6000);
    } finally {
      busy = false;
    }
  }

  async function markDone() {
    try {
      await api('POST', '/backup/manual-drill');
      toast('已记录本次手动恢复演练', 'ok');
      await loadBackup();
    } catch (e) {
      toast(errMsg(e), 'error');
    }
  }
</script>

<h2>备份校验</h2>
<p class="intro">备份写上去不等于能恢复。服务器<b>每周自动</b>从备份目标下载最新的备份，用服务器自己的密钥解密到临时目录，检查数据库完整性、条目数与备份清单一致、抽查附件存在，然后删除临时文件。不影响线上数据。</p>

{#if b}
  <section class="card">
    <div class="row wrap">
      <h3 class="grow">自动校验</h3>
      <button class="btn primary" disabled={busy || !b.targets.some((t) => t.target.enabled)} onclick={checkNow}>{busy ? '校验中…' : '立即校验'}</button>
    </div>
    {#if last}
      <div class="result" class:bad={!last.ok}>
        <span class="mark">{last.ok ? '✓' : '✗'}</span>
        <div class="grow">
          <b>{last.ok ? '上次校验通过' : '上次校验失败'}</b> · {relativeTime(last.at)}（{dateTime(last.at)}） · {targetName(last.target_id)}
          <div class="small muted brk">{last.detail}</div>
        </div>
      </div>
      <p class="faint small">下次自动校验：{dateTime(last.at + CHECK_EVERY)} 之后的第一次备份完成时。失败会通过“告警通知”发出提醒。</p>
    {:else}
      <p class="faint small">还没有校验过。有备份目标后，每周在一次备份完成后自动校验；也可以现在就点“立即校验”。</p>
    {/if}
    {#if b.drills.length > 1}
      <details>
        <summary class="small">校验记录（{b.drills.length}）</summary>
        {#each b.drills as d (d.id)}
          <div class="drill small"><span class:ok={d.ok} class:err={!d.ok}>{d.ok ? '✓' : '✗'}</span>
            <div><div>{dateTime(d.at)} · {targetName(d.target_id)} · {(d.duration_ms / 1000).toFixed(1)} 秒</div><div class="faint brk">{d.detail}</div></div></div>
        {/each}
      </details>
    {/if}
  </section>

  <section class="card">
    <div class="row wrap">
      <h3 class="grow">每季度用离线恢复密钥做一次完整恢复演练</h3>
      {#if overdue}<span class="badge warn">{manualDays === null ? '还没做过' : `已 ${manualDays} 天`}</span>{:else}<span class="badge ok">{manualDays} 天前做过</span>{/if}
    </div>
    <p class="small muted">自动校验用的是服务器自己的密钥。真正的灾难里服务器已经没了，能用的只有离线恢复密钥和你的记录。手动演练检查的就是这条路：私钥还在、能找到、命令会用。</p>
    {#if !b.settings.recipients.length}
      <div class="banner small"><span class="grow">需要先登记一把离线恢复密钥。</span><button class="btn sm" onclick={() => onnavigate('keys')}>去生成</button></div>
    {/if}
    <ol class="small steps">
      <li>找出离线恢复密钥（打印件，或 U 盘里的 <span class="mono">nyapassword-recovery-key.txt</span>）。</li>
      <li>在<b>另一台电脑</b>上准备 nyapassword-server（从发布页下载，或用服务器的 Docker 镜像）。</li>
      <li>只下载、解密、校验，不写入任何东西（目标的密码 / AccessKey Secret 用环境变量 <span class="mono">NYAPASSWORD_RESTORE_SECRET</span> 传）：
        <div class="cmd mono">{restoreCommand(firstTarget)} --dry-run</div></li>
      <li>看到 <span class="mono">verified: decrypts, integrity_check ok, counts match the manifest</span> 就是成功。</li>
      <li>回到这里点“标记为已完成”。</li>
    </ol>
    <div class="row wrap">
      <span class="small grow">上次手动演练：{manual ? `${dateTime(manual)}（${manualDays} 天前）` : '从未'}</span>
      <button class="btn" onclick={markDone}>标记为已完成</button>
    </div>
  </section>
{/if}

<style>
  .intro { margin: 0 0 14px; color: var(--text-2); max-width: 760px; }
  section { padding: 12px 14px; margin-bottom: 14px; display: flex; flex-direction: column; gap: 8px; }
  h3 { margin: 0; font-size: 14px; }
  p { margin: 0; }
  .wrap { flex-wrap: wrap; }
  .result { display: flex; gap: 10px; padding: 10px 12px; border-radius: 9px; background: var(--ok-bg); }
  .result.bad { background: var(--bad-bg); }
  .result .mark { font-weight: 700; color: var(--ok); }
  .result.bad .mark { color: var(--bad); }
  .brk { word-break: break-all; }
  details summary { cursor: pointer; color: var(--text-2); }
  .drill { display: flex; gap: 8px; padding: 5px 0; border-top: 1px solid var(--border); }
  .ok { color: var(--ok); }
  .err { color: var(--bad); }
  .steps { padding-left: 18px; margin: 0; display: flex; flex-direction: column; gap: 6px; }
  .cmd { background: var(--surface-2); border-radius: 6px; padding: 5px 8px; margin-top: 4px; word-break: break-all; font-size: 12px; }
  .banner { align-items: center; }
</style>
