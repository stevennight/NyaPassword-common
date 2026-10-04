<script lang="ts">
  import { onMount } from 'svelte';
  import { vault } from '$lib/vault.svelte';
  import type { Finding, HealthReport, SecurityReport } from '$lib/types';
  import { dateTime } from '$lib/i18n';

  let report = $state<SecurityReport | null>(null);
  let health = $state<HealthReport | null>(null);
  let tab = $state<Finding['issue']>('weak');

  onMount(async () => {
    try {
      report = await vault.bridge.securityReport();
      health = await vault.bridge.healthCheck();
      const first = (['weak', 'reused', 'totp_available', 'old', 'insecure'] as const).find((k) => report!.findings.some((f) => f.issue === k));
      if (first) tab = first;
    } catch (e) {
      vault.fail(e);
    }
  });

  const TABS: [Finding['issue'], string, string][] = [
    ['weak', '弱密码', '容易被猜到，建议用生成器换成随机密码'],
    ['reused', '重复使用', '同一个密码用在多个网站，一处泄露处处受影响'],
    ['totp_available', '可开启两步验证', '这些网站支持一次性密码（TOTP），开启后在这里保存即可自动填写'],
    ['old', '长期未改', '超过一年没有更换的密码'],
    ['insecure', '不安全的网址', '在 http（未加密）页面上使用的密码'],
  ];
  const list = $derived(report?.findings.filter((f) => f.issue === tab) ?? []);
  const count = (k: Finding['issue']) => report?.findings.filter((f) => f.issue === k).length ?? 0;

  function open(f: Finding) {
    vault.page = 'items';
    vault.nav = { kind: 'all' };
    vault.query = '';
    void vault.reload().then(() => (vault.selected = { vault_id: f.vault_id, item_id: f.item_id }));
  }
</script>

<div class="page">
  <h2>安全检查</h2>
  <p class="muted">全部在本机计算，不会把任何密码发出去。</p>
  {#if report}
    <div class="tiles">
      {#each TABS as [k, l] (k)}
        <button class="tile" class:on={tab === k} onclick={() => (tab = k)}><b class:bad={count(k) > 0 && k !== 'old'}>{count(k)}</b><span>{l}</span></button>
      {/each}
    </div>
    <p class="muted small">{TABS.find((t) => t[0] === tab)?.[2]}</p>
    <div class="card">
      {#each list as f (f.item_id + f.issue)}
        <button class="row line" onclick={() => open(f)}>
          <span class="grow">{f.title}</span>
          <span class="faint small">{tab === 'reused' ? `${f.detail} 个条目共用` : tab === 'old' ? `${f.detail} 天` : tab === 'weak' ? `强度 ${f.detail}/4` : f.detail}</span>
        </button>
      {:else}
        <div class="line faint">没有问题 🎉</div>
      {/each}
    </div>
  {/if}

  {#if health}
    <h3>密码库健康检查</h3>
    <div class="card pad">
      <div>检查了 {health.checked} 个条目：{health.ok} 个正常{health.pending ? `，${health.pending} 个尚未同步` : ''}{health.conflicts ? `，${health.conflicts} 个有冲突待处理` : ''}{health.read_only ? `，${health.read_only} 个需要新版本才能编辑` : ''}。</div>
      {#each health.problems as [, item, p] (item + p)}<div class="banner bad small" style="margin-top:8px">{item.slice(0, 8)}…：{p}</div>{/each}
      <div class="faint small">检查时间 {dateTime(health.checked_at)}</div>
    </div>
  {/if}
</div>

<style>
  .page { padding: 22px 28px 40px; max-width: 860px; }
  h2 { margin: 0 0 4px; }
  h3 { margin: 24px 0 8px; font-size: 15px; }
  .tiles { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 12px 0; }
  .tile { border: 1px solid var(--border); border-radius: 12px; background: var(--surface); padding: 10px; display: flex; flex-direction: column; align-items: flex-start; gap: 2px; text-align: left; }
  .tile.on { border-color: var(--accent); background: var(--accent-2); }
  .tile b { font-size: 22px; }
  .tile b.bad { color: var(--warn); }
  .tile span { font-size: 12.5px; color: var(--text-2); }
  .line { width: 100%; padding: 10px 14px; border: 0; border-bottom: 1px solid var(--border); background: none; text-align: left; }
  .line:hover { background: var(--surface-2); }
  .pad { padding: 12px 14px; }
  @media (max-width: 760px) { .tiles { grid-template-columns: repeat(2, 1fr); } }
</style>
