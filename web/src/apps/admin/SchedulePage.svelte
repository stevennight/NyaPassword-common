<script lang="ts">
  import { dateTime } from '$lib/i18n';
  import { admin, saveSettings } from './store.svelte';
  import { localTimeOfUtcHour, nextDailyAt, zoneLabel } from './checks';

  const b = $derived(admin.backup);
  let debounce = $state(10);
  let hourUtc = $state(19);
  let ret = $state({ recent: 48, daily: 30, weekly: 12, monthly: 24 });
  let loaded = false;

  $effect(() => {
    if (b && !loaded) {
      loaded = true;
      debounce = b.settings.debounce_minutes;
      hourUtc = b.settings.daily_hour_utc;
      ret = { ...b.settings.retention };
    }
  });

  // the 24 possible UTC hours, shown and sorted by the browser's local time
  const hours = Array.from({ length: 24 }, (_, h) => ({ h, local: localTimeOfUtcHour(h) })).sort((a, c) => a.local.localeCompare(c.local));
  const zone = zoneLabel();

  const dirty = $derived(
    !!b &&
      (debounce !== b.settings.debounce_minutes ||
        hourUtc !== b.settings.daily_hour_utc ||
        (['recent', 'daily', 'weekly', 'monthly'] as const).some((k) => ret[k] !== b.settings.retention[k])),
  );
  const valid = $derived(debounce >= 1 && debounce <= 1440 && ret.recent >= 1 && ret.daily >= 0 && ret.weekly >= 0 && ret.monthly >= 0);
  const protectTargets = $derived((b?.targets ?? []).filter((t) => t.target.protect_mode));

  async function save() {
    await saveSettings((s) => {
      s.debounce_minutes = Math.round(debounce);
      s.daily_hour_utc = hourUtc;
      s.retention = { recent: Math.round(ret.recent), daily: Math.round(ret.daily), weekly: Math.round(ret.weekly), monthly: Math.round(ret.monthly) };
    });
  }

  const RET: { key: 'recent' | 'daily' | 'weekly' | 'monthly'; label: string; text: string; min: number }[] = [
    { key: 'recent', label: '最近', text: '保留最新的这么多份，不管时间', min: 1 },
    { key: 'daily', label: '每日', text: '最近这么多天，每天留最后一份', min: 0 },
    { key: 'weekly', label: '每周', text: '最近这么多周，每周留最后一份', min: 0 },
    { key: 'monthly', label: '每月', text: '最近这么多个月，每月留最后一份', min: 0 },
  ];
</script>

<h2>计划与保留</h2>
{#if b}
  <section class="card">
    <h3>什么时候备份</h3>
    <label class="line">
      <span class="grow"><b>变更后等待</b><br /><span class="small muted">有人改了数据后，停下来这么久再备份，避免改一条备份一次。每小时最多一次。</span></span>
      <span class="num"><input class="input" type="number" min="1" max="1440" bind:value={debounce} /> 分钟</span>
    </label>
    <label class="line">
      <span class="grow"><b>每日备份时间</b><br /><span class="small muted">即使没有变更，每天也备份一次，证明一切正常。时区：{zone}。</span></span>
      <select class="select" bind:value={hourUtc}>
        {#each hours as o (o.h)}<option value={o.h}>{o.local}</option>{/each}
      </select>
    </label>
    <p class="faint small">下一次每日备份：{dateTime(nextDailyAt(hourUtc))}（服务器按 UTC {String(hourUtc).padStart(2, '0')}:00 执行）</p>
  </section>

  <section class="card">
    <h3>保留多少份</h3>
    <p class="small muted">每次备份都是完整的一份。下面四条规则合起来决定保留哪些，其余的由服务器在每次备份后删除；同一份可以同时满足几条规则。</p>
    <div class="ret">
      {#each RET as r (r.key)}
        <label class="retc"><b>{r.label}</b><input class="input" type="number" min={r.min} bind:value={ret[r.key]} /><span class="small muted">{r.text}</span></label>
      {/each}
    </div>
    <p class="faint small">按默认值（48 / 30 / 12 / 24）最多保留约 110 份（规则重叠时更少），最早能回到两年前。</p>
    {#if protectTargets.length}
      <div class="banner small">
        <span><b>防删模式的目标不按这里清理：</b>{protectTargets.map((t) => t.target.name).join('、')}。它们的凭据删不掉文件，旧备份要靠存储端的生命周期规则（如 OSS 生命周期规则 + 版本控制 / 合规保留）清理，建议按上面的天数设置。</span>
      </div>
    {/if}
  </section>

  <div class="row"><span class="spacer"></span>
    {#if !valid}<span class="err small">请检查数值</span>{/if}
    <button class="btn primary" disabled={!dirty || !valid} onclick={save}>保存</button></div>
{/if}

<style>
  section { padding: 12px 14px; margin-bottom: 14px; display: flex; flex-direction: column; gap: 10px; }
  h3 { margin: 0; font-size: 14px; }
  p { margin: 0; }
  .line { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
  .num { display: flex; align-items: center; gap: 6px; white-space: nowrap; }
  .num .input { width: 90px; }
  .line .select { width: auto; min-width: 110px; }
  .ret { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
  .retc { display: flex; flex-direction: column; gap: 4px; background: var(--surface-2); border-radius: 9px; padding: 10px; }
  .err { color: var(--bad); }
  @media (max-width: 700px) {
    .ret { grid-template-columns: 1fr 1fr; }
  }
</style>
