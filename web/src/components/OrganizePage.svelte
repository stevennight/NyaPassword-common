<script lang="ts">
  import { vault } from '$lib/vault.svelte';
  import { confirm, toast } from '$lib/ui.svelte';
  import { itemKey } from '$lib/reprompt';
  import { deleteTag, mergeBlocker, mergeItems, renameTag } from '$lib/bulk.svelte';
  import { errorCode, errorMessage } from '$lib/bridge';
  import { errorText } from '$lib/i18n';
  import type { DuplicateGroup, TagCount } from '$lib/types';
  import MergeRows from './MergeRows.svelte';

  // ------------------------------------------------------------ duplicates

  const IGNORE_KEY = 'npw.dupIgnore';
  const groupKey = (g: DuplicateGroup) => g.items.map((i) => itemKey(i.vault_id, i.item_id)).sort().join('|');

  function loadIgnored(): string[] {
    try {
      const v = JSON.parse(localStorage.getItem(IGNORE_KEY) ?? '[]');
      return Array.isArray(v) ? v.filter((x) => typeof x === 'string') : [];
    } catch {
      return [];
    }
  }

  let groups = $state<DuplicateGroup[] | null>(null);
  let keeps = $state<Record<string, string>>({});
  let ignored = $state<string[]>(loadIgnored());
  let busy = $state('');

  const visible = $derived((groups ?? []).filter((g) => !ignored.includes(groupKey(g))));
  const hidden = $derived((groups ?? []).length - visible.length);
  const identical = $derived(visible.filter((g) => g.identical && !mergeBlocker(g.items)));

  async function loadDuplicates() {
    try {
      const gs = await vault.bridge.duplicates();
      const next: Record<string, string> = {};
      for (const g of gs) {
        const k = groupKey(g);
        const keys = g.items.map((i) => itemKey(i.vault_id, i.item_id));
        next[k] = keeps[k] && keys.includes(keeps[k]) ? keeps[k] : keys[0]!;
      }
      keeps = next;
      groups = gs;
      // forget dismissals of groups that no longer exist
      const live = new Set(gs.map(groupKey));
      if (ignored.some((k) => !live.has(k))) saveIgnored(ignored.filter((k) => live.has(k)));
    } catch (e) {
      vault.fail(e);
    }
  }

  function saveIgnored(list: string[]) {
    ignored = list;
    try {
      localStorage.setItem(IGNORE_KEY, JSON.stringify(list));
    } catch {
      /* storage unavailable: dismissals last for this session */
    }
  }

  function split(g: DuplicateGroup) {
    const k = keeps[groupKey(g)];
    const keep = g.items.find((i) => itemKey(i.vault_id, i.item_id) === k) ?? g.items[0]!;
    return { keep, others: g.items.filter((i) => i !== keep) };
  }

  async function merge(g: DuplicateGroup) {
    busy = groupKey(g);
    const { keep, others } = split(g);
    await mergeItems(keep, others);
    busy = '';
  }

  async function mergeAllIdentical() {
    const list = identical;
    if (!(await confirm('合并完全相同的条目？', `${list.length} 组内容完全相同的条目，每组保留选中的一个（默认最新的），其余移到回收站。`, '全部合并'))) return;
    busy = 'all';
    let done = 0;
    let trashed = 0;
    try {
      for (const g of list) {
        const { keep, others } = split(g);
        const r = await vault.bridge.mergeItems(
          { vault_id: keep.vault_id, item_id: keep.item_id },
          others.map((o) => ({ vault_id: o.vault_id, item_id: o.item_id })),
        );
        done++;
        trashed += r.trashed;
      }
      toast(`已合并 ${done} 组，${trashed} 个条目移到了回收站`, 'ok', 5000);
    } catch (e) {
      toast(`合并了 ${done} 组后出错：${errorText(errorCode(e), errorMessage(e))}`, 'error', 6000);
    } finally {
      busy = '';
      await vault.edited();
    }
  }

  function label(g: DuplicateGroup): string {
    return g.site || g.items[0]?.title || '（无标题）';
  }

  // ------------------------------------------------------------------ tags

  let counts = $state<TagCount[] | null>(null);
  let tagQuery = $state('');
  const shownTags = $derived((counts ?? []).filter((c) => !tagQuery.trim() || c.tag.toLowerCase().includes(tagQuery.trim().toLowerCase())));

  async function loadTags() {
    try {
      counts = await vault.bridge.tagCounts();
    } catch (e) {
      vault.fail(e);
    }
  }

  function showTag(tag: string) {
    vault.query = '';
    void vault.setNav({ kind: 'tag', id: tag });
  }

  // reload after edits and syncs
  $effect(() => {
    void vault.version;
    if (vault.organizeTab === 'duplicates') void loadDuplicates();
    else void loadTags();
  });
</script>

<div class="page">
  <h2>整理</h2>
  <div class="tabs">
    <button class="tab" class:on={vault.organizeTab === 'duplicates'} onclick={() => (vault.organizeTab = 'duplicates')}>重复条目{#if groups && visible.length}<span class="cnt">{visible.length}</span>{/if}</button>
    <button class="tab" class:on={vault.organizeTab === 'tags'} onclick={() => (vault.organizeTab = 'tags')}>标签</button>
  </div>

  {#if vault.organizeTab === 'duplicates'}
    <p class="muted small">同一网站上用户名相同、没有网址但标题和用户名相同、或者内容完全一样的条目。合并时选一个保留，其他条目的内容并入它后移到回收站：不同的密码存入密码历史，其他不同的内容作为额外字段保留，不会丢失任何数据。</p>
    {#if groups === null}
      <div class="faint">正在查找…</div>
    {:else}
      <div class="row head">
        <span class="grow">{visible.length ? `找到 ${visible.length} 组可能重复的条目` : '没有发现重复的条目 🎉'}</span>
        {#if hidden}<button class="btn ghost sm" onclick={() => saveIgnored([])}>显示已忽略的 {hidden} 组</button>{/if}
        {#if identical.length > 1}
          <button class="btn sm primary" disabled={!!busy} onclick={mergeAllIdentical}>{busy === 'all' ? '正在合并…' : `合并全部完全相同的（${identical.length} 组）`}</button>
        {/if}
      </div>
      {#each visible as g (groupKey(g))}
        {@const k = groupKey(g)}
        {@const blocker = mergeBlocker(g.items)}
        <div class="card group">
          <div class="gh">
            <b>{label(g)}</b>
            {#if g.username}<span class="muted">· {g.username}</span>{/if}
            <span class="grow"></span>
            {#if g.identical}<span class="badge ok">内容相同</span>
            {:else if g.same_password}<span class="badge">密码相同</span>
            {:else}<span class="badge warn" title="合并后保留条目的密码不变，其他密码存入密码历史">密码不同</span>{/if}
          </div>
          <MergeRows items={g.items} bind:keep={keeps[k]} name="dup-{k}" />
          {#if blocker}<div class="banner bad small">{blocker}</div>{/if}
          <div class="gf">
            {#if !g.same_password}<span class="faint small grow">“保留”条目的密码不变，其他不同的密码会存进它的密码历史</span>{:else}<span class="grow"></span>{/if}
            <button class="btn ghost sm" onclick={() => saveIgnored([...ignored, k])}>不是重复</button>
            <button class="btn sm primary" disabled={!!busy || !!blocker} onclick={() => merge(g)}>{busy === k ? '正在合并…' : `合并为一个`}</button>
          </div>
        </div>
      {/each}
    {/if}
  {:else}
    <p class="muted small">重命名会连同子标签一起改（“工作”改名后“工作/开发”也跟着改）；改成已有的标签名就是把两个标签合并。删除标签只去掉标签，不会删除条目。要给很多条目加标签，可以在条目列表里点“选择”后批量添加。</p>
    {#if counts === null}
      <div class="faint">加载中…</div>
    {:else if !counts.length}
      <div class="faint">还没有标签</div>
    {:else}
      <input class="input filter" bind:value={tagQuery} placeholder="筛选标签" autocomplete="off" />
      <div class="card">
        {#each shownTags as c (c.tag)}
          {@const depth = c.tag.split('/').length - 1}
          <div class="trow">
            <button class="tname" style="padding-left:{depth * 18}px" title={c.tag} onclick={() => showTag(c.tag)}>
              {#if depth}<span class="faint">└ </span>{/if}# {c.tag.split('/').pop()}
            </button>
            <span class="faint small cnt2">{c.items} 个条目</span>
            <button class="btn ghost sm" onclick={() => renameTag(c.tag)}>重命名</button>
            <button class="btn ghost sm danger" onclick={() => deleteTag(c.tag, c.items)}>删除</button>
          </div>
        {:else}
          <div class="trow faint">没有匹配的标签</div>
        {/each}
      </div>
    {/if}
  {/if}
</div>

<style>
  .page { padding: 22px 28px 40px; max-width: 900px; }
  h2 { margin: 0 0 10px; }
  .tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--border); margin-bottom: 12px; }
  .tab { border: 0; background: none; padding: 8px 14px; border-bottom: 2px solid transparent; color: var(--text-2); display: flex; align-items: center; gap: 6px; }
  .tab.on { color: var(--accent); border-bottom-color: var(--accent); font-weight: 600; }
  .cnt { font-size: 11.5px; background: var(--surface-3); border-radius: 999px; padding: 0 7px; color: var(--text-2); }
  .head { margin: 6px 0 12px; gap: 8px; flex-wrap: wrap; }
  .group { margin-bottom: 14px; overflow: hidden; }
  .gh { display: flex; align-items: center; gap: 8px; padding: 10px 12px; border-bottom: 1px solid var(--border); background: var(--surface-2); }
  .gf { display: flex; align-items: center; gap: 8px; padding: 8px 12px; border-top: 1px solid var(--border); flex-wrap: wrap; }
  .group .banner { margin: 8px 12px; }
  .filter { margin-bottom: 10px; max-width: 320px; }
  .trow { display: flex; align-items: center; gap: 8px; padding: 6px 12px; border-bottom: 1px solid var(--border); }
  .trow:last-child { border-bottom: 0; }
  .tname { flex: 1; min-width: 0; text-align: left; border: 0; background: none; color: var(--text); padding: 4px 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .tname:hover { color: var(--accent); }
  .cnt2 { white-space: nowrap; }
  @media (max-width: 700px) { .page { padding: 16px; } }
</style>
