<script lang="ts">
  import { vault } from '$lib/vault.svelte';
  import { avatar } from '$lib/ui.svelte';
  import { relativeTime } from '$lib/i18n';
  import { itemKey } from '$lib/reprompt';
  import type { ItemView } from '$lib/types';

  // Items to merge; `keep` (an itemKey) is the one the others are merged into.
  let { items, keep = $bindable(), name }: { items: ItemView[]; keep: string | undefined; name: string } = $props();

  const manyVaults = $derived(new Set(items.map((i) => i.vault_id)).size > 1);
  const mixedTypes = $derived(new Set(items.map((i) => i.template)).size > 1);
  const vaultName = (id: string) => vault.vaults.find((v) => v.id === id)?.name ?? '';
  const templateName = (id: string) => vault.templates.find((t) => t.id === id)?.label ?? id;

  function open(it: ItemView) {
    vault.page = 'items';
    vault.nav = { kind: it.archived ? 'archived' : 'all' };
    vault.query = '';
    vault.clearPicks();
    void vault.reload().then(() => (vault.selected = { vault_id: it.vault_id, item_id: it.item_id }));
  }
</script>

<div class="rows">
  {#each items as it (it.vault_id + it.item_id)}
    {@const k = itemKey(it.vault_id, it.item_id)}
    {@const a = avatar(it.title, it.template)}
    <label class="r" class:keep={keep === k}>
      <input type="radio" {name} value={k} bind:group={keep} />
      <div class="ico" style="background:{a.color}">{a.letter}</div>
      <div class="grow">
        <div class="t">
          {it.title || '（无标题）'}
          {#if keep === k}<span class="badge acc">保留</span>{/if}
        </div>
        <div class="s">
          {it.subtitle || (it.urls[0] ? vault.bridge.displayHost(it.urls[0]) : '')}
          {#if manyVaults}<span class="faint"> · {vaultName(it.vault_id)}</span>{/if}
          {#if mixedTypes}<span class="faint"> · {templateName(it.template)}</span>{/if}
          <span class="faint"> · 更新于{relativeTime(it.updated_at)}</span>
        </div>
      </div>
      <div class="marks">
        {#if it.conflicts > 0}<span class="badge warn">冲突</span>{/if}
        {#if it.archived}<span class="badge">归档</span>{/if}
        {#if it.has_totp}<span class="badge" title="一次性密码">TOTP</span>{/if}
        {#if it.passkeys}<span class="badge" title="通行密钥">通行密钥</span>{/if}
        {#if it.attachments}<span class="badge" title="附件">📎 {it.attachments}</span>{/if}
        {#if it.tags.length}<span class="badge" title={it.tags.join('，')}># {it.tags.length}</span>{/if}
      </div>
      <button class="btn ghost sm" type="button" onclick={(e) => { e.preventDefault(); open(it); }}>查看</button>
    </label>
  {/each}
</div>

<style>
  .rows { display: flex; flex-direction: column; }
  .r { display: flex; align-items: center; gap: 10px; padding: 8px 10px; border-bottom: 1px solid var(--border); cursor: pointer; }
  .r:last-child { border-bottom: 0; }
  .r:hover { background: var(--surface-2); }
  .r.keep { background: var(--accent-2); }
  .t { font-weight: 600; display: flex; align-items: center; gap: 6px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .s { font-size: 12.5px; color: var(--text-2); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .grow { min-width: 0; }
  .marks { display: flex; gap: 4px; flex-wrap: wrap; justify-content: flex-end; }
  @media (max-width: 700px) { .marks { display: none; } }
</style>
