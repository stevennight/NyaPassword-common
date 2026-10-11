<script lang="ts">
  import { untrack } from 'svelte';
  import { vault } from '$lib/vault.svelte';
  import { itemKey } from '$lib/reprompt';
  import { mergeBlocker, mergeItems } from '$lib/bulk.svelte';
  import type { ItemView } from '$lib/types';
  import Modal from './Modal.svelte';
  import MergeRows from './MergeRows.svelte';

  let { items, onclose }: { items: ItemView[]; onclose: () => void } = $props();

  // suggest the most recently changed one
  let keep = $state(
    untrack(() => {
      const newest = [...items].sort((a, b) => b.updated_at - a.updated_at)[0]!;
      return itemKey(newest.vault_id, newest.item_id);
    }),
  );
  let busy = $state(false);

  const blocker = $derived(mergeBlocker(items));
  const mixed = $derived(new Set(items.map((i) => i.template)).size > 1);

  async function merge() {
    const k = items.find((i) => itemKey(i.vault_id, i.item_id) === keep);
    if (!k) return;
    busy = true;
    const ok = await mergeItems(k, items.filter((i) => i !== k));
    busy = false;
    if (ok) {
      vault.clearPicks();
      vault.selected = { vault_id: k.vault_id, item_id: k.item_id };
      onclose();
    }
  }
</script>

<Modal title="合并 {items.length} 个条目" {onclose} width={620}>
  <p class="muted small">选择要保留的条目，其他条目的内容会并入它，然后移到回收站：空着的字段会补上，不同的密码存入密码历史，其他不同的内容作为额外字段保留；网址、标签、备注、通行密钥和附件都会合并。</p>
  {#if mixed}<div class="banner small">这些条目的类型不同，合并后保持“保留”条目的类型。</div>{/if}
  {#if blocker}<div class="banner bad small">{blocker}</div>{/if}
  <div class="card"><MergeRows {items} bind:keep name="merge-dialog" /></div>
  <div class="row" style="justify-content:flex-end; margin-top:14px">
    <button class="btn" onclick={onclose}>取消</button>
    <button class="btn primary" disabled={busy || !!blocker} onclick={merge}>{busy ? '正在合并…' : '合并'}</button>
  </div>
</Modal>

<style>
  p { margin: 0 0 10px; }
  .banner { margin-bottom: 10px; }
</style>
