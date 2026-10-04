<script lang="ts">
  import { vault } from '$lib/vault.svelte';
  import { TEMPLATE_ICONS } from '$lib/ui.svelte';
  import Modal from './Modal.svelte';

  let { onclose }: { onclose: () => void } = $props();
  let vaultId = $state(vault.defaultVault());

  function pick(template: string) {
    vault.newTemplate = template;
    vault.newVault = vaultId;
    vault.editing = { vault_id: vaultId, item_id: null };
    vault.page = 'items';
    onclose();
  }
</script>

<Modal title="新建条目" {onclose} width={520}>
  {#if vault.vaults.length > 1}
    <label class="lbl" for="nv">保险库</label>
    <select id="nv" class="select" bind:value={vaultId}>
      {#each vault.vaults as v (v.id)}<option value={v.id}>{v.name}</option>{/each}
    </select>
  {/if}
  <div class="grid">
    {#each vault.templates as t (t.id)}
      <button class="tpl" onclick={() => pick(t.id)}><span class="i">{TEMPLATE_ICONS[t.id] ?? '•'}</span>{t.label}</button>
    {/each}
  </div>
</Modal>

<style>
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 8px; margin-top: 12px; }
  .tpl { display: flex; align-items: center; gap: 8px; padding: 10px 12px; border: 1px solid var(--border); border-radius: 10px; background: var(--surface-2); text-align: left; }
  .tpl:hover { border-color: var(--accent); background: var(--accent-2); }
  .i { font-size: 18px; width: 24px; text-align: center; }
</style>
