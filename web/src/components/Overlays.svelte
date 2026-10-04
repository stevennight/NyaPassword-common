<script lang="ts">
  import { confirmState, toasts } from '$lib/ui.svelte';

  function answer(v: boolean) {
    confirmState.req?.resolve(v);
    confirmState.req = null;
  }
</script>

<div class="toasts" aria-live="polite">
  {#each toasts as t (t.id)}
    <div class="toast {t.kind}">{t.text}</div>
  {/each}
</div>

{#if confirmState.req}
  {@const r = confirmState.req}
  <div class="backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && answer(false)}>
    <div class="dialog" role="dialog" aria-modal="true" aria-label={r.title}>
      <h3>{r.title}</h3>
      <p class="muted">{r.body}</p>
      <div class="row" style="justify-content:flex-end">
        <button class="btn" onclick={() => answer(false)}>取消</button>
        <!-- svelte-ignore a11y_autofocus -->
        <button class="btn {r.danger ? 'danger solid' : 'primary'}" autofocus onclick={() => answer(true)}>{r.ok}</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .toasts { position: fixed; left: 50%; bottom: 24px; transform: translateX(-50%); display: flex; flex-direction: column; gap: 8px; z-index: 100; align-items: center; pointer-events: none; }
  .toast { background: var(--text); color: var(--surface); padding: 8px 16px; border-radius: 999px; font-size: 13px; box-shadow: var(--shadow); max-width: min(560px, 90vw); }
  .toast.error { background: var(--bad); color: #fff; }
  .toast.ok { background: var(--ok); color: #fff; }
  .backdrop { position: fixed; inset: 0; background: rgba(10, 15, 25, .45); display: grid; place-items: center; z-index: 90; padding: 16px; }
  .dialog { width: min(440px, 100%); background: var(--surface); border-radius: 14px; box-shadow: var(--shadow); padding: 18px 20px; }
  .dialog h3 { margin: 0 0 6px; }
  .dialog p { margin: 0 0 16px; white-space: pre-wrap; }
</style>
