<script lang="ts">
  import type { Snippet } from 'svelte';

  let { title, onclose, width = 560, children }: { title: string; onclose: () => void; width?: number; children: Snippet } = $props();
</script>

<svelte:window onkeydown={(e) => e.key === 'Escape' && onclose()} />

<div class="backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && onclose()}>
  <div class="box" role="dialog" aria-modal="true" aria-label={title} style="width:min({width}px,100%)">
    <div class="head">
      <h3>{title}</h3>
      <button class="btn ghost sm" onclick={onclose} aria-label="关闭">✕</button>
    </div>
    <div class="body">{@render children()}</div>
  </div>
</div>

<style>
  .backdrop { position: fixed; inset: 0; background: rgba(10, 15, 25, .45); display: grid; place-items: center; z-index: 80; padding: 16px; }
  .box { background: var(--surface); border-radius: 14px; box-shadow: var(--shadow); max-height: 88vh; display: flex; flex-direction: column; }
  .head { display: flex; align-items: center; padding: 14px 18px 8px; }
  .head h3 { margin: 0; flex: 1; font-size: 16px; }
  .body { padding: 4px 18px 18px; overflow: auto; }
</style>
