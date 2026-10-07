<script lang="ts">
  import { tick } from 'svelte';
  import { closeMenu, menu, type MenuItem } from '$lib/menu.svelte';

  let box = $state<HTMLDivElement>();
  let w = $state(0);
  let h = $state(0);

  // keep the menu inside the window
  const left = $derived(menu.open ? Math.max(4, Math.min(menu.open.x, window.innerWidth - w - 4)) : 0);
  const top = $derived(menu.open ? Math.max(4, Math.min(menu.open.y, window.innerHeight - h - 4)) : 0);

  $effect(() => {
    if (!menu.open) return;
    void tick().then(() => box?.querySelector<HTMLButtonElement>('button:not(:disabled)')?.focus());
    const outside = (e: Event) => {
      if (!box?.contains(e.target as Node)) closeMenu();
    };
    const close = () => closeMenu();
    window.addEventListener('pointerdown', outside, true);
    window.addEventListener('wheel', close, { passive: true });
    window.addEventListener('scroll', close, true);
    window.addEventListener('resize', close);
    window.addEventListener('blur', close);
    return () => {
      window.removeEventListener('pointerdown', outside, true);
      window.removeEventListener('wheel', close);
      window.removeEventListener('scroll', close, true);
      window.removeEventListener('resize', close);
      window.removeEventListener('blur', close);
    };
  });

  function keys(e: KeyboardEvent) {
    if (e.key === 'Escape' || e.key === 'Tab') {
      e.preventDefault();
      closeMenu();
      return;
    }
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
    e.preventDefault();
    const items = [...(box?.querySelectorAll<HTMLButtonElement>('button:not(:disabled)') ?? [])];
    if (!items.length) return;
    const i = items.indexOf(document.activeElement as HTMLButtonElement);
    const next = e.key === 'ArrowDown' ? (i + 1) % items.length : (i - 1 + items.length) % items.length;
    items[next]?.focus();
  }

  function run(it: MenuItem) {
    closeMenu();
    void (async () => it.run())();
  }
</script>

{#if menu.open}
  <div
    class="menu"
    role="menu"
    tabindex="-1"
    bind:this={box}
    bind:clientWidth={w}
    bind:clientHeight={h}
    style="left:{left}px;top:{top}px"
    onkeydown={keys}
    oncontextmenu={(e) => e.preventDefault()}
  >
    {#each menu.open.entries as it, i (i)}
      {#if it}
        <button role="menuitem" class:danger={it.danger} disabled={it.disabled} onclick={() => run(it)}>{it.label}</button>
      {:else}
        <div class="sep" role="separator"></div>
      {/if}
    {/each}
  </div>
{/if}

<style>
  .menu { position: fixed; z-index: 120; min-width: 168px; max-width: 320px; padding: 4px; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; box-shadow: var(--shadow); }
  button { display: block; width: 100%; padding: 6px 12px; border: 0; border-radius: 6px; background: transparent; color: var(--text); text-align: left; font-size: 13px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  button:hover:not(:disabled), button:focus-visible { background: var(--surface-3); outline: none; }
  button:disabled { opacity: .5; cursor: default; }
  button.danger { color: var(--bad); }
  .sep { height: 1px; margin: 4px 6px; background: var(--border); }
</style>
