<script lang="ts">
  import { choiceState, confirmState, promptState, toasts } from '$lib/ui.svelte';
  import ContextMenu from './ContextMenu.svelte';

  function answer(v: boolean) {
    confirmState.req?.resolve(v);
    confirmState.req = null;
  }

  let text = $state('');
  let ticked = $state<string[]>([]);

  // fresh input for every request
  $effect(() => {
    text = promptState.req?.value ?? '';
  });
  $effect(() => {
    void choiceState.req;
    ticked = [];
  });

  function reply(v: string | null) {
    promptState.req?.resolve(v);
    promptState.req = null;
  }

  function choose(v: string[] | null) {
    choiceState.req?.resolve(v);
    choiceState.req = null;
  }

  function addSuggestion(s: string) {
    const parts = text.split(/[,，]/).map((t) => t.trim()).filter(Boolean);
    if (!parts.includes(s)) parts.push(s);
    text = parts.join(', ');
  }

  // `autofocus` loses to the button that opened the dialog
  function focusSoon(el: HTMLInputElement) {
    setTimeout(() => {
      el.focus();
      el.select();
    }, 0);
  }

  function tick(o: string) {
    ticked = ticked.includes(o) ? ticked.filter((x) => x !== o) : [...ticked, o];
  }
</script>

<div class="toasts" aria-live="polite">
  {#each toasts as t (t.id)}
    <div class="toast {t.kind}">{t.text}</div>
  {/each}
</div>

<ContextMenu />

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

{#if promptState.req}
  {@const r = promptState.req}
  <div class="backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && reply(null)}>
    <div class="dialog" role="dialog" aria-modal="true" aria-label={r.title}>
      <form onsubmit={(e) => { e.preventDefault(); reply(text); }}>
        <h3>{r.title}</h3>
        {#if r.body}<p class="muted">{r.body}</p>{/if}
        <input class="input" bind:value={text} placeholder={r.placeholder} {@attach focusSoon} autocomplete="off" onkeydown={(e) => { if (e.key === 'Escape') { e.preventDefault(); reply(null); } }} />
        {#if r.suggestions.length}
          <div class="sugg">
            {#each r.suggestions as s (s)}<button type="button" class="chip" onclick={() => addSuggestion(s)}>#{s}</button>{/each}
          </div>
        {/if}
        <div class="row" style="justify-content:flex-end; margin-top:14px">
          <button type="button" class="btn" onclick={() => reply(null)}>取消</button>
          <button type="submit" class="btn primary" disabled={!text.trim()}>{r.ok}</button>
        </div>
      </form>
    </div>
  </div>
{/if}

{#if choiceState.req}
  {@const r = choiceState.req}
  <div class="backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && choose(null)}>
    <div class="dialog" role="dialog" aria-modal="true" aria-label={r.title}>
      <h3>{r.title}</h3>
      {#if r.body}<p class="muted">{r.body}</p>{/if}
      <div class="choices">
        {#each r.options as o (o)}
          <label class="choice"><input type="checkbox" checked={ticked.includes(o)} onchange={() => tick(o)} /> {o}</label>
        {/each}
      </div>
      <div class="row" style="justify-content:flex-end; margin-top:14px">
        <button class="btn" onclick={() => choose(null)}>取消</button>
        <button class="btn {r.danger ? 'danger solid' : 'primary'}" disabled={!ticked.length} onclick={() => choose(ticked)}>{r.ok}</button>
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
  .sugg { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; max-height: 120px; overflow: auto; }
  .chip { font-size: 12px; padding: 2px 9px; border-radius: 999px; border: 0; background: var(--surface-3); color: var(--text); }
  .chip:hover { background: var(--sel); color: var(--accent); }
  .choices { display: flex; flex-direction: column; gap: 4px; max-height: 300px; overflow: auto; }
  .choice { display: flex; align-items: center; gap: 8px; padding: 4px 2px; }
</style>
