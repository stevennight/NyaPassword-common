<script lang="ts">
  import { copyValue, isSecret } from '$lib/item-actions';
  import { openExternal } from '$lib/links';
  import { openMenu } from '$lib/menu.svelte';
  import { vault } from '$lib/vault.svelte';
  import type { Field } from '$lib/types';
  import TotpCode from './TotpCode.svelte';
  import Modal from './Modal.svelte';

  let { field }: { field: Field } = $props();
  let shown = $state(false);
  let large = $state(false);

  const secret = $derived(isSecret(field));
  const text = $derived(fieldText(field));

  function fieldText(f: Field): string {
    const v = f.value;
    if (v == null) return '';
    if (typeof v === 'string') return v;
    if (f.kind === 'address' && typeof v === 'object') {
      const a = v as Record<string, string>;
      return [a.country, a.province, a.city, a.district, a.street, a.postal_code].filter(Boolean).join(' ');
    }
    return JSON.stringify(v);
  }

  function copy(t: string, label = field.label) {
    return copyValue(field, t, label);
  }

  function contextMenu(e: MouseEvent) {
    // selected text keeps the usual menu (copy the selection)
    if (window.getSelection()?.toString()) return;
    openMenu(e, [
      { label: field.kind === 'totp' ? '复制验证码' : field.multiline ? '全部复制' : '复制', run: () => copy(text) },
      isUrl ? { label: '打开链接', run: () => openExternal(text).catch(vault.fail.bind(vault)) } : null,
      secret ? { label: shown ? '隐藏' : '显示', run: () => (shown = !shown) } : null,
      field.multiline && lines.length > 1
        ? { label: '按行复制', run: () => (large = true) }
        : secret
          ? { label: '大字显示', run: () => (large = true) }
          : null,
    ].filter((x) => x !== null));
  }

  const lines = $derived(text.split('\n').filter((l) => l.trim()));
  const isUrl = $derived(field.kind === 'url' && /^https?:\/\//.test(text));
</script>

<div class="field" role="group" oncontextmenu={contextMenu}>
  <div class="lab">{field.label || field.id}</div>
  <div class="val" class:mono={secret || field.kind === 'totp' || field.kind === 'pin'}>
    {#if field.kind === 'totp'}
      <TotpCode uri={text} />
    {:else if secret && !shown}
      ••••••••••••{#if field.multiline && lines.length > 1}<span class="faint small">（{lines.length} 行，已隐藏）</span>{/if}
    {:else if field.multiline || field.kind === 'multiline'}
      <div class="pre">{text}</div>
    {:else if isUrl}
      <a href={text} target="_blank" rel="noreferrer noopener">{text}</a>
    {:else if field.kind === 'reference'}
      <span class="badge acc">引用：{text}</span>
    {:else}
      {text}
    {/if}
  </div>
  <div class="tools">
    {#if secret}<button class="t" onclick={() => (shown = !shown)}>{shown ? '隐藏' : '显示'}</button>{/if}
    <button class="t" onclick={() => copy(text)}>{field.multiline ? '全部复制' : '复制'}</button>
    {#if field.multiline && lines.length > 1}
      <button class="t" onclick={() => (large = true)}>按行复制</button>
    {:else if secret}
      <button class="t" onclick={() => (large = true)}>大字</button>
    {/if}
  </div>
</div>

{#if large}
  <Modal title={field.label} onclose={() => (large = false)} width={640}>
    {#if field.multiline && lines.length > 1}
      {#each lines as l, i (i)}
        <div class="line"><span class="mono grow">{l}</span><button class="btn sm" onclick={() => copy(l, `第 ${i + 1} 行`)}>复制</button></div>
      {/each}
    {:else}
      <div class="big mono">
        {#each [...text] as ch, i (i)}<span class:digit={/\d/.test(ch)} class:sym={/[^\w]/.test(ch)}>{ch}</span>{/each}
      </div>
    {/if}
  </Modal>
{/if}

<style>
  .field { display: grid; grid-template-columns: 1fr auto; gap: 2px 10px; padding: 9px 14px; border-bottom: 1px solid var(--border); align-items: center; }
  .field:last-child { border-bottom: 0; }
  .field:hover { background: var(--surface-2); }
  .lab { font-size: 12px; color: var(--text-2); grid-column: 1; }
  .val { grid-column: 1; word-break: break-all; min-height: 20px; }
  .pre { white-space: pre-wrap; line-height: 1.7; }
  .tools { grid-row: 1 / 3; grid-column: 2; display: flex; gap: 2px; opacity: .3; transition: opacity .15s; }
  .field:hover .tools, .field:focus-within .tools { opacity: 1; }
  .t { border: 0; background: transparent; border-radius: 6px; padding: 4px 7px; color: var(--text-2); font-size: 12.5px; }
  .t:hover { background: var(--surface-3); color: var(--accent); }
  .line { display: flex; gap: 10px; align-items: center; padding: 6px 0; border-bottom: 1px solid var(--border); }
  .big { font-size: 34px; letter-spacing: .12em; word-break: break-all; text-align: center; padding: 20px 0; }
  .big .digit { color: var(--accent); }
  .big .sym { color: var(--warn); }
</style>
