<script lang="ts">
  import { vault } from '$lib/vault.svelte';
  import { toast } from '$lib/ui.svelte';
  import type { Generated, Recipe } from '$lib/types';
  import Modal from './Modal.svelte';

  let { onclose, onuse, inline = false }: { onclose?: () => void; onuse?: (pw: string) => void; inline?: boolean } = $props();

  let kind = $state<'random' | 'memorable' | 'pin'>('random');
  let length = $state(20);
  let upper = $state(true);
  let lower = $state(true);
  let digits = $state(true);
  let symbols = $state(true);
  let avoid = $state(true);
  let words = $state(4);
  let sep = $state('-');
  let cap = $state(true);
  let wordDigits = $state(true);
  let pinLen = $state(6);
  let result = $state<Generated>({ password: '', bits: 0 });

  const recipe = $derived<Recipe>(
    kind === 'random'
      ? { kind, length, upper, lower, digits, symbols, avoid_ambiguous: avoid }
      : kind === 'memorable'
        ? { kind, words, separator: sep, capitalize: cap, digits: wordDigits }
        : { kind, length: pinLen },
  );

  function regen() {
    result = vault.bridge.generate($state.snapshot(recipe) as Recipe);
  }
  $effect(() => {
    void recipe;
    regen();
  });

  const strength = $derived(result.bits >= 100 ? '非常强' : result.bits >= 70 ? '强' : result.bits >= 45 ? '一般' : '弱');
</script>

{#snippet body()}
  <div class="out mono">{result.password}</div>
  <div class="row small muted"><span>{Math.round(result.bits)} 位熵 · {strength}</span><span class="spacer"></span>
    <button class="btn sm" onclick={regen}>↻ 换一个</button>
    <button class="btn sm" onclick={async () => { await vault.bridge.copy(result.password, true); toast('已复制，90 秒后清除'); }}>复制</button>
    {#if onuse}<button class="btn sm primary" onclick={() => onuse(result.password)}>使用</button>{/if}
  </div>
  <div class="seg">
    {#each [['random', '随机字符'], ['memorable', '易记口令'], ['pin', 'PIN']] as [k, l] (k)}
      <button class:on={kind === k} onclick={() => (kind = k as typeof kind)}>{l}</button>
    {/each}
  </div>
  {#if kind === 'random'}
    <label class="lbl">长度 {length}<input type="range" min="8" max="64" bind:value={length} /></label>
    <div class="checks">
      <label><input type="checkbox" bind:checked={upper} /> 大写</label>
      <label><input type="checkbox" bind:checked={lower} /> 小写</label>
      <label><input type="checkbox" bind:checked={digits} /> 数字</label>
      <label><input type="checkbox" bind:checked={symbols} /> 符号</label>
      <label><input type="checkbox" bind:checked={avoid} /> 排除易混字符</label>
    </div>
  {:else if kind === 'memorable'}
    <label class="lbl">组数 {words}<input type="range" min="3" max="10" bind:value={words} /></label>
    <div class="checks">
      <label>分隔符 <select bind:value={sep}><option value="-">-</option><option value=".">.</option><option value="_">_</option><option value=" ">空格</option></select></label>
      <label><input type="checkbox" bind:checked={cap} /> 大写首字母</label>
      <label><input type="checkbox" bind:checked={wordDigits} /> 加数字</label>
    </div>
  {:else}
    <label class="lbl">位数 {pinLen}<input type="range" min="4" max="12" bind:value={pinLen} /></label>
  {/if}
{/snippet}

{#if inline}
  <div class="inline">{@render body()}</div>
{:else}
  <Modal title="密码生成器" onclose={() => onclose?.()} width={480}>{@render body()}</Modal>
{/if}

<style>
  .out { font-size: 20px; padding: 14px; background: var(--surface-2); border-radius: 10px; word-break: break-all; margin-bottom: 8px; min-height: 58px; }
  .seg { display: grid; grid-template-columns: repeat(3, 1fr); background: var(--surface-2); border-radius: 10px; padding: 3px; margin: 14px 0 4px; }
  .seg button { border: 0; background: transparent; padding: 6px; border-radius: 8px; color: var(--text-2); }
  .seg button.on { background: var(--surface); color: var(--text); font-weight: 600; }
  .lbl input[type='range'] { width: 100%; }
  .checks { display: flex; flex-wrap: wrap; gap: 8px 16px; font-size: 13px; }
  .checks label { display: flex; gap: 4px; align-items: center; }
  .inline { max-width: 560px; padding: 22px 28px; }
</style>
