<script lang="ts">
  import { onDestroy } from 'svelte';
  import { vault } from '$lib/vault.svelte';

  let { uri, size = 20 }: { uri: string; size?: number } = $props();
  let now = $state(Date.now());
  const timer = setInterval(() => (now = Date.now()), 1000);
  onDestroy(() => clearInterval(timer));

  const otp = $derived(vault.bridge.otpCode(uri, Math.floor(now / 1000)));
  const pretty = $derived(otp ? (otp.code.length === 6 ? `${otp.code.slice(0, 3)} ${otp.code.slice(3)}` : otp.code) : '');
  const frac = $derived(otp ? otp.remaining / otp.period : 0);
</script>

{#if otp}
  <span class="totp">
    <span class="code mono" style="font-size:{size}px">{pretty}</span>
    <svg class="ring" viewBox="0 0 22 22" aria-label="剩余 {otp.remaining} 秒">
      <circle cx="11" cy="11" r="9" fill="none" stroke="var(--surface-3)" stroke-width="3" />
      <circle cx="11" cy="11" r="9" fill="none" stroke={otp.remaining <= 5 ? 'var(--bad)' : 'var(--accent)'} stroke-width="3"
        stroke-dasharray="56.5" stroke-dashoffset={56.5 * (1 - frac)} transform="rotate(-90 11 11)" stroke-linecap="round" />
    </svg>
    <span class="faint small">{otp.remaining} 秒</span>
  </span>
{:else}
  <span class="badge bad">无效的一次性密码设置</span>
{/if}

<style>
  .totp { display: inline-flex; align-items: center; gap: 10px; }
  .code { color: var(--accent); letter-spacing: .08em; }
  .ring { width: 20px; height: 20px; }
</style>
