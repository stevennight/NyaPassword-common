<script lang="ts">
  import { vault } from '$lib/vault.svelte';
  import Welcome from '$components/Welcome.svelte';
  import LockScreen from '$components/LockScreen.svelte';
  import Shell from '$components/Shell.svelte';
  import Overlays from '$components/Overlays.svelte';
</script>

{#if vault.phase === 'loading'}
  <div class="loading faint">加载中…</div>
{:else if vault.phase === 'welcome'}
  <Welcome />
{:else if vault.phase === 'locked'}
  <LockScreen />
{:else}
  <Shell />
{/if}
<Overlays />

<style>
  .loading { height: 100%; display: grid; place-items: center; }
</style>
