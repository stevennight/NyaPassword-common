<script lang="ts">
  let { size = 28 }: { size?: number } = $props();
</script>

<svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true" style="color: var(--accent)">
  <path d="M6 13 L7.5 4 L13 9.5 Z M26 13 L24.5 4 L19 9.5 Z" fill="currentColor" />
  <rect x="5" y="9" width="22" height="20" rx="7" fill="currentColor" />
  <circle cx="16" cy="17.5" r="3.2" fill="var(--surface)" />
  <rect x="14.6" y="19" width="2.8" height="5.5" rx="1.2" fill="var(--surface)" />
</svg>
