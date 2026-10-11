<script lang="ts">
  // A password with digits and symbols in their own colors (tells 0 from O, l from 1 and | at a glance).
  let { text }: { text: string } = $props();

  const kind = (ch: string) => (/\p{N}/u.test(ch) ? 'digit' : /[^\p{L}\s]/u.test(ch) ? 'sym' : undefined);
</script>

{#each [...text] as ch, i (i)}<span class={kind(ch)}>{ch}</span>{/each}

<style>
  .digit { color: var(--accent); }
  .sym { color: var(--warn); }
</style>
