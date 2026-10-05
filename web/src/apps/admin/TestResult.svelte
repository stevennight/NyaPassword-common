<script lang="ts">
  // The steps of a target connection test (write, read back, delete a probe file).
  import type { TestStep } from './api';
  import Modal from '$components/Modal.svelte';

  let { steps, onclose, inline = false }: { steps: TestStep[]; onclose?: () => void; inline?: boolean } = $props();

  const NAME: Record<string, string> = { write: '写入探测文件', read: '读回并比对', delete: '删除探测文件' };
  const protectDeleted = $derived(steps.some((s) => s.step === 'delete' && s.ok && s.expected_to_fail));
</script>

{#snippet body()}
  {#each steps as s (s.step)}
    <div class="row line">
      <span class="grow">{NAME[s.step] ?? s.step}</span>
      {#if s.ok}<span class="badge ok">成功</span>{:else if s.expected_to_fail}<span class="badge ok">失败（防删模式下符合预期）</span>{:else}<span class="badge bad">失败</span>{/if}
    </div>
    {#if s.error && !s.expected_to_fail}<div class="err small">{s.error}</div>{/if}
  {/each}
  {#if steps.length && steps.length < 3 && !steps[0].ok}<p class="faint small">写入失败时不会继续读和删。检查地址、Bucket、账号和密码，以及这个账号有没有写权限。</p>{/if}
  {#if protectDeleted}<div class="banner small" style="margin-top:8px">防删模式下删除竟然成功了：这个凭据能删除备份，服务器被入侵时历史备份也可能被删。建议收紧权限（只给写和读）。</div>{/if}
{/snippet}

{#if inline}
  <div class="inline">{@render body()}</div>
{:else}
  <Modal title="连接测试结果" onclose={() => onclose?.()} width={480}>{@render body()}</Modal>
{/if}

<style>
  .line { padding: 6px 0; border-bottom: 1px solid var(--border); }
  .err { color: var(--bad); word-break: break-word; padding: 4px 0; }
  p { margin: 8px 0 0; }
</style>
