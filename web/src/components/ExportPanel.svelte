<script lang="ts">
  // Export the whole account to a file now (the import page and the settings' 导出与备份).
  import { vault } from '$lib/vault.svelte';
  import { errorCode, errorMessage } from '$lib/bridge';
  import { errorText } from '$lib/i18n';
  import { confirm, toast } from '$lib/ui.svelte';

  let format = $state<'native' | 'kdbx' | 'csv'>('native');
  let password = $state('');
  let busy = $state(false);
  let error = $state('');

  async function doExport() {
    busy = true;
    error = '';
    try {
      if (format === 'csv' && !(await confirm('导出明文 CSV？', 'CSV 文件不加密，任何拿到文件的人都能看到全部密码。用完请立即删除。', '仍然导出', true))) return;
      const data = await vault.bridge.exportVault(format, password);
      const stamp = new Date().toISOString().slice(0, 10);
      const [ext, mime] = format === 'native' ? ['npwexport', 'application/octet-stream'] : format === 'kdbx' ? ['kdbx', 'application/octet-stream'] : ['csv', 'text/csv'];
      await vault.bridge.saveFile(`NyaPassword-${stamp}.${ext}`, data, mime);
      password = '';
      toast('已导出');
    } catch (e) {
      error = errorText(errorCode(e), errorMessage(e));
    } finally {
      busy = false;
    }
  }
</script>

<div class="formats">
  <label class:on={format === 'native'}><input type="radio" bind:group={format} value="native" /> <b>NyaPassword 加密导出</b><span>无损，含附件、通行密钥、历史；用主密码 + Secret Key 打开</span></label>
  <label class:on={format === 'kdbx'}><input type="radio" bind:group={format} value="kdbx" /> <b>KDBX 4（KeePassXC）</b><span>用主密码加密；没有本软件也能用 KeePassXC 打开</span></label>
  <label class:on={format === 'csv'}><input type="radio" bind:group={format} value="csv" /> <b>CSV（明文）</b><span>不加密，仅用于迁移到别的软件</span></label>
</div>
{#if error}<div class="banner bad small" style="margin-top:10px">{error}</div>{/if}
<form class="row go" onsubmit={(e) => { e.preventDefault(); void doExport(); }}>
  <input class="input" type="password" bind:value={password} placeholder="输入主密码确认" autocomplete="current-password" />
  <button class="btn primary" disabled={busy || !password}>{busy ? '导出中…' : '导出'}</button>
</form>

<style>
  .formats { display: grid; gap: 8px; }
  .formats label { display: grid; grid-template-columns: auto 1fr; gap: 2px 8px; border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px; background: var(--surface); cursor: pointer; }
  .formats label.on { border-color: var(--accent); background: var(--accent-2); }
  .formats span { grid-column: 2; font-size: 12.5px; color: var(--text-2); }
  .go { margin-top: 10px; }
  .go .input { max-width: 280px; }
</style>
