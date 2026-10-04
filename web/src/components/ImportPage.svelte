<script lang="ts">
  import { onMount } from 'svelte';
  import { vault } from '$lib/vault.svelte';
  import { errorCode, errorMessage } from '$lib/bridge';
  import { bytes, dateTime, errorText } from '$lib/i18n';
  import { confirm, toast } from '$lib/ui.svelte';
  import type { ImportPreview } from '$lib/types';

  type Step = 'choose' | 'password' | 'preview' | 'done';
  let step = $state<Step>('choose');
  let file = $state<{ name: string; data: Uint8Array } | null>(null);
  let filePassword = $state('');
  let preview = $state<ImportPreview | null>(null);
  let vaultId = $state(vault.defaultVault());
  let busy = $state(false);
  let error = $state('');
  let result = $state<{ imported: number; attachments: number; problems: string[] } | null>(null);
  let batches = $state<[string, string, number, number][]>([]);
  let exportFormat = $state<'native' | 'kdbx' | 'csv'>('native');
  let exportPassword = $state('');

  const SOURCES = 'Bitwarden / Vaultwarden（.json、.zip、加密 .json、.csv）、1Password（.1pux、.csv）、KeePass / KeePassXC（.kdbx、.csv）、Chrome / Edge / Google 密码管理器（.csv）';

  onMount(loadBatches);
  async function loadBatches() {
    batches = await vault.bridge.importBatches().catch(() => []);
  }

  async function pick(e: Event) {
    const f = (e.target as HTMLInputElement).files?.[0];
    if (!f) return;
    file = { name: f.name, data: new Uint8Array(await f.arrayBuffer()) };
    filePassword = '';
    await parse();
  }

  async function parse() {
    if (!file) return;
    busy = true;
    error = '';
    try {
      preview = await vault.bridge.importPreview(file.name, file.data, filePassword || undefined);
      step = 'preview';
    } catch (e) {
      const msg = errorMessage(e);
      if (msg === 'need_password') step = 'password';
      else if (errorCode(e) === 'wrong_password') {
        step = 'password';
        error = '文件密码不正确';
      } else error = errorText(errorCode(e), msg);
    } finally {
      busy = false;
    }
  }

  async function commit() {
    if (!preview) return;
    busy = true;
    error = '';
    try {
      const r = (await vault.bridge.importCommit(preview.token, vaultId)) as unknown as { imported: number; attachments: number; problems: string[] };
      result = r;
      step = 'done';
      file = null;
      await vault.edited();
      await loadBatches();
    } catch (e) {
      error = errorText(errorCode(e), errorMessage(e));
    } finally {
      busy = false;
    }
  }

  async function undo(id: string, n: number) {
    if (!(await confirm('撤销这次导入？', `这次导入的 ${n} 个条目会移到回收站（可以再恢复）。`, '撤销导入', true))) return;
    const k = await vault.bridge.undoImport(id);
    toast(`已把 ${k} 个条目移到回收站`);
    await vault.edited();
    await loadBatches();
  }

  async function doExport() {
    busy = true;
    error = '';
    try {
      if (exportFormat === 'csv' && !(await confirm('导出明文 CSV？', 'CSV 文件不加密，任何拿到文件的人都能看到全部密码。用完请立即删除。', '仍然导出', true))) return;
      const data = await vault.bridge.exportVault(exportFormat, exportPassword);
      const stamp = new Date().toISOString().slice(0, 10);
      const [ext, mime] = exportFormat === 'native' ? ['npwexport', 'application/octet-stream'] : exportFormat === 'kdbx' ? ['kdbx', 'application/octet-stream'] : ['csv', 'text/csv'];
      await vault.bridge.saveFile(`NyaPassword-${stamp}.${ext}`, data, mime);
      exportPassword = '';
      toast('已导出');
    } catch (e) {
      error = errorText(errorCode(e), errorMessage(e));
    } finally {
      busy = false;
    }
  }
</script>

<div class="page">
  <h2>导入</h2>
  {#if step === 'choose'}
    <p class="muted">支持：{SOURCES}。先解析并预览，确认后整批写入；之后可以一键撤销整次导入。</p>
    <label class="drop">
      <input type="file" hidden onchange={pick} accept=".json,.zip,.csv,.1pux,.kdbx" />
      {busy ? '解析中…' : '选择导出文件'}
    </label>
  {:else if step === 'password'}
    <p>“{file?.name}” 有密码保护。</p>
    <input class="input" type="password" bind:value={filePassword} placeholder="导出文件的密码" onkeydown={(e) => e.key === 'Enter' && parse()} />
    <div class="row" style="margin-top:10px"><button class="btn" onclick={() => (step = 'choose')}>返回</button><button class="btn primary" disabled={busy} onclick={parse}>解锁并解析</button></div>
  {:else if step === 'preview' && preview}
    <div class="stats">
      <div class="stat"><b>{preview.items.length}</b><span>个条目</span></div>
      {#each Object.entries(preview.counts) as [t, n] (t)}<div class="stat"><b>{n}</b><span>{vault.templates.find((x) => x.id === t)?.label ?? t}</span></div>{/each}
      <div class="stat"><b>{preview.passkeys}</b><span>通行密钥</span></div>
      <div class="stat"><b>{bytes(preview.attachment_bytes)}</b><span>附件</span></div>
    </div>
    {#if preview.skipped.length}<div class="banner small">跳过 {preview.skipped.length} 个：{preview.skipped.map(([t, r]) => `${t}（${r}）`).join('；')}</div>{/if}
    <div class="card tblwrap">
      <table class="tbl">
        <thead><tr><th>条目</th><th>类型</th><th>映射</th><th>说明</th></tr></thead>
        <tbody>
          {#each preview.items as it, i (i)}
            <tr>
              <td>{it.title}</td>
              <td>{vault.templates.find((x) => x.id === it.template)?.label ?? it.template}</td>
              <td><span class="badge {it.mapping === 'full' ? 'ok' : it.mapping === 'partial' ? 'warn' : 'bad'}">{it.mapping === 'full' ? '完整' : it.mapping === 'partial' ? '部分' : '兜底'}</span></td>
              <td class="small">{[it.passkeys ? `${it.passkeys} 个通行密钥` : '', it.attachments ? `${it.attachments} 个附件` : '', ...it.warnings].filter(Boolean).join('；')}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    <p class="muted small">“部分 / 兜底”的条目，无法对应的内容都放在“其他字段”分区或备注里，不会丢。</p>
    <div class="row">
      <label class="small muted">导入到
        <select class="select" style="width:auto" bind:value={vaultId}>{#each vault.vaults as v (v.id)}<option value={v.id}>{v.name}</option>{/each}</select>
      </label>
      <span class="spacer"></span>
      <button class="btn" onclick={() => { step = 'choose'; preview = null; }}>取消</button>
      <button class="btn primary" disabled={busy} onclick={commit}>{busy ? '导入中…' : `导入 ${preview.items.length} 个条目`}</button>
    </div>
  {:else if step === 'done' && result}
    <div class="banner {result.problems.length ? 'bad' : 'ok'}">
      <div>已导入 {result.imported} 个条目、{result.attachments} 个附件。
        {#if result.problems.length}逐条比对发现 {result.problems.length} 处差异：<ul>{#each result.problems as p (p)}<li>{p}</li>{/each}</ul>
        {:else}逐条比对：全部一致。{/if}</div>
    </div>
    <button class="btn" style="margin-top:10px" onclick={() => { step = 'choose'; result = null; }}>继续导入</button>
  {/if}
  {#if error}<div class="banner bad small" style="margin-top:10px">{error}</div>{/if}

  {#if batches.length}
    <h3>导入记录</h3>
    <div class="card">
      {#each batches as [id, src, at, n] (id)}
        <div class="row line"><span class="grow">{src} · {dateTime(at)} · {n} 个条目</span><button class="btn sm" onclick={() => undo(id, n)}>撤销</button></div>
      {/each}
    </div>
  {/if}

  <h2 style="margin-top:28px">导出</h2>
  <div class="formats">
    <label class:on={exportFormat === 'native'}><input type="radio" bind:group={exportFormat} value="native" /> <b>NyaPassword 加密导出</b><span>无损，含附件、通行密钥、历史；用主密码 + Secret Key 打开</span></label>
    <label class:on={exportFormat === 'kdbx'}><input type="radio" bind:group={exportFormat} value="kdbx" /> <b>KDBX 4（KeePassXC）</b><span>用主密码加密；没有本软件也能用 KeePassXC 打开</span></label>
    <label class:on={exportFormat === 'csv'}><input type="radio" bind:group={exportFormat} value="csv" /> <b>CSV（明文）</b><span>不加密，仅用于迁移到别的软件</span></label>
  </div>
  <div class="row" style="margin-top:10px">
    <input class="input" type="password" bind:value={exportPassword} placeholder="输入主密码确认" style="max-width:280px" />
    <button class="btn primary" disabled={busy || !exportPassword} onclick={doExport}>导出</button>
  </div>
</div>

<style>
  .page { padding: 22px 28px 40px; max-width: 920px; }
  h2 { margin: 0 0 6px; }
  h3 { margin: 22px 0 8px; font-size: 15px; }
  .drop { display: grid; place-items: center; height: 120px; border: 2px dashed var(--border); border-radius: 14px; color: var(--text-2); cursor: pointer; background: var(--surface); }
  .drop:hover { border-color: var(--accent); color: var(--accent); }
  .stats { display: flex; flex-wrap: wrap; gap: 10px; margin: 8px 0 12px; }
  .stat { border: 1px solid var(--border); border-radius: 10px; padding: 8px 12px; background: var(--surface); display: flex; flex-direction: column; min-width: 90px; }
  .stat b { font-size: 20px; }
  .stat span { font-size: 12px; color: var(--text-2); }
  .tblwrap { max-height: 380px; overflow: auto; margin: 10px 0; }
  .line { padding: 9px 14px; border-bottom: 1px solid var(--border); }
  .formats { display: grid; gap: 8px; }
  .formats label { display: grid; grid-template-columns: auto 1fr; gap: 2px 8px; border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px; background: var(--surface); cursor: pointer; }
  .formats label.on { border-color: var(--accent); background: var(--accent-2); }
  .formats span { grid-column: 2; font-size: 12.5px; color: var(--text-2); }
</style>
