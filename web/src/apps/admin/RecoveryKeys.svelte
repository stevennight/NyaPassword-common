<script lang="ts">
  import { api, type RecipientInfo } from './api';
  import { dateTime } from '$lib/i18n';
  import { confirm, toast } from '$lib/ui.svelte';
  import Modal from '$components/Modal.svelte';
  import Logo from '$components/Logo.svelte';
  import { admin, errMsg, loadBackup } from './store.svelte';
  import { generateIdentity, isRecipient, keyFileText, KEY_FILE_NAME, restoreCommand, type AgeKeyPair, type RestoreTarget } from './agekey';

  const b = $derived(admin.backup);
  const keys = $derived<RecipientInfo[]>(
    b ? b.settings.recipients.map((r) => b.settings.recipient_info?.find((i) => i.recipient === r) ?? { recipient: r, label: '', created_at: 0 }) : [],
  );
  const short = (r: string) => `${r.slice(0, 12)}…${r.slice(-6)}`;
  const today = () => new Date().toISOString().slice(0, 10);

  // ---- generating a key
  let gen = $state<{ label: string; pair: AgeKeyPair | null; createdAt: number; saved: boolean; downloaded: boolean } | null>(null);
  let busy = $state(false);

  const targets = $derived<RestoreTarget[]>(
    (b?.targets ?? []).map(({ target: t }) => ({ kind: t.kind, name: t.name, endpoint: t.endpoint, bucket: t.bucket, root: t.root, username: t.username })),
  );
  const sheet = $derived(
    gen?.pair ? { pair: gen.pair, label: gen.label, createdAt: gen.createdAt, server: location.origin, targets } : null,
  );

  function startGenerate() {
    gen = { label: `离线恢复密钥 ${today()}`, pair: null, createdAt: 0, saved: false, downloaded: false };
  }

  async function generate() {
    if (!gen) return;
    busy = true;
    try {
      gen.pair = await generateIdentity();
      gen.createdAt = Date.now();
    } catch (e) {
      toast(`生成失败：${errMsg(e)}`, 'error', 6000);
    } finally {
      busy = false;
    }
  }

  function download() {
    if (!sheet || !gen) return;
    const url = URL.createObjectURL(new Blob([keyFileText(sheet)], { type: 'text/plain;charset=utf-8' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = KEY_FILE_NAME;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    gen.downloaded = true;
  }

  async function closeGenerate() {
    if (gen?.pair && !(await confirm('放弃这把密钥？', '公钥还没有登记，关闭后这把私钥就作废了（备份不会加密给它）。', '放弃', true))) return;
    gen = null;
  }

  async function register() {
    if (!gen?.pair) return;
    busy = true;
    try {
      await api('POST', '/backup/recipients', { recipient: gen.pair.recipient, label: gen.label.trim() });
      gen = null; // drop the private key from memory
      toast('已登记：之后的备份都能用这把离线密钥解开', 'ok', 5000);
      await loadBackup();
    } catch (e) {
      toast(errMsg(e), 'error', 6000);
    } finally {
      busy = false;
    }
  }

  // ---- pasting an existing public key
  let pasteOpen = $state(false);
  let pasted = $state('');
  let pastedLabel = $state('');
  const pastedOk = $derived(isRecipient(pasted));

  async function addPasted() {
    if (!pastedOk) return;
    try {
      await api('POST', '/backup/recipients', { recipient: pasted.trim(), label: pastedLabel.trim() || `离线恢复密钥 ${today()}` });
      pasted = pastedLabel = '';
      pasteOpen = false;
      toast('已登记', 'ok');
      await loadBackup();
    } catch (e) {
      toast(errMsg(e), 'error', 6000);
    }
  }

  async function remove(k: RecipientInfo) {
    const last = keys.length === 1;
    const body = last
      ? '这是最后一把离线恢复密钥。删除后，新的备份只有服务器自己的密钥能解开：服务器整个丢失时，这些备份就无法恢复。已有的备份不受影响。'
      : '之后的备份不再加密给这把密钥；已有的备份仍然可以用它解开。';
    if (!(await confirm(`删除“${k.label || short(k.recipient)}”？`, body, '删除', true))) return;
    try {
      await api('DELETE', `/backup/recipients/${encodeURIComponent(k.recipient)}`);
      await loadBackup();
    } catch (e) {
      toast(errMsg(e), 'error');
    }
  }
</script>

<h2>恢复密钥</h2>
<p class="intro">每个备份都同时加密给<b>服务器自己的密钥</b>和你登记的<b>离线恢复密钥</b>。服务器自己的密钥和服务器在一起：服务器整个丢失（硬盘坏、被删、被入侵）时它也没了，只有离线恢复密钥还能解开备份。</p>

{#if b}
  <section class="card">
    <div class="row head"><h3 class="grow">离线恢复密钥</h3>
      <button class="btn primary" onclick={startGenerate}>生成离线恢复密钥</button></div>
    {#each keys as k (k.recipient)}
      <div class="row key">
        <span class="kicon">🔑</span>
        <div class="grow">
          <div><b>{k.label || '未命名的密钥'}</b></div>
          <div class="faint small"><span class="mono">{short(k.recipient)}</span> · {k.created_at ? `登记于 ${dateTime(k.created_at)}` : '较早登记（没有记录时间）'}</div>
        </div>
        <button class="btn sm ghost danger" onclick={() => remove(k)}>删除</button>
      </div>
    {:else}
      <div class="banner bad small nokey">还没有离线恢复密钥。现在的备份只有服务器自己的密钥能解开：服务器丢了，备份也就解不开了。点右上角生成一把，打印或存到 U 盘。</div>
    {/each}
    <details class="adv" bind:open={pasteOpen}>
      <summary class="small">高级：登记已有的公钥（age1…）</summary>
      <p class="faint small">已经用 <span class="mono">nyapassword-server age-keygen</span> 或 <span class="mono">age-keygen</span> 生成过密钥时，把公钥粘贴到这里。私钥自己保管好。</p>
      <div class="pasterow">
        <input class="input mono" bind:value={pasted} placeholder="age1…" spellcheck="false" />
        <input class="input" bind:value={pastedLabel} placeholder="标签（如：保险柜里的纸）" />
        <button class="btn" disabled={!pastedOk} onclick={addPasted}>登记</button>
      </div>
      {#if pasted && !pastedOk}<div class="err small">不是有效的 age 公钥（应以 age1 开头，共 62 个字符）</div>{/if}
    </details>
  </section>

  <section class="card">
    <h3>服务器自己的密钥</h3>
    <p class="small muted">自动生成，保存在服务器数据目录的 <span class="mono">server.key</span> 里，总会作为接收者，不需要也不能在这里管理。“备份校验”每周用它解开最新备份做检查。</p>
    <div class="mono small faint brk">{b.server_recipient}</div>
  </section>
{/if}

{#if gen}
  <Modal title="生成离线恢复密钥" onclose={closeGenerate} width={720}>
    {#if !gen.pair}
      <p class="small">密钥在<b>这个浏览器里</b>生成，私钥不会发送给服务器。生成后请下载或打印，再确认登记。</p>
      <label class="lbl" for="kl">标签<span class="faint">（写明放在哪里，方便以后找）</span></label>
      <input id="kl" class="input" bind:value={gen.label} />
      <div class="row foot"><span class="spacer"></span><button class="btn ghost" onclick={closeGenerate}>取消</button>
        <button class="btn primary" disabled={busy || !gen.label.trim()} onclick={generate}>{busy ? '生成中…' : '生成'}</button></div>
    {:else if sheet}
      <div class="sheet" id="recovery-sheet">
        <div class="row shead"><Logo size={32} /><div><h2>NyaPassword 备份恢复密钥</h2><div class="faint small">{gen.label} · 创建于 {dateTime(gen.createdAt)} · {sheet.server}</div></div></div>
        <p class="warn">服务器整个丢失时，只有这把私钥能解开备份。打印或存到 U 盘，和紧急恢复包放在一起；<b>不要只存在密码库或这台服务器上</b>。</p>
        <div class="lbl2">私钥（保密）</div>
        <div class="secret mono">{sheet.pair.identity}</div>
        <div class="lbl2">公钥（会登记到服务器）</div>
        <div class="mono small brk">{sheet.pair.recipient}</div>
        <div class="lbl2">恢复步骤</div>
        <ol class="small howto">
          <li>在新服务器上安装 nyapassword-server（Docker 镜像里已有），把上面的私钥存成文件 <span class="mono">{KEY_FILE_NAME}</span>（下载的文件可以直接用）。</li>
          <li>从备份目标直接恢复（目标的密码 / AccessKey Secret 用环境变量 <span class="mono">NYAPASSWORD_RESTORE_SECRET</span> 传）：
            {#each sheet.targets as t, i (i)}<div class="cmd mono">{restoreCommand(t)}</div>{/each}
            或用已下载的备份文件：<div class="cmd mono">{restoreCommand(null)}</div></li>
          <li>只想检查能不能解开：命令末尾加 <span class="mono">--dry-run</span>（只下载、解密、校验，不写入）。</li>
          <li>启动服务器；客户端下次同步时会自动对账，并把比备份新的内容重新上传。</li>
        </ol>
      </div>
      <div class="row foot wrapbtn">
        <button class="btn" onclick={download}>下载密钥文件</button>
        <button class="btn" onclick={() => window.print()}>打印 / 存为 PDF</button>
        {#if gen.downloaded}<span class="badge ok">已下载</span>{/if}
      </div>
      <label class="chk"><input type="checkbox" bind:checked={gen.saved} /> <span>我已保存这把私钥（已下载或打印），并且放在这台服务器以外的地方</span></label>
      <div class="row foot"><span class="spacer"></span><button class="btn ghost" onclick={closeGenerate}>放弃</button>
        <button class="btn primary" disabled={!gen.saved || busy} onclick={register}>{busy ? '登记中…' : '登记公钥'}</button></div>
    {/if}
  </Modal>
{/if}

<style>
  .intro { margin: 0 0 14px; color: var(--text-2); max-width: 760px; }
  section { padding: 12px 14px; margin-bottom: 14px; }
  h3 { margin: 0 0 6px; font-size: 14px; }
  .head { margin-bottom: 4px; flex-wrap: wrap; }
  .key { padding: 9px 0; border-top: 1px solid var(--border); }
  .kicon { font-size: 18px; }
  .nokey { margin: 6px 0; }
  .adv { margin-top: 10px; border-top: 1px solid var(--border); padding-top: 8px; }
  .adv summary { cursor: pointer; color: var(--text-2); }
  .adv p { margin: 6px 0; }
  .pasterow { display: grid; grid-template-columns: 2fr 1fr auto; gap: 8px; }
  .err { color: var(--bad); margin-top: 4px; }
  .brk { word-break: break-all; }
  p { margin: 4px 0 8px; }
  .foot { margin-top: 12px; }
  .wrapbtn { flex-wrap: wrap; }
  .chk { display: flex; gap: 8px; align-items: flex-start; margin-top: 12px; font-size: 13.5px; }
  .chk input { margin-top: 3px; }
  .sheet { border: 1px solid var(--border); border-radius: 12px; padding: 16px 18px; background: var(--surface); }
  .shead { gap: 12px; margin-bottom: 6px; }
  .sheet h2 { margin: 0; font-size: 17px; }
  .warn { background: var(--warn-bg); border-radius: 8px; padding: 8px 10px; font-size: 13px; }
  .lbl2 { color: var(--text-2); font-size: 12.5px; margin: 10px 0 3px; }
  .secret { font-size: 15px; word-break: break-all; color: var(--accent); background: var(--surface-2); padding: 8px 10px; border-radius: 8px; letter-spacing: .02em; }
  .howto { padding-left: 18px; margin: 4px 0 0; display: flex; flex-direction: column; gap: 6px; }
  .cmd { background: var(--surface-2); border-radius: 6px; padding: 5px 8px; margin: 4px 0; word-break: break-all; font-size: 12px; }
  @media (max-width: 600px) {
    .pasterow { grid-template-columns: 1fr; }
  }
  @media print {
    :global(body *) { visibility: hidden; }
    #recovery-sheet, #recovery-sheet :global(*) { visibility: visible; }
    #recovery-sheet { position: absolute; left: 0; top: 0; width: 100%; border: none; color: #000; background: #fff; }
  }
</style>
