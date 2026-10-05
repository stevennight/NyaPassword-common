<script lang="ts">
  // "添加目标": choose a type → fill in the fields → test the connection → save.
  // Editing an existing target starts at the fields.
  import { untrack } from 'svelte';
  import { api, type BackupTarget, type TestStep } from './api';
  import { toast } from '$lib/ui.svelte';
  import Modal from '$components/Modal.svelte';
  import { errMsg, loadBackup } from './store.svelte';
  import TestResult from './TestResult.svelte';

  let { target, onclose }: { target: BackupTarget | null; onclose: () => void } = $props();

  type Kind = BackupTarget['kind'];
  // the wizard edits its own copy; the target passed in is only the starting point
  const initial = untrack(() => target);
  const isNew = !initial;
  let step = $state(initial ? 2 : 1);
  let t = $state<BackupTarget>(initial ? { ...initial, secret: '' } : blank('oss'));
  let steps = $state<TestStep[] | null>(null);
  let testing = $state(false);
  let saving = $state(false);
  let error = $state('');

  function blank(kind: Kind): BackupTarget {
    return {
      id: crypto.randomUUID(),
      kind,
      name: kind === 'oss' ? '阿里云 OSS' : kind === 'webdav' ? 'WebDAV' : 'NAS 目录',
      enabled: true,
      protect_mode: kind === 'oss',
      endpoint: kind === 'oss' ? 'https://oss-cn-hangzhou.aliyuncs.com' : '',
      bucket: '',
      root: 'nyapassword',
      username: '',
      secret: '',
      has_secret: false,
    };
  }

  const TYPES: { kind: Kind; title: string; text: string }[] = [
    { kind: 'oss', title: '阿里云 OSS', text: '对象存储。推荐：可以开防删模式，服务器被入侵也删不掉历史备份。' },
    { kind: 'webdav', title: 'WebDAV', text: '坚果云、NAS 自带的 WebDAV、Nextcloud 等。' },
    { kind: 'fs', title: '服务器上的目录', text: '服务器能访问的文件夹，如挂载的 NAS。Docker 部署时要先把目录映射进容器。' },
  ];

  function choose(kind: Kind) {
    t = blank(kind);
    steps = null;
    step = 2;
  }

  /** What is missing before the target can be tested. */
  const missing = $derived.by(() => {
    if (!t.name.trim()) return '请填写名称';
    if (!t.endpoint.trim()) return t.kind === 'fs' ? '请填写目录' : '请填写地址';
    if (t.kind !== 'fs' && !/^https?:\/\//.test(t.endpoint.trim())) return '地址要以 https:// 开头';
    if (t.kind === 'fs' && !/^(\/|[A-Za-z]:[\\/])/.test(t.endpoint.trim())) return '目录要写绝对路径（如 /backup）';
    if (t.kind === 'oss' && !t.bucket.trim()) return '请填写 Bucket 名称';
    if (t.kind !== 'fs' && !t.username.trim()) return t.kind === 'oss' ? '请填写 AccessKey ID' : '请填写用户名';
    if (t.kind !== 'fs' && !t.secret && !t.has_secret) return t.kind === 'oss' ? '请填写 AccessKey Secret' : '请填写密码';
    return '';
  });
  const passed = $derived(!!steps && steps.length === 3 && steps.every((s) => s.ok || s.expected_to_fail));

  async function runTest() {
    if (missing) return (error = missing);
    error = '';
    step = 3;
    testing = true;
    steps = null;
    try {
      steps = (await api<{ steps: TestStep[] }>('POST', '/backup/test-target', { ...t, endpoint: t.endpoint.trim() })).steps;
    } catch (e) {
      error = errMsg(e);
    } finally {
      testing = false;
    }
  }

  async function save() {
    saving = true;
    try {
      await api('PUT', `/backup/targets/${t.id}`, { ...t, endpoint: t.endpoint.trim() });
      toast(isNew ? '备份目标已添加' : '已保存', 'ok');
      await loadBackup();
      onclose();
    } catch (e) {
      error = errMsg(e);
    } finally {
      saving = false;
    }
  }
</script>

<Modal title={isNew ? '添加备份目标' : `编辑：${initial?.name}`} {onclose} width={600}>
  <ol class="steps">
    {#each ['选择类型', '填写', '测试连接', '保存'] as s, i (s)}
      <li class:on={step === i + 1} class:done={step > i + 1 || (i === 3 && passed)}>{i + 1}. {s}</li>
    {/each}
  </ol>

  {#if step === 1}
    <div class="types">
      {#each TYPES as ty (ty.kind)}
        <button class="type card" onclick={() => choose(ty.kind)}><b>{ty.title}</b><span class="small muted">{ty.text}</span></button>
      {/each}
    </div>
  {:else if step === 2}
    <label class="lbl" for="tn">名称<span class="hint">只用来在后台区分目标</span></label>
    <input id="tn" class="input" bind:value={t.name} />
    {#if t.kind === 'oss'}
      <label class="lbl" for="te">Endpoint（地域节点）<span class="hint">OSS 控制台 → Bucket → 概览 → 访问端口，外网或内网地址</span></label>
      <input id="te" class="input mono" bind:value={t.endpoint} placeholder="https://oss-cn-hangzhou.aliyuncs.com" spellcheck="false" />
      <label class="lbl" for="tb">Bucket<span class="hint">建议单独建一个，开版本控制</span></label>
      <input id="tb" class="input mono" bind:value={t.bucket} placeholder="example-backup" spellcheck="false" />
    {:else if t.kind === 'webdav'}
      <label class="lbl" for="te">WebDAV 地址<span class="hint">坚果云：https://dav.jianguoyun.com/dav/</span></label>
      <input id="te" class="input mono" bind:value={t.endpoint} placeholder="https://dav.example.com/dav/" spellcheck="false" />
    {:else}
      <label class="lbl" for="te">目录（服务器上的绝对路径）<span class="hint">Docker：先在 compose 里把 NAS 目录映射到容器，如 /backup</span></label>
      <input id="te" class="input mono" bind:value={t.endpoint} placeholder="/backup" spellcheck="false" />
    {/if}
    <label class="lbl" for="tr">子目录<span class="hint">备份放在这个目录下；多个服务器共用一个存储时各用一个</span></label>
    <input id="tr" class="input mono" bind:value={t.root} spellcheck="false" />
    {#if t.kind !== 'fs'}
      <div class="two">
        <div>
          <label class="lbl" for="tu">{t.kind === 'oss' ? 'AccessKey ID' : '用户名'}</label>
          <input id="tu" class="input mono" bind:value={t.username} autocomplete="off" spellcheck="false" />
        </div>
        <div>
          <label class="lbl" for="ts">{t.kind === 'oss' ? 'AccessKey Secret' : '密码 / 应用密码'}</label>
          <input id="ts" class="input" type="password" bind:value={t.secret} placeholder={t.has_secret ? '已设置，留空则不修改' : ''} autocomplete="new-password" />
        </div>
      </div>
      <p class="faint small">{t.kind === 'oss' ? '建议用 RAM 子账号，只授 oss:PutObject、oss:GetObject、oss:ListObjects，并只限这个 Bucket。' : '坚果云要用“第三方应用管理”里生成的应用密码，不是登录密码。'}密钥加密保存在服务器上，之后只写不读。</p>
    {/if}
    <label class="chk"><input type="checkbox" bind:checked={t.protect_mode} />
      <span><b>防删模式</b><br /><span class="small muted">凭据只能写不能删，旧备份由存储端的生命周期规则清理，服务器不做清理。{t.kind === 'oss' ? '推荐：配合 Bucket 版本控制或合规保留策略。' : 'WebDAV 和目录通常做不到“只写不删”，一般不需要开。'}</span></span></label>
    <label class="chk"><input type="checkbox" bind:checked={t.enabled} /> <span>启用（自动备份写到这个目标）</span></label>
  {:else}
    <p class="small muted">写入一个探测文件、读回比对、再删除它{t.protect_mode ? '（防删模式下删除失败才是对的）' : ''}。</p>
    {#if testing}<p>正在测试…</p>
    {:else if steps}
      <TestResult {steps} inline />
      {#if passed}<div class="banner ok small" style="margin-top:10px">连接正常，可以保存。</div>
      {:else}<div class="banner bad small" style="margin-top:10px">连接测试没有通过。返回修改，或者先保存稍后再测试。</div>{/if}
    {/if}
  {/if}

  {#if error}<div class="banner bad small" style="margin-top:10px">{error}</div>{/if}

  <div class="row foot">
    {#if step === 2 && isNew}<button class="btn" onclick={() => (step = 1)}>‹ 上一步</button>{/if}
    {#if step === 3}<button class="btn" onclick={() => (step = 2)} disabled={testing}>‹ 返回修改</button>{/if}
    <span class="spacer"></span>
    <button class="btn ghost" onclick={onclose}>取消</button>
    {#if step === 2}
      <button class="btn primary" onclick={runTest}>测试连接 ›</button>
    {:else if step === 3 && !testing}
      {#if passed}<button class="btn primary" onclick={save} disabled={saving}>保存</button>
      {:else}<button class="btn" onclick={runTest}>重新测试</button><button class="btn danger" onclick={save} disabled={saving}>仍然保存</button>{/if}
    {/if}
  </div>
</Modal>

<style>
  .steps { display: flex; gap: 6px; list-style: none; padding: 0; margin: 0 0 12px; flex-wrap: wrap; }
  .steps li { font-size: 12px; padding: 2px 9px; border-radius: 999px; background: var(--surface-2); color: var(--text-3); }
  .steps li.on { background: var(--accent-2); color: var(--accent); font-weight: 600; }
  .steps li.done { color: var(--ok); }
  .types { display: grid; gap: 10px; }
  .type { display: flex; flex-direction: column; gap: 3px; align-items: flex-start; text-align: left; padding: 12px 14px; cursor: pointer; }
  .type:hover { border-color: var(--accent); background: var(--surface-2); }
  .hint { color: var(--text-3); margin-left: 8px; font-size: 12px; }
  .two { display: grid; grid-template-columns: 1fr 1fr; gap: 0 10px; }
  .chk { display: flex; gap: 8px; align-items: flex-start; margin-top: 12px; font-size: 13.5px; }
  .chk input { margin-top: 3px; }
  p { margin: 8px 0 0; }
  .foot { margin-top: 16px; flex-wrap: wrap; }
  @media (max-width: 520px) {
    .two { grid-template-columns: 1fr; }
    .hint { display: block; margin-left: 0; }
  }
</style>
