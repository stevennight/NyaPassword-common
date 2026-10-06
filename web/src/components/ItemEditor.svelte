<script lang="ts">
  import { onMount } from 'svelte';
  import { vault } from '$lib/vault.svelte';
  import { confirm, toast } from '$lib/ui.svelte';
  import { bytes } from '$lib/i18n';
  import type { Field, ItemContent } from '$lib/types';
  import { desktopApi } from '$lib/desktop';
  import Generator from './Generator.svelte';
  import RepromptGate from './RepromptGate.svelte';

  // desktop-only parts: the auto-type sequence of Quick Access
  const desktop = desktopApi(vault.bridge);
  let { vaultId, itemId }: { vaultId: string; itemId: string | null } = $props();
  let c = $state<ItemContent | null>(null);
  let tagsText = $state('');
  let busy = $state(false);
  let genFor = $state<string | null>(null);
  let showAdd = $state(false);
  let dirty = $state(false);
  let reveal = $state<Record<string, boolean>>({});
  /** The saved item asks for verification ("使用前需要验证"); editing shows its secrets. */
  let savedReprompt = $state(false);
  const locked = $derived(!!itemId && vault.gated({ vault_id: vaultId, item_id: itemId, reprompt: savedReprompt }));

  const KINDS: [string, string][] = [
    ['text', '文本'], ['concealed', '密文'], ['multiline', '多行文本'], ['pin', '数字密码（PIN）'], ['totp', '一次性密码（TOTP）'],
    ['email', '邮箱'], ['phone', '电话'], ['url', '网址'], ['date', '日期'], ['month_year', '年月'], ['number', '数字'], ['boolean', '是 / 否'],
  ];
  const MATCHES: [string, string][] = [['domain', '域名'], ['host', '主机'], ['starts_with', '前缀'], ['exact', '完全一致'], ['regex', '正则'], ['never', '从不填写']];

  onMount(async () => {
    try {
      if (itemId) {
        const v = await vault.bridge.item(vaultId, itemId);
        savedReprompt = !!v.reprompt;
        c = structuredClone($state.snapshot(v.content!)) as ItemContent;
      } else {
        c = await vault.bridge.newItem(vault.newTemplate);
        if (c.template === 'login') c.urls = [];
      }
      tagsText = (c.tags ?? []).join(', ');
      setTimeout(() => document.getElementById('ed-title')?.focus(), 0);
    } catch (e) {
      vault.fail(e);
      vault.editing = null;
    }
  });

  function mark() {
    dirty = true;
  }

  function fieldValue(f: Field): string {
    return typeof f.value === 'string' ? f.value : f.value == null ? '' : JSON.stringify(f.value);
  }

  function addField(kind: string, label: string, multiline = false, preset?: Field) {
    if (!c) return;
    const f: Field = preset ? { ...structuredClone($state.snapshot(preset)), id: vault.bridge.newShortId('f') } : { id: vault.bridge.newShortId('f'), label, kind, value: '' };
    if (multiline) f.multiline = true;
    c.fields.push(f);
    showAdd = false;
    mark();
    setTimeout(() => document.getElementById(`lbl-${f.id}`)?.focus(), 0);
  }

  function addSection() {
    if (!c) return;
    const id = vault.bridge.newShortId('s');
    c.sections = [...(c.sections ?? []), { id, label: '新分区' }];
    mark();
  }

  function removeSection(id: string) {
    if (!c) return;
    c.sections = (c.sections ?? []).filter((s) => s.id !== id);
    for (const f of c.fields) if (f.section === id) delete f.section;
    mark();
  }

  async function removeAttachment(id: string, name: string) {
    if (!c || !itemId) return;
    if (!(await confirm('移除附件？', `“${name}”会从条目中移除（旧版本里仍然有）。`, '移除', true))) return;
    c.attachments = (c.attachments ?? []).filter((a) => a.id !== id);
    mark();
  }

  async function addAttachment(e: Event) {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    input.value = '';
    if (!file || !itemId) return;
    if (file.size > 100 * 1024 * 1024) return toast('附件不能超过 100 MB', 'error');
    busy = true;
    try {
      await save(false);
      await vault.bridge.addAttachment(vaultId, itemId, file.name, file.type || 'application/octet-stream', new Uint8Array(await file.arrayBuffer()));
      const v = await vault.bridge.item(vaultId, itemId);
      c = structuredClone($state.snapshot(v.content!)) as ItemContent;
      toast(`已添加附件 ${file.name}`);
      await vault.edited();
    } catch (err) {
      vault.fail(err);
    } finally {
      busy = false;
    }
  }

  async function save(close = true) {
    if (!c) return;
    const seq = c.autofill?.auto_type;
    if (desktop && typeof seq === 'string' && seq.trim()) {
      try {
        await desktop.checkAutoType(seq);
      } catch (e) {
        return vault.fail(e);
      }
    }
    c.tags = tagsText.split(/[,，]/).map((t) => t.trim()).filter(Boolean);
    c.urls = (c.urls ?? []).filter((u) => u.url.trim());
    busy = true;
    try {
      const id = await vault.bridge.saveItem(vaultId, itemId, $state.snapshot(c) as ItemContent);
      dirty = false;
      if (close) {
        // read the props before closing: they come from `vault.editing`, which is null afterwards
        vault.selected = { vault_id: vaultId, item_id: id };
        vault.editing = null;
        toast('已保存');
      }
      await vault.edited();
    } catch (e) {
      vault.fail(e);
    } finally {
      busy = false;
    }
  }

  async function cancel() {
    if (dirty && !(await confirm('放弃修改？', '尚未保存的修改会丢失。', '放弃', true))) return;
    vault.editing = null;
  }

  const secretKinds = ['concealed', 'pin'];
  const ADDRESS_PARTS: [string, string][] = [['province', '省'], ['city', '市'], ['district', '区'], ['street', '详细地址'], ['postal_code', '邮编'], ['country', '国家']];
</script>

<svelte:window onkeydown={(e) => { if (locked) { if (e.key === 'Escape') vault.editing = null; return; } if ((e.ctrlKey || e.metaKey) && e.key === 's') { e.preventDefault(); void save(); } if (e.key === 'Escape' && !genFor && !showAdd) void cancel(); }} />

{#if c && locked && itemId}
  <div class="ed">
    <div class="bar"><h2 class="grow gate-title">{c.title || '（无标题）'}</h2><button class="btn" onclick={() => (vault.editing = null)}>取消</button></div>
    <RepromptGate {vaultId} {itemId} what="编辑这个条目" />
  </div>
{:else if c}
  <div class="ed">
    <div class="bar">
      <input id="ed-title" class="title" bind:value={c.title} oninput={mark} placeholder="标题" />
      <label class="fav"><input type="checkbox" bind:checked={c.favorite} onchange={mark} /> 收藏</label>
      <button class="btn" onclick={cancel}>取消</button>
      <button class="btn primary" disabled={busy} onclick={() => save()}>保存（Ctrl+S）</button>
    </div>

    {#each [{ id: '', label: '' }, ...(c.sections ?? [])] as sec (sec.id)}
      <div class="card group">
        {#if sec.id}
          <div class="sec-h row">
            <input class="sec-name" value={sec.label} oninput={(e) => { const s = c!.sections!.find((x) => x.id === sec.id); if (s) s.label = (e.target as HTMLInputElement).value; mark(); }} />
            <button class="btn ghost sm" onclick={() => removeSection(sec.id)}>删除分区</button>
          </div>
        {/if}
        {#each c.fields.filter((f) => (f.section ?? '') === sec.id) as f (f.id)}
          <div class="frow">
            <input id="lbl-{f.id}" class="flabel" bind:value={f.label} oninput={mark} placeholder="字段名" />
            <div class="fval">
              {#if f.kind === 'address'}
                {@const a = (f.value && typeof f.value === 'object' ? f.value : {}) as Record<string, string>}
                <div class="addr">
                  {#each ADDRESS_PARTS as [k, l] (k)}
                    <input class="input" placeholder={l} value={a[k] ?? ''} oninput={(e) => { f.value = { ...a, [k]: (e.target as HTMLInputElement).value }; mark(); }} />
                  {/each}
                </div>
              {:else if f.multiline || f.kind === 'multiline'}
                <textarea class="textarea" class:mono={secretKinds.includes(f.kind)} class:masked={secretKinds.includes(f.kind) && !reveal[f.id]} rows="4"
                  value={fieldValue(f)} oninput={(e) => { f.value = (e.target as HTMLTextAreaElement).value; mark(); }}></textarea>
              {:else if f.kind === 'boolean'}
                <label><input type="checkbox" checked={f.value === 'true'} onchange={(e) => { f.value = (e.target as HTMLInputElement).checked ? 'true' : 'false'; mark(); }} /> 是</label>
              {:else}
                <input class="input" class:mono={secretKinds.includes(f.kind) || f.kind === 'totp'}
                  type={secretKinds.includes(f.kind) && !reveal[f.id] ? 'password' : f.kind === 'date' ? 'date' : f.kind === 'month_year' ? 'month' : f.kind === 'email' ? 'email' : 'text'}
                  inputmode={f.kind === 'pin' || f.kind === 'number' ? 'numeric' : undefined}
                  placeholder={f.kind === 'totp' ? 'otpauth://… 或密钥' : ''} value={fieldValue(f)} autocomplete="off"
                  oninput={(e) => { f.value = (e.target as HTMLInputElement).value; mark(); }} />
              {/if}
            </div>
            <div class="ftools">
              {#if secretKinds.includes(f.kind)}
                <button class="btn ghost sm" title="显示" onclick={() => (reveal[f.id] = !reveal[f.id])}>{reveal[f.id] ? '🙈' : '👁'}</button>
                <button class="btn ghost sm" title="生成" onclick={() => (genFor = f.id)}>⚿</button>
              {/if}
              <select class="kind" value={f.kind} onchange={(e) => { f.kind = (e.target as HTMLSelectElement).value; mark(); }} title="字段类型">
                {#each KINDS as [k, l] (k)}<option value={k}>{l}</option>{/each}
                {#if !KINDS.some(([k]) => k === f.kind)}<option value={f.kind}>{f.kind}</option>{/if}
              </select>
              {#if c.sections?.length}
                <select class="kind" value={f.section ?? ''} onchange={(e) => { const v = (e.target as HTMLSelectElement).value; if (v) f.section = v; else delete f.section; mark(); }} title="分区">
                  <option value="">（无分区）</option>
                  {#each c.sections as s (s.id)}<option value={s.id}>{s.label}</option>{/each}
                </select>
              {/if}
              <button class="btn ghost sm" title="删除字段" onclick={() => { c!.fields = c!.fields.filter((x) => x.id !== f.id); mark(); }}>✕</button>
            </div>
          </div>
        {/each}
      </div>
    {/each}

    <div class="row adds">
      <div class="addwrap">
        <button class="btn" onclick={() => (showAdd = !showAdd)}>＋ 添加字段</button>
        {#if showAdd}
          <div class="menu">
            {#each KINDS as [k, l] (k)}<button onclick={() => addField(k, l)}>{l}</button>{/each}
            <button onclick={() => addField('concealed', '多行密文', true)}>多行密文（恢复码、私钥）</button>
            <hr />
            {#each vault.bridge.fieldPresets() as p (p.id)}<button onclick={() => addField(p.kind, p.label, p.multiline, p)}>{p.label}</button>{/each}
          </div>
        {/if}
      </div>
      <button class="btn" onclick={addSection}>＋ 添加分区</button>
    </div>

    <div class="card group">
      <div class="sec-h">网站与应用</div>
      {#each c.urls ?? [] as u, i (u.id)}
        <div class="frow">
          <input class="input grow" bind:value={u.url} oninput={mark} placeholder="https://example.com 或 androidapp://包名" />
          <select class="kind" bind:value={u.match} onchange={mark}>{#each MATCHES as [k, l] (k)}<option value={k}>{l}</option>{/each}</select>
          <button class="btn ghost sm" onclick={() => { c!.urls!.splice(i, 1); mark(); }}>✕</button>
        </div>
      {/each}
      <div class="pad"><button class="btn sm" onclick={() => { c!.urls = [...(c!.urls ?? []), { id: vault.bridge.newShortId('u'), url: '', match: 'domain' }]; mark(); }}>＋ 网址</button>
        <label class="small muted chk"><input type="checkbox" checked={!!c.autofill?.never} onchange={(e) => { c!.autofill = { ...(c!.autofill ?? {}), never: (e.target as HTMLInputElement).checked }; mark(); }} /> 不要自动填充这个条目</label></div>
    </div>

    <div class="card group">
      <div class="sec-h">使用前验证</div>
      <div class="pad col">
        <label class="small chk"><input id="ed-reprompt" type="checkbox" checked={!!c.reprompt} onchange={(e) => { if ((e.target as HTMLInputElement).checked) c!.reprompt = true; else delete c!.reprompt; mark(); }} /> 使用前需要验证（主密码 / Windows Hello / 指纹）</label>
        <span class="faint small">查看、复制、填写这个条目的密码等内容前，都要再次验证身份。防的是别人趁你离开时使用已解锁的设备；条目的加密方式不变。</span>
      </div>
    </div>

    {#if c.template === 'ssh_key' || c.ssh}
      <div class="card group">
        <div class="sec-h">SSH agent（桌面端）</div>
        <div class="pad col">
          <label class="small chk"><input type="checkbox" checked={c.ssh?.agent !== false} onchange={(e) => { const { agent: _a, ...rest } = c!.ssh ?? {}; c!.ssh = (e.target as HTMLInputElement).checked ? rest : { ...rest, agent: false }; mark(); }} /> 提供给桌面端的 SSH agent</label>
          <label class="small chk"><input type="checkbox" checked={c.ssh?.confirm_each_use !== false} onchange={(e) => { c!.ssh = { ...(c!.ssh ?? {}), confirm_each_use: (e.target as HTMLInputElement).checked }; mark(); }} /> 每次签名都确认（关闭后每次解锁只确认一次）</label>
        </div>
      </div>
    {/if}

    {#if desktop && c.fields.some((f) => f.purpose === 'username' || f.purpose === 'password')}
      <div class="card group">
        <div class="sec-h">自动输入（桌面端快捷搜索）</div>
        <div class="pad col">
          <input class="input mono" value={typeof c.autofill?.auto_type === 'string' ? c.autofill.auto_type : ''} placeholder={'{USERNAME}{TAB}{PASSWORD}{ENTER}'} spellcheck="false"
            oninput={(e) => { const v = (e.target as HTMLInputElement).value; const { auto_type: _t, ...rest } = c!.autofill ?? {}; c!.autofill = v.trim() ? { ...rest, auto_type: v } : rest; mark(); }} />
          <span class="faint small">留空使用默认序列。可用 {'{USERNAME} {PASSWORD} {TOTP} {TAB} {ENTER} {SPACE} {DELAY 500} {S:字段名}'}，其他文字原样输入。</span>
        </div>
      </div>
    {/if}

    {#if c.passkeys?.length}
      <div class="card group">
        <div class="sec-h">通行密钥</div>
        {#each c.passkeys as p, i (p.id)}
          <div class="frow"><span class="grow">{p.rp_id} · {p.user_name}</span>
            <button class="btn ghost sm danger" onclick={async () => { if (await confirm('删除通行密钥？', `删除后需要在 ${p.rp_id} 上重新创建。`, '删除', true)) { c!.passkeys!.splice(i, 1); mark(); } }}>删除</button></div>
        {/each}
      </div>
    {/if}

    <div class="card group">
      <div class="sec-h">附件</div>
      {#each c.attachments ?? [] as a (a.id)}
        <div class="frow"><span class="grow">📎 {a.name}</span><span class="faint small">{bytes(a.size)}</span><button class="btn ghost sm" onclick={() => removeAttachment(a.id, a.name)}>✕</button></div>
      {/each}
      <div class="pad">
        {#if itemId}<label class="btn sm">＋ 添加附件<input type="file" hidden onchange={addAttachment} /></label>
        {:else}<span class="faint small">先保存条目，再添加附件</span>{/if}
      </div>
    </div>

    <label class="lbl" for="ed-tags">标签（逗号分隔，“工作/开发”表示嵌套）</label>
    <input id="ed-tags" class="input" bind:value={tagsText} oninput={mark} />
    <label class="lbl" for="ed-notes">备注</label>
    <textarea id="ed-notes" class="textarea" rows="5" bind:value={c.notes} oninput={mark}></textarea>
  </div>

  {#if genFor}
    <Generator onclose={() => (genFor = null)} onuse={(pw) => { const f = c!.fields.find((x) => x.id === genFor); if (f) { f.value = pw; reveal[f.id] = true; mark(); } genFor = null; }} />
  {/if}
{/if}

<style>
  .ed { padding: 18px 24px 40px; max-width: 900px; }
  .bar { display: flex; gap: 8px; align-items: center; margin-bottom: 14px; position: sticky; top: 0; background: var(--bg); padding: 6px 0; z-index: 2; }
  .title { flex: 1; font-size: 19px; font-weight: 600; border: 1px solid transparent; border-radius: 8px; padding: 6px 8px; background: transparent; outline: none; min-width: 0; }
  .title:focus { border-color: var(--accent); background: var(--surface); }
  .gate-title { margin: 0; font-size: 19px; word-break: break-word; }
  .fav { display: flex; gap: 4px; align-items: center; font-size: 13px; color: var(--text-2); }
  .group { margin-bottom: 12px; }
  .sec-h { padding: 7px 14px; font-size: 11.5px; font-weight: 600; color: var(--text-3); background: var(--surface-2); border-bottom: 1px solid var(--border); }
  .sec-name { border: 1px solid transparent; background: transparent; font-weight: 600; color: var(--text-2); padding: 2px 4px; flex: 1; }
  .sec-name:focus { border-color: var(--accent); outline: none; }
  .frow { display: flex; gap: 8px; align-items: flex-start; padding: 8px 12px; border-bottom: 1px solid var(--border); }
  .frow:last-child { border-bottom: 0; }
  .flabel { width: 140px; flex: none; border: 1px solid transparent; background: transparent; color: var(--text-2); font-size: 13px; padding: 8px 4px; outline: none; }
  .flabel:focus { border-color: var(--accent); border-radius: 6px; }
  .fval { flex: 1; min-width: 0; }
  .ftools { display: flex; gap: 2px; align-items: center; }
  .kind { border: 1px solid var(--border); background: var(--surface-2); border-radius: 6px; font-size: 12px; padding: 4px; max-width: 120px; }
  .addr { display: grid; grid-template-columns: repeat(3, 1fr); gap: 6px; }
  .masked { -webkit-text-security: disc; }
  .adds { margin: 4px 0 14px; }
  .addwrap { position: relative; }
  .menu { position: absolute; top: 100%; left: 0; margin-top: 4px; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; box-shadow: var(--shadow); padding: 6px; z-index: 5; min-width: 220px; display: flex; flex-direction: column; }
  .menu button { border: 0; background: none; text-align: left; padding: 6px 10px; border-radius: 6px; }
  .menu button:hover { background: var(--sel); }
  .menu hr { border: 0; border-top: 1px solid var(--border); margin: 4px 0; width: 100%; }
  .pad { padding: 8px 12px; display: flex; gap: 12px; align-items: center; }
  .chk { display: flex; gap: 6px; align-items: center; }
  .col { flex-direction: column; align-items: stretch; gap: 6px; }
  @media (max-width: 760px) { .frow { flex-wrap: wrap; } .flabel { width: 100%; } .addr { grid-template-columns: 1fr 1fr; } }
</style>
