<script lang="ts">
  import { api, SECRET_MASK, type AlertEvent, type Channel, type NotifyConfig } from './api';
  import { toast } from '$lib/ui.svelte';
  import { admin, errMsg, saveSettings } from './store.svelte';
  import { channelConfigured, CHANNELS } from './checks';

  type Field = { key: keyof NotifyConfig; label: string; hint?: string; placeholder?: string; secret?: boolean; number?: boolean; wide?: boolean };
  const INFO: Record<Channel, { name: string; text: string; fields: Field[] }> = {
    webhook: {
      name: 'Webhook',
      text: '向一个地址 POST JSON：{"title", "message", "source": "nyapassword"}。适合接企业微信 / 钉钉 / 飞书机器人的中转、Home Assistant、自建脚本。',
      fields: [{ key: 'webhook_url', label: 'URL', placeholder: 'https://hooks.example.com/nyapassword', wide: true, hint: '地址里可能含密钥，管理后台会原样显示' }],
    },
    telegram: {
      name: 'Telegram',
      text: '用你自己的机器人发消息：找 @BotFather 创建机器人得到 Token；给机器人发一条消息后，用 getUpdates 查到自己的 Chat ID。',
      fields: [
        { key: 'telegram_bot_token', label: 'Bot Token', placeholder: '123456:ABC…', secret: true },
        { key: 'telegram_chat_id', label: 'Chat ID', placeholder: '123456789' },
      ],
    },
    bark: {
      name: 'Bark',
      text: 'iPhone 上的推送应用。打开 Bark，复制首页上的地址（含你的 key）。',
      fields: [{ key: 'bark_url', label: 'Bark 地址', placeholder: 'https://api.day.app/你的key', wide: true }],
    },
    email: {
      name: '邮件（SMTP）',
      text: '用邮箱的 SMTP 发信。QQ / 网易邮箱要在网页版设置里开启 SMTP 并生成授权码，密码处填授权码。',
      fields: [
        { key: 'smtp_host', label: 'SMTP 服务器', placeholder: 'smtp.example.com' },
        { key: 'smtp_port', label: '端口', placeholder: '465', number: true, hint: '465 直接 TLS，587 用 STARTTLS' },
        { key: 'smtp_username', label: '用户名', placeholder: 'me@example.com' },
        { key: 'smtp_password', label: '密码 / 授权码', secret: true },
        { key: 'smtp_from', label: '发件人', placeholder: '留空则用用户名', hint: '可写成 NyaPassword <me@example.com>' },
        { key: 'smtp_to', label: '收件人', placeholder: 'me@example.com', hint: '多个用逗号分隔' },
      ],
    },
  };
  const EVENTS: [AlertEvent, string, string][] = [
    ['backup_failed', '备份失败', '某个目标写入或读回校验失败，包括目标连不上'],
    ['check_failed', '备份校验失败', '每周自动校验解不开或数据不完整'],
    ['stale', '太久没有成功备份', '超过 26 小时没有一次成功的备份（每天最多提醒一次）'],
  ];

  const stored = $derived(admin.backup?.settings.notify);
  // the form: a copy of the saved settings, edited per channel
  let n = $state<NotifyConfig | null>(null);
  let open = $state<Channel | null>(null);
  let busy = $state('');

  $effect(() => {
    if (stored && !n) n = { ...$state.snapshot(stored) } as NotifyConfig;
  });

  const isOn = (c: Channel) => !!stored && channelConfigured(stored, c) && !(stored.off ?? []).includes(c);

  /** The saved settings with this channel's fields taken from the form. */
  function withChannel(c: Channel, base: NotifyConfig): NotifyConfig {
    const out = { ...base };
    for (const f of INFO[c].fields) (out as unknown as Record<string, unknown>)[f.key] = n![f.key];
    return out;
  }

  async function save(c: Channel) {
    if (!n || !stored) return;
    busy = `save-${c}`;
    const ok = await saveSettings((s) => (s.notify = withChannel(c, s.notify)), `${INFO[c].name} 已保存`);
    busy = '';
    if (ok) resetFromStored(c);
  }

  function resetFromStored(c: Channel) {
    if (!n || !admin.backup) return;
    for (const f of INFO[c].fields) (n as unknown as Record<string, unknown>)[f.key] = admin.backup.settings.notify[f.key];
  }

  async function clear(c: Channel) {
    if (!n) return;
    for (const f of INFO[c].fields) (n as unknown as Record<string, unknown>)[f.key] = f.number ? 0 : '';
    await save(c);
  }

  async function toggle(c: Channel, on: boolean) {
    await saveSettings((s) => {
      const off = new Set(s.notify.off ?? []);
      if (on) off.delete(c);
      else off.add(c);
      s.notify.off = [...off];
    }, on ? `${INFO[c].name} 已开启` : `${INFO[c].name} 已关闭`);
  }

  async function test(c: Channel) {
    if (!n || !stored) return;
    busy = `test-${c}`;
    try {
      const r = await api<{ failed: string[] }>('POST', '/notify/test', { channel: c, notify: withChannel(c, $state.snapshot(stored) as NotifyConfig) });
      toast(r.failed.length ? `发送失败：${r.failed.join('；')}` : `已通过 ${INFO[c].name} 发送测试通知，请查收`, r.failed.length ? 'error' : 'ok', 7000);
    } catch (e) {
      toast(errMsg(e), 'error', 6000);
    } finally {
      busy = '';
    }
  }

  async function setEvent(e: AlertEvent, notify: boolean) {
    await saveSettings((s) => {
      const muted = new Set(s.notify.muted_events ?? []);
      if (notify) muted.delete(e);
      else muted.add(e);
      s.notify.muted_events = [...muted];
    });
  }

  function setField(f: Field, e: Event) {
    if (!n) return;
    const v = (e.target as HTMLInputElement).value;
    (n as unknown as Record<string, unknown>)[f.key] = f.number ? Number(v) || 0 : v;
  }

  const formConfigured = (c: Channel) => !!n && channelConfigured(n, c);
  const dirty = (c: Channel) => !!n && !!stored && INFO[c].fields.some((f) => n![f.key] !== stored[f.key]);
</script>

<h2>告警通知</h2>
<p class="intro">备份失败、校验失败或太久没有成功备份时，通过下面开启的通道提醒你。至少开一个，最好是你每天会看的。</p>

{#if n && stored}
  <section class="card">
    {#each CHANNELS as c (c)}
      {@const info = INFO[c]}
      <div class="ch" class:open={open === c}>
        <div class="chead">
          <button class="name" onclick={() => (open = open === c ? null : c)} aria-expanded={open === c}>
            <span class="caret">{open === c ? '▾' : '▸'}</span><b>{info.name}</b>
            {#if channelConfigured(stored, c)}<span class="badge ok">已配置</span>{:else}<span class="badge">未配置</span>{/if}
          </button>
          <label class="switch" title={channelConfigured(stored, c) ? '' : '先填写并保存'}>
            <input type="checkbox" checked={isOn(c)} disabled={!channelConfigured(stored, c)} onchange={(e) => toggle(c, (e.target as HTMLInputElement).checked)} />
            <span>{isOn(c) ? '开' : '关'}</span>
          </label>
        </div>
        {#if open === c}
          <div class="body">
            <p class="small muted">{info.text}</p>
            <div class="fields">
              {#each info.fields as f (f.key)}
                <label class="lbl" class:wide={f.wide}>{f.label}{#if f.hint}<span class="hint">{f.hint}</span>{/if}
                  {#if f.number}
                    <input class="input" type="number" min="0" max="65535" value={n[f.key] || ''} oninput={(e) => setField(f, e)} placeholder={f.placeholder} />
                  {:else if f.secret}
                    <input class="input" type="password" value={n[f.key]} oninput={(e) => setField(f, e)} placeholder={stored[f.key] === SECRET_MASK ? '已设置，不改就留着' : f.placeholder} autocomplete="new-password" />
                  {:else}
                    <input class="input mono" value={n[f.key]} oninput={(e) => setField(f, e)} placeholder={f.placeholder} spellcheck="false" />
                  {/if}
                </label>
              {/each}
            </div>
            <div class="row acts">
              <button class="btn" disabled={!formConfigured(c) || !!busy} onclick={() => test(c)}>{busy === `test-${c}` ? '发送中…' : '发送测试'}</button>
              <span class="faint small grow">测试用的是上面填写的内容，不需要先保存</span>
              {#if channelConfigured(stored, c)}<button class="btn ghost danger sm" onclick={() => clear(c)}>清除</button>{/if}
              <button class="btn primary" disabled={!dirty(c) || !!busy} onclick={() => save(c)}>保存</button>
            </div>
          </div>
        {/if}
      </div>
    {/each}
  </section>

  <section class="card events">
    <h3>哪些事件发通知</h3>
    {#each EVENTS as [e, name, text] (e)}
      <label class="ev"><input type="checkbox" checked={!(stored.muted_events ?? []).includes(e)} onchange={(ev) => setEvent(e, (ev.target as HTMLInputElement).checked)} />
        <span><b>{name}</b><br /><span class="small muted">{text}</span></span></label>
    {/each}
  </section>
{/if}

<style>
  .intro { margin: 0 0 14px; color: var(--text-2); max-width: 760px; }
  section { margin-bottom: 14px; }
  .ch + .ch { border-top: 1px solid var(--border); }
  .chead { display: flex; align-items: center; gap: 8px; padding: 4px 12px 4px 4px; }
  .name { flex: 1; display: flex; align-items: center; gap: 8px; border: 0; background: transparent; padding: 9px 10px; text-align: left; border-radius: 8px; min-width: 0; }
  .name:hover { background: var(--surface-2); }
  .caret { color: var(--text-3); width: 12px; }
  .switch { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--text-2); }
  .body { padding: 0 14px 14px 32px; }
  .body p { margin: 0 0 4px; }
  .fields { display: grid; grid-template-columns: 1fr 1fr; gap: 0 12px; }
  .fields .wide { grid-column: 1 / -1; }
  .hint { color: var(--text-3); margin-left: 8px; }
  .acts { margin-top: 12px; flex-wrap: wrap; }
  .events { padding: 12px 14px; display: flex; flex-direction: column; gap: 8px; }
  h3 { margin: 0 0 2px; font-size: 14px; }
  .ev { display: flex; gap: 8px; align-items: flex-start; font-size: 13.5px; }
  .ev input { margin-top: 3px; }
  @media (max-width: 600px) {
    .fields { grid-template-columns: 1fr; }
    .body { padding-left: 14px; }
    .hint { display: block; margin-left: 0; }
  }
</style>
