<script lang="ts">
  import { vault, type Nav } from '$lib/vault.svelte';
  import { TEMPLATE_ICONS } from '$lib/ui.svelte';

  const isOn = (n: Nav) => {
    const c = vault.nav;
    if (vault.page !== 'items') return false;
    if (c.kind !== n.kind) return false;
    return !('id' in n) || ('id' in c && c.id === n.id);
  };

  // nested tags: "工作/开发" shows under "工作"
  const tagTree = $derived.by(() => {
    const roots = new Set<string>();
    for (const t of vault.tags) roots.add(t.split('/')[0]);
    return [...roots].sort((a, b) => a.localeCompare(b, 'zh-CN'));
  });
  const usedTemplates = $derived(vault.templates.filter((t) => ['login', 'credit_card', 'bank_account', 'identity', 'document', 'secure_note', 'ssh_key', 'server', 'wifi', 'api_credential', 'database', 'software_license', 'crypto_wallet', 'password'].includes(t.id)));
</script>

<nav class="side">
  <div class="acct">
    <div class="avatar">{(vault.lock?.login ?? '?').slice(0, 1).toUpperCase()}</div>
    <div class="grow">
      <div class="name">{vault.lock?.login}</div>
      <div class="faint tiny">{vault.lock?.server_url.replace(/^https?:\/\//, '')}</div>
    </div>
  </div>

  <button class="nav" class:on={isOn({ kind: 'all' })} onclick={() => vault.setNav({ kind: 'all' })}>全部条目</button>
  <button class="nav" class:on={isOn({ kind: 'favorites' })} onclick={() => vault.setNav({ kind: 'favorites' })}>★ 收藏</button>
  {#if vault.attention[0] > 0}
    <button class="nav warn" class:on={isOn({ kind: 'conflicts' })} onclick={() => vault.setNav({ kind: 'conflicts' })}>⚠ 待处理冲突 <span class="cnt">{vault.attention[0]}</span></button>
  {/if}

  <h4>保险库</h4>
  {#each vault.vaults as v (v.id)}
    <button class="nav" class:on={isOn({ kind: 'vault', id: v.id })} onclick={() => vault.setNav({ kind: 'vault', id: v.id })}>
      <span class="dot"></span>{v.name}<span class="cnt">{v.items}</span>
    </button>
  {/each}

  <h4>分类</h4>
  {#each usedTemplates as t (t.id)}
    <button class="nav" class:on={isOn({ kind: 'template', id: t.id })} onclick={() => vault.setNav({ kind: 'template', id: t.id })}>
      <span class="ti">{TEMPLATE_ICONS[t.id] ?? '•'}</span>{t.label}
    </button>
  {/each}

  {#if tagTree.length}
    <h4>标签</h4>
    {#each tagTree as t (t)}
      <button class="nav" class:on={isOn({ kind: 'tag', id: t })} onclick={() => vault.setNav({ kind: 'tag', id: t })}># {t}</button>
    {/each}
  {/if}

  <h4>其他</h4>
  <button class="nav" class:on={vault.page === 'generator'} onclick={() => (vault.page = 'generator')}>⚿ 密码生成器</button>
  <button class="nav" class:on={vault.page === 'security'} onclick={() => (vault.page = 'security')}>🛡 安全检查</button>
  <button class="nav" class:on={isOn({ kind: 'archived' })} onclick={() => vault.setNav({ kind: 'archived' })}>🗄 归档</button>
  <button class="nav" class:on={isOn({ kind: 'trash' })} onclick={() => vault.setNav({ kind: 'trash' })}>🗑 回收站</button>
  <button class="nav" class:on={vault.page === 'import'} onclick={() => (vault.page = 'import')}>⇪ 导入 / 导出</button>
  <button class="nav" class:on={vault.page === 'settings'} onclick={() => (vault.page = 'settings')}>⚙ 设置</button>
</nav>

<style>
  .side { background: var(--sidebar); border-right: 1px solid var(--border); padding: 12px 10px; overflow: auto; }
  .acct { display: flex; align-items: center; gap: 8px; padding: 4px 8px 12px; }
  .avatar { width: 30px; height: 30px; border-radius: 50%; background: linear-gradient(135deg, #7b8cff, var(--accent)); color: #fff; display: grid; place-items: center; font-weight: 700; flex: none; }
  .name { font-weight: 600; font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .tiny { font-size: 11.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  h4 { margin: 14px 8px 4px; font-size: 11px; letter-spacing: .06em; color: var(--text-3); font-weight: 600; }
  .nav { display: flex; align-items: center; gap: 8px; width: 100%; border: 0; background: transparent; padding: 6px 8px; border-radius: 7px; text-align: left; color: var(--text); }
  .nav:hover { background: var(--surface-3); }
  .nav.on { background: var(--sel); color: var(--accent); font-weight: 600; }
  .nav.warn { color: var(--warn); }
  .cnt { margin-left: auto; font-size: 12px; color: var(--text-3); }
  .dot { width: 8px; height: 8px; border-radius: 3px; background: var(--accent); }
  .ti { width: 18px; text-align: center; }
</style>
