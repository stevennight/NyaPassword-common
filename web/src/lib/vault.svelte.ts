// State and actions of the vault app (web vault and desktop).

import { AUTO_LOCK_DEFAULT, parseAutoLock } from './autolock';
import type { Bridge } from './bridge';
import { errorCode, errorMessage } from './bridge';
import { errorText } from './i18n';
import { afterOpen, gated, itemKey, type ItemRef } from './reprompt';
import { toast } from './ui.svelte';
import type { ItemFilter, ItemView, LockState, SyncReport, TemplateInfo, VaultView } from './types';

export type Nav =
  | { kind: 'all' }
  | { kind: 'favorites' }
  | { kind: 'conflicts' }
  | { kind: 'archived' }
  | { kind: 'trash' }
  | { kind: 'vault'; id: string }
  | { kind: 'template'; id: string }
  | { kind: 'tag'; id: string };

export type Page = 'items' | 'security' | 'settings' | 'import' | 'generator';

class VaultState {
  bridge!: Bridge;
  phase = $state<'loading' | 'welcome' | 'locked' | 'unlocked'>('loading');
  lock = $state<LockState | null>(null);
  vaults = $state<VaultView[]>([]);
  tags = $state<string[]>([]);
  templates = $state<TemplateInfo[]>([]);
  nav = $state<Nav>({ kind: 'all' });
  page = $state<Page>('items');
  query = $state('');
  items = $state<ItemView[]>([]);
  selected = $state<{ vault_id: string; item_id: string } | null>(null);
  editing = $state<{ vault_id: string; item_id: string | null } | null>(null);
  /** Template and vault for a new item (when editing.item_id is null). */
  newTemplate = $state('login');
  newVault = $state('');
  attention = $state<[number, number, number]>([0, 0, 0]);
  syncing = $state(false);
  lastSync = $state<SyncReport | null>(null);
  syncError = $state('');
  /** Bumps when items change, so open views reload. */
  version = $state(0);
  /** Idle minutes before locking; 0 = never ([parseAutoLock]). */
  autoLockMinutes = $state(AUTO_LOCK_DEFAULT);
  /** The item verified for "使用前需要验证" (`itemKey`), while it stays open. */
  verified = $state<string | null>(null);
  /** Desktop: a browser extension waits for this app to be unlocked (its browser's name). */
  unlockRequest = $state('');

  private ws: WebSocket | null = null;
  private syncTimer: ReturnType<typeof setInterval> | undefined;
  private idleTimer: ReturnType<typeof setTimeout> | undefined;
  private wsRetry = 0;

  async init(bridge: Bridge) {
    this.bridge = bridge;
    this.templates = bridge.templates();
    try {
      // the extension keeps it where its service worker reads it
      const saved = bridge.autoLockMinutes ? await bridge.autoLockMinutes() : localStorage.getItem('npw.autoLock');
      this.autoLockMinutes = parseAutoLock(saved) ?? AUTO_LOCK_DEFAULT;
    } catch {
      /* storage unavailable */
    }
    await this.refreshLock();
    for (const ev of ['mousemove', 'keydown', 'pointerdown', 'wheel']) {
      window.addEventListener(ev, () => this.touch(), { passive: true });
    }
  }

  async refreshLock() {
    this.lock = await this.bridge.lockState();
    this.phase = !this.lock.signed_in ? 'welcome' : this.lock.unlocked ? 'unlocked' : 'locked';
    if (this.phase === 'unlocked') await this.onUnlocked();
  }

  async onUnlocked() {
    this.phase = 'unlocked';
    this.lock = await this.bridge.lockState();
    await this.reload();
    this.touch();
    this.startSync();
    void this.sync();
  }

  async doLock() {
    this.stopSync();
    await this.bridge.lock();
    this.items = [];
    this.selected = null;
    this.editing = null;
    this.verified = null;
    this.phase = 'locked';
  }

  touch() {
    if (this.phase !== 'unlocked') return;
    clearTimeout(this.idleTimer);
    if (this.autoLockMinutes > 0) this.idleTimer = setTimeout(() => void this.doLock(), this.autoLockMinutes * 60_000);
  }

  async setAutoLock(minutes: number) {
    const m = parseAutoLock(minutes);
    if (m === null) return;
    this.autoLockMinutes = m;
    try {
      if (this.bridge.setAutoLockMinutes) await this.bridge.setAutoLockMinutes(m);
      else localStorage.setItem('npw.autoLock', String(m));
    } catch {
      /* ignore */
    }
    this.touch();
  }

  filter(): ItemFilter {
    const f: ItemFilter = { query: this.query };
    const n = this.nav;
    if (n.kind === 'favorites') f.favorites = true;
    if (n.kind === 'conflicts') f.conflicts = true;
    if (n.kind === 'archived') f.archived = true;
    if (n.kind === 'trash') f.trash = true;
    if (n.kind === 'vault') f.vault_id = n.id;
    if (n.kind === 'template') f.template = n.id;
    if (n.kind === 'tag') f.tag = n.id;
    return f;
  }

  async reload() {
    if (this.phase !== 'unlocked') return;
    try {
      const [items, vaults, tags, attention] = await Promise.all([
        this.bridge.listItems(this.filter()),
        this.bridge.vaults(),
        this.bridge.tags(),
        this.bridge.attention(),
      ]);
      this.items = items;
      this.vaults = vaults;
      this.tags = tags;
      this.attention = attention;
      this.version++;
      if (this.selected && !items.some((i) => i.item_id === this.selected!.item_id) && !this.editing) {
        this.selected = items[0] ? { vault_id: items[0].vault_id, item_id: items[0].item_id } : null;
      }
    } catch (e) {
      this.fail(e);
    }
  }

  async setNav(n: Nav) {
    this.nav = n;
    this.page = 'items';
    this.editing = null;
    await this.reload();
    this.selected = this.items[0] ? { vault_id: this.items[0].vault_id, item_id: this.items[0].item_id } : null;
  }

  async search(q: string) {
    this.query = q;
    await this.reload();
    if (this.items[0] && !this.items.some((i) => i.item_id === this.selected?.item_id)) {
      this.selected = { vault_id: this.items[0].vault_id, item_id: this.items[0].item_id };
    }
  }

  /** An item was opened: a verification of another item ends. */
  opened(vaultId: string, itemId: string) {
    this.verified = afterOpen(this.verified, vaultId, itemId);
  }

  /** The item's secrets are hidden until the user verifies. */
  gated(item: ItemRef | null | undefined): boolean {
    return gated(item, this.verified);
  }

  /** Verifies the user (master password, PIN, or biometrics without either) for this item. */
  async verify(vaultId: string, itemId: string, password?: string, pin?: string) {
    await this.bridge.verifyUser(password, pin);
    this.verified = itemKey(vaultId, itemId);
  }

  defaultVault(): string {
    if (this.nav.kind === 'vault') return this.nav.id;
    return this.vaults[0]?.id ?? '';
  }

  async sync(silent = true) {
    if (this.syncing || this.phase !== 'unlocked') return;
    this.syncing = true;
    try {
      this.lastSync = await this.bridge.sync();
      this.syncError = '';
      const r = this.lastSync;
      if (r.conflicts > 0) toast(`同步时有 ${r.conflicts} 处冲突，两个值都已保留，请到“待处理冲突”查看`, 'info', 6000);
      if (r.restored_to_server > 0) toast(`服务器似乎从备份恢复过：已重新上传 ${r.restored_to_server} 个更新的条目`, 'info', 6000);
      if (r.rejected > 0) toast(`${r.rejected} 处修改被服务器拒绝（已保留在本地）`, 'error', 6000);
      if (!silent) toast('已同步', 'ok');
      await this.reload();
    } catch (e) {
      const code = errorCode(e);
      this.syncError = errorText(code, errorMessage(e));
      if (code === 'device_revoked') {
        toast(this.syncError, 'error', 8000);
        await this.bridge.signOut(true);
        await this.refreshLock();
      } else if (code === 'session_expired') {
        await this.doLock();
        toast(this.syncError, 'error', 6000);
      } else if (!silent) {
        toast(this.syncError, 'error');
      }
    } finally {
      this.syncing = false;
    }
  }

  /** Sync now and then: every 5 minutes, after edits, and when the server says something changed. */
  private startSync() {
    this.stopSync();
    this.syncTimer = setInterval(() => void this.sync(), 5 * 60_000);
    void this.connectEvents();
  }

  private stopSync() {
    clearInterval(this.syncTimer);
    this.ws?.close();
    this.ws = null;
  }

  private async connectEvents() {
    if (this.phase !== 'unlocked' || !this.lock) return;
    try {
      const token = await this.bridge.eventsToken();
      const url = new URL('/v1/events', this.lock.server_url);
      url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
      url.searchParams.set('token', token);
      const ws = new WebSocket(url);
      this.ws = ws;
      ws.onopen = () => (this.wsRetry = 0);
      ws.onmessage = (m) => {
        try {
          const ev = JSON.parse(String(m.data));
          if (ev.kind === 'device_revoked' && ev.device_id === this.lock?.device_id) {
            void this.sync(false);
          } else {
            void this.sync();
          }
        } catch {
          /* ignore */
        }
      };
      ws.onclose = () => {
        if (this.ws !== ws || this.phase !== 'unlocked') return;
        this.wsRetry = Math.min(this.wsRetry + 1, 6);
        setTimeout(() => void this.connectEvents(), 2 ** this.wsRetry * 1000);
      };
    } catch {
      this.wsRetry = Math.min(this.wsRetry + 1, 6);
      setTimeout(() => void this.connectEvents(), 2 ** this.wsRetry * 1000);
    }
  }

  /** After a local edit: refresh lists now, push soon. */
  async edited() {
    await this.reload();
    setTimeout(() => void this.sync(), 800);
  }

  fail(e: unknown) {
    toast(errorText(errorCode(e), errorMessage(e)), 'error', 5000);
  }
}

export const vault = new VaultState();
