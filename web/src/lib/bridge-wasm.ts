// Bridge for the web vault: the core runs in this page as WebAssembly. The
// replica (ciphertext only) is kept in IndexedDB when the user chose to
// remember this browser; otherwise everything lives in memory only.

import init, * as npw from '../wasm/pkg/npw.js';
import type { Bridge } from './bridge';
import type { ImportPreview, Recipe } from './types';
import { locale } from './i18n';

const DB = 'nyapassword';
const STORE = 'replica';

function idb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

async function idbGet<T>(key: string): Promise<T | undefined> {
  try {
    const db = await idb();
    return await new Promise((resolve, reject) => {
      const r = db.transaction(STORE).objectStore(STORE).get(key);
      r.onsuccess = () => resolve(r.result as T | undefined);
      r.onerror = () => reject(r.error);
    });
  } catch {
    return undefined;
  }
}

async function idbPut(key: string, value: unknown): Promise<void> {
  try {
    const db = await idb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      if (value === undefined) tx.objectStore(STORE).delete(key);
      else tx.objectStore(STORE).put(value, key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch {
    /* private mode: nothing persists */
  }
}

let client: npw.NpwClient;
let remember = false;
let savedGeneration = -1;
let saveTimer: ReturnType<typeof setTimeout> | undefined;

function persistSoon() {
  if (!remember) return;
  clearTimeout(saveTimer);
  saveTimer = setTimeout(async () => {
    const g = client.generation();
    if (g === savedGeneration) return;
    savedGeneration = g;
    await idbPut('snapshot', client.snapshot());
  }, 300);
}

async function mut<T>(p: Promise<T> | T): Promise<T> {
  const r = await p;
  persistSoon();
  return r;
}

function browserName(): string {
  const ua = navigator.userAgent;
  const b = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /Windows/.test(ua) ? 'Windows' : /Mac OS/.test(ua) ? 'macOS' : /Android/.test(ua) ? 'Android' : /Linux/.test(ua) ? 'Linux' : '';
  return `${b}${os ? ' · ' + os : ''}`;
}

export interface WasmBridgeOptions {
  /** Device name shown in the account's device list. */
  deviceName?: string;
  platform?: string;
  /** Always persist the replica (the extension), instead of following the sign-in choice. */
  alwaysRemember?: boolean;
}

/** The underlying client, for hosts that need more than the Bridge (the extension's service worker). */
export function wasmClient(): npw.NpwClient {
  return client;
}

/** Persists the replica soon if it changed (hosts calling the client directly use this). */
export function persistReplica() {
  persistSoon();
}

export async function createBridge(opts: WasmBridgeOptions = {}): Promise<Bridge> {
  await init();
  let deviceKey = await idbGet<Uint8Array>('device_key');
  if (!deviceKey) {
    deviceKey = npw.randomKey();
    await idbPut('device_key', deviceKey);
  }
  const snapshot = (await idbGet<Uint8Array>('snapshot')) ?? new Uint8Array();
  remember = opts.alwaysRemember || snapshot.length > 0;
  client = new npw.NpwClient(opts.deviceName ?? `网页版 · ${browserName()}`, opts.platform ?? 'web', __APP_VERSION__, locale(), deviceKey, snapshot);
  savedGeneration = client.generation();

  const bridge: Bridge = {
    kind: 'web',
    defaultServer: () => location.origin,

    lockState: async () => client.lockState(),
    register: async (server, login, password, invite) => {
      remember = true;
      return mut(client.register(server, login, password, invite || undefined));
    },
    signIn: async (server, login, password, secretKey, rem) => {
      remember = rem || !!opts.alwaysRemember;
      await mut(client.signIn(server, login, password, secretKey));
      if (!rem) await idbPut('snapshot', undefined);
    },
    unlock: async (password) => client.unlock(password),
    lock: async () => client.lock(),
    verifyUser: async (password) => {
      if (!password) throw { code: 'invalid', message: '请输入主密码' };
      client.verifyPassword(password);
    },
    verifyUserOptions: async () => ({ biometric: false, label: '' }),
    signOut: async (force) => {
      await client.signOut(force);
      await idbPut('snapshot', undefined);
      remember = !!opts.alwaysRemember;
    },
    emergencyKit: async () => client.emergencyKit(),

    quickUnlockStatus: async () => ({ available: false, enabled: false, label: '' }),
    setQuickUnlock: async () => {
      throw { code: 'invalid', message: '网页版不支持生物识别解锁' };
    },
    quickUnlock: async () => {
      throw { code: 'invalid', message: '网页版不支持生物识别解锁' };
    },

    sync: async () => mut(client.sync()),
    eventsToken: async () => client.eventsToken(),

    vaults: async () => client.vaults(),
    createVault: async (name) => mut(client.createVault(name)),
    renameVault: async (id, name) => mut(client.renameVault(id, name)),
    listItems: async (filter) => client.listItems(filter),
    item: async (v, i) => client.item(v, i),
    tags: async () => client.tags(),
    newItem: async (template) => client.newItem(template, locale()),
    saveItem: async (v, i, content) => mut(client.saveItem(v, i ?? undefined, content)),
    deleteItem: async (v, i) => mut(client.deleteItem(v, i)),
    restoreItem: async (v, i) => mut(client.restoreItem(v, i)),
    resolveConflict: async (v, i, c, use) => mut(client.resolveConflict(v, i, c, use)),
    attention: async () => client.attention(),

    itemHistory: async (v, i) => client.itemHistory(v, i),
    itemRevision: async (v, i, r) => client.itemRevision(v, i, r),
    restoreRevision: async (v, i, r) => mut(client.restoreRevision(v, i, r)),
    purge: async (v, ids) => mut(client.purge(v, ids)),

    addAttachment: async (v, i, name, mime, data) => mut(client.addAttachment(v, i, name, mime, data)),
    attachment: async (v, i, a) => mut(client.attachment(v, i, a)),
    removeAttachment: async (v, i, a) => mut(client.removeAttachment(v, i, a)),

    importPreview: async (fileName, data, password) => client.importParse(fileName, data, password || undefined, locale()) as ImportPreview,
    importCommit: async (token, vaultId) => mut(client.importCommit(token, vaultId)),
    importBatches: async () => client.importBatches(),
    undoImport: async (b) => mut(client.undoImport(b)),
    exportVault: async (format, password) => client.exportVault(format, password),

    securityReport: async () => client.securityReport(),
    healthCheck: async () => client.healthCheck(),
    changePassword: async (cur, next) => mut(client.changePassword(cur, next)),
    devices: async () => client.devices(),
    revokeDevice: async (id) => client.revokeDevice(id),
    auditLog: async () => client.auditLog(),

    otpCode: (uri, t) => {
      try {
        return npw.otpCode(uri, t);
      } catch {
        return null;
      }
    },
    generate: (recipe: Recipe) => npw.generate(recipe),
    passwordStrength: (pw) => npw.passwordStrength(pw),
    templates: () => npw.templates(locale()),
    fieldPresets: () => npw.fieldPresets(locale()),
    newShortId: (p) => npw.newShortId(p),
    displayHost: (u) => npw.displayHost(u),
    normalizeSecretKey: (t) => npw.normalizeSecretKey(t),

    copy: async (text, secret) => {
      await navigator.clipboard.writeText(text);
      if (secret) {
        setTimeout(async () => {
          try {
            if ((await navigator.clipboard.readText()) !== text) return;
          } catch {
            /* cannot read: clear anyway */
          }
          await navigator.clipboard.writeText('').catch(() => {});
        }, 90_000);
      }
    },
    saveFile: async (name, data, mime) => {
      const url = URL.createObjectURL(new Blob([data as BlobPart], { type: mime }));
      const a = document.createElement('a');
      a.href = url;
      a.download = name;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
    },
  };
  return bridge;
}
