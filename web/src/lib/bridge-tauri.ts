// Bridge for the desktop app: the native core (npw-core over a SQLite
// replica) behind Tauri commands in desktop/src-tauri/src/commands.rs.
// Semantics match bridge-wasm.ts; errors are thrown as {code, message}.
//
// - Binary arguments go as the raw request body, the other arguments as
//   percent-encoded JSON in the `npw-args` header; binary results come back
//   as ArrayBuffers.
// - The Bridge's synchronous functions (otpCode, generate, ...) use a
//   synchronous XMLHttpRequest to the app's `npwsync:` scheme (pure functions,
//   see desktop/src-tauri/src/pure.rs); templates and field presets are
//   fetched once at start.

import { convertFileSrc, invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type { Bridge } from './bridge';
import type { DesktopApi, DesktopInfo, DesktopSettings, UpdateCheck } from './desktop';
import type { Field, Generated, ImportPreview, OtpCode, TemplateInfo } from './types';
import { locale } from './i18n';
import { toast } from './ui.svelte';
import { vault } from './vault.svelte';

function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  return invoke<T>(cmd, args);
}

function callRaw<T>(cmd: string, data: Uint8Array, args: Record<string, unknown>): Promise<T> {
  return invoke<T>(cmd, data, { headers: { 'npw-args': encodeURIComponent(JSON.stringify(args)) } });
}

async function bytes(p: Promise<ArrayBuffer>): Promise<Uint8Array> {
  return new Uint8Array(await p);
}

/** A synchronous call into the core's pure functions. */
function callSync<T>(fn: string, args: Record<string, unknown>): T {
  const xhr = new XMLHttpRequest();
  xhr.open('POST', convertFileSrc(fn, 'npwsync'), false);
  xhr.setRequestHeader('Content-Type', 'text/plain');
  xhr.send(JSON.stringify(args));
  let body: unknown = null;
  try {
    body = xhr.responseText ? JSON.parse(xhr.responseText) : null;
  } catch {
    /* not JSON */
  }
  if (xhr.status === 200) return body as T;
  throw body ?? { code: 'invalid', message: `${fn}: HTTP ${xhr.status}` };
}

const hosts = new Map<string, string>();

function displayHost(url: string): string {
  let h = hosts.get(url);
  if (h === undefined) {
    try {
      h = callSync<string>('displayHost', { url });
    } catch {
      h = url;
    }
    if (hosts.size > 5000) hosts.clear();
    hosts.set(url, h);
  }
  return h;
}

interface ExportEvent {
  ok: boolean;
  message: string;
  files: string[];
}

async function listenToApp() {
  // the tray's "lock", the session locking, the machine going to sleep
  await listen('npw:locked', () => {
    if (vault.phase === 'unlocked') void vault.doLock();
  });
  await listen('npw:sync', () => {
    if (vault.phase === 'unlocked') void vault.sync(false);
  });
  await listen<ExportEvent>('npw:export', (e) => {
    if (e.payload.ok) toast(`已完成定期离线导出（${e.payload.files.length} 个文件）`, 'ok', 5000);
    else toast(`定期离线导出失败：${e.payload.message}`, 'error', 8000);
  });
  await listen<UpdateCheck>('npw:update', (e) => {
    toast(`NyaPassword ${e.payload.latest} 已发布，可在“设置 → 更新”中安装`, 'info', 8000);
  });
}

export async function createBridge(): Promise<Bridge> {
  const loc = locale();
  const [templates, presets] = await Promise.all([
    call<TemplateInfo[]>('templates', { locale: loc }),
    call<Field[]>('field_presets', { locale: loc }),
  ]);
  await listenToApp();

  const desktop: DesktopApi = {
    info: () => call<DesktopInfo>('desktop_info'),
    settings: () => call<DesktopSettings>('desktop_settings'),
    setSettings: (exp, checkUpdates) => call<DesktopSettings>('set_desktop_settings', { export: exp, checkUpdates }),
    setAutostart: (enabled) => call('set_autostart', { enabled }),
    pickFolder: () => call<string | null>('pick_export_folder'),
    exportNow: (password) => call('export_now', { password }),
    checkUpdate: () => call<UpdateCheck>('update_check'),
    installUpdate: (version) => call('update_install', { version }),
    openReleasePage: (url) => call('open_release_page', { url }),
  };

  const bridge: Bridge & { desktop: DesktopApi } = {
    kind: 'desktop',
    // the user types their server
    defaultServer: () => '',
    desktop,

    lockState: () => call('lock_state'),
    register: (server, login, password, invite) => call('register', { server, login, password, invite: invite || null }),
    // the desktop always keeps its replica (the "remember" choice is web-only)
    signIn: (server, login, password, secretKey) => call('sign_in', { server, login, password, secretKey }),
    unlock: (password) => call('unlock', { password }),
    lock: () => call('lock'),
    signOut: (force) => call('sign_out', { force }),
    emergencyKit: () => call('emergency_kit'),

    quickUnlockStatus: () => call('quick_unlock_status'),
    setQuickUnlock: (enabled) => call('set_quick_unlock', { enabled }),
    quickUnlock: () => call('quick_unlock'),

    sync: () => call('sync'),
    eventsToken: () => call('events_token'),

    vaults: () => call('vaults'),
    createVault: (name) => call('create_vault', { name }),
    renameVault: (id, name) => call('rename_vault', { id, name }),
    listItems: (filter) => call('list_items', { filter }),
    item: (vaultId, itemId) => call('item', { vaultId, itemId }),
    tags: () => call('tags'),
    newItem: (template) => call('new_item', { template, locale: loc }),
    saveItem: (vaultId, itemId, content) => call('save_item', { vaultId, itemId, content }),
    deleteItem: (vaultId, itemId) => call('delete_item', { vaultId, itemId }),
    restoreItem: (vaultId, itemId) => call('restore_item', { vaultId, itemId }),
    resolveConflict: (vaultId, itemId, conflictId, useConflictValue) =>
      call('resolve_conflict', { vaultId, itemId, conflictId, useConflictValue }),
    attention: () => call('attention'),

    itemHistory: (vaultId, itemId) => call('item_history', { vaultId, itemId }),
    itemRevision: (vaultId, itemId, revision) => call('item_revision', { vaultId, itemId, revision }),
    restoreRevision: (vaultId, itemId, revision) => call('restore_revision', { vaultId, itemId, revision }),
    purge: (vaultId, itemIds) => call('purge', { vaultId, itemIds }),

    addAttachment: (vaultId, itemId, name, mime, data) => callRaw('add_attachment', data, { vaultId, itemId, name, mime }),
    attachment: (vaultId, itemId, attachmentId) => bytes(call('attachment', { vaultId, itemId, attachmentId })),
    removeAttachment: (vaultId, itemId, attachmentId) => call('remove_attachment', { vaultId, itemId, attachmentId }),

    importPreview: (fileName, data, password) =>
      callRaw<ImportPreview>('import_preview', data, { fileName, password: password || null, locale: loc }),
    importCommit: (token, vaultId) => call('import_commit', { token, vaultId }),
    importBatches: () => call('import_batches'),
    undoImport: (batchId) => call('undo_import', { batchId }),
    exportVault: (format, password) => bytes(call('export_vault', { format, password })),

    securityReport: () => call('security_report'),
    healthCheck: () => call('health_check'),
    changePassword: (current, next) => call('change_password', { current, next }),
    devices: () => call('devices'),
    revokeDevice: (id) => call('revoke_device', { id }),
    auditLog: () => call('audit_log'),

    otpCode: (uri, unixSecs) => {
      try {
        return callSync<OtpCode>('otpCode', { uri, t: unixSecs });
      } catch {
        return null;
      }
    },
    generate: (recipe) => callSync<Generated>('generate', { recipe }),
    passwordStrength: (password) => callSync<number>('passwordStrength', { password }),
    templates: () => templates,
    fieldPresets: () => presets,
    newShortId: (prefix) => callSync<string>('newShortId', { prefix }),
    displayHost,
    normalizeSecretKey: (text) => callSync<string>('normalizeSecretKey', { text }),

    copy: (text, secret) => call('copy', { text, secret }),
    saveFile: (name, data, mime) => callRaw('save_file', data, { name, mime }),
  };
  return bridge;
}
