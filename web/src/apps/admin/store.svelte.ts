// State shared by the admin console's pages: the backup status (targets,
// settings, runs, checks) and the admin's own security settings.

import { api, type AdminSecurity, type BackupSettings, type BackupStatus } from './api';
import { toast } from '$lib/ui.svelte';

export const admin = $state<{ backup: BackupStatus | null; security: AdminSecurity | null; securityLoaded: boolean }>({
  backup: null,
  security: null,
  securityLoaded: false,
});

export const errMsg = (e: unknown) => String((e as Error)?.message ?? e);

export async function loadBackup(): Promise<BackupStatus | null> {
  try {
    admin.backup = await api<BackupStatus>('GET', '/backup');
  } catch (e) {
    toast(errMsg(e), 'error');
  }
  return admin.backup;
}

export async function loadSecurity(): Promise<void> {
  try {
    admin.security = await api<AdminSecurity>('GET', '/security');
  } catch {
    /* older servers: unknown */
  }
  admin.securityLoaded = true;
}

/**
 * Saves the backup settings with one change applied to the current ones.
 * Secrets that were not touched go back as the mask, which keeps them.
 */
export async function saveSettings(change: (s: BackupSettings) => void, done = '已保存'): Promise<boolean> {
  if (!admin.backup) return false;
  const s = $state.snapshot(admin.backup.settings) as BackupSettings;
  change(s);
  try {
    await api('PUT', '/backup/settings', s);
    if (done) toast(done, 'ok');
    await loadBackup();
    return true;
  } catch (e) {
    toast(errMsg(e), 'error', 6000);
    return false;
  }
}
