// Desktop-only extras of the bridge (settings page section, offline export,
// self-update). Only bridge-tauri.ts provides them; other builds get null.

import type { Bridge } from './bridge';

export interface DesktopInfo {
  version: string;
  platform: 'windows' | 'macos' | 'linux';
  /** Where the device key is kept: the OS credential store, or a file (fallback). */
  key_storage: 'os' | 'file' | null;
  key_store_name: string;
  data_dir: string;
  update_repo: string;
  /** The build has an update signing key compiled in. */
  update_signed: boolean;
}

export interface ExportSettings {
  enabled: boolean;
  folder: string;
  interval_days: number;
  native: boolean;
  kdbx: boolean;
  keep: number;
  last_export_at: number;
  last_error: string;
}

export type ExportSettingsInput = Omit<ExportSettings, 'last_export_at' | 'last_error'>;

export interface DesktopSettings {
  export: ExportSettings;
  exporting: boolean;
  autostart: boolean;
  check_updates: boolean;
}

export interface UpdateCheck {
  current: string;
  /** The newer version, or null when up to date. */
  latest: string | null;
  notes: string;
  url: string;
  can_install: boolean;
  reason: string;
}

export interface DesktopApi {
  info(): Promise<DesktopInfo>;
  settings(): Promise<DesktopSettings>;
  setSettings(exp: ExportSettingsInput, checkUpdates: boolean): Promise<DesktopSettings>;
  setAutostart(enabled: boolean): Promise<void>;
  pickFolder(): Promise<string | null>;
  /** Runs the offline export now (needs the master password; it is not kept). */
  exportNow(password: string): Promise<{ files: string[]; pruned: string[] }>;
  checkUpdate(): Promise<UpdateCheck>;
  /** Downloads, verifies (signature + SHA-256), starts the installer and quits. */
  installUpdate(version: string): Promise<void>;
  openReleasePage(url: string): Promise<void>;
}

export function desktopApi(bridge: Bridge): DesktopApi | null {
  if (bridge.kind !== 'desktop') return null;
  return (bridge as Bridge & { desktop?: DesktopApi }).desktop ?? null;
}
