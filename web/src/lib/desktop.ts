// Desktop-only extras of the bridge (settings page section, offline export,
// self-update, ssh-agent, Quick Access, browser extension bridge). Only bridge-tauri.ts provides them; other builds get null.

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

export interface SshAgentStatus {
  /** The configured pipe name / socket path (empty = default). */
  endpoint_setting: string;
  enabled: boolean;
  running: boolean;
  endpoint: string;
  default_endpoint: string;
  /** The value for SSH_AUTH_SOCK / IdentityAgent. */
  auth_sock: string;
  error: string;
  /** Windows: the OpenSSH Authentication Agent service. */
  system_agent: { state: '' | 'running' | 'stopped' | 'not_installed'; start_type: '' | 'auto' | 'manual' | 'disabled' };
}

export interface QuickAccessSettings {
  enabled: boolean;
  shortcut: string;
  /** Why the shortcut could not be registered. */
  error: string;
  auto_type_supported: boolean;
}

export interface Pairing {
  id: string;
  name: string;
  public_key: string;
  extension_id: string;
  account_id: string;
  created_at: number;
  last_used_at: number;
}

export interface BrowserBridgeSettings {
  enabled: boolean;
  extension_ids: string[];
  pairings: Pairing[];
  running: boolean;
  /** Where the native messaging host was registered. */
  registered: string[];
  error: string;
}

export interface DesktopSettings {
  export: ExportSettings;
  exporting: boolean;
  autostart: boolean;
  check_updates: boolean;
  ssh_agent: SshAgentStatus;
  quick_access: QuickAccessSettings;
  browser_bridge: BrowserBridgeSettings;
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
  setSshAgent(enabled: boolean, endpoint: string): Promise<DesktopSettings>;
  setQuickAccess(enabled: boolean, shortcut: string): Promise<DesktopSettings>;
  setBrowserBridge(enabled: boolean, extensionIds: string[]): Promise<DesktopSettings>;
  removePairing(id: string): Promise<DesktopSettings>;
  /** Rejects with a message when an auto-type sequence is not valid. */
  checkAutoType(sequence: string): Promise<void>;
  /** Unlocks with the PIN; rejects with `wrong_pin` (message: tries left), `pin_wiped`, `password_required`. */
  pinUnlock(pin: string): Promise<void>;
  /** Sets or changes the PIN (at least 4 characters; while unlocked). */
  setPin(pin: string): Promise<void>;
  removePin(): Promise<void>;
  /** "启动时可直接用生物识别解锁". */
  setBiometricAtStart(enabled: boolean): Promise<void>;
}

/**
 * The Quick Access shortcut of a new installation (desktop `settings.rs`
 * `DEFAULT_SHORTCUT`). Ctrl+Shift+Space, the old default, is taken by IDEs
 * (VS Code / JetBrains parameter hints) and some input methods.
 */
export const DEFAULT_SHORTCUT = 'Ctrl+Shift+Alt+Space';

export function desktopApi(bridge: Bridge): DesktopApi | null {
  if (bridge.kind !== 'desktop') return null;
  return (bridge as Bridge & { desktop?: DesktopApi }).desktop ?? null;
}
