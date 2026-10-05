// The UI talks to the client core only through this interface. Two
// implementations: bridge-wasm.ts (web vault: the core compiled to
// WebAssembly) and bridge-tauri.ts (desktop: the native core via Tauri
// commands). Vite picks one through the `$bridge` alias.

import type {
  AuditEntry,
  DeviceRecord,
  EmergencyKit,
  Field,
  Generated,
  HealthReport,
  ImportPreview,
  ImportResultSummary,
  ItemContent,
  ItemFilter,
  ItemView,
  LockState,
  OtpCode,
  Recipe,
  RevisionInfo,
  SecurityReport,
  SyncReport,
  TemplateInfo,
  VaultView,
} from './types';

/**
 * What the lock screen can offer besides the master password. The web vault
 * and the extension only fill the first three fields; the desktop app adds
 * the rest (Windows Hello at start, PIN, the 14-day rule).
 */
export interface QuickUnlockStatus {
  /** The OS offers biometrics (Windows Hello). */
  available: boolean;
  /** Biometrics can unlock right now. */
  enabled: boolean;
  label: string;
  /** Biometric unlock is set up (it may be suspended right now). */
  quick_set?: boolean;
  /** "启动时可直接用生物识别解锁". */
  biometric_at_start?: boolean;
  /** A PIN can be set up on this device. */
  pin_supported?: boolean;
  pin_set?: boolean;
  /** The PIN can unlock right now. */
  pin?: boolean;
  pin_tries_left?: number;
  /** Why biometrics and the PIN need the master password now (empty: they do not). */
  password_reason?: string;
}

/** How `verifyUser` can check the user besides the master password. */
export interface VerifyOptions {
  /** Biometrics (Windows Hello): `verifyUser()` without a secret. */
  biometric: boolean;
  label: string;
  /** Desktop: a PIN is set and usable (`verifyUser(undefined, pin)`). */
  pin?: boolean;
  pin_tries_left?: number;
}

export interface Bridge {
  readonly kind: 'web' | 'desktop';
  /** The server URL to suggest on the welcome screen (the web vault's own origin). */
  defaultServer(): string;

  lockState(): Promise<LockState>;
  register(server: string, login: string, password: string, invite?: string): Promise<EmergencyKit>;
  signIn(server: string, login: string, password: string, secretKey: string, remember: boolean): Promise<void>;
  unlock(password: string): Promise<void>;
  lock(): Promise<void>;
  signOut(force: boolean): Promise<void>;
  emergencyKit(): Promise<EmergencyKit>;

  /**
   * Verifies the user again without changing the lock state, before using an
   * item marked "使用前需要验证": the master password, (desktop) the PIN, or
   * (desktop) Windows Hello when both are omitted. Rejects with
   * `wrong_password` / `wrong_pin` / `pin_wiped` / a message.
   */
  verifyUser(password?: string, pin?: string): Promise<void>;
  /** Whether `verifyUser()` without a password (biometrics, PIN) can be offered, and its label. */
  verifyUserOptions(): Promise<VerifyOptions>;

  /** Biometric / OS unlock (Windows Hello, Touch ID), and the desktop's PIN. */
  quickUnlockStatus(): Promise<QuickUnlockStatus>;
  setQuickUnlock(enabled: boolean): Promise<void>;
  quickUnlock(): Promise<void>;

  sync(): Promise<SyncReport>;
  eventsToken(): Promise<string>;

  vaults(): Promise<VaultView[]>;
  createVault(name: string): Promise<string>;
  renameVault(id: string, name: string): Promise<void>;
  listItems(filter: ItemFilter): Promise<ItemView[]>;
  item(vaultId: string, itemId: string): Promise<ItemView>;
  tags(): Promise<string[]>;
  newItem(template: string): Promise<ItemContent>;
  saveItem(vaultId: string, itemId: string | null, content: ItemContent): Promise<string>;
  deleteItem(vaultId: string, itemId: string): Promise<void>;
  restoreItem(vaultId: string, itemId: string): Promise<void>;
  resolveConflict(vaultId: string, itemId: string, conflictId: string, useConflictValue: boolean): Promise<void>;
  attention(): Promise<[number, number, number]>;

  itemHistory(vaultId: string, itemId: string): Promise<RevisionInfo[]>;
  itemRevision(vaultId: string, itemId: string, revision: number): Promise<ItemContent>;
  restoreRevision(vaultId: string, itemId: string, revision: number): Promise<void>;
  purge(vaultId: string, itemIds: string[]): Promise<string[]>;

  addAttachment(vaultId: string, itemId: string, name: string, mime: string, data: Uint8Array): Promise<string>;
  attachment(vaultId: string, itemId: string, attachmentId: string): Promise<Uint8Array>;
  removeAttachment(vaultId: string, itemId: string, attachmentId: string): Promise<void>;

  /** Parses an export file from another manager (or our own). */
  importPreview(fileName: string, data: Uint8Array, password?: string): Promise<ImportPreview>;
  importCommit(token: string, vaultId: string): Promise<ImportResultSummary>;
  importBatches(): Promise<[string, string, number, number][]>;
  undoImport(batchId: string): Promise<number>;
  /** `native` (lossless, needs password + Secret Key to open), `kdbx` (KeePassXC), `csv` (plaintext). */
  exportVault(format: 'native' | 'kdbx' | 'csv', password: string): Promise<Uint8Array>;

  securityReport(): Promise<SecurityReport>;
  healthCheck(): Promise<HealthReport>;
  changePassword(current: string, next: string): Promise<void>;
  devices(): Promise<DeviceRecord[]>;
  revokeDevice(id: string): Promise<void>;
  auditLog(): Promise<AuditEntry[]>;

  otpCode(uri: string, unixSecs: number): OtpCode | null;
  generate(recipe: Recipe): Generated;
  passwordStrength(password: string): number;
  templates(): TemplateInfo[];
  fieldPresets(): Field[];
  newShortId(prefix: string): string;
  displayHost(url: string): string;
  normalizeSecretKey(text: string): string;

  /** Copies; secrets are cleared from the clipboard after a while and kept out of clipboard history. */
  copy(text: string, secret: boolean): Promise<void>;
  saveFile(name: string, data: Uint8Array, mime: string): Promise<void>;
}

export function errorMessage(e: unknown): string {
  if (e && typeof e === 'object' && 'message' in e) return String((e as { message: unknown }).message);
  return String(e);
}

export function errorCode(e: unknown): string {
  if (e && typeof e === 'object' && 'code' in e) return String((e as { code: unknown }).code);
  return '';
}
