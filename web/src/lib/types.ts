// Mirrors of the Rust types the core hands to the UI (npw-core, npw-model, npw-api).

export interface LockState {
  signed_in: boolean;
  unlocked: boolean;
  login: string;
  server_url: string;
  account_id: string;
  device_id: string;
  last_sync_at: number;
}

export interface EmergencyKit {
  server_url: string;
  login: string;
  account_id: string;
  secret_key: string;
  created_at: number;
}

export interface VaultView {
  id: string;
  name: string;
  role: string;
  items: number;
}

export interface Field {
  id: string;
  label: string;
  kind: string;
  purpose?: string;
  value: unknown;
  section?: string;
  multiline?: boolean;
  generator?: unknown;
  [extra: string]: unknown;
}

export interface Section {
  id: string;
  label: string;
  [extra: string]: unknown;
}

export interface UrlEntry {
  id: string;
  url: string;
  match: string;
  cert_sha256?: string[];
  [extra: string]: unknown;
}

export interface Passkey {
  id: string;
  rp_id: string;
  credential_id: string;
  user_handle: string;
  user_name: string;
  user_display_name?: string;
  rp_name?: string;
  alg: number;
  private_key: string;
  counter: number;
  discoverable: boolean;
  created_at?: number;
  [extra: string]: unknown;
}

export interface Attachment {
  id: string;
  name: string;
  size: number;
  mime?: string;
  key: string;
  blob_sha256?: string;
  created_at?: number;
  [extra: string]: unknown;
}

export interface HistoryEntry {
  id: string;
  field: string;
  label?: string;
  value: unknown;
  until: number;
}

export interface Conflict {
  id: string;
  path: string;
  label: string;
  value: unknown;
  kept?: unknown;
  device?: string;
  at: number;
}

export interface ItemContent {
  format: string;
  template: string;
  title: string;
  favorite?: boolean;
  archived?: boolean;
  tags?: string[];
  fields: Field[];
  sections?: Section[];
  urls?: UrlEntry[];
  passkeys?: Passkey[];
  notes?: string;
  attachments?: Attachment[];
  history?: HistoryEntry[];
  autofill?: { auto_submit?: boolean; never?: boolean; [k: string]: unknown };
  ssh?: { confirm_each_use?: boolean; git_signing?: boolean; [k: string]: unknown };
  conflicts?: Conflict[];
  created_at: number;
  updated_at: number;
  [extra: string]: unknown;
}

export interface ItemView {
  vault_id: string;
  item_id: string;
  template: string;
  title: string;
  subtitle: string;
  favorite: boolean;
  archived: boolean;
  deleted: boolean;
  tags: string[];
  urls: string[];
  has_totp: boolean;
  passkeys: number;
  attachments: number;
  conflicts: number;
  read_only: boolean;
  pending: boolean;
  rejected?: string;
  revision: number;
  created_at: number;
  updated_at: number;
  content?: ItemContent;
}

export interface ItemFilter {
  vault_id?: string;
  template?: string;
  tag?: string;
  favorites?: boolean;
  conflicts?: boolean;
  archived?: boolean;
  trash?: boolean;
  query?: string;
}

export interface SyncReport {
  pulled: number;
  pushed: number;
  merged: number;
  conflicts: number;
  rejected: number;
  restored_to_server: number;
  undecryptable: number;
  rollbacks_detected: number;
  full_resyncs: number;
  finished_at: number;
  /** Vaults the server no longer lists; kept locally (with unsynced edits) but not synced. */
  vaults_missing_on_server?: number;
  /** The server sent unlock material that failed validation; this device keeps its own. */
  account_key_update_refused?: boolean;
}

export interface RevisionInfo {
  revision: number;
  deleted?: boolean;
  created_at: number;
  device_id: string;
  size: number;
}

export interface DeviceRecord {
  id: string;
  name: string;
  platform: string;
  client_version: string;
  created_at: number;
  last_seen_at: number;
  revoked_at?: number;
  current: boolean;
}

export interface AuditEntry {
  at: number;
  action: string;
  device_id: string;
  ip: string;
  detail: string;
}

export interface Finding {
  issue: 'weak' | 'reused' | 'old' | 'totp_available' | 'insecure';
  vault_id: string;
  item_id: string;
  title: string;
  detail: string;
}

export interface SecurityReport {
  findings: Finding[];
  weak: number;
  reused: number;
  old: number;
  totp_available: number;
  insecure: number;
}

export interface HealthReport {
  checked: number;
  ok: number;
  pending: number;
  rejected: number;
  read_only: number;
  conflicts: number;
  problems: [string, string, string][];
  checked_at: number;
}

export interface TemplateInfo {
  id: string;
  label: string;
  icon: string;
  fields: { id: string; kind: string; purpose?: string; multiline: boolean; label: string }[];
}

export type Recipe =
  | { kind: 'random'; length: number; upper: boolean; lower: boolean; digits: boolean; symbols: boolean; avoid_ambiguous: boolean }
  | { kind: 'memorable'; words: number; separator: string; capitalize: boolean; digits: boolean }
  | { kind: 'pin'; length: number };

export interface Generated {
  password: string;
  bits: number;
}

export interface OtpCode {
  code: string;
  remaining: number;
  period: number;
  issuer: string;
  account: string;
}

export interface ImportResultSummary {
  batch_id: string;
  imported: number;
}

export interface ImportPreviewItem {
  title: string;
  template: string;
  mapping: 'full' | 'partial' | 'fallback' | string;
  warnings: string[];
  attachments: number;
  passkeys: number;
}

export interface ImportPreview {
  source: string;
  items: ImportPreviewItem[];
  counts: Record<string, number>;
  warnings: number;
  attachment_bytes: number;
  passkeys: number;
  skipped: [string, string][];
  /** Opaque handle the bridge uses to commit this preview. */
  token: string;
}

export interface CoreErrorShape {
  code: string;
  message: string;
}
