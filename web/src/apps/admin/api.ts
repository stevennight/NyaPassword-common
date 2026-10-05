// The server's admin API (npw-api admin.rs). Same origin as the console.

export interface BackupTarget {
  id: string;
  kind: 'oss' | 'webdav' | 'fs';
  name: string;
  enabled: boolean;
  protect_mode: boolean;
  endpoint: string;
  bucket: string;
  root: string;
  username: string;
  secret?: string;
  has_secret: boolean;
}

export interface NotifyConfig {
  webhook_url: string;
  telegram_bot_token: string;
  telegram_chat_id: string;
  bark_url: string;
  smtp_host: string;
  smtp_port: number;
  smtp_username: string;
  smtp_password: string;
  smtp_from: string;
  smtp_to: string;
  /** Channels switched off although configured (`webhook`, `telegram`, `bark`, `email`). */
  off: string[];
  /** Alert events that do not notify (`backup_failed`, `check_failed`, `stale`). */
  muted_events: string[];
}

export type Channel = 'webhook' | 'telegram' | 'bark' | 'email';
export type AlertEvent = 'backup_failed' | 'check_failed' | 'stale';

/** Label and date of an offline recovery key (a `recipients` entry). */
export interface RecipientInfo {
  recipient: string;
  label: string;
  /** 0: registered before labels existed. */
  created_at: number;
}

export interface TestStep {
  step: string;
  ok: boolean;
  expected_to_fail?: boolean;
  error?: string | null;
}

export interface AdminSecurity {
  totp_enabled: boolean;
}

export interface TotpSetup {
  secret: string;
  uri: string;
}

/** Stands in for a stored secret in GET /backup; sending it back keeps the stored value. */
export const SECRET_MASK = '••••••••';

export interface BackupSettings {
  retention: { recent: number; daily: number; weekly: number; monthly: number };
  recipients: string[];
  debounce_minutes: number;
  daily_hour_utc: number;
  notify: NotifyConfig;
  recipient_info: RecipientInfo[];
}

export interface TargetResult {
  target_id: string;
  ok: boolean;
  object: string;
  verified: boolean;
  error: string;
}

export interface BackupRun {
  id: string;
  started_at: number;
  finished_at: number;
  trigger: string;
  size: number;
  items: number;
  max_seq: number;
  results: TargetResult[];
}

export interface DrillRun {
  id: string;
  at: number;
  target_id: string;
  object: string;
  ok: boolean;
  detail: string;
  duration_ms: number;
}

export interface TargetStatus {
  target: BackupTarget;
  last_success_at?: number | null;
  last_attempt_at?: number | null;
  last_error: string;
}

export interface BackupStatus {
  settings: BackupSettings;
  server_recipient: string;
  targets: TargetStatus[];
  runs: BackupRun[];
  drills: DrillRun[];
  last_success_at?: number | null;
  last_manual_drill_at?: number | null;
  pending_changes: boolean;
}

export interface Health {
  version: string;
  started_at: number;
  db_ok: boolean;
  integrity_checked_at: number;
  accounts: number;
  devices: number;
  items: number;
  revisions: number;
  attachments: number;
  attachment_bytes: number;
  db_bytes: number;
}

export interface Device {
  id: string;
  name: string;
  platform: string;
  client_version: string;
  created_at: number;
  last_seen_at: number;
  revoked_at?: number;
}

export interface AdminAccount {
  account_id: string;
  login: string;
  created_at: number;
  items: number;
  devices: Device[];
}

export interface Invite {
  code: string;
  expires_at: number;
  used_at?: number | null;
}

export interface AuditEntry {
  at: number;
  action: string;
  device_id: string;
  ip: string;
  detail: string;
}

const KEY = 'npw.admin.token';

export function token(): string | null {
  try {
    return sessionStorage.getItem(KEY);
  } catch {
    return null;
  }
}

export function setToken(t: string | null) {
  try {
    if (t) sessionStorage.setItem(KEY, t);
    else sessionStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
}

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

export async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  const t = token();
  if (t) headers.authorization = `Bearer ${t}`;
  if (body !== undefined) headers['content-type'] = 'application/json';
  const r = await fetch(`/v1/admin${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await r.text();
  const data = text ? JSON.parse(text) : null;
  if (!r.ok) {
    if (r.status === 401) setToken(null);
    throw new ApiError(r.status, data?.code ?? 'http', data?.message ?? r.statusText);
  }
  return data as T;
}
