// Pure helpers of the admin console: the overview's to-do list, schedule
// times in the browser's time zone, and alert channel status. Tested in
// checks.test.ts.

import type { AdminSecurity, BackupStatus, Channel, NotifyConfig } from './api';

export type Page =
  | 'overview'
  | 'backup'
  | 'keys'
  | 'verify'
  | 'notify'
  | 'schedule'
  | 'accounts'
  | 'invites'
  | 'audit'
  | 'admin';

export const HOUR = 3_600_000;
export const DAY = 24 * HOUR;
/** The server alerts when no backup succeeded for this long. */
export const STALE_AFTER = 26 * HOUR;
/** A manual restore drill with the offline key is due every quarter. */
export const MANUAL_DRILL_DUE = 90 * DAY;
/** The automatic check runs weekly. */
export const CHECK_EVERY = 7 * DAY;

export interface Todo {
  id: string;
  text: string;
  /** Where it is fixed. */
  page: Page;
  /** `bad`: data is at risk now; `warn`: should be done. */
  level: 'bad' | 'warn';
}

export function channelConfigured(n: NotifyConfig, c: Channel): boolean {
  switch (c) {
    case 'webhook':
      return !!n.webhook_url;
    case 'telegram':
      return !!n.telegram_bot_token && !!n.telegram_chat_id;
    case 'bark':
      return !!n.bark_url;
    case 'email':
      return !!n.smtp_host && !!n.smtp_to;
  }
}

export const CHANNELS: Channel[] = ['webhook', 'telegram', 'bark', 'email'];

/** Configured and switched on. */
export function activeChannels(n: NotifyConfig): Channel[] {
  return CHANNELS.filter((c) => channelConfigured(n, c) && !(n.off ?? []).includes(c));
}

/** The overview's checklist, most urgent first. */
export function todos(b: BackupStatus, sec: AdminSecurity | null, now = Date.now()): Todo[] {
  const out: Todo[] = [];
  const enabled = b.targets.filter((t) => t.target.enabled);
  if (!enabled.length) {
    out.push({ id: 'no-target', text: '还没有启用的备份目标：数据只在这台服务器上', page: 'backup', level: 'bad' });
  } else {
    const last = b.last_success_at ?? 0;
    const lastRun = b.runs[0];
    if (lastRun && lastRun.results.some((r) => !r.ok)) {
      out.push({ id: 'backup-failed', text: '最近一次备份有目标失败', page: 'backup', level: 'bad' });
    }
    if (!last) out.push({ id: 'never', text: '还没有成功的备份', page: 'backup', level: 'bad' });
    else if (now - last > STALE_AFTER) out.push({ id: 'stale', text: '超过 26 小时没有成功的备份', page: 'backup', level: 'bad' });
  }
  if (!b.settings.recipients.length) {
    out.push({ id: 'no-key', text: '还没有登记离线恢复密钥：服务器整个丢失时备份解不开', page: 'keys', level: 'bad' });
  }
  const check = b.drills[0];
  if (check && !check.ok) out.push({ id: 'check-failed', text: '最近一次自动备份校验失败', page: 'verify', level: 'bad' });
  if (!activeChannels(b.settings.notify).length) {
    out.push({ id: 'no-alert', text: '没有开启的告警通道：备份出问题时没人知道', page: 'notify', level: 'warn' });
  }
  if (sec && !sec.totp_enabled) out.push({ id: 'no-totp', text: '管理员没有开启两步验证（TOTP）', page: 'admin', level: 'warn' });
  const manual = b.last_manual_drill_at ?? 0;
  if (b.settings.recipients.length && (!manual || now - manual > MANUAL_DRILL_DUE)) {
    out.push({
      id: 'manual-drill',
      text: manual ? `上次手动恢复演练是 ${Math.floor((now - manual) / DAY)} 天前，建议每季度一次` : '还没有用离线恢复密钥做过手动恢复演练',
      page: 'verify',
      level: 'warn',
    });
  }
  return out.sort((a, b2) => (a.level === b2.level ? 0 : a.level === 'bad' ? -1 : 1));
}

const pad = (n: number) => String(n).padStart(2, '0');

/** The local wall-clock time ("03:00") of `hourUtc` o'clock UTC on the day of `ref`. */
export function localTimeOfUtcHour(hourUtc: number, ref = new Date()): string {
  const d = new Date(Date.UTC(ref.getUTCFullYear(), ref.getUTCMonth(), ref.getUTCDate(), hourUtc));
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** "UTC+8" / "UTC-3:30" and the IANA name when the browser knows it. */
export function zoneLabel(ref = new Date()): string {
  const off = -ref.getTimezoneOffset();
  const sign = off >= 0 ? '+' : '-';
  const h = Math.floor(Math.abs(off) / 60);
  const m = Math.abs(off) % 60;
  const utc = `UTC${sign}${h}${m ? `:${pad(m)}` : ''}`;
  let name = '';
  try {
    name = Intl.DateTimeFormat().resolvedOptions().timeZone ?? '';
  } catch {
    /* ignore */
  }
  return name ? `${name}（${utc}）` : utc;
}

/** The next daily backup: today's `hourUtc` o'clock UTC, or tomorrow's once that has passed. */
export function nextDailyAt(hourUtc: number, now = Date.now()): number {
  const dayStart = now - (((now % DAY) + DAY) % DAY);
  const today = dayStart + hourUtc * HOUR;
  return today > now ? today : today + DAY;
}
