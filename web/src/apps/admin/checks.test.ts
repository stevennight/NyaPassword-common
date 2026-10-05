import { describe, expect, it } from 'vitest';
import type { BackupStatus, BackupTarget, NotifyConfig } from './api';
import { activeChannels, DAY, HOUR, localTimeOfUtcHour, nextDailyAt, todos } from './checks';

const now = Date.UTC(2026, 9, 5, 12);

function notify(over: Partial<NotifyConfig> = {}): NotifyConfig {
  return {
    webhook_url: '', telegram_bot_token: '', telegram_chat_id: '', bark_url: '',
    smtp_host: '', smtp_port: 0, smtp_username: '', smtp_password: '', smtp_from: '', smtp_to: '',
    off: [], muted_events: [], ...over,
  };
}

const target: BackupTarget = {
  id: 't', kind: 'fs', name: 'NAS', enabled: true, protect_mode: false, endpoint: '/backup', bucket: '', root: 'npw', username: '', has_secret: false,
};

function status(over: Partial<BackupStatus> = {}): BackupStatus {
  return {
    settings: { retention: { recent: 48, daily: 30, weekly: 12, monthly: 24 }, recipients: ['age1x'], debounce_minutes: 10, daily_hour_utc: 19, notify: notify({ bark_url: 'https://bark.example.com/k' }), recipient_info: [] },
    server_recipient: 'age1server',
    targets: [{ target, last_success_at: now - HOUR, last_error: '' }],
    runs: [{ id: 'r', started_at: now - HOUR, finished_at: now - HOUR, trigger: 'daily', size: 1, items: 1, max_seq: 1, results: [{ target_id: 't', ok: true, object: 'o', verified: true, error: '' }] }],
    drills: [{ id: 'd', at: now - DAY, target_id: 't', object: 'o', ok: true, detail: '', duration_ms: 5 }],
    last_success_at: now - HOUR,
    last_manual_drill_at: now - 10 * DAY,
    pending_changes: false,
    ...over,
  };
}

describe('admin overview checklist', () => {
  it('is empty when everything is set up', () => {
    expect(todos(status(), { totp_enabled: true }, now)).toEqual([]);
  });

  it('lists each problem with the page that fixes it, urgent ones first', () => {
    const s = status({
      targets: [],
      settings: { ...status().settings, recipients: [], notify: notify({ bark_url: 'https://bark.example.com/k', off: ['bark'] }) },
      drills: [{ id: 'd', at: now, target_id: 't', object: '', ok: false, detail: 'x', duration_ms: 1 }],
    });
    const list = todos(s, { totp_enabled: false }, now);
    expect(list.map((t) => [t.id, t.page])).toEqual([
      ['no-target', 'backup'],
      ['no-key', 'keys'],
      ['check-failed', 'verify'],
      ['no-alert', 'notify'],
      ['no-totp', 'admin'],
    ]);
  });

  it('notices stale and failed backups and an overdue manual drill', () => {
    const s = status({
      last_success_at: now - 30 * HOUR,
      runs: [{ ...status().runs[0], results: [{ target_id: 't', ok: false, object: '', verified: false, error: 'down' }] }],
      last_manual_drill_at: now - 100 * DAY,
    });
    expect(todos(s, null, now).map((t) => t.id)).toEqual(['backup-failed', 'stale', 'manual-drill']);
  });

  it('counts only configured channels that are switched on', () => {
    expect(activeChannels(notify({ telegram_bot_token: 'x' }))).toEqual([]);
    expect(activeChannels(notify({ telegram_bot_token: 'x', telegram_chat_id: '1', webhook_url: 'https://h.example.com', off: ['webhook'] }))).toEqual(['telegram']);
  });
});

describe('schedule times', () => {
  it('finds the next daily backup', () => {
    expect(nextDailyAt(19, now)).toBe(Date.UTC(2026, 9, 5, 19));
    expect(nextDailyAt(3, now)).toBe(Date.UTC(2026, 9, 6, 3));
  });

  it('shows UTC hours in local time', () => {
    const ref = new Date(now);
    const d = new Date(Date.UTC(2026, 9, 5, 19));
    expect(localTimeOfUtcHour(19, ref)).toBe(`${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`);
  });
});
