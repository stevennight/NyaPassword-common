// The UI is Chinese first. `locale()` decides the labels of new template
// fields in the core; UI strings live in the components (English can be
// added later by moving them here).

export function locale(): string {
  const l = (typeof navigator !== 'undefined' && navigator.language) || 'zh-CN';
  return l.toLowerCase().startsWith('zh') ? 'zh-CN' : 'zh-CN';
}

const rtf = typeof Intl !== 'undefined' ? new Intl.RelativeTimeFormat('zh-CN', { numeric: 'auto' }) : null;

export function relativeTime(ms: number, now = Date.now()): string {
  if (!ms) return '从未';
  const diff = (ms - now) / 1000;
  const abs = Math.abs(diff);
  if (!rtf) return new Date(ms).toLocaleString();
  if (abs < 45) return '刚刚';
  if (abs < 3600) return rtf.format(Math.round(diff / 60), 'minute');
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), 'hour');
  if (abs < 86400 * 30) return rtf.format(Math.round(diff / 86400), 'day');
  if (abs < 86400 * 365) return rtf.format(Math.round(diff / (86400 * 30)), 'month');
  return rtf.format(Math.round(diff / (86400 * 365)), 'year');
}

export function dateTime(ms: number): string {
  if (!ms) return '—';
  return new Date(ms).toLocaleString('zh-CN', { hour12: false });
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

/** Messages for core error codes. */
export function errorText(code: string, message: string): string {
  switch (code) {
    case 'wrong_password':
      return '主密码或 Secret Key 不正确';
    case 'locked':
      return '已锁定，请先解锁';
    case 'offline':
    case 'network':
      return `无法连接服务器（${message}）`;
    case 'session_expired':
      return '登录已过期，请重新输入主密码';
    case 'device_revoked':
      return '此设备已被移出账户，请重新登录';
    case 'read_only':
      return '这个条目由更新版本的 NyaPassword 写入，请先更新本应用再编辑';
    case 'not_signed_in':
      return '此设备尚未登录';
    default:
      return message || code;
  }
}
