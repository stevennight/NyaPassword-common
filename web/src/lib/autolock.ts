// Idle auto-lock: the same choices on every client (web, desktop, extension;
// Android mirrors them in Settings.kt). Minutes; 0 = never.

export const AUTO_LOCK_DEFAULT = 10;
/** Longest custom value: 7 days. */
export const AUTO_LOCK_MAX = 7 * 24 * 60;
export const AUTO_LOCK_PRESETS = [1, 5, 10, 15, 30, 60, 240, 0];

/** A stored value, or null when it is not one (missing, negative, too long, fractional). */
export function parseAutoLock(v: unknown): number | null {
  const n = typeof v === 'string' && v.trim() !== '' ? Number(v) : v;
  return typeof n === 'number' && Number.isInteger(n) && n >= 0 && n <= AUTO_LOCK_MAX ? n : null;
}

export function autoLockLabel(m: number): string {
  if (m === 0) return '从不';
  if (m < 60) return `${m} 分钟`;
  const h = Math.floor(m / 60);
  const r = m % 60;
  if (h % 24 === 0 && r === 0) return `${h / 24} 天`;
  return r === 0 ? `${h} 小时` : `${h} 小时 ${r} 分钟`;
}

/** The presets plus the current value when it is a custom one, shortest first, "never" last. */
export function autoLockOptions(current: number): number[] {
  const timed = new Set(AUTO_LOCK_PRESETS.filter((m) => m > 0));
  if (current > 0) timed.add(current);
  return [...[...timed].sort((a, b) => a - b), 0];
}
