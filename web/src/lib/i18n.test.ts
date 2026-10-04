import { describe, expect, it } from 'vitest';
import { bytes, errorText, relativeTime } from './i18n';
import { errorCode, errorMessage } from './bridge';

describe('i18n helpers', () => {
  it('formats relative times', () => {
    const now = Date.UTC(2026, 9, 4, 12);
    expect(relativeTime(0, now)).toBe('从未');
    expect(relativeTime(now - 10_000, now)).toBe('刚刚');
    expect(relativeTime(now - 5 * 60_000, now)).toContain('5');
  });

  it('formats sizes', () => {
    expect(bytes(512)).toBe('512 B');
    expect(bytes(1536)).toBe('1.5 KB');
    expect(bytes(3 * 1024 * 1024)).toBe('3.0 MB');
  });

  it('maps core error codes', () => {
    expect(errorText('wrong_password', 'x')).toContain('Secret Key');
    expect(errorText('unknown', 'raw message')).toBe('raw message');
  });

  it('reads core error objects', () => {
    const e = { code: 'locked', message: 'locked' };
    expect(errorCode(e)).toBe('locked');
    expect(errorMessage(e)).toBe('locked');
    expect(errorMessage('plain')).toBe('plain');
  });
});
