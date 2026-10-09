import { describe, expect, it } from 'vitest';
import { autoLockLabel, autoLockOptions, parseAutoLock } from './autolock';

describe('auto-lock', () => {
  it('accepts whole minutes from 0 (never) to 7 days', () => {
    expect(parseAutoLock(0)).toBe(0);
    expect(parseAutoLock('45')).toBe(45);
    expect(parseAutoLock(10080)).toBe(10080);
    for (const bad of [-1, 1.5, 10081, '', 'x', null, undefined, NaN]) expect(parseAutoLock(bad)).toBeNull();
  });

  it('labels', () => {
    expect(autoLockLabel(0)).toBe('从不');
    expect(autoLockLabel(45)).toBe('45 分钟');
    expect(autoLockLabel(90)).toBe('1 小时 30 分钟');
    expect(autoLockLabel(240)).toBe('4 小时');
    expect(autoLockLabel(2880)).toBe('2 天');
  });

  it('lists a custom value among the presets', () => {
    expect(autoLockOptions(10)).toEqual([1, 5, 10, 15, 30, 60, 240, 0]);
    expect(autoLockOptions(45)).toEqual([1, 5, 10, 15, 30, 45, 60, 240, 0]);
    expect(autoLockOptions(0)).toEqual([1, 5, 10, 15, 30, 60, 240, 0]);
  });
});
