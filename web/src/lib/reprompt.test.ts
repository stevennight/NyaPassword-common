import { describe, expect, it } from 'vitest';
import { afterOpen, gated, itemKey, verifyError } from './reprompt';

const a = { vault_id: 'v1', item_id: 'a', reprompt: true };
const b = { vault_id: 'v1', item_id: 'b', reprompt: true };
const plain = { vault_id: 'v1', item_id: 'c' };

describe('reprompt gating', () => {
  it('gates only items that ask for it', () => {
    expect(gated(plain, null)).toBe(false);
    expect(gated({ ...plain, reprompt: false }, null)).toBe(false);
    expect(gated(a, null)).toBe(true);
    expect(gated(null, null)).toBe(false);
  });

  it('verification is for one item', () => {
    const v = itemKey('v1', 'a');
    expect(gated(a, v)).toBe(false);
    expect(gated(b, v)).toBe(true);
    // same item id in another vault is another item
    expect(gated({ ...a, vault_id: 'v2' }, v)).toBe(true);
  });

  it('opening another item ends the verification, reopening the same keeps it', () => {
    const v = itemKey('v1', 'a');
    expect(afterOpen(v, 'v1', 'a')).toBe(v);
    expect(afterOpen(v, 'v1', 'b')).toBeNull();
    expect(afterOpen(null, 'v1', 'a')).toBeNull();
    // back to the first item: it has to be verified again
    expect(gated(a, afterOpen(afterOpen(v, 'v1', 'b'), 'v1', 'a'))).toBe(true);
  });

  it('explains failures', () => {
    expect(verifyError('wrong_password', 'x')).toBe('主密码不正确');
    expect(verifyError('invalid', '已取消 Windows Hello 验证')).toBe('已取消 Windows Hello 验证');
    expect(verifyError('', '')).toBe('验证失败');
  });
});
