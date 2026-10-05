import { describe, expect, it } from 'vitest';
import raw from './agekey.vectors.json?raw';
import {
  bech32Decode,
  bech32Encode,
  generateIdentity,
  identityFromSecret,
  isRecipient,
  keyFileText,
  recipientOf,
  restoreCommand,
  x25519BaseLadder,
  x25519BaseWebCrypto,
  type RestoreTarget,
} from './agekey';

const fromHex = (h: string) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

interface Vectors {
  fixed: { secret_hex: string; identity: string; recipient: string }[];
  generated: {
    identity: string;
    recipient: string;
    sheet: { label: string; createdAt: number; server: string; targets: RestoreTarget[] };
    key_file: string;
  };
}
const vectors = JSON.parse(raw) as Vectors;

describe('offline recovery keys (age X25519)', () => {
  it('computes X25519 like RFC 7748 §6.1, on WebCrypto and with the fallback', async () => {
    const alice = fromHex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
    const expected = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';
    expect(hex(x25519BaseLadder(alice))).toBe(expected);
    const wc = await x25519BaseWebCrypto(alice);
    expect(wc && hex(wc)).toBe(expected);
    const bob = fromHex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
    expect(hex(x25519BaseLadder(bob))).toBe('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
  });

  it('still produces the vectors the Rust tests check', async () => {
    for (const v of vectors.fixed) {
      expect(await identityFromSecret(fromHex(v.secret_hex))).toEqual({ identity: v.identity, recipient: v.recipient });
      expect(await recipientOf(v.identity)).toBe(v.recipient);
    }
    const g = vectors.generated;
    expect(await recipientOf(g.identity)).toBe(g.recipient);
    expect(keyFileText({ ...g.sheet, pair: { identity: g.identity, recipient: g.recipient } })).toBe(g.key_file);
  });

  it('generates fresh, well-formed pairs', async () => {
    const a = await generateIdentity();
    const b = await generateIdentity();
    expect(a.identity).not.toBe(b.identity);
    expect(a.identity).toMatch(/^AGE-SECRET-KEY-1[0-9A-Z]{58}$/);
    expect(a.recipient).toMatch(/^age1[0-9a-z]{58}$/);
    expect(isRecipient(a.recipient)).toBe(true);
    expect(await recipientOf(a.identity)).toBe(a.recipient);
    // the fallback agrees with WebCrypto
    const secret = bech32Decode(a.identity).bytes;
    const wc = await x25519BaseWebCrypto(secret);
    expect(hex(x25519BaseLadder(secret))).toBe(hex(wc!));
  });

  it('rejects damaged or foreign keys', async () => {
    const r = vectors.fixed[1].recipient;
    const flipped = r.slice(0, 10) + (r[10] === 'q' ? 'p' : 'q') + r.slice(11);
    expect(isRecipient(flipped)).toBe(false);
    expect(isRecipient(r.toUpperCase())).toBe(false);
    expect(isRecipient('age1')).toBe(false);
    expect(isRecipient(vectors.fixed[1].identity)).toBe(false);
    expect(isRecipient(bech32Encode('age', new Uint8Array(31)))).toBe(false);
    await expect(recipientOf(r)).rejects.toThrow();
  });

  it('writes the key file so that restore finds exactly one identity line', () => {
    const g = vectors.generated;
    const lines = g.key_file.split('\n').filter((l) => l.startsWith('AGE-SECRET-KEY-'));
    expect(lines).toEqual([g.identity]);
    expect(g.key_file.split('\n').filter((l) => l && !l.startsWith('#') && !l.startsWith('AGE-'))).toEqual([]);
    expect(restoreCommand({ kind: 'webdav', name: 'NAS', endpoint: 'https://dav.example.com/dav/', bucket: '', root: 'my backups', username: 'me' })).toBe(
      "nyapassword-server restore --identity nyapassword-recovery-key.txt --to ./data --kind webdav --endpoint https://dav.example.com/dav/ --root 'my backups' --username me",
    );
  });
});
