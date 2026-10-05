// Offline backup recovery keys, generated in the browser: an age X25519 key
// pair (identity `AGE-SECRET-KEY-1…`, recipient `age1…`). The private key
// never leaves the page; only the recipient is sent to the server.
//
// X25519 runs on WebCrypto; browsers without X25519 in WebCrypto fall back to
// a small BigInt Montgomery ladder (RFC 7748). Keys are Bech32-encoded the way
// age does it (BIP 173 checksum, no length limit, the identity upper-case).
// Interop with the server's age implementation is tested in
// agekey.test.ts (fixed vectors written to agekey.vectors.json) and on the
// Rust side (npw-backup and the server's restore path read the same vectors).

export interface AgeKeyPair {
  /** `AGE-SECRET-KEY-1…`: the private key. */
  identity: string;
  /** `age1…`: the public key (backup recipient). */
  recipient: string;
}

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const IDENTITY_HRP = 'age-secret-key-';
const RECIPIENT_HRP = 'age';

function polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >>> i) & 1) chk ^= GEN[i];
  }
  return chk >>> 0;
}

function hrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}

function convertBits(data: ArrayLike<number>, from: number, to: number, pad: boolean): number[] {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  const max = (1 << to) - 1;
  for (let i = 0; i < data.length; i++) {
    const v = data[i];
    if (v < 0 || v >> from) throw new Error('bech32: bad value');
    acc = (acc << from) | v;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & max);
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & max);
  } else if (bits >= from || ((acc << (to - bits)) & max)) {
    throw new Error('bech32: bad padding');
  }
  return out;
}

/** Bech32 (BIP 173) without the 90-character limit, lower case. */
export function bech32Encode(hrp: string, bytes: Uint8Array): string {
  const data = convertBits(bytes, 8, 5, true);
  const mod = polymod([...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = [0, 1, 2, 3, 4, 5].map((i) => (mod >>> (5 * (5 - i))) & 31);
  return `${hrp}1${[...data, ...checksum].map((d) => CHARSET[d]).join('')}`;
}

/** Decodes Bech32 (either case, not mixed). Throws on a bad checksum. */
export function bech32Decode(s: string): { hrp: string; bytes: Uint8Array } {
  if (s !== s.toLowerCase() && s !== s.toUpperCase()) throw new Error('bech32: mixed case');
  const str = s.toLowerCase();
  const pos = str.lastIndexOf('1');
  if (pos < 1 || pos + 7 > str.length) throw new Error('bech32: no separator');
  const hrp = str.slice(0, pos);
  const data: number[] = [];
  for (const c of str.slice(pos + 1)) {
    const d = CHARSET.indexOf(c);
    if (d < 0) throw new Error('bech32: bad character');
    data.push(d);
  }
  if (polymod([...hrpExpand(hrp), ...data]) !== 1) throw new Error('bech32: bad checksum');
  return { hrp, bytes: new Uint8Array(convertBits(data.slice(0, -6), 5, 8, false)) };
}

// ---- X25519

const P = (1n << 255n) - 19n;

function mod(a: bigint): bigint {
  const r = a % P;
  return r < 0n ? r + P : r;
}

function powMod(b: bigint, e: bigint): bigint {
  let r = 1n;
  b = mod(b);
  while (e > 0n) {
    if (e & 1n) r = mod(r * b);
    b = mod(b * b);
    e >>= 1n;
  }
  return r;
}

/** X25519(k, 9) with BigInt (RFC 7748 §5): the fallback and the test oracle. */
export function x25519BaseLadder(secret: Uint8Array): Uint8Array {
  const k = secret.slice();
  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;
  let scalar = 0n;
  for (let i = 31; i >= 0; i--) scalar = (scalar << 8n) | BigInt(k[i]);
  const x1 = 9n;
  let [x2, z2, x3, z3] = [1n, 0n, 9n, 1n];
  let swap = 0n;
  for (let t = 254n; t >= 0n; t--) {
    const kt = (scalar >> t) & 1n;
    swap ^= kt;
    if (swap) [x2, x3, z2, z3] = [x3, x2, z3, z2];
    swap = kt;
    const a = mod(x2 + z2);
    const aa = mod(a * a);
    const b = mod(x2 - z2);
    const bb = mod(b * b);
    const e = mod(aa - bb);
    const c = mod(x3 + z3);
    const d = mod(x3 - z3);
    const da = mod(d * a);
    const cb = mod(c * b);
    x3 = mod((da + cb) * (da + cb));
    z3 = mod(x1 * mod((da - cb) * (da - cb)));
    x2 = mod(aa * bb);
    z2 = mod(e * (aa + 121665n * e));
  }
  if (swap) [x2, z2] = [x3, z3];
  let u = mod(x2 * powMod(z2, P - 2n));
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(u & 0xffn);
    u >>= 8n;
  }
  return out;
}

// PKCS#8 wrapping of a raw X25519 private key (RFC 8410).
const PKCS8_PREFIX = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20];

function b64urlDecode(s: string): Uint8Array {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}

/** X25519(k, 9) on WebCrypto; null when the browser does not support X25519. */
export async function x25519BaseWebCrypto(secret: Uint8Array): Promise<Uint8Array | null> {
  try {
    const der = new Uint8Array([...PKCS8_PREFIX, ...secret]);
    const key = await crypto.subtle.importKey('pkcs8', der, { name: 'X25519' }, true, ['deriveBits']);
    const jwk = await crypto.subtle.exportKey('jwk', key);
    return jwk.x ? b64urlDecode(jwk.x) : null;
  } catch {
    return null;
  }
}

export async function publicKeyOf(secret: Uint8Array): Promise<Uint8Array> {
  if (secret.length !== 32) throw new Error('X25519 keys are 32 bytes');
  return (await x25519BaseWebCrypto(secret)) ?? x25519BaseLadder(secret);
}

export async function identityFromSecret(secret: Uint8Array): Promise<AgeKeyPair> {
  const pub = await publicKeyOf(secret);
  return {
    identity: bech32Encode(IDENTITY_HRP, secret).toUpperCase(),
    recipient: bech32Encode(RECIPIENT_HRP, pub),
  };
}

/** A new random key pair (the secret comes from crypto.getRandomValues). */
export async function generateIdentity(): Promise<AgeKeyPair> {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  try {
    return await identityFromSecret(secret);
  } finally {
    secret.fill(0);
  }
}

export async function recipientOf(identity: string): Promise<string> {
  const { hrp, bytes } = bech32Decode(identity.trim());
  if (hrp !== IDENTITY_HRP || bytes.length !== 32) throw new Error('不是 age 私钥（AGE-SECRET-KEY-1…）');
  return (await identityFromSecret(bytes)).recipient;
}

/** An X25519 age recipient (`age1…`, 32 bytes, valid checksum). */
export function isRecipient(s: string): boolean {
  try {
    const t = s.trim();
    if (t !== t.toLowerCase()) return false;
    const { hrp, bytes } = bech32Decode(t);
    return hrp === RECIPIENT_HRP && bytes.length === 32;
  } catch {
    return false;
  }
}

// ---- the recovery sheet

/** The non-secret parts of a backup target needed on the restore command line. */
export interface RestoreTarget {
  kind: 'oss' | 'webdav' | 'fs';
  name: string;
  endpoint: string;
  bucket: string;
  root: string;
  username: string;
}

/** The file the identity is saved as (`--identity`). */
export const KEY_FILE_NAME = 'nyapassword-recovery-key.txt';

const quote = (s: string) => (/^[\w./:@-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`);

/** `nyapassword-server restore …` for one target (secrets come from NYAPASSWORD_RESTORE_SECRET). */
export function restoreCommand(t: RestoreTarget | null, keyFile = KEY_FILE_NAME): string {
  const base = `nyapassword-server restore --identity ${keyFile} --to ./data`;
  if (!t) return `${base} --file <备份文件 nyapassword-….tar.zst.age>`;
  const parts = [base, `--kind ${t.kind}`, `--endpoint ${quote(t.endpoint)}`];
  if (t.kind === 'oss') parts.push(`--bucket ${quote(t.bucket)}`);
  if (t.root) parts.push(`--root ${quote(t.root)}`);
  if (t.kind !== 'fs' && t.username) parts.push(`--username ${quote(t.username)}`);
  return parts.join(' ');
}

export interface SheetInfo {
  pair: AgeKeyPair;
  label: string;
  createdAt: number;
  server: string;
  targets: RestoreTarget[];
}

const isoDate = (ms: number) => new Date(ms).toISOString().slice(0, 10);

/**
 * The downloadable key file: comment lines (`#`) with the instructions, then
 * the identity on its own line. `nyapassword-server restore --identity` and
 * `age -d -i` both read it as is.
 */
export function keyFileText(s: SheetInfo): string {
  const lines = [
    '# NyaPassword 备份恢复密钥（age 私钥）',
    `# 标签：${s.label}`,
    `# 创建：${isoDate(s.createdAt)}`,
    `# 服务器：${s.server}`,
    `# 公钥：${s.pair.recipient}`,
    '#',
    '# 服务器（连同数据目录）整个丢失时，只有这把私钥能解开备份。',
    '# 恢复（在新服务器上；目标的密码 / AccessKey Secret 用环境变量 NYAPASSWORD_RESTORE_SECRET 传）：',
    ...s.targets.map((t) => `#   ${restoreCommand(t)}`),
    `#   ${restoreCommand(null)}`,
    '# 只下载、解密、校验，不写入任何东西：在命令末尾加 --dry-run',
    '# 没有 nyapassword-server 时也可以用 age 解密：age -d -i 本文件 备份文件 > backup.tar.zst',
    '# 请打印或存到 U 盘，与紧急恢复包放在一起；不要只存在密码库或这台服务器上。',
    s.pair.identity,
    '',
  ];
  return lines.join('\n');
}
