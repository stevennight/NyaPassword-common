// Writes src/apps/admin/agekey.vectors.json: age key pairs produced by the
// admin console's in-browser key generator (agekey.ts, run here on Node's
// WebCrypto). The Rust side checks that the server's age implementation
// accepts them (npw-backup tests, server tests/backup.rs), and agekey.test.ts
// checks that agekey.ts still produces exactly these values.
//
//   node scripts/age-vectors.mjs        (Node 22.18+: runs the .ts directly)

import { writeFileSync } from 'node:fs';
import { generateIdentity, identityFromSecret, keyFileText } from '../src/apps/admin/agekey.ts';

const fromHex = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));

const secrets = [
  '0000000000000000000000000000000000000000000000000000000000000000',
  '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
  'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
];
const fixed = [];
for (const s of secrets) fixed.push({ secret_hex: s, ...(await identityFromSecret(fromHex(s))) });

// one random pair, exactly as the "生成离线恢复密钥" button makes it, with its key file
const pair = await generateIdentity();
const sheet = {
  pair,
  label: '测试恢复密钥',
  createdAt: Date.UTC(2026, 9, 5),
  server: 'https://vault.example.com',
  targets: [
    { kind: 'oss', name: '阿里云 OSS', endpoint: 'https://oss-cn-hangzhou.aliyuncs.com', bucket: 'example-backup', root: 'nyapassword', username: 'EXAMPLE-ACCESS-KEY-ID' },
    { kind: 'fs', name: 'NAS', endpoint: '/mnt/nas/backup', bucket: '', root: 'npw', username: '' },
  ],
};
const out = {
  note: 'Test vectors only (not real keys). Written by scripts/age-vectors.mjs from src/apps/admin/agekey.ts.',
  fixed,
  generated: { ...pair, sheet: { ...sheet, pair: undefined }, key_file: keyFileText(sheet) },
};
writeFileSync(new URL('../src/apps/admin/agekey.vectors.json', import.meta.url), JSON.stringify(out, null, 2) + '\n');
console.log('wrote agekey.vectors.json');
