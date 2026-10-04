// Builds crates/npw-wasm for the browser and generates the JS bindings into
// src/wasm/pkg (needs the wasm32-unknown-unknown target and wasm-bindgen-cli
// matching the wasm-bindgen version in Cargo.lock).
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const web = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const common = path.dirname(web);
const run = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, stdio: 'inherit' });

run('cargo', ['build', '--profile', 'wasm-release', '--target', 'wasm32-unknown-unknown', '-p', 'npw-wasm'], common);
const wasm = path.join(common, '..', 'target', 'wasm32-unknown-unknown', 'wasm-release', 'npw_wasm.wasm');
if (!existsSync(wasm)) throw new Error(`not found: ${wasm}`);
run('wasm-bindgen', ['--target', 'web', '--out-dir', path.join(web, 'src', 'wasm', 'pkg'), '--out-name', 'npw', wasm], web);
console.log('npw-wasm → src/wasm/pkg');
