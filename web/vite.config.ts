import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

// Two pages: index.html (the vault) and admin.html (the server's admin console);
// the desktop build has desktop.html (Quick Access, confirmations) instead of admin.
// The default build is the web vault served by the server: the core runs as
// WebAssembly (src/wasm/pkg, built by scripts/build-wasm.mjs). `--mode desktop`
// builds the vault for the Tauri app, which talks to the native core instead.
export default defineConfig(({ mode }) => {
  const desktop = mode === 'desktop';
  return {
    plugins: [svelte()],
    define: { __APP_VERSION__: JSON.stringify(process.env.NPW_VERSION ?? pkg.version) },
    base: desktop ? './' : '/',
    resolve: {
      alias: {
        $lib: fileURLToPath(new URL('./src/lib', import.meta.url)),
        $components: fileURLToPath(new URL('./src/components', import.meta.url)),
        $bridge: fileURLToPath(new URL(desktop ? './src/lib/bridge-tauri.ts' : './src/lib/bridge-wasm.ts', import.meta.url)),
      },
    },
    build: {
      outDir: desktop ? 'dist-desktop' : 'dist',
      emptyOutDir: true,
      target: ['es2022', 'chrome110', 'safari16'],
      rollupOptions: {
        // desktop.html: the desktop app's Quick Access and confirmation windows
        input: desktop ? { index: 'index.html', desktop: 'desktop.html' } : { index: 'index.html', admin: 'admin.html' },
      },
    },
    server: {
      port: 5180,
      strictPort: true,
      // the dev server proxies the API to a local nyapassword-server
      proxy: { '/v1': { target: 'http://127.0.0.1:8087', ws: true } },
    },
    test: { include: ['src/**/*.test.ts'] },
  };
});
