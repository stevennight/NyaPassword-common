// The desktop app's small windows (built only with `--mode desktop`):
// `desktop.html#quick` is Quick Access, `desktop.html#prompt` a confirmation
// window (SSH signature, browser extension pairing). They talk to the app with
// plain Tauri commands and do not load the vault UI.

import { mount } from 'svelte';
import '$lib/theme.css';
import { installDesktopWebview } from '$lib/desktop-webview';
import QuickAccess from '$components/desktop/QuickAccess.svelte';
import Prompt from '$components/desktop/Prompt.svelte';

try {
  const t = localStorage.getItem('npw.theme');
  if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
} catch {
  /* storage unavailable */
}

installDesktopWebview();

const target = document.getElementById('app')!;
const app = location.hash.startsWith('#prompt') ? mount(Prompt, { target }) : mount(QuickAccess, { target });

export default app;
