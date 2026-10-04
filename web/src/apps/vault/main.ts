import { mount } from 'svelte';
import '$lib/theme.css';
import { createBridge } from '$bridge';
import { vault } from '$lib/vault.svelte';
import App from './App.svelte';

try {
  const t = localStorage.getItem('npw.theme');
  if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
} catch {
  /* storage unavailable */
}

const app = mount(App, { target: document.getElementById('app')! });

createBridge()
  .then((bridge) => vault.init(bridge))
  .catch((e) => {
    document.getElementById('app')!.textContent = `启动失败：${e?.message ?? e}`;
  });

export default app;
