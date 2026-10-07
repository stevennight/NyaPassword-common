// Desktop windows behave like an app, not a web page: links open in the
// default browser (the window cannot open a new one), and the WebView's own
// right-click menu (back, refresh, save, print...) is not shown. Text fields
// and selected text keep it for cut / copy / paste; links get the app's menu.

import { invoke } from '@tauri-apps/api/core';
import { openExternal, setExternalOpener, webUrl } from './links';
import { openMenu } from './menu.svelte';
import { toast } from './ui.svelte';

/** An http(s) link to another site under the event target. */
function externalLink(e: Event): string | null {
  const a = (e.target as Element | null)?.closest?.('a[href]') as HTMLAnchorElement | null;
  if (!a) return null;
  const url = webUrl(a.href);
  return url && new URL(url).origin !== location.origin ? url : null;
}

function open(url: string) {
  openExternal(url).catch((err) => toast(`无法打开链接：${err?.message ?? err}`, 'error', 5000));
}

export function installDesktopWebview() {
  setExternalOpener((url) => invoke('open_url', { url }));

  const onClick = (e: MouseEvent) => {
    if (e.defaultPrevented || e.button > 1) return;
    const url = externalLink(e);
    if (!url) return;
    e.preventDefault();
    open(url);
  };
  document.addEventListener('click', onClick);
  document.addEventListener('auxclick', onClick);

  window.addEventListener('contextmenu', (e) => {
    if (e.defaultPrevented) return;
    if ((e.target as Element | null)?.closest?.('input, textarea, [contenteditable=""], [contenteditable="true"]')) return;
    const url = externalLink(e);
    if (url) {
      openMenu(e, [
        { label: '在浏览器中打开', run: () => open(url) },
        {
          label: '复制链接',
          run: () => invoke('copy', { text: url, secret: false }).then(() => toast('已复制链接')),
        },
      ]);
      return;
    }
    if (window.getSelection()?.toString()) return;
    e.preventDefault();
  });
}
