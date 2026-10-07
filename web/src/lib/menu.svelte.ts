// The app's own right-click menu (components/ContextMenu.svelte, shown by
// Overlays): what a right-click on an item or a field offers instead of the
// browser's / WebView's menu.

export interface MenuItem {
  label: string;
  run: () => unknown;
  danger?: boolean;
  disabled?: boolean;
}

/** `null` is a separator. */
export type MenuEntry = MenuItem | null;

export const menu = $state<{ open: { x: number; y: number; entries: MenuEntry[] } | null }>({ open: null });

/** Shows the menu at the pointer; leading, trailing and repeated separators are dropped. */
export function openMenu(e: MouseEvent, entries: MenuEntry[]) {
  e.preventDefault();
  const clean: MenuEntry[] = [];
  for (const it of entries) {
    if (it === null && (clean.length === 0 || clean[clean.length - 1] === null)) continue;
    clean.push(it);
  }
  if (clean[clean.length - 1] === null) clean.pop();
  menu.open = clean.length ? { x: e.clientX, y: e.clientY, entries: clean } : null;
}

export function closeMenu() {
  menu.open = null;
}
