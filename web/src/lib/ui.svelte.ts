// Small shared UI state: toasts and confirm dialogs.

export interface Toast {
  id: number;
  text: string;
  kind: 'info' | 'ok' | 'error';
}

export const toasts = $state<Toast[]>([]);
let next = 1;

export function toast(text: string, kind: Toast['kind'] = 'info', ms = 2600) {
  const id = next++;
  toasts.push({ id, text, kind });
  setTimeout(() => {
    const i = toasts.findIndex((t) => t.id === id);
    if (i >= 0) toasts.splice(i, 1);
  }, ms);
}

export interface ConfirmRequest {
  title: string;
  body: string;
  ok: string;
  danger: boolean;
  resolve: (v: boolean) => void;
}

export const confirmState = $state<{ req: ConfirmRequest | null }>({ req: null });

export function confirm(title: string, body: string, ok = '确定', danger = false): Promise<boolean> {
  return new Promise((resolve) => {
    confirmState.req = { title, body, ok, danger, resolve };
  });
}

/** Template id → icon letter / colour for list avatars. */
export function avatar(title: string, template: string): { letter: string; color: string } {
  const palette = ['#3d63f5', '#e07a2e', '#0e9f6e', '#7a3cff', '#c8102e', '#0891b2', '#334155', '#d97706', '#db2777', '#2f6fde'];
  const t = (title || '?').trim();
  const letter = [...t][0]?.toUpperCase() ?? '?';
  let h = 0;
  for (const c of t + template) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return { letter, color: palette[h % palette.length] ?? '#3d63f5' };
}

export const TEMPLATE_ICONS: Record<string, string> = {
  login: '🔑', password: '🔒', secure_note: '📝', credit_card: '💳', bank_account: '🏦', identity: '🪪', document: '📄',
  ssh_key: '⌘', server: '🖥', database: '🗄', api_credential: '🔌', wifi: '📶', software_license: '📦', crypto_wallet: '🪙',
};
