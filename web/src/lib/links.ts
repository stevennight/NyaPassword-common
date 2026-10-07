// Opening websites from the vault (an item's URLs, link fields). The desktop
// app registers its own opener: its window cannot open another one, the link
// goes to the default browser instead.

let opener: ((url: string) => Promise<unknown>) | null = null;

export function setExternalOpener(f: (url: string) => Promise<unknown>) {
  opener = f;
}

/** The http(s) address to open for a stored URL ("example.com" → https://example.com/), or null (apps, other schemes). */
export function webUrl(raw: string): string | null {
  const s = raw.trim();
  if (!s) return null;
  // another scheme (androidapp:, javascript:, file:...), but not "host:port"
  const scheme = /^([a-z][a-z0-9+.-]*):(.*)$/is.exec(s);
  if (scheme && !/^https?$/i.test(scheme[1]!) && !/^\d+([/?#]|$)/.test(scheme[2]!)) return null;
  try {
    const u = new URL(/^https?:/i.test(s) ? s : `https://${s}`);
    return (u.protocol === 'http:' || u.protocol === 'https:') && u.hostname ? u.href : null;
  } catch {
    return null;
  }
}

export async function openExternal(url: string) {
  const u = webUrl(url);
  if (!u) return;
  if (opener) await opener(u);
  else window.open(u, '_blank', 'noopener,noreferrer');
}
