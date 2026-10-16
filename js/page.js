// ページ共通の小さなヘルパー（ブラウザ専用）。

/**
 * connect-src をこのサーバーだけに絞る CSP を追加する。
 * HTML 側の CSP は connect-src https: までしか絞れない（サーバーを変更可能にしているため）。
 * CSP は複数あると「すべてを満たす」ものだけが許可されるので、ここで追加すると
 * 以後このページから接続できるのはこのサーバーのオリジンだけになる（緩めることはできない）。
 * @param {string | null} server null なら一切の接続を禁止
 */
export function lockConnectSrc(server) {
  const meta = document.createElement('meta');
  meta.httpEquiv = 'Content-Security-Policy';
  meta.content = `connect-src ${server ? new URL(server).origin : "'none'"}`;
  document.head.append(meta);
}

/**
 * 他のサイトの iframe に埋め込まれていたら、表示を消して止める（クリックジャッキング対策）。
 * GitHub Pages ではレスポンスヘッダー（frame-ancestors / X-Frame-Options）を設定できないため。
 */
export function ensureTopLevel() {
  if (window.top !== window.self) {
    document.documentElement.replaceChildren();
    throw new Error('iframe 内では動作しません');
  }
}

/**
 * @param {string} id
 * @returns {HTMLElement}
 */
export function $(id) {
  const el = document.getElementById(id);
  if (!el) throw new Error(`#${id} がありません`);
  return el;
}

/** @param {number} ms */
export function formatTime(ms) {
  return new Date(ms).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

/**
 * @param {string} text
 * @returns {Promise<boolean>}
 */
export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/**
 * @param {HTMLElement} el
 * @param {string} text
 * @param {'ok' | 'error' | ''} [kind]
 */
export function setStatus(el, text, kind = '') {
  el.textContent = text;
  el.className = `status ${kind}`.trim();
}
