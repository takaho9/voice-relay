// ペアリング情報（マスターシークレット + ntfy サーバー URL）の読み書き。
// URL ではフラグメント（# 以降）にだけ載せる: #k=<秘密>&s=<サーバー>
// s は既定サーバーのときは省略する。
// エラーメッセージには入力値を含めない（秘密が漏れないように）。

import { SECRET_BYTES, decodeBase64url, encodeBase64url } from './crypto.js';

export const DEFAULT_SERVER = 'https://ntfy.sh';

/** @typedef {{ secret: Uint8Array, server: string }} Pairing */

/**
 * ntfy サーバー URL を正規化する。https のみ（開発用に localhost の http は許可）。
 * @param {string} input
 * @returns {string} 末尾スラッシュなしの URL
 */
export function normalizeServer(input) {
  let u;
  try {
    u = new URL(String(input).trim());
  } catch {
    throw new Error('ntfy サーバーの URL が不正です');
  }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  if (!(u.protocol === 'https:' || (u.protocol === 'http:' && local))) {
    throw new Error('ntfy サーバーは https:// の URL にしてください');
  }
  if (u.username || u.password || u.search || u.hash) {
    throw new Error('ntfy サーバーの URL にユーザー名・クエリ・# は含められません');
  }
  return (u.origin + u.pathname).replace(/\/+$/, '');
}

/**
 * @param {Pairing} p
 * @returns {string} 先頭の # を含まないフラグメント文字列
 */
export function formatPairing(p) {
  let s = 'k=' + encodeBase64url(p.secret);
  const server = normalizeServer(p.server);
  if (server !== DEFAULT_SERVER) s += '&s=' + encodeURIComponent(server);
  return s;
}

/**
 * 次のどれでも受け付ける: ページの URL 全体 / "#k=..." / "k=...&s=..." / 秘密そのもの。
 * @param {string} text
 * @returns {Pairing}
 */
export function parsePairing(text) {
  let frag = String(text).trim();
  const hashAt = frag.indexOf('#');
  if (hashAt >= 0) frag = frag.slice(hashAt + 1);
  let k;
  let s = null;
  if (frag.includes('=')) {
    const params = new URLSearchParams(frag);
    k = params.get('k');
    s = params.get('s');
  } else {
    k = frag;
  }
  let secret;
  try {
    secret = decodeBase64url(k ?? '');
  } catch {
    secret = null;
  }
  if (!secret || secret.length !== SECRET_BYTES) {
    throw new Error('ペアリング情報（秘密）が見つからないか、形式が不正です');
  }
  return { secret, server: s ? normalizeServer(s) : DEFAULT_SERVER };
}

/**
 * ページの URL を組み立てる。
 * @param {string} pageUrl 例: https://example.github.io/voice-relay/send.html
 * @param {Pairing} p
 */
export function buildPageUrl(pageUrl, p) {
  const u = new URL(pageUrl);
  u.hash = formatPairing(p);
  return u.toString();
}
