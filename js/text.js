// 受信テキストを表示するときの無害化（ブラウザと CLI で共用）。
// 見た目と中身が食い違う文字（制御文字・表示の向きを変える文字・幅ゼロの文字）を
// 目に見える表記に置き換える。コピーするときは元のテキストを使う。
// 改行・タブと、絵文字の結合に使う ZWJ（U+200D）はそのまま残す。

// eslint-disable-next-line no-control-regex
const HIDDEN_RE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f­؜᠎​‌‎‏‪-‮⁠-⁤⁦-⁩﻿￹-￻]/g;

/**
 * @param {string} s
 * @returns {{ text: string, replaced: number }}
 */
export function revealHidden(s) {
  let replaced = 0;
  const text = s.replace(HIDDEN_RE, (ch) => {
    replaced++;
    return `⟦U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}⟧`;
  });
  return { text, replaced };
}
