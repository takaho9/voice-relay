// 受信テキストを表示するときの無害化（ブラウザと CLI で共用）。
// 見た目と中身が食い違う文字（制御文字・表示の向きを変える文字・幅ゼロの文字・空白に見える文字・
// タグ文字・未割り当ての文字など）を目に見える表記に置き換える。コピーするときは元のテキストを使う。
// 改行・タブ、絵文字に使う ZWJ（U+200D）と異体字セレクタ U+FE0E/U+FE0F はそのまま残す。

const HIDDEN_RE = new RegExp(
  '(?![\\t\\n\\u200d\\ufe0e\\ufe0f])[' +
    '\\p{Cc}\\p{Cf}\\p{Co}\\p{Cn}\\p{Cs}\\p{Zl}\\p{Zp}' + // 制御・書式・私用・未割り当て・孤立サロゲート・行/段落区切り
    '\\u034f\\u115f\\u1160\\u2800\\u3164\\uffa0' + // 結合書記素ジョイナー・ハングルフィラー・点字の空白
    '\\ufe00-\\ufe0f\\u{e0100}-\\u{e01ef}' + // 異体字セレクタ
    ']',
  'gu',
);

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
