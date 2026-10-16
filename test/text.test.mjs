import { test } from 'node:test';
import assert from 'node:assert/strict';

import { revealHidden } from '../js/text.js';

test('普通のテキスト・改行・タブ・絵文字はそのまま', () => {
  const s = 'こんにちは\n\tHello 👨\u{200D}👩\u{200D}👧 é';
  assert.deepEqual(revealHidden(s), { text: s, replaced: 0 });
});

test('端末のエスケープシーケンスを無害化する', () => {
  const r = revealHidden('a\u001b[31mred\u001b]0;title\u0007\r');
  assert.equal(r.text, 'a⟦U+001B⟧[31mred⟦U+001B⟧]0;title⟦U+0007⟧⟦U+000D⟧');
  assert.equal(r.replaced, 4);
  assert.ok(!/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/.test(r.text));
});

test('表示の向きを変える文字・幅ゼロの文字を見える形にする', () => {
  const r = revealHidden('rm -rf /tmp/x\u{202E}\u{2066} \u{200B}\u{FEFF}\u{AD}');
  assert.equal(r.replaced, 5);
  assert.match(r.text, /⟦U\+202E⟧⟦U\+2066⟧ ⟦U\+200B⟧⟦U\+FEFF⟧⟦U\+00AD⟧$/);
});

test('タグ文字・異体字セレクタ・空白に見える文字・行区切りも見える形にする', () => {
  const samples = ['\u{e0041}', '\u{e0100}', '\u{FE00}', '\u{3164}', '\u{115F}', '\u{1160}', '\u{FFA0}', '\u{34F}', '\u{2800}', '\u{2028}', '\u{2029}', '\u{f0000}', '\ud800'];
  for (const ch of samples) {
    const r = revealHidden(`a${ch}b`);
    assert.equal(r.replaced, 1, `U+${ch.codePointAt(0).toString(16)}`);
    assert.ok(!r.text.includes(ch));
  }
});

test('絵文字の異体字セレクタ（U+FE0F）と ZWJ はそのまま', () => {
  const s = '❤\u{FE0F} 👩\u{200D}💻 ☺\u{FE0E}';
  assert.deepEqual(revealHidden(s), { text: s, replaced: 0 });
});
