import { test } from 'node:test';
import assert from 'node:assert/strict';

import { revealHidden } from '../js/text.js';

test('普通のテキスト・改行・タブ・絵文字はそのまま', () => {
  const s = 'こんにちは\n\tHello 👨‍👩‍👧 é';
  assert.deepEqual(revealHidden(s), { text: s, replaced: 0 });
});

test('端末のエスケープシーケンスを無害化する', () => {
  const r = revealHidden('a\u001b[31mred\u001b]0;title\u0007\r');
  assert.equal(r.text, 'a⟦U+001B⟧[31mred⟦U+001B⟧]0;title⟦U+0007⟧⟦U+000D⟧');
  assert.equal(r.replaced, 4);
  assert.ok(!/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/.test(r.text));
});

test('表示の向きを変える文字・幅ゼロの文字を見える形にする', () => {
  const r = revealHidden('rm -rf /tmp/x‮⁦ ​﻿­');
  assert.equal(r.replaced, 5);
  assert.match(r.text, /⟦U\+202E⟧⟦U\+2066⟧ ⟦U\+200B⟧⟦U\+FEFF⟧⟦U\+00AD⟧$/);
});
