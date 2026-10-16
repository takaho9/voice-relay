import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { Inbox, deriveSession, openBody } from '../js/crypto.js';
import { pairCode, parsePairing } from '../js/pairing.js';

const vec = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'));

async function decryptAll(session, bodies) {
  const inbox = new Inbox();
  let msg = null;
  for (const b of bodies) {
    const p = await openBody(session, b);
    assert.ok(p, '復号できるはず');
    msg = inbox.accept(p, vec.t) ?? msg;
  }
  return msg;
}

test('相互運用: 派生値が固定値と一致する', async () => {
  const { secret } = parsePairing(vec.pairing);
  const s = await deriveSession(secret);
  assert.equal(s.topic, vec.topic);
  assert.equal(pairCode(s.topic), vec.pair_code);
});

test('相互運用: Python 版で暗号化したものを JS 版で復号できる', async () => {
  const s = await deriveSession(parsePairing(vec.pairing).secret);
  const m = await decryptAll(s, vec.py_bodies);
  assert.equal(m?.text, vec.text);
  assert.equal(m?.t, vec.t);
});

test('相互運用: JS 版の固定値も復号できる', async () => {
  const s = await deriveSession(parsePairing(vec.pairing).secret);
  assert.equal((await decryptAll(s, vec.js_bodies))?.text, vec.text);
});
