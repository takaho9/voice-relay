import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hkdfSync } from 'node:crypto';

import {
  Inbox,
  MAX_BODY_BYTES,
  MAX_PARTS,
  MessageTooLongError,
  SECRET_BYTES,
  countParts,
  decodeBase64url,
  deriveSession,
  encodeBase64url,
  generateSecret,
  openBody,
  sealText,
  splitText,
} from '../js/crypto.js';

const FIXED_SECRET = new Uint8Array(SECRET_BYTES).map((_, i) => i);

/** 送信 → 受け付けを 1 通ずつ通す */
async function deliver(session, inbox, bodies, now) {
  const out = [];
  for (const b of bodies) {
    const p = await openBody(session, b);
    assert.ok(p, '復号できるはず');
    const m = inbox.accept(p, now);
    if (m) out.push(m);
  }
  return out;
}

test('base64url の往復と不正入力の拒否', () => {
  for (let len = 0; len < 40; len++) {
    const b = generateSecret().subarray(0, len);
    assert.deepEqual(decodeBase64url(encodeBase64url(b)), b);
  }
  assert.throws(() => decodeBase64url('ab+c'));
  assert.throws(() => decodeBase64url('abc='));
  assert.throws(() => decodeBase64url('a'));
});

test('秘密は 256bit でランダム', () => {
  const a = generateSecret();
  const b = generateSecret();
  assert.equal(a.length, 32);
  assert.notDeepEqual(a, b);
});

test('派生値の決定性: 同じ秘密なら同じトピックと鍵', async () => {
  const s1 = await deriveSession(FIXED_SECRET);
  const s2 = await deriveSession(new Uint8Array(FIXED_SECRET));
  assert.equal(s1.topic, s2.topic);
  assert.match(s1.topic, /^[A-Za-z0-9_-]{32}$/);
  // s1 で暗号化したものを s2 で復号できる = 鍵も同じ
  const [body] = await sealText(s1, 'hello');
  const p = await openBody(s2, body);
  assert.equal(p?.x, 'hello');
});

test('派生値の既知解: Node の hkdfSync で独立に計算した値と一致', async () => {
  const expected = Buffer.from(
    hkdfSync('sha256', FIXED_SECRET, 'voice-relay/v1', 'voice-relay/v1/ntfy-topic', 24),
  ).toString('base64url');
  const s = await deriveSession(FIXED_SECRET);
  assert.equal(s.topic, expected);
});

test('トピック名と暗号鍵は別の値（トピック漏洩で鍵は分からない）', () => {
  const topic = Buffer.from(hkdfSync('sha256', FIXED_SECRET, 'voice-relay/v1', 'voice-relay/v1/ntfy-topic', 32));
  const key = Buffer.from(hkdfSync('sha256', FIXED_SECRET, 'voice-relay/v1', 'voice-relay/v1/aes-256-gcm-key', 32));
  assert.notDeepEqual(topic, key);
});

test('秘密が違えばトピックも違い、復号もできない', async () => {
  const a = await deriveSession(generateSecret());
  const b = await deriveSession(generateSecret());
  assert.notEqual(a.topic, b.topic);
  const [body] = await sealText(a, 'secret text');
  assert.equal(await openBody(b, body), null);
});

test('deriveSession は長さの違う秘密を拒否する', async () => {
  await assert.rejects(deriveSession(new Uint8Array(16)));
});

test('暗号化 → 復号の往復（日本語・絵文字・改行・引用符）', async () => {
  const s = await deriveSession(generateSecret());
  const inbox = new Inbox();
  const text = 'こんにちは、世界 🌏👨\u{200D}👩\u{200D}👧\n"quoted" \\ back\ttab\u0001';
  const now = Date.now();
  const bodies = await sealText(s, text, { now });
  assert.equal(bodies.length, 1);
  const msgs = await deliver(s, inbox, bodies, now);
  assert.equal(msgs.length, 1);
  assert.equal(msgs[0].text, text);
  assert.equal(msgs[0].t, now);
});

test('同じ平文でも毎回 IV が違い、暗号文も違う', async () => {
  const s = await deriveSession(generateSecret());
  const [a] = await sealText(s, 'same');
  const [b] = await sealText(s, 'same');
  assert.notEqual(a, b);
  assert.notDeepEqual(decodeBase64url(a).subarray(1, 13), decodeBase64url(b).subarray(1, 13));
});

test('送信フォーマット: version | IV(12) | 暗号文+タグ(16)', async () => {
  const s = await deriveSession(generateSecret());
  const [body] = await sealText(s, 'x');
  const raw = decodeBase64url(body);
  assert.equal(raw[0], 1);
  const plainLen = new TextEncoder().encode(JSON.stringify(await openBody(s, body))).length;
  assert.equal(raw.length, 1 + 12 + plainLen + 16);
});

test('改ざん検出: どのバイトを書き換えても復号に失敗する', async () => {
  const s = await deriveSession(generateSecret());
  const [body] = await sealText(s, '改ざんテスト');
  const raw = decodeBase64url(body);
  for (let i = 0; i < raw.length; i++) {
    const t = new Uint8Array(raw);
    t[i] ^= 0x01;
    assert.equal(await openBody(s, encodeBase64url(t)), null, `byte ${i}`);
  }
  // 切り詰め・延長・空・ゴミ
  assert.equal(await openBody(s, encodeBase64url(raw.subarray(0, raw.length - 1))), null);
  assert.equal(await openBody(s, encodeBase64url(new Uint8Array([...raw, 0]))), null);
  assert.equal(await openBody(s, ''), null);
  assert.equal(await openBody(s, 'not base64!'), null);
  assert.equal(await openBody(s, 12345), null);
  assert.equal(await openBody(s, 'A'.repeat(MAX_BODY_BYTES + 4)), null);
});

test('未知のバージョンは拒否する', async () => {
  const s = await deriveSession(generateSecret());
  const [body] = await sealText(s, 'v');
  const raw = decodeBase64url(body);
  raw[0] = 2;
  assert.equal(await openBody(s, encodeBase64url(raw)), null);
});

test('リプレイ拒否: 同じメッセージは 1 回しか受け付けない', async () => {
  const s = await deriveSession(generateSecret());
  const inbox = new Inbox();
  const now = Date.now();
  const bodies = await sealText(s, 'once', { now });
  assert.equal((await deliver(s, inbox, bodies, now)).length, 1);
  assert.equal((await deliver(s, inbox, bodies, now + 1000)).length, 0);
});

test('リプレイ拒否: 10 分以上前のメッセージは捨てる', async () => {
  const s = await deriveSession(generateSecret());
  const now = Date.now();
  const old = await sealText(s, 'old', { now: now - 10 * 60 * 1000 - 1 });
  assert.equal((await deliver(s, new Inbox(), old, now)).length, 0);
  const fresh = await sealText(s, 'fresh', { now: now - 9 * 60 * 1000 });
  assert.equal((await deliver(s, new Inbox(), fresh, now)).length, 1);
});

test('リプレイ拒否: 未来すぎるメッセージは捨てる', async () => {
  const s = await deriveSession(generateSecret());
  const now = Date.now();
  const future = await sealText(s, 'future', { now: now + 3 * 60 * 1000 });
  assert.equal((await deliver(s, new Inbox(), future, now)).length, 0);
});

test('リプレイ拒否: 記録を掃除した後に再送されても時刻で弾かれる', async () => {
  const s = await deriveSession(generateSecret());
  const inbox = new Inbox();
  const now = Date.now();
  const bodies = await sealText(s, 'x', { now });
  assert.equal((await deliver(s, inbox, bodies, now)).length, 1);
  const later = now + 10 * 60 * 1000 + 1;
  inbox.prune(later);
  assert.equal((await deliver(s, inbox, bodies, later)).length, 0);
});

test('長文は分割され、各本文は上限以下、受信側で元通りに結合される', async () => {
  const s = await deriveSession(generateSecret());
  for (const [unit, count] of [['あ', 5000], ['a', 5000], ['😀', 4000], ['"', 5000], ['\n', 5000], ['\u0001', 2000], ['é', 5000], ['\u{2028}', 5000]]) {
    const text = unit.repeat(count);
    const bodies = await sealText(s, text);
    assert.ok(bodies.length > 1, unit);
    for (const b of bodies) assert.ok(b.length <= MAX_BODY_BYTES, `${JSON.stringify(unit)}: ${b.length}`);
    // 順不同で届いても結合できる
    const shuffled = [...bodies].reverse();
    const msgs = await deliver(s, new Inbox(), shuffled, Date.now());
    assert.equal(msgs.length, 1);
    assert.equal(msgs[0].text, text);
  }
});

test('分割上限を超える入力は送信前に拒否する', async () => {
  const s = await deriveSession(generateSecret());
  const text = 'あ'.repeat(30000);
  assert.ok(countParts(text) > MAX_PARTS);
  await assert.rejects(sealText(s, text), MessageTooLongError);
  await assert.rejects(sealText(s, ''));
});

test('分割はコードポイント単位（サロゲートペアを壊さない）', () => {
  const text = '😀'.repeat(3000);
  const chunks = splitText(text);
  assert.ok(chunks.length > 1);
  for (const c of chunks) assert.doesNotThrow(() => encodeURIComponent(c));
  assert.equal(chunks.join(''), text);
});

test('分割メッセージの一部が欠けたら表示しない・重複した分割片は無視', async () => {
  const s = await deriveSession(generateSecret());
  const now = Date.now();
  const bodies = await sealText(s, 'あ'.repeat(3000), { now });
  assert.ok(bodies.length >= 2);
  const inbox = new Inbox();
  assert.equal((await deliver(s, inbox, [bodies[0], bodies[0]], now)).length, 0);
  assert.equal((await deliver(s, inbox, bodies.slice(1), now)).length, 1);
});

test('base64url は正準形以外を拒否する（同じバイト列の別表記）', () => {
  assert.deepEqual(decodeBase64url('AA'), new Uint8Array([0]));
  assert.throws(() => decodeBase64url('AB'));
});
