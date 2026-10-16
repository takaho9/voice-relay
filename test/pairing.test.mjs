import { test } from 'node:test';
import assert from 'node:assert/strict';

import { generateSecret } from '../js/crypto.js';
import { DEFAULT_SERVER, buildPageUrl, formatPairing, normalizeServer, parsePairing } from '../js/pairing.js';

test('既定サーバーなら s を省略し、往復できる', () => {
  const secret = generateSecret();
  const frag = formatPairing({ secret, server: DEFAULT_SERVER });
  assert.match(frag, /^k=[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(parsePairing(frag), { secret, server: DEFAULT_SERVER });
});

test('独自サーバーは s に入り、URL 全体・#付き・秘密だけ、どれでも読める', () => {
  const secret = generateSecret();
  const server = 'https://ntfy.example.com/sub';
  const url = buildPageUrl('https://user.github.io/voice-relay/send.html', { secret, server });
  assert.ok(url.startsWith('https://user.github.io/voice-relay/send.html#k='));
  assert.deepEqual(parsePairing(url), { secret, server });
  assert.deepEqual(parsePairing('  ' + url.slice(url.indexOf('#')) + '\n'), { secret, server });
  assert.deepEqual(parsePairing(formatPairing({ secret, server: DEFAULT_SERVER }).slice(2)), {
    secret,
    server: DEFAULT_SERVER,
  });
});

test('不正なペアリング情報はエラー、エラー文に入力値を含めない', () => {
  const bad = 'k=AAAA-secret-looking-value';
  assert.throws(() => parsePairing(bad), (e) => !String(e.message).includes('secret-looking'));
  assert.throws(() => parsePairing(''));
  assert.throws(() => parsePairing('https://x/#s=https%3A%2F%2Fa.example'));
});

test('サーバー URL の正規化と拒否', () => {
  assert.equal(normalizeServer('https://ntfy.sh/'), 'https://ntfy.sh');
  assert.equal(normalizeServer('https://n.example.com:8443/ntfy/'), 'https://n.example.com:8443/ntfy');
  assert.equal(normalizeServer('http://localhost:8080'), 'http://localhost:8080');
  assert.throws(() => normalizeServer('http://ntfy.example.com'));
  assert.throws(() => normalizeServer('javascript:alert(1)'));
  assert.throws(() => normalizeServer('https://u:p@ntfy.sh'));
  assert.throws(() => normalizeServer('https://ntfy.sh/?x=1'));
  assert.throws(() => normalizeServer('not a url'));
});

test('確認コードは 16 進 8 桁で、トピックが違えば違う', async () => {
  const { deriveSession } = await import('../js/crypto.js');
  const { pairCode } = await import('../js/pairing.js');
  const a = pairCode((await deriveSession(generateSecret())).topic);
  const b = pairCode((await deriveSession(generateSecret())).topic);
  assert.match(a, /^[0-9a-f]{4}-[0-9a-f]{4}$/);
  assert.notEqual(a, b);
});
