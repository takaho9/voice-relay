import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';

import { subscribe } from '../js/ntfy.js';

/** @param {(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void} handler */
async function withServer(handler, fn) {
  const server = createServer(handler);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = /** @type {import('node:net').AddressInfo} */ (server.address());
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    server.closeAllConnections();
    server.close();
  }
}

test('JSON ストリームから message イベントだけを取り出す', async () => {
  await withServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/x-ndjson' });
    res.write('{"id":"o1","event":"open","topic":"t"}\n');
    res.write('{"id":"k1","event":"keepalive"}\n\nnot json\n');
    res.write('{"id":"m1","event":"message","message":"AAA"}\n{"id":"m2","event":"mes');
    res.write('sage","message":"BBB"}\n');
  }, async (server) => {
    const got = [];
    const ctrl = new AbortController();
    await new Promise((resolve) => {
      subscribe(server, 'topic', {
        signal: ctrl.signal,
        onMessage(body) {
          got.push(body);
          if (got.length === 2) resolve(undefined);
        },
      });
    });
    ctrl.abort();
    assert.deepEqual(got, ['AAA', 'BBB']);
  });
});

test('改行のない巨大なデータを送り続けるサーバーからは切断する', async () => {
  let streamed = 0;
  await withServer((req, res) => {
    res.writeHead(200);
    const chunk = 'x'.repeat(16 * 1024);
    const timer = setInterval(() => {
      if (res.destroyed || streamed > 4 * 1024 * 1024) return clearInterval(timer);
      streamed += chunk.length;
      res.write(chunk);
    }, 1);
    res.on('close', () => clearInterval(timer));
  }, async (server) => {
    const ctrl = new AbortController();
    const err = await new Promise((resolve) => {
      subscribe(server, 'topic', {
        signal: ctrl.signal,
        onMessage() {},
        onState(state, info) {
          if (state === 'retrying') resolve(info?.error);
        },
      });
    });
    ctrl.abort();
    assert.equal(err?.kind, 'http');
    assert.ok(streamed < 1024 * 1024, `切断までに ${streamed} バイト`);
  });
});

test('429 はレート制限のエラーとして伝え、60 秒以上待つ', async () => {
  await withServer((req, res) => {
    res.writeHead(429);
    res.end();
  }, async (server) => {
    const ctrl = new AbortController();
    const info = await new Promise((resolve) => {
      subscribe(server, 'topic', {
        signal: ctrl.signal,
        onMessage() {},
        onState(state, i) {
          if (state === 'retrying') resolve(i);
        },
      });
    });
    ctrl.abort();
    assert.equal(info?.error?.kind, 'rate');
    assert.ok((info?.retryInMs ?? 0) >= 60_000);
  });
});
