// ntfy との通信（送信と購読）。ブラウザと Node の両方で使う。
// 購読は JSON ストリーム（GET /<topic>/json）を fetch で読む。
// EventSource と違って HTTP ステータス（429 など）が分かるので、エラーを具体的に表示できる。
//
// ntfy.sh の匿名利用の制限は IP 単位（https://docs.ntfy.sh/publish/#limitations）:
//   1 日 250 通 / リクエストは連続 60 回まで、以降 5 秒ごとに 1 回分回復 / 同時購読 30 本
// 同じ NAT の内側にいる人（学校・会社の Wi-Fi など）はこの枠を共有する。

// ntfy の 1 行は本文 4KB + メタデータ程度。余裕を見て 64K 文字で打ち切る
const MAX_LINE_CHARS = 64 * 1024;

export class NtfyError extends Error {
  /**
   * @param {'rate' | 'too-large' | 'forbidden' | 'http' | 'network'} kind
   * @param {string} message
   * @param {number} [status]
   */
  constructor(kind, message, status) {
    super(message);
    this.name = 'NtfyError';
    this.kind = kind;
    this.status = status;
  }
}

/**
 * @param {number} status
 * @returns {NtfyError}
 */
function errorForStatus(status) {
  switch (status) {
    case 429:
      return new NtfyError(
        'rate',
        'ntfy のレート制限に達しました（429）。同じネットワークの他の利用者と上限を共有している可能性があります。' +
          'しばらく待つか、モバイル回線に切り替えるか、自前の ntfy サーバーを使ってください。',
        status,
      );
    case 413:
      return new NtfyError('too-large', 'メッセージが ntfy のサイズ上限を超えました（413）。', status);
    case 401:
    case 403:
      return new NtfyError('forbidden', `ntfy サーバーにアクセスが拒否されました（${status}）。`, status);
    default:
      return new NtfyError('http', `ntfy サーバーがエラーを返しました（HTTP ${status}）。`, status);
  }
}

/**
 * @param {string} server
 * @param {string} topic
 */
export function topicUrl(server, topic) {
  return `${server}/${encodeURIComponent(topic)}`;
}

/**
 * 暗号文を 1 通送る。
 * @param {string} server
 * @param {string} topic
 * @param {string} body
 * @param {{ signal?: AbortSignal }} [opts]
 */
export async function publish(server, topic, body, opts = {}) {
  let res;
  try {
    res = await fetch(topicUrl(server, topic), {
      method: 'POST',
      body,
      // Firebase（Android アプリへのプッシュ）には転送しない。暗号文だが不要な経路は減らす
      headers: { 'Content-Type': 'text/plain', Firebase: 'no' },
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      redirect: 'error', // 中継サーバーに別のホストや http:// へ誘導されないように
      signal: opts.signal,
    });
  } catch (e) {
    if (opts.signal?.aborted) throw e;
    throw new NtfyError('network', 'ntfy サーバーに接続できませんでした。通信状態を確認してください。');
  }
  if (!res.ok) throw errorForStatus(res.status);
}

/**
 * @typedef {'connecting' | 'open' | 'retrying' | 'stopped'} SubscribeState
 */

/**
 * トピックを購読し続ける。切れたら待ってから再接続する。
 * @param {string} server
 * @param {string} topic
 * @param {{
 *   onMessage: (body: string) => void,
 *   onState?: (state: SubscribeState, info?: { error?: NtfyError, retryInMs?: number }) => void,
 *   signal: AbortSignal,
 *   since?: string,
 *   idleTimeoutMs?: number,
 * }} opts
 */
export async function subscribe(server, topic, opts) {
  const { onMessage, signal } = opts;
  const onState = opts.onState ?? (() => {});
  const idleTimeoutMs = opts.idleTimeoutMs ?? 90_000; // ntfy の keepalive は既定 45 秒
  let since = opts.since ?? '10m';
  let backoff = 2000;

  while (!signal.aborted) {
    onState('connecting');
    const ctrl = new AbortController();
    const abortInner = () => ctrl.abort();
    signal.addEventListener('abort', abortInner, { once: true });
    /** @type {ReturnType<typeof setTimeout> | undefined} */
    let idleTimer;
    const touch = () => {
      clearTimeout(idleTimer);
      idleTimer = setTimeout(() => ctrl.abort(), idleTimeoutMs);
    };
    /** @type {NtfyError | undefined} */
    let error;
    try {
      touch();
      const res = await fetch(`${topicUrl(server, topic)}/json?since=${encodeURIComponent(since)}`, {
        cache: 'no-store',
        referrerPolicy: 'no-referrer',
        redirect: 'error',
        signal: ctrl.signal,
      });
      if (!res.ok || !res.body) throw errorForStatus(res.status);
      onState('open');
      backoff = 2000;
      const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
      let buf = '';
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        touch();
        buf += value;
        let nl;
        while ((nl = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, nl).trim();
          buf = buf.slice(nl + 1);
          if (!line || line.length > MAX_LINE_CHARS) continue;
          let ev;
          try {
            ev = JSON.parse(line);
          } catch {
            continue;
          }
          if (ev && ev.event === 'message' && typeof ev.message === 'string') {
            if (typeof ev.id === 'string' && /^[A-Za-z0-9]+$/.test(ev.id)) since = ev.id;
            onMessage(ev.message);
          }
        }
        // 改行のないまま巨大なデータを送り続けるサーバーでメモリを使い果たさないよう、1 行の長さを制限する
        if (buf.length > MAX_LINE_CHARS) {
          throw new NtfyError('http', 'ntfy サーバーから想定外に大きなデータが届いたため切断しました。');
        }
      }
    } catch (e) {
      if (e instanceof NtfyError) error = e;
      else if (!signal.aborted) {
        error = new NtfyError('network', 'ntfy サーバーとの接続が切れました。再接続します。');
      }
    } finally {
      clearTimeout(idleTimer);
      signal.removeEventListener('abort', abortInner);
    }
    if (signal.aborted) break;
    // 最初の接続は since=10m、以降は最後に受け取った ntfy のメッセージ ID から
    const wait = error?.kind === 'rate' ? Math.max(backoff, 60_000) : backoff;
    onState('retrying', { error, retryInMs: wait });
    await sleep(wait, signal);
    backoff = Math.min(backoff * 2, 60_000);
  }
  onState('stopped');
}

/**
 * @param {number} ms
 * @param {AbortSignal} signal
 */
function sleep(ms, signal) {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    signal.addEventListener('abort', () => { clearTimeout(t); resolve(undefined); }, { once: true });
  });
}
