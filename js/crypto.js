// voice-relay の暗号処理。ブラウザと Node（v20 以上）の両方で動く。
// 暗号プリミティブはすべて WebCrypto（crypto.subtle）を使い、自前実装はしない。
//
// 送信フォーマット（ntfy のメッセージ本文）:
//   base64url( version(1 byte) | IV(12 bytes) | AES-256-GCM 暗号文 + タグ(16 bytes) )
// バージョンバイトは AAD にも入れ、改ざんされたら復号に失敗する。
//
// 平文は JSON: {"id": メッセージID, "t": 送信時刻(ms), "i": 分割番号, "n": 分割数, "x": 本文}

export const FORMAT_VERSION = 1;
export const SECRET_BYTES = 32;
export const MAX_PARTS = 8;
// ntfy の本文上限は 4,096 バイト。それを超えると添付ファイル扱いになるので余裕を持たせる
export const MAX_BODY_BYTES = 4000;

const IV_BYTES = 12;
const TAG_BYTES = 16;
const ID_BYTES = 16;
const TOPIC_BYTES = 24; // base64url で 32 文字
const MAX_PLAIN_BYTES = (MAX_BODY_BYTES / 4) * 3 - 1 - IV_BYTES - TAG_BYTES;
// JSON の id/t/i/n 部分のための予約。実際は 70 バイト前後
const ENVELOPE_RESERVE = 96;

const HKDF_SALT = utf8('voice-relay/v1');
const INFO_KEY = utf8('voice-relay/v1/aes-256-gcm-key');
const INFO_TOPIC = utf8('voice-relay/v1/ntfy-topic');
const AAD = new Uint8Array([FORMAT_VERSION]);

const ID_RE = /^[A-Za-z0-9_-]{22}$/;

/** @typedef {{ key: CryptoKey, topic: string }} Session */
/** @typedef {{ id: string, t: number, i: number, n: number, x: string }} Payload */
/** @typedef {{ id: string, t: number, text: string }} ReceivedMessage */

export class MessageTooLongError extends Error {
  /** @param {number} parts */
  constructor(parts) {
    super(`メッセージが長すぎます（${parts} 分割が必要、上限は ${MAX_PARTS} 分割）`);
    this.name = 'MessageTooLongError';
    this.parts = parts;
  }
}

function subtle() {
  const c = globalThis.crypto;
  if (!c || !c.subtle) {
    throw new Error('WebCrypto が使えません（HTTPS または localhost で開いてください）');
  }
  return c.subtle;
}

/** @param {string} s */
function utf8(s) {
  return new TextEncoder().encode(s);
}

/** @param {number} n */
function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

/** @param {Uint8Array} bytes */
export function encodeBase64url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * パディングなしの base64url だけを受け付ける。
 * @param {string} s
 * @returns {Uint8Array}
 */
export function decodeBase64url(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) {
    throw new Error('base64url として不正です');
  }
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  // 余りビットが 0 でない表記（同じバイト列の別表記）は拒否する
  if (encodeBase64url(out) !== s) throw new Error('base64url として不正です');
  return out;
}

/** 256bit のマスターシークレットを生成する。 */
export function generateSecret() {
  return randomBytes(SECRET_BYTES);
}

/**
 * マスターシークレットから暗号鍵とトピック名を HKDF-SHA256 で派生する。
 * info を分けているので、トピック名が漏れても暗号鍵は分からない。
 * @param {Uint8Array} secret
 * @returns {Promise<Session>}
 */
export async function deriveSession(secret) {
  if (!(secret instanceof Uint8Array) || secret.length !== SECRET_BYTES) {
    throw new Error('秘密の長さが不正です');
  }
  const s = subtle();
  const ikm = await s.importKey('raw', secret, 'HKDF', false, ['deriveKey', 'deriveBits']);
  const key = await s.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info: INFO_KEY },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  const topicBits = await s.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info: INFO_TOPIC },
    ikm,
    TOPIC_BYTES * 8,
  );
  return { key, topic: encodeBase64url(new Uint8Array(topicBits)) };
}

/**
 * 1 文字（コードポイント）を JSON 文字列に入れたときのバイト数。
 * @param {string} ch
 */
function jsonCost(ch) {
  const c = ch.codePointAt(0) ?? 0;
  if (c === 0x22 || c === 0x5c) return 2; // " と \
  if (c === 0x08 || c === 0x09 || c === 0x0a || c === 0x0c || c === 0x0d) return 2; // \b \t \n \f \r
  if (c < 0x20) return 6; // その他の制御文字は \uXXXX
  if (c < 0x80) return 1;
  if (c < 0x800) return 2;
  if (c >= 0xd800 && c <= 0xdfff) return 6; // 孤立サロゲートは \uXXXX
  if (c < 0x10000) return 3;
  return 4;
}

/**
 * 本文を、1 通あたりの平文上限に収まるよう分割する。
 * @param {string} text
 * @returns {string[]}
 */
export function splitText(text) {
  const budget = MAX_PLAIN_BYTES - ENVELOPE_RESERVE;
  const chunks = [];
  let cur = '';
  let used = 0;
  for (const ch of text) {
    const cost = jsonCost(ch);
    if (used + cost > budget) {
      chunks.push(cur);
      cur = '';
      used = 0;
    }
    cur += ch;
    used += cost;
  }
  if (cur !== '' || chunks.length === 0) chunks.push(cur);
  return chunks;
}

/**
 * @param {Session} session
 * @param {Payload} payload
 */
async function encryptPayload(session, payload) {
  const plain = utf8(JSON.stringify(payload));
  if (plain.length > MAX_PLAIN_BYTES) throw new Error('内部エラー: 分割サイズの計算が不正です');
  const iv = randomBytes(IV_BYTES);
  const ct = new Uint8Array(
    await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: AAD, tagLength: 128 }, session.key, plain),
  );
  const out = new Uint8Array(1 + IV_BYTES + ct.length);
  out[0] = FORMAT_VERSION;
  out.set(iv, 1);
  out.set(ct, 1 + IV_BYTES);
  return encodeBase64url(out);
}

/**
 * テキストを暗号化し、ntfy に POST する本文の配列を返す（長い場合は複数）。
 * @param {Session} session
 * @param {string} text
 * @param {{ now?: number }} [opts]
 * @returns {Promise<string[]>}
 */
export async function sealText(session, text, opts = {}) {
  if (typeof text !== 'string' || text.length === 0) throw new Error('本文が空です');
  const chunks = splitText(text);
  if (chunks.length > MAX_PARTS) throw new MessageTooLongError(chunks.length);
  const id = encodeBase64url(randomBytes(ID_BYTES));
  const t = opts.now ?? Date.now();
  const n = chunks.length;
  const bodies = [];
  for (let i = 0; i < n; i++) {
    bodies.push(await encryptPayload(session, { id, t, i, n, x: chunks[i] }));
  }
  return bodies;
}

/**
 * 本文の分割数だけを見積もる（送信前の表示用）。
 * @param {string} text
 */
export function countParts(text) {
  return text.length === 0 ? 0 : splitText(text).length;
}

/**
 * @param {unknown} p
 * @returns {p is Payload}
 */
function isPayload(p) {
  if (typeof p !== 'object' || p === null) return false;
  const o = /** @type {Record<string, unknown>} */ (p);
  return (
    typeof o.id === 'string' && ID_RE.test(o.id) &&
    Number.isSafeInteger(o.t) && /** @type {number} */ (o.t) > 0 &&
    Number.isInteger(o.n) && /** @type {number} */ (o.n) >= 1 && /** @type {number} */ (o.n) <= MAX_PARTS &&
    Number.isInteger(o.i) && /** @type {number} */ (o.i) >= 0 && /** @type {number} */ (o.i) < /** @type {number} */ (o.n) &&
    typeof o.x === 'string'
  );
}

/**
 * ntfy から届いた本文を復号する。形式不正・改ざん・鍵違いはすべて null（黙って捨てる）。
 * @param {Session} session
 * @param {unknown} body
 * @returns {Promise<Payload | null>}
 */
export async function openBody(session, body) {
  try {
    if (typeof body !== 'string' || body.length > MAX_BODY_BYTES) return null;
    const raw = decodeBase64url(body);
    if (raw.length < 1 + IV_BYTES + TAG_BYTES || raw[0] !== FORMAT_VERSION) return null;
    const iv = raw.subarray(1, 1 + IV_BYTES);
    const ct = raw.subarray(1 + IV_BYTES);
    const plain = await subtle().decrypt(
      { name: 'AES-GCM', iv, additionalData: AAD, tagLength: 128 },
      session.key,
      ct,
    );
    const payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plain));
    return isPayload(payload) ? payload : null;
  } catch {
    return null;
  }
}

/**
 * 復号済みメッセージの受け付け（リプレイ防止と分割メッセージの結合）。
 * - 送信時刻が maxAgeMs より古い、または maxSkewMs より未来のものは捨てる
 * - 一度受け付けた ID は捨てる（ntfy の再接続で同じものが再送されても重複しない）
 */
export class Inbox {
  /** @type {Map<string, { t: number, n: number, chunks: (string | undefined)[], count: number }>} */
  #pending = new Map();
  /** @type {Map<string, number>} */
  #done = new Map();

  /** @param {{ maxAgeMs?: number, maxSkewMs?: number, maxPending?: number }} [opts] */
  constructor(opts = {}) {
    this.maxAgeMs = opts.maxAgeMs ?? 10 * 60 * 1000;
    this.maxSkewMs = opts.maxSkewMs ?? 2 * 60 * 1000;
    this.maxPending = opts.maxPending ?? 64;
  }

  /**
   * @param {Payload} p
   * @param {number} [now]
   * @returns {ReceivedMessage | null} 全分割が揃ったときだけメッセージを返す
   */
  accept(p, now = Date.now()) {
    this.prune(now);
    if (p.t < now - this.maxAgeMs || p.t > now + this.maxSkewMs) return null;
    if (this.#done.has(p.id)) return null;
    let e = this.#pending.get(p.id);
    if (!e) {
      if (this.#pending.size >= this.maxPending) return null;
      e = { t: p.t, n: p.n, chunks: new Array(p.n), count: 0 };
      this.#pending.set(p.id, e);
    }
    if (e.t !== p.t || e.n !== p.n || e.chunks[p.i] !== undefined) return null;
    e.chunks[p.i] = p.x;
    e.count++;
    if (e.count < e.n) return null;
    this.#pending.delete(p.id);
    this.#done.set(p.id, p.t);
    return { id: p.id, t: p.t, text: e.chunks.join('') };
  }

  /** 受け付け期間を過ぎた記録を消す。消した ID は時刻チェックで弾かれるのでリプレイにはならない。 */
  prune(now = Date.now()) {
    const limit = now - this.maxAgeMs;
    for (const [id, t] of this.#done) if (t < limit) this.#done.delete(id);
    for (const [id, e] of this.#pending) if (e.t < limit) this.#pending.delete(id);
  }
}
