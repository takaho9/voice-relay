#!/usr/bin/env node
// voice-relay のターミナル版（Node.js 20 以上、依存パッケージなし）。
// 暗号処理と ntfy との通信は Web 版と同じモジュール（../js/）を使う。
//
// 秘密はコマンドライン引数では受け取らない（共有マシンでは ps で他のユーザーに見えるため）。
// ファイル（権限 600）に保存するか、起動時にエコーなしのプロンプトで入力する。

import { spawn } from 'node:child_process';
import { lstat, mkdir, readFile, rm, writeFile, chmod } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { parseArgs } from 'node:util';

import { Inbox, MessageTooLongError, deriveSession, generateSecret, openBody, sealText } from '../js/crypto.js';
import { NtfyError, publish, subscribe } from '../js/ntfy.js';
import { DEFAULT_SERVER, buildPageUrl, normalizeServer, parsePairing, formatPairing } from '../js/pairing.js';
import { qrMatrix } from '../js/qr.js';
import { revealHidden } from '../js/text.js';

// フォークして自分の GitHub Pages にデプロイした場合はここを書き換えるか、
// 環境変数 VOICE_RELAY_PAGES_URL / --pages で指定する
const DEFAULT_PAGES_URL = 'https://takaho9.github.io/voice-relay/';

const USAGE = `使い方: node cli/voice-relay.mjs <コマンド> [オプション]

コマンド:
  setup     新しい秘密を作って保存し、スマホ用の QR コードを表示する
  import    Web のセットアップページで作った受信用 URL を貼り付けて保存する
  receive   受信を開始する（Ctrl-C で終了）
  send      標準入力のテキストを送る（動作確認用）
  forget    保存した秘密を削除する

オプション:
  --secret-file <path>  秘密の保存先（既定: ~/.config/voice-relay/secret）
  --server <url>        setup: ntfy サーバー（既定: ${DEFAULT_SERVER}）
  --pages <url>         setup: 送信ページを置いた URL（既定: ${DEFAULT_PAGES_URL}）
  --force               setup/import: 既存の秘密を上書きする
  --show-url            setup: QR コードに加えて送信用 URL も表示する
  --copy                receive: 受信したテキストをクリップボードにもコピーする
                        （wl-copy / xclip / xsel のどれかが必要。貼り付けは自分で行う）`;

function fail(msg) {
  process.stderr.write(`エラー: ${msg}\n`);
  process.exit(1);
}

function info(msg) {
  process.stderr.write(`${msg}\n`);
}

function defaultSecretFile() {
  if (process.env.VOICE_RELAY_SECRET_FILE) return process.env.VOICE_RELAY_SECRET_FILE;
  const base = process.env.XDG_CONFIG_HOME || join(homedir(), '.config');
  return join(base, 'voice-relay', 'secret');
}

/**
 * 秘密をファイルに保存する（ディレクトリ 700 / ファイル 600）。
 * @param {string} path
 * @param {import('../js/pairing.js').Pairing} pairing
 * @param {boolean} force
 */
async function saveSecret(path, pairing, force) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  try {
    await writeFile(path, formatPairing(pairing) + '\n', { mode: 0o600, flag: force ? 'w' : 'wx' });
  } catch (e) {
    if (/** @type {NodeJS.ErrnoException} */ (e).code === 'EEXIST') {
      fail(`${path} は既にあります。上書きするなら --force を付けてください（古い送信ページは使えなくなります）。`);
    }
    throw e;
  }
  await chmod(path, 0o600); // 既存ファイルを上書きした場合や umask の影響に備える
}

/**
 * 保存された秘密を読む。他人が読める権限やシンボリックリンクなら拒否する。
 * @param {string} path
 * @returns {Promise<import('../js/pairing.js').Pairing | null>}
 */
async function loadSecret(path) {
  let st;
  try {
    st = await lstat(path);
  } catch (e) {
    if (/** @type {NodeJS.ErrnoException} */ (e).code === 'ENOENT') return null;
    throw e;
  }
  if (!st.isFile()) fail(`${path} が通常のファイルではありません（シンボリックリンクは使えません）。`);
  if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
    fail(`${path} の所有者が自分ではありません。`);
  }
  if ((st.mode & 0o077) !== 0) {
    fail(`${path} が他のユーザーから読める権限になっています。chmod 600 ${path} を実行してください。`);
  }
  try {
    return parsePairing(await readFile(path, 'utf8'));
  } catch {
    fail(`${path} の内容が不正です。setup か import をやり直してください。`);
  }
}

/**
 * エコーなしで 1 行読む。標準入力が端末でなければ、パイプから 1 行読む。
 * @param {string} prompt
 * @returns {Promise<string>}
 */
function readHidden(prompt) {
  const stdin = process.stdin;
  if (!stdin.isTTY) {
    return new Promise((resolve, reject) => {
      let buf = '';
      stdin.setEncoding('utf8');
      stdin.on('data', (d) => { buf += d; });
      stdin.on('end', () => resolve(buf.split('\n')[0] ?? ''));
      stdin.on('error', reject);
    });
  }
  process.stderr.write(prompt);
  return new Promise((resolve) => {
    let buf = '';
    stdin.setRawMode(true);
    stdin.setEncoding('utf8');
    stdin.resume();
    /** @param {string} chunk */
    const onData = (chunk) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.off('data', onData);
          process.stderr.write('\n');
          resolve(buf);
          return;
        }
        if (ch === '\u0003') { // Ctrl-C
          stdin.setRawMode(false);
          process.stderr.write('\n');
          process.exit(130);
        }
        if (ch === '\u007f' || ch === '\b') buf = buf.slice(0, -1);
        else if (ch >= ' ') buf += ch;
      }
    };
    stdin.on('data', onData);
  });
}

/** 標準入力をすべて読む */
async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8');
}

/** QR コードを端末に描く（上下 2 モジュールを 1 文字で表す。色は明示して端末テーマに依存しない） */
function printQr(text) {
  const { size, isDark } = qrMatrix(text);
  const quiet = 4;
  const total = size + quiet * 2;
  const dark = (r, c) => {
    const rr = r - quiet;
    const cc = c - quiet;
    return rr >= 0 && cc >= 0 && rr < size && cc < size && isDark(rr, cc);
  };
  let out = '';
  for (let r = 0; r < total; r += 2) {
    for (let c = 0; c < total; c++) {
      const fg = dark(r, c) ? 30 : 97;
      const bg = dark(r + 1, c) ? 40 : 107;
      out += `\x1b[${fg};${bg}m▀`;
    }
    out += '\x1b[0m\n';
  }
  process.stdout.write(out);
}

/** @param {string} text */
function copyToClipboard(text) {
  const candidates = process.env.WAYLAND_DISPLAY
    ? [['wl-copy', []], ['xclip', ['-selection', 'clipboard']], ['xsel', ['--clipboard', '--input']]]
    : [['xclip', ['-selection', 'clipboard']], ['xsel', ['--clipboard', '--input']], ['wl-copy', []]];
  return new Promise((resolve) => {
    const tryNext = (i) => {
      if (i >= candidates.length) return resolve(false);
      const [cmd, args] = candidates[i];
      const child = spawn(cmd, args, { stdio: ['pipe', 'ignore', 'ignore'] });
      child.on('error', () => tryNext(i + 1));
      child.on('exit', (code) => (code === 0 ? resolve(true) : tryNext(i + 1)));
      child.stdin.on('error', () => {});
      child.stdin.end(text);
    };
    tryNext(0);
  });
}

/** @param {number} ms */
function hhmmss(ms) {
  return new Date(ms).toLocaleTimeString('ja-JP', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

/** @param {string} topic */
function pairCode(topic) {
  return `${topic.slice(0, 4)}-${topic.slice(4, 8)}`;
}

/** 保存済みの秘密を読み、無ければプロンプトで入力してもらう（保存はしない） */
async function obtainPairing(secretFile) {
  const saved = await loadSecret(secretFile);
  if (saved) return saved;
  info(`${secretFile} がないので、受信用 URL（または秘密）を入力してください（画面には表示されません）。`);
  try {
    return parsePairing(await readHidden('> '));
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
}

async function cmdSetup(opts) {
  const server = normalizeServer(opts.server ?? DEFAULT_SERVER);
  const pages = opts.pages ?? process.env.VOICE_RELAY_PAGES_URL ?? DEFAULT_PAGES_URL;
  const pairing = { secret: generateSecret(), server };
  await saveSecret(opts.secretFile, pairing, opts.force);
  const session = await deriveSession(pairing.secret);
  const sendUrl = buildPageUrl(new URL('send.html', pages).href, pairing);
  info('スマホのカメラで読み取り、開いたページをブックマークしてください。\n');
  printQr(sendUrl);
  if (opts.showUrl) process.stdout.write(`\n${sendUrl}\n`);
  info(`\n確認コード: ${pairCode(session.topic)}（スマホの送信ページにも同じコードが出ます）`);
  info(`秘密を ${opts.secretFile} に保存しました（権限 600）。`);
  info('受信するには: node cli/voice-relay.mjs receive');
  info('ターミナルのスクロールバックに QR コードが残るので、終わったら clear してください。');
}

async function cmdImport(opts) {
  info('Web のセットアップページの「受信用 URL」を貼り付けて Enter（画面には表示されません）。');
  let pairing;
  try {
    pairing = parsePairing(await readHidden('> '));
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  await saveSecret(opts.secretFile, pairing, opts.force);
  const session = await deriveSession(pairing.secret);
  info(`保存しました（${opts.secretFile}、権限 600）。確認コード: ${pairCode(session.topic)}`);
}

async function cmdReceive(opts) {
  const pairing = await obtainPairing(opts.secretFile);
  const session = await deriveSession(pairing.secret);
  const inbox = new Inbox();
  const ctrl = new AbortController();
  process.on('SIGINT', () => {
    ctrl.abort();
    info('\n終了しました。');
    process.exit(0);
  });
  info(`サーバー: ${new URL(pairing.server).host} / 確認コード: ${pairCode(session.topic)}`);
  info('Ctrl-C で終了します。受信内容は表示するだけで、どこにも保存しません。');

  let queue = Promise.resolve();
  await subscribe(pairing.server, session.topic, {
    signal: ctrl.signal,
    onMessage(body) {
      queue = queue.then(async () => {
        const payload = await openBody(session, body);
        if (!payload) return; // 偽造・改ざん・別の鍵のものは黙って捨てる
        const m = inbox.accept(payload);
        if (!m) return;
        const head = `── ${hhmmss(m.t)} `;
        process.stdout.write(`\n\x1b[2m${head}${'─'.repeat(Math.max(0, 40 - head.length))}\x1b[0m\n`);
        // 端末を操作できるエスケープシーケンスや見えない文字は ⟦U+XXXX⟧ の形で表示する
        const shown = revealHidden(m.text);
        process.stdout.write(shown.text + '\n');
        if (shown.replaced > 0) info(`（見えない文字・制御文字が ${shown.replaced} 個含まれています）`);
        if (opts.copy) {
          info((await copyToClipboard(m.text))
            ? '（クリップボードにコピーしました）'
            : '（コピーできませんでした。wl-copy / xclip / xsel が必要です）');
        }
      });
    },
    onState(state, i) {
      if (state === 'open') info('受信待機中…');
      else if (state === 'retrying') {
        info(`${i?.error?.message ?? '接続が切れました。'}（${Math.round((i?.retryInMs ?? 0) / 1000)} 秒後に再接続）`);
      }
    },
  });
}

async function cmdSend(opts) {
  const pairing = await loadSecret(opts.secretFile);
  if (!pairing) fail(`${opts.secretFile} がありません。先に setup か import をしてください。`);
  const text = (await readStdin()).replace(/\n$/, '');
  if (text === '') fail('標準入力が空です。');
  const session = await deriveSession(pairing.secret);
  try {
    const bodies = await sealText(session, text);
    for (const b of bodies) await publish(pairing.server, session.topic, b);
    info(`送信しました（${bodies.length} 通）。`);
  } catch (e) {
    if (e instanceof NtfyError || e instanceof MessageTooLongError) fail(e.message);
    throw e;
  }
}

async function cmdForget(opts) {
  await rm(opts.secretFile, { force: true });
  info(`${opts.secretFile} を削除しました。`);
}

async function main() {
  const major = Number(process.versions.node.split('.')[0]);
  if (major < 20 || !globalThis.crypto?.subtle) fail('Node.js 20 以上が必要です。');

  let parsed;
  try {
    parsed = parseArgs({
      allowPositionals: true,
      options: {
        'secret-file': { type: 'string' },
        server: { type: 'string' },
        pages: { type: 'string' },
        force: { type: 'boolean', default: false },
        'show-url': { type: 'boolean', default: false },
        copy: { type: 'boolean', default: false },
        help: { type: 'boolean', short: 'h', default: false },
      },
    });
  } catch (e) {
    fail(`${e instanceof Error ? e.message : e}\n\n${USAGE}`);
  }
  const { values, positionals } = parsed;
  const cmd = positionals[0];
  if (values.help || !cmd) {
    process.stdout.write(USAGE + '\n');
    return;
  }
  const opts = {
    secretFile: values['secret-file'] ?? defaultSecretFile(),
    server: values.server,
    pages: values.pages,
    force: values.force,
    showUrl: values['show-url'],
    copy: values.copy,
  };
  const commands = { setup: cmdSetup, import: cmdImport, receive: cmdReceive, send: cmdSend, forget: cmdForget };
  const run = commands[cmd];
  if (!run) fail(`不明なコマンド: ${cmd}\n\n${USAGE}`);
  await run(opts);
}

main().catch((e) => fail(e instanceof Error ? e.message : String(e)));
