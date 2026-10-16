import { MAX_PARTS, MessageTooLongError, countParts, deriveSession, sealText } from './crypto.js';
import { $, ensureTopLevel, formatTime, lockConnectSrc, setStatus } from './page.js';
import { NtfyError, publish } from './ntfy.js';
import { pairCode, parsePairing } from './pairing.js';

// 送信ページは秘密を URL のフラグメントに置いたままにする（ブックマークして使うため）。
// フラグメントはサーバーへのリクエストにも Referer にも含まれない。

ensureTopLevel();

const textEl = /** @type {HTMLTextAreaElement} */ ($('text'));
const sendBtn = /** @type {HTMLButtonElement} */ ($('send'));
const statusEl = $('status');
const counterEl = $('counter');

/** @type {import('./pairing.js').Pairing} */
let pairing;
try {
  pairing = parsePairing(location.hash);
} catch {
  lockConnectSrc(null);
  textEl.disabled = true;
  const err = $('setup-error');
  err.textContent = 'このページはセットアップページで作った QR コード（URL）から開いてください。';
  err.hidden = false;
  throw new Error('ペアリング情報がありません');
}
lockConnectSrc(pairing.server);

const session = await deriveSession(pairing.secret);
$('pair-info').textContent = `${new URL(pairing.server).host} · ${pairCode(session.topic)}`;

// 送信モード
// - auto（既定）: 入力が止まってから少し待って自動で送る。音声入力キーボードは文章をまとめて入れるので、
//   話し終えた直後に送られる。1 文字ごとに送ると ntfy の上限（1 日 250 通など）をすぐ使い切るため待ち時間を置く
// - manual: 送信ボタン（または Ctrl+Enter）を押したときだけ送る
// モードと待ち時間はこの端末の localStorage に保存する（秘密ではない表示上の設定だけ）
const MODE_KEY = 'voice-relay:send-mode';
const DELAY_KEY = 'voice-relay:send-delay';
const delayEl = /** @type {HTMLSelectElement} */ ($('delay'));
const modeInputs = /** @type {NodeListOf<HTMLInputElement>} */ (document.querySelectorAll('input[name="mode"]'));

/** @param {string} key */
function loadPref(key) {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

/** @param {string} key @param {string} value */
function savePref(key, value) {
  try {
    localStorage.setItem(key, value);
  } catch {
    // 保存できなくても動作はする
  }
}

let mode = loadPref(MODE_KEY) === 'manual' ? 'manual' : 'auto';
const savedDelay = loadPref(DELAY_KEY);
if (savedDelay && [...delayEl.options].some((o) => o.value === savedDelay)) delayEl.value = savedDelay;
else delayEl.value = '1000';

let sending = false;
let composing = false; // 日本語入力の変換中（未確定文字がある間）は送らない
/** @type {ReturnType<typeof setTimeout> | undefined} */
let autoTimer;

function applyMode() {
  for (const input of modeInputs) input.checked = input.value === mode;
  $('delay-wrap').hidden = mode !== 'auto';
  sendBtn.textContent = mode === 'auto' ? '今すぐ送信' : '送信';
  $('mode-hint').textContent = mode === 'auto'
    ? `入力が止まって ${Number(delayEl.value) / 1000} 秒たつと自動で送信します。`
    : '送信ボタン（または Ctrl+Enter）で送信します。';
}

function isTooLong() {
  return countParts(textEl.value) > MAX_PARTS;
}

function updateCounter() {
  const text = textEl.value;
  const parts = countParts(text);
  counterEl.textContent = text.length === 0 ? '' : `${[...text].length} 文字` + (parts > 1 ? ` · ${parts} 通に分割` : '');
  const tooLong = parts > MAX_PARTS;
  if (tooLong) setStatus(statusEl, `長すぎます（${MAX_PARTS} 通まで）。分けて送ってください。`, 'error');
  sendBtn.disabled = sending || text.trim() === '' || tooLong;
}

function cancelAuto() {
  clearTimeout(autoTimer);
  autoTimer = undefined;
}

function scheduleAuto() {
  cancelAuto();
  if (mode !== 'auto' || composing || sending) return;
  if (textEl.value.trim() === '' || isTooLong()) return;
  autoTimer = setTimeout(() => {
    autoTimer = undefined;
    send();
  }, Number(delayEl.value));
}

async function send() {
  cancelAuto();
  // 送信中に追加で入力された分を消さないよう、送る時点の内容を控えておく
  const text = textEl.value;
  if (sending || text.trim() === '' || isTooLong()) return;
  sending = true;
  sendBtn.disabled = true;
  setStatus(statusEl, '送信中…');
  let sent = 0;
  let total = 0;
  let ok = false;
  try {
    const bodies = await sealText(session, text);
    total = bodies.length;
    for (const body of bodies) {
      await publish(pairing.server, session.topic, body);
      sent++;
      if (total > 1) setStatus(statusEl, `送信中… ${sent}/${total}`);
    }
    // 送った分だけ取り除く（送信中に続けて入力された分は残す）
    if (textEl.value.startsWith(text)) {
      textEl.value = textEl.value.slice(text.length).replace(/^\s+/, '');
      ok = true;
      setStatus(statusEl, `送信しました（${formatTime(Date.now())}）`, 'ok');
    } else {
      // 送信中に途中が書き換えられた（音声入力キーボードが前の単語を直した場合など）。
      // 送った内容と共通の先頭部分は送信済みとして取り除き、残りだけを残す（同じ文を二重に送らないように）。
      // 残りは自動では送らず、次に入力されたとき（または送信ボタン）に送る
      const current = textEl.value;
      let common = 0;
      while (common < text.length && common < current.length && text[common] === current[common]) common++;
      // サロゲートペア（絵文字など）の途中で切らない
      if (common > 0 && /[\ud800-\udbff]/.test(text[common - 1])) common--;
      textEl.value = current.slice(common).replace(/^\s+/, '');
      setStatus(statusEl, `送信しました（${formatTime(Date.now())}）。` +
        (textEl.value ? '送信中に編集された部分は残してあります。必要なら確認してから送信してください。' : ''), 'ok');
    }
  } catch (e) {
    let msg;
    if (e instanceof NtfyError || e instanceof MessageTooLongError) msg = e.message;
    else msg = '送信に失敗しました。';
    if (sent > 0) msg += `（${total} 通中 ${sent} 通は送信済み。受信側では表示されないので、もう一度送信してください）`;
    setStatus(statusEl, `${msg} 入力内容は残してあります。`, 'error');
  } finally {
    sending = false;
    updateCounter();
    // 失敗したときは自動で再送しない（送り直しはボタンで）。成功して残りがあれば続けて送る
    if (ok) scheduleAuto();
  }
}

textEl.addEventListener('input', (e) => {
  if (statusEl.classList.contains('ok')) setStatus(statusEl, '');
  updateCounter();
  if (/** @type {InputEvent} */ (e).isComposing) return;
  scheduleAuto();
});
textEl.addEventListener('compositionstart', () => {
  composing = true;
  cancelAuto();
});
textEl.addEventListener('compositionend', () => {
  composing = false;
  scheduleAuto();
});
textEl.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    send();
  }
});
sendBtn.addEventListener('click', send);
for (const input of modeInputs) {
  input.addEventListener('change', () => {
    if (!input.checked) return;
    mode = input.value === 'manual' ? 'manual' : 'auto';
    savePref(MODE_KEY, mode);
    applyMode();
    if (mode === 'auto') scheduleAuto();
    else cancelAuto();
    textEl.focus();
  });
}
delayEl.addEventListener('change', () => {
  savePref(DELAY_KEY, delayEl.value);
  applyMode();
  scheduleAuto();
});

// 開いた瞬間にキーボードを出す（textarea の autofocus と合わせて）。
// Android の Chrome では出るが、iPhone の Safari はユーザーがタップするまでキーボードを出さない仕様
function focusInput() {
  if (document.visibilityState !== 'visible' || document.activeElement === textEl) return;
  textEl.focus({ preventScroll: true });
  // カーソルを末尾に置く（続けて入力できるように）
  textEl.setSelectionRange(textEl.value.length, textEl.value.length);
}
// 他のアプリから戻ってきたときもすぐ入力できるようにする
document.addEventListener('visibilitychange', focusInput);
addEventListener('pageshow', focusInput);

applyMode();
focusInput();
// 開いた時点で入力欄に残っている文字（ブラウザが前回の内容を復元した場合など）は自動では送らない
updateCounter();
