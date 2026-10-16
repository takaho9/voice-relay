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
  const err = $('setup-error');
  err.textContent = 'このページはセットアップページで作った QR コード（URL）から開いてください。';
  err.hidden = false;
  throw new Error('ペアリング情報がありません');
}
lockConnectSrc(pairing.server);

const session = await deriveSession(pairing.secret);
$('pair-info').textContent = `${new URL(pairing.server).host} · ${pairCode(session.topic)}`;

let sending = false;

function updateCounter() {
  const text = textEl.value;
  const parts = countParts(text);
  counterEl.textContent = text.length === 0 ? '' : `${[...text].length} 文字` + (parts > 1 ? ` · ${parts} 通に分割` : '');
  const tooLong = parts > MAX_PARTS;
  if (tooLong) setStatus(statusEl, `長すぎます（${MAX_PARTS} 通まで）。分けて送ってください。`, 'error');
  sendBtn.disabled = sending || text.trim() === '' || tooLong;
}

async function send() {
  const text = textEl.value;
  if (sending || text.trim() === '') return;
  sending = true;
  sendBtn.disabled = true;
  setStatus(statusEl, '送信中…');
  let sent = 0;
  let total = 0;
  try {
    const bodies = await sealText(session, text);
    total = bodies.length;
    for (const body of bodies) {
      await publish(pairing.server, session.topic, body);
      sent++;
      if (total > 1) setStatus(statusEl, `送信中… ${sent}/${total}`);
    }
    textEl.value = '';
    setStatus(statusEl, `送信しました（${formatTime(Date.now())}）`, 'ok');
  } catch (e) {
    let msg;
    if (e instanceof NtfyError || e instanceof MessageTooLongError) msg = e.message;
    else msg = '送信に失敗しました。';
    if (sent > 0) msg += `（${total} 通中 ${sent} 通は送信済み。受信側では表示されないので、もう一度送信してください）`;
    setStatus(statusEl, `${msg} 入力内容は残してあります。`, 'error');
  } finally {
    sending = false;
    updateCounter();
  }
}

textEl.addEventListener('input', () => {
  if (statusEl.classList.contains('ok')) setStatus(statusEl, '');
  updateCounter();
});
textEl.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    send();
  }
});
sendBtn.addEventListener('click', send);

textEl.disabled = false;
textEl.focus();
updateCounter();
