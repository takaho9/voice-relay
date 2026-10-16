import { deriveSession, generateSecret } from './crypto.js';
import { $, copyText, pairCode, setStatus } from './page.js';
import { DEFAULT_SERVER, buildPageUrl, formatPairing, normalizeServer } from './pairing.js';
import { qrMatrix } from './qr.js';

const SVG_NS = 'http://www.w3.org/2000/svg';
const SESSION_KEY = 'voice-relay:pairing';

/** @type {import('./pairing.js').Pairing} */
let pairing = { secret: generateSecret(), server: DEFAULT_SERVER };

/** @param {string} text */
function renderQr(text) {
  const { size, isDark } = qrMatrix(text);
  const quiet = 4;
  const total = size + quiet * 2;
  let d = '';
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (isDark(r, c)) d += `M${c + quiet} ${r + quiet}h1v1h-1z`;
    }
  }
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', `0 0 ${total} ${total}`);
  svg.setAttribute('class', 'qr');
  svg.setAttribute('shape-rendering', 'crispEdges');
  svg.setAttribute('role', 'img');
  const bg = document.createElementNS(SVG_NS, 'rect');
  bg.setAttribute('width', String(total));
  bg.setAttribute('height', String(total));
  bg.setAttribute('fill', '#ffffff');
  const path = document.createElementNS(SVG_NS, 'path');
  path.setAttribute('d', d);
  path.setAttribute('fill', '#000000');
  svg.append(bg, path);
  $('qr').replaceChildren(svg);
}

async function render() {
  const sendUrl = buildPageUrl(new URL('send.html', location.href).href, pairing);
  const receiveUrl = buildPageUrl(new URL('receive.html', location.href).href, pairing);
  renderQr(sendUrl);
  $('send-url').textContent = sendUrl;
  $('receive-url').textContent = receiveUrl;
  /** @type {HTMLInputElement} */ ($('server')).value = pairing.server;
  const { topic } = await deriveSession(pairing.secret);
  $('pair-code').textContent = pairCode(topic);
}

/** @param {string} id @param {() => string} get */
function bindCopy(id, get) {
  const btn = /** @type {HTMLButtonElement} */ ($(id));
  btn.addEventListener('click', async () => {
    btn.textContent = (await copyText(get())) ? 'コピーしました' : 'コピーできませんでした';
    setTimeout(() => { btn.textContent = 'コピー'; }, 1500);
  });
}

bindCopy('copy-send', () => $('send-url').textContent ?? '');
bindCopy('copy-receive', () => $('receive-url').textContent ?? '');

$('start-receive').addEventListener('click', () => {
  try {
    sessionStorage.setItem(SESSION_KEY, formatPairing(pairing));
  } catch {
    // sessionStorage が使えない環境では、受信ページで受信用 URL を貼り付けてもらう
  }
  location.href = 'receive.html';
});

$('apply-server').addEventListener('click', async () => {
  const status = $('server-status');
  try {
    pairing = { ...pairing, server: normalizeServer(/** @type {HTMLInputElement} */ ($('server')).value || DEFAULT_SERVER) };
    await render();
    setStatus(status, 'サーバーを変更しました。QR コードと URL も更新されています。', 'ok');
  } catch (e) {
    setStatus(status, e instanceof Error ? e.message : String(e), 'error');
  }
});

$('regenerate').addEventListener('click', async () => {
  pairing = { ...pairing, secret: generateSecret() };
  await render();
  setStatus($('server-status'), '新しい秘密を作りました。', 'ok');
});

render().catch((e) => {
  document.querySelector('main')?.prepend(Object.assign(document.createElement('p'), {
    className: 'warn',
    textContent: `初期化に失敗しました: ${e instanceof Error ? e.message : e}`,
  }));
});
