import { Inbox, deriveSession, openBody } from './crypto.js';
import { $, copyText, ensureTopLevel, formatTime, lockConnectSrc, setStatus } from './page.js';
import { subscribe } from './ntfy.js';
import { pairCode, parsePairing } from './pairing.js';
import { revealHidden } from './text.js';

// 受信ページは秘密をどこにも保存しない（ページのメモリ上にだけ持つ）。
// - URL のフラグメントで渡されたら、読み取ってすぐにアドレスバーと履歴から消す
// - セットアップページからは sessionStorage で受け取り、読んだらすぐに消す。
//   sessionStorage は「閉じたタブを開き直す」で復元されるので、置いたままにしない
// そのためリロードすると受信用 URL の再入力が必要になる。

const SESSION_KEY = 'voice-relay:pairing';

ensureTopLevel();

/** @returns {string | null} */
function takeInitialPairing() {
  let handoff = null;
  try {
    handoff = sessionStorage.getItem(SESSION_KEY);
    sessionStorage.removeItem(SESSION_KEY);
  } catch {
    // sessionStorage が使えない環境では入力欄から受け取る
  }
  if (location.hash.length > 1) {
    const frag = location.hash.slice(1);
    history.replaceState(null, '', location.pathname + location.search);
    return frag;
  }
  return handoff;
}

/** @param {import('./pairing.js').Pairing} pairing */
async function start(pairing) {
  lockConnectSrc(pairing.server);
  const session = await deriveSession(pairing.secret);
  $('login').hidden = true;
  $('inbox').hidden = false;
  $('pair-code').textContent = pairCode(session.topic);
  $('server-host').textContent = new URL(pairing.server).host;

  const list = $('messages');
  const empty = $('empty');
  const conn = $('conn-status');
  const inbox = new Inbox();
  const ctrl = new AbortController();
  // 復号を直列化して、届いた順に処理する
  let queue = Promise.resolve();

  /** @param {import('./crypto.js').ReceivedMessage} m */
  function show(m) {
    const li = document.createElement('li');
    li.className = 'message';
    const meta = document.createElement('div');
    meta.className = 'meta';
    const time = document.createElement('span');
    time.className = 'muted';
    time.textContent = formatTime(m.t);
    const buttons = document.createElement('div');
    buttons.className = 'row';
    const copyBtn = document.createElement('button');
    copyBtn.type = 'button';
    copyBtn.textContent = 'コピー';
    const delBtn = document.createElement('button');
    delBtn.type = 'button';
    delBtn.textContent = '削除';
    const text = document.createElement('div');
    text.className = 'text';
    // 受信内容は必ず textContent で表示する（HTML として解釈しない）。
    // 見た目と中身が食い違う文字は ⟦U+XXXX⟧ の形で見せる
    const revealed = revealHidden(m.text);
    text.textContent = revealed.text;
    if (revealed.replaced > 0) {
      const warn = document.createElement('p');
      warn.className = 'warn';
      warn.textContent = `見えない文字・制御文字が ${revealed.replaced} 個含まれています（⟦U+XXXX⟧ の箇所）。` +
        'コピーすると元の文字のままコピーされるので、貼り付け先に注意してください。';
      li.append(warn);
    }

    copyBtn.addEventListener('click', async () => {
      const ok = await copyText(m.text);
      copyBtn.textContent = ok ? 'コピーしました' : 'コピー失敗（選択してコピーしてください）';
      if (ok) li.classList.add('copied');
      setTimeout(() => { copyBtn.textContent = 'コピー'; }, 1500);
    });
    delBtn.addEventListener('click', () => {
      li.remove();
      empty.hidden = list.childElementCount > 0;
    });

    buttons.append(copyBtn, delBtn);
    meta.append(time, buttons);
    li.prepend(meta, text);
    list.prepend(li);
    empty.hidden = true;
  }

  $('clear').addEventListener('click', () => {
    list.replaceChildren();
    empty.hidden = false;
  });
  $('quit').addEventListener('click', () => {
    ctrl.abort();
    list.replaceChildren();
    location.replace('receive.html');
  });

  subscribe(pairing.server, session.topic, {
    signal: ctrl.signal,
    onMessage(body) {
      queue = queue.then(async () => {
        const payload = await openBody(session, body);
        if (!payload) return; // 偽造・改ざん・別の鍵のものは黙って捨てる
        const m = inbox.accept(payload);
        if (m) show(m);
      });
    },
    onState(state, info) {
      if (state === 'connecting') setStatus(conn, '接続中…');
      else if (state === 'open') setStatus(conn, '受信待機中', 'ok');
      else if (state === 'retrying') {
        const sec = Math.round((info?.retryInMs ?? 0) / 1000);
        const why = info?.error?.message ?? '接続が切れました。';
        setStatus(conn, `${why}（${sec} 秒後に再接続）`, 'error');
      } else if (state === 'stopped') setStatus(conn, '停止しました');
    },
  });
}

const initial = takeInitialPairing();
let started = false;
if (initial) {
  try {
    const pairing = parsePairing(initial);
    started = true;
    await start(pairing);
  } catch {
    // 不正な値なら入力欄を出す
  }
}

if (!started) {
  $('login').hidden = false;
  const input = /** @type {HTMLInputElement} */ ($('pairing-input'));
  const go = async () => {
    if (started) return;
    try {
      const pairing = parsePairing(input.value);
      input.value = '';
      started = true;
      await start(pairing);
    } catch (e) {
      setStatus($('login-status'), e instanceof Error ? e.message : String(e), 'error');
    }
  };
  // form-action 'none' なので送信はされないが、念のため既定動作を止める
  $('login-form').addEventListener('submit', (e) => {
    e.preventDefault();
    go();
  });
  input.focus();
}
