#!/usr/bin/env python3
"""voice-relay のターミナル版（Python 3.8 以上 + cryptography パッケージ）。

Node.js 20 以上が使えない環境向け。Web 版・Node 版と同じ形式でやり取りし、
秘密ファイル（~/.config/voice-relay/secret）も共通。
暗号処理は cryptography パッケージ（AES-GCM, HKDF）を使い、自前実装はしない。

    python3 -m pip install --user --upgrade "cryptography>=50.0.2"
    python3 cli/voice_relay.py import
    python3 cli/voice_relay.py receive

秘密はコマンドライン引数では受け取らない（共有マシンでは ps で他のユーザーに見えるため）。
"""

import argparse
import base64
import binascii
import errno
import fcntl
import getpass
import json
import os
import re
import secrets
import select
import shutil
import signal
import stat
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

try:
    import cryptography
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:
    sys.stderr.write(
        'エラー: cryptography パッケージが必要です。次のコマンドで入れてください:\n'
        '  python3 -m pip install --user --upgrade "cryptography>=50.0.2"\n'
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# 定数（js/crypto.js・js/pairing.js と同じ値にすること）

FORMAT_VERSION = 1
SECRET_BYTES = 32
MAX_PARTS = 8
MAX_BODY_BYTES = 4000
IV_BYTES = 12
TAG_BYTES = 16
ID_BYTES = 16
TOPIC_BYTES = 24
MAX_PLAIN_BYTES = (MAX_BODY_BYTES // 4) * 3 - 1 - IV_BYTES - TAG_BYTES
ENVELOPE_RESERVE = 96

HKDF_SALT = b'voice-relay/v1'
INFO_KEY = b'voice-relay/v1/aes-256-gcm-key'
INFO_TOPIC = b'voice-relay/v1/ntfy-topic'
AAD = bytes([FORMAT_VERSION])

DEFAULT_SERVER = 'https://ntfy.sh'
MAX_AGE_SEC = 10 * 60
MAX_SKEW_SEC = 2 * 60
MAX_LINE_BYTES = 64 * 1024

B64URL_RE = re.compile(r'^[A-Za-z0-9_-]*$')
ID_RE = re.compile(r'^[A-Za-z0-9_-]{22}$')
NTFY_ID_RE = re.compile(r'^[A-Za-z0-9]+$')


# 2026-10 時点で既知の脆弱性（CVE）が報告されていない最初の版
RECOMMENDED_CRYPTOGRAPHY = (50, 0, 2)


def _version_tuple(s):
    parts = []
    for p in s.split('.')[:3]:
        m = re.match(r'\d+', p)
        parts.append(int(m.group()) if m else 0)
    return tuple(parts + [0] * (3 - len(parts)))


def check_cryptography_version():
    """古い cryptography（OS 付属のものなど）なら警告する。
    OS のパッケージは版番号が古いまま修正だけ取り込んでいることがあるので、止めはしない。"""
    ver = getattr(cryptography, '__version__', '0')
    if _version_tuple(ver) < RECOMMENDED_CRYPTOGRAPHY:
        info('警告: cryptography {} は古い版です（既知の脆弱性があります）。次のコマンドで更新してください:\n'
             '  python3 -m pip install --user --upgrade "cryptography>={}"'.format(
                 ver, '.'.join(str(x) for x in RECOMMENDED_CRYPTOGRAPHY)))


def fail(msg):
    sys.stderr.write('エラー: {}\n'.format(msg))
    sys.exit(1)


def info(msg):
    sys.stderr.write(msg + '\n')
    sys.stderr.flush()


# ---------------------------------------------------------------------------
# base64url・ペアリング情報

def b64url_encode(data):
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def b64url_decode(s):
    """パディングなし・正準形の base64url だけを受け付ける。"""
    if not isinstance(s, str) or not B64URL_RE.match(s) or len(s) % 4 == 1:
        raise ValueError('base64url として不正です')
    try:
        out = base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
    except (binascii.Error, ValueError):
        raise ValueError('base64url として不正です')
    if b64url_encode(out) != s:
        raise ValueError('base64url として不正です')
    return out


def normalize_server(value):
    u = urllib.parse.urlsplit(str(value).strip())
    host = (u.hostname or '')
    local = host in ('localhost', '127.0.0.1')
    if not (u.scheme == 'https' or (u.scheme == 'http' and local)) or not host:
        raise ValueError('ntfy サーバーは https:// の URL にしてください')
    if u.username or u.password or u.query or u.fragment:
        raise ValueError('ntfy サーバーの URL にユーザー名・クエリ・# は含められません')
    netloc = host + (':{}'.format(u.port) if u.port else '')
    return '{}://{}{}'.format(u.scheme, netloc, u.path).rstrip('/')


def parse_pairing(text):
    """ページの URL 全体 / "#k=..." / "k=...&s=..." / 秘密そのもの、のどれでも受け付ける。"""
    frag = str(text).strip()
    if '#' in frag:
        frag = frag.split('#', 1)[1]
    server = None
    if '=' in frag:
        params = urllib.parse.parse_qs(frag, keep_blank_values=True)
        k = (params.get('k') or [''])[0]
        server = (params.get('s') or [None])[0]
    else:
        k = frag
    try:
        secret = b64url_decode(k)
    except ValueError:
        secret = b''
    if len(secret) != SECRET_BYTES:
        raise ValueError('ペアリング情報（秘密）が見つからないか、形式が不正です')
    return secret, normalize_server(server) if server else DEFAULT_SERVER


def format_pairing(secret, server):
    s = 'k=' + b64url_encode(secret)
    server = normalize_server(server)
    if server != DEFAULT_SERVER:
        s += '&s=' + urllib.parse.quote(server, safe='')
    return s


# ---------------------------------------------------------------------------
# 暗号（js/crypto.js と同じ形式）

class Session(object):
    def __init__(self, secret):
        if len(secret) != SECRET_BYTES:
            raise ValueError('秘密の長さが不正です')
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=HKDF_SALT, info=INFO_KEY).derive(secret)
        topic = HKDF(algorithm=hashes.SHA256(), length=TOPIC_BYTES, salt=HKDF_SALT, info=INFO_TOPIC).derive(secret)
        self.aead = AESGCM(key)
        self.topic = b64url_encode(topic)

    def pair_code(self):
        h = b64url_decode(self.topic)[:4].hex()
        return '{}-{}'.format(h[:4], h[4:])


def _json_cost(ch):
    c = ord(ch)
    if c in (0x22, 0x5c):
        return 2
    if c in (0x08, 0x09, 0x0a, 0x0c, 0x0d):
        return 2
    if c < 0x20:
        return 6
    if c < 0x80:
        return 1
    if c < 0x800:
        return 2
    if 0xd800 <= c <= 0xdfff:
        return 6
    if c < 0x10000:
        return 3
    return 4


def split_text(text):
    budget = MAX_PLAIN_BYTES - ENVELOPE_RESERVE
    chunks, cur, used = [], [], 0
    for ch in text:
        cost = _json_cost(ch)
        if used + cost > budget:
            chunks.append(''.join(cur))
            cur, used = [], 0
        cur.append(ch)
        used += cost
    if cur or not chunks:
        chunks.append(''.join(cur))
    return chunks


def seal_text(session, text, now_ms=None):
    if not text:
        raise ValueError('本文が空です')
    # 孤立サロゲート（不正な UTF-8 入力由来など）は U+FFFD に置き換える。
    # そのままでは JS の JSON.stringify と表現が変わり、受信側で弾かれるため
    text = ''.join('\ufffd' if 0xd800 <= ord(ch) <= 0xdfff else ch for ch in text)
    chunks = split_text(text)
    if len(chunks) > MAX_PARTS:
        raise ValueError('メッセージが長すぎます（{} 分割が必要、上限は {} 分割）'.format(len(chunks), MAX_PARTS))
    msg_id = b64url_encode(secrets.token_bytes(ID_BYTES))
    t = int(time.time() * 1000) if now_ms is None else now_ms
    bodies = []
    for i, chunk in enumerate(chunks):
        payload = {'id': msg_id, 't': t, 'i': i, 'n': len(chunks), 'x': chunk}
        plain = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        if len(plain) > MAX_PLAIN_BYTES:
            raise RuntimeError('内部エラー: 分割サイズの計算が不正です')
        iv = secrets.token_bytes(IV_BYTES)
        ct = session.aead.encrypt(iv, plain, AAD)
        bodies.append(b64url_encode(bytes([FORMAT_VERSION]) + iv + ct))
    return bodies


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def open_body(session, body):
    """復号できたら payload の dict、形式不正・改ざん・鍵違いは None（黙って捨てる）。"""
    try:
        if not isinstance(body, str) or len(body) > MAX_BODY_BYTES:
            return None
        raw = b64url_decode(body)
        if len(raw) < 1 + IV_BYTES + TAG_BYTES or raw[0] != FORMAT_VERSION:
            return None
        plain = session.aead.decrypt(raw[1:1 + IV_BYTES], raw[1 + IV_BYTES:], AAD)
        p = json.loads(plain.decode('utf-8'))
    except (ValueError, InvalidTag, UnicodeDecodeError):
        return None
    if not isinstance(p, dict):
        return None
    ok = (
        isinstance(p.get('id'), str) and ID_RE.match(p['id'])
        and _is_int(p.get('t')) and 0 < p['t'] <= 2 ** 53 - 1
        and _is_int(p.get('n')) and 1 <= p['n'] <= MAX_PARTS
        and _is_int(p.get('i')) and 0 <= p['i'] < p['n']
        and isinstance(p.get('x'), str)
    )
    return p if ok else None


class Inbox(object):
    """リプレイ防止と分割メッセージの結合（js/crypto.js の Inbox と同じ規則）。"""

    def __init__(self, max_age_ms=MAX_AGE_SEC * 1000, max_skew_ms=MAX_SKEW_SEC * 1000, max_pending=64):
        self.max_age_ms = max_age_ms
        self.max_skew_ms = max_skew_ms
        self.max_pending = max_pending
        self._pending = {}
        self._done = {}

    def accept(self, p, now_ms=None):
        now = int(time.time() * 1000) if now_ms is None else now_ms
        self.prune(now)
        if p['t'] < now - self.max_age_ms or p['t'] > now + self.max_skew_ms:
            return None
        if p['id'] in self._done:
            return None
        e = self._pending.get(p['id'])
        if e is None:
            if len(self._pending) >= self.max_pending:
                return None
            e = {'t': p['t'], 'n': p['n'], 'chunks': [None] * p['n'], 'count': 0}
            self._pending[p['id']] = e
        if e['t'] != p['t'] or e['n'] != p['n'] or e['chunks'][p['i']] is not None:
            return None
        e['chunks'][p['i']] = p['x']
        e['count'] += 1
        if e['count'] < e['n']:
            return None
        del self._pending[p['id']]
        self._done[p['id']] = p['t']
        return {'id': p['id'], 't': p['t'], 'text': ''.join(e['chunks'])}

    def prune(self, now_ms):
        limit = now_ms - self.max_age_ms
        for k in [k for k, t in self._done.items() if t < limit]:
            del self._done[k]
        for k in [k for k, e in self._pending.items() if e['t'] < limit]:
            del self._pending[k]


# ---------------------------------------------------------------------------
# 表示の無害化（js/text.js と同じ方針）

_KEEP = {'\t', '\n', '‍', '︎', '️'}
_EXTRA = {'͏', 'ᅟ', 'ᅠ', '⠀', 'ㅤ', 'ﾠ'}


def _is_hidden(ch):
    if ch in _KEEP:
        return False
    if unicodedata.category(ch) in ('Cc', 'Cf', 'Co', 'Cn', 'Cs', 'Zl', 'Zp') or ch in _EXTRA:
        return True
    c = ord(ch)
    return 0xfe00 <= c <= 0xfe0f or 0xe0100 <= c <= 0xe01ef


def reveal_hidden(s):
    """端末を操作できる文字や見えない文字を ⟦U+XXXX⟧ の形にする。(表示用文字列, 置き換えた数)"""
    out, n = [], 0
    for ch in s:
        if _is_hidden(ch):
            out.append('⟦U+{:04X}⟧'.format(ord(ch)))
            n += 1
        else:
            out.append(ch)
    return ''.join(out), n


# ---------------------------------------------------------------------------
# ntfy

class NtfyError(Exception):
    def __init__(self, kind, message):
        Exception.__init__(self, message)
        self.kind = kind


def _error_for_status(status):
    if status == 429:
        return NtfyError('rate', 'ntfy のレート制限に達しました（429）。同じネットワークの他の利用者と上限を共有している'
                                 '可能性があります。しばらく待つか、モバイル回線に切り替えるか、自前の ntfy サーバーを使ってください。')
    if status == 413:
        return NtfyError('too-large', 'メッセージが ntfy のサイズ上限を超えました（413）。')
    if status in (401, 403):
        return NtfyError('forbidden', 'ntfy サーバーにアクセスが拒否されました（{}）。'.format(status))
    return NtfyError('http', 'ntfy サーバーがエラーを返しました（HTTP {}）。'.format(status))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """リダイレクトは辿らない（中継サーバーに別のホストや http:// へ誘導されないように）。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def topic_url(server, topic):
    return '{}/{}'.format(server, urllib.parse.quote(topic, safe=''))


def publish(server, topic, body):
    req = urllib.request.Request(topic_url(server, topic), data=body.encode('ascii'), method='POST',
                                 headers={'Content-Type': 'text/plain', 'Firebase': 'no'})
    try:
        with _opener.open(req, timeout=30) as res:
            res.read()
    except urllib.error.HTTPError as e:
        raise _error_for_status(e.code)
    except (urllib.error.URLError, OSError):
        raise NtfyError('network', 'ntfy サーバーに接続できませんでした。通信状態を確認してください。')


def subscribe(server, topic, on_message, on_state, since='10m', idle_timeout=90):
    """トピックを購読し続ける（Ctrl-C まで戻らない）。切れたら待ってから再接続する。"""
    backoff = 2
    while True:
        on_state('connecting', None, 0)
        error = None
        url = '{}/json?since={}'.format(topic_url(server, topic), urllib.parse.quote(since, safe=''))
        try:
            # timeout は読み込みごとに効くので、keepalive（既定 45 秒）が途絶えたら切断になる
            with _opener.open(url, timeout=idle_timeout) as res:
                on_state('open', None, 0)
                backoff = 2
                while True:
                    line = res.readline(MAX_LINE_BYTES + 1)
                    if not line:
                        break
                    if len(line) > MAX_LINE_BYTES:
                        # 改行のない巨大なデータを送り続けるサーバーでメモリを使い果たさないよう切断する
                        raise NtfyError('http', 'ntfy サーバーから想定外に大きなデータが届いたため切断しました。')
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line.decode('utf-8'))
                    except (ValueError, UnicodeDecodeError):
                        continue
                    if isinstance(ev, dict) and ev.get('event') == 'message' and isinstance(ev.get('message'), str):
                        if isinstance(ev.get('id'), str) and NTFY_ID_RE.match(ev['id']):
                            since = ev['id']
                        on_message(ev['message'])
        except urllib.error.HTTPError as e:
            error = _error_for_status(e.code)
        except NtfyError as e:
            error = e
        except (urllib.error.URLError, OSError, ValueError):
            error = NtfyError('network', 'ntfy サーバーとの接続が切れました。再接続します。')
        wait = max(backoff, 60) if error is not None and error.kind == 'rate' else backoff
        on_state('retrying', error, wait)
        time.sleep(wait)
        backoff = min(backoff * 2, 60)


# ---------------------------------------------------------------------------
# 秘密ファイル（cli/voice-relay.mjs と同じ場所・形式・権限）

def default_secret_file():
    if os.environ.get('VOICE_RELAY_SECRET_FILE'):
        return os.environ['VOICE_RELAY_SECRET_FILE']
    base = os.environ.get('XDG_CONFIG_HOME') or os.path.join(os.path.expanduser('~'), '.config')
    return os.path.join(base, 'voice-relay', 'secret')


def _check_secret_dir(d):
    st = os.lstat(d)
    if not stat.S_ISDIR(st.st_mode):
        fail('{} がディレクトリではありません（シンボリックリンクは使えません）。'.format(d))
    if st.st_uid != os.getuid():
        fail('{} の所有者が自分ではありません。'.format(d))
    if st.st_mode & 0o022:
        fail('{} が他のユーザーから書き込める権限になっています。chmod go-w {} を実行してください。'.format(d, d))


def save_secret(path, secret, server, force):
    """一時ファイルを O_EXCL で作って書き込み、rename で置き換える（既存ファイルやリンクを辿らない）。"""
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, mode=0o700, exist_ok=True)
    _check_secret_dir(d)
    if not force and os.path.lexists(path):
        fail('{} は既にあります。上書きするなら --force を付けてください。'.format(path))
    tmp = os.path.join(d, '.secret-{}.tmp'.format(secrets.token_hex(8)))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(format_pairing(secret, server) + '\n')
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, path)


def load_secret(path):
    """シンボリックリンク・他人のファイル・他人が読める権限なら拒否する。確認と読み込みは同じ fd で行う。"""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    except FileNotFoundError:
        return None
    except OSError as e:
        if e.errno == errno.ELOOP:
            fail('{} がシンボリックリンクです。通常のファイルにしてください。'.format(path))
        raise
    with os.fdopen(fd, 'r', encoding='utf-8') as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode):
            fail('{} が通常のファイルではありません。'.format(path))
        if st.st_uid != os.getuid():
            fail('{} の所有者が自分ではありません。'.format(path))
        if st.st_mode & 0o077:
            fail('{} が他のユーザーから読める権限になっています。chmod 600 {} を実行してください。'.format(path, path))
        text = f.read(4096)
    try:
        return parse_pairing(text)
    except ValueError:
        fail('{} の内容が不正です。import をやり直してください。'.format(path))


def read_hidden(prompt):
    """エコーなしで 1 行読む。標準入力が端末でなければパイプから 1 行読む。"""
    if not sys.stdin.isatty():
        return sys.stdin.readline().strip()
    return getpass.getpass(prompt)


def _copy_with_command(text):
    if os.environ.get('WAYLAND_DISPLAY'):
        cands = [['wl-copy'], ['xclip', '-selection', 'clipboard'], ['xsel', '--clipboard', '--input']]
    else:
        cands = [['xclip', '-selection', 'clipboard'], ['xsel', '--clipboard', '--input'], ['wl-copy']]
    for cmd in cands:
        if not shutil.which(cmd[0]):
            continue
        try:
            p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            p.communicate(text.encode('utf-8', 'surrogatepass'), timeout=5)
            if p.returncode == 0:
                return True
        except (OSError, subprocess.SubprocessError):
            continue
    return False


def _read_line(proc, timeout):
    ready, _, _ = select.select([proc.stdout], [], [], timeout)
    if not ready:
        return None
    return proc.stdout.readline().decode('utf-8', 'replace').strip()


class Clipboard(object):
    """wl-copy / xclip / xsel のどれかでコピーする。どれもなければ、GTK の補助プロセス
    （clipboard_gtk.py、Ubuntu のデスクトップに標準で入っている PyGObject を使う）を常駐させてコピーする。"""

    def __init__(self):
        self._helper = None

    def copy(self, text):
        return _copy_with_command(text) or self._copy_with_gtk(text)

    def _start_helper(self):
        helper = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'clipboard_gtk.py')
        try:
            proc = subprocess.Popen([sys.executable, helper], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL)
        except OSError:
            return None
        if _read_line(proc, 10) != 'ready':
            proc.kill()
            proc.wait()
            return None
        return proc

    def _copy_with_gtk(self, text):
        if not (os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')):
            return False
        for _ in range(2):  # 補助プロセスが落ちていたら 1 回だけ起動し直す
            if self._helper is None or self._helper.poll() is not None:
                self._helper = self._start_helper()
                if self._helper is None:
                    return False
            try:
                self._helper.stdin.write((json.dumps({'text': text}) + '\n').encode('ascii'))
                self._helper.stdin.flush()
                if _read_line(self._helper, 5) == 'ok':
                    return True
            except OSError:
                pass
            self.close()
        return False

    def close(self):
        if self._helper is not None:
            try:
                self._helper.stdin.close()
                self._helper.wait(timeout=3)
            except (OSError, subprocess.SubprocessError):
                self._helper.kill()
            self._helper = None


# ---------------------------------------------------------------------------
# フォーカス中の入力欄への入力（--type。X11 + xdotool のみ）
#
# 受信したテキストを、いまフォーカスが当たっているウィンドウに貼り付ける。
# 秘密を知った人が PC にキー入力を送れることになるので、次のように制限する:
# - 改行と制御文字（ESC を含む）を取り除き、Enter は押さない。端末に貼り付けても入力欄に入るだけで、
#   実行されるのは自分で Enter を押したときだけ。ESC を除くので、貼り付けの終わりを装うエスケープ
#   シーケンス（ESC[201~）で端末の貼り付け保護をすり抜けることもできない
# - 画面ロック中・フォーカス先を判定できないときは入力しない
# 入力はクリップボード経由で行う（端末は Ctrl+Shift+V、それ以外は Ctrl+V）。日本語入力（IME）がオンでも化けない。

# WM_CLASS にこれらの文字列が含まれるウィンドウは端末とみなし、Ctrl+Shift+V で貼り付ける
TERMINAL_CLASS_HINTS = (
    'terminal', 'xterm', 'rxvt', 'kitty', 'alacritty', 'konsole', 'terminator', 'tilix', 'wezterm',
    'st-256color', 'foot', 'guake', 'yakuake', 'terminology', 'sakura', 'ghostty', 'tabby', 'hyper',
    'warp', 'contour', 'blackbox', 'ptyxis', 'kgx', 'console', 'tmux', 'screen', 'putty', 'remmina',
)
# Ctrl+Shift+V で CLIPBOARD を貼り付けられない端末（Shift+Insert で PRIMARY を貼る）。コピーだけにする
UNSUPPORTED_TERMINAL_CLASSES = ('"xterm"', 'rxvt')

_LINE_BREAKS_RE = re.compile('\r\n|[\n\r\u0085  ]')
_CONTROL_RE = re.compile('[\u0000-\u0008\u000b-\u001f\u007f-\u009f]')


def flatten_for_typing(text):
    """入力用に、改行を空白にし、制御文字を取り除く（タブは残す）。"""
    return _CONTROL_RE.sub('', _LINE_BREAKS_RE.sub(' ', text)).strip()


def _run(cmd, timeout=3):
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout,
                           universal_newlines=True)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def _screen_locked():
    """GNOME などの画面ロック中か（判定できなければ False）。"""
    if not shutil.which('gdbus'):
        return False
    for dest, path in (('org.gnome.ScreenSaver', '/org/gnome/ScreenSaver'),
                       ('org.freedesktop.ScreenSaver', '/org/freedesktop/ScreenSaver')):
        out = _run(['gdbus', 'call', '--session', '--dest', dest, '--object-path', path,
                    '--method', dest + '.GetActive'])
        if out is not None:
            return 'true' in out
    return False


def _focused_window_class():
    """フォーカス中のウィンドウの WM_CLASS（小文字）。取れなければ None。"""
    wid = _run(['xdotool', 'getactivewindow'])
    if not wid or not wid.strip().isdigit():
        return None
    out = _run(['xprop', '-id', wid.strip(), 'WM_CLASS'])
    if not out or '=' not in out:
        return None
    return out.split('=', 1)[1].strip().lower()


def typing_unavailable_reason():
    """--type が使えない理由（使えるなら None）。"""
    if os.environ.get('XDG_SESSION_TYPE') == 'wayland' or not os.environ.get('DISPLAY'):
        return 'X11 のセッションでのみ使えます（Wayland では他のアプリへの入力が OS に禁止されています）'
    for tool in ('xdotool', 'xprop'):
        if not shutil.which(tool):
            return '{} が見つかりません'.format(tool)
    return None


def paste_into_focused(clipboard_ready):
    """フォーカス中のウィンドウに Ctrl+V を送る。結果を表す短い文字列を返す。
    clipboard_ready: 直前にクリップボードへのコピーが成功したか。"""
    if not clipboard_ready:
        return 'クリップボードにコピーできなかったので入力しませんでした'
    reason = typing_unavailable_reason()
    if reason:
        return '入力しませんでした（{}）'.format(reason)
    if _screen_locked():
        return '画面ロック中なので入力しませんでした'
    cls = _focused_window_class()
    if cls is None:
        return 'フォーカス先を判定できなかったので入力しませんでした'
    if any(u in cls for u in UNSUPPORTED_TERMINAL_CLASSES):
        return 'この端末には入力できないのでコピーだけしました（Shift+Insert ではなく、メニューから貼り付けてください）'
    terminal = any(h in cls for h in TERMINAL_CLASS_HINTS)
    if _run(['xdotool', 'key', '--clearmodifiers', 'ctrl+shift+v' if terminal else 'ctrl+v']) is None:
        return '入力に失敗しました'
    return '端末に入力しました（Enter は押していません）' if terminal else '入力しました'


def notify(summary, body):
    """デスクトップ通知を出す（notify-send がなければ何もしない）。本文は含めないこと。"""
    if not shutil.which('notify-send'):
        return
    try:
        subprocess.run(['notify-send', '-a', 'voice-relay', '-i', 'edit-paste', summary, body],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    except (OSError, subprocess.SubprocessError):
        pass


def _runtime_lock_path():
    d = os.environ.get('XDG_RUNTIME_DIR')
    if not d or not os.path.isdir(d):
        return None
    return os.path.join(d, 'voice-relay-receive.lock')


def acquire_instance_lock():
    """同じ PC で受信プロセスが 2 つ動かないようにする（XDG_RUNTIME_DIR は PC ごとの領域）。"""
    path = _runtime_lock_path()
    if path is None:
        return None
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        fail('この PC では既に受信プロセスが動いています（常駐させている場合は service status で確認できます）。')
    os.ftruncate(fd, 0)
    os.write(fd, str(os.getpid()).encode('ascii'))
    return fd


def running_receiver_pid():
    """常駐中の受信プロセスの PID（いなければ None）。"""
    path = _runtime_lock_path()
    if path is None or not os.path.exists(path):
        return None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    except OSError:
        return None
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            return None  # ロックが取れた = 誰も動いていない
        except OSError:
            pass
        pid = os.read(fd, 32).decode('ascii', 'replace').strip()
        return int(pid) if pid.isdigit() else None
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# コマンド

def obtain_pairing(secret_file):
    saved = load_secret(secret_file)
    if saved:
        return saved
    info('{} がないので、受信用 URL（または秘密）を入力してください（画面には表示されません）。'.format(secret_file))
    try:
        return parse_pairing(read_hidden('> '))
    except ValueError as e:
        fail(str(e))


def cmd_import(args):
    info('Web のセットアップページの「受信用 URL をコピー」を押し、ここに貼り付けて Enter（画面には表示されません）。')
    try:
        secret, server = parse_pairing(read_hidden('> '))
    except ValueError as e:
        fail(str(e))
    save_secret(args.secret_file, secret, server, args.force)
    info('保存しました（{}、権限 600）。確認コード: {}'.format(args.secret_file, Session(secret).pair_code()))


def cmd_receive(args):
    secret, server = obtain_pairing(args.secret_file)
    session = Session(secret)
    inbox = Inbox()
    started_ms = int(time.time() * 1000)
    out = sys.stdout
    if args.type:
        args.copy = True  # 入力はクリップボード経由なのでコピーも有効にする
        reason = typing_unavailable_reason()
        if reason:
            info('警告: --type は使えません（{}）。クリップボードへのコピーだけ行います。'.format(reason))
    clipboard = Clipboard() if args.copy else None
    lock = acquire_instance_lock()  # noqa: F841（プロセスが終わるまで保持する）
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    info('サーバー: {} / 確認コード: {}'.format(urllib.parse.urlsplit(server).netloc, session.pair_code()))
    if args.no_print:
        info('受信したテキストは表示しません（--no-print）。時刻と文字数だけを記録します。')
    else:
        info('Ctrl-C で終了します。受信内容はファイルには保存しません（ターミナルのスクロールバックには残ります）。')
        info('直近 10 分以内に送られたメッセージも表示されます。')
    state = {'was_open': False}

    def on_message(body):
        p = open_body(session, body)
        if p is None:
            return  # 偽造・改ざん・別の鍵のものは黙って捨てる
        m = inbox.accept(p)
        if m is None:
            return
        at = time.strftime('%H:%M:%S', time.localtime(m['t'] / 1000))
        shown, n = reveal_hidden(m['text'])
        if args.no_print:
            # 常駐時の出力はログ（journald）に残るので、本文は出さない
            info('受信 {}（{} 文字）'.format(at, len(m['text'])))
        else:
            head = '── {} '.format(at)
            out.write('\n\x1b[2m{}{}\x1b[0m\n'.format(head, '─' * max(0, 40 - len(head))))
            out.write(shown + '\n')
            out.flush()
        if n:
            info('（見えない文字・制御文字が {} 個含まれています）'.format(n))
        # 再起動のたびにクリップボードを上書きしないよう、コピーするのは起動後に送られたものだけ
        copied = None
        typed = None
        if clipboard is not None and m['t'] >= started_ms:
            # 入力する場合は、改行を空白にしたものをコピーして貼り付ける（Enter を押したことにならないように）
            text = flatten_for_typing(m['text']) if args.type else m['text']
            copied = clipboard.copy(text) if text else False
            info('（クリップボードにコピーしました）' if copied
                 else '（コピーできませんでした。xclip / xsel / wl-copy か、PyGObject（GTK）が必要です）')
            if args.type:
                typed = paste_into_focused(copied)
                info('（{}）'.format(typed))
        if args.notify:
            # 通知に本文は出さない（画面をのぞかれても内容が分からないように）
            detail = '{} 文字'.format(len(m['text']))
            if typed:
                detail += '・' + typed
            elif copied is True:
                detail += '・クリップボードにコピーしました'
            elif copied is False:
                detail += '・コピーできませんでした'
            if n:
                detail += '・見えない文字を含みます'
            notify('voice-relay: 受信しました', detail)

    def on_state(st, error, wait):
        if st == 'open':
            info('受信待機中…')
            if args.notify and state['was_open'] is None:
                notify('voice-relay: 再接続しました', '受信を再開しました')
            state['was_open'] = True
        elif st == 'retrying':
            info('{}（{} 秒後に再接続）'.format(str(error) if error else '接続が切れました。', wait))
            if args.notify and state['was_open']:
                notify('voice-relay: 接続が切れました', str(error) if error else '再接続します')
                state['was_open'] = None  # 通知は切れたときと戻ったときの 1 回ずつ

    try:
        subscribe(server, session.topic, on_message, on_state)
    finally:
        if clipboard is not None:
            clipboard.close()


def cmd_send(args):
    loaded = load_secret(args.secret_file)
    if not loaded:
        fail('{} がありません。先に import をしてください。'.format(args.secret_file))
    secret, server = loaded
    text = sys.stdin.read()
    if text.endswith('\n'):
        text = text[:-1]
    if not text:
        fail('標準入力が空です。')
    session = Session(secret)
    try:
        bodies = seal_text(session, text)
        for b in bodies:
            publish(server, session.topic, b)
    except (ValueError, NtfyError) as e:
        fail(str(e))
    info('送信しました（{} 通）。'.format(len(bodies)))


def cmd_forget(args):
    try:
        os.unlink(args.secret_file)
    except FileNotFoundError:
        pass
    info('{} を削除しました。'.format(args.secret_file))


# ---------------------------------------------------------------------------
# 常駐（ログイン中ずっと受信し、届いたらクリップボードにコピー）

SERVICE_NAME = 'voice-relay.service'


def _config_home():
    return os.environ.get('XDG_CONFIG_HOME') or os.path.join(os.path.expanduser('~'), '.config')


def _unit_path():
    return os.path.join(_config_home(), 'systemd', 'user', SERVICE_NAME)


def _autostart_path():
    return os.path.join(_config_home(), 'autostart', 'voice-relay.desktop')


def _receiver_command(secret_file, type_text=False):
    return [sys.executable, os.path.abspath(__file__), '--secret-file', os.path.abspath(secret_file),
            'receive', '--copy', '--no-print', '--notify'] + (['--type'] if type_text else [])


def _systemd_quote(arg):
    return '"' + arg.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%') + '"'


def _desktop_quote(arg):
    escaped = arg
    for ch in ('\\', '"', '`', '$'):
        escaped = escaped.replace(ch, '\\' + ch)
    return '"' + escaped.replace('%', '%%') + '"'


def _systemctl(*args):
    return subprocess.run(['systemctl', '--user'] + list(args), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True)


def _has_systemd_user():
    if not shutil.which('systemctl'):
        return False
    try:
        return _systemctl('show-environment').returncode == 0
    except OSError:
        return False


def _write_private(path, content):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + '.tmp-' + secrets.token_hex(4)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o644)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(content)
    os.replace(tmp, path)


def service_install(args):
    if not load_secret(args.secret_file):
        # まだ秘密を取り込んでいなければ、ここで受信用 URL を尋ねる（import と同じ）
        args.force = False
        cmd_import(args)
    cmd = _receiver_command(args.secret_file, getattr(args, 'type', False))
    if _has_systemd_user():
        _write_private(_unit_path(), '\n'.join([
            '# voice-relay: ログイン中ずっと受信し、届いたテキストをクリップボードにコピーする',
            '# 削除: python3 {} service uninstall'.format(os.path.abspath(__file__)),
            '[Unit]',
            'Description=voice-relay receiver (copy received text to clipboard)',
            'PartOf=graphical-session.target',
            'After=graphical-session.target',
            '',
            '[Service]',
            'ExecStart=' + ' '.join(_systemd_quote(a) for a in cmd),
            'Restart=on-failure',
            'RestartSec=15',
            '',
            '[Install]',
            'WantedBy=graphical-session.target',
            '',
        ]))
        _systemctl('daemon-reload')
        r = _systemctl('enable', '--now', SERVICE_NAME)
        if r.returncode != 0:
            fail('systemd への登録に失敗しました:\n' + r.stdout.strip())
        time.sleep(2)
        active = _systemctl('is-active', SERVICE_NAME).stdout.strip()
        info('常駐を登録しました（systemd のユーザーサービス）。状態: {}'.format(active))
        info('ログインするたびに自動で起動します。ログ: journalctl --user -u voice-relay -f')
    else:
        _write_private(_autostart_path(), '\n'.join([
            '[Desktop Entry]',
            'Type=Application',
            'Name=voice-relay',
            'Comment=Receive text and copy it to the clipboard',
            'Exec=' + ' '.join(_desktop_quote(a) for a in cmd),
            'Terminal=false',
            'NoDisplay=true',
            'X-GNOME-Autostart-enabled=true',
            '',
        ]))
        if running_receiver_pid() is None:
            subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
        info('常駐を登録しました（デスクトップの自動起動）。ログインするたびに自動で起動します。')
    info('スマホから送ると、この PC のクリップボードにコピーされ、通知が出ます（本文は通知に出ません）。')


def service_uninstall(args):
    removed = False
    if os.path.exists(_unit_path()):
        _systemctl('disable', '--now', SERVICE_NAME)
        os.unlink(_unit_path())
        _systemctl('daemon-reload')
        removed = True
    if os.path.exists(_autostart_path()):
        os.unlink(_autostart_path())
        removed = True
    pid = running_receiver_pid()
    if pid is not None:
        try:
            with open('/proc/{}/cmdline'.format(pid), 'rb') as f:
                if b'voice_relay.py' in f.read():
                    os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    info('常駐を解除しました。' if removed else '常駐は登録されていませんでした。')


def service_status(args):
    if os.path.exists(_unit_path()):
        info('登録: systemd のユーザーサービス（{}）'.format(_unit_path()))
        info('状態: ' + _systemctl('is-active', SERVICE_NAME).stdout.strip())
    elif os.path.exists(_autostart_path()):
        info('登録: デスクトップの自動起動（{}）'.format(_autostart_path()))
    else:
        info('登録: なし')
    pid = running_receiver_pid()
    info('この PC で受信中のプロセス: ' + ('PID {}'.format(pid) if pid else 'なし'))


def cmd_service(args):
    {'install': service_install, 'uninstall': service_uninstall, 'status': service_status}[args.action](args)


def main():
    if sys.version_info < (3, 8):
        fail('Python 3.8 以上が必要です。')
    # 端末の文字コードが UTF-8 でなくても落ちないようにする
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors='replace')
        except (AttributeError, ValueError):
            pass
    parser = argparse.ArgumentParser(
        prog='voice_relay.py',
        description='voice-relay のターミナル版（Python）。秘密の作成は Web のセットアップページで行い、import で取り込みます。')
    parser.add_argument('--secret-file', default=default_secret_file(),
                        help='秘密の保存先（既定: ~/.config/voice-relay/secret）')
    sub = parser.add_subparsers(dest='command')
    p = sub.add_parser('import', help='Web のセットアップページで作った受信用 URL を貼り付けて保存する')
    p.add_argument('--force', action='store_true', help='既存の秘密を上書きする')
    p = sub.add_parser('receive', help='受信を開始する（Ctrl-C で終了）')
    p.add_argument('--copy', action='store_true',
                   help='受信したテキストをクリップボードにもコピーする（xclip / xsel / wl-copy か PyGObject が必要。'
                        '貼り付けは自分で行う）')
    p.add_argument('--no-print', action='store_true', help='受信したテキストを表示しない（時刻と文字数だけ）')
    p.add_argument('--notify', action='store_true', help='受信したらデスクトップ通知を出す（本文は出さない）')
    p.add_argument('--type', action='store_true',
                   help='フォーカス中の入力欄に貼り付ける（X11 + xdotool。改行は空白にし Enter は押さない。端末は Ctrl+Shift+V）')
    p = sub.add_parser('service', help='ログイン中ずっと受信してクリップボードにコピーする常駐プロセスを登録・解除する')
    p.add_argument('action', choices=['install', 'uninstall', 'status'])
    p.add_argument('--type', action='store_true',
                   help='install: 受信したらフォーカス中の入力欄にも貼り付ける（X11 + xdotool のみ）')
    sub.add_parser('send', help='標準入力のテキストを送る（動作確認用）')
    sub.add_parser('forget', help='保存した秘密を削除する')
    args = parser.parse_args()
    check_cryptography_version()
    commands = {'import': cmd_import, 'receive': cmd_receive, 'send': cmd_send, 'forget': cmd_forget,
                'service': cmd_service}
    if args.command not in commands:
        parser.print_help()
        return
    try:
        commands[args.command](args)
    except KeyboardInterrupt:
        info('\n終了しました。')


if __name__ == '__main__':
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    main()
