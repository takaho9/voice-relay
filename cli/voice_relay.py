#!/usr/bin/env python3
"""voice-relay のターミナル版（Python 3.8 以上 + cryptography パッケージ）。

Node.js 20 以上が使えない環境向け。Web 版・Node 版と同じ形式でやり取りし、
秘密ファイル（~/.config/voice-relay/secret）も共通。
暗号処理は cryptography パッケージ（AES-GCM, HKDF）を使い、自前実装はしない。

    pip install --user cryptography
    python3 cli/voice_relay.py import
    python3 cli/voice_relay.py receive

秘密はコマンドライン引数では受け取らない（共有マシンでは ps で他のユーザーに見えるため）。
"""

import argparse
import base64
import binascii
import errno
import getpass
import json
import os
import re
import secrets
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
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:
    sys.stderr.write(
        'エラー: cryptography パッケージが必要です。次のコマンドで入れてください:\n'
        '  python3 -m pip install --user cryptography\n'
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


def copy_to_clipboard(text):
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
    info('Web のセットアップページの「受信用 URL」を貼り付けて Enter（画面には表示されません）。')
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

    info('サーバー: {} / 確認コード: {}'.format(urllib.parse.urlsplit(server).netloc, session.pair_code()))
    info('Ctrl-C で終了します。受信内容はファイルには保存しません（ターミナルのスクロールバックには残ります）。')
    info('直近 10 分以内に送られたメッセージも表示されます。')

    def on_message(body):
        p = open_body(session, body)
        if p is None:
            return  # 偽造・改ざん・別の鍵のものは黙って捨てる
        m = inbox.accept(p)
        if m is None:
            return
        head = '── {} '.format(time.strftime('%H:%M:%S', time.localtime(m['t'] / 1000)))
        out.write('\n\x1b[2m{}{}\x1b[0m\n'.format(head, '─' * max(0, 40 - len(head))))
        shown, n = reveal_hidden(m['text'])
        out.write(shown + '\n')
        out.flush()
        if n:
            info('（見えない文字・制御文字が {} 個含まれています）'.format(n))
        # 再起動のたびにクリップボードを上書きしないよう、コピーするのは起動後に送られたものだけ
        if args.copy and m['t'] >= started_ms:
            info('（クリップボードにコピーしました）' if copy_to_clipboard(m['text'])
                 else '（コピーできませんでした。wl-copy / xclip / xsel が必要です）')

    def on_state(state, error, wait):
        if state == 'open':
            info('受信待機中…')
        elif state == 'retrying':
            info('{}（{} 秒後に再接続）'.format(str(error) if error else '接続が切れました。', wait))

    subscribe(server, session.topic, on_message, on_state)


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
                   help='受信したテキストをクリップボードにもコピーする（wl-copy / xclip / xsel が必要。貼り付けは自分で行う）')
    sub.add_parser('send', help='標準入力のテキストを送る（動作確認用）')
    sub.add_parser('forget', help='保存した秘密を削除する')
    args = parser.parse_args()
    commands = {'import': cmd_import, 'receive': cmd_receive, 'send': cmd_send, 'forget': cmd_forget}
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
