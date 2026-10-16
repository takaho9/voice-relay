"""cli/voice_relay.py のテスト。 python3 -m unittest discover -s test -v"""

import hashlib
import hmac
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'cli'))

import voice_relay as v  # noqa: E402

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vectors.json'), encoding='utf-8') as f:
    VEC = json.load(f)

FIXED = bytes(range(32))


def hkdf_sha256(ikm, salt, info, length):
    """テスト用に標準ライブラリの hmac で HKDF を独立に計算する（RFC 5869）。"""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, block, i = b'', b'', 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        okm += block
        i += 1
    return okm[:length]


def deliver(session, inbox, bodies, now_ms):
    out = []
    for b in bodies:
        p = v.open_body(session, b)
        assert p is not None, '復号できるはず'
        m = inbox.accept(p, now_ms)
        if m:
            out.append(m)
    return out


class InteropTest(unittest.TestCase):
    def test_derivation_matches_vectors(self):
        secret, server = v.parse_pairing(VEC['pairing'])
        s = v.Session(secret)
        self.assertEqual(server, 'https://ntfy.sh')
        self.assertEqual(s.topic, VEC['topic'])
        self.assertEqual(s.pair_code(), VEC['pair_code'])

    def test_decrypt_js_bodies(self):
        s = v.Session(v.parse_pairing(VEC['pairing'])[0])
        msgs = deliver(s, v.Inbox(), VEC['js_bodies'], VEC['t'])
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0]['text'], VEC['text'])

    def test_decrypt_py_bodies(self):
        s = v.Session(v.parse_pairing(VEC['pairing'])[0])
        self.assertEqual(deliver(s, v.Inbox(), VEC['py_bodies'], VEC['t'])[0]['text'], VEC['text'])


class CryptoTest(unittest.TestCase):
    def test_topic_known_answer(self):
        expected = v.b64url_encode(hkdf_sha256(FIXED, b'voice-relay/v1', b'voice-relay/v1/ntfy-topic', 24))
        self.assertEqual(v.Session(FIXED).topic, expected)

    def test_roundtrip_and_iv_uniqueness(self):
        s = v.Session(os.urandom(32))
        text = 'こんにちは 😀\n"q" \\ \t\x01'
        a = v.seal_text(s, text)
        b = v.seal_text(s, text)
        self.assertNotEqual(a, b)
        now = v.open_body(s, a[0])['t']
        self.assertEqual(deliver(s, v.Inbox(), a, now)[0]['text'], text)

    def test_tamper_every_byte(self):
        s = v.Session(os.urandom(32))
        raw = bytearray(v.b64url_decode(v.seal_text(s, '改ざん')[0]))
        for i in range(len(raw)):
            t = bytearray(raw)
            t[i] ^= 1
            self.assertIsNone(v.open_body(s, v.b64url_encode(bytes(t))), i)
        self.assertIsNone(v.open_body(s, ''))
        self.assertIsNone(v.open_body(s, 'not base64!'))
        self.assertIsNone(v.open_body(s, 123))

    def test_wrong_key(self):
        a, b = v.Session(os.urandom(32)), v.Session(os.urandom(32))
        self.assertNotEqual(a.topic, b.topic)
        self.assertIsNone(v.open_body(b, v.seal_text(a, 'x')[0]))

    def test_replay(self):
        s = v.Session(os.urandom(32))
        now = 1790000000000
        bodies = v.seal_text(s, 'once', now_ms=now)
        inbox = v.Inbox()
        self.assertEqual(len(deliver(s, inbox, bodies, now)), 1)
        self.assertEqual(len(deliver(s, inbox, bodies, now + 1000)), 0)
        old = v.seal_text(s, 'old', now_ms=now - 10 * 60 * 1000 - 1)
        self.assertEqual(len(deliver(s, v.Inbox(), old, now)), 0)
        future = v.seal_text(s, 'future', now_ms=now + 3 * 60 * 1000)
        self.assertEqual(len(deliver(s, v.Inbox(), future, now)), 0)

    def test_split_limits(self):
        s = v.Session(os.urandom(32))
        for unit, count in [('あ', 5000), ('a', 5000), ('😀', 4000), ('\n', 5000), ('\x01', 2000), ('"', 5000)]:
            text = unit * count
            bodies = v.seal_text(s, text, now_ms=1790000000000)
            self.assertGreater(len(bodies), 1)
            for b in bodies:
                self.assertLessEqual(len(b), v.MAX_BODY_BYTES)
            msgs = deliver(s, v.Inbox(), list(reversed(bodies)), 1790000000000)
            self.assertEqual(msgs[0]['text'], text)
        with self.assertRaises(ValueError):
            v.seal_text(s, 'あ' * 30000)
        with self.assertRaises(ValueError):
            v.seal_text(s, '')

    def test_lone_surrogate_is_replaced(self):
        s = v.Session(os.urandom(32))
        b = v.seal_text(s, 'a\udc80b', now_ms=1790000000000)
        self.assertEqual(deliver(s, v.Inbox(), b, 1790000000000)[0]['text'], 'a�b')

    def test_b64url_canonical(self):
        self.assertEqual(v.b64url_decode('AA'), b'\x00')
        for bad in ('AB', 'ab+c', 'abc=', 'a'):
            with self.assertRaises(ValueError):
                v.b64url_decode(bad)


class PairingTest(unittest.TestCase):
    def test_formats(self):
        secret = os.urandom(32)
        frag = v.format_pairing(secret, 'https://ntfy.example.com/sub/')
        url = 'https://u.github.io/voice-relay/receive.html#' + frag
        expected = (secret, 'https://ntfy.example.com/sub')
        self.assertEqual(v.parse_pairing(url), expected)
        self.assertEqual(v.parse_pairing('  #' + frag + '\n'), expected)
        self.assertEqual(v.parse_pairing(v.b64url_encode(secret)), (secret, 'https://ntfy.sh'))

    def test_rejects(self):
        for bad in ('', 'k=short', 'https://x/#s=https%3A%2F%2Fa.example'):
            with self.assertRaises(ValueError):
                v.parse_pairing(bad)
        for bad in ('http://ntfy.example.com', 'javascript:alert(1)', 'https://u:p@ntfy.sh', 'https://ntfy.sh/?x=1'):
            with self.assertRaises(ValueError):
                v.normalize_server(bad)
        self.assertEqual(v.normalize_server('http://localhost:8080/'), 'http://localhost:8080')

    def test_error_does_not_echo_secret(self):
        try:
            v.parse_pairing('k=AAAA-secret-looking-value')
        except ValueError as e:
            self.assertNotIn('secret-looking', str(e))


class TypingTest(unittest.TestCase):
    def test_flatten_removes_line_breaks_and_controls(self):
        self.assertEqual(v.flatten_for_typing('a\nb\r\nc\rd\u2028e\u0085f'), 'a b c d e f')
        self.assertEqual(v.flatten_for_typing('rm -rf ~\n'), 'rm -rf ~')
        self.assertEqual(v.flatten_for_typing('x\x1b[31my\x07\tz'), 'x[31my\tz')
        self.assertNotIn('\n', v.flatten_for_typing('\n\n\n'))

    def test_terminal_hints(self):
        for cls in ['"gnome-terminal-server", "Gnome-terminal"', '"xterm", "XTerm"', '"kitty", "kitty"',
                    '"org.gnome.Console", "Kgx"', '"Alacritty", "Alacritty"', '"konsole", "konsole"']:
            self.assertTrue(any(h in cls.lower() for h in v.TERMINAL_CLASS_HINTS), cls)
        for cls in ['"gedit", "Gedit"', '"google-chrome", "Google-chrome"', '"code", "Code"', '"slack", "Slack"']:
            self.assertFalse(any(h in cls.lower() for h in v.TERMINAL_CLASS_HINTS), cls)

    def _paste_with(self, wm_class):
        sent = []
        saved = (v.typing_unavailable_reason, v._screen_locked, v._focused_window_class, v._run)
        try:
            v.typing_unavailable_reason = lambda: None
            v._screen_locked = lambda: False
            v._focused_window_class = lambda: wm_class
            v._run = lambda cmd, timeout=3: sent.append(cmd) or ''
            return v.paste_into_focused(True), sent
        finally:
            v.typing_unavailable_reason, v._screen_locked, v._focused_window_class, v._run = saved

    def test_paste_key_by_window(self):
        result, sent = self._paste_with('"gedit", "gedit"')
        self.assertEqual(result, '入力しました')
        self.assertEqual(sent, [['xdotool', 'key', '--clearmodifiers', 'ctrl+v']])
        result, sent = self._paste_with('"gnome-terminal-server", "gnome-terminal-server"')
        self.assertIn('端末に入力しました', result)
        self.assertEqual(sent, [['xdotool', 'key', '--clearmodifiers', 'ctrl+shift+v']])
        for cls in ['"xterm", "XTerm"', '"urxvt", "URxvt"']:
            result, sent = self._paste_with(cls)
            self.assertIn('コピーだけ', result)
            self.assertEqual(sent, [])
        result, sent = self._paste_with(None)
        self.assertIn('判定できなかった', result)
        self.assertEqual(sent, [])

    def test_flatten_blocks_bracketed_paste_escape(self):
        # 貼り付けの終わりを装う ESC[201~ や C1 の CSI（0x9b）は取り除かれる
        out = v.flatten_for_typing('safe\x1b[201~rm -rf ~\n\x9b201~')
        self.assertNotIn('\x1b', out)
        self.assertNotIn('\x9b', out)
        self.assertNotIn('\n', out)

    def test_unavailable_on_wayland(self):
        old = dict(os.environ)
        try:
            os.environ['XDG_SESSION_TYPE'] = 'wayland'
            self.assertIn('X11', v.typing_unavailable_reason())
            self.assertIn('入力しませんでした', v.paste_into_focused(True))
            self.assertIn('コピーできなかった', v.paste_into_focused(False))
        finally:
            os.environ.clear()
            os.environ.update(old)


class VersionTest(unittest.TestCase):
    def test_version_tuple(self):
        self.assertEqual(v._version_tuple('50.0.2'), (50, 0, 2))
        self.assertEqual(v._version_tuple('3.4.8'), (3, 4, 8))
        self.assertEqual(v._version_tuple('51.0'), (51, 0, 0))
        self.assertEqual(v._version_tuple('50.0.3rc1'), (50, 0, 3))
        self.assertLess(v._version_tuple('46.0.5'), v.RECOMMENDED_CRYPTOGRAPHY)


class RevealTest(unittest.TestCase):
    def test_plain_kept(self):
        s = 'こんにちは\n\tHello \U0001F468‍\U0001F469 ❤️'
        self.assertEqual(v.reveal_hidden(s), (s, 0))

    def test_hidden_revealed(self):
        shown, n = v.reveal_hidden('a\x1b[31m‮⁦​﻿­\U000E0041ㅤ \r')
        self.assertEqual(n, 10)
        self.assertNotIn('\x1b', shown)
        self.assertIn('⟦U+202E⟧', shown)
        self.assertIn('⟦U+E0041⟧', shown)

    def test_same_as_js_rules(self):
        """js/text.js と同じ文字を置き換えることを、代表的な文字で確かめる。"""
        for ch in ['͏', 'ᅟ', 'ᅠ', '⠀', 'ﾠ', '︀', '\U000E0100', '\U000F0000', '\ud800']:
            self.assertEqual(v.reveal_hidden('x' + ch)[1], 1, hex(ord(ch)))


if __name__ == '__main__':
    unittest.main()
