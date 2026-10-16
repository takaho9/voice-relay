#!/usr/bin/env python3
"""クリップボードを保持し続ける補助プロセス（voice_relay.py が xclip などがないときに使う）。

Ubuntu のデスクトップに標準で入っている PyGObject（GTK 3）を使う。
X11 のクリップボードは、書き込んだプロセスが生きている間だけ中身を提供する仕組みなので、
受信プロセスと同じだけ常駐し、標準入力から 1 行 1 件の JSON {"text": ...} を受け取って設定する。
テキストはコマンドライン引数では渡さない（ps で他のユーザーに見えるため）。
"""

import json
import os
import sys

# Wayland ではバックグラウンドのプロセスがクリップボードを設定できないので、XWayland 経由にする。
# GNOME（mutter）は X11 側のクリップボードを Wayland 側にも反映する。
os.environ['GDK_BACKEND'] = 'x11'

try:
    import gi
    gi.require_version('Gtk', '3.0')
    gi.require_version('Gdk', '3.0')
    from gi.repository import Gdk, GLib, Gtk
except (ImportError, ValueError):
    sys.exit(2)

if not Gtk.init_check(sys.argv)[0]:
    sys.exit(3)

clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
stdin = sys.stdin.buffer


def on_input(_fd, condition):
    line = stdin.readline()
    if not line:
        Gtk.main_quit()
        return False
    try:
        text = json.loads(line.decode('utf-8'))['text']
        if not isinstance(text, str):
            raise ValueError
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        sys.stdout.write('error\n')
        sys.stdout.flush()
        return True
    try:
        clipboard.set_text(text, -1)
        clipboard.store()
        reply = 'ok'
    except Exception:  # noqa: BLE001  1 件の失敗で補助プロセス全体が止まらないようにする
        reply = 'error'
    sys.stdout.write(reply + '\n')
    sys.stdout.flush()
    return True


GLib.io_add_watch(sys.stdin.fileno(), GLib.PRIORITY_DEFAULT, GLib.IO_IN | GLib.IO_HUP, on_input)
sys.stdout.write('ready\n')
sys.stdout.flush()
Gtk.main()
