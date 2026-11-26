"""The UI's /captcha/ relay: nothing without the UI session, same-origin WebSocket only, bytes carried both ways;
the operator at the screen (human_viewing, audit I12); token rotation (audit B1). The tunnel is a local `cat` and
human_viewing a list: never a `podman exec`."""

import base64
import http.client
import io
import os
import socket
import subprocess
import threading
import time
from http.server import ThreadingHTTPServer

import pytest

from bh.ui import server, ws
from bh.ui.server import CAPTCHA_CSP, CSP, COOKIE, Handler, UIServer, new_session, rotate_token, token_path, ui_token

TOKEN = "ui-test-token"


@pytest.fixture
def ui(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.token = TOKEN
    srv.daemon_threads = True
    srv.tunnels = []
    srv.viewing_calls = []
    srv.human_viewing = srv.viewing_calls.append  # on -> list, never a real `podman exec`

    def open_tunnel():
        p = subprocess.Popen(["cat"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
        srv.tunnels.append(p)
        return p

    srv.open_tunnel = open_tunnel
    srv.novnc_files = lambda: {"core/rfb.js": b"export default class RFB {}"}
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def _get(srv, path, cookie=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
    h = dict(headers or {})
    if cookie:
        h["Cookie"] = f"{COOKIE}={cookie}"
    c.request("GET", path, headers=h)
    r = c.getresponse()
    return r.status, dict(r.getheaders()), r.read()


def _ws_headers(srv, origin=None):
    host = f"127.0.0.1:{srv.server_address[1]}"
    return {
        "Host": host,
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode(),
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Protocol": "binary",
        "Origin": origin or f"http://{host}",
    }


def test_captcha_pages_need_the_ui_session(ui):
    for path in ("/captcha/", "/captcha/captcha.js", "/captcha/novnc/core/rfb.js", "/captcha/ws", "/captcha"):
        code, _, body = _get(ui, path)
        assert code == 401 and b"secrets/ui.token" in body, path
    code, _, _ = _get(ui, "/captcha/ws", headers=_ws_headers(ui))
    assert code == 401 and ui.tunnels == []  # no tunnel was opened
    code, _, _ = _get(ui, "/captcha/", cookie="forged.cookie")
    assert code == 401
    c = http.client.HTTPConnection("127.0.0.1", ui.server_address[1], timeout=10)
    c.request("POST", "/api/captcha/done", body="{}", headers={"X-BH": "1"})
    assert c.getresponse().status == 403


def test_captcha_page_with_session(ui):
    s = new_session(TOKEN)
    code, h, body = _get(ui, "/captcha/", cookie=s)
    assert code == 200 and h["Content-Security-Policy"] == CAPTCHA_CSP and b"captcha.js" in body
    assert "unsafe-inline" not in CAPTCHA_CSP and "frame-ancestors 'none'" in CAPTCHA_CSP
    code, h, body = _get(ui, "/captcha/novnc/core/rfb.js", cookie=s)
    assert code == 200 and h["Content-Type"] == "text/javascript" and body.startswith(b"export")
    assert _get(ui, "/captcha/novnc/../../secrets/ui.token", cookie=s)[0] == 404
    assert _get(ui, "/captcha/novnc/app/ui.js", cookie=s)[0] == 404
    assert _get(ui, "/", cookie=s)[1]["Content-Security-Policy"] == CSP  # the rest of the UI is unchanged


def test_websocket_refuses_another_origin(ui):
    s = new_session(TOKEN)
    for origin in ("http://evil.example", "null", "http://127.0.0.1:1"):
        code, _, _ = _get(ui, "/captcha/ws", cookie=s, headers=_ws_headers(ui, origin))
        assert code == 403
    h = _ws_headers(ui)
    del h["Upgrade"]
    assert _get(ui, "/captcha/ws", cookie=s, headers=h)[0] == 400
    assert ui.tunnels == []


def _masked(op, payload):
    mask = os.urandom(4)
    n = len(payload)
    head = bytes([0x80 | op, 0x80 | n]) if n < 126 else bytes([0x80 | op, 0x80 | 126]) + n.to_bytes(2, "big")
    return head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


def _read_server_frame(f):
    b0, b1 = f.read(2)
    n = b1 & 0x7F
    if n == 126:
        n = int.from_bytes(f.read(2), "big")
    return b0 & 0x0F, f.read(n)


def _open_screen(srv, token=TOKEN):
    """A /captcha/ws connection past its 101: (socket, reader, response headers, request headers)."""
    sock = socket.create_connection(("127.0.0.1", srv.server_address[1]), timeout=10)
    h = _ws_headers(srv)
    h["Cookie"] = f"{COOKIE}={new_session(token)}"
    req = "GET /captcha/ws HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n"
    sock.sendall(req.encode())
    f = sock.makefile("rb")
    status = f.readline()
    assert b" 101 " in status
    head = {}
    while (line := f.readline()) not in (b"\r\n", b""):
        k, _, v = line.decode().partition(":")
        head[k.strip().lower()] = v.strip()
    return sock, f, head, h


def _close_screen(sock):
    sock.sendall(_masked(ws.OP_CLOSE, b"\x03\xe8"))
    sock.close()


def _until(cond, timeout=10.0):
    end = time.monotonic() + timeout
    while not cond():
        assert time.monotonic() < end, "timed out"
        time.sleep(0.01)


def test_websocket_relays_bytes_both_ways(ui):
    sock, f, head, h = _open_screen(ui)
    assert head["sec-websocket-accept"] == ws.accept_key(h["Sec-WebSocket-Key"])
    assert head["sec-websocket-protocol"] == "binary"
    sock.sendall(_masked(ws.OP_BIN, b"RFB 003.008\n"))
    got = b""
    while len(got) < 12:
        op, data = _read_server_frame(f)
        assert op == ws.OP_BIN
        got += data
    assert got == b"RFB 003.008\n"  # through the tunnel (cat) and back
    sock.sendall(_masked(ws.OP_PING, b"hi"))
    assert _read_server_frame(f) == (ws.OP_PONG, b"hi")
    sock.sendall(_masked(ws.OP_CLOSE, b"\x03\xe8"))
    sock.close()
    for p in ui.tunnels:
        p.wait(timeout=10)  # the tunnel dies with the screen


def test_ws_codec():
    assert ws.accept_key("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="  # RFC 6455 example
    assert ws.valid_key(base64.b64encode(b"x" * 16).decode()) and not ws.valid_key("short") and not ws.valid_key(None)
    big = os.urandom(70_000)
    frame = ws.encode_frame(ws.OP_BIN, big)
    assert frame[1] == 127 and frame.endswith(big)
    assert ws.read_frame(io.BytesIO(_masked(ws.OP_BIN, b"abc"))) == (ws.OP_BIN, b"abc")
    with pytest.raises(ValueError):
        ws.read_frame(io.BytesIO(bytes([0x82, 3]) + b"abc"))  # unmasked client frame
    assert ws.read_frame(io.BytesIO(b"")) is None


# ---------------------------------------------------------------- I12: the operator at the screen
def test_an_open_screen_tells_human_viewing_on_then_off_when_the_last_one_closes(ui):
    s1, *_ = _open_screen(ui)
    _until(lambda: ui.viewing_calls == [True])
    assert ui.viewers == 1
    s2, *_ = _open_screen(ui)
    _until(lambda: ui.viewers == 2)
    assert ui.viewing_calls == [True, True]
    _close_screen(s1)
    _until(lambda: ui.viewers == 1)
    assert False not in ui.viewing_calls  # another screen is still open: the agent stays read-only
    _close_screen(s2)
    _until(lambda: ui.viewers == 0 and ui.viewing_calls[-1] is False)
    assert ui.viewing_calls == [True, True, False]


def test_the_screen_re_asserts_human_viewing_while_open_and_stops_once_closed(ui, monkeypatch):
    assert server.VIEWING_REFRESH_S < 600  # under the controller's VIEWING_TTL_S
    monkeypatch.setattr(server, "VIEWING_REFRESH_S", 0.05)
    s, *_ = _open_screen(ui)
    _until(lambda: ui.viewing_calls.count(True) >= 3)  # opening + at least two refreshes
    _close_screen(s)
    _until(lambda: ui.viewing_calls[-1:] == [False])
    n = len(ui.viewing_calls)
    time.sleep(0.3)
    assert len(ui.viewing_calls) == n and ui.viewing_calls[-1] is False  # no late `on` after the `off`


def test_a_third_screen_is_refused_and_does_not_count(ui):
    opened = [_open_screen(ui)[0] for _ in range(server.CAPTCHA_TUNNELS)]
    _until(lambda: ui.viewers == server.CAPTCHA_TUNNELS)
    assert _get(ui, "/captcha/ws", cookie=new_session(TOKEN), headers=_ws_headers(ui))[0] == 429
    assert ui.viewers == server.CAPTCHA_TUNNELS and len(ui.tunnels) == server.CAPTCHA_TUNNELS
    for s in opened:
        _close_screen(s)
    _until(lambda: ui.viewers == 0 and ui.viewing_calls[-1] is False)


def test_a_controller_that_cannot_be_told_does_not_break_the_screen(ui):
    def boom(on):
        raise OSError("podman exec failed")

    ui.human_viewing = boom
    s, f, *_ = _open_screen(ui)
    s.sendall(_masked(ws.OP_BIN, b"ping"))
    assert _read_server_frame(f) == (ws.OP_BIN, b"ping")
    _close_screen(s)
    _until(lambda: ui.viewers == 0)


# ---------------------------------------------------------------- B1: token rotation
def test_rotate_token_replaces_the_file_0600(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    old = ui_token()
    assert len(old) >= 24 and token_path().stat().st_mode & 0o777 == 0o600
    rotate_token()
    new = ui_token()
    assert new != old and token_path().stat().st_mode & 0o777 == 0o600
    assert [p.name for p in token_path().parent.iterdir()] == ["ui.token"]  # no temporary file left behind


def _post_login(port, token):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("POST", "/login", body=f"token={token}", headers={"Content-Type": "application/x-www-form-urlencoded"})
    r = c.getresponse()
    r.read()
    return r.status, r.getheader("Set-Cookie") or ""


def test_rotation_reaches_the_running_ui_and_kills_old_sessions(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    srv = UIServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        old = ui_token()
        assert srv.token == old
        code, set_cookie = _post_login(port, old)
        assert code == 303 and set_cookie.startswith(f"{COOKIE}=")
        cookie = set_cookie.split(";", 1)[0].split("=", 1)[1]
        assert _get(srv, "/", cookie=cookie)[0] == 200
        rotate_token()
        new = ui_token()
        assert srv.token == new  # re-read without a restart
        assert _get(srv, "/", cookie=cookie)[0] == 401  # the old session is dead
        assert _get(srv, "/captcha/", cookie=cookie)[0] == 401
        assert _post_login(port, old)[0] == 403
        code, set_cookie = _post_login(port, new)
        assert code == 303
        assert _get(srv, "/", cookie=set_cookie.split(";", 1)[0].split("=", 1)[1])[0] == 200
    finally:
        srv.shutdown()
        srv.server_close()
