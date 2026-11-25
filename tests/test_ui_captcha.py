"""The UI's /captcha/ relay: nothing without the UI session, same-origin WebSocket only, bytes carried both ways.
The tunnel is a local `cat` (no podman)."""

import base64
import http.client
import io
import os
import socket
import subprocess
import threading
from http.server import ThreadingHTTPServer

import pytest

from bh.ui import ws
from bh.ui.server import CAPTCHA_CSP, CSP, COOKIE, Handler, new_session

TOKEN = "ui-test-token"


@pytest.fixture
def ui(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.token = TOKEN
    srv.daemon_threads = True
    srv.tunnels = []

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


def test_websocket_relays_bytes_both_ways(ui):
    sock = socket.create_connection(("127.0.0.1", ui.server_address[1]), timeout=10)
    h = _ws_headers(ui)
    h["Cookie"] = f"{COOKIE}={new_session(TOKEN)}"
    req = "GET /captcha/ws HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items()) + "\r\n"
    sock.sendall(req.encode())
    f = sock.makefile("rb")
    status = f.readline()
    assert b" 101 " in status
    head = {}
    while (line := f.readline()) not in (b"\r\n", b""):
        k, _, v = line.decode().partition(":")
        head[k.strip().lower()] = v.strip()
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
