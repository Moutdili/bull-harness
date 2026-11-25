"""The gate's websocket hooks (mitmproxy simulated): journal of client messages, bounds, fail-closed refusals."""

import importlib
import json
import os
import sys
import time
import types
from types import SimpleNamespace
from unittest import mock

import pytest

from bh import paths
from bh.gate import policy as pol


@pytest.fixture
def addon(monkeypatch):
    """bh.gate.addon without mitmproxy (only in the gate image): stub modules, umask restored after import."""
    for name in ("mitmproxy", "mitmproxy.net", "mitmproxy.net.http", "mitmproxy.net.http.url", "mitmproxy.proxy"):
        mod = types.ModuleType(name)
        mod.__getattr__ = lambda attr: mock.MagicMock(name=attr)
        monkeypatch.setitem(sys.modules, name, mod)
    monkeypatch.delitem(sys.modules, "bh.gate.addon", raising=False)
    old = os.umask(0o022)
    os.umask(old)
    try:
        mod = importlib.import_module("bh.gate.addon")
    finally:
        os.umask(old)
    monkeypatch.setattr(mod, "_LOGIN_IPS", (time.time(), frozenset()))
    yield mod
    sys.modules.pop("bh.gate.addon", None)


class _Msg:
    def __init__(self, content, *, from_client=True, is_text=True):
        self.content, self.from_client, self.is_text, self.dropped = content, from_client, is_text, False

    def drop(self):
        self.dropped = True


def _flow(klass="target", ws=True):
    killed = []
    url = "https://app.example.com/socket"
    flow = SimpleNamespace(
        id="ws1",
        metadata={"bh_class": klass, "bh_ws": ws, "bh_identity": "user-a", "bh_dest": (url, "app.example.com")},
        client_conn=SimpleNamespace(peername=("10.89.0.5", 40000)),
        websocket=SimpleNamespace(messages=[], timestamp_end=None),
        kill=lambda: killed.append(True),
    )
    return flow, killed


def _gate(addon, tmp_path, websockets=True):
    scope = tmp_path / "scope.yaml"
    doc = {"schema": 1, "program": "t", "platform": "test", "in_scope": ["app.example.com"], "websockets": websockets}
    scope.write_text(json.dumps(doc))
    g = addon.Gate()
    g.state = tmp_path
    g.policy = pol.Policy(scope, ws_limits=pol.WsLimits(msgs_per_min=2, max_bytes=50, max_seconds=60, max_open=1))
    return g


def _events(tmp_path):
    p = tmp_path / paths.EVENTS
    return [json.loads(line) for line in p.read_text().splitlines()] if p.exists() else []


def _send(g, f, m):
    f.websocket.messages.append(m)
    g.websocket_message(f)
    return m


def test_messages_are_journaled_bounded_and_the_connection_closed(addon, tmp_path):
    g = _gate(addon, tmp_path)
    f, killed = _flow()
    g.websocket_start(f)
    assert not killed and "ws1" in g.policy.ws_live
    sent = [
        _send(g, f, _Msg(b'{"password": "hunter2", "q": "hi"}')),
        _send(g, f, _Msg(b"\x00\x01", is_text=False)),
        _send(g, f, _Msg(b"x" * 500, from_client=False)),  # a server frame: not rated, more room
    ]
    assert not killed and not any(m.dropped for m in sent)
    assert _send(g, f, _Msg(b"one too many")).dropped and killed  # over 2 client messages a minute
    assert _send(g, f, _Msg(b"late", from_client=False)).dropped  # closed for good, both directions
    g.websocket_end(f)
    ev = _events(tmp_path)
    msgs = [e for e in ev if e["kind"] == "ws-message"]
    assert [m["from"] for m in msgs] == ["client", "client", "server"]  # both directions, redacted alike
    assert "hunter2" not in json.dumps(msgs) and msgs[1]["binary"] is True
    assert all(len(m["sha256"]) == 64 for m in msgs)
    assert [e for e in ev if e["kind"] == "blocked" and "per minute" in e["reason"]]
    (end,) = [e for e in ev if e["kind"] == "websocket" and e["phase"] == "end"]
    assert (end["client"], end["binary"], end["server"]) == (2, 1, 1) and end["closed"]
    assert not g.policy.ws_live


def test_an_oversized_client_message_is_dropped(addon, tmp_path):
    g = _gate(addon, tmp_path)
    f, killed = _flow()
    g.websocket_start(f)
    assert _send(g, f, _Msg(b"y" * 51)).dropped and killed


@pytest.mark.parametrize(("klass", "ws"), [("support", True), ("passive", True), ("target", False), ("deny", True)])
def test_a_websocket_the_handshake_did_not_open_is_killed(addon, tmp_path, klass, ws):
    g = _gate(addon, tmp_path)
    f, killed = _flow(klass=klass, ws=ws)
    g.websocket_start(f)
    assert killed and not g.policy.ws_live


def test_frames_of_an_unknown_connection_and_a_scope_without_websockets(addon, tmp_path):
    g = _gate(addon, tmp_path)
    f, killed = _flow()
    assert _send(g, f, _Msg(b"hello")).dropped and killed
    g = _gate(addon, tmp_path, websockets=False)
    f, killed = _flow()
    g.websocket_start(f)
    assert killed
