"""`sso` and `passthrough` support hosts at the gate (no network, mitmproxy simulated).

sso: the application's own silent sign-in. GET/HEAD from anyone, POST only on the scope's token_paths, the identity's
jar cookies for that host and nothing else of ours. passthrough: an anti-bot challenge, CONNECT 443 only, never
intercepted (mitmproxy ignore_hosts + show_ignored_hosts), bounded, journaled as host + bytes + duration.
"""

import asyncio
import importlib
import json
import os
import sys
import time
import types
from types import SimpleNamespace
from unittest import mock

import pytest
import yaml

from bh import paths
from bh.agent.contract import IDENTITY_HEADER
from bh.gate import policy as pol
from bh.gate.policy import PassthroughGuard, Policy

SCOPE = {
    "schema": 1,
    "program": "t",
    "platform": "test",
    "in_scope": ["app.example.com"],
    "required_headers": {"X-Program": "bb"},
    "user_agent": "bh-ua",
    "identities": [{"name": "user-a", "origins": ["https://app.example.com/"]}],
    "support": [
        {"value": "login.example.org", "kind": "sso", "token_paths": ["/*/oauth2/v2.0/token", "/token.srf"]},
        {"value": "challenges.example.net", "kind": "passthrough"},
        {"value": "cdn.example.net", "kind": "assets"},
        {"value": "signin.example.org", "kind": "auth"},
    ],
}
TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad"


def _policy(tmp_path) -> Policy:
    p = tmp_path / "active-scope.yaml"
    p.write_text(yaml.safe_dump(SCOPE))
    return Policy(p)


def req(p, url, method="GET", **kw):
    return p.classify_request(url, url.split("/")[2], method, **kw)


# ------------------------------------------------------------------ policy: sso
@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_sso_get_and_head_from_any_client(tmp_path, method):
    v = req(_policy(tmp_path), f"https://login.example.org/{TENANT}/oauth2/v2.0/authorize?prompt=none", method)
    assert v.allowed and v.klass == "support" and v.support == "sso"


def test_sso_post_only_on_a_token_path(tmp_path):
    p = _policy(tmp_path)
    ok = req(p, f"https://login.example.org/{TENANT}/oauth2/v2.0/token", "POST", body_len=300, identity="user-a")
    assert ok.allowed and ok.support == "sso"
    assert req(p, "https://login.example.org/token.srf", "POST", body_len=10).allowed
    for url in (
        f"https://login.example.org/{TENANT}/oauth2/v2.0/authorize",  # the login form, not the exchange
        "https://login.example.org/savedusers",
        f"https://login.example.org/{TENANT}/oauth2/v2.0/token/extra",
        f"https://login.example.org/{TENANT}/x/../oauth2/v2.0/token",  # a dotted path never matches
        "https://login.example.org/../oauth2/v2.0/token",
        f"https://login.example.org/{TENANT}%2Foauth2/v2.0/token",
        "https://login.example.org//oauth2/v2.0/token",  # an empty segment is no tenant
        "https://login.example.org/a/b/oauth2/v2.0/token",  # `*` is one segment, not several
    ):
        v = req(p, url, "POST", body_len=10)
        assert not v.allowed and "token_paths" in v.reason, url


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "OPTIONS"])
def test_sso_refuses_other_methods_and_bodies(tmp_path, method):
    p = _policy(tmp_path)
    assert not req(p, f"https://login.example.org/{TENANT}/oauth2/v2.0/token", method).allowed
    assert not req(p, "https://login.example.org/x", "GET", body_len=5).allowed


def test_sso_enrollment_keeps_the_login_methods(tmp_path):
    p = _policy(tmp_path)
    assert req(p, "https://login.example.org/ppsecure/post.srf", "POST", body_len=50, enroll=True).allowed
    assert not req(p, "https://login.example.org/x", "DELETE", enroll=True).allowed


def test_sso_connect_and_resolution(tmp_path):
    p = _policy(tmp_path)
    assert p.classify_connect("login.example.org", 443).support == "sso"
    assert not p.classify_connect("login.example.org", 8443).allowed
    assert p.check_ip("login.example.org", "93.184.216.34").allowed
    assert not p.check_ip("login.example.org", "192.168.1.1").allowed
    assert not req(p, "https://login.example.org/x", host_header="app.example.com").allowed
    # the `auth` kind is unchanged: enrollment only
    assert not p.classify_connect("signin.example.org", 443).allowed
    assert p.classify_connect("signin.example.org", 443, enroll=True).allowed


# ------------------------------------------------------------------ policy: passthrough
def test_passthrough_connect_443_only_and_never_decrypted(tmp_path):
    p = _policy(tmp_path)
    v = p.classify_connect("challenges.example.net", 443)
    assert v.allowed and v.klass == "support" and v.support == "passthrough"
    for port in (80, 8443):
        assert not p.classify_connect("challenges.example.net", port).allowed
    # a request the gate can read means the tunnel was intercepted, or it is plain HTTP: refused either way
    for url in ("https://challenges.example.net/turnstile/v0/api.js", "http://challenges.example.net/"):
        for enroll in (False, True):
            d = req(p, url, enroll=enroll)
            assert not d.allowed and "never intercepted" in d.reason
    assert not req(p, "https://challenges.example.net/", websocket=True).allowed
    assert p.check_ip("challenges.example.net", "104.16.1.1").allowed
    assert not p.check_ip("challenges.example.net", "10.0.0.1").allowed


def test_passthrough_guard_bounds_rate_open_bytes_and_time():
    g = PassthroughGuard(per_min=3, max_open=2, max_bytes=100, max_seconds=10)
    assert g.open("a", "h", 0) is None and g.open("b", "h", 0) is None
    assert "already open" in g.open("c", "h", 0)
    assert g.data("a", 60, from_client=True, now=1) is None
    assert "bytes" in g.data("a", 41, from_client=False, now=1)
    assert g.data("a", 1, from_client=True, now=1)  # closed for good
    assert g.data("b", 1, from_client=True, now=11) and "s" in g.live["b"]["closed"]
    rec = g.end("a", 5)
    assert rec == {"host": "h", "bytes_up": 60, "bytes_down": 41, "seconds": 5, "closed": rec["closed"]}
    g.end("b", 12)
    assert g.open("c", "h", 30) is None
    assert "per minute" in g.open("d", "h", 30)  # 3 tunnels within the minute
    assert g.open("d", "h", 61) is None
    assert "not opened" in g.data("zzz", 1, from_client=True, now=61)


def test_a_redirect_to_a_passthrough_host_is_flagged(tmp_path):
    p = _policy(tmp_path)
    p.reload()
    assert p.passthrough_redirect("https://app.example.com/a", 302, "https://challenges.example.net/x")
    assert p.passthrough_redirect("https://app.example.com/a", 302, "//challenges.example.net/x")
    assert p.passthrough_redirect("https://app.example.com/a", 200, "https://challenges.example.net/x") is None
    assert p.passthrough_redirect("https://app.example.com/a", 302, "/next") is None
    assert p.passthrough_redirect("https://app.example.com/a", 302, "https://login.example.org/x") is None


# ------------------------------------------------------------------ the addon (mitmproxy simulated)
@pytest.fixture
def addon(monkeypatch):
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


class Headers:
    """The part of mitmproxy's Headers the gate uses: case-insensitive, multi-valued."""

    def __init__(self, items=()):
        self.items_ = [(k, v) for k, v in items]

    def _k(self, k):
        return k.lower()

    def __contains__(self, k):
        return any(self._k(a) == self._k(k) for a, _ in self.items_)

    def __getitem__(self, k):
        return next(v for a, v in self.items_ if self._k(a) == self._k(k))

    def __setitem__(self, k, v):
        self.items_ = [(a, b) for a, b in self.items_ if self._k(a) != self._k(k)] + [(k, v)]

    def get(self, k, default=None):
        return next((v for a, v in self.items_ if self._k(a) == self._k(k)), default)

    def get_all(self, k):
        return [v for a, v in self.items_ if self._k(a) == self._k(k)]

    def set_all(self, k, values):
        self.items_ = [(a, b) for a, b in self.items_ if self._k(a) != self._k(k)] + [(k, v) for v in values]

    def pop(self, k, default=None):
        if k not in self:
            return default
        v = self[k]
        self.items_ = [(a, b) for a, b in self.items_ if self._k(a) != self._k(k)]
        return v

    def keys(self):
        return [a for a, _ in self.items_]

    def items(self, multi=False):
        return list(self.items_)


class Options:
    def __init__(self):
        self.ignore_hosts, self.show_ignored_hosts, self.rawtcp = [], False, False

    def update(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


def _gate(addon, tmp_path, monkeypatch):
    p = _policy(tmp_path)
    p.reload()
    ident = tmp_path / paths.IDENTITIES / "t"
    ident.mkdir(parents=True)
    cookie = {"path": "/", "expires": None, "host_only": True, "secure": True}
    (ident / "user-a.json").write_text(
        json.dumps(
            {
                "headers": {"Authorization": "Bearer SECRET-TOKEN"},
                "cookies": {
                    "login.example.org": {"ESTSAUTH": {"value": "sso-cookie", **cookie}},
                    "app.example.com": {"sid": {"value": "app-cookie", **cookie}},
                },
            }
        )
    )
    g = addon.Gate()
    g.state, g.policy = tmp_path, p
    monkeypatch.setattr(g, "_is_relay", lambda flow: False)
    monkeypatch.setattr(addon, "ctx", SimpleNamespace(options=Options(), log=mock.MagicMock()))
    return g


def _http(url, method="GET", headers=(), body=b""):
    host = url.split("/")[2]
    path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
    request = SimpleNamespace(
        method=method,
        path=path,
        headers=Headers(headers),
        authority="",
        is_http2=False,
        is_http3=False,
        host_header=None,
        raw_content=body,
    )
    return SimpleNamespace(
        request=request,
        response=None,
        metadata={"bh_dest": (url, host)},
        client_conn=SimpleNamespace(peername=("10.89.0.5", 40000)),
    )


def _events(tmp_path):
    p = tmp_path / paths.EVENTS
    return [json.loads(line) for line in p.read_text().splitlines()] if p.exists() else []


def test_sso_get_under_an_identity_gets_its_cookies_and_nothing_else(addon, tmp_path, monkeypatch):
    g = _gate(addon, tmp_path, monkeypatch)
    f = _http(
        f"https://login.example.org/{TENANT}/oauth2/v2.0/authorize?prompt=none",
        headers=[(IDENTITY_HEADER, "user-a"), ("Cookie", "mine=1; ESTSAUTH=agent-value"), ("User-Agent", "chromium")],
    )
    asyncio.run(g.request(f))
    h = f.request.headers
    assert not f.metadata.get("bh_denied") and f.metadata["bh_support"] == "sso"
    assert IDENTITY_HEADER not in h  # never forwarded
    assert h["Cookie"] == "ESTSAUTH=sso-cookie; mine=1"  # the jar's value for this host wins, the agent's others pass
    assert "app-cookie" not in h["Cookie"]  # another host's cookie never travels here
    assert "Authorization" not in h and "X-Program" not in h and h["User-Agent"] == "chromium"


def test_sso_without_identity_passes_the_clients_own_cookies(addon, tmp_path, monkeypatch):
    g = _gate(addon, tmp_path, monkeypatch)
    f = _http("https://login.example.org/savedusers", headers=[("Cookie", "mine=1")])
    asyncio.run(g.request(f))
    assert not f.metadata.get("bh_denied") and f.request.headers["Cookie"] == "mine=1"
    assert "X-Program" not in f.request.headers


def test_sso_post_outside_the_token_paths_is_refused_on_one_is_allowed(addon, tmp_path, monkeypatch):
    g = _gate(addon, tmp_path, monkeypatch)
    who = [(IDENTITY_HEADER, "user-a")]
    bad = _http(f"https://login.example.org/{TENANT}/oauth2/v2.0/authorize", "POST", who, b"x=1")
    asyncio.run(g.request(bad))
    assert bad.metadata.get("bh_denied")
    assert any(e["kind"] == "blocked" and "token_paths" in e["reason"] for e in _events(tmp_path))
    ok = _http(f"https://login.example.org/{TENANT}/oauth2/v2.0/token", "POST", who, b"code=1")
    asyncio.run(g.request(ok))
    assert not ok.metadata.get("bh_denied") and "sso-cookie" in ok.request.headers["Cookie"]


def test_sso_set_cookie_rotates_the_jar_masked_and_is_journaled_as_support(addon, tmp_path, monkeypatch):
    g = _gate(addon, tmp_path, monkeypatch)
    f = _http("https://login.example.org/x", headers=[(IDENTITY_HEADER, "user-a")])
    asyncio.run(g.request(f))
    f.response = SimpleNamespace(
        status_code=200,
        headers=Headers([("Set-Cookie", "ESTSAUTH=rotated; Path=/; Secure")]),
        raw_content=b"ok",
    )
    g.response(f)
    assert f.response.headers.get_all("set-cookie") == ["ESTSAUTH=<identity:user-a>; Path=/; Secure"]
    jar = json.loads((tmp_path / paths.IDENTITIES / "t" / "user-a.json").read_text())["cookies"]
    assert jar["login.example.org"]["ESTSAUTH"]["value"] == "rotated"
    (rec,) = [json.loads(line) for line in (tmp_path / paths.FLOWS).read_text().splitlines()]
    assert rec["class"] == "support" and rec["support"] == "sso"
    assert not list(tmp_path.glob(f"{paths.FLOWS_DIR}/*.json"))  # never a full exchange: not a target, not a test


def test_a_target_redirect_to_a_passthrough_host_under_an_identity_is_refused(addon, tmp_path, monkeypatch):
    g = _gate(addon, tmp_path, monkeypatch)
    f = _http("https://app.example.com/start", headers=[(IDENTITY_HEADER, "user-a")])
    asyncio.run(g.request(f))
    assert "X-Program" in f.request.headers  # a target: program headers as usual
    f.response = SimpleNamespace(
        status_code=302, headers=Headers([("Location", "https://challenges.example.net/c")]), raw_content=b""
    )
    g.response(f)
    assert f.metadata.get("bh_denied")
    assert any(e.get("where") == "response" and "passthrough" in e["reason"] for e in _events(tmp_path))


def _connect(host, port=443, sid="s1"):
    return SimpleNamespace(
        request=SimpleNamespace(host=host, port=port, method="CONNECT", url=f"{host}:{port}"),
        response=None,
        metadata={},
        client_conn=SimpleNamespace(peername=("10.89.0.5", 40000)),
        server_conn=SimpleNamespace(id=sid, address=("104.16.1.1", port)),
    )


class _Tcp:
    def __init__(self, sid="s1"):
        self.server_conn = SimpleNamespace(id=sid, address=("104.16.1.1", 443))
        self.messages, self.metadata, self.killed = [], {}, False

    def kill(self):
        self.killed = True

    def send(self, g, content, from_client=True):
        msg = SimpleNamespace(content=content, from_client=from_client)
        self.messages.append(msg)
        g.tcp_message(self)
        return msg


HELLO = bytes([0x16, 0x03, 0x01, 0x00, 0x40, 0x01]) + b"\x00" * 64


def test_passthrough_connect_is_never_intercepted_and_only_counted(addon, tmp_path, monkeypatch):
    g = _gate(addon, tmp_path, monkeypatch)
    f = _connect("challenges.example.net")
    g.http_connect(f)
    assert not f.metadata.get("bh_denied") and g._tunnels == {"s1": "challenges.example.net"}
    opts = addon.ctx.options
    assert opts.ignore_hosts == [r"^challenges\.example\.net:443$"] and opts.show_ignored_hosts is True
    t = _Tcp()
    g.tcp_start(t)
    assert not t.killed
    first = t.send(g, HELLO)
    second = t.send(g, b"\x17\x03\x03" + b"s" * 100, from_client=False)
    assert first.content == HELLO and len(second.content) == 103  # relayed unchanged
    assert t.messages == [] and not t.killed  # the bytes are never kept
    g.server_disconnected(SimpleNamespace(server=SimpleNamespace(id="s1")))
    (ev,) = [e for e in _events(tmp_path) if e["kind"] == "passthrough"]
    assert set(ev) == {"kind", "host", "bytes_up", "bytes_down", "seconds", "ts", "program", "run"}
    assert (ev["host"], ev["bytes_up"], ev["bytes_down"]) == ("challenges.example.net", len(HELLO), 103)
    assert not g._tunnels and not g.policy.passthrough.live


def test_passthrough_on_another_port_or_in_clear_is_refused(addon, tmp_path, monkeypatch):
    g = _gate(addon, tmp_path, monkeypatch)
    for port in (80, 8443):
        f = _connect("challenges.example.net", port, sid=f"p{port}")
        g.http_connect(f)
        assert f.metadata.get("bh_denied") and not g._tunnels
    # plain HTTP inside the tunnel: the first bytes are no ClientHello, the tunnel is blackholed
    g.http_connect(_connect("challenges.example.net"))
    t = _Tcp()
    g.tcp_start(t)
    m = t.send(g, b"GET / HTTP/1.1\r\nHost: challenges.example.net\r\n\r\n")
    assert m.content == b"" and t.killed
    assert t.send(g, b"\x00" * 10, from_client=False).content == b""  # closed for good
    # a decrypted request to it (the tunnel was intercepted after all) is refused too
    r = _http("https://challenges.example.net/turnstile/v0/api.js")
    asyncio.run(g.request(r))
    assert r.metadata.get("bh_denied")


def test_raw_tcp_outside_a_registered_passthrough_stays_refused(addon, tmp_path, monkeypatch):
    """An SNI that names the passthrough host inside a CONNECT to something else is ignored by mitmproxy, but the
    tunnel was never registered: its bytes are dropped."""
    g = _gate(addon, tmp_path, monkeypatch)
    t = _Tcp(sid="other")
    g.tcp_start(t)
    assert t.killed
    assert t.send(g, HELLO).content == b""


def test_passthrough_tunnel_bytes_and_rate_bounds(addon, tmp_path, monkeypatch):
    g = _gate(addon, tmp_path, monkeypatch)
    g.policy.passthrough = PassthroughGuard(per_min=2, max_open=5, max_bytes=len(HELLO) + 10)
    g.http_connect(_connect("challenges.example.net", sid="a"))
    t = _Tcp(sid="a")
    g.tcp_start(t)
    t.send(g, HELLO)
    assert t.send(g, b"x" * 11, from_client=False).content == b"" and t.killed
    g.http_connect(_connect("challenges.example.net", sid="b"))
    f = _connect("challenges.example.net", sid="c")
    g.http_connect(f)
    assert f.metadata.get("bh_denied") and "c" not in g._tunnels  # 2 new tunnels a minute


def test_passthrough_patterns_are_anchored_exact_names(addon):
    assert addon.passthrough_patterns(["Challenges.Example.net.", "*.x.com", ""]) == [r"^challenges\.example\.net:443$"]
    assert addon.starts_like_tls_hello(HELLO) and not addon.starts_like_tls_hello(b"GET / HTTP/1.1")


def test_policy_module_bounds_are_positive():
    assert pol.PASSTHROUGH_PER_MIN > 0 and pol.PASSTHROUGH_OPEN > 0 and pol.PASSTHROUGH_MAX_BYTES > 0
