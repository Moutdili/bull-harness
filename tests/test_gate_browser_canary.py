"""bh-browser at the gate (B2, I2, I6), the canaries (I1), the host's session probe, origin_headers (I19) and the real
close of a connection (I18). No network, mitmproxy simulated; every address table is pinned (no DNS lookup)."""

import asyncio
import gzip
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

AGENT_IP, JUDGE_IP, LOGIN_IP, BROWSER_IP, OTHER_IP = "10.89.0.5", "10.89.0.6", "10.89.0.7", "10.89.0.9", "10.89.0.99"
TOKEN = "BH-SECRET-0123456789abcdef"
SCOPE = {
    "schema": 1,
    "program": "t",
    "platform": "test",
    "in_scope": ["app.example.com", "api.example.com"],
    "max_rps": 1000,
    "websockets": True,
    "browser_only": ["https://app.example.com/chathub/"],
    "identities": [{"name": "user-a", "origins": ["https://app.example.com/"]}],
    "support": [{"value": "challenges.example.net", "kind": "passthrough"}],
}
EVENT_KEYS = {"kind", "token", "where", "host", "url", "identity", "client", "run", "ts", "program"}


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
    later = time.time() + 3600  # a cache "fresh" for an hour: never a real lookup
    monkeypatch.setattr(mod, "_LOGIN_IPS", (later, frozenset({LOGIN_IP})))
    monkeypatch.setattr(mod, "_BROWSER_IPS", (later, frozenset({BROWSER_IP})))
    monkeypatch.setattr(mod, "_RELAY_IPS", (later, {"agent": frozenset({AGENT_IP}), "judge": frozenset({JUDGE_IP})}))
    monkeypatch.setattr(mod, "ctx", SimpleNamespace(options=SimpleNamespace(), log=mock.MagicMock()))
    yield mod
    sys.modules.pop("bh.gate.addon", None)


class Headers:
    """The part of mitmproxy's Headers the gate uses: case-insensitive, multi-valued."""

    def __init__(self, items=()):
        self.items_ = list(items)

    def __contains__(self, k):
        return any(a.lower() == k.lower() for a, _ in self.items_)

    def __getitem__(self, k):
        return next(v for a, v in self.items_ if a.lower() == k.lower())

    def __setitem__(self, k, v):
        self.items_ = [(a, b) for a, b in self.items_ if a.lower() != k.lower()] + [(k, v)]

    def get(self, k, default=None):
        return next((v for a, v in self.items_ if a.lower() == k.lower()), default)

    def get_all(self, k):
        return [v for a, v in self.items_ if a.lower() == k.lower()]

    def set_all(self, k, values):
        self.items_ = [(a, b) for a, b in self.items_ if a.lower() != k.lower()] + [(k, v) for v in values]

    def pop(self, k, default=None):
        if k not in self:
            return default
        v = self[k]
        self.items_ = [(a, b) for a, b in self.items_ if a.lower() != k.lower()]
        return v

    def keys(self):
        return [a for a, _ in self.items_]

    def items(self, multi=False):
        return list(self.items_)


def _gate(addon, tmp_path, scope=None):
    p = tmp_path / "active-scope.yaml"
    p.write_text(yaml.safe_dump(scope or SCOPE))
    pol_ = pol.Policy(p)
    pol_.reload()
    ident = tmp_path / paths.IDENTITIES / "t"
    ident.mkdir(parents=True, exist_ok=True)
    cookie = {"path": "/", "expires": None, "host_only": True, "secure": True}
    (ident / "user-a.json").write_text(
        json.dumps(
            {
                "headers": {"Authorization": "Bearer DEFAULT-TOKEN"},
                "origin_headers": {"https://api.example.com:443": {"Authorization": "Bearer API-AUDIENCE"}},
                "cookies": {"app.example.com": {"sid": {"value": "jar-cookie", **cookie}}},
            }
        )
    )
    g = addon.Gate()
    g.state, g.policy = tmp_path, pol_
    g._is_relay = lambda flow: False
    return g


def _http(url, method="GET", headers=(), body=b"", *, peer=AGENT_IP, fid="f1"):
    host = url.split("/")[2]
    path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
    request = SimpleNamespace(
        method=method,
        path=path,
        host=host,
        headers=Headers(headers),
        authority="",
        is_http2=False,
        is_http3=False,
        host_header=None,
        raw_content=body,
    )
    return SimpleNamespace(
        id=fid,
        request=request,
        response=None,
        metadata={"bh_dest": (url, host)},
        client_conn=SimpleNamespace(id=f"c-{fid}", peername=(peer, 40000)),
        websocket=None,
    )


def _answer(flow, status=200, headers=(), body=b"ok"):
    flow.response = SimpleNamespace(status_code=status, headers=Headers(headers), raw_content=body)


def _events(tmp_path, kind=None):
    p = tmp_path / paths.EVENTS
    ev = [json.loads(line) for line in p.read_text().splitlines()] if p.exists() else []
    return [e for e in ev if kind is None or e["kind"] == kind]


def _flows(tmp_path):
    p = tmp_path / paths.FLOWS
    return [json.loads(line) for line in p.read_text().splitlines()] if p.exists() else []


def _last_refusal(tmp_path):
    return _events(tmp_path, "blocked")[-1]


def _load_browser(tmp_path, identity="user-a", program="t"):
    p = tmp_path / addon_const()
    p.write_text(json.dumps({"program": program, "identity": identity, "loaded_at": 1}))
    _BUMP[0] += 1
    os.utime(p, (_BUMP[0], _BUMP[0]))  # a new mtime on every write: the gate reloads on mtime


_BUMP = [1_000_000]


def addon_const():
    return sys.modules["bh.gate.addon"].BROWSER_IDENTITY


def run(g, flow):
    asyncio.run(g.request(flow))
    return flow


# ------------------------------------------------------------------ B2: browser only
def test_a_websocket_handshake_is_the_browsers_alone(addon, tmp_path):
    g = _gate(addon, tmp_path)
    ws = [("Upgrade", "websocket"), ("Connection", "Upgrade")]
    for peer in (AGENT_IP, JUDGE_IP):
        f = run(g, _http("https://app.example.com/socket", headers=ws, peer=peer))
        assert f.metadata.get("bh_denied") and _last_refusal(tmp_path)["reason"].startswith("browser only")
    assert {e["rule"] for e in _events(tmp_path, "blocked")} == {"browser-only"}
    f = run(g, _http("https://app.example.com/socket", headers=ws, peer=BROWSER_IP))
    assert not f.metadata.get("bh_denied") and f.metadata["bh_ws"] and f.metadata["bh_browser"]


def test_a_browser_only_path_is_refused_to_everyone_but_the_browser(addon, tmp_path):
    g = _gate(addon, tmp_path)
    for peer in (AGENT_IP, JUDGE_IP, LOGIN_IP, "127.0.0.1"):
        for url in ("https://app.example.com/chathub/x", "https://app.example.com/ChatHub/negotiate?id=1"):
            f = run(g, _http(url, "POST", body=b"{}", peer=peer))
            assert f.metadata.get("bh_denied") and "browser only" in _last_refusal(tmp_path)["reason"], (peer, url)
    assert all(e["reason"].startswith("browser only") for e in _events(tmp_path, "blocked"))
    assert not run(g, _http("https://app.example.com/chathub/x", "POST", body=b"{}", peer=BROWSER_IP)).metadata.get(
        "bh_denied"
    )
    assert not run(g, _http("https://app.example.com/other", peer=AGENT_IP)).metadata.get("bh_denied")


# ------------------------------------------------------------------ I2: the browser's identity
def test_browser_traffic_carries_the_identity_the_host_loaded(addon, tmp_path):
    g = _gate(addon, tmp_path)
    f = run(g, _http("https://app.example.com/a", peer=BROWSER_IP))
    assert f.metadata["bh_identity"] is None  # no file: no identity
    _load_browser(tmp_path)
    page = [(IDENTITY_HEADER, "someone-else"), ("Cookie", "browser=own")]
    f = run(g, _http("https://app.example.com/a", headers=page, peer=BROWSER_IP))
    assert f.metadata["bh_identity"] == "user-a"  # the host's label, never the page's header
    h = f.request.headers
    assert IDENTITY_HEADER not in h and h["Cookie"] == "browser=own" and "Authorization" not in h  # nothing injected
    _answer(f)
    g.response(f)
    (rec,) = _flows(tmp_path)
    assert rec["identity"] == "user-a" and rec["class"] == "target"
    for program, identity in (("other", "user-a"), ("t", "ghost"), ("t", None), ("t", "../x")):
        _load_browser(tmp_path, identity, program)
        f = run(g, _http("https://app.example.com/a", peer=BROWSER_IP))
        assert f.metadata["bh_identity"] is None, (program, identity)
    (tmp_path / addon_const()).write_text("{not json")
    assert run(g, _http("https://app.example.com/a", peer=BROWSER_IP)).metadata["bh_identity"] is None


def test_an_agents_page_header_never_labels_the_browser_and_the_agent_keeps_its_own(addon, tmp_path):
    g = _gate(addon, tmp_path)
    _load_browser(tmp_path)
    f = run(g, _http("https://app.example.com/a", peer=AGENT_IP))
    assert f.metadata["bh_identity"] is None  # the browser's file labels the browser only


@pytest.mark.parametrize("method", ["DELETE", "PUT", "PATCH"])
def test_identity_only_methods_for_the_browser_under_its_identity_not_for_the_agent(addon, tmp_path, method):
    g = _gate(addon, tmp_path)
    f = run(g, _http("https://app.example.com/item/1", method, peer=BROWSER_IP))
    assert f.metadata.get("bh_denied")  # no identity loaded yet
    _load_browser(tmp_path)
    assert not run(g, _http("https://app.example.com/item/1", method, peer=BROWSER_IP)).metadata.get("bh_denied")
    f = run(g, _http("https://app.example.com/item/1", method, peer=AGENT_IP))
    assert f.metadata.get("bh_denied") and "X-BH-Identity" in _last_refusal(tmp_path)["reason"]


def test_browser_set_cookie_reaches_it_unmasked_and_goes_to_the_jar(addon, tmp_path):
    g = _gate(addon, tmp_path)
    _load_browser(tmp_path)
    f = run(g, _http("https://app.example.com/a", peer=BROWSER_IP))
    _answer(f, headers=[("Set-Cookie", "sid=rotated; Path=/; Secure")])
    g.response(f)
    assert f.response.headers.get_all("set-cookie") == ["sid=rotated; Path=/; Secure"]
    jar = json.loads((tmp_path / paths.IDENTITIES / "t" / "user-a.json").read_text())["cookies"]
    assert jar["app.example.com"]["sid"]["value"] == "rotated"
    # the agent under the same identity gets it masked, as before
    f = run(g, _http("https://app.example.com/a", headers=[(IDENTITY_HEADER, "user-a")], peer=AGENT_IP))
    _answer(f, headers=[("Set-Cookie", "sid=again; Path=/")])
    g.response(f)
    assert f.response.headers.get_all("set-cookie") == ["sid=<identity:user-a>; Path=/"]


def test_the_browser_is_never_paused_by_the_waf_guard(addon, tmp_path):
    g = _gate(addon, tmp_path)
    for _ in range(pol.WAF_LIMIT + 2):
        f = run(g, _http("https://app.example.com/a", peer=BROWSER_IP))
        _answer(f, 403, [("cf-mitigated", "challenge")])
        g.response(f)
    assert len(_events(tmp_path, "waf")) == pol.WAF_LIMIT + 2
    assert not run(g, _http("https://app.example.com/a", peer=AGENT_IP)).metadata.get("bh_denied")


# ------------------------------------------------------------------ I1: canaries
def _canary(tmp_path):
    ev = _events(tmp_path, "canary")
    assert all(set(e) == EVENT_KEYS for e in ev), ev
    return ev


def test_canary_in_the_url(addon, tmp_path):
    g = _gate(addon, tmp_path)
    run(g, _http(f"https://app.example.com/x?q={TOKEN.lower()}&token=hunter2", peer=AGENT_IP))
    (ev,) = _canary(tmp_path)
    assert (ev["token"], ev["where"], ev["host"], ev["client"]) == (TOKEN, "request-url", "app.example.com", "agent")
    assert ev["program"] == "t" and ev["identity"] is None and "hunter2" not in ev["url"]


def test_canary_in_a_gzip_request_body_from_the_browser(addon, tmp_path):
    g = _gate(addon, tmp_path)
    _load_browser(tmp_path)
    body = gzip.compress(b'{"msg": "padding ' + b"x" * 5000 + TOKEN.encode() + b'"}')
    assert TOKEN.encode() not in body
    run(g, _http("https://app.example.com/send", "POST", [("Content-Encoding", "gzip")], body, peer=BROWSER_IP))
    (ev,) = _canary(tmp_path)
    assert (ev["where"], ev["client"], ev["identity"]) == ("request-body", "browser", "user-a")
    assert "padding" not in json.dumps(ev)  # nothing around the token


def test_canary_in_a_response_body(addon, tmp_path):
    g = _gate(addon, tmp_path)
    f = run(g, _http("https://api.example.com/v1/me", headers=[(IDENTITY_HEADER, "user-a")], peer=JUDGE_IP))
    _answer(f, body=gzip.compress(f"name={TOKEN}; other=BH-SECRET-fedcba9876543210".encode()))
    f.response.headers["Content-Encoding"] = "gzip"
    g.response(f)
    ev = _canary(tmp_path)
    assert [e["token"] for e in ev] == [TOKEN, "BH-SECRET-fedcba9876543210"]
    assert {(e["where"], e["client"], e["identity"], e["host"]) for e in ev} == {
        ("response-body", "judge", "user-a", "api.example.com")
    }


def test_canary_in_the_websocket_frames_both_ways(addon, tmp_path):
    g = _gate(addon, tmp_path)
    f = _ws(g, tmp_path)
    _frame(g, f, f"say {TOKEN}".encode())
    _frame(g, f, f'{{"text": "{TOKEN}"}}'.encode(), from_client=False)
    ev = _canary(tmp_path)
    assert [(e["where"], e["client"]) for e in ev] == [("ws-client", "browser"), ("ws-server", "browser")]
    assert all(e["identity"] == "user-a" and e["url"] == "https://app.example.com/chathub/" for e in ev)


def test_canary_clients_and_no_hit_no_event(addon, tmp_path):
    g = _gate(addon, tmp_path)
    run(g, _http("https://app.example.com/x?a=BH-SECRET-0123", peer=OTHER_IP))  # too short: no token
    assert _canary(tmp_path) == []
    run(g, _http(f"https://app.example.com/x?a={TOKEN}", peer=OTHER_IP))
    run(g, _http(f"https://app.example.com/x?a={TOKEN}", peer=LOGIN_IP))
    run(g, _http(f"https://app.example.com/x?a={TOKEN}", peer="127.0.0.1"))
    assert [e["client"] for e in _canary(tmp_path)] == ["other", "login", "login"]


# ------------------------------------------------------------------ the host's session probe
PROBE = [(IDENTITY_HEADER, "user-a"), ("X-BH-Probe", "1")]


def test_the_probe_from_the_gates_loopback_borrows_the_identity(addon, tmp_path):
    g = _gate(addon, tmp_path)
    f = run(g, _http("https://app.example.com/me", headers=PROBE, peer="127.0.0.1"))
    assert f.metadata["bh_identity"] == "user-a"
    h = f.request.headers
    assert h["Authorization"] == "Bearer DEFAULT-TOKEN" and "sid=jar-cookie" in h["Cookie"]
    assert "X-BH-Probe" not in h and IDENTITY_HEADER not in h


@pytest.mark.parametrize(
    "peer, headers",
    [
        (LOGIN_IP, PROBE),  # bh-login is an enrollment source, never the probe
        ("127.0.0.1", [(IDENTITY_HEADER, "user-a")]),  # enrollment without the marker
        ("127.0.0.1", [(IDENTITY_HEADER, "user-a"), ("X-BH-Probe", "yes")]),
    ],
)
def test_enrollment_never_borrows_a_session_without_the_loopback_probe(addon, tmp_path, peer, headers):
    g = _gate(addon, tmp_path)
    f = run(g, _http("https://app.example.com/me", headers=headers, peer=peer))
    h = f.request.headers
    assert f.metadata["bh_identity"] is None and "Authorization" not in h and "Cookie" not in h
    assert "X-BH-Probe" not in h and IDENTITY_HEADER not in h


@pytest.mark.parametrize("peer", [AGENT_IP, BROWSER_IP])
def test_the_probe_marker_means_nothing_elsewhere_and_never_leaves(addon, tmp_path, peer):
    g = _gate(addon, tmp_path)
    f = run(g, _http("https://app.example.com/me", headers=[("X-BH-Probe", "1")], peer=peer))
    assert f.metadata["bh_identity"] is None and "X-BH-Probe" not in f.request.headers
    f = run(g, _http("https://app.example.com/me", headers=[("x-bh-probe", "1")], peer=AGENT_IP))
    assert "X-BH-Probe" not in f.request.headers


# ------------------------------------------------------------------ I19: origin_headers
def test_origin_headers_go_to_their_exact_origin_only_and_are_never_journaled(addon, tmp_path):
    g = _gate(addon, tmp_path)
    who = [(IDENTITY_HEADER, "user-a")]
    api = run(g, _http("https://api.example.com/v1/me", headers=who))
    assert api.request.headers["Authorization"] == "Bearer API-AUDIENCE"  # not one of the identity's origins
    app = run(g, _http("https://app.example.com/me", headers=who, fid="f2"))
    assert app.request.headers["Authorization"] == "Bearer DEFAULT-TOKEN"  # its own origin: the default header
    plain = run(g, _http("http://api.example.com/v1/me", headers=who, fid="f3"))
    assert "Authorization" not in plain.request.headers  # another scheme is another origin
    for f in (api, app, plain):
        _answer(f, headers=[("Content-Type", "application/json")], body=b"{}")
        g.response(f)
    assert [r["identity"] for r in _flows(tmp_path)] == ["user-a"] * 3
    for p in tmp_path.rglob("*"):
        if p.is_file() and p.parent.name != "t":  # every journal and flow file, not the session itself
            text = p.read_text(errors="replace")
            assert "API-AUDIENCE" not in text and "DEFAULT-TOKEN" not in text and "jar-cookie" not in text, p


# ------------------------------------------------------------------ I18: closing a connection for real
class _Task:
    def __init__(self, done=False):
        self._done, self.cancelled = done, None

    def done(self):
        return self._done

    def cancel(self, msg=None):
        self.cancelled = msg


def _master(addon, connections):
    proxyserver = SimpleNamespace(connections=connections)
    addons = SimpleNamespace(get=lambda name: proxyserver if name == "proxyserver" else None)
    addon.ctx.master = SimpleNamespace(addons=addons)


def _handler(task):
    client = object()
    return SimpleNamespace(client=client, transports={client: SimpleNamespace(handler=task)})


def test_close_connection_cancels_the_client_reader_task(addon):
    task = _Task()
    _master(addon, {"c1": _handler(task)})
    flow = SimpleNamespace(client_conn=SimpleNamespace(id="c1"))
    assert addon.close_connection(flow) is True and task.cancelled == "bh-gate: closed"
    assert addon.close_connection(SimpleNamespace(client_conn=SimpleNamespace(id="gone"))) is False
    _master(addon, {"c1": _handler(_Task(done=True))})
    assert addon.close_connection(flow) is False
    _master(addon, {"c1": _handler(None)})
    assert addon.close_connection(flow) is False
    del addon.ctx.master  # internals missing: "not closed", never an exception
    assert addon.close_connection(flow) is False


# ------------------------------------------------------------------ websockets: one `blocked` per zombie
class _Msg:
    def __init__(self, content, from_client=True, is_text=True):
        self.content, self.from_client, self.is_text, self.dropped = content, from_client, is_text, False

    def drop(self):
        self.dropped = True


def _ws(g, tmp_path, peer=BROWSER_IP, fid="ws1"):
    _load_browser(tmp_path)
    f = run(g, _http("https://app.example.com/chathub/", headers=[("Upgrade", "websocket")], peer=peer, fid=fid))
    assert not f.metadata.get("bh_denied")
    killed = []
    f.kill = lambda: killed.append(True)
    f.killed = killed
    f.websocket = SimpleNamespace(messages=[], timestamp_end=None)
    g.websocket_start(f)
    return f


def _frame(g, f, content, from_client=True):
    m = _Msg(content, from_client)
    f.websocket.messages.append(m)
    g.websocket_message(f)
    return m


def test_a_zombie_websocket_gets_one_blocked_event_and_a_real_close(addon, tmp_path):
    g = _gate(addon, tmp_path)
    task = _Task()
    f = _ws(g, tmp_path)
    _master(addon, {f.client_conn.id: _handler(task)})
    assert g.policy.ws_live["ws1"].limits.max_seconds == g.policy.ws_limits_browser.max_seconds
    big = b"x" * (g.policy.ws_live["ws1"].limits.max_bytes + 1)
    assert _frame(g, f, big).dropped and f.killed and task.cancelled
    for i in range(5):  # the connection outlived the close: every frame dropped, no new event
        assert _frame(g, f, b"late", from_client=bool(i % 2)).dropped
    g._ws_expire(f)
    (ev,) = [e for e in _events(tmp_path, "blocked") if e["where"].startswith("websocket")]
    assert ev["closed"] is True and "bytes" in ev["reason"]


def test_a_websocket_that_cannot_be_closed_says_so(addon, tmp_path):
    g = _gate(addon, tmp_path)
    f = _ws(g, tmp_path)  # no ctx.master: the internals are missing
    g.policy.ws_live["ws1"].started -= 10_000
    g._ws_expire(f)
    _frame(g, f, b"after")
    (ev,) = _events(tmp_path, "blocked")
    assert ev["closed"] is False and ev["reason"] == "websocket time limit" and f.killed


# ------------------------------------------------------------------ bounds from the environment
def test_passthrough_guard_from_env():
    d = pol.PassthroughGuard.from_env({})
    assert (d.per_min, d.max_open, d.max_bytes, d.max_seconds) == (
        pol.PASSTHROUGH_PER_MIN,
        pol.PASSTHROUGH_OPEN,
        pol.PASSTHROUGH_MAX_BYTES,
        pol.PASSTHROUGH_MAX_SECONDS,
    )
    env = {
        "BH_PASSTHROUGH_PER_MIN": "7",
        "BH_PASSTHROUGH_OPEN": "1",
        "BH_PASSTHROUGH_MAX_BYTES": "1000",
        "BH_PASSTHROUGH_MAX_SECONDS": "30.5",
    }
    g = pol.PassthroughGuard.from_env(env)
    assert (g.per_min, g.max_open, g.max_bytes, g.max_seconds) == (7, 1, 1000, 30.5)
    bad = pol.PassthroughGuard.from_env({"BH_PASSTHROUGH_PER_MIN": "-1", "BH_PASSTHROUGH_OPEN": "x"})
    assert (bad.per_min, bad.max_open) == (pol.PASSTHROUGH_PER_MIN, pol.PASSTHROUGH_OPEN)  # never 0 nor negative


def test_ws_limits_from_env_for_the_browser():
    assert pol.WsLimits.from_env({}).max_seconds == pol.WsLimits().max_seconds
    b = pol.WsLimits.from_env({}, browser=True)
    assert b.max_seconds == pol.WS_BROWSER_MAX_SECONDS > pol.WsLimits().max_seconds
    assert (b.msgs_per_min, b.max_bytes, b.max_open) == (
        pol.WsLimits().msgs_per_min,
        pol.WsLimits().max_bytes,
        pol.WsLimits().max_open,
    )
    env = {"BH_WS_MAX_SECONDS": "90", "BH_WS_MSGS_PER_MIN": "3", "BH_WS_MAX_BYTES": "0"}
    for browser in (False, True):  # an explicit lifetime applies to both
        w = pol.WsLimits.from_env(env, browser=browser)
        assert (w.max_seconds, w.msgs_per_min, w.max_bytes) == (90.0, 3, pol.WsLimits().max_bytes)
