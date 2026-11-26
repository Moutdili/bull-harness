"""W1-D: gate, scope and accounts (T5, D26, D27, R37, R1, R46, R14, R20, R22, R26, R43, R12, R28, R7).

No network: mitmproxy simulated (test_gate_browser_canary), the gate script either simulated (FakeGate) or run
against a proxy bound on this machine's loopback."""

import base64
import http.server
import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest
import yaml

from bh import paths, stack
from bh.accounts import enroll as en
from bh.accounts import secrets
from bh.agent.contract import IDENTITY_HEADER
from bh.gate import policy as pol
from bh.gate import session
from bh.scope import ScopeError, load_scope, scope_from_dict
from bh.scope.model import origin_covered
from test_accounts import RECIPE, FakeGate
import test_gate_browser_canary as gbc
from test_gate_browser_canary import (
    AGENT_IP,
    BROWSER_IP,
    JUDGE_IP,
    TOKEN,
    _answer,
    _events,
    _flows,
    _gate,
    _http,
    _load_browser,
    run,
)

addon = gbc.addon  # the simulated mitmproxy and the gate module, as in test_gate_browser_canary

ROOT = Path(__file__).resolve().parents[1]
COPILOT = ROOT / "scopes" / "msrc" / "copilot.yaml"
SUB = "https://sub.example.com"
SUB_ORIGIN = "https://sub.example.com:443"
W1 = {
    "schema": 1,
    "program": "t",
    "platform": "test",
    "in_scope": ["app.example.com", "api.example.com", f"{SUB}/hub/"],
    "max_rps": 1000,
    "websockets": True,
    "identities": [{"name": "user-a", "origins": ["https://app.example.com/", f"{SUB}/"]}],
    "support": [
        {"value": "login.example.net", "kind": "sso", "get_paths": ["/authorize"]},
        {"value": "cdn.example.net", "kind": "assets"},
    ],
    "payload_hosts": ["example.org"],
}


def _jwt(exp: float) -> str:
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    return f"{b64({'alg': 'RS256'})}.{b64({'exp': exp, 'aud': 'substrate'})}.c2lnbmF0dXJl"


LIVE = "Bearer " + _jwt(time.time() + 3600)
DEAD = "Bearer " + _jwt(time.time() - 60)


def _policy(tmp_path, doc=None):
    p = tmp_path / "active-scope.yaml"
    p.write_text(yaml.safe_dump(doc or W1))
    pol_ = pol.Policy(p)
    pol_.reload()
    assert pol_.scope is not None, pol_.scope_error
    return pol_


def _session_file(tmp_path):
    return tmp_path / paths.IDENTITIES / "t" / "user-a.json"


def _no_leak(tmp_path, *secret_values):
    """No journal, flow line nor flow file holds a secret value (the identity's own file excepted)."""
    for p in tmp_path.rglob("*"):
        if p.is_file() and p.parent.name != "t":
            text = p.read_text(errors="replace")
            for v in secret_values:
                assert v not in text, p


# ------------------------------------------------------------------ T5: protected URLs
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_logout_is_refused_to_every_client_whatever_the_method(addon, tmp_path, method):
    g = _gate(addon, tmp_path, W1)
    _load_browser(tmp_path)
    for i, peer in enumerate((AGENT_IP, JUDGE_IP, BROWSER_IP)):
        f = run(g, _http("https://app.example.com/logout", method, peer=peer, fid=f"p{i}"))
        assert f.metadata.get("bh_denied"), peer
    blocked = _events(tmp_path, "blocked")
    assert [e["reason"] for e in blocked] == ["protected url"] * 3  # journaled, one line each (not aggregated)
    assert [e["client"] for e in blocked] == ["agent", "judge", "browser"]


@pytest.mark.parametrize(
    "path",
    [
        "/logout",
        "/LogOut/",
        "/api/sign-out",
        "/x/signout?next=/",
        "/auth/log%6Fut",
        "/logout;jsessionid=1",
        "/account/reset-password",
        "/forgot_password",
        "/changePassword",
        "/me/delete-account",
        "/closeaccount",
        "/deactivate_account/confirm",
        "/checkout",
        "/billing/",
        "/api/payment/1",
        "/purchase",
        "/subscribe",
    ],
)
def test_protected_defaults_refuse(tmp_path, path):
    v = _policy(tmp_path).classify_request(f"https://app.example.com{path}", "app.example.com", "GET")
    assert not v.allowed and v.reason == "protected url", path


@pytest.mark.parametrize(
    "path",
    [
        "/chat",
        "/resources/app-shell-action",
        "/m365Copilot/Chathub/x",
        "/search/api/v1/prompts",
        "/common/oauth2/v2.0/authorize",
        "/search?q=logout",  # the query string is never looked at
        "/blog/how-to-logout-safely",
        "/subscriber/list",
    ],
)
def test_protected_defaults_never_bite_the_application_paths(path):
    assert pol.protected_rule(f"https://copilot.com{path}") is None, path


def test_protected_urls_of_the_scope_add_to_the_defaults_and_are_validated(tmp_path):
    p = _policy(tmp_path, {**W1, "protected_urls": [r"^/api/v\d+/danger"]})
    assert p.scope.protected_urls == (r"^/api/v\d+/danger",)
    v = p.classify_request("https://app.example.com/API/v2/danger/x", "app.example.com", "GET")
    assert not v.allowed and v.reason == "protected url"
    assert not p.classify_request("https://app.example.com/logout", "app.example.com", "GET").allowed
    with pytest.raises(ScopeError, match="not a valid regex"):
        scope_from_dict({**W1, "protected_urls": ["(unclosed"]})
    with pytest.raises(ScopeError, match="protected_urls"):
        scope_from_dict({**W1, "protected_urls": "logout"})


# ------------------------------------------------------------------ D26: six ids per route
def test_six_ids_pass_the_seventh_is_refused(tmp_path):
    assert (pol.ID_LIMIT, pol.ID_WINDOW_S) == (6, 600)
    p = _policy(tmp_path)
    url = "https://app.example.com/api/items/{}"
    for i in range(1, 7):
        assert p.classify_request(url.format(1000 + i), "app.example.com", "GET", authenticated=True).allowed, i
    v = p.classify_request(url.format(1007), "app.example.com", "GET", authenticated=True)
    assert not v.allowed and "id enumeration" in v.reason
    escape = (ROOT / "tests" / "escape" / "escape_check.sh").read_text()
    assert "seq 900001 900006" in escape and "Feedbacks/900007" in escape and "seq 900001 900012" not in escape


# ------------------------------------------------------------------ D27: payload hosts
def test_payload_hosts_are_validated():
    assert scope_from_dict({k: v for k, v in W1.items() if k != "payload_hosts"}).payload_hosts == []
    assert scope_from_dict({**W1, "payload_hosts": ["Example.ORG.", "bh.datk.ch"]}).payload_hosts == [
        "example.org",
        "bh.datk.ch",
    ]
    for bad in (
        "app.example.com",  # a target
        "x.app.example.com",  # a subdomain of a target
        "sub.example.com",  # the host of a URL rule
        "login.example.net",  # a support host
        "cdn.example.net",
        "x.sub.example.com",  # under the host of a URL rule
        "*.example.org",
        "https://example.org/",
        "example.org:8080",
        "203.0.113.7",
        "co.uk",
    ):
        with pytest.raises(ScopeError, match="payload_hosts"):
            scope_from_dict({**W1, "payload_hosts": [bad]})
    with pytest.raises(ScopeError, match="payload_hosts"):
        scope_from_dict({**W1, "out_of_scope": ["example.org"]})


def test_payload_policy_connect_methods_and_addresses(tmp_path):
    p = _policy(tmp_path)
    assert p.classify_connect("example.org", 443).klass == "payload"
    assert not p.classify_connect("example.org", 8443).allowed
    assert not p.classify_connect("example.net", 443).allowed  # not declared by this scope
    for m in ("GET", "HEAD", "OPTIONS"):
        assert p.classify_request("https://example.org/x", "example.org", m).klass == "payload"
    for m in ("POST", "PUT", "DELETE", "PATCH"):
        v = p.classify_request("https://example.org/x", "example.org", m)
        assert not v.allowed and v.reason == "payload host: GET/HEAD/OPTIONS only"
    assert not p.classify_request("https://example.org/x", "example.org", "GET", body_len=3).allowed
    assert not p.classify_request("https://example.org/x", "example.org", "GET", host_header="app.example.com").allowed
    assert p.check_ip("example.org", "93.184.215.14").allowed
    assert not p.check_ip("example.org", "10.0.0.5").allowed
    assert p.bucket("payload").rps == p.scope.rate


def test_payload_get_goes_without_cookie_nor_identity_and_post_is_refused(addon, tmp_path):
    g = _gate(addon, tmp_path, W1)
    _load_browser(tmp_path)
    ours = [(IDENTITY_HEADER, "user-a"), ("Cookie", "mine=1"), ("Authorization", "Bearer x")]
    for i, peer in enumerate((AGENT_IP, BROWSER_IP)):
        f = run(g, _http(f"https://example.org/img.png?c={TOKEN}", headers=ours, peer=peer, fid=f"g{i}"))
        h = f.request.headers
        assert not f.metadata.get("bh_denied") and f.metadata["bh_class"] == "payload"
        assert f.metadata["bh_identity"] is None
        assert "Cookie" not in h and "Authorization" not in h and IDENTITY_HEADER not in h
        _answer(f, headers=[("Access-Control-Allow-Origin", "*")])
        g.response(f)
    assert [r["class"] for r in _flows(tmp_path)] == ["payload", "payload"]
    assert not list((tmp_path / paths.FLOWS_DIR).glob("*.json"))  # never a target flow file
    assert len(_events(tmp_path, "canary")) == 2  # a canary in the URL is reported as anywhere else
    f = run(g, _http("https://example.org/form", "POST", body=b"a=1", peer=AGENT_IP, fid="post"))
    assert f.metadata.get("bh_denied")
    assert _events(tmp_path, "blocked")[-1]["reason"] == "payload host: GET/HEAD/OPTIONS only"


# ------------------------------------------------------------------ R37: bh-browser's noise aggregated
def _clock(monkeypatch, addon_mod, start=1_000_000.0):
    t = [start]
    monkeypatch.setattr(addon_mod.time, "time", lambda: t[0])
    return t


def test_browser_not_in_scope_refusals_are_aggregated_per_host(addon, tmp_path, monkeypatch):
    g = _gate(addon, tmp_path, W1)
    t = _clock(monkeypatch, addon)
    denied = 0
    for i in range(100):
        f = run(g, _http("https://admin.example.net/api/poll", peer=BROWSER_IP, fid=f"n{i}"))
        denied += bool(f.metadata.get("bh_denied"))
        t[0] += 0.5  # 100 refusals in 50 s
    assert denied == 100
    lines = _events(tmp_path, "blocked")
    assert len(lines) == 1 and "repeats" not in lines[0] and lines[0]["client"] == "browser"
    t[0] += 30  # the window is over: the next line carries the count
    run(g, _http("https://admin.example.net/api/poll", peer=BROWSER_IP, fid="late"))
    lines = _events(tmp_path, "blocked")
    assert len(lines) == 2 and lines[1]["repeats"] == 99


def test_aggregation_is_the_browsers_and_not_in_scope_only(addon, tmp_path, monkeypatch):
    g = _gate(addon, tmp_path, W1)
    _clock(monkeypatch, addon)
    for i in range(4):
        run(g, _http("https://admin.example.net/x", peer=AGENT_IP, fid=f"a{i}"))
        run(g, _http("https://admin.example.net/x", peer=JUDGE_IP, fid=f"j{i}"))
        run(g, _http("https://app.example.com/logout", peer=BROWSER_IP, fid=f"b{i}"))  # another reason
    lines = _events(tmp_path, "blocked")
    assert [e["client"] for e in lines].count("agent") == 4 and [e["client"] for e in lines].count("judge") == 4
    assert len([e for e in lines if e["reason"] == "protected url"]) == 4


def test_a_canary_in_the_host_name_is_never_aggregated(addon, tmp_path, monkeypatch):
    g = _gate(addon, tmp_path, W1)
    addon.ctx.options.ignore_hosts = []
    _clock(monkeypatch, addon)
    host = f"{TOKEN.lower()}.exfil.example.net"
    for i in range(3):
        f = _http(f"https://{host}/", "CONNECT", peer=BROWSER_IP, fid=f"c{i}")
        f.request.port = 443
        g.http_connect(f)
        assert f.metadata.get("bh_denied")
    assert len(_events(tmp_path, "canary")) == 3
    assert len(_events(tmp_path, "blocked")) == 3


def test_a_canary_in_the_path_of_a_refused_connect_gives_no_event(addon, tmp_path):
    """R7: a CONNECT names host:port only; whatever rides in its request target is not searched."""
    g = _gate(addon, tmp_path, W1)
    addon.ctx.options.ignore_hosts = []
    req = SimpleNamespace(
        method="CONNECT",
        host="evil.example.net",
        port=443,
        url=f"evil.example.net:443/{TOKEN}",
        path=f"/{TOKEN}",
        headers={},
    )
    f = SimpleNamespace(
        request=req,
        response=None,
        metadata={},
        client_conn=SimpleNamespace(id="c-x", peername=(AGENT_IP, 4000)),
        server_conn=SimpleNamespace(id="s-x"),
    )
    g.http_connect(f)
    assert f.metadata.get("bh_denied")
    assert _events(tmp_path, "canary") == [] and len(_events(tmp_path, "blocked")) == 1


# ------------------------------------------------------------------ R1: an origin judged on its host
def test_origin_covered_by_a_url_rule_of_the_same_scheme_and_port():
    scope = scope_from_dict(W1)
    assert origin_covered(scope, SUB_ORIGIN) and origin_covered(scope, f"{SUB}/")
    assert not origin_covered(scope, "http://sub.example.com:80")  # another scheme
    assert not origin_covered(scope, "https://sub.example.com:8443")  # another port
    assert not origin_covered(scope, "https://other.example.com:443")
    assert not origin_covered(scope, "https://login.example.net:443")  # a support host
    with pytest.raises(ScopeError, match="not in scope"):
        scope_from_dict({**W1, "identities": [{"name": "user-a", "origins": ["http://sub.example.com/"]}]})


def test_enrollment_keeps_the_bearer_of_an_origin_covered_by_a_url_rule(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    browser = {
        "kind": "browser",
        "steps": [{"goto": "https://app.example.com/login"}],
        "capture": {"authorization": True},
    }
    scope = scope_from_dict({**W1, "identities": [{"name": "user-a", "enroll": browser, "origins": [f"{SUB}/"]}]})
    result = {"authorizations": {SUB_ORIGIN: LIVE, "https://login.example.net:443": "Bearer sso-value"}}
    sess = en.browser_session(en.identity(scope, "user-a"), result, time.time())
    assert sess["origin_headers"] == {SUB_ORIGIN: {"Authorization": LIVE}}  # never the support host's


def test_a_path_outside_the_prefix_stays_refused(tmp_path):
    p = _policy(tmp_path)
    assert p.classify_request(f"{SUB}/hub/x", "sub.example.com", "GET").allowed
    v = p.classify_request(f"{SUB}/mail/inbox", "sub.example.com", "GET")
    assert not v.allowed and v.reason == "not in scope"


# ------------------------------------------------------------------ R46: bh-browser's bearer
def _origin_headers(tmp_path):
    return json.loads(_session_file(tmp_path).read_text()).get("origin_headers")


def test_the_browsers_bearer_is_kept_for_its_origin_and_injected_under_the_identity(addon, tmp_path):
    g = _gate(addon, tmp_path, W1)
    (tmp_path / paths.FLOWS_DIR).mkdir(exist_ok=True)
    _load_browser(tmp_path)
    f = run(g, _http(f"{SUB}/hub/conversations", headers=[("Authorization", LIVE)], peer=BROWSER_IP, fid="b1"))
    assert not f.metadata.get("bh_denied") and f.request.headers["Authorization"] == LIVE  # the browser's own
    assert _origin_headers(tmp_path)[SUB_ORIGIN] == {"Authorization": LIVE}
    _answer(f, headers=[("Content-Type", "application/json")], body=b"{}")
    g.response(f)
    mtime = _session_file(tmp_path).stat().st_mtime_ns
    run(g, _http(f"{SUB}/hub/again", headers=[("Authorization", LIVE)], peer=BROWSER_IP, fid="b2"))
    assert _session_file(tmp_path).stat().st_mtime_ns == mtime  # unchanged token: the file is not rewritten
    a = run(g, _http(f"{SUB}/hub/conversations", headers=[(IDENTITY_HEADER, "user-a")], peer=AGENT_IP, fid="a1"))
    assert a.request.headers["Authorization"] == LIVE
    _answer(a, 401, body=b"{}")  # a 401 to a live bearer stays the target's 401: nothing rewritten
    g.response(a)
    assert a.response.status_code == 401 and _origin_headers(tmp_path)[SUB_ORIGIN] == {"Authorization": LIVE}
    token = LIVE.split(" ", 1)[1]
    _no_leak(tmp_path, token)
    kept = [json.loads(p.read_text()) for p in (tmp_path / paths.FLOWS_DIR).glob("*.json")]
    assert len(kept) == 2  # the browser's capture and the agent's 401
    for k in kept:  # the agent only ever sees the mark
        assert dict(k["request"]["headers"]).get("Authorization") == "<identity:user-a>"
    (learned,) = _events(tmp_path, "bearer-learned")
    assert (learned["identity"], learned["origin"]) == ("user-a", SUB_ORIGIN)


def test_nothing_else_is_learned(addon, tmp_path):
    g = _gate(addon, tmp_path, W1)
    before = _origin_headers(tmp_path)
    bearer = [("Authorization", LIVE)]
    run(g, _http(f"{SUB}/hub/x", headers=bearer, peer=BROWSER_IP, fid="noid"))  # no identity loaded yet
    _load_browser(tmp_path)
    run(g, _http(f"{SUB}/hub/x", headers=[*bearer, (IDENTITY_HEADER, "user-a")], peer=AGENT_IP, fid="agent"))
    run(g, _http("https://api.example.com/v1/x", headers=bearer, peer=BROWSER_IP, fid="notdeclared"))
    run(g, _http("https://login.example.net/authorize", headers=bearer, peer=BROWSER_IP, fid="sso"))
    run(g, _http("https://cdn.example.net/a.js", headers=bearer, peer=BROWSER_IP, fid="assets"))
    run(g, _http(f"{SUB}/mail/x", headers=bearer, peer=BROWSER_IP, fid="outside"))  # refused: not in scope
    run(g, _http(f"{SUB}/hub/x", headers=[("Authorization", "Basic dXNlcjpwYXNz")], peer=BROWSER_IP, fid="basic"))
    run(g, _http(f"{SUB}/hub/x", headers=[("X-Api-Key", "k" * 20)], peer=BROWSER_IP, fid="other"))
    assert _origin_headers(tmp_path) == before
    assert _events(tmp_path, "bearer-learned") == []


def test_an_expired_bearer_is_never_sent_and_the_request_is_refused(addon, tmp_path, monkeypatch):
    g = _gate(addon, tmp_path, W1)
    f = _session_file(tmp_path)
    doc = json.loads(f.read_text())
    doc["origin_headers"] = {
        SUB_ORIGIN: {"Authorization": DEAD},
        "https://app.example.com:443": {"Authorization": "Bearer opaque-token-1"},
    }
    f.write_text(json.dumps(doc))
    who = [(IDENTITY_HEADER, "user-a")]
    for i in range(3):
        r = run(g, _http(f"{SUB}/hub/x", headers=who, peer=AGENT_IP, fid=f"e{i}"))
        assert r.metadata.get("bh_denied") and "Authorization" not in r.request.headers
    blocked = _events(tmp_path, "blocked")
    assert [e["reason"] for e in blocked] == ["identity bearer expired"] * 3
    (ev,) = _events(tmp_path, "bearer-expired")  # once per identity and minute
    assert (ev["identity"], ev["host"]) == ("user-a", "sub.example.com") and isinstance(ev["ts"], float)
    opaque = run(g, _http("https://app.example.com/x", headers=who, peer=AGENT_IP, fid="o"))
    assert opaque.request.headers["Authorization"] == "Bearer opaque-token-1"  # no readable exp: sent as before
    _no_leak(tmp_path, DEAD.split(" ", 1)[1], "opaque-token-1")


# ------------------------------------------------------------------ R14: the browser only adds to the jar
def test_the_browser_never_deletes_a_cookie_of_the_jar(addon, tmp_path):
    g = _gate(addon, tmp_path, W1)
    _load_browser(tmp_path)
    for i, sc in enumerate(
        ("sid=; Path=/", "sid=gone; Max-Age=0; Path=/", "sid=x; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
    ):
        f = run(g, _http("https://app.example.com/a", peer=BROWSER_IP, fid=f"d{i}"))
        _answer(f, headers=[("Set-Cookie", sc), ("Set-Cookie", f"new{i}=v{i}; Path=/")])
        g.response(f)
    jar = json.loads(_session_file(tmp_path).read_text())["cookies"]["app.example.com"]
    assert jar["sid"]["value"] == "jar-cookie" and {"new0", "new1", "new2"} <= set(jar)
    f = run(g, _http("https://app.example.com/a", headers=[(IDENTITY_HEADER, "user-a")], peer=AGENT_IP, fid="ag"))
    _answer(f, headers=[("Set-Cookie", "sid=; Max-Age=0; Path=/")])
    g.response(f)
    assert "sid" not in json.loads(_session_file(tmp_path).read_text())["cookies"]["app.example.com"]


def test_merge_without_deletions():
    s = {
        "cookies": {"a.test": {"sid": {"value": "v", "path": "/", "expires": None, "host_only": True, "secure": False}}}
    }
    assert session.merge(s, "https://a.test/", ["sid=; Max-Age=0", "sid="], deletions=False) == []
    assert s["cookies"]["a.test"]["sid"]["value"] == "v"
    assert session.merge(s, "https://a.test/", ["sid=; Max-Age=0"]) == ["sid"]


# ------------------------------------------------------------------ R20: the browser's pushback slows the rate
@pytest.mark.parametrize("status", [429, 503])
def test_the_browsers_429_and_503_slow_the_shared_rate(addon, tmp_path, status):
    g = _gate(addon, tmp_path, W1)
    f = run(g, _http("https://app.example.com/a", peer=BROWSER_IP))
    _answer(f, status)
    g.response(f)
    assert g.policy.backoff_until > time.time()
    assert not g.policy.host_blocked_until  # never a WAF pause


# ------------------------------------------------------------------ R22: bh-browser lives on the gate's networks
ROUTE = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
    "eth0\t00000000\t0100590A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
    "eth0\t0000590A\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
    "lo\t0000007F\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0\n"
)
ROUTE6 = (
    "fd000000000000000000000000000000 40 00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n"
    "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
    "fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n"
)


def test_local_networks_and_the_browsers_addresses(addon, monkeypatch):
    nets = addon.local_networks(ROUTE, ROUTE6)
    assert {str(n) for n in nets} == {"10.89.0.0/16", "fd00::/64"}
    ips = {"10.89.0.9", "203.0.113.5", "fd00::9", "2001:db8::9", "not-an-ip"}
    assert addon.on_local_networks(ips, nets) == {"10.89.0.9", "fd00::9"}
    assert addon.local_networks("", "") == frozenset()  # unreadable: no network, so no browser
    monkeypatch.setattr(addon, "resolve_hosts", lambda hosts: frozenset({"10.89.0.9", "198.51.100.1"}))
    monkeypatch.setattr(addon, "local_networks", lambda: nets)
    monkeypatch.setattr(addon, "_BROWSER_IPS", (0.0, frozenset()))
    assert addon._browser_ips() == {"10.89.0.9"}
    assert addon.is_browser_peer("10.89.0.9") and not addon.is_browser_peer("198.51.100.1")


# ------------------------------------------------------------------ R26, R43: the probe
class _Proxy(http.server.BaseHTTPRequestHandler):
    """Stands for the gate's proxy on this machine's loopback: answers from `plan`, counts the requests."""

    plan: ClassVar[dict] = {}
    seen: ClassVar[list] = []

    def _answer(self):
        size = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(size) if size else b""
        type(self).seen.append((self.command, self.path, dict(self.headers), body))
        status, headers, out = type(self).plan[self.path.split("?")[0]]
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST = _answer

    def log_message(self, *a):
        pass


@pytest.fixture
def gate_script(monkeypatch, capsys):
    """Runs the real GATE_SCRIPT against a proxy bound on 127.0.0.1."""
    for k in ("no_proxy", "NO_PROXY", "http_proxy", "HTTP_PROXY"):
        monkeypatch.delenv(k, raising=False)
    _Proxy.seen = []
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Proxy)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    ns: dict = {}
    exec(compile(en.GATE_SCRIPT, "gate_script", "exec"), ns)

    def call(steps):
        ns["main"](
            json.dumps(
                {"proxy": f"http://127.0.0.1:{srv.server_port}", "cafile": "/nonexistent", "timeout": 5, "steps": steps}
            )
        )
        return capsys.readouterr().out

    yield call
    srv.shutdown()


def test_the_probe_does_not_follow_a_redirect(gate_script):
    _Proxy.plan = {"http://app.test/resources/app-shell-action": (302, {"Location": "http://app.test/login"}, b"")}
    _Proxy.plan["http://app.test/login"] = (200, {}, b"login page")
    step = {
        "step": "probe",
        "method": "POST",
        "url": "http://app.test/resources/app-shell-action",
        "headers": {"Accept": "application/json", "X-BH-Identity": "user-a", "X-BH-Probe": "1"},
        "json": {"action": "RefreshNavPane"},
    }
    (rec,) = json.loads(gate_script([step]))
    assert rec["status"] == 302 and len(_Proxy.seen) == 1  # the first answer's status, the login never requested
    method, _, headers, body = _Proxy.seen[0]
    assert method == "POST" and json.loads(body) == {"action": "RefreshNavPane"}
    assert headers["Accept"] == "application/json" and headers["Content-Type"] == "application/json"


def test_a_probe_body_without_the_expected_text_fails_and_is_never_returned(gate_script):
    """R26: `expect` is checked in the gate; only the verdict comes back, never the body."""
    secret_body = b'{"user": "someone-else@example.test", "nav": "private-conversation-title"}'
    _Proxy.plan = {"http://app.test/me": (200, {"Content-Type": "application/json"}, secret_body)}
    out = gate_script(
        [{"step": "probe", "method": "GET", "url": "http://app.test/me", "headers": {}, "expect": "me@example.test"}]
    )
    (rec,) = json.loads(out)
    assert rec == {"step": "probe", "status": 200, "match": False}
    assert "private-conversation-title" not in out and "someone-else" not in out


PROBE_POST = {
    "url": "http://app.test/resources/app-shell-action",
    "method": "POST",
    "status": 200,
    "headers": {"Accept": "application/json"},
    "json": {"action": "RefreshNavPane"},
    "expect": "{email}",
}


@pytest.mark.parametrize(
    "change",
    [
        {"method": "PUT"},
        {"method": "post"},
        {"headers": {"Cookie": "a=1"}},
        {"headers": {"Authorization": "Bearer x"}},
        {"headers": {"Accept": "a\r\nX-Injected: 1"}},
        {"headers": {"Accept": 3}},
        {"headers": {}},
        {"headers": ["Accept"]},
        {"json": ["not", "an", "object"]},
        {"json": {"pad": "x" * 2100}},
        {"method": "GET"},  # json with a GET
        {"expect": "{password}"},
        {"expect": "{email} {answer}"},
        {"expect": ""},
        {"body": "x"},
    ],
)
def test_each_probe_key_is_validated(change):
    with pytest.raises(ScopeError, match="probe"):
        scope_from_dict(
            {
                "program": "p",
                "platform": "local",
                "in_scope": ["app.test"],
                "identities": [{"name": "user-a", "probe": {**PROBE_POST, **change}}],
            }
        )


def test_a_full_probe_loads():
    scope = scope_from_dict(
        {
            "program": "p",
            "platform": "local",
            "in_scope": ["app.test"],
            "identities": [
                {
                    "name": "user-a",
                    "probe": {
                        **PROBE_POST,
                        "headers": {"accept": "x", "x-route-id": "r1", "Content-Type": "application/json"},
                    },
                }
            ],
        }
    )
    assert scope.identities[0]["probe"]["method"] == "POST"


@pytest.fixture
def acct(tmp_path, monkeypatch):
    from bh.board import Board

    monkeypatch.setenv("BH_HOME", str(tmp_path))
    paths.state().mkdir(parents=True)
    paths.active_scope().write_text("program: p\n")
    return Board(paths.board_db())


def _acct_scope():
    return scope_from_dict(
        {
            "program": "p",
            "platform": "local",
            "in_scope": ["app.test"],
            "self_signup": True,
            "identities": [{"name": "user-a", "probe": PROBE_POST, "enroll": RECIPE}],
        }
    )


TOK = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjQxMDI0NDQ4MDB9.c2lnbmF0dXJlLXZhbHVl"


def _login_ok(s):
    assert s["step"] == "login"
    return {"step": "login", "status": 200, "token": TOK, "set_cookies": []}


def test_the_probe_template_is_resolved_on_the_host_without_leaking(acct, monkeypatch, caplog, capsys):
    secrets.save("p", "user-a", {"email": "owner-a@example.test", "password": "pw-123456"})
    seen = []

    def probe(s):
        seen.append(s)
        return {"step": "probe", "status": 200, "match": True}

    monkeypatch.setattr(stack, "gate_python", FakeGate(_login_ok, probe))
    scope = _acct_scope()
    out = en.enroll(scope, "user-a", board=acct, force=True)
    (step,) = seen
    assert step["expect"] == "owner-a@example.test"  # resolved for the gate script, on stdin only
    assert step["method"] == "POST" and step["json"] == {"action": "RefreshNavPane"}
    assert step["headers"] == {"Accept": "application/json", "X-BH-Identity": "user-a", "X-BH-Probe": "1"}
    sess = paths.identities_dir("p").joinpath("user-a.json").read_text()
    assert "owner-a" not in sess and json.loads(sess)["probe"]["method"] == "POST"
    assert "owner-a" not in out + caplog.text + capsys.readouterr().out


def test_refresh_logs_in_again_when_the_body_lacks_the_expected_text(acct, monkeypatch):
    secrets.save("p", "user-a", {"email": "owner-a@example.test", "password": "pw-123456"})
    paths.identities_dir("p").mkdir(parents=True, exist_ok=True)
    paths.identities_dir("p").joinpath("user-a.json").write_text(json.dumps({"headers": {}}))
    calls = FakeGate(
        lambda s: {"step": "probe", "status": 200, "match": False},  # 200, but not this account's page
        _login_ok,
        lambda s: {"step": "probe", "status": 200, "match": True},
    )
    monkeypatch.setattr(stack, "gate_python", calls)
    assert en.refresh(_acct_scope(), "user-a", board=acct) == "logged in, probe ok"
    assert [c[0]["step"] for c in calls.calls] == ["probe", "login", "probe"]


def test_an_expired_bearer_makes_the_probe_fail_so_refresh_logs_in(acct, monkeypatch):
    secrets.save("p", "user-a", {"email": "owner-a@example.test", "password": "pw-123456"})
    paths.identities_dir("p").mkdir(parents=True, exist_ok=True)
    paths.identities_dir("p").joinpath("user-a.json").write_text(json.dumps({"headers": {}}))
    gate = "bh-gate: DENIED (identity bearer expired)"
    calls = FakeGate(
        lambda s: {"step": "probe", "status": 403, "gate": gate},
        _login_ok,
        lambda s: {"step": "probe", "status": 200, "match": True},
    )
    monkeypatch.setattr(stack, "gate_python", calls)
    assert en.refresh(_acct_scope(), "user-a", board=acct) == "logged in, probe ok"


def test_a_post_probe_says_nothing_about_a_get_of_its_url():
    pr = {"url": "https://copilot.com/resources/app-shell-action", "status": 200, "method": "POST"}
    url = pr["url"]
    assert session.dead_reason("GET", url, 405, None, probe=pr) is None
    assert session.dead_reason("POST", url, 302, "https://copilot.com/", probe=pr) == "probe"
    assert session.dead_reason("GET", url, 302, None, probe={"url": url, "status": 200}) == "probe"


# ------------------------------------------------------------------ the real MSRC scope (R1, R12, R28, R43, D27)
def test_the_real_copilot_scope():
    scope = load_scope(COPILOT)
    assert "MSOBB" not in scope.notes and ".claude/skills" not in scope.notes  # R12
    assert scope.cards == ("msrc-copilot", "bh-web-manual")  # R28
    for card in scope.cards:
        assert (ROOT / "src" / "bh" / "cards" / f"{card}.md").is_file(), card
    assert all("*" not in r.value and r.type.value != "wildcard" for r in scope.in_scope)
    assert scope.payload_hosts == ["example.org", "example.com", "example.net", "bh.datk.ch"]
    for ident in scope.identities:
        assert "https://substrate.office.com/" in ident["origins"]  # R1
        assert ident["probe"] == {
            "url": "https://copilot.com/resources/app-shell-action",
            "method": "POST",
            "status": 200,
            "headers": {"Accept": "application/json"},
            "json": {"action": "RefreshNavPane"},
        }
    assert origin_covered(scope, "https://substrate.office.com:443")


def test_the_real_copilot_scope_at_the_gate(tmp_path):
    p = tmp_path / "active-scope.yaml"
    p.write_text(COPILOT.read_text())
    g = pol.Policy(p)
    for path in ("/common/oauth2/v2.0/authorize?client_id=x", "/savedusers"):  # R9: the agent's silent sign-in
        v = g.classify_request(f"https://login.microsoftonline.com{path}", "login.microsoftonline.com", "GET")
        assert v.allowed and v.support == "sso", path
    assert not g.classify_connect("admin.microsoft.com", 443).allowed
    v = g.classify_request("https://substrate.office.com/api/v2.0/me/messages", "substrate.office.com", "GET")
    assert not v.allowed  # substrate outside the prefixes stays refused
    assert g.classify_request("https://example.com/", "example.com", "GET").klass == "payload"
    assert not g.classify_request("https://copilot.com/logout", "copilot.com", "GET").allowed
    assert g.classify_request("https://copilot.com/resources/app-shell-action", "copilot.com", "POST").allowed


def test_escape_suite_shape():
    text = (ROOT / "tests" / "escape" / "escape_check.sh").read_text()
    for name in (
        "positive:in-scope-target-answers",
        "positive:relay-refuses-without-run",
        "witness:in-scope-request-passes",
    ):
        assert text.count(f'check "{name}"') == 1, name
    assert '"relay: no run in progress"' not in text
    assert "SNI different from the CONNECT name" in text and "bh-web goto to the loopback" in text
    msrc = text.split('if [ "$PROFILE" = msrc ]; then', 1)[1].split("\nfi\n", 1)[0]
    assert "positive:" not in msrc and "witness:" not in msrc
