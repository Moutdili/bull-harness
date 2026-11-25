"""Support hosts (assets the targets load, our own login) and bounded websockets, at the gate's policy (no network)."""

import time
from pathlib import Path

import pytest
import yaml

from bh.accounts.enroll import browser_jar, identity
from bh.gate import policy as pol
from bh.gate.policy import Policy, WsGuard, WsLimits, ws_message_record
from bh.scope import load_scope

COPILOT = Path(__file__).resolve().parents[1] / "scopes" / "msrc" / "copilot.yaml"

BASE = {
    "schema": 1,
    "program": "t",
    "platform": "test",
    "in_scope": ["app.example.com"],
    "support": [
        {"value": "cdn.example.net", "kind": "assets", "note": "app scripts"},
        {"value": "*.static.example.org", "kind": "assets"},
        {"value": "login.example.org", "kind": "auth", "note": "login"},
    ],
}


def _policy(tmp_path, **over) -> Policy:
    doc = {**BASE, **over}
    p = tmp_path / "active-scope.yaml"
    p.write_text(yaml.safe_dump(doc))
    return Policy(p, ws_limits=WsLimits(msgs_per_min=3, max_bytes=100, max_seconds=60, max_open=1))


def req(p, url, method="GET", **kw):
    host = url.split("/")[2]
    return p.classify_request(url, host, method, **kw)


# ------------------------------------------------------------------ support hosts
def test_assets_get_and_head_from_anyone(tmp_path):
    p = _policy(tmp_path)
    for url in ("https://cdn.example.net/app.js", "https://a.static.example.org/x.css"):
        for m in ("GET", "HEAD"):
            v = req(p, url, m)
            assert v.allowed and v.klass == "support" and v.support == "assets"
    assert p.classify_connect("cdn.example.net", 443).klass == "support"
    assert not p.classify_connect("cdn.example.net", 8443).allowed  # 80 and 443 only
    assert p.check_ip("cdn.example.net", "93.184.216.34").klass == "support"
    assert not p.check_ip("cdn.example.net", "10.0.0.5").allowed  # never an internal address


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "OPTIONS", "PATCH"])
def test_assets_refuse_anything_but_get_head(tmp_path, method):
    v = req(_policy(tmp_path), "https://cdn.example.net/x", method, identity="user-a")
    assert not v.allowed and "assets" in v.reason


def test_assets_refuse_a_body_and_another_host_header(tmp_path):
    p = _policy(tmp_path)
    assert not req(p, "https://cdn.example.net/x", body_len=3).allowed
    assert not req(p, "https://cdn.example.net/x", host_header="app.example.com").allowed


def test_auth_is_enrollment_only(tmp_path):
    p = _policy(tmp_path)
    v = req(p, "https://login.example.org/login", "POST")
    assert not v.allowed and "login host, enrollment only" in v.reason
    assert not p.classify_connect("login.example.org", 443).allowed
    assert "enrollment only" in p.classify_connect("login.example.org", 443).reason
    v = req(p, "https://login.example.org/login", "POST", enroll=True, body_len=40)
    assert v.allowed and v.klass == "support" and v.support == "auth"
    assert p.classify_connect("login.example.org", 443, enroll=True).allowed
    assert not req(p, "https://login.example.org/x", "DELETE", enroll=True).allowed


def test_support_never_counts_as_a_target(tmp_path):
    p = _policy(tmp_path)
    for url in ("https://cdn.example.net/api/users/1", "https://cdn.example.net/api/users/2"):
        assert req(p, url).klass == "support"
    assert not p.ids_seen  # no enumeration bookkeeping, no scanner bookkeeping
    assert p.bucket("support").rps == pol.SUPPORT_RPS and p.bucket("support") is not p.bucket("target")
    p.penalize("cdn.example.net", waf=True)
    assert req(p, "https://cdn.example.net/x").allowed  # WAF pauses only targets
    # the asset graph keeps target flows only (assets.py: class None or "target")
    import inspect

    from bh import assets

    assert 'f.get("class") not in (None, "target")' in inspect.getsource(assets)


def test_out_of_scope_beats_support(tmp_path):
    p = _policy(tmp_path, out_of_scope=["cdn.example.net"])
    v = req(p, "https://cdn.example.net/x")
    assert not v.allowed and v.klass == "deny"


# ------------------------------------------------------------------ websockets
def test_websocket_refused_without_the_scope_field(tmp_path):
    for value in (None, False):
        doc = {} if value is None else {"websockets": value}
        v = req(_policy(tmp_path, **doc), "https://app.example.com/ws", websocket=True)
        assert not v.allowed and "websockets are not allowed" in v.reason


def test_websocket_only_to_targets(tmp_path):
    p = _policy(tmp_path, websockets=True)
    assert req(p, "https://app.example.com/ws", websocket=True).klass == "target"
    for url in ("https://cdn.example.net/ws", "https://login.example.org/ws", "https://other.com/ws"):
        assert not req(p, url, websocket=True, enroll=True).allowed
    assert not req(p, "https://app.example.com/ws", "POST", websocket=True).allowed


def test_websocket_handshake_goes_through_the_target_rules(tmp_path):
    p = _policy(tmp_path, websockets=True, out_of_scope=["https://app.example.com/admin/"])
    assert not req(p, "https://app.example.com/admin/ws", websocket=True).allowed
    assert not req(p, "https://app.example.com/ws", websocket=True, host_header="evil.com").allowed


def test_websocket_open_count_and_rate(tmp_path):
    p = _policy(tmp_path, websockets=True)
    assert p.ws_start("f1", now=1000.0) is None
    assert "already open" in req(p, "https://app.example.com/ws", websocket=True).reason  # max_open = 1
    assert p.ws_start("f2", now=1000.0) is not None
    for i in range(3):
        assert p.ws_message("f1", 10, binary=False, from_client=True, now=1000.0 + i) is None
    assert p.ws_message("f1", 10, binary=False, from_client=False, now=1003.0) is None  # server frames: not rated
    why = p.ws_message("f1", 10, binary=False, from_client=True, now=1004.0)
    assert why and "per minute" in why
    assert p.ws_message("f1", 1, binary=False, from_client=False, now=2000.0) == why  # closed for good
    g = p.ws_end("f1")
    assert g.counts() == {"client": 3, "server": 1, "binary": 0, "bytes": 30}
    assert p.ws_message("f1", 1, binary=False, from_client=True) is not None  # unknown connection
    assert p.ws_start("f2", now=1000.0) is None  # the slot is free again


def test_websocket_rate_window_slides_size_and_lifetime():
    lim = WsLimits(msgs_per_min=2, max_bytes=100, max_seconds=60, max_open=1)
    g = WsGuard(lim, 0.0)
    assert g.message(1, binary=True, from_client=True, now=1) is None
    assert g.message(1, binary=False, from_client=True, now=2) is None
    assert g.message(1, binary=False, from_client=True, now=59) is not None
    g = WsGuard(lim, 0.0)
    assert g.message(1, binary=True, from_client=True, now=1) is None
    assert g.binary == 1
    assert g.message(1, binary=False, from_client=True, now=40) is None
    assert g.message(1, binary=False, from_client=True, now=62) is not None  # past max_seconds
    g = WsGuard(lim, 0.0)
    assert "bytes" in g.message(101, binary=False, from_client=True, now=1)
    g = WsGuard(lim, 0.0)
    assert g.message(101 * 10, binary=False, from_client=False, now=1) is None  # a server frame gets more room
    assert g.message(100 * pol.WS_SERVER_FACTOR + 1, binary=False, from_client=False, now=2) is not None


def test_websocket_message_journal_is_redacted_and_bounded():
    text = ('{"token": "s3cr3t-value", "prompt": "' + "a" * 400 + '"}').encode()
    rec = ws_message_record(text, binary=False)
    assert rec["len"] == len(text) and len(rec["sha256"]) == 64 and rec["binary"] is False
    assert "s3cr3t" not in rec["text"] and len(rec["text"]) <= 220
    rec = ws_message_record(b"\x00\x01secret", binary=True)
    assert rec["binary"] is True and "text" not in rec


def test_ws_limits_from_env():
    lim = WsLimits.from_env({"BH_WS_MSGS_PER_MIN": "5", "BH_WS_MAX_BYTES": "junk", "BH_WS_MAX_OPEN": "-1"})
    assert lim.msgs_per_min == 5 and lim.max_bytes == WsLimits().max_bytes and lim.max_open == WsLimits().max_open


# ------------------------------------------------------------------ the Copilot scope
def test_copilot_scope_targets_and_support():
    s = load_scope(COPILOT)
    assert {r.value for r in s.in_scope} == {
        "copilot.microsoft.com",
        "copilot.com",
        "substrate.office.com",
        "substrate.svc.cloud.microsoft",
    }
    assert s.websockets_on
    assert set(s.support_hosts("sso")) == {"login.live.com", "login.microsoftonline.com"}
    assert s.support_hosts("passthrough") == ("challenges.cloudflare.com", "brunhild.challenges.cloudflare.com")
    assert "login.microsoft.com" in s.support_hosts("auth") and "res.cdn.office.net" in s.support_hosts("assets")
    entry = next(e for e in s.support if e.rule.value == "login.microsoftonline.com")
    assert entry.token_path("/9188040d-6c67-4c5b-b112-36a304b66dad/oauth2/v2.0/token")
    assert not entry.token_path("/9188040d-6c67-4c5b-b112-36a304b66dad/oauth2/v2.0/authorize")


def test_copilot_login_keeps_the_cookies_of_its_login_host():
    """bh-login captures its own jar: login.live.com (a support auth host, the recipe's goto) stays in it."""
    s = load_scope(COPILOT)
    ident = identity(s, "user-a")
    now = time.time()
    jar = browser_jar(
        ident,
        [
            {"name": "MSPAuth", "value": "x1", "domain": "login.live.com", "path": "/"},
            {"name": "_C_Auth", "value": "x2", "domain": "copilot.microsoft.com", "path": "/"},
            {"name": "other", "value": "x3", "domain": "evil.example", "path": "/"},
        ],
        now,
    )
    assert "login.live.com" in jar and "copilot.microsoft.com" in jar and "evil.example" not in jar


def test_copilot_login_keeps_the_cookies_of_its_sso_hosts():
    """The silent sign-in needs login.microsoftonline.com's cookies (not a goto of the recipe): an `sso` host, kept;
    a parent domain of an sso host too (a domain cookie the browser would send there); an `auth` host is not."""
    s = load_scope(COPILOT)
    jar = browser_jar(
        identity(s, "user-a"),
        [
            {"name": "ESTSAUTHPERSISTENT", "value": "e1", "domain": "login.microsoftonline.com", "path": "/"},
            {"name": "MSPOK", "value": "e2", "domain": ".live.com", "path": "/"},
            {"name": "fp", "value": "e3", "domain": "fpt.live.com", "path": "/"},
            {"name": "x", "value": "e4", "domain": "challenges.cloudflare.com", "path": "/"},
        ],
        time.time(),
    )
    assert "login.microsoftonline.com" in jar and "live.com" in jar
    assert "fpt.live.com" not in jar and "challenges.cloudflare.com" not in jar
