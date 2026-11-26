import asyncio
import os
import shutil
import time
from pathlib import Path

import pytest

from bh.gate import policy as pol
from bh.gate.policy import Policy, TokenBucket

DEMO = Path(__file__).resolve().parents[1] / "scopes" / "examples" / "demo.yaml"


def _policy(tmp_path, with_scope=True):
    p = tmp_path / "active-scope.yaml"
    if with_scope:
        shutil.copy(DEMO, p)
    return Policy(p)


def req(policy, url, host, method="GET", **kw):
    return policy.classify_request(url, host, method, **kw)


def test_claude_api_only_through_the_relay(tmp_path):
    p = _policy(tmp_path, with_scope=False)
    for port in (443, 22):
        v = p.classify_connect("api.anthropic.com", port)
        assert not v.allowed and "relay" in v.reason
    assert not req(p, "http://api.anthropic.com/v1/messages", "api.anthropic.com", "POST").allowed
    assert not p.classify_connect("claude.ai", 443).allowed
    assert p.check_ip("api.anthropic.com", "160.79.104.10").allowed  # the relay's own upstream
    v = req(p, "https://a.example.com/", "a.example.com")
    assert not v.allowed and "no active scope" in v.reason


def test_target_out_of_scope_and_ports(tmp_path):
    p = _policy(tmp_path)
    assert req(p, "https://a.example.com/x", "a.example.com").klass == "target"
    v = req(p, "https://admin.example.com/", "admin.example.com")
    assert not v.allowed and v.rule == "domain:admin.example.com"
    assert p.classify_connect("a.example.com", 443).allowed
    assert not p.classify_connect("a.example.com", 22).allowed  # domain rule: web ports only
    assert p.classify_connect("192.0.2.10", 22).allowed  # CIDR rule: explicit range, any port


def test_decision_uses_destination_not_host_header(tmp_path):
    p = _policy(tmp_path)
    # identity headers must never reach a third party that claims to be the target
    assert not req(p, "https://web.archive.org/x", "web.archive.org", host_header="a.example.com").allowed
    # a target reached with a passive Host header is not "passive"
    assert not req(p, "https://a.example.com/x", "a.example.com", host_header="web.archive.org").allowed
    # Host header injection between two in-scope names stays possible
    assert req(p, "https://a.example.com/x", "a.example.com", host_header="b.example.com").allowed


def test_methods(tmp_path):
    p = _policy(tmp_path)
    for m in ("PURGE", "DEBUG", "TRACE", "PROPFIND"):
        assert not req(p, "https://a.example.com/", "a.example.com", m).allowed, m
    assert not req(p, "https://a.example.com/u/1", "a.example.com", "DELETE").allowed
    assert req(p, "https://a.example.com/u/1", "a.example.com", "DELETE", identity="user-a").allowed
    assert req(p, "https://a.example.com/login", "a.example.com", "POST").allowed


def test_passive_sources(tmp_path):
    p = _policy(tmp_path)
    assert req(p, "https://web.archive.org/cdx?url=example.com", "web.archive.org").klass == "passive"
    assert not req(p, "https://web.archive.org/save/https://evil.test", "web.archive.org").allowed
    assert not req(p, "https://web.archive.org/cdx", "web.archive.org", "POST").allowed
    assert not req(p, "https://web.archive.org/cdx", "web.archive.org", body_len=3).allowed
    assert not req(p, "https://x.web.archive.org/", "x.web.archive.org").allowed  # exact hosts only
    for host in ("api.hackertarget.com", "raw.githubusercontent.com", "jldc.me", "archive.org"):
        assert not req(p, f"https://{host}/", host).allowed, host


def test_unknown_host_denied(tmp_path):
    assert not req(_policy(tmp_path), "https://evil.com/", "evil.com").allowed


def test_resolved_ip_checks(tmp_path):
    p = _policy(tmp_path)
    assert p.check_ip("a.example.com", "93.184.216.34").allowed
    assert not p.check_ip("a.example.com", "10.1.2.3").allowed
    assert p.check_ip("web.archive.org", "207.241.224.2").allowed
    assert not p.check_ip("web.archive.org", "10.231.0.10").allowed  # no pivot to the lab via a passive name
    assert not p.check_ip("api.anthropic.com", "127.0.0.1").allowed


def test_the_gate_itself_is_never_a_destination(tmp_path):
    """B3: a scope that covers loopback or the gate's own address (a lab CIDR) still cannot reach the gate."""
    f = tmp_path / "active-scope.yaml"
    f.write_text("program: p\nplatform: x\nin_scope: [127.0.0.0/8, '::1/128', 10.231.0.0/24]\n")
    p = Policy(f, local_ips=frozenset({"10.231.0.2"}))
    assert p.check_ip("10.231.0.10", "10.231.0.10").allowed  # the lab target itself stays reachable
    for ip in ("127.0.0.1", "127.8.9.1", "::1", "::ffff:127.0.0.1", "0.0.0.0", "::", "10.231.0.2"):
        v = p.check_ip("lab.test", ip)
        assert not v.allowed and v.rule == "self", ip
    for host in ("127.0.0.1", "10.231.0.2", "[::1]"):
        assert not p.classify_connect(host, 8080).allowed, host
        assert not req(p, f"http://{host}:8080/", host.strip("[]")).allowed, host
    assert not pol.is_self_address("lab.test") and not pol.is_self_address("93.184.216.34")


@pytest.mark.parametrize(
    ("status", "headers", "body", "expected"),
    [
        (403, {"Server": "cloudflare"}, b"<h1>Forbidden</h1> you cannot read this order", False),  # the app's 403
        (403, {"Server": "AkamaiGHost"}, b"{}", False),
        (403, {"cf-mitigated": "challenge"}, b"", True),
        (403, {}, b"<title>Just a moment...</title>", True),
        (403, {}, b"<title>Attention Required! | Cloudflare</title>", True),
        (403, {}, b"error code: 1020", True),
        (403, {}, b"Access Denied ... You don't have permission ... Reference #18.2f", True),
        (429, {}, b"Request blocked. ... CloudFront", True),
        (503, {"Server": "cloudflare"}, b"Service Unavailable", False),  # pushback, not a WAF page
        (200, {"cf-mitigated": "challenge"}, b"Just a moment...", False),
        (401, {}, b"Just a moment...", False),
    ],
)
def test_waf_answers_are_the_waf_own_pages_only(status, headers, body, expected):
    """H3: `Server: cloudflare` on the application's own 403 never counts."""
    assert pol.is_waf(status, headers, body) is expected


def test_broken_scope_fails_closed(tmp_path):
    p = _policy(tmp_path)
    assert req(p, "https://a.example.com/", "a.example.com").allowed
    f = tmp_path / "active-scope.yaml"
    f.write_text("program: p\nplatform: x\nin_scope: ['https://[::1']\n")
    os.utime(f, (time.time() + 5, time.time() + 5))
    v = req(p, "https://a.example.com/", "a.example.com")
    assert not v.allowed and "invalid active scope" in v.reason


def test_scope_hot_reload(tmp_path):
    p = _policy(tmp_path)
    assert req(p, "https://a.example.com/", "a.example.com").allowed
    f = tmp_path / "active-scope.yaml"
    f.write_text("program: other\nplatform: local\nin_scope: [other.test]\n")
    os.utime(f, (time.time() + 5, time.time() + 5))
    assert not req(p, "https://a.example.com/", "a.example.com").allowed
    assert p.program == "other"


def test_default_rate_and_backoff(tmp_path):
    p = _policy(tmp_path)
    p.reload()
    assert p.target_rps() == 5  # demo scope: max_rps 5
    p.penalize()
    assert p.target_rps() == 5 * pol.BACKOFF_FACTOR
    f = tmp_path / "active-scope.yaml"
    f.write_text("program: p\nplatform: x\nin_scope: [a.test]\n")  # no max_rps
    os.utime(f, (time.time() + 5, time.time() + 5))
    p.reload()
    assert p.target_rps() == 2.0


def test_token_bucket_rate():
    async def go():
        b = TokenBucket(rps=20)
        t0 = time.monotonic()
        for _ in range(30):
            await b.take()
        return time.monotonic() - t0

    assert asyncio.run(go()) >= (30 - 20) / 20 * 0.9


def test_id_enumeration_is_refused(tmp_path):
    p = _policy(tmp_path)
    url = "https://a.example.com/api/baskets/{}"
    assert pol.ID_LIMIT == 12
    for i in range(1, pol.ID_LIMIT + 1):
        assert req(p, url.format(i), "a.example.com", authenticated=True).allowed, i
    v = req(p, url.format(pol.ID_LIMIT + 1), "a.example.com", authenticated=True)
    assert not v.allowed and "enumeration" in v.reason
    assert req(p, url.format(2), "a.example.com", authenticated=True).allowed  # an id already seen
    for i in range(1, pol.ID_LIMIT * 2):  # public, non-API pages (blog posts, products) are not limited
        assert req(p, f"https://a.example.com/blog/{i}", "a.example.com").allowed


def test_body_size_cap(tmp_path):
    p = _policy(tmp_path)
    assert not req(p, "https://a.example.com/up", "a.example.com", "POST", body_len=pol.MAX_BODY_BYTES + 1).allowed


def test_scanner_guard_when_the_program_forbids_scanners(tmp_path):
    p = _policy(tmp_path)
    p.scope_path.write_text(DEMO.read_text() + "\nscanners_allowed: false\n")
    p.scope_mtime = -2  # force the reload
    url = "https://a.example.com/guess-{}"
    for i in range(pol.MISS_LIMIT):
        assert req(p, url.format(i), "a.example.com").allowed, i
        p.note_answer(url.format(i), 404)
    v = req(p, "https://a.example.com/api/me", "a.example.com")
    assert not v.allowed and "scanner signature" in v.reason


def test_scanner_guard_off_when_scanners_are_allowed(tmp_path):
    p = _policy(tmp_path)  # demo scope: scanners not forbidden
    for i in range(pol.MISS_LIMIT * 2):
        p.note_answer(f"https://a.example.com/g{i}", 404)
    assert req(p, "https://a.example.com/api/me", "a.example.com").allowed


def test_web_ports_on_every_request_not_only_connect(tmp_path):
    p = _policy(tmp_path)
    assert not req(p, "http://a.example.com:22/", "a.example.com").allowed
    assert not req(p, "http://a.example.com:6379/", "a.example.com").allowed
    assert req(p, "http://a.example.com:8080/", "a.example.com").allowed
    assert req(p, "http://192.0.2.5:3000/", "192.0.2.5").allowed  # a CIDR rule grants the address, all ports


def test_id_enumeration_sees_through_path_variants(tmp_path):
    p = _policy(tmp_path)
    for i in range(1, pol.ID_LIMIT + 1):
        assert req(p, f"https://a.example.com/api/baskets/{i}", "a.example.com", authenticated=True).allowed
    for variant in (
        "/api/baskets/50/",
        "/API/baskets/60",
        "/api//baskets/70",
        "/api/baskets/80;x=1",
        "/api/baskets/%39%39",
    ):
        v = req(p, "https://a.example.com" + variant, "a.example.com", authenticated=True)
        assert not v.allowed and "enumeration" in v.reason, variant


def test_id_enumeration_counts_path_ids_only(tmp_path):
    """I6: a parameter (telemetry `eventid`, a body id) is not an object read; only the path's ids count."""
    p = _policy(tmp_path)
    host = "a.example.com"
    for i in range(1, pol.ID_LIMIT * 3):
        assert req(p, f"https://{host}/api/events?eventid={i}", host, authenticated=True).allowed, i
        body = b'{"query": "query { user(id: %d) { email } }"}' % i
        assert req(p, f"https://{host}/graphql", host, "POST", body=body, authenticated=True).allowed, i


def _waf_policy(tmp_path, monkeypatch, clock):
    f = tmp_path / "active-scope.yaml"
    f.write_text("program: p\nplatform: x\nin_scope: [a.t, b.t]\n")
    monkeypatch.setattr(pol, "_now", lambda: clock[0])
    return Policy(f)


def test_repeated_waf_pauses_only_that_host(tmp_path, monkeypatch):
    clock = [1_000_000.0]
    p = _waf_policy(tmp_path, monkeypatch, clock)
    for _ in range(pol.WAF_LIMIT - 1):
        p.penalize("a.t", waf=True)
        clock[0] += 10
    assert req(p, "https://a.t/", "a.t").allowed  # two challenges: slowed down, not paused
    p.penalize("A.T.", waf=True)
    v = req(p, "https://a.t/x", "a.t")
    assert not v.allowed and v.reason.startswith("waf-cooldown: a.t until ") and v.rule == "waf-cooldown"
    assert not req(p, "https://a.t/u/1", "a.t", "DELETE", identity="user-a").allowed  # an identity changes nothing
    assert not p.classify_connect("a.t", 443).allowed
    assert req(p, "https://b.t/", "b.t").allowed
    clock[0] += pol.WAF_COOLDOWN_S + 1
    assert req(p, "https://a.t/", "a.t").allowed and p.classify_connect("a.t", 443).allowed


def test_waf_answers_spread_over_the_window_do_not_pause(tmp_path, monkeypatch):
    clock = [1_000_000.0]
    p = _waf_policy(tmp_path, monkeypatch, clock)
    for _ in range(2 * pol.WAF_LIMIT):
        p.penalize("a.t", waf=True)
        clock[0] += pol.WAF_WINDOW_S / (pol.WAF_LIMIT - 1) + 1
    assert req(p, "https://a.t/", "a.t").allowed
    for _ in range(pol.WAF_LIMIT):
        p.penalize("a.t")  # 429 / 503 without a challenge: global slowdown only
    assert req(p, "https://a.t/", "a.t").allowed
    assert p.target_rps() == max(pol.MIN_RPS, p.scope.rate * pol.BACKOFF_FACTOR)


def test_waf_pause_never_touches_passive_or_system_hosts(tmp_path, monkeypatch):
    p = _waf_policy(tmp_path, monkeypatch, [1_000_000.0])
    for host in ("web.archive.org", "api.anthropic.com"):
        for _ in range(pol.WAF_LIMIT):
            p.penalize(host, waf=True)
    assert not p.host_blocked_until
    assert req(p, "https://web.archive.org/cdx?url=a.t", "web.archive.org").allowed


# ------------------------------------------------------------------ Claude API relay: who may use it
@pytest.fixture
def addon(monkeypatch):
    """bh.gate.addon without mitmproxy (only in the gate image): stub modules, umask restored after import."""
    import importlib
    import sys
    import types
    from unittest import mock

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
    monkeypatch.setattr(mod, "_RELAY_IPS", (0.0, {}))
    yield mod
    sys.modules.pop("bh.gate.addon", None)


def _dns(table):
    def getaddrinfo(host, port):
        if host not in table:
            raise OSError("unknown host")
        return [(2, 1, 6, "", (ip, port)) for ip in table[host]]

    return getaddrinfo


def test_relay_admits_the_agent_the_judge_and_the_auditor_only(addon, monkeypatch):
    assert addon.RELAY_CLIENT_HOSTS == ("agent", "judge", "audit")
    dns = _dns({"agent": ["10.89.0.5"], "judge": ["10.89.0.6"], "juiceshop": ["10.231.0.10"]})
    allowed = addon.resolve_hosts(addon.RELAY_CLIENT_HOSTS, dns)  # the auditor is down: no address, nothing admitted
    assert allowed == {"10.89.0.5", "10.89.0.6"}
    assert addon.relay_client_allowed("10.89.0.5", allowed)
    assert addon.relay_client_allowed("10.89.0.6", allowed)
    for peer in ("10.231.0.10", "127.0.0.1", "", "?"):  # the lab target, the gate itself, no peer
        assert not addon.relay_client_allowed(peer, allowed)
    monkeypatch.setattr(addon.socket, "getaddrinfo", dns)
    assert addon._relay_peer_ok("10.89.0.6") and not addon._relay_peer_ok("10.231.0.10")


def test_a_judge_that_is_down_does_not_cost_the_agent_the_relay(addon):
    allowed = addon.resolve_hosts(("agent", "judge"), _dns({"agent": ["10.89.0.5"]}))
    assert allowed == {"10.89.0.5"}


def test_a_recreated_judge_is_admitted_after_one_fresh_lookup(addon, monkeypatch):
    table = {"agent": ["10.89.0.5"], "judge": ["10.89.0.6"]}
    monkeypatch.setattr(addon.socket, "getaddrinfo", _dns(table))
    assert addon._relay_peer_ok("10.89.0.6")
    table["judge"] = ["10.89.0.9"]  # recreated with another IP, the cache still holds the old one
    clock = [addon.time.time()]
    monkeypatch.setattr(addon.time, "time", lambda: clock[0])
    assert not addon._relay_peer_ok("10.89.0.9")  # within the retry delay: no lookup storm from refused peers
    clock[0] += addon.RELAY_IPS_RETRY + 1
    assert addon._relay_peer_ok("10.89.0.9") and not addon._relay_peer_ok("10.89.0.6")


def test_prefixed_random_ids_are_ids():
    from bh.agent.contract import ID_SEGMENT

    assert ID_SEGMENT.match("bk_6c49e125463f") and ID_SEGMENT.match("ord-9f3a2b7c11")
    assert not ID_SEGMENT.match("user_settings") and not ID_SEGMENT.match("api")
