import asyncio
import os
import shutil
import time
from pathlib import Path

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


def test_system_only_the_claude_api_on_443(tmp_path):
    p = _policy(tmp_path, with_scope=False)
    assert p.classify_connect("api.anthropic.com", 443).klass == "system"
    assert not p.classify_connect("api.anthropic.com", 22).allowed
    assert not p.classify_connect("claude.ai", 443).allowed
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
    assert not req(p, "https://web.archive.org/cdx", "web.archive.org", has_body=True).allowed
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
