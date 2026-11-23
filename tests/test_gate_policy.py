import asyncio
import shutil
import time
from pathlib import Path

from bh.gate.policy import Policy, TokenBucket

DEMO = Path(__file__).resolve().parents[1] / "scopes" / "examples" / "demo.yaml"


def _policy(tmp_path, with_scope=True):
    p = tmp_path / "active-scope.yaml"
    if with_scope:
        shutil.copy(DEMO, p)
    return Policy(p)


def test_system_always_allowed_even_without_scope(tmp_path):
    pol = _policy(tmp_path, with_scope=False)
    assert pol.classify("api.anthropic.com:443", "api.anthropic.com").klass == "system"
    v = pol.classify("https://a.example.com/", "a.example.com")
    assert not v.allowed and "no active scope" in v.reason


def test_target_and_out_of_scope(tmp_path):
    pol = _policy(tmp_path)
    assert pol.classify("https://a.example.com/x", "a.example.com", "GET").klass == "target"
    v = pol.classify("https://admin.example.com/", "admin.example.com", "GET")
    assert not v.allowed and v.rule == "domain:admin.example.com"


def test_passive_get_only_and_never_target(tmp_path):
    pol = _policy(tmp_path)
    assert pol.classify("https://web.archive.org/cdx?url=example.com", "web.archive.org", "GET").klass == "passive"
    assert not pol.classify("https://web.archive.org/save", "web.archive.org", "POST").allowed
    assert pol.classify("web.archive.org:443", "web.archive.org").klass == "passive"


def test_unknown_host_denied(tmp_path):
    pol = _policy(tmp_path)
    assert not pol.classify("https://evil.com/", "evil.com", "GET").allowed


def test_resolved_ip_checks(tmp_path):
    pol = _policy(tmp_path)
    pol.reload()
    assert pol.check_ip("a.example.com", "93.184.216.34").allowed
    assert not pol.check_ip("a.example.com", "10.1.2.3").allowed
    assert pol.check_ip("web.archive.org", "10.1.2.3").allowed  # non-target: proxy-level only


def test_scope_hot_reload(tmp_path):
    pol = _policy(tmp_path)
    assert pol.classify("https://a.example.com/", "a.example.com").allowed
    p = tmp_path / "active-scope.yaml"
    p.write_text("program: other\nplatform: local\nin_scope: [other.test]\n")
    import os
    os.utime(p, (time.time() + 5, time.time() + 5))
    assert not pol.classify("https://a.example.com/", "a.example.com").allowed
    assert pol.program == "other"


def test_token_bucket_rate():
    async def go():
        b = TokenBucket(rps=20)
        t0 = time.monotonic()
        for _ in range(30):
            await b.take()
        return time.monotonic() - t0
    elapsed = asyncio.run(go())
    assert elapsed >= (30 - 20) / 20 * 0.9
