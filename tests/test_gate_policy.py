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
    for i in range(1, 5):
        assert req(p, url.format(i), "a.example.com", authenticated=True).allowed, i
    v = req(p, url.format(5), "a.example.com", authenticated=True)
    assert not v.allowed and "enumeration" in v.reason
    assert req(p, url.format(2), "a.example.com", authenticated=True).allowed  # an id already seen
    for i in range(1, 9):  # public, non-API pages (blog posts, products) are not limited
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
    for i in range(1, 5):
        assert req(p, f"https://a.example.com/api/baskets/{i}", "a.example.com", authenticated=True).allowed
    for variant in ("/api/baskets/5/", "/API/baskets/6", "/api//baskets/7", "/api/baskets/8;x=1", "/api/baskets/%39"):
        v = req(p, "https://a.example.com" + variant, "a.example.com", authenticated=True)
        assert not v.allowed and "enumeration" in v.reason, variant


def test_id_enumeration_in_query_body_and_graphql(tmp_path):
    p = _policy(tmp_path)
    host = "a.example.com"
    for i in range(1, 5):
        assert req(p, f"https://{host}/api/order?id={i}&page=2", host).allowed, i
    v = req(p, f"https://{host}/api/order?id=5&page=2", host)
    assert not v.allowed and "?id" in v.reason
    assert req(p, f"https://{host}/api/order?id=3&page=9", host).allowed  # an id already seen, other params free

    for i in range(1, 5):
        assert req(p, f"https://{host}/api/cart", host, "POST", body=b'{"cart": {"basketId": %d}}' % i).allowed
    assert not req(p, f"https://{host}/api/cart", host, "POST", body=b'{"cart": {"basketId": 5}}').allowed

    gql = b'{"query": "query { user(id: %d) { email } }"}'
    for i in range(1, 5):
        assert req(p, f"https://{host}/graphql", host, "POST", body=gql % i).allowed, i
    assert not req(p, f"https://{host}/graphql", host, "POST", body=gql % 5).allowed
    variables = b'{"query": "query($u: ID!) { user(id: $u) { email } }", "variables": {"userId": "%d"}}'
    for i in range(1, 5):
        assert req(p, f"https://{host}/graphql", host, "POST", body=variables % (100 + i)).allowed, i
    assert not req(p, f"https://{host}/graphql", host, "POST", body=variables % 200).allowed


def test_id_enumeration_batch_in_one_request(tmp_path):
    p = _policy(tmp_path)
    batch = b"[%s]" % b",".join(b'{"query": "{ user(id: %d) { email } }"}' % i for i in range(1, 7))
    v = req(p, "https://a.example.com/graphql", "a.example.com", "POST", body=batch)
    assert not v.allowed and "enumeration" in v.reason
    # anonymous, non-API pages stay free: search filters are not object reads
    for i in range(1, 9):
        assert req(p, f"https://a.example.com/shop?categoryId={i}", "a.example.com").allowed


def test_id_enumeration_in_a_form_body_when_authenticated(tmp_path):
    p = _policy(tmp_path)
    for i in range(1, 5):
        assert req(
            p,
            "https://a.example.com/account/show",
            "a.example.com",
            "POST",
            body=b"account_id=%d&x=1" % i,
            authenticated=True,
        ).allowed
    v = req(p, "https://a.example.com/account/show", "a.example.com", "POST", body=b"account_id=5", authenticated=True)
    assert not v.allowed and "?account_id" in v.reason
