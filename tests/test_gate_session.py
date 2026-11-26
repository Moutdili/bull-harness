import json
import os
import stat
import threading

import pytest

from bh.gate import session as s

NOW = 1_800_000_000.0
URL = "https://app.example.com/account/settings"


def _file(tmp_path, content=None):
    p = tmp_path / "identities" / "p" / "user-a.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(content if content is not None else {"headers": {"X-Api": "k"}}))
    p.chmod(0o600)
    return p


def test_old_session_file_still_loads(tmp_path):
    sess = s.load(_file(tmp_path, {"headers": {"Authorization": "Bearer t"}, "updated": 1}), NOW)
    assert sess["headers"] == {"Authorization": "Bearer t"}
    assert sess["cookies"] == {} and sess["expires_at"] is None and sess["probe"] is None
    assert s.cookies_for(sess, URL, NOW) == []


def test_set_cookie_under_identity_in_scope_updates_the_jar(tmp_path):
    p = _file(tmp_path)
    assert s.absorb(p, URL, ["sid=abc; Path=/; HttpOnly; Secure", "pref=1"], in_scope=True, now=NOW)
    sess = s.load(p, NOW)
    assert sess["headers"] == {"X-Api": "k"}  # untouched
    assert sess["cookies"]["app.example.com"]["sid"] == {
        "value": "abc",
        "path": "/",
        "expires": None,
        "host_only": True,
        "secure": True,
    }
    assert sess["cookies"]["app.example.com"]["pref"]["path"] == "/account"  # RFC 6265 default path
    assert sess["updated"] == NOW
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert [f.name for f in p.parent.glob("*.json")] == ["user-a.json"]  # no temp file left as an identity


def test_out_of_scope_or_without_identity_leaves_the_file_intact(tmp_path):
    p = _file(tmp_path)
    before = p.read_bytes(), os.stat(p).st_mtime_ns
    assert not s.absorb(p, URL, ["sid=abc"], in_scope=False, now=NOW)
    assert not s.absorb(None, URL, ["sid=abc"], in_scope=True, now=NOW)
    assert not s.absorb(p, URL, [], in_scope=True, now=NOW)
    assert (p.read_bytes(), os.stat(p).st_mtime_ns) == before


def test_missing_or_broken_file_is_never_created(tmp_path):
    p = tmp_path / "gone.json"
    assert not s.absorb(p, URL, ["sid=abc"], in_scope=True, now=NOW)
    assert not p.exists()
    p.write_text("not json")
    assert not s.absorb(p, URL, ["sid=abc"], in_scope=True, now=NOW)
    assert p.read_text() == "not json"


def test_expiry_max_age_and_expires():
    sess = s.normalize({"headers": {}}, NOW)
    s.merge(sess, URL, ["a=1; Max-Age=60", "b=2; Expires=Wed, 21 Oct 2099 07:28:00 GMT", "c=3; Max-Age=60"], NOW)
    jar = sess["cookies"]["app.example.com"]
    assert jar["a"]["expires"] == NOW + 60 and jar["b"]["expires"] > NOW
    # Max-Age wins over Expires; Max-Age=0 and a past Expires delete
    s.merge(
        sess, URL, ["a=1; Max-Age=0", "b=x; Expires=Thu, 01-Jan-1970 00:00:00 GMT", "c=3; Max-Age=5; Expires=x"], NOW
    )
    assert set(sess["cookies"]["app.example.com"]) == {"c"}
    assert s.cookies_for(sess, URL, NOW + 4) == [("c", "3")]
    assert s.cookies_for(sess, URL, NOW + 6) == []  # expired: not sent
    assert s.expire(sess, NOW + 6) and sess["cookies"] == {}  # and dropped


def test_expired_cookie_is_dropped_on_load(tmp_path):
    p = _file(tmp_path, {"headers": {}, "cookies": {"app.example.com": {"old": {"value": "1", "expires": NOW - 1}}}})
    assert s.load(p, NOW)["cookies"] == {}


def test_domain_of_another_site_or_a_public_suffix_is_ignored():
    sess = s.normalize({"headers": {}}, NOW)
    changed = s.merge(
        sess,
        URL,
        [
            "evil=1; Domain=evil.example.net",
            "sub=1; Domain=other.app.example.com",
            "psl=1; Domain=com",
            "ok=1; Domain=example.com",
        ],
        NOW,
    )
    assert changed == ["ok"]
    assert sess["cookies"] == {
        "example.com": {"ok": {"value": "1", "path": "/account", "expires": None, "host_only": False, "secure": False}}
    }


def test_secure_cookie_is_not_set_from_http():
    sess = s.normalize({"headers": {}}, NOW)
    assert s.merge(sess, "http://app.example.com/", ["sid=1; Secure"], NOW) == []


def test_cookie_header_only_for_matching_urls():
    sess = s.normalize(
        {
            "headers": {},
            "cookies": {
                "app.example.com": {
                    "host": {"value": "h", "path": "/", "host_only": True},
                    "api": {"value": "a", "path": "/api", "host_only": True},
                    "sec": {"value": "s", "path": "/", "host_only": True, "secure": True},
                },
                ".example.com": {"wide": {"value": "w", "path": "/"}},  # browser export: leading dot
            },
        },
        NOW,
    )
    assert s.cookies_for(sess, "https://app.example.com/api/v1", NOW) == [
        ("api", "a"),
        ("host", "h"),
        ("sec", "s"),
        ("wide", "w"),
    ]
    assert s.cookies_for(sess, "https://app.example.com/apix", NOW) == [("host", "h"), ("sec", "s"), ("wide", "w")]
    assert s.cookies_for(sess, "http://app.example.com/", NOW) == [("host", "h"), ("wide", "w")]  # no Secure on http
    assert s.cookies_for(sess, "https://x.app.example.com/", NOW) == [("wide", "w")]  # host-only stays on its host
    assert s.cookies_for(sess, "https://notexample.com/", NOW) == []
    assert s.cookies_for(sess, "https://evil.example.net/", NOW) == []


def test_identity_cookies_win_over_the_agent_ones_with_the_same_name():
    cookie, replaced = s.combine("sid=agent; theme=dark", [("sid", "jar"), ("csrf", "c")])
    assert cookie == "sid=jar; csrf=c; theme=dark" and replaced == ["sid"]
    assert s.combine(None, [("sid", "jar")]) == ("sid=jar", [])
    assert s.combine("a=1", []) == ("a=1", [])


def test_set_cookie_masked_for_the_agent():
    masked = s.mask_set_cookie("sid=abc123; Path=/; HttpOnly; SameSite=Lax", "<identity:user-a>")
    assert masked == "sid=<identity:user-a>; Path=/; HttpOnly; SameSite=Lax" and "abc123" not in masked


@pytest.mark.parametrize(
    ("method", "url", "status", "location", "expected"),
    [
        ("GET", URL, 401, None, None),  # one 401 is an access rule, not a dead session (H4)
        ("GET", URL, 302, "/login?next=/account", "login-redirect"),
        ("POST", URL, 303, "https://app.example.com/login/", "login-redirect"),
        ("GET", URL, 302, "/dashboard", None),
        ("GET", URL, 302, "https://evil.example.net/login", None),
        ("GET", URL, 200, "/login", None),
        ("GET", "https://app.example.com/api/me", 403, None, "probe"),
        ("GET", "https://app.example.com/api/me", 200, None, None),
        ("POST", "https://app.example.com/api/me", 403, None, None),
        ("GET", URL, 403, None, None),
    ],
)
def test_session_dead(method, url, status, location, expected):
    probe = {"url": "https://app.example.com/api/me", "status": 200}
    got = s.dead_reason(method, url, status, location, login_url="https://app.example.com/login", probe=probe)
    assert got == expected


def test_redirect_without_declared_login_url_is_not_dead():
    assert s.dead_reason("GET", URL, 302, "/login", login_url=None) is None


def test_a_single_401_or_401s_on_one_route_never_kill_the_session():
    """H4: the control of an access test answers 401 to a live session; only distinct routes count."""
    u = s.Unauthorized()
    for i in range(10):  # an IDOR test over many ids is one route (/u/{id})
        assert u.hit("user-a", f"https://app.example.com/api/u/{i}", NOW + i) is None
    assert u.hit("user-a", "https://app.example.com/api/orders", NOW + 20) is None
    assert u.hit("user-b", "https://app.example.com/api/me", NOW + 21) is None  # per identity
    assert u.hit("user-a", "https://app.example.com/api/me/", NOW + 30) == 3


def test_401_on_routes_spread_over_more_than_the_window_do_not_count():
    u = s.Unauthorized()
    assert u.hit("user-a", "https://app.example.com/a", NOW) is None
    assert u.hit("user-a", "https://app.example.com/b", NOW + 300) is None
    assert u.hit("user-a", "https://app.example.com/c", NOW + s.UNAUTH_WINDOW_S + 1) is None  # /a has expired
    assert u.hit("user-a", "https://other.example.com/a", NOW + s.UNAUTH_WINDOW_S + 2) == 3  # another host
    assert u.hit("user-a", "https://app.example.com/d", NOW + s.UNAUTH_WINDOW_S + 3) is None  # starts over


def test_identity_headers_only_go_to_the_identity_origins():
    """M7: a bearer token is not handed to another host of the scope."""
    decl = {
        "name": "user-a",
        "login_url": "https://app.example.com/login",
        "probe": {"url": "https://api.example.com/me", "status": 200},
        "enroll": {"login": {"url": "https://auth.example.com:8443/token"}},
        "origins": ["https://cdn.example.com"],
    }
    assert s.identity_origins(decl) == {
        "https://app.example.com:443",
        "https://api.example.com:443",
        "https://auth.example.com:8443",
        "https://cdn.example.com:443",
    }
    assert s.headers_go_to(decl, "https://api.example.com/v1/orders?x=1")
    assert not s.headers_go_to(decl, "https://echo.example.com/headers")
    assert not s.headers_go_to(decl, "http://app.example.com/")  # another scheme is another origin
    assert not s.headers_go_to(decl, "https://auth.example.com/")  # another port too
    # nothing declared: the old behaviour (every in-scope host), documented
    assert s.identity_origins({"name": "user-a"}) == frozenset()
    assert s.headers_go_to({"name": "user-a"}, "https://echo.example.com/")
    assert s.headers_go_to(None, "https://echo.example.com/")


def test_a_parent_domain_cookie_never_passes_ahead_of_the_session_cookie():
    """B12 (a): another host of the scope sets sid for the parent domain with a longer Path."""
    sess = s.normalize({"headers": {}}, NOW)
    s.merge(sess, "https://app.example.com/login", ["sid=mine; Path=/"], NOW)
    s.merge(sess, "https://blog.example.com/x", ["sid=theirs; Domain=example.com; Path=/api/", "t=1; Path=/"], NOW)
    got = s.cookies_for(sess, "https://app.example.com/api/orders", NOW)
    assert got[0] == ("sid", "mine") and ("sid", "theirs") not in got
    assert s.cookies_for(sess, "https://shop.example.com/api/x", NOW) == [("sid", "theirs")]


def test_session_dead_at_most_once_a_minute_per_identity():
    lim = s.DeadLimiter()
    assert lim.allow("user-a", NOW)
    assert not lim.allow("user-a", NOW + 59)
    assert lim.allow("user-b", NOW + 1)
    assert lim.allow("user-a", NOW + 60)


def test_concurrent_merges_lose_nothing(tmp_path):
    p = _file(tmp_path)
    threads = [
        threading.Thread(target=s.absorb, args=(p, URL, [f"c{i}={i}; Path=/"]), kwargs={"in_scope": True, "now": NOW})
        for i in range(20)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert set(s.load(p, NOW)["cookies"]["app.example.com"]) == {f"c{i}" for i in range(20)}


def test_hostile_target_cannot_grow_the_jar_without_bound():
    sess = s.normalize({"headers": {}}, NOW)
    s.merge(sess, URL, [f"c{i}=1" for i in range(500)] + ["big=" + "x" * 5000, "bad name=1", "noequals"], NOW)
    assert len(sess["cookies"]["app.example.com"]) == s.MAX_COOKIES_PER_DOMAIN
