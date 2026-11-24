from pathlib import Path

import pytest

from bh.scope import ScopeError, check, check_resolved, load_scope, scope_from_dict

DEMO = Path(__file__).resolve().parents[2] / "scopes" / "examples" / "demo.yaml"


@pytest.fixture(scope="module")
def s():
    return load_scope(DEMO)


@pytest.mark.parametrize(
    "target",
    [
        "https://a.example.com/",
        "https://deep.a.b.example.com/x",
        "https://example.com/",
        "EXAMPLE.COM.",
        "a.example.com:8443",
        "https://api.example.org/v2/users?id=1",
        "https://api.example.org/v2",
        "https://API.EXAMPLE.ORG:443/v2/x",
        "192.0.2.10",
        "http://192.0.2.10:8080/",
        "https://www.example.com/checkoutX",  # prefix is /checkout/, not /checkout*
    ],
)
def test_allowed(s, target):
    assert check(s, target).allowed, check(s, target)


@pytest.mark.parametrize(
    "target,why",
    [
        ("https://evil.com/", "not in scope"),
        ("https://example.com.evil.com/", "suffix trick"),
        ("https://evilexample.com/", "no dot boundary"),
        ("https://admin.example.com/", "out domain"),
        ("https://ADMIN.example.com./", "out domain, case + trailing dot"),
        ("https://x.corp.example.com/", "out wildcard"),
        ("https://www.example.com/checkout/pay", "out path"),
        ("https://www.example.com/a/../checkout/pay", "out path via dot segments"),
        ("https://www.example.com/%63heckout/pay", "out path via percent-encoding"),
        ("https://www.example.com//checkout/pay", "out path via double slash"),
        ("https://www.example.com\\checkout/pay", "backslash"),
        ("http://www.example.com/checkout/pay", "out path, other scheme"),
        ("https://www.example.com:8443/checkout/pay", "out path, other port"),
        ("https://api.example.org/v1/users", "path outside in-scope prefix"),
        ("https://api.example.org/v2/../v1/users", "dot segments escape prefix"),
        ("http://api.example.org/v2/", "scheme differs from rule"),
        ("https://api.example.org:8443/v2/", "port differs from rule"),
        ("192.0.2.66", "out IP"),
        ("https://192.0.2.66/", "out IP in URL"),
        ("198.51.100.1", "raw IP not in CIDR"),
        ("https://example.com@evil.com/", "userinfo trick"),
        ("https://evil.com\\@example.com/", "backslash userinfo trick"),
        ("https://evil.com @example.com/", "space in authority"),
        ("http://2130706433/", "decimal IPv4 (127.0.0.1)"),
        ("http://0x7f.1/", "hex IPv4"),
        ("http://[::1]/", "IPv6 loopback"),
        ("ftp://example.com/", "unsupported scheme"),
        ("", "empty"),
        ("example.com/path", "ambiguous bare path"),
    ],
)
def test_denied(s, target, why):
    assert not check(s, target).allowed, (target, why)


def test_out_url_with_path_does_not_ban_host_at_dns_layer(s):
    assert check(s, "www.example.com").allowed


def test_in_url_authorizes_host_at_dns_layer(s):
    assert check(s, "api.example.org").allowed
    assert check(s, "api.example.org:443").allowed
    assert not check(s, "api.example.org:22").allowed


def test_idn_is_punycoded():
    sc = scope_from_dict({"program": "p", "platform": "x", "in_scope": ["bücher.example"]})
    assert check(sc, "https://xn--bcher-kva.example/").allowed
    assert check(sc, "https://BÜCHER.example/").allowed


def test_resolved_public_ok(s):
    assert check_resolved(s, "a.example.com", "93.184.216.34").allowed


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "fd00::1", "0.0.0.0"])
def test_resolved_non_public_denied(s, ip):
    assert not check_resolved(s, "a.example.com", ip).allowed


def test_resolved_out_ip_denied(s):
    assert not check_resolved(s, "a.example.com", "192.0.2.66").allowed


def test_resolved_requires_authorized_host(s):
    assert not check_resolved(s, "evil.com", "93.184.216.34").allowed


def test_local_scope_allows_explicit_private_cidr():
    sc = scope_from_dict({"program": "mine", "platform": "local", "in_scope": ["127.0.0.1/32", "app.local.test"]})
    assert check(sc, "http://127.0.0.1:3000/").allowed
    assert check_resolved(sc, "app.local.test", "127.0.0.1").allowed
    assert not check_resolved(sc, "app.local.test", "10.0.0.1").allowed


@pytest.mark.parametrize(
    "doc,msg",
    [
        ({"program": "p", "platform": "x", "in_scope": []}, "non-empty"),
        ({"program": "p", "platform": "x", "in_scope": ["a.com"], "out_scope": []}, "unknown keys"),
        ({"program": "p", "platform": "x", "in_scope": ["acme.*"]}, "wildcard"),
        ({"program": "p", "platform": "x", "in_scope": ["*acme.com"]}, "wildcard"),
        ({"program": "p", "platform": "x", "in_scope": ["a.*.acme.com"]}, "wildcard"),
        ({"program": "p", "platform": "x", "in_scope": ["https://1.2.3.4/"]}, "cidr"),
        ({"program": "p", "platform": "x", "in_scope": [{"value": "a.com", "typ": "domain"}]}, "unknown rule keys"),
        ({"program": "p", "platform": "x", "in_scope": ["a.com"], "max_rps": 0}, "max_rps"),
        ({"program": "p", "platform": "x", "in_scope": ["a.com"], "schema": 2}, "schema"),
        ({"platform": "x", "in_scope": ["a.com"]}, "program"),
    ],
)
def test_invalid_scopes_fail_closed(doc, msg):
    with pytest.raises(ScopeError, match=msg):
        scope_from_dict(doc)


def test_repo_and_other_rules_never_match_network():
    sc = scope_from_dict(
        {
            "program": "p",
            "platform": "x",
            "in_scope": [{"type": "repo", "value": "github.com/a/b"}, {"type": "other", "value": "com.acme.app"}],
        }
    )
    assert not check(sc, "https://github.com/a/b").allowed


def test_digest_changes_with_content():
    a = scope_from_dict({"program": "p", "platform": "x", "in_scope": ["a.com"]})
    b = scope_from_dict({"program": "p", "platform": "x", "in_scope": ["b.com"]})
    assert a.digest != b.digest


def test_malformed_url_rules_are_scope_errors():
    import pytest

    from bh.scope import ScopeError, scope_from_dict

    for bad in ("https://[::1", "https://[::1]:x/", "https://a.example.com:99999/", "https://a.example.com:0/"):
        with pytest.raises(ScopeError):
            scope_from_dict({"program": "p", "platform": "x", "in_scope": [bad]})


def test_path_exclusion_variants():
    from bh.scope import check, scope_from_dict

    s = scope_from_dict(
        {
            "program": "p",
            "platform": "x",
            "in_scope": ["www.example.com", "https://api.example.com/v2/"],
            "out_of_scope": ["https://www.example.com/checkout/"],
        }
    )
    for p in (
        "/checkout/x",
        "/checkout;x/",
        "/CHECKOUT/",
        "/;/checkout/",
        "/checkout%252f",
        "/checkout.json",
        "/checkout",
        "/x/..;/checkout/",
    ):
        assert not check(s, "https://www.example.com" + p).allowed, p
    assert check(s, "https://www.example.com/checkouts-help").allowed  # not the excluded prefix
    for p in ("/v2/..;/admin", "/v2%2f..%2fadmin", "/v2/%2e%2e/admin"):
        assert not check(s, "https://api.example.com" + p).allowed, p
    assert check(s, "https://api.example.com/v2/users;jsessionid=1").allowed
