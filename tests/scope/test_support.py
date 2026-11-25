"""`support` hosts and the `websockets` field of a scope: parsing, overlap with targets, enforce's third answer."""

import pytest

from bh.scope import ScopeError, check, scope_from_dict
from bh.scope.enforce import check_support_resolved, patterns_overlap

BASE = {"schema": 1, "program": "t", "platform": "test", "in_scope": ["app.example.com", "*.api.example.com"]}


def scope(**over):
    return scope_from_dict({**BASE, **over})


def test_support_entries_parse_and_answer_apart():
    s = scope(
        support=[
            {"value": "cdn.example.net", "kind": "assets", "note": "scripts"},
            {"value": "*.auth.example.org", "kind": "auth"},
        ]
    )
    d = check(s, "https://cdn.example.net/a.js")
    assert not d.allowed and d.support == "assets" and d.rule is None  # neither a target nor an exclusion
    d = check(s, "https://x.auth.example.org/login")
    assert not d.allowed and d.support == "auth"
    assert check(s, "https://auth.example.org/").support is None  # `*.x` never covers the apex
    assert check(s, "https://app.example.com/").allowed
    assert check(s, "https://other.net/").support is None


@pytest.mark.parametrize(
    "value",
    [
        "app.example.com",  # same host as a target
        "v1.api.example.com",  # under a target wildcard
        "*.example.com",  # covers a target
        "*.api.example.com",
        "ap*.example.com",  # one label under example.com that matches the target `app`
    ],
)
def test_support_that_overlaps_a_target_is_refused(value):
    with pytest.raises(ScopeError, match="overlaps in_scope"):
        scope(support=[{"value": value, "kind": "assets"}])


def test_support_against_url_rules_and_between_kinds():
    with pytest.raises(ScopeError, match="overlaps in_scope"):
        scope_from_dict(
            {
                **BASE,
                "in_scope": ["https://cdn.example.net/app/"],
                "support": [{"value": "cdn.example.net", "kind": "assets"}],
            }
        )
    with pytest.raises(ScopeError, match="both auth and assets"):
        scope(support=[{"value": "*.x.net", "kind": "auth"}, {"value": "a.x.net", "kind": "assets"}])


@pytest.mark.parametrize(
    "entry, match",
    [
        ({"value": "cdn.example.net", "kind": "scripts"}, "kind"),
        ({"value": "cdn.example.net"}, "kind"),
        ({"value": "https://cdn.example.net/x", "kind": "assets"}, "domain or a wildcard"),
        ({"value": "10.0.0.0/8", "kind": "assets"}, "domain or a wildcard"),
        ({"value": "cdn.example.net", "kind": "assets", "methods": ["POST"]}, "unknown support keys"),
        ("cdn.example.net", "mapping"),
        ({"value": "*.co.uk", "kind": "assets"}, "public suffix"),
    ],
)
def test_bad_support_entries(entry, match):
    with pytest.raises(ScopeError, match=match):
        scope(support=[entry])


def test_websockets_field():
    assert not scope().websockets_on
    assert not scope(websockets=None).websockets_on
    assert not scope(websockets=False).websockets_on
    assert scope(websockets=True).websockets_on
    with pytest.raises(ScopeError, match="websockets"):
        scope(websockets="yes")


def test_login_urls_may_be_auth_support_but_probe_and_origins_may_not():
    sup = [{"value": "login.example.org", "kind": "auth"}, {"value": "cdn.example.net", "kind": "assets"}]
    ok = scope(support=sup, identities=[{"name": "a", "login_url": "https://login.example.org/"}])
    assert ok.identities[0]["login_url"]
    with pytest.raises(ScopeError, match=r"probe\.url"):
        scope(support=sup, identities=[{"name": "a", "probe": {"url": "https://login.example.org/me", "status": 200}}])
    with pytest.raises(ScopeError, match="origins"):
        scope(support=sup, identities=[{"name": "a", "origins": ["https://login.example.org/"]}])
    with pytest.raises(ScopeError, match="login_url"):  # an assets host is no login host
        scope(support=sup, identities=[{"name": "a", "login_url": "https://cdn.example.net/"}])


def test_browser_login_derived_origins_keep_targets_only():
    recipe = {
        "kind": "browser",
        "steps": [{"goto": "https://login.example.org/"}, {"goto": "https://app.example.com/"}],
    }
    s = scope(support=[{"value": "login.example.org", "kind": "auth"}], identities=[{"name": "a", "enroll": recipe}])
    assert s.identities[0]["origins"] == ["https://app.example.com:443/"]


def test_support_resolution_public_only():
    s = scope(support=[{"value": "cdn.example.net", "kind": "assets"}], out_of_scope=["203.0.113.0/24"])
    assert check_support_resolved(s, "cdn.example.net", "93.184.216.34").allowed
    assert not check_support_resolved(s, "cdn.example.net", "10.1.2.3").allowed
    assert not check_support_resolved(s, "cdn.example.net", "203.0.113.9").allowed
    assert not check_support_resolved(s, "app.example.com", "93.184.216.34").allowed  # a target is not support


@pytest.mark.parametrize(
    "a, b, overlap",
    [
        ("a.x.com", "a.x.com", True),
        ("a.x.com", "*.x.com", True),
        ("x.com", "*.x.com", False),
        ("*.x.com", "*.y.x.com", True),
        ("*.x.com", "*.y.com", False),
        ("api-*.x.com", "*.x.com", True),
        ("api-*.x.com", "*.a.x.com", False),
        ("api-*.x.com", "api-1.x.com", True),
        ("api-*.x.com", "web-1.x.com", False),
    ],
)
def test_patterns_overlap(a, b, overlap):
    assert patterns_overlap(a, b) is overlap and patterns_overlap(b, a) is overlap


# ------------------------------------------------------------------ sso and passthrough
def test_sso_with_token_paths_and_passthrough_parse():
    s = scope(
        support=[
            {"value": "login.example.org", "kind": "sso", "token_paths": ["/*/oauth2/v2.0/token", "/token.srf"]},
            {"value": "challenges.example.net", "kind": "passthrough", "note": "anti-bot"},
            {"value": "sso-nopost.example.org", "kind": "sso"},
        ]
    )
    sso, pt, bare = s.support
    assert (sso.kind, sso.token_paths) == ("sso", ("/*/oauth2/v2.0/token", "/token.srf"))
    assert sso.token_path("/common/oauth2/v2.0/token") and sso.token_path("/token.srf")
    assert not sso.token_path("/common/oauth2/v2.0/authorize") and not sso.token_path("/../oauth2/v2.0/token")
    assert not sso.token_path("/common/oauth2/v2.0/token/") and not sso.token_path("/a/b/oauth2/v2.0/token")
    assert pt.kind == "passthrough" and pt.token_paths == () and bare.token_paths == ()
    assert not bare.token_path("/token.srf")  # no token path declared: no POST at all
    assert check(s, "https://login.example.org/x").support == "sso"
    assert check(s, "challenges.example.net:443").support == "passthrough"
    assert s.support_hosts("passthrough") == ("challenges.example.net",)


@pytest.mark.parametrize(
    "entry, match",
    [
        ({"value": "*.login.example.org", "kind": "sso"}, "one exact domain"),
        ({"value": "*.challenges.example.net", "kind": "passthrough"}, "one exact domain"),
        ({"value": "cdn.example.net", "kind": "assets", "token_paths": ["/t"]}, "sso"),
        ({"value": "c.example.net", "kind": "passthrough", "token_paths": ["/t"]}, "sso"),
        ({"value": "l.example.org", "kind": "sso", "token_paths": "/token"}, "token_paths"),
        ({"value": "l.example.org", "kind": "sso", "token_paths": []}, "token_paths"),
        ({"value": "l.example.org", "kind": "sso", "token_paths": ["token"]}, "token_paths"),
        ({"value": "l.example.org", "kind": "sso", "token_paths": ["/a/../token"]}, "token_paths"),
        ({"value": "l.example.org", "kind": "sso", "token_paths": ["/a*b/token"]}, "token_paths"),
        ({"value": "l.example.org", "kind": "sso", "token_paths": ["/token?x=1"]}, "token_paths"),
        ({"value": "l.example.org", "kind": "sso", "token_paths": ["/"]}, "token_paths"),
    ],
)
def test_bad_sso_and_passthrough_entries(entry, match):
    with pytest.raises(ScopeError, match=match):
        scope(support=[entry])


@pytest.mark.parametrize(
    "support, match",
    [
        ([{"value": "app.example.com", "kind": "sso"}], "overlaps in_scope"),
        ([{"value": "v1.api.example.com", "kind": "passthrough"}], "overlaps in_scope"),
        (
            [{"value": "*.example.org", "kind": "auth"}, {"value": "login.example.org", "kind": "sso"}],
            "both auth and sso",
        ),
        (
            [{"value": "c.example.net", "kind": "passthrough"}, {"value": "*.example.net", "kind": "assets"}],
            "both passthrough and assets",
        ),
        (
            [{"value": "l.example.org", "kind": "sso"}, {"value": "l.example.org", "kind": "passthrough"}],
            "both sso and passthrough",
        ),
    ],
)
def test_sso_and_passthrough_never_overlap_a_target_or_another_kind(support, match):
    with pytest.raises(ScopeError, match=match):
        scope(support=support)


def test_login_urls_may_be_sso_support():
    sup = [{"value": "login.example.org", "kind": "sso"}, {"value": "c.example.net", "kind": "passthrough"}]
    assert scope(support=sup, identities=[{"name": "a", "login_url": "https://login.example.org/"}])
    with pytest.raises(ScopeError, match="login_url"):  # a challenge host is never a login
        scope(support=sup, identities=[{"name": "a", "login_url": "https://c.example.net/"}])
    with pytest.raises(ScopeError, match="origins"):  # an identity's headers never go to an sso host
        scope(support=sup, identities=[{"name": "a", "origins": ["https://login.example.org/"]}])
