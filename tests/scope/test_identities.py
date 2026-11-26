from pathlib import Path

import pytest

from bh.scope import ScopeError, load_scope, scope_from_dict

DEMO = Path(__file__).resolve().parents[2] / "scopes" / "examples" / "demo.yaml"


def _doc(*identities):
    return {
        "schema": 1,
        "program": "p",
        "platform": "local",
        "in_scope": ["app.example.com"],
        "out_of_scope": ["https://app.example.com/admin/"],
        "identities": list(identities),
    }


def test_existing_scope_files_still_load():
    assert load_scope(DEMO).identities == ({"name": "user-a", "secret_ref": "secrets/demo/user-a"},)


def test_login_and_probe_are_declared():
    ident = {
        "name": "user-a",
        "secret_ref": "secrets/p/user-a",
        "login_url": "https://app.example.com/login",
        "signup_url": "https://app.example.com/register",
        "probe": {"url": "https://app.example.com/api/me", "status": 200},
    }
    assert scope_from_dict(_doc(ident)).identities == (ident,)


@pytest.mark.parametrize("key", ["password", "Password", "secret", "totp", "totp_secret", "token", "api_key"])
def test_a_secret_in_the_scope_file_is_refused(key):
    with pytest.raises(ScopeError, match="secret"):
        scope_from_dict(_doc({"name": "user-a", key: "hunter2"}))


@pytest.mark.parametrize(
    "ident",
    [
        {"name": "user-a", "login_url": "https://evil.example.net/login"},
        {"name": "user-a", "login_url": "https://app.example.com/admin/login"},  # out_of_scope prefix
        {"name": "user-a", "probe": {"url": "https://other.example.org/me", "status": 200}},
        {"name": "user-a", "signup_url": "https://evil.example.net/"},
    ],
)
def test_identity_urls_must_be_in_scope(ident):
    with pytest.raises(ScopeError, match="not in scope"):
        scope_from_dict(_doc(ident))


@pytest.mark.parametrize(
    "ident",
    [
        {"name": "user-a", "probe": {"url": "https://app.example.com/me"}},
        {"name": "user-a", "probe": {"url": "https://app.example.com/me", "status": "200"}},
        {"name": "user-a", "probe": {"url": "https://app.example.com/me", "status": True}},
        {"name": "user-a", "probe": {"url": "https://app.example.com/me", "status": 200, "expect": ""}},
        {"name": "user-a", "probe": {"url": "https://app.example.com/me", "status": 200, "other": 1}},
        {"name": "user-a", "enroll": {"headers": {"X": "y"}}},
        {"name": "user-a", "login_url": "ftp://app.example.com/"},
        {"name": "../x"},
        {"name": "user-a", "role": "admin@A"},
        {"name": "user-a", "tenant": ""},
        {"name": "user-a", "role": 1},
        "user-a",
    ],
)
def test_malformed_identities_are_refused(ident):
    with pytest.raises(ScopeError):
        scope_from_dict(_doc(ident))


def test_identity_names_are_unique():
    with pytest.raises(ScopeError, match="share a name"):
        scope_from_dict(_doc({"name": "a"}, {"name": "a"}))


def test_probe_may_expect_a_text_in_the_body():
    probe = {"url": "https://app.example.com/api/me", "status": 200, "expect": '"email"'}
    assert scope_from_dict(_doc({"name": "user-a", "probe": probe})).identities[0]["probe"] == probe


def test_identity_origins_are_urls_in_scope():
    import pytest

    from bh.scope import ScopeError, scope_from_dict

    base = {"program": "p", "platform": "x", "in_scope": ["*.example.com"]}
    ok = {**base, "identities": [{"name": "a", "origins": ["https://api.example.com"]}]}
    assert scope_from_dict(ok).identities[0]["origins"] == ["https://api.example.com"]
    for bad in (["https://evil.test"], [], "https://api.example.com", ["ftp://api.example.com"]):
        with pytest.raises(ScopeError):
            scope_from_dict({**base, "identities": [{"name": "a", "origins": bad}]})


def test_role_and_tenant_are_short_labels_never_secrets():
    scope = scope_from_dict(_doc({"name": "admin-a", "role": "admin", "tenant": "A"}, {"name": "guest"}))
    assert scope.identities[0]["role"] == "admin" and scope.identities[0]["tenant"] == "A"
    assert "role" not in scope.identities[1]
    for bad in ({"role": "admin,x"}, {"tenant": "A=B"}, {"role": "x" * 33}):
        with pytest.raises(ScopeError):
            scope_from_dict(_doc({"name": "a", **bad}))
