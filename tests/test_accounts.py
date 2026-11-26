"""Autonomous test accounts (issue 25): recipes, credentials, enroll / refresh / probe through a simulated gate."""

import ast
import json
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

from bh import paths, stack
from bh.accounts import enroll as en
from bh.accounts import recipe as rc
from bh.accounts import secrets
from bh.board import Board
from bh.cli import main
from bh.scope import ScopeError, load_scope, scope_from_dict

LAB = Path(__file__).resolve().parents[1] / "scopes" / "lab" / "juiceshop.yaml"
BASE = "http://app.test"
RECIPE = {
    "email": "bh-{name}-{rand}@example.test",
    "signup": {
        "method": "POST",
        "url": f"{BASE}/api/Users",
        "json": {"email": "{email}", "password": "{password}", "securityAnswer": "{answer}", "q": {"id": 1}},
    },
    "login": {"method": "POST", "url": f"{BASE}/rest/login", "json": {"email": "{email}", "password": "{password}"}},
    "token": "authentication.token",
    "headers": {"Authorization": "Bearer {token}", "Cookie": "token={token}"},
}
PROBE = {"url": f"{BASE}/rest/whoami", "status": 200, "expect": '"email"'}
TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjQxMDI0NDQ4MDB9.c2lnbmF0dXJlLXZhbHVl"  # exp 2100-01-01


def _scope(self_signup=True, **ident):
    return scope_from_dict(
        {
            "program": "p",
            "platform": "local",
            "in_scope": ["app.test"],
            "self_signup": self_signup,
            "identities": [{"name": "user-a", "probe": PROBE, "enroll": RECIPE, **ident}],
        }
    )


class FakeGate:
    """Stands for `podman exec -i bh-gate python3 -I -`: reads the steps from the script, answers from `plan`."""

    def __init__(self, *answers):
        self.answers = list(answers)  # one callable(step) -> record per step, in order
        self.calls: list[list[dict]] = []
        self.argv_seen: list[str] = []

    def __call__(self, script: str, timeout: float = 60):
        m = re.search(r"\nmain\((.*)\)\n$", script)
        steps = json.loads(ast.literal_eval(m.group(1)))["steps"]
        self.calls.append(steps)
        out = [self.answers.pop(0)(s) for s in steps]
        return subprocess.CompletedProcess([], 0, json.dumps(out), "")


def probe_ok(s):
    assert s["step"] == "probe" and s["headers"] == {"X-BH-Identity": "user-a", "X-BH-Probe": "1"}
    return {"step": "probe", "status": 200, "match": True}


def probe_bad(s):
    assert s["step"] == "probe"
    return {"step": "probe", "status": 200, "match": False}


def login_ok(s):
    assert s["step"] == "login"
    return {"step": "login", "status": 200, "token": TOKEN, "set_cookies": ["sid=abc; Path=/"]}


def signup_ok(s):
    assert s["step"] == "signup"
    return {"step": "signup", "status": 201}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    paths.state().mkdir(parents=True)
    paths.active_scope().write_text("program: p\n")
    return Board(paths.board_db())


def _gate(monkeypatch, *answers) -> FakeGate:
    fake = FakeGate(*answers)
    monkeypatch.setattr(stack, "gate_python", fake)
    return fake


# ---------------------------------------------------------------- recipe (pure)
def test_templates_render_and_unknown_placeholders_name_no_value():
    body = rc.render({"a": "{email}", "b": ["x{name}y", 3], "c": {"id": 1}}, {"email": "e@x", "name": "n"})
    assert body == {"a": "e@x", "b": ["xny", 3], "c": {"id": 1}}
    with pytest.raises(rc.RecipeError, match=r"\{password\}") as exc:
        rc.render("{password}", {"email": "hunter2"})
    assert "hunter2" not in str(exc.value)


def test_json_path():
    doc = {"authentication": {"token": "t", "list": [{"id": 7}]}}
    assert rc.json_path(doc, "authentication.token") == "t"
    assert rc.json_path(doc, "authentication.list.0.id") == 7
    assert rc.json_path(doc, "authentication.missing") is None
    assert rc.json_path(doc, "authentication.list.4") is None
    assert rc.json_path("not a dict", "a") is None


@pytest.mark.parametrize(
    "change, match",
    [
        ({"login": {**RECIPE["login"], "json": {"email": "{email}", "password": "hunter2"}}}, "literal"),
        ({"headers": {"Authorization": "Bearer abc123"}}, "literal"),
        ({"login": {**RECIPE["login"], "url": f"{BASE}/login?u={{email}}"}}, "no placeholder in a URL"),
        ({"login": {**RECIPE["login"], "method": "PUT"}}, "method"),
        ({"headers": {"Authorization": "Bearer {password}"}}, "unknown placeholders"),
        ({"token": None}, "token"),
    ],
)
def test_bad_recipes_are_refused(change, match):
    with pytest.raises(ScopeError, match=match):
        _scope(enroll={**RECIPE, **change})


def test_recipe_urls_must_be_in_scope():
    with pytest.raises(ScopeError, match=r"enroll\.login\.url"):
        _scope(enroll={**RECIPE, "login": {**RECIPE["login"], "url": "https://evil.example/login"}})


def test_self_signup_is_true_false_or_null():
    assert _scope(None).self_signup is None
    with pytest.raises(ScopeError, match="self_signup"):
        _scope("yes")


def test_lab_scope_is_valid():
    scope = load_scope(LAB)
    assert scope.self_signup is True
    assert [i["name"] for i in scope.identities] == ["user-a", "user-b", "user-c"]
    for ident in scope.identities:
        assert ident["probe"] == {"url": "http://10.231.0.10:3000/rest/user/whoami", "status": 200, "expect": '"email"'}
    user_c = scope.identities[2]["enroll"]
    assert user_c["kind"] == "browser" and user_c["steps"][0] == {
        "action": "goto",
        "url": "http://10.231.0.10:3000/#/login",
    }
    assert user_c["capture"]["local_storage"] == {"token": {"Authorization": "Bearer {value}"}}
    for ident in scope.identities[:2]:
        assert ident["enroll"]["kind"] == "json"
        assert ident["enroll"]["login"]["url"].endswith("/rest/user/login")
        assert ident["enroll"]["token"] == "authentication.token"
        assert ident["probe"] == {"url": "http://10.231.0.10:3000/rest/user/whoami", "status": 200, "expect": '"email"'}


# ---------------------------------------------------------------- credentials
def test_secrets_are_owner_only(env):
    cred = secrets.new("bh-{name}-{rand}@example.test", "user-a")
    assert re.fullmatch(r"bh-user-a-[0-9a-f]{6}@example\.test", cred["email"])
    p = secrets.save("p", "user-a", cred)
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert stat.S_IMODE(p.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE((paths.secrets_dir() / "identities").stat().st_mode) == 0o700
    assert secrets.load("p", "user-a") == cred


# ---------------------------------------------------------------- enroll / refresh
def test_enroll_signs_up_logs_in_and_writes_the_session(env, monkeypatch):
    fake = _gate(monkeypatch, signup_ok, login_ok, probe_ok)
    assert en.enroll(_scope(), "user-a", board=env) == "signed up, logged in, probe ok"
    cred = secrets.load("p", "user-a")
    signup, login = fake.calls[0]
    assert signup["json"]["password"] == cred["password"] and signup["json"]["q"] == {"id": 1}
    assert login["token_path"] == "authentication.token" and login["required"]
    sess = json.loads(paths.identities_dir("p").joinpath("user-a.json").read_text())
    assert sess["headers"] == {"Authorization": f"Bearer {TOKEN}", "Cookie": f"token={TOKEN}"}
    assert sess["cookies"] == {
        "app.test": {"sid": {"value": "abc", "path": "/", "expires": None, "host_only": True, "secure": False}}
    }
    assert sess["expires_at"] == 4102444800.0 and sess["probe"] == {"url": PROBE["url"], "status": 200}


@pytest.mark.parametrize("bad", ["abc\r\nX-Injected: 1", "has space", "é-token", "x" * 4097])
def test_a_token_outside_printable_ascii_fails_the_login_without_showing_it(env, monkeypatch, bad):
    def login_bad(s):
        return {"step": "login", "status": 200, "token": bad, "set_cookies": []}

    _gate(monkeypatch, signup_ok, login_bad)
    with pytest.raises(en.AccountError, match="printable ASCII") as exc:
        en.enroll(_scope(), "user-a", board=env)
    assert bad not in str(exc.value) and "X-Injected" not in str(exc.value)
    assert not paths.identities_dir("p").joinpath("user-a.json").exists()


def test_self_signup_null_refuses_to_create_an_account(env, monkeypatch):
    fake = _gate(monkeypatch)
    with pytest.raises(en.AccountError, match="self_signup is not true"):
        en.enroll(_scope(None), "user-a", board=env)
    assert fake.calls == [] and secrets.load("p", "user-a") is None


def test_enroll_needs_the_gate_on_this_program(env, monkeypatch):
    _gate(monkeypatch)
    paths.active_scope().write_text("program: other\n")
    with pytest.raises(en.AccountError, match="active scope is other"):
        en.enroll(_scope(), "user-a", board=env)


def _logged_in(env, monkeypatch):
    _gate(monkeypatch, signup_ok, login_ok, probe_ok)
    en.enroll(_scope(), "user-a", board=env)
    env.meta_set("accounts-login:user-a:p", "0")  # the hour has passed


def test_good_probe_does_not_log_in_again_and_lifts_a_false_stale_mark(env, monkeypatch):
    _logged_in(env, monkeypatch)
    f = paths.identities_dir("p") / "user-a.json"
    os.utime(f, (1000, 1000))
    env.meta_set("identity-stale:user-a:p", "2000")
    fake = _gate(monkeypatch, probe_ok)
    assert en.refresh(_scope(), "user-a", board=env) == "session ok"
    assert [s["step"] for c in fake.calls for s in c] == ["probe"]
    assert f.stat().st_mtime > 2000  # rewritten: the stale mark no longer applies
    assert json.loads(f.read_text())["headers"]["Authorization"] == f"Bearer {TOKEN}"


def test_bad_probe_logs_in_with_the_stored_secret(env, monkeypatch):
    _logged_in(env, monkeypatch)
    cred = secrets.load("p", "user-a")
    fake = _gate(monkeypatch, probe_bad, login_ok, probe_ok)
    assert en.refresh(_scope(), "user-a", board=env) == "logged in, probe ok"
    login = fake.calls[1][0]
    assert login["step"] == "login" and login["json"] == {"email": cred["email"], "password": cred["password"]}
    assert secrets.load("p", "user-a") == cred  # same account, no new sign-up


def test_one_login_per_hour(env, monkeypatch):
    _logged_in(env, monkeypatch)
    _gate(monkeypatch, probe_bad, login_ok, probe_ok, probe_bad)
    en.refresh(_scope(), "user-a", board=env)
    with pytest.raises(en.AccountError, match="at most one per hour"):
        en.refresh(_scope(), "user-a", board=env)


def test_failed_login_message_holds_no_secret(env, monkeypatch):
    _logged_in(env, monkeypatch)
    cred = secrets.load("p", "user-a")

    def login_401(s):
        return {"step": "login", "status": 401}

    _gate(monkeypatch, probe_bad, login_401)
    with pytest.raises(en.AccountError) as exc:
        en.refresh(_scope(False), "user-a", board=env)
    assert str(exc.value) == "login: HTTP 401"
    assert cred["password"] not in str(exc.value)


def test_dead_lab_account_is_signed_up_again_with_the_same_credential(env, monkeypatch):
    _logged_in(env, monkeypatch)
    env.meta_set("accounts-signup:user-a:p", "0")
    cred = secrets.load("p", "user-a")
    fake = _gate(monkeypatch, probe_bad, lambda s: {"step": "login", "status": 401}, signup_ok, login_ok, probe_ok)
    assert en.refresh(_scope(), "user-a", board=env) == "signed up again, logged in, probe ok"
    assert fake.calls[2][0]["json"]["email"] == cred["email"] and secrets.load("p", "user-a") == cred


def test_accounts_ls_shows_no_secret(env, monkeypatch, tmp_path, capsys):
    _logged_in(env, monkeypatch)
    cred = secrets.load("p", "user-a")
    scope_file = tmp_path / "p.yaml"
    scope_file.write_text(
        json.dumps(
            {
                "program": "p",
                "platform": "local",
                "in_scope": ["app.test"],
                "self_signup": True,
                "identities": [{"name": "user-a", "probe": PROBE, "enroll": RECIPE}],
            }
        )
    )
    monkeypatch.setattr(stack, "container_running", lambda name: True)
    _gate(monkeypatch, probe_ok)
    assert main(["accounts", "ls", str(scope_file)]) == 0
    out = capsys.readouterr().out
    assert "user-a" in out and "ok (HTTP 200)" in out
    for secret in (cred["password"], cred["answer"], cred["email"], TOKEN, "abc"):
        assert secret not in out
