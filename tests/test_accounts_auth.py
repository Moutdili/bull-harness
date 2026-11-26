"""Auth engine: browser and oauth_refresh recipes, expiry, MFA, without network or podman (simulated executors)."""

import base64
import json
import time

import pytest

from bh import paths, stack
from bh.accounts import browser, expiry, mail, secrets, totp
from bh.accounts import enroll as en
from bh.board import Board
from bh.scope import ScopeError, scope_from_dict
from test_accounts import FakeGate

BASE = "https://app.test"
API = "https://api.app.test"


def _jwt(exp: float) -> str:
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    return f"{b64({'alg': 'HS256'})}.{b64({'exp': exp, 'sub': 'x'})}.c2ln"


BROWSER = {
    "kind": "browser",
    "email": "bh-{name}-{rand}@example.test",
    "steps": [
        {"goto": f"{BASE}/#/login"},
        {"click": "button.banner", "optional": True, "timeout": 2},
        {"fill": "#email", "value": "{email}"},
        {"fill": "#password", "value": "{password}"},
        {"click": "#login"},
        {"totp": "#otp"},
        {"wait_for": {"url": "#/home"}},
    ],
    "capture": {"local_storage": {"token": {"Authorization": "Bearer {value}"}}},
}
OAUTH = {
    "kind": "oauth_refresh",
    "token_url": "https://login.app.test/oauth2/v2.0/token",
    "client_id": "11111111-2222-3333-4444-555555555555",
    "scope": "openid offline_access https://api.app.test/.default",
}


def _scope(**ident):
    ident.setdefault("name", "user-a")
    return scope_from_dict(
        {
            "program": "p",
            "platform": "local",
            "in_scope": ["*.app.test", "app.test"],
            "self_signup": True,
            "identities": [ident],
        }
    )


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    paths.state().mkdir(parents=True)
    paths.active_scope().write_text("program: p\n")
    return Board(paths.board_db())


def _session(name="user-a"):
    return json.loads(paths.identities_dir("p").joinpath(f"{name}.json").read_text())


# ---------------------------------------------------------------- expiry
def test_jwt_exp_is_read_without_checking_the_signature():
    tok = _jwt(4102444800)
    assert expiry.jwt_exp(tok) == 4102444800.0
    assert expiry.jwt_exp(f"Bearer {tok}") == 4102444800.0
    for bad in (None, "", "abc", "a.b", "a.%%%.c", f"{tok}.extra", _jwt("soon"), _jwt(True)):
        assert expiry.jwt_exp(bad) is None


def test_known_expiry_prefers_tokens_then_session_cookies():
    now = 1_000_000.0
    jar = {"app.test": {"sid": {"expires": now + 900}, "__cf_bm": {"expires": now + 60}, "lang": {"expires": now + 5}}}
    assert expiry.known(tokens=[_jwt(now + 3600)], expires_in=1800, jar=jar, now=now) == now + 1800
    assert expiry.known(tokens=[_jwt(now + 3600), None], jar=jar, now=now) == now + 3600
    assert expiry.known(expires_in="600", now=now) == now + 600
    assert expiry.known(jar=jar, now=now) == now + 900  # the bot and language cookies do not count
    assert expiry.known(jar={"app.test": {"lang": {"expires": now + 5}}}, now=now) is None


# ---------------------------------------------------------------- schema
def test_browser_recipe_is_checked_and_its_origins_derived():
    ident = _scope(enroll=BROWSER).identities[0]
    steps = ident["enroll"]["steps"]
    assert [s["action"] for s in steps] == ["goto", "click", "fill", "fill", "click", "totp", "wait_for"]
    assert steps[1] == {"action": "click", "selector": "button.banner", "optional": True, "timeout": 2.0}
    assert ident["enroll"]["capture"] == {
        "cookies": True,
        "authorization": True,
        "local_storage": {"token": {"Authorization": "Bearer {value}"}},
        "authorization_origins": [],
    }
    assert ident["origins"] == ["https://app.test:443/"]  # M7: its bearer goes to the login's origin only
    assert _scope(enroll=BROWSER, origins=[f"{API}/"]).identities[0]["origins"] == [f"{API}/"]


@pytest.mark.parametrize(
    ("change", "match"),
    [
        ({"steps": [{"goto": "https://evil.example/login"}]}, "not in scope"),
        ({"steps": [{"goto": f"{BASE}/login?u={{email}}"}]}, "no placeholder in a URL"),
        ({"steps": [{"goto": f"{BASE}/"}, {"fill": "#password", "value": "hunter2"}]}, "credential"),
        ({"steps": [{"goto": f"{BASE}/"}, {"fill": "input[name=otp_code]", "value": "123456"}]}, "credential"),
        ({"steps": [{"goto": f"{BASE}/"}, {"fill": "#email", "value": "{token}"}]}, "unknown placeholders"),
        ({"steps": [{"click": "#x"}]}, "first step is a goto"),
        ({"steps": [{"goto": f"{BASE}/", "click": "#x"}]}, "exactly one action"),
        ({"steps": [{"goto": f"{BASE}/"}, {"email_code": "#code"}]}, "from"),
        ({"steps": [{"goto": f"{BASE}/"}, {"goto": f"{BASE}/x", "optional": True}]}, "optional"),
        ({"capture": {"local_storage": {"token": {"Authorization": "Bearer abc"}}}}, r"\{value\}"),
        ({"capture": {"cookies": False, "authorization": False}}, "nothing to capture"),
        ({"capture": {"local_storage": {"token": {"Bad Header": "{value}"}}}}, "header name"),
        ({"headers": {"Authorization": "Bearer {token}"}}, "unknown keys"),
        ({"kind": "saml"}, "kind"),
    ],
)
def test_bad_browser_recipes_are_refused(change, match):
    with pytest.raises(ScopeError, match=match):
        _scope(enroll={**BROWSER, **change})


@pytest.mark.parametrize(
    ("change", "match"),
    [
        ({"token_url": "https://evil.example/token"}, "not in scope"),
        ({"client_id": "has space"}, "client_id"),
        ({"headers": {"Authorization": "Bearer abc"}}, "literal"),
        ({"headers": {"Authorization": "Bearer {token}"}}, "unknown placeholders"),
        ({"refresh_token": "abc"}, "unknown keys"),
    ],
)
def test_bad_oauth_recipes_are_refused(change, match):
    with pytest.raises(ScopeError, match=match):
        _scope(enroll={**OAUTH, **change}, origins=[f"{API}/"])


def test_an_oauth_identity_says_where_its_token_goes():
    with pytest.raises(ScopeError, match="origins"):
        _scope(enroll=OAUTH)
    ident = _scope(enroll=OAUTH, origins=[f"{API}/"]).identities[0]
    assert ident["enroll"]["headers"] == {"Authorization": "Bearer {access_token}"}


# ---------------------------------------------------------------- oauth_refresh
def _oauth_gate(monkeypatch, *answers):
    fake = FakeGate(*answers)
    monkeypatch.setattr(stack, "gate_python", fake)
    return fake


def test_oauth_refresh_stores_the_new_refresh_token_then_the_session(env, monkeypatch):
    scope = _scope(enroll=OAUTH, origins=[f"{API}/"])
    secrets.save("p", "user-a", {"refresh_token": "RT-old-0123456789", "client_secret": "cs-0123456789"})
    access = _jwt(time.time() + 3600)

    def token(s):
        assert s["step"] == "token" and s["method"] == "POST" and s["url"] == OAUTH["token_url"]
        assert s["form"] == {
            "grant_type": "refresh_token",
            "refresh_token": "RT-old-0123456789",
            "client_id": OAUTH["client_id"],
            "scope": OAUTH["scope"],
            "client_secret": "cs-0123456789",
        }
        assert s["token_paths"]["refresh_token"] == "refresh_token"
        return {
            "step": "token",
            "status": 200,
            "tokens": {"access_token": access, "refresh_token": "RT-new-9876543210", "expires_in": 1800},
        }

    _oauth_gate(monkeypatch, token)
    t0 = time.time()
    assert en.enroll(scope, "user-a", board=env) == "token refreshed, no probe declared"
    stored = secrets.load_raw("p", "user-a")
    assert stored["refresh_token"] == "RT-new-9876543210" and stored["client_secret"] == "cs-0123456789"
    sess = _session()
    assert sess["headers"] == {"Authorization": f"Bearer {access}"}
    assert t0 + 1790 <= sess["expires_at"] <= time.time() + 1800  # expires_in is earlier than the JWT exp


def test_oauth_refresh_failure_names_the_oauth_error_never_the_token(env, monkeypatch):
    scope = _scope(enroll=OAUTH, origins=[f"{API}/"])
    secrets.save("p", "user-a", {"refresh_token": "RT-secret-value-42"})
    _oauth_gate(monkeypatch, lambda s: {"step": "token", "status": 400, "tokens": {"error": "invalid_grant"}})
    with pytest.raises(en.AccountError, match=r"HTTP 400 \(invalid_grant\)") as exc:
        en.enroll(scope, "user-a", board=env)
    assert "RT-secret" not in str(exc.value)
    assert secrets.load_raw("p", "user-a")["refresh_token"] == "RT-secret-value-42"
    assert not paths.identities_dir("p").joinpath("user-a.json").exists()


def test_oauth_without_a_deposited_refresh_token_never_signs_up(env, monkeypatch):
    fake = _oauth_gate(monkeypatch)
    with pytest.raises(en.AccountError, match="no refresh token stored"):
        en.enroll(_scope(enroll=OAUTH, origins=[f"{API}/"]), "user-a", board=env)
    assert fake.calls == []


# ---------------------------------------------------------------- browser
SEED = base64.b32encode(b"12345678901234567890").decode()


def _browser_result(token, **extra):
    return {
        "cookies": [
            {
                "name": "sid",
                "value": "s1",
                "domain": "app.test",
                "path": "/",
                "expires": time.time() + 900,
                "secure": True,
            },
            {"name": "pref", "value": "x", "domain": ".app.test", "path": "/", "expires": -1, "secure": False},
            {"name": "track", "value": "t", "domain": ".tracker.example", "path": "/", "expires": -1},
            {"name": "bad", "value": "a;b", "domain": "app.test", "path": "/", "expires": -1},
        ],
        "authorization": f"Bearer {token}",
        "authorization_url": f"{BASE}/rest/basket/1",
        "local_storage": {"token": token},
        "final_url": f"{BASE}/#/home",
        **extra,
    }


def test_browser_login_writes_the_session_and_answers_totp_on_the_host(env, monkeypatch):
    scope = _scope(enroll=BROWSER)
    secrets.save("p", "user-a", {"email": "a@example.test", "password": "pw-secret-123", "totp": SEED})
    token = _jwt(time.time() + 3600)
    seen = {}

    def fake_execute(payload, ask, timeout=None):
        steps = payload["steps"]
        assert steps[2]["value"] == "a@example.test" and steps[3]["value"] == "pw-secret-123"
        assert "pw-secret-123" not in json.dumps(payload["capture"])
        seen["code"] = ask({"need": "totp", "step": 5})
        return _browser_result(token)

    monkeypatch.setattr(browser, "execute", fake_execute)
    monkeypatch.setattr(stack, "gate_python", FakeGate())
    assert en.enroll(scope, "user-a", board=env) == "logged in, no probe declared"
    p = totp.params(SEED)
    assert seen["code"] in {totp.totp(p, time.time() + d) for d in (-30, 0, 30)}
    sess = _session()
    assert sess["headers"] == {"Authorization": f"Bearer {token}"}
    assert sess["cookies"] == {
        "app.test": {
            "sid": {
                "value": "s1",
                "path": "/",
                "expires": pytest.approx(time.time() + 900, abs=5),
                "host_only": True,
                "secure": True,
            },
            "pref": {"value": "x", "path": "/", "expires": None, "host_only": False, "secure": False},
        }
    }  # the tracker's domain is out of scope, a value with ';' cannot ride in a Cookie header
    assert sess["expires_at"] == pytest.approx(time.time() + 3600, abs=5)


def test_browser_signup_then_login(env, monkeypatch):
    recipe = {
        **BROWSER,
        "signup": {
            "method": "POST",
            "url": f"{BASE}/api/Users",
            "json": {"email": "{email}", "password": "{password}"},
        },
    }
    recipe["steps"] = [s for s in recipe["steps"] if "totp" not in s]
    fake = FakeGate(lambda s: {"step": "signup", "status": 201})
    monkeypatch.setattr(stack, "gate_python", fake)
    monkeypatch.setattr(browser, "execute", lambda payload, ask, timeout=None: _browser_result(_jwt(time.time() + 60)))
    assert en.enroll(_scope(enroll=recipe), "user-a", board=env) == "signed up, logged in, no probe declared"
    cred = secrets.load("p", "user-a")
    assert fake.calls[0][0]["json"]["password"] == cred["password"]


def test_browser_failures_are_one_line_without_secrets(env, monkeypatch):
    scope = _scope(enroll=BROWSER)
    secrets.save("p", "user-a", {"email": "a@example.test", "password": "pw-secret-123"})

    def fails(payload, ask, timeout=None):
        assert ask({"need": "totp", "step": 5}) is None  # no seed stored: no code, a note
        raise browser.BrowserError("step 5 (totp): no code from the host pw-secret-123")

    monkeypatch.setattr(browser, "execute", fails)
    with pytest.raises(en.AccountError) as exc:
        en.enroll(scope, "user-a", board=env)
    msg = str(exc.value)
    assert "no TOTP seed" in msg and "pw-secret-123" not in msg and "\n" not in msg


def test_email_code_without_a_mailbox_fails_cleanly(env, monkeypatch):
    recipe = {**BROWSER, "steps": [{"goto": f"{BASE}/"}, {"email_code": "#code", "from": "app.test"}]}
    secrets.save("p", "user-a", {"email": "a@example.test", "password": "pw-secret-123"})
    monkeypatch.setattr(mail, "default", mail.NoMailbox)

    def run(payload, ask, timeout=None):
        if ask({"need": "email_code", "step": 1}) is None:
            raise browser.BrowserError("step 1 (email_code): no code from the host")
        return _browser_result("x")

    monkeypatch.setattr(browser, "execute", run)
    with pytest.raises(en.AccountError, match=r"no mail from app\.test"):
        en.enroll(_scope(enroll=recipe), "user-a", board=env)


def test_browser_session_refuses_what_a_header_cannot_carry(env):
    ident = en.identity(_scope(enroll=BROWSER), "user-a")
    with pytest.raises(en.AccountError, match="localStorage 'token' is empty"):
        en.browser_session(ident, {**_browser_result("x"), "local_storage": {}}, time.time())
    with pytest.raises(en.AccountError, match="printable ASCII"):
        en.browser_session(ident, _browser_result("tok\r\nX-Injected: 1"), time.time())
    # an Authorization seen on a request to a host outside the scope is not kept
    no_ls = en.identity(_scope(enroll={**BROWSER, "capture": {}}), "user-a")
    sess = en.browser_session(
        no_ls, {**_browser_result("t"), "authorization_url": "https://cdn.other.example/x"}, time.time()
    )
    assert sess["headers"] == {} and "app.test" in sess["cookies"]


def test_the_login_script_is_sent_on_stdin_with_the_credential(monkeypatch):
    """The host side of bh-login: script and payload on stdin, questions answered on the same pipe."""
    import io

    sent = io.StringIO()
    lines = [json.dumps({"need": "totp", "step": 3}) + "\n", json.dumps({"result": {"cookies": []}}) + "\n"]

    class Proc:
        stdin = sent
        stdout = iter(lines)
        returncode = 0

        def poll(self):
            return 0

        def wait(self, timeout=None):
            return 0

        def kill(self):
            pass

    argv_seen = []
    monkeypatch.setattr(stack, "reset_login", lambda: None)
    monkeypatch.setattr(stack, "login_popen", lambda argv, stderr=None: argv_seen.append(argv) or Proc())
    out = browser.execute(
        {"steps": [{"action": "fill", "selector": "#p", "value": "pw-secret"}], "capture": {}}, lambda msg: "123456"
    )
    assert out == {"cookies": []}
    assert argv_seen == [["python3", "-I", "-c", browser.BOOT]] and "pw-secret" not in json.dumps(argv_seen)
    text = sent.getvalue()
    n, rest = text.split("\n", 1)
    assert rest[: int(n)] == browser.LOGIN_SCRIPT
    payload, answer = rest[int(n) :].splitlines()
    assert json.loads(payload)["steps"][0]["value"] == "pw-secret" and json.loads(answer) == {"value": "123456"}
