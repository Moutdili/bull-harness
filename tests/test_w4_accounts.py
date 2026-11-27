"""W4-B: the host-planted canary (T24), the baseline per role copied by the host (T25), why a login failed (T51).
No network, no podman: the gate's script is simulated (test_accounts.FakeGate), the browser login too, the gate's
addon runs on simulated flows (test_gate_browser_canary)."""

import asyncio
import gzip
import hashlib
import json
import os

import pytest

from bh import accounts, paths, stack
from bh.accounts import baseline, browser
from bh.accounts import canary as cn
from bh.accounts import enroll as en
from bh.accounts import secrets as sec
from bh.agent.contract import CANARY_RE, IDENTITY_HEADER
from bh.board import Board
from bh.runner import observation
from bh.scope import scope_from_dict
from test_accounts import RECIPE, FakeGate, login_ok, probe_ok
import test_gate_browser_canary as gbc
from test_gate_browser_canary import _answer, _events, _gate, _http

addon = gbc.addon  # the simulated mitmproxy fixture
BASE = "http://app.test"
PRIVATE = {"url": f"{BASE}/api/profile", "method": "PATCH", "field": "profile.bio"}


def _scope(private=PRIVATE, **extra):
    """Two identities; user-b declares its private field. The scope's loader (lot A) learns `private_field`: until
    then it is set on the loaded identity's mapping, which is where bh.accounts.canary reads it."""
    sc = scope_from_dict(
        {
            "program": "p",
            "platform": "local",
            "in_scope": ["app.test"],
            "identities": [
                {"name": "user-a", "probe": {"url": f"{BASE}/rest/whoami", "status": 200}, "enroll": RECIPE},
                {"name": "user-b", "probe": {"url": f"{BASE}/rest/whoami", "status": 200}, "enroll": RECIPE, **extra},
            ],
        }
    )
    if private is not None:
        sc.identities[1]["private_field"] = private
    return sc


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    paths.state().mkdir(parents=True)
    paths.active_scope().write_text("program: p\n")
    for name in ("user-a", "user-b"):
        f = paths.identities_dir("p") / f"{name}.json"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(json.dumps({"headers": {"Authorization": f"Bearer {name}"}}))
    paths.work_bh("p").mkdir(parents=True)  # what the sandbox sees of this program
    return Board(paths.board_db())


def _gate_script(monkeypatch, *answers) -> FakeGate:
    fake = FakeGate(*answers)
    monkeypatch.setattr(stack, "gate_python", fake)
    return fake


def _written(s):
    assert s["step"] == "plant"
    return {"step": "plant", "status": 200}


def _token(fake: FakeGate) -> str:
    """The canary as it left the host (the gate script's stdin): the only place a test can read it."""
    (step,) = fake.calls[-1]
    return step["json"]["profile"]["bio"]


def _files_holding(root, needle: str) -> list[str]:
    out = []
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            p = os.path.join(dirpath, f)
            try:
                data = open(p, "rb").read()  # noqa: SIM115 - a byte scan of every file
            except OSError:
                continue
            if needle.encode() in data or needle.lower().encode() in data:
                out.append(p)
    return out


# ------------------------------------------------------------------ T24: the plant
def test_the_host_plants_a_canary_in_the_declared_field_and_keeps_its_digest_only(env, monkeypatch, tmp_path, capsys):
    fake = _gate_script(monkeypatch, _written)
    out = accounts.plant(_scope(), "user-b", now=1000.0)
    (step,) = fake.calls[0]
    token = _token(fake)
    assert CANARY_RE.fullmatch(token)
    assert (step["method"], step["url"]) == ("PATCH", PRIVATE["url"])
    assert step["headers"] == {"X-BH-Identity": "user-b", "X-BH-Probe": "1"}  # the victim's own session, by the gate
    assert step["json"] == {"profile": {"bio": token}}  # the declared field and nothing else
    digest = hashlib.sha256(token.encode()).hexdigest()
    assert out == {
        "identity": "user-b",
        "program": "p",
        "sha256": digest,
        "at": PRIVATE,
        "ts": 1000.0,
        "planted": True,
    }
    assert cn.planted("p", "user-b") == {k: v for k, v in out.items() if k != "planted"}
    assert oct(cn.state_file("p", "user-b").stat().st_mode & 0o777) == "0o600"
    # the canary in clear is nowhere on disk (the sandbox's view, the state, the board), nor in what was printed
    assert _files_holding(tmp_path, token) == []
    assert token not in json.dumps(out) and token not in "".join(capsys.readouterr())
    # the hunter gets the location only: no token, no digest
    at = cn.canary_at(_scope())
    assert json.loads(at) == {"user-b": PRIVATE} and digest not in at


def test_a_second_plant_draws_a_new_canary(env, monkeypatch):
    fake = _gate_script(monkeypatch, _written, _written)
    accounts.plant(_scope(), "user-b")
    first = _token(fake)
    accounts.plant(_scope(), "user-b")
    assert _token(fake) != first
    assert cn.planted("p", "user-b")["sha256"] == hashlib.sha256(_token(fake).encode()).hexdigest()


def test_without_a_private_field_nothing_is_planted(env, monkeypatch):
    fake = _gate_script(monkeypatch)
    assert accounts.plant(_scope(), "user-a") == {
        "identity": "user-a",
        "planted": False,
        "why": "no private_field declared",
    }
    assert fake.calls == [] and cn.planted("p", "user-a") is None and cn.canary_at(_scope(None)) == ""


@pytest.mark.parametrize(
    "private, why",
    [
        ({**PRIVATE, "url": "https://elsewhere.example/api/profile"}, "not a target"),
        ({**PRIVATE, "method": "DELETE"}, "private_field.method"),
        ({**PRIVATE, "field": "a b"}, "private_field.field"),
        ({**PRIVATE, "extra": 1}, "a mapping of url, method, field"),
        ("profile.bio", "a mapping"),
    ],
)
def test_a_bad_declaration_plants_nothing(env, monkeypatch, private, why):
    fake = _gate_script(monkeypatch)
    with pytest.raises(cn.CanaryError, match=why):
        accounts.plant(_scope(private), "user-b")
    assert fake.calls == [] and cn.planted("p", "user-b") is None


def test_a_refused_plant_keeps_nothing_and_names_no_canary(env, monkeypatch):
    def refused(s):
        return {"step": "plant", "status": 403, "gate": f"bh-gate: DENIED (x {s['json']['profile']['bio']})"}

    fake = _gate_script(monkeypatch, refused)
    with pytest.raises(cn.CanaryError) as exc:
        accounts.plant(_scope(), "user-b")
    assert _token(fake) not in str(exc.value) and "<canary>" in str(exc.value)
    assert cn.planted("p", "user-b") is None


def test_a_plant_needs_the_gate_on_this_program_and_a_session(env, monkeypatch):
    fake = _gate_script(monkeypatch)
    (paths.identities_dir("p") / "user-b.json").unlink()
    with pytest.raises(cn.CanaryError, match="no session"):
        accounts.plant(_scope(), "user-b")
    paths.active_scope().write_text("program: other\n")
    with pytest.raises(en.AccountError, match="active scope is other"):
        accounts.plant(_scope(), "user-b")
    assert fake.calls == []


# ------------------------------------------------------------------ T24: the proof, through the gate
def _chain(addon, tmp_path, monkeypatch, attacker_sends_first: bool):
    """Plant through the simulated gate script, replay the plant and the attack through the gate's addon, and
    return (planted digest, the gate's canary events)."""
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    paths.state().mkdir(parents=True, exist_ok=True)
    fake = _gate_script(monkeypatch, _written)
    scope = {
        "schema": 1,
        "program": "t",
        "platform": "test",
        "in_scope": ["app.test"],
        "max_rps": 1000,
        "identities": [{"name": "user-a"}, {"name": "user-b"}],
    }
    g = _gate(addon, tmp_path, scope)
    (tmp_path / paths.FLOWS_DIR).mkdir(exist_ok=True)
    (tmp_path / paths.IDENTITIES / "t" / "user-b.json").write_text(json.dumps({"headers": {}}))
    paths.active_scope().write_text("program: p\n")
    for name in ("user-a", "user-b"):
        f = paths.identities_dir("p") / f"{name}.json"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("{}")
    accounts.plant(_scope(), "user-b")
    token = _token(fake)
    # the host's plant, as the gate sees it: from its loopback, under the victim, the canary in the body
    body = json.dumps({"profile": {"bio": token}}).encode()
    headers = [(IDENTITY_HEADER, "user-b"), ("X-BH-Probe", "1"), ("Content-Type", "application/json")]
    plant = _http("https://app.test/api/profile", "PATCH", headers, body, peer="127.0.0.1", fid="plant")
    asyncio.run(g.request(plant))
    assert not plant.metadata.get("bh_denied")
    _answer(plant, body=b"{}")
    g.response(plant)
    if attacker_sends_first:  # the hunter read B's canary as B, then sends it as A: it must not count
        sent = _http("https://app.test/api/notes", "POST", [(IDENTITY_HEADER, "user-a")], token.encode(), fid="s")
        asyncio.run(g.request(sent))
    attack = _http("https://app.test/api/profile/2", headers=[(IDENTITY_HEADER, "user-a")], fid="attack")
    asyncio.run(g.request(attack))
    _answer(attack, body=gzip.compress(json.dumps({"bio": token}).encode()), headers=[("Content-Encoding", "gzip")])
    g.response(attack)
    return cn.planted("p", "user-b")["sha256"], _events(tmp_path, "canary")


def _decide(events, digest):
    """The host's comparison by digest: the events whose `sha256` is the planted one. The verdict is
    observation.decide's (lot A compares `token_sha256` itself; the event's token stands in until then)."""
    mine = [e for e in events if e.get("sha256") == digest]
    obs = {"token": mine[0]["token"], "victim": "user-b", "attacker": "user-a"}
    by_token = observation.decide(mine, obs)
    try:
        by_digest = observation.decide(events, {"token_sha256": digest, "victim": "user-b", "attacker": "user-a"})
    except (KeyError, TypeError):  # observation.decide without token_sha256 yet (lot A)
        by_digest = None
    return by_token, by_digest


def test_a_planted_canary_seen_on_the_attackers_side_is_proved_by_its_digest(addon, tmp_path, monkeypatch):
    digest, events = _chain(addon, tmp_path, monkeypatch, attacker_sends_first=False)
    assert [(e["where"], e["identity"], e["client"]) for e in events] == [
        ("request-body", "user-b", "login"),  # the plant: the victim's own write
        ("response-body", "user-a", "agent"),  # the attacker received it
    ]
    assert {e["sha256"] for e in events} == {digest}
    by_token, by_digest = _decide(events, digest)
    assert by_token["status"] == "verified-evidence"
    assert by_digest is None or by_digest["status"] == "verified-evidence"
    flows = [json.loads(x) for x in (tmp_path / paths.FLOWS).read_text().splitlines()]
    assert [f["class"] for f in flows] == ["enroll", "target"]
    assert len(list((tmp_path / paths.FLOWS_DIR).glob("*.json"))) == 1  # the plant's exchange is never kept


def test_a_canary_the_attacker_sent_itself_is_rejected(addon, tmp_path, monkeypatch):
    digest, events = _chain(addon, tmp_path, monkeypatch, attacker_sends_first=True)
    assert ("request-body", "user-a") in [(e["where"], e["identity"]) for e in events]
    by_token, by_digest = _decide(events, digest)
    assert by_token["status"] == "rejected" and "the attacker supplied it" in by_token["why"]
    assert by_digest is None or by_digest["status"] == "rejected"


# ------------------------------------------------------------------ T25: the host's copy of the baseline
def _flow(identity, url, program="p", klass="target"):
    return {"identity": identity, "url": url, "program": program, "class": klass, "method": "GET", "status": 200}


def test_the_baseline_keeps_only_the_routes_the_gate_saw_under_that_identity(env):
    d = paths.work_bh("p") / "baseline"
    d.mkdir()
    (d / "user-a.json").write_text(
        json.dumps(
            {
                "routes": [
                    "http://app.test/#/basket",  # the document / was fetched as user-a
                    "http://app.test/api/Notes/12",  # same route as /api/notes/7 seen as user-a
                    "http://app.test/admin",  # only user-b fetched it
                    "http://app.test/settings",  # anonymous only
                    "http://other.test/",  # never seen
                    "javascript:alert(1)",
                    42,
                ],
                "ts": 1,
            }
        )
    )
    (d / "user-b.json").write_text(json.dumps({"routes": "not a list"}))
    (d / "intruder.json").write_text(json.dumps({"routes": ["http://app.test/"]}))  # not an identity of the scope
    flows = [
        _flow("user-a", "http://app.test/"),
        _flow("user-a", "http://app.test/api/notes/7?x=1"),
        _flow("user-b", "http://app.test/admin"),
        _flow(None, "http://app.test/settings"),
        _flow("user-a", "http://app.test/settings", program="q"),
        _flow("user-a", "http://app.test/settings", klass="enroll"),
    ]
    assert baseline.copy(_scope(), now=5.0, flows=flows) == {"user-a": 2, "user-b": 0}
    kept = json.loads(baseline.host_file("p", "user-a").read_text())
    assert kept == {"routes": ["http://app.test/#/basket", "http://app.test/api/Notes/12"], "ts": 5.0}
    assert json.loads(baseline.host_file("p", "user-b").read_text())["routes"] == []
    assert not baseline.host_file("p", "intruder").exists()
    assert baseline.host_file("p", "user-a") == paths.state() / "baseline" / "p" / "user-a.json"


def test_the_baseline_reads_the_gates_flow_log_and_bounds_the_sandbox_file(env):
    d = paths.work_bh("p") / "baseline"
    d.mkdir()
    routes = [f"http://app.test/r{i}" for i in range(baseline.ROUTES_MAX + 50)]
    (d / "user-a.json").write_text(json.dumps({"routes": routes}))
    paths.flows_log().write_text(json.dumps(_flow("user-a", "http://app.test/r3")) + "\n")
    with gzip.open(paths.flows_log().with_name("flows.jsonl.1.gz"), "wt") as fh:
        fh.write(json.dumps(_flow("user-a", "http://app.test/r4")) + "\n")
    assert baseline.copy(_scope()) == {"user-a": 2}
    assert json.loads(baseline.host_file("p", "user-a").read_text())["routes"] == [routes[3], routes[4]]
    (d / "user-a.json").write_text(json.dumps({"routes": ["http://app.test/" + "x" * baseline.FILE_MAX]}))
    assert baseline.copy(_scope()) == {}  # too big: ignored, the last copy stays


# ------------------------------------------------------------------ T51: why a login failed
@pytest.mark.parametrize(
    "message, cause",
    [
        ("login: HTTP 401", "credentials"),
        ("login: HTTP 422 (signup: HTTP 409)", "credentials"),
        ("token refresh: HTTP 400 (invalid_grant)", "credentials"),
        ("token refresh: HTTP 400 (interaction_required)", "out-of-band"),
        ("login: HTTP 429", "challenge"),
        ("browser login: step 5 (totp): no code from the host (no TOTP seed in the secrets file)", "totp"),
        (
            "browser login: step 5 (totp): timeout | at https://app.test/#/login title 'Login' fields "
            "['input[type=password,name=password]'] buttons ['Log in']",
            "credentials",
        ),
        ("browser login: step 6 (email_code): no code from the host (no mail from app.test in 120 s)", "out-of-band"),
        (
            "browser login: step 4 (wait_for): timeout | at https://app.test/verify title 'Just a moment...' "
            "fields [] buttons []",
            "challenge",
        ),
        (
            "browser login: step 4 (wait_for): timeout | at https://app.test/mfa title 'Two-factor' fields "
            "['input[type=text,name=code]'] buttons ['Verify']",
            "totp",
        ),
        (
            "browser login: step 4 (wait_for): timeout | at https://app.test/check title 'Check your email' "
            "fields [] buttons []",
            "out-of-band",
        ),
        (
            "browser login: step 4 (wait_for): timeout | at https://app.test/login title 'Sign in' fields "
            "['input[type=email,name=email]', 'input[type=password,name=password]'] buttons ['Sign in']",
            "credentials",
        ),
        ("login: no token and no cookie in the answer", "unknown"),
        ("the gate script timed out (1 request(s))", "unknown"),
    ],
)
def test_the_cause_of_a_failed_login_is_one_closed_word(message, cause):
    assert en.login_cause({"kind": "browser", "steps": []}, message) == cause
    assert cause in en.CAUSES


def test_diagnose_runs_the_recipe_once_and_says_ok(env, monkeypatch):
    sec.save("p", "user-a", {"email": "a@example.test", "password": "hunter2-secret"})
    fake = _gate_script(monkeypatch, login_ok, probe_ok)
    assert en.diagnose(_scope(), "user-a", board=env) == "ok"
    assert [s["step"] for c in fake.calls for s in c] == ["login", "probe"]  # one login, never a sign-up


def test_diagnose_names_refused_credentials_without_any_secret(env, monkeypatch):
    sec.save("p", "user-a", {"email": "a@example.test", "password": "hunter2-secret"})
    fake = _gate_script(monkeypatch, lambda s: {"step": "login", "status": 401})
    out = en.diagnose(_scope(), "user-a", board=env)
    assert out == "credentials" and "hunter2" not in out
    assert len(fake.calls) == 1  # one attempt, no retry, no sign-up
    assert en.diagnose(_scope(), "user-b", board=env) == "credentials"  # no credential stored at all


def test_diagnose_of_a_browser_recipe_fills_each_field_once(env, monkeypatch):
    steps = [
        {"goto": f"{BASE}/#/login"},
        {"fill": "#email", "value": "{email}"},
        {"fill": "#password", "value": "{password}"},
        {"click": "#login"},
        {"totp": "#otp"},
        {"wait_for": {"url": "#/home"}},
    ]
    capture = {"local_storage": {"token": {"Authorization": "x {value}"}}}
    recipe = {"kind": "browser", "steps": steps, "capture": capture}
    sc = scope_from_dict(
        {
            "program": "p",
            "platform": "local",
            "in_scope": ["app.test"],
            "identities": [{"name": "user-a", "enroll": recipe, "origins": [f"{BASE}/"]}],
        }
    )
    sec.save("p", "user-a", {"email": "a@example.test", "password": "hunter2-secret"})
    runs = []

    def no_seed(payload, ask, timeout=None):
        runs.append([s["action"] for s in payload["steps"]])
        assert ask({"need": "totp", "step": 4}) is None  # no seed in the secrets file
        raise browser.BrowserError("step 4 (totp): no code from the host")

    monkeypatch.setattr(browser, "execute", no_seed)
    assert en.diagnose(sc, "user-a", board=env) == "totp"
    assert runs == [["goto", "fill", "fill", "click", "totp", "wait_for"]]  # one pass, each field once

    def captcha(payload, ask, timeout=None):
        raise browser.BrowserError(
            "step 3 (click): timeout | at https://app.test/#/login title 'Login' fields [] buttons ['I am not a robot']"
        )

    monkeypatch.setattr(browser, "execute", captcha)
    assert en.diagnose(sc, "user-a", board=env) == "challenge"


def test_login_failed_blockers_carry_the_cause(env, monkeypatch):
    sec.save("p", "user-a", {"email": "a@example.test", "password": "hunter2-secret"})
    _gate_script(monkeypatch, lambda s: {"step": "probe", "status": 401}, lambda s: {"step": "login", "status": 401})
    with pytest.raises(en.AccountError) as exc:
        en.refresh(_scope(), "user-a", board=env)
    assert exc.value.cause == "credentials" and str(exc.value).startswith("[credentials] ")
    env.meta_set("accounts-login:user-a:p", str(10**12))  # a login just tried: the hourly limit refuses
    _gate_script(monkeypatch, lambda s: {"step": "probe", "status": 401})
    with pytest.raises(en.AccountError) as exc:
        en.refresh(_scope(), "user-a", board=env)
    assert exc.value.cause == "unknown" and str(exc.value).startswith("[unknown] ") and "hunter2" not in str(exc.value)
