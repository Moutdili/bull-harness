import json
from types import SimpleNamespace

import pytest

from bh.browser_service import host as bhost
from bh.browser_service import notify, watch


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def _watcher(st, pushed, clock, **kw):
    return watch.ChallengeWatcher(
        status=lambda: st,
        push=lambda *a: pushed.append(a),
        running=lambda: True,
        view=lambda: "http://ui/captcha/",
        clock=clock,
        **kw,
    )


def test_a_challenge_is_pushed_once_then_reminded_once_at_ten_minutes():
    pushed, clock = [], Clock()
    st = {"challenge": {"pending": True, "since": 10.0}, "program": "p", "identity": "user-a"}
    w = _watcher(st, pushed, clock)
    w.tick()
    w.tick()
    assert pushed == [("p", "user-a", "http://ui/captcha/")]
    clock.t += 599
    w.tick()
    assert len(pushed) == 1
    clock.t += 1
    w.tick()
    assert pushed[-1] == ("p", "user-a", "http://ui/captcha/", True)  # the reminder
    clock.t += 3600
    w.tick()
    assert len(pushed) == 2  # never more for that challenge


def test_at_most_one_push_per_five_minutes_even_for_a_flickering_challenge():
    pushed, clock = [], Clock()
    st = {"challenge": {"pending": True, "since": 1.0}, "program": "p", "identity": "a"}
    w = _watcher(st, pushed, clock)
    for i in range(30):  # a new `since` every 10 s for 5 minutes
        st["challenge"] = {"pending": True, "since": float(i)}
        w.tick()
        clock.t += 10
    assert len(pushed) == 1
    st["challenge"] = {"pending": True, "since": 99.0}
    clock.t += 1
    w.tick()
    assert len(pushed) == 2  # five minutes later, the one still there is pushed


def test_a_failed_push_and_a_failing_status_are_said_once():
    said, clock = [], Clock()
    st = {"challenge": {"pending": True, "since": 1.0}}
    w = watch.ChallengeWatcher(
        status=lambda: st, push=lambda *a: False, running=lambda: True, view=lambda: "", say=said.append, clock=clock
    )
    w.tick()
    st["challenge"] = {"pending": True, "since": 2.0}
    clock.t += 400
    w.tick()
    assert len([m for m in said if "push failed" in m]) == 1

    def boom():
        raise OSError("down")

    said2 = []
    w2 = watch.ChallengeWatcher(status=boom, push=lambda *a: 1 / 0, running=lambda: True, view=lambda: "", say=said2.append)
    w2.tick()
    w2.tick()
    assert said2 == ["bh-browser watcher: OSError: down"]
    w3 = watch.ChallengeWatcher(status=boom, push=lambda *a: 1 / 0, running=lambda: False, view=lambda: "")
    w3.tick()  # a stopped browser: nothing, no exception


def test_only_scopes_with_a_passthrough_host_want_the_browser():
    assert watch.wanted(SimpleNamespace(support_hosts=lambda k: ("challenges.cloudflare.com",)))
    assert not watch.wanted(SimpleNamespace(support_hosts=lambda k: ()))
    assert watch.prepare(SimpleNamespace(support_hosts=lambda k: ()), ["user-a"]) is None


# ---------------------------------------------------------------- B3: prepare resets before loading another account
class FakeBrowser:
    """The controller's host door, as prepare() and the watcher see it (records every op in order)."""

    def __init__(self, program=None, identity=None, pending=False):
        self.program, self.identity, self.pending = program, identity, pending
        self.ops, self.switch = [], None

    def __call__(self, req, timeout=None):
        op = req["op"]
        self.ops.append(op)
        if op == "status":
            return {
                "code": 200,
                "program": self.program,
                "identity": self.identity,
                "switch_requested": self.switch,
                "challenge": {"pending": self.pending, "since": 1.0 if self.pending else None},
            }
        if op == "reset":
            self.program = self.identity = None
            return {"code": 200}
        if op == "load_session":
            if self.identity not in (None, req["identity"]):
                return {"code": 409, "error": "profile-holds-another-identity"}
            self.program, self.identity = req["program"], req["identity"]
            self.switch = None
            self.ops.append(("add_cookies", req["identity"]))
            return {"code": 200, "cookies": len(req["cookies"])}
        return {"code": 200}


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    for name in ("user-a", "user-b"):
        d = tmp_path / "var" / "state" / "identities" / "prog"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{name}.json").write_text(json.dumps({"headers": {}, "cookies": {}}))
    monkeypatch.setattr(bhost, "view_url", lambda *a, **k: "http://ui/captcha/")
    return tmp_path


SCOPE = SimpleNamespace(program="prog", support_hosts=lambda k: ("challenges.cloudflare.com",))


def test_prepare_resets_a_profile_holding_another_identity_before_adding_cookies(home):
    br = FakeBrowser("prog", "user-a")
    assert watch.prepare(SCOPE, ["user-b"], call=br, ensure_up=lambda: True) == "user-b"
    assert br.ops.index("reset") < br.ops.index(("add_cookies", "user-b"))
    assert "fill_budget_reset" in br.ops
    rec = json.loads(bhost.identity_file().read_text())
    assert rec["program"] == "prog" and rec["identity"] == "user-b" and isinstance(rec["loaded_at"], float)


def test_prepare_keeps_a_live_identity_already_in_the_profile(home):
    br = FakeBrowser("prog", "user-b")
    assert watch.prepare(SCOPE, ["user-a", "user-b"], call=br, ensure_up=lambda: True) == "user-b"
    assert "reset" not in br.ops  # its challenge clearance survives
    br = FakeBrowser("other-prog", "user-a")
    assert watch.prepare(SCOPE, ["user-a"], call=br, ensure_up=lambda: True) == "user-a"
    assert br.ops.index("reset") < br.ops.index(("add_cookies", "user-a"))  # same name, another program


# ---------------------------------------------------------------- I2: switch
def test_a_switch_to_a_live_identity_is_carried_out(home):
    br = FakeBrowser("prog", "user-a")
    br.switch = "user-b"
    said = []
    w = watch.ChallengeWatcher(
        status=lambda: br({"op": "status"}),
        call=br,
        push=lambda *a: True,
        running=lambda: True,
        view=lambda: "",
        program="prog",
        identities=["user-a", "user-b"],
        say=said.append,
    )
    w.tick()
    assert br.identity == "user-b" and br.ops.index("reset") < br.ops.index(("add_cookies", "user-b"))
    assert json.loads(bhost.identity_file().read_text())["identity"] == "user-b"
    assert any("switched" in m for m in said)


def test_a_switch_outside_the_live_list_or_during_a_challenge_is_not_done(home):
    br = FakeBrowser("prog", "user-a")
    br.switch = "admin"
    w = watch.ChallengeWatcher(
        status=lambda: br({"op": "status"}),
        call=br,
        push=lambda *a: True,
        running=lambda: True,
        view=lambda: "",
        program="prog",
        identities=["user-a", "user-b"],
    )
    w.tick()
    assert "switch_refused" in br.ops and "reset" not in br.ops and br.identity == "user-a"
    br2 = FakeBrowser("prog", "user-a", pending=True)
    br2.switch = "user-b"
    w2 = watch.ChallengeWatcher(
        status=lambda: br2({"op": "status"}),
        call=br2,
        push=lambda *a: True,
        running=lambda: True,
        view=lambda: "",
        program="prog",
        identities=["user-a", "user-b"],
    )
    w2.tick()
    assert "reset" not in br2.ops and br2.identity == "user-a"  # the challenge and the typed message stay


def test_reset_writes_no_identity_for_the_gate(home):
    bhost.reset("prog", call_=lambda req, timeout=None: {"code": 200})
    rec = json.loads(bhost.identity_file().read_text())
    assert rec["identity"] is None and rec["program"] == "prog"
    assert not list(bhost.identity_file().parent.glob(".*.tmp"))


# ---------------------------------------------------------------- B1: ntfy topic rotation
def test_notify_rotate_replaces_the_topic(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    first = notify.topic(create=True)
    new = notify.rotate()
    assert new != first and notify.topic() == new and len(new) >= 20
    assert notify.env_path().stat().st_mode & 0o777 == 0o600
    assert not list(notify.env_path().parent.glob(".*.tmp"))
