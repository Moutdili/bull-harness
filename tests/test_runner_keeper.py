"""Session keeper (renewal during a segment) and the role matrix handed to the agent (BH_IDENTITY_ROLES)."""

import json
from pathlib import Path

import pytest

from bh import paths
from bh.accounts import enroll as en
from bh.board import Board
from bh.gate import session as gs
from bh.runner import run
from bh.scope import scope_from_dict

BASE = "http://app.test"
RECIPE = {
    "login": {"method": "POST", "url": f"{BASE}/login", "json": {"email": "{email}", "password": "{password}"}},
    "token": "token",
    "headers": {"Authorization": "Bearer {token}"},
}


def _scope():
    return scope_from_dict(
        {
            "program": "p",
            "platform": "local",
            "in_scope": ["app.test"],
            "identities": [
                {"name": "user-a", "enroll": RECIPE, "role": "member", "tenant": "A"},
                {"name": "user-b", "enroll": RECIPE, "role": "member", "tenant": "B"},
                {"name": "admin-a", "enroll": RECIPE, "role": "admin", "tenant": "A"},
                {"name": "manual"},  # no recipe: never logged in by the keeper, no role declared
            ],
        }
    )


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    paths.identities_dir("p").mkdir(parents=True)
    return Board(paths.board_db())


def _session(name, expires_at):
    f = paths.identities_dir("p") / f"{name}.json"
    gs.save(f, {"headers": {"Authorization": "Bearer x"}, "cookies": {}, "expires_at": expires_at, "updated": 0})


def _dead(name, ts, program="p"):
    with open(paths.events_log(), "a") as fh:
        fh.write(json.dumps({"kind": "session-dead", "identity": name, "ts": ts, "program": program}) + "\n")


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


# ---------------------------------------------------------------- plan (pure)
def test_plan_renews_before_expiry_with_the_margin():
    now = 10_000.0
    exp = {"a": now + 119, "b": now + 121, "c": None}
    assert run.keeper_plan(exp, {}, {}, now, margin=120) == [("a", "expiry")]
    assert run.keeper_plan(exp, {}, {}, now + 2, margin=120) == [("a", "expiry"), ("b", "expiry")]


def test_plan_dead_first_and_one_login_per_five_minutes():
    now = 10_000.0
    exp = {"a": now + 30, "b": None}
    assert run.keeper_plan(exp, {"b": now - 1}, {}, now) == [("a", "expiry"), ("b", "dead")]
    assert run.keeper_plan(exp, {"a": now}, {"a": now - 299}, now) == []
    assert run.keeper_plan(exp, {"a": now}, {"a": now - 300}, now) == [("a", "dead")]
    assert run.KEEP_EVERY_S == 300 and run.KEEP_MARGIN_S == 120


# ---------------------------------------------------------------- keeper (simulated renew)
def test_keeper_renews_before_expiry_then_waits_five_minutes(env):
    clock = Clock(1_000_000.0)
    calls = []
    _session("user-a", clock.t + 100)  # inside the 2-minute margin
    _session("user-b", clock.t + 3600)

    def renew(board, name, reason):
        calls.append((name, reason))
        _session(name, clock.t + 110)  # a short-lived session again: due at once, but rate-limited
        return "logged in"

    k = run.SessionKeeper(_scope(), env.path, 1, ["user-a", "user-b", "manual"], renew=renew, clock=clock)
    assert k.names == ["user-a", "user-b"]
    assert k.tick(env) == [("user-a", "expiry", "logged in")]
    clock.t += 299
    assert k.tick(env) == []
    clock.t += 1
    assert k.tick(env) == [("user-a", "expiry", "logged in")]
    assert calls == [("user-a", "expiry"), ("user-a", "expiry")]


def test_keeper_follows_session_dead_events_of_this_program(env):
    clock = Clock(1_000_000.0)
    for n in ("user-a", "user-b", "admin-a"):
        _session(n, None)
    paths.events_log().write_text(json.dumps({"kind": "session-dead", "identity": "user-a", "ts": 1.0}) + "\n")
    k = run.SessionKeeper(
        _scope(),
        env.path,
        1,
        ["user-a", "user-b", "admin-a"],
        renew=lambda b, n, r: f"ok {r}",
        clock=clock,
        events_offset=paths.events_log().stat().st_size,
    )
    assert k.tick(env) == []  # the death before the segment is not the keeper's (refresh_identities saw to it)
    _dead("user-b", clock.t - 5)
    _dead("admin-a", clock.t - 5, program="other")
    _dead("manual", clock.t - 5)
    with open(paths.events_log(), "a") as fh:
        fh.write('{"kind": "session-dead", "identity": "user-a"')  # a line the gate is still writing
    assert k.tick(env) == [("user-b", "dead", "ok dead")]
    with open(paths.events_log(), "a") as fh:
        fh.write(f', "ts": {clock.t}, "program": "p"}}\n')
    assert k.tick(env) == [("user-a", "dead", "ok dead")]
    _dead("user-a", clock.t - 1)  # seen before the keeper's own login: the old session's death
    clock.t += 400
    assert k.tick(env) == []


def test_keeper_failure_is_a_login_failed_blocker_and_is_bounded(env):
    clock = Clock(1_000_000.0)
    _session("user-a", clock.t + 10)

    def renew(board, name, reason):
        raise en.AccountError("login: HTTP 500")

    k = run.SessionKeeper(_scope(), env.path, 7, ["user-a"], renew=renew, clock=clock)
    assert k.tick(env)[0][2].startswith("login failed")
    clock.t += 60
    assert k.tick(env) == []  # retried after 5 minutes, not before
    rows = env.rows("SELECT title, run_id FROM facts WHERE kind='blocker'")
    assert [(r["title"], r["run_id"]) for r in rows] == [("[login-failed] identity user-a", 7)]


def test_keeper_uses_a_forced_refresh_probe_first_only_on_death(env, monkeypatch):
    seen = []
    monkeypatch.setattr(en, "refresh", lambda scope, name, **kw: seen.append((name, kw)) or "logged in")
    k = run.SessionKeeper(_scope(), env.path, 1, ["user-a"])
    k._renew(env, "user-a", "expiry")
    k._renew(env, "user-a", "dead")
    assert [kw["probe_first"] for _, kw in seen] == [False, True]
    assert all(kw["force"] for _, kw in seen)


def test_keeper_thread_starts_only_with_identities_to_keep(env):
    k = run.SessionKeeper(_scope(), env.path, 1, ["manual"], tick=0.01).start()
    assert k._thread is None
    k.stop()


# ---------------------------------------------------------------- role matrix
def test_identity_roles_follows_the_live_identities_in_order():
    scope = _scope()
    assert (
        run.identity_roles(scope, ["user-a", "user-b", "admin-a"]) == "user-a=member@A,user-b=member@B,admin-a=admin@A"
    )
    assert run.identity_roles(scope, ["admin-a", "manual", "ui-made"]) == "admin-a=admin@A,manual=@,ui-made=@"
    assert run.identity_roles(scope, []) == ""


def test_agent_command_passes_roles_next_to_identities(env):
    cmd = run.agent_command(
        _scope(),
        "task",
        run_id=1,
        model="sonnet",
        max_turns=5,
        effort=None,
        session=None,
        identities=["user-b", "admin-a"],
    )
    env_args = {cmd[i + 1].split("=", 1)[0]: cmd[i + 1].split("=", 1)[1] for i, x in enumerate(cmd) if x == "-e"}
    assert env_args["BH_IDENTITIES"] == "user-b,admin-a"
    assert env_args["BH_IDENTITY_ROLES"] == "user-b=member@B,admin-a=admin@A"


def test_lab_bench_declares_a_role_matrix():
    from bh.scope import load_scope

    scope = load_scope(Path(__file__).resolve().parents[1] / "scopes" / "lab" / "bench.yaml")
    assert run.identity_roles(scope, ["user-a", "user-b"]) == "user-a=member@A,user-b=member@B"
