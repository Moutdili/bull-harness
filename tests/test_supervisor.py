"""TODO 4.2 acceptance: 3 programs, forced stagnation -> rotation then cooldown; simulated quota -> sleep, resume."""

import json

import pytest

from bh.board import Board
from bh.runner import supervisor
from bh.runner.run import SegmentResult


def _scope(tmp_path, name):
    p = tmp_path / f"{name}.yaml"
    p.write_text(f"program: {name}\nplatform: local\nin_scope: [{name}.test]\n")
    return p


def test_rotation_stagnation_and_quota(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    clock = {"t": 1_000_000.0}
    sleeps: list[float] = []
    calls: list[str] = []
    script = {"a": ["quota", 1, 0, 0], "b": [0, 0], "c": [2, 0, 0]}  # per program: status or progress

    def fake_run(scope_file, **kw):
        name = scope_file.stem
        calls.append(name)
        clock["t"] += 600
        step = script[name].pop(0) if script[name] else 0
        if step == "quota":
            return SegmentResult(program=name, run_id=len(calls), status="quota")
        return SegmentResult(program=name, run_id=len(calls), status="ok", progress=step)

    def fake_sleep(s):
        sleeps.append(s)
        clock["t"] += s

    monkeypatch.setattr(supervisor, "run_segment", fake_run)
    monkeypatch.setattr(supervisor.time, "time", lambda: clock["t"])
    monkeypatch.setattr(supervisor.time, "sleep", fake_sleep)
    supervisor.hunt([_scope(tmp_path, n) for n in "abc"], hours=3, minutes=10, model="m", max_turns=5)

    assert calls[:3] == ["a", "b", "c"]  # rotation: least recently run first
    assert supervisor.QUOTA_SLEEP_S in sleeps  # quota -> sleep, then the hunt goes on
    assert calls.count("b") == 2  # two stagnant segments -> cooldown, never picked again
    assert all(s >= 0 for s in sleeps)


def test_quota_wake_uses_the_announced_reset():
    now = 1_000_000.0
    res = SegmentResult(
        program="p", run_id=1, status="quota", rate_limit={"status": "rejected", "resetsAt": now + 3600}
    )
    assert supervisor.quota_wake(res, now) == now + 3600 + supervisor.QUOTA_MARGIN_S
    for bad in (
        {},
        {"resetsAt": now - 10},
        {"resetsAt": now + 30 * 86400},
        {"resetsAt": now + 8 * 86400 + 1},
        {"resetsAt": "soon"},
        {"resetsAt": True},
    ):
        res.rate_limit = bad
        assert supervisor.quota_wake(res, now) == now + supervisor.QUOTA_SLEEP_S


def test_quota_past_the_deadline_stops_the_hunt(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    clock = {"t": 1_000_000.0}
    calls: list[str] = []

    def fake_run(scope_file, **kw):
        calls.append(scope_file.stem)
        return SegmentResult(
            program="a", run_id=1, status="quota", rate_limit={"status": "rejected", "resetsAt": clock["t"] + 86400}
        )

    monkeypatch.setattr(supervisor, "run_segment", fake_run)
    monkeypatch.setattr(supervisor.time, "time", lambda: clock["t"])
    monkeypatch.setattr(supervisor.time, "sleep", lambda s: (_ for _ in ()).throw(AssertionError("slept")))
    supervisor.hunt([_scope(tmp_path, "a")], hours=2, minutes=10, model="m", max_turns=5)
    assert calls == ["a"]


def test_stream_rate_limit_event_and_quota_line():
    import io
    import json

    from bh.runner import run

    info = {"status": "allowed", "resetsAt": 1795935600, "unifiedWindows": {"seven_day": {"utilization": 0.05}}}
    lines = [json.dumps({"type": "rate_limit_event", "rate_limit_info": info}) + "\n"]

    class Proc:
        stdout = iter(lines)

    res = SegmentResult(program="p", run_id=1)
    run.consume_stream(Proc(), io.StringIO(), res, lambda s: None)
    assert res.rate_limit == info
    assert run.quota_line(info).startswith(" · quota seven_day 5% (resets ")
    assert run.quota_line({}) == ""


def _clocked(monkeypatch, start=1_000_000.0):
    clock = {"t": start}
    monkeypatch.setattr(supervisor.time, "time", lambda: clock["t"])
    monkeypatch.setattr(supervisor.time, "sleep", lambda s: clock.__setitem__("t", clock["t"] + s))
    return clock


def test_two_refusals_park_the_program(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    clock = _clocked(monkeypatch)
    calls: list[str] = []

    def fake_run(scope_file, **kw):
        name = scope_file.stem
        calls.append(name)
        clock["t"] += 600
        status = "refusal" if name == "b" else "ok"
        return SegmentResult(program=name, run_id=len(calls), status=status, progress=1)

    monkeypatch.setattr(supervisor, "run_segment", fake_run)
    supervisor.hunt([_scope(tmp_path, n) for n in "abc"], hours=12, minutes=10, model="m", max_turns=5)

    assert calls.count("b") == 2  # paused 6 h after the first refusal, parked after the second
    second = len(calls) - 1 - calls[::-1].index("b")
    assert second > 30  # the second refusal came after the 6 h pause, not right away
    assert {"a", "c"} <= set(calls[second + 1 :])  # the others go on


def test_program_not_ready_mid_hunt_is_parked(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    clock = _clocked(monkeypatch)
    calls: list[str] = []

    def fake_run(scope_file, **kw):
        name = scope_file.stem
        calls.append(name)
        clock["t"] += 600
        if name == "c":
            raise supervisor.ProgramNotReady("c", ["scanners_allowed"], "c: scanners_allowed unknown")
        return SegmentResult(program=name, run_id=len(calls), status="ok", progress=1)

    monkeypatch.setattr(supervisor, "run_segment", fake_run)
    supervisor.hunt([_scope(tmp_path, n) for n in "abc"], hours=2, minutes=10, model="m", max_turns=5)
    assert calls.count("c") == 1
    assert calls.count("a") > 2 and calls.count("b") > 2


def test_a_segment_that_crashes_parks_its_program_only(tmp_path, monkeypatch, capsys):
    """M4: a sandbox file that breaks ingestion (an Exception, not a SystemExit) parks that program; the others go
    on. It would fail again at once: its files stay."""
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    clock = _clocked(monkeypatch)
    calls: list[str] = []

    def fake_run(scope_file, **kw):
        name = scope_file.stem
        calls.append(name)
        clock["t"] += 600
        if name == "b":
            raise AttributeError("'list' object has no attribute 'get'")
        return SegmentResult(program=name, run_id=len(calls), status="ok", progress=1)

    monkeypatch.setattr(supervisor, "run_segment", fake_run)
    supervisor.hunt([_scope(tmp_path, n) for n in "abc"], hours=2, minutes=10, model="m", max_turns=5)
    assert calls.count("b") == 1
    assert calls.count("a") > 2 and calls.count("c") > 2
    assert "b: parked until the end of the hunt (segment failed: AttributeError(" in capsys.readouterr().out


def test_a_refusal_on_a_cause_already_refused_does_not_climb_the_ladder(tmp_path, monkeypatch):
    """M8: the same page refused again costs a cooldown, not the program's place in the hunt."""
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    clock = _clocked(monkeypatch)
    calls: list[str] = []

    def fake_run(scope_file, **kw):
        name = scope_file.stem
        calls.append(name)
        clock["t"] += 600
        if name == "b":
            first = calls.count("b") == 1
            return SegmentResult(program=name, run_id=len(calls), status="refusal", refusal_repeat=not first)
        return SegmentResult(program=name, run_id=len(calls), status="ok", progress=1)

    monkeypatch.setattr(supervisor, "run_segment", fake_run)
    supervisor.hunt([_scope(tmp_path, n) for n in "ab"], hours=24, minutes=10, model="m", max_turns=5)
    assert calls.count("b") > 2  # never parked: every later refusal was on the page already refused


def test_other_system_exit_stops_the_hunt(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    _clocked(monkeypatch)

    def fake_run(scope_file, **kw):
        raise SystemExit("container bh-agent is not running")

    monkeypatch.setattr(supervisor, "run_segment", fake_run)
    with pytest.raises(SystemExit, match="not running"):
        supervisor.hunt([_scope(tmp_path, "a")], hours=1, minutes=10, model="m", max_turns=5)


def test_preflight_excludes_unready_and_refused_programs(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    clock = _clocked(monkeypatch)
    now = clock["t"]
    Board().meta_set("refusals:b", json.dumps([now - 86400, now - 7200, now - 3600]))
    unready = tmp_path / "c.yaml"
    unready.write_text("program: c\nplatform: yeswehack\nin_scope: [c.test]\nautomation_allowed: true\n")
    calls: list[str] = []

    def fake_run(scope_file, **kw):
        calls.append(scope_file.stem)
        clock["t"] += 600
        return SegmentResult(program=scope_file.stem, run_id=len(calls), status="ok", progress=1)

    monkeypatch.setattr(supervisor, "run_segment", fake_run)
    files = [_scope(tmp_path, "a"), _scope(tmp_path, "b"), unready]
    supervisor.hunt(files, hours=1, minutes=10, model="m", max_turns=5)
    out = capsys.readouterr().out
    assert set(calls) == {"a"}
    assert "b: excluded (3 model refusals" in out
    assert "c: excluded (" in out and "scanners_allowed" in out


def test_no_ready_program_exits_cleanly(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    p = tmp_path / "x.yaml"
    p.write_text("program: x\nplatform: yeswehack\nin_scope: [x.test]\nautomation_allowed: false\n")
    monkeypatch.setattr(supervisor, "run_segment", lambda *a, **k: (_ for _ in ()).throw(AssertionError("ran")))
    supervisor.hunt([p], hours=1, minutes=10, model="m", max_turns=5)
    assert "no program is ready" in capsys.readouterr().out
