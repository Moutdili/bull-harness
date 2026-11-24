"""TODO 4.2 acceptance: 3 programs, forced stagnation -> rotation then cooldown; simulated quota -> sleep, resume."""

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
    for bad in ({}, {"resetsAt": now - 10}, {"resetsAt": now + 30 * 86400}, {"resetsAt": "soon"}):
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
