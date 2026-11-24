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
