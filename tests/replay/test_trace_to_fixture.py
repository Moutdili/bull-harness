"""T19 (d): tools/trace-to-fixture.py turns a run of a BH_HOME into a replay fixture, run here on a synthetic trace laid
out as the runner and the gate lay out a real one."""

import importlib.util
import json
import shutil
from pathlib import Path

import pytest

import harness
from bh import paths
from bh.board import Board

TOOL = Path(__file__).resolve().parents[2] / "tools" / "trace-to-fixture.py"
SRC = harness.TRACES / "normal-segment"
PROGRAM, HOST = "replay-lab", "app.replay.test"


def _tool():
    spec = importlib.util.spec_from_file_location("trace_to_fixture", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A BH_HOME holding run 1 of `replay-lab` where the runner and the gate put its files."""
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    (tmp_path / "scopes").mkdir()
    (tmp_path / "scopes" / "replay.yaml").write_text(
        f"program: {PROGRAM}\nplatform: local\nin_scope: [{HOST}]\nforbidden_vulns: [dos]\n"
        "identities:\n  - {name: user-a}\n  - {name: user-b}\n"
    )
    board = Board(paths.board_db())
    board.db.execute("INSERT INTO runs(id, program, model, started, status) VALUES (1, ?, 'm', 0, 'ok')", (PROGRAM,))
    board.db.commit()
    paths.work_bh(PROGRAM).mkdir(parents=True)
    shutil.copyfile(SRC / "notes.jsonl", paths.work_bh(PROGRAM) / "notes-1.jsonl")
    paths.state().mkdir(parents=True)
    other = {"kind": "blocked", "url": f"http://{HOST}/x", "client": "agent", "program": PROGRAM, "run": 2}
    paths.events_log().write_text((SRC / "events.jsonl").read_text() + json.dumps(other) + "\n")
    shutil.copyfile(SRC / "flows.jsonl", paths.flows_log())
    shutil.copytree(SRC / "flows", paths.state() / paths.FLOWS_DIR)
    paths.runs_dir().mkdir(parents=True)
    shutil.copyfile(SRC / "stream.jsonl", paths.run_log(1, PROGRAM))
    return tmp_path


def _all_text(d: Path) -> str:
    return "\n".join(p.read_text() for p in sorted(d.rglob("*")) if p.is_file())


def test_fixture_from_a_run_is_templated_and_replays(home):
    out = home / "fixture"
    assert _tool().main(["1", str(out)]) == 0
    text = _all_text(out)
    for name in (HOST, PROGRAM, "appreplaytest", "user-a", "user-b"):
        assert name not in text.lower(), name
    assert "target-1.example" in text and "identity-2" in text
    meta = harness.meta(out)
    assert meta["synthetic"] is False and meta["program"] == "program" and meta["run_id"] == 1
    assert sorted(p.name for p in (out / "flows").iterdir()) == sorted(p.name for p in (SRC / "flows").iterdir())
    assert len((out / "events.jsonl").read_text().splitlines()) == 2  # run 2's event left out
    # the fixture replays to the same board as the source trace, names aside
    board = harness.replay(out, home / "replay")
    assert harness.differences(board, out) == []
    got = harness.snapshot(board, "program")
    want = harness.expected(SRC)
    assert [(f["status"], f["vuln_class"]) for f in got["findings"]] == [
        (f["status"], f["vuln_class"]) for f in want["findings"]
    ]
    assert [(f["kind"], f["grounded"]) for f in got["facts"]] == [(f["kind"], f["grounded"]) for f in want["facts"]]
    assert got["findings"][0]["url"] == "http://target-1.example/api/v1/bookings/bk_0a1b2c3d4e5f"


def test_a_surviving_name_writes_nothing(home):
    notes = paths.work_bh(PROGRAM) / "notes-1.jsonl"
    with notes.open("a") as fh:  # the host without its dots: no template catches it, the check does
        fh.write(json.dumps({"op": "fact", "title": "see AppReplayTest docs", "summary": ""}) + "\n")
    out = home / "fixture"
    assert _tool().main(["1", str(out)]) == 2
    assert not out.exists()
    assert not [p for p in home.iterdir() if p.name.startswith(".trace-")]


def test_secrets_go_through_bh_redact(home):
    notes = paths.work_bh(PROGRAM) / "notes-1.jsonl"
    with notes.open("a") as fh:
        fh.write(
            json.dumps(
                {
                    "op": "fact",
                    "title": "creds",
                    "summary": "password=hunter2 Authorization: Bearer abc.def eyJhbGciOiJIUzI1.eyJzdWIiOiIx.c2ln",
                    "token": "t0k3n",
                }
            )
            + "\n"
        )
    out = home / "fixture"
    assert _tool().main(["1", str(out), "--no-expected"]) == 0
    text = _all_text(out)
    for secret in ("hunter2", "abc.def", "eyJhbGciOiJIUzI1", "t0k3n"):
        assert secret not in text, secret
    assert not (out / harness.EXPECTED).exists()


def test_refuses_a_non_empty_target_and_an_unknown_run(home):
    (home / "busy").mkdir()
    (home / "busy" / "x").write_text("x")
    assert _tool().main(["1", str(home / "busy")]) == 1
    assert _tool().main(["99", str(home / "new")]) == 1
