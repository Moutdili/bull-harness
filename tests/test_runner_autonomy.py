"""The runner acts on the walls of a segment without a human: refusals, WAF hosts, expired identities."""

import json
import os
import time

from bh import paths
from bh.assets import Graph
from bh.board import Board
from bh.runner import ingest, run
from bh.scope import scope_from_dict


def _board(tmp_path, monkeypatch) -> Board:
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    return Board(tmp_path / "var" / "board.sqlite")


def _env(cmd: list[str], key: str) -> str:
    return next(x.split("=", 1)[1] for x in cmd if x.startswith(f"{key}="))


def test_stale_identity_is_not_offered(tmp_path, monkeypatch):
    b = _board(tmp_path, monkeypatch)
    d = paths.identities_dir("p")
    d.mkdir(parents=True)
    for name in ("alice", "bob"):
        (d / f"{name}.json").write_text("{}")
        os.utime(d / f"{name}.json", (1000, 1000))
    b.meta_set("identity-stale:alice:p", "2000")  # the gate saw alice expire after her file was written
    b.meta_set("identity-stale:carol:p", "2000")  # a scope identity without a file: stale too
    scope = scope_from_dict(
        {"program": "p", "platform": "x", "in_scope": ["a.test"], "identities": [{"name": "carol"}, {"name": "dan"}]}
    )
    assert run.live_identities(b, "p") == ["bob"]
    names = run.live_identities(b, "p", also=[i["name"] for i in scope.identities])
    cmd = run.agent_command(scope, "t", run_id=1, model="m", max_turns=5, effort=None, session=None, identities=names)
    assert _env(cmd, "BH_IDENTITIES") == "bob,dan"
    os.utime(d / "alice.json", (3000, 3000))  # the file was refreshed: the mark is lifted
    assert run.live_identities(b, "p") == ["alice", "bob"]


def test_finish_on_refusal_records_a_blocker_not_a_todo(tmp_path, monkeypatch):
    b = _board(tmp_path, monkeypatch)
    scope = scope_from_dict({"program": "p", "platform": "local", "in_scope": ["a.test"]})
    rid = b.run_start("p", "m")
    flows = paths.flows_log()
    flows.parent.mkdir(parents=True, exist_ok=True)
    flows.write_text(
        json.dumps({"run": rid, "class": "target", "method": "GET", "url": "https://x.other.test/"}) + "\n"
    )
    monkeypatch.setattr(run, "rotate_notes", lambda prog, run_id: tmp_path / "none.jsonl")
    monkeypatch.setattr(ingest, "gate_events", lambda *a: ingest.GateOutcome(blockers=1, waf_hosts={"a.test"}))
    res = run.SegmentResult(program="p", run_id=rid, status="refusal")
    res.tool_log = [{"cmd": "sqlmap -u https://a.test/x"}, {"cmd": ""}]
    run.finish(b, res, scope, (0, 0), effort=None, note="refused")

    assert b.rows("SELECT COUNT(*) n FROM todos")[0]["n"] == 0
    blockers = b.rows("SELECT title, summary FROM facts WHERE kind='blocker'")
    assert [r["title"] for r in blockers] == [f"[refusal] run {rid}"]
    assert blockers[0]["summary"].startswith("sqlmap -u https://a.test/x\nlog: ")
    assert len(run.recent_refusals(b, "p")) == 1
    assert res.new_blockers == 2  # the gate's WAF blocker + the refusal
    assert b.rows("SELECT blockers FROM runs WHERE id=?", rid)[0]["blockers"] == 2
    assert "a.test" in Graph(b, scope).blocked()  # the WAF host is set aside for an hour
    oos = b.rows("SELECT summary FROM facts WHERE kind='out-of-scope'")
    assert [r["summary"] for r in oos] == ["x.other.test"]
    # the next run of the program is told which lead is closed
    assert run.last_refusal(b, "p", b.run_start("p", "m")) == "sqlmap -u https://a.test/x"


def test_refusal_window_is_seven_days(tmp_path, monkeypatch):
    b = _board(tmp_path, monkeypatch)
    now = time.time()
    b.meta_set("refusals:p", json.dumps([now - 8 * 86400, now - 3600, "junk"]))
    assert run.record_refusal(b, "p", now) == 2
    assert run.recent_refusals(b, "p", now) == [now - 3600, now]
    b.meta_set("refusals:p", "not json")
    assert run.recent_refusals(b, "p", now) == []


def test_pending_findings_counts_every_waiting_proof(tmp_path, monkeypatch):
    b = _board(tmp_path, monkeypatch)
    b.add_finding("p", "with proof", proof={"steps": []})  # left 'new' by an earlier segment
    b.add_finding("p", "no proof")
    done = b.add_finding("p", "judged", proof={"steps": []})
    b.set_finding(done, "rejected")
    assert run.pending_findings(b, "p") == 1
