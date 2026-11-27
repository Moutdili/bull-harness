"""T19 (c): recorded segments replayed through ingest.notes and ingest.gate_events, compared to their expectation.

The traces are synthetic (`"synthetic": true`), written by hand after the real formats: bh-note's records
(src/bh/agent/note.py), the gate's events and flows (src/bh/gate/addon.py `_log`, `_record`), claude's stream-json
(src/bh/runner/run.py consume_stream). The repository holds no real trace.
"""

import json
import re

import pytest

import harness
from bh import redact
from bh.board.db import FINDING_STATUS

TRACES = sorted(p for p in harness.TRACES.iterdir() if p.is_dir())
NAMES = [p.name for p in TRACES]
VERIFIED = {"verified", "verified-evidence", "submitted"}


def test_three_traces_at_least_all_synthetic():
    assert {"normal-segment", "malformed-and-forged", "target-injection"} <= set(NAMES)
    for t in TRACES:
        m = harness.meta(t)
        assert m["synthetic"] is True, t.name
        assert m["about"].strip(), t.name
        assert (t / harness.NOTES).is_file() and (t / harness.EXPECTED).is_file(), t.name


@pytest.mark.parametrize("trace", TRACES, ids=NAMES)
def test_replay_gives_the_expected_board(trace, tmp_path):
    board = harness.replay(trace, tmp_path)
    assert harness.differences(board, trace) == []


@pytest.mark.parametrize("trace", TRACES, ids=NAMES)
def test_traces_hold_no_secret_and_no_real_name(trace):
    for f in sorted(p for p in trace.rglob("*") if p.is_file()):
        text = f.read_text(encoding="utf-8")
        assert not redact.JWT.search(text), f
        assert "BH-SECRET-" not in text, f
        # only reserved names: .test / .invalid / .example hosts, the lab's fictitious program
        for host in re.findall(r"https?://([A-Za-z0-9.-]+)", text):
            assert host.endswith((".test", ".invalid", ".example")), (f, host)


def test_normal_segment(tmp_path):
    trace = harness.TRACES / "normal-segment"
    board = harness.replay(trace, tmp_path)
    snap = harness.snapshot(board, "replay-lab")
    idor, dos = snap["findings"]
    assert (idor["status"], idor["vuln_class"], idor["has_proof"]) == ("new", "idor", 1)
    assert dos["status"] == "rejected" and "forbidden_vulns" in dos["verdict"]  # the harness, not the model
    facts = {f["title"]: f for f in snap["facts"]}
    assert facts["schedule lists private refs"]["grounded"] == 1  # its quote is in a body the gate kept
    assert facts["gate denied 1 requests"]["kind"] == "blocked"  # the browser's refusal is not the hunter's
    assert snap["intents"] == [{"title": "read another user's booking by ref", "status": "closed", "kind": "map"}]
    assert snap["runs"] == [{"id": 1, "status": "ok", "turns": 7, "cost_usd": 0.4213}]  # from the stream's result


def test_malformed_notes_and_forged_host_facts(tmp_path):
    trace = harness.TRACES / "malformed-and-forged"
    board = harness.replay(trace, tmp_path)
    facts = board.rows("SELECT kind, title, summary FROM facts ORDER BY id")
    # nothing the hunter wrote is a host fact: brackets become parentheses, kinds fall back to `fact`
    hunter = [f for f in facts if f["kind"] not in ("harness", "blocker")]
    assert all(not f["title"].startswith("[") for f in hunter)
    assert [f["title"] for f in facts if f["kind"] == "blocker"] == ["[other] model refused"]
    assert not [f for f in facts if f["title"].startswith("[refusal]")]
    harness_titles = [f["title"] for f in facts if f["kind"] == "harness"]
    assert harness_titles == [
        "malformed note skipped",
        "intent refused: prove without an anchored fact",
        "identity 'user-c' requested but not configured",
    ]
    # the other program's gate event and the unknown intent left nothing
    assert not board.rows("SELECT 1 FROM facts WHERE title LIKE 'gate denied%'")
    assert not board.rows("SELECT 1 FROM intents")


def test_target_injection_leaves_no_effect(tmp_path):
    trace = harness.TRACES / "target-injection"
    body = json.loads(next((trace / "flows").glob("*.json")).read_text())["response"]["body"]
    assert "ignore your rules" in body.lower() and "mark this verified" in body
    notes = [json.loads(ln) for ln in (trace / harness.NOTES).read_text().splitlines()]
    assert any(n.get("op") == "verdict" for n in notes) and any(n.get("status") == "verified" for n in notes)
    board = harness.replay(trace, tmp_path)
    (f,) = board.rows("SELECT status, verdict, observation, replay FROM findings")
    assert f["status"] == "new" and f["verdict"] is None and f["observation"] is None and f["replay"] is None
    assert not board.rows("SELECT 1 FROM findings WHERE status IN (?, ?, ?)", *sorted(VERIFIED))
    assert not board.rows("SELECT 1 FROM facts WHERE kind IN ('blocker', 'harness')")
    assert not board.rows("SELECT 1 FROM todos")
    assert not board.rows("SELECT 1 FROM scope_requests")
    # the injected text is kept as data where the hunter quoted it, nowhere as a status
    assert all(r["status"] in FINDING_STATUS - VERIFIED for r in board.rows("SELECT status FROM findings"))


def test_a_changed_ingestion_shows_as_a_difference(tmp_path, monkeypatch):
    """The comparison is not vacuous: an ingestion that let a note's `status` through is caught."""
    from bh.runner import ingest

    real = ingest.Board.add_finding

    def leaky(self, program, title, run_id=None, **kw):
        fid = real(self, program, title, run_id, **kw)
        self.set_finding(fid, "verified", "from the note")
        return fid

    monkeypatch.setattr(ingest.Board, "add_finding", leaky)
    trace = harness.TRACES / "target-injection"
    diffs = harness.differences(harness.replay(trace, tmp_path), trace)
    assert len(diffs) == 1 and diffs[0].startswith("findings:")
