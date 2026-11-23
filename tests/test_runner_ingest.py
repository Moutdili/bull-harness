import json

from bh.board import Board
from bh.runner.run import ingest_gate_events, ingest_notes


def _write(path, recs):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in recs))


def test_handoff_and_dead_ends_are_not_progress(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    _write(tmp_path / "notes.jsonl", [
        {"op": "fact", "title": "HANDOFF: nothing new", "kind": "handoff"},
        {"op": "fact", "title": "alg none rejected", "kind": "dead-end"},
    ])
    facts, findings, todos, progress = ingest_notes(b, "p", 1, tmp_path)
    assert (facts, findings, progress) == (2, 0, 0)
    _write(tmp_path / "notes.jsonl", [
        {"op": "fact", "title": "HANDOFF: nothing new", "kind": "handoff"},
        {"op": "fact", "title": "alg none rejected", "kind": "dead-end"},
        {"op": "fact", "title": "/metrics exposed", "kind": "fact"},
        {"op": "finding", "title": "IDOR", "severity": "high"},
    ])
    assert ingest_notes(b, "p", 2, tmp_path)[3] == 2


def test_auth_todos(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    b = Board(tmp_path / "b.sqlite")
    ev = tmp_path / "var" / "state" / "events.jsonl"
    anon = [{"kind": "auth", "host": "t", "program": "p"}] * 3
    _write(ev, anon)
    assert ingest_gate_events(b, "p", 1, identities=["user-a"])[1] == 0  # probing unauth on purpose
    _write(ev, anon * 2)
    assert ingest_gate_events(b, "p", 2, identities=[])[1] == 1  # no identity at all -> ask the human
    _write(ev, anon * 3 + [{"kind": "auth", "host": "t", "program": "p", "identity": "user-a"}] * 3)
    assert ingest_gate_events(b, "p", 3, identities=["user-a"])[1] == 1  # expired session
    titles = [r["title"] for r in b.rows("SELECT title FROM todos")]
    assert any("user-a" in t and "expired" in t for t in titles)
