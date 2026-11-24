import json

from bh.board import Board
from bh.runner import ingest


def _write(path, recs):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in recs))


def test_notes_are_read_from_the_rotated_file(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    f = tmp_path / "notes-1.jsonl"
    _write(
        f,
        [
            {"op": "fact", "title": "HANDOFF: nothing new", "kind": "handoff"},
            {"op": "finding", "title": "IDOR", "severity": "high"},
            {"op": "todo", "kind": "auth", "title": "need a session"},
            {"op": "intent", "title": "test /api/x"},
        ],
    )
    assert ingest.notes(b, "p", 1, f) == (1, 1, 1)
    assert ingest.notes(b, "p", 2, tmp_path / "missing.jsonl") == (0, 0, 0)


def test_auth_todos(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    b = Board(tmp_path / "b.sqlite")
    ev = tmp_path / "var" / "state" / "events.jsonl"
    anon = [{"kind": "auth", "host": "t", "program": "p"}] * 3
    _write(ev, anon)
    assert ingest.gate_events(b, "p", 1, identities=["user-a"]) == 0  # probing unauth on purpose
    _write(ev, anon * 2)
    assert ingest.gate_events(b, "p", 2, identities=[]) == 1  # no identity at all -> ask the human
    _write(ev, anon * 3 + [{"kind": "auth", "host": "t", "program": "p", "identity": "user-a"}] * 3)
    assert ingest.gate_events(b, "p", 3, identities=["user-a"]) == 1  # expired session
    titles = [r["title"] for r in b.rows("SELECT title FROM todos")]
    assert any("user-a" in t and "expired" in t for t in titles)


def test_reset_program(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    b.add_fact("p", "x")
    b.add_fact("q", "y")
    b.meta_set("notes:p", "42")
    assert b.reset_program("p")["facts"] == 1
    assert b.meta_get("notes:p") == "" and len(b.rows("SELECT * FROM facts")) == 1


def test_manual_requests_seen_by_the_gate_count_as_tested(tmp_path, monkeypatch):
    from bh.agent import contract as c
    from bh.runner.run import manually_tested

    monkeypatch.setenv("BH_HOME", str(tmp_path))
    b = Board(tmp_path / "b.sqlite")
    rid = b.run_start("p", "m")
    other = b.run_start("q", "m")
    _write(
        tmp_path / "var" / "state" / "flows.jsonl",
        [
            {"run": rid, "method": "GET", "url": "http://h/api/Users/12", "ua": "curl/8.10.1"},
            {"run": rid, "method": "GET", "url": "http://h/api/Cards", "ua": "Fuzz Faster U Fool v2.3.0"},
            {"run": other, "method": "GET", "url": "http://h/api/Feedbacks", "ua": "curl/8.10.1"},
            {
                "run": None,
                "method": "GET",
                "url": "http://h/api/Quantitys",
                "ua": "curl/8.10.1",
            },  # operator, between runs
        ],
    )
    tested = manually_tested(b, "p")
    assert tested == {("http://h:80", "GET /api/Users/{id}")}
    d = tmp_path / "bh"
    c.append_jsonl(
        d / c.ENDPOINTS,
        *[
            {"origin": "http://h:80", "key": k, "params": p, "source": "js"}
            for k, p in (("GET /api/Users/", []), ("GET /api/Cards", []), ("GET /s", ["q"]))
        ],
    )
    s = c.surface(d, also_tested=tested)
    assert "1 tested, 2 untested" in s and "GET /s ?q  → bh-sqli / bh-xss" in s
    assert c.surface_counts(d, also_tested=tested) == (1, 0)
    for phase in c.REQUIRED_PHASES:
        c.record_phase(d, "http://h:80", phase, status="error rc=1" if phase == "scan" else "ok", count=0, raw="")
    assert c.surface_counts(d, also_tested=tested) == (1, 2)  # a tool error is not coverage


def test_legacy_cursor_is_honoured_once(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    f = tmp_path / "notes-9.jsonl"
    _write(f, [{"op": "finding", "title": "old", "severity": "low"}])
    old_size = f.stat().st_size
    with open(f, "a") as fh:
        fh.write('{"op": "fact", "title": "new"}\n')
    b.meta_set("notes:p", str(old_size))  # what the pre-rotation cursor had already ingested
    assert ingest.notes(b, "p", 9, f) == (1, 0, 0)
    assert b.meta_get("notes:p") == ""
    assert ingest.notes(b, "p", 10, f) == (1, 1, 0)  # no cursor any more: a new file is read in full
