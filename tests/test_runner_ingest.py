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


def test_findings_of_excluded_classes_are_rejected_by_the_harness(tmp_path):
    from bh.scope import canonical_vuln, scope_from_dict

    assert canonical_vuln("Denial of Service") == canonical_vuln("DDoS") == "dos"
    assert canonical_vuln("Missing_Security headers") == "missing-headers"
    scope = scope_from_dict(
        {"program": "p", "platform": "x", "in_scope": ["a.test"], "forbidden_vulns": ["DoS", "self-xss"]}
    )
    b = Board(tmp_path / "b.sqlite")
    f = tmp_path / "notes-1.jsonl"
    _write(
        f,
        [
            {"op": "finding", "title": "slow regex", "severity": "high", "vuln_class": "denial-of-service"},
            {"op": "finding", "title": "IDOR", "severity": "high", "vuln_class": "idor"},
        ],
    )
    assert ingest.notes(b, "p", 1, f, scope) == (0, 1, 0)
    rows = {r["title"]: (r["status"], r["verdict"]) for r in b.rows("SELECT title, status, verdict FROM findings")}
    assert rows["slow regex"][0] == "rejected" and "forbidden_vulns: DoS" in rows["slow regex"][1]
    assert rows["IDOR"][0] == "new"


def test_malformed_notes_never_stop_the_host(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    f = tmp_path / "notes-9.jsonl"
    f.write_text(
        "\n".join(
            [
                "[1, 2]",
                '"text"',
                json.dumps({"op": "finding", "title": None, "vuln_class": [1], "severity": {"x": 1}, "proof": [1]}),
                json.dumps({"op": "todo", "title": 5, "kind": None}),
                json.dumps({"op": "done", "intent_id": "9" * 30}),
                json.dumps({"op": "finding", "title": "ok", "poc": "curl -H 'Cookie: sid=s3cr3t' https://h/"}),
            ]
        )
        + "\n"
    )
    _, findings, todos = ingest.notes(b, "p", 9, f)
    assert findings == 2 and todos == 1
    pocs = [r["poc"] for r in b.rows("SELECT poc FROM findings")]
    assert all("s3cr3t" not in (p or "") for p in pocs)
    assert all(r["proof"] is None for r in b.rows("SELECT proof FROM findings"))  # a list is no proof
