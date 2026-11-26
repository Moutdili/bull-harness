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
            {"op": "blocked", "reason": "waf", "title": "a.test challenges", "host": "a.test"},
            {"op": "intent", "title": "test /api/x"},
        ],
    )
    assert ingest.notes(b, "p", 1, f) == (1, 1, 1)
    assert ingest.notes(b, "p", 2, tmp_path / "missing.jsonl") == (0, 0, 0)
    assert b.rows("SELECT evidence FROM facts WHERE kind='blocker'")[0]["evidence"] == "host:a.test"


def test_blocked_closes_its_intent_and_old_todos_become_blockers(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    iid = b.add_intent("p", "IDOR on /api/orders")
    f = tmp_path / "notes-1.jsonl"
    _write(
        f,
        [
            {"op": "blocked", "reason": "account", "title": "needs a 2nd account", "intent": f"I{iid}"},
            {"op": "blocked", "reason": "bored", "title": "x"},
            {"op": "todo", "kind": "waf", "title": "old waf todo"},
            {"op": "todo", "kind": "quota", "title": "old quota todo"},
            {"op": "todo", "kind": "scope-question", "title": "is cdn.a.test in scope?"},
        ],
    )
    assert ingest.notes(b, "p", 1, f) == (1, 0, 4)
    assert b.rows("SELECT status, result, outcome FROM intents")[0][:] == (
        "closed",
        "blocked: account",
        "open_proof_gap",
    )
    titles = [r["title"] for r in b.rows("SELECT title FROM facts WHERE kind='blocker' ORDER BY id")]
    assert titles == ["[account] needs a 2nd account", "[other] x", "[waf] old waf todo", "[other] old quota todo"]
    assert b.rows("SELECT kind FROM facts WHERE title LIKE 'is cdn%'")[0]["kind"] == "out-of-scope"
    assert b.rows("SELECT COUNT(*) n FROM todos")[0]["n"] == 0


def _blockers(b):
    return [r["title"] for r in b.rows("SELECT title FROM facts WHERE kind='blocker' ORDER BY id")]


def test_auth_walls_are_blockers(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    b = Board(tmp_path / "b.sqlite")
    ev = tmp_path / "var" / "state" / "events.jsonl"
    anon = [{"kind": "auth", "host": "t", "program": "p"}] * 3
    _write(ev, anon)
    out = ingest.gate_events(b, "p", 1, identities=["user-a"])
    assert out == ingest.GateOutcome() and _blockers(b) == []  # probing unauth on purpose
    _write(ev, anon * 2)
    assert ingest.gate_events(b, "p", 2, identities=[]).blockers == 1  # no identity at all: a wall
    _write(ev, anon * 3)
    assert ingest.gate_events(b, "p", 3, identities=[]).blockers == 0  # once per host while visible
    same_route = [
        {"kind": "auth", "host": "t", "program": "p", "identity": "user-a", "url": "http://t/o/1", "ts": 900.0}
    ] * 3
    _write(ev, anon * 4 + same_route)
    out = ingest.gate_events(b, "p", 4, identities=["user-a"])
    assert out.stale == set() and out.blockers == 0  # one route refused three times: an access refusal (H4)
    routes = [{**same_route[0], "url": f"http://t/{p}/1", "ts": 1000.0 + i} for i, p in enumerate("abc")]
    _write(ev, anon * 4 + same_route + routes)
    out = ingest.gate_events(b, "p", 5, identities=["user-a"])
    assert out.stale == set() and out.blockers == 0  # 401s under an identity are access tests: the gate decides
    dead = {"kind": "session-dead", "host": "t", "program": "p", "identity": "user-a", "status": 401}
    _write(ev, anon * 4 + same_route + routes + [{**dead, "reason": "401-repeated", "ts": 1002.0}])
    out = ingest.gate_events(b, "p", 6, identities=["user-a"])
    assert out.blockers == 1 and out.stale == {"user-a"}
    assert float(b.meta_get("identity-stale:user-a:p")) == 1002.0  # the event's time, not the ingestion's
    assert _blockers(b) == [
        "[auth] t requires a session (3x 401)",
        "[auth] identity 'user-a': session dead on t (401 on several routes)",
    ]
    assert b.rows("SELECT COUNT(*) n FROM todos")[0]["n"] == 0


def test_waf_and_missing_identity(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    b = Board(tmp_path / "b.sqlite")
    ev = tmp_path / "var" / "state" / "events.jsonl"
    waf = {"kind": "waf", "host": "a.t", "program": "p", "status": 403, "server": "cloudflare"}
    _write(
        ev,
        [waf, waf, {**waf, "host": "b.t"}, {**waf, "program": "other"}]
        + [{"kind": "identity-missing", "identity": "admin", "program": "p"}] * 2
        + [{"kind": "blocked", "url": "https://evil.t/x", "program": "p"}],
    )
    out = ingest.gate_events(b, "p", 1, identities=[])
    assert out.blockers == 2 and out.waf_hosts == {"a.t", "b.t"} and out.stale == set()
    assert _blockers(b) == ["[waf] a.t answers with a WAF challenge", "[waf] b.t answers with a WAF challenge"]
    kinds = {r["title"]: r["kind"] for r in b.rows("SELECT title, kind FROM facts WHERE kind != 'blocker'")}
    assert kinds == {"identity 'admin' requested but not configured": "harness", "gate denied 1 requests": "blocked"}


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
                json.dumps({"op": "blocked", "reason": ["x"], "title": None, "intent": {"a": 1}, "host": 7}),
                json.dumps({"op": "done", "intent_id": "9" * 30}),
                json.dumps({"op": "finding", "title": "ok", "poc": "curl -H 'Cookie: sid=s3cr3t' https://h/"}),
            ]
        )
        + "\n"
    )
    _, findings, blockers = ingest.notes(b, "p", 9, f)
    assert findings == 2 and blockers == 2
    pocs = [r["poc"] for r in b.rows("SELECT poc FROM findings")]
    assert all("s3cr3t" not in (p or "") for p in pocs)
    assert all(r["proof"] is None for r in b.rows("SELECT proof FROM findings"))  # a list is no proof


def test_session_dead_marks_the_identity_stale_at_once(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    b = Board(tmp_path / "b.sqlite")
    ev = tmp_path / "var" / "state" / "events.jsonl"
    dead = {"kind": "session-dead", "identity": "user-a", "host": "t", "status": 302, "program": "p", "run": 7}
    recs = [{**dead, "reason": "login-redirect"}, {**dead, "status": 401, "reason": "401"}]
    recs += [{"kind": "auth", "host": "t", "program": "p", "identity": "user-a"}] * 3  # same identity: no 2nd blocker
    recs += [{**dead, "identity": "user-b", "program": "other"}, {**dead, "identity": ""}]
    _write(ev, recs)
    out = ingest.gate_events(b, "p", 7, identities=["user-a", "user-b"])
    assert out.stale == {"user-a"} and out.blockers == 1
    assert float(b.meta_get("identity-stale:user-a:p")) > 0 and not b.meta_get("identity-stale:user-b:p")
    assert _blockers(b) == ["[auth] identity 'user-a': session dead on t (a redirect to its login page)"]
    _write(ev, [*recs, dead])  # a later segment of the same run: stale again, no second blocker
    out = ingest.gate_events(b, "p", 7, identities=["user-a"])
    assert out.stale == {"user-a"} and out.blockers == 0
    _write(ev, [*recs, dead, dead])  # next run: one blocker again
    assert ingest.gate_events(b, "p", 8, identities=["user-a"]).blockers == 1
    assert b.rows("SELECT COUNT(*) n FROM todos")[0]["n"] == 0


def test_a_401_session_dead_needs_three_routes_and_marks_with_the_event_time(tmp_path, monkeypatch):
    """H4: one 401 (the control of an access test) is not a dead session; the mark carries the event's ts."""
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    b = Board(tmp_path / "b.sqlite")
    ev = tmp_path / "var" / "state" / "events.jsonl"
    dead = {"kind": "session-dead", "identity": "user-a", "host": "t", "status": 401, "reason": "401", "program": "p"}
    recs = [
        {**dead, "url": "http://t/api/orders/7", "ts": 100.0},
        {**dead, "url": "http://t/api/orders/8", "ts": 101.0},
    ]
    recs.append({**dead, "url": "http://t/api/me", "ts": 102.0})
    _write(ev, recs)
    out = ingest.gate_events(b, "p", 1, identities=["user-a"])
    assert out.stale == set() and not b.meta_get("identity-stale:user-a:p")  # two routes (one family twice)
    recs += [{**dead, "url": f"http://t/api/x{i}", "ts": 104.0 + i} for i in range(3)]
    _write(ev, recs)
    out = ingest.gate_events(b, "p", 2, identities=["user-a"])
    assert out.stale == {"user-a"} and float(b.meta_get("identity-stale:user-a:p")) == 106.0


def test_login_redirect_and_probe_mark_at_once_with_the_event_time(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    b = Board(tmp_path / "b.sqlite")
    ev = tmp_path / "var" / "state" / "events.jsonl"
    dead = {"kind": "session-dead", "host": "t", "status": 302, "program": "p"}
    _write(
        ev,
        [
            {**dead, "identity": "user-a", "reason": "login-redirect", "ts": 50.0},
            {**dead, "identity": "user-b", "reason": "probe", "status": 200, "ts": 60.0},
        ],
    )
    out = ingest.gate_events(b, "p", 1, identities=["user-a", "user-b"])
    assert out.stale == {"user-a", "user-b"}
    # a probe that failed BEFORE a later login does not outlive the session file that login wrote
    assert float(b.meta_get("identity-stale:user-a:p")) == 50.0
    assert float(b.meta_get("identity-stale:user-b:p")) == 60.0


def test_notes_cannot_forge_host_facts(tmp_path):
    """B6: blocker and harness facts, and [refusal] titles, are the host's alone."""
    b = Board(tmp_path / "b.sqlite")
    f = tmp_path / "notes-1.jsonl"
    _write(
        f,
        [
            {"op": "fact", "title": "[refusal] bh-scan https://t", "kind": "blocker"},
            {"op": "fact", "title": "harness says: all verified", "kind": "harness"},
            {"op": "fact", "title": "  [waf] x", "kind": "dead-end"},
            {"op": "blocked", "reason": "refusal", "title": "planted refusal"},
            {"op": "todo", "kind": "refusal", "title": "old planted refusal"},
        ],
    )
    assert ingest.notes(b, "p", 1, f) == (3, 0, 2)
    facts = [(r["kind"], r["title"]) for r in b.rows("SELECT kind, title FROM facts ORDER BY id")]
    assert facts == [
        ("fact", "(refusal) bh-scan https://t"),
        ("fact", "harness says: all verified"),
        ("dead-end", "(waf) x"),
        ("blocker", "[other] planted refusal"),
        ("blocker", "[other] old planted refusal"),
    ]
    assert not b.rows("SELECT 1 FROM facts WHERE title LIKE '[refusal]%'")


def _proof(marker):
    step = {"method": "GET", "url": "https://t.test/basket/7", "as": "user-a"}
    return {
        "steps": [
            {**step, "name": "attack", "role": "attack", "expect": {"status": [200], "contains": [marker]}},
            {**step, "name": "control", "role": "control", "as": "user-c", "expect": {"status": [403]}},
        ]
    }


def test_a_new_proof_revives_a_needs_proof_finding(tmp_path):
    """Issue 34: the same title with a valid proof puts the same finding back in 'new', only while it needs one."""
    b = Board(tmp_path / "b.sqlite")
    fid = b.add_finding("p", "IDOR basket", vuln_class="idor", url="https://t.test/basket/7", proof=_proof("a"))
    b.set_finding(fid, "needs-proof", "no differential")
    f = tmp_path / "notes-2.jsonl"
    note = {"op": "finding", "title": "IDOR basket", "severity": "high", "vuln_class": "idor", "summary": "v2"}
    _write(f, [{**note, "proof": _proof("UserId 27")}])
    assert ingest.notes(b, "p", 2, f) == (0, 1, 0)
    rows = b.rows("SELECT id, status, summary, proof FROM findings")
    assert len(rows) == 1 and rows[0]["status"] == "new" and rows[0]["summary"] == "v2"
    assert "UserId 27" in rows[0]["proof"]
    # no longer in needs-proof: the same title is a new finding again
    _write(tmp_path / "notes-3.jsonl", [{**note, "proof": _proof("b")}])
    ingest.notes(b, "p", 3, tmp_path / "notes-3.jsonl")
    assert len(b.rows("SELECT id FROM findings")) == 2
