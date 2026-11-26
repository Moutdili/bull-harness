"""W2-A, typed legs: anchored facts (T12), typed closure (T13), coverage by (endpoint, class) (T14), typed intents
(T15), reasoning journal (D15), threat model (T16 part), frontier without facts, scope requests (D40, agent side)."""

import json
import sqlite3

import pytest

from bh import assets, paths
from bh.agent import contract as c
from bh.agent import note
from bh.assets import Graph
from bh.board import Board
from bh.runner import ingest
from bh.scope import scope_from_dict

RUN = 5
BODY = {"id": 7, "role": "admin", "owner": "user-b", "note": "café crème"}


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    monkeypatch.setenv("BH_DIR", str(tmp_path / "bh"))
    monkeypatch.setenv("BH_PROGRAM", "p")
    monkeypatch.delenv("BH_ROLE", raising=False)
    (tmp_path / "bh").mkdir()
    return tmp_path


def _flow(fid, *, run=RUN, program="p", body=None, request="", ua="curl/8.5", url="https://t.test/api/orders/7"):
    """A target flow as gate/addon.py `_record` writes it: a flows.jsonl line and the full exchange, bodies redacted
    (a JSON body re-serialized by bh.redact.body: ", " / ": " separators, \\u escapes)."""
    line = {
        "id": fid,
        "class": "target",
        "method": "GET",
        "url": url,
        "status": 200,
        "ua": ua,
        "run": run,
        "program": program,
        "ts": 1.0,
    }
    flows = paths.flows_log()
    flows.parent.mkdir(parents=True, exist_ok=True)
    with open(flows, "a") as fh:
        fh.write(json.dumps(line) + "\n")
    full = {
        **line,
        "request": {"headers": [], "body": request},
        "response": {"headers": [], "body": json.dumps(body if body is not None else BODY)},
    }
    f = paths.flow_file(fid)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(full))


def _ingest(home, b, recs, run=RUN):
    f = home / f"notes-{run}.jsonl"
    f.write_text("".join(json.dumps(r) + "\n" for r in recs))
    return ingest.notes(b, "p", run, f)


def _sandbox(home):
    return [{k: v for k, v in r.items() if k not in ("ts", "program")} for r in c.read_jsonl(home / "bh" / c.NOTES)]


def _refused(argv) -> str:
    with pytest.raises(SystemExit) as exc:
        note.main(argv)
    assert exc.value.code not in (0, None)
    return str(exc.value.code)


# ------------------------------------------------------------------ T12: anchored facts
def test_quote_is_anchored_only_in_a_response_body_of_the_run(home):
    _flow("1700000000-abcdef-1", request='{"secret_plan": "I wrote this myself"}')
    _flow("1700000001-abcdef-2", run=RUN - 1, body={"other": "only in an older run"})
    (home / "bh" / "raw.txt").write_text("text only in the sandbox, never a receipt")
    b = Board(home / "b.sqlite")
    recs = [
        {"op": "fact", "title": "compact", "quote": '"role":"admin"', "url": "https://t.test/api/orders/7"},
        {"op": "fact", "title": "as stored", "quote": '"owner": "user-b"', "flow": "1700000000-abcdef-1"},
        {"op": "fact", "title": "unescaped", "quote": '"note":"café crème"'},
        {"op": "fact", "title": "wrong", "quote": '"role":"superuser"'},
        {"op": "fact", "title": "older run", "quote": '"only in an older run"'},
        {"op": "fact", "title": "named older flow", "quote": '"only in an older run"', "flow": "1700000001-abcdef-2"},
        {"op": "fact", "title": "request body", "quote": "I wrote this myself"},
        {"op": "fact", "title": "sandbox file", "quote": "text only in the sandbox"},
        {"op": "fact", "title": "unknown flow", "quote": '"role": "admin"', "flow": "1700000009-abcdef-9"},
        {"op": "fact", "title": "traversal", "quote": '"role": "admin"', "flow": "../../board"},
        {"op": "fact", "title": "two lines", "quote": '"role":\n"admin"'},
        {"op": "fact", "title": "too short", "quote": "admin"},
        {"op": "fact", "title": "too long", "quote": '"role": "admin"' + " " * 400},
        {"op": "fact", "title": "forged", "quote": "nothing", "grounded": 1},
    ]
    assert _ingest(home, b, recs) == (len(recs), 0, 0)
    got = {r["title"]: (r["grounded"], r["flow"]) for r in b.rows("SELECT title, grounded, flow FROM facts")}
    assert got["compact"] == (1, "1700000000-abcdef-1")
    assert got["as stored"] == (1, "1700000000-abcdef-1")
    assert got["unescaped"][0] == 1
    assert {t for t, (g, _) in got.items() if g} == {"compact", "as stored", "unescaped"}
    assert got["unknown flow"] == (0, "1700000009-abcdef-9") and got["traversal"] == (0, None)
    row = b.rows("SELECT endpoint, quote FROM facts WHERE title='compact'")[0]
    assert (row["endpoint"], row["quote"]) == ("GET /api/orders/{id}", '"role":"admin"')
    assert "(fact, anchored) compact" in b.frontier("p")


def test_quote_is_compared_after_redaction(home):
    _flow("1700000000-abcdef-1", body={"token": "s3cr3t-value-123", "plan": "gold tier member"})
    b = Board(home / "b.sqlite")
    _ingest(
        home,
        b,
        [
            {"op": "fact", "title": "t", "quote": '"token": "s3cr3t-value-123"'},
            {"op": "fact", "title": "p", "quote": '"plan": "gold tier member"'},
        ],
    )
    rows = {r["title"]: r for r in b.rows("SELECT title, grounded, quote FROM facts")}
    assert rows["p"]["grounded"] == 1
    assert "s3cr3t" not in rows["t"]["quote"]  # stored redacted, whatever the verdict


def test_fact_note_flags(home):
    note.main(
        [
            "fact",
            "B's order as A",
            "--quote",
            '"owner":"user-b"',
            "--flow",
            "1700000000-abcdef-1",
            "--url",
            "https://t.test/api/orders/7",
            "--class",
            "IDOR",
            "--technique",
            "id swap",
            "--as",
            "user-a,user-b",
        ]
    )
    assert _sandbox(home)[0] == {
        "op": "fact",
        "title": "B's order as A",
        "summary": "",
        "evidence": "",
        "kind": "fact",
        "quote": '"owner":"user-b"',
        "flow": "1700000000-abcdef-1",
        "url": "https://t.test/api/orders/7",
        "vuln_class": "IDOR",
        "technique": "id swap",
        "identities": "user-a,user-b",
    }
    assert "one line" in _refused(["fact", "x", "--quote", "line one\nline two"])
    assert "characters" in _refused(["fact", "x", "--quote", "short"])
    assert "characters" in _refused(["fact", "x", "--quote", "y" * 401])
    assert "flow id" in _refused(["fact", "x", "--quote", '"role":"admin"', "--flow", "../x"])
    assert "--url" in _refused(["fact", "x", "--url", "not a url"])
    _ingest(home, b := Board(home / "b.sqlite"), _sandbox(home))
    r = b.rows("SELECT vuln_class, technique, identities, grounded FROM facts")[0]
    assert (r["vuln_class"], r["technique"], r["identities"], r["grounded"]) == ("idor", "id swap", "user-a,user-b", 0)


# ------------------------------------------------------------------ T13: typed closure
def test_dead_end_needs_a_cause_and_the_frontier_shows_it(home):
    assert "--why technical|environment|approach|external|rule" in _refused(["fact", "x", "-k", "dead-end"])
    _refused(["fact", "x", "-k", "dead-end", "--why", "boredom"])
    note.main(["fact", "SSTI on /render: sandboxed", "-k", "dead-end", "--why", "approach"])
    b = Board(home / "b.sqlite")
    _ingest(home, b, [*_sandbox(home), {"op": "fact", "title": "old", "kind": "dead-end", "why": "forged"}])
    assert [r["why"] for r in b.rows("SELECT why FROM facts ORDER BY id")] == ["approach", None]
    front = b.frontier("p")
    assert "(dead-end: approach) SSTI on /render: sandboxed" in front and "(dead-end) old" in front


def test_done_outcome_blocked_tried_and_close_open_intents(home):
    b = Board(home / "b.sqlite")
    done = b.add_intent("p", "IDOR on /orders", abandon="3 tries", run_id=RUN, endpoint="GET /api/orders/{id}")
    blocked = b.add_intent("p", "SSRF on /fetch", run_id=RUN)
    left = b.add_intent("p", "XSS on /search", run_id=RUN)
    earlier = b.add_intent("p", "older run", run_id=RUN - 1)
    (home / "bh" / c.FRONTIER).write_text(b.frontier("p"))
    note.main(["done", f"I{done}", "--reached", "abandon", "--outcome", "ruled_out", "--why", "technical", "403 x3"])
    _refused(["done", f"I{done}", "--outcome", "maybe", "x"])
    msg = _refused(["blocked", "oob-needed", "SSRF needs a callback", "--intent", f"I{blocked}"])
    assert "--tried is required" in msg and "--would-prove is required" in msg
    note.main(
        [
            "blocked",
            "oob-needed",
            "SSRF needs a callback",
            "--intent",
            f"I{blocked}",
            "--tried",
            "url=http://127.0.0.1",
            "--would-prove",
            "a DNS hit on our collaborator",
        ]
    )
    note.main(["blocked", "third-party-data", "stranger's invoice"])  # a stop asks nothing
    _ingest(home, b, _sandbox(home))
    rows = {r["id"]: r for r in b.rows("SELECT * FROM intents")}
    assert (rows[done]["outcome"], rows[done]["result"], rows[done]["reached"]) == ("ruled_out", "403 x3", "abandon")
    assert (rows[blocked]["outcome"], rows[blocked]["result"]) == ("open_proof_gap", "blocked: oob-needed")
    dead = b.rows("SELECT why, outcome, endpoint FROM facts WHERE kind='dead-end'")[0]
    assert (dead["why"], dead["outcome"], dead["endpoint"]) == ("technical", "ruled_out", "GET /api/orders/{id}")
    blk = b.rows("SELECT summary, outcome FROM facts WHERE kind='blocker' ORDER BY id")
    assert "tried: url=http://127.0.0.1" in blk[0]["summary"] and "would prove: a DNS hit" in blk[0]["summary"]
    assert blk[0]["outcome"] == "open_proof_gap" and blk[1]["outcome"] is None
    assert ingest.close_open_intents(b, "p", RUN) == 1
    rows = {r["id"]: r for r in b.rows("SELECT * FROM intents")}
    assert (rows[left]["status"], rows[left]["outcome"]) == ("closed", "open_proof_gap")
    assert rows[earlier]["status"] == "open"  # another run's intent is that run's to close
    assert ingest.close_open_intents(b, "p", RUN) == 0


def test_old_free_text_outcomes_move_to_result(tmp_path):
    db = sqlite3.connect(tmp_path / "b.sqlite")
    db.executescript(
        "CREATE TABLE intents (id INTEGER PRIMARY KEY, program TEXT NOT NULL, run_id INTEGER, title TEXT NOT NULL,"
        " status TEXT NOT NULL DEFAULT 'open', created REAL NOT NULL, closed REAL, outcome TEXT);"
        "INSERT INTO intents(program, title, created, status, outcome) VALUES ('p', 't', 1, 'closed', 'mapped it');"
    )
    db.commit()
    db.close()
    b = Board(tmp_path / "b.sqlite")
    assert tuple(b.rows("SELECT outcome, result FROM intents")[0]) == (None, "mapped it")
    b.db.execute("UPDATE intents SET outcome='confirmed'")
    b.db.commit()
    assert b.rows("SELECT outcome FROM intents")[0]["outcome"] == "confirmed"
    assert Board(tmp_path / "b.sqlite").rows("SELECT outcome FROM intents")[0]["outcome"] == "confirmed"


# ------------------------------------------------------------------ T14: coverage by (endpoint, class)
def test_clean_on_an_endpoint_the_gate_did_not_see_is_refused(home):
    _flow("1700000000-abcdef-1", url="https://t.test/api/orders/7")  # curl: rank gate
    _flow("1700000001-abcdef-2", url="https://t.test/api/users/3", ua="Mozilla/5.0")  # a browser: seen, not gate
    _flow("1700000002-abcdef-3", url="https://t.test/api/carts/3", run=RUN - 1)  # another run
    ev = home / "bh" / "raw.txt"
    ev.write_text("x")
    note.main(["cover", "GET /api/orders/9", "XSS (stored)", "clean", "-e", str(ev)])
    note.main(["cover", "GET https://t.test/api/users/3", "idor", "clean", "-e", str(ev)])
    note.main(["cover", "GET /api/carts/{id}", "idor", "clean", "-e", str(ev)])
    note.main(["cover", "POST /api/never", "sqli", "suspect", "-e", str(ev)])
    assert "-e <file> is required" in _refused(["cover", "GET /x", "idor", "clean"])
    assert "not found" in _refused(["cover", "GET /x", "idor", "clean", "-e", str(home / "nope")])
    _refused(["cover", "GET /x", "idor", "safe", "-e", str(ev)])
    _refused(["cover", "somewhere", "idor", "clean", "-e", str(ev)])
    b = Board(home / "b.sqlite")
    assert _ingest(
        home, b, [*_sandbox(home), {"op": "cover", "endpoint": "nowhere", "vuln_class": "x", "outcome": "clean"}]
    ) == (2, 0, 0)  # 2 refusals (+1 malformed)
    rows = [tuple(r) for r in b.rows("SELECT endpoint, vuln_class, outcome, gate_seen FROM coverage_class")]
    assert rows == [
        ("GET /api/orders/{id}", "xss", "clean", 1),
        ("GET /api/users/{id}", "idor", "retry", 0),
        ("GET /api/carts/{id}", "idor", "retry", 0),
        ("POST /api/never", "sqli", "suspect", 0),
    ]
    harness = [r["title"] for r in b.rows("SELECT title FROM facts WHERE kind='harness' ORDER BY id")]
    assert harness[:2] == ["clean refused: GET /api/users/{id} idor", "clean refused: GET /api/carts/{id} idor"]
    assert harness[2].startswith("malformed note skipped")
    assert assets.class_coverage(b, "p")[("GET /api/orders/{id}", "xss")]["outcome"] == "clean"


def test_gate_seen_reads_the_tests_table(home):
    scope = scope_from_dict({"program": "p", "platform": "x", "in_scope": ["t.test"]})
    b = Board(home / "b.sqlite")
    b.db.execute("INSERT INTO runs(id, program, started) VALUES (?, 'p', 1)", (RUN,))
    b.db.commit()
    _flow("1700000000-abcdef-1", url="https://t.test/api/orders/7")
    Graph(b, scope).sync(RUN)
    paths.flows_log().write_text("")  # the log rotated: only the table remembers
    assert assets.gate_tested(b, "p", "GET /api/orders/{id}", RUN)
    assert not assets.gate_tested(b, "p", "GET /api/orders/{id}", RUN + 1)
    assert not assets.gate_tested(b, "q", "GET /api/orders/{id}", RUN)
    b.reset_program("p")
    assert not b.rows("SELECT 1 FROM coverage_class")


# ------------------------------------------------------------------ T15: typed intents
def test_test_and_prove_need_a_recall_map_does_not(home):
    msg = _refused(
        ["intent", "IDOR on orders", "--kind", "test", "--url", "https://t.test/api/orders/7", "--class", "idor"]
    )
    assert 'bh-recall "IDOR on orders" --url https://t.test/api/orders/7 --class idor' in msg
    _refused(["intent", "x", "--kind", "prove", "--recall", "none"])  # a prove names its endpoint
    _refused(["intent", "x", "--kind", "test", "--recall", "maybe"])
    _refused(["intent", "x", "--kind", "map", "--after", "3"])
    note.main(["intent", "map the API", "--kind", "map"])
    note.main(
        [
            "intent",
            "IDOR on orders",
            "--kind",
            "test",
            "--url",
            "https://t.test/api/orders/7",
            "--class",
            "idor",
            "--recall",
            "R-12",
            "--basis",
            "F3",
            "--after",
            "I1",
        ]
    )
    assert _sandbox(home)[1] == {
        "op": "intent",
        "title": "IDOR on orders",
        "kind": "test",
        "url": "https://t.test/api/orders/7",
        "vuln_class": "idor",
        "recall": "R-12",
        "basis": "F3",
        "after": "I1",
    }


def test_prove_needs_an_anchored_fact_on_the_same_endpoint(home):
    _flow("1700000000-abcdef-1")
    b = Board(home / "b.sqlite")
    prove = {
        "op": "intent",
        "title": "prove IDOR",
        "kind": "prove",
        "recall": "none",
        "url": "https://t.test/api/orders/9",
        "vuln_class": "idor",
    }
    assert _ingest(home, b, [prove]) == (1, 0, 0)
    assert not b.rows("SELECT 1 FROM intents")
    assert b.rows("SELECT title FROM facts WHERE kind='harness'")[0]["title"].startswith("intent refused: prove")
    _ingest(
        home,
        b,
        [
            {"op": "fact", "title": "anchored elsewhere", "quote": '"role":"admin"', "url": "https://t.test/api/x"},
            {"op": "think", "title": "maybe", "why": "hunch", "quote": '"role":"admin"', "url": prove["url"]},
            prove,
        ],
    )
    assert not b.rows("SELECT 1 FROM intents")
    _ingest(
        home,
        b,
        [
            {"op": "fact", "title": "B's order", "quote": '"owner": "user-b"', "url": prove["url"]},
            prove,
            {"op": "intent", "title": "map", "kind": "map"},
            {"op": "intent", "title": "untyped"},
        ],
    )
    rows = b.rows("SELECT kind, endpoint, vuln_class, recall, status FROM intents ORDER BY id")
    assert [tuple(r) for r in rows] == [
        ("prove", "GET /api/orders/{id}", "idor", "none", "open"),
        ("map", None, None, None, "open"),
        (None, None, None, None, "open"),
    ]


def test_reorder_sets_the_frontier_order(home):
    b = Board(home / "b.sqlite")
    a, m, z = (b.add_intent("p", t, kind=k) for t, k in (("a", "map"), ("m", "test"), ("z", None)))
    other = b.add_intent("q", "other program")
    note.main(["reorder", f"I{z}", f"{a}"])
    _refused(["reorder", "F2"])
    _ingest(home, b, [*_sandbox(home), {"op": "reorder", "intents": [f"I{other}", "junk", 7]}])
    lines = [ln for ln in b.frontier("p").splitlines() if ln.startswith("- I")]
    assert lines == [f"- I{z} z", f"- I{a} (map) a", f"- I{m} (test) m"]
    assert c.intent_has_criteria(b.frontier("p"), a) is False


# ------------------------------------------------------------------ D15, T16
def test_think_is_never_anchored(home):
    _flow("1700000000-abcdef-1")
    _refused(["think", "the id looks sequential"])
    note.main(["think", "the id looks sequential", "--why", "7 then 8 in two answers"])
    b = Board(home / "b.sqlite")
    _ingest(home, b, [*_sandbox(home), {"op": "fact", "kind": "think", "title": "t", "quote": '"role":"admin"'}])
    rows = b.rows("SELECT kind, why, grounded FROM facts ORDER BY id")
    assert [tuple(r) for r in rows] == [("think", "7 then 8 in two answers", 0), ("think", None, 0)]
    assert "sequential" not in b.frontier("p")  # the lineage's journal, not the frontier


def test_threat_model_lines_inferred_and_the_latest_is_active(home):
    _flow("1700000000-abcdef-1")
    assert "1 to 8" in _refused(["threat-model", "tm", *[x for i in range(9) for x in ("-l", f"line {i}")]])
    _refused(["threat-model", "tm", "-l", 'claim :: "x"'])  # a quote too short to anchor
    note.main(
        [
            "threat-model",
            "orders app",
            "-l",
            'orders hold the owner :: "owner": "user-b"',
            "-l",
            "admins export every user",
        ]
    )
    b = Board(home / "b.sqlite")
    _ingest(home, b, _sandbox(home))
    b.db.execute("UPDATE facts SET created=1000 WHERE kind='threat-model'")
    b.db.commit()
    first = b.threat_model("p")
    assert first["summary"].splitlines() == [
        'orders hold the owner :: "owner": "user-b"',
        "admins export every user (inferred)",
    ]
    assert first["grounded"] == 0
    lines = [f"claim {i}" for i in range(12)]
    _ingest(home, b, [{"op": "threat-model", "title": "v2", "lines": lines}])
    tm = b.rows("SELECT title, summary, created FROM facts WHERE kind='threat-model' ORDER BY id")
    assert len(tm) == 2 and tm[0]["created"] == 1000  # the old one stays, with its date
    assert len(tm[1]["summary"].splitlines()) == c.THREAT_MODEL_LINES
    front = b.frontier("p")
    assert "## threat model" in front and ": v2" in front and "orders app" not in front
    assert "- claim 0 (inferred)" in front


# ------------------------------------------------------------------ frontier, scope requests
def test_frontier_without_facts(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    b.add_fact("p", "a fact")
    b.add_intent("p", "an intent")
    assert "## facts" in b.frontier("p") and "a fact" in b.frontier("p")
    front = b.frontier("p", facts=False)
    assert "## facts" not in front and "a fact" not in front and "an intent" in front


def test_scope_request(home, capsys):
    note.main(["scope-request", "https://api.t-cdn.test/v2/", "seen in main.js: fetch('/v2/orders')"])
    assert "asked, pending" in capsys.readouterr().out
    for bad in ("http://a.test/", "https://*.a.test/", "https://a.test/x?y=1", "https://10.0.0.1/", "a.test"):
        _refused(["scope-request", bad, "seen"])
    _refused(["scope-request", "https://a.test/", " "])
    assert _sandbox(home) == [
        {
            "op": "scope-request",
            "kind": "scope-request",
            "prefix": "https://api.t-cdn.test/v2/",
            "why": "seen in main.js: fetch('/v2/orders')",
            "run": None,
        }
    ]
    b = Board(home / "b.sqlite")
    recs = [*_sandbox(home), *_sandbox(home), {"op": "scope-request", "prefix": "https://*.x.test/", "why": "w"}]
    assert _ingest(home, b, recs) == (1, 0, 0)
    (r,) = b.scope_requests("p")
    assert (r["prefix"], r["status"], r["run_id"]) == ("https://api.t-cdn.test/v2/", "pending", RUN)
    b.decide_scope_request(r["id"], "approved", "same org, used with our accounts", "judge")
    assert b.scope_requests("p", "approved")[0]["decided_by"] == "judge"
    with pytest.raises(ValueError):
        b.decide_scope_request(r["id"], "maybe", "", "x")
