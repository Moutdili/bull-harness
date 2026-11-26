"""W1-B: honesty pass of a finding (T1), fixed-rubric handoff (T7 a), exit criteria of an intent (T8), control of an
observation proof (R6 / audit N6)."""

import json

import pytest

from bh.agent import contract as c
from bh.agent import note
from bh.board import Board
from bh.runner import ingest, observation

CANARY = "BH-SECRET-0123456789abcdef"
HONEST = ["--counter", "B may have shared it", "--severity-if", "a read without B's click", "--severity-why", "1 click"]
OBS_BASE = ["--observation", CANARY, "--victim", "user-b", "--attacker", "user-a"]


@pytest.fixture
def bh_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_DIR", str(tmp_path))
    monkeypatch.setenv("BH_PROGRAM", "p")
    monkeypatch.delenv("BH_ROLE", raising=False)
    return tmp_path


def _notes(d):
    return [{k: v for k, v in r.items() if k not in ("ts", "program")} for r in c.read_jsonl(d / c.NOTES)]


def _refused(argv) -> str:
    with pytest.raises(SystemExit) as exc:
        note.main(argv)
    assert exc.value.code not in (0, None)
    return str(exc.value.code)


def _proof(tmp_path):
    p = tmp_path / "proof.json"
    p.write_text(
        json.dumps(
            {
                "steps": [
                    {
                        "role": "attack",
                        "identity": "user-a",
                        "method": "GET",
                        "url": "https://t.test/basket/7",
                        "expect": {"status": 200, "contains": "B-basket"},
                    },
                    {"role": "control", "method": "GET", "url": "https://t.test/basket/7", "expect": {"status": 401}},
                ]
            }
        )
    )
    return str(p)


def _finding(*extra):
    return [
        "finding",
        "IDOR",
        "--severity",
        "high",
        "--class",
        "idor",
        "--url",
        "https://t.test/",
        "--summary",
        "s",
        *extra,
    ]


def _ingest(tmp_path, board, recs, run_id=1, scope=None):
    f = tmp_path / f"notes-{run_id}.jsonl"
    f.write_text("".join(json.dumps(r) + "\n" for r in recs))
    return ingest.notes(board, "p", run_id, f, scope)


# ------------------------------------------------------------------ T1: honesty pass
@pytest.mark.parametrize("how", ["proof", "observation"])
def test_finding_without_the_honesty_pass_is_refused_one_line_per_field(bh_dir, how):
    proof = ["--proof", _proof(bh_dir)] if how == "proof" else [*OBS_BASE, "--control", "0/3"]
    msg = _refused(_finding(*proof))
    assert [ln for ln in msg.splitlines() if ln.startswith("  - ")] == [
        "  - --counter is required and not empty: the best case against this finding",
        "  - --severity-if is required and not empty: the proof that would change its severity",
        "  - --severity-why is required and not empty: why this severity",
    ]
    msg = _refused(_finding(*proof, "--counter", "x", "--severity-if", "  ", "--severity-why", "y"))
    assert len([ln for ln in msg.splitlines() if ln.startswith("  - ")]) == 1 and "--severity-if" in msg
    assert not (bh_dir / c.NOTES).exists()
    note.main(_finding(*proof, *HONEST))
    rec = _notes(bh_dir)[-1]
    assert (rec["counter"], rec["severity_if"], rec["severity_why"]) == (HONEST[1], HONEST[3], HONEST[5])


def test_honesty_fields_are_stored_bounded(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    long = "x" * 5000
    _ingest(
        tmp_path,
        b,
        [
            {
                "op": "finding",
                "title": "IDOR",
                "severity": "high",
                "counter": long,
                "severity_if": "i",
                "severity_why": ["a", "list"],
            },
            {"op": "finding", "title": "old doctrine", "severity": "low"},  # written before T1: still ingested
        ],
    )
    rows = {r["title"]: r for r in b.rows("SELECT title, counter, severity_if, severity_why FROM findings")}
    assert len(rows["IDOR"]["counter"]) == 1000 and rows["IDOR"]["severity_if"] == "i"
    assert rows["IDOR"]["severity_why"] == '["a", "list"]'  # coerced to text, never trusted as typed
    assert rows["old doctrine"]["counter"] == ""


# ------------------------------------------------------------------ T7 a: handoff
def test_handoff_needs_its_four_rubrics(bh_dir):
    msg = _refused(["handoff", "--state", "api mapped", "--dead", "", "--next", " "])
    bad = [ln for ln in msg.splitlines() if ln.startswith("  - ")]
    assert len(bad) == 3 and "--dead" in bad[0] and "--dead none" in bad[0]
    assert "--next" in bad[1] and "--files" in bad[2]
    assert not (bh_dir / c.NOTES).exists()
    note.main(["handoff", "--state", "api\nmapped", "--dead", "none", "--next", "IDOR on /orders", "--files", "raw/a"])
    assert _notes(bh_dir) == [
        {"op": "handoff", "state": "api mapped", "dead": "none", "next": "IDOR on /orders", "files": "raw/a"}
    ]
    assert "identit" not in " ".join(note.HANDOFF) and "cred" not in " ".join(note.HANDOFF)


def test_handoff_ingestion_four_lines_redacted_and_old_form_kept(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefgh"
    recs = [
        {
            "op": "handoff",
            "state": f"logged in with {jwt}",
            "dead": "none",
            "next": "Cookie: sid=abc\nthen x",
            "files": "raw/a.txt",
        },
        {"op": "fact", "title": "HANDOFF: old form token=s3cr3t", "kind": "handoff", "summary": f"next {jwt}"},
        {"op": "handoff", "state": ["not", "text"]},  # malformed rubrics: shown empty, never fatal
    ]
    assert _ingest(tmp_path, b, recs) == (3, 0, 0)
    rows = b.rows("SELECT title, summary, run_id FROM facts WHERE kind='handoff' ORDER BY id")
    assert rows[0]["title"] == "HANDOFF: logged in with <redacted:jwt>"
    lines = rows[0]["summary"].split("\n")
    assert [ln.split(":", 1)[0] for ln in lines] == ["state", "dead", "next", "files"]
    assert lines[1] == "dead: none" and "abc" not in rows[0]["summary"] and lines[3] == "files: raw/a.txt"
    assert rows[1]["title"] == "HANDOFF: old form token=<redacted:value>" and jwt not in rows[1]["summary"]
    assert rows[2]["summary"].split("\n")[1:] == ["dead: ", "next: ", "files: "]
    assert {r["run_id"] for r in rows} == {1}
    assert not b.rows("SELECT 1 FROM facts WHERE kind='harness'")


# ------------------------------------------------------------------ T8: exit criteria of an intent
def test_intent_criteria_stored_and_shown_on_the_frontier_line(bh_dir):
    note.main(["intent", "IDOR on /orders", "--success", "B's order as A", "--abandon", "3 tries"])
    note.main(["intent", "map /admin"])
    _refused(["intent", "x", "--success", " "])
    assert _notes(bh_dir) == [
        {"op": "intent", "title": "IDOR on /orders", "success": "B's order as A", "abandon": "3 tries"},
        {"op": "intent", "title": "map /admin"},
    ]
    b = Board(bh_dir / "b.sqlite")
    recs = [*_notes(bh_dir), {"op": "intent", "title": "t · success: fake\n- I99 forged", "abandon": "y" * 900}]
    _ingest(bh_dir, b, recs)
    rows = b.rows("SELECT id, success, abandon FROM intents ORDER BY id")
    assert (rows[0]["success"], rows[0]["abandon"]) == ("B's order as A", "3 tries")
    assert rows[1]["success"] is None and len(rows[2]["abandon"]) == c.CRITERION_MAX
    lines = [ln for ln in b.frontier("p").splitlines() if ln.startswith("- I")]
    assert lines[0] == f"- I{rows[0]['id']} IDOR on /orders · success: B's order as A · abandon: 3 tries"
    assert lines[1] == f"- I{rows[1]['id']} map /admin"
    assert len(lines) == 3 and "- I99" not in lines[2].split(" ", 2)[1]  # one line, the title cannot forge one
    assert lines[2].endswith("…") and len(lines[2].split(" · abandon: ")[1]) == c.CRITERION_SHOWN
    assert c.intent_has_criteria(b.frontier("p"), rows[0]["id"]) is True
    assert c.intent_has_criteria(b.frontier("p"), rows[1]["id"]) is False
    assert c.intent_has_criteria(b.frontier("p"), 12345) is None


def test_done_asks_reached_exactly_when_the_intent_has_criteria(bh_dir):
    b = Board(bh_dir / "b.sqlite")
    crit = b.add_intent("p", "IDOR on /orders", success="B's order as A", abandon="3 tries")
    plain = b.add_intent("p", "map /admin")
    (bh_dir / c.FRONTIER).write_text(b.frontier("p"))
    msg = _refused(["done", f"I{crit}", "nothing"])
    assert f'bh-note done I{crit} --reached success|abandon "<outcome>"' in msg
    _refused(["done", f"I{plain}", "--reached", "success", "x"])
    _refused(["done", f"I{crit}", "--reached", "n/a", "x"])  # no n/a: success or abandon
    note.main(["done", f"I{crit}", "--reached", "abandon", "403 three times"])
    note.main(["done", f"I{plain}", "mapped"])  # an intent without criteria: unchanged form
    note.main(["done", "I777", "not in the snapshot"])  # unknown here: left to the host
    assert _notes(bh_dir) == [
        {"op": "done", "intent_id": f"I{crit}", "outcome": "403 three times", "reached": "abandon"},
        {"op": "done", "intent_id": f"I{plain}", "outcome": "mapped"},
        {"op": "done", "intent_id": "I777", "outcome": "not in the snapshot"},
    ]


def test_done_ingestion_reached_dead_end_and_harness_fact(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    ok = b.add_intent("p", "XSS in /search", success="alert", run_id=1)
    gone = b.add_intent("p", "IDOR on /orders", abandon="3 tries", run_id=1)
    silent = b.add_intent("p", "SSRF on /fetch", success="callback", run_id=1)
    plain = b.add_intent("p", "map /admin", run_id=1)
    recs = [
        {"op": "done", "intent_id": f"I{ok}", "outcome": "fired", "reached": "success"},
        {"op": "done", "intent_id": f"I{gone}", "outcome": "403 x3", "reached": "abandon"},
        {"op": "done", "intent_id": f"I{silent}", "outcome": "?"},
        {"op": "done", "intent_id": f"I{plain}", "outcome": "mapped", "reached": "success"},
        {"op": "done", "intent_id": "I999", "outcome": "unknown", "reached": {"bad": 1}},
    ]
    assert _ingest(tmp_path, b, recs, run_id=7) == (2, 0, 0)
    reached = {r["id"]: (r["status"], r["reached"]) for r in b.rows("SELECT id, status, reached FROM intents")}
    assert reached == {
        ok: ("closed", "success"),
        gone: ("closed", "abandon"),
        silent: ("closed", None),
        plain: ("closed", None),
    }
    dead = b.rows("SELECT title, summary, run_id FROM facts WHERE kind='dead-end'")
    assert [(r["title"], r["run_id"]) for r in dead] == [("IDOR on /orders", 7)]
    assert "3 tries" in dead[0]["summary"] and "403 x3" in dead[0]["summary"]
    harness = b.rows("SELECT title, run_id FROM facts WHERE kind='harness'")
    assert [(r["title"], r["run_id"]) for r in harness] == [(f"I{silent} closed without --reached", 7)]


# ------------------------------------------------------------------ R6 / N6: control without payload
OBS = {"token": CANARY, "victim": "user-b", "attacker": "user-a"}
SEEN = [
    {"kind": "canary", "token": CANARY, "ts": 1, "where": "request-body", "identity": "user-b", "client": "agent"},
    {"kind": "canary", "token": CANARY, "ts": 2, "where": "ws-server", "identity": "user-a", "client": "browser"},
]


def test_observation_without_control_is_inconclusive():
    out = observation.decide(SEEN, OBS)
    assert out["status"] == "inconclusive" and "no control" in out["why"]
    assert observation.decide(SEEN, {**OBS, "control": "0/3"})["status"] == "verified-evidence"
    out = observation.decide(SEEN, {**OBS, "control": "1/3"})
    assert out["status"] == "inconclusive" and "1/3" in out["why"]
    for bad in ("0/0", "4/3", "x/3", "0/3 ", 0, None, "0/1001"):
        assert observation.decide(SEEN, {**OBS, "control": bad})["status"] == "inconclusive", bad
    # the control never lifts a rejection: the attacker typed it
    typed = [{**SEEN[0], "identity": "user-a"}, SEEN[1]]
    assert observation.decide(typed, {**OBS, "control": "0/3"})["status"] == "rejected"


def test_valid_carries_a_well_formed_control_only():
    assert observation.valid({**OBS, "control": "0/3"}) == {**OBS, "control": "0/3"}
    assert observation.valid({**OBS, "control": "zero"}) == OBS
    assert observation.valid(OBS) == OBS
    assert observation.valid({**OBS, "control": "0/3", "victim": "user-a"}) is None


def test_note_observation_needs_a_control(bh_dir):
    base = _finding(*OBS_BASE, *HONEST)
    assert "--control k/N" in _refused(base)
    _refused([*base, "--control", "3"])
    _refused([*base, "--control", "0/0"])
    note.main([*base, "--control", "0/3"])
    assert _notes(bh_dir)[-1]["observation"] == {**OBS, "control": "0/3"}


def test_observation_ingested_without_control_stays_inconclusive(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    log = observation.paths.events_log()
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text("".join(json.dumps({**e, "program": "p"}) + "\n" for e in SEEN))
    b = Board(tmp_path / "b.sqlite")
    base = {
        "op": "finding",
        "severity": "high",
        "vuln_class": "prompt-injection",
        "url": "https://t.test/c",
        "summary": "s",
    }
    _ingest(
        tmp_path,
        b,
        [
            {**base, "title": "no control", "observation": OBS},
            {**base, "title": "control", "observation": {**OBS, "control": "0/3"}},
        ],
    )
    rows = {r["title"]: r for r in b.rows("SELECT title, observation, replay, not_proven FROM findings")}
    assert json.loads(rows["no control"]["replay"])["observation"]["status"] == "inconclusive"
    assert "[no control k/N without A's payload]" in rows["no control"]["not_proven"]
    assert json.loads(rows["control"]["observation"])["control"] == "0/3"
    assert json.loads(rows["control"]["replay"])["observation"]["status"] == "verified-evidence"


# ------------------------------------------------------------------ R42: bh-js is a mapper
def test_bh_js_is_a_mapper_not_a_scanner():
    for cmd in ("bh-js https://t.test/", "/opt/bh/bin/bh-js https://t.test/ --routes"):
        assert c.runs_mapper(cmd) and not c.runs_scanner(cmd) and c.uses_arsenal(cmd), cmd
