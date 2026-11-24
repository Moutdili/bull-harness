import time

import pytest

from bh.agent.contract import BLOCKER_TTL_S
from bh.board import Board


def test_board_crud(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    rid = b.run_start("demo", "sonnet")
    b.add_fact("demo", "httpx: 12 live hosts", "list in evidence", "/work/raw/1.log", run_id=rid)
    iid = b.add_intent("demo", "test IDOR on /api/orders")
    fid = b.add_finding("demo", "IDOR on /api/orders/{id}", severity="high", poc="curl ...", bogus="x")
    assert b.add_todo("submit", "submit F1", program="demo", dedup="submit:F1") is not None
    assert b.add_todo("submit", "submit F1", program="demo", dedup="submit:F1") is None
    b.add_blocker("demo", "account", "IDOR on /api/orders needs a 2nd account", run_id=rid)
    b.set_finding(fid, "verified", "submit")
    b.close_intent(iid, "done")
    b.run_end(rid, status="ok", session_id="s1", turns=3)
    assert b.last_session("demo") == "s1"
    f = b.frontier("demo")
    assert "F1 [verified/high]" in f and "httpx: 12 live hosts" in f
    assert "## blocked (do not retry)" in f and "[account] IDOR on /api/orders" in f
    assert "submit F1" not in f and "waiting on human" not in f  # post-triage work is not the agent's
    assert len(f.splitlines()) <= 40


def test_orphaned_run_closed_at_next_start(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    orphan = b.run_start("p", "m")  # never ended: crash / hard kill
    b.run_start("p", "m")
    assert b.rows("SELECT status FROM runs WHERE id=?", orphan)[0]["status"] == "stopped"


def test_frontier_keeps_only_the_latest_bookkeeping_fact(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    for i in range(5):
        b.add_fact("p", f"HANDOFF {i}", kind="handoff")
        b.add_fact("p", f"gate denied {i}", kind="blocked")
    b.add_fact("p", "real fact")
    f = b.frontier("p")
    assert "HANDOFF 4" in f and "HANDOFF 3" not in f and "gate denied 4" in f and "gate denied 0" not in f
    assert "real fact" in f


def test_metrics_are_recorded_per_run(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    rid = b.run_start("p", "m")
    b.record_metrics(
        rid,
        [{"ts": 1, "input": 2, "cache_read": 7000, "cache_write": 900, "output": 40}],
        [{"ts": 1, "tool": "Bash", "kind": "arsenal", "cmd": "bh-crawl http://h", "ms": 12000, "locked": False}],
    )
    b.record_metrics(rid, [{"ts": 2, "output": 5}], [])  # a second leg appends
    assert b.rows("SELECT COUNT(*) n FROM turns WHERE run_id=?", rid)[0]["n"] == 2
    assert b.rows("SELECT kind, ms FROM tool_calls WHERE run_id=?", rid)[0]["ms"] == 12000


def test_only_submit_todos_exist(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    for kind in ("auth", "waf", "verify", "other"):
        with pytest.raises(ValueError):
            b.add_todo(kind, "x", program="p")
    assert b.rows("SELECT COUNT(*) n FROM todos")[0]["n"] == 0


def test_migration_obsoletes_old_todos_once(tmp_path):
    path = tmp_path / "b.sqlite"
    b = Board(path)
    now = time.time()
    b.db.executemany(
        "INSERT INTO todos(program, kind, title, status, created) VALUES (?,?,?,?,?)",
        [("p", "waf", "WAF on h", "open", now), ("p", "submit", "F1", "open", now), ("p", "auth", "x", "done", now)],
    )
    b.db.execute("DELETE FROM meta WHERE k='todos-v2'")  # as if the board predated the migration
    b.db.commit()
    b = Board(path)
    assert {r["kind"]: r["status"] for r in b.rows("SELECT kind, status FROM todos")} == {
        "waf": "obsolete",
        "submit": "open",
        "auth": "done",
    }
    b.db.execute("INSERT INTO todos(program, kind, title, created) VALUES ('p', 'waf', 'later', ?)", (now,))
    b.db.commit()
    Board(path)  # the migration runs once only
    assert b.rows("SELECT status FROM todos WHERE title='later'")[0]["status"] == "open"
    assert "blockers" in {r["name"] for r in b.rows("PRAGMA table_info(runs)")}


def test_blockers_in_the_frontier(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    bid = b.add_blocker("p", "nope", "something", detail="why", host="a.test")
    row = b.rows("SELECT kind, title, summary, evidence FROM facts WHERE id=?", bid)[0]
    assert tuple(row) == ("blocker", "[other] something", "why", "host:a.test")  # unknown reason -> other
    b.add_blocker("p", "waf", "a.test challenges every request")
    old = b.add_blocker("p", "auth", "stale wall")
    b.db.execute("UPDATE facts SET created=? WHERE id=?", (time.time() - BLOCKER_TTL_S - 1, old))
    for i in range(12):
        b.add_blocker("q", "paid", f"q blocker {i}")
    b.db.commit()
    f = b.frontier("p")
    assert f.split("## blocked (do not retry)\n")[1].splitlines() == [
        f"- {bid} [other] something",
        f"- {bid + 1} [waf] a.test challenges every request",
    ]
    assert "stale wall" not in f and "## facts" not in f  # blockers are not repeated as plain facts
    q = b.frontier("q").splitlines()
    assert sum("[paid]" in line for line in q) == 10 and q[-1].endswith("q blocker 11")
    assert not any(line.endswith("q blocker 1") for line in q)  # the oldest ones are cut
