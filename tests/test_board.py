from bh.board import Board


def test_board_crud(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    rid = b.run_start("demo", "sonnet")
    b.add_fact("demo", "httpx: 12 live hosts", "list in evidence", "/work/raw/1.log", run_id=rid)
    iid = b.add_intent("demo", "test IDOR on /api/orders")
    fid = b.add_finding("demo", "IDOR on /api/orders/{id}", severity="high", poc="curl ...", bogus="x")
    assert b.add_todo("auth", "need 2nd account", program="demo", dedup="auth:demo") is not None
    assert b.add_todo("auth", "need 2nd account", program="demo", dedup="auth:demo") is None
    b.set_finding(fid, "verified", "submit")
    b.close_intent(iid, "done")
    b.run_end(rid, status="ok", session_id="s1", turns=3)
    assert b.last_session("demo") == "s1"
    f = b.frontier("demo")
    assert "F1 [verified/high]" in f and "httpx: 12 live hosts" in f and "T1 [auth]" in f
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
    b.record_metrics(rid, [{"ts": 1, "input": 2, "cache_read": 7000, "cache_write": 900, "output": 40}],
                     [{"ts": 1, "tool": "Bash", "kind": "arsenal", "cmd": "bh-crawl http://h", "ms": 12000, "locked": False}])
    b.record_metrics(rid, [{"ts": 2, "output": 5}], [])  # a second leg appends
    assert b.rows("SELECT COUNT(*) n FROM turns WHERE run_id=?", rid)[0]["n"] == 2
    assert b.rows("SELECT kind, ms FROM tool_calls WHERE run_id=?", rid)[0]["ms"] == 12000
