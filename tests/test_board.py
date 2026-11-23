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
