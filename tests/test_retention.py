import gzip
import json
import os
import time

from bh import paths, retention
from bh.board import Board


def _state(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    st = paths.state()
    (st / paths.FLOWS_DIR).mkdir(parents=True)
    return st


def test_old_flow_files_go_recent_ones_stay(tmp_path, monkeypatch):
    st = _state(tmp_path, monkeypatch)
    now = time.time()
    old = st / paths.FLOWS_DIR / f"{int(now - 15 * 86400)}-aa-1.json"
    new = st / paths.FLOWS_DIR / f"{int(now - 3600)}-bb-2.json"
    for p in (old, new):
        p.write_text("{}")
    out = retention.prune(days=14, now=now)
    assert out["flow files deleted"] == 1 and not old.exists() and new.exists()


def test_rotation_keeps_every_line_for_the_cursor(tmp_path, monkeypatch):
    st = _state(tmp_path, monkeypatch)
    log = st / paths.FLOWS
    board = Board(tmp_path / "board.sqlite")
    log.write_text("".join(json.dumps({"n": i}) + "\n" for i in range(50)))
    assert len(board.new_lines(log, "c")) == 50
    out = retention.prune(rotate_bytes=100)
    assert out["logs rotated"] == 1 and not log.exists()
    (archive,) = st.glob("flows.jsonl.*.gz")
    assert len(gzip.decompress(archive.read_bytes()).splitlines()) == 50
    # the gate writes a new, larger log (another inode): read from its start, not from the old offset
    log.write_text("".join(json.dumps({"m": i}) + "\n" for i in range(300)))
    assert len(board.new_lines(log, "c")) == 300
    assert board.new_lines(log, "c") == []


def test_cursor_waits_for_a_partial_line(tmp_path):
    board = Board(tmp_path / "board.sqlite")
    log = tmp_path / "x.jsonl"
    log.write_text('{"a": 1}\n{"b": ')
    assert board.new_lines(log, "k") == [{"a": 1}]
    with open(log, "a") as fh:
        fh.write("2}\n")
    assert board.new_lines(log, "k") == [{"b": 2}]


def test_old_archives_are_deleted(tmp_path, monkeypatch):
    st = _state(tmp_path, monkeypatch)
    arch = st / "events.jsonl.20260101-000000.gz"
    arch.write_bytes(b"")
    os.utime(arch, (time.time() - 100 * 86400,) * 2)
    assert retention.prune(archive_days=90)["archives deleted"] == 1


# ------------------------------------------------------------------ tiers (W2-D, D11)
def _old_flow(st, now, days, tag):
    p = st / paths.FLOWS_DIR / f"{int(now - days * 86400)}-{tag}-1.json"
    p.write_text("{}")
    return p


def test_flows_a_pinning_finding_cites_are_never_pruned(tmp_path, monkeypatch):
    st = _state(tmp_path, monkeypatch)
    now = 1_800_000_000.0  # a fixed date: nothing here depends on the clock
    board = Board(paths.board_db())
    flows = {s: _old_flow(st, now, 400, tag) for s, tag in (
        ("verified", "aaaaaa"), ("inconclusive", "bbbbbb"), ("submitted", "cccccc"),
        ("rejected", "dddddd"), ("new", "eeeeee"))}  # fmt: skip
    loose = _old_flow(st, now, 20, "ffffff")
    for status, p in flows.items():
        fid = board.add_finding("prog", f"f-{status}", proof=json.dumps({"steps": [{"flow": p.stem}]}))
        board.set_finding(fid, status)
    recent = _old_flow(st, now, 1, "999999")
    out = retention.prune(days=14, now=now)
    for status in ("verified", "inconclusive", "submitted"):
        assert flows[status].exists(), status
    assert not flows["rejected"].exists() and not flows["new"].exists() and not loose.exists() and recent.exists()
    assert out["flow files pinned"] == 3 and out["flow files deleted"] == 3
    # a finding that leaves the pinning states unpins its flows at the next prune
    fid = board.rows("SELECT id FROM findings WHERE title='f-inconclusive'")[0]["id"]
    board.set_finding(fid, "rejected")
    retention.prune(days=14, now=now)
    assert not flows["inconclusive"].exists() and flows["verified"].exists()


def test_cold_tier_is_never_touched(tmp_path, monkeypatch):
    st = _state(tmp_path, monkeypatch)
    now = 1_800_000_000.0
    agent = paths.var() / "lineage" / "prog" / "0001-zero-plague"
    agent.mkdir(parents=True)
    kept = [agent / n for n in ("identity.json", "stream.jsonl", "manifest.json")]
    for p in kept:
        p.write_text("{}")
        os.utime(p, (now - 1000 * 86400,) * 2)
    _old_flow(st, now, 30, "abcdef")
    retention.prune(days=14, archive_days=90, now=now)
    assert all(p.exists() for p in kept)


def test_an_unreadable_board_stops_flow_deletion(tmp_path, monkeypatch):
    st = _state(tmp_path, monkeypatch)
    now = 1_800_000_000.0
    paths.board_db().parent.mkdir(parents=True, exist_ok=True)
    paths.board_db().write_bytes(b"not a database, not even close" * 10)
    old = _old_flow(st, now, 30, "abcdef")
    out = retention.prune(days=14, now=now)
    assert old.exists() and out["pins unreadable"] == 1 and out["flow files deleted"] == 0
