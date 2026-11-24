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
