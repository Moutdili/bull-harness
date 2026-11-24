"""Retention of what the gate writes: per-flow files, and the flow and event logs.

At 2 req/s the gate stores about 650 MB a day of full exchanges (`flows/<id>.json`). Nothing in the board
points to them: they exist so a human can read an exchange in the UI. They are deleted after FLOW_DAYS.

`flows.jsonl` and `events.jsonl` are read by the host through cursors (`Board.new_lines`). Past
ROTATE_BYTES a log is gzipped to `<name>.<stamp>.gz`, and the gate opens a new file on its next write
(it appends with open/close per line). A cursor remembers the inode it read, so a rotated log is read
from its start. Archives are deleted after ARCHIVE_DAYS.

Prune only while holding the run lock: no segment is running, every consumer has read its lines, and
the gate is idle.
"""

from __future__ import annotations

import gzip
import os
import shutil
import time
from pathlib import Path

from bh import paths

FLOW_DAYS = float(os.environ.get("BH_FLOW_DAYS", "14"))
ARCHIVE_DAYS = float(os.environ.get("BH_ARCHIVE_DAYS", "90"))
ROTATE_BYTES = int(os.environ.get("BH_ROTATE_BYTES", str(64 << 20)))
DAY = 86400


def _flow_time(p: Path) -> float:
    """Flow ids start with the epoch second they were written (`1795393259-ab12cd-3`)."""
    head = p.name.split("-", 1)[0]
    return float(head) if head.isdigit() else p.stat().st_mtime


def prune(
    *, days: float = FLOW_DAYS, archive_days: float = ARCHIVE_DAYS, rotate_bytes: int = ROTATE_BYTES, now=None
) -> dict[str, int]:
    now = time.time() if now is None else now
    state = paths.state()
    out = {"flow files deleted": 0, "bytes freed": 0, "logs rotated": 0, "archives deleted": 0}
    flows_dir = state / paths.FLOWS_DIR
    if flows_dir.is_dir():
        cutoff = now - days * DAY
        for p in flows_dir.iterdir():
            try:
                if p.suffix == ".json" and _flow_time(p) < cutoff:
                    size = p.stat().st_size
                    p.unlink()
                    out["flow files deleted"] += 1
                    out["bytes freed"] += size
            except OSError:
                continue
    for name in (paths.FLOWS, paths.EVENTS):
        log = state / name
        try:
            if log.stat().st_size <= rotate_bytes:
                continue
        except OSError:
            continue
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(now))
        moved = log.with_name(f"{name}.{stamp}")
        os.replace(log, moved)  # the gate's next write creates a fresh log
        with open(moved, "rb") as src, gzip.open(f"{moved}.gz", "wb") as dst:
            shutil.copyfileobj(src, dst)
        os.chmod(f"{moved}.gz", 0o600)
        moved.unlink()
        out["logs rotated"] += 1
    for p in state.glob("*.jsonl.*.gz"):
        try:
            if p.stat().st_mtime < now - archive_days * DAY:
                p.unlink()
                out["archives deleted"] += 1
        except OSError:
            continue
    return out
