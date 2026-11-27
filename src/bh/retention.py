"""Retention of what the gate writes: per-flow files, and the flow and event logs.

At 2 req/s the gate stores about 650 MB a day of full exchanges (`flows/<id>.json`). Nothing in the board
points to them: they exist so a human can read an exchange in the UI. They are deleted after FLOW_DAYS.

`flows.jsonl` and `events.jsonl` are read by the host through cursors (`Board.new_lines`). Past
ROTATE_BYTES a log is gzipped to `<name>.<stamp>.gz`, and the gate opens a new file on its next write
(it appends with open/close per line). A cursor remembers the inode it read, so a rotated log is read
from its start. Archives are deleted after ARCHIVE_DAYS.

Three tiers (D11, wave W2):
- hot: the raw exchanges (`flows/<id>.json`), FLOW_DAYS (14 days), as before;
- pinned: every flow a finding cites while it is `verified`, `verified-evidence`, `inconclusive` or `submitted`
  (its id appears in the finding's proof, evidence, PoC, replay or observation): never deleted by `prune`, whatever
  its age. A finding that leaves those states unpins its flows at the next prune;
- cold: what the lineage keeps of an agent (card, block, handover, redacted trace: `var/lineage/`, and the board):
  `prune` never touches it.
The pins are read from the board read-only; a board that exists and cannot be read stops flow deletion for this
prune (nothing a finding may cite is lost to a locked database).

Prune only while holding the run lock: no segment is running, every consumer has read its lines, and
the gate is idle.
"""

from __future__ import annotations

import gzip
import os
import re
import shutil
import sqlite3
import time
from pathlib import Path

from bh import paths

FLOW_DAYS = float(os.environ.get("BH_FLOW_DAYS", "14"))
ARCHIVE_DAYS = float(os.environ.get("BH_ARCHIVE_DAYS", "90"))
ROTATE_BYTES = int(os.environ.get("BH_ROTATE_BYTES", str(64 << 20)))
DAY = 86400
TIERS = {"hot": "flows/<id>.json, FLOW_DAYS", "pinned": "flows a pinning finding cites", "cold": "var/lineage, kept"}
PIN_STATUS = ("verified", "verified-evidence", "inconclusive", "submitted")
_PIN_FIELDS = ("proof", "evidence", "poc", "poc_triager", "replay", "observation", "summary", "url")
FLOW_ID = re.compile(r"\b\d{9,11}-[0-9a-f]{6}-\d+\b")  # bh.gate.addon: <epoch>-<6 hex>-<seq>


def pinned_flows(db_path: Path | None = None) -> set[str] | None:
    """Ids of the flows the pinning findings cite; None when a board exists but cannot be read."""
    p = paths.board_db() if db_path is None else Path(db_path)
    if not p.exists():
        return set()
    try:
        con = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=10)
        try:
            have = {r[1] for r in con.execute("PRAGMA table_info(findings)")}
            cols = [c for c in _PIN_FIELDS if c in have]
            if not cols:
                return set()
            rows = con.execute(
                f"SELECT {', '.join(cols)} FROM findings WHERE status IN ({', '.join('?' * len(PIN_STATUS))})",
                PIN_STATUS,
            ).fetchall()
        finally:
            con.close()
    except sqlite3.Error:
        return None
    return {m for row in rows for v in row if v for m in FLOW_ID.findall(str(v))}


def _flow_time(p: Path) -> float:
    """Flow ids start with the epoch second they were written (`1795393259-ab12cd-3`)."""
    head = p.name.split("-", 1)[0]
    return float(head) if head.isdigit() else p.stat().st_mtime


def prune(
    *,
    days: float = FLOW_DAYS,
    archive_days: float = ARCHIVE_DAYS,
    rotate_bytes: int = ROTATE_BYTES,
    now=None,
    db_path: Path | None = None,
) -> dict[str, int]:
    now = time.time() if now is None else now
    state = paths.state()
    out = {"flow files deleted": 0, "bytes freed": 0, "flow files pinned": 0, "logs rotated": 0, "archives deleted": 0}
    flows_dir = state / paths.FLOWS_DIR
    pins = pinned_flows(db_path) if flows_dir.is_dir() else set()
    if pins is None:
        out["pins unreadable"] = 1
    if flows_dir.is_dir() and pins is not None:
        cutoff = now - days * DAY
        for p in flows_dir.iterdir():
            try:
                if p.suffix == ".json" and _flow_time(p) < cutoff:
                    if p.stem in pins:
                        out["flow files pinned"] += 1
                        continue
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
