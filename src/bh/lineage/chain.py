"""Hash chains (D10): the trace of one agent, and the blocks that link agents of a program.

Trace: one canonical JSON line per event, `{"i", "ts", "prev", "event", "hash"}`. `prev` is the hash of the line
before (GENESIS for the first), and `hash = sha256(prev + canonical {"event", "i", "ts"})`: the event's key order
does not matter, and the line's position and time are bound with it, so any byte changed anywhere in a line is
found by `verify()`, which also requires every line to be in its canonical form. `Trace.append` takes any JSON
object as it is, `{"type": "bh_decision", ...}` included (T20).

Block: when the harness closes an agent, `close_block()` writes in `blocks` the body `{no, pseudo, program,
setup_sha256, parent_no, trace_head, summary, prev_hash, ts}` (canonical JSON) and `block_hash = sha256(body)`;
`prev_hash` is the program's previous block hash. `verify_blocks()` walks the program's blocks in order.

What a chain proves: that a trace or a block has not moved since it was written. Not that what it says is true.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from bh.lineage import archive

GENESIS = "0" * 64


def canonical(doc) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def event_hash(prev: str, i: int, ts: float, event: dict) -> str:
    return _sha(prev + canonical({"event": event, "i": i, "ts": ts}))


def _last_line(path: Path) -> str | None:
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            end = fh.tell()
            pos, buf = end, b""
            while pos > 0:
                step = min(4096, pos)
                pos -= step
                fh.seek(pos)
                buf = fh.read(step) + buf
                lines = buf.rstrip(b"\n").split(b"\n")
                if len(lines) > 1 or pos == 0:
                    last = lines[-1]
                    return last.decode("utf-8") if last else None
    except FileNotFoundError:
        return None
    return None


class Trace:
    """Append-only hash-chained trace of one agent. One writer (the host); reopening continues the chain."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        last = _last_line(self.path)
        if last:
            rec = json.loads(last)
            self._next, self._head = int(rec["i"]) + 1, str(rec["hash"])
        else:
            self._next, self._head = 0, GENESIS

    def append(self, event: dict, *, ts: float | None = None) -> str:
        if not isinstance(event, dict):
            raise TypeError("a trace event is a JSON object")
        ts = time.time() if ts is None else float(ts)
        i, prev = self._next, self._head
        h = event_hash(prev, i, ts, event)
        line = canonical({"i": i, "ts": ts, "prev": prev, "event": event, "hash": h})
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        self._next, self._head = i + 1, h
        return h

    def head(self) -> str:
        """Hash of the last line (GENESIS for an empty trace)."""
        return self._head


def verify(path: str | Path) -> tuple[bool, int | None]:
    """(True, None) when every line holds; else (False, index of the first line that does not)."""
    prev = GENESIS
    try:
        raw = Path(path).read_bytes()
    except FileNotFoundError:
        return True, None
    lines = raw.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    for i, b in enumerate(lines):
        try:
            text = b.decode("utf-8")
            rec = json.loads(text)
            ok = (
                isinstance(rec, dict)
                and set(rec) == {"i", "ts", "prev", "event", "hash"}
                and rec["i"] == i
                and rec["prev"] == prev
                and isinstance(rec["event"], dict)
                and rec["hash"] == event_hash(prev, i, rec["ts"], rec["event"])
                and canonical(rec) == text
            )
        except (ValueError, TypeError, KeyError):
            ok = False
        if not ok:
            return False, i
        prev = rec["hash"]
    return True, None


def count(path: str | Path, type: str) -> int:
    """Events of a given `type` in a trace (T20: `bh_decision`)."""
    n = 0
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    ev = json.loads(line).get("event") or {}
                except (ValueError, AttributeError):
                    continue
                if isinstance(ev, dict) and ev.get("type") == type:
                    n += 1
    except FileNotFoundError:
        return 0
    return n


def _last_block(board, program: str) -> str:
    row = board.db.execute(
        "SELECT block_hash FROM blocks WHERE program=? ORDER BY rowid DESC LIMIT 1", (program,)
    ).fetchone()
    return row[0] if row else GENESIS


def close_block(board, no: int, trace_head: str, summary: dict) -> str:
    """Write agent `no`'s block (once) and return its hash. The summary goes through bh.redact (archive.scrub)."""
    row = board.db.execute(
        "SELECT no, pseudo, program, setup_sha256, parent_no FROM agents WHERE no=?", (int(no),)
    ).fetchone()
    if row is None:
        raise LookupError(f"no agent {no}")
    if board.db.execute("SELECT 1 FROM blocks WHERE no=?", (int(no),)).fetchone():
        raise ValueError(f"agent {no} already has its block")
    no_, pseudo, program, setup_sha256, parent_no = tuple(row)
    ts = time.time()
    prev = _last_block(board, program)
    body = canonical(
        {
            "no": no_,
            "pseudo": pseudo,
            "program": program,
            "setup_sha256": setup_sha256,
            "parent_no": parent_no,
            "trace_head": trace_head,
            "summary": archive.scrub(summary or {}),
            "prev_hash": prev,
            "ts": ts,
        }
    )
    h = _sha(body)
    board.db.execute(
        "INSERT INTO blocks(no, program, prev_hash, block_hash, body, ts) VALUES (?,?,?,?,?,?)",
        (no_, program, prev, h, body, ts),
    )
    board.db.commit()
    return h


def verify_blocks(board, program: str) -> tuple[bool, int | None]:
    """(True, None) when the program's blocks chain; else (False, agent number of the first block that does not)."""
    prev = GENESIS
    rows = board.db.execute(
        "SELECT no, program, prev_hash, block_hash, body, ts FROM blocks WHERE program=? ORDER BY rowid", (program,)
    ).fetchall()
    for no, prog, prev_hash, block_hash, body, ts in (tuple(r) for r in rows):
        try:
            doc = json.loads(body)
            ok = (
                canonical(doc) == body
                and _sha(body) == block_hash
                and prev_hash == prev
                and doc.get("prev_hash") == prev
                and doc.get("no") == no
                and doc.get("program") == prog
                and doc.get("ts") == ts
            )
        except (ValueError, TypeError, AttributeError):
            ok = False
        if not ok:
            return False, no
        prev = block_hash
    return True, None
