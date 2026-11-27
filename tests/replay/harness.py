"""Replay of a recorded segment through the host's ingestion (T19 c): what the board would hold after it.

A trace is a directory:

  trace.json       {"synthetic": bool, "program", "run_id", "identities": [...], "scope"?: {...}, "about": "..."}
  notes.jsonl      the rotated notes of the segment, as bh-note wrote them (the runner's notes-<run>.jsonl)
  events.jsonl     the gate's events (var/state/events.jsonl)
  flows.jsonl      the gate's flow log (var/state/flows.jsonl)
  flows/<id>.json  the exchanges the gate kept for target flows (the receipts a quote is anchored in)
  stream.jsonl     the claude stream-json of the segment (paths.run_log)
  expected.json    {"board": snapshot(...)}: the state the replay must give

`replay` copies the gate's files into the state dir of a fresh BH_HOME, opens a board there, opens the run, reads
the stream with the runner's own reader (consume_stream + merge_result: cost, turns, status), then runs
`ingest.notes` and `ingest.gate_events`, the two entry points of the runner, with their real signatures. Nothing is
mocked between the files and the board: a regression of the ingestion shows as a different snapshot.

The discipline (replay a recorded trace, compare to a stored expectation, one trace per bug) follows PentestGPT's
benchmark replays (MIT); the code is ours.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

from bh import paths
from bh.board import Board
from bh.runner import ingest
from bh.runner import run as runner
from bh.scope import scope_from_dict

TRACES = Path(__file__).parent / "traces"
META, NOTES, EVENTS, FLOWS, FLOWS_DIR, STREAM, EXPECTED = (
    "trace.json",
    "notes.jsonl",
    "events.jsonl",
    "flows.jsonl",
    "flows",
    "stream.jsonl",
    "expected.json",
)


@contextlib.contextmanager
def home(path: Path):
    """BH_HOME set to `path` for the block (paths.* read it at call time), restored after."""
    old = os.environ.get("BH_HOME")
    os.environ["BH_HOME"] = str(path)
    try:
        yield path
    finally:
        if old is None:
            os.environ.pop("BH_HOME", None)
        else:
            os.environ["BH_HOME"] = old


def meta(trace_dir: Path) -> dict:
    return json.loads((Path(trace_dir) / META).read_text(encoding="utf-8"))


def _stream(board: Board, run_id: int, program: str, stream: Path) -> None:
    """The stream through the runner's reader: the result event gives cost, turns, status and session."""
    if not stream.is_file():
        return
    res = runner.SegmentResult(program=program, run_id=run_id)
    lines = stream.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    result = runner.consume_stream(SimpleNamespace(stdout=lines), io.StringIO(), res, lambda _m: None)
    runner.merge_result(res, result)
    board.run_end(
        run_id,
        status=res.status,
        turns=res.turns,
        cost_usd=round(res.cost_usd, 6),
        session_id=res.session_id,
    )


def replay(trace_dir: Path, work: Path | None = None) -> Board:
    """The board a recorded segment leaves, built in `work` (a fresh temporary directory by default)."""
    trace_dir = Path(trace_dir)
    m = meta(trace_dir)
    program, run_id = str(m["program"]), int(m["run_id"])
    work = Path(work) if work is not None else Path(tempfile.mkdtemp(prefix="bh-replay-"))
    with home(work):
        state = paths.state()
        state.mkdir(parents=True, exist_ok=True)
        for name in (EVENTS, FLOWS):
            if (trace_dir / name).is_file():
                shutil.copyfile(trace_dir / name, state / name)
        if (trace_dir / FLOWS_DIR).is_dir():
            shutil.copytree(trace_dir / FLOWS_DIR, state / paths.FLOWS_DIR, dirs_exist_ok=True)
        board = Board(paths.board_db())
        board.db.execute(
            "INSERT INTO runs(id, program, model, started, status) VALUES (?,?,?,?, 'running')",
            (run_id, program, m.get("model", "replay"), time.time()),
        )
        board.db.commit()
        scope = scope_from_dict(m["scope"]) if m.get("scope") else None
        _stream(board, run_id, program, trace_dir / STREAM)
        ingest.notes(board, program, run_id, trace_dir / NOTES, scope)
        ingest.gate_events(board, program, run_id, list(m.get("identities") or []))
    return board


def snapshot(board: Board, program: str) -> dict:
    """What a trace's expectation compares: the rows a segment writes, without times or ids."""
    return {
        "findings": [
            dict(r)
            for r in board.rows(
                "SELECT title, status, verdict, severity, vuln_class, url, not_proven, "
                "proof IS NOT NULL AS has_proof FROM findings WHERE program=? ORDER BY id",
                program,
            )
        ],
        "facts": [
            dict(r)
            for r in board.rows(
                "SELECT kind, title, grounded FROM facts WHERE program=? ORDER BY id",
                program,
            )
        ],
        "intents": [
            dict(r) for r in board.rows("SELECT title, status, kind FROM intents WHERE program=? ORDER BY id", program)
        ],
        "runs": [
            dict(r)
            for r in board.rows("SELECT id, status, turns, cost_usd FROM runs WHERE program=? ORDER BY id", program)
        ],
    }


def expected(trace_dir: Path) -> dict:
    return json.loads((Path(trace_dir) / EXPECTED).read_text(encoding="utf-8"))["board"]


def differences(board: Board, trace_dir: Path) -> list[str]:
    """One line per section of the snapshot that differs from the trace's expectation (empty: the replay holds)."""
    got, want = snapshot(board, meta(trace_dir)["program"]), expected(trace_dir)
    out = []
    for k in sorted(set(got) | set(want)):
        if got.get(k) != want.get(k):
            out.append(f"{k}: got {json.dumps(got.get(k), ensure_ascii=False)} want {json.dumps(want.get(k))}")
    return out


def write_expected(board: Board, trace_dir: Path) -> Path:
    """The current snapshot as the trace's expectation (a baseline to review by hand, never to trust blindly)."""
    p = Path(trace_dir) / EXPECTED
    doc = {"board": snapshot(board, meta(trace_dir)["program"])}
    p.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return p
