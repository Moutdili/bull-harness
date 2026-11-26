"""Birth, closing, relaunch check and diff of an agent (D8, D9).

An agent is one `claude -p` session with a fresh context: a segment's first session, and every session a context
rotation starts. `birth()` gives it a number (a global counter, never reused, kept in `meta` so a deleted row does
not free its number), a pseudo (bh.lineage.names), a generation (its rank on the program) and a parent (by default
the program's previous agent), and writes its row in `agents`. The harness closes it with `close()`.

The birth condensate (`birth_sha256`) binds what the agent started from: the setup condensate (bh.runner.identity),
the lineage block it was shown, its mission and the date of the memory it read. Two agents born from the same four
inputs share it. A relaunch is allowed when `relaunch_check()` finds no setup field that moved; by default a
relaunch targets the lab (RELAUNCH_DEFAULT), never a live program.

The tables `agents` and `blocks` belong to bh.lineage.store (`store.ensure`); this module only reads and writes rows.
"""

from __future__ import annotations

import hashlib
import json
import time

from bh.lineage import names

NO_KEY = "lineage-next-no"  # meta: the next agent number (the counter never goes back)
RELAUNCH_DEFAULT = "lab"  # scopes/lab: where `bh agent relaunch` points unless told otherwise
OPEN = "running"  # status of an agent not closed yet

# runs columns compared by diff() (those the board has)
COUNTERS = (
    "status",
    "turns",
    "cost_usd",
    "input_tokens",
    "output_tokens",
    "cache_read",
    "cache_write",
    "arsenal_calls",
    "manual_calls",
    "locked_calls",
    "gate_requests",
    "gate_denied",
    "gate_errors",
    "gate_pushback",
    "blockers",
    "rotations",
    "max_context",
    "early_stop",
)


def _canonical(doc) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def birth_sha256(setup_sha256: str, lineage_block: str | None, mission: str | None, memory_as_of) -> str:
    """Condensate of an agent's start: setup, lineage block shown (as its own sha256), mission, memory date."""
    doc = {
        "setup_sha256": setup_sha256 or "",
        "lineage_sha256": _sha(lineage_block or ""),
        "mission": mission or "",
        "memory_as_of": memory_as_of,
    }
    return _sha(_canonical(doc))


def _program(scope) -> str:
    return scope if isinstance(scope, str) else scope.program


def next_no(board) -> int:
    """Reserve the next agent number: max(counter, largest number in `agents`) + 1, then move the counter."""
    stored = int(board.meta_get(NO_KEY, "0") or 0)
    row = board.db.execute("SELECT MAX(no) AS m FROM agents").fetchone()
    no = max(stored, int(row[0] or 0)) + 1
    board.meta_set(NO_KEY, str(no))
    return no


def birth(
    board,
    scope,
    run_id: int | None,
    *,
    setup_sha256: str,
    parent_no: int | None = None,
    mission: str | None = None,
    lineage_block: str | None = None,
    memory_as_of=None,
    relaunch_of: int | None = None,
) -> dict:
    """Write the `agents` row of a new agent; {no, label, pseudo, program, generation, parent_no, birth_sha256}."""
    program = _program(scope)
    no = next_no(board)
    taken = [r[0] for r in board.db.execute("SELECT pseudo FROM agents")]
    pseudo = names.pseudo(no, program, taken)
    rank = board.db.execute("SELECT COUNT(*) FROM agents WHERE program=?", (program,)).fetchone()[0]
    if parent_no is None:
        prev = board.db.execute("SELECT MAX(no) FROM agents WHERE program=?", (program,)).fetchone()[0]
        parent_no = int(prev) if prev is not None else None
    digest = birth_sha256(setup_sha256, lineage_block, mission, memory_as_of)
    board.db.execute(
        "INSERT INTO agents(no, pseudo, program, generation, parent_no, run_id, setup_sha256, birth_sha256, "
        "relaunch_of, born, closed, status) VALUES (?,?,?,?,?,?,?,?,?,?,NULL,?)",
        (no, pseudo, program, rank + 1, parent_no, run_id, setup_sha256, digest, relaunch_of, time.time(), OPEN),
    )
    board.db.commit()
    return {
        "no": no,
        "label": names.label(no),
        "pseudo": pseudo,
        "program": program,
        "generation": rank + 1,
        "parent_no": parent_no,
        "birth_sha256": digest,
    }


def close(board, no: int, status: str) -> None:
    """Closed by the harness, never by the agent: the first closing stands."""
    board.db.execute(
        "UPDATE agents SET status=?, closed=? WHERE no=? AND closed IS NULL", (str(status), time.time(), int(no))
    )
    board.db.commit()


def agent(board, no: int) -> dict:
    row = board.db.execute("SELECT * FROM agents WHERE no=?", (int(no),)).fetchone()
    if row is None:
        raise LookupError(f"no agent {names.label(no)}")
    return dict(zip(row.keys(), tuple(row), strict=True))


def _setup_of(board, ag: dict) -> dict | None:
    """The setup document the agent was born under: its run's setup_json, else any run with the same condensate."""
    rows = []
    if ag.get("run_id") is not None:
        rows = board.db.execute("SELECT setup_sha256, setup_json FROM runs WHERE id=?", (ag["run_id"],)).fetchall()
    rows = [r for r in rows if r[1] and r[0] == ag.get("setup_sha256")] or board.db.execute(
        "SELECT setup_sha256, setup_json FROM runs WHERE setup_sha256=? AND setup_json IS NOT NULL LIMIT 1",
        (ag.get("setup_sha256"),),
    ).fetchall()
    return json.loads(rows[0][1]) if rows else None


def relaunch_check(board, no: int, current_setup: dict) -> list[str]:
    """Setup fields that moved since agent `no` was born (sorted); an empty list allows the relaunch. A setup the
    board no longer holds cannot be compared: `["setup_json"]`."""
    old = _setup_of(board, agent(board, no))
    if old is None:
        return ["setup_json"]
    return sorted(k for k in set(old) | set(current_setup) if old.get(k, ...) != current_setup.get(k, ...))


def _run_counters(board, run_id) -> dict:
    have = {r[1] for r in board.db.execute("PRAGMA table_info(runs)")}
    cols = [c for c in COUNTERS if c in have]
    out: dict = {}
    if run_id is not None and cols:
        row = board.db.execute(f"SELECT {', '.join(cols)} FROM runs WHERE id=?", (run_id,)).fetchone()
        if row is not None:
            out = dict(zip(cols, tuple(row), strict=True))
    out["findings"] = (
        board.db.execute("SELECT COUNT(*) FROM findings WHERE run_id=?", (run_id,)).fetchone()[0]
        if run_id is not None
        else 0
    )
    return out


def diff(board, a: int, b: int) -> dict:
    """What separates agents `a` and `b`: the condensates that differ (setup, birth, every `*_sha256` of the setup
    and the cards), the other setup fields that differ, and the counters of both runs."""
    ag_a, ag_b = agent(board, a), agent(board, b)
    sa, sb = _setup_of(board, ag_a) or {}, _setup_of(board, ag_b) or {}
    digests = {}
    for key in ("setup_sha256", "birth_sha256"):
        if ag_a.get(key) != ag_b.get(key):
            digests[key] = [ag_a.get(key), ag_b.get(key)]
    fields = {}
    for key in sorted(set(sa) | set(sb)):
        va, vb = sa.get(key), sb.get(key)
        if va == vb:
            continue
        if key.endswith("sha256") or key in ("cards", "pseudo_rule"):
            digests[key] = [va, vb]
        else:
            fields[key] = [va, vb]
    return {
        "a": {"no": ag_a["no"], "label": names.label(ag_a["no"]), "pseudo": ag_a["pseudo"], "run_id": ag_a["run_id"]},
        "b": {"no": ag_b["no"], "label": names.label(ag_b["no"]), "pseudo": ag_b["pseudo"], "run_id": ag_b["run_id"]},
        "digests": digests,
        "fields": fields,
        "counters": {"a": _run_counters(board, ag_a["run_id"]), "b": _run_counters(board, ag_b["run_id"])},
    }
