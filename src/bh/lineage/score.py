"""The credit ledger of a lineage (W2-G): what each agent contributed, counted by the host.

Rule: credit rewards what the host verified (the gate, the judge, the canary), never what the agent says about itself.
compute() therefore reads statuses, labels, keys, counters and dates only. No free text of the agent reaches Python
here: the two text tests it needs (the host's verdict "excluded by program policy", the shape of a handoff's four
rubrics) are booleans computed by SQLite, and a finding's URL is only parsed into its cell key (origin + path family).

The score chooses (which setup to run again), shows (which kind of contribution counted) and makes "credit is counted
by the host" true. It never enters a prompt as a number attached to a running agent; the judge never sees it.

A missing table or column is zero signal, never an error: the tables come from other lots (agents, mem_items,
mem_receipts, coverage_class, intents.basis) and older boards lack them.

Weights: WEIGHTS are the defaults Mio chose; var/state/score-weights.json (host file) may override them, known signals
and integers in [-1000, 1000] only. Caps (CAPS) are counts of occurrences, not points, and are not tunable.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from bh import paths
from bh.agent import contract as c
from bh.board import Board
from bh.classes import canonical
from bh.text import escape_invisible

WEIGHTS: dict[str, int] = {
    "finding_verified": 100,  # findings.status verified | verified-evidence (| submitted, which was verified first)
    "finding_inconclusive": 10,
    "finding_rejected": -40,
    "finding_refused": -10,  # refused at ingestion: class excluded by the program, or no proof the host accepted
    "finding_duplicate": -10,
    "ruled_out_anchored": 20,  # mem_items label ANCHORED, outcome ruled_out
    "dead_end_anchored": 15,  # first on its cell and its cause
    "candidate_anchored": 10,
    "legacy_basis": 25,  # a fact of this agent is the basis of another agent's verified finding
    "legacy_consulted": 2,  # a later agent read this agent's item (mem_receipts), once per reader
    "pair_tested": 2,  # a new (endpoint, class) pair the gate saw tested (coverage_class.gate_seen = 1)
    "endpoint_new": 1,  # a new in-scope endpoint, first seen in the agent's run, seen by the gate
    "handoff_complete": 5,
    "handoff_missing": -5,
    "legacy_contradicted": -15,  # a ruled-out lead or a dead end on a cell where a finding was then verified
    "gate_denied": -5,  # each gate refusal after the first
}
# Occurrences counted at most, per agent (per item for legacy_consulted). gate_denied: 5 x -5 = -25 at the defaults.
CAPS: dict[str, int] = {
    "ruled_out_anchored": 5,
    "dead_end_anchored": 5,
    "candidate_anchored": 3,
    "legacy_consulted": 10,
    "pair_tested": 30,
    "endpoint_new": 15,
    "gate_denied": 5,
}
# Worth nothing, on purpose, and not tunable: a blocker on third-party data or server execution (a stop, never a
# reward), the number of notes, words, intents and recalls, and the severity the agent announces.
NEVER_SCORED = ("blocker_stop", "notes", "words", "intents", "recalls", "severity_declared")
WEIGHT_MIN, WEIGHT_MAX = -1000, 1000
WEIGHTS_FILE = "score-weights.json"

VERIFIED = ("verified", "verified-evidence", "submitted")
ANCHORED = "ANCHORED"
LEGACY_LABELS = ("OBSERVED", "JUDGED", "ANCHORED")  # a NOTE never earns: the gate saw nothing of it
OPERATOR = "operator"
DEAD_END = frozenset({"dead_end", "dead-end", "deadend"})
CANDIDATE = frozenset({"candidate"})
RULED_OUT = "ruled_out"

LEDGER_SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger (
  id INTEGER PRIMARY KEY, program TEXT NOT NULL, agent_no INTEGER, signal TEXT NOT NULL, points INTEGER NOT NULL,
  ref_kind TEXT, ref_id INTEGER, ts REAL
);
CREATE INDEX IF NOT EXISTS ledger_prog ON ledger(program, agent_no);
"""
_HANDOFF_RUBRICS = ("state", "dead", "next", "files")  # bh.runner.ingest._handoff writes them in this order
_SAFE = re.compile(r"[^A-Za-z0-9 ._:/{}\-]")


# ------------------------------------------------------------------ weights
def weights_path() -> Path:
    return paths.state() / WEIGHTS_FILE


def load_weights(path: str | Path | None = None) -> dict[str, int]:
    """The weights in force: WEIGHTS, overridden by the host file if it is valid as a whole. A file with an unknown
    signal, a value that is not an integer in [WEIGHT_MIN, WEIGHT_MAX] or that is not a JSON object is ignored, said
    on stderr, and the defaults stay: never half a file."""
    p = Path(path) if path is not None else weights_path()
    out = dict(WEIGHTS)
    if not p.exists():
        return out
    try:
        data = json.loads(p.read_text())
    except (OSError, ValueError) as exc:
        return _refuse(p, f"unreadable ({type(exc).__name__})", out)
    if not isinstance(data, dict):
        return _refuse(p, "not a JSON object", out)
    if unknown := sorted(set(data) - set(WEIGHTS)):
        return _refuse(p, f"unknown signal(s): {', '.join(map(str, unknown))[:200]}", out)
    for k, v in data.items():
        if isinstance(v, bool) or not isinstance(v, int) or not WEIGHT_MIN <= v <= WEIGHT_MAX:
            return _refuse(p, f"{k}: {v!r} is not an integer within [{WEIGHT_MIN}, {WEIGHT_MAX}]"[:200], out)
    out.update(data)
    return out


def _refuse(p: Path, why: str, defaults: dict[str, int]) -> dict[str, int]:
    sys.stderr.write(f"score: {p} ignored, default weights kept: {why}\n")
    return defaults


def weights_sha256(path: str | Path | None = None) -> str:
    """Digest of the weights in force (sorted keys, compact JSON): the setup records it next to the run."""
    blob = json.dumps(load_weights(path), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


# ------------------------------------------------------------------ schema helpers
def ensure(board: Board) -> None:
    board.db.executescript(LEDGER_SCHEMA)
    board.db.commit()


def _cols(board: Board, table: str) -> set[str]:
    return {r["name"] for r in board.db.execute(f"PRAGMA table_info({table})")}


def _rows(board: Board, sql: str, *args) -> list[sqlite3.Row]:
    try:
        return board.rows(sql, *args)
    except sqlite3.OperationalError:  # a table or column of another lot, absent here: zero signal
        return []


# ------------------------------------------------------------------ cells
def cell_of_url(url: str | None) -> tuple[str | None, str | None]:
    """(origin, path family) of a URL: the cell a finding sits on. Ids collapse (/users/1 and /users/7 are one)."""
    if not url:
        return None, None
    o = c.origin(url)
    try:
        path = urlsplit(url.strip()).path or "/"
    except ValueError:
        return o, None
    return o, c.family(c.path_key(path))


def norm_cell(cell: str | None) -> tuple[str | None, str | None]:
    """A mem_items cell in the comparable form of cell_of_url: an origin (if any), an HTTP method (dropped) and a
    path. Accepts "origin METHOD /path", "origin /path", "METHOD /path", "/path" or a URL."""
    if not cell:
        return None, None
    if "://" in cell and " " not in cell.strip():
        return cell_of_url(cell)
    o, path = None, None
    for tok in cell.split():
        if "://" in tok:
            o = c.origin(tok)
            try:
                p = urlsplit(tok).path
            except ValueError:
                p = ""
            if p and p != "/":
                path = p
        elif tok.startswith("/"):
            path = tok
    return o, (c.family(c.path_key(path)) if path else None)


def same_cell(a: tuple[str | None, str | None], b: tuple[str | None, str | None]) -> bool:
    return bool(a[1]) and a[1] == b[1] and (a[0] is None or b[0] is None or a[0] == b[0])


def _shown(cell: tuple[str | None, str | None]) -> str:
    return _safe(" ".join(x for x in cell if x) or "?", 100)


def _safe(s: str | None, n: int) -> str:
    """A key for a line another agent reads: invisible characters shown, anything but key characters dropped."""
    s = _SAFE.sub("?", escape_invisible(s or ""))
    return s if len(s) <= n else s[: n - 1] + "…"


# ------------------------------------------------------------------ entries
@dataclass(frozen=True)
class Entry:
    agent_no: int
    signal: str
    points: int
    ref_kind: str
    ref_id: int | None
    ts: float | None


def _agents(board: Board, program: str) -> dict[int, dict]:
    """agent_no -> {run_id, ...}. The operator (agent 0) is nobody's agent: never credited."""
    return {
        int(r["no"]): dict(r)
        for r in _rows(board, "SELECT no, run_id FROM agents WHERE program=?", program)
        if r["no"] is not None and int(r["no"]) > 0
    }


def entries(board: Board, program: str, weights: dict[str, int] | None = None) -> list[Entry]:
    """Every credit line of the program, computed, not written. Deterministic: same board, same lines."""
    w = weights if weights is not None else load_weights()
    agents = _agents(board, program)
    if not agents:
        return []
    run_agent = {a["run_id"]: no for no, a in agents.items() if a["run_id"] is not None}
    runs = {
        r["id"]: dict(r)
        for r in _rows(board, "SELECT id, started, ended, gate_denied FROM runs WHERE program=?", program)
        if r["id"] in run_agent
    }
    out: list[Entry] = []
    verified_cells: list[tuple[tuple[str | None, str | None], str | None, int, float | None]] = []
    credited_runs: dict[int, list[float]] = defaultdict(list)  # run_id -> times of its credited verified findings

    # -- findings: statuses only; the verdict and the proof are tested by SQLite, never read
    fcols = _cols(board, "findings")
    refused_sql = "(status='rejected' AND verdict LIKE 'excluded by program policy%')"
    if {"proof", "observation"} <= fcols:
        refused_sql += " OR (status IN ('new','verifying') AND proof IS NULL AND observation IS NULL)"
    best: dict[tuple, tuple[int, sqlite3.Row]] = {}  # (class, cell) -> (rank, finding): one credit per class and cell
    for f in _rows(
        board,
        f"SELECT id, run_id, status, vuln_class, url, created, COALESCE(updated, created) AS ts, "
        f"({refused_sql}) AS refused FROM findings WHERE program=? ORDER BY id",
        program,
    ):
        agent = run_agent.get(f["run_id"])
        cell = cell_of_url(f["url"])
        if f["status"] in VERIFIED:
            verified_cells.append((cell, f["vuln_class"], f["id"], f["ts"]))
        if agent is None:
            continue
        if f["refused"]:
            out.append(Entry(agent, "finding_refused", w["finding_refused"], "finding", f["id"], f["ts"]))
        elif f["status"] == "rejected":
            out.append(Entry(agent, "finding_rejected", w["finding_rejected"], "finding", f["id"], f["ts"]))
        elif f["status"] == "duplicate":
            out.append(Entry(agent, "finding_duplicate", w["finding_duplicate"], "finding", f["id"], f["ts"]))
        elif f["status"] in VERIFIED or f["status"] == "inconclusive":
            rank = 0 if f["status"] in VERIFIED else 1
            key = (f["vuln_class"] or "?", cell if cell[1] else ("F", str(f["id"])))
            if key not in best or rank < best[key][0]:
                best[key] = (rank, f)
    for rank, f in sorted(best.values(), key=lambda x: x[1]["id"]):
        signal = "finding_verified" if rank == 0 else "finding_inconclusive"
        out.append(Entry(run_agent[f["run_id"]], signal, w[signal], "finding", f["id"], f["ts"]))
        if rank == 0:
            credited_runs[f["run_id"]].append(f["created"])

    # -- memory items: labels, outcomes, cells, keys; never the item's text
    mcols = _cols(board, "mem_items")
    items: dict[int, dict] = {}
    if mcols:
        src = "src_kind" if "src_kind" in mcols else "NULL"
        cause = "cause" if "cause" in mcols else "outcome"
        for r in _rows(
            board,
            f"SELECT id, kind, ckey, cell, vuln_class, outcome, label, agent_no, created, {src} AS src_kind, "
            f"{cause} AS cause FROM mem_items WHERE program=? ORDER BY created, id",
            program,
        ):
            if r["src_kind"] == OPERATOR or r["agent_no"] is None or int(r["agent_no"]) <= 0:
                continue  # an operator's lead pays no one
            items[r["id"]] = dict(r) | {"agent_no": int(r["agent_no"]), "ncell": norm_cell(r["cell"])}
    taken: dict[tuple[int, str], int] = defaultdict(int)  # (agent, signal) -> occurrences counted
    first_dead: set[tuple] = set()
    contradicted: set[int] = set()
    for it in items.values():
        kind = _item_kind(it)
        if kind in ("ruled_out", "dead_end") and it["label"] in LEGACY_LABELS:
            hit = next(
                (
                    v
                    for v in verified_cells
                    if same_cell(it["ncell"], v[0])
                    and (not it["vuln_class"] or canonical(it["vuln_class"]) == canonical(v[1] or ""))
                ),
                None,
            )
            if hit is not None:
                contradicted.add(it["id"])
                out.append(
                    Entry(
                        it["agent_no"],
                        "legacy_contradicted",
                        w["legacy_contradicted"],
                        "mem_item",
                        it["id"],
                        it["created"],
                    )
                )
                continue
        if it["label"] != ANCHORED or kind is None:
            continue
        signal = f"{kind}_anchored"
        if kind == "dead_end":
            key = (it["ncell"] if it["ncell"][1] else it["ckey"], it["cause"], it["vuln_class"])
            if key in first_dead:
                continue
            first_dead.add(key)
        if taken[(it["agent_no"], signal)] >= CAPS[signal]:
            continue
        taken[(it["agent_no"], signal)] += 1
        out.append(Entry(it["agent_no"], signal, w[signal], "mem_item", it["id"], it["created"]))

    # -- receipts: a later agent read the item. Once per reader, CAPS per item; reading earns the reader nothing
    by_ckey: dict[str, list[dict]] = defaultdict(list)
    for it in items.values():
        if it["label"] in LEGACY_LABELS and it["ckey"] is not None and it["id"] not in contradicted:
            by_ckey[it["ckey"]].append(it)
    readers: dict[int, set[int]] = defaultdict(set)
    for r in _rows(board, "SELECT id, agent_no, ckey, ts FROM mem_receipts WHERE program=? ORDER BY ts, id", program):
        reader = int(r["agent_no"]) if r["agent_no"] is not None else 0
        if reader <= 0:
            continue
        it = next((i for i in by_ckey.get(r["ckey"], []) if i["agent_no"] < reader), None)
        if it is None or reader in readers[it["id"]] or len(readers[it["id"]]) >= CAPS["legacy_consulted"]:
            continue
        readers[it["id"]].add(reader)
        out.append(Entry(it["agent_no"], "legacy_consulted", w["legacy_consulted"], "mem_item", it["id"], r["ts"]))

    # -- basis: a fact of agent A cited by an intent of agent B, whose run then got a verified finding
    if "basis" in _cols(board, "intents"):
        fact_run = {r["id"]: r["run_id"] for r in _rows(board, "SELECT id, run_id FROM facts WHERE program=?", program)}
        paid: set[tuple[int, int]] = set()
        for i in _rows(
            board,
            "SELECT id, run_id, created, basis FROM intents WHERE program=? AND basis IS NOT NULL ORDER BY id",
            program,
        ):
            heir = run_agent.get(i["run_id"])
            done = [t for t in credited_runs.get(i["run_id"], []) if t is not None and t >= (i["created"] or 0)]
            if heir is None or not done:
                continue
            for fid in (int(x) for x in re.findall(r"\d{1,12}", str(i["basis"]))):
                author = run_agent.get(fact_run.get(fid))
                if author is None or author == heir or (fid, heir) in paid:
                    continue
                paid.add((fid, heir))
                out.append(Entry(author, "legacy_basis", w["legacy_basis"], "fact", fid, min(done)))

    # -- coverage: a new (endpoint, class) pair the gate saw tested, credited to its first run
    first_pair: dict[tuple, sqlite3.Row] = {}
    for r in _rows(
        board,
        "SELECT rowid AS rid, endpoint, vuln_class, run_id FROM coverage_class "
        "WHERE program=? AND gate_seen=1 AND run_id IS NOT NULL ORDER BY run_id, rowid",
        program,
    ):
        first_pair.setdefault((r["endpoint"], r["vuln_class"]), r)
    for r in first_pair.values():
        agent = run_agent.get(r["run_id"])
        if agent is None or taken[(agent, "pair_tested")] >= CAPS["pair_tested"]:
            continue
        taken[(agent, "pair_tested")] += 1
        ts = (runs.get(r["run_id"]) or {}).get("started")
        out.append(Entry(agent, "pair_tested", w["pair_tested"], "coverage_class", r["rid"], ts))

    # -- endpoints: new, in scope, first seen during the run, and seen by the gate (a sandbox claim alone earns nothing)
    spans = sorted((r["started"], r["ended"], rid) for rid, r in runs.items() if r["started"] is not None)
    for a in _rows(
        board,
        "SELECT a.id, a.first_seen FROM assets a WHERE a.program=? AND a.kind='endpoint' AND a.in_scope=1 "
        "AND EXISTS (SELECT 1 FROM tests t WHERE t.asset_id=a.id AND t.evidence IN ('gate','seen')) "
        "ORDER BY a.first_seen, a.id",
        program,
    ):
        rid = next((rid for s, e, rid in spans if s <= a["first_seen"] and (e is None or a["first_seen"] <= e)), None)
        agent = run_agent.get(rid)
        if agent is None or taken[(agent, "endpoint_new")] >= CAPS["endpoint_new"]:
            continue
        taken[(agent, "endpoint_new")] += 1
        out.append(Entry(agent, "endpoint_new", w["endpoint_new"], "asset", a["id"], a["first_seen"]))

    # -- per run: the handoff (its shape, tested by SQLite) and the gate's refusals after the first
    nl = "char(10)"
    shape = " AND ".join(
        [f"summary LIKE '{_HANDOFF_RUBRICS[0]}: _%'"]
        + [f"instr(summary, {nl}||'{k}: ')>0" for k in _HANDOFF_RUBRICS[1:]]
        + [f"instr(summary, {nl}||'{k}: '||{nl})=0" for k in _HANDOFF_RUBRICS[1:-1]]
        + [f"summary NOT LIKE '%'||{nl}||'{_HANDOFF_RUBRICS[-1]}: '"]
    )
    handoffs = {
        r["run_id"]: (r["complete"], r["fid"])
        for r in _rows(
            board,
            f"SELECT run_id, MAX(title NOT LIKE 'HANDOFF (runner)%' AND {shape}) AS complete, MAX(id) AS fid "
            "FROM facts WHERE program=? AND kind='handoff' GROUP BY run_id",
            program,
        )
    }
    for rid, agent in sorted(run_agent.items(), key=lambda x: x[1]):
        run = runs.get(rid)
        if run is None:
            continue
        if run["ended"] is not None:
            complete, fid = handoffs.get(rid, (None, None))
            if complete:
                out.append(Entry(agent, "handoff_complete", w["handoff_complete"], "fact", fid, run["ended"]))
            elif complete is None:  # a handoff that lacks a rubric is neither paid nor fined
                out.append(Entry(agent, "handoff_missing", w["handoff_missing"], "run", rid, run["ended"]))
        extra = min(max(0, int(run["gate_denied"] or 0) - 1), CAPS["gate_denied"])
        if extra:
            out.append(
                Entry(agent, "gate_denied", w["gate_denied"] * extra, "run", rid, run["ended"] or run["started"])
            )
    return out


def _item_kind(it: dict) -> str | None:
    if it["outcome"] == RULED_OUT:
        return "ruled_out"
    if it["kind"] in DEAD_END or it["outcome"] in DEAD_END:
        return "dead_end"
    if it["kind"] in CANDIDATE or it["outcome"] in CANDIDATE:
        return "candidate"
    return None


# ------------------------------------------------------------------ public API
def compute(board: Board, program: str, weights: dict[str, int] | None = None) -> int:
    """Rewrite the ledger rows of `program` from the board (idempotent: two calls leave the same ledger). Returns the
    number of rows written. Called by the runner when an agent closes."""
    ensure(board)
    rows = entries(board, program, weights)
    with board.db:
        board.db.execute("DELETE FROM ledger WHERE program=?", (program,))
        board.db.executemany(
            "INSERT INTO ledger(program, agent_no, signal, points, ref_kind, ref_id, ts) VALUES (?,?,?,?,?,?,?)",
            [(program, e.agent_no, e.signal, e.points, e.ref_kind, e.ref_id, e.ts) for e in rows],
        )
    return len(rows)


def honor_roll(board: Board, program: str) -> list[str]:
    """At most three lines about contributions, never agents' totals: the best verified contribution, the most
    reused dead end, and a verified finding the program then closed informative (findings.outcome, from W4). Built
    from keys only (class, cell, ids): no text of an agent crosses into another agent's prompt."""
    es = entries(board, program)
    lines: list[str] = []
    verified = [e for e in es if e.signal == "finding_verified"]
    if verified:
        e = min(verified, key=lambda x: (-x.points, x.ref_id))
        f = _rows(board, "SELECT vuln_class, url FROM findings WHERE id=?", e.ref_id)
        if f:
            lines.append(
                f"Verified finding F{e.ref_id}: {_safe(f[0]['vuln_class'], 40)} on {_shown(cell_of_url(f[0]['url']))}, "
                f"left by agent #{e.agent_no}."
            )
    dead = {e.ref_id for e in es if e.signal in ("dead_end_anchored", "ruled_out_anchored")}
    reads: dict[int, int] = defaultdict(int)  # anchored dead end -> later agents that read it
    for e in es:
        if e.signal == "legacy_consulted" and e.ref_id in dead:
            reads[e.ref_id] += 1
    if reads:
        iid = min(reads, key=lambda i: (-reads[i], i))
        it = _rows(board, "SELECT cell, vuln_class, outcome FROM mem_items WHERE id=?", iid)
        if it:
            what = "ruled-out lead" if it[0]["outcome"] == RULED_OUT else "dead end"
            lines.append(
                f"Most reused {what}: {_safe(it[0]['vuln_class'] or '?', 40)} on {_shown(norm_cell(it[0]['cell']))}, "
                f"read by {reads[iid]} later agent(s)."
            )
    if "outcome" in _cols(board, "findings"):
        inf = _rows(
            board,
            f"SELECT id, vuln_class, url FROM findings WHERE program=? AND outcome='informative' AND status IN "
            f"({','.join('?' * len(VERIFIED))}) ORDER BY id DESC LIMIT 1",
            program,
            *VERIFIED,
        )
        if inf:
            f = inf[0]
            lines.append(
                f"F{f['id']} {_safe(f['vuln_class'], 40)} on {_shown(cell_of_url(f['url']))}: verified by the harness, "
                "then closed informative by the program."
            )
    return lines[:3]


def summary(board: Board, program: str) -> dict:
    """The UI's view: ledger by signal and by agent (from the stored ledger, as the runner last computed it)."""
    if not _cols(board, "ledger"):
        return {"by_signal": [], "by_agent": {}}
    by_signal = [
        dict(r)
        for r in board.rows(
            "SELECT signal, COUNT(*) AS n, SUM(points) AS points FROM ledger WHERE program=? GROUP BY signal "
            "ORDER BY SUM(points) DESC, signal",
            program,
        )
    ]
    by_agent: dict[int, dict[str, int]] = defaultdict(dict)
    for r in board.rows(
        "SELECT agent_no, signal, SUM(points) AS points FROM ledger WHERE program=? GROUP BY agent_no, signal", program
    ):
        by_agent[r["agent_no"]][r["signal"]] = r["points"]
    return {"by_signal": by_signal, "by_agent": dict(by_agent)}
