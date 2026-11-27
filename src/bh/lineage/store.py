"""Memory of a program's lineage, kept in board.sqlite by the host.

  mem_items      one typed item per attempt, under its canonical key (bh.lineage.key)
  mem_fts        full-text index of title + summary (SQLite FTS5, porter stemming; LIKE when FTS5 is missing)
  mem_receipts   what a successor asked the memory, and what it got (written by recall, not here)
  agents         one row per session: the numbered agent, its parent, its birth
  blocks         the lineage's hash chain
  ledger         points of the lineage, by signal

Rules kept here:
- dated, then superseded: a fact that changes is closed (valid_to, superseded_by) and a new one is written; the old
  one stays readable. Only purge() removes rows from mem_items, for `bh board reset ... --with-lineage`.
- deduplicated at write time: the same key and the same normalized text is one row seen twice; the same key and a
  title with a word Jaccard index >= 0.8 merges into the oldest row. Any doubt (another kind, label, outcome or
  author): a new row.
- labels come from the host: OBSERVED (the gate saw it), JUDGED (the verifier's verdict), ANCHORED (a note citing an
  exact receipt the host checked), NOTE (the agent's word). Never from the agent's text.
- what is indexed went through bh.redact.text, and a canary is `<canary>`: no credential and no planted secret is
  resent to a successor. Raw tool output, target pages and the stream-json are never ingested.
- every query filters by program.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Any

from bh import paths, redact
from bh.agent import contract as c
from bh.board import Board
from bh.lineage import key
from bh.text import escape_invisible

SCHEMA = """
CREATE TABLE IF NOT EXISTS mem_items (
  id INTEGER PRIMARY KEY, program TEXT NOT NULL, kind TEXT NOT NULL, ckey TEXT NOT NULL, cell TEXT NOT NULL,
  host TEXT, route TEXT, vuln_class TEXT, technique TEXT, identities TEXT, outcome TEXT, label TEXT NOT NULL,
  title TEXT NOT NULL, summary TEXT, agent_no INTEGER, run_id INTEGER, src_kind TEXT, src_id TEXT,
  valid_from REAL NOT NULL, valid_to REAL, superseded_by INTEGER, seen INTEGER NOT NULL DEFAULT 1,
  text_hash TEXT NOT NULL, created REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS mem_items_key ON mem_items(program, ckey);
CREATE INDEX IF NOT EXISTS mem_items_cell ON mem_items(program, cell);
CREATE INDEX IF NOT EXISTS mem_items_src ON mem_items(program, src_kind, src_id);
CREATE TABLE IF NOT EXISTS mem_receipts (
  id INTEGER PRIMARY KEY, program TEXT NOT NULL, agent_no INTEGER, run_id INTEGER, query TEXT, ckey TEXT,
  verdict TEXT, hits TEXT, ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS mem_receipts_prog ON mem_receipts(program, agent_no);
CREATE TABLE IF NOT EXISTS agents (
  no INTEGER NOT NULL, pseudo TEXT, program TEXT NOT NULL, generation INTEGER, parent_no INTEGER, run_id INTEGER,
  setup_sha256 TEXT, birth_sha256 TEXT, relaunch_of INTEGER, born REAL, closed REAL, status TEXT,
  UNIQUE(program, no)
);
CREATE TABLE IF NOT EXISTS blocks (
  no INTEGER NOT NULL, program TEXT NOT NULL, prev_hash TEXT, block_hash TEXT NOT NULL, body TEXT, ts REAL NOT NULL,
  UNIQUE(program, no)
);
CREATE TABLE IF NOT EXISTS ledger (
  id INTEGER PRIMARY KEY, program TEXT NOT NULL, agent_no INTEGER, signal TEXT NOT NULL, points REAL,
  ref_kind TEXT, ref_id TEXT, ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ledger_prog ON ledger(program, agent_no);
"""
# The index, chosen once, when the table is created: FTS5 if this SQLite has it, else a plain table searched by LIKE.
FTS5_SQL = "CREATE VIRTUAL TABLE IF NOT EXISTS mem_fts USING fts5(title, summary, tokenize='porter unicode61')"
LIKE_SQL = "CREATE TABLE IF NOT EXISTS mem_fts (id INTEGER PRIMARY KEY, title TEXT, summary TEXT)"
TABLES = ("mem_items", "mem_fts", "mem_receipts", "agents", "blocks", "ledger")

KINDS = ("test", "dead-end", "candidate", "blocker", "think", "finding", "run-summary", "threat-model", "handoff")
OUTCOMES = ("confirmed", "ruled_out", "open_proof_gap")
LABELS = ("OBSERVED", "JUDGED", "ANCHORED", "NOTE")
OPERATOR = "operator"  # src_kind of an item the operator imported (agent 0): the ledger gives it no points
TITLE_MAX = 300
SUMMARY_MAX = 4000
JACCARD_MIN = 0.8
SUMMARY_LINES = 20  # run-summary
SUMMARY_LINE_MAX = 200

# A finding the verifier has closed, and the outcome it stands for. needs-proof (the hunter may send a better proof),
# new and verifying are not final: they wait.
FINAL_FINDINGS = {
    "verified": "confirmed",
    "verified-evidence": "confirmed",
    "submitted": "confirmed",
    "rejected": "ruled_out",
    "inconclusive": "open_proof_gap",
    "duplicate": None,
}
FACT_KINDS = ("dead-end", "candidate", "blocker", "think")

# Operator leads (bh memory import): why a lead was closed or is still open. Closed list.
WHY = (
    "not-vulnerable",
    "fixed",
    "by-design",
    "no-impact",
    "not-reproduced",
    "control-failed",
    "out-of-scope",
    "duplicate",
    "blocked",
    "rate-limited",
    "needs-identity",
    "needs-write",
    "untested",
    "partial",
    "other",
)
# the whys of a lead shown not to work: its outcome is ruled_out (the others leave the outcome open)
WHY_RULED_OUT = frozenset({"not-vulnerable", "fixed", "by-design", "no-impact", "not-reproduced", "control-failed"})
IMPORT_KINDS = ("dead-end", "candidate")
IMPORT_FIELDS = frozenset(
    {"kind", "method", "url", "class", "technique", "identities", "why", "title", "summary", "flow", "quote"}
)
IMPORT_LINE_MAX = 64 * 1024
QUOTE_MIN, QUOTE_MAX = 8, 1000  # a receipt shorter than this anchors nothing (any body holds "200 OK")
_METHOD = re.compile(r"[A-Za-z]{3,10}")
_IDENTITY = re.compile(r"[A-Za-z0-9_.@-]{1,64}")
_FLOW_ID = re.compile(r"[0-9A-Za-z-]{1,64}")  # the gate's flow ids (bh.ui.server reads them the same way)
_CANARY = re.compile(c.CANARY_RE.pattern, re.I)
_WORD = re.compile(r"\w+")

_FTS5: bool | None = None


# ------------------------------------------------------------------ schema
def fts5_available() -> bool:
    """Does this process's SQLite have FTS5 with the porter tokenizer? Probed once, on a scratch database."""
    global _FTS5
    if _FTS5 is None:
        con = sqlite3.connect(":memory:")
        try:
            con.execute("CREATE VIRTUAL TABLE probe USING fts5(x, tokenize='porter unicode61')")
            _FTS5 = True
        except sqlite3.Error:
            _FTS5 = False
        finally:
            con.close()
    return _FTS5


def ensure(board: Board) -> None:
    """Create the lineage tables (idempotent). None of them is in db.PROGRAM_TABLES: a plain reset keeps them."""
    board.db.executescript(SCHEMA)
    if not board.db.execute("SELECT 1 FROM sqlite_master WHERE name='mem_fts'").fetchone():
        board.db.executescript(FTS5_SQL if fts5_available() else LIKE_SQL)


def fts_mode(board: Board) -> str:
    """`fts5` or `like`: how this board's index was created."""
    row = board.db.execute("SELECT sql FROM sqlite_master WHERE name='mem_fts'").fetchone()
    return "fts5" if row and "fts5" in (row[0] or "").lower() else "like"


# ------------------------------------------------------------------ text
def clean(s: object, n: int, *, one_line: bool = False) -> str:
    """Text as the memory keeps and indexes it: bh.redact.text, every canary `<canary>`, invisible characters shown,
    whitespace collapsed (per line, or all of it for a title), cut at n characters. Redacted before the cut, so a cut
    never splits a secret out of reach of the patterns."""
    s = _CANARY.sub("<canary>", redact.text(str(s or "")))
    lines = escape_invisible(s).splitlines()
    s = " ".join(" ".join(lines).split()) if one_line else "\n".join(" ".join(ln.split()) for ln in lines).strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def normalize(s: str) -> str:
    """Lower case, whitespace collapsed: two texts that differ only there are the same text."""
    return " ".join(str(s or "").lower().split())


def text_hash(title: str, summary: str) -> str:
    return hashlib.sha256(f"{normalize(title)}\n{normalize(summary)}".encode()).hexdigest()


def jaccard(a: str, b: str) -> float:
    """Word Jaccard index of two titles; 0 when either has no word."""
    wa, wb = set(_WORD.findall(a.lower())), set(_WORD.findall(b.lower()))
    return len(wa & wb) / len(wa | wb) if wa and wb else 0.0


# ------------------------------------------------------------------ write
def _prepare(item: dict) -> dict[str, Any]:
    """A row of mem_items from an item, checked. The key is item["ckey"], or built from host, method, route,
    vuln_class, technique and identities. Raises ValueError on a bad item (a caller bug, not agent input)."""
    program = item.get("program")
    if not isinstance(program, str) or not program:
        raise ValueError("item without a program")
    kind, label, outcome = item.get("kind"), item.get("label"), item.get("outcome")
    if kind not in KINDS:
        raise ValueError(f"bad kind {kind!r}")
    if label not in LABELS:
        raise ValueError(f"bad label {label!r}")
    if outcome not in (*OUTCOMES, None):
        raise ValueError(f"bad outcome {outcome!r}")
    ckey = item.get("ckey") or key.canonical(
        str(item.get("host") or ""),
        str(item.get("method") or ""),
        str(item.get("route") or ""),
        str(item.get("vuln_class") or ""),
        str(item.get("technique") or ""),
        item.get("identities") or (),
    )
    ckey = str(ckey).lower()
    if ckey.count(key.SEP) != key.FIELDS - 1:
        raise ValueError(f"bad key {ckey!r}")
    title = clean(item.get("title"), TITLE_MAX, one_line=True)
    if not title:
        raise ValueError("item without a title")
    summary = clean(item.get("summary"), SUMMARY_MAX)
    f = key.split(ckey)
    return {
        "program": program,
        "kind": kind,
        "ckey": ckey,
        "cell": key.cell(ckey),
        "host": f["host"],
        "route": f["route"],
        "vuln_class": f["vuln_class"],
        "technique": f["technique"],
        "identities": f["identities"],
        "outcome": outcome,
        "label": label,
        "title": title,
        "summary": summary,
        "agent_no": item.get("agent_no"),
        "run_id": item.get("run_id"),
        "src_kind": item.get("src_kind"),
        "src_id": None if item.get("src_id") is None else str(item.get("src_id")),
        "text_hash": text_hash(title, summary),
    }


def _duplicate(board: Board, row: dict) -> int | None:
    """The current row this one merges into, or None. Same program, key, kind, label, outcome and authorship
    (operator or not): the same text, else the oldest with a title Jaccard >= JACCARD_MIN."""
    rows = board.db.execute(
        "SELECT id, title, text_hash FROM mem_items WHERE program=? AND ckey=? AND kind=? AND label=? "
        "AND outcome IS ? AND (COALESCE(src_kind, '')=?)=? AND valid_to IS NULL ORDER BY id",
        (
            row["program"],
            row["ckey"],
            row["kind"],
            row["label"],
            row["outcome"],
            OPERATOR,
            int(row["src_kind"] == OPERATOR),
        ),
    ).fetchall()
    same = next((r["id"] for r in rows if r["text_hash"] == row["text_hash"]), None)
    if same is not None:
        return int(same)
    near = next((r["id"] for r in rows if jaccard(r["title"], row["title"]) >= JACCARD_MIN), None)
    return None if near is None else int(near)


def _insert(board: Board, row: dict, now: float) -> int:
    cols = [*row, "valid_from", "seen", "created"]
    cur = board.db.execute(
        f"INSERT INTO mem_items({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
        (*row.values(), now, 1, now),
    )
    iid = int(cur.lastrowid)
    board.db.execute("INSERT INTO mem_fts(rowid, title, summary) VALUES (?,?,?)", (iid, row["title"], row["summary"]))
    return iid


def _put_row(board: Board, row: dict) -> int:
    if (dup := _duplicate(board, row)) is not None:
        board.db.execute("UPDATE mem_items SET seen=seen+1 WHERE id=?", (dup,))
        return dup
    return _insert(board, row, time.time())


def put(board: Board, item: dict) -> int:
    """Write one item (deduplicated, see the module docstring); returns the id of the row that holds it."""
    ensure(board)
    iid = _put_row(board, _prepare(item))
    board.db.commit()
    return iid


def _supersede_row(board: Board, old_id: int, row: dict) -> int:
    old = board.db.execute("SELECT program, valid_to FROM mem_items WHERE id=?", (old_id,)).fetchone()
    if old is None or old["program"] != row["program"]:
        raise ValueError(f"no item {old_id} in program {row['program']!r}")
    if old["valid_to"] is not None:
        raise ValueError(f"item {old_id} is already superseded")
    now = time.time()
    nid = _insert(board, row, now)
    board.db.execute("UPDATE mem_items SET valid_to=?, superseded_by=? WHERE id=?", (now, nid, old_id))
    return nid


def supersede(board: Board, old_id: int, new_item: dict) -> int:
    """Close item old_id (valid_to = now, superseded_by = the new id) and write new_item, valid from now. The old row
    stays. new_item must be of the same program; it is not deduplicated (it replaces, it is not seen again)."""
    ensure(board)
    nid = _supersede_row(board, old_id, _prepare(new_item))
    board.db.commit()
    return nid


def purge(board: Board, program: str) -> dict[str, int]:
    """Forget a program's lineage: its rows in every lineage table. Only `bh board reset ... --with-lineage` calls
    this; nothing else deletes from mem_items."""
    ensure(board)
    ids = "SELECT id FROM mem_items WHERE program=?"
    id_col = "rowid" if fts_mode(board) == "fts5" else "id"
    out = {"mem_fts": board.db.execute(f"DELETE FROM mem_fts WHERE {id_col} IN ({ids})", (program,)).rowcount}
    out["mem_items"] = board.db.execute("DELETE FROM mem_items WHERE program=?", (program,)).rowcount
    for t in ("mem_receipts", "agents", "blocks", "ledger"):
        out[t] = board.db.execute(f"DELETE FROM {t} WHERE program=?", (program,)).rowcount
    # the cursors of ingest_run and import_items: a purged program is ingested and imported afresh
    board.db.execute(
        "DELETE FROM meta WHERE k LIKE 'lineage-%' AND substr(k, -length(?) - 1) = ':' || ?", (program, program)
    )
    board.db.commit()
    return out


# ------------------------------------------------------------------ read
def search(board: Board, program: str, query: str, limit: int = 20, *, current: bool = True) -> list[dict]:
    """Items of `program` whose title or summary matches words of `query`, best first. FTS5 (bm25, porter stems, any
    word) when the board has it, else LIKE (most words matched first). `current`: superseded items left out."""
    ensure(board)
    words = list(dict.fromkeys(_WORD.findall(clean(query, 2000, one_line=True).lower())))[:32]
    if not words:
        return []
    live = " AND m.valid_to IS NULL" if current else ""
    if fts_mode(board) == "fts5":
        match = " OR ".join(f'"{w}"' for w in words)
        rows = board.db.execute(
            f"SELECT m.* FROM mem_fts f JOIN mem_items m ON m.id=f.rowid WHERE mem_fts MATCH ? AND m.program=?{live} "
            "ORDER BY bm25(mem_fts), m.id LIMIT ?",
            (match, program, limit),
        )
    else:
        hit = "(lower(f.title || ' ' || COALESCE(f.summary, '')) LIKE ? ESCAPE '\\')"
        score = " + ".join([hit] * len(words))
        likes = ["%" + w.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%" for w in words]
        rows = board.db.execute(
            f"SELECT * FROM (SELECT m.*, ({score}) AS score FROM mem_fts f JOIN mem_items m ON m.id=f.id "
            f"WHERE m.program=?{live}) WHERE score > 0 ORDER BY score DESC, id LIMIT ?",
            (*likes, program, limit),
        )
    out = [dict(r) for r in rows]
    for r in out:
        r.pop("score", None)  # the LIKE ranking, not a column of mem_items
    return out


def items(board: Board, program: str, *, current: bool = False) -> list[dict]:
    """Every item of a program, by key then date (the export's order)."""
    ensure(board)
    live = " AND valid_to IS NULL" if current else ""
    return [
        dict(r)
        for r in board.db.execute(
            f"SELECT * FROM mem_items WHERE program=?{live} ORDER BY ckey, valid_from, id", (program,)
        )
    ]


# ------------------------------------------------------------------ ingestion of a run
def _columns(board: Board, table: str) -> set[str]:
    return {r[1] for r in board.db.execute(f"PRAGMA table_info({table})")}


def _read(board: Board, table: str, cols: tuple[str, ...], where: str, *args: Any, need: tuple = ()) -> list[dict]:
    """Rows of `table` with `cols`; a column the board does not have (yet) reads as NULL. A missing table, or a
    missing column of `need` (those `where` filters on), reads as no rows."""
    have = _columns(board, table)
    if not have or not set(need) <= have:
        return []
    sel = ", ".join(col if col in have else f"NULL AS {col}" for col in cols)
    return [dict(r) for r in board.db.execute(f"SELECT rowid AS _rowid, {sel} FROM {table} WHERE {where}", args)]


def _endpoint(value: object) -> tuple[str, str, str]:
    """(host, method, path) of an endpoint as the board writes it: `https://h:443 GET /p` (an asset key),
    `GET https://h/p`, `https://h/p` or `GET /p`. Unknown parts are empty."""
    parts = str(value or "").split()
    if len(parts) >= 3 and "://" in parts[0] and _METHOD.fullmatch(parts[1]):
        return parts[0], parts[1], parts[2]
    if len(parts) >= 2 and _METHOD.fullmatch(parts[0]):
        return (parts[1] if "://" in parts[1] else ""), parts[0], parts[1]
    if len(parts) == 1:
        return (parts[0], "", parts[0]) if "://" in parts[0] else ("", "", parts[0])
    return "", "", ""


def _route_hosts(board: Board, program: str) -> dict[str, set[str]]:
    """route (key.split(...)["route"]) -> the hosts the program's asset graph holds it on."""
    out: dict[str, set[str]] = {}
    if not _columns(board, "assets"):
        return out
    for r in board.db.execute("SELECT key FROM assets WHERE program=? AND kind='endpoint'", (program,)).fetchall():
        h, m, p = _endpoint(r["key"])
        if h:
            out.setdefault(key.split(key.canonical("", m, p, ""))["route"], set()).add(h)
    return out


def _host_for(hosts: dict[str, set[str]], h: str, m: str, p: str) -> str:
    """`h`, or when a note named a route without its host (`bh-note cover "GET /p"`), the one host the asset graph
    holds that route on: otherwise the same endpoint splits into two cells and a settled one reads open (lab, agent
    #0004 against #0003, 2026-11-27). Several hosts, or none: left empty."""
    if h or not (m or p):
        return h
    found = hosts.get(key.split(key.canonical("", m, p, ""))["route"], set())
    return next(iter(found)) if len(found) == 1 else h


def _identities(value: object) -> list[str]:
    """A JSON list or a comma-separated string, as the board may hold them."""
    if isinstance(value, str) and value.strip().startswith("["):
        try:
            value = json.loads(value)
        except ValueError:
            return []
    if isinstance(value, str):
        return [v for v in value.split(",") if v.strip()]
    return [v for v in value or () if isinstance(v, str)] if isinstance(value, list) else []


def _flag(value: object) -> bool:
    """A 0/1 column of the board: 1 only (an integer, or the text '1'); anything else, NULL included, is 0."""
    return str(value).strip() == "1"


def _outcome(value: object) -> str | None:
    v = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    return v if v in OUTCOMES else None


def _first_paragraph(text: object, n: int = 800) -> str:
    paras = [p.strip() for p in re.split(r"\n\s*\n", str(text or "")) if p.strip()]
    return paras[0][:n] if paras else ""


def _proof_steps(proof: object) -> list[dict]:
    try:
        data = json.loads(proof) if isinstance(proof, str) else proof
    except ValueError:
        return []
    steps = data.get("steps") if isinstance(data, dict) else None
    return [s for s in steps if isinstance(s, dict)] if isinstance(steps, list) else []


def _gate_seen(board: Board, program: str, run_id: int) -> set[str]:
    """Endpoints (key.endpoint) whose coverage the gate saw in this run (coverage_class.gate_seen = 1)."""
    out = set()
    hosts = _route_hosts(board, program)
    for r in _read(
        board,
        "coverage_class",
        ("endpoint",),
        "program=? AND run_id=? AND CAST(gate_seen AS INTEGER)=1",
        program,
        run_id,
        need=("program", "run_id", "gate_seen", "endpoint"),
    ):
        h, m, p = _endpoint(r["endpoint"])
        out.add(key.endpoint(key.canonical(_host_for(hosts, h, m, p), m, p, "")))
    return out


def _run_items(board: Board, program: str, run_id: int, agent_no: int) -> list[dict]:
    """The items of one run, from the board's tables (never from raw output, a target page or the stream)."""
    base = {"program": program, "run_id": run_id, "agent_no": agent_no}
    out: list[dict] = []
    hosts = _route_hosts(board, program)
    # hand-made requests the gate saw (bh.assets tests, evidence 'gate'): what was tested, by whom the gate says
    tested = (
        board.db.execute(
            "SELECT DISTINCT a.id, a.key FROM tests t JOIN assets a ON a.id=t.asset_id "
            "WHERE a.program=? AND a.kind='endpoint' AND t.run_id=? AND t.evidence='gate' ORDER BY a.id",
            (program, run_id),
        ).fetchall()
        if _columns(board, "tests") and _columns(board, "assets")
        else []
    )
    for r in tested:
        h, m, p = _endpoint(r["key"])
        ck = key.canonical(h, m, p, "")
        route = key.split(ck)["route"]
        out.append(
            base
            | {
                "kind": "test",
                "label": "OBSERVED",
                "ckey": ck,
                "src_kind": "test",
                "src_id": r["id"],
                "title": f"{route} tested by hand (seen by the gate)",
                "summary": "",
            }
        )
    # coverage by class (lot A): OBSERVED only where the gate saw the endpoint in this run
    for r in _read(
        board,
        "coverage_class",
        ("endpoint", "vuln_class", "outcome", "evidence", "gate_seen"),
        "program=? AND run_id=?",
        program,
        run_id,
        need=("program", "run_id"),
    ):
        h, m, p = _endpoint(r["endpoint"])
        ck = key.canonical(_host_for(hosts, h, m, p), m, p, str(r["vuln_class"] or ""))
        f, outcome = key.split(ck), _outcome(r["outcome"])
        out.append(
            base
            | {
                "kind": "test",
                "label": "OBSERVED" if _flag(r["gate_seen"]) else "NOTE",
                "ckey": ck,
                "outcome": outcome,
                "src_kind": "coverage",
                "src_id": r["_rowid"],
                "title": f"{f['vuln_class'] or 'tested'} on {f['route'] or f['host']}: {outcome or 'tested'}",
                "summary": str(r["evidence"] or "")[:1000],
            }
        )
    # findings the verifier closed, with the paragraph of its verdict
    for r in _read(
        board,
        "findings",
        ("id", "title", "severity", "vuln_class", "url", "status", "verdict", "proof"),
        "program=? AND run_id=? ORDER BY id",
        program,
        run_id,
    ):
        if r["status"] not in FINAL_FINDINGS:
            continue
        steps = _proof_steps(r["proof"])
        attack = next((s for s in steps if s.get("role") == "attack"), {})
        url = str(r["url"] or attack.get("url") or "")
        method = str(attack.get("method") or ("GET" if attack else ""))
        who = sorted({str(s["as"]) for s in steps if isinstance(s.get("as"), str) and s["as"]})
        h, _, _ = _endpoint(url)
        out.append(
            base
            | {
                "kind": "finding",
                "label": "JUDGED",
                "outcome": FINAL_FINDINGS[r["status"]],
                "ckey": key.canonical(h, method, url if "://" in url else "", str(r["vuln_class"] or ""), "", who),
                "src_kind": "finding",
                "src_id": r["id"],
                "title": r["title"],
                "summary": f"[{r['status']}/{r['severity'] or '?'}] {_first_paragraph(r['verdict'])}".strip(),
            }
        )
    # the agent's own notes: ANCHORED when it cited a receipt (grounded) on an endpoint the gate saw in this run
    seen = _gate_seen(board, program, run_id)
    for r in _read(
        board,
        "facts",
        (
            "id",
            "kind",
            "title",
            "summary",
            "evidence",
            "grounded",
            "why",
            "endpoint",
            "vuln_class",
            "outcome",
            "technique",
            "identities",
        ),
        f"program=? AND run_id=? AND kind IN ({', '.join('?' * len(FACT_KINDS))}) ORDER BY id",
        program,
        run_id,
        *FACT_KINDS,
    ):
        h, m, p = _endpoint(r["endpoint"])
        if not h and r["kind"] == "blocker" and str(r["evidence"] or "").startswith("host:"):
            h = str(r["evidence"])[5:]
        h = _host_for(hosts, h, m, p)
        ck = key.canonical(h, m, p, str(r["vuln_class"] or ""), str(r["technique"] or ""), _identities(r["identities"]))
        anchored = _flag(r["grounded"]) and bool(m or p) and key.endpoint(ck) in seen
        why = f"why: {r['why']}\n" if r["why"] else ""
        out.append(
            base
            | {
                "kind": r["kind"],
                "label": "ANCHORED" if anchored else "NOTE",
                "ckey": ck,
                "outcome": _outcome(r["outcome"]),
                "src_kind": "fact",
                "src_id": r["id"],
                "title": r["title"],
                "summary": why + str(r["summary"] or ""),
            }
        )
    return out


def _summary(board: Board, program: str, run: dict, agent_no: int) -> dict:
    """The run-summary item: a skeleton in figures from the board (runs, findings, coverage, blockers), then the
    rubrics of the run's last handoff, marked [NOTE] (the agent's word). At most SUMMARY_LINES lines."""
    rid = run["id"]
    n = {k: run.get(k) or 0 for k in ("turns", "gate_requests", "gate_denied", "gate_errors", "gate_pushback")}
    lines = [
        f"run {rid} · agent {agent_no} · {run.get('status') or '?'} · {n['turns']} turns · "
        f"${float(run.get('cost_usd') or 0):.2f}",
        f"gate: {n['gate_requests']} requests, {n['gate_denied']} denied, {n['gate_errors']} errors, "
        f"{n['gate_pushback']} pushed back",
    ]
    by_status = board.db.execute(
        "SELECT status, COUNT(*) FROM findings WHERE program=? AND run_id=? GROUP BY status ORDER BY status",
        (program, rid),
    ).fetchall()
    lines.append("findings: " + (", ".join(f"{s} {k}" for s, k in by_status) or "none"))
    cov = _read(
        board,
        "coverage_class",
        ("vuln_class", "outcome", "gate_seen"),
        "program=? AND run_id=?",
        program,
        rid,
        need=("program", "run_id"),
    )
    classes: dict[str, list[int]] = {}
    for r in cov:
        k = classes.setdefault(key.norm_class(str(r["vuln_class"] or "")) or "?", [0, 0])
        k[0] += 1
        k[1] += _flag(r["gate_seen"])
    cov_line = ", ".join(f"{cl} {t} (gate-seen {s})" for cl, (t, s) in sorted(classes.items())[:8])
    lines.append("coverage: " + (cov_line + (f", +{len(classes) - 8} classes" if len(classes) > 8 else "") or "none"))
    reasons: dict[str, int] = {}
    for (title,) in board.db.execute(
        "SELECT title FROM facts WHERE program=? AND run_id=? AND kind='blocker'", (program, rid)
    ):
        m = re.match(r"\[([a-z-]+)\]", title or "")
        reasons[m.group(1) if m else "other"] = reasons.get(m.group(1) if m else "other", 0) + 1
    total = sum(reasons.values())
    lines.append(
        f"blockers: {total}" + (f" ({', '.join(f'{r} {k}' for r, k in sorted(reasons.items()))})" if total else "")
    )
    handoff = board.db.execute(
        "SELECT summary FROM facts WHERE program=? AND run_id=? AND kind='handoff' ORDER BY id DESC LIMIT 1",
        (program, rid),
    ).fetchone()
    if handoff:
        lines += [f"[NOTE] {ln.strip()}" for ln in str(handoff[0] or "").splitlines() if ln.strip()]
    lines = [ln if len(ln) <= SUMMARY_LINE_MAX else ln[: SUMMARY_LINE_MAX - 1] + "…" for ln in lines]
    return {
        "program": program,
        "kind": "run-summary",
        "label": "NOTE",
        "ckey": key.canonical("", "", "", "", f"run-{rid}"),
        "title": f"run {rid} (agent {agent_no}): {run.get('status') or '?'}",
        "summary": "\n".join(lines[:SUMMARY_LINES]),
        "agent_no": agent_no,
        "run_id": rid,
        "src_kind": "run",
        "src_id": rid,
    }


def backfill(board: Board, program: str, *, before: int | None = None) -> int:
    """Pour into memory the runs of `program` that ran before the lineage (no agent owns them), as agent #0, and date
    each item at its run's end, not today: what an agent finds by `bh-recall` on a program already worked must not
    start from nothing, and an old blocker must age like one. Idempotent (ingest_run is). Returns items written."""
    ensure(board)
    owned = (
        {int(r[0]) for r in board.db.execute("SELECT run_id FROM agents WHERE program=?", (program,))}
        if _has(board, "agents")
        else set()
    )
    sql = "SELECT id, COALESCE(ended, started) AS t FROM runs WHERE program=?" + (" AND id<?" if before else "")
    runs = board.db.execute(sql + " ORDER BY id", (program, before) if before else (program,)).fetchall()
    n = 0
    for rid, t in runs:
        if int(rid) in owned:
            continue
        n += ingest_run(board, program, int(rid), 0)
        if t:
            board.db.execute(
                "UPDATE mem_items SET valid_from=?, created=? WHERE program=? AND run_id=? AND agent_no=0",
                (float(t), float(t), program, int(rid)),
            )
    board.db.commit()
    return n


def _has(board: Board, table: str) -> bool:
    return (
        board.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None
    )


def ingest_run(board: Board, program: str, run_id: int, agent_no: int) -> int:
    """Write the memory items of one run of `program` (see _run_items, _summary). Returns the items written or
    merged. Idempotent: a source already ingested with the same text is skipped; one whose text changed (a finding
    the verifier closed later, a longer summary) supersedes its earlier item."""
    ensure(board)
    runs = _read(
        board,
        "runs",
        ("id", "status", "turns", "cost_usd", "gate_requests", "gate_denied", "gate_errors", "gate_pushback"),
        "id=? AND program=?",
        run_id,
        program,
    )
    if not runs:
        return 0  # not a run of this program
    done_key = f"lineage-ingested:{run_id}:{program}"  # reset_program forgets it with the program's other cursors
    try:
        done = json.loads(board.meta_get(done_key, "{}"))
    except ValueError:
        done = {}
    n = 0
    for item in [*_run_items(board, program, run_id, agent_no), _summary(board, program, runs[0], agent_no)]:
        row = _prepare(item)
        src = f"{row['src_kind']}:{row['src_id']}"
        # the cell is part of what was ingested: a source whose cell changed (a host filled in) supersedes its item
        print_ = f"{row['ckey']}|{row['text_hash']}"
        if done.get(src) == print_:
            continue
        prior = board.db.execute(
            "SELECT id FROM mem_items WHERE program=? AND src_kind=? AND src_id=? AND run_id=? AND valid_to IS NULL "
            "ORDER BY id DESC LIMIT 1",
            (program, row["src_kind"], row["src_id"], run_id),
        ).fetchone()
        if src in done and prior:
            _supersede_row(board, int(prior["id"]), row)
        else:
            _put_row(board, row)
        done[src] = print_
        n += 1
    board.db.commit()
    board.meta_set(done_key, json.dumps(done, sort_keys=True))
    return n


# ------------------------------------------------------------------ operator leads (bh memory import)
def _str(v: object, lo: int, hi: int) -> bool:
    return isinstance(v, str) and lo <= len(v) <= hi


def _valid_lead(d: object) -> bool:
    """One line of the operator's file, every field typed and bounded, closed lists checked."""
    if not isinstance(d, dict) or not set(d) <= IMPORT_FIELDS:
        return False
    if not IMPORT_FIELDS - {"flow", "quote"} <= set(d):
        return False
    ids = d["identities"]
    return (
        d["kind"] in IMPORT_KINDS
        and d["why"] in WHY
        and _str(d["method"], 3, 10)
        and bool(_METHOD.fullmatch(d["method"]))
        and _str(d["url"], 8, 2000)
        and c.origin(d["url"]) is not None
        and _str(d["class"], 1, 80)
        and _str(d["technique"], 0, 120)
        and isinstance(ids, list)
        and len(ids) <= 10
        and all(isinstance(i, str) and _IDENTITY.fullmatch(i) for i in ids)
        and _str(d["title"], 1, TITLE_MAX)
        and _str(d["summary"], 0, SUMMARY_MAX)
        and (d.get("flow") is None or (isinstance(d["flow"], str) and bool(_FLOW_ID.fullmatch(d["flow"]))))
        and (d.get("quote") is None or _str(d["quote"], 1, QUOTE_MAX))
    )


def quote_in_flow(program: str, flow: str | None, quote: str | None) -> bool:
    """Is `quote` an exact substring of the body the gate kept for `flow`, a target exchange of `program`? Both sides
    go through bh.redact.text first (the flow file is already redacted by the gate). A short quote anchors nothing."""
    if not flow or not quote or not _FLOW_ID.fullmatch(flow) or len(quote.strip()) < QUOTE_MIN:
        return False
    try:
        rec = json.loads(paths.flow_file(flow).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(rec, dict) or rec.get("program") != program or rec.get("class") != "target":
        return False
    body = (rec.get("response") or {}).get("body") if isinstance(rec.get("response"), dict) else None
    return isinstance(body, str) and redact.text(quote) in redact.text(body)


def import_items(board: Board, program: str, path: str | Path) -> tuple[int, int]:
    """Import the operator's leads (JSONL, one per line: kind, method, url, class, technique, identities, why, title,
    summary, flow?, quote?). Returns (imported, skipped): a malformed line is skipped and counted, so is a line this
    program already imported. Agent 0, src_kind `operator`; label ANCHORED only when `quote` is in the gate's body
    of `flow` (quote_in_flow), else NOTE; never OBSERVED or JUDGED. Same key, deduplication and redaction as put."""
    ensure(board)
    imported = skipped = 0
    done_key = f"lineage-import:{program}"  # lines already imported, merged rows included (their src_id is another)
    try:
        done = set(json.loads(board.meta_get(done_key, "[]")))
    except (TypeError, ValueError):
        done = set()
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                d = json.loads(line) if len(line) <= IMPORT_LINE_MAX else None
            except ValueError:
                d = None
            if not _valid_lead(d):
                skipped += 1
                continue
            src_id = hashlib.sha256(json.dumps(d, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:24]
            if src_id in done:
                skipped += 1
                continue
            row = _prepare(
                {
                    "program": program,
                    "kind": d["kind"],
                    "label": "ANCHORED" if quote_in_flow(program, d.get("flow"), d.get("quote")) else "NOTE",
                    "outcome": "ruled_out" if d["kind"] == "dead-end" and d["why"] in WHY_RULED_OUT else None,
                    "ckey": key.canonical(d["url"], d["method"], d["url"], d["class"], d["technique"], d["identities"]),
                    "title": d["title"],
                    "summary": f"why: {d['why']}\n{d['summary']}",
                    "agent_no": 0,
                    "run_id": None,
                    "src_kind": OPERATOR,
                    "src_id": src_id,
                }
            )
            _put_row(board, row)
            done.add(src_id)
            imported += 1
    board.db.commit()
    board.meta_set(done_key, json.dumps(sorted(done)))
    return imported, skipped
