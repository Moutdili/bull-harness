"""Recall (D4, D13, D16): what the lineage already knows, asked by an agent before it tests.

Host side only. The sandbox never reads board.sqlite: it drops a request file, bh.lineage.serve answers it with the
text this module renders. Every answer is bounded by the code, not by the model: LINES_MAX lines and BUDGET_TOKENS
tokens (estimated at CHARS_PER_TOKEN characters per token), `full` alone may run to FULL_LINES lines.

search(): (1) the exact cell when the agent gives a URL and a class, (2) and in any case the FTS_TOP best full-text
hits (FTS5, or LIKE when the store built its index without it), current items of this program only, (3) one line per
cell with its item count and its strongest item (JUDGED, OBSERVED, ANCHORED, NOTE, then the most recent), (4) a header
and a verdict computed here, outside the data tag, and the predecessors' text inside `<lineage-data-NONCE>`, a nonce
drawn per answer: what a predecessor wrote is data shown to its successor, never an instruction to it.

The host decides nothing but the exact cell: on full-text hits the verdict is CANDIDATES and the model judges whether
one is its idea. A recall informs, it never refuses a test and never widens the scope. It fails open: any error is
UNAVAILABLE, and the agent tests anyway.

Each search writes a receipt (mem_receipts, `R-<8 hex>` kept in its `hits` JSON); mark_intents() then checks the
receipts the run's intents cite (intents.verified) and counts the recalls that missed an older item (mem_misses).
"""

from __future__ import annotations

import json
import re
import secrets
import sqlite3
import time
from typing import Any

from bh import classes
from bh.agent import contract as c
from bh.text import escape_invisible

SEP = "|"
LINES_MAX = 12
SERIAL_AFTER = 30  # searches of one run beyond which an answer shrinks to SERIAL_LINES
SERIAL_LINES = 6
FULL_LINES = 40
FULL_TOKENS = 1000  # `full` is the one long answer: 40 lines of up to LINE_MAX characters would be 2000 tokens
CHARS_PER_TOKEN = 4
BUDGET_TOKENS = 400
FTS_TOP = 20
K_MAX = 20
QUERY_MAX = 500
LINE_MAX = 200
CHAIN_DEFAULT, CHAIN_MAX = 5, 8
DAY = 86400.0
# strongest first: the verifier's verdict, what the gate saw, a note anchored on a receipt, the agent's word
LABEL_ORDER = ("JUDGED", "OBSERVED", "ANCHORED", "NOTE")
# How long a settled item holds, by type (`dead-end:<why>` for a dead end's cause). A type absent here never goes stale.
STALE_TTL_S: dict[str, float] = {
    "blocker": float(c.BLOCKER_TTL_S),
    "dead-end:environment": 30 * DAY,
    "dead-end:external": 30 * DAY,
}
VERDICTS = ("EXACT-SETTLED", "EXACT-OPEN", "STALE", "CANDIDATES", "NEW", "UNAVAILABLE")
MODES = ("map", "cell", "run", "chain", "full", "history", "techniques")
# T18: the technique cards (bh.lineage.techniques), the only partition a program reads that is not its own
TECHNIQUES = "*techniques*"
TECHNIQUE_LINES = 8
UNAVAILABLE_LINE = "recall UNAVAILABLE (test anyway; pass --recall none)"
RECEIPT_RE = re.compile(r"R-[0-9a-f]{8}")
# Host-written sentences, one per verdict. They inform: none of them forbids a test.
VERDICT_LINE = {
    "EXACT-SETTLED": "verdict EXACT-SETTLED: a predecessor settled this cell. Read it (--cell) before retesting; "
    "a new technique is your call.",
    "EXACT-OPEN": "verdict EXACT-OPEN: this cell is open (candidate or proof gap). Continue it rather than restart.",
    "STALE": "verdict STALE: settled once, but older than its lifetime. A retest is fair.",
    "CANDIDATES": "verdict CANDIDATES: no exact cell; you judge whether one is your idea.",
    "NEW": "verdict NEW: nothing on record for this idea. Test it.",
}

MISSES_SQL = """
CREATE TABLE IF NOT EXISTS mem_misses (
  id INTEGER PRIMARY KEY, program TEXT NOT NULL, run_id INTEGER, receipt TEXT NOT NULL, cell TEXT, item_id INTEGER,
  ts REAL NOT NULL, found REAL NOT NULL, UNIQUE(program, receipt)
);
CREATE INDEX IF NOT EXISTS mem_misses_run ON mem_misses(program, run_id);
"""

_METHOD_URL = re.compile(r"([A-Za-z]{3,10})\s+(\S+)")
_WORD = re.compile(r"\w+")
_TAG = re.compile(r"<\s*/?\s*lineage-data", re.I)
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_DEFAULT_PORT = {"http": "80", "https": "443"}


class Unavailable(Exception):
    """The memory cannot answer (tables missing, unreadable board)."""


# ------------------------------------------------------------------ helpers
def _db(board: Any) -> sqlite3.Connection:
    """A Board, or any object with a `.db` connection (bh.lineage.serve opens its own)."""
    return board.db if hasattr(board, "db") else board


def _rows(db: sqlite3.Connection, sql: str, *args: Any) -> list[dict]:
    cur = db.execute(sql, args)
    names = [d[0] for d in cur.description or ()]
    return [dict(zip(names, tuple(r), strict=True)) for r in cur.fetchall()]


def _columns(db: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in db.execute(f"PRAGMA table_info({table})")}


def _need(db: sqlite3.Connection, *tables: str) -> None:
    for t in tables:
        if not _columns(db, t):
            raise Unavailable(t)


def _field(value: object) -> str:
    """One field of a key, as bh.lineage.key writes it: lower case, whitespace collapsed, `|` and `,` replaced."""
    return " ".join(str(value or "").replace(SEP, "/").replace(",", " ").split()).lower()


def norm_class(value: object) -> str:
    return _field(classes.canonical(str(value))) if _field(value) else ""


def cell_of(url: str | None, vuln_class: str | None) -> str | None:
    """`host|method family|class` of a URL (`METHOD URL` accepted, GET otherwise) and a class, or None.

    Local stand-in for bh.lineage.key (cell of canonical(...)), same rule: default port dropped, ids collapsed by
    contract.endpoint_key and family, lower case, class through bh.classes.canonical."""
    if not url or not vuln_class:
        return None
    s, method = str(url).strip(), "GET"
    if m := _METHOD_URL.fullmatch(s):
        method, s = m.group(1), m.group(2)
    k = c.endpoint_key(s, method)
    cls = norm_class(vuln_class)
    if k is None or not cls:
        return None
    scheme, _, hostport = k[0].partition("://")
    host, _, port = hostport.rpartition(":")
    host = host.rstrip(".")
    hostport = host if port == _DEFAULT_PORT.get(scheme) else f"{host}:{port}"
    return SEP.join((_field(hostport), _field(c.family(k[1])), cls))


def cell_of_key(key: str) -> str:
    """The cell (first three fields) of a key or of a cell the agent copied."""
    return SEP.join(_field(p) for p in str(key).strip().split(SEP)[:3])


def _clean(value: object, n: int = LINE_MAX) -> str:
    """Predecessor text on one line: invisible characters shown, controls dropped, the data tag defused, cut at n."""
    s = _TAG.sub("‹lineage-data", _CTRL.sub(" ", escape_invisible(str(value or ""))))
    s = " ".join(s.split())
    return s if len(s) <= n else s[: max(n - 1, 0)] + "…"


def _tokens(text: str) -> int:
    return -(-len(text) // CHARS_PER_TOKEN)


def _date(ts: object) -> str:
    try:
        return time.strftime("%Y-%m-%d", time.gmtime(float(ts)))  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return "?"


def _agent(no: object) -> str:
    return f"A{no}" if isinstance(no, int) else "A?"


def _nonce() -> str:
    return secrets.token_hex(6)


def _frame(
    head: list[str],
    data: list[tuple[str, str]],
    tail: list[str],
    *,
    max_lines: int = LINES_MAX,
    budget: int = BUDGET_TOKENS,
) -> str:
    """Header, the data lines inside a fresh nonce tag, tail. Each data line is (fixed part, cut part): the cut parts
    shrink first (longest first), then the last lines go, until the text holds in `max_lines` and `budget` tokens."""
    nonce = _nonce()
    room = max_lines - len(head) - len(tail) - 2
    rows = [list(d) for d in data[: max(room, 0)]]
    while True:
        lines = list(head)
        if rows:
            lines += [f"<lineage-data-{nonce}>", *(a + b for a, b in rows), f"</lineage-data-{nonce}>"]
        text = "\n".join([*lines, *tail])
        over = len(text) - budget * CHARS_PER_TOKEN
        if over <= 0 or not rows:
            return text
        i = max(range(len(rows)), key=lambda j: len(rows[j][1]))
        cut = rows[i][1]
        if len(cut) > 24:
            keep = max(len(cut) - over - 1, 23)
            rows[i][1] = cut[:keep] + "…"
        else:
            rows.pop()


# ------------------------------------------------------------------ item classification
def _rank(item: dict) -> tuple:
    label = item.get("label")
    lab = LABEL_ORDER.index(label) if label in LABEL_ORDER else len(LABEL_ORDER)
    return (lab, -float(item.get("valid_from") or item.get("created") or 0), -int(item.get("id") or 0))


def _why(item: dict) -> str:
    first = str(item.get("summary") or "").split("\n", 1)[0].strip().lower()
    return first.removeprefix("why:").strip() if first.startswith("why:") else ""


def ttl(item: dict) -> float | None:
    """Lifetime of a settled item, None when it never goes stale."""
    if item.get("kind") == "dead-end":
        return STALE_TTL_S.get(f"dead-end:{_why(item)}")
    return STALE_TTL_S.get(str(item.get("kind")))


def is_settled(item: dict) -> bool:
    """Ruled out, a dead end or a blocker, or a finding the verifier closed (an inconclusive one stays open)."""
    kind, outcome = item.get("kind"), item.get("outcome")
    if outcome == "ruled_out" or kind in ("dead-end", "blocker"):
        return True
    return kind == "finding" and item.get("label") == "JUDGED" and outcome != "open_proof_gap"


def is_stale(item: dict, now: float) -> bool:
    life = ttl(item)
    born = float(item.get("valid_from") or item.get("created") or 0)
    return is_settled(item) and life is not None and now - born > life


def cell_state(items: list[dict], now: float) -> str:
    """settled | open | candidate | stale, the state of a cell from its current items."""
    if any(is_settled(i) and not is_stale(i, now) for i in items):
        return "settled"
    if any(i.get("outcome") == "open_proof_gap" for i in items):
        return "open"
    if any(i.get("kind") == "candidate" for i in items):
        return "candidate"
    if any(is_settled(i) for i in items):
        return "stale"
    return "open"


_STATE_VERDICT = {"settled": "EXACT-SETTLED", "stale": "STALE", "open": "EXACT-OPEN", "candidate": "EXACT-OPEN"}


def _kind(item: dict) -> str:
    return f"{item.get('kind')}/{item.get('outcome')}" if item.get("outcome") else str(item.get("kind"))


# ------------------------------------------------------------------ queries
def _fts_mode(board: Any, db: sqlite3.Connection) -> str:
    """`fts5` or `like`, as the store says (bh.lineage.store.fts_mode), else read from the index's own schema."""
    try:
        from bh.lineage import store  # type: ignore[attr-defined]

        return store.fts_mode(board)
    except (ImportError, AttributeError):
        row = db.execute("SELECT sql FROM sqlite_master WHERE name='mem_fts'").fetchone()
        return "fts5" if row and "fts5" in (row[0] or "").lower() else "like"


def fts(board: Any, program: str, query: str, limit: int = FTS_TOP) -> list[dict]:
    """Current items of `program` whose title or summary match words of `query`, best first."""
    db = _db(board)
    words = list(dict.fromkeys(_WORD.findall(str(query or "")[:QUERY_MAX].lower())))[:32]
    if not words:
        return []
    if _fts_mode(board, db) == "fts5":
        match = " OR ".join(f'"{w}"' for w in words)
        return _rows(
            db,
            "SELECT m.* FROM mem_fts f JOIN mem_items m ON m.id=f.rowid WHERE mem_fts MATCH ? AND m.program=? "
            "AND m.valid_to IS NULL ORDER BY bm25(mem_fts), m.id LIMIT ?",
            match,
            program,
            limit,
        )
    hit = "(lower(f.title || ' ' || COALESCE(f.summary, '')) LIKE ? ESCAPE '\\')"
    score = " + ".join([hit] * len(words))
    likes = ["%" + w.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%" for w in words]
    rows = _rows(
        db,
        f"SELECT * FROM (SELECT m.*, ({score}) AS score FROM mem_fts f JOIN mem_items m ON m.id=f.id "
        "WHERE m.program=? AND m.valid_to IS NULL) WHERE score > 0 ORDER BY score DESC, id LIMIT ?",
        *likes,
        program,
        limit,
    )
    for r in rows:
        r.pop("score", None)
    return rows


def _current(db: sqlite3.Connection, program: str, cells: list[str]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {x: [] for x in cells}
    if cells:
        marks = ",".join("?" * len(cells))
        for r in _rows(
            db,
            f"SELECT * FROM mem_items WHERE program=? AND valid_to IS NULL AND cell IN ({marks})",
            program,
            *cells,
        ):
            out[r["cell"]].append(r)
    for items in out.values():
        items.sort(key=_rank)
    return out


def _count(db: sqlite3.Connection, sql: str, *args: Any) -> int:
    return int(db.execute(sql, args).fetchone()[0])


def _new_receipt(db: sqlite3.Connection, program: str) -> str:
    while True:
        r = f"R-{secrets.token_hex(4)}"
        if not db.execute(
            "SELECT 1 FROM mem_receipts WHERE program=? AND json_extract(hits, '$.receipt')=?", (program, r)
        ).fetchone():
            return r


def _write_receipt(
    db: sqlite3.Connection,
    program: str,
    *,
    query: str,
    cell: str | None,
    verdict: str,
    ids: list[int],
    agent_no: int | None,
    run_id: int | None,
    now: float,
) -> str:
    receipt = _new_receipt(db, program)
    db.execute(
        "INSERT INTO mem_receipts(program, agent_no, run_id, query, ckey, verdict, hits, ts) VALUES (?,?,?,?,?,?,?,?)",
        (
            program,
            agent_no,
            run_id,
            query,
            cell,
            verdict,
            json.dumps({"receipt": receipt, "ids": ids}, separators=(",", ":")),
            now,
        ),
    )
    db.commit()
    return receipt


def receipt_row(board: Any, program: str, receipt: str) -> dict | None:
    """The receipt row of `program` named `R-<8 hex>`, or None."""
    if not isinstance(receipt, str) or not RECEIPT_RE.fullmatch(receipt):
        return None
    rows = _rows(
        _db(board),
        "SELECT * FROM mem_receipts WHERE program=? AND json_extract(hits, '$.receipt')=? ORDER BY id LIMIT 1",
        program,
        receipt,
    )
    return rows[0] if rows else None


# ------------------------------------------------------------------ search (D4)
def search(
    board: Any,
    program: str,
    query: str,
    *,
    url: str | None = None,
    vuln_class: str | None = None,
    k: int = 10,
    budget_tokens: int = BUDGET_TOKENS,
    agent_no: int | None = None,
    run_id: int | None = None,
) -> dict:
    """{"receipt", "verdict", "hits", "text"}. Never raises: an unreadable memory is UNAVAILABLE."""
    now = time.time()
    query = str(query or "")[:QUERY_MAX]
    budget = max(1, min(int(budget_tokens), BUDGET_TOKENS))
    k = max(1, min(int(k or 10), K_MAX))
    db = None
    try:
        if program == TECHNIQUES:  # never a program (bh.lineage.techniques): its cards are read with `techniques`
            raise Unavailable(program)
        db = _db(board)
        _need(db, "mem_items", "mem_fts", "mem_receipts")
        cell = cell_of(url, vuln_class)
        serial = (
            0
            if run_id is None
            else _count(db, "SELECT COUNT(*) FROM mem_receipts WHERE program=? AND run_id=?", program, run_id)
        )
        exact = _current(db, program, [cell])[cell] if cell else []
        order: list[str] = [cell] if exact and cell else []
        for it in fts(board, program, query):
            if it["cell"] not in order:
                order.append(it["cell"])
        shown = order[:k]
        by_cell = _current(db, program, shown)
        verdict = _STATE_VERDICT[cell_state(exact, now)] if exact else ("CANDIDATES" if shown else "NEW")
        ids = [by_cell[x][0]["id"] for x in shown if by_cell[x]]
        receipt = _write_receipt(
            db,
            program,
            query=query,
            cell=cell,
            verdict=verdict,
            ids=ids,
            agent_no=agent_no,
            run_id=run_id,
            now=now,
        )
    except (Unavailable, sqlite3.Error, ValueError, TypeError, KeyError):
        receipt = None
        if db is not None:
            try:
                receipt = _write_receipt(
                    db,
                    program,
                    query=query,
                    cell=None,
                    verdict="UNAVAILABLE",
                    ids=[],
                    agent_no=agent_no,
                    run_id=run_id,
                    now=now,
                )
            except (sqlite3.Error, ValueError):
                receipt = None
        return {"receipt": receipt, "verdict": "UNAVAILABLE", "hits": [], "text": UNAVAILABLE_LINE}

    max_lines = SERIAL_LINES if serial >= SERIAL_AFTER else LINES_MAX
    n_items = sum(len(v) for v in by_cell.values())
    head = [
        f"recall {receipt} · {verdict} · {len(shown)} cell(s) found, {n_items} item(s)"
        + (f" · search {serial + 1} of this run: short answers" if max_lines == SERIAL_LINES else "")
    ]
    data = []
    hits = []
    for x in shown:
        items = by_cell[x]
        if not items:
            continue
        top = items[0]
        mark = "=" if x == cell else "~"
        state = cell_state(items, now)
        fixed = (
            f"{mark} #{top['id']} {_clean(x, 90)} ×{len(items)} [{state}] · {top.get('label')} {_kind(top)} · "
            f"{_agent(top.get('agent_no'))} {_date(top.get('valid_from'))} · "
        )
        data.append((fixed, _clean(top.get("title"), 120)))
        hits.append({"cell": x, "id": top["id"], "count": len(items), "state": state})
    tail = [
        VERDICT_LINE[verdict],
        f"more: bh-recall --cell '<cell>' | --full <#id> | --map · cite: --recall {receipt}",
    ]
    text = _frame(head, data, tail, max_lines=max_lines, budget=budget)
    return {"receipt": receipt, "verdict": verdict, "hits": hits, "text": text}


# ------------------------------------------------------------------ navigation (D16, D13)
def navigate(board: Any, program: str, mode: str, arg: str | None = None) -> str:
    """map | cell | run | chain | full | history. Never raises: an unreadable memory is UNAVAILABLE."""
    fn = {
        "map": _map,
        "cell": _cell,
        "run": _run,
        "chain": _chain,
        "full": _full,
        "history": _history,
        "techniques": _techniques,
    }.get(mode)
    if fn is None:
        return "recall ERROR: unknown mode"
    if program == TECHNIQUES:  # the partition is read through `techniques` only, never as a program
        return UNAVAILABLE_LINE
    try:
        return fn(_db(board), program, (arg or "").strip(), time.time())
    except (Unavailable, sqlite3.Error, ValueError, TypeError, KeyError):
        return UNAVAILABLE_LINE


def _techniques(db: sqlite3.Connection, program: str, arg: str, now: float) -> str:
    """T18: full-text search of the technique cards, the TECHNIQUES partition only (never the caller's program nor
    another one): the best card in full, then the titles of the next ones, TECHNIQUE_LINES data lines at most. Host-
    derived, redacted and checked cards (bh.lineage.techniques); still data inside the tag, never an instruction."""
    _need(db, "mem_items", "mem_fts")
    if not arg:
        return "recall ERROR: --techniques needs an idea"
    hits = [r for r in fts(db, TECHNIQUES, arg, TECHNIQUE_LINES) if r.get("kind") == "technique"]
    if not hits:
        return "techniques · 0 cards for this idea (cards come from verified findings of other programs)."
    top, data = hits[0], []
    data.append((f"#{top['id']} ×{top.get('seen') or 1} · ", _clean(top.get("title"), 160)))
    for ln in str(top.get("summary") or "").splitlines():
        if ln.strip() and len(data) < TECHNIQUE_LINES:
            data.append(("  ", _clean(ln, 180)))
    for r in hits[1:]:
        if len(data) >= TECHNIQUE_LINES:
            break
        data.append((f"#{r['id']} ×{r.get('seen') or 1} · ", _clean(r.get("title"), 160)))
    head = [f"techniques · {len(hits)} card(s), best first · from verified findings, hosts and values templated"]
    tail = ["a card is a method, not a lead on this program: prove it here with your own proof.json"]
    return _frame(head, data, tail, max_lines=TECHNIQUE_LINES + 4, budget=BUDGET_TOKENS)


def _int_arg(arg: str, default: int | None = None) -> int | None:
    s = arg.lstrip("#AaBb")
    if not s:
        return default
    return int(s) if s.isdigit() and len(s) <= 12 else None


def _map(db: sqlite3.Connection, program: str, arg: str, now: float) -> str:
    _need(db, "mem_items")
    prefix = arg.lower()
    cells: dict[str, list[dict]] = {}
    for r in _rows(db, "SELECT * FROM mem_items WHERE program=? AND valid_to IS NULL", program):
        route = str(r.get("cell") or "").split(SEP)
        path = route[1].split(" ", 1)[-1] if len(route) > 1 else ""
        if prefix and not (
            path.startswith(prefix) or (len(route) > 1 and route[1].startswith(prefix)) or r["cell"].startswith(prefix)
        ):
            continue
        cells.setdefault(r["cell"], []).append(r)
    states = {x: cell_state(v, now) for x, v in cells.items()}
    last = {x: max(v, key=lambda i: (float(i.get("valid_from") or 0), int(i["id"]))) for x, v in cells.items()}
    counts = {s: sum(1 for v in states.values() if v == s) for s in ("settled", "open", "candidate", "stale")}
    head = [f"map · {len(cells)} cell(s): " + ", ".join(f"{n} {s}" for s, n in counts.items())]
    data = []
    for x in sorted(cells, key=lambda y: (-float(last[y].get("valid_from") or 0), y)):
        li = last[x]
        fixed = f"[{states[x]}] ×{len(cells[x])} {_agent(li.get('agent_no'))} {_date(li.get('valid_from'))} · "
        data.append((fixed, _clean(x, 140)))
    tail = ["more: bh-recall --cell '<cell>' | --map <route prefix>"]
    if not cells:
        return "\n".join([*head, "nothing on record here.", *tail])
    return _frame(head, data, tail)


def _item_line(r: dict) -> tuple[str, str]:
    fixed = f"#{r['id']} {r.get('label')} {_kind(r)} · {_agent(r.get('agent_no'))} {_date(r.get('valid_from'))} · "
    return fixed, _clean(r.get("title"), 160)


def _cell(db: sqlite3.Connection, program: str, arg: str, now: float) -> str:
    _need(db, "mem_items")
    if not arg:
        return "recall ERROR: --cell needs a key"
    cell = cell_of_key(arg)
    items = _current(db, program, [cell])[cell]
    if not items:
        return "cell · 0 items: nothing on record for this cell.\nmore: bh-recall --map | --history <key>"
    head = [f"cell · {len(items)} item(s) · state {cell_state(items, now)} · strongest first"]
    tail = ["more: bh-recall --full <#id> | --history <key>"]
    return _frame(head, [_item_line(r) for r in items], tail)


def _history(db: sqlite3.Connection, program: str, arg: str, now: float) -> str:
    _need(db, "mem_items")
    if not arg:
        return "recall ERROR: --history needs a key"
    cell = cell_of_key(arg)
    rows = _rows(
        db,
        "SELECT * FROM mem_items WHERE program=? AND cell=? AND valid_to IS NOT NULL ORDER BY valid_to DESC, id DESC",
        program,
        cell,
    )
    if not rows:
        return "history · 0 replaced items for this cell.\nmore: bh-recall --cell <key>"
    head = [f"history · {len(rows)} replaced item(s), newest first"]
    data = []
    for r in rows:
        nxt = f"#{r['superseded_by']}" if r.get("superseded_by") else "closed"
        fixed = (
            f"#{r['id']} → {nxt} {_date(r.get('valid_to'))} · {r.get('label')} {_kind(r)} · "
            f"{_agent(r.get('agent_no'))} {_date(r.get('valid_from'))} · "
        )
        data.append((fixed, _clean(r.get("title"), 160)))
    return _frame(head, data, ["more: bh-recall --full <#id>"])


def _run(db: sqlite3.Connection, program: str, arg: str, now: float) -> str:
    _need(db, "mem_items")
    no = _int_arg(arg)
    if no is None:
        return "recall ERROR: --run needs an agent number"
    head = f"run A{no}"
    if _columns(db, "agents"):
        ag = _rows(db, "SELECT generation, parent_no, status FROM agents WHERE program=? AND no=?", program, no)
        if ag:
            a = ag[0]
            head += f" · status {_clean(a.get('status'), 20)} · generation {a.get('generation')}"
            head += f" · parent {_agent(a.get('parent_no'))}" if a.get("parent_no") is not None else ""
    rows = _rows(
        db,
        "SELECT * FROM mem_items WHERE program=? AND agent_no=? AND kind='run-summary' AND valid_to IS NULL "
        "ORDER BY valid_from DESC, id DESC LIMIT 1",
        program,
        no,
    )
    if not rows:
        return f"{head}\nno run summary for this agent.\nmore: bh-recall --chain"
    r = rows[0]
    lines = [r.get("title"), *str(r.get("summary") or "").splitlines()]
    data = [("", _clean(x, 160)) for x in lines if str(x or "").strip()]
    return _frame([f"{head} · summary #{r['id']}"], data, ["more: bh-recall --full <#id> | --chain"])


def _chain(db: sqlite3.Connection, program: str, arg: str, now: float) -> str:
    _need(db, "blocks")
    n = _int_arg(arg, CHAIN_DEFAULT)
    if n is None:
        return "recall ERROR: --chain takes a number"
    n = max(1, min(n, CHAIN_MAX))
    total = _count(db, "SELECT COUNT(*) FROM blocks WHERE program=?", program)
    rows = _rows(db, "SELECT no, body, ts FROM blocks WHERE program=? ORDER BY rowid DESC LIMIT ?", program, n)
    status = {}
    if _columns(db, "agents"):
        status = {r["no"]: r["status"] for r in _rows(db, "SELECT no, status FROM agents WHERE program=?", program)}
    if not rows:
        return "chain · 0 blocks: no agent closed yet."
    data = []
    for r in rows:
        try:
            body = json.loads(r["body"] or "{}")
        except ValueError:
            body = {}
        body = body if isinstance(body, dict) else {}
        summary = body.get("summary")
        if not isinstance(summary, str):
            summary = json.dumps(summary, ensure_ascii=False) if summary else ""
        fixed = f"B{r['no']} {_date(r.get('ts'))} {_clean(body.get('pseudo') or '?', 40)} "
        fixed += f"[{_clean(status.get(r['no'], '?'), 20)}] · "
        data.append((fixed, _clean(summary.splitlines()[0] if summary.strip() else "", 160)))
    head = [f"chain · last {len(rows)} of {total} block(s), newest first"]
    return _frame(head, data, ["more: bh-recall --run <n> | --chain <n>"])


def _full(db: sqlite3.Connection, program: str, arg: str, now: float) -> str:
    _need(db, "mem_items")
    iid = _int_arg(arg.lstrip("Mm"))
    if iid is None:
        return "recall ERROR: --full needs an item id"
    rows = _rows(db, "SELECT * FROM mem_items WHERE program=? AND id=?", program, iid)
    if not rows:
        return f"full #{iid}: no such item in this program."
    r = rows[0]
    head = [
        f"full #{r['id']} · {r.get('label')} {_kind(r)} · {_agent(r.get('agent_no'))} run {r.get('run_id')} · "
        f"from {_date(r.get('valid_from'))} · seen {r.get('seen')}"
        + (
            f" · replaced {_date(r.get('valid_to'))}" + (f" by #{r['superseded_by']}" if r.get("superseded_by") else "")
            if r.get("valid_to")
            else ""
        )
    ]
    data = [("key: ", _clean(r.get("ckey"), LINE_MAX)), ("title: ", _clean(r.get("title"), LINE_MAX))]
    data += [("", _clean(x, LINE_MAX)) for x in str(r.get("summary") or "").splitlines() if x.strip()]
    return _frame(head, data, [], max_lines=FULL_LINES, budget=FULL_TOKENS)


# ------------------------------------------------------------------ receipts checked at the end of a run
def ensure(board: Any) -> None:
    """intents.verified and this module's mem_misses (idempotent). The lineage tables are bh.lineage.store's."""
    db = _db(board)
    db.executescript(MISSES_SQL)
    cols = _columns(db, "intents")
    if cols and "verified" not in cols:
        db.execute("ALTER TABLE intents ADD COLUMN verified INTEGER")
    db.commit()


def _intent_cell(it: dict) -> tuple[str | None, str, str] | None:
    """(host or None, route, class) of a typed intent: intents.endpoint is `METHOD route` (no host) or a URL."""
    endpoint, vc = str(it.get("endpoint") or "").strip(), it.get("vuln_class")
    cls = norm_class(vc) if vc else ""
    if not endpoint or not cls:
        return None
    if "://" in endpoint:
        cell = cell_of(endpoint, str(vc))
        if cell is None:
            return None
        host, route, cls = cell.split(SEP)
        return host, route, cls
    parts = endpoint.split(None, 1)
    method, path = (parts[0], parts[1]) if len(parts) == 2 else ("GET", parts[0])
    if not path.startswith("/"):
        return None
    return None, _field(c.family(f"{method.upper()} {c.path_key(path)}")), cls


def _same_cell(receipt_cell: str | None, ic: tuple[str | None, str, str] | None) -> bool:
    if not receipt_cell or ic is None:
        return False
    host, route, cls = [*receipt_cell.split(SEP), "", "", ""][:3]
    return route == ic[1] and cls == ic[2] and (ic[0] is None or ic[0] == host)


def mark_intents(board: Any, program: str, run_id: int | None) -> dict:
    """intents.verified of the run: 1 when the receipt the intent cites exists in this program and run, precedes the
    intent and is about the same cell; 0 otherwise. Then mem_misses: every NEW receipt of the run for which an older
    item sat in the same cell. No intents.recall column: nothing is done. Never raises."""
    out = {"verified": 0, "unverified": 0, "misses": 0}
    db = _db(board)
    try:
        ensure(board)
        cols = _columns(db, "intents")
        if "recall" not in cols:
            return out
        sel = ", ".join(
            x if x in cols else f"NULL AS {x}" for x in ("id", "created", "recall", "endpoint", "vuln_class", "kind")
        )
        intents = _rows(db, f"SELECT {sel} FROM intents WHERE program=? AND run_id IS ?", program, run_id)
        have_receipts = bool(_columns(db, "mem_receipts"))
        cited: dict[str, dict] = {}
        for it in intents:
            if "kind" in cols and it["kind"] not in ("test", "prove"):
                continue  # only a test or a proof owes a receipt (T15): mapping and untyped intents are not counted
            ok = False
            rec = receipt_row(board, program, it["recall"]) if have_receipts else None
            if rec is not None:
                cited.setdefault(it["recall"], it)
                ok = (
                    rec.get("run_id") == run_id
                    and float(rec["ts"]) <= float(it["created"] or 0)
                    and _same_cell(rec.get("ckey"), _intent_cell(it))
                )
            db.execute("UPDATE intents SET verified=? WHERE id=?", (int(ok), it["id"]))
            out["verified" if ok else "unverified"] += 1
        if have_receipts and _columns(db, "mem_items"):
            _record_misses(db, program, run_id, cited)
            out["misses"] = _count(
                db, "SELECT COUNT(*) FROM mem_misses WHERE program=? AND run_id IS ?", program, run_id
            )
        db.commit()
    except sqlite3.Error as exc:
        out["error"] = type(exc).__name__
    return out


def _record_misses(db: sqlite3.Connection, program: str, run_id: int | None, cited: dict[str, dict]) -> None:
    now = time.time()
    for r in _rows(db, "SELECT * FROM mem_receipts WHERE program=? AND run_id IS ? AND verdict='NEW'", program, run_id):
        try:
            receipt = json.loads(r.get("hits") or "{}").get("receipt")
        except (ValueError, AttributeError):
            continue
        if not isinstance(receipt, str):
            continue
        cell, found = r.get("ckey"), None
        if cell:
            found = db.execute(
                "SELECT id FROM mem_items WHERE program=? AND cell=? AND created < ? ORDER BY created, id LIMIT 1",
                (program, cell, r["ts"]),
            ).fetchone()
        elif receipt in cited and (ic := _intent_cell(cited[receipt])) is not None:
            host, route, cls = ic
            cell = SEP.join((host or "*", route, cls))
            found = db.execute(
                "SELECT id FROM mem_items WHERE program=? AND route=? AND vuln_class=? AND (? IS NULL OR host=?) "
                "AND created < ? ORDER BY created, id LIMIT 1",
                (program, route, cls, host, host, r["ts"]),
            ).fetchone()
        if found:
            db.execute(
                "INSERT OR IGNORE INTO mem_misses(program, run_id, receipt, cell, item_id, ts, found) "
                "VALUES (?,?,?,?,?,?,?)",
                (program, run_id, receipt, cell, found[0], r["ts"], now),
            )
