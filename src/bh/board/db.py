"""SQLite board.

Only the host side (runner, CLI, UI) writes here. The agent never touches the
DB: it appends JSON lines to /work/.bh/notes.jsonl, which the runner ingests.
That keeps the sandbox from forging state it does not own.

Facts are layered like sapper-v2: a one-line title, a short summary, and a path
to the full evidence. The frontier shown to the agent is titles only.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from bh import paths
from bh.agent.contract import (
    BLOCKER_REASONS,
    BLOCKER_TTL_S,
    CHALLENGE_BLOCKER_TTL_S,
    CHALLENGE_REASONS,
    CRITERION_MAX,
    CRITERION_SHOWN,
    INTENT_OUTCOMES,
    REACHED,
    SCOPE_REQUEST_STATUS,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY, program TEXT NOT NULL, session_id TEXT, model TEXT,
  started REAL NOT NULL, ended REAL, status TEXT, turns INTEGER, cost_usd REAL,
  input_tokens INTEGER, output_tokens INTEGER, cache_read INTEGER, note TEXT
);
CREATE TABLE IF NOT EXISTS facts (
  id INTEGER PRIMARY KEY, program TEXT NOT NULL, run_id INTEGER, kind TEXT NOT NULL DEFAULT 'fact',
  title TEXT NOT NULL, summary TEXT, evidence TEXT, created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS intents (
  id INTEGER PRIMARY KEY, program TEXT NOT NULL, run_id INTEGER, title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open', created REAL NOT NULL, closed REAL, outcome TEXT
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY, program TEXT NOT NULL, run_id INTEGER, title TEXT NOT NULL,
  severity TEXT, vuln_class TEXT, url TEXT, summary TEXT, poc TEXT, evidence TEXT,
  not_proven TEXT, status TEXT NOT NULL DEFAULT 'new', verdict TEXT, created REAL NOT NULL, updated REAL
);
CREATE TABLE IF NOT EXISTS todos (
  id INTEGER PRIMARY KEY, program TEXT, kind TEXT NOT NULL, title TEXT NOT NULL, detail TEXT,
  status TEXT NOT NULL DEFAULT 'open', dedup TEXT UNIQUE, created REAL NOT NULL, closed REAL
);
CREATE TABLE IF NOT EXISTS turns (
  run_id INTEGER NOT NULL, idx INTEGER NOT NULL, ts REAL, input INTEGER, cache_read INTEGER, cache_write INTEGER,
  output INTEGER, PRIMARY KEY(run_id, idx)
);
CREATE TABLE IF NOT EXISTS tool_calls (
  run_id INTEGER NOT NULL, idx INTEGER NOT NULL, ts REAL, tool TEXT, kind TEXT, cmd TEXT, ms INTEGER,
  locked INTEGER, PRIMARY KEY(run_id, idx)
);
-- D40: an https prefix the agent asked for; the host's judge decides (pending, approved, refused, revoked)
CREATE TABLE IF NOT EXISTS scope_requests (
  id INTEGER PRIMARY KEY, run_id INTEGER, program TEXT NOT NULL, prefix TEXT NOT NULL, why TEXT,
  status TEXT NOT NULL DEFAULT 'pending', reason TEXT, decided_by TEXT, ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS facts_prog ON facts(program, id);
CREATE INDEX IF NOT EXISTS findings_prog ON findings(program, status);
CREATE INDEX IF NOT EXISTS todos_status ON todos(status);
"""

# Columns added after v0: (table, column, type). Applied idempotently at open.
MIGRATIONS = (
    ("runs", "effort", "TEXT"),
    ("runs", "arsenal_calls", "INTEGER"),
    ("runs", "manual_calls", "INTEGER"),
    ("runs", "locked_calls", "INTEGER"),
    ("runs", "cache_write", "INTEGER"),
    ("runs", "cards", "TEXT"),  # method cards loaded for the segment, comma-separated
    ("runs", "gate_requests", "INTEGER"),  # target requests the gate forwarded for the run
    ("runs", "gate_denied", "INTEGER"),
    ("runs", "gate_errors", "INTEGER"),  # requests that never got an answer
    ("runs", "gate_pushback", "INTEGER"),  # 429 / 503 answers (the gate slowed down)
    ("runs", "verify_cost", "REAL"),  # verifier sessions started by this run (USD equivalent)
    ("findings", "proof", "TEXT"),  # proof.json written by the agent (steps: setup / attack / control)
    ("findings", "replay", "TEXT"),  # verifier stage A: deterministic replay result (JSON)
    ("findings", "poc_triager", "TEXT"),  # PoC generated from the replayed proof, sessions as placeholders
    ("runs", "blockers", "INTEGER"),  # blocker facts the segment recorded
    ("runs", "rotations", "INTEGER"),  # fresh sessions started on the context threshold (runner, 4.2b)
    ("runs", "max_context", "INTEGER"),  # largest per-turn context of the segment, tokens
    # observation proof (audit I1): {"token": "BH-SECRET-<16 hex>", "victim": ..., "attacker": ...}; the verdict
    # comes from the gate's journal, read by the host (bh.runner.observation), never from the hunter
    ("findings", "observation", "TEXT"),
    # honesty pass of the hunter (T1): the best case against the finding, the proof that would change its severity,
    # why this severity. Sandbox text, bounded at ingestion (HONESTY_MAX)
    ("findings", "counter", "TEXT"),
    ("findings", "severity_if", "TEXT"),
    ("findings", "severity_why", "TEXT"),
    # exit criteria written before the test (T8), and which one `bh-note done --reached` says was met
    ("intents", "success", "TEXT"),
    ("intents", "abandon", "TEXT"),
    ("intents", "reached", "TEXT"),  # success | abandon | NULL (no criteria, or a done without --reached)
    # W2-A, typed legs. grounded: 1 only when the host found the quote in a response body the gate kept for the run
    # (T12); never set from the agent's text. The other columns are the agent's words, typed and bounded.
    ("facts", "grounded", "INTEGER NOT NULL DEFAULT 0"),
    ("facts", "quote", "TEXT"),  # one line, QUOTE_MAX characters, redacted
    ("facts", "flow", "TEXT"),  # the gate flow the quote was found in (or the one the note named)
    ("facts", "why", "TEXT"),  # dead-end: DEAD_END_WHY; think: the reason
    ("facts", "endpoint", "TEXT"),  # "METHOD route" (contract.endpoint_label)
    ("facts", "vuln_class", "TEXT"),  # classes.canonical
    ("facts", "outcome", "TEXT"),  # INTENT_OUTCOMES, on a fact the host derived from an intent's closure
    ("facts", "technique", "TEXT"),
    ("facts", "identities", "TEXT"),  # comma-separated identity names
    ("intents", "kind", "TEXT"),  # INTENT_KINDS, NULL for an untyped intent
    ("intents", "basis", "TEXT"),  # F<n>
    ("intents", "after", "TEXT"),  # I<n>
    ("intents", "recall", "TEXT"),  # R-<id> | none, as written (lot C checks the receipt)
    ("intents", "endpoint", "TEXT"),
    ("intents", "vuln_class", "TEXT"),
    ("intents", "outcome", "TEXT"),  # INTENT_OUTCOMES (base column, typed since W2: the free text moved to result)
    ("intents", "result", "TEXT"),  # the hunter's free-text outcome of `bh-note done`
)
FACT_TYPED = ("grounded", "quote", "flow", "why", "endpoint", "vuln_class", "outcome", "technique", "identities")
INTENT_TYPED = ("kind", "basis", "after", "recall", "endpoint", "vuln_class")
# Rows deleted by reset_program. Runs are archived instead: their ids (and log files) are never reused.
PROGRAM_TABLES = ("facts", "intents", "findings", "todos", "scope_requests")

# The only human step left: submitting a verified finding. Anything that blocks the hunt is a blocker fact.
TODO_KINDS = {"submit"}
# needs-proof: stage A found no differential (the control answered like the attack). The proof is at fault, not
# necessarily the finding: the hunter gets one chance to send a better one (issue 34). The column has no CHECK
# constraint, so a new status needs no schema migration.
FINDING_STATUS = {
    "new",
    "verifying",
    "verified",
    # observation proof: the gate saw the victim's canary on the attacker's side, the hunter never sent it (I1)
    "verified-evidence",
    "inconclusive",
    "needs-proof",
    "rejected",
    "submitted",
    "duplicate",
}
FINDING_FIELDS = (
    "severity",
    "vuln_class",
    "url",
    "summary",
    "poc",
    "evidence",
    "not_proven",
    "proof",
    "observation",
    "counter",
    "severity_if",
    "severity_why",
)
HONESTY_FIELDS = ("counter", "severity_if", "severity_why")
HONESTY_MAX = 1000  # stored length of each honesty field


def _flat(text: str | None, n: int) -> str:
    """Hunter text on one frontier line: whitespace runs (newlines too) become one space, the separator `·` of the
    intent line becomes `-` (a title never fakes a criterion), cut at n characters."""
    s = " ".join((text or "").replace("·", "-").split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _intent_line(r: sqlite3.Row) -> str:
    """`- I<n> (<kind>) <title> · after: I<m> · success: <...> · abandon: <...>`: an open intent on its own line,
    bounded. bh-note done reads this shape (bh.agent.contract.intent_has_criteria) to ask for --reached."""
    kind = f"({r['kind']}) " if r["kind"] else ""
    after = f" · after: {r['after']}" if r["after"] else ""
    crit = "".join(f" · {k}: {_flat(r[k], CRITERION_SHOWN)}" for k in REACHED if r[k])
    return f"- I{r['id']} {kind}{_flat(r['title'], 300)}{after}{crit}"


def _fact_label(r: sqlite3.Row) -> str:
    """The kind of a frontier fact line: a dead end shows its cause (T13), an anchored fact says so (T12)."""
    if r["kind"] == "dead-end" and r["why"]:
        return f"dead-end: {r['why']}"
    return f"{r['kind']}, anchored" if r["grounded"] else r["kind"]


def _typed_value(k: str, v: Any) -> Any:
    if k == "grounded":
        return 1 if v is True or v == 1 else 0
    return None if v is None or v == "" else str(v)[: 500 if k != "quote" else 400]


class Board:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else paths.board_db()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        for table, col, typ in MIGRATIONS:
            if col not in {r["name"] for r in self.db.execute(f"PRAGMA table_info({table})")}:
                self.db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
        if not self.meta_get("todos-v2"):
            # Todos of the old model (auth, waf, ...) waited on a human who is no longer in the loop.
            # They are marked obsolete, not deleted: the history stays readable.
            self.db.execute(
                "UPDATE todos SET status='obsolete', closed=? WHERE status='open' AND kind NOT IN "
                f"({', '.join('?' * len(TODO_KINDS))})",
                (time.time(), *sorted(TODO_KINDS)),
            )
            self.meta_set("todos-v2", str(time.time()))
        if not self.meta_get("intents-outcome-v2"):
            # intents.outcome held the hunter's free text; since W2 it holds a typed INTENT_OUTCOMES value and the
            # text lives in `result`. Old rows move once.
            self.db.execute(
                "UPDATE intents SET result=outcome, outcome=NULL WHERE outcome IS NOT NULL AND outcome NOT IN "
                f"({', '.join('?' * len(INTENT_OUTCOMES))})",
                INTENT_OUTCOMES,
            )
            self.meta_set("intents-outcome-v2", str(time.time()))
        self.db.commit()

    # ---- meta (cursors, flags)
    def meta_get(self, key: str, default: str = "") -> str:
        row = self.db.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
        return row["v"] if row else default

    def meta_set(self, key: str, value: str) -> None:
        self.db.execute("INSERT INTO meta(k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, value))
        self.db.commit()

    def new_lines(self, path: Path, key: str) -> list[dict]:
        """JSON objects appended to the log `path` since the last call with the same cursor `key`. The cursor
        is "inode:offset": a log that was rotated (another inode) or that shrank is read from the start.
        Lines that are not JSON objects are skipped; a partial last line is left for the next call."""
        if not path.exists():
            return []
        ino, _, off_s = self.meta_get(key, "").rpartition(":")
        st = path.stat()
        off = int(off_s) if off_s.isdigit() else 0
        if (ino and ino != str(st.st_ino)) or st.st_size < off:
            off = 0
        out = []
        with open(path, "rb") as fh:
            fh.seek(off)
            for line in fh:
                if not line.endswith(b"\n"):
                    break  # the gate is still writing it
                off += len(line)
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict):
                    out.append(rec)
        self.meta_set(key, f"{st.st_ino}:{off}")
        return out

    def reset_program(self, program: str) -> dict[str, int]:
        """Forget everything about one program (training labs). Returns affected rows per table."""
        out = {t: self.db.execute(f"DELETE FROM {t} WHERE program=?", (program,)).rowcount for t in PROGRAM_TABLES}
        # the asset graph (bh.assets) lives in the same file: without this a reset lab keeps its old surface
        if self.rows("SELECT 1 FROM sqlite_master WHERE type='table' AND name='assets'"):
            ids = "SELECT id FROM assets WHERE program=?"
            for t in ("coverage", "tests", "asset_links"):
                self.db.execute(f"DELETE FROM {t} WHERE asset_id IN ({ids})", (program,))
            out["assets"] = self.db.execute("DELETE FROM assets WHERE program=?", (program,)).rowcount
        if self.rows("SELECT 1 FROM sqlite_master WHERE type='table' AND name='coverage_class'"):
            out["coverage_class"] = self.db.execute("DELETE FROM coverage_class WHERE program=?", (program,)).rowcount
        archived = f"{program}~{time.strftime('%Y%m%d-%H%M%S')}"
        out["runs (archived)"] = self.db.execute(
            "UPDATE runs SET program=? WHERE program=?", (archived, program)
        ).rowcount
        self.db.execute("DELETE FROM meta WHERE k LIKE ?", (f"%:{program}",))
        self.db.commit()
        return out

    # ---- runs
    def run_start(self, program: str, model: str) -> int:
        # One agent at a time: a run still 'running' here was orphaned by a crash or a hard kill.
        self.db.execute(
            "UPDATE runs SET status='stopped', ended=?, note='orphaned (closed at next start)' WHERE status='running'",
            (time.time(),),
        )
        cur = self.db.execute(
            "INSERT INTO runs(program, model, started, status) VALUES (?,?,?, 'running')", (program, model, time.time())
        )
        self.db.commit()
        return int(cur.lastrowid)

    def run_set(self, run_id: int, **fields: Any) -> None:
        cols = ", ".join(f"{k}=?" for k in fields)
        self.db.execute(f"UPDATE runs SET {cols} WHERE id=?", (*fields.values(), run_id))
        self.db.commit()

    def run_end(self, run_id: int, **fields: Any) -> None:
        self.run_set(run_id, ended=time.time(), **fields)

    def record_metrics(self, run_id: int, turns: list[dict], tools: list[dict]) -> None:
        """Per-turn tokens and per-tool-call durations of a run (observability, plan v2 step 4)."""
        base = self.db.execute("SELECT COUNT(*) FROM turns WHERE run_id=?", (run_id,)).fetchone()[0]
        self.db.executemany(
            "INSERT OR REPLACE INTO turns VALUES (?,?,?,?,?,?,?)",
            [
                (
                    run_id,
                    base + i,
                    t.get("ts"),
                    t.get("input"),
                    t.get("cache_read"),
                    t.get("cache_write"),
                    t.get("output"),
                )
                for i, t in enumerate(turns)
            ],
        )
        base = self.db.execute("SELECT COUNT(*) FROM tool_calls WHERE run_id=?", (run_id,)).fetchone()[0]
        self.db.executemany(
            "INSERT OR REPLACE INTO tool_calls VALUES (?,?,?,?,?,?,?,?)",
            [
                (
                    run_id,
                    base + i,
                    t.get("ts"),
                    t.get("tool"),
                    t.get("kind"),
                    t.get("cmd"),
                    t.get("ms"),
                    int(bool(t.get("locked"))),
                )
                for i, t in enumerate(tools)
            ],
        )
        self.db.commit()

    def run_ids(self, program: str) -> set[int]:
        return {r["id"] for r in self.db.execute("SELECT id FROM runs WHERE program=?", (program,))}

    def last_session(self, program: str) -> str | None:
        row = self.db.execute(
            "SELECT session_id FROM runs WHERE program=? AND session_id IS NOT NULL ORDER BY id DESC LIMIT 1",
            (program,),
        ).fetchone()
        return row["session_id"] if row else None

    # ---- facts / intents
    def add_fact(
        self,
        program: str,
        title: str,
        summary: str = "",
        evidence: str = "",
        *,
        kind: str = "fact",
        run_id: int | None = None,
        **typed: Any,
    ) -> int:
        """`typed`: the FACT_TYPED columns (W2-A). `grounded` is the host's word: the ingestion sets it, nothing the
        agent wrote does."""
        extra = {k: _typed_value(k, v) for k, v in typed.items() if k in FACT_TYPED}
        cols = ["program", "run_id", "kind", "title", "summary", "evidence", "created", *extra]
        cur = self.db.execute(
            f"INSERT INTO facts({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
            (program, run_id, kind, title[:300], summary[:2000], evidence[:500], time.time(), *extra.values()),
        )
        self.db.commit()
        return int(cur.lastrowid)

    def add_blocker(
        self,
        program: str,
        reason: str,
        title: str,
        detail: str = "",
        *,
        run_id: int | None = None,
        host: str | None = None,
        **typed: Any,
    ) -> int:
        """A lead the agent cannot finish without a human: recorded, never waited on.
        Fact kind 'blocker', title "[reason] title"; the host (if any) is kept as evidence "host:<name>"."""
        if reason not in BLOCKER_REASONS:
            reason = "other"
        return self.add_fact(
            program,
            f"[{reason}] {title}",
            detail,
            f"host:{host}" if host else "",
            kind="blocker",
            run_id=run_id,
            **typed,
        )

    def add_intent(
        self,
        program: str,
        title: str,
        run_id: int | None = None,
        *,
        success: str | None = None,
        abandon: str | None = None,
        **typed: Any,
    ) -> int:
        """An intent, with the exit criteria the hunter wrote before the test (T8), if any: empty means none.
        `typed`: the INTENT_TYPED columns (kind, basis, after, recall, endpoint, vuln_class)."""
        extra = {k: _typed_value(k, v) for k, v in typed.items() if k in INTENT_TYPED}
        cols = ["program", "run_id", "title", "created", "success", "abandon", *extra]
        cur = self.db.execute(
            f"INSERT INTO intents({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
            (
                program,
                run_id,
                title[:300],
                time.time(),
                (success or "")[:CRITERION_MAX] or None,
                (abandon or "")[:CRITERION_MAX] or None,
                *extra.values(),
            ),
        )
        self.db.commit()
        return int(cur.lastrowid)

    def close_intent(
        self, intent_id: int, outcome: str, reached: str | None = None, *, closure: str | None = None
    ) -> None:
        """`outcome`: the hunter's text (column `result`); `closure`: the typed INTENT_OUTCOMES value (column
        `outcome`), NULL when the note gave none."""
        self.db.execute(
            "UPDATE intents SET status='closed', closed=?, result=?, reached=?, outcome=? WHERE id=?",
            (
                time.time(),
                outcome[:500],
                reached if reached in REACHED else None,
                closure if closure in INTENT_OUTCOMES else None,
                intent_id,
            ),
        )
        self.db.commit()

    def intent_order(self, program: str) -> list[int]:
        """The order of open intents the hunter last gave (`bh-note reorder`), ids only."""
        try:
            ids = json.loads(self.meta_get(f"intent-order:{program}", "[]"))
        except ValueError:
            return []
        return [i for i in ids if isinstance(i, int) and not isinstance(i, bool)] if isinstance(ids, list) else []

    def set_intent_order(self, program: str, ids: list[int]) -> None:
        self.meta_set(f"intent-order:{program}", json.dumps(list(dict.fromkeys(ids))[:200]))

    def threat_model(self, program: str) -> sqlite3.Row | None:
        """The active threat model (T16): the latest one. Older ones stay, with their dates."""
        rows = self.rows(
            "SELECT id, title, summary, created, grounded FROM facts WHERE program=? AND kind='threat-model' "
            "ORDER BY id DESC LIMIT 1",
            program,
        )
        return rows[0] if rows else None

    # ---- scope requests (D40): written at ingestion, decided by the host's judge or the operator
    def add_scope_request(self, program: str, prefix: str, why: str, run_id: int | None = None) -> int | None:
        """A pending request; None when the same prefix is already pending or approved for the program."""
        if self.rows(
            "SELECT 1 FROM scope_requests WHERE program=? AND prefix=? AND status IN ('pending', 'approved')",
            program,
            prefix,
        ):
            return None
        cur = self.db.execute(
            "INSERT INTO scope_requests(run_id, program, prefix, why, status, ts) VALUES (?,?,?,?, 'pending', ?)",
            (run_id, program, prefix[:500], why[:1000], time.time()),
        )
        self.db.commit()
        return int(cur.lastrowid)

    def scope_requests(self, program: str | None = None, status: str | None = None) -> list[sqlite3.Row]:
        sql, args = "SELECT * FROM scope_requests WHERE 1=1", []
        if program is not None:
            sql, args = sql + " AND program=?", [*args, program]
        if status is not None:
            sql, args = sql + " AND status=?", [*args, status]
        return self.rows(sql + " ORDER BY id", *args)

    def decide_scope_request(self, request_id: int, status: str, reason: str, decided_by: str) -> None:
        if status not in SCOPE_REQUEST_STATUS:
            raise ValueError(f"bad scope request status {status}")
        self.db.execute(
            "UPDATE scope_requests SET status=?, reason=?, decided_by=? WHERE id=?",  # ts stays the request's
            (status, reason[:1000], decided_by[:80], request_id),
        )
        self.db.commit()

    # ---- findings
    def add_finding(self, program: str, title: str, run_id: int | None = None, **kw: Any) -> int:
        data = {
            k: (json.dumps(v) if isinstance(v, (dict, list)) else str(v) if v is not None else None)
            for k, v in kw.items()
            if k in FINDING_FIELDS
        }
        cols = ["program", "run_id", "title", "created", *data]
        cur = self.db.execute(
            f"INSERT INTO findings({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
            (program, run_id, title[:300], time.time(), *data.values()),
        )
        self.db.commit()
        return int(cur.lastrowid)

    def finding_set(self, fid: int, **fields: Any) -> None:
        """Verifier outputs (replay, poc_triager). Status changes go through set_finding."""
        cols = ", ".join(f"{k}=?" for k in fields)
        self.db.execute(f"UPDATE findings SET {cols}, updated=? WHERE id=?", (*fields.values(), time.time(), fid))
        self.db.commit()

    def set_finding(self, fid: int, status: str, verdict: str | None = None) -> None:
        if status not in FINDING_STATUS:
            raise ValueError(f"bad status {status}")
        self.db.execute(
            "UPDATE findings SET status=?, verdict=COALESCE(?, verdict), updated=? WHERE id=?",
            (status, verdict, time.time(), fid),
        )
        self.db.commit()

    # ---- todos
    def add_todo(
        self, kind: str, title: str, detail: str = "", program: str | None = None, dedup: str | None = None
    ) -> int | None:
        if kind not in TODO_KINDS:
            raise ValueError(f"todo kind {kind!r} is not post-triage work (blockers go through add_blocker)")
        try:
            cur = self.db.execute(
                "INSERT INTO todos(program, kind, title, detail, dedup, created) VALUES (?,?,?,?,?,?)",
                (program, kind, title[:300], detail[:4000], dedup, time.time()),
            )
        except sqlite3.IntegrityError:
            return None  # same dedup key already open/closed
        self.db.commit()
        return int(cur.lastrowid)

    def close_todo(self, tid: int) -> None:
        self.db.execute("UPDATE todos SET status='done', closed=? WHERE id=?", (time.time(), tid))
        self.db.commit()

    # ---- queries
    def rows(self, sql: str, *args: Any) -> list[sqlite3.Row]:
        return list(self.db.execute(sql, args))

    def frontier(self, program: str, max_facts: int = 25, *, passthrough: bool = False, facts: bool = True) -> str:
        """Compact context for the agent: titles only, newest first. Target <= ~40 lines.
        `passthrough`: the scope has a host behind a human challenge that the operator passes in bh-web. A captcha or
        challenge blocker is then a wait, not a wall: shown CHALLENGE_BLOCKER_TTL_S only, under "retry".
        `facts=False`: no section of latest facts (the inheritance block of the prompt takes its place)."""
        # Bookkeeping facts repeat every segment (one HANDOFF, one "gate denied" per run): only the latest
        # of each kind is worth resending; every other fact stays, newest first. Blockers have their own section, the
        # threat model too (the latest is the active one); `think` lines are the lineage's journal, not the frontier.
        latest = (
            self.rows(
                "SELECT id, kind, title, why, grounded FROM facts WHERE program=? AND kind NOT IN "
                "('blocker', 'think', 'threat-model') AND "
                "(kind NOT IN ('handoff', 'blocked') OR id IN "
                "(SELECT MAX(id) FROM facts WHERE program=? AND kind IN ('handoff', 'blocked') GROUP BY kind)) "
                "ORDER BY id DESC LIMIT ?",
                program,
                program,
                max_facts,
            )
            if facts
            else []
        )
        # Past the TTL a blocker is dropped from view: the wall may be gone, the lead is worth a new look.
        now = time.time()
        blockers = self.rows(
            "SELECT id, title, created FROM facts WHERE program=? AND kind='blocker' AND created>=? "
            "ORDER BY id DESC LIMIT 10",
            program,
            now - BLOCKER_TTL_S,
        )
        retry = []
        if passthrough:
            waits = tuple(f"[{r}]" for r in CHALLENGE_REASONS)
            retry = [r for r in blockers if r["title"].startswith(waits)]
            waiting = {r["id"] for r in retry}
            blockers = [r for r in blockers if r["id"] not in waiting]
            retry = [r for r in retry if r["created"] >= now - CHALLENGE_BLOCKER_TTL_S]
        intents = self.rows(
            "SELECT id, title, success, abandon, kind, after FROM intents WHERE program=? AND status='open' "
            "ORDER BY id",
            program,
        )
        rank = {iid: i for i, iid in enumerate(self.intent_order(program))}  # bh-note reorder; the rest by id
        intents.sort(key=lambda r: (rank.get(r["id"], len(rank)), r["id"]))
        findings = self.rows("SELECT id, status, severity, title FROM findings WHERE program=? ORDER BY id", program)
        model = self.threat_model(program)
        out: list[str] = []
        if findings:
            out.append("## findings")
            out += [f"- F{r['id']} [{r['status']}/{r['severity'] or '?'}] {r['title']}" for r in findings]
        if intents:
            out.append("## open intents")
            out += [_intent_line(r) for r in intents]
        if model is not None:
            day = time.strftime("%Y-%m-%d", time.localtime(model["created"]))
            out.append(f"## threat model ({model['id']}, {day}): {_flat(model['title'], 200)}")
            out += [f"- {_flat(ln, 300)}" for ln in (model["summary"] or "").splitlines() if ln.strip()]
        if latest:
            out.append(f"## facts (latest {len(latest)}; details: bh-note show <id>)")
            out += [f"- {r['id']} ({_fact_label(r)}) {r['title']}" for r in reversed(latest)]
        if blockers:
            out.append("## blocked (do not retry)")
            out += [f"- {r['id']} {r['title']}" for r in reversed(blockers)]
        if retry:
            out.append("## blocked, retry: `bh-web state` (a human challenge the operator may have passed)")
            out += [f"- {r['id']} {r['title']}" for r in reversed(retry)]
        if out:
            return "\n".join(out)
        return "(board empty: first session on this program)" if facts else "(no open intents, candidates or blockers)"

    def export_facts(self, program: str, path: Path) -> None:
        """Read-only snapshot for the agent (bh-note show)."""
        data = {
            r["id"]: dict(r)
            for r in self.rows(
                "SELECT id, kind, title, summary, evidence, grounded, quote, flow, why, endpoint, vuln_class, outcome, "
                "technique, identities FROM facts WHERE program=?",
                program,
            )
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False))
