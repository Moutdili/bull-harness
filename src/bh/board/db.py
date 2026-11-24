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
    ("findings", "proof", "TEXT"),  # proof.json written by the agent (steps: setup / attack / control)
    ("findings", "replay", "TEXT"),  # verifier stage A: deterministic replay result (JSON)
    ("findings", "poc_triager", "TEXT"),  # PoC generated from the replayed proof, sessions as placeholders
)
# Rows deleted by reset_program. Runs are archived instead: their ids (and log files) are never reused.
PROGRAM_TABLES = ("facts", "intents", "findings", "todos")

TODO_KINDS = {"auth", "waf", "account", "scope-question", "refusal", "submit", "verify", "quota", "other"}
FINDING_STATUS = {"new", "verifying", "verified", "inconclusive", "rejected", "submitted", "duplicate"}
FINDING_FIELDS = ("severity", "vuln_class", "url", "summary", "poc", "evidence", "not_proven", "proof")


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
        self.db.commit()

    # ---- meta (cursors, flags)
    def meta_get(self, key: str, default: str = "") -> str:
        row = self.db.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
        return row["v"] if row else default

    def meta_set(self, key: str, value: str) -> None:
        self.db.execute("INSERT INTO meta(k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, value))
        self.db.commit()

    def reset_program(self, program: str) -> dict[str, int]:
        """Forget everything about one program (training labs). Returns affected rows per table."""
        out = {t: self.db.execute(f"DELETE FROM {t} WHERE program=?", (program,)).rowcount for t in PROGRAM_TABLES}
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
        kind: str = "fact",
        run_id: int | None = None,
    ) -> int:
        cur = self.db.execute(
            "INSERT INTO facts(program, run_id, kind, title, summary, evidence, created) VALUES (?,?,?,?,?,?,?)",
            (program, run_id, kind, title[:300], summary[:2000], evidence[:500], time.time()),
        )
        self.db.commit()
        return int(cur.lastrowid)

    def add_intent(self, program: str, title: str, run_id: int | None = None) -> int:
        cur = self.db.execute(
            "INSERT INTO intents(program, run_id, title, created) VALUES (?,?,?,?)",
            (program, run_id, title[:300], time.time()),
        )
        self.db.commit()
        return int(cur.lastrowid)

    def close_intent(self, intent_id: int, outcome: str) -> None:
        self.db.execute(
            "UPDATE intents SET status='closed', closed=?, outcome=? WHERE id=?",
            (time.time(), outcome[:500], intent_id),
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
            kind = "other"
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

    def frontier(self, program: str, max_facts: int = 25) -> str:
        """Compact context for the agent: titles only, newest first. Target <= ~40 lines."""
        facts = self.rows(
            "SELECT id, kind, title FROM facts WHERE program=? ORDER BY id DESC LIMIT ?", program, max_facts
        )
        intents = self.rows("SELECT id, title FROM intents WHERE program=? AND status='open' ORDER BY id", program)
        findings = self.rows("SELECT id, status, severity, title FROM findings WHERE program=? ORDER BY id", program)
        todos = self.rows(
            "SELECT id, kind, title FROM todos WHERE status='open' AND (program=? OR program IS NULL)", program
        )
        out: list[str] = []
        if findings:
            out.append("## findings")
            out += [f"- F{r['id']} [{r['status']}/{r['severity'] or '?'}] {r['title']}" for r in findings]
        if intents:
            out.append("## open intents")
            out += [f"- I{r['id']} {r['title']}" for r in intents]
        if facts:
            out.append(f"## facts (latest {len(facts)}; details: bh-note show <id>)")
            out += [f"- {r['id']} ({r['kind']}) {r['title']}" for r in reversed(facts)]
        if todos:
            out.append("## waiting on human")
            out += [f"- T{r['id']} [{r['kind']}] {r['title']}" for r in todos]
        return "\n".join(out) if out else "(board empty: first session on this program)"

    def export_facts(self, program: str, path: Path) -> None:
        """Read-only snapshot for the agent (bh-note show)."""
        data = {
            r["id"]: dict(r)
            for r in self.rows("SELECT id, kind, title, summary, evidence FROM facts WHERE program=?", program)
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False))
