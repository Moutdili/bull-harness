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
from bh.agent.contract import BLOCKER_REASONS, BLOCKER_TTL_S

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
)
# Rows deleted by reset_program. Runs are archived instead: their ids (and log files) are never reused.
PROGRAM_TABLES = ("facts", "intents", "findings", "todos")

# The only human step left: submitting a verified finding. Anything that blocks the hunt is a blocker fact.
TODO_KINDS = {"submit"}
# needs-proof: stage A found no differential (the control answered like the attack). The proof is at fault, not
# necessarily the finding: the hunter gets one chance to send a better one (issue 34). The column has no CHECK
# constraint, so a new status needs no schema migration.
FINDING_STATUS = {
    "new",
    "verifying",
    "verified",
    "inconclusive",
    "needs-proof",
    "rejected",
    "submitted",
    "duplicate",
}
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
        if not self.meta_get("todos-v2"):
            # Todos of the old model (auth, waf, ...) waited on a human who is no longer in the loop.
            # They are marked obsolete, not deleted: the history stays readable.
            self.db.execute(
                "UPDATE todos SET status='obsolete', closed=? WHERE status='open' AND kind NOT IN "
                f"({', '.join('?' * len(TODO_KINDS))})",
                (time.time(), *sorted(TODO_KINDS)),
            )
            self.meta_set("todos-v2", str(time.time()))
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
    ) -> int:
        cur = self.db.execute(
            "INSERT INTO facts(program, run_id, kind, title, summary, evidence, created) VALUES (?,?,?,?,?,?,?)",
            (program, run_id, kind, title[:300], summary[:2000], evidence[:500], time.time()),
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
        )

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

    def frontier(self, program: str, max_facts: int = 25) -> str:
        """Compact context for the agent: titles only, newest first. Target <= ~40 lines."""
        # Bookkeeping facts repeat every segment (one HANDOFF, one "gate denied" per run): only the latest
        # of each kind is worth resending; every other fact stays, newest first. Blockers have their own section.
        facts = self.rows(
            "SELECT id, kind, title FROM facts WHERE program=? AND kind != 'blocker' AND "
            "(kind NOT IN ('handoff', 'blocked') OR id IN "
            "(SELECT MAX(id) FROM facts WHERE program=? AND kind IN ('handoff', 'blocked') GROUP BY kind)) "
            "ORDER BY id DESC LIMIT ?",
            program,
            program,
            max_facts,
        )
        # Past the TTL a blocker is dropped from view: the wall may be gone, the lead is worth a new look.
        blockers = self.rows(
            "SELECT id, title FROM facts WHERE program=? AND kind='blocker' AND created>=? ORDER BY id DESC LIMIT 10",
            program,
            time.time() - BLOCKER_TTL_S,
        )
        intents = self.rows("SELECT id, title FROM intents WHERE program=? AND status='open' ORDER BY id", program)
        findings = self.rows("SELECT id, status, severity, title FROM findings WHERE program=? ORDER BY id", program)
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
        if blockers:
            out.append("## blocked (do not retry)")
            out += [f"- {r['id']} {r['title']}" for r in reversed(blockers)]
        return "\n".join(out) if out else "(board empty: first session on this program)"

    def export_facts(self, program: str, path: Path) -> None:
        """Read-only snapshot for the agent (bh-note show)."""
        data = {
            r["id"]: dict(r)
            for r in self.rows("SELECT id, kind, title, summary, evidence FROM facts WHERE program=?", program)
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False))
