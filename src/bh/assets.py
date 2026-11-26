"""Asset graph of a program, kept by the host (plan v2, step 3; replaces the scattered surface).

  host ──< origin ──< endpoint            (assets, kind + key, parent)
            │            └── tests        (who tested it: gate-observed hand request, builtin, literal URL)
            └── coverage                  (recon / crawl / content / scan ... per origin)
  any asset ──< anchors >── fact | finding (asset_links)

Authority: the gate's observations (flows tagged with the run, hand-made User-Agents) rank above what
the sandbox writes (endpoints.jsonl, coverage.json, touched.jsonl can be edited by the agent; they feed
the map, they never widen the scope). Every host is checked against the hard scope when it enters the
graph: an out-of-scope host is kept as such (in_scope=0): it is recorded, never a target. A host the gate cools
down (WAF) is marked blocked until a deadline: its untested endpoints leave the agent's list until then.
"""

from __future__ import annotations

import json
import re
import time
from urllib.parse import urlsplit

from bh import paths
from bh.agent import contract as c
from bh.board import Board
from bh.scope import Scope, check

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY, program TEXT NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL, parent INTEGER,
  in_scope INTEGER NOT NULL DEFAULT 1, source TEXT, meta TEXT, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
  UNIQUE(program, kind, key)
);
CREATE TABLE IF NOT EXISTS coverage (
  asset_id INTEGER NOT NULL, phase TEXT NOT NULL, status TEXT, ts REAL, raw TEXT, UNIQUE(asset_id, phase)
);
CREATE TABLE IF NOT EXISTS tests (
  asset_id INTEGER NOT NULL, evidence TEXT NOT NULL, run_id INTEGER, ts REAL, UNIQUE(asset_id, evidence, run_id)
);
CREATE TABLE IF NOT EXISTS asset_links (
  asset_id INTEGER NOT NULL, ref_kind TEXT NOT NULL, ref_id INTEGER NOT NULL, UNIQUE(asset_id, ref_kind, ref_id)
);
CREATE INDEX IF NOT EXISTS assets_prog ON assets(program, kind);
-- T14: coverage of one (endpoint, class), one row per `bh-note cover`, the latest wins. endpoint is "METHOD route"
-- (contract.endpoint_label), vuln_class classes.canonical. gate_seen = 1 only when `tests` holds a `gate` proof for
-- that endpoint in that run; without it a `clean` is stored as `retry`.
CREATE TABLE IF NOT EXISTS coverage_class (
  program TEXT NOT NULL, endpoint TEXT NOT NULL, vuln_class TEXT NOT NULL, outcome TEXT NOT NULL, evidence TEXT,
  run_id INTEGER, ts REAL NOT NULL, gate_seen INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS coverage_class_key ON coverage_class(program, endpoint, vuln_class);
"""
# User-Agents of hand-made requests (curl, PoC scripts). Builtins (katana, ffuf, nuclei, sqlmap...) differ.
MANUAL_UA = re.compile(r"^(curl|wget|python-requests|python-urllib|httpie|xh|node-fetch|axios|undici)/", re.I)
# a scanner's probe with these answers found no path (nuclei alone sent thousands to the lab)
_ABSENT = frozenset({404, 410, "error"})
# What makes an endpoint "tested". The gate's word ranks first: a hand-made request it saw ("gate") counts alone;
# what the sandbox claims (touched.jsonl: "tool", "literal") counts only if the gate saw that endpoint asked at all
# ("seen", any client). Same for coverage: a phase counts on an origin the gate saw traffic to.
EVIDENCE_RANK = {"gate": 3, "tool": 2, "literal": 1, "seen": 0}
_CLAIMS = {"tool", "literal"}


def _text(e: dict, k: str) -> str | None:
    v = e.get(k)
    return v[:2000] if isinstance(v, str) and v else None


def _origin(e) -> str | None:
    """A sandbox-written origin, normalized (scheme://host:port), or None when it is not one."""
    return c.origin(e["origin"]) if isinstance(e, dict) and isinstance(e.get("origin"), str) else None


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _typed_endpoint(e: dict) -> bool:
    """Every field of an endpoints.jsonl entry has the type SQL and the graph expect (M4): a dict or a list where a
    string is expected drops the entry, it never raises."""
    return (
        isinstance(e.get("source"), str | None)
        and (e.get("params") is None or isinstance(e.get("params"), list))
        and (e.get("status") is None or _is_int(e.get("status")))
    )


def _coverage_row(phase, entry) -> tuple[str, str | None, float | None, str | None] | None:
    """(phase, status, ts, raw) of a coverage.json entry, typed for SQL; None when a value has the wrong type."""
    if not isinstance(phase, str) or not phase or len(phase) > 40 or not isinstance(entry, dict):
        return None
    status, ts, raw = entry.get("status"), entry.get("ts"), entry.get("raw")
    if not isinstance(status, str | None) or not isinstance(raw, str | None):
        return None
    if ts is not None:
        if isinstance(ts, bool) or not isinstance(ts, int | float):
            return None
        try:
            ts = float(ts)  # an integer too large for SQLite would raise at bind time
        except OverflowError:
            return None
    return phase, status[:200] if status else status, ts, raw[:2000] if raw else raw


def ensure(board: Board) -> None:
    board.db.executescript(SCHEMA)


def gate_flow(f: dict) -> tuple[str, str] | None:
    """(origin, "METHOD route") of a flows.jsonl line that is a proof of rank `gate`: a hand-made request (MANUAL_UA)
    to a target. The one rule Graph.sync and gate_tested share."""
    if not isinstance(f, dict) or f.get("class") not in (None, "target") or not MANUAL_UA.match(str(f.get("ua") or "")):
        return None
    url = f.get("url") if isinstance(f.get("url"), str) else ""
    k = c.endpoint_key(url, str(f.get("method", "GET")))
    return (k[0], c.family(k[1])) if k else None


def gate_endpoints(run_id: int | None, window: int = 8_000_000) -> set[str]:
    """ "METHOD route" of the hand-made target requests the gate logged for the run, from the tail of flows.jsonl:
    what `tests` will hold as `gate` once Graph.sync has read the log (the runner syncs after the notes)."""
    out = set()
    for f in c.tail_jsonl(paths.flows_log(), 10**6, window):
        # a run id belongs to one program (runs table): the run is the filter, as in Graph.sync
        if run_id is not None and f.get("run") == run_id and (k := gate_flow(f)):
            out.add(k[1])
    return out


def gate_tested(board: Board, program: str, endpoint: str, run_id: int | None, logged: set[str] | None = None) -> bool:
    """`tests` holds a proof of rank `gate` (a hand-made request the gate forwarded) for the endpoint "METHOD route"
    of the program, on any of its origins, in run `run_id`; or the gate's flow log of that run does, not yet synced
    (`logged`: gate_endpoints, computed once by the caller). Never the sandbox's files."""
    ensure(board)
    if logged is not None and endpoint in logged:
        return True
    return bool(
        board.rows(
            "SELECT 1 FROM tests t JOIN assets a ON a.id=t.asset_id WHERE a.program=? AND a.kind='endpoint' "
            "AND t.evidence='gate' AND t.run_id=? AND substr(a.key, instr(a.key, ' ') + 1)=? LIMIT 1",
            program,
            run_id,
            endpoint,
        )
    )


def class_coverage(board: Board, program: str) -> dict[tuple[str, str], dict]:
    """(endpoint, class) -> the latest `bh-note cover` row for it."""
    ensure(board)
    out: dict[tuple[str, str], dict] = {}
    for r in board.rows("SELECT * FROM coverage_class WHERE program=? ORDER BY ts, rowid", program):
        out[(r["endpoint"], r["vuln_class"])] = dict(r)
    return out


class Graph:
    def __init__(self, board: Board, scope: Scope):
        ensure(board)
        self.b, self.scope, self.program = board, scope, scope.program
        self.new_out_of_scope: list[str] = []

    # ------------------------------------------------------------------ upserts
    def _upsert(
        self, kind: str, key: str, parent: int | None, source: str, *, in_scope: bool = True, meta: dict | None = None
    ) -> int:
        now = time.time()
        row = self.b.db.execute(
            "SELECT id, meta FROM assets WHERE program=? AND kind=? AND key=?", (self.program, kind, key)
        ).fetchone()
        if row:
            merged = {**json.loads(row["meta"] or "{}"), **(meta or {})}
            if meta and "params" in meta:
                merged["params"] = sorted(set(json.loads(row["meta"] or "{}").get("params", [])) | set(meta["params"]))
            self.b.db.execute("UPDATE assets SET last_seen=?, meta=? WHERE id=?", (now, json.dumps(merged), row["id"]))
            return int(row["id"])
        cur = self.b.db.execute(
            "INSERT INTO assets(program, kind, key, parent, in_scope, source, meta, first_seen, last_seen) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (self.program, kind, key, parent, int(in_scope), source, json.dumps(meta or {}), now, now),
        )
        return int(cur.lastrowid)

    def host(self, name: str, source: str) -> int:
        name = name.lower().rstrip(".")
        allowed = check(self.scope, name).allowed
        exists = self.b.db.execute(
            "SELECT 1 FROM assets WHERE program=? AND kind='host' AND key=?", (self.program, name)
        ).fetchone()
        hid = self._upsert("host", name, None, source, in_scope=allowed)
        if not allowed and not exists:
            self.new_out_of_scope.append(name)
        return hid

    def mark_blocked(self, name: str, reason: str, until: float) -> None:
        """Set a host aside until `until` (epoch seconds); the latest mark wins."""
        self.host(name, "gate")
        self._upsert("host", name.lower().rstrip("."), None, "gate", meta={"blocked": reason, "until": until})
        self.b.db.commit()

    def blocked(self) -> dict[str, tuple[str, float]]:
        """Hosts blocked right now: host -> (reason, until). An expired mark is ignored."""
        now, out = time.time(), {}
        for r in self.b.rows(
            "SELECT key, meta FROM assets WHERE program=? AND kind='host' AND meta LIKE '%\"blocked\"%'", self.program
        ):
            meta = json.loads(r["meta"] or "{}")
            if isinstance(until := meta.get("until"), int | float) and until > now:
                out[r["key"]] = (str(meta.get("blocked")), float(until))
        return out

    def origin(self, origin_: str, source: str) -> int:
        host = origin_.split("://", 1)[1].rsplit(":", 1)[0].strip("[]")
        return self._upsert(
            "origin",
            origin_,
            self.host(host, source),
            source,
            in_scope=check(self.scope, origin_.rsplit(":", 1)[0] + "/").allowed,
        )

    def endpoint(
        self, origin_: str, key: str, source: str, params: list[str] | None = None, status: int | None = None
    ) -> int:
        oid = self.origin(origin_, source)
        meta = {"params": sorted(set(params or []))} | ({"status": status} if status is not None else {})
        in_scope = check(self.scope, origin_ + "/").allowed  # an endpoint is in scope only where its origin is
        return self._upsert("endpoint", f"{origin_} {key}", oid, source, in_scope=in_scope, meta=meta)

    def tested(self, origin_: str, key: str, evidence: str, run_id: int | None) -> None:
        eid = self.endpoint(origin_, c.family(key), evidence)
        self.b.db.execute(
            "INSERT OR IGNORE INTO tests(asset_id, evidence, run_id, ts) VALUES (?,?,?,?)",
            (eid, evidence, run_id, time.time()),
        )

    def link(self, url: str, ref_kind: str, ref_id: int) -> None:
        if k := c.endpoint_key(url, "GET"):
            eid = self.endpoint(k[0], c.family(k[1]), ref_kind)
            self.b.db.execute(
                "INSERT OR IGNORE INTO asset_links(asset_id, ref_kind, ref_id) VALUES (?,?,?)", (eid, ref_kind, ref_id)
            )

    # ------------------------------------------------------------------ sync from the sandbox and the gate
    def sync(self, run_id: int | None) -> dict[str, int]:
        """The sandbox writes these files: every entry is checked, a malformed one is skipped (never fatal)."""
        d = paths.work_bh(self.program)
        n = {"endpoints": 0, "coverage": 0, "tests": 0, "skipped": 0}
        for e in c.read_jsonl(d / c.ENDPOINTS):
            o, key = _origin(e), _text(e, "key") if isinstance(e, dict) else None
            if not o or not key or c.STATIC_EXT.search(key) or not _typed_endpoint(e):
                n["skipped"] += isinstance(e, dict) and not c.STATIC_EXT.search(key or "")
                continue
            params = [p[:200] for p in e.get("params") or [] if isinstance(p, str)][:200]
            status = e.get("status") if _is_int(e.get("status")) else None
            self.endpoint(o, c.family(key), _text(e, "source") or "tool", params, status)
            n["endpoints"] += 1
        coverage = c.read_json(d / c.COVERAGE, {})
        for origin_, phases in (coverage if isinstance(coverage, dict) else {}).items():
            if not (o := c.origin(str(origin_))) or not isinstance(phases, dict):
                n["skipped"] += 1
                continue
            oid = self.origin(o, "tool")
            for phase, entry in phases.items():
                row = _coverage_row(phase, entry)
                if row is None:
                    n["skipped"] += 1
                    continue
                self.b.db.execute(
                    "INSERT INTO coverage(asset_id, phase, status, ts, raw) VALUES (?,?,?,?,?) "
                    "ON CONFLICT(asset_id, phase) DO UPDATE SET "
                    "status=excluded.status, ts=excluded.ts, raw=excluded.raw",
                    (oid, *row),
                )
                n["coverage"] += 1
        for t in c.read_jsonl(d / c.TOUCHED):
            if not isinstance(t, dict) or not isinstance(t.get("via"), str | None):
                continue
            if (o := _origin(t)) and (key := _text(t, "key")):
                self.tested(o, key, "tool" if t.get("via") != "manual" else "literal", run_id)
                n["tests"] += 1
        runs = self.b.run_ids(self.program)
        for f in self.b.new_lines(paths.flows_log(), f"assets-flows:{self.program}"):  # incremental: a cursor
            if f.get("run") not in runs or f.get("class") not in (None, "target"):
                continue
            url = f.get("url") if isinstance(f.get("url"), str) else ""
            if host := urlsplit(url).hostname:
                self.host(host, "gate")
            if k := c.endpoint_key(url, str(f.get("method", "GET"))):
                manual = MANUAL_UA.match(str(f.get("ua") or ""))
                if not manual and f.get("status") in _ABSENT:
                    continue  # a scanner's probe that found nothing (404, error) is not an endpoint of the target
                self.tested(k[0], k[1], "gate" if manual else "seen", f.get("run"))
                n["tests"] += bool(manual)
        self.b.db.commit()
        return n

    # ------------------------------------------------------------------ reads
    def surface(self, phases: tuple[str, ...]) -> tuple[dict, list, dict]:
        """Same shapes as bh.agent.contract._surface_data, from the board (the host's authority)."""
        eps, tested, seen_origins = {}, set(), set()
        for r in self.b.rows(
            "SELECT a.id, a.key, a.source, a.meta, (SELECT GROUP_CONCAT(DISTINCT t.evidence) FROM tests t "
            "WHERE t.asset_id=a.id) AS ev FROM assets a WHERE a.program=? AND a.kind='endpoint' AND a.in_scope=1",
            self.program,
        ):
            origin_, key = r["key"].split(" ", 1)
            meta = json.loads(r["meta"] or "{}")
            eps[(origin_, key)] = {"params": set(meta.get("params", [])), "sources": {r["source"] or "?"}}
            ev = set((r["ev"] or "").split(",")) - {""}
            if ev & {"gate", "seen"}:
                seen_origins.add(origin_)
            if "gate" in ev or (ev & _CLAIMS and "seen" in ev):
                tested.add((origin_, key))
        # An untested endpoint of a blocked host is set aside (neither counted nor listed): retrying it wastes turns.
        blocked = self.blocked()
        eps = {k: v for k, v in eps.items() if k in tested or urlsplit(k[0]).hostname not in blocked}
        untested = [(k, v) for k, v in eps.items() if k not in tested]
        untested.sort(key=c.frontier_order)
        cov: dict[str, dict] = {}
        for r in self.b.rows(
            "SELECT a.key, c.phase, c.status, c.ts FROM coverage c JOIN assets a ON a.id=c.asset_id WHERE a.program=?",
            self.program,
        ):
            status = r["status"] if r["key"] in seen_origins else "error: no traffic seen by the gate"
            cov.setdefault(r["key"], {})[r["phase"]] = {"status": status, "ts": r["ts"]}
        return eps, untested, cov

    def counts(self, phases: tuple[str, ...]) -> tuple[int, int]:
        eps, untested, cov = self.surface(phases)
        return len(eps) - len(untested), sum(c.phase_done(ph.get(p)) for ph in cov.values() for p in phases)

    def render(self, phases: tuple[str, ...], limit: int = 12) -> str:
        eps, untested, cov = self.surface(phases)
        oos = [
            r["key"]
            for r in self.b.rows(
                "SELECT key FROM assets WHERE program=? AND kind='host' AND in_scope=0 ORDER BY id DESC LIMIT 5",
                self.program,
            )
        ]
        lines = c.format_surface(eps, untested, cov, phases, limit).split("\n")
        for host, (reason, until) in self.blocked().items():
            mark = f"blocked ({reason}) until {time.strftime('%H:%M', time.localtime(until))}, do not retry"
            hits = [
                i for i, ln in enumerate(lines) if ln[:2] == "- " and urlsplit(ln[2:].split(": ")[0]).hostname == host
            ]
            for i in hits:
                lines[i] += f" · {mark}"
            if not hits:
                lines.append(f"- {host}: {mark}")
        if oos:
            lines.append("- discovered, NOT in scope (never touch): " + ", ".join(oos))
        return "\n".join(ln for ln in lines if ln)
