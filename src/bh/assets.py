"""Asset graph of a program, kept by the host (plan v2, step 3; replaces the scattered surface).

  host ──< origin ──< endpoint            (assets, kind + key, parent)
            │            └── tests        (who tested it: gate-observed hand request, builtin, literal URL)
            └── coverage                  (recon / crawl / content / scan ... per origin)
  any asset ──< anchors >── fact | finding (asset_links)

Authority: the gate's observations (flows tagged with the run, hand-made User-Agents) rank above what
the sandbox writes (endpoints.jsonl, coverage.json, touched.jsonl can be edited by the agent; they feed
the map, they never widen the scope). Every host is checked against the hard scope when it enters the
graph: an out-of-scope host is kept as such (in_scope=0) and raises a scope-question todo, never a target.
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
"""
# User-Agents of hand-made requests (curl, PoC scripts). Builtins (katana, ffuf, nuclei, sqlmap...) differ.
MANUAL_UA = re.compile(r"^(curl|wget|python-requests|python-urllib|httpie|xh|node-fetch|axios|undici)/", re.I)
EVIDENCE_RANK = {"gate": 3, "tool": 2, "literal": 1}  # gate-observed is authoritative


def _text(e: dict, k: str) -> str | None:
    v = e.get(k)
    return v[:2000] if isinstance(v, str) and v else None


def _origin(e) -> str | None:
    """A sandbox-written origin, normalized (scheme://host:port), or None when it is not one."""
    return c.origin(e["origin"]) if isinstance(e, dict) and isinstance(e.get("origin"), str) else None


def ensure(board: Board) -> None:
    board.db.executescript(SCHEMA)


class Graph:
    def __init__(self, board: Board, scope: Scope):
        ensure(board)
        self.b, self.scope, self.program = board, scope, scope.program
        self.new_out_of_scope: list[str] = []

    # ------------------------------------------------------------------ upserts
    def _upsert(
        self, kind: str, key: str, parent: int | None, source: str, in_scope: bool = True, meta: dict | None = None
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
            self.b.add_todo(
                "scope-question",
                f"{name} discovered, not in scope",
                f"found by {source}; add it to the scope file only if the program lists it",
                program=self.program,
                dedup=f"{self.program}:oos-host:{name}",
            )
        return hid

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
        return self._upsert("endpoint", f"{origin_} {key}", oid, source, meta=meta)

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
            if not o or not key or c.STATIC_EXT.search(key):
                n["skipped"] += isinstance(e, dict) and not c.STATIC_EXT.search(key or "")
                continue
            params = (
                [p for p in e.get("params") or [] if isinstance(p, str)] if isinstance(e.get("params"), list) else []
            )
            status = e.get("status") if isinstance(e.get("status"), int) else None
            self.endpoint(o, c.family(key), _text(e, "source") or "tool", params, status)
            n["endpoints"] += 1
        coverage = c.read_json(d / c.COVERAGE, {})
        for origin_, phases in (coverage if isinstance(coverage, dict) else {}).items():
            if not (o := c.origin(str(origin_))) or not isinstance(phases, dict):
                n["skipped"] += 1
                continue
            oid = self.origin(o, "tool")
            for phase, entry in phases.items():
                if not isinstance(entry, dict):
                    n["skipped"] += 1
                    continue
                self.b.db.execute(
                    "INSERT INTO coverage(asset_id, phase, status, ts, raw) VALUES (?,?,?,?,?) "
                    "ON CONFLICT(asset_id, phase) DO UPDATE SET "
                    "status=excluded.status, ts=excluded.ts, raw=excluded.raw",
                    (oid, phase, entry.get("status"), entry.get("ts"), entry.get("raw")),
                )
                n["coverage"] += 1
        for t in c.read_jsonl(d / c.TOUCHED):
            if (o := _origin(t)) and (key := _text(t, "key")):
                self.tested(o, key, "tool" if t.get("via") != "manual" else "literal", run_id)
                n["tests"] += 1
        runs = self.b.run_ids(self.program)
        for f in c.read_jsonl(paths.flows_log()):
            if f.get("run") in runs and f.get("class") in (None, "target") and MANUAL_UA.match(f.get("ua") or ""):
                if k := c.endpoint_key(f.get("url", ""), f.get("method", "GET")):
                    self.tested(k[0], k[1], "gate", f.get("run"))
                    n["tests"] += 1
            elif f.get("run") in runs and f.get("class") in (None, "target"):
                host = urlsplit(f.get("url", "")).hostname
                if host:
                    self.host(host, "gate")
        self.b.db.commit()
        return n

    # ------------------------------------------------------------------ reads
    def surface(self, phases: tuple[str, ...]) -> tuple[dict, list, dict]:
        """Same shapes as bh.agent.contract._surface_data, from the board (the host's authority)."""
        eps, tested = {}, set()
        for r in self.b.rows(
            "SELECT a.id, a.key, a.source, a.meta, (SELECT COUNT(*) FROM tests t WHERE t.asset_id=a.id) AS n "
            "FROM assets a WHERE a.program=? AND a.kind='endpoint' AND a.in_scope=1",
            self.program,
        ):
            origin_, key = r["key"].split(" ", 1)
            meta = json.loads(r["meta"] or "{}")
            eps[(origin_, key)] = {"params": set(meta.get("params", [])), "sources": {r["source"] or "?"}}
            if r["n"]:
                tested.add((origin_, key))
        untested = [(k, v) for k, v in eps.items() if k not in tested]
        untested.sort(
            key=lambda kv: (-len(kv[1]["params"]), not re.search(r"/(api|rest|graphql|v\d)/", kv[0][1]), kv[0][1])
        )
        cov: dict[str, dict] = {}
        for r in self.b.rows(
            "SELECT a.key, c.phase, c.status, c.ts FROM coverage c JOIN assets a ON a.id=c.asset_id WHERE a.program=?",
            self.program,
        ):
            cov.setdefault(r["key"], {})[r["phase"]] = {"status": r["status"], "ts": r["ts"]}
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
        block = c.format_surface(eps, untested, cov, phases, limit)
        if oos:
            block += "\n- discovered, NOT in scope (never touch, a human decides): " + ", ".join(oos)
        return block
