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

Priority (T42): Graph.score(asset_id) is a sum of observed signals (SCORE_WEIGHTS), computed by this code from the
board's columns and the gate's log, never by a model; the untested list is ordered by it (equal scores keep the older
order, contract.frontier_order) and the agent is shown the rank, never the number. Clones (Graph.clusters): origins
whose home page, as the gate saw it answered (GET / 2xx, the flow file the gate wrote), has the same 64-bit simhash
within CLONE_HAMMING bits; one origin per cluster stays in the list, the others are shown as "clone of".
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections import Counter
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

# T42: what an endpoint is worth testing first. One weight per observed signal; the score is their weighted sum.
# identity: the gate logged the endpoint asked under one of our identities (behind the login); cross_account_open: no
# coverage of a cross-account class the gate saw (coverage_class.gate_seen = 1); api: contract.API_PATH; write: the
# method is a write; id_in_path: the route holds `{id}`; param: per parameter (PARAMS_CAP at most); login: the sandbox
# said its origin shows a login form (bh-recon) AND the gate saw traffic to that origin; new: first seen since the
# start of the program's latest run. Mio decides the weights; the orchestrator measures the order they give.
SCORE_WEIGHTS: dict[str, float] = {
    "identity": 4.0,
    "cross_account_open": 2.0,
    "api": 1.5,
    "write": 1.5,
    "id_in_path": 1.5,
    "param": 0.25,
    "login": 1.0,
    "new": 1.0,
}
PARAMS_CAP = 8
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
CROSS_ACCOUNT = ("idor", "broken-access-control")  # classes.canonical ids of the between-accounts classes
# Clones: simhash of the words of the home page's body (64 bits); this many differing bits or fewer = same cluster.
CLONE_HAMMING = 3
SIMHASH_BITS = 64
SIMHASH_MIN_WORDS = 8  # a body of fewer words (an empty page, "Not Found") gives no fingerprint: no cluster
_BODY_WORD = re.compile(r"\w+")


def _text(e: dict, k: str) -> str | None:
    v = e.get(k)
    return v[:2000] if isinstance(v, str) and v else None


def _origin(e) -> str | None:
    """A sandbox-written origin, normalized (scheme://host:port), or None when it is not one."""
    return c.origin(e["origin"]) if isinstance(e, dict) and isinstance(e.get("origin"), str) else None


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def simhash(text: str) -> int | None:
    """64-bit simhash of the words of `text` (lower case, each word weighted by its count, blake2b-64 per word);
    None when it holds fewer than SIMHASH_MIN_WORDS words."""
    words = _BODY_WORD.findall(str(text or "").lower())
    if len(words) < SIMHASH_MIN_WORDS:
        return None
    acc = [0] * SIMHASH_BITS
    for word, n in Counter(words).items():
        h = int.from_bytes(hashlib.blake2b(word.encode(), digest_size=SIMHASH_BITS // 8).digest(), "big")
        for i in range(SIMHASH_BITS):
            acc[i] += n if (h >> i) & 1 else -n
    return sum(1 << i for i in range(SIMHASH_BITS) if acc[i] > 0)


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def _home_body(f: dict) -> str | None:
    """The response body of a flows.jsonl line that is the gate's GET / of a target answered 2xx, read from the flow
    file the gate wrote (paths.flow_file); None for any other line, or when the file is gone or unreadable."""
    if f.get("method") != "GET" or not _is_int(f.get("status")) or not 200 <= f["status"] < 300:
        return None
    fid = f.get("id")
    if not isinstance(fid, str) or not c.FLOW_ID_RE.fullmatch(fid):
        return None
    try:
        doc = json.loads(paths.flow_file(fid).read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    resp = doc.get("response") if isinstance(doc, dict) else None
    body = resp.get("body") if isinstance(resp, dict) else None
    return body if isinstance(body, str) else None


def _typed_endpoint(e: dict) -> bool:
    """Every field of an endpoints.jsonl entry has the type SQL and the graph expect (M4): a dict or a list where a
    string is expected drops the entry, it never raises."""
    return (
        isinstance(e.get("source"), str | None)
        and (e.get("params") is None or isinstance(e.get("params"), list))
        and (e.get("status") is None or _is_int(e.get("status")))
        and (e.get("login_form") is None or isinstance(e.get("login_form"), bool))
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

    def origin(self, origin_: str, source: str, meta: dict | None = None) -> int:
        host = origin_.split("://", 1)[1].rsplit(":", 1)[0].strip("[]")
        return self._upsert(
            "origin",
            origin_,
            self.host(host, source),
            source,
            in_scope=check(self.scope, origin_.rsplit(":", 1)[0] + "/").allowed,
            meta=meta,
        )

    def endpoint(
        self,
        origin_: str,
        key: str,
        source: str,
        params: list[str] | None = None,
        status: int | None = None,
        extra: dict | None = None,
    ) -> int:
        oid = self.origin(origin_, source)
        meta = {"params": sorted(set(params or []))} | ({"status": status} if status is not None else {})
        in_scope = check(self.scope, origin_ + "/").allowed  # an endpoint is in scope only where its origin is
        return self._upsert("endpoint", f"{origin_} {key}", oid, source, in_scope=in_scope, meta=meta | (extra or {}))

    def tested(self, origin_: str, key: str, evidence: str, run_id: int | None, extra: dict | None = None) -> None:
        eid = self.endpoint(origin_, c.family(key), evidence, extra=extra)
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
            if isinstance(e.get("login_form"), bool):  # bh-recon's word: believed only where the gate saw the origin
                self.origin(o, "tool", meta={"login_form": e["login_form"]})
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
                ident = f.get("identity")
                extra = {"identity_seen": True} if isinstance(ident, str) and ident else None
                self.tested(k[0], k[1], "gate" if manual else "seen", f.get("run"), extra)
                n["tests"] += bool(manual)
                if k[1] == "GET /" and (body := _home_body(f)) is not None:
                    h = simhash(body)  # the latest home page the gate saw wins; a page too short clears it
                    self.origin(k[0], "gate", meta={"simhash": None if h is None else f"{h:016x}"})
        self.b.db.commit()
        return n

    # ------------------------------------------------------------------ score and clones (T42)
    def _score_context(self) -> dict:
        """What every endpoint's signals are read against, once per call: the origins the gate saw traffic to, the
        origins with a login form, the start of the latest run, the endpoints whose cross-account coverage the gate
        saw."""
        seen = {
            r["key"]
            for r in self.b.rows(
                "SELECT DISTINCT o.key FROM assets e JOIN tests t ON t.asset_id=e.id JOIN assets o ON o.id=e.parent "
                "WHERE e.program=? AND e.kind='endpoint' AND t.evidence IN ('gate','seen')",
                self.program,
            )
        }
        login = set()
        for r in self.b.rows("SELECT id, key, meta FROM assets WHERE program=? AND kind='origin'", self.program):
            if json.loads(r["meta"] or "{}").get("login_form") is True and r["key"] in seen:
                login.add(r["id"])
        last = self.b.rows("SELECT MAX(started) AS t FROM runs WHERE program=?", self.program)[0]["t"]
        marks = ",".join("?" * len(CROSS_ACCOUNT))
        covered = {
            r["endpoint"]
            for r in self.b.rows(
                f"SELECT DISTINCT endpoint FROM coverage_class WHERE program=? AND vuln_class IN ({marks}) "
                "AND CAST(gate_seen AS INTEGER)=1",
                self.program,
                *CROSS_ACCOUNT,
            )
        }
        return {"login": login, "last_run": last, "covered": covered}

    @staticmethod
    def _signals_of(row, ctx: dict) -> dict[str, float]:
        """The observed signals of one endpoint row (id, key, parent, meta, first_seen), as counts (0/1, or the
        number of parameters)."""
        _, label = row["key"].split(" ", 1)
        method, _, route = label.partition(" ")
        meta = json.loads(row["meta"] or "{}")
        params = meta.get("params") if isinstance(meta.get("params"), list) else []
        last = ctx["last_run"]
        return {
            "identity": float(meta.get("identity_seen") is True),
            "cross_account_open": float(label not in ctx["covered"]),
            "api": float(bool(c.API_PATH.search(route))),
            "write": float(method.upper() in WRITE_METHODS),
            "id_in_path": float("{id}" in route),
            "param": float(min(len(params), PARAMS_CAP)),
            "login": float(row["parent"] in ctx["login"]),
            "new": float(last is not None and float(row["first_seen"]) >= float(last)),
        }

    @staticmethod
    def _weigh(signals: dict[str, float]) -> float:
        return float(sum(SCORE_WEIGHTS[k] * v for k, v in signals.items()))

    def signals(self, asset_id: int) -> dict[str, float]:
        """The signals of an endpoint of this program ({} for any other asset)."""
        rows = self.b.rows(
            "SELECT id, key, parent, meta, first_seen FROM assets WHERE id=? AND program=? AND kind='endpoint'",
            asset_id,
            self.program,
        )
        return self._signals_of(rows[0], self._score_context()) if rows else {}

    def score(self, asset_id: int) -> float:
        """T42: the weighted sum of an endpoint's observed signals (SCORE_WEIGHTS). An origin scores its best in-scope
        endpoint, a host its best origin; any other id, or an asset of another program, scores 0.0. Deterministic:
        the same board gives the same number."""
        rows = self.b.rows("SELECT kind FROM assets WHERE id=? AND program=?", asset_id, self.program)
        if not rows:
            return 0.0
        kind, ctx = rows[0]["kind"], self._score_context()
        if kind == "endpoint":
            return self._weigh(self.signals(asset_id))
        if kind == "origin":
            where, args = "e.parent=?", (asset_id,)
        elif kind == "host":
            where, args = "e.parent IN (SELECT id FROM assets WHERE parent=? AND kind='origin')", (asset_id,)
        else:
            return 0.0
        eps = self.b.rows(
            f"SELECT e.id, e.key, e.parent, e.meta, e.first_seen FROM assets e WHERE e.program=? "
            f"AND e.kind='endpoint' AND e.in_scope=1 AND {where}",
            self.program,
            *args,
        )
        return max((self._weigh(self._signals_of(r, ctx)) for r in eps), default=0.0)

    def clusters(self) -> dict[str, list[str]]:
        """T42: origins (in scope) whose home page the gate saw answered with nearly the same words (simhash within
        CLONE_HAMMING bits, linked transitively). {representative: [its clones, sorted]}, clusters of two or more
        only; the representative is the cluster's origin first entered in the graph. An origin whose home page the
        gate never saw (or saw too short) is in no cluster."""
        prints: list[tuple[int, str, int]] = []
        for r in self.b.rows(
            "SELECT id, key, meta FROM assets WHERE program=? AND kind='origin' AND in_scope=1 ORDER BY id",
            self.program,
        ):
            h = json.loads(r["meta"] or "{}").get("simhash")
            if isinstance(h, str) and re.fullmatch(r"[0-9a-f]{16}", h):
                prints.append((int(r["id"]), r["key"], int(h, 16)))
        parent = list(range(len(prints)))

        def find(i: int) -> int:
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        for i in range(len(prints)):
            for j in range(i + 1, len(prints)):
                if hamming(prints[i][2], prints[j][2]) <= CLONE_HAMMING:
                    a, b = find(i), find(j)
                    parent[max(a, b)] = min(a, b)  # the lower index (the older origin) stays the root
        groups: dict[int, list[int]] = {}
        for i in range(len(prints)):
            groups.setdefault(find(i), []).append(i)
        return {
            prints[root][1]: sorted(prints[i][1] for i in members if i != root)
            for root, members in sorted(groups.items())
            if len(members) > 1
        }

    def clone_of(self) -> dict[str, str]:
        """clone origin -> the representative of its cluster."""
        return {m: rep for rep, members in self.clusters().items() for m in members}

    # ------------------------------------------------------------------ reads
    def surface(self, phases: tuple[str, ...]) -> tuple[dict, list, dict]:
        """Same shapes as bh.agent.contract._surface_data, from the board (the host's authority). The untested list is
        ordered by score (Graph.score), then by contract.frontier_order; the untested endpoints of a clone origin
        (Graph.clusters) leave it, as those of a blocked host do."""
        eps, tested, seen_origins, scores = {}, set(), set(), {}
        ctx = self._score_context()
        for r in self.b.rows(
            "SELECT a.id, a.key, a.source, a.meta, a.parent, a.first_seen, (SELECT GROUP_CONCAT(DISTINCT t.evidence) "
            "FROM tests t WHERE t.asset_id=a.id) AS ev FROM assets a WHERE a.program=? AND a.kind='endpoint' "
            "AND a.in_scope=1",
            self.program,
        ):
            origin_, key = r["key"].split(" ", 1)
            meta = json.loads(r["meta"] or "{}")
            eps[(origin_, key)] = {"params": set(meta.get("params", [])), "sources": {r["source"] or "?"}}
            scores[(origin_, key)] = self._weigh(self._signals_of(r, ctx))
            ev = set((r["ev"] or "").split(",")) - {""}
            if ev & {"gate", "seen"}:
                seen_origins.add(origin_)
            if "gate" in ev or (ev & _CLAIMS and "seen" in ev):
                tested.add((origin_, key))
        # An untested endpoint of a blocked host is set aside (neither counted nor listed): retrying it wastes turns.
        # So is one of a clone origin: its cluster's representative stands for it.
        blocked, clones = self.blocked(), self.clone_of()
        eps = {
            k: v
            for k, v in eps.items()
            if k in tested or (urlsplit(k[0]).hostname not in blocked and k[0] not in clones)
        }
        untested = [(k, v) for k, v in eps.items() if k not in tested]
        untested.sort(key=lambda it: (-scores[it[0]], *c.frontier_order(it)))
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
        # the rank, never the score: "  - #1 POST /api/..." (the list is in score order)
        rank = 0
        for i, ln in enumerate(lines):
            if ln.startswith("  - ") and rank < len(untested):
                rank += 1
                lines[i] = f"  - #{rank} {ln[4:]}"
        for host, (reason, until) in self.blocked().items():
            mark = f"blocked ({reason}) until {time.strftime('%H:%M', time.localtime(until))}, do not retry"
            hits = [
                i for i, ln in enumerate(lines) if ln[:2] == "- " and urlsplit(ln[2:].split(": ")[0]).hostname == host
            ]
            for i in hits:
                lines[i] += f" · {mark}"
            if not hits:
                lines.append(f"- {host}: {mark}")
        for clone, rep in sorted(self.clone_of().items()):
            mark = f"clone of {rep} (same home page): test {rep}, its untested routes stand for this one"
            hits = [i for i, ln in enumerate(lines) if ln[:2] == "- " and ln[2:].split(": ")[0] == clone]
            for i in hits:
                lines[i] += f" · {mark}"
            if not hits:
                lines.append(f"- {clone}: {mark}")
        if oos:
            lines.append("- discovered, NOT in scope (never touch): " + ", ".join(oos))
        return "\n".join(ln for ln in lines if ln)
