"""Missions (T17): one narrow objective per segment, drawn by code from the board, never by a model.

A mission is a dict {kind, surface, vuln_class, turns, skill, ref, pass, title}: `kind` one of KINDS, `surface` the
asset key of an endpoint (`<origin> METHOD route`), `F<a>+F<b>` for a chain, None for a map or a free hunt;
`turns` the segment's budget, set here and never by the agent; `ref` what the mission was drawn on, so that nothing
is drawn twice. The draw (`next`) reads the board only: the same board gives the same mission.

Order of the draw:
  1. prove: a candidate waiting for its proof, oldest first: a fact `CANDIDATE: ...`, or a typed test/prove intent
     closed `open_proof_gap`. Each one once.
  -  map: nothing in scope is mapped yet (no endpoint asset): at most MAP_TRIES times.
  -  free: one draw in FREE_EVERY (the 5th, the 10th...), so the whole board stays in sight.
  2. test: a (surface, class) pair never tested (no coverage_class row, no mem_items cell, never drawn), by value:
     `assets.Graph.score(asset_id)` when lot F's graph has it, else the order of the program's skills, then how
     strongly the endpoint calls for the class.
  3. test, second pass: a pair among the SECOND_PASS_TOP most valuable, settled once (one run wrote `clean` on it),
     with another skill than the first pass's.
  4. chain (T29): two findings verified, verified-evidence or inconclusive, a pair never drawn.
  5. free: nothing else left.

Budgets in turns (TURNS), clamped to [FLOOR, CEIL]. One extension at most, of half the budget and never past CEIL,
decided by the host (`extension_due`): the gate saw a new test on the mission's surface in this run, or an anchored
fact arrived within the last EXTENSION_RECENT_TURNS turns.

Shipped off: BH_MISSIONS=0 (the default) changes nothing in a segment.
"""

from __future__ import annotations

import json
import os
import re
import time

from bh import classes

ENV = "BH_MISSIONS"
KINDS = ("map", "test", "prove", "chain", "free")
TURNS = {"map": 15, "test": 40, "prove": 25, "chain": 30, "free": 50}
FLOOR, CEIL = 15, 80
EXTENSION_RECENT_TURNS = 10
FREE_EVERY = 5
MAP_TRIES = 2
SECOND_PASS_TOP = 10
CHAIN_STATUSES = ("verified", "verified-evidence", "inconclusive")
CHAIN_SKILL = "chaining"
MAP_SKILL = "api-surface-mapping"
PROVE_SKILL = "proof-package"
# The second pass on a pair settled once: another method on the same class, never the one of the first pass.
SECOND_SKILLS = {
    "idor": ("multi-tenant", "broken-access-control"),
    "broken-access-control": ("function-level-authz", "multi-tenant"),
    "function-level-authz": ("broken-access-control",),
    "multi-tenant": ("idor",),
    "mass-assignment": ("type-confusion",),
    "xss": ("postmessage",),
    "sqli": ("nosql-injection",),
    "nosql-injection": ("sqli",),
    "auth": ("jwt", "oauth-oidc"),
}
SECOND_DEFAULT = "business-logic"
TITLE_MAX = 160
_CANDIDATE = re.compile(r"^\s*CANDIDATE\s*:", re.I)
_CHAIN_TITLE = re.compile(r"^chain F(\d+)\+F(\d+)\b")


# ------------------------------------------------------------------ switch, schema, budgets
def setting(env=None) -> str:
    """BH_MISSIONS as a segment runs with it: "1" (missions) or "0" (the generalist segment, the default)."""
    env = os.environ if env is None else env
    return "1" if str(env.get(ENV, "0")).strip() == "1" else "0"


def enabled(env=None) -> bool:
    return setting(env) == "1"


def ensure(board) -> None:
    """runs.mission (the mission of the run, canonical JSON), idempotent."""
    have = {r["name"] for r in board.db.execute("PRAGMA table_info(runs)")}
    if "mission" not in have:
        board.db.execute("ALTER TABLE runs ADD COLUMN mission TEXT")
        board.db.commit()


def clamp(turns) -> int:
    return max(FLOOR, min(CEIL, int(turns)))


def budget(kind: str) -> int:
    return clamp(TURNS[kind])


def extension_turns(mission: dict | None) -> int:
    """Turns one extension adds: half the mission's budget, never past CEIL."""
    if not isinstance(mission, dict):
        return 0
    turns = clamp(mission.get("turns") or FLOOR)
    return max(0, min(turns // 2, CEIL - turns))


def dumps(mission: dict) -> str:
    return json.dumps(mission, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def make(kind: str, *, surface=None, vuln_class=None, skill=None, ref=None, **extra) -> dict:
    if kind not in KINDS:
        raise ValueError(f"unknown mission kind {kind!r}")
    return {
        "kind": kind,
        "surface": surface,
        "vuln_class": vuln_class,
        "turns": budget(kind),
        "skill": skill,
        "ref": ref,
        **extra,
    }


# ------------------------------------------------------------------ board reads
def _has_table(board, name: str) -> bool:
    return bool(board.rows("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", name))


def _cols(board, table: str) -> set[str]:
    return {r["name"] for r in board.db.execute(f"PRAGMA table_info({table})")}


def history(board, program: str) -> list[dict]:
    """The missions of this program's earlier runs, oldest first (a row that is not a mission dict is skipped)."""
    ensure(board)
    out = []
    for r in board.rows("SELECT mission FROM runs WHERE program=? AND mission IS NOT NULL ORDER BY id", program):
        try:
            m = json.loads(r["mission"])
        except (TypeError, ValueError):
            continue
        if isinstance(m, dict):
            out.append(m)
    return out


def _flat(text, n: int = TITLE_MAX) -> str:
    s = " ".join(str(text or "").split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _allowed_skills(scope) -> set[str]:
    """The skills a session on this program may load (the runner's allowed_skills, without its import)."""
    out = set()
    for s in classes.all_skills():
        if "scanners" in str(s.get("requires") or "") and not scope.scanners_on:
            continue
        out.add(str(s.get("name") or ""))
    return out


def _program_skills(scope) -> list[str]:
    try:
        return classes.program_skills(scope)
    except ValueError:  # a scope skill that does not exist: the runner refuses the segment before this matters
        return []


def candidates(board, program: str) -> list[dict]:
    """Leads waiting for their proof, oldest first: `CANDIDATE:` facts and typed test/prove intents closed
    `open_proof_gap` (a chain intent excepted: its pair is drawn as a chain)."""
    out = []
    fcols = _cols(board, "facts")
    endpoint = "endpoint" if "endpoint" in fcols else "NULL AS endpoint"
    vclass = "vuln_class" if "vuln_class" in fcols else "NULL AS vuln_class"
    for r in board.rows(
        f"SELECT id, title, {endpoint}, {vclass}, created FROM facts WHERE program=? AND kind='fact' ORDER BY id",
        program,
    ):
        if _CANDIDATE.match(r["title"] or ""):
            out.append(("fact", r))
    icols = _cols(board, "intents")
    if {"kind", "endpoint", "vuln_class", "outcome"} <= icols:
        for r in board.rows(
            "SELECT id, title, endpoint, vuln_class, created FROM intents WHERE program=? AND status='closed' "
            "AND outcome='open_proof_gap' AND kind IN ('test', 'prove') ORDER BY id",
            program,
        ):
            if not _CHAIN_TITLE.match(r["title"] or ""):
                out.append(("intent", r))
    out.sort(key=lambda kr: (kr[1]["created"] or 0, kr[0], kr[1]["id"]))
    return [
        {
            "ref": f"{kind}:{r['id']}",
            "endpoint": r["endpoint"],
            "vuln_class": r["vuln_class"],
            "title": _flat(r["title"]),
        }
        for kind, r in out
    ]


def chain_pairs(board, program: str) -> list[tuple[int, int]]:
    """(a, b), a < b, of this program's findings verified, verified-evidence or inconclusive."""
    ids = [
        r["id"]
        for r in board.rows(
            f"SELECT id FROM findings WHERE program=? AND status IN ({','.join('?' * len(CHAIN_STATUSES))}) "
            "ORDER BY id",
            program,
            *CHAIN_STATUSES,
        )
    ]
    return [(a, b) for i, a in enumerate(ids) for b in ids[i + 1 :]]


def chain_title(a: int, b: int) -> str:
    """The intent T29 adds for one pair: names the skill, says the chain has its own proof."""
    return f"chain F{a}+F{b}: load the skill {CHAIN_SKILL}; the chain gets its own proof.json"


def _endpoints(board, scope, now: float) -> list[dict]:
    """In-scope endpoint assets, those of a host set aside (WAF) left out: {id, key, endpoint, params}."""
    if not _has_table(board, "assets"):
        return []
    blocked = _blocked(board, scope.program, now)
    out = []
    for r in board.rows(
        "SELECT id, key, meta FROM assets WHERE program=? AND kind='endpoint' AND in_scope=1 ORDER BY id",
        scope.program,
    ):
        origin, _, label = (r["key"] or "").partition(" ")
        if not label:
            continue
        host = origin.split("://", 1)[-1].rsplit(":", 1)[0].strip("[]")
        if host in blocked:
            continue
        try:
            meta = json.loads(r["meta"] or "{}")
        except ValueError:
            meta = {}
        params = [p for p in (meta.get("params") or []) if isinstance(p, str)] if isinstance(meta, dict) else []
        out.append({"id": r["id"], "key": r["key"], "endpoint": label, "params": params})
    return out


def _blocked(board, program: str, now: float) -> set[str]:
    out = set()
    for r in board.rows(
        "SELECT key, meta FROM assets WHERE program=? AND kind='host' AND meta LIKE '%\"blocked\"%'", program
    ):
        try:
            meta = json.loads(r["meta"] or "{}")
        except ValueError:
            continue
        until = meta.get("until") if isinstance(meta, dict) else None
        if isinstance(until, int | float) and until > now:
            out.add(r["key"])
    return out


def _scorer(board, scope):
    """lot F's `Graph.score(asset_id) -> float`, None while the graph has none."""
    try:
        from bh.assets import Graph

        fn = getattr(Graph(board, scope), "score", None)
    except Exception:  # noqa: BLE001 (the order falls back on the program's skills)
        return None
    if not callable(fn):
        return None

    def score(asset_id: int) -> float:
        try:
            v = fn(asset_id)
            return float(v) if isinstance(v, int | float) and not isinstance(v, bool) else 0.0
        except Exception:  # noqa: BLE001
            return 0.0

    return score


def pairs(board, scope, now: float | None = None) -> list[dict]:
    """Every (endpoint, class) the surface calls for, in value order: {asset_id, surface, endpoint, vuln_class,
    skill, match}. A class the program excludes, or without a skill this session may load, is left out."""
    now = time.time() if now is None else now
    allowed = _allowed_skills(scope)
    excluded = {e for x in (scope.forbidden_vulns or ()) if (e := classes.exclusion(x))}
    order = {name: i for i, name in enumerate(_program_skills(scope))}
    class_order = {cls.id: i for i, cls in enumerate(classes.CLASSES)}
    score = _scorer(board, scope)
    out = []
    for ep in _endpoints(board, scope, now):
        key = re.sub(r"/(?=$| )", "/{id}", ep["endpoint"].split("?")[0])
        for cls in classes.CLASSES:
            if cls.id in excluded or (match := cls.matches(key, ep["params"])) <= 0:
                continue
            skill = classes.skill_for(cls.id)
            if skill is None or skill not in allowed:
                continue
            out.append(
                {
                    "asset_id": ep["id"],
                    "surface": ep["key"],
                    "endpoint": ep["endpoint"],
                    "vuln_class": cls.id,
                    "skill": skill,
                    "match": match,
                    "_rank": (
                        -(score(ep["id"]) if score else 0.0),
                        order.get(skill, len(order)),
                        -match,
                        ep["id"],
                        class_order[cls.id],
                    ),
                }
            )
    out.sort(key=lambda p: p["_rank"])
    for p in out:
        del p["_rank"]
    return out


def _cell_suffix(endpoint: str, vuln_class: str) -> str:
    """The end of a mem_items cell (`host|method route|class`) for one pair, lower case like bh.lineage.key."""
    method, _, route = endpoint.partition(" ")
    try:
        from bh.lineage import key

        return f"|{key.norm_route(method, route)}|{key.norm_class(vuln_class)}"
    except Exception:  # noqa: BLE001 (no lineage: the coverage table alone says what was tested)
        return f"|{endpoint.lower()}|{vuln_class.lower()}"


def coverage(board, program: str) -> dict[tuple[str, str], list[dict]]:
    """(endpoint, class) -> its coverage_class rows, oldest first."""
    if not _has_table(board, "coverage_class"):
        return {}
    out: dict[tuple[str, str], list[dict]] = {}
    for r in board.rows("SELECT * FROM coverage_class WHERE program=? ORDER BY ts, rowid", program):
        out.setdefault((r["endpoint"], r["vuln_class"]), []).append(dict(r))
    return out


def _mem_cells(board, program: str) -> set[str]:
    if not _has_table(board, "mem_items") or "cell" not in _cols(board, "mem_items"):
        return set()
    return {str(r["cell"] or "") for r in board.rows("SELECT DISTINCT cell FROM mem_items WHERE program=?", program)}


def _tried(cells: set[str], endpoint: str, vuln_class: str) -> bool:
    suffix = _cell_suffix(endpoint, vuln_class)
    return any(cell.endswith(suffix) for cell in cells)


def settled_once(rows: list[dict]) -> bool:
    """One run wrote on the pair, and its last word is `clean`."""
    return bool(rows) and len({r.get("run_id") for r in rows}) == 1 and rows[-1].get("outcome") == "clean"


# ------------------------------------------------------------------ the draw
def next(board, scope, now: float | None = None) -> dict | None:
    """The mission of the next segment on this program (see the module's docstring for the order)."""
    ensure(board)
    program = scope.program
    past = history(board, program)
    given = {m.get("ref") for m in past if m.get("ref")}
    allowed = _allowed_skills(scope)

    # 1. a candidate waiting for its proof
    for cand in candidates(board, program):
        if cand["ref"] in given:
            continue
        skill = classes.skill_for(cand["vuln_class"]) if cand["vuln_class"] else None
        skill = skill if skill in allowed else (PROVE_SKILL if PROVE_SKILL in allowed else None)
        return make(
            "prove",
            surface=cand["endpoint"],
            vuln_class=cand["vuln_class"],
            skill=skill,
            ref=cand["ref"],
            title=cand["title"],
        )

    now = time.time() if now is None else now
    every = pairs(board, scope, now)
    # nothing mapped yet
    if not every and not _endpoints(board, scope, now):
        if sum(1 for m in past if m.get("kind") == "map") < MAP_TRIES:
            return make("map", skill=MAP_SKILL if MAP_SKILL in allowed else None, ref=f"map:{len(past)}")
        return make("free", ref=f"free:{len(past)}")

    # one draw in FREE_EVERY is a free hunt
    if len(past) % FREE_EVERY == FREE_EVERY - 1:
        return make("free", ref=f"free:{len(past)}")

    cov = coverage(board, program)
    cells = _mem_cells(board, program)
    # 2. a pair never tested, by value
    for p in every:
        ref = f"pair:{p['endpoint']}|{p['vuln_class']}"
        if ref in given or (p["endpoint"], p["vuln_class"]) in cov or _tried(cells, p["endpoint"], p["vuln_class"]):
            continue
        return make("test", surface=p["surface"], vuln_class=p["vuln_class"], skill=p["skill"], ref=ref, **{"pass": 1})

    # 3. a second pass, another skill, on a valuable pair settled once
    for p in every[:SECOND_PASS_TOP]:
        ref = f"pair2:{p['endpoint']}|{p['vuln_class']}"
        if ref in given or not settled_once(cov.get((p["endpoint"], p["vuln_class"]), [])):
            continue
        first = skill_used(past, p) or p["skill"]
        other = [s for s in (*SECOND_SKILLS.get(p["vuln_class"], ()), SECOND_DEFAULT) if s in allowed and s != first]
        if other:
            return make(
                "test", surface=p["surface"], vuln_class=p["vuln_class"], skill=other[0], ref=ref, **{"pass": 2}
            )

    # 4. two findings the judge did not reject: a chain
    for a, b in chain_pairs(board, program):
        ref = f"chain:F{a}+F{b}"
        if ref not in given:
            return make("chain", surface=f"F{a}+F{b}", vuln_class="chain", skill=CHAIN_SKILL, ref=ref)

    # 5. nothing else: a free hunt
    return make("free", ref=f"free:{len(past)}")


def skill_used(past: list[dict], pair: dict) -> str | None:
    """The skill an earlier mission used on this pair, if a mission tested it."""
    ref = f"pair:{pair['endpoint']}|{pair['vuln_class']}"
    for m in reversed(past):
        if m.get("ref") == ref and m.get("skill"):
            return str(m["skill"])
    return None


# ------------------------------------------------------------------ the host's extension
def surface_endpoint(mission: dict | None) -> str | None:
    """ "METHOD route" of the mission's surface (an asset key or a label), None when it names no endpoint."""
    s = (mission or {}).get("surface")
    if not isinstance(s, str) or not s:
        return None
    if s.startswith(("http://", "https://")):
        return s.split(" ", 1)[1] if " " in s else None
    return s if re.match(r"^[A-Z]+ /", s) else None


def gate_new_test(board, program: str, mission: dict | None, run_id: int, logged: set[str] | None = None) -> bool:
    """The gate saw, in run `run_id`, a hand-made request on the mission's surface (any endpoint for a mission without
    one) that no earlier run had the gate see. `logged`: assets.gate_endpoints(run_id), read by the caller."""
    from bh import assets

    if (mission or {}).get("kind") == "chain":
        return False
    assets.ensure(board)
    seen = assets.gate_endpoints(run_id) if logged is None else logged
    target = surface_endpoint(mission)
    wanted = [target] if target else sorted(seen)
    for ep in wanted:
        if ep not in seen:
            continue
        earlier = board.rows(
            "SELECT 1 FROM tests t JOIN assets a ON a.id=t.asset_id WHERE a.program=? AND a.kind='endpoint' "
            "AND t.evidence='gate' AND t.run_id IS NOT NULL AND t.run_id<? "
            "AND substr(a.key, instr(a.key, ' ') + 1)=? LIMIT 1",
            program,
            run_id,
            ep,
        )
        if not earlier:
            return True
    return False


def extension_due(board, program: str, mission: dict | None, run_id: int, recent_grounded: int, **kw) -> bool:
    """The host extends a mission once: a new test the gate saw on its surface, or an anchored fact among the
    last EXTENSION_RECENT_TURNS turns (`recent_grounded`, counted by the runner when it ingests them)."""
    if not isinstance(mission, dict) or extension_turns(mission) <= 0:
        return False
    return recent_grounded > 0 or gate_new_test(board, program, mission, run_id, **kw)


__all__ = [
    "CEIL",
    "FLOOR",
    "KINDS",
    "TURNS",
    "budget",
    "chain_pairs",
    "chain_title",
    "clamp",
    "enabled",
    "ensure",
    "extension_due",
    "extension_turns",
    "history",
    "make",
    "next",
    "pairs",
    "setting",
]
