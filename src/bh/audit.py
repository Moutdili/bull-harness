"""Audit of a hunt against an oracle (T19): recall, false positives and cost per verified finding, on a lab whose
vulnerabilities are known.

The oracle is the list of planted vulnerabilities of a lab (`lab/bench/ANSWERS.md` for the bench). It lives on the
host only: never under a directory a container mounts as its /work (var/work: the hunter, var/judge: the judge,
var/audit/current: the code auditor), and `run_audit` refuses one that sits there. Nothing the agent wrote is a number
here: statuses are the host's verdicts (`findings.status`), costs are the runner's (`runs.cost_usd`,
`runs.verify_cost`), early stops and the setup digest are the runner's columns. The agent's words are used only to
say WHERE a finding is (its class, its URL, the method of its proof's attack), never whether it holds.

Matching is typed, never by words: a finding answers an oracle line when its class is the line's class
(`bh.classes.canonical` on both sides) and one of its routes is one of the line's routes. A route is a method and a
path template (`bh.agent.contract.endpoint_key` + `family`: /bookings/bk_6c49e125463f and /bookings/{ref} are one
route); a client-side route (`/#/join?...`) is its hash path, whatever the method. A finding whose method is unknown
(a bare URL, no proof) matches the line whatever its method; when two lines then fit, it is credited to one only
(the first not yet recalled), never to both.

`summary` aggregates several runs of a lab by setup digest (`runs.setup_sha256`). A board reset deletes the findings
of a lab: `run_audit` therefore keeps each result under var/measure/<program>/ (host only), and `summary` reads those
records for runs the board no longer holds.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from bh import paths
from bh.agent import contract as c
from bh.classes import BY_ID, canonical

VERIFIED = ("verified", "verified-evidence", "submitted")  # a submitted finding was verified first
RUN_COLUMNS = ("program", "setup_sha256", "early_stop", "cost_usd", "verify_cost")
FINDING_COLUMNS = ("id", "title", "status", "vuln_class", "url", "proof")
# a lab's default oracle, relative to BH_HOME (the repository); Juice Shop has none in the repository
ORACLES = {"lab-bench": Path("lab") / "bench" / "ANSWERS.md"}
SPA = "*"  # method of a client-side route: a page load, whatever the method

_ROW = re.compile(r"^\s*\|(.+)\|\s*$")
_TICK = re.compile(r"`([^`]+)`")
_ROUTE = re.compile(r"(?:([A-Z]{3,7})\s+)?(/\S*)")
_PLACEHOLDER = re.compile(r"\{[^}/]*\}")
_SEVERITY = frozenset(c.SEVERITIES)


class OracleError(ValueError):
    """The oracle cannot be used: unreadable, empty, or where a container could read it."""


# ---------------------------------------------------------------- routes
Route = tuple[str | None, str]  # (METHOD | None when unknown | SPA, path template)


def _template(path: str) -> str:
    """Path template of a route: oracle placeholders ({ref}, {id}) and id-like segments become {id}."""
    return c.path_key(_PLACEHOLDER.sub("0", path.split("?", 1)[0].split("#", 1)[0] or "/"))


def _spa(fragment: str) -> Route | None:
    """`#/rooms/3?x=1` -> (SPA, "#/rooms/{id}"); None when the fragment is no client route."""
    frag = fragment.lstrip("#")
    return (SPA, "#" + _template(frag)) if frag.startswith("/") else None


def route_of(value: str, method: str | None = None) -> Route | None:
    """The route an oracle cell names: `GET /api/x/{id}`, `/api/x`, `/#/join`. None for anything else (a parameter
    name, a value)."""
    m = _ROUTE.fullmatch(value.strip())
    if m is None:
        return None
    meth, path = m.group(1) or method, m.group(2)
    if path.startswith("/#"):
        return _spa(path[1:])
    k = c.family(f"{meth or 'GET'} {_template(path)}")
    return (meth.upper() if meth else None, k.split(" ", 1)[1])


def routes_of_url(value: object, method: str | None = None) -> list[Route]:
    """Routes of a finding's URL (`URL` or `METHOD URL`): its path through endpoint_key and family, plus its hash
    route when the fragment is one."""
    if not isinstance(value, str) or not value.strip():
        return []
    s = value.strip()
    if (m := re.fullmatch(r"([A-Za-z]{3,7})\s+(\S+)", s)) is not None:
        method, s = m.group(1).upper(), m.group(2)
    k = c.endpoint_key(s, method or "GET")
    if k is None:
        return []
    out: list[Route] = [(method, c.family(k[1]).split(" ", 1)[1])]
    try:
        frag = urlsplit(s).fragment
    except ValueError:
        frag = ""
    if (spa := _spa(frag)) is not None:
        out.append(spa)
    return out


def _proof_routes(proof: object) -> list[Route]:
    """Routes of the attack steps of a finding's proof.json (method known)."""
    try:
        doc = json.loads(proof) if isinstance(proof, str) else proof
    except ValueError:
        return []
    steps = doc.get("steps") if isinstance(doc, dict) else None
    out: list[Route] = []
    for st in steps if isinstance(steps, list) else []:
        if isinstance(st, dict) and st.get("role") == "attack" and isinstance(st.get("url"), str):
            out += routes_of_url(st["url"], str(st.get("method") or "GET").upper())
    return out


def finding_routes(f: dict) -> list[Route]:
    """The finding's routes: its URL's and its proof's attacks'. A path the proof gives with its method loses the
    URL's method-less copy (the proof says which method it is)."""
    routes = list(dict.fromkeys(routes_of_url(f.get("url")) + _proof_routes(f.get("proof"))))
    known = {p for m, p in routes if m is not None}
    return [(m, p) for m, p in routes if m is not None or p not in known]


def _same(a: Route, b: Route) -> bool:
    if a[1] != b[1]:
        return False
    return a[0] is None or b[0] is None or a[0] == b[0] or SPA in (a[0], b[0])


# ---------------------------------------------------------------- oracle
def _cells(line: str) -> list[str] | None:
    m = _ROW.match(line)
    return [x.strip() for x in m.group(1).split("|")] if m else None


def _markdown(text: str) -> list[dict]:
    """Rows of the bench's grid (lab/bench/ANSWERS.md): `| V<n> | `class` (variant) | routes | severity |` for a
    vulnerability, `| L<n> | `route` | why |` for a lure, and the classes named in the section of expected noise."""
    out: list[dict] = []
    section = ""
    for line in text.splitlines():
        if line.startswith("#"):
            section = line.lstrip("#").strip().lower()
            continue
        cells = _cells(line)
        if cells and re.fullmatch(r"V\d{1,3}", cells[0]) and len(cells) >= 4:
            klass = _TICK.search(cells[1])
            routes, markers = [], []
            for tok in _TICK.findall(cells[2]):
                r = route_of(tok)
                (routes if r else markers).append(r or tok)
            if klass is None or not routes:
                raise OracleError(f"oracle line {cells[0]}: a class and a route are required")
            sev = cells[3].strip("` ").lower()
            out.append(
                {
                    "id": cells[0],
                    "kind": "vuln",
                    "vuln_class": canonical(klass.group(1)),
                    "variant": re.sub(r"[`()]", "", cells[1].replace(klass.group(0), "")).strip() or None,
                    "routes": list(dict.fromkeys(routes)),
                    "markers": markers,
                    "severity": sev if sev in _SEVERITY else None,
                }
            )
        elif cells and re.fullmatch(r"L\d{1,3}", cells[0]) and len(cells) >= 2:
            routes = [r for r in (route_of(t) for t in _TICK.findall(cells[1])) if r]
            if routes:
                out.append({"id": cells[0], "kind": "lure", "vuln_class": None, "routes": routes, "markers": []})
        elif section.startswith("bruits attendus") or section.startswith("expected noise"):
            for tok in _TICK.findall(line):
                if (k := canonical(tok)) in BY_ID and k not in {o["vuln_class"] for o in out if o["kind"] == "noise"}:
                    out.append({"id": f"N-{k}", "kind": "noise", "vuln_class": k, "routes": [], "markers": []})
    return out


def _json_oracle(text: str) -> list[dict]:
    """The same entries as JSON: [{"id", "kind"?: vuln|lure|noise, "vuln_class", "routes": ["GET /x", ...],
    "markers"?, "severity"?}]."""
    doc = json.loads(text)
    if not isinstance(doc, list):
        raise OracleError("a JSON oracle is a list of entries")
    out = []
    for e in doc:
        if not isinstance(e, dict) or not isinstance(e.get("id"), str):
            raise OracleError("each oracle entry is an object with an id")
        kind = e.get("kind", "vuln")
        routes = [r for r in (route_of(str(x)) for x in e.get("routes") or []) if r]
        if kind not in ("vuln", "lure", "noise") or (kind != "noise" and not routes):
            raise OracleError(f"oracle entry {e['id']}: kind vuln|lure|noise, a route unless noise")
        if kind != "lure" and not e.get("vuln_class"):
            raise OracleError(f"oracle entry {e['id']}: a class is required")
        out.append(
            {
                "id": e["id"],
                "kind": kind,
                "vuln_class": canonical(str(e["vuln_class"])) if e.get("vuln_class") else None,
                "routes": routes,
                "markers": [str(m) for m in e.get("markers") or []],
                "severity": e.get("severity") if e.get("severity") in _SEVERITY else None,
            }
        )
    return out


def load_oracle(path: Path) -> list[dict]:
    """Entries of an oracle file: the bench's markdown grid, or the same entries as JSON (`.json`). Each entry:
    id, kind (vuln | lure | noise), vuln_class (canonical), routes [(METHOD | None | "*", template)], markers
    (parameters, fields), severity. Raises OracleError on a file without a vulnerability line."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise OracleError(f"cannot read the oracle {p.name}: {type(exc).__name__}") from None
    try:
        entries = _json_oracle(text) if p.suffix == ".json" else _markdown(text)
    except ValueError as exc:
        raise OracleError(str(exc)) from None
    if not any(e["kind"] == "vuln" for e in entries):
        raise OracleError(f"the oracle {p.name} lists no vulnerability")
    return entries


def mounted_dirs() -> list[Path]:
    """Host directories a container sees as its /work: an oracle there is readable by the hunter, the judge or the
    code auditor."""
    v = paths.var()
    return [v / "work", v / "judge", v / "audit" / "current"]


def check_oracle_path(oracle: Path) -> Path:
    """The oracle's real path; OracleError when it is (or links) under a directory a container mounts."""
    real = Path(oracle).resolve()
    for d in mounted_dirs():
        if real.is_relative_to(d.resolve()):
            raise OracleError(f"oracle refused: it sits under {d.relative_to(paths.home())}, mounted in a container")
    return real


def default_oracle(program: str) -> Path | None:
    rel = ORACLES.get(program)
    return paths.home() / rel if rel is not None and (paths.home() / rel).is_file() else None


# ---------------------------------------------------------------- one run
def _columns(board, table: str) -> set[str]:
    return {r["name"] for r in board.db.execute(f"PRAGMA table_info({table})")}


def _select(board, table: str, cols: tuple[str, ...], where: str, *args: Any) -> list[dict]:
    have = _columns(board, table)
    sel = ", ".join(k if k in have else f"NULL AS {k}" for k in cols)
    return [dict(r) for r in board.rows(f"SELECT {sel} FROM {table} WHERE {where}", *args)]


def _num(v: object) -> float:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else 0.0


def _candidates(f: dict, vulns: list[dict]) -> list[str]:
    klass = canonical(f.get("vuln_class") or "")
    routes = finding_routes(f)
    return [
        o["id"] for o in vulns if o["vuln_class"] == klass and any(_same(a, b) for a in routes for b in o["routes"])
    ]


def match(findings: list[dict], entries: list[dict]) -> dict[int, str | None]:
    """finding id -> the oracle vulnerability it is credited to (None: none). One finding, one line at most; a finding
    that fits several lines (method unknown) goes to the first one no other finding recalled yet."""
    vulns = [e for e in entries if e["kind"] == "vuln"]
    cands = {f["id"]: _candidates(f, vulns) for f in findings}
    out: dict[int, str | None] = {fid: (cs[0] if len(cs) == 1 else None) for fid, cs in cands.items()}
    recalled = {out[f["id"]] for f in findings if f.get("status") in VERIFIED and out[f["id"]]}
    for f in findings:
        cs = cands[f["id"]]
        if len(cs) > 1:
            pick = next((x for x in cs if x not in recalled), cs[0])
            out[f["id"]] = pick
            if f.get("status") in VERIFIED:
                recalled.add(pick)
    return out


def _lure(f: dict, entries: list[dict]) -> str | None:
    routes = finding_routes(f)
    return next(
        (e["id"] for e in entries if e["kind"] == "lure" and any(_same(a, b) for a in routes for b in e["routes"])),
        None,
    )


def _brief(f: dict) -> dict:
    return {k: f.get(k) for k in ("id", "title", "status", "vuln_class", "url")}


def evaluate(findings: list[dict], entries: list[dict]) -> dict:
    """The oracle's numbers over a set of findings (host statuses only)."""
    vulns = [e for e in entries if e["kind"] == "vuln"]
    noise = {e["vuln_class"] for e in entries if e["kind"] == "noise"}
    credit = match(findings, entries)
    by_status: dict[str, int] = {}
    for f in findings:
        st = f.get("status") or "?"
        by_status[st] = by_status.get(st, 0) + 1
    verified = [f for f in findings if f.get("status") in VERIFIED]
    recalled = sorted({credit[f["id"]] for f in verified if credit[f["id"]]}, key=lambda x: int(x[1:]))
    false_pos, noisy, lures, judge_fn, inconclusive = [], [], {}, [], []
    for f in findings:
        hit = credit[f["id"]]
        if hit is None and (lure := _lure(f, entries)) is not None:
            st = f.get("status") or "?"
            lures.setdefault(lure, {})[st] = lures.setdefault(lure, {}).get(st, 0) + 1
        if f.get("status") in VERIFIED and hit is None:
            entry = {**_brief(f), "lure": _lure(f, entries)}
            (noisy if canonical(f.get("vuln_class") or "") in noise else false_pos).append(entry)
        elif f.get("status") == "rejected" and hit is not None:
            judge_fn.append({**_brief(f), "oracle": hit})
        elif f.get("status") == "inconclusive" and hit is not None:
            inconclusive.append({**_brief(f), "oracle": hit})
    counted = len(verified) - len(noisy)
    return {
        "findings": dict(sorted(by_status.items())),
        "recall": round(len(recalled) / len(vulns), 4) if vulns else 0.0,
        "recalled": recalled,
        "oracle_size": len(vulns),
        "precision": round((counted - len(false_pos)) / counted, 4) if counted else None,
        "false_positives": false_pos,
        "noise": noisy,
        "missed": [
            {"id": e["id"], "vuln_class": e["vuln_class"], "routes": [f"{m or '?'} {p}" for m, p in e["routes"]]}
            for e in vulns
            if e["id"] not in recalled
        ],
        "lures": lures,
        "judge_false_negatives": judge_fn,
        "inconclusive": inconclusive,
        "verified": len(verified),
        "matches": {str(fid): hit for fid, hit in credit.items() if hit},
    }


def run_audit(board, run_id: int, oracle: Path, *, save: bool = True) -> dict:
    """The audit of one run (segment) against `oracle`: its findings by status, recall (oracle vulnerabilities found
    by a verified finding / their number), false positives (verified findings no oracle line explains, each listed),
    missed lines, cost (hunt + verification, USD), cost per verified finding, early stop and setup digest. A column
    the board lacks counts as None. `save`: keep the result under var/measure/<program>/ for `summary`."""
    real = check_oracle_path(oracle)
    entries = load_oracle(real)
    runs = _select(board, "runs", RUN_COLUMNS, "id=?", run_id)
    if not runs:
        raise ValueError(f"no run {run_id} on the board")
    run = runs[0]
    findings = _select(board, "findings", FINDING_COLUMNS, "run_id=? ORDER BY id", run_id)
    program = str(run["program"]).split("~", 1)[0]  # a reset archives a run's program as P~<date>
    result = {"run_id": run_id, "program": program, "oracle": real.name, **evaluate(findings, entries)}
    hunt, verify = _num(run["cost_usd"]), _num(run["verify_cost"])
    cost = round(hunt + verify, 4)
    result.update(
        cost_usd=cost,
        cost={"hunt": round(hunt, 4), "verify": round(verify, 4)},
        cost_per_verified=round(cost / result["verified"], 4) if result["verified"] else None,
        early_stop=run["early_stop"],
        setup_sha256=run["setup_sha256"],
    )
    if save:
        record(result)
    return result


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{round(x * 100)}%"


def render(result: dict) -> str:
    """The audit as text, one fact per line."""
    r = result
    out = [
        f"audit of run {r['run_id']} ({r.get('program')}) against {r.get('oracle')}"
        + (f" · setup {str(r['setup_sha256'])[:12]}" if r.get("setup_sha256") else ""),
        "findings: " + (", ".join(f"{k} {v}" for k, v in r["findings"].items()) or "none"),
        f"recall: {len(r['recalled'])}/{r['oracle_size']} ({_pct(r['recall'])})"
        + (f" · {', '.join(r['recalled'])}" if r["recalled"] else ""),
        f"precision: {_pct(r['precision'])} · false positives: {len(r['false_positives'])}",
    ]
    out += [
        f"  FP F{f['id']} [{f['status']}/{f['vuln_class']}] {f['title']} · {f['url'] or '-'}"
        + (f" (lure {f['lure']})" if f.get("lure") else "")
        for f in r["false_positives"]
    ]
    if r.get("noise"):
        out.append(f"expected noise (not counted): {', '.join(f'F{f["id"]} {f["vuln_class"]}' for f in r['noise'])}")
    if r["missed"]:
        out.append(
            "missed: " + "; ".join(f"{m['id']} {m['vuln_class']} {' | '.join(m['routes'])}" for m in r["missed"])
        )
    if r.get("lures"):
        out.append("lures hit: " + "; ".join(f"{k} {v}" for k, v in sorted(r["lures"].items())))
    if r.get("judge_false_negatives"):
        out.append(
            "rejected on an oracle line: " + ", ".join(f"F{f['id']}→{f['oracle']}" for f in r["judge_false_negatives"])
        )
    if r.get("inconclusive"):
        out.append(
            "inconclusive on an oracle line: " + ", ".join(f"F{f['id']}→{f['oracle']}" for f in r["inconclusive"])
        )
    cpv = r["cost_per_verified"]
    out.append(
        f"cost: ${r['cost_usd']:.2f} (hunt ${r['cost']['hunt']:.2f} + verify ${r['cost']['verify']:.2f})"
        f" · per verified finding: {'n/a' if cpv is None else f'${cpv:.2f}'}"
        f" · early stop: {'n/a' if r['early_stop'] is None else r['early_stop']}"
    )
    return "\n".join(out)


# ---------------------------------------------------------------- several runs
def measure_dir(program: str) -> Path:
    """var/measure/<program>: the audits kept on the host (never mounted)."""
    return paths.var() / "measure" / re.sub(r"[^A-Za-z0-9_.-]", "_", program)


def record(result: dict) -> Path:
    d = measure_dir(str(result.get("program") or "-"))
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"run-{int(result['run_id'])}.json"
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True))
    tmp.replace(p)
    return p


def _saved(program: str) -> dict[int, dict]:
    out = {}
    for f in sorted(measure_dir(program).glob("run-*.json")):
        try:
            doc = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(doc, dict) and isinstance(doc.get("run_id"), int) and doc.get("program") == program:
            out[doc["run_id"]] = doc
    return out


def summary(board, program: str, *, setup_sha256: str | None = None, oracle: Path | None = None) -> dict:
    """Several runs of a lab, grouped by setup digest: mean recall per run, recall of the group's findings together,
    false positives passed by the judge, cost per verified finding. Runs on the board are audited now against
    `oracle` (default: the lab's, ORACLES); runs a reset removed come from the records `run_audit` kept.
    `setup_sha256`: a prefix of the digest."""
    live_ids = sorted(board.run_ids(program))
    results = _saved(program)
    if live_ids:
        oracle = oracle or default_oracle(program)
        if oracle is None:
            raise OracleError(f"no oracle for {program}: pass one")
        for rid in live_ids:
            results[rid] = run_audit(board, rid, oracle, save=False)
    groups: dict[str, dict] = {}
    for rid in sorted(results):
        r = results[rid]
        setup = r.get("setup_sha256") or "-"
        if setup_sha256 and not str(setup).startswith(setup_sha256):
            continue
        g = groups.setdefault(
            setup,
            {
                "setup": setup,
                "runs": 0,
                "recalls": [],
                "recalled": set(),
                "oracle_size": 0,
                "false_positives": 0,
                "verified": 0,
                "cost_usd": 0.0,
                "early_stop": 0,
                "findings": {},
            },
        )
        g["runs"] += 1
        g["recalls"].append(float(r.get("recall") or 0.0))
        g["recalled"] |= set(r.get("recalled") or [])
        g["oracle_size"] = max(g["oracle_size"], int(r.get("oracle_size") or 0))
        g["false_positives"] += len(r.get("false_positives") or [])
        g["verified"] += int(r.get("verified") or 0)
        g["cost_usd"] += _num(r.get("cost_usd"))
        g["early_stop"] += int(_num(r.get("early_stop")))
        for st, n in (r.get("findings") or {}).items():
            g["findings"][st] = g["findings"].get(st, 0) + int(n)
    out = []
    for g in groups.values():
        n = g.pop("recalls")
        recalled = sorted(g.pop("recalled"), key=lambda x: int(x[1:]) if x[1:].isdigit() else 0)
        g.update(
            recall_mean=round(sum(n) / len(n), 4) if n else 0.0,
            recall_union=round(len(recalled) / g["oracle_size"], 4) if g["oracle_size"] else 0.0,
            recalled=recalled,
            cost_usd=round(g["cost_usd"], 4),
            cost_per_verified=round(g["cost_usd"] / g["verified"], 4) if g["verified"] else None,
            findings=dict(sorted(g["findings"].items())),
        )
        out.append(g)
    return {"program": program, "runs": sum(g["runs"] for g in out), "groups": sorted(out, key=lambda g: g["setup"])}
