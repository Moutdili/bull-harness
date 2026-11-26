"""`bh stats`: what the analysis between two phases reads (L3, wave W2).

From the columns of `runs` and `findings` only, grouped by phase and by setup (runs.setup_sha256): runs, cost (hunt
and verification), findings by status, cost per verified finding, early stops (runs.early_stop), gate denials
(runs.gate_denied), friction (runs.friction) and quota (runs.quota). A column the board does not have yet counts as
zero; a division by zero is "n/a". No column is added here.

The keys of `summary()` are a contract (wave W4 extends this module with the platform outcomes, accepted and paid,
without renaming them): runs, cost_usd, findings, cost_per_verified, early_stop, gate_denied, friction, quota.
"""

from __future__ import annotations

import json

NA = "n/a"
VERIFIED = ("verified", "submitted")  # a submitted finding was verified first
KEYS = ("runs", "cost_usd", "findings", "cost_per_verified", "early_stop", "gate_denied", "friction", "quota")
RUN_COLUMNS = ("phase", "setup_sha256", "cost_usd", "verify_cost", "early_stop", "gate_denied", "friction", "quota")
NO_PHASE, NO_SETUP = "-", "-"


def _columns(board, table: str) -> set[str]:
    return {r["name"] for r in board.db.execute(f"PRAGMA table_info({table})")}


def _num(v) -> float:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else 0.0


def _json(v) -> dict:
    if not isinstance(v, str) or not v:
        return {}
    try:
        doc = json.loads(v)
    except ValueError:
        return {}
    return doc if isinstance(doc, dict) else {}


def _empty() -> dict:
    return {
        "runs": 0,
        "cost_usd": {"hunt": 0.0, "verify": 0.0, "total": 0.0},
        "findings": {},
        "cost_per_verified": NA,
        "early_stop": 0,
        "gate_denied": 0,
        "friction": {"runs": 0, "challenges_extra": 0, "browser_429": 0},
        "quota": {"runs": 0, "sent": 0, "spent": 0},
    }


def _add_run(acc: dict, r: dict) -> None:
    acc["runs"] += 1
    acc["cost_usd"]["hunt"] += _num(r.get("cost_usd"))
    acc["cost_usd"]["verify"] += _num(r.get("verify_cost"))
    acc["early_stop"] += int(_num(r.get("early_stop")))
    acc["gate_denied"] += int(_num(r.get("gate_denied")))
    if fr := _json(r.get("friction")):
        acc["friction"]["runs"] += 1
        acc["friction"]["challenges_extra"] += int(_num(fr.get("challenges_extra")))
        acc["friction"]["browser_429"] += int(_num(fr.get("browser_429")))
    if qu := _json(r.get("quota")):
        acc["quota"]["runs"] += 1
        acc["quota"]["sent"] += int(_num(qu.get("sent")))
        acc["quota"]["spent"] += 1 if qu.get("spent") is True else 0


def _close(acc: dict) -> dict:
    c = acc["cost_usd"]
    c["hunt"], c["verify"] = round(c["hunt"], 4), round(c["verify"], 4)
    c["total"] = round(c["hunt"] + c["verify"], 4)
    verified = sum(n for s, n in acc["findings"].items() if s in VERIFIED)
    acc["cost_per_verified"] = round(c["total"] / verified, 4) if verified else NA
    acc["findings"] = dict(sorted(acc["findings"].items()))
    return acc


def summary(board, *, program: str | None = None, phase: str | None = None, setup: str | None = None) -> dict:
    """Totals under the contract keys, plus `groups`: one entry per (phase, setup) with the same keys. `setup`
    matches a prefix of runs.setup_sha256. Findings count in the group of the run that recorded them."""
    rcols = _columns(board, "runs")
    sel = ", ".join(["id", "program"] + [c if c in rcols else f"NULL AS {c}" for c in RUN_COLUMNS])
    where, args = [], []
    if program:
        where, args = [*where, "program=?"], [*args, program]
    if phase and "phase" in rcols:
        where, args = [*where, "phase=?"], [*args, phase]
    elif phase:
        where.append("0")  # no phase column: no run belongs to a phase
    if setup and "setup_sha256" in rcols:
        where, args = [*where, "setup_sha256 LIKE ?"], [*args, f"{setup}%"]
    elif setup:
        where.append("0")
    runs = [
        dict(r)
        for r in board.rows(f"SELECT {sel} FROM runs" + (f" WHERE {' AND '.join(where)}" if where else ""), *args)
    ]

    total, groups = _empty(), {}

    def group(r: dict) -> dict:
        key = (r.get("phase") or NO_PHASE, r.get("setup_sha256") or NO_SETUP)
        if key not in groups:
            groups[key] = {"phase": key[0], "setup": key[1], **_empty()}
        return groups[key]

    by_run = {}
    for r in runs:
        _add_run(total, r)
        _add_run(group(r), r)
        by_run[r["id"]] = r
    fcols = _columns(board, "findings")
    if {"status", "run_id"} <= fcols and by_run:
        fsql, fargs = "SELECT run_id, status, COUNT(*) AS n FROM findings", []
        if program and "program" in fcols:
            fsql, fargs = fsql + " WHERE program=?", [program]
        for f in board.rows(fsql + " GROUP BY run_id, status", *fargs):
            r = by_run.get(f["run_id"])
            if r is None:
                continue
            st = f["status"] or "?"
            for acc in (total, group(r)):
                acc["findings"][st] = acc["findings"].get(st, 0) + f["n"]
    out = _close(total)
    out["groups"] = [_close(groups[k]) for k in sorted(groups)]
    return out


def _cell(v) -> str:
    if isinstance(v, float):
        return f"{v:.2f}"
    return str(v)


def table(s: dict) -> str:
    """The summary as a text table: one line per (phase, setup), then the total."""
    head = (
        "phase",
        "setup",
        "runs",
        "hunt $",
        "verify $",
        "findings",
        "$/verified",
        "early",
        "denied",
        "friction",
        "quota",
    )

    def row(label: tuple[str, str], a: dict) -> tuple[str, ...]:
        f = ", ".join(f"{k} {n}" for k, n in a["findings"].items()) or "0"
        fr = a["friction"]
        qu = a["quota"]
        return (
            label[0],
            label[1][:12],
            _cell(a["runs"]),
            _cell(a["cost_usd"]["hunt"]),
            _cell(a["cost_usd"]["verify"]),
            f,
            _cell(a["cost_per_verified"]),
            _cell(a["early_stop"]),
            _cell(a["gate_denied"]),
            f"+{fr['challenges_extra']} ch / {fr['browser_429']} 429" if fr["runs"] else "-",
            f"{qu['sent']} sent / {qu['spent']} spent" if qu["runs"] else "-",
        )

    lines = [row((g["phase"], g["setup"]), g) for g in s.get("groups", [])]
    lines.append(row(("total", ""), s))
    widths = [max(len(x[i]) for x in [head, *lines]) for i in range(len(head))]
    fmt = "  ".join(f"{{:{w}}}" for w in widths)
    return "\n".join(fmt.format(*x).rstrip() for x in [head, *lines])
