"""`bh stats`: what the analysis between two phases reads (L3, waves W2 and W4).

From the columns of `runs` and `findings` only, grouped by phase and by setup (runs.setup_sha256): runs, cost (hunt
and verification), findings by status, cost per verified finding, early stops (runs.early_stop), gate denials
(runs.gate_denied), friction (runs.friction) and quota (runs.quota). A column the board does not have yet counts as
zero; a division by zero is "n/a". summary() adds no column.

The keys of `summary()` are a contract: runs, cost_usd, findings, cost_per_verified, early_stop, gate_denied,
friction, quota (W2). W4 adds, without renaming them: outcomes, cost_per_accepted, cost_per_paid,
verified_to_accepted, bounty_total.

W4 also keeps here:
- the platform outcome Mio types after the triage (`bh outcome`, the UI's button): `ensure()` adds its columns,
  `set_outcome()` is the one writer. The outcome only ever comes from Mio; the judge never sees it;
- the streak alert (L10): STREAK outcomes in a row on a program that are neither accepted nor paid. A line and a
  proposal, never a parking;
- the checklist before a submission (L1): internal duplicates, keywords to search by hand in the program's
  published reports, the replay reminder, the root cause, the rules' reading date. Nothing is sent anywhere;
- the one-off PoC screenshot (D12): `poc_shot(program, fid)`, host only, never during a challenge or while the
  operator has the screen, never mounted in a container, never given to the judge or the agent.
"""

from __future__ import annotations

import base64
import calendar
import json
import math
import os
import re
import sys
import time
from pathlib import Path

NA = "n/a"
VERIFIED = ("verified", "verified-evidence", "submitted")  # a submitted finding was verified first
KEYS = ("runs", "cost_usd", "findings", "cost_per_verified", "early_stop", "gate_denied", "friction", "quota")
OUTCOME_KEYS = ("outcomes", "cost_per_accepted", "cost_per_paid", "verified_to_accepted", "bounty_total")
RUN_COLUMNS = ("phase", "setup_sha256", "cost_usd", "verify_cost", "early_stop", "gate_denied", "friction", "quota")
NO_PHASE, NO_SETUP = "-", "-"

# ------------------------------------------------------------------ outcomes (L4)
OUTCOMES = ("accepted", "paid", "duplicate", "informative", "na")
ACCEPTED = ("accepted", "paid")  # a paid finding was accepted first
UNPAID = ("duplicate", "informative", "na")  # closed without a bounty
OUTCOME_STATUSES = ("verified", "verified-evidence", "submitted")
OUTCOME_COLUMNS = (("outcome", "TEXT"), ("bounty", "REAL"), ("outcome_ts", "REAL"), ("outcome_note", "TEXT"))
BOUNTY_MAX = 10_000_000.0
NOTE_MAX = 1000
STREAK = 5  # L10: outcomes in a row neither accepted nor paid before the alert


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
        "outcomes": {},
        "cost_per_accepted": NA,
        "cost_per_paid": NA,
        "verified_to_accepted": NA,
        "bounty_total": 0.0,
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


def _ratio(a: float, b: float):
    return round(a / b, 4) if b else NA


def _close(acc: dict) -> dict:
    c = acc["cost_usd"]
    c["hunt"], c["verify"] = round(c["hunt"], 4), round(c["verify"], 4)
    c["total"] = round(c["hunt"] + c["verify"], 4)
    verified = sum(n for s, n in acc["findings"].items() if s in VERIFIED)
    acc["cost_per_verified"] = _ratio(c["total"], verified)
    acc["findings"] = dict(sorted(acc["findings"].items()))
    o = acc["outcomes"]
    accepted, paid = sum(o.get(k, 0) for k in ACCEPTED), o.get("paid", 0)
    acc["cost_per_accepted"] = _ratio(c["total"], accepted)
    acc["cost_per_paid"] = _ratio(c["total"], paid)
    acc["verified_to_accepted"] = _ratio(accepted, verified)
    acc["bounty_total"] = round(acc["bounty_total"], 2)
    acc["outcomes"] = {k: o[k] for k in OUTCOMES if o.get(k)}
    return acc


def summary(board, *, program: str | None = None, phase: str | None = None, setup: str | None = None) -> dict:
    """Totals under the contract keys, plus `groups`: one entry per (phase, setup) with the same keys. `setup`
    matches a prefix of runs.setup_sha256. Findings (and their outcomes) count in the group of the run that recorded
    them."""
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
        oc = "outcome" if "outcome" in fcols else "NULL"
        bo = "bounty" if "bounty" in fcols else "NULL"
        fsql, fargs = f"SELECT run_id, status, {oc} AS outcome, {bo} AS bounty FROM findings", []
        if program and "program" in fcols:
            fsql, fargs = fsql + " WHERE program=?", [program]
        for f in board.rows(fsql, *fargs):
            r = by_run.get(f["run_id"])
            if r is None:
                continue
            st = f["status"] or "?"
            for acc in (total, group(r)):
                acc["findings"][st] = acc["findings"].get(st, 0) + 1
                if f["outcome"] in OUTCOMES:
                    acc["outcomes"][f["outcome"]] = acc["outcomes"].get(f["outcome"], 0) + 1
                    acc["bounty_total"] += _num(f["bounty"])
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
        "outcomes",
        "$/accepted",
        "$/paid",
        "bounty",
        "early",
        "denied",
        "friction",
        "quota",
    )

    def row(label: tuple[str, str], a: dict) -> tuple[str, ...]:
        f = ", ".join(f"{k} {n}" for k, n in a["findings"].items()) or "0"
        o = ", ".join(f"{k} {n}" for k, n in a.get("outcomes", {}).items()) or "-"
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
            o,
            _cell(a.get("cost_per_accepted", NA)),
            _cell(a.get("cost_per_paid", NA)),
            _cell(a.get("bounty_total", 0.0)),
            _cell(a["early_stop"]),
            _cell(a["gate_denied"]),
            f"+{fr['challenges_extra']} ch / {fr['browser_429']} 429" if fr["runs"] else "-",
            f"{qu['sent']} sent / {qu['spent']} spent" if qu["runs"] else "-",
        )

    lines = [row((g["phase"], g["setup"]), g) for g in s.get("groups", [])]
    lines.append(row(("total", ""), s))
    widths = [max(len(x[i]) for x in [head, *lines]) for i in range(len(head))]
    fmt = "  ".join(f"{{:{w}}}" for w in widths)
    out = "\n".join(fmt.format(*x).rstrip() for x in [head, *lines])
    rate = s.get("verified_to_accepted", NA)
    return out + f"\nverified -> accepted: {rate if rate == NA else f'{rate:.0%}'}"


# ------------------------------------------------------------------ outcome: columns and the one writer
def ensure(board) -> None:
    """findings.outcome, findings.bounty, findings.outcome_ts, findings.outcome_note (idempotent)."""
    have = _columns(board, "findings")
    for col, typ in OUTCOME_COLUMNS:
        if col not in have:
            board.db.execute(f"ALTER TABLE findings ADD COLUMN {col} {typ}")
    board.db.commit()


def _bounty(v) -> float | None:
    if v is None or v == "":
        return None
    if isinstance(v, bool):
        raise ValueError("bounty: a number")
    try:
        x = float(v)
    except (TypeError, ValueError):
        raise ValueError("bounty: a number") from None
    if not math.isfinite(x) or not 0 <= x <= BOUNTY_MAX:
        raise ValueError(f"bounty: a number within [0, {BOUNTY_MAX:g}]")
    return round(x, 2)


def set_outcome(board, fid: int, outcome: str, bounty=None, note: str = "") -> dict:
    """Record the platform's outcome of a finding, as Mio read it after the triage: `bh outcome` and the UI's
    button both come here. Only a verified, verified-evidence or submitted finding gets one. The outcome is
    retroactive: the program's credit ledger is computed again. Raises KeyError (no such finding) or ValueError."""
    if isinstance(fid, bool) or not isinstance(fid, int):
        raise ValueError("finding id: an integer")
    outcome = str(outcome or "").strip().lower()
    if outcome not in OUTCOMES:
        raise ValueError(f"outcome: one of {', '.join(OUTCOMES)}")
    amount = _bounty(bounty)
    if amount and outcome in UNPAID:
        raise ValueError(f"a bounty on a finding closed {outcome}")
    if not isinstance(note, str):
        raise ValueError("note: a text")
    if len(note) > NOTE_MAX:
        raise ValueError(f"note: at most {NOTE_MAX} characters")
    ensure(board)
    rows = board.rows("SELECT id, program, status FROM findings WHERE id=?", fid)
    if not rows:
        raise KeyError(f"finding F{fid}")
    if rows[0]["status"] not in OUTCOME_STATUSES:
        raise ValueError(
            f"F{fid} is {rows[0]['status']}: only a {', '.join(OUTCOME_STATUSES)} finding gets a platform outcome"
        )
    ts = time.time()
    board.db.execute(
        "UPDATE findings SET outcome=?, bounty=?, outcome_ts=?, outcome_note=? WHERE id=?",
        (outcome, amount, ts, note.strip(), fid),
    )
    board.db.commit()
    program = rows[0]["program"]
    try:
        from bh.lineage import score

        ledger: int | str = score.compute(board, program)
    except Exception as exc:  # noqa: BLE001 - the outcome is stored; the ledger is computed again at the next close
        ledger = f"not recomputed ({type(exc).__name__})"
    return {"ok": True, "finding": fid, "program": program, "outcome": outcome, "bounty": amount, "ledger": ledger}


# ------------------------------------------------------------------ L10: the streak alert
def streaks(board, program: str | None = None, n: int = STREAK) -> list[dict]:
    """Programs whose last `n` outcomes (by outcome_ts) are all neither accepted nor paid."""
    if not {"outcome", "outcome_ts", "program"} <= _columns(board, "findings"):
        return []
    sql = "SELECT program, outcome FROM findings WHERE outcome IS NOT NULL"
    args: list = []
    if program:
        sql, args = sql + " AND program=?", [program]
    last: dict[str, list[str]] = {}
    for r in board.rows(sql + " ORDER BY outcome_ts DESC, id DESC", *args):
        seen = last.setdefault(r["program"], [])
        if len(seen) < n:
            seen.append(r["outcome"])
    out = []
    for prog, outs in sorted(last.items()):
        if len(outs) == n and not any(o in ACCEPTED for o in outs):
            out.append({"program": prog, "outcomes": {k: outs.count(k) for k in OUTCOMES if k in outs}})
    return out


def alert_lines(board, program: str | None = None, n: int = STREAK) -> list[str]:
    """One line per program over the streak, with the proposal to park it. Nothing is parked here."""
    return [
        f"ALERT {s['program']}: the last {n} outcomes were neither accepted nor paid "
        f"({', '.join(f'{k} {v}' for k, v in s['outcomes'].items())}); platforms punish noise: consider parking "
        f"{s['program']} (nothing was parked)"
        for s in streaks(board, program, n)
    ]


# ------------------------------------------------------------------ L1: before a submission
_KEY = re.compile(r"[^A-Za-z0-9 ._:/{}\\\-]")  # the backslash: escape_invisible's \u{XXXX} stays readable
_METHOD = re.compile(r"[A-Z]{3,7}")
TO_SUBMIT = ("verified", "verified-evidence")
OPEN_REPORT = ("submitted",)


def _key(s, n: int = 80) -> str:
    """A hunter-derived key for Mio's screen: invisible characters shown, anything but key characters dropped."""
    from bh.text import escape_invisible

    s = _KEY.sub("?", escape_invisible(str(s or "")))
    return s if len(s) <= n else s[: n - 1] + "…"


def _scopes() -> dict[str, object]:
    """program -> scope, for every scope file that loads."""
    from bh import paths
    from bh.scope import ScopeError, load_scope

    out: dict[str, object] = {}
    for f in sorted(paths.scopes_dir().rglob("*.yaml")):
        try:
            s = load_scope(f)
        except (ScopeError, OSError):
            continue
        out.setdefault(s.program, s)
    return out


def _platform(program: str, scopes: dict) -> str:
    s = scopes.get(program)
    if s is not None:
        return str(getattr(s, "platform", "") or "")
    return program.split("-", 1)[0] if "-" in program else ""


def _mechanism(f: dict) -> str:
    """How the proof works, from the host's view of it: the attack step's method and whether it crosses identities;
    an observation proof says so. Keys only, never the hunter's words."""
    if f.get("status") == "verified-evidence" or (f.get("observation") and not f.get("proof")):
        return "observation (canary seen on the other side)"
    try:
        proof = json.loads(f.get("proof") or "{}")
    except (TypeError, ValueError):
        proof = {}
    steps = [s for s in (proof.get("steps") or []) if isinstance(s, dict)] if isinstance(proof, dict) else []
    attack = [s for s in steps if s.get("role") == "attack"]
    if not attack:
        return "?"
    methods = sorted({m for s in attack if (m := str(s.get("method") or "GET").upper()) and _METHOD.fullmatch(m)})
    owners = {str(s.get("as")) for s in steps if s.get("role") == "setup" and s.get("as")}
    actors = {str(s.get("as")) for s in attack if s.get("as")}
    if not actors:
        who = "no session"
    elif owners and not owners & actors:
        who = "cross-identity"
    else:
        who = "same identity"
    return f"{'/'.join(methods) or '?'} {who}"


def root_cause(f: dict) -> tuple[str, str, str]:
    """(class, component, mechanism) of a finding: the canonical class, the cell its URL sits on (origin and path
    family) and the proof's mechanism."""
    from bh.classes import canonical
    from bh.lineage.score import cell_of_url

    cls = canonical(f.get("vuln_class") or "") or "?"
    o, fam = cell_of_url(f.get("url"))
    return _key(cls, 40), _key(" ".join(x for x in (o, fam) if x) or "?", 120), _mechanism(f)


def _dedupe(board, f: dict, programs: list[str]) -> tuple[str, list[dict]]:
    """Internal duplicates of `f` on `programs`: by verify.dedupe_key (lot C) when it exists, else verify.duplicate_of
    on each program. Returns (method, rows)."""
    try:
        from bh import verify
    except Exception:  # noqa: BLE001
        return "unavailable", []
    marks = ",".join("?" * len(programs))
    others = [
        dict(r)
        for r in board.rows(
            f"SELECT * FROM findings WHERE program IN ({marks}) AND id<>? AND status NOT IN ('rejected') ORDER BY id",
            *programs,
            f["id"],
        )
    ]
    keyfn = getattr(verify, "dedupe_key", None)
    if keyfn is not None:
        try:
            mine = keyfn(f)
        except Exception:  # noqa: BLE001
            mine = None
        if mine:
            hits = []
            for o in others:
                try:
                    if keyfn(o) == mine:
                        hits.append(o)
                except Exception:  # noqa: BLE001 - one odd row says nothing of the others
                    continue
            return "verify.dedupe_key", hits
    dup = getattr(verify, "duplicate_of", None)
    if dup is None:
        return "unavailable", []
    hits, seen = [], set()
    for p in programs:
        try:
            d = dup(board, {**f, "program": p})
        except Exception:  # noqa: BLE001
            continue
        if d is not None and d not in seen:
            seen.add(d)
            hits += [o for o in others if o["id"] == d]
    return "verify.duplicate_of", hits


def _rules_line(program: str, created: float | None) -> str:
    """When the program's rules were last read, whether a page changed since the finding (bh.rules, W2), whether a
    run could start on them. Read from the host's files only: nothing is fetched here."""
    try:
        from bh import rules
    except Exception:  # noqa: BLE001
        return "program rules: bh.rules unavailable; read the program page by hand"
    try:
        d = rules.rules_dir(program)
        st = json.loads((d / "state.json").read_text(encoding="utf-8")) if (d / "state.json").is_file() else {}
    except (OSError, ValueError):
        st = {}
    reads = [u.get("read") for u in (st.get("urls") or {}).values() if isinstance(u, dict)]
    reads = [x for x in reads if isinstance(x, (int, float))]
    when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(min(reads))) if reads else "never"
    changed = "unknown"
    try:
        snaps = sorted(p.stem for p in d.glob("*.txt") if not p.name.startswith("."))
        stamps = [calendar.timegm(time.strptime(s, "%Y-%m-%dT%H%M%SZ")) for s in snaps]
        if created is not None and stamps:
            changed = "yes (`bh rules diff " + program + "`)" if any(t > created for t in stamps[1:]) else "no"
    except (OSError, ValueError):
        pass
    try:
        ok, why = rules.fresh(program)
        fresh = "yes" if ok else f"no: {why}"
    except Exception as exc:  # noqa: BLE001
        fresh = f"unknown ({type(exc).__name__})"
    return (
        f"program rules: last read {when}; a page changed since the finding: {changed}; fresh: {fresh}. Read them "
        f"again (`bh rules check <scope>`) and check the asset is listed: a confirmed bug is not paid otherwise"
    )


def checklist(board, fid: int, fence=None) -> list[str]:
    """What Mio checks before submitting finding `fid` (L1). Keys derived from the hunter's class and URL go through
    `fence` (the CLI's untrusted-text fence; default: escaped and filtered to key characters). Nothing here sends
    anything anywhere: the published reports are searched by Mio, by hand."""
    wrap = fence or (lambda s: s)
    rows = board.rows("SELECT * FROM findings WHERE id=?", fid)
    if not rows:
        return []
    f = dict(rows[0])
    program = f["program"]
    scopes = _scopes()
    platform = _platform(program, scopes)
    programs = sorted(
        {program}
        | {p for p, s in scopes.items() if platform and getattr(s, "platform", "") == platform}
        | {
            r["program"]
            for r in board.rows("SELECT DISTINCT program FROM findings")
            if platform and _platform(r["program"], scopes) == platform
        }
    )
    has_outcome = "outcome" in _columns(board, "findings")
    out = [f"Before submitting F{fid} ({program}) — nothing below is sent anywhere:"]

    how, dups = _dedupe(board, f, programs)
    if dups:
        listed = ", ".join(
            f"F{d['id']} ({', '.join(x for x in (d['program'], d['status'], d.get('outcome')) if x)})"
            for d in dups[:10]
        )
        out.append(f" (a) internal duplicates ({how}, {platform or program} programs): {listed}")
    else:
        out.append(f" (a) internal duplicates ({how}, {platform or program} programs): none")

    cls, component, mechanism = root_cause(f)
    family = component.split(" ", 1)[-1] if " " in component else component
    product = program.split("-", 1)[1] if "-" in program else program
    out.append(
        f" (b) search the program's published reports and hacktivity by hand, with: class {wrap(cls)}, route family "
        f"{wrap(family)}, product {_key(product, 40)}"
    )
    out.append(" (c) replay the proof yourself right before sending (the triager PoC, a new canary): state moves")

    submitted = board.rows(
        f"SELECT * FROM findings WHERE program IN ({','.join('?' * len(programs))}) AND id<>? AND status IN "
        f"({','.join('?' * len(OPEN_REPORT))})",
        *programs,
        fid,
        *OPEN_REPORT,
    )
    same = [dict(o) for o in submitted if root_cause(dict(o)) == (cls, component, mechanism)]
    opened = [o for o in same if not (has_outcome and o.get("outcome"))]
    cause = f"class {wrap(cls)} · component {wrap(component)} · mechanism {mechanism}"
    if same:
        listed = ", ".join(f"F{o['id']} ({o['program']}, {o.get('outcome') or 'open'})" for o in same)
        line = f" (d) root cause: {cause}; already submitted on this cause: {listed}"
        if opened:
            line += (
                f". Two open reports on one cause ({', '.join('F' + str(o['id']) for o in opened)} and F{fid}): the "
                "program closes one as a duplicate; add this one to the open report instead"
            )
        out.append(line)
    else:
        out.append(f" (d) root cause: {cause}; no submitted finding shares it")

    out.append(" (e) " + _rules_line(program, f.get("created")))
    if "copilot" in program.lower():
        out.append(' (f) Copilot: the report says "the test ran on copilot.com"')
    return out


def submit_fid(todo: dict) -> int | None:
    """The finding a submit todo is about: its dedup key `<program>:submit:F<n>`, else its title `F<n> ...`."""
    if m := re.search(r":submit:F(\d{1,12})$", todo.get("dedup") or ""):
        return int(m.group(1))
    if m := re.match(r"F(\d{1,12})\b", todo.get("title") or ""):
        return int(m.group(1))
    return None


# ------------------------------------------------------------------ D12: the one-off PoC screenshot
SHOT_NOTE = "review before sending"
_PROGRAM = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}")
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def poc_path(program: str, fid: int) -> Path:
    from bh import paths

    return paths.lineage_dir() / program / "poc" / f"F{int(fid)}.png"


def _say(msg: str) -> None:
    sys.stderr.write(f"poc-shot: {msg}\n")


def poc_shot(
    program: str,
    fid: int,
    *,
    board=None,
    scope=None,
    call=None,
    running=None,
) -> Path | None:
    """After a finding turns verified or verified-evidence on a scope with the persistent browser: one screenshot
    of bh-browser's page, stored under var/lineage/<program>/poc/F<n>.png (0600, host only: never mounted in a
    container, never given to the judge or the agent), and the submit todo cites it ("review before sending").

    Never during a pending human challenge, never while the operator has the screen (checked here on the status,
    and again by the controller's `shot` op); no gesture on the page, nothing injected in it. Never raises: None
    when there is no screenshot, with one line on stderr. `board`, `scope`, `call`, `running`: tests."""
    try:
        return _poc_shot(program, fid, board=board, scope=scope, call=call, running=running)
    except Exception as exc:  # noqa: BLE001 - the screenshot is a convenience, never a failure of the verification
        _say(f"F{fid}: no screenshot ({type(exc).__name__}: {str(exc)[:120]})")
        return None


def _poc_shot(program, fid, *, board, scope, call, running) -> Path | None:
    if not isinstance(program, str) or not _PROGRAM.fullmatch(program) or isinstance(fid, bool):
        _say("bad program or finding id")
        return None
    fid = int(fid)
    from bh.board import Board

    own = board is None
    board = board if board is not None else Board()
    try:
        rows = board.rows("SELECT status FROM findings WHERE id=? AND program=?", fid, program)
        if not rows or rows[0]["status"] not in TO_SUBMIT:
            _say(f"F{fid}: not a verified finding of {program}")
            return None
        if scope is None:
            scope = _scopes().get(program)
        if scope is None or not scope.support_hosts("passthrough"):
            return None  # no persistent browser on this scope: nothing to shoot, nothing to say
        from bh import stack
        from bh.browser_service import host as bhost

        is_up = running if running is not None else (lambda: stack.container_running(stack.BROWSER_CTR))
        if not is_up():
            _say(f"F{fid}: {stack.BROWSER_CTR} is not running")
            return None
        st = (call or bhost.call)({"op": "status"})
        if st.get("code") != 200:
            _say(f"F{fid}: status of the browser: {st.get('error', 'no reply')}")
            return None
        if (st.get("challenge") or {}).get("pending"):
            _say(f"F{fid}: a human challenge is pending: no screenshot")
            return None
        if st.get("human_viewing") or st.get("human_watching"):
            _say(f"F{fid}: the operator has the screen: no screenshot")
            return None
        if st.get("program") != program:
            _say(f"F{fid}: the browser holds {st.get('program') or 'no program'}, not {program}")
            return None
        dest = poc_path(program, fid)
        out = bhost.shot(dest, call_=call)
        if not out.get("ok"):
            _say(f"F{fid}: {out.get('error', 'no screenshot')}")
            return None
        _cite(board, program, fid, dest)
        return dest
    finally:
        if own:
            board.db.close()


def _cite(board, program: str, fid: int, dest: Path) -> None:
    """The submit todo of the finding names the screenshot, once."""
    line = f"PoC screenshot: {dest} ({SHOT_NOTE})"
    for t in board.rows("SELECT id, detail FROM todos WHERE kind='submit' AND dedup=?", f"{program}:submit:F{fid}"):
        if line not in (t["detail"] or ""):
            board.db.execute(
                "UPDATE todos SET detail=? WHERE id=?", (((t["detail"] or "") + "\n" + line).strip()[:4000], t["id"])
            )
    board.db.commit()


def write_png(dest: Path, b64: str) -> int:
    """Decode a screenshot and write it 0600 (directory 0700), atomically. Raises ValueError if it is not a PNG."""
    data = base64.b64decode(b64 or "", validate=True)
    if not data.startswith(PNG_MAGIC):
        raise ValueError("the screenshot is not a PNG")
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(dest.parent, 0o700)
    tmp = dest.with_name(f".{dest.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.replace(tmp, dest)
    return len(data)
