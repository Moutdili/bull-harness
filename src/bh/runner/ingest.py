"""Turn what the sandbox and the gate wrote into board rows.

Read offsets live in the board (host side), never in the sandbox, so the agent cannot
replay or hide its own notes.
"""

from __future__ import annotations

import contextlib
import json
import re
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

from bh import paths, redact
from bh.agent import contract as c
from bh.agent import proof
from bh.board import Board
from bh.board.db import FINDING_FIELDS
from bh.classes import canonical
from bh.scope import Scope
from bh.text import one_line

AUTH_THRESHOLD = 3  # 401 answers on one host (and identity) before it counts as a wall, not a probe
# session-dead events with reason 401, on distinct routes of one identity, before it is marked stale (H4): a single
# 401 is often an access refusal (the control of a test), not a dead session. The gate applies a threshold too.
DEAD_401_ROUTES = 3
# Fact kinds and blocker reasons only the host writes: a note asking for them is downgraded (B6)
HOST_FACT_KINDS = frozenset({"blocker", "harness"})
HOST_BLOCKER_REASONS = frozenset({"refusal"})
_BRACKET_TITLE = re.compile(r"^\s*\[([^\]]*)\]")
INTENT_ID = re.compile(r"I?(\d{1,12})")


@dataclass
class GateOutcome:
    """What the gate events of one segment left for the runner to act on."""

    blockers: int = 0  # blocker facts added
    waf_hosts: set[str] = field(default_factory=set)  # hosts that answered with a WAF challenge
    stale: set[str] = field(default_factory=set)  # identities whose session looks expired


def notes(
    board: Board, program: str, run_id: int, notes_file: Path, scope: Scope | None = None
) -> tuple[int, int, int]:
    """Ingest one rotated notes file in full. Returns (facts, findings, blockers).

    The runner renames notes.jsonl at the end of each segment, so the agent can neither replay
    old notes (truncate + rewrite) nor hide them behind a moved cursor.
    Migration: before rotation existed, a byte cursor (meta `notes:<program>`) marked what the
    single notes.jsonl had already given; it is honoured once, then dropped."""
    legacy_key = f"notes:{program}"
    skip = int(board.meta_get(legacy_key, "0"))
    if skip:
        board.db.execute("DELETE FROM meta WHERE k=?", (legacy_key,))
        board.db.commit()
    facts = findings = blockers = 0
    for n in c.read_jsonl(notes_file, offset=skip):
        if not isinstance(n, dict):
            continue  # the sandbox writes this file: a malformed line is skipped, never fatal
        try:
            f, fi, t = _note(board, program, run_id, n, scope)
        except (TypeError, ValueError, OverflowError, sqlite3.Error) as exc:
            board.add_fact(
                program, "malformed note skipped", f"{exc!r}: {one_line(n, 300)}", kind="harness", run_id=run_id
            )
            continue
        facts, findings, blockers = facts + f, findings + fi, blockers + t
    return facts, findings, blockers


def _s(value, n: int = 2000) -> str:
    """A sandbox-written field as text (null, numbers, lists... are coerced, never trusted as typed)."""
    return "" if value is None else (value if isinstance(value, str) else json.dumps(value))[:n]


def _hunter_title(title: str) -> str:
    """A note's title never starts like a host-written one ("[refusal] ...", "[waf] ..."): brackets become parens."""
    return _BRACKET_TITLE.sub(r"(\1)", title, count=1)


def _hunter_reason(reason: str) -> str:
    """A blocker reason the hunter may give (the host alone records model refusals)."""
    return "other" if reason in HOST_BLOCKER_REASONS else reason


def _revive(board: Board, program: str, title: str, fields: dict, doc) -> int | None:
    """A new, valid proof under the title of a needs-proof finding (issue 34): that finding takes the proof and goes
    back to 'new' for one more verification (bh.verify rejects it if this proof has no differential either)."""
    if doc is None or not title:
        return None
    rows = board.rows(
        "SELECT id FROM findings WHERE program=? AND title=? AND status='needs-proof' ORDER BY id DESC LIMIT 1",
        program,
        title,
    )
    if not rows:
        return None
    fid = int(rows[0]["id"])
    keep = {k: v for k, v in fields.items() if k in ("severity", "summary", "poc", "evidence", "not_proven")}
    board.finding_set(fid, proof=json.dumps(doc), replay=None, **keep)
    board.set_finding(fid, "new", "new proof received from the hunter: verified once more")
    return fid


def _note(board: Board, program: str, run_id: int, n: dict, scope: Scope | None) -> tuple[int, int, int]:
    """One note -> (facts, findings, blockers) added."""
    match n.get("op"):
        case "fact":
            kind = _s(n.get("kind") or "fact", 40)
            board.add_fact(
                program,
                _hunter_title(_s(n.get("title"), 300)),
                _s(n.get("summary")),
                _s(n.get("evidence")),
                # blocker and harness facts are the host's (add_blocker, ingestion): a note cannot forge them
                kind=kind if kind in c.FACT_KINDS else "fact",
                run_id=run_id,
            )
            return 1, 0, 0
        case "intent":
            board.add_intent(program, _s(n.get("title"), 300), run_id=run_id)
        case "done":
            if m := INTENT_ID.fullmatch(_s(n.get("intent_id"), 20)):
                board.close_intent(int(m.group(1)), _s(n.get("outcome")))
        case "finding":
            fields = {k: n.get(k) for k in FINDING_FIELDS if k not in ("vuln_class", "proof")}
            fields = {k: _s(v, 20000) for k, v in fields.items()}
            fields["poc"] = redact.text(fields.get("poc", ""))
            doc = n.get("proof")
            if doc is not None and proof.validate(doc):  # re-checked on the host: the sandbox check is advisory
                fields["not_proven"] = (fields.get("not_proven", "") + " [proof refused by the host]").strip()
                doc = None
            title = _s(n.get("title"), 300)
            if _revive(board, program, title, fields, doc) is not None:
                return 0, 1, 0
            fid = board.add_finding(
                program,
                title or "(untitled)",
                run_id=run_id,
                proof=doc,
                **fields,
                vuln_class=canonical(_s(n.get("vuln_class"), 80) or "unknown"),
            )
            if scope is not None and (excluded := scope.excludes(_s(n.get("vuln_class"), 80))):
                # the program does not pay for this class: rejected by the harness, not by the model's judgment
                board.set_finding(fid, "rejected", f"excluded by program policy (forbidden_vulns: {excluded})")
                return 0, 0, 0
            return 0, 1, 0
        case "blocked":
            reason = _hunter_reason(_s(n.get("reason"), 40))
            board.add_blocker(
                program,
                reason,
                _s(n.get("title"), 300),
                _s(n.get("detail")),
                run_id=run_id,
                host=_s(n.get("host"), 255) or None,
            )
            if m := INTENT_ID.fullmatch(_s(n.get("intent"), 20)):
                board.close_intent(int(m.group(1)), f"blocked: {reason}")
            return 0, 0, 1
        case "todo":  # written by an agent of the old doctrine: nobody answers todos during the hunt any more
            kind, title = _s(n.get("kind") or "other", 40), _s(n.get("title"), 300)
            if kind == "scope-question":  # a scope is never widened from the hunt: kept as a fact
                board.add_fact(program, title, _s(n.get("detail")), kind="out-of-scope", run_id=run_id)
                return 1, 0, 0
            board.add_blocker(program, _hunter_reason(kind), title, _s(n.get("detail")), run_id=run_id)
            return 0, 0, 1
    return 0, 0, 0


def _ts(e: dict, default: float) -> float:
    """The event's own time (the gate stamps every event), `default` when it has none."""
    v = e.get("ts")
    return float(v) if isinstance(v, int | float) and not isinstance(v, bool) and v > 0 else default


def _route(e: dict, host: str) -> str:
    """The route a gate event is about (origin + method + path family), for counting distinct ones."""
    url = e.get("url") if isinstance(e.get("url"), str) else ""
    k = c.endpoint_key(url, _s(e.get("method") or "GET", 10))
    return f"{k[0]} {c.family(k[1])}" if k else f"{host} ?"


def _identity_dead(
    board: Board, program: str, run_id: int, out: GateOutcome, *, ident: str, host: str, title: str, ts: float
) -> None:
    """Mark an identity stale (meta `identity-stale:<ident>:<program>`: the runner leaves it out of the prompt
    and the judge until its session file is rewritten) and record one `auth` blocker per identity and run.
    The mark carries the time of the EVENT, not of the ingestion: a probe that failed before a login must not
    mark stale the session that login wrote afterwards (H4 b). The latest mark wins."""
    key = f"identity-stale:{ident}:{program}"
    with contextlib.suppress(ValueError):
        ts = max(ts, float(board.meta_get(key, "0") or 0))
    board.meta_set(key, str(ts))
    out.stale.add(ident)
    key = f"auth-blocker:{ident}:{program}"
    if board.meta_get(key) == str(run_id):
        return
    board.meta_set(key, str(run_id))
    board.add_blocker(
        program,
        "auth",
        title,
        f"left out until var/state/identities/{program}/{ident}.json is refreshed",
        run_id=run_id,
        host=host,
    )
    out.blockers += 1


def gate_events(board: Board, program: str, run_id: int, identities: list[str]) -> GateOutcome:
    """One summary fact for denials, blocker facts for walls (WAF, 401) and missing identities.

    `session-dead` with a redirect to the login page, a failed probe or `401-repeated` (the gate saw 401s on
    several distinct routes: its own threshold) -> that identity is stale at once (_identity_dead). The older
    single-401 reason (`401`, logs written before the gate thresholded) needs DEAD_401_ROUTES distinct routes.
    `GateOutcome.stale` lists the dead identities: the entry point for logging in again (issue 25).
    A 401 sent WITH an identity (`auth` event) never marks it: it is the control of an access test.
    401 sent WITHOUT one -> blocker only if the program has no identity at all: an agent probing
    unauthenticated access control on purpose has hit no wall."""
    out = GateOutcome()
    blocked: dict[str, int] = {}
    auth: dict[str, int] = {}  # host -> 401 answers sent without an identity
    dead401: dict[str, dict[str, tuple[str, float]]] = {}  # identity -> route -> (host, ts)
    missing: set[str] = set()
    now = time.time()
    for e in board.new_lines(paths.events_log(), "gate-events"):
        if e.get("program") not in (program, "-"):
            continue
        match e.get("kind"):
            case "blocked":
                host = re.sub(r"https?://([^/]+).*", r"\1", e.get("url") or e.get("host") or "?")
                blocked[host] = blocked.get(host, 0) + 1
            case "waf":
                host = _s(e.get("host") or "?", 255)
                if host not in out.waf_hosts:
                    out.waf_hosts.add(host)
                    board.add_blocker(
                        program,
                        "waf",
                        f"{host} answers with a WAF challenge",
                        f"status {e.get('status')} server={e.get('server')} url={e.get('url')} flow={e.get('flow')}",
                        run_id=run_id,
                        host=host,
                    )
                    out.blockers += 1
            case "auth":
                host, ident = _s(e.get("host") or "?", 255), _s(e.get("identity"), 80)
                if not ident:  # a 401 under an identity is an access refusal; the gate decides when it is death
                    auth[host] = auth.get(host, 0) + 1
            case "session-dead":
                if ident := _s(e.get("identity"), 80):
                    host = _s(e.get("host") or "?", 255)
                    reason = _s(e.get("reason"), 20)
                    if reason == "401" or (not reason and e.get("status") == 401):
                        dead401.setdefault(ident, {})[_route(e, host)] = (host, _ts(e, now))
                        continue
                    why = {
                        "login-redirect": "a redirect to its login page",
                        "probe": "a failed probe",
                        "401-repeated": "401 on several routes",
                    }
                    _identity_dead(
                        board,
                        program,
                        run_id,
                        out,
                        ident=ident,
                        host=host,
                        title=f"identity '{ident}': session dead on {host} "
                        f"({why.get(reason, 'status ' + _s(e.get('status'), 5))})",
                        ts=_ts(e, now),
                    )
            case "identity-missing":
                ident = _s(e.get("identity"), 80)
                if ident not in missing:
                    missing.add(ident)
                    board.add_fact(
                        program,
                        f"identity '{ident}' requested but not configured",
                        f"no var/state/identities/{program}/{ident}.json",
                        kind="harness",
                        run_id=run_id,
                    )
    for ident, routes in dead401.items():
        if len(routes) < DEAD_401_ROUTES:
            continue  # an access refusal on one or two objects is the finding's control, not a dead session
        host, ts = max(routes.values(), key=lambda v: v[1])
        _identity_dead(
            board,
            program,
            run_id,
            out,
            ident=ident,
            host=host,
            title=f"identity '{ident}': session dead on {host} (401 on {len(routes)} routes)",
            ts=ts,
        )
    for host, n in auth.items():
        if n < AUTH_THRESHOLD:
            continue
        if not identities:
            # once per host while the blocker is visible; past its TTL the wall is reported again if still there
            key = f"auth-wall:{host}:{program}"
            if now - float(board.meta_get(key, "0") or 0) < c.BLOCKER_TTL_S:
                continue
            board.meta_set(key, str(now))
            board.add_blocker(program, "auth", f"{host} requires a session ({n}x 401)", run_id=run_id, host=host)
            out.blockers += 1
    if blocked:
        top = sorted(blocked.items(), key=lambda kv: -kv[1])[:8]
        board.add_fact(
            program,
            f"gate denied {sum(blocked.values())} requests",
            ", ".join(f"{h} x{n}" for h, n in top),
            kind="blocked",
            run_id=run_id,
        )
    return out
