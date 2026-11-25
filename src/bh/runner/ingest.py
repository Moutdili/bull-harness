"""Turn what the sandbox and the gate wrote into board rows.

Read offsets live in the board (host side), never in the sandbox, so the agent cannot
replay or hide its own notes.
"""

from __future__ import annotations

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


def _note(board: Board, program: str, run_id: int, n: dict, scope: Scope | None) -> tuple[int, int, int]:
    """One note -> (facts, findings, blockers) added."""
    match n.get("op"):
        case "fact":
            board.add_fact(
                program,
                _s(n.get("title"), 300),
                _s(n.get("summary")),
                _s(n.get("evidence")),
                kind=_s(n.get("kind") or "fact", 40),
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
            fid = board.add_finding(
                program,
                _s(n.get("title"), 300) or "(untitled)",
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
            reason = _s(n.get("reason"), 40)
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
            board.add_blocker(program, kind, title, _s(n.get("detail")), run_id=run_id)  # unknown kind -> other
            return 0, 0, 1
    return 0, 0, 0


def _identity_dead(
    board: Board, program: str, run_id: int, out: GateOutcome, *, ident: str, host: str, title: str
) -> None:
    """Mark an identity stale (meta `identity-stale:<ident>:<program>`: the runner leaves it out of the prompt
    and the judge until its session file is rewritten) and record one `auth` blocker per identity and run."""
    board.meta_set(f"identity-stale:{ident}:{program}", str(time.time()))
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

    `session-dead` (the gate saw a 401, a redirect to the login page or a failed probe under an identity) ->
    that identity is stale at once (_identity_dead). `GateOutcome.stale` lists the dead identities: the entry
    point for logging in again (issue 25).
    401 sent WITH an identity, AUTH_THRESHOLD times -> same (gates older than session-dead only sent `auth`).
    401 sent WITHOUT one -> blocker only if the program has no identity at all: an agent probing
    unauthenticated access control on purpose has hit no wall."""
    out = GateOutcome()
    blocked: dict[str, int] = {}
    auth: dict[tuple[str, str], int] = {}
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
                key = (_s(e.get("host") or "?", 255), _s(e.get("identity"), 80))
                auth[key] = auth.get(key, 0) + 1
            case "session-dead":
                if ident := _s(e.get("identity"), 80):
                    host = _s(e.get("host") or "?", 255)
                    why = {"401": "401", "login-redirect": "a redirect to its login page", "probe": "a failed probe"}
                    _identity_dead(
                        board,
                        program,
                        run_id,
                        out,
                        ident=ident,
                        host=host,
                        title=f"identity '{ident}': session dead on {host} "
                        f"({why.get(_s(e.get('reason'), 20), 'status ' + _s(e.get('status'), 5))})",
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
    for (host, ident), n in auth.items():
        if n < AUTH_THRESHOLD:
            continue
        if ident:
            _identity_dead(
                board,
                program,
                run_id,
                out,
                ident=ident,
                host=host,
                title=f"identity '{ident}' gets 401 on {host} ({n}x): session expired",
            )
        elif not identities:
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
