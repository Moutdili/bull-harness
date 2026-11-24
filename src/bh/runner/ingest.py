"""Turn what the sandbox and the gate wrote into board rows.

Read offsets live in the board (host side), never in the sandbox, so the agent cannot
replay or hide its own notes.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

from bh import paths, redact
from bh.agent import contract as c
from bh.agent import proof
from bh.board import Board
from bh.board.db import FINDING_FIELDS
from bh.classes import canonical
from bh.scope import Scope
from bh.text import one_line

AUTH_TODO_THRESHOLD = 3


def notes(
    board: Board, program: str, run_id: int, notes_file: Path, scope: Scope | None = None
) -> tuple[int, int, int]:
    """Ingest one rotated notes file in full. Returns (facts, findings, todos).

    The runner renames notes.jsonl at the end of each segment, so the agent can neither replay
    old notes (truncate + rewrite) nor hide them behind a moved cursor.
    Migration: before rotation existed, a byte cursor (meta `notes:<program>`) marked what the
    single notes.jsonl had already given; it is honoured once, then dropped."""
    legacy_key = f"notes:{program}"
    skip = int(board.meta_get(legacy_key, "0"))
    if skip:
        board.db.execute("DELETE FROM meta WHERE k=?", (legacy_key,))
        board.db.commit()
    facts = findings = todos = 0
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
        facts, findings, todos = facts + f, findings + fi, todos + t
    return facts, findings, todos


def _s(value, n: int = 2000) -> str:
    """A sandbox-written field as text (null, numbers, lists... are coerced, never trusted as typed)."""
    return "" if value is None else (value if isinstance(value, str) else json.dumps(value))[:n]


def _note(board: Board, program: str, run_id: int, n: dict, scope: Scope | None) -> tuple[int, int, int]:
    """One note -> (facts, findings, todos) added."""
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
            if m := re.fullmatch(r"I?(\d{1,12})", _s(n.get("intent_id"), 20)):
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
        case "todo":
            kind, title = _s(n.get("kind") or "other", 40), _s(n.get("title"), 300)
            added = board.add_todo(
                kind, title, _s(n.get("detail")), program=program, dedup=f"{program}:{kind}:{title[:120]}"
            )
            return 0, 0, int(bool(added))
    return 0, 0, 0


def gate_events(board: Board, program: str, run_id: int, identities: list[str]) -> int:
    """One summary fact for denials + human todos (WAF, 401). Returns the number of new todos.

    401 sent WITH an identity -> that session probably expired (todo per identity and run).
    401 sent WITHOUT one -> todo only if the program has no identity at all: an agent probing
    unauthenticated access control on purpose must not page the human."""
    blocked: dict[str, int] = {}
    auth: dict[tuple[str, str | None], int] = {}
    todos = 0
    for e in board.new_lines(paths.events_log(), "gate-events"):
        if e.get("program") not in (program, "-"):
            continue
        match e.get("kind"):
            case "blocked":
                host = re.sub(r"https?://([^/]+).*", r"\1", e.get("url") or e.get("host") or "?")
                blocked[host] = blocked.get(host, 0) + 1
            case "waf":
                todos += bool(
                    board.add_todo(
                        "waf",
                        f"WAF challenge on {e.get('host')}",
                        f"status {e.get('status')} server={e.get('server')} url={e.get('url')} flow={e.get('flow')}",
                        program=program,
                        dedup=f"{program}:waf:{e.get('host')}",
                    )
                )
            case "auth":
                key = (e.get("host", "?"), e.get("identity"))
                auth[key] = auth.get(key, 0) + 1
            case "identity-missing":
                todos += bool(
                    board.add_todo(
                        "account",
                        f"identity '{e.get('identity')}' requested but not configured",
                        f"create var/state/identities/{program}/{e.get('identity')}.json",
                        program=program,
                        dedup=f"{program}:identity:{e.get('identity')}",
                    )
                )
    for (host, ident), n in auth.items():
        if n < AUTH_TODO_THRESHOLD:
            continue
        if ident:
            todos += bool(
                board.add_todo(
                    "auth",
                    f"identity '{ident}' gets 401 on {host} ({n}x): session expired?",
                    f"refresh var/state/identities/{program}/{ident}.json",
                    program=program,
                    dedup=f"{program}:auth:{host}:{ident}:{run_id}",
                )
            )
        elif not identities:
            todos += bool(
                board.add_todo(
                    "auth",
                    f"{host} answers 401 ({n}x): session needed",
                    "log in through the gate capture flow and store an identity",
                    program=program,
                    dedup=f"{program}:auth:{host}",
                )
            )
    if blocked:
        top = sorted(blocked.items(), key=lambda kv: -kv[1])[:8]
        board.add_fact(
            program,
            f"gate denied {sum(blocked.values())} requests",
            ", ".join(f"{h} x{n}" for h, n in top),
            kind="blocked",
            run_id=run_id,
        )
    return todos
