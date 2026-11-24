"""Turn what the sandbox and the gate wrote into board rows.

Read offsets live in the board (host side), never in the sandbox, so the agent cannot
replay or hide its own notes.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from bh import paths
from bh.agent import contract as c
from bh.board import Board

# Facts that record bookkeeping, not progress: a segment that only writes these is stagnant.
BOOKKEEPING_KINDS = ("handoff", "dead-end", "blocked")
AUTH_TODO_THRESHOLD = 3


def read_new_lines(board: Board, path: Path, key: str) -> list[dict]:
    """JSON lines appended to `path` since the last call with the same `key`."""
    if not path.exists():
        return []
    off = int(board.meta_get(key, "0"))
    if path.stat().st_size < off:  # truncated / recreated
        off = 0
    out = []
    with open(path, "rb") as fh:
        fh.seek(off)
        for line in fh:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        board.meta_set(key, str(fh.tell()))
    return out


def skip_existing(board: Board, path: Path, key: str) -> None:
    """Move the cursor to the end of `path` (events produced outside any run)."""
    board.meta_set(key, str(path.stat().st_size if path.exists() else 0))


def notes(board: Board, program: str, run_id: int, bh_dir: Path) -> tuple[int, int, int, int]:
    """Returns (facts, findings, todos, progress)."""
    facts = findings = todos = progress = 0
    for n in read_new_lines(board, bh_dir / c.NOTES, f"notes:{program}"):
        match n.get("op"):
            case "fact":
                kind = n.get("kind", "fact")
                board.add_fact(
                    program, n.get("title", ""), n.get("summary", ""), n.get("evidence", ""), kind=kind, run_id=run_id
                )
                facts += 1
                progress += kind not in BOOKKEEPING_KINDS
            case "intent":
                board.add_intent(program, n.get("title", ""), run_id=run_id)
            case "done":
                if m := re.fullmatch(r"I?(\d+)", str(n.get("intent_id", ""))):
                    board.close_intent(int(m.group(1)), n.get("outcome", ""))
            case "finding":
                board.add_finding(
                    program,
                    n.get("title", ""),
                    run_id=run_id,
                    **{
                        k: n.get(k)
                        for k in ("severity", "vuln_class", "url", "summary", "poc", "evidence", "not_proven")
                    },
                )
                findings += 1
                progress += 1
            case "todo":
                todos += bool(
                    board.add_todo(
                        n.get("kind", "other"),
                        n.get("title", ""),
                        n.get("detail", ""),
                        program=program,
                        dedup=f"{program}:{n.get('kind')}:{n.get('title', '')[:120]}",
                    )
                )
    return facts, findings, todos, progress


def gate_events(board: Board, program: str, run_id: int, identities: list[str]) -> int:
    """One summary fact for denials + human todos (WAF, 401). Returns the number of new todos.

    401 sent WITH an identity -> that session probably expired (todo per identity and run).
    401 sent WITHOUT one -> todo only if the program has no identity at all: an agent probing
    unauthenticated access control on purpose must not page the human."""
    blocked: dict[str, int] = {}
    auth: dict[tuple[str, str | None], int] = {}
    todos = 0
    for e in read_new_lines(board, paths.events_log(), "gate-events"):
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
