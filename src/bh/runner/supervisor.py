"""Zero-strategy supervisor (sapper-v2 watchdog pattern): keeps segments running, rotates
programs on stagnation, sleeps on quota, starts a fresh session (handoff) when a session
has been resumed too many times. It never decides what to test — the agent does — and it
never waits on a human: a program that cannot go on is paused or parked, the others go on."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path

from bh.board import Board
from bh.runner.run import (
    RESET_HORIZON_S,
    ProgramNotReady,
    SegmentResult,
    check_automation,
    recent_refusals,
    run_segment,
)
from bh.scope import load_scope

STAGNANT_LIMIT = 2  # segments without a new fact/finding before cooldown
COOLDOWN_S = 2 * 3600
# A refusal is never rephrased (CVP account): 1st -> pause, 2nd in the same hunt -> parked until it ends,
# REFUSAL_LIMIT within 7 days -> excluded at preflight until someone reviews it out of the hunt. Only refusals on
# distinct causes (page or command, see run.refusal_cause) climb this ladder: a page that makes the model refuse
# again is closed by its blocker, and costs the program a plain cooldown, not its place in the hunt.
REFUSAL_COOLDOWN_S = 6 * 3600
REFUSALS_TO_PARK = 2
REFUSAL_LIMIT = 3
QUOTA_SLEEP_S = 30 * 60  # when the stream gave no reset time
QUOTA_MARGIN_S = 120
# Resuming re-reads the whole session history every turn: lab runs 5-7 cost $0.13-0.20 for 3-10 turns,
# fresh sessions from the board + HANDOFF $0.03-0.04 for similar output. Default: always fresh.
MAX_RESUMES = int(os.environ.get("BH_MAX_RESUMES", "0"))


@dataclass
class ProgState:
    file: Path
    program: str
    stagnant: int = 0
    cooldown_until: float = 0.0
    last_run: float = 0.0
    resumes: int = 0
    refusals: int = 0  # in this hunt
    parked: bool = False  # never picked again in this hunt


def quota_wake(res: SegmentResult, now: float) -> float:
    """When to try again after a quota stop: the reset time the API announced (`rate_limit_event.resetsAt`)
    plus a margin, else QUOTA_SLEEP_S from now. A reset further than RESET_HORIZON_S is not believed."""
    reset = (res.rate_limit or {}).get("resetsAt")
    if isinstance(reset, (int, float)) and not isinstance(reset, bool) and now < reset <= now + RESET_HORIZON_S:
        return reset + QUOTA_MARGIN_S
    return now + QUOTA_SLEEP_S


def _fmt(ts: float) -> str:
    return time.strftime("%H:%M", time.localtime(ts))


def preflight(board: Board, scope_files: list[Path]) -> list[ProgState]:
    """The programs this hunt may run: onboarding done and fewer than REFUSAL_LIMIT refusals in 7 days."""
    ready = []
    for f in scope_files:
        scope = load_scope(f)
        try:
            check_automation(scope)
        except ProgramNotReady as exc:
            print(f"{scope.program}: excluded ({exc})")
            continue
        if (n := len(recent_refusals(board, scope.program, time.time()))) >= REFUSAL_LIMIT:
            print(f"{scope.program}: excluded ({n} model refusals in 7 days: review its [refusal] blockers)")
            continue
        ready.append(ProgState(f, scope.program))
    return ready


def _after_refusal(p: ProgState) -> None:
    p.refusals += 1
    if p.refusals >= REFUSALS_TO_PARK:
        p.parked = True
        print(f"{p.program}: parked until the end of the hunt ({p.refusals} refusals)")
    else:
        p.cooldown_until = time.time() + REFUSAL_COOLDOWN_S
        print(f"{p.program}: paused until {_fmt(p.cooldown_until)} (refusal)")


def hunt(
    scope_files: list[Path], *, hours: float, minutes: float, model: str, max_turns: int, effort: str | None = None
) -> None:
    board = Board()
    progs = preflight(board, scope_files)
    if not progs:
        print("hunt: no program is ready: nothing to do")
        return
    deadline = time.time() + hours * 3600
    print(f"hunt: {len(progs)} program(s) until {_fmt(deadline)} · segments of {minutes:g} min / {max_turns} turns")
    while time.time() < deadline:
        now = time.time()
        active = [p for p in progs if not p.parked]
        if not active:
            print("every program is parked: stopping")
            break
        ready = [p for p in active if p.cooldown_until <= now]
        if not ready:
            wake = min(p.cooldown_until for p in active)
            if wake >= deadline:
                print("every program is cooling down past the deadline: nothing left to do")
                break
            print(f"all programs cooling down; sleeping until {_fmt(wake)}")
            time.sleep(max(30, wake - now))
            continue
        p = min(ready, key=lambda x: x.last_run)
        resume = p.resumes < MAX_RESUMES
        p.last_run = time.time()
        try:
            res: SegmentResult = run_segment(
                p.file,
                model=model,
                max_turns=max_turns,
                minutes=minutes,
                resume=resume,
                board=board,
                effort=effort,
            )
        except ProgramNotReady as exc:  # its scope file changed mid-hunt; any other SystemExit stops the hunt
            p.parked = True
            print(f"{p.program}: parked until the end of the hunt ({exc})")
            continue
        except Exception as exc:  # noqa: BLE001 - e.g. a sandbox file that breaks ingestion: this program only
            # SystemExit (container down, lock held: the whole stack) and Ctrl-C are not Exceptions: they still stop
            # the hunt. A failing program would fail again at once (its files stay): parked, the others go on.
            p.parked = True
            print(f"{p.program}: parked until the end of the hunt (segment failed: {exc!r})"[:500])
            continue
        p.resumes = p.resumes + 1 if resume else 0
        if res.status == "parked":  # third-party data or server-side execution: only the operator lifts it
            p.parked = True
            print(f"{p.program}: parked (stop note: third-party data or server-side execution), see `bh unpark`")
            continue
        if res.status == "quota":
            wake = quota_wake(res, time.time())
            if wake >= deadline:
                print(f"quota reached; it resets at {_fmt(wake)}, after the deadline: stopping")
                break
            print(f"quota reached; sleeping until {_fmt(wake)}")
            time.sleep(max(30, wake - time.time()))
            continue
        if res.status == "refusal":
            if res.refusal_repeat:
                p.cooldown_until = time.time() + COOLDOWN_S
                print(f"{p.program}: cooldown until {_fmt(p.cooldown_until)} (refusal on a cause already refused)")
            else:
                _after_refusal(p)
            continue
        if res.progress == 0:  # a HANDOFF or dead-ends alone is not progress
            p.stagnant += 1
        else:
            p.stagnant = 0
        if p.stagnant >= STAGNANT_LIMIT or res.status == "error":
            p.cooldown_until = time.time() + COOLDOWN_S
            p.stagnant = 0
            print(f"{p.program}: cooldown until {_fmt(p.cooldown_until)} ({res.status})")
    else:
        print("hunt: deadline reached")
