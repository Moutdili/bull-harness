"""Zero-strategy supervisor (sapper-v2 watchdog pattern): keeps segments running, rotates
programs on stagnation, sleeps on quota, starts a fresh session (handoff) when a session
has been resumed too many times. It never decides what to test — the agent does."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path

from bh.board import Board
from bh.runner.run import SegmentResult, run_segment
from bh.scope import load_scope

STAGNANT_LIMIT = 2  # segments without a new fact/finding before cooldown
COOLDOWN_S = 2 * 3600
QUOTA_SLEEP_S = 30 * 60
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


def _fmt(ts: float) -> str:
    return time.strftime("%H:%M", time.localtime(ts))


def hunt(
    scope_files: list[Path], *, hours: float, minutes: float, model: str, max_turns: int, effort: str | None = None
) -> None:
    board = Board()
    progs = [ProgState(f, load_scope(f).program) for f in scope_files]
    deadline = time.time() + hours * 3600
    print(f"hunt: {len(progs)} program(s) until {_fmt(deadline)} · segments of {minutes:g} min / {max_turns} turns")
    while time.time() < deadline:
        now = time.time()
        ready = [p for p in progs if p.cooldown_until <= now]
        if not ready:
            wake = min(p.cooldown_until for p in progs)
            if wake >= deadline:
                print("every program is cooling down past the deadline: nothing left to do")
                break
            print(f"all programs cooling down; sleeping until {_fmt(wake)}")
            time.sleep(max(30, wake - now))
            continue
        p = min(ready, key=lambda x: x.last_run)
        resume = p.resumes < MAX_RESUMES
        p.last_run = time.time()
        res: SegmentResult = run_segment(
            p.file,
            model=model,
            max_turns=max_turns,
            minutes=minutes,
            resume=resume,
            board=board,
            effort=effort,
        )
        p.resumes = p.resumes + 1 if resume else 0
        if res.status == "quota":
            print(f"quota reached; sleeping {QUOTA_SLEEP_S // 60} min")
            time.sleep(QUOTA_SLEEP_S)
            continue
        if res.progress == 0:  # a HANDOFF or dead-ends alone is not progress
            p.stagnant += 1
        else:
            p.stagnant = 0
        if p.stagnant >= STAGNANT_LIMIT or res.status in ("refusal", "error"):
            p.cooldown_until = time.time() + COOLDOWN_S
            p.stagnant = 0
            print(f"{p.program}: cooldown until {_fmt(p.cooldown_until)} ({res.status})")
    else:
        print("hunt: deadline reached")
