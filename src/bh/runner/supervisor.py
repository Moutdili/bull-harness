"""Zero-strategy supervisor (sapper-v2 watchdog pattern): keeps segments running, rotates
programs on stagnation, sleeps on quota, starts a fresh session (handoff) when a session
has been resumed too many times. It never decides what to test — the agent does."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from bh.board import Board
from bh.runner.run import SegmentResult, run_segment
from bh.scope import load_scope

STAGNANT_LIMIT = 2  # segments without a new fact/finding before cooldown
COOLDOWN_S = 2 * 3600
QUOTA_SLEEP_S = 30 * 60
MAX_RESUMES = 3  # then fresh session that reads the HANDOFF fact


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


def hunt(scope_files: list[Path], *, hours: float, minutes: float, model: str, max_turns: int,
         effort: str | None = None) -> None:
    board = Board()
    progs = [ProgState(f, load_scope(f).program) for f in scope_files]
    deadline = time.time() + hours * 3600
    print(f"hunt: {len(progs)} program(s) until {_fmt(deadline)} · segments of {minutes:g} min / {max_turns} turns")
    while time.time() < deadline:
        now = time.time()
        ready = [p for p in progs if p.cooldown_until <= now]
        if not ready:
            wake = min(p.cooldown_until for p in progs)
            print(f"all programs cooling down; sleeping until {_fmt(wake)}")
            time.sleep(max(30, min(wake, deadline) - now))
            continue
        p = min(ready, key=lambda x: x.last_run)
        resume = p.resumes < MAX_RESUMES
        extra = "" if resume else "Fresh session: read the HANDOFF facts on the board first."
        p.last_run = time.time()
        res: SegmentResult = run_segment(p.file, model=model, max_turns=max_turns, minutes=minutes,
                                         resume=resume, board=board, extra_task=extra, effort=effort)
        p.resumes = p.resumes + 1 if resume else 0
        if res.status == "quota":
            print(f"quota reached; sleeping {QUOTA_SLEEP_S // 60} min")
            time.sleep(QUOTA_SLEEP_S)
            continue
        if res.new_facts + res.new_findings == 0:
            p.stagnant += 1
        else:
            p.stagnant = 0
        if p.stagnant >= STAGNANT_LIMIT or res.status in ("refusal", "error"):
            p.cooldown_until = time.time() + COOLDOWN_S
            p.stagnant = 0
            print(f"{p.program}: cooldown until {_fmt(p.cooldown_until)} ({res.status})")
    print("hunt: deadline reached")
