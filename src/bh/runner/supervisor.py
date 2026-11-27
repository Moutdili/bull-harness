"""Zero-strategy supervisor (sapper-v2 watchdog pattern): keeps segments running, rotates
programs on stagnation, sleeps on quota, starts a fresh session (handoff) when a session
has been resumed too many times. It never decides what to test — the agent does — and it
never waits on a human: a program that cannot go on is paused or parked, the others go on.

Caps (D25), held in code: a hunt on real programs is one session of RUNS_PER_SESSION runs inside a named phase
(`bh hunt --phase NAME`), SESSIONS_PER_DAY sessions a day, MAX_RUNS_PER_DAY runs a day (a lone `bh run` included),
RUNS_PER_PHASE runs a phase. A cap refuses: it never waits, never postpones, and no option or variable raises it.
`platform: local` programs (scopes/lab, scopes/examples) count in none of them."""

from __future__ import annotations

import math
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

from bh.board import Board
from bh.runner import identity
from bh.runner.run import (
    RESET_HORIZON_S,
    ProgramNotReady,
    SegmentResult,
    check_automation,
    note_decision,
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
# D25: Mio's rhythm, 3 sessions a day of 11 runs in a row (morning, afternoon break, evening). Literals on purpose:
# a test reads this module and fails if one of them comes from the environment or an argument.
RUNS_PER_SESSION = 11
SESSIONS_PER_DAY = 3
MAX_RUNS_PER_DAY = 33
RUNS_PER_PHASE = 33
# R44: Copilot gives about 45 prompts a day and account. Spread evenly over 33 runs no run finishes a surface: they
# are concentrated in quanta of PROMPT_QUANTUM, a remainder of at least PROMPT_FLOOR makes one more quantum. Only the
# orchestrator changes them, between two phases.
PROMPT_QUANTUM = 10
PROMPT_FLOOR = 6
# Resuming re-reads the whole session history every turn: lab runs 5-7 cost $0.13-0.20 for 3-10 turns,
# fresh sessions from the board + HANDOFF $0.03-0.04 for similar output. Default: always fresh.
MAX_RESUMES = int(os.environ.get("BH_MAX_RESUMES", "0"))


class CapReached(SystemExit):
    """A run the caps refuse (D25): said with the reason, never waited on."""


PHASE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,39}")


def _phase_name(phase: str) -> str:
    if not PHASE_RE.fullmatch(phase or ""):
        raise CapReached(f"phase {phase!r} refused: letters, digits, - _ . (40 at most)")
    return phase


# ------------------------------------------------------------------ caps (D25)
def day_of(ts: float) -> str:
    """The host's local date of `ts`."""
    return time.strftime("%Y-%m-%d", time.localtime(ts))


def session_day(session: str) -> str:
    return session.rsplit("-", 1)[0]


def counted(scope) -> bool:
    """Real programs count in the caps; `platform: local` ones (lab, examples) never do."""
    return scope.platform != "local"


def _capped_runs(board: Board) -> list:
    identity.ensure(board)
    return board.rows("SELECT id, started, phase, session FROM runs WHERE phase IS NOT NULL")


def runs_on_day(board: Board, day: str) -> int:
    """Runs of real programs that belong to `day`: a session's runs to the day it started (even past midnight), a
    lone run to the day it started."""
    return sum(
        1 for r in _capped_runs(board) if (session_day(r["session"]) if r["session"] else day_of(r["started"])) == day
    )


def sessions_on_day(board: Board, day: str) -> list[str]:
    return sorted({r["session"] for r in _capped_runs(board) if r["session"] and session_day(r["session"]) == day})


def runs_in_session(board: Board, session: str) -> int:
    return sum(1 for r in _capped_runs(board) if r["session"] == session)


def runs_in_phase(board: Board, phase: str) -> int:
    return sum(1 for r in _capped_runs(board) if r["phase"] == phase)


def open_session(board: Board, phase: str, now: float) -> str:
    """`<local date>-<n>` of a new session of `phase`, or CapReached with the reason."""
    _phase_name(phase)
    if (k := runs_in_phase(board, phase)) >= RUNS_PER_PHASE:
        raise CapReached(f"phase {phase}: {k}/{RUNS_PER_PHASE} runs, the phase is over (refused)")
    day = day_of(now)
    if len(held := sessions_on_day(board, day)) >= SESSIONS_PER_DAY:
        raise CapReached(
            f"session {len(held) + 1} of {day} refused: {SESSIONS_PER_DAY} sessions a day ({', '.join(held)})"
        )
    if (n := runs_on_day(board, day)) >= MAX_RUNS_PER_DAY:
        raise CapReached(f"{day}: {n}/{MAX_RUNS_PER_DAY} runs today, no new session (refused)")
    return f"{day}-{len(held) + 1}"


def admit(board: Board, scope, *, phase: str | None, session: str | None, now: float) -> tuple[str | None, str | None]:
    """(phase, session) to record for this run, or CapReached with the reason. A local program records neither and
    is never refused here."""
    if not counted(scope):
        return None, None
    if not phase:
        raise CapReached(
            f"{scope.program} ({scope.platform}): a real program runs inside a phase: `--phase NAME` "
            f"(sessions of {RUNS_PER_SESSION} runs, {SESSIONS_PER_DAY} a day, {MAX_RUNS_PER_DAY} runs a day)"
        )
    _phase_name(phase)
    if (k := runs_in_phase(board, phase)) >= RUNS_PER_PHASE:
        raise CapReached(f"phase {phase}: {k}/{RUNS_PER_PHASE} runs, the phase is over (run {k + 1} refused)")
    day = session_day(session) if session else day_of(now)
    if (n := runs_on_day(board, day)) >= MAX_RUNS_PER_DAY:
        raise CapReached(f"{day}: {n}/{MAX_RUNS_PER_DAY} runs today (run {n + 1} of the day refused)")
    if session:
        if (r := runs_in_session(board, session)) >= RUNS_PER_SESSION:
            raise CapReached(f"session {session}: {r}/{RUNS_PER_SESSION} runs (run {r + 1} refused)")
        held = sessions_on_day(board, day)
        if session not in held and len(held) >= SESSIONS_PER_DAY:
            raise CapReached(f"session {len(held) + 1} of {day} refused: {SESSIONS_PER_DAY} sessions a day")
    return phase, session


def runs_left(board: Board, session: str | None, programs: int, now: float, limit: int = RUNS_PER_SESSION) -> int:
    """Runs this program may still get today, this one included (R44): those left in the session plus
    RUNS_PER_SESSION per session of the day not started yet, over the hunt's programs, rounded up. A lone run: 1."""
    if not session:
        return 1
    day = session_day(session)
    in_session = max(0, limit - runs_in_session(board, session))
    started = len(set(sessions_on_day(board, day)) | {session})
    total = in_session + RUNS_PER_SESSION * max(0, SESSIONS_PER_DAY - started)
    total = min(total, max(0, MAX_RUNS_PER_DAY - runs_on_day(board, day)))
    return max(1, math.ceil(total / max(1, programs)))


def prompt_allotment(quotas: dict, runs_left: int) -> dict[str, int]:
    """Prompts each identity may send this run (R44). `quotas`: the controller's {identity: {"left": int, ...}}.
    k = sum of left // PROMPT_QUANTUM, plus one per identity whose remainder is at least PROMPT_FLOOR. The run is
    served when k > 0 and runs_left % ceil(runs_left / k) == 0: then every identity with left >= PROMPT_FLOOR gets
    min(PROMPT_QUANTUM, left), the others 0; otherwise every identity gets 0."""
    lefts: dict[str, int] = {}
    for name, q in (quotas or {}).items():
        v = q.get("left") if isinstance(q, dict) else None
        lefts[str(name)] = max(0, v) if isinstance(v, int) and not isinstance(v, bool) else 0
    k = sum(v // PROMPT_QUANTUM for v in lefts.values()) + sum(
        1 for v in lefts.values() if v % PROMPT_QUANTUM >= PROMPT_FLOOR
    )
    served = k > 0 and runs_left > 0 and runs_left % math.ceil(runs_left / k) == 0
    return {n: (min(PROMPT_QUANTUM, v) if served and v >= PROMPT_FLOOR else 0) for n, v in lefts.items()}


def status_line(board: Board, now: float) -> str | None:
    """`phase NAME: k/33 · session j/3: r/11` (bh status), None before any phased run."""
    identity.ensure(board)
    last = board.rows("SELECT phase FROM runs WHERE phase IS NOT NULL ORDER BY id DESC LIMIT 1")
    if not last:
        return None
    phase = last[0]["phase"]
    held = sessions_on_day(board, day_of(now))
    r = runs_in_session(board, held[-1]) if held else 0
    return (
        f"phase {phase}: {runs_in_phase(board, phase)}/{RUNS_PER_PHASE} · "
        f"session {len(held)}/{SESSIONS_PER_DAY}: {r}/{RUNS_PER_SESSION}"
    )


# ------------------------------------------------------------------ hunt
@dataclass
class ProgState:
    file: Path
    program: str
    counted: bool = False  # a real program: its runs count in the caps
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


def rules_fresh(scope) -> tuple[bool, str]:
    """bh.rules.fresh(program) (lot H): rules never read, read more than 7 days ago, or changed without `bh rules
    ack` -> (False, the reason). Without the module nothing changes (True). The rules are the authorisation to
    test: a check that raises refuses (fails closed). Local labs have no rules page: exempt."""
    if scope.platform == "local":
        return True, ""
    try:
        from bh import rules
    except ImportError:
        return True, ""
    try:
        ok, why = rules.fresh(scope.program, scope=scope)
    except Exception as exc:  # noqa: BLE001
        return False, f"program rules check failed: {type(exc).__name__}: {exc}"
    return bool(ok), str(why or "")


def preflight(board: Board, scope_files: list[Path]) -> list[ProgState]:
    """The programs this hunt may run: onboarding done, program rules fresh (bh.rules) and fewer than
    REFUSAL_LIMIT refusals in 7 days."""
    ready = []
    for f in scope_files:
        scope = load_scope(f)
        try:
            check_automation(scope)
        except ProgramNotReady as exc:
            print(f"{scope.program}: excluded ({exc})")
            continue
        fresh, why = rules_fresh(scope)
        if not fresh:
            print(f"{scope.program}: excluded (program rules: {why or 'not fresh'}; `bh rules check`, `bh rules ack`)")
            continue
        if (n := len(recent_refusals(board, scope.program, time.time()))) >= REFUSAL_LIMIT:
            print(f"{scope.program}: excluded ({n} model refusals in 7 days: review its [refusal] blockers)")
            continue
        ready.append(ProgState(f, scope.program, counted(scope)))
    return ready


def _after_refusal(p: ProgState, board: Board | None = None, res: SegmentResult | None = None) -> None:
    p.refusals += 1
    if p.refusals >= REFUSALS_TO_PARK:
        p.parked = True
        if board is not None and res is not None:  # T20: the park is journaled in the run that caused it
            note_decision(board, res, "park")
        print(f"{p.program}: parked until the end of the hunt ({p.refusals} refusals)")
    else:
        p.cooldown_until = time.time() + REFUSAL_COOLDOWN_S
        print(f"{p.program}: paused until {_fmt(p.cooldown_until)} (refusal)")


def hunt(
    scope_files: list[Path],
    *,
    hours: float,
    minutes: float,
    model: str,
    max_turns: int,
    effort: str | None = None,
    phase: str | None = None,
    runs: int | None = None,
) -> None:
    """One session: RUNS_PER_SESSION runs (or `runs`, which can only lower it) on the given programs, the least
    recently run first, then a clean stop; `hours` bounds its duration. Real programs need a `phase`; local ones
    run without one, outside every cap. The gate's preflight runs before each program's first segment."""
    if runs is not None and not 1 <= runs <= RUNS_PER_SESSION:
        raise SystemExit(f"--runs {runs} refused: a session is at most {RUNS_PER_SESSION} runs, --runs only lowers it")
    board = Board()
    identity.ensure(board)
    progs = preflight(board, scope_files)
    if not progs:
        print("hunt: no program is ready: nothing to do")
        return
    real = [p for p in progs if p.counted]
    if real and not phase:
        raise SystemExit(
            f"hunt refused: {', '.join(p.program for p in real)} is a real program: `--phase NAME` (one session of "
            f"{RUNS_PER_SESSION} runs, {SESSIONS_PER_DAY} sessions and {MAX_RUNS_PER_DAY} runs a day)"
        )
    session = open_session(board, phase, time.time()) if real else None
    limit = runs or RUNS_PER_SESSION
    deadline = time.time() + hours * 3600
    print(
        f"hunt: {len(progs)} program(s) until {_fmt(deadline)} · segments of {minutes:g} min / {max_turns} turns"
        + (f" · phase {phase} · session {session}: {limit} runs" if session else "")
    )
    checked: dict[str, dict] = {}  # program -> its preflight result (run once per program and hunt)
    done = 0  # segments of this hunt (bounds a local-only hunt given --runs)
    while time.time() < deadline:
        if session and (r := runs_in_session(board, session)) >= limit:
            print(f"session {session} complete: {r}/{limit} runs")
            break
        if not session and runs is not None and done >= runs:
            print(f"hunt: {done}/{runs} runs done")
            break
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
        left = runs_left(board, session, len(real), p.last_run, limit) if p.counted else 1
        try:
            res: SegmentResult = run_segment(
                p.file,
                model=model,
                max_turns=max_turns,
                minutes=minutes,
                resume=resume,
                board=board,
                effort=effort,
                phase=phase if p.counted else None,
                session=session if p.counted else None,
                runs_left=left,
                preflight=checked.get(p.program, True),
            )
        except CapReached as exc:  # a cap refuses: the session ends here, nothing waits
            print(f"hunt: {exc}")
            break
        except ProgramNotReady as exc:  # its scope file changed mid-hunt; any other SystemExit stops the hunt
            p.parked = True
            print(f"{p.program}: parked until the end of the hunt ({exc})")
            continue
        except Exception as exc:  # noqa: BLE001 - e.g. a sandbox file that breaks ingestion: this program only
            # SystemExit (container down, lock held, preflight failed: the whole stack) and Ctrl-C are not
            # Exceptions: they still stop the hunt. A failing program would fail again at once (its files stay):
            # parked, the others go on.
            p.parked = True
            print(f"{p.program}: parked until the end of the hunt (segment failed: {exc!r})"[:500])
            continue
        done += 1
        if isinstance(getattr(res, "preflight", None), dict):
            checked[p.program] = res.preflight
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
                _after_refusal(p, board, res)
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
