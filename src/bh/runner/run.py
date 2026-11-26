"""Run one segment of `claude -p` inside the agent container for one program.

Host side only:
  lock (one agent at a time) -> activate the scope for the gate -> tag gate flows with the run
  -> clean the sandbox (fresh HOME, no planted CLAUDE.md / .claude) -> push frontier / doctrine
  -> podman exec claude -p (stream-json), nudged to continue in the same session when it stops early (the sandbox
     is scrubbed again before every leg)
  -> rotate + ingest notes, gate events -> measured progress.

The stream is written by a process the hunter shares a uid with: what it claims about refusals and quota is
believed only where another source agrees (see `refusal_confirmed`, `quota_confirmed`).
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO
from urllib.parse import urlsplit

from bh.browser_service import watch as browser_watch
from bh import classes, paths, retention, stack
from bh.assets import Graph
from bh.agent import contract as c
from bh.board import Board
from bh.runner import identity, ingest
from bh.runner.prompt import build_system_prompt, build_task
from bh.scope import Scope, load_scope
from bh.text import one_line

DEFAULT_MODEL = "sonnet"  # alias resolved by Claude Code (claude-sonnet-5-5 on 2.1.330)
# Claude usage-limit wording only: "rate limit" is everyday bug bounty vocabulary (false positives). Matched on
# claude's stderr only, never on the model's text (a target page quoted by the model says "limit reached" too).
QUOTA_RE = re.compile(r"(usage limit|limit reached|resets? at \d|out of (extra )?usage)", re.I)
RESET_HORIZON_S = 8 * 86400  # a resetsAt further away than this is ignored (no quota window is that long)
# The hunter's system prompt: a file root pushes (0444) in a directory of root's (755), outside the work tree. The
# hunter reads it, never rewrites it between two legs.
SYSTEM_DIR = "/var/lib/bh-run"
SYSTEM_FILE = f"{SYSTEM_DIR}/{c.SYSTEM}"
# Builtins run for minutes (ffuf, nuclei, sqlmap): the Bash tool's 2-minute default would kill them.
BASH_TIMEOUT_MS = {"BASH_DEFAULT_TIMEOUT_MS": "330000", "BASH_MAX_TIMEOUT_MS": "900000"}
# Token economy: every turn resends tool schemas + command listings; keep only what the hunt uses.
AGENT_TOOLS = os.environ.get("BH_TOOLS", "Bash,Read")
# The model ends its turn after one finding. Within a segment the same session is nudged to go on
# (cheap: the context is still small), at most MAX_LEGS times, while less than EARLY_STOP of the
# turn budget is used.
MAX_LEGS, EARLY_STOP, MIN_LEFT_TURNS, MIN_LEFT_S = 3, 0.5, 5, 180
MIN_LEG_TOOL_CALLS = 2  # a leg that barely used tools has run out of leads: nudging it again only costs tokens
CONTINUE_PROMPT = (
    "Continue in this session: about {turns} turns and {minutes} minutes remain. Run `bh-note frontier`, "
    "take the next untested endpoint or open intent, or the next unchecked surface of the program card, test it, "
    "record the outcome, and keep going. Keep the HANDOFF fact current."
)
# Context rotation (issue 10, TODO 4.2b). A turn's context = input + cache read + cache write tokens. Measured
# (plan v3 §1): 8.4-10.3k at the base of a session, a 19.4k peak over 22 turns (run 12). 30k is 3x the base and
# 1.5x the highest peak measured: a healthy segment never rotates, one whose observations pile up does. Above it,
# the next leg is a fresh session from the board instead of `--resume` (which re-reads the whole history every
# turn). At CONTEXT_HARD_FACTOR x the threshold the leg is stopped after the turn in progress, then rotated.
CONTEXT_ROTATE_TOKENS = int(os.environ.get("BH_CONTEXT_ROTATE_TOKENS", "30000"))
CONTEXT_HARD_FACTOR = 2
# A hunt in the persistent browser (scope with a `passthrough` host) piles up selectors and page state: 30k is reached
# in 20-45 turns and every fresh session forgets the page (audit I9). There: 60k and 5 legs. BH_CONTEXT_ROTATE_TOKENS
# and BH_MAX_LEGS, when set, win for every scope.
BROWSER_ROTATE_TOKENS, BROWSER_MAX_LEGS = 60000, 5


def _env_int(env, name: str) -> int | None:
    try:
        v = int(str(env.get(name, "")).strip())
    except ValueError:
        return None
    return v if v > 0 else None


def segment_limits(scope: Scope, env=None) -> tuple[int, int]:
    """(context rotation threshold in tokens, legs at most) for this scope's segments."""
    env = os.environ if env is None else env
    browser = bool(scope.support_hosts("passthrough"))
    rotate = _env_int(env, "BH_CONTEXT_ROTATE_TOKENS") or (BROWSER_ROTATE_TOKENS if browser else CONTEXT_ROTATE_TOKENS)
    legs = _env_int(env, "BH_MAX_LEGS") or (BROWSER_MAX_LEGS if browser else MAX_LEGS)
    return rotate, legs


@dataclass
class SegmentResult:
    program: str
    run_id: int
    status: str = "error"  # ok | max_turns | timeout | quota | error | refusal | stopped | parked
    session_id: str | None = None
    legs: int = 0
    turns: int = 0
    cost_usd: float = 0.0
    new_facts: int = 0
    new_findings: int = 0
    new_blockers: int = 0
    progress: int = 0  # findings + endpoints newly tested + phases newly covered (facts alone are not progress)
    tool_calls: int = 0
    arsenal_calls: int = 0  # Bash commands running a builtin or an arsenal tool
    manual_calls: int = 0  # Bash commands hand-crafting HTTP
    locked_calls: int = 0  # commands refused by the tool lock
    text: str = ""
    usage: dict = field(default_factory=dict)
    rate_limit: dict = field(default_factory=dict)  # last `rate_limit_info` of the stream: status, resetsAt, windows
    turn_log: list[dict] = field(default_factory=list)  # one per model message: tokens (observability)
    rotations: int = 0  # legs started as a fresh session because the previous one crossed the context threshold
    leg_context: list[int] = field(default_factory=list)  # max context (tokens) of each leg
    overflow: bool = False  # the last leg was stopped by the runner past CONTEXT_HARD_FACTOR x the threshold
    tool_log: list[dict] = field(default_factory=list)  # one per tool call: kind, duration, locked
    refusal_id: str | None = None  # id of the message the stream says was refused
    refusal_cause: dict = field(default_factory=dict)  # cmd, url, host, key: what the refusal most likely followed
    refusal_repeat: bool = False  # a refusal on a cause already refused within 7 days: not escalated again
    quota_claimed: bool = False  # the stream said `rejected`, confirmed or not: no verification after it
    early_stops: int = 0  # legs that closed themselves on an announced action they never ran (T11)
    preflight: dict | None = None  # the gate self-test this segment started after (T4)
    _pending: dict = field(default_factory=dict, repr=False)  # tool_use id -> index in tool_log
    _last_urls: list[str] = field(default_factory=list, repr=False)  # URLs of the last tool result


def quota_line(info: dict) -> str:
    """` · quota seven_day 5% (resets Mon 10:00)` from the stream's rate_limit_info, or ''."""
    wins = info.get("unifiedWindows") or {}
    parts = [
        f"{name} {round(100 * w['utilization'])}%"
        for name, w in wins.items()
        if isinstance(w, dict) and isinstance(w.get("utilization"), (int, float))
    ]
    if not parts:
        return ""
    reset = info.get("resetsAt")
    when = f" (resets {time.strftime('%a %H:%M', time.localtime(reset))})" if isinstance(reset, (int, float)) else ""
    return " · quota " + ", ".join(parts) + when


def turn_context(turn: dict) -> int:
    """Tokens of context one model turn was sent: input + cache read + cache write (missing = 0)."""
    return sum(v for k in ("input", "cache_read", "cache_write") if isinstance(v := turn.get(k), int))


def leg_context(turns: list[dict]) -> tuple[int, int]:
    """(context of the last turn, max context) over the turns of one leg; (0, 0) for none."""
    ctx = [turn_context(t) for t in turns]
    return (ctx[-1], max(ctx)) if ctx else (0, 0)


# ------------------------------------------------------------------ guards
@contextmanager
def signals_ignored() -> Iterator[None]:
    """Cleanup after Ctrl-C / SIGTERM must not be cut short by a second signal."""
    old = {s: signal.signal(s, signal.SIG_IGN) for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    try:
        yield
    finally:
        for s, handler in old.items():
            signal.signal(s, handler)


@contextmanager
def run_lock() -> Iterator[None]:
    """One agent at a time (CLI and UI share the Pro quota and the gate's active scope)."""
    paths.var().mkdir(parents=True, exist_ok=True)
    with open(paths.var() / "run.lock", "w") as fh:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("another bh run/hunt is in progress (var/run.lock)") from None
        yield


# Program rules decided at onboarding, out of the hunt (None = not read yet): they are the legal authorisation
# to test, which an agent cannot grant itself. Local labs are exempt.
ONBOARDING_DECISIONS = {
    "automation_allowed": "is automation (an AI agent) allowed?",
    "scanners_allowed": "are automated scanners (ffuf, nuclei, sqlmap, dalfox) allowed?",
}


class ProgramNotReady(SystemExit):
    """The program cannot be hunted until its onboarding is done. A SystemExit, so `bh run` still exits with the
    message; the supervisor catches it and parks the program instead of stopping the hunt."""

    def __init__(self, program: str, fields: list[str], message: str):
        super().__init__(message)
        self.program, self.fields = program, fields


def parked_file(program: str) -> Path:
    """Marker of a program stopped on third-party data or server-side execution (audit I11). Only the operator lifts
    it (`bh unpark <program>`), after reading the board and reporting to the program if needed."""
    return paths.var() / "parked" / f"{program}.json"


def park(program: str, reason: str, run_id: int | None) -> None:
    p = parked_file(program)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"program": program, "reason": reason, "run_id": run_id, "ts": time.time()}))


def parked(program: str) -> dict | None:
    p = parked_file(program)
    if not p.exists():
        return None
    try:
        rec = json.loads(p.read_text())
    except (OSError, ValueError):
        rec = None
    return rec if isinstance(rec, dict) else {"reason": "unreadable marker"}


def check_automation(scope: Scope) -> None:
    """Unknown program rules = onboarding not done; automation forbidden = never run; parked = never run until the
    operator lifts it. Nobody is asked mid-hunt."""
    if (rec := parked(scope.program)) is not None:
        raise ProgramNotReady(
            scope.program,
            ["parked"],
            f"{scope.program}: parked since run {rec.get('run_id')} ({rec.get('reason')}: third-party data or "
            f"server-side execution). Read the board, report it to the program if needed, then `bh unpark "
            f"{scope.program}`",
        )
    if scope.automation_allowed is False:
        raise ProgramNotReady(
            scope.program,
            ["automation_allowed"],
            f"{scope.program}: automation_allowed is false — refusing to run an agent on it",
        )
    if scope.platform == "local":
        return
    if unknown := [f for f in ONBOARDING_DECISIONS if getattr(scope, f) is None]:
        raise ProgramNotReady(
            scope.program,
            unknown,
            f"{scope.program}: {', '.join(unknown)} unknown — read the program rules and set it in the scope file",
        )


# ------------------------------------------------------------------ hunt-time memory (board meta)
REFUSAL_WINDOW_S = 7 * 86400
WAF_PAUSE_S = 3600  # same length as the gate's waf-cooldown


# A stale mark the runner can neither check nor lift (identity without `enroll` recipe nor `probe`, e.g. one made
# in the UI) stops counting after this long: the gate marks it again if the session is really dead.
UNVERIFIABLE_STALE_S = 6 * 3600


def stale_mark(board: Board, program: str, name: str) -> float:
    """When the gate last saw this identity's session die (meta `identity-stale`), 0 when never or when the identity
    file was written after it (rewriting the file lifts the mark)."""
    try:
        mark = float(board.meta_get(f"identity-stale:{name}:{program}", "0") or 0)
    except ValueError:
        return 0.0
    f = paths.identities_dir(program) / f"{name}.json"
    return mark if mark > (f.stat().st_mtime if f.exists() else 0.0) else 0.0


def verifiable(scope: Scope | None, name: str) -> bool:
    """The runner can check this identity's session before a segment: it has a login recipe or a probe."""
    decl = next((i for i in (scope.identities if scope else ()) if i["name"] == name), None)
    return bool(decl and (decl.get("enroll") or decl.get("probe")))


def live_identities(
    board: Board,
    program: str,
    also: list[str] | tuple[str, ...] = (),
    scope: Scope | None = None,
    now: float | None = None,
) -> list[str]:
    """Identity names (files, plus `also`) minus those the gate saw expire: an `identity-stale` mark newer than
    the identity file. Rewriting the file lifts the mark; so does a good probe (refresh_identities). The mark of an
    identity the runner cannot verify (see `verifiable`, needs `scope`; any identity when `scope` is None) is never
    final: it lapses after UNVERIFIABLE_STALE_S."""
    now = time.time() if now is None else now
    out = []
    for name in sorted(set(paths.identities(program)) | set(also)):
        mark = stale_mark(board, program, name)
        if not mark or (not verifiable(scope, name) and now - mark > UNVERIFIABLE_STALE_S):
            out.append(name)
    return out


LOGIN_RETRY_S = 3600  # one login attempt per identity and hour, whatever its outcome


def _probe_only(board: Board, scope: Scope, name: str, run_id: int, say) -> None:
    """An identity with a probe and no recipe, marked stale: one request through the gate. A good probe lifts the
    mark (the 401 was an access refusal, not a dead session); a bad or impossible one leaves it."""
    from bh.accounts import enroll as en

    try:
        ok, detail = en.probe(en.identity(scope, name))
    except en.AccountError as exc:
        ok, detail = None, one_line(str(exc), 200)
    if ok:
        board.meta_set(f"identity-stale:{name}:{scope.program}", "0")
    if say:
        say(f"  identity {name}: probe {'ok, stale mark lifted' if ok else f'not ok ({detail})'}")


def refresh_identities(board: Board, scope: Scope, run_id: int, say=None) -> set[str]:
    """Before a segment (and before the verification): every identity with an `enroll` recipe whose session is
    missing or stale (the gate saw it die in an earlier segment: GateOutcome.stale left the `identity-stale` mark) is
    refreshed through the gate (bh.accounts.enroll.refresh), which probes first: a good probe lifts a false stale
    mark (a 401 that was an authorization refusal, not a dead session). An identity with a probe but no recipe is
    probed when marked. Logins are rate-limited inside refresh; after a failure the identity is retried after
    LOGIN_RETRY_S. A failure is a `login-failed` blocker, never a todo.
    Returns the verifiable identities still without a live session: they stay out of the prompt."""
    from bh.accounts import enroll as en

    prog = scope.program
    files = set(paths.identities(prog))
    for ident in scope.identities:
        name = ident["name"]
        if not (ident.get("enroll") or ident.get("probe")):
            continue
        if not ident.get("enroll"):
            if stale_mark(board, prog, name) and name in files:
                _probe_only(board, scope, name, run_id, say)
            continue
        if name in files and not stale_mark(board, prog, name):
            continue
        key = f"accounts-attempt:{name}:{prog}"
        try:
            last = float(board.meta_get(key, "0") or 0)
        except ValueError:
            last = 0.0
        if time.time() - last < LOGIN_RETRY_S:  # failed recently: do not hammer the login
            continue
        try:
            outcome = en.refresh(scope, name, board=board)
            if say:
                say(f"  identity {name}: {outcome}")
        except en.AccountError as exc:
            board.meta_set(key, str(time.time()))
            board.add_blocker(prog, "login-failed", f"identity {name}", one_line(str(exc), 300), run_id=run_id)
            if say:
                say(f"  identity {name}: login failed ({one_line(str(exc), 200)})")
    files = set(paths.identities(prog))
    return {
        i["name"]
        for i in scope.identities
        if (i.get("enroll") and i["name"] not in files)
        or (verifiable(scope, i["name"]) and stale_mark(board, prog, i["name"]))
    }


# ------------------------------------------------------------------ session keeper (during a segment)
KEEP_MARGIN_S = float(os.environ.get("BH_KEEP_MARGIN_S", "120"))  # renew this long before a known expiry
KEEP_EVERY_S = 300.0  # at most one keeper login per identity in this window, whatever its outcome
KEEP_TICK_S = 15.0


def keeper_plan(
    expires: dict[str, float | None],
    dead: dict[str, float],
    last: dict[str, float],
    now: float,
    *,
    margin: float = KEEP_MARGIN_S,
    every: float = KEEP_EVERY_S,
) -> list[tuple[str, str]]:
    """Which identities to renew now, and why (pure). `expires`: name -> session `expires_at` (None: unknown);
    `dead`: name -> time of its latest `session-dead` event not yet handled; `last`: name -> last keeper login.
    A dead session goes first (`dead`, probe first), then one within `margin` of its end (`expiry`). One login per
    identity per `every` seconds: a name inside that window waits for the next tick."""
    out = []
    for name in sorted(set(expires) | set(dead)):
        if now - last.get(name, float("-inf")) < every:
            continue
        if name in dead:
            out.append((name, "dead"))
        elif (exp := expires.get(name)) is not None and now >= exp - margin:
            out.append((name, "expiry"))
    return out


class SessionKeeper:
    """A host thread alive during one segment: keeps the agent's identities logged in without stopping it (the gate
    re-reads the session file on every request). Renews an identity before its known expiry (`expires_at` minus
    KEEP_MARGIN_S) and on a `session-dead` event of the gate's journal (probe first: a 401 storm on access rules is
    no death). At most one login per identity per KEEP_EVERY_S (board meta `accounts-keeper:<name>:<program>`); a
    failure is a `login-failed` blocker. Only identities with an `enroll` recipe and a session file are kept."""

    def __init__(
        self,
        scope: Scope,
        board_path: Path,
        run_id: int,
        names: list[str],
        say=None,
        *,
        events_offset: int = 0,
        margin: float = KEEP_MARGIN_S,
        every: float = KEEP_EVERY_S,
        tick: float = KEEP_TICK_S,
        renew=None,
        clock=time.time,
    ) -> None:
        declared = {i["name"]: i for i in scope.identities}
        self.scope, self.board_path, self.run_id, self.say = scope, board_path, run_id, say
        self.names = [n for n in names if (declared.get(n) or {}).get("enroll")]
        self.offset, self.margin, self.every, self.tick_s, self.clock = events_offset, margin, every, tick, clock
        self.dead: dict[str, float] = {}
        self.renewed: dict[str, float] = {}  # name -> end of its last successful keeper login
        self._renew = renew or self._refresh
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _refresh(self, board: Board, name: str, reason: str) -> str:
        from bh.accounts import enroll as en

        return en.refresh(self.scope, name, board=board, force=True, probe_first=reason == "dead")

    def _key(self, name: str) -> str:
        return f"accounts-keeper:{name}:{self.scope.program}"

    def read_events(self) -> None:
        """New `session-dead` events of this program's kept identities since the last read (complete lines)."""
        p = paths.events_log()
        try:
            size = p.stat().st_size
            if size < self.offset:  # rotated: start over
                self.offset = 0
            with open(p, "rb") as fh:
                fh.seek(self.offset)
                chunk = fh.read()
        except OSError:
            return
        end = chunk.rfind(b"\n") + 1
        self.offset += end
        for line in chunk[:end].splitlines():
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if not isinstance(ev, dict) or ev.get("kind") != "session-dead":
                continue
            name, ts = ev.get("identity"), ev.get("ts")
            if name not in self.names or ev.get("program") not in (None, self.scope.program):
                continue
            ts = float(ts) if isinstance(ts, (int, float)) and not isinstance(ts, bool) else self.clock()
            if ts > self.renewed.get(name, 0.0):  # a death seen before our last login is the old session's
                self.dead[name] = max(ts, self.dead.get(name, 0.0))

    def tick(self, board: Board) -> list[tuple[str, str, str]]:
        """One round: read the journal, renew what is due. Returns (name, reason, outcome) per login tried."""
        from bh.accounts import enroll as en
        from bh.gate import session as gs

        self.read_events()
        now = self.clock()
        expires: dict[str, float | None] = {}
        last: dict[str, float] = {}
        for name in self.names:
            sess = gs.load(paths.identities_dir(self.scope.program) / f"{name}.json", now)
            if sess is not None:
                expires[name] = sess.get("expires_at")
            try:
                last[name] = float(board.meta_get(self._key(name), "0") or 0)
            except ValueError:
                last[name] = 0.0
        dead = {n: t for n, t in self.dead.items() if n in expires}
        done = []
        for name, reason in keeper_plan(expires, dead, last, now, margin=self.margin, every=self.every):
            board.meta_set(self._key(name), str(now))
            self.dead.pop(name, None)
            try:
                outcome = self._renew(board, name, reason)
                self.renewed[name] = self.clock()
            except en.AccountError as exc:
                outcome = f"login failed ({one_line(str(exc), 200)})"
                board.add_blocker(
                    self.scope.program, "login-failed", f"identity {name}", one_line(str(exc), 300), run_id=self.run_id
                )
            if self.say:
                self.say(f"  ⟲ identity {name} ({reason}): {outcome}")
            done.append((name, reason, outcome))
        return done

    def _loop(self) -> None:
        board = Board(self.board_path)  # sqlite: one connection per thread
        while not self._stop.wait(self.tick_s):
            try:
                self.tick(board)
            except Exception as exc:  # noqa: BLE001 (the keeper must never take the segment down)
                if self.say:
                    self.say(f"  ⚠ session keeper: {type(exc).__name__}: {one_line(str(exc), 160)}")

    def start(self) -> SessionKeeper:
        if self.names and self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="bh-session-keeper", daemon=True)
            self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(30.0, self.tick_s))
            self._thread = None


# ------------------------------------------------------------------ stop on third-party data (during a segment)
STOP_TICK_S = 2.0
STOP_TITLE = "bull-harness: STOP"


class StopWatcher:
    """A host thread alive during one segment (audit I11, MSRC rule of docs/research/15): it follows the sandbox's
    notes.jsonl and, on `bh-note blocked third-party-data|server-exec`, parks the program (marker first: it holds even
    if the push fails), pushes a ntfy WITHOUT content (program name only) and kills the agent. The runner then starts
    no other leg and judges nothing. The note itself is ingested as usual at the end of the segment."""

    def __init__(
        self,
        program: str,
        run_id: int,
        *,
        path: Path | None = None,
        notify=None,
        kill=None,
        say=None,
        tick: float = STOP_TICK_S,
    ) -> None:
        self.program, self.run_id, self.say, self.tick_s = program, run_id, say, tick
        self.path = path or paths.work_bh(program) / c.NOTES
        self._notify, self._kill = notify, kill
        self.offset, self.inode = 0, None
        self.triggered: str | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def _send(self, title: str, message: str) -> bool:
        if self._notify is not None:
            return bool(self._notify(title, message))
        from bh.browser_service import notify

        return notify.send(title, message)

    def poll(self) -> str | None:
        """Read the new complete lines; fire on the first stop reason. Returns the reason, if any."""
        with self._lock:
            try:
                st = self.path.stat()
                if st.st_ino != self.inode or st.st_size < self.offset:  # rotated mid-segment: a new file
                    self.inode, self.offset = st.st_ino, 0
                with open(self.path, "rb") as fh:
                    fh.seek(self.offset)
                    chunk = fh.read()
            except OSError:
                return self.triggered
            end = chunk.rfind(b"\n") + 1
            self.offset += end
            for line in chunk[:end].splitlines():
                try:
                    n = json.loads(line)
                except ValueError:
                    continue
                if isinstance(n, dict) and n.get("op") == "blocked" and n.get("reason") in c.STOP_REASONS:
                    self._fire(str(n["reason"]))
                    break
            return self.triggered

    def _fire(self, reason: str) -> None:
        if self.triggered:
            return
        self.triggered = reason
        park(self.program, reason, self.run_id)
        # content-free: neither the note's title nor its detail (they may describe someone else's data)
        sent = self._send(STOP_TITLE, f"{self.program}: arret, donnee tierce ou execution serveur. Voir le board.")
        if self.say:
            self.say(f"  ■ STOP {reason}: program parked, agent stopped" + ("" if sent else " (ntfy push failed)"))
        try:
            (self._kill or (lambda: stack.kill_agent(self.program)))()
        except Exception as exc:  # noqa: BLE001 (the runner checks `triggered` after the leg anyway)
            if self.say:
                self.say(f"  ⚠ stop: cannot kill the agent: {exc!r}"[:200])

    def _loop(self) -> None:
        while not self._stop.wait(self.tick_s):
            try:
                if self.poll():
                    return
            except Exception as exc:  # noqa: BLE001 (never take the segment down)
                if self.say:
                    self.say(f"  ⚠ stop watcher: {type(exc).__name__}: {one_line(str(exc), 160)}")

    def start(self) -> StopWatcher:
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="bh-stop-watcher", daemon=True)
            self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(10.0, self.tick_s * 2))
            self._thread = None


def identity_roles(scope: Scope, names: list[str]) -> str:
    """BH_IDENTITY_ROLES (contract with bh.agent): `name=role@tenant` per name, comma-separated, in the order of
    `names` (BH_IDENTITIES). An undeclared role or tenant is empty: `user-x=@`, `admin-a=admin@`."""
    decl = {i["name"]: i for i in scope.identities}
    return ",".join(f"{n}={(decl.get(n) or {}).get('role', '')}@{(decl.get(n) or {}).get('tenant', '')}" for n in names)


def _refusal_log(board: Board, program: str, now: float) -> list[tuple[float, str]]:
    """(timestamp, cause) of this program's model refusals within the last 7 days (meta `refusals:<program>`). An
    entry of the old format (a bare timestamp) is its own cause."""
    try:
        entries = json.loads(board.meta_get(f"refusals:{program}", "[]") or "[]")
    except ValueError:
        return []
    if not isinstance(entries, list):
        return []
    out = []
    for e in entries:
        ts, cause = (e.get("ts"), e.get("cause")) if isinstance(e, dict) else (e, None)
        if isinstance(ts, (int, float)) and not isinstance(ts, bool) and now - REFUSAL_WINDOW_S < ts <= now:
            out.append((float(ts), cause if isinstance(cause, str) and cause else f"@{ts}"))
    return out


def recent_refusals(board: Board, program: str, now: float | None = None) -> list[float]:
    """One timestamp per distinct cause (its first refusal) within the last 7 days: what the escalation counts.
    Three refusals on the same page are one."""
    now = time.time() if now is None else now
    first: dict[str, float] = {}
    for ts, cause in _refusal_log(board, program, now):
        first.setdefault(cause, ts)
    return sorted(first.values())


def record_refusal(board: Board, program: str, now: float | None = None, cause: str = "") -> int:
    """Add a refusal to the sliding window; returns how many distinct causes it now holds."""
    now = time.time() if now is None else now
    entries = [{"ts": ts, "cause": k} for ts, k in _refusal_log(board, program, now)]
    entries.append({"ts": now, "cause": cause or f"@{now}"})
    board.meta_set(f"refusals:{program}", json.dumps(entries))
    return len(recent_refusals(board, program, now))


def refused_before(board: Board, program: str, cause: str, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    return bool(cause) and any(k == cause for _, k in _refusal_log(board, program, now))


_URL = re.compile(r"https?://[^\s'\"<>`|;)\]}]+", re.I)


def refusal_cause(cmd: str, result_urls: list[str]) -> dict:
    """What a refusal most likely followed: the last command, and the URL it aimed at (else the first URL of the
    last tool result: the page the tool reports on comes before the links of its body). `key` is what the
    escalation compares: host + path of that URL (same page = same cause, whatever its query), else the command."""
    urls = _URL.findall(cmd or "")
    url = urls[-1] if urls else (result_urls[0] if result_urls else "")
    host, key = "", ""
    if url:
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
            key = f"{host}{parts.path.rstrip('/') or '/'}" if host else ""
        except ValueError:
            host = ""
    if not key:
        key = "cmd:" + re.sub(r"\s+", " ", cmd or "").strip()[:200] if cmd else ""
    return {"cmd": cmd or "", "url": url[:300], "host": host, "key": key}


def last_refusal(board: Board, program: str, run_id: int) -> str:
    """The command the previous run of this program was refused on ('' if it did not end on a refusal)."""
    rows = board.rows(
        "SELECT summary FROM facts WHERE program=? AND kind='blocker' AND title LIKE '[refusal]%' "
        "AND run_id=(SELECT MAX(id) FROM runs WHERE program=? AND id<?) ORDER BY id DESC LIMIT 1",
        program,
        program,
        run_id,
    )
    return (rows[0]["summary"] or "").split("\n", 1)[0] if rows else ""


# ------------------------------------------------------------------ sandbox + gate state
def activate_scope(scope_file: Path) -> None:
    """Atomically make this scope the gate's active scope (the gate hot-reloads on mtime)."""
    dst = paths.active_scope()
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(".tmp")
    shutil.copyfile(scope_file, tmp)
    os.replace(tmp, dst)


def relay_budget(max_turns: int) -> int:
    """Claude API requests the gate relays for one segment: one per turn (measured), x3 for retries and legs."""
    return 3 * max_turns + 30


def set_active_run(run_id: int | None, program: str = "", relay_max: int | None = None) -> None:
    """Tag every gate flow with the run that caused it (operator traffic between runs stays untagged). The gate
    relays Claude API calls only while a run is active, at most `relay_max` of them (gate default otherwise)."""
    p = paths.active_run()
    if run_id is None:
        p.unlink(missing_ok=True)
    else:
        rec = {"run_id": run_id, "program": program}
        if relay_max is not None:
            rec["relay_max"] = relay_max
        p.write_text(json.dumps(rec))


def sandbox_home(session: int | str) -> str:
    return f"/tmp/bh-home-{session}"


def clean_sandbox(program: str, home: str) -> None:
    """Nothing the agent wrote can configure the next session: no process of the previous one alive, fresh
    HOME (no ~/.claude settings or memory), no CLAUDE.md / CLAUDE.local.md / .claude / .mcp.json anywhere in the
    program's work tree (claude -p would load a project .mcp.json, whose tools the Bash-only hooks never see). And the
    agent reaches only this program's work dir: /work is root's, every other program's dir is closed (root, 700),
    so notes, endpoints or coverage of program B cannot be written from a segment on program A."""
    stack.reset_agent_user(home)
    _clean_work(program)


def clean_leg(program: str, home: str) -> None:
    """Before every leg after the first: the same, except that `home` keeps the session transcripts `--resume`
    needs. The previous leg's process has exited; the next one is not started yet."""
    stack.scrub_agent_user(home)
    _clean_work(program)


def _clean_work(program: str) -> None:
    r = stack.agent_sh(_WORK_SCRIPT, f"{c.WORK_ROOT}/{program}", c.WORK_ROOT, user="root", timeout=120)
    if r.returncode != 0:
        raise SystemExit(f"cannot clean the work tree of {program}: {r.stderr.strip()}")


# Claude Code reads CLAUDE.md files from the work dir up to / and from any subdirectory it touches, and settings
# from .claude/: every copy goes, at any depth (find does not follow links; rm removes a link, not its target).
_PLANTED = r"\( -name CLAUDE.md -o -name CLAUDE.local.md -o -name .claude -o -name .mcp.json \)"
_WORK_SCRIPT = rf"""
rm -rf -- "$2/CLAUDE.md" "$2/CLAUDE.local.md" "$2/.claude" "$2/.mcp.json"
chown root:root "$2" && chmod 755 "$2"
for d in "$2"/*/ "$2"/.[!.]*/; do
  d=${{d%/}}; [ -d "$d" ] && [ "$d" != "$1" ] && chown -h root:root "$d" && chmod 700 "$d"
done
if [ -L "$1" ]; then rm -f -- "$1"; fi
if [ -d "$1" ]; then find "$1" -mindepth 1 {_PLANTED} -prune -exec rm -rf -- {{}} + ; fi
rm -f -- "$1/.bh/{c.SYSTEM}"
mkdir -p "$1" && chown -h hunter:hunter "$1" && chmod 755 "$1"  # 755: the host reads it (another uid)
"""

_SYSTEM_SCRIPT = r"""
umask 022
mkdir -p /var/lib && rm -rf -- "$1" && mkdir -m 755 -- "$1" && cat > "$1/$2" && chown -R root:root -- "$1" \
  && chmod 444 -- "$1/$2"
"""


def push_system_prompt(text: str) -> None:
    """The hunter's system prompt, out of its reach: written by root under SYSTEM_DIR (see SYSTEM_FILE)."""
    r = stack.agent_sh(_SYSTEM_SCRIPT, SYSTEM_DIR, c.SYSTEM, user="root", stdin=text)
    if r.returncode != 0:
        raise SystemExit(f"cannot write the system prompt in {stack.AGENT}: {r.stderr.strip()}")


def rotate_notes(program: str, run_id: int, leg: int | None = None) -> Path:
    """Freeze this segment's notes under a per-run name (per leg for a mid-segment context rotation, so the
    end-of-segment rotation never re-reads a file already ingested); returns the host path to ingest."""
    name = f"notes-{run_id}.jsonl" if leg is None else f"notes-{run_id}-leg{leg}.jsonl"
    stack.agent_sh(
        'cd "$1" 2>/dev/null && [ -f notes.jsonl ] && mv notes.jsonl "$2"; true', c.sandbox_dir(program), name
    )
    return paths.work_bh(program) / name


def phases_for(scope: Scope | None) -> tuple[str, ...]:
    """Tool-lock phases for this program: the light ones only when it forbids automated scanners."""
    return c.required_phases(scope is None or scope.scanners_on)


def frontier(board: Board, program: str, scope: Scope | None = None) -> str:
    """Board view + the attack surface from the asset graph (needs the scope: every host is checked)."""
    if scope is None:
        return board.frontier(program)
    surface = Graph(board, scope).render(phases_for(scope))
    return board.frontier(program, passthrough=has_browser(scope)) + (f"\n{surface}" if surface else "")


def has_browser(scope: Scope | None) -> bool:
    """The scope has a host behind a human challenge: the hunt drives bh-browser (docs/research/18)."""
    return bool(scope is not None and scope.support_hosts("passthrough"))


def coverage_counts(board: Board, scope: Scope) -> tuple[int, int]:
    return Graph(board, scope).counts(phases_for(scope))


def pick_cards(board: Board, scope: Scope) -> list[str]:
    """Method cards for this segment, from the attack surface the tools found (none before mapping)."""
    endpoints = [  # the sandbox writes this file: anything but {key: str, params: [str]} is skipped
        (
            e["key"],
            [x for x in e.get("params") or [] if isinstance(x, str)] if isinstance(e.get("params"), list) else [],
        )
        for e in c.read_jsonl(paths.work_bh(scope.program) / c.ENDPOINTS)
        if isinstance(e, dict) and isinstance(e.get("key"), str)
    ]
    recent = [
        cid
        for r in board.rows(
            "SELECT cards FROM runs WHERE program=? AND cards IS NOT NULL ORDER BY id DESC LIMIT 2", scope.program
        )
        for cid in (r["cards"] or "").split(",")
        if cid
    ]
    pinned = classes.pinned_cards(scope)
    return [
        cid
        for cid in classes.select_cards(endpoints, exclude=scope.forbidden_vulns, recently_used=recent)
        if cid not in pinned
    ]


def segment_cards(scope: Scope, picked: list[str]) -> str:
    """The cards block of a task: the scope's pinned cards, always, then the picked ones."""
    return classes.cards_block(picked, classes.pinned_cards(scope), scanners=scope.scanners_on)


def prepare_workdir(board: Board, scope: Scope, scope_file: Path, identities: list[str] | None = None) -> None:
    """Push what the segment reads. `identities`: the live ones offered to the agent (BH_IDENTITIES), the only ones
    the system prompt names."""
    prog = scope.program
    if identities is None:
        identities = live_identities(board, prog, also=[i["name"] for i in scope.identities], scope=scope)
    stage = paths.stage(prog)
    stage.mkdir(parents=True, exist_ok=True)
    board.export_facts(prog, stage / c.FACTS)
    cbh = c.sandbox_dir(prog)
    # bh-note frontier = this board view + the surface recomputed live in the sandbox
    stack.push_file(f"{cbh}/{c.FRONTIER}", board.frontier(prog, passthrough=has_browser(scope)))
    tested = board.rows(
        "SELECT a.key FROM assets a WHERE a.program=? AND a.kind='endpoint' "
        "AND EXISTS (SELECT 1 FROM tests t WHERE t.asset_id=a.id)",
        prog,
    )
    stack.push_file(f"{cbh}/{c.MANUAL_TESTED}", json.dumps(sorted(r["key"].split(" ", 1) for r in tested)))
    stack.push_file(f"{cbh}/{c.FACTS}", (stage / c.FACTS).read_text())
    push_system_prompt(build_system_prompt(scope, identities))
    stack.push_file(f"{cbh}/{c.SCOPE}", Path(scope_file).read_text())


# ------------------------------------------------------------------ one claude process
def agent_command(
    scope: Scope,
    task: str,
    *,
    run_id: int,
    model: str,
    max_turns: int,
    effort: str | None,
    session: str | None,
    bh_dir: str | None = None,
    extra_env: dict[str, str] | None = None,
    user: str = "hunter",
    identities: list[str] | None = None,
) -> list[str]:
    """claude -p inside the agent for this program. `bh_dir`/`extra_env`/`user` let the verifier reuse it with
    its own work dir, role and Unix user. `identities`: the names offered to the agent (default: every one)."""
    prog = scope.program
    bh = bh_dir or c.sandbox_dir(prog)
    if identities is None:
        identities = sorted({i["name"] for i in scope.identities} | set(paths.identities(prog)))
    env = {
        "BH_DIR": bh,
        "BH_PROGRAM": prog,
        "BH_RPS": f"{scope.rate:g}",
        "BH_SCANNERS": "1" if scope.scanners_on else "0",
        "BH_IDENTITIES": ",".join(identities),
        "BH_IDENTITY_ROLES": identity_roles(scope, identities),  # never a secret: role and tenant labels
        "HOME": sandbox_home(run_id),
        **BASH_TIMEOUT_MS,
        **(extra_env or {}),
    }
    cmd = [
        "podman",
        "exec",
        "-i",
        "--user",
        user,
        "-w",
        f"{c.WORK_ROOT}/{prog}",
        *[x for k, v in env.items() for x in ("-e", f"{k}={v}")],
        # the wrapper records claude's pid so stack.kill_agent can stop it from the host
        stack.AGENT,
        "sh",
        "-c",
        f'echo $$ > "$BH_DIR/{c.AGENT_PID}"; exec claude "$@"',
        "sh",
        "-p",
        task,
        "--output-format",
        "stream-json",
        "--verbose",
        "--model",
        model,
        "--max-turns",
        str(max_turns),
        "--permission-mode",
        "bypassPermissions",
        "--tools",
        AGENT_TOOLS,
        "--disable-slash-commands",
        "--settings",
        "/opt/bh/hooks/settings.json",
        "--strict-mcp-config",  # no --mcp-config: no MCP server at all, whatever the work tree holds
        "--append-system-prompt-file",
        f"{bh_dir}/{c.SYSTEM}" if bh_dir else SYSTEM_FILE,  # the verifier's is pushed by bh.verify
    ]
    if effort:
        cmd += ["--effort", effort]
    if session:
        cmd += ["--resume", session]
    return cmd


_QUOTED = re.compile(r"'[^']*'|\"(?:[^\"\\]|\\.)*\"")


def command_kind(cmd: str) -> str:
    """arsenal | manual | note | other: how a Bash command is counted in the metrics. Quoted text is ignored for
    the arsenal test: a note that mentions sqlmap is not a sqlmap run."""
    if c.uses_arsenal(_QUOTED.sub("''", cmd)):
        return "arsenal"
    if c.uses_manual_http(cmd):
        return "manual"
    return "note" if "bh-note" in cmd else "other"


def _tool_result_text(block: dict) -> str:
    content = block.get("content")
    if isinstance(content, list):
        return "\n".join(t for x in content if isinstance(x, dict) and isinstance(t := x.get("text"), str))
    return content if isinstance(content, str) else ""


def _str(v) -> str:
    return v if isinstance(v, str) else ""


def _int(v) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def rate_limit_info(info, now: float | None = None) -> dict:
    """The stream's `rate_limit_info`, kept only as a dict; a `resetsAt` that is not a time within the next
    RESET_HORIZON_S is dropped (a forged far reset must not put the hunt to sleep for days)."""
    if not isinstance(info, dict):
        return {}
    now = time.time() if now is None else now
    out = dict(info)
    reset = out.get("resetsAt")
    if "resetsAt" in out and not (
        isinstance(reset, (int, float)) and not isinstance(reset, bool) and now - 86400 < reset <= now + RESET_HORIZON_S
    ):
        del out["resetsAt"]
    return out


_USAGE = (
    ("input", "input_tokens"),
    ("cache_read", "cache_read_input_tokens"),
    ("cache_write", "cache_creation_input_tokens"),
    ("output", "output_tokens"),
)


def consume_stream(
    proc: subprocess.Popen, log: IO[str], res: SegmentResult, say, *, limit: int | None = None, stop=None
) -> dict | None:
    """Mirror the stream to the run log (the UI tails it), update `res`, return the result event.
    `limit`: once a turn's context exceeds it, `stop()` is called when that turn's tool results are back
    (the turn in progress ends, the next one is cut) and `res.overflow` is set.
    The hunter can write into this stream: a line that is not a JSON object, or a field of the wrong type, is
    skipped; what it says about refusals and quota is checked after the segment."""
    result = None
    over = False
    for line in proc.stdout:
        log.write(line)
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if not isinstance(ev, dict):
            continue
        match ev.get("type"):
            case "system" if ev.get("subtype") == "init":
                res.session_id = _str(ev.get("session_id")) or res.session_id
            case "assistant":
                msg = ev.get("message")
                msg = msg if isinstance(msg, dict) else {}
                mid = _str(msg.get("id"))
                if msg.get("stop_reason") == "refusal":
                    res.status = "refusal"  # no further leg either way; refusal_confirmed decides what it costs
                    if res.refusal_id is None:
                        last = next((t["cmd"] for t in reversed(res.tool_log) if t.get("cmd")), "")
                        res.refusal_id = mid
                        res.refusal_cause = refusal_cause(last, res._last_urls)
                if mid and mid not in {t["id"] for t in res.turn_log[-3:]}:
                    u = msg.get("usage")
                    u = u if isinstance(u, dict) else {}
                    turn = {"id": mid, "ts": time.time(), **{k: _int(u.get(f)) for k, f in _USAGE}}
                    res.turn_log.append(turn)
                    if limit and not over and (ctx := turn_context(turn)) > limit:
                        over = True
                        say(f"  ⚠ context {ctx} tokens > {limit}: the leg stops after this turn")
                content = msg.get("content")
                for block in content if isinstance(content, list) else []:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "text" and _str(block.get("text")).strip():
                        say(f"  💬 {one_line(block['text'], 220)}")
                    elif block.get("type") == "tool_use":
                        res.tool_calls += 1
                        inp = block.get("input")
                        inp = inp if isinstance(inp, dict) else {}
                        cmd = _str(inp.get("command"))
                        res.arsenal_calls += c.uses_arsenal(cmd)
                        res.manual_calls += c.uses_manual_http(cmd)
                        if tid := _str(block.get("id")):
                            res._pending[tid] = len(res.tool_log)
                        name = _str(block.get("name"))
                        res.tool_log.append(
                            {
                                "ts": time.time(),
                                "tool": name,
                                "kind": command_kind(cmd),
                                "cmd": cmd[:300],
                                "ms": None,
                                "locked": False,
                            }
                        )
                        say(f"  ⚙ {name}: {one_line(cmd or _str(inp.get('description')) or str(inp))}")
            case "user":
                msg = ev.get("message")
                content = msg.get("content") if isinstance(msg, dict) else None
                for block in content if isinstance(content, list) else []:
                    if not isinstance(block, dict) or block.get("type") != "tool_result":
                        continue
                    text = _tool_result_text(block)
                    res._last_urls = _URL.findall(text[:20000])[:5]
                    locked = any(m in text for m in (c.LOCK_MARK, c.RULES_MARK))
                    if (i := res._pending.pop(_str(block.get("tool_use_id")), None)) is not None:
                        call = res.tool_log[i]
                        call["ms"], call["locked"] = int((time.time() - call["ts"]) * 1000), locked
                    if locked:
                        res.locked_calls += 1
                        say("  🔒 manual HTTP refused by the tool lock")
                    if over and not res.overflow and stop is not None:  # the turn's tool results are back
                        res.overflow = True
                        stop()
            case "rate_limit_event":
                res.rate_limit = rate_limit_info(ev.get("rate_limit_info"))
            case "result":
                result = ev
    return result


def run_leg(
    cmd: list[str],
    log: IO[str],
    err_path: Path,
    res: SegmentResult,
    say,
    *,
    program: str,
    timeout_s: float,
    bh_dir: str | None = None,
    context_limit: int | None = None,
) -> tuple[dict | None, bool]:
    """One claude process. Returns (result event, timed out). Past `context_limit` the process is stopped after
    the turn in progress, the same way as on timeout; `res.overflow` tells the two apart."""
    res.overflow = False
    with open(err_path, "a") as err_fh:  # a pipe read only at the end can fill up and block claude
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=err_fh, text=True, bufsize=1)
    timed_out = threading.Event()

    def kill() -> None:
        stack.kill_agent(program, bh_dir=bh_dir)
        time.sleep(5)
        if proc.poll() is None:
            proc.kill()

    def on_timeout() -> None:
        timed_out.set()
        kill()

    killers: list[threading.Thread] = []

    def on_overflow() -> None:  # off the reading thread: the stream keeps draining until claude exits
        t = threading.Thread(target=kill, daemon=True)
        killers.append(t)
        t.start()

    timer = threading.Timer(max(1.0, timeout_s), on_timeout)
    timer.start()
    try:
        result = consume_stream(proc, log, res, say, limit=context_limit, stop=on_overflow)
    except BaseException:
        with signals_ignored():
            timer.cancel()
            stack.kill_agent(program, bh_dir=bh_dir)
            if proc.poll() is None:
                proc.kill()
            proc.wait()
        raise
    finally:
        timer.cancel()
    proc.wait()
    # a kill still in flight reads the pid file: it must be done before the next leg's wrapper rewrites it
    for t in (timer, *killers):
        if t.is_alive():
            t.join()
    return result, timed_out.is_set()


def merge_result(res: SegmentResult, result: dict | None) -> None:
    if not result:
        return
    res.session_id = _str(result.get("session_id")) or res.session_id
    res.turns += _int(result.get("num_turns")) or 0
    cost = result.get("total_cost_usd")
    res.cost_usd += cost if isinstance(cost, (int, float)) and not isinstance(cost, bool) else 0.0
    usage = result.get("usage")
    for k, v in (usage if isinstance(usage, dict) else {}).items():
        if _int(v) is not None:
            res.usage[k] = res.usage.get(k, 0) + v
    res.text = _str(result.get("result"))
    if res.status != "refusal":
        sub = result.get("subtype", "")
        res.status = (
            "ok"
            if sub == "success" and not result.get("is_error")
            else "max_turns"
            if sub == "error_max_turns"
            else "error"
        )


def gate_counts(board: Board, run_id: int) -> dict[str, int]:
    """What the gate did for this run (flows and events are tagged with the run id); logs read from a cursor."""
    flows = [
        f
        for f in board.new_lines(paths.flows_log(), "gate-counts:flows")
        if f.get("run") == run_id and f.get("class") in (None, "target")
    ]
    events = board.new_lines(paths.events_log(), "gate-counts:events")
    denied = sum(
        1
        for e in events
        if e.get("run") == run_id and e.get("kind") == "blocked" and e.get("client", "agent") in ("agent", "judge")
    )
    return {
        "gate_requests": len(flows),
        "gate_denied": denied,
        "gate_errors": sum(1 for f in flows if f.get("status") == "error"),
        "gate_pushback": sum(1 for f in flows if f.get("status") in (429, 503)),
    }


# ------------------------------------------------------------------ what the stream claims, checked
# The hunter shares claude's uid: it can write into claude's stdout and stderr (/proc/<pid>/fd), not into the gate's
# journal. The relay logs every Claude API request of the run (`kind: relay`); when the gate also logs what came back
# (`status` of the upstream response, `msg_id` of the message it streamed), those fields decide.
def events_size() -> int:
    try:
        return paths.events_log().stat().st_size
    except OSError:
        return 0


def relay_events(run_id: int, offset: int = 0) -> list[dict]:
    """The relay's lines for this run in the gate's journal, from `offset` (its size when the segment began)."""
    try:
        if paths.events_log().stat().st_size < offset:  # rotated meanwhile: read it all
            offset = 0
    except OSError:
        return []
    lines = c.read_jsonl(paths.events_log(), offset)
    return [e for e in lines if isinstance(e, dict) and e.get("kind") == "relay" and e.get("run") == run_id]


def refusal_confirmed(res: SegmentResult, relay: list[dict]) -> bool:
    """A refusal stands when the refused message is one the relay streamed: its id among the relay's `msg_id`s (with
    `stop_reason`, when logged, `refusal`). While the gate logs no message id, the stream's word stands: wrongly
    ignoring a real refusal (rephrasing on the CVP account) costs more than a forged one, which the escalation
    counts once per page (record_refusal)."""
    seen = {e["msg_id"]: e.get("stop_reason") for e in relay if isinstance(e.get("msg_id"), str)}
    if not seen:
        return True
    return res.refusal_id in seen and seen[res.refusal_id] in (None, "refusal")


def quota_confirmed(res: SegmentResult, stderr: str, relay: list[dict]) -> bool:
    """A quota stop needs the stream's `rate_limit_event` (`rejected`) and a second source: a 429 from upstream in
    the relay's journal when the gate logs response statuses for this run, else claude's stderr (QUOTA_RE). The
    model's text never counts: it quotes target pages."""
    if res.rate_limit.get("status") != "rejected":
        return False
    statuses = [s for e in relay if (s := _int(e.get("status"))) is not None]
    if statuses:
        return 429 in statuses
    return bool(QUOTA_RE.search(stderr))


def finish(
    board: Board, res: SegmentResult, scope: Scope, before: tuple[int, int], *, effort: str | None, note: str
) -> None:
    """Ingest what the segment left and act on its walls without anyone: a refusal closes its lead, WAF hosts are
    set aside, new out-of-scope hosts are recorded once."""
    prog = scope.program
    facts, findings, blockers = ingest.notes(board, prog, res.run_id, rotate_notes(prog, res.run_id), scope)
    # added to what a mid-segment context rotation already ingested
    res.new_facts += facts
    res.new_findings += findings
    res.new_blockers += blockers
    outcome = ingest.gate_events(board, prog, res.run_id, live_identities(board, prog, scope=scope))
    res.new_blockers += outcome.blockers
    if res.status == "refusal":
        # never rephrased: the next task names the command as a closed lead (last_refusal reads the first line). The
        # blocker aims at the page (or host) the refusal followed: a target that makes the model refuse closes that
        # page, and the escalation counts it once however often it comes back.
        cause = res.refusal_cause or refusal_cause(
            next((t["cmd"] for t in reversed(res.tool_log) if t.get("cmd")), ""), []
        )
        last = cause.get("cmd") or "(no command recorded)"
        board.add_blocker(
            prog,
            "refusal",
            one_line(cause.get("url") or cause.get("host") or f"run {res.run_id}", 200),
            f"{one_line(last, 200)}\ncause: {one_line(cause.get('key') or '?', 200)}\n"
            f"log: {paths.run_log(res.run_id, prog)}",
            run_id=res.run_id,
            host=cause.get("host") or None,
        )
        res.new_blockers += 1
        res.refusal_repeat = refused_before(board, prog, cause.get("key", ""))
        record_refusal(board, prog, cause=cause.get("key", ""))
    board.record_metrics(res.run_id, res.turn_log, res.tool_log)
    board.run_set(res.run_id, blockers=res.new_blockers, **gate_counts(board, res.run_id))
    board.run_set(res.run_id, rotations=res.rotations, max_context=max(res.leg_context, default=None))
    graph = Graph(board, scope)
    graph.sync(res.run_id)
    for r in board.rows("SELECT id, url FROM findings WHERE run_id=? AND url IS NOT NULL", res.run_id):
        graph.link(r["url"], "finding", r["id"])
    until = time.time() + WAF_PAUSE_S
    for host in sorted(outcome.waf_hosts - {"?", ""}):
        graph.mark_blocked(host, "waf", until)
    if graph.new_out_of_scope:  # read at the next onboarding review, never added to the scope
        board.add_fact(
            prog,
            f"{len(graph.new_out_of_scope)} new out-of-scope host(s)",
            ", ".join(graph.new_out_of_scope),
            kind="out-of-scope",
            run_id=res.run_id,
        )
    board.db.commit()
    after = coverage_counts(board, scope)
    res.progress = res.new_findings + max(0, after[0] - before[0]) + max(0, after[1] - before[1])
    u = res.usage
    board.run_end(
        res.run_id,
        status=res.status,
        session_id=res.session_id,
        turns=res.turns,
        cost_usd=res.cost_usd or None,
        input_tokens=u.get("input_tokens"),
        output_tokens=u.get("output_tokens"),
        cache_read=u.get("cache_read_input_tokens"),
        cache_write=u.get("cache_creation_input_tokens"),
        effort=effort,
        arsenal_calls=res.arsenal_calls,
        manual_calls=res.manual_calls,
        locked_calls=res.locked_calls,
        note=one_line(note, 500),
    )


def last_fact_id(board: Board) -> int:
    return board.rows("SELECT COALESCE(MAX(id), 0) AS n FROM facts")[0]["n"]


def browser_status(call=None) -> dict | None:
    """bh-browser's state as the host sees it (op `status`), None when it cannot be read: never raises."""
    try:
        if call is None:
            from bh.browser_service import host

            call = host.call
        st = call({"op": "status"})
    except Exception:  # noqa: BLE001 (a handoff never fails on the browser)
        return None
    return st if isinstance(st, dict) and "error" not in st else None


def browser_line(st: dict | None) -> str:
    """One bounded line for the HANDOFF: page (scheme, host and path: no query, no title, both written by the target),
    identity, challenge."""
    if not st:
        return ""
    try:
        u = urlsplit(str(st.get("url") or ""))
        page = f"{u.scheme}://{u.hostname}{u.path}" if u.hostname else "-"
    except ValueError:
        page = "-"
    ch = st.get("challenge") if isinstance(st.get("challenge"), dict) else {}
    return one_line(
        f"bh-web: page {page[:120]} · identity {st.get('identity') or '-'} · "
        "challenge " + ("PENDING (`bh-web state` first, then resume the last intent)" if ch.get("pending") else "none"),
        260,
    )


def challenge_pending(st: dict | None) -> bool:
    ch = st.get("challenge") if isinstance(st, dict) else None
    return isinstance(ch, dict) and ch.get("pending") is True


def challenge_resume(board: Board, program: str, *, replay: bool = True) -> str:
    """First line of the next leg's task when a human challenge was still pending as the leg ended: the hunt goes on
    with the task it was on, never with another surface (Mio, 2026-11-26). `replay` False (T9: this leg's requests
    with effects already left the sandbox): the intent is named, never handed back to be sent again."""
    if not replay:
        return (
            "A human challenge was pending: `bh-web state` first. [bh] This leg already sent requests with effects: "
            "check on the page what the last one did before sending anything again."
        )
    rows = board.rows(
        "SELECT id, title FROM intents WHERE program=? AND status='open' ORDER BY id DESC LIMIT 1", program
    )
    what = f"I{rows[0]['id']} {one_line(rows[0]['title'], 120)}" if rows else "what you were doing"
    return f"A human challenge was pending: `bh-web state` first, then resume {what}."


def auto_handoff(
    board: Board, program: str, run_id: int, *, since: int, context: int, last_cmd: str, browser: str = ""
) -> tuple[str, str]:
    """(title, summary) of the HANDOFF the runner writes when a session rotates without one. Built from the board
    (the agent's own notes, each title cut to one bounded line), the last command and `browser` (browser_line),
    never from target output."""
    intents = board.rows(
        "SELECT id, title FROM intents WHERE program=? AND status='open' ORDER BY id DESC LIMIT 5", program
    )
    facts = board.rows(
        "SELECT kind, title FROM facts WHERE program=? AND run_id=? AND id>? AND kind IN ('fact', 'recon', 'dead-end') "
        "ORDER BY id DESC LIMIT 6",
        program,
        run_id,
        since,
    )
    findings = board.rows("SELECT id, title FROM findings WHERE program=? AND run_id=? ORDER BY id", program, run_id)
    lines = [f"Written by the runner: the session reached {context} tokens of context and rotated before its HANDOFF."]
    if findings:
        lines.append("Findings this run: " + "; ".join(f"F{r['id']} {one_line(r['title'], 80)}" for r in findings))
    if intents:
        lines.append("Open intents: " + "; ".join(f"I{r['id']} {one_line(r['title'], 80)}" for r in intents))
    if dead := [r for r in facts if r["kind"] == "dead-end"]:
        lines.append("Dead ends (do not redo): " + "; ".join(one_line(r["title"], 80) for r in dead))
    if done := [r for r in facts if r["kind"] != "dead-end"]:
        lines.append("Recorded: " + "; ".join(one_line(r["title"], 80) for r in done))
    if last_cmd:
        lines.append("Last command: " + one_line(last_cmd, 150))
    if browser:
        lines.append(browser)
    return f"HANDOFF (runner): context rotation at {context} tokens", "\n".join(lines)


def prepare_rotation(
    board: Board,
    scope: Scope,
    scope_file: Path,
    res: SegmentResult,
    *,
    since: int,
    context: int,
    identities: list[str] | None = None,
    stopper: StopWatcher | None = None,
) -> bool:
    """Before a fresh session takes over mid-segment: ingest the notes so far, write the HANDOFF if none was
    ingested since fact id `since`, push the updated frontier to the sandbox. True when the runner wrote it."""
    prog = scope.program
    if stopper is not None:  # the last lines of the file about to move: a stop note in them still fires
        stopper.poll()
    facts, findings, blockers = ingest.notes(board, prog, res.run_id, rotate_notes(prog, res.run_id, res.legs), scope)
    res.new_facts += facts
    res.new_findings += findings
    res.new_blockers += blockers
    wrote = not board.rows(
        "SELECT 1 FROM facts WHERE program=? AND run_id=? AND kind='handoff' AND id>? LIMIT 1", prog, res.run_id, since
    )
    if wrote:
        last = next((t["cmd"] for t in reversed(res.tool_log) if t.get("cmd")), "")
        browser = browser_line(browser_status()) if has_browser(scope) else ""
        title, summary = auto_handoff(
            board, prog, res.run_id, since=since, context=context, last_cmd=last, browser=browser
        )
        board.add_fact(prog, title, summary, kind="handoff", run_id=res.run_id)
    Graph(board, scope).sync(res.run_id)
    prepare_workdir(board, scope, scope_file, identities)
    return wrote


def pending_findings(board: Board, program: str) -> int:
    """Findings with a proof or an observation still waiting for the judge ('verifying' = a verification that died
    mid-way)."""
    return board.rows(
        "SELECT COUNT(*) AS n FROM findings WHERE program=? AND status IN ('new', 'verifying') "
        "AND (proof IS NOT NULL OR observation IS NOT NULL)",
        program,
    )[0]["n"]


# ------------------------------------------------------------------ harness lines, journal checks (W1)
# Lines the runner adds to a task it builds, signed `[bh]`: facts the harness observed, never how to end a segment.
EARLY_STOP_LINE = (
    "[bh] The previous leg closed itself on an announced action it never ran (early stop recorded by the harness)."
)
NO_PROMPT_LINE = "[bh] no prompt this run: HTTP surfaces only"
# T11: the last message of a leg that closes itself announces an action it never ran.
_ANNOUNCED = re.compile(
    r"\bnext,?\s+i(?:'ll|\u2019ll| will)\b|\bi(?:'ll|\u2019ll| will) now\b|\bnow,?\s+i(?:'ll|\u2019ll| will)\b"
    r"|\bproceeding to\b|\blet me now\b|(?:\.\.\.|\u2026)\s*$",
    re.I,
)
ANNOUNCE_TAIL = 400  # chars of the last message searched: the announcement is its end, not a plan quoted earlier


def announced_action(text: str) -> bool:
    """The text ends on an action announced and not run: "Next, I will...", "I'll now...", "Proceeding to...",
    a final ellipsis."""
    tail = (text or "").strip()[-ANNOUNCE_TAIL:]
    return bool(tail) and bool(_ANNOUNCED.search(tail))


def early_stop(res: SegmentResult, result: dict | None, *, timed_out: bool, max_turns: int) -> bool:
    """The leg closed itself (a success result, not cut by the runner or the clock) before its turn budget, on an
    announced action."""
    return (
        result is not None
        and res.status == "ok"
        and not res.overflow
        and not timed_out
        and res.turns < max_turns
        and announced_action(res.text)
    )


def early_stop_key(program: str) -> str:
    return f"early-stop:{program}"


WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
FILL_KINDS = frozenset({"fill", "bh-web-fill"})


def _since(rec: dict, since: float) -> bool:
    ts = rec.get("ts")
    return isinstance(ts, (int, float)) and not isinstance(ts, bool) and ts >= since


def left_the_sandbox(run_id: int, since: float) -> bool:
    """T9: something of this run left the sandbox with an effect since `since`, per the gate's journal (out of the
    sandbox's reach): a POST/PUT/PATCH/DELETE request, a client websocket message, a bh-web `fill`. The host's own
    logins (class `enroll`) are not the run's actions."""
    for f in c.read_jsonl(paths.flows_log()):
        if (
            isinstance(f, dict)
            and f.get("run") == run_id
            and _since(f, since)
            and str(f.get("method", "")).upper() in WRITE_METHODS
            and f.get("class") != "enroll"
        ):
            return True
    for e in c.read_jsonl(paths.events_log()):
        if not isinstance(e, dict) or e.get("run") != run_id or not _since(e, since):
            continue
        kind = e.get("kind")
        if kind == "ws-message" and e.get("from") == "client":
            return True
        if kind in FILL_KINDS or (kind == "bh-web" and e.get("op") == "fill"):
            return True
    return False


def resumable(board: Board, program: str) -> str | None:
    """The session an automatic resume would reopen, None when that run left the sandbox (T9): the resume then
    starts a fresh session from the board instead of replaying the intent in progress."""
    rows = board.rows(
        "SELECT id, started, session_id FROM runs WHERE program=? AND session_id IS NOT NULL ORDER BY id DESC LIMIT 1",
        program,
    )
    if not rows:
        return None
    return None if left_the_sandbox(rows[0]["id"], rows[0]["started"]) else rows[0]["session_id"]


BUDGET = "budget.json"  # /work/<program>/.bh/budget.json, read by the agent's hook (T7)


def push_budget(program: str, max_turns: int, used: int) -> None:
    stack.push_file(
        f"{c.sandbox_dir(program)}/{BUDGET}",
        json.dumps({"max_turns": int(max_turns), "used": int(used), "ts": time.time()}),
        user="root",  # the hunter reads it, never rewrites it in place
    )


# ------------------------------------------------------------------ bh-browser budget and friction (R44, D35)
def browser_prompts(scope: Scope, st: dict | None, runs_left: int, say) -> dict[str, int] | None:
    """Prompts per identity for this run, None when the controller gives no quotas (its own limits apply) or the
    program is local."""
    if scope.platform == "local":
        return None
    quotas = st.get("quotas") if isinstance(st, dict) else None
    if not isinstance(quotas, dict) or not quotas:
        say("  bh-browser: status " + ("has no quotas" if st else "unreadable") + ": no prompt allotment this run")
        return None
    from bh.runner.supervisor import prompt_allotment

    return prompt_allotment(quotas, runs_left)


def prepare_browser(scope: Scope, identities: list[str], say, prompts: dict[str, int] | None) -> str | None:
    """watch.prepare with the run's prompt allotment, when the controller takes one."""
    import inspect

    try:
        takes = "prompts" in inspect.signature(browser_watch.prepare).parameters
    except (TypeError, ValueError):
        takes = False
    if takes:
        return browser_watch.prepare(scope, identities, say, prompts=prompts)
    if prompts is not None:
        say("  bh-browser: this controller takes no prompt allotment; its own fill limits apply")
    return browser_watch.prepare(scope, identities, say)


def _counters(st: dict | None) -> dict[str, int] | None:
    cnt = st.get("counters") if isinstance(st, dict) else None
    if not isinstance(cnt, dict):
        return None
    out = {k: v for k in ("challenges", "sessions") if isinstance(v := cnt.get(k), int) and not isinstance(v, bool)}
    return out if len(out) == 2 else None


def browser_pushback(run_id: int, offset: int = 0) -> int:
    """429 / 503 answers the `browser` client got for this run, per the gate's flows journal (from `offset`)."""
    try:
        if paths.flows_log().stat().st_size < offset:
            offset = 0
    except OSError:
        return 0
    return sum(
        1
        for f in c.read_jsonl(paths.flows_log(), offset)
        if isinstance(f, dict)
        and f.get("run") == run_id
        and f.get("status") in (429, 503)
        and (f.get("client") == "browser" or f.get("browser") is True)
    )


def friction(start: dict | None, end: dict | None, run_id: int, flows_at: int) -> dict | None:
    """D35: {"challenges_extra", "browser_429"} of a bh-browser segment, None when the end status is unreadable.
    One challenge per new session is the normal regime: only the challenges beyond the sessions are friction."""
    e = _counters(end)
    if e is None:
        return None
    s = _counters(start) or {"challenges": 0, "sessions": 0}
    if e["challenges"] < s["challenges"] or e["sessions"] < s["sessions"]:  # the counters restarted meanwhile
        s = {"challenges": 0, "sessions": 0}
    extra = max(0, (e["challenges"] - s["challenges"]) - (e["sessions"] - s["sessions"]))
    return {"challenges_extra": extra, "browser_429": browser_pushback(run_id, flows_at)}


def quota_record(st: dict | None, ident: str | None, prompts: dict[str, int] | None) -> dict | None:
    """R44: {"identity", "allot", "sent", "remaining_pct", "spent"} (+ clock_mismatch) of the identity this run
    used, read in the controller's status at the close; None when unreadable."""
    quotas = st.get("quotas") if isinstance(st, dict) else None
    if not ident or not isinstance(quotas, dict) or not isinstance(q := quotas.get(ident), dict):
        return None
    rec = {
        "identity": ident,
        "allot": (prompts or {}).get(ident) if prompts is not None else None,
        "sent": q.get("sent"),
        "remaining_pct": q.get("remaining_pct"),
        "spent": q.get("spent"),
    }
    if "clock_mismatch" in q:
        rec["clock_mismatch"] = q["clock_mismatch"]
    elif "clock_mismatch" in st:
        rec["clock_mismatch"] = st["clock_mismatch"]
    return rec


def close_browser(
    board: Board,
    run_id: int,
    counters_at: dict | None,
    loaded: str | None,
    prompts: dict[str, int] | None,
    flows_at: int,
    status=None,
) -> None:
    """At the close of a bh-browser segment: runs.friction and runs.quota from the controller's status (NULL when
    it cannot be read). Never raises: the segment's own record comes first."""
    try:
        st = (status or browser_status)()
        fr = friction(counters_at, st, run_id, flows_at)
        qu = quota_record(st, loaded, prompts)
        board.run_set(
            run_id,
            friction=json.dumps(fr, sort_keys=True) if fr is not None else None,
            quota=json.dumps(qu, sort_keys=True) if qu is not None else None,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"  ⚠ bh-browser friction/quota not recorded: {type(exc).__name__}: {one_line(str(exc), 160)}")


def flows_size() -> int:
    try:
        return paths.flows_log().stat().st_size
    except OSError:
        return 0


# ------------------------------------------------------------------ setup identity (T10)
TASK_TEMPLATE_BOARD = "{board}"  # the task's template is rendered on this placeholder: the board is not the setup


def record_setup(
    board: Board,
    run_id: int,
    scope: Scope,
    *,
    model: str,
    effort: str | None,
    max_turns: int,
    minutes: float,
    system_prompt: str,
    task: str,
    cards: list[str],
    shape: dict,
) -> str:
    """runs.setup_sha256 / setup_json, and the segment's system prompt and task under var/runs/."""
    from bh.browser_service import controller
    from bh.runner import supervisor as sv
    from bh.verify import verifier_model

    template = build_task(TASK_TEMPLATE_BOARD, first=False, max_turns=max_turns, **shape)
    digest, doc = identity.setup(
        scope,
        model=model,
        effort=effort,
        verifier_model=verifier_model(model),
        max_turns=max_turns,
        minutes=minutes,
        system_prompt=system_prompt,
        task_template=template,
        cards=cards,
        max_runs_per_day=sv.MAX_RUNS_PER_DAY,
        runs_per_session=sv.RUNS_PER_SESSION,
        sessions_per_day=sv.SESSIONS_PER_DAY,
        fill_segment=controller.FILL_SEGMENT,
        fill_day=controller.FILL_DAY,
        prompt_quantum=sv.PROMPT_QUANTUM,
        prompt_floor=sv.PROMPT_FLOOR,
    )
    board.run_set(run_id, setup_sha256=digest, setup_json=identity.canonical(doc))
    paths.runs_dir().mkdir(parents=True, exist_ok=True)
    paths.run_text(run_id, "system").write_text(system_prompt)
    paths.run_text(run_id, "task").write_text(task)
    return digest


# ------------------------------------------------------------------ segment
def run_segment(
    scope_file: Path,
    *,
    model: str = DEFAULT_MODEL,
    max_turns: int = 60,
    minutes: float = 30,
    resume: bool = False,
    board: Board | None = None,
    quiet: bool = False,
    extra_task: str = "",
    effort: str | None = None,
    phase: str | None = None,
    session: str | None = None,
    runs_left: int = 1,
    preflight: bool | dict = True,
) -> SegmentResult:
    """One segment. `phase` / `session`: the caps this run counts in (supervisor.admit: refused with the reason,
    before anything starts). `preflight`: True runs the gate's self-test first (bh.runner.preflight), a dict is the
    result of one already passed in this hunt. `runs_left`: runs this program may still get today (R44)."""
    from bh.runner import preflight as gate_check
    from bh.runner import supervisor as sv

    scope = load_scope(scope_file)
    board = board or Board()
    identity.ensure(board)
    check_automation(scope)
    for name in (stack.GATE, stack.AGENT):
        if not stack.container_running(name):
            raise SystemExit(f"container {name} is not running — start the stack with `bh up`")
    try:
        classes.pinned_cards(scope)  # an operator error, said before anything starts
    except ValueError as exc:
        raise SystemExit(f"{scope.program}: {exc}") from None
    say = (lambda _m: None) if quiet else (lambda m: print(m, flush=True))
    with run_lock():
        phase, session = sv.admit(board, scope, phase=phase, session=session, now=time.time())
        if isinstance(preflight, dict):
            checked = preflight
        elif preflight and gate_check.enabled(scope, say=say):
            checked = gate_check.require(scope, scope_file=Path(scope_file), say=say)
        else:
            checked = {"ok": None, "skipped": "BH_PREFLIGHT=0 (local program)", "ts": time.time()}
            say(f"preflight: skipped for {scope.platform}/{scope.program} (BH_PREFLIGHT=0)")
        return _run_locked(
            scope,
            scope_file,
            board,
            model=model,
            max_turns=max_turns,
            minutes=minutes,
            resume=resume,
            quiet=quiet,
            extra_task=extra_task,
            effort=effort,
            phase=phase,
            session=session,
            runs_left=runs_left,
            preflight=checked,
        )


def _run_locked(
    scope: Scope,
    scope_file: Path,
    board: Board,
    *,
    model: str,
    max_turns: int,
    minutes: float,
    resume: bool,
    quiet: bool,
    extra_task: str,
    effort: str | None,
    phase: str | None = None,
    session: str | None = None,
    runs_left: int = 1,
    preflight: dict | None = None,
) -> SegmentResult:
    prog = scope.program
    identity.ensure(board)
    say = (lambda _m: None) if quiet else (lambda m: print(m, flush=True))
    try:  # under the lock, before the gate sees this segment: every log consumer is up to date
        retention.prune()
    except OSError as exc:
        print(f"retention: {exc}", file=sys.stderr)
    activate_scope(scope_file)
    hunt_session = session
    session = None
    if resume:  # T9: a run that left the sandbox is never resumed: a fresh session from the board instead
        session = resumable(board, prog)
        if session is None and board.last_session(prog):
            say(f"  ↺ {prog}: the last run sent requests with effects: fresh session from the board, no resume")
    first = session is None and not board.rows("SELECT 1 FROM facts WHERE program=? LIMIT 1", prog)
    run_id = board.run_start(prog, model)  # closes a run orphaned by a crash (we hold the lock)
    board.run_set(
        run_id,
        phase=phase,
        session=hunt_session,
        preflight=json.dumps(preflight, sort_keys=True) if preflight is not None else None,
        early_stop=0,
    )
    clean_sandbox(prog, sandbox_home(run_id))
    # before the prompt is written: a recipe identity without a live session is left out of it
    no_session = refresh_identities(board, scope, run_id, None if quiet else (lambda m: print(m, flush=True)))
    # the live ones only, for BH_IDENTITIES and the system prompt alike
    identities = [
        n
        for n in live_identities(board, prog, also=[i["name"] for i in scope.identities], scope=scope)
        if n not in no_session
    ]
    Graph(board, scope).sync(None)  # whatever the sandbox holds from earlier segments
    prepare_workdir(board, scope, scope_file, identities)
    # targets behind a third-party challenge: bh-browser holds a live session, the operator is pushed any challenge
    watcher = None
    prompts: dict[str, int] | None = None
    loaded: str | None = None
    counters_at: dict | None = None
    flows_at = flows_size()
    bh_lines: list[str] = []  # `[bh]` lines of every task the runner builds in this segment
    first_lines: list[str] = []  # `[bh]` lines of the segment's first task only
    if browser_watch.wanted(scope):
        prompts = browser_prompts(scope, browser_status(), runs_left, say)
        if prompts is not None:
            say("  bh-browser: prompts this run " + ", ".join(f"{k} {v}" for k, v in sorted(prompts.items())))
            if not any(prompts.values()):
                bh_lines.append(NO_PROMPT_LINE)
        loaded = prepare_browser(scope, identities, say, prompts)
        counters_at = browser_status()
        watcher = browser_watch.ChallengeWatcher(program=prog, identities=identities, say=say)
    if board.meta_get(early_stop_key(prog)):  # the previous segment closed itself on an announced action
        first_lines.append(EARLY_STOP_LINE)
        board.meta_set(early_stop_key(prog), "")
    before = coverage_counts(board, scope)
    cards = pick_cards(board, scope)
    pinned = classes.pinned_cards(scope)
    refused = last_refusal(board, prog, run_id)
    operator = f"\n\nOperator instruction for this segment: {extra_task}" if extra_task else ""
    harness = "".join(f"\n\n{line}" for line in bh_lines)
    shape = {"scanners": scope.scanners_on, "browser": has_browser(scope)}
    task = (
        build_task(
            frontier(board, prog, scope),
            first=first,
            max_turns=max_turns,
            cards=segment_cards(scope, cards),
            refused=refused,
            **shape,
        )
        + harness
        + "".join(f"\n\n{line}" for line in first_lines)
        + operator
    )
    record_setup(
        board,
        run_id,
        scope,
        model=model,
        effort=effort,
        max_turns=max_turns,
        minutes=minutes,
        system_prompt=build_system_prompt(scope, identities),
        task=task,
        cards=[*pinned, *cards],
        shape=shape,
    )
    log_path = paths.run_log(run_id, prog)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    res = SegmentResult(program=prog, run_id=run_id, session_id=session, preflight=preflight)
    board.run_set(run_id, cards=",".join([*pinned, *cards]) or None)
    say(
        f"▶ run {run_id} · {scope.platform}/{prog} · model={model} effort={effort or 'default'} · "
        f"max {max_turns} turns / {minutes:g} min"
        + (f" · resume {session[:8]}" if session else "")
        + (f" · cards {', '.join([*pinned, *cards])}" if pinned or cards else "")
    )

    deadline = time.monotonic() + minutes * 60
    prompt, timed_out, next_session = task, False, session
    limit, max_legs = segment_limits(scope)
    events_at = events_size()  # the relay's journal of this segment starts here
    set_active_run(run_id, prog, relay_budget(max_turns))
    # the agent's sessions are kept alive while it hunts (renewal before expiry and on session-dead)
    keeper = SessionKeeper(scope, board.path, run_id, identities, say, events_offset=events_at).start()
    # third-party data or server-side execution: push, stop, park (audit I11)
    stopper = StopWatcher(prog, run_id, say=say).start()
    try:
        with open(log_path, "x", buffering=1) as log:  # never overwrite another run's log
            while res.legs < max_legs and not stopper.triggered:
                res.legs += 1
                if res.legs > 1:  # whatever the previous leg planted goes before the next one loads it
                    clean_leg(prog, sandbox_home(run_id))
                calls_before, turns_before, facts_before = res.tool_calls, len(res.turn_log), last_fact_id(board)
                leg_started = time.time()
                push_budget(prog, max_turns, res.turns)  # T7: the hook reads what this segment has left
                cmd = agent_command(
                    scope,
                    prompt,
                    run_id=run_id,
                    model=model,
                    max_turns=max_turns - res.turns,
                    effort=effort,
                    session=next_session,
                    identities=identities,
                )
                if watcher is not None:
                    watcher.start()
                try:
                    result, timed_out = run_leg(
                        cmd,
                        log,
                        log_path.with_suffix(".stderr"),
                        res,
                        say,
                        program=prog,
                        timeout_s=deadline - time.monotonic(),
                        context_limit=CONTEXT_HARD_FACTOR * limit,
                    )
                finally:
                    if watcher is not None:
                        watcher.stop()
                merge_result(res, result)
                leg_turns = res.turn_log[turns_before:]
                if res.overflow and result is None:  # stopped by the runner: no result event to count from
                    res.turns += len(leg_turns)
                    if res.status != "refusal":
                        res.status = "ok"
                stopped_early = early_stop(res, result, timed_out=timed_out, max_turns=max_turns)
                if stopped_early:
                    res.early_stops += 1
                    board.run_set(run_id, early_stop=res.early_stops)
                    say("  ⏸ the leg closed itself on an announced action it never ran (early stop)")
                last_ctx, max_ctx = leg_context(leg_turns)
                res.leg_context.append(max_ctx)
                rotate = res.overflow or last_ctx > limit
                log.write(
                    json.dumps(
                        {
                            "type": "bh_leg",
                            "leg": res.legs,
                            "turns": len(leg_turns),
                            "context_last": last_ctx,
                            "context_max": max_ctx,
                            "threshold": limit,
                            "overflow": res.overflow,
                            "rotate": rotate,
                        }
                    )
                    + "\n"
                )
                say(f"  ◆ leg {res.legs}: {len(leg_turns)} turns, context max {max_ctx} / last {last_ctx} tokens")
                left_turns, left_s = max_turns - res.turns, deadline - time.monotonic()
                if (
                    stopper.poll()
                    or timed_out
                    or res.status != "ok"
                    or res.legs >= max_legs
                    or left_turns < MIN_LEFT_TURNS
                    or left_s < MIN_LEFT_S
                    # the agent ended the leg itself (not cut by the runner) after most of the budget, or
                    # with almost no tool use: it says there is nothing left to do
                    or (
                        not res.overflow
                        and (res.turns >= max_turns * EARLY_STOP or res.tool_calls - calls_before < MIN_LEG_TOOL_CALLS)
                    )
                ):
                    if stopped_early:  # the next segment of this program is told
                        board.meta_set(early_stop_key(prog), str(run_id))
                    break
                waiting = has_browser(scope) and challenge_pending(browser_status())
                if not cards and (cards := pick_cards(board, scope)):  # the surface exists once mapping is done
                    board.run_set(run_id, cards=",".join(cards))
                    say(f"  ↻ cards {', '.join(cards)}")
                    new_cards = classes.cards_block(
                        cards, scanners=scope.scanners_on
                    )  # the pinned ones are already in this session
                else:
                    new_cards = ""
                if rotate:
                    res.rotations += 1
                    wrote = prepare_rotation(
                        board,
                        scope,
                        scope_file,
                        res,
                        since=facts_before,
                        context=last_ctx,
                        identities=identities,
                        stopper=stopper,
                    )
                    if stopper.triggered:
                        break
                    say(
                        f"  ⟳ context {last_ctx} tokens > {limit}: fresh session from the board"
                        + (" (HANDOFF written by the runner)" if wrote else "")
                    )
                    prompt = (
                        build_task(
                            frontier(board, prog, scope),
                            first=False,
                            max_turns=left_turns,
                            cards=segment_cards(scope, cards),
                            refused=refused,
                            rotated=True,
                            **shape,
                        )
                        + harness
                        + operator
                    )
                    next_session = None
                else:
                    say(f"  ↻ stopped early ({res.turns}/{max_turns} turns): nudging the same session to continue")
                    prompt = CONTINUE_PROMPT.format(turns=left_turns, minutes=int(left_s // 60))
                    prompt += f"\n\n{new_cards}" if new_cards else ""
                    next_session = res.session_id
                if stopped_early:
                    prompt = EARLY_STOP_LINE + "\n\n" + prompt
                if waiting:  # the next leg starts where this one waited, not on another surface
                    # T9: an intent whose request already left is not resumed by the harness
                    replay = not left_the_sandbox(run_id, leg_started)
                    prompt = challenge_resume(board, prog, replay=replay) + "\n\n" + prompt
    except BaseException as exc:  # Ctrl-C / SIGTERM, or a harness error: record what the agent already wrote
        with signals_ignored():
            keeper.stop()
            stopper.stop()
            stopped = isinstance(exc, KeyboardInterrupt)
            res.status = "stopped" if stopped else "error"
            note = "stopped by operator" if stopped else f"harness error: {exc!r}"
            board.run_end(run_id, status=res.status, note=one_line(note, 500))
            set_active_run(None)
            stack.kill_agent(prog)
            if watcher is not None:
                close_browser(board, run_id, counters_at, loaded, prompts, flows_at)
            finish(board, res, scope, before, effort=effort, note=note)
            say(f"■ run {run_id} {res.status}: {one_line(note, 200)}")
        raise
    with signals_ignored():
        keeper.stop()
        stopper.stop()
        stopper.poll()  # a stop note written as the last leg ended
        set_active_run(None)
        stderr = log_path.with_suffix(".stderr").read_text(errors="replace")
        if timed_out:
            res.status = "timeout"
        relay = relay_events(run_id, events_at)
        if res.status == "refusal" and not refusal_confirmed(res, relay):
            say(f"  ⚠ the stream reports a refusal of {res.refusal_id or '?'} that the relay never streamed: ignored")
            res.status = "error"
        res.quota_claimed = res.rate_limit.get("status") == "rejected"
        if quota_confirmed(res, stderr, relay):
            res.status = "quota"
        elif res.quota_claimed:
            say("  ⚠ the stream reports a quota stop that neither stderr nor the relay confirms: not a quota stop")
        if stopper.triggered:
            res.status = "parked"
        if watcher is not None:
            close_browser(board, run_id, counters_at, loaded, prompts, flows_at)
        finish(board, res, scope, before, effort=effort, note=res.text or stderr)
    # every finding waiting with a proof, not only this segment's: one left 'new' by an earlier stop is picked up
    # here, and a refused segment's findings are verified too (the refusal closes a lead, not the findings). After a
    # quota claim, even an unconfirmed one, nothing is judged: a judge without quota would bury a good finding.
    # A parked program is judged by nobody: a replay would touch the third-party data again.
    if res.status not in ("quota", "parked") and not res.quota_claimed and (pending := pending_findings(board, prog)):
        from bh.verify import verifier_model, verify_pending

        judge = verifier_model(model)  # never the hunter's model (audit I10)
        # sessions first: one the gate saw die (or a false mark) is refreshed before the replay leans on it
        refresh_identities(board, scope, run_id, say)
        say(f"▶ verifying {pending} finding(s) with {judge}")
        set_active_run(run_id, prog)  # the verifier's requests are this run's traffic too
        try:
            verify_pending(board, scope, run_id=run_id, model=judge, effort=effort, say=say)
        finally:
            set_active_run(None)
    say(
        f"■ run {run_id} {res.status} · {res.legs} leg(s)"
        + (f" ({res.rotations} context rotation(s))" if res.rotations else "")
        + f" · {res.turns} turns · {res.tool_calls} tools "
        f"(arsenal {res.arsenal_calls}, manual {res.manual_calls}, locked {res.locked_calls}) · "
        f"+{res.new_facts} facts +{res.new_findings} findings +{res.new_blockers} blockers (progress {res.progress})"
        + (f" · ${res.cost_usd:.2f} eq." if res.cost_usd else "")
        + quota_line(res.rate_limit)
    )
    if res.status == "error" and stderr.strip():
        say("  stderr: " + one_line(stderr, 400))
    return res
