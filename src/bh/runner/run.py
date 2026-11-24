"""Run one segment of `claude -p` inside the agent container for one program.

Host side only:
  lock (one agent at a time) -> activate the scope for the gate -> tag gate flows with the run
  -> clean the sandbox (fresh HOME, no planted CLAUDE.md / .claude) -> push frontier / doctrine
  -> podman exec claude -p (stream-json), nudged to continue in the same session when it stops early
  -> rotate + ingest notes, gate events -> measured progress.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

from bh import classes, paths, stack
from bh.assets import Graph
from bh.agent import contract as c
from bh.board import Board
from bh.runner import ingest
from bh.runner.prompt import build_system_prompt, build_task
from bh.scope import Scope, load_scope
from bh.text import one_line

DEFAULT_MODEL = "sonnet"  # alias resolved by Claude Code (claude-sonnet-5-5 on 2.1.330)
# Claude usage-limit wording only: "rate limit" is everyday bug bounty vocabulary (false positives).
QUOTA_RE = re.compile(r"(usage limit|limit reached|resets? at \d|out of (extra )?usage)", re.I)
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
    "take the next untested endpoint or open intent, test it, record the outcome, and keep going. "
    "Stop only when every lead on the board is a recorded dead end; then write the HANDOFF fact."
)


@dataclass
class SegmentResult:
    program: str
    run_id: int
    status: str = "error"  # ok | max_turns | timeout | quota | error | refusal | stopped
    session_id: str | None = None
    legs: int = 0
    turns: int = 0
    cost_usd: float = 0.0
    new_facts: int = 0
    new_findings: int = 0
    new_todos: int = 0
    progress: int = 0  # findings + endpoints newly tested + phases newly covered (facts alone are not progress)
    tool_calls: int = 0
    arsenal_calls: int = 0  # Bash commands running a builtin or an arsenal tool
    manual_calls: int = 0  # Bash commands hand-crafting HTTP
    locked_calls: int = 0  # commands refused by the tool lock
    text: str = ""
    usage: dict = field(default_factory=dict)
    turn_log: list[dict] = field(default_factory=list)  # one per model message: tokens (observability)
    tool_log: list[dict] = field(default_factory=list)  # one per tool call: kind, duration, locked
    _pending: dict = field(default_factory=dict, repr=False)  # tool_use id -> index in tool_log


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


# program rules a human must have decided before any agent runs (None = not read yet). Local labs are exempt.
HUMAN_DECISIONS = {
    "automation_allowed": "is automation (an AI agent) allowed?",
    "scanners_allowed": "are automated scanners (ffuf, nuclei, sqlmap, dalfox) allowed?",
}


def check_automation(board: Board, scope: Scope) -> None:
    """Unknown program rules = a human reads the program policy first; automation forbidden = never run."""
    if scope.automation_allowed is False:
        raise SystemExit(f"{scope.program}: automation_allowed is false — refusing to run an agent on it")
    if scope.platform == "local":
        return
    unknown = [f for f in HUMAN_DECISIONS if getattr(scope, f) is None]
    for f in unknown:
        board.add_todo(
            "scope-question",
            f"{scope.program}: {HUMAN_DECISIONS[f]}",
            f"read the program rules, then set {f}: true/false in its scope file",
            program=scope.program,
            dedup=f"{scope.program}:{f}-unknown",
        )
    if unknown:
        raise SystemExit(f"{scope.program}: {', '.join(unknown)} unknown — set it in the scope file first")


# ------------------------------------------------------------------ sandbox + gate state
def activate_scope(scope_file: Path) -> None:
    """Atomically make this scope the gate's active scope (the gate hot-reloads on mtime)."""
    dst = paths.active_scope()
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(".tmp")
    shutil.copyfile(scope_file, tmp)
    os.replace(tmp, dst)


def set_active_run(run_id: int | None, program: str = "") -> None:
    """Tag every gate flow with the run that caused it (operator traffic between runs stays untagged)."""
    p = paths.active_run()
    if run_id is None:
        p.unlink(missing_ok=True)
    else:
        p.write_text(json.dumps({"run_id": run_id, "program": program}))


def sandbox_home(session: int | str) -> str:
    return f"/tmp/bh-home-{session}"


def clean_sandbox(program: str, home: str) -> None:
    """Nothing the agent wrote can configure the next session: no process of the previous one alive, fresh
    HOME (no ~/.claude settings or memory), no CLAUDE.md / .claude planted in the work tree. And the agent
    reaches only this program's work dir: /work is root's, every other program's dir is closed (root, 700),
    so notes, endpoints or coverage of program B cannot be written from a segment on program A."""
    stack.reset_agent_user(home)
    stack.agent_sh(_WORK_SCRIPT, f"{c.WORK_ROOT}/{program}", c.WORK_ROOT, user="root")


_WORK_SCRIPT = r"""
rm -rf -- "$1/CLAUDE.md" "$1/.claude" "$2/CLAUDE.md" "$2/.claude"
chown root:root "$2" && chmod 755 "$2"
for d in "$2"/*/ "$2"/.[!.]*/; do
  d=${d%/}; [ -d "$d" ] && [ "$d" != "$1" ] && chown root:root "$d" && chmod 700 "$d"
done
mkdir -p "$1" && chown hunter:hunter "$1" && chmod 755 "$1"  # 755: the host reads it (another uid)
"""


def rotate_notes(program: str, run_id: int) -> Path:
    """Freeze this segment's notes under a per-run name; returns the host path to ingest."""
    name = f"notes-{run_id}.jsonl"
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
    return board.frontier(program) + (f"\n{surface}" if surface else "")


def coverage_counts(board: Board, scope: Scope) -> tuple[int, int]:
    return Graph(board, scope).counts(phases_for(scope))


def pick_cards(board: Board, scope: Scope) -> list[str]:
    """Method cards for this segment, from the attack surface the tools found (none before mapping)."""
    endpoints = [
        (e.get("key", ""), e.get("params") or []) for e in c.read_jsonl(paths.work_bh(scope.program) / c.ENDPOINTS)
    ]
    recent = [
        cid
        for r in board.rows(
            "SELECT cards FROM runs WHERE program=? AND cards IS NOT NULL ORDER BY id DESC LIMIT 2", scope.program
        )
        for cid in (r["cards"] or "").split(",")
        if cid
    ]
    return classes.select_cards(endpoints, exclude=scope.forbidden_vulns, recently_used=recent)


def prepare_workdir(board: Board, scope: Scope, scope_file: Path) -> None:
    prog = scope.program
    stage = paths.stage(prog)
    stage.mkdir(parents=True, exist_ok=True)
    board.export_facts(prog, stage / c.FACTS)
    cbh = c.sandbox_dir(prog)
    # bh-note frontier = this board view + the surface recomputed live in the sandbox
    stack.push_file(f"{cbh}/{c.FRONTIER}", board.frontier(prog))
    tested = board.rows(
        "SELECT a.key FROM assets a WHERE a.program=? AND a.kind='endpoint' "
        "AND EXISTS (SELECT 1 FROM tests t WHERE t.asset_id=a.id)",
        prog,
    )
    stack.push_file(f"{cbh}/{c.MANUAL_TESTED}", json.dumps(sorted(r["key"].split(" ", 1) for r in tested)))
    stack.push_file(f"{cbh}/{c.FACTS}", (stage / c.FACTS).read_text())
    stack.push_file(f"{cbh}/{c.SYSTEM}", build_system_prompt(scope, paths.identities(prog)))
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
) -> list[str]:
    """claude -p inside the agent for this program. `bh_dir`/`extra_env` let the verifier reuse it with its own
    work dir and role."""
    prog = scope.program
    bh = bh_dir or c.sandbox_dir(prog)
    env = {
        "BH_DIR": bh,
        "BH_PROGRAM": prog,
        "BH_RPS": f"{scope.rate:g}",
        "BH_SCANNERS": "1" if scope.scanners_on else "0",
        "HOME": sandbox_home(run_id),
        **BASH_TIMEOUT_MS,
        **(extra_env or {}),
    }
    cmd = [
        "podman",
        "exec",
        "-i",
        "--user",
        "hunter",
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
        "--append-system-prompt-file",
        f"{bh}/{c.SYSTEM}",
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
        return "\n".join(x.get("text", "") for x in content if isinstance(x, dict))
    return content if isinstance(content, str) else ""


def consume_stream(proc: subprocess.Popen, log: IO[str], res: SegmentResult, say) -> dict | None:
    """Mirror the stream to the run log (the UI tails it), update `res`, return the result event."""
    result = None
    for line in proc.stdout:
        log.write(line)
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        match ev.get("type"):
            case "system" if ev.get("subtype") == "init":
                res.session_id = ev.get("session_id") or res.session_id
            case "assistant":
                msg = ev.get("message", {})
                if msg.get("stop_reason") == "refusal":
                    res.status = "refusal"
                if msg.get("id") and msg["id"] not in {t["id"] for t in res.turn_log[-3:]}:
                    u = msg.get("usage") or {}
                    res.turn_log.append(
                        {
                            "id": msg["id"],
                            "ts": time.time(),
                            "input": u.get("input_tokens"),
                            "cache_read": u.get("cache_read_input_tokens"),
                            "cache_write": u.get("cache_creation_input_tokens"),
                            "output": u.get("output_tokens"),
                        }
                    )
                for block in msg.get("content", []):
                    if block.get("type") == "text" and block.get("text", "").strip():
                        say(f"  💬 {one_line(block['text'], 220)}")
                    elif block.get("type") == "tool_use":
                        res.tool_calls += 1
                        inp = block.get("input", {})
                        cmd = inp.get("command") or ""
                        res.arsenal_calls += c.uses_arsenal(cmd)
                        res.manual_calls += c.uses_manual_http(cmd)
                        res._pending[block.get("id")] = len(res.tool_log)
                        res.tool_log.append(
                            {
                                "ts": time.time(),
                                "tool": block.get("name"),
                                "kind": command_kind(cmd),
                                "cmd": cmd[:300],
                                "ms": None,
                                "locked": False,
                            }
                        )
                        say(f"  ⚙ {block.get('name')}: {one_line(cmd or inp.get('description') or inp)}")
            case "user":
                for block in (ev.get("message") or {}).get("content") or []:
                    if not isinstance(block, dict) or block.get("type") != "tool_result":
                        continue
                    locked = any(m in _tool_result_text(block) for m in (c.LOCK_MARK, c.RULES_MARK))
                    if (i := res._pending.pop(block.get("tool_use_id"), None)) is not None:
                        call = res.tool_log[i]
                        call["ms"], call["locked"] = int((time.time() - call["ts"]) * 1000), locked
                    if locked:
                        res.locked_calls += 1
                        say("  🔒 manual HTTP refused by the tool lock")
            case "result":
                result = ev
    return result


def run_leg(
    cmd: list[str],
    log: IO[str],
    err_path: Path,
    res: SegmentResult,
    say,
    program: str,
    timeout_s: float,
    bh_dir: str | None = None,
) -> tuple[dict | None, bool]:
    """One claude process. Returns (result event, timed out)."""
    with open(err_path, "a") as err_fh:  # a pipe read only at the end can fill up and block claude
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=err_fh, text=True, bufsize=1)
    timed_out = threading.Event()

    def on_timeout() -> None:
        timed_out.set()
        stack.kill_agent(program, bh_dir=bh_dir)
        time.sleep(5)
        if proc.poll() is None:
            proc.kill()

    timer = threading.Timer(max(1.0, timeout_s), on_timeout)
    timer.start()
    try:
        result = consume_stream(proc, log, res, say)
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
    return result, timed_out.is_set()


def merge_result(res: SegmentResult, result: dict | None) -> None:
    if not result:
        return
    res.session_id = result.get("session_id") or res.session_id
    res.turns += result.get("num_turns") or 0
    res.cost_usd += result.get("total_cost_usd") or 0.0
    for k, v in (result.get("usage") or {}).items():
        if isinstance(v, int):
            res.usage[k] = res.usage.get(k, 0) + v
    res.text = result.get("result") or ""
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
    denied = sum(1 for e in events if e.get("run") == run_id and e.get("kind") == "blocked")
    return {
        "gate_requests": len(flows),
        "gate_denied": denied,
        "gate_errors": sum(1 for f in flows if f.get("status") == "error"),
        "gate_pushback": sum(1 for f in flows if f.get("status") in (429, 503)),
    }


def finish(
    board: Board, res: SegmentResult, scope: Scope, before: tuple[int, int], *, effort: str | None, note: str
) -> None:
    prog = scope.program
    res.new_facts, res.new_findings, res.new_todos = ingest.notes(
        board, prog, res.run_id, rotate_notes(prog, res.run_id), scope
    )
    res.new_todos += ingest.gate_events(board, prog, res.run_id, paths.identities(prog))
    if res.status == "refusal":
        res.new_todos += bool(
            board.add_todo(
                "refusal",
                f"model refused during run {res.run_id}",
                f"see {paths.run_log(res.run_id, prog)}",
                program=prog,
                dedup=f"{prog}:refusal:{res.run_id}",
            )
        )
    board.record_metrics(res.run_id, res.turn_log, res.tool_log)
    board.run_set(res.run_id, **gate_counts(board, res.run_id))
    graph = Graph(board, scope)
    graph.sync(res.run_id)
    for r in board.rows("SELECT id, url FROM findings WHERE run_id=? AND url IS NOT NULL", res.run_id):
        graph.link(r["url"], "finding", r["id"])
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
) -> SegmentResult:
    scope = load_scope(scope_file)
    board = board or Board()
    check_automation(board, scope)
    for name in (stack.GATE, stack.AGENT):
        if not stack.container_running(name):
            raise SystemExit(f"container {name} is not running — start the stack with `bh up`")
    with run_lock():
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
) -> SegmentResult:
    prog = scope.program
    activate_scope(scope_file)
    session = board.last_session(prog) if resume else None
    first = session is None and not board.rows("SELECT 1 FROM facts WHERE program=? LIMIT 1", prog)
    run_id = board.run_start(prog, model)  # closes a run orphaned by a crash (we hold the lock)
    clean_sandbox(prog, sandbox_home(run_id))
    Graph(board, scope).sync(None)  # whatever the sandbox holds from earlier segments
    prepare_workdir(board, scope, scope_file)
    before = coverage_counts(board, scope)
    cards = pick_cards(board, scope)
    task = build_task(frontier(board, prog, scope), first=first, max_turns=max_turns, cards=classes.cards_block(cards))
    if extra_task:
        task += "\n\nOperator instruction for this segment: " + extra_task
    log_path = paths.run_log(run_id, prog)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    res = SegmentResult(program=prog, run_id=run_id, session_id=session)
    board.run_set(run_id, cards=",".join(cards) or None)
    say = (lambda _m: None) if quiet else (lambda m: print(m, flush=True))
    say(
        f"▶ run {run_id} · {scope.platform}/{prog} · model={model} effort={effort or 'default'} · "
        f"max {max_turns} turns / {minutes:g} min"
        + (f" · resume {session[:8]}" if session else "")
        + (f" · cards {', '.join(cards)}" if cards else "")
    )

    deadline = time.monotonic() + minutes * 60
    prompt, timed_out = task, False
    set_active_run(run_id, prog)
    try:
        with open(log_path, "x", buffering=1) as log:  # never overwrite another run's log
            while res.legs < MAX_LEGS:
                res.legs += 1
                calls_before = res.tool_calls
                cmd = agent_command(
                    scope,
                    prompt,
                    run_id=run_id,
                    model=model,
                    max_turns=max_turns - res.turns,
                    effort=effort,
                    session=res.session_id if res.legs > 1 else session,
                )
                result, timed_out = run_leg(
                    cmd, log, log_path.with_suffix(".stderr"), res, say, prog, deadline - time.monotonic()
                )
                merge_result(res, result)
                left_turns, left_s = max_turns - res.turns, deadline - time.monotonic()
                if (
                    timed_out
                    or res.status != "ok"
                    or res.turns >= max_turns * EARLY_STOP
                    or left_turns < MIN_LEFT_TURNS
                    or left_s < MIN_LEFT_S
                    or res.tool_calls - calls_before < MIN_LEG_TOOL_CALLS  # it says there is nothing left to do
                ):
                    break
                say(f"  ↻ stopped early ({res.turns}/{max_turns} turns): nudging the same session to continue")
                prompt = CONTINUE_PROMPT.format(turns=left_turns, minutes=int(left_s // 60))
                if not cards and (cards := pick_cards(board, scope)):  # the surface exists once mapping is done
                    board.run_set(run_id, cards=",".join(cards))
                    prompt += "\n\n" + classes.cards_block(cards)
                    say(f"  ↻ cards {', '.join(cards)}")
    except BaseException as exc:  # Ctrl-C / SIGTERM, or a harness error: record what the agent already wrote
        with signals_ignored():
            stopped = isinstance(exc, KeyboardInterrupt)
            res.status = "stopped" if stopped else "error"
            note = "stopped by operator" if stopped else f"harness error: {exc!r}"
            board.run_end(run_id, status=res.status, note=one_line(note, 500))
            set_active_run(None)
            stack.kill_agent(prog)
            finish(board, res, scope, before, effort=effort, note=note)
            say(f"■ run {run_id} {res.status}: {one_line(note, 200)}")
        raise
    with signals_ignored():
        set_active_run(None)
        stderr = log_path.with_suffix(".stderr").read_text(errors="replace")
        if timed_out:
            res.status = "timeout"
        if res.status != "ok" and (QUOTA_RE.search(res.text) or QUOTA_RE.search(stderr)):
            res.status = "quota"
        finish(board, res, scope, before, effort=effort, note=res.text or stderr)
    if res.new_findings and res.status not in ("quota", "refusal"):
        from bh.verify import VERIFIER_MODEL, verify_pending

        say(f"▶ verifying {res.new_findings} new finding(s) with {VERIFIER_MODEL}")
        set_active_run(run_id, prog)  # the verifier's requests are this run's traffic too
        try:
            verify_pending(board, scope, run_id=run_id, model=VERIFIER_MODEL, effort=effort, say=say)
        finally:
            set_active_run(None)
    say(
        f"■ run {run_id} {res.status} · {res.legs} leg(s) · {res.turns} turns · {res.tool_calls} tools "
        f"(arsenal {res.arsenal_calls}, manual {res.manual_calls}, locked {res.locked_calls}) · "
        f"+{res.new_facts} facts +{res.new_findings} findings +{res.new_todos} todos (progress {res.progress})"
        + (f" · ${res.cost_usd:.2f} eq." if res.cost_usd else "")
    )
    if res.status == "error" and stderr.strip():
        say("  stderr: " + one_line(stderr, 400))
    return res
