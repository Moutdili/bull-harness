"""Run one segment of `claude -p` inside the agent container for one program.

Host side only:
  activate the scope for the gate -> push frontier / facts / doctrine into /work/<program>/.bh
  -> podman exec claude -p (stream-json) -> live compact log + tool-usage metrics
  -> ingest notes and gate events into the board.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from bh import paths, stack
from bh.agent import contract as c
from bh.board import Board
from bh.runner import ingest
from bh.runner.prompt import build_system_prompt, build_task
from bh.scope import Scope, load_scope
from bh.text import one_line

QUOTA_RE = re.compile(r"(usage limit|limit reached|rate limit|resets? (at|in)|out of (extra )?usage)", re.I)
# Builtins run for minutes (ffuf, nuclei, sqlmap): the Bash tool's 2-minute default would kill them.
BASH_TIMEOUT_MS = {"BASH_DEFAULT_TIMEOUT_MS": "330000", "BASH_MAX_TIMEOUT_MS": "900000"}
# Token economy: every turn resends tool schemas + command listings; keep only what the hunt uses.
AGENT_TOOLS = os.environ.get("BH_TOOLS", "Bash,Read")


@dataclass
class SegmentResult:
    program: str
    run_id: int
    status: str = "error"  # ok | max_turns | timeout | quota | error | refusal | stopped
    session_id: str | None = None
    turns: int = 0
    cost_usd: float | None = None
    new_facts: int = 0
    new_findings: int = 0
    new_todos: int = 0
    progress: int = 0  # findings + non-bookkeeping facts: what the supervisor calls progress
    tool_calls: int = 0
    arsenal_calls: int = 0  # Bash commands running a bh-* builtin
    manual_calls: int = 0  # Bash commands hand-crafting HTTP
    locked_calls: int = 0  # commands refused by the tool lock
    text: str = ""
    usage: dict = field(default_factory=dict)


def activate_scope(scope_file: Path) -> None:
    """Atomically make this scope the gate's active scope (the gate hot-reloads on mtime)."""
    dst = paths.active_scope()
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(".tmp")
    shutil.copyfile(scope_file, tmp)
    os.replace(tmp, dst)


def frontier(board: Board, program: str) -> str:
    """Board view + attack surface found by the tools (read from the agent's work dir)."""
    surface = c.surface(paths.work_bh(program))
    return board.frontier(program) + (f"\n{surface}" if surface else "")


def prepare_workdir(board: Board, scope: Scope, scope_file: Path) -> None:
    prog = scope.program
    stage = paths.stage(prog)
    stage.mkdir(parents=True, exist_ok=True)
    board.export_facts(prog, stage / c.FACTS)
    cbh = f"/work/{prog}/.bh"
    stack.push_file(f"{cbh}/{c.FRONTIER}", board.frontier(prog))
    stack.push_file(f"{cbh}/{c.FACTS}", (stage / c.FACTS).read_text())
    stack.push_file(f"{cbh}/{c.SYSTEM}", build_system_prompt(scope, paths.identities(prog)))
    stack.push_file(f"{cbh}/{c.SCOPE}", Path(scope_file).read_text())


def agent_command(
    scope: Scope, task: str, *, model: str, max_turns: int, effort: str | None, session: str | None
) -> list[str]:
    prog = scope.program
    bh = f"/work/{prog}/.bh"
    env = {
        "BH_DIR": bh,
        "BH_PROGRAM": prog,
        "BH_RPS": f"{scope.max_rps or 5:g}",
        "HOME": "/home/hunter",
        **BASH_TIMEOUT_MS,
    }
    cmd = [
        "podman",
        "exec",
        "-i",
        "--user",
        "hunter",
        "-w",
        f"/work/{prog}",
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


def _tool_result_text(block: dict) -> str:
    content = block.get("content")
    if isinstance(content, list):
        return "\n".join(x.get("text", "") for x in content if isinstance(x, dict))
    return content if isinstance(content, str) else ""


def consume_stream(proc: subprocess.Popen, log_path: Path, res: SegmentResult, say) -> dict | None:
    """Mirror the stream to the run log (line-buffered: the UI tails it), update `res`, return the result event."""
    result = None
    with open(log_path, "w", buffering=1) as log:
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
                    for block in msg.get("content", []):
                        if block.get("type") == "text" and block.get("text", "").strip():
                            say(f"  💬 {one_line(block['text'], 220)}")
                        elif block.get("type") == "tool_use":
                            res.tool_calls += 1
                            inp = block.get("input", {})
                            cmd = inp.get("command") or ""
                            res.arsenal_calls += c.uses_arsenal(cmd)
                            res.manual_calls += c.uses_manual_http(cmd)
                            say(f"  ⚙ {block.get('name')}: {one_line(cmd or inp.get('description') or inp)}")
                case "user":
                    for block in (ev.get("message") or {}).get("content") or []:
                        if (
                            isinstance(block, dict)
                            and block.get("type") == "tool_result"
                            and c.LOCK_MARK in _tool_result_text(block)
                        ):
                            res.locked_calls += 1
                            say("  🔒 manual HTTP refused by the tool lock")
                case "result":
                    result = ev
    return result


def apply_result(res: SegmentResult, result: dict | None, stderr: str, timed_out: bool) -> None:
    if result:
        res.session_id = result.get("session_id") or res.session_id
        res.turns = result.get("num_turns") or 0
        res.cost_usd = result.get("total_cost_usd")
        res.usage = result.get("usage") or {}
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
    if timed_out:
        res.status = "timeout"
    if res.status != "ok" and (QUOTA_RE.search(res.text) or QUOTA_RE.search(stderr)):
        res.status = "quota"


def finish(board: Board, res: SegmentResult, scope: Scope, model: str, effort: str | None, note: str) -> None:
    prog = scope.program
    res.new_facts, res.new_findings, res.new_todos, res.progress = ingest.notes(
        board, prog, res.run_id, paths.work_bh(prog)
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
    u = res.usage
    board.run_end(
        res.run_id,
        status=res.status,
        session_id=res.session_id,
        turns=res.turns,
        cost_usd=res.cost_usd,
        input_tokens=u.get("input_tokens"),
        output_tokens=u.get("output_tokens"),
        cache_read=u.get("cache_read_input_tokens"),
        effort=effort,
        arsenal_calls=res.arsenal_calls,
        manual_calls=res.manual_calls,
        locked_calls=res.locked_calls,
        note=one_line(note, 500),
    )


def run_segment(
    scope_file: Path,
    *,
    model: str = "sonnet",
    max_turns: int = 60,
    minutes: float = 30,
    resume: bool = False,
    board: Board | None = None,
    quiet: bool = False,
    extra_task: str = "",
    effort: str | None = None,
) -> SegmentResult:
    scope = load_scope(scope_file)
    if scope.automation_allowed is False:
        raise SystemExit(f"{scope.program}: automation_allowed is false — refusing to run an agent on it")
    for name in (stack.GATE, stack.AGENT):
        if not stack.container_running(name):
            raise SystemExit(f"container {name} is not running — start the stack with `bh up`")
    board = board or Board()
    prog = scope.program
    activate_scope(scope_file)
    prepare_workdir(board, scope, scope_file)

    session = board.last_session(prog) if resume else None
    first = session is None and not board.rows("SELECT 1 FROM facts WHERE program=? LIMIT 1", prog)
    task = build_task(frontier(board, prog), first=first, max_turns=max_turns)
    if extra_task:
        task += "\n\nOperator instruction for this segment: " + extra_task
    run_id = board.run_start(prog, model)
    log_path = paths.run_log(run_id, prog)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    res = SegmentResult(program=prog, run_id=run_id, session_id=session)
    say = (lambda _m: None) if quiet else (lambda m: print(m, flush=True))
    say(
        f"▶ run {run_id} · {scope.platform}/{prog} · model={model} effort={effort or 'default'} · "
        f"max {max_turns} turns / {minutes:g} min" + (f" · resume {session[:8]}" if session else "")
    )

    cmd = agent_command(scope, task, model=model, max_turns=max_turns, effort=effort, session=session)
    # stderr goes to a file: a pipe read only at the end can fill up and block claude.
    err_path = log_path.with_suffix(".stderr")
    with open(err_path, "w") as err_fh:  # the child keeps its own descriptor
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=err_fh, text=True, bufsize=1)
    timed_out = threading.Event()

    def on_timeout() -> None:
        timed_out.set()
        stack.kill_agent(prog)
        time.sleep(5)
        if proc.poll() is None:
            proc.kill()

    timer = threading.Timer(minutes * 60, on_timeout)
    timer.start()
    try:
        result = consume_stream(proc, log_path, res, say)
    except BaseException:  # Ctrl-C / SIGTERM: kill the agent in the container, keep what it already wrote
        timer.cancel()
        stack.kill_agent(prog)
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        res.status = "stopped"
        finish(board, res, scope, model, effort, "stopped by operator")
        say(f"■ run {run_id} stopped by operator (agent killed in {stack.AGENT})")
        raise
    finally:
        timer.cancel()
    proc.wait()
    stderr = err_path.read_text(errors="replace")
    apply_result(res, result, stderr, timed_out.is_set())
    finish(board, res, scope, model, effort, res.text or stderr)
    say(
        f"■ run {run_id} {res.status} · {res.turns} turns · {res.tool_calls} tools "
        f"(arsenal {res.arsenal_calls}, manual {res.manual_calls}, locked {res.locked_calls}) · "
        f"+{res.new_facts} facts +{res.new_findings} findings +{res.new_todos} todos (progress {res.progress})"
        + (f" · ${res.cost_usd:.2f} eq." if res.cost_usd else "")
    )
    if res.status == "error" and stderr.strip():
        say("  stderr: " + one_line(stderr, 400))
    return res
