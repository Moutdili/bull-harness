"""Run one segment of `claude -p` inside the agent container for one program.

Host side only. Flow:
  activate scope for the gate -> prepare /work/<program>/.bh (frontier, system prompt)
  -> podman exec claude -p (stream-json) -> live compact log -> ingest notes + gate events.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from bh.board import Board
from bh.runner.prompt import build_system_prompt, build_task
from bh.scope import Scope, load_scope

AGENT = "bh-agent"
GATE = "bh-gate"
QUOTA_RE = re.compile(r"(usage limit|limit reached|rate limit|resets? (at|in)|out of (extra )?usage)", re.I)


def home() -> Path:
    return Path(os.environ.get("BH_HOME", Path.cwd()))


@dataclass
class SegmentResult:
    program: str
    run_id: int
    status: str  # ok | max_turns | timeout | quota | error | refusal
    session_id: str | None = None
    turns: int = 0
    cost_usd: float | None = None
    new_facts: int = 0
    new_findings: int = 0
    new_todos: int = 0
    tool_calls: int = 0
    text: str = ""
    usage: dict = field(default_factory=dict)
    progress: int = 0  # new findings + new facts that are not bookkeeping (handoff, dead-end, blocked)


def container_running(name: str) -> bool:
    r = subprocess.run(["podman", "container", "inspect", "-f", "{{.State.Running}}", name],
                       capture_output=True, text=True)
    return r.returncode == 0 and r.stdout.strip() == "true"


def push_file(container_path: str, text: str) -> None:
    """Write a file inside the agent container as `hunter` (creates parent dirs)."""
    r = subprocess.run(["podman", "exec", "-i", "--user", "hunter", AGENT, "sh", "-c",
                        'mkdir -p "$(dirname "$1")" && cat > "$1"', "sh", container_path],
                       input=text, text=True, capture_output=True)
    if r.returncode != 0:
        raise SystemExit(f"cannot write {container_path} in {AGENT}: {r.stderr.strip()}")


def kill_agent(program: str, grace: float = 8.0) -> None:
    """Stop the claude process of this program inside the container (pid written by the launch wrapper).
    `podman exec` does not forward signals, so killing the host-side process alone leaves an orphan."""
    pidfile = f"/work/{program}/.bh/agent.pid"
    script = (f'p=$(cat {pidfile} 2>/dev/null) || exit 0; kill -0 "$p" 2>/dev/null || exit 0; '
              f'kill -INT "$p"; i=0; while kill -0 "$p" 2>/dev/null && [ $i -lt {int(grace * 2)} ]; do sleep 0.5; i=$((i+1)); done; '
              f'pkill -KILL -P "$p" 2>/dev/null; kill -KILL "$p" 2>/dev/null; rm -f {pidfile}; true')
    subprocess.run(["podman", "exec", AGENT, "sh", "-c", script], capture_output=True, timeout=grace + 20)


def activate_scope(scope_file: Path) -> None:
    """Atomically make this scope the gate's active scope (the gate hot-reloads on mtime)."""
    dst = home() / "var" / "state" / "active-scope.yaml"
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(".tmp")
    shutil.copyfile(scope_file, tmp)
    os.replace(tmp, dst)
    os.utime(dst, None)


def _meta_get(board: Board, key: str, default: str = "0") -> str:
    row = board.db.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
    return row["v"] if row else default


def _meta_set(board: Board, key: str, value: str) -> None:
    board.db.execute("INSERT INTO meta(k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, value))
    board.db.commit()


def _read_new_lines(board: Board, path: Path, key: str) -> list[dict]:
    """Offsets live in the board (host side), never in the sandbox."""
    if not path.exists():
        return []
    off = int(_meta_get(board, key))
    size = path.stat().st_size
    if size < off:
        off = 0
    out = []
    with open(path, "rb") as fh:
        fh.seek(off)
        for line in fh:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        _meta_set(board, key, str(fh.tell()))
    return out


BOOKKEEPING_KINDS = ("handoff", "dead-end", "blocked")


def ingest_notes(board: Board, program: str, run_id: int, bh_dir: Path) -> tuple[int, int, int, int]:
    """Returns (facts, findings, todos, progress). A segment that only writes a HANDOFF is stagnant."""
    facts = findings = todos = progress = 0
    for n in _read_new_lines(board, bh_dir / "notes.jsonl", f"notes:{program}"):
        op = n.get("op")
        if op == "fact":
            board.add_fact(program, n.get("title", ""), n.get("summary", ""), n.get("evidence", ""),
                           kind=n.get("kind", "fact"), run_id=run_id)
            facts += 1
            progress += n.get("kind", "fact") not in BOOKKEEPING_KINDS
        elif op == "intent":
            board.add_intent(program, n.get("title", ""), run_id=run_id)
        elif op == "done":
            m = re.fullmatch(r"I?(\d+)", str(n.get("intent_id", "")))
            if m:
                board.close_intent(int(m.group(1)), n.get("outcome", ""))
        elif op == "finding":
            board.add_finding(program, n.get("title", ""), run_id=run_id,
                              **{k: n.get(k) for k in ("severity", "vuln_class", "url", "summary", "poc",
                                                       "evidence", "not_proven")})
            findings += 1
            progress += 1
        elif op == "todo":
            if board.add_todo(n.get("kind", "other"), n.get("title", ""), n.get("detail", ""), program=program,
                              dedup=f"{program}:{n.get('kind')}:{n.get('title', '')[:120]}"):
                todos += 1
    return facts, findings, todos, progress


def ingest_gate_events(board: Board, program: str, run_id: int,
                       identities: list[str] | None = None) -> tuple[int, int]:
    """Turn gate events into one summary fact + human todos (WAF, repeated 401).

    401 sent WITH an identity -> that identity's session is probably expired (todo per identity).
    401 sent WITHOUT one -> todo only when the program has no identity at all: an agent probing
    unauthenticated access control on purpose must not page the human."""
    events = _read_new_lines(board, home() / "var" / "state" / "events.jsonl", "gate-events")
    blocked: dict[str, int] = {}
    auth: dict[tuple[str, str | None], int] = {}
    todos = 0
    for e in events:
        if e.get("program") not in (program, "-"):
            continue
        kind = e.get("kind")
        if kind == "blocked":
            key = re.sub(r"https?://([^/]+).*", r"\1", e.get("url") or e.get("host") or "?")
            blocked[key] = blocked.get(key, 0) + 1
        elif kind == "waf":
            if board.add_todo("waf", f"WAF challenge on {e.get('host')}",
                              f"status {e.get('status')} server={e.get('server')} url={e.get('url')} flow={e.get('flow')}",
                              program=program, dedup=f"{program}:waf:{e.get('host')}"):
                todos += 1
        elif kind == "auth":
            key = (e.get("host", "?"), e.get("identity"))
            auth[key] = auth.get(key, 0) + 1
        elif kind == "identity-missing":
            if board.add_todo("account", f"identity '{e.get('identity')}' requested but not configured",
                              f"create var/state/identities/{program}/{e.get('identity')}.json",
                              program=program, dedup=f"{program}:identity:{e.get('identity')}"):
                todos += 1
    for (host, ident), n in auth.items():
        if n < 3:
            continue
        if ident:
            added = board.add_todo("auth", f"identity '{ident}' gets 401 on {host} ({n}x): session expired?",
                                   f"refresh var/state/identities/{program}/{ident}.json",
                                   program=program, dedup=f"{program}:auth:{host}:{ident}:{run_id}")
        elif not identities:
            added = board.add_todo("auth", f"{host} answers 401 ({n}x): session needed",
                                   "log in through the gate capture flow and store an identity",
                                   program=program, dedup=f"{program}:auth:{host}")
        else:
            added = None
        todos += bool(added)
    if blocked:
        top = sorted(blocked.items(), key=lambda kv: -kv[1])[:8]
        board.add_fact(program, f"gate denied {sum(blocked.values())} requests",
                       ", ".join(f"{h} x{n}" for h, n in top), kind="blocked", run_id=run_id)
    return len(events), todos


def _short(obj, n=140) -> str:
    s = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False)
    s = s.replace("\n", " ⏎ ")
    return s if len(s) <= n else s[: n - 1] + "…"


def run_segment(scope_file: Path, *, model: str = "sonnet", max_turns: int = 60, minutes: float = 30,
                resume: bool = True, board: Board | None = None, quiet: bool = False,
                extra_task: str = "", effort: str | None = None) -> SegmentResult:
    scope: Scope = load_scope(scope_file)
    if scope.automation_allowed is False:
        raise SystemExit(f"{scope.program}: automation_allowed is false — refusing to run an agent on it")
    for c in (GATE, AGENT):
        if not container_running(c):
            raise SystemExit(f"container {c} is not running — start the stack with `bh up`")
    board = board or Board()
    prog = scope.program
    activate_scope(scope_file)

    # /work belongs to `hunter` inside the container, i.e. a subuid on the host (rootless podman):
    # the host cannot write there. Stage on the host, push through the container as hunter.
    # The host only reads back (notes.jsonl), which the default 0644/0755 modes allow.
    bh_dir = home() / "var" / "work" / prog / ".bh"
    stage = home() / "var" / "stage" / prog
    stage.mkdir(parents=True, exist_ok=True)
    board.export_facts(prog, stage / "facts.json")
    ident_dir = home() / "var" / "state" / "identities" / prog
    idents = sorted(p.stem for p in ident_dir.glob("*.json")) if ident_dir.is_dir() else []
    cbh = f"/work/{prog}/.bh"
    push_file(f"{cbh}/frontier.md", board.frontier(prog))
    push_file(f"{cbh}/facts.json", (stage / "facts.json").read_text())
    push_file(f"{cbh}/system.md", build_system_prompt(scope, idents))
    push_file(f"{cbh}/scope.yaml", Path(scope_file).read_text())

    session = board.last_session(prog) if resume else None
    task = build_task(board.frontier(prog), first=session is None and not board.rows(
        "SELECT 1 FROM facts WHERE program=? LIMIT 1", prog), max_turns=max_turns)
    if extra_task:
        task += "\n\nOperator instruction for this segment: " + extra_task
    run_id = board.run_start(prog, model)
    runs_dir = home() / "var" / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    stream_log = runs_dir / f"{run_id:05d}-{prog}.jsonl"

    cmd = ["podman", "exec", "-i", "--user", "hunter", "-w", f"/work/{prog}",
           "-e", f"BH_DIR=/work/{prog}/.bh", "-e", f"BH_PROGRAM={prog}",
           "-e", f"BH_RPS={scope.max_rps or 5:g}", "-e", "HOME=/home/hunter",
           AGENT, "sh", "-c", 'echo $$ > "$BH_DIR/agent.pid"; exec claude "$@"', "sh", "-p", task, "--output-format", "stream-json", "--verbose",
           "--model", model, "--max-turns", str(max_turns),
           "--permission-mode", "bypassPermissions",
           # token economy: every turn resends tool schemas + command listings; keep only what the hunt uses
           "--tools", os.environ.get("BH_TOOLS", "Bash,Read"), "--disable-slash-commands",
           "--settings", "/opt/bh/hooks/settings.json",
           "--append-system-prompt-file", f"/work/{prog}/.bh/system.md"]
    if effort:
        cmd += ["--effort", effort]
    if session:
        cmd += ["--resume", session]

    res = SegmentResult(program=prog, run_id=run_id, status="error", session_id=session)
    say = (lambda *_: None) if quiet else (lambda m: print(m, flush=True))
    say(f"▶ run {run_id} · {scope.platform}/{prog} · model={model} effort={effort or 'default'} · max {max_turns} turns / {minutes:g} min"
        + (f" · resume {session[:8]}" if session else ""))

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    timed_out = threading.Event()

    def _timeout():
        timed_out.set()
        kill_agent(prog)
        time.sleep(5)
        if proc.poll() is None:
            proc.kill()

    timer = threading.Timer(minutes * 60, _timeout)
    timer.start()
    result_msg: dict | None = None
    try:
        with open(stream_log, "w", buffering=1) as log:  # line-buffered: the UI tails this file live
            for line in proc.stdout:
                log.write(line)
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                t = ev.get("type")
                if t == "system" and ev.get("subtype") == "init":
                    res.session_id = ev.get("session_id") or res.session_id
                elif t == "assistant":
                    msg = ev.get("message", {})
                    if msg.get("stop_reason") == "refusal":
                        res.status = "refusal"
                    for c in msg.get("content", []):
                        if c.get("type") == "text" and c.get("text", "").strip():
                            say(f"  💬 {_short(c['text'], 220)}")
                        elif c.get("type") == "tool_use":
                            res.tool_calls += 1
                            inp = c.get("input", {})
                            say(f"  ⚙ {c.get('name')}: {_short(inp.get('command') or inp.get('description') or inp)}")
                elif t == "result":
                    result_msg = ev
    except BaseException:  # Ctrl-C / SIGTERM (bh hunt stopped): kill the agent, keep what it already wrote
        timer.cancel()
        kill_agent(prog)
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        ingest_notes(board, prog, run_id, bh_dir)
        board.run_end(run_id, status="stopped", session_id=res.session_id, note="stopped by operator")
        say(f"■ run {run_id} stopped by operator (agent killed in {AGENT})")
        raise
    finally:
        timer.cancel()
        proc.wait()
    err = proc.stderr.read() if proc.stderr else ""

    if result_msg:
        res.session_id = result_msg.get("session_id") or res.session_id
        res.turns = result_msg.get("num_turns") or 0
        res.cost_usd = result_msg.get("total_cost_usd")
        res.usage = result_msg.get("usage") or {}
        res.text = result_msg.get("result") or ""
        sub = result_msg.get("subtype", "")
        if res.status != "refusal":
            if sub == "success" and not result_msg.get("is_error"):
                res.status = "ok"
            elif sub == "error_max_turns":
                res.status = "max_turns"
            else:
                res.status = "error"
    if timed_out.is_set():
        res.status = "timeout"
    if QUOTA_RE.search(res.text or "") or QUOTA_RE.search(err or ""):
        if res.status != "ok":
            res.status = "quota"

    res.new_facts, res.new_findings, res.new_todos, res.progress = ingest_notes(board, prog, run_id, bh_dir)
    _, gate_todos = ingest_gate_events(board, prog, run_id, idents)
    res.new_todos += gate_todos
    if res.status == "refusal":
        board.add_todo("refusal", f"model refused during run {run_id}", f"see {stream_log}", program=prog,
                       dedup=f"{prog}:refusal:{run_id}")
        res.new_todos += 1

    u = res.usage
    board.run_end(run_id, status=res.status, session_id=res.session_id, turns=res.turns, cost_usd=res.cost_usd,
                  input_tokens=u.get("input_tokens"), output_tokens=u.get("output_tokens"),
                  cache_read=u.get("cache_read_input_tokens"), note=_short(res.text or err, 500))
    say(f"■ run {run_id} {res.status} · {res.turns} turns · {res.tool_calls} tools · "
        f"+{res.new_facts} facts +{res.new_findings} findings +{res.new_todos} todos (progress {res.progress})"
        + (f" · ${res.cost_usd:.2f} eq." if res.cost_usd else ""))
    if res.status == "error" and err.strip():
        say("  stderr: " + _short(err, 400))
    return res
