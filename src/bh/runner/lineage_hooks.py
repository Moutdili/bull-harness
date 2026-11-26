"""The runner's only door to `bh.lineage` (wave W2): every call into the lineage goes through here.

Memory fails OPEN. A lineage module that is missing (ImportError) or raises is one line,
`lineage: <step> skipped (<reason>)`, and a neutral value (None, "", 0): the hunt goes on. Each step of `close` is
guarded on its own, so one failing step never keeps the next ones from running. Nothing here can cancel or delay a
safety stop: the runner calls these hooks after its own decisions, never before them.

The modules are imported inside the functions, never at import time: `bh.runner.run` loads without `bh.lineage`.

An agent is the dict `identity.birth` returns (at least `no`; `pseudo` when there is one). The handles this module
opens for it (trace, recall server, archive dir, texts) live in `_LIVE`, keyed by (program, agent no), never in the
dict itself: the dict goes to the task block as it came.
"""

from __future__ import annotations

import importlib
import inspect
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bh import paths
from bh.text import one_line

PACKAGE = "bh.lineage"
TRACE_FILE = "trace.jsonl"


def say(line: str) -> None:
    """Where the `lineage: ... skipped` lines go (the runner's stdout; tests replace it)."""
    print(line, flush=True)


def skipped(step: str, reason: object) -> None:
    if isinstance(reason, BaseException):
        reason = f"{type(reason).__name__}: {reason}"
    say(f"lineage: {step} skipped ({one_line(str(reason), 200)})")


def module(name: str):
    """`bh.lineage.<name>`, or ImportError. A test puts its doubles in sys.modules (None there = absent)."""
    return importlib.import_module(f"{PACKAGE}.{name}")


def _call(step: str, mod: str, attr: str, *args, default=None, **kwargs):
    """`bh.lineage.<mod>.<attr>(*args, **kwargs)`; on any failure one line and `default`."""
    try:
        fn = getattr(module(mod), attr)
        return fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 (fail open: the hunt goes on without this step)
        skipped(step, exc)
        return default


def available(name: str) -> tuple[bool, str]:
    """(True, "") when `bh.lineage.<name>` imports, else (False, the reason): for the CLI's messages."""
    try:
        module(name)
        return True, ""
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


@dataclass
class _Handles:
    program: str
    no: Any
    setup_sha256: str
    dir: Path | None = None
    trace: Any = None
    server: Any = None
    system_prompt: str | None = None
    task: str | None = None
    extra: dict = field(default_factory=dict)


_LIVE: dict[tuple[str, Any], _Handles] = {}


def _key(agent: dict | None, program: str | None = None) -> tuple[str, Any] | None:
    if not isinstance(agent, dict) or agent.get("no") is None:
        return None
    return (str(program or agent.get("program") or ""), agent.get("no"))


def _handles(agent: dict | None) -> _Handles | None:
    k = _key(agent)
    return _LIVE.get(k) if k else None


def _public(agent: dict) -> dict:
    return dict(agent)


# ------------------------------------------------------------------ start
def start(board, scope, run_id: int, setup_sha256: str, *, parent_no=None, mode: str | None = None) -> dict | None:
    """Tables ensured (store, recall, score), the agent born, its trace opened in its archive dir, its recall server
    started. Returns the agent, None when it could not be born (the segment runs without a lineage)."""
    try:  # no lineage package at all: one line, not one per step
        importlib.import_module(PACKAGE)
    except Exception as exc:  # noqa: BLE001
        skipped("start", exc)
        return None
    for mod in ("store", "recall", "score"):
        _call(f"{mod}.ensure", mod, "ensure", board)
    try:
        ident = module("identity")
        kwargs: dict = {"setup_sha256": setup_sha256, "parent_no": parent_no}
        if mode is not None:  # `bh agent relaunch --same-birth|--fresh-legacy`, when birth takes it
            try:
                if "mode" in inspect.signature(ident.birth).parameters:
                    kwargs["mode"] = mode
            except (TypeError, ValueError):
                pass
        agent = ident.birth(board, scope, run_id, **kwargs)
    except Exception as exc:  # noqa: BLE001
        skipped("birth", exc)
        return None
    if not isinstance(agent, dict) or agent.get("no") is None:
        skipped("birth", f"identity.birth returned {type(agent).__name__}, no agent number")
        return None
    agent.setdefault("program", scope.program)
    h = _Handles(program=scope.program, no=agent["no"], setup_sha256=setup_sha256)
    _LIVE[_key(agent, scope.program)] = h
    try:
        d = Path(module("archive").agent_dir(scope.program, agent["no"], agent.get("pseudo")))
        d.mkdir(parents=True, exist_ok=True)
        h.dir = d
        h.trace = module("chain").Trace(d / TRACE_FILE)
    except Exception as exc:  # noqa: BLE001
        skipped("trace", exc)
    try:
        h.server = module("serve").RecallServer(scope.program, run_id, Path(board.path), agent["no"])
        h.server.start()
    except Exception as exc:  # noqa: BLE001
        h.server = None
        skipped("recall server", exc)
    return agent


def remember(agent: dict | None, *, system_prompt: str | None = None, task: str | None = None) -> None:
    """The texts this agent started with, for its archive (default at close: the run's var/runs/ texts)."""
    if (h := _handles(agent)) is None:
        return
    if system_prompt is not None:
        h.system_prompt = system_prompt
    if task is not None:
        h.task = task


# ------------------------------------------------------------------ during the segment
def task_block(board, scope, agent: dict | None) -> str:
    """The `## Lineage` block of the agent's task; "" without an agent or on any failure."""
    if agent is None:
        return ""
    out = _call("task block", "block", "build", board, scope, _public(agent), default="")
    return out if isinstance(out, str) else ""


def event(agent: dict | None, ev: dict) -> str | None:
    """Append one event to the agent's chained trace; returns the new head, None when there is no trace."""
    h = _handles(agent)
    if h is None or h.trace is None:
        return None
    try:
        return h.trace.append(ev)
    except Exception as exc:  # noqa: BLE001
        skipped("trace event", exc)
        return None


def rotate(board, scope, agent: dict | None, run_id: int) -> dict | None:
    """Context rotation: the current agent is closed, another is born in the same run, its parent the old one."""
    if agent is None:
        return None
    h = _handles(agent)
    setup = h.setup_sha256 if h is not None else str(agent.get("setup_sha256") or "")
    close(board, scope, agent, run_id, "rotated")
    return start(board, scope, run_id, setup, parent_no=agent.get("no"))


# ------------------------------------------------------------------ close
def _text(h: _Handles | None, run_id: int, kind: str) -> str:
    held = (h.system_prompt if kind == "system" else h.task) if h is not None else None
    if held is not None:
        return held
    try:
        return paths.run_text(run_id, kind).read_text()
    except OSError:
        return ""


def close(board, scope, agent: dict | None, run_id: int, status: str) -> None:
    """Close the agent: open intents closed, the run's notes into its memory, intents marked for recall, the score
    computed, the archive written, the trace's block chained, the identity closed, the recall server stopped. Each
    step on its own: one that fails is said and the next ones still run."""
    if agent is None:
        return
    prog, no = scope.program, agent.get("no")
    h = _LIVE.pop(_key(agent, prog), None) or _LIVE.pop(_key(agent), None)
    try:
        from bh.runner import ingest

        ingest.close_open_intents(board, prog, run_id)
    except Exception as exc:  # noqa: BLE001
        skipped("close open intents", exc)
    _call("memory ingest", "store", "ingest_run", board, prog, run_id, no)
    _call("recall marks", "recall", "mark_intents", board, prog, run_id)
    _call("score", "score", "compute", board, prog)
    if h is not None and h.dir is not None:
        _call(
            "archive",
            "archive",
            "write",
            h.dir,
            identity=_public(agent),
            system_prompt=_text(h, run_id, "system"),
            task=_text(h, run_id, "task"),
            stream_path=paths.run_log(run_id, prog),
            hooks_path=paths.work_bh(prog) / "commands.jsonl",
        )
    else:
        skipped("archive", "no archive dir for this agent")
    head = None
    if h is not None and h.trace is not None:
        try:
            head = h.trace.head()
        except Exception as exc:  # noqa: BLE001
            skipped("trace head", exc)
    _call("chain block", "chain", "close_block", board, no, head, f"run {run_id} · {status}")
    _call("identity close", "identity", "close", board, no, status)
    if h is not None and h.server is not None:
        try:
            h.server.stop()
        except Exception as exc:  # noqa: BLE001
            skipped("recall server stop", exc)


# ------------------------------------------------------------------ setup knobs (the hashed setup records them)
def weights_sha256() -> str | None:
    """`score.weights_sha256()`, None without a score module."""
    out = _call("score weights", "score", "weights_sha256", default=None)
    return out if isinstance(out, str) else None


def live_agents() -> int:
    """Agents still open in this process (a test checks every one was closed)."""
    return len(_LIVE)


def _reset() -> None:  # tests
    _LIVE.clear()


__all__ = [
    "available",
    "close",
    "event",
    "live_agents",
    "module",
    "remember",
    "rotate",
    "start",
    "task_block",
    "weights_sha256",
]
