"""Filesystem layout of a bull-harness home (BH_HOME, default: the current directory).

Functions, not constants: BH_HOME is read at call time (tests and the UI daemon set it).
Host paths only; the sandbox side of a program's work dir is described in bh.agent.contract.
"""

from __future__ import annotations

import os
from pathlib import Path


def home() -> Path:
    return Path(os.environ.get("BH_HOME", Path.cwd()))


def var() -> Path:
    return home() / "var"


def state() -> Path:
    """Shared with the gate container (mounted at /state)."""
    return var() / "state"


def active_scope() -> Path:
    return state() / "active-scope.yaml"


def events_log() -> Path:
    return state() / "events.jsonl"


def flows_log() -> Path:
    return state() / "flows.jsonl"


def flow_file(flow_id: str) -> Path:
    return state() / "flows" / f"{flow_id}.json"


def identities_dir(program: str) -> Path:
    return state() / "identities" / program


def identities(program: str) -> list[str]:
    d = identities_dir(program)
    return sorted(p.stem for p in d.glob("*.json")) if d.is_dir() else []


def board_db() -> Path:
    return var() / "board.sqlite"


def runs_dir() -> Path:
    return var() / "runs"


def run_log(run_id: int, program: str) -> Path:
    return runs_dir() / f"{run_id:05d}-{program}.jsonl"


def work_bh(program: str) -> Path:
    """Host view of the agent's /work/<program>/.bh (owned by the container user: read-only here)."""
    return var() / "work" / program / ".bh"


def stage(program: str) -> Path:
    """Host-writable staging area for files pushed into the container."""
    return var() / "stage" / program


def scopes_dir() -> Path:
    return home() / "scopes"


def secrets_dir() -> Path:
    return home() / "secrets"


def tools_dir() -> Path:
    return var() / "tools"
