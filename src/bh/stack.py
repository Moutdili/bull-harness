"""The podman stack: container names, compose, and the few operations the host does inside the agent."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from bh import paths
from bh.agent import contract as c

AGENT = "bh-agent"
GATE = "bh-gate"
COMPOSE_FILE = "container/compose.yaml"


def compose(*args: str) -> int:
    return subprocess.call(["podman-compose", "-f", COMPOSE_FILE, *args], cwd=paths.home())


def pid_alive(pidfile: Path) -> int | None:
    """Pid stored in `pidfile` if that process is alive (UI daemon, UI-launched runs)."""
    try:
        pid = int(pidfile.read_text())
        os.kill(pid, 0)
        return pid
    except (OSError, ValueError):
        return None


def container_running(name: str) -> bool:
    r = subprocess.run(
        ["podman", "container", "inspect", "-f", "{{.State.Running}}", name], capture_output=True, text=True
    )
    return r.returncode == 0 and r.stdout.strip() == "true"


def agent_sh(
    script: str, *args: str, user: str = "hunter", stdin: str | None = None, timeout: float | None = 60
) -> subprocess.CompletedProcess:
    """Run `sh -c script args...` in the agent container."""
    return subprocess.run(
        ["podman", "exec", "-i", "--user", user, AGENT, "sh", "-c", script, "sh", *args],
        input=stdin,
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def push_file(container_path: str, text: str) -> None:
    """Write a file inside the agent as `hunter`. Rootless podman maps hunter to a host subuid,
    so the host cannot write the agent's /work directly."""
    r = agent_sh('mkdir -p "$(dirname "$1")" && cat > "$1"', container_path, stdin=text)
    if r.returncode != 0:
        raise SystemExit(f"cannot write {container_path} in {AGENT}: {r.stderr.strip()}")


def wipe_program(program: str) -> None:
    agent_sh('rm -rf -- "$1"', f"{c.WORK_ROOT}/{program}")


def kill_agent(program: str, grace: float = 8.0) -> None:
    """Stop the claude process of `program` (pid written by the launch wrapper). podman exec
    does not forward signals: killing the host-side process alone would leave an orphan."""
    pidfile = f"{c.sandbox_dir(program)}/{c.AGENT_PID}"
    script = (
        'p=$(cat "$1" 2>/dev/null) || exit 0; kill -0 "$p" 2>/dev/null || exit 0; kill -INT "$p"; i=0; '
        f'while kill -0 "$p" 2>/dev/null && [ $i -lt {int(grace * 2)} ]; do sleep 0.5; i=$((i+1)); done; '
        'pkill -KILL -P "$p" 2>/dev/null; kill -KILL "$p" 2>/dev/null; rm -f "$1"; true'
    )
    agent_sh(script, pidfile, user="root", timeout=grace + 20)
