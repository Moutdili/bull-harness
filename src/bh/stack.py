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
    """Delete the program's sandbox work dir, through the agent or, when it is down, from the host
    (`podman unshare`: the files belong to the container's subuid)."""
    if container_running(AGENT):
        agent_sh('rm -rf -- "$1"', f"{c.WORK_ROOT}/{program}", user="root")
    else:
        subprocess.run(["podman", "unshare", "rm", "-rf", "--", str(paths.var() / "work" / program)], check=False)


# The pid file lives in the agent's writable work dir: only a `claude` process owned by hunter is
# accepted as a target (the agent must not be able to aim this root-run kill at anything else).
# Descendants (bash, nuclei, sqlmap...) are collected first: once claude dies they are reparented.
_KILL_SCRIPT = r"""
p=$(cat "$1" 2>/dev/null) || exit 0
case "$p" in ''|*[!0-9]*) exit 0 ;; esac
case "$(cat /proc/$p/comm 2>/dev/null)" in claude*) ;; *) exit 0 ;; esac
[ "$(stat -c %U /proc/$p 2>/dev/null)" = hunter ] || exit 0
desc() { for k in $(pgrep -P "$1"); do desc "$k"; echo "$k"; done; }
all="$(desc "$p") $p"
kill -INT "$p"; i=0
while kill -0 "$p" 2>/dev/null && [ $i -lt "$2" ]; do sleep 0.5; i=$((i+1)); done
kill -KILL $all 2>/dev/null; rm -f "$1"; true
"""


# Every process of the agent user dies (except the container's keep-alive, a child of root's runuser),
# every session HOME and the user site-packages go, then one fresh HOME is created. Nothing the hunter
# started or planted (background job, usercustomize.py, ~/.claude) survives into the next session.
_RESET_SCRIPT = r"""
keep=" $(for r in $(pgrep -u root -x runuser); do pgrep -P "$r"; done | tr '\n' ' ') "
for p in $(pgrep -u hunter); do case "$keep" in *" $p "*) ;; *) kill -KILL "$p" 2>/dev/null ;; esac; done
rm -rf /tmp/bh-home-* /home/hunter/.local /home/hunter/.claude /home/hunter/.config/claude
mkdir -p "$1" && chown hunter:hunter "$1" && chmod 700 "$1"
"""


def reset_agent_user(home: str) -> None:
    """Start a session from nothing the previous one left behind; `home` is the new session's HOME."""
    r = agent_sh(_RESET_SCRIPT, home, user="root", timeout=30)
    if r.returncode != 0:
        raise SystemExit(f"cannot reset the agent user in {AGENT}: {r.stderr.strip()}")


def kill_agent(program: str, grace: float = 8.0, bh_dir: str | None = None) -> None:
    """Stop the claude process of `program` (or of the work dir `bh_dir`, e.g. a verifier's) and everything
    it started. podman exec does not forward signals: killing the host-side process alone would leave an orphan."""
    pidfile = f"{bh_dir or c.sandbox_dir(program)}/{c.AGENT_PID}"
    agent_sh(_KILL_SCRIPT, pidfile, str(int(grace * 2)), user="root", timeout=grace + 20)
