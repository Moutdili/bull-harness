"""The podman stack: container names, compose, and the few operations the host does inside the agent and judge."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from bh import paths
from bh.agent import contract as c

AGENT = "bh-agent"
GATE = "bh-gate"
# The verifier's own container (compose service `judge`): same image and gate as the agent, its own /work
# (var/judge on the host), so the hunter can neither read nor prepare anything the judge sees.
JUDGE_CTR = "bh-judge"
# Browser logins (compose service `login`, bh.accounts.browser): the agent's image on the sandbox network, behind
# the gate, no /work, no relay, nothing kept between two logins. Driven by the host only.
LOGIN_CTR = "bh-login"
LOGIN_USER = "hunter"
# The persistent headful browser with a remote screen (compose service `browser`, profile `browser`;
# bh.browser_service). Driven by the host through `podman exec -i` and by the agent through its narrow HTTP API.
BROWSER_CTR = "bh-browser"
BROWSER_USER = "hunter"
BROWSER_SERVICE = "browser"
# The practice lab (compose service `juiceshop`, profile `lab`): the gate's preflight runs its positive checks against
# it before every hunt, a real one included (bh.runner.preflight).
LAB_CTR = "bh-lab-juiceshop"
VERIFY_SUBDIR = ".verify"  # /work/<program>/.verify/F<id>: a verifier's work dir, only in the judge container
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
    """False when the container is not running, and when podman itself is missing (a host without it, the audit
    container): a status page answers "down" rather than failing."""
    try:
        r = subprocess.run(
            ["podman", "container", "inspect", "-f", "{{.State.Running}}", name], capture_output=True, text=True
        )
    except OSError:
        return False
    return r.returncode == 0 and r.stdout.strip() == "true"


def agent_sh(
    script: str,
    *args: str,
    user: str = "hunter",
    stdin: str | None = None,
    timeout: float | None = 60,
    container: str = AGENT,
) -> subprocess.CompletedProcess:
    """Run `sh -c script args...` in the agent container (or `container`, e.g. the judge's)."""
    return subprocess.run(
        ["podman", "exec", "-i", "--user", user, container, "sh", "-c", script, "sh", *args],
        input=stdin,
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def gate_python(script: str, timeout: float = 60) -> subprocess.CompletedProcess:
    """Run a Python script (stdin, isolated mode) in the gate, the only container that reaches the targets.
    Whatever the script needs travels inside `script` on stdin: never in argv (visible in `ps`) or the
    environment. Raises subprocess.TimeoutExpired past `timeout`."""
    return subprocess.run(
        ["podman", "exec", "-i", GATE, "python3", "-I", "-"],
        input=script,
        text=True,
        capture_output=True,
        timeout=timeout,
    )


def push_file(container_path: str, text: str, user: str = "hunter", container: str = AGENT) -> None:
    """Write a file inside the agent (or `container`) as `user`. Rootless podman maps the sandbox users to host
    subuids, so the host cannot write the containers' /work directly."""
    r = agent_sh('mkdir -p "$(dirname "$1")" && cat > "$1"', container_path, stdin=text, user=user, container=container)
    if r.returncode != 0:
        raise SystemExit(f"cannot write {container_path} in {container}: {r.stderr.strip()}")


def is_verify_dir(bh_dir: str | None) -> bool:
    return bool(bh_dir) and f"/{VERIFY_SUBDIR}/" in f"{bh_dir}/"


def container_of(bh_dir: str | None) -> str:
    """The container a claude process with this BH_DIR runs in: a verifier's work dir lives in the judge's."""
    return JUDGE_CTR if is_verify_dir(bh_dir) else AGENT


def in_container(cmd: list[str], container: str) -> list[str]:
    """`podman exec ... bh-agent ...` (bh.runner.run.agent_command) aimed at `container` instead. Exactly one
    argument may name the agent, else the command is not the one expected and nothing runs."""
    if cmd[:2] != ["podman", "exec"] or cmd.count(AGENT) != 1:
        raise ValueError("not a `podman exec` aimed at the agent container")
    return [container if x == AGENT else x for x in cmd]


def wipe_program(program: str) -> None:
    """Delete the program's sandbox work dir, through the agent or, when it is down, from the host
    (`podman unshare`: the files belong to the container's subuid)."""
    for name, vol in ((AGENT, "work"), (JUDGE_CTR, "judge")):
        if container_running(name):
            agent_sh('rm -rf -- "$1"', f"{c.WORK_ROOT}/{program}", user="root", container=name)
        else:
            subprocess.run(["podman", "unshare", "rm", "-rf", "--", str(paths.var() / vol / program)], check=False)


# The pid file lives in the agent's writable work dir: only a `claude` process owned by a sandbox user is
# accepted as a target (the agent must not be able to aim this root-run kill at anything else).
# Descendants (bash, nuclei, sqlmap...) are collected first: once claude dies they are reparented.
_KILL_SCRIPT = r"""
p=$(cat "$1" 2>/dev/null) || exit 0
case "$p" in ''|*[!0-9]*) exit 0 ;; esac
case "$(cat /proc/$p/comm 2>/dev/null)" in claude*) ;; *) exit 0 ;; esac
case "$(stat -c %U /proc/$p 2>/dev/null)" in hunter|judge) ;; *) exit 0 ;; esac
desc() { for k in $(pgrep -P "$1"); do desc "$k"; echo "$k"; done; }
all="$(desc "$p") $p"
kill -INT "$p"; i=0
while kill -0 "$p" 2>/dev/null && [ $i -lt "$2" ]; do sleep 0.5; i=$((i+1)); done
kill -KILL $all 2>/dev/null; rm -f "$1"; true
"""


# Kill every process of `$users` (but the container's keep-alive, a child of root's runuser) until none is left:
# a process that respawns or forks during the sweep is caught by the next round. Zombies are skipped (they hold
# nothing; init reaps them). Past the limit the script fails: a session never starts next to a survivor.
_KILL_USERS = r"""
keep=" $(for r in $(pgrep -u root -x runuser); do pgrep -P "$r"; done | tr '\n' ' ') "
i=0
while :; do
  left=""
  for u in $users; do
    id "$u" >/dev/null 2>&1 || continue
    for p in $(pgrep -u "$u"); do
      case "$keep" in *" $p "*) continue ;; esac
      case "$(ps -o stat= -p "$p" 2>/dev/null)" in Z*|'') continue ;; esac
      left="$left $p"
    done
  done
  [ -z "$left" ] && break
  [ $i -ge 50 ] && { echo "processes of $users survive the kill:$left" >&2; exit 1; }
  kill -KILL $left 2>/dev/null; sleep 0.1; i=$((i+1))
done
"""

# Every process of the agent user dies, every session HOME, the user site-packages and every file the hunter left
# in the temporary dirs go, then one fresh HOME is created (never through a link the hunter could have planted).
# Nothing the hunter started or planted (background job, usercustomize.py, ~/.claude) survives into the next session.
_RESET_SCRIPT = (
    'users="hunter judge"\n'
    + _KILL_USERS
    + r"""
rm -rf /tmp/bh-home-* /home/hunter/.local /home/hunter/.claude /home/hunter/.claude.json /home/hunter/.config/claude
find /tmp /var/tmp /dev/shm -mindepth 1 -user hunter -exec rm -rf -- {} + 2>/dev/null
rm -rf -- "$1" && mkdir -m 700 -- "$1" && chown -h hunter:hunter -- "$1"
"""
)

# Between two legs of one segment: the same kill, and the session HOME keeps only what `--resume` needs (the
# transcripts under .claude/projects), without auto memory or any CLAUDE.md. Settings, memory, MCP or plugin files
# the hunter wrote there are gone before the next leg loads them. A HOME that is not a plain directory of the
# hunter's is recreated empty (the resume then fails: a leg error, never a planted configuration).
_SCRUB_SCRIPT = (
    'users="hunter judge"\n'
    + _KILL_USERS
    + r"""
rm -rf /home/hunter/.local /home/hunter/.claude /home/hunter/.claude.json /home/hunter/.config/claude
h="$1"
if [ -L "$h" ] || [ ! -d "$h" ] || [ "$(stat -c %U -- "$h")" != hunter ]; then
  rm -rf -- "$h" && mkdir -m 700 -- "$h" && chown -h hunter:hunter -- "$h" || exit 1
  exit 0
fi
find "$h" -mindepth 1 -maxdepth 1 ! -name .claude -exec rm -rf -- {} +
if [ -L "$h/.claude" ] || [ ! -d "$h/.claude" ]; then rm -rf -- "$h/.claude"; exit 0; fi
find "$h/.claude" -mindepth 1 -maxdepth 1 ! -name projects -exec rm -rf -- {} +
if [ -L "$h/.claude/projects" ] || [ ! -d "$h/.claude/projects" ]; then rm -rf -- "$h/.claude/projects"; exit 0; fi
find "$h/.claude/projects" -mindepth 1 \( -name memory -o -name 'CLAUDE*.md' -o -name .claude -o -type l \) \
  -prune -exec rm -rf -- {} +
true
"""
)


# The verifier's own Unix user, in its own container (created on first use: the image needs no rebuild). The
# container is the judge's alone; the user keeps its files away from the keep-alive (hunter, from the entrypoint).
# Between two verifications every judge process dies, every HOME and every file the judge left in the
# temporary dirs go, and the work dir is recreated empty.
JUDGE = "judge"
_JUDGE_SCRIPT = (
    "id judge >/dev/null 2>&1 || useradd --no-create-home --home-dir /nonexistent --shell /bin/sh judge || exit 1\n"
    'users="judge"\n'
    + _KILL_USERS
    + r"""
rm -rf -- /tmp/bh-home-* "$1" "$2"
find /tmp /var/tmp /dev/shm -mindepth 1 -user judge -exec rm -rf -- {} + 2>/dev/null
mkdir -p -- "$1" "$2" && chown -h judge:judge -- "$1" "$2" && chmod 700 "$1" && chmod 755 "$2"
"""
)


# Before and after every browser login: no process of the login user alive (but the keep-alive), no HOME, profile or
# temporary file of an earlier login left (bh.accounts.browser makes them under /tmp/bh-login-*).
_LOGIN_RESET = (
    f'users="{LOGIN_USER}"\n'
    + _KILL_USERS
    + rf"""
rm -rf /tmp/bh-login-* /tmp/playwright* /home/{LOGIN_USER}/.cache/ms-playwright-* 2>/dev/null
find /tmp /var/tmp /dev/shm -mindepth 1 -user {LOGIN_USER} -exec rm -rf -- {{}} + 2>/dev/null
true
"""
)


def reset_login() -> None:
    """Kill and wipe whatever a browser login left in the login container. Raises SystemExit when it cannot."""
    r = agent_sh(_LOGIN_RESET, user="root", timeout=60, container=LOGIN_CTR)
    if r.returncode != 0:
        raise SystemExit(f"cannot reset {LOGIN_CTR}: {(r.stderr or '').strip()[:200]}")


def login_popen(argv: list[str], stderr=None) -> subprocess.Popen:
    """`podman exec -i` in the login container as the login user, text pipes on stdin/stdout. What the process
    needs (script, credential) travels on stdin, never in argv or the environment."""
    return subprocess.Popen(
        ["podman", "exec", "-i", "--user", LOGIN_USER, LOGIN_CTR, *argv],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=stderr if stderr is not None else subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )


def prepare_judge(home: str, work_dir: str) -> None:
    """Fresh HOME (700) and work dir (755: the host reads the verdict) for the verifier, owned by `judge`,
    in the judge container."""
    r = agent_sh(_JUDGE_SCRIPT, home, work_dir, user="root", timeout=30, container=JUDGE_CTR)
    if r.returncode != 0:
        raise SystemExit(f"cannot prepare the verifier user in {JUDGE_CTR}: {r.stderr.strip()}")


def reset_agent_user(home: str) -> None:
    """Start a session from nothing the previous one left behind; `home` is the new session's HOME."""
    r = agent_sh(_RESET_SCRIPT, home, user="root", timeout=60)
    if r.returncode != 0:
        raise SystemExit(f"cannot reset the agent user in {AGENT}: {r.stderr.strip()}")


def scrub_agent_user(home: str) -> None:
    """Between two legs of a segment: no process of the previous leg alive, nothing in `home` but the session
    transcripts `--resume` reads. Runs before the next leg starts, so it never touches that leg's process."""
    r = agent_sh(_SCRUB_SCRIPT, home, user="root", timeout=60)
    if r.returncode != 0:
        raise SystemExit(f"cannot scrub the agent user in {AGENT}: {r.stderr.strip()}")


def kill_agent(program: str, grace: float = 8.0, bh_dir: str | None = None) -> None:
    """Stop the claude process of `program` (or of the work dir `bh_dir`, e.g. a verifier's, in the judge
    container) and everything it started. podman exec does not forward signals: killing the host-side process
    alone would leave an orphan."""
    pidfile = f"{bh_dir or c.sandbox_dir(program)}/{c.AGENT_PID}"
    agent_sh(
        _KILL_SCRIPT, pidfile, str(int(grace * 2)), user="root", timeout=grace + 20, container=container_of(bh_dir)
    )
