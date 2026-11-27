"""Gate self-test before a hunt (T4): the escape suite, run from inside the agent container, must pass before the
first segment of `bh run` and `bh hunt`.

1. The lab container is up (a prerequisite of every hunt, a real one included: the positive checks need it).
2. No run in progress (active-run.json absent: `positive:relay-refuses-without-run` expects the relay's refusal).
3. Lab scope active, profile `lab`: refusals, both positive checks and the witness, every one `ok`.
4. When the real scope has a passthrough host: that scope active, profile `msrc` (refusals only: no request of it
   reaches the target).

The suite runs with BH_ESC_JSONL=1: one JSON object per check {"check", "profile", "want", "got", "ok"}, then
{"summary": true, "checks": N, "fails": K}. An unreadable line, a check not ok, a missing summary (or one that
disagrees with the lines) fail the preflight; in profile `lab` only, a missing positive check or witness fails it
too. A failure cancels: there is no degraded mode. Nothing here is skipped for a real program (BH_PREFLIGHT=0 is
read for a `platform: local` program only).

`arsenal()` (T46) is another check, run before every segment: is each builtin's binary in the agent image (and each
tool ported from the HexStrike registry)? It cancels nothing: a missing builtin leaves the system prompt's Arsenal."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from bh import paths, stack

LAB_SCOPE = Path("lab") / "juiceshop.yaml"  # under paths.scopes_dir(): the lab the `lab` profile aims at
SUITE = Path("tests") / "escape" / "escape_check.sh"  # under paths.home()
LAB_REQUIRED = (
    "positive:in-scope-target-answers",
    "positive:relay-refuses-without-run",
    "witness:in-scope-request-passes",
)
CHECK_KEYS = ("check", "profile", "want", "got", "ok")
SUITE_TIMEOUT_S = 900
SETTLE_S = 1.5  # the gate reloads the active scope on its mtime


class PreflightFailed(SystemExit):
    """The gate's self-test failed: the hunt is cancelled (a SystemExit: `bh hunt` stops, `bh run` exits)."""

    def __init__(self, message: str, result: dict | None = None):
        super().__init__(message)
        self.result = result or {}


def default_exec(profile: str) -> str:
    """The suite inside the agent, as the hunter, JSON lines on stdout."""
    suite = paths.home() / SUITE
    with open(suite, "rb") as fh:
        r = subprocess.run(
            ["podman", "exec", "-i", "-e", "BH_ESC_JSONL=1", "--user", "hunter", stack.AGENT, "bash", "-s", profile],
            stdin=fh,
            capture_output=True,
            timeout=SUITE_TIMEOUT_S,
        )
    return r.stdout.decode("utf-8", "replace")


def parse(profile: str, out: str) -> dict:
    """{"profile", "ok", "checks", "fails", "failed": [names], "error": reason or None} of one profile's output."""
    rec: dict = {"profile": profile, "ok": False, "checks": 0, "fails": 0, "failed": [], "error": None}
    names: list[str] = []
    summary = None
    for n, line in enumerate(out.splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            obj = None
        if not isinstance(obj, dict):
            rec["error"] = f"line {n} is not a JSON object"
            return rec
        if obj.get("summary") is True:
            if summary is not None:
                rec["error"] = "two summary lines"
                return rec
            summary = obj
            continue
        if summary is not None:
            rec["error"] = f"line {n} after the summary"
            return rec
        if any(k not in obj for k in CHECK_KEYS) or not isinstance(obj["check"], str) or obj["ok"] not in (True, False):
            rec["error"] = f"line {n} is not a check line"
            return rec
        if obj["profile"] != profile:
            rec["error"] = f"line {n}: profile {obj['profile']!r}, expected {profile!r}"
            return rec
        names.append(obj["check"])
        if obj["ok"] is not True:
            rec["failed"].append(obj["check"])
    rec["checks"], rec["fails"] = len(names), len(rec["failed"])
    if summary is None:
        rec["error"] = "no summary line"
        return rec
    s_checks, s_fails = summary.get("checks"), summary.get("fails")
    if not all(isinstance(v, int) and not isinstance(v, bool) for v in (s_checks, s_fails)):
        rec["error"] = "summary line without integer checks/fails"
        return rec
    if (s_checks, s_fails) != (rec["checks"], rec["fails"]):
        rec["error"] = f"summary says {s_checks} checks / {s_fails} fails, the lines {rec['checks']} / {rec['fails']}"
        return rec
    if rec["failed"]:
        rec["error"] = "failed: " + ", ".join(rec["failed"])
        return rec
    if not names:
        rec["error"] = "no check ran"
        return rec
    if profile == "lab" and (missing := [c for c in LAB_REQUIRED if c not in names]):
        rec["error"] = "missing: " + ", ".join(missing)
        return rec
    rec["ok"] = True
    return rec


def enabled(scope, env=None, say: Callable[[str], None] | None = None) -> bool:
    """BH_PREFLIGHT=0 turns the preflight off for a `platform: local` program only; elsewhere it is ignored, said."""
    env = os.environ if env is None else env
    off = str(env.get("BH_PREFLIGHT", "1")).strip() == "0"
    if not off:
        return True
    if scope.platform == "local":
        return False
    if say:
        say(f"preflight: BH_PREFLIGHT=0 ignored for {scope.platform}/{scope.program} (read for local programs only)")
    return True


def _activate(scope_file: Path) -> None:
    from bh.runner.run import activate_scope

    activate_scope(scope_file)


def run(
    scope,
    *,
    exec_suite: Callable[[str], str] = default_exec,
    scope_file: Path | None = None,
    activate: Callable[[Path], None] | None = None,
    lab_up: Callable[[], bool] | None = None,
    settle: Callable[[], None] | None = None,
    say: Callable[[str], None] | None = None,
    now: Callable[[], float] = time.time,
) -> dict:
    """{"ok", "ts", "profiles": {name: parse()}, "error"}: the result for runs.preflight. Never raises on a failed
    check (see `require`). Must run under the run lock, before active-run.json is written."""
    say = say or (lambda m: None)
    activate = activate or _activate
    lab_up = lab_up or (lambda: stack.container_running(stack.LAB_CTR))
    settle = settle or (lambda: time.sleep(SETTLE_S))
    out: dict = {"ok": False, "ts": now(), "profiles": {}, "error": None}
    if not lab_up():
        out["error"] = (
            f"the lab container {stack.LAB_CTR} is down: the lab is a prerequisite of every hunt, a real one "
            "included (the gate's positive checks run against it). Start it: "
            "`podman-compose -f container/compose.yaml --profile lab up -d`"
        )
        return out
    paths.active_run().unlink(missing_ok=True)  # under the lock: no run is in progress, the relay must refuse
    plan = [("lab", paths.scopes_dir() / LAB_SCOPE)]
    if scope is not None and scope.support_hosts("passthrough"):
        if scope_file is None:
            out["error"] = f"{scope.program}: passthrough host but no scope file to activate for the msrc profile"
            return out
        plan.append(("msrc", Path(scope_file)))
    for profile, file in plan:
        try:
            activate(file)
            settle()
            text = exec_suite(profile)
        except (OSError, subprocess.SubprocessError, SystemExit) as exc:
            out["profiles"][profile] = {"profile": profile, "ok": False, "error": f"{type(exc).__name__}: {exc}"}
            out["error"] = f"profile {profile}: the escape suite did not run ({type(exc).__name__}: {exc})"[:400]
            return out
        rec = parse(profile, text)
        out["profiles"][profile] = rec
        say(
            f"preflight {profile}: {rec['checks']} checks, {rec['fails']} failed"
            + ("" if rec["ok"] else f" ({rec['error']})")
        )
        if not rec["ok"]:
            out["error"] = f"profile {profile}: {rec['error']}"
            return out
    out["ok"] = True
    return out


def require(scope, **kw) -> dict:
    """run(), and a PreflightFailed with the reason when it did not pass."""
    res = run(scope, **kw)
    if not res["ok"]:
        raise PreflightFailed(f"preflight failed, hunt cancelled: {res['error']}", res)
    return res


# ------------------------------------------------------------------ the arsenal (T46)
# The binary each builtin of bh.agent.tools runs (and bh-zap's java). One missing: the builtin fails at its first
# call, so its line leaves the system prompt's Arsenal (prompt.build_system_prompt, `missing_tools`).
BUILTIN_BINARIES = {
    "bh-recon": ("subfinder", "httpx-toolkit"),
    "bh-crawl": ("katana",),
    "bh-content": ("ffuf",),
    "bh-scan": ("nuclei",),
    "bh-params": ("arjun",),
    "bh-sqli": ("sqlmap",),
    "bh-xss": ("dalfox",),
    "bh-zap": ("java",),
}
_BINARY_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
# One line per binary: `+name` found on the hunter's PATH, `-name` not. The names travel as arguments, never in the
# script; the shell only answers for them.
_ARSENAL_SCRIPT = r"""
for b in "$@"; do
  if command -v -- "$b" >/dev/null 2>&1; then echo "+$b"; else echo "-$b"; fi
done
"""


def default_exec_in_agent(binaries: list[str]) -> str:
    """`command -v` of each binary inside the agent, as the hunter (its PATH)."""
    r = stack.agent_sh(_ARSENAL_SCRIPT, *binaries, timeout=60)
    if r.returncode != 0:
        raise OSError(f"arsenal check failed in {stack.AGENT}: {(r.stderr or '').strip()[:200]}")
    return r.stdout


def hexstrike_binaries() -> dict[str, str] | None:
    """{tool name: binary} of the tools ported from the HexStrike registry (lot B: bh.agent.hexstrike.registry.TOOLS,
    entries with `binary` and `ported`); None while that module is not there."""
    try:
        from bh.agent.hexstrike import registry  # type: ignore[attr-defined]
    except ImportError:
        return None
    tools = getattr(registry, "TOOLS", None)
    items = tools.items() if isinstance(tools, dict) else enumerate(tools or ())
    out: dict[str, str] = {}
    for key, t in items:
        get = t.get if isinstance(t, dict) else (lambda k, d=None, t=t: getattr(t, k, d))
        binary, ported = get("binary"), get("ported")
        if not ported or not isinstance(binary, str) or not _BINARY_NAME.fullmatch(binary):
            continue
        out[str(get("name") or key)] = binary
    return out


def arsenal(exec_in_agent: Callable[[list[str]], str] = default_exec_in_agent) -> dict:
    """{"ok", "builtins": {builtin: bool}, "binaries": {binary: bool}, "hexstrike": {tool: bool} | None,
    "missing": [builtin], "error"} for runs.preflight. A builtin is missing when one of its binaries is. Never
    raises: a check that cannot run says so in `error` and removes nothing from the prompt."""
    hex_tools = hexstrike_binaries()
    wanted = sorted({b for bins in BUILTIN_BINARIES.values() for b in bins} | set((hex_tools or {}).values()))
    out: dict = {"ok": False, "builtins": {}, "binaries": {}, "hexstrike": None, "missing": [], "error": None}
    try:
        text = exec_in_agent(wanted)
    except (OSError, subprocess.SubprocessError, SystemExit) as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"[:300]
        return out
    seen: dict[str, bool] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if len(line) > 1 and line[0] in "+-" and line[1:] in wanted:
            seen[line[1:]] = line[0] == "+"
    if set(seen) != set(wanted):
        out["error"] = "no answer for " + ", ".join(sorted(set(wanted) - set(seen)))
        return out
    out["binaries"] = seen
    out["builtins"] = {name: all(seen[b] for b in bins) for name, bins in BUILTIN_BINARIES.items()}
    out["missing"] = sorted(name for name, ok in out["builtins"].items() if not ok)
    if hex_tools is not None:
        out["hexstrike"] = {name: seen[b] for name, b in sorted(hex_tools.items())}
    out["ok"] = not out["missing"]
    return out
