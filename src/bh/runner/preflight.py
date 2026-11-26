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
read for a `platform: local` program only)."""

from __future__ import annotations

import json
import os
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
