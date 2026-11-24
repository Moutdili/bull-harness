"""Claude Code hooks for the agent (registered in container/agent/hooks/settings.json).

PreToolUse(Bash):  log the command; enforce the tool lock; record tested endpoints.
PostToolUse(Bash): long outputs go to raw/, the model sees head + tail + the path.

Both fail open on unexpected errors: a broken hook must not stall the hunt. An unreadable
coverage file is not an error, it reads as "nothing covered" and keeps the lock closed.
Measured on Claude Code 2.1.330: updatedToolOutput must keep the Bash output shape
{stdout, stderr, interrupted, isImage}; a plain string is ignored.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time

from bh.agent import contract as c

MAX_LINES = int(os.environ.get("BH_TRUNC_LINES", "80"))
MAX_CHARS = int(os.environ.get("BH_TRUNC_CHARS", "8000"))
HEAD, TAIL = 30, 12


# ------------------------------------------------------------------ PreToolUse
def lock_decision(cmd: str) -> str | None:
    """Denial message if `cmd` hand-crafts HTTP to an origin the tools have not covered yet."""
    if not c.uses_manual_http(cmd):
        return None
    d = c.bh_dir()
    missing: dict[str, list[str]] = {}
    for url in c.urls_in(cmd):
        o = c.origin(url)
        if o is None or c.is_passive(c.host_of(url)):
            continue
        if m := c.missing_phases(d, o):
            missing[o] = m
    if not missing:
        return None
    lines = [f"{c.LOCK_MARK} manual HTTP is locked until your tools have covered the target. Run first:"]
    for o, phases in missing.items():
        lines += [f"  bh-{p} {o}" for p in phases]
    lines.append("Then the attack surface lands on the board and manual requests unlock for that origin.")
    return "\n".join(lines)


def pre_tool_use(ev: dict) -> dict | None:
    cmd = (ev.get("tool_input") or {}).get("command") or ""
    if ev.get("tool_name") != "Bash" or not cmd:
        return None
    denial = lock_decision(cmd)
    d = c.bh_dir()
    c.append_jsonl(
        d / c.COMMANDS,
        {
            "session": ev.get("session_id"),
            "cmd": cmd[:2000],
            "decision": "deny" if denial else "allow",
            "arsenal": c.uses_arsenal(cmd),
            "manual": c.uses_manual_http(cmd),
        },
    )
    if denial:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": denial,
            }
        }
    if c.uses_manual_http(cmd):
        c.record_touched(d, c.urls_in(cmd), via="manual")
    return None


# ------------------------------------------------------------------ PostToolUse
def _shrink(text: str, label: str, tool_id: str) -> tuple[str, dict | None]:
    lines = text.splitlines()
    if len(lines) <= MAX_LINES and len(text) <= MAX_CHARS:
        return text, None
    raw = c.bh_dir() / c.RAW
    raw.mkdir(parents=True, exist_ok=True)
    path = raw / f"{int(time.time())}-{hashlib.sha1(tool_id.encode()).hexdigest()[:8]}-{label}.log"
    path.write_text(text)
    head = [line[:400] for line in lines[:HEAD]]
    tail = [line[:400] for line in lines[-TAIL:]] if len(lines) > HEAD + TAIL else []
    elided = [f"... [{len(lines) - len(head) - len(tail)} lines elided] ..."] if tail else []
    note = (
        f"[bh] {len(lines)} lines / {len(text)} chars; showing {len(head)}+{len(tail)}. "
        f"Full {label}: {path} (query it with grep/jq/sed -n, never cat it whole)"
    )
    return "\n".join(head + elided + tail) + "\n" + note, {"label": label, "lines": len(lines), "path": str(path)}


def post_tool_use(ev: dict) -> dict | None:
    resp = ev.get("tool_response") or {}
    if ev.get("tool_name") != "Bash" or not isinstance(resp, dict):
        return None
    tid = ev.get("tool_use_id") or str(time.time())
    out, s1 = _shrink(resp.get("stdout") or "", "stdout", tid)
    err, s2 = _shrink(resp.get("stderr") or "", "stderr", tid)
    if not (s1 or s2):
        return None
    c.append_jsonl(c.bh_dir() / "trunc.jsonl", {"stdout": s1, "stderr": s2})
    return {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolOutput": {
                "stdout": out,
                "stderr": err,
                "interrupted": bool(resp.get("interrupted")),
                "isImage": bool(resp.get("isImage")),
            },
        }
    }


# ------------------------------------------------------------------ entry
def run(handler) -> None:
    try:
        ev = json.load(sys.stdin)
    except ValueError:
        return
    try:
        out = handler(ev)
    except Exception as exc:  # noqa: BLE001 - fail open, but say so
        print(f"bh hook error: {exc}", file=sys.stderr)
        return
    if out:
        print(json.dumps(out))
