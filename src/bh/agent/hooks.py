"""Claude Code hooks for the agent (registered in container/agent/hooks/settings.json).

PreToolUse(Bash):  log the command; enforce the program rules and the tool lock; record tested endpoints.
PreToolUse(mcp__*): the same rules for an MCP tool, classified by bh.agent.mcp_policy: an unknown tool is refused,
  a scanner is refused when the program forbids scanners, a `request` tool is under the tool lock on the origins of
  its URLs, the verifier gets no MCP tool at all. Every call is logged in commands.jsonl (tool, klass, decision).
PostToolUse(Bash): long outputs go to raw/, the model sees head + tail + the path. Exception: a single
  `bh-web text|frames|outline` or `bh-web net --body <i>` (already bounded by bh-browser; a chat's answer sits at the
  end and must not be elided) is shown whole up to EXEMPT_CHARS. Then the turn budget (budget_line).
PostToolUse(mcp__*): no rewrite (the shape of an MCP result is the server's); an output over MAX_CHARS is logged in
  trunc.jsonl.

Both fail open on unexpected errors: a broken hook must not stall the hunt (the gate is the boundary, the hooks
only help). An unknown MCP tool is not an error: it is refused. An unreadable coverage file is not an error either,
it reads as "nothing covered" and keeps the lock closed.
Measured on Claude Code 2.1.330: updatedToolOutput must keep the Bash output shape
{stdout, stderr, interrupted, isImage}; a plain string is ignored. The matcher `mcp__.*` is read as a regular
expression (a matcher with a character outside [A-Za-z0-9_|] is one, tested with RegExp.test): seen in the code of
the 2.1.332 binary, not measured on 2.1.330.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shlex
import sys
import time
from pathlib import Path

from bh.agent import contract as c
from bh.agent import mcp_policy

MAX_LINES = int(os.environ.get("BH_TRUNC_LINES", "80"))
MAX_CHARS = int(os.environ.get("BH_TRUNC_CHARS", "8000"))
HEAD, TAIL = 30, 12
# bh-web text answers at most TAIL_MAX (20 000) characters plus a one-line note; frames at most 200 redacted frames
EXEMPT_CHARS = int(os.environ.get("BH_TRUNC_EXEMPT_CHARS", "24000"))
EXEMPT_WEB = ("text", "frames", "outline")
_OPERATORS = ";&|()<>\n"

SCANNER_DENIAL = (
    f"{c.RULES_MARK} this program forbids automated scanners. Use bh-recon / bh-crawl and "
    "hand-made requests at a low rate; do not try another scanner."
)
VERIFIER_DENIAL = (
    f"{c.RULES_MARK} the verifier re-tests with single requests (curl, q, bh-agent replay, bh-browse), no other tools."
)

# Turn budget (written by the runner): {"max_turns": int, "used": int, "ts": float}; the steps already said go to
# budget.seen in the same directory.
BUDGET, BUDGET_SEEN = "budget.json", "budget.seen"
BUDGET_STEPS = (70, 85, 95)
BUDGET_LINE = (
    "[bh-budget] {pct}% of the turn budget is used: save your state now with bh-note handoff. "
    "This is not a request to finish."
)


# ------------------------------------------------------------------ PreToolUse
def rules_decision(cmd: str) -> str | None:
    """Program rules the harness enforces in the sandbox: no automated scanner when the program forbids them,
    and the verifier re-tests by hand only (no scanners, no mapping tools but bh-browse). A bh-note's text is
    never taken for a tool run."""
    if c.is_verifier():
        # bh-browse renders one page: the only way to re-test a DOM XSS or a client-side route
        tools = c.without_commands(cmd, ("bh-note", "bh-browse"))
        if c.runs_scanner(tools) or c.runs_mapper(tools):
            return VERIFIER_DENIAL
        return None
    tools = c.without_commands(cmd, ("bh-note",))
    # one rendered page with one marker is an observation, not a scan (audit I14, Mio's decision)
    if not c.scanners_allowed() and c.runs_scanner(tools) and not c.single_page_xss(tools):
        return SCANNER_DENIAL
    return None


def lock_for(urls: list[str]) -> str | None:
    """Denial message if one of `urls` is on an origin the tools have not covered yet."""
    d = c.bh_dir()
    missing: dict[str, list[str]] = {}
    for url in urls:
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


def lock_decision(cmd: str) -> str | None:
    """Denial message if `cmd` hand-crafts HTTP to an origin the tools have not covered yet."""
    if not c.uses_manual_http(cmd):
        return None
    return lock_for(c.urls_in(cmd))


def mcp_decision(name: str, klass: str, urls: list[str]) -> str | None:
    """Denial message for an MCP tool of class `klass` (mcp_policy.classify), None to let it run."""
    if c.is_verifier():
        return (
            f"{c.RULES_MARK} the verifier re-tests with single requests (curl, q, bh-agent replay, bh-browse), "
            "no MCP tools."
        )
    if klass == "unknown":
        return f"{c.RULES_MARK} unknown MCP tool {name[:120]}: only tools the harness has classified may run."
    if klass == "scanner" and not c.scanners_allowed():
        return SCANNER_DENIAL
    if klass == "request":
        return lock_for(urls)
    return None


def _deny(reason: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def _mcp_pre(ev: dict, name: str) -> dict | None:
    """Unlike the rest of the hooks, a failure here refuses: an MCP tool runs only once it is classified and logged."""
    try:
        klass, urls = mcp_policy.classify(name, ev.get("tool_input"))
        denial = mcp_decision(name, klass, urls)
        d = c.bh_dir()
        c.append_jsonl(
            d / c.COMMANDS,
            {
                "session": ev.get("session_id"),
                "tool": name[:200],
                "klass": klass,
                "decision": "deny" if denial else "allow",
                "urls": [u[:300] for u in urls[:20]],
            },
        )
        if not denial and klass == "request":
            c.record_touched(d, urls, via="mcp")
    except Exception as exc:  # noqa: BLE001 - fail closed for an MCP tool
        print(f"bh hook error: {exc}", file=sys.stderr)
        return _deny(f"{c.RULES_MARK} MCP tool {name[:120]} refused: the hook could not classify or log it.")
    return _deny(denial) if denial else None


def pre_tool_use(ev: dict) -> dict | None:
    name = ev.get("tool_name")
    if mcp_policy.is_mcp(name):
        return _mcp_pre(ev, name)
    cmd = (ev.get("tool_input") or {}).get("command") or ""
    if name != "Bash" or not cmd:
        return None
    denial = rules_decision(cmd) or (None if c.is_verifier() else lock_decision(cmd))
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
        return _deny(denial)
    if c.uses_manual_http(cmd):
        c.record_touched(d, c.urls_in(cmd), via="manual")
    return None


# ------------------------------------------------------------------ PostToolUse
def _expands(cmd: str) -> bool:
    """A `$` or a backquote that bash expands: outside single quotes (double quotes do not stop `$(...)`)."""
    single = escaped = False
    for ch in cmd:
        if escaped:
            escaped = False
        elif single:
            single = ch != "'"
        elif ch == "\\":
            escaped = True
        elif ch == "'":
            single = True
        elif ch in "$`":
            return True
    return False


def exempt(cmd: str) -> bool:
    """A single `bh-web text|frames|outline ...` or `bh-web net --body <i> ...`: its output is the browser's own
    bounded answer, so the hook does not elide it (up to EXEMPT_CHARS). The command is split by shlex first, so an
    operator inside quotes (`:has-text("a > b")`, `a > b`) is part of a selector; a pipe, a redirection, a second
    command or an expansion outside quotes ends the exemption."""
    if not cmd or _expands(cmd):
        return False
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=_OPERATORS)
    lex.whitespace, lex.whitespace_split, lex.commenters = " \t\r", True, ""
    try:
        words = list(lex)
    except ValueError:
        return False
    if len(words) < 2 or any(w and set(w) <= set(_OPERATORS) for w in words):
        return False
    if os.path.basename(words[0]) != "bh-web":
        return False
    op, rest = words[1], words[2:]
    return op in EXEMPT_WEB or (op == "net" and any(w == "--body" or w.startswith("--body=") for w in rest))


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


_LINE_TS = re.compile(rb'^\{"ts":\s*(-?[0-9]+(?:\.[0-9]+)?)')


def _line_ts(line: bytes) -> float | None:
    if m := _LINE_TS.match(line):
        return float(m.group(1))
    try:
        ts = json.loads(line).get("ts")
    except (ValueError, AttributeError):
        return None
    return float(ts) if isinstance(ts, (int, float)) and not isinstance(ts, bool) else None


def calls_since(path: Path, since: float, block: int = 1 << 16) -> int:
    """Lines of commands.jsonl stamped at or after `since`, read from the end (the file is in time order and only
    grows): the cost is the segment's lines, not the program's history."""
    try:
        fh = open(path, "rb")  # noqa: SIM115 - closed below
    except OSError:
        return 0
    n, rest = 0, b""
    with fh:
        pos = fh.seek(0, os.SEEK_END)
        while pos > 0:
            step = min(block, pos)
            pos -= step
            fh.seek(pos)
            lines = (fh.read(step) + rest).split(b"\n")
            rest = lines[0]  # maybe the end of a line that starts in the previous block
            for line in reversed(lines[1:]):
                ts = _line_ts(line)
                if ts is None:
                    continue
                if ts < since:
                    return n
                n += 1
        ts = _line_ts(rest)
        if ts is not None and ts >= since:
            n += 1
    return n


def budget_line(d: Path | None = None) -> str | None:
    """The `[bh-budget]` line when the turn budget crosses 70, 85 or 95 %, once per step; None otherwise.

    Used = budget.json `used` + the lines commands.jsonl got since its `ts`. This is an approximation: it counts tool
    calls (one line per Bash or MCP call, logged by PreToolUse) against a budget counted in turns, and one turn can
    make several calls, so a step falls a little early, never late. One caveat: a turn that only calls the other
    tools (Read, Grep, Edit...) writes no line, so in a segment made mostly of those the count runs behind.
    budget.json missing or unreadable: nothing. The steps already said are kept in budget.seen, reset when the
    runner writes a new budget (another `ts`)."""
    d = d or c.bh_dir()
    doc = c.read_json(d / BUDGET, None)
    if not isinstance(doc, dict):
        return None
    max_turns, used, ts = doc.get("max_turns"), doc.get("used", 0), doc.get("ts")
    if not all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in (max_turns, used, ts)):
        return None
    if max_turns <= 0:
        return None
    since = math.floor(float(ts) * 1000) / 1000  # commands.jsonl stamps are rounded to the millisecond
    pct = 100 * (max(0, used) + calls_since(d / c.COMMANDS, since)) / max_turns
    crossed = [p for p in BUDGET_STEPS if pct >= p]
    seen_doc = c.read_json(d / BUDGET_SEEN, {})
    seen: set[int] = set()
    if isinstance(seen_doc, dict) and seen_doc.get("ts") == ts and isinstance(seen_doc.get("seen"), list):
        seen = {p for p in seen_doc["seen"] if p in BUDGET_STEPS}
    new = [p for p in crossed if p not in seen]
    if not new:
        return None
    c.write_json(d / BUDGET_SEEN, {"ts": ts, "seen": sorted(seen | set(crossed))})
    return BUDGET_LINE.format(pct=new[-1])  # several steps crossed at once: the highest is said, all are marked


def _safe_budget_line() -> str | None:
    try:
        return budget_line()
    except Exception as exc:  # noqa: BLE001 - the budget is a hint: never lose the truncation for it
        print(f"bh hook error (budget): {exc}", file=sys.stderr)
        return None


def _size(resp: object) -> int:
    if isinstance(resp, str):
        return len(resp)
    try:
        return len(json.dumps(resp, ensure_ascii=False, default=str))
    except (TypeError, ValueError):
        return 0


def post_tool_use(ev: dict) -> dict | None:
    name = ev.get("tool_name")
    resp = ev.get("tool_response")
    if mcp_policy.is_mcp(name):
        # no rewrite: the result's shape belongs to the server; an oversized one is only logged
        if (size := _size(resp)) > MAX_CHARS:
            c.append_jsonl(c.bh_dir() / "trunc.jsonl", {"tool": name[:200], "chars": size})
        return None
    resp = resp or {}
    if name != "Bash" or not isinstance(resp, dict):
        return None
    tid = ev.get("tool_use_id") or str(time.time())
    inp = ev.get("tool_input")
    cmd = inp.get("command") if isinstance(inp, dict) else None
    stdout = resp.get("stdout") or ""
    if isinstance(cmd, str) and exempt(cmd) and len(stdout) <= EXEMPT_CHARS:
        out, s1 = stdout, None
    else:
        out, s1 = _shrink(stdout, "stdout", tid)
    err, s2 = _shrink(resp.get("stderr") or "", "stderr", tid)
    budget = _safe_budget_line()
    if not (s1 or s2 or budget):
        return None
    if s1 or s2:
        c.append_jsonl(c.bh_dir() / "trunc.jsonl", {"stdout": s1, "stderr": s2})
    if budget:
        out = out + ("\n" if out and not out.endswith("\n") else "") + budget
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
