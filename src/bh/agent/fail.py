"""Typed failures of the builtins (T36): one line, one class, one action.

  [bh-fail] <class>: <action>

The class comes from the tool's exit (classify); the action is the harness's own text, one per class, never a word
of the target. `rate` never triggers a retry: the gate alone sets the pace. A failed tool writes no endpoint and no
lead (tools.Job): only observed values are recorded, and a failure observed nothing.

Stdlib only (the sandbox runs bh/agent with python3 -I).
"""

from __future__ import annotations

import re

MARK = "[bh-fail]"
CLASSES = ("timeout", "rate", "missing-tool", "bad-argument", "unreachable", "auth", "parse", "gate-denied")
# One action per class, written by the harness.
ACTIONS = {
    "timeout": "the output so far is kept in raw/ (partial, not coverage); rerun on a narrower target",
    "rate": "the gate sets the pace, nothing is retried: work on another lead and come back to this one later",
    "missing-tool": "this tool is not in the image: do this step by hand with single requests (curl, q)",
    "bad-argument": "fix the arguments (run it with --help); the target was not the problem",
    "unreachable": "check the origin with one `curl -sS --max-time 10 <url>` before anything else",
    "auth": "the identity's session is refused: test as another identity or anonymously; the host renews sessions",
    "parse": "the tool's answer could not be read: query its files in raw/ with grep or jq",
    "gate-denied": "the gate refused it (scope or rule): choose another route in scope, never one around the gate",
}
NO_PROOF = "[bh] no proof.json on this test"

# Most specific first: a gate refusal is a 403 too, a rate limit may say "forbidden".
_PATTERNS = (
    (
        "gate-denied",
        re.compile(r"x-bh-gate|bh-gate|denied by the gate|gate denied|tunnel connection failed: 403", re.I),
    ),
    ("rate", re.compile(r"\b429\b|too many requests|rate[- ]?limit", re.I)),
    (
        "missing-tool",
        re.compile(r"command not found|executable file not found|no module named|not installed", re.I),
    ),
    (
        "bad-argument",
        re.compile(
            r"usage:|unrecognized arguments|flag provided but not defined|unknown (flag|option|shorthand)|"
            r"invalid (argument|option|value)|required argument|missing argument",
            re.I,
        ),
    ),
    ("auth", re.compile(r"\b401\b|unauthori[sz]ed|authentication (failed|required)|session (expired|invalid)", re.I)),
    (
        "unreachable",
        re.compile(
            r"connection refused|connection reset|no such host|could not resolve|name or service not known|"
            r"network is unreachable|no route to host|proxyconnect|dial tcp|failed to connect|unreachable|"
            r"timed? ?out",
            re.I,
        ),
    ),
    ("parse", re.compile(r"json|decode|unmarshal|parse|syntax error|malformed", re.I)),
)


def line(klass: str, action: str | None = None) -> str:
    """`[bh-fail] <class>: <action>`; the default action is the class's own (ACTIONS). An unknown class reads as
    `parse`: the line is always one of the eight."""
    if klass not in CLASSES:
        klass = "parse"
    text = " ".join((action or ACTIONS[klass]).split())
    return f"{MARK} {klass}: {text}"


def classify(returncode: int | None, stderr: str | None, timed_out: bool) -> str:
    """The failure class of a tool run. Timeouts and exit codes first (124 = killed at the budget, 127 = no such
    program, 2 = the usual usage error), then the tool's stderr. Nothing recognised: `parse` (its answer is in raw/,
    unread)."""
    if timed_out or returncode == 124:
        return "timeout"
    if returncode == 127:
        return "missing-tool"
    text = stderr or ""
    for klass, rx in _PATTERNS:
        if rx.search(text):
            return klass
    if returncode == 2:
        return "bad-argument"
    return "parse"
