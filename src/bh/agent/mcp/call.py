"""Run a builtin's own `main` in the server's process and shape what it printed into one MCP result.

The builtin parses, validates, refuses and prints exactly as on the command line: its stdout and stderr are captured,
its sys.exit() becomes the result's code. Nothing here repeats a builtin's logic. A result longer than LIMIT goes to
raw/ in full and the text gives its head and the path, the way the PostToolUse hook does for Bash.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import re
import sys
import time
from collections.abc import Callable

from bh.agent import contract as c

LIMIT = 8000  # characters of one tool result (hooks.MAX_CHARS)
_OPEN = re.compile(r"<page-data-([0-9a-f]{8,64})>")


def run_main(fn: Callable[..., object], *args: object) -> tuple[str, int]:
    """(stdout then stderr, exit code) of `fn(*args)`. A string given to sys.exit is a refusal: code 1, the string
    in the text. stdin is empty for the builtin: the protocol's stream is never theirs to read."""
    out, err = io.StringIO(), io.StringIO()
    code: object = 0
    with (
        contextlib.redirect_stdout(out),
        contextlib.redirect_stderr(err),
        _stdin(io.StringIO("")),
    ):
        try:
            fn(*args)
        except SystemExit as exc:
            code = exc.code
    if isinstance(code, str):
        err.write(code if code.endswith("\n") else code + "\n")
        rc = 1
    elif code is None:
        rc = 0
    else:
        try:
            rc = int(code)  # type: ignore[call-overload]
        except (TypeError, ValueError):
            rc = 1
    return out.getvalue() + err.getvalue(), rc


@contextlib.contextmanager
def _stdin(stream: io.StringIO):
    saved = sys.stdin
    sys.stdin = stream
    try:
        yield
    finally:
        sys.stdin = saved


def _close_fences(head: str, full: str) -> str:
    """A page-data fence the cut left open is closed again: what comes from the page stays between its tags. Only
    the nonces the full output both opens and closes are considered (a page never knows the call's nonce)."""
    tail = []
    for nonce in dict.fromkeys(_OPEN.findall(full)):
        close = f"</page-data-{nonce}>"
        if close in full and head.count(f"<page-data-{nonce}>") > head.count(close):
            tail.append(close)
    return head + ("\n" + "\n".join(reversed(tail)) if tail else "")


def bound(text: str, label: str) -> str:
    """`text` itself when it fits LIMIT; else its head, the fences closed, and the raw/ path of the whole."""
    if len(text) <= LIMIT:
        return text
    raw = c.bh_dir() / c.RAW
    try:
        raw.mkdir(parents=True, exist_ok=True)
        path = raw / f"{int(time.time())}-mcp-{hashlib.sha1(text.encode()).hexdigest()[:8]}-{label}.log"
        path.write_text(text)
        where = f"full output: {path} (query it with grep/jq/sed -n, never cat it whole)"
    except OSError as exc:
        where = f"full output not kept ({type(exc).__name__})"
    note = f"\n[bh] {len(text)} characters; showing the head. {where}"
    head = text[: LIMIT - len(note) - 200]
    if (nl := head.rfind("\n")) > len(head) // 2:
        head = head[:nl]
    return _close_fences(head, text) + note


def result(text: str, rc: int, label: str) -> dict:
    """The MCP tools/call result: one text block, isError when the builtin exited non-zero (its code is said)."""
    text = text.rstrip("\n")
    if rc:
        text = (text + "\n" if text else "") + f"[exit {rc}]"
    return {"content": [{"type": "text", "text": bound(text or "(no output)", label)}], "isError": bool(rc)}
