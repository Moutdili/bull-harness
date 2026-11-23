#!/usr/bin/env python3
"""PostToolUse(Bash): keep long outputs on disk, show the model a head/tail + path.

Measured on Claude Code 2.1.330: updatedToolOutput must match the Bash output
shape {stdout, stderr, interrupted, isImage}; a plain string is ignored.
Fails open on its own errors (the original output is then shown), never blocks.
"""
import hashlib
import json
import os
import sys
import time
from pathlib import Path

MAX_LINES = int(os.environ.get("BH_TRUNC_LINES", "80"))
MAX_CHARS = int(os.environ.get("BH_TRUNC_CHARS", "8000"))
HEAD, TAIL = 30, 12
RAW = Path(os.environ.get("BH_DIR", "/work/.bh")) / "raw"


def shrink(text: str, label: str, tool_id: str) -> tuple[str, dict | None]:
    lines = text.splitlines()
    if len(lines) <= MAX_LINES and len(text) <= MAX_CHARS:
        return text, None
    RAW.mkdir(parents=True, exist_ok=True)
    name = f"{int(time.time())}-{hashlib.sha1(tool_id.encode()).hexdigest()[:8]}-{label}.log"
    path = RAW / name
    path.write_text(text)
    head = [l[:400] for l in lines[:HEAD]]
    tail = [l[:400] for l in lines[-TAIL:]] if len(lines) > HEAD + TAIL else []
    note = (f"[bh] {len(lines)} lines / {len(text)} chars; showing {len(head)}+{len(tail)}. "
            f"Full {label}: {path} (use grep/jq/sed -n on it, do not cat it whole)")
    body = "\n".join(head + ([f"... [{len(lines) - len(head) - len(tail)} lines elided] ..."] + tail if tail else []))
    return body + "\n" + note, {"label": label, "lines": len(lines), "chars": len(text), "path": str(path)}


def main() -> None:
    ev = json.load(sys.stdin)
    resp = ev.get("tool_response") or {}
    if ev.get("tool_name") != "Bash" or not isinstance(resp, dict):
        return
    tid = ev.get("tool_use_id", str(time.time()))
    out, s1 = shrink(resp.get("stdout") or "", "stdout", tid)
    err, s2 = shrink(resp.get("stderr") or "", "stderr", tid)
    if not (s1 or s2):
        return
    with open(RAW.parent / "trunc.jsonl", "a") as fh:
        fh.write(json.dumps({"ts": time.time(), "cmd": (ev.get("tool_input") or {}).get("command", "")[:300],
                             "stdout": s1, "stderr": s2}) + "\n")
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": {
        "stdout": out, "stderr": err, "interrupted": bool(resp.get("interrupted")),
        "isImage": bool(resp.get("isImage"))}}}))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # fail open: original output is kept
        print(f"bh post-hook error: {exc}", file=sys.stderr)
