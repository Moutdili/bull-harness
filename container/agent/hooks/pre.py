#!/usr/bin/env python3
"""PreToolUse(Bash): log every command (input of the alias miner / watchdog). Never blocks."""
import json
import os
import sys
import time
from pathlib import Path

LOG = Path(os.environ.get("BH_DIR", "/work/.bh")) / "commands.jsonl"

try:
    ev = json.load(sys.stdin)
    cmd = (ev.get("tool_input") or {}).get("command")
    if ev.get("tool_name") == "Bash" and cmd:
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(LOG, "a") as fh:
            fh.write(json.dumps({"ts": time.time(), "session": ev.get("session_id"), "cmd": cmd}) + "\n")
except Exception as exc:
    print(f"bh pre-hook error: {exc}", file=sys.stderr)
