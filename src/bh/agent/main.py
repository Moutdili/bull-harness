"""Single entry point for the sandbox: dispatch on the program name.

container/agent/bin/bh-agent is the only executable; bh-note, bh-crawl, ... are symlinks
to it (so are the short request helpers `q` and `qq`). `bh-agent hook-pre|hook-post` is what Claude Code's
hooks call.
"""

from __future__ import annotations

import sys
from pathlib import Path

TOOLS = ("recon", "crawl", "content", "scan", "params", "sqli", "xss")


def main() -> None:
    name = Path(sys.argv[0]).name
    args = sys.argv[1:]
    if name == "bh-agent":
        if not args:
            tools = ", ".join((*TOOLS, "browse", "zap"))
            sys.exit(f"usage: bh-agent hook-pre|hook-post|note|<tool> ...  (tools: {tools})")
        name, args = f"bh-{args[0]}", args[1:]
    cmd = name.removeprefix("bh-")
    if cmd in ("hook-pre", "hook-post"):
        from bh.agent import hooks

        hooks.run(hooks.pre_tool_use if cmd == "hook-pre" else hooks.post_tool_use)
    elif cmd == "replay":
        from bh.agent import proof

        proof.main(args)
    elif cmd == "note":
        from bh.agent import note

        note.main(args)
    elif cmd in ("q", "qq"):
        from bh.agent import q

        q.main(cmd, args)
    elif cmd == "browse":  # the only module that imports playwright, lazily: bh-agent starts without it
        from bh.agent import browse

        browse.main(args)
    elif cmd == "zap":  # starts a ZAP daemon (Java) only inside run(): bh-agent starts without ZAP
        from bh.agent import zap

        zap.main(args)
    elif cmd in TOOLS:
        from bh.agent import tools

        tools.main(cmd, args)
    else:
        sys.exit(f"bh-agent: unknown command {cmd!r}")
