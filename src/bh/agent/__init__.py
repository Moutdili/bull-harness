"""Code that runs inside the agent sandbox (stdlib only, Python >= 3.12).

Mounted read-only at /opt/bh/lib/bh/agent in the agent container. The host side
(runner) imports `bh.agent.contract` too, so the file layout of a program's work
directory is defined exactly once.
"""
