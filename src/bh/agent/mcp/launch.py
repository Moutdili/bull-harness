"""`bh-agent mcp <server>`: start one of the sandbox's stdio MCP servers by name.

The name is looked up in SERVERS, never imported as given: a server outside the table does not start.
"""

from __future__ import annotations

import importlib
import sys

SERVERS = {"bh": "bh.agent.mcp.server", "hexstrike": "bh.agent.hexstrike.server"}


def main(argv: list[str]) -> None:
    if not argv or argv[0] not in SERVERS:
        sys.exit(f"usage: bh-agent mcp {'|'.join(SERVERS)}")
    try:
        module = importlib.import_module(SERVERS[argv[0]])
    except ImportError as exc:
        sys.exit(f"bh-agent mcp {argv[0]}: server not available ({exc.name})")
    module.main(argv[1:])
