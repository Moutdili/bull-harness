"""Classification of MCP tools for the sandbox hooks (hooks.pre_tool_use), the twin of contract's Bash table.

An MCP tool reaches the hooks as `mcp__<server>__<tool>` (matcher `mcp__.*` in container/agent/hooks/settings.json).
MSRC forbids scanners: an MCP tool is classified, and refused, the way a Bash command is, before any server runs in
the sandbox. A tool absent from MCP_TOOLS is `unknown` and refused; the table is filled when a server is added
(wave W3), never by the agent.

Classes:
  mapper   maps the surface (allowed; refused to the verifier like every MCP tool)
  scanner  an automated scanner: refused when the program forbids scanners (BH_SCANNERS=0)
  request  sends a hand-made request: same tool lock as curl on the origins of its URLs, which are then `touched`
  note     writes to the board
  passive  reads a third-party passive source
  browser  drives a browser
  unknown  not in the table: refused

Stdlib only, nothing outside bh.agent (the sandbox mounts bh/agent alone).
"""

from __future__ import annotations

from bh.agent import contract as c

CLASSES = ("mapper", "scanner", "request", "note", "passive", "browser", "unknown")
PREFIX = "mcp__"
# full name `mcp__<server>__<tool>` -> class. Empty in W1: only the tests put entries in it.
MCP_TOOLS: dict[str, str] = {}
_MAX_DEPTH, _MAX_STRINGS = 32, 10_000


def is_mcp(tool_name: object) -> bool:
    return isinstance(tool_name, str) and tool_name.startswith(PREFIX)


def _strings(value: object, depth: int = 0):
    """Every string of `value`, keys included, depth first. Past the bounds, nothing more (the caller then sees
    fewer URLs; the gate stays the boundary)."""
    if depth > _MAX_DEPTH:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(k, depth + 1)
            yield from _strings(v, depth + 1)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v, depth + 1)


def urls_of(tool_input: object) -> list[str]:
    """The URLs (contract.URL_RE) in every string of the input, recursively, in order, without duplicates."""
    out: list[str] = []
    for i, s in enumerate(_strings(tool_input)):
        if i >= _MAX_STRINGS:
            break
        out += c.URL_RE.findall(s)
    return list(dict.fromkeys(out))


def classify(tool_name: str, tool_input: object) -> tuple[str, list[str]]:
    """(class, URLs of the input). A name outside the table, or a class outside CLASSES, is `unknown`."""
    klass = MCP_TOOLS.get(tool_name, "unknown") if is_mcp(tool_name) else "unknown"
    if klass not in CLASSES:
        klass = "unknown"
    return klass, urls_of(tool_input)
