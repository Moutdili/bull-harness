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
  local    runs in the sandbox only, sends nothing (a HexStrike tool of the registry)
  refused  a HexStrike tool the registry refuses, with its reason
  no-route a HexStrike tool that has no route through the gate, with its reason
  unknown  not in the table: refused

`mcp__hexstrike__tool_run` takes its class from the HexStrike registry (bh.agent.hexstrike.registry, lot B), by the
`name` of the tool it runs: a registry or a tool that cannot be found is `unknown`, so refused.

Stdlib only, nothing outside bh.agent (the sandbox mounts bh/agent alone).
"""

from __future__ import annotations

from bh.agent import contract as c

CLASSES = ("mapper", "scanner", "request", "note", "passive", "browser", "local", "refused", "no-route", "unknown")
PREFIX = "mcp__"
HEXSTRIKE_RUN = "mcp__hexstrike__tool_run"
# full name `mcp__<server>__<tool>` -> class. The names are fixed by the servers (lots A and B of W3).
MCP_TOOLS: dict[str, str] = {
    "mcp__bh__web_read": "browser",
    "mcp__bh__web_act": "browser",
    "mcp__bh__web_wait_human": "browser",
    "mcp__bh__web_switch": "browser",
    "mcp__bh__request": "request",
    "mcp__bh__request_all": "request",
    "mcp__bh__note": "note",
    "mcp__bh__finding": "note",
    "mcp__bh__canary": "note",
    "mcp__bh__recall": "note",
    "mcp__bh__flows": "note",
    "mcp__bh__docs": "passive",
    "mcp__hexstrike__tools_list": "note",
    "mcp__hexstrike__tool_help": "note",
}
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


def _hexstrike_name(tool_input: object) -> str | None:
    """The registry name of the tool `tool_run` runs: `name` of its input (or of its `arguments`)."""
    if not isinstance(tool_input, dict):
        return None
    name = tool_input.get("name")
    if not isinstance(name, str) and isinstance(tool_input.get("arguments"), dict):
        name = tool_input["arguments"].get("name")
    return name if isinstance(name, str) and name else None


def _hexstrike_entry(tool_input: object):
    """The registry entry of the tool `tool_run` would run, None when the registry or the tool is not found."""
    name = _hexstrike_name(tool_input)
    if name is None:
        return None
    try:
        from bh.agent.hexstrike import registry  # lot B; imported here so the hooks start without it
    except ImportError:
        return None
    tools = getattr(registry, "TOOLS", None)
    try:
        return tools[name] if tools is not None else None
    except (KeyError, TypeError, IndexError):
        return None


def _field(entry, attr: str):
    return entry.get(attr) if isinstance(entry, dict) else getattr(entry, attr, None)


def hexstrike_reason(tool_input: object) -> str:
    """Why the registry refuses the tool (its `reason`), one line, at most 200 characters; empty when it says none."""
    entry = _hexstrike_entry(tool_input)
    for attr in ("reason", "why", "note"):
        value = _field(entry, attr) if entry is not None else None
        if isinstance(value, str) and value.strip():
            return " ".join(value.split())[:200]
    return ""


def classify(tool_name: str, tool_input: object) -> tuple[str, list[str]]:
    """(class, URLs of the input). A name outside the table, or a class outside CLASSES, is `unknown`.
    `mcp__hexstrike__tool_run` is classed by the registry entry of the tool it runs."""
    if tool_name == HEXSTRIKE_RUN:
        entry = _hexstrike_entry(tool_input)
        klass = _field(entry, "klass") if entry is not None else None
        klass = klass if isinstance(klass, str) else "unknown"
    else:
        klass = MCP_TOOLS.get(tool_name, "unknown") if is_mcp(tool_name) else "unknown"
    if klass not in CLASSES:
        klass = "unknown"
    return klass, urls_of(tool_input)
