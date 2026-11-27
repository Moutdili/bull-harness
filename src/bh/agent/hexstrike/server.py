"""MCP server of the HexStrike arsenal over stdio: one JSON-RPC message per line, three tools.

Origin: HexStrike AI (MIT, Copyright (c) 2026 Muhammad Osama (0x4m4)), hexstrike_mcp.py lines 267-5414 (its FastMCP
server exposing 151 tools). Modified: none of its code is kept; this loop is our own, in the standard library,
and exposes three meta-tools (tools_list, tool_help, tool_run) over the registry instead of 151 schemas, so the agent
sees at most 20 tools across all servers. Launched by `bh-agent mcp hexstrike` (lot A) as `main(argv)`.

Methods: initialize, notifications/initialized (and any notification: no answer), ping, tools/list, tools/call.
Stdout carries JSON-RPC only; the tools write their output under raw/.
"""

from __future__ import annotations

import json
import sys

from bh.agent.hexstrike import run

NAME, VERSION = "hexstrike", "0.1.0"
PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
_OBJ = "object"
TOOLS = [
    {
        "name": "tools_list",
        "description": "List the HexStrike tools: name, class (passive, mapper, scanner, local, no-route, refused), "
        "ported or not, category, binary present or not. 50 rows per page.",
        "inputSchema": {
            "type": _OBJ,
            "properties": {"category": {"type": "string"}, "page": {"type": "integer", "minimum": 1}},
        },
    },
    {
        "name": "tool_help",
        "description": "Parameters of one HexStrike tool, why it is refused or not ported, and a safe example call.",
        "inputSchema": {"type": _OBJ, "properties": {"name": {"type": "string"}}, "required": ["name"]},
    },
    {
        "name": "tool_run",
        "description": "Run one ported HexStrike tool through the gate, without a shell. args: its parameters "
        "(see tool_help); additional_args is a list of tokens. Returns 25 lines at most and the raw/ path.",
        "inputSchema": {
            "type": _OBJ,
            "properties": {
                "name": {"type": "string"},
                "args": {"type": _OBJ},
                "timeout": {"type": "integer", "minimum": 1, "maximum": run.MAX_TIMEOUT},
            },
            "required": ["name"],
        },
    },
]


def call(name: str, a: dict) -> tuple[str, bool]:
    """(text, isError) of one tool call."""
    if name == "tools_list":
        text = run.tools_list(a.get("category"), a.get("page", 1))
        return text, text.startswith(("unknown", "page:"))
    if name == "tool_help":
        text = run.tool_help(a.get("name"))
        return text, text.startswith("unknown")
    res = run.tool_run(a.get("name"), a.get("args"), a.get("timeout"))
    return json.dumps(res, ensure_ascii=False), not res.get("ok") and not res.get("partial")


def handle(msg: object) -> dict | None:
    """The answer to one message, None for a notification."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
        return _err(msg.get("id") if isinstance(msg, dict) else None, -32600, "invalid request")
    mid, method, params = msg.get("id"), msg["method"], msg.get("params") or {}
    if "id" not in msg:
        return None
    if method == "initialize":
        asked = params.get("protocolVersion") if isinstance(params, dict) else None
        return _ok(mid, {
            "protocolVersion": asked if asked in PROTOCOLS else PROTOCOLS[0],
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": NAME, "version": VERSION},
        })  # fmt: skip
    if method == "ping":
        return _ok(mid, {})
    if method == "tools/list":
        return _ok(mid, {"tools": TOOLS})
    if method == "tools/call":
        name = params.get("name") if isinstance(params, dict) else None
        if name not in {t["name"] for t in TOOLS}:
            return _err(mid, -32602, f"unknown tool {name!r}")
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            return _err(mid, -32602, "arguments: an object")
        try:
            text, is_error = call(name, args)
        except Exception as e:  # noqa: BLE001 - a tool bug answers this call, the server keeps serving
            text, is_error = f"internal error: {type(e).__name__}: {e}", True
        return _ok(mid, {"content": [{"type": "text", "text": text}], "isError": is_error})
    return _err(mid, -32601, f"method not found: {method}")


def _ok(mid: object, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid: object, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def main(argv: list[str] | None = None) -> int:
    if argv and argv[0] in ("-h", "--help"):
        print("usage: bh-agent mcp hexstrike  (MCP server on stdio: tools_list, tool_help, tool_run)", file=sys.stderr)
        return 0
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            out = _err(None, -32700, "parse error")
        else:
            out = handle(msg)
        if out is not None:
            sys.stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
