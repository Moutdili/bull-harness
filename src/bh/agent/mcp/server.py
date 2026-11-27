"""`bh-agent mcp bh`: the agent's builtins as typed MCP tools, over stdio (JSON-RPC 2.0, one message per line).

Methods: initialize, notifications/initialized (no answer), ping, tools/list, tools/call. Any other request: -32601.
A notification is never answered. stdout carries the protocol and nothing else: at start the server keeps the
process's stdin and stdout for itself and points fd 0 at /dev/null and fd 1 at stderr, so a builtin (or the curl it
runs) can neither print into the protocol nor read from it. Logs go to stderr.

The server opens no connection of its own: each tool runs a builtin (tools.py), whose requests go through the gate
(q, through curl and the proxy) or to the browser's API on the sandbox network (bh-web). Stdlib only, nothing
outside bh.agent. It never starts for the verifier (BH_ROLE=verifier): the hooks refuse every MCP tool to it anyway.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
from typing import IO

from bh.agent import contract as c
from bh.agent.mcp import tools

NAME, VERSION = "bh", "1"
DEFAULT_PROTOCOL = "2025-06-18"  # answered when the client names none; else its own version is echoed
MAX_LINE = 4 << 20  # bytes of one message
PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL_ERROR = -32700, -32600, -32601, -32602, -32603


def log(msg: str) -> None:
    print(f"bh-mcp: {msg}", file=sys.stderr, flush=True)


def _error(rid: object, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def _ok(rid: object, res: dict) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "result": res}


def initialize(params: dict) -> dict:
    version = params.get("protocolVersion")
    return {
        "protocolVersion": version if isinstance(version, str) and version else DEFAULT_PROTOCOL,
        "capabilities": {"tools": {}},
        "serverInfo": {"name": NAME, "version": VERSION},
    }


def tools_list(_params: dict) -> dict:
    return {"tools": [t.listing() for t in tools.TOOLS]}


class ParamsError(Exception):
    pass


def tools_call(params: dict) -> dict:
    name, args = params.get("name"), params.get("arguments", {})
    tool = tools.BY_NAME.get(name) if isinstance(name, str) else None
    if tool is None:
        raise ParamsError(f"unknown tool: {str(name)[:100]}")
    if args is None:
        args = {}
    if bad := tools.check(tool.schema, args):
        log(f"call {name}: refused (arguments)")
        return tools.error(f"{name}: invalid arguments:\n  - " + "\n  - ".join(bad[:20]))
    res = tool.run(args)
    log(f"call {name}: {'error' if res.get('isError') else 'ok'}")
    return res


METHODS = {"initialize": initialize, "ping": lambda _p: {}, "tools/list": tools_list, "tools/call": tools_call}


def handle(msg: object) -> dict | None:
    """The answer to one message, None for a notification (or a response, which this server never asked for)."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return _error(msg.get("id") if isinstance(msg, dict) else None, INVALID_REQUEST, "invalid request")
    method = msg.get("method")
    if "id" not in msg:
        return None  # notifications/initialized, notifications/cancelled, ...: never answered
    rid = msg["id"]
    if not isinstance(rid, (str, int)) or isinstance(rid, bool):
        return _error(None, INVALID_REQUEST, "invalid id")
    if not isinstance(method, str):
        return None if ("result" in msg or "error" in msg) else _error(rid, INVALID_REQUEST, "invalid request")
    fn = METHODS.get(method)
    if fn is None:
        return _error(rid, METHOD_NOT_FOUND, f"method not found: {method[:100]}")
    params = msg.get("params", {})
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return _error(rid, INVALID_PARAMS, "params must be an object")
    try:
        return _ok(rid, fn(params))
    except ParamsError as exc:
        return _error(rid, INVALID_PARAMS, str(exc))
    except Exception as exc:  # noqa: BLE001 - one failed call never ends the session
        log(f"{method}: {type(exc).__name__}: {exc}")
        return _error(rid, INTERNAL_ERROR, f"internal error: {type(exc).__name__}")


def _send(out: IO[bytes], msg: dict) -> None:
    out.write(json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode() + b"\n")
    out.flush()


def serve(rin: IO[bytes], out: IO[bytes]) -> None:
    """Read messages until EOF; answer each request on `out`, in order."""
    while True:
        line = rin.readline(MAX_LINE + 1)
        if not line:
            return
        if len(line) > MAX_LINE and not line.endswith(b"\n"):
            while (more := rin.readline(MAX_LINE)) and not more.endswith(b"\n"):
                pass
            _send(out, _error(None, PARSE_ERROR, "message too long"))
            continue
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            _send(out, _error(None, PARSE_ERROR, "parse error"))
            continue
        if isinstance(msg, list):
            _send(out, _error(None, INVALID_REQUEST, "batches are not supported"))
            continue
        if (answer := handle(msg)) is not None:
            _send(out, answer)


def _claim_stdio() -> tuple[IO[bytes], IO[bytes]]:
    """The protocol's streams, kept for the server alone; fd 0 becomes /dev/null and fd 1 a copy of stderr."""
    rin = os.fdopen(os.dup(0), "rb")
    out = os.fdopen(os.dup(1), "wb")
    null = os.open(os.devnull, os.O_RDONLY)
    os.dup2(null, 0)
    os.close(null)
    os.dup2(2, 1)
    return rin, out


def main(argv: list[str] | None = None, rin: IO[bytes] | None = None, out: IO[bytes] | None = None) -> None:
    if argv:
        sys.exit("usage: bh-agent mcp bh   (stdio MCP server, no options)")
    if c.is_verifier():
        sys.exit("bh-mcp: not for the verifier: it re-tests with single requests, no MCP tools")
    if rin is None or out is None:
        rin, out = _claim_stdio()
    log(f"{NAME} {VERSION}: {len(tools.TOOLS)} tools, stdio")
    with contextlib.suppress(BrokenPipeError, KeyboardInterrupt):
        serve(rin, out)
