"""W3-A: the `bh` MCP server (stdio, JSON-RPC 2.0): the agent's builtins as 12 typed tools, guards intact."""

import ast
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from bh.agent import contract as c
from bh.agent import note, q, web
from bh.agent.mcp import call, launch, server

MCP_DIR = Path(server.__file__).parent
NAMES = {
    "web_read",
    "web_act",
    "web_wait_human",
    "web_switch",
    "request",
    "request_all",
    "note",
    "finding",
    "canary",
    "recall",
    "docs",
    "flows",
}
HONEST = {"counter": "B may have shared it", "severity_if": "a read without B's click", "severity_why": "1 click"}
LAUNCH = "import sys; from bh.agent.main import main; sys.argv = ['bh-agent', 'mcp', 'bh']; main()"
FORBIDDEN = ("bypass", "evade", "stealth", "brute", "exploit", "weaponiz")


@pytest.fixture
def bh_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_DIR", str(tmp_path))
    monkeypatch.setenv("BH_PROGRAM", "p")
    monkeypatch.delenv("BH_ROLE", raising=False)
    return tmp_path


def _call(name: str, arguments: dict) -> dict:
    ans = server.handle(
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    )
    assert ans is not None and ans["id"] == 7
    return ans["result"]


def _text(res: dict) -> str:
    assert [b["type"] for b in res["content"]] == ["text"]
    return res["content"][0]["text"]


def _cli(fn, *args) -> tuple[str, int]:
    """What the command line prints and returns: the same capture as the server, for an exact comparison."""
    return call.run_main(fn, *args)


def _notes(d: Path) -> list[dict]:
    return c.read_jsonl(d / c.NOTES) if (d / c.NOTES).exists() else []


# ------------------------------------------------------------------ D19: a whole session through pipes
def test_session_through_pipes(tmp_path):
    msgs = [
        {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "t", "version": "0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 1, "method": "ping"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "canary", "arguments": {}}},
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "note", "arguments": {"op": "think", "title": "-x first", "why": "--a reason"}},
        },
        {"jsonrpc": "2.0", "id": 5, "method": "resources/list"},
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "shell", "arguments": {}}},
        {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 3}},
    ]
    lines = "\n".join(json.dumps(m) for m in msgs) + "\n{not json\n"
    env = {"BH_DIR": str(tmp_path), "BH_PROGRAM": "p", "PATH": "/usr/bin:/bin"}
    p = subprocess.run(
        [sys.executable, "-I", "-c", LAUNCH],
        input=lines,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert p.returncode == 0, p.stderr
    out = [json.loads(x) for x in p.stdout.splitlines()]  # nothing but JSON-RPC on stdout
    assert all(m["jsonrpc"] == "2.0" for m in out)
    assert [m.get("id") for m in out] == [0, 1, 2, 3, 4, 5, 6, None]  # notifications never answered
    by = {m["id"]: m for m in out if m.get("id") is not None}
    init = by[0]["result"]
    assert init["protocolVersion"] == "2025-03-26"
    assert init["capabilities"] == {"tools": {}}
    assert init["serverInfo"]["name"] == "bh"
    assert by[1]["result"] == {}
    assert {t["name"] for t in by[2]["result"]["tools"]} == NAMES
    res3 = by[3]["result"]
    assert res3["isError"] is False and c.CANARY_RE.fullmatch(res3["content"][0]["text"])
    assert by[4]["result"] == {"content": [{"type": "text", "text": "ok think"}], "isError": False}
    assert by[5]["error"]["code"] == -32601
    assert by[6]["error"]["code"] == -32602
    assert out[-1]["error"]["code"] == -32700
    assert "bh-mcp:" in p.stderr  # logs on stderr
    rec = c.read_jsonl(tmp_path / c.NOTES)
    assert [(r["op"], r["title"], r["why"]) for r in rec] == [("think", "-x first", "--a reason")]


def test_initialize_without_version_and_bad_messages():
    ans = server.handle({"jsonrpc": "2.0", "id": "a", "method": "initialize", "params": {}})
    assert ans["result"]["protocolVersion"] == server.DEFAULT_PROTOCOL
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert server.handle({"id": 1, "method": "ping"})["error"]["code"] == -32600
    assert server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": []})["error"]["code"] == -32602
    out = io.BytesIO()
    server.serve(io.BytesIO(b'[{"jsonrpc":"2.0","id":1,"method":"ping"}]\n\n'), out)
    assert json.loads(out.getvalue())["error"]["code"] == -32600


def test_never_for_the_verifier(monkeypatch):
    monkeypatch.setenv("BH_ROLE", "verifier")
    with pytest.raises(SystemExit) as exc:
        server.main([], io.BytesIO(b""), io.BytesIO())
    assert "verifier" in str(exc.value.code)


# ------------------------------------------------------------------ launch and dispatch
def test_launch_table_and_dispatch(monkeypatch):
    assert launch.SERVERS == {"bh": "bh.agent.mcp.server", "hexstrike": "bh.agent.hexstrike.server"}
    with pytest.raises(SystemExit):
        launch.main(["bh.agent.note"])  # a name outside the table is never imported
    seen = []
    monkeypatch.setattr(server, "main", lambda argv: seen.append(argv))
    monkeypatch.setattr(sys, "argv", ["bh-agent", "mcp", "bh"])
    from bh.agent import main as agent_main

    agent_main.main()
    assert seen == [[]]


def test_main_dispatches_other_lots_commands():
    src = (MCP_DIR.parent / "main.py").read_text()
    for cmd, mod in (("docs", "docs"), ("cve", "cve"), ("flows", "flows"), ("fuzz", "fuzz"), ("js", "js")):
        assert f'cmd == "{cmd}"' in src and f"{mod}.main(args)" in src


# ------------------------------------------------------------------ the 12 tools: contract, schemas, help
def test_twelve_tools_strict_schemas():
    listed = server.tools_list({})["tools"]
    assert len(listed) == 12 and {t["name"] for t in listed} == NAMES
    for t in listed:
        s = t["inputSchema"]
        assert s["type"] == "object" and s["additionalProperties"] is False, t["name"]
        assert len(t["description"].splitlines()) <= 3, t["name"]
        assert set(s["required"]) <= set(s["properties"]), t["name"]
    by = {t["name"]: t["inputSchema"] for t in listed}
    assert set(by["web_read"]["properties"]["op"]["enum"]) == {
        "state",
        "text",
        "outline",
        "attr",
        "net",
        "frames",
        "tabs",
    }
    assert {"body", "clipboard"} <= set(by["web_read"]["properties"])
    assert set(by["web_act"]["properties"]["op"]["enum"]) == {"goto", "fill", "click", "press", "upload", "wait"}
    assert set(by["note"]["properties"]["op"]["enum"]) == {
        "fact",
        "intent",
        "done",
        "blocked",
        "think",
        "handoff",
        "cover",
        "reorder",
        "show",
        "frontier",
    }
    assert by["request"]["properties"]["url"]["pattern"] == "^https?://"  # the hook reads arguments.url


def _help_strings(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k in ("description", "examples", "example"):
                yield from (v if isinstance(v, list) else [v])
            yield from _help_strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _help_strings(v)


def test_help_holds_the_safe_case_only():
    texts = [str(x).lower() for x in _help_strings(server.tools_list({}))]
    assert len(texts) > 50
    assert not [(w, t) for t in texts for w in FORBIDDEN if w in t]


# ------------------------------------------------------------------ guards intact
def test_finding_without_honesty_refused_as_on_the_command_line(bh_dir, tmp_path):
    proof = tmp_path / "proof.json"
    proof.write_text("{}")
    base = {"title": "IDOR", "severity": "high", "class": "idor", "url": "https://t.test/a", "summary": "s"}
    res = _call("finding", {**base, "proof": str(proof)})
    cli = _cli(
        note.main, ["finding", "IDOR", "--severity", "high", "--class", "idor", "--url", "https://t.test/a",
                    "--proof", str(proof), "--summary", "s"]
    )  # fmt: skip
    assert res["isError"] is True
    assert _text(res) == f"{cli[0].rstrip()}\n[exit {cli[1]}]"
    assert "--counter is required and not empty" in _text(res)
    res = _call("finding", {**base, "proof": str(proof), **HONEST, "counter": "  "})
    assert res["isError"] and "--counter is required and not empty" in _text(res)
    assert _call("finding", {"title": "x", **HONEST})["isError"]  # no severity, class, url, summary
    assert _notes(bh_dir) == []


def test_note_has_no_verdict(bh_dir):
    res = _call("note", {"op": "verdict", "finding_id": "F1", "verdict": "confirmed", "reason": "r"})
    assert res["isError"] and "op must be one of" in _text(res)
    assert _notes(bh_dir) == []


def test_note_same_validations(bh_dir):
    res = _call("note", {"op": "intent", "title": "IDOR on orders", "kind": "test", "url": "https://t.test/o/1"})
    assert res["isError"] and "--kind test needs --recall" in _text(res)
    res = _call("note", {"op": "think", "title": "x", "summary": "y"})
    assert res["isError"] and "summary does not apply" in _text(res)
    res = _call("note", {"op": "handoff", "state": "s", "dead": "", "next": "n", "files": "f"})
    assert res["isError"] and "--dead is required" in _text(res)
    ok = _call(
        "note",
        {
            "op": "intent",
            "title": "IDOR on orders",
            "kind": "test",
            "url": "https://t.test/o/1",
            "class": "idor",
            "recall": "none",
            "success": "B's order",
        },
    )
    assert ok == {"content": [{"type": "text", "text": "ok intent"}], "isError": False}
    rec = _notes(bh_dir)[-1]
    assert (rec["op"], rec["kind"], rec["recall"], rec["vuln_class"], rec["success"]) == (
        "intent",
        "test",
        "none",
        "idor",
        "B's order",
    )
    assert _call("note", {"op": "fact", "title": "t", "as": ["user-a", "user-b"]})["isError"] is False
    assert _notes(bh_dir)[-1]["identities"] == "user-a,user-b"


def test_note_blocked_and_cover_positionals(bh_dir, tmp_path):
    ev = tmp_path / "ev.txt"
    ev.write_text("x")
    res = _call("note", {"op": "cover", "endpoint": "GET /api/o/{id}", "class": "idor", "status": "clean",
                         "evidence": str(ev)})  # fmt: skip
    assert res["isError"] is False
    res = _call("note", {"op": "blocked", "reason": "captcha", "title": "login", "tried": "t", "would_prove": "w"})
    assert res["isError"] is False
    assert [r["op"] for r in _notes(bh_dir)] == ["cover", "blocked"]
    assert _notes(bh_dir)[-1]["would_prove"] == "w"


class FakeBrowser:
    def __init__(self, answer: dict):
        self.answer, self.seen = answer, []

    def __call__(self, req, timeout=120):
        self.seen.append(req)
        return self.answer


def test_web_act_during_a_challenge_same_refusal(monkeypatch):
    fake = FakeBrowser({"error": "human-needed", "challenge": {"pending": True}, "url": "https://copilot.test/"})
    monkeypatch.setattr(web, "_call", fake)
    monkeypatch.setattr(web.secrets, "token_hex", lambda n: "0" * 16)
    res = _call("web_act", {"op": "click", "css": "#send"})
    cli_text, rc = _cli(web.main, ["click", "#send"])
    assert rc == 3 and res["isError"] is True
    assert _text(res) == f"{cli_text.rstrip()}\n[exit 3]"
    assert "never try to pass it yourself" in _text(res)
    assert fake.seen[0] == {"op": "click", "css": "#send"}


def test_web_fill_budget_same_code(monkeypatch):
    monkeypatch.setattr(web, "_call", FakeBrowser({"error": "fill-budget", "detail": "segment"}))
    res = _call("web_act", {"op": "fill", "css": "textarea", "text": "-hello"})
    assert res["isError"] and "prompt budget spent" in _text(res) and _text(res).endswith("[exit 4]")


def test_web_read_argv(monkeypatch):
    fake = FakeBrowser({"text": "hi"})
    monkeypatch.setattr(web, "_call", fake)
    _call("web_read", {"op": "net", "body": 3})
    _call("web_read", {"op": "text", "clipboard": True})
    _call("web_read", {"op": "text", "css": "main", "tail": 200})
    _call("web_read", {"op": "attr", "css": "a.share", "name": "href"})
    assert fake.seen == [
        {"op": "net", "body": 3},
        {"op": "text", "clipboard": True},
        {"op": "text", "css": "main", "tail": 200},
        {"op": "attr", "css": "a.share", "name": "href"},
    ]
    assert _call("web_read", {"op": "state", "css": "x"})["isError"]  # css does not apply to state
    assert _call("web_read", {"op": "ws-rewrite"})["isError"]  # not exposed


def test_web_read_long_page_stays_fenced(monkeypatch, bh_dir):
    page = "\n".join(f"line {i} " + "x" * 80 for i in range(400))
    monkeypatch.setattr(web, "_call", FakeBrowser({"text": page}))
    monkeypatch.setattr(web.secrets, "token_hex", lambda n: "ab" * 8)
    t = _text(_call("web_read", {"op": "text"}))
    assert len(t) <= call.LIMIT
    body, _, tail = t.rpartition("</page-data-abababababababab>")
    assert body.startswith("<page-data-abababababababab>") and "[bh]" in tail
    path = Path(tail.split("full output: ", 1)[1].split(" ", 1)[0])
    assert path.parent == bh_dir / c.RAW and page in path.read_text()


def test_upload_only_from_the_work_directory(monkeypatch, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    (work / "a.png").write_bytes(b"png")
    monkeypatch.setattr(c, "WORK_ROOT", str(work))
    fake = FakeBrowser({"ok": True})
    monkeypatch.setattr(web, "_call", fake)
    assert _call("web_act", {"op": "upload", "css": "input", "file": "/etc/hostname"})["isError"]
    assert _call("web_act", {"op": "upload", "css": "input", "file": str(work / "../work/../../etc")})["isError"]
    assert fake.seen == []
    assert _call("web_act", {"op": "upload", "css": "input", "file": str(work / "a.png")})["isError"] is False
    assert fake.seen[0]["name"] == "a.png"


def test_request_maps_to_q(monkeypatch, bh_dir):
    seen = []

    def fetch(url, **kw):
        seen.append((url, kw))
        return "200", "2", "application/json", b"{}", ""

    monkeypatch.setattr(q, "fetch", fetch)
    res = _call(
        "request",
        {"url": "https://t.test/api", "as": "user-a", "method": "PUT", "json": {"a": 1}, "headers": ["X-T: -1"]},
    )
    assert res["isError"] is False and _text(res).startswith("[200] 2B application/json")
    url, kw = seen[0]
    assert url == "https://t.test/api" and kw["method"] == "PUT" and kw["body"] == '{"a":1}'
    assert kw["headers"] == ["X-T: -1", f"{c.IDENTITY_HEADER}: user-a", "Content-Type: application/json"]
    _call("request", {"url": "https://t.test/b", "body": "-v --x"})
    assert seen[1][1]["body"] == "-v --x" and seen[1][1]["method"] == "POST"
    assert _call("request", {"url": "https://t.test/c", "body": "@/etc/passwd"})["isError"]
    assert _call("request", {"url": "https://t.test/c", "headers": ["@/etc/passwd"]})["isError"]
    assert _call("request", {"url": "https://t.test/c", "body": "a", "json": "{}"})["isError"]
    assert _call("request", {"url": "/relative"})["isError"]  # the hook's lock needs an absolute URL
    assert _call("request", {"url": "https://t.test/c", "shell": "id"})["isError"]
    assert len(seen) == 2


def test_request_all_is_get_only(monkeypatch, bh_dir):
    monkeypatch.setenv("BH_IDENTITIES", "user-a")
    seen = []
    monkeypatch.setattr(q, "fetch", lambda url, **kw: seen.append(kw) or ("200", "1", "", b"x", ""))
    assert _call("request_all", {"url": "https://t.test/x"})["isError"] is False
    assert [k["method"] for k in seen] == ["GET", "GET"]
    assert _call("request_all", {"url": "https://t.test/x", "method": "POST"})["isError"]


def test_docs_and_flows_follow_their_builtins_command_line(monkeypatch):
    """W3 merge: the MCP tools named --library/--id/--last/--contains, flags bh-docs and bh-flows do not take."""
    from bh.agent import docs, flows

    got = {}
    monkeypatch.setattr(docs, "main", lambda argv: got.setdefault("docs", argv))
    monkeypatch.setattr(flows, "main", lambda argv: got.setdefault("flows", argv))
    _call("docs", {"library": "/vercel/next.js", "query": "middleware matcher"})
    _call("flows", {"status": 403, "method": "POST", "n": 5})
    assert got["docs"] == ["/vercel/next.js", "middleware matcher"]
    assert got["flows"] == ["--status", "403", "--method", "POST", "-n", "5"]
    assert flows.parse(got["flows"]).status == 403


def test_recall_maps(monkeypatch, bh_dir):
    from bh.agent import recall

    seen = []
    monkeypatch.setattr(recall, "ask", lambda req: seen.append(req) or "R-1 nothing")
    assert _text(_call("recall", {"idea": "idor", "url": "https://t.test/o", "class": "idor"})) == "R-1 nothing"
    assert _call("recall", {"mode": "cell", "arg": "k1"})["isError"] is False
    assert seen[0]["mode"] == "search" and seen[0]["class"] == "idor" and seen[1] == {**seen[1], "arg": "k1"}
    assert _call("recall", {"mode": "map", "idea": "x"})["isError"]  # bh-recall's own refusal


def test_bound_keeps_raw(bh_dir):
    text = "a" * (call.LIMIT * 3)
    out = call.bound(text, "t")
    assert len(out) <= call.LIMIT and str(bh_dir / c.RAW) in out
    assert call.bound("short", "t") == "short"


def test_server_imports_no_socket_and_no_shell():
    for f in MCP_DIR.glob("*.py"):
        tree = ast.parse(f.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(a.name.split(".")[0] not in ("socket", "subprocess") for a in node.names), f
            if isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] not in ("socket", "subprocess"), f
            if isinstance(node, ast.keyword) and node.arg == "shell":
                pytest.fail(f"shell= in {f}")
