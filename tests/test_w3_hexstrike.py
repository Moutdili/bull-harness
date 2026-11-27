"""W3-B: the HexStrike fork (registry D20, tools_list / tool_help / tool_run, stdio MCP server, hygiene).

No tool binary is run: tool_run is exercised with stand-in executables written by the tests."""

import ast
import io
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from bh.agent import contract as c
from bh.agent.hexstrike import registry as r
from bh.agent.hexstrike import run, server

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src/bh/agent/hexstrike"
BANNED = ("weaponiz", "nation-state", "evasion", "stealth", "bypass")


def _hexstrike_mcp() -> Path | None:
    """HexStrike's file next to the repository (../hexstrike), when the checkout has it."""
    for base in (ROOT.parent, *ROOT.parents):
        p = base / "hexstrike" / "hexstrike_mcp.py"
        if p.is_file():
            return p
    return None


@pytest.fixture
def bh(tmp_path, monkeypatch):
    work = tmp_path / "work" / "prog"
    (work / ".bh").mkdir(parents=True)
    monkeypatch.setenv("BH_DIR", str(work / ".bh"))
    monkeypatch.setenv("HTTPS_PROXY", "http://gate:8080")
    monkeypatch.delenv("BH_SCANNERS", raising=False)
    monkeypatch.delenv("BH_RPS", raising=False)
    return work


def _stand_in(tmp_path, monkeypatch, name: str, body: str) -> Path:
    """An executable called `name` on PATH, written by the test (python, no shell)."""
    d = tmp_path / "bin"
    d.mkdir(exist_ok=True)
    exe = d / name
    exe.write_text(f"#!{sys.executable}\n{body}\n")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{d}{os.pathsep}{os.environ.get('PATH', '')}")
    return exe


# ------------------------------------------------------------------ registry (D20)
def test_registry_has_every_hexstrike_tool_once():
    assert r.SPEC_COUNT == 151
    assert len(r.TOOLS) == 150
    assert r.DUPLICATES == {"httpx_probe": (2676, 3392)}
    assert r.TOOLS["httpx_probe"].origin == 3392 and r.TOOLS["httpx_probe"].duplicates == (2676,)


def test_registry_matches_hexstrike_source():
    src = _hexstrike_mcp()
    if src is None:
        pytest.skip("../hexstrike/hexstrike_mcp.py is not next to this checkout")
    found: dict[str, tuple[int, tuple]] = {}
    count = 0
    for node in ast.walk(ast.parse(src.read_text())):  # parsed, never run
        if isinstance(node, ast.FunctionDef) and any(
            isinstance(d, ast.Call) and getattr(d.func, "attr", "") == "tool" for d in node.decorator_list
        ):
            count += 1
            a = node.args
            defaults = [None] * (len(a.args) - len(a.defaults)) + list(a.defaults)
            params = tuple(
                (x.arg, r._type(x.annotation), None if d is None else ast.literal_eval(d), d is None)
                for x, d in zip(a.args, defaults, strict=True)
            )
            found[node.name] = (node.lineno, params)  # the last definition wins, as in FastMCP
    assert count == r.SPEC_COUNT
    assert set(found) == set(r.TOOLS)
    for name, (line, params) in found.items():
        t = r.TOOLS[name]
        assert t.origin == line, name
        assert tuple((p.name, p.type, p.default, p.required) for p in t.params) == params, name


def test_every_tool_has_a_class_and_a_short_help():
    for t in r.TOOLS.values():
        assert t.klass and t.klass in r.CLASSES, t.name
        assert t.help.strip() and t.help.count("\n") <= 1, t.name
        assert t.category, t.name
        if t.klass in ("refused", "no-route") or not t.ported:
            assert t.why, t.name


def test_contract_classes_are_kept():
    """A binary of contract.MAPPERS stays a mapper; one of contract.SCANNERS is a scanner, or stricter."""
    for t in r.TOOLS.values():
        if t.binary in c.MAPPERS:
            assert t.klass == "mapper", t.name
        if t.binary in c.SCANNERS:
            assert t.klass in ("scanner", "no-route", "refused"), t.name


def test_doctrine_classes():
    refused = {"hydra_attack", "john_crack", "hashcat_crack", "metasploit_run", "msfvenom_generate",
               "responder_credential_harvest", "netexec_scan", "pacu_exploitation", "prowler_scan",
               "execute_command", "generate_payload", "ai_generate_payload", "generate_exploit_from_cve",
               "create_attack_chain_ai", "discover_attack_chains", "pwntools_exploit", "hashpump_attack",
               "bugbounty_authentication_bypass_testing", "bugbounty_file_upload_testing"}  # fmt: skip
    no_route = {"nmap_scan", "nmap_advanced_scan", "masscan_high_speed", "rustscan_fast_scan", "smbmap_scan",
                "enum4linux_scan", "arp_scan_discovery", "nbtscan_netbios", "fierce_scan", "dnsenum_scan"}  # fmt: skip
    for n in refused:
        assert r.TOOLS[n].klass == "refused", n
    for n in no_route:
        assert r.TOOLS[n].klass == "no-route", n
    assert r.klass_of("ffuf_scan") == "scanner" and r.klass_of("katana_crawl") == "mapper"
    assert r.klass_of("gau_discovery") == "passive" and r.klass_of("strings_extract") == "local"
    assert r.klass_of("nope") is None and r.klass_of(None) is None


def _image_binaries() -> set[str]:
    pk = (ROOT / "container/agent/packages.txt").read_text().splitlines()
    names = {x.strip() for x in pk if x.strip() and not x.strip().startswith("#")}
    cf = (ROOT / "container/agent/Containerfile").read_text()
    if "/usr/local/bin/gau" in cf:
        names.add("gau")
    return names


def test_web_tools_of_the_image_are_ported():
    image = _image_binaries()
    for t in r.TOOLS.values():
        if t.category in ("web", "recon") and t.binary in image and t.klass not in ("refused", "no-route"):
            assert t.ported, t.name
    assert sum(t.ported for t in r.TOOLS.values()) >= 20


def test_ported_templates_are_tokens_without_shell():
    shells = {"sh", "bash", "dash", "zsh", "ksh", "env", "python", "python3", "perl", "ruby", "node", "busybox"}
    for t in r.TOOLS.values():
        if not t.ported:
            assert t.argv == (), t.name
            continue
        assert t.argv[0] == t.binary and t.binary not in shells, t.name
        assert "-c" not in t.argv[:2], t.name
        names = {p.name for p in t.params} | set(r.INTERNAL) | {"additional_args"}
        for template in t.argv:
            assert isinstance(template, str) and template and "\n" not in template, (t.name, template)
            m = r.GUARD.match(template)
            if m:
                assert m.group(2) in names, (t.name, template)
            for v in r.VAR.findall(m.group(4) if m else template):
                assert v in names, (t.name, template)
        for p in t.params:
            assert p.name in t.checks, (t.name, p.name)
            assert t.checks[p.name].kind in r.KINDS, (t.name, p.name)


def test_help_texts_avoid_banned_words():
    for t in r.TOOLS.values():
        text = f"{t.help}\n{t.why}\n{run.tool_help(t.name).replace(t.name, '')}".lower()
        for w in BANNED:
            assert w not in text, (t.name, w)


# ------------------------------------------------------------------ tools_list / tool_help
def test_tools_list_pages(bh):
    seen = set()
    page = 1
    while True:
        text = run.tools_list(page=page)
        lines = text.splitlines()
        assert len(lines) <= 60
        for line in lines[1:]:
            parts = line.split(" | ")
            if len(parts) == 5:
                seen.add(parts[0])
                assert parts[1] in r.CLASSES and parts[2] in ("ported", "-")
                assert parts[4].endswith(("present", "absent", "n/a"))
        if "more: tools_list" not in text:
            break
        page += 1
    assert seen == set(r.TOOLS)
    web = run.tools_list(category="web")
    assert "ffuf_scan" in web and "hydra_attack" not in web
    assert run.tools_list(category="nope").startswith("unknown category")
    assert run.tools_list(page=99).startswith("page:")


def test_tool_help(bh):
    h = run.tool_help("ffuf_scan")
    assert "scanner, ported" in h and "example: tool_run(" in h and "runs: ffuf " in h
    assert "-x http://gate:8080" in h
    assert "not ported" in run.tool_help("x8_parameter_discovery")
    assert "refused" in run.tool_help("hydra_attack")
    assert "no route" in run.tool_help("nmap_scan") or "no-route" in run.tool_help("nmap_scan")
    assert run.tool_help("ffuf").startswith("unknown tool")
    for t in r.TOOLS.values():
        if t.ported:  # the example is a safe call that passes every check
            argv = run.render(t, run.check_call(t, run.example(t)), run.internal_vars(bh / ".bh/raw/x"))
            assert argv[0] == t.binary


# ------------------------------------------------------------------ refusals
def test_refused_and_no_route_give_the_reason(bh):
    res = run.tool_run("hydra_attack", {"target": "x", "service": "ssh"})
    assert res["ok"] is False and "password attack" in res["refused"]
    res = run.tool_run("nmap_scan", {"target": "example.com"})
    assert res["ok"] is False and "gate" in res["refused"]
    res = run.tool_run("x8_parameter_discovery", {"url": "https://a.example/"})
    assert "not ported" in res["refused"]
    assert "unknown tool" in run.tool_run("nope")["refused"]


def test_scanner_refused_when_program_forbids_scanners(bh, monkeypatch):
    monkeypatch.setenv("BH_SCANNERS", "0")
    res = run.tool_run("ffuf_scan", {"url": "https://a.example"})
    assert res["ok"] is False and res["refused"].startswith(c.RULES_MARK)
    res = run.tool_run("katana_crawl", {"url": "https://a.example/"})
    assert not res.get("refused", "").startswith(c.RULES_MARK)


@pytest.mark.parametrize(
    "args",
    [
        {"url": "ftp://a.example/"},
        {"url": "https://a.example/\nx"},
        {"url": "https://a.example/" + "a" * 3000},
        {"url": "https://a.example/", "wordlist": "/etc/passwd"},
        {"url": "https://a.example/", "wordlist": "../../../etc/passwd"},
        {"url": "https://a.example/", "mode": "spider"},
        {"url": "https://a.example/", "match_codes": "200;id"},
        {"url": "https://a.example/", "nope": 1},
        {"wordlist": "x"},
        {"url": "https://a.example/", "additional_args": "-mc 200"},
    ],
)
def test_bad_parameters_are_refused(bh, args):
    res = run.tool_run("ffuf_scan", args)
    assert res["ok"] is False and res["refused"]


@pytest.mark.parametrize(
    ("tool", "tokens"),
    [
        ("ffuf_scan", [";", "id"]),
        ("ffuf_scan", ["-H", "a b"]),
        ("ffuf_scan", ["$(id)"]),
        ("ffuf_scan", ["`id`"]),
        ("ffuf_scan", ["a|b"]),
        ("ffuf_scan", ["-x", "http://evil:8080"]),
        ("ffuf_scan", ["-replay-proxy", "http://evil:8080"]),
        ("ffuf_scan", ["-rate", "500"]),
        ("ffuf_scan", ["-input-cmd", "id"]),
        ("ffuf_scan", ["-o", "/etc/cron.d/x"]),
        ("ffuf_scan", ["-o", "../../x"]),
        ("ffuf_scan", ["-w", "/etc/shadow"]),
        ("ffuf_scan", ["@args.txt"]),
        ("ffuf_scan", ["-request", "file:///etc/passwd"]),
        ("ffuf_scan", ["-H", "x\ny"]),
        ("ffuf_scan", ["-config", "x.toml"]),
        ("nuclei_scan", ["-proxy", "http://evil"]),
        ("nuclei_scan", ["-p", "http://evil"]),
        ("nuclei_scan", ["-itags", "dos"]),
        ("nuclei_scan", ["-code"]),
        ("nuclei_scan", ["--socks5", "x"]),
        ("sqlmap_scan", ["--os-shell"]),
        ("sqlmap_scan", ["--os-sh"]),
        ("sqlmap_scan", ["--os-cmd=id"]),
        ("sqlmap_scan", ["--os-pwn"]),
        ("sqlmap_scan", ["--risk", "3"]),
        ("sqlmap_scan", ["--risk=2"]),
        ("sqlmap_scan", ["--tamper=space2comment"]),
        ("sqlmap_scan", ["--tor"]),
        ("sqlmap_scan", ["--dump"]),
        ("sqlmap_scan", ["--technique", "T"]),
        ("sqlmap_scan", ["--eval=import os"]),
        ("sqlmap_scan", ["--output-dir", "/tmp/elsewhere"]),
        ("wpscan_analyze", ["--passwords", "rockyou.txt"]),
        ("wpscan_analyze", ["--api-token", "t"]),
        ("dalfox_xss_scan", ["--found-action", "id"]),
        ("katana_crawl", ["-d", "5"]),
        ("httpx_probe", ["-paths", "x.txt"]),
        ("strings_extract", ["-a"]),
        ("sqlmap_scan", ["-dmysql://u:p@db.example/x"]),
        ("sqlmap_scan", ["-ba"]),
        ("gobuster_scan", ["-o/etc/x"]),
        ("wfuzz_scan", ["-z", "file,/etc/passwd"]),
        ("ffuf_scan", ["-w", "/root/.claude/x:FUZZ"]),
        ("ffuf_scan", ["-u", "gopher://a.example/"]),
    ],
)
def test_additional_args_refused(bh, tool, tokens):
    t = r.TOOLS[tool]
    with pytest.raises(run.Refused):
        run.check_args(t, tokens)


@pytest.mark.parametrize(
    ("tool", "tokens"),
    [
        ("ffuf_scan", ["-H", "X-BH-Identity:alice", "-fc", "404"]),
        ("ffuf_scan", ["-o", "ffuf.json", "-of", "json"]),
        ("ffuf_scan", ["-w", "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"]),
        ("sqlmap_scan", ["--risk", "1", "--level=3", "-p", "id", "--technique=BE"]),
        ("nuclei_scan", ["-H", "Cookie:a=b"]),
        ("ffuf_scan", ["-w", "/usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ"]),
        ("sqlmap_scan", ["-v3", "--forms"]),
        ("gobuster_scan", ["-ofound.txt"]),
    ],
)
def test_additional_args_allowed(bh, tool, tokens):
    assert run.check_args(r.TOOLS[tool], tokens) == tokens


def test_value_cannot_become_an_option(bh):
    t = r.TOOLS["arjun_scan"]
    with pytest.raises(run.Refused):
        run.render(t, run.check_call(t, {"url": "https://a.example/", "data": "--proxy=http://x"}), {})


def test_locked_and_bounded_parameters(bh):
    t = r.TOOLS["katana_crawl"]
    with pytest.raises(run.Refused):
        run.check_call(t, {"url": "https://a.example/", "depth": 4})
    t = r.TOOLS["dalfox_xss_scan"]
    with pytest.raises(run.Refused):
        run.check_call(t, {"url": "https://a.example/", "blind": True})
    t = r.TOOLS["gau_discovery"]
    with pytest.raises(run.Refused):
        run.check_call(t, {"domain": "example.com", "providers": "wayback,commoncrawl"})
    assert run.check_call(t, {"domain": "example.com"})["providers"] == "wayback,otx,urlscan"


def test_timeout_bounds(bh):
    assert "timeout" in run.tool_run("katana_crawl", {"url": "https://a.example/"}, timeout=901)["refused"]
    assert "timeout" in run.tool_run("katana_crawl", {"url": "https://a.example/"}, timeout=0)["refused"]


# ------------------------------------------------------------------ running (stand-in binaries)
def test_tool_run_summary_and_raw(bh, tmp_path, monkeypatch):
    _stand_in(tmp_path, monkeypatch, "katana", "import sys\nfor i in range(100):\n    print('line', i, sys.argv[1:3])")
    calls = []
    real = subprocess.run

    def spy(*a, **kw):
        calls.append((a, kw))
        return real(*a, **kw)

    monkeypatch.setattr(run.subprocess, "run", spy)
    res = run.tool_run("katana_crawl", {"url": "https://a.example/", "additional_args": ["-H", "X-BH-Identity:a"]})
    assert res["ok"] is True and res["partial"] is False and res["rc"] == 0
    assert res["lines"] == 100 and len(res["summary"]) == 25
    assert res["summary"][0].startswith("line 0") and res["summary"][-1].startswith("line 99")
    raw = Path(res["raw"])
    assert raw.is_relative_to(bh / ".bh" / c.RAW) and (raw / "stdout.txt").read_text().count("\n") == 100
    assert "-proxy http://gate:8080" in (raw / "cmd.txt").read_text()
    (argv,), kw = calls[0]
    assert isinstance(argv, list) and kw["shell"] is False and 0 < kw["timeout"] <= run.MAX_TIMEOUT
    assert argv[-2:] == ["-H", "X-BH-Identity:a"]


def test_tool_run_timeout_is_partial(bh, tmp_path, monkeypatch):
    _stand_in(tmp_path, monkeypatch, "katana", "import time\nprint('first', flush=True)\ntime.sleep(30)")
    res = run.tool_run("katana_crawl", {"url": "https://a.example/"}, timeout=1)
    assert res["partial"] is True and res["ok"] is False and res["summary"] == ["first"]


def test_failed_tool_gives_no_lead(bh, tmp_path, monkeypatch):
    _stand_in(tmp_path, monkeypatch, "katana",
              "import sys\nprint('https://a.example/admin')\nprint('boom', file=sys.stderr)\nsys.exit(2)")  # fmt: skip
    res = run.tool_run("katana_crawl", {"url": "https://a.example/"})
    assert res["ok"] is False and res["rc"] == 2 and res["summary"] == [] and res["stderr"] == ["boom"]


def test_stdin_and_conf(bh, tmp_path, monkeypatch):
    _stand_in(tmp_path, monkeypatch, "hakrawler", "import sys\nprint('got', sys.stdin.read().strip())")
    res = run.tool_run("hakrawler_crawl", {"url": "https://a.example/"})
    assert res["summary"] == ["got https://a.example/"]
    _stand_in(tmp_path, monkeypatch, "gau", "import sys\nprint(open(sys.argv[2]).read().splitlines()[0])")
    res = run.tool_run("gau_discovery", {"domain": "example.com"})
    assert res["ok"] and res["summary"] == ["threads = 1"]


def test_missing_binary(bh, monkeypatch):
    monkeypatch.setattr(run.shutil, "which", lambda _b: None)
    res = run.tool_run("katana_crawl", {"url": "https://a.example/"})
    assert res["ok"] is False and "not installed" in res["refused"]


# ------------------------------------------------------------------ MCP server
def _rpc(method, params=None, mid=1):
    m = {"jsonrpc": "2.0", "method": method}
    if mid is not None:
        m["id"] = mid
    if params is not None:
        m["params"] = params
    return m


def test_server_methods(bh):
    init = server.handle(_rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}}))
    assert init["result"]["protocolVersion"] == "2025-06-18" and "tools" in init["result"]["capabilities"]
    assert server.handle(_rpc("notifications/initialized", mid=None)) is None
    assert server.handle(_rpc("ping"))["result"] == {}
    tools = server.handle(_rpc("tools/list"))["result"]["tools"]
    assert [t["name"] for t in tools] == ["tools_list", "tool_help", "tool_run"]
    out = server.handle(_rpc("tools/call", {"name": "tool_help", "arguments": {"name": "katana_crawl"}}))
    assert out["result"]["isError"] is False and "katana" in out["result"]["content"][0]["text"]
    out = server.handle(_rpc("tools/call", {"name": "tool_run", "arguments": {"name": "hydra_attack", "args": {}}}))
    assert out["result"]["isError"] is True and json.loads(out["result"]["content"][0]["text"])["refused"]
    assert server.handle(_rpc("tools/call", {"name": "nmap_scan"}))["error"]["code"] == -32602
    assert server.handle(_rpc("resources/list"))["error"]["code"] == -32601


def test_server_main_loop(bh, monkeypatch):
    lines = [
        json.dumps(_rpc("initialize", {"protocolVersion": "1999-01-01"})),
        json.dumps(_rpc("notifications/initialized", mid=None)),
        "{not json",
        "",
        json.dumps(_rpc("tools/call", {"name": "tools_list", "arguments": {"category": "recon"}}, mid=2)),
    ]
    monkeypatch.setattr(sys, "stdin", io.StringIO("\n".join(lines) + "\n"))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    assert server.main([]) == 0
    answers = [json.loads(x) for x in out.getvalue().splitlines()]
    assert len(answers) == 3
    assert answers[0]["result"]["protocolVersion"] == server.PROTOCOLS[0]
    assert answers[1]["error"]["code"] == -32700
    assert "gau_discovery" in answers[2]["result"]["content"][0]["text"]


# ------------------------------------------------------------------ hygiene and attribution
def _sources():
    files = sorted(SRC.rglob("*.py"))
    assert {f.name for f in files} >= {"__init__.py", "registry.py", "run.py", "server.py"}
    return files


def test_sources_have_no_shell_and_no_network_library():
    for f in _sources():
        text = f.read_text()
        assert not re.search(r"shell\s*=\s*True", text), f
        assert "os.system" not in text and "os.popen" not in text, f
        for node in ast.walk(ast.parse(text)):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            for n in names:
                top = n.split(".")[0]
                assert n != "http.server" and top not in ("flask", "requests", "socket", "httpx", "urllib3"), (f, n)
                assert top == "bh" or top in sys.stdlib_module_names or top == "__future__", (f, n)


def test_sources_carry_the_attribution():
    for f in _sources():
        head = ast.get_docstring(ast.parse(f.read_text())) or ""
        assert "HexStrike AI" in head and "MIT" in head and "modified" in head.lower(), f
        assert "hexstrike_mcp.py" in head, f
