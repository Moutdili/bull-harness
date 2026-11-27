"""W3-F: the runner wires skills, MCP servers and the new tools into the hunter's session, and only into it.

Lot C's skills (bh.classes.all_skills ...) and lots A/B's servers may not be merged yet: the `skills` fixture uses the
real functions when they are there, else stand-ins with the contract's shape."""

import importlib.util
import io
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from bh import classes
from bh.agent import flows
from bh.board import Board
from bh.gate import policy
from bh.runner import identity, preflight, run
from bh.scope import load_scope, scope_from_dict

ROOT = Path(__file__).resolve().parents[1]
MCP_JSON = ROOT / "container" / "agent" / "hooks" / "mcp.json"
COPILOT = ROOT / "scopes" / "msrc" / "copilot.yaml"
MYTHOS = "claude-mythos-5-2"
SERVER_TOOLS = {"bh": 12, "hexstrike": 3}  # contracts of lots A and B


def _scope(**kw):
    return scope_from_dict({"program": "p", "platform": "x", "in_scope": ["example.com"], **kw})


@pytest.fixture
def skills(monkeypatch, tmp_path):
    """Lot C's skill functions: the real ones once merged, else stand-ins of the same shape (prompt-injection pinned
    for Opus and Mythos on Copilot, D34)."""
    if run.skills_on():
        return classes.skills_dir()
    root = tmp_path / "skills"
    texts = {
        "prompt-injection": "## Indirect prompt injection\nPlant the canary in a document the assistant reads.",
        "idor": "## IDOR\nTwo identities, one object.",
        "nuclei-sweep": "## Template sweep\nRun the templates.",
    }
    for name, text in texts.items():
        (root / name).mkdir(parents=True)
        (root / name / "SKILL.md").write_text(f"---\nname: {name}\ndescription: d\n---\n{text}\n")
    meta = [
        {"name": "idor", "description": "d", "requires": None},
        {"name": "prompt-injection", "description": "d", "requires": None},
        {"name": "nuclei-sweep", "description": "d", "requires": "scanners"},
    ]

    def pinned(scope, model):
        m = str(model or "")
        return ["prompt-injection"] if "copilot" in scope.program and ("opus" in m or "mythos" in m) else []

    monkeypatch.setattr(classes, "all_skills", lambda: [dict(m) for m in meta], raising=False)
    named = ["idor", "prompt-injection"]
    monkeypatch.setattr(classes, "program_skills", lambda scope, model=None: list(named), raising=False)
    monkeypatch.setattr(classes, "pinned_skills", pinned, raising=False)
    monkeypatch.setattr(classes, "skill_text", lambda n: (root / n / "SKILL.md").read_text(), raising=False)
    monkeypatch.setattr(classes, "skills_dir", lambda: root, raising=False)
    return root


def _cmd(scope=None, **kw):
    return run.agent_command(
        scope or _scope(), "t", run_id=1, model="sonnet", max_turns=5, effort=None, session=None, **kw
    )


def _verifier(scope=None):
    return _cmd(scope, bh_dir="/work/p/.verify/F1", extra_env={"BH_ROLE": "verifier", "HOME": "/tmp/h"}, user="judge")


def _env(cmd: list[str]) -> dict[str, str]:
    return dict(cmd[i + 1].split("=", 1) for i, x in enumerate(cmd) if x == "-e")


# ------------------------------------------------------------------ the command line (D18-D20)
def test_hunter_gets_skills_and_both_servers(monkeypatch, skills):
    monkeypatch.delenv("BH_MCP", raising=False)
    cmd = _cmd()
    assert cmd[cmd.index("--tools") + 1] == "Bash,Read,Skill"
    assert "--disable-slash-commands" not in cmd  # it turns every skill off (Claude Code 2.1.330 --help)
    assert cmd[cmd.index("--setting-sources") + 1] == "user"  # no project skill or setting from the work tree
    assert cmd[cmd.index("--mcp-config") + 1] == run.MCP_CONFIG == "/opt/bh/hooks/mcp.json"
    assert "--strict-mcp-config" in cmd
    assert _env(cmd)["ENABLE_TOOL_SEARCH"] == "false"


def test_bh_mcp_0_removes_the_servers(monkeypatch, skills):
    monkeypatch.setenv("BH_MCP", "0")
    cmd = _cmd()
    assert "--mcp-config" not in cmd and "--strict-mcp-config" in cmd


def test_the_verifier_has_no_skill_and_no_server(monkeypatch, skills):
    monkeypatch.delenv("BH_MCP", raising=False)
    v = _verifier()
    assert v[v.index("--tools") + 1] == "Bash,Read"
    assert "--disable-slash-commands" in v and "--strict-mcp-config" in v
    assert "--mcp-config" not in v and "--setting-sources" not in v
    assert "ENABLE_TOOL_SEARCH" not in _env(v)
    # a verifier's role alone is enough, whatever the other arguments say
    w = _cmd(extra_env={"BH_ROLE": "verifier"})
    assert "--mcp-config" not in w and w[w.index("--tools") + 1] == "Bash,Read"


def test_the_scope_judge_has_no_tool_skill_or_server(monkeypatch, tmp_path, skills):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    seen = []

    def fake_run(cmd, **kw):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, json.dumps({"result": "", "total_cost_usd": 0}), "")

    monkeypatch.setattr(run.subprocess, "run", fake_run)
    board = Board(tmp_path / "b.sqlite")
    run.judge_request(board, _scope(), {"id": 1, "host": "x.example.com"}, run_id=1, model="opus")
    (cmd,) = seen
    assert cmd[cmd.index("--tools") + 1] == ""
    assert "--disable-slash-commands" in cmd and "--strict-mcp-config" in cmd and "--mcp-config" not in cmd


def test_without_lot_c_the_hunter_keeps_the_cards_path(monkeypatch):
    monkeypatch.setattr(run, "skills_on", lambda: False)
    cmd = _cmd()
    assert cmd[cmd.index("--tools") + 1] == "Bash,Read" and "--disable-slash-commands" in cmd
    assert run.allowed_skills(_scope()) is None


def test_mcp_json_declares_the_two_stdio_servers():
    doc = json.loads(MCP_JSON.read_text())
    servers = doc["mcpServers"]
    assert set(servers) == {"bh", "hexstrike"}
    for name, s in servers.items():
        assert s["type"] == "stdio" and s["command"] == "/opt/bh/bin/bh-agent" and s["args"] == ["mcp", name]
        assert not any(k in s for k in ("url", "headers")), "no remote server"


def test_compose_mounts_the_skills_for_the_agent_only():
    compose = (ROOT / "container" / "compose.yaml").read_text()
    agent = compose.split("\n  agent:\n")[1].split("\n  judge:\n")[0]
    judge = compose.split("\n  judge:\n")[1].split("\n  # ")[0]
    assert "../src/bh/skills:/opt/bh/skills:ro" in agent
    assert "skills" not in judge
    assert "- ./agent/hooks:/opt/bh/hooks:ro" in agent  # mcp.json travels with the hooks


def test_links_to_bh_agent():
    for name in ("bh-flows", "bh-docs", "bh-cve", "bh-fuzz", "bh-recall"):
        link = ROOT / "container" / "agent" / "bin" / name
        assert link.is_symlink() and link.readlink() == Path("bh-agent"), name


# ------------------------------------------------------------------ D22: 20 tools at most, no tool search beta
def _tools_list(server: str) -> int | None:
    """tools/list of one server, run from the sources (None while its module is not merged or it does not answer)."""
    mod = {"bh": "bh.agent.mcp", "hexstrike": "bh.agent.hexstrike"}[server]
    if importlib.util.find_spec(mod) is None:
        return None
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]  # fmt: skip
    code = (
        f"import sys; sys.path.insert(0, {str(ROOT / 'src')!r}); sys.argv = ['bh-agent', 'mcp', {server!r}]; "
        "from bh.agent.main import main; main()"
    )
    try:
        r = subprocess.run(
            [sys.executable, "-I", "-c", code],
            input="".join(json.dumps(m) + "\n" for m in msgs),
            capture_output=True,
            text=True,
            timeout=30,
            env={"PATH": "/usr/bin:/bin", "BH_DIR": "/nonexistent", "BH_PROGRAM": "p"},
        )
    except subprocess.TimeoutExpired:
        return None
    for line in r.stdout.splitlines():
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        if isinstance(doc, dict) and doc.get("id") == 2 and isinstance(doc.get("result"), dict):
            return len(doc["result"].get("tools") or [])
    return None


def test_at_most_twenty_visible_tools(skills):
    native = run.hunter_tools().split(",")
    servers = json.loads(MCP_JSON.read_text())["mcpServers"]
    counts = {}
    for name in servers:
        live = _tools_list(name)
        if live is not None:
            assert live == SERVER_TOOLS[name], (name, live)
        counts[name] = SERVER_TOOLS[name] if live is None else live
    assert len(native) + sum(counts.values()) <= run.MAX_VISIBLE_TOOLS == 20, (native, counts)
    assert len(native) + sum(counts.values()) == 18


def test_the_relay_lets_no_tool_search_beta_through():
    bad = [b for b in policy.RELAY_BETAS_DEFAULT if "advanced-tool-use" in b or "tool-search" in b]
    assert not bad, bad


# ------------------------------------------------------------------ skills in the HOME and the task (D18, D34)
def test_allowed_skills_leave_out_the_scanner_ones(skills):
    names = {s["name"] for s in classes.all_skills()}
    scan, no_scan = _scope(scanners_allowed=True), _scope(scanners_allowed=False)
    assert scan.scanners_on and not no_scan.scanners_on
    on, off = run.allowed_skills(scan), run.allowed_skills(no_scan)
    needs = {s["name"] for s in classes.all_skills() if "scanners" in run._requires(s)}
    # another program's own skill (msrc-*) is left out where the scope does not name it in `cards`
    others = {n for n in names if n.startswith(run.PROGRAM_SKILL_PREFIX) and n not in set(scan.cards or ())}
    assert needs and set(on) == names - others
    assert not needs & set(off) and set(off) == names - needs - others


def _block(model: str) -> tuple[str, str]:
    scope = load_scope(COPILOT)
    text = classes.skill_text("prompt-injection").strip()
    return run.segment_guides(scope, model, []), text if scope.scanners_on else classes.no_scanner(text)


def test_sonnet_task_names_skills_without_the_pinned_text(skills):
    block, text = _block("sonnet")
    assert text not in block
    assert "Load them first" in block and "Pinned skill" not in block


@pytest.mark.parametrize("model", ["opus", MYTHOS])
def test_opus_and_mythos_tasks_carry_prompt_injection(skills, model):
    block, text = _block(model)
    assert text in block and "# Pinned skill: prompt-injection" in block
    assert f"Proof standard (the verifier applies exactly this): {classes.evidence('prompt-injection')}" in block


def test_runs_cards_keeps_the_skill_list(skills):
    scope = load_scope(COPILOT)
    names = run.guide_names(scope, "opus", ["idor"])
    named, pinned = run.task_skills(scope, "opus")
    assert names == [*pinned, *named] and "prompt-injection" in names and "idor" not in pinned


def test_link_skills_passes_names_as_arguments(monkeypatch):
    calls = []

    def fake(script, *a, **k):
        calls.append((script, a, k))
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr(run.stack, "agent_sh", fake)
    run.link_skills("/tmp/bh-home-3", ["idor", "prompt-injection"])
    ((script, args, kw),) = calls
    assert args == ("/tmp/bh-home-3", "idor", "prompt-injection") and kw["user"] == "root"
    assert "idor" not in script
    with pytest.raises(SystemExit):
        run.link_skills("/tmp/bh-home-3", ["../etc"])


def test_skills_script_builds_a_links_only_directory(tmp_path):
    """The script for real on a temporary tree: HOME/.claude/skills holds one link per skill, to the read-only mount,
    and a planted skills directory is replaced."""
    mount = tmp_path / "opt-skills"
    for n in ("idor", "xss"):
        (mount / n).mkdir(parents=True)
        (mount / n / "SKILL.md").write_text(n)
    home = tmp_path / "home"
    (home / ".claude" / "skills" / "evil").mkdir(parents=True)
    (home / ".claude" / "skills" / "evil" / "SKILL.md").write_text("planted")
    (home / ".claude" / "projects").mkdir()
    script = run._SKILLS_SCRIPT.replace(run.SANDBOX_SKILLS, str(mount)).replace("chown -h hunter:hunter", "true")
    r = subprocess.run(["sh", "-c", script, "sh", str(home), "idor"], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    entries = sorted((home / ".claude" / "skills").iterdir())
    assert [e.name for e in entries] == ["idor"] and entries[0].is_symlink()
    assert entries[0].readlink() == mount / "idor"
    assert (home / ".claude" / "projects").is_dir()  # the transcripts --resume reads stay
    bad = subprocess.run(["sh", "-c", script, "sh", str(home), "nope"], capture_output=True, text=True, timeout=30)
    assert bad.returncode != 0


def test_clean_sandbox_and_clean_leg_link_the_skills(monkeypatch):
    calls = []
    monkeypatch.setattr(run.stack, "reset_agent_user", lambda h: calls.append(("reset", h)))
    monkeypatch.setattr(run.stack, "scrub_agent_user", lambda h: calls.append(("scrub", h)))
    monkeypatch.setattr(run, "_clean_work", lambda p: calls.append(("work", p)))
    monkeypatch.setattr(run, "link_skills", lambda h, s: calls.append(("link", h, tuple(s))))
    run.clean_sandbox("p", "/tmp/h", ["idor"])
    run.clean_leg("p", "/tmp/h", ["idor"])
    run.clean_leg("p", "/tmp/h")  # the cards path: no skill directory
    assert calls == [
        ("reset", "/tmp/h"), ("work", "p"), ("link", "/tmp/h", ("idor",)),
        ("scrub", "/tmp/h"), ("work", "p"), ("link", "/tmp/h", ("idor",)),
        ("scrub", "/tmp/h"), ("work", "p"),
    ]  # fmt: skip


# ------------------------------------------------------------------ the hashed setup
def _setup(skills=None, pinned=None, mcp=None):
    scope = SimpleNamespace(program="p", platform="local", digest="d" * 64, scanners_on=True, rate=2.0, identities=[])
    return identity.setup(
        scope, model="sonnet", effort=None, verifier_model="opus", max_turns=10, minutes=5.0, system_prompt="s",
        task_template="t", cards=[], max_runs_per_day=1, runs_per_session=1, sessions_per_day=1, fill_segment=1,
        fill_day=1, prompt_quantum=1, prompt_floor=1, skills=skills, pinned=pinned, tools="Bash,Read,Skill", mcp=mcp,
    )  # fmt: skip


def test_a_modified_skill_changes_the_setup(monkeypatch, skills, tmp_path):
    monkeypatch.setattr(identity, "claude_version", lambda: "2.1.330")
    root = tmp_path / "copy"
    (root / "idor").mkdir(parents=True)
    (root / "idor" / "SKILL.md").write_text("## IDOR\n")
    monkeypatch.setattr(classes, "skills_dir", lambda: root, raising=False)
    first, doc = _setup(skills=["idor"])
    assert doc["skills"][0]["name"] == "idor" and doc["skills"][0]["sha256"]
    (root / "idor" / "SKILL.md").write_text("## IDOR\nchanged\n")
    assert _setup(skills=["idor"])[0] != first


def test_bh_mcp_0_changes_the_setup(monkeypatch):
    monkeypatch.setattr(identity, "claude_version", lambda: "2.1.330")
    monkeypatch.delenv("BH_MCP", raising=False)
    on, doc = _setup()
    assert doc["mcp"]["enabled"] and doc["mcp"]["servers"] == ["bh", "hexstrike"] and doc["mcp"]["config_sha256"]
    monkeypatch.setenv("BH_MCP", "0")
    off, doc0 = _setup()
    assert off != on and doc0["mcp"]["enabled"] is False and doc0["mcp"]["servers"] == []
    assert doc["tools"] == "Bash,Read,Skill"


def test_sonnet_and_opus_setups_on_copilot_differ_by_pinned(monkeypatch, skills):
    monkeypatch.setattr(identity, "claude_version", lambda: "2.1.330")
    scope = load_scope(COPILOT)
    kw = dict(effort=None, max_turns=10, minutes=5.0, system_prompt="s", cards=[], shape={},
              skills=run.allowed_skills(scope))  # fmt: skip
    _, sonnet = run.setup_doc(scope, model="sonnet", **kw)
    _, opus = run.setup_doc(scope, model="opus", **kw)
    assert sonnet["pinned"] == [] and opus["pinned"] == ["prompt-injection"]
    diff = {k for k in sonnet if sonnet[k] != opus[k]}
    assert "pinned" in diff and diff <= {"pinned", "model", "verifier_model"}


# ------------------------------------------------------------------ counters
def _result(text: str) -> str:
    return json.dumps(
        {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "x", "content": text}]}}
    )


def test_repeat_refusals_and_fail_lines_are_counted(tmp_path):
    class Proc:
        stdout = iter(
            [
                _result("[bh-repeat] the same command already ran twice"),
                _result("ok\n[bh-fail] ffuf: no wordlist\n  [bh-fail] second\npage says [bh-fail] mid-line"),
                _result("nothing"),
            ]
        )

    res = run.SegmentResult(program="p", run_id=1)
    run.consume_stream(Proc(), io.StringIO(), res, lambda s: None)
    assert (res.repeats, res.fails) == (1, 2)
    b = Board(tmp_path / "b.sqlite")
    identity.ensure(b)
    cols = {r["name"] for r in b.db.execute("PRAGMA table_info(runs)")}
    assert {"repeats", "fails"} <= cols


# ------------------------------------------------------------------ T52: traffic index and bh-flows
def _flows(tmp_path, monkeypatch, recs):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    from bh import paths

    p = paths.flows_log()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("".join(json.dumps(r) + "\n" for r in recs) + "not json\n")
    pushed = {}
    monkeypatch.setattr(run.stack, "push_file", lambda path, text, **k: pushed.update({path: text}))
    return pushed


def test_flows_index_keeps_this_runs_target_traffic_redacted(tmp_path, monkeypatch):
    tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlc2lnbmF0dXJl"
    recs = [
        {"id": "1-aaaaaa-1", "ts": 1.0, "run": 7, "class": "target", "method": "GET", "status": 200, "len": 10,
         "identity": "user-a", "url": f"https://a.example.com/x?token=secret1&jwt={tok}"},
        {"id": "1-aaaaaa-2", "ts": 2.0, "run": 7, "class": "relay", "method": "POST", "url": "https://api.anthropic.com/v1"},
        {"id": "1-aaaaaa-3", "ts": 3.0, "run": 7, "class": "enroll", "method": "POST", "url": "https://login.example.com"},
        {"id": "1-aaaaaa-4", "ts": 4.0, "run": 6, "class": "target", "method": "GET", "url": "https://a.example.com/old"},
        {"id": "1-aaaaaa-5", "ts": 5.0, "run": 7, "class": "target", "method": "POST", "status": 403, "len": 5,
         "identity": None, "url": "https://a.example.com/y"},
    ]  # fmt: skip
    pushed = _flows(tmp_path, monkeypatch, recs)
    assert run.write_flows_index("p", 7) == 2
    ((path, text),) = pushed.items()
    assert path == "/work/p/.bh/flows.idx.jsonl"
    rows = [json.loads(x) for x in text.splitlines()]
    assert [r["id"] for r in rows] == ["1-aaaaaa-1", "1-aaaaaa-5"]
    assert set(rows[0]) == {"id", "ts", "method", "url", "status", "size", "identity"}
    assert "secret1" not in rows[0]["url"] and tok not in rows[0]["url"]
    assert rows[1]["status"] == 403 and rows[1]["identity"] is None and rows[0]["size"] == 10


def test_flows_index_is_capped(tmp_path, monkeypatch):
    recs = [{"id": f"1-abcdef-{i}", "run": 1, "class": "target", "method": "GET", "url": f"https://a.t/{i}"}
            for i in range(2100)]  # fmt: skip
    pushed = _flows(tmp_path, monkeypatch, recs)
    assert run.write_flows_index("p", 1) == flows.INDEX_MAX == 2000
    rows = next(iter(pushed.values())).splitlines()
    assert json.loads(rows[-1])["id"] == "1-abcdef-2099" and json.loads(rows[0])["id"] == "1-abcdef-100"


def test_a_failed_index_never_stops_the_segment(monkeypatch):
    def boom(*a, **k):
        raise SystemExit("podman down")

    said = []
    monkeypatch.setattr(run, "write_flows_index", boom)
    run.refresh_flows_index("p", 1, 0, said.append)
    assert said and "traffic index not written" in said[0]


def _index(tmp_path, n=50):
    rows = [
        {"id": f"1-abcdef-{i}", "ts": float(i), "method": "POST" if i % 5 == 0 else "GET",
         "url": f"https://a.example.com/api/{'admin' if i % 7 == 0 else 'item'}/{i}",
         "status": 403 if i % 3 == 0 else 200, "size": i, "identity": "user-a" if i % 2 else None}
        for i in range(n)
    ]  # fmt: skip
    p = tmp_path / ".bh" / flows.INDEX
    p.parent.mkdir(parents=True)
    p.write_text("".join(json.dumps(r) + "\n" for r in rows) + '{"id": 3}\n[]\n')
    return p


def test_bh_flows_filters_and_caps(tmp_path):
    rows = flows.read_index(_index(tmp_path))
    assert len(rows) == 50
    lines, note = flows.render(rows, flows.parse([]))
    assert len(lines) == flows.MAX_LINES == 30 and "50 flows match" in note
    lines, _ = flows.render(rows, flows.parse(["-n", "500"]))
    assert len(lines) == 30
    lines, _ = flows.render(rows, flows.parse(["--status", "403", "--method", "post", "--as", "user-a"]))
    assert lines and all(" POST 403 " in x and "[user-a]" in x for x in lines)
    lines, _ = flows.render(rows, flows.parse(["--grep", "admin", "--as", "none", "-n", "3"]))
    assert len(lines) == 3 and all("/admin/" in x and "[" not in x for x in lines)
    assert flows.render(rows, flows.parse(["--grep", "("]))[1].startswith("bh-flows: bad --grep")


def test_bh_flows_grep_has_a_time_limit():
    rows = [{"id": "1-abcdef-1", "method": "GET", "url": "https://a.t/" + "a" * 40 + "!"}]
    import re

    out, timed_out = flows.grep(rows, re.compile(r"(a+)+$"), budget_s=0.2)
    assert timed_out and out == []


def test_bh_flows_is_read_only(tmp_path, monkeypatch, capsys):
    p = _index(tmp_path, 5)
    monkeypatch.setenv("BH_DIR", str(p.parent))
    before = {x: x.stat().st_mtime_ns for x in p.parent.iterdir()}
    with pytest.raises(SystemExit) as e:
        flows.main(["--grep", "item"])
    assert e.value.code == 0
    assert {x: x.stat().st_mtime_ns for x in p.parent.iterdir()} == before
    out = capsys.readouterr().out.splitlines()
    assert len(out) == 4 and out[0].startswith("1-abcdef-1 GET 200 1 [user-a] https://a.example.com/api/item/1")


def test_bh_flows_lines_cannot_be_split_by_a_target():
    line = flows.line({"id": "1-a-1", "method": "GET", "url": "https://a.t/x\nfake-line\x1b[2J"})
    assert "\n" not in line and "\x1b" not in line


# ------------------------------------------------------------------ T46: the arsenal
def _answers(present):
    return lambda binaries: "".join(f"{'+' if b in present else '-'}{b}\n" for b in binaries)


def test_arsenal_finds_the_missing_builtins(monkeypatch):
    monkeypatch.setattr(preflight, "hexstrike_binaries", lambda: None)
    every = {b for bins in preflight.BUILTIN_BINARIES.values() for b in bins}
    res = preflight.arsenal(_answers(every - {"nuclei", "httpx-toolkit"}))
    assert res["missing"] == ["bh-recon", "bh-scan"] and res["ok"] is False and res["error"] is None
    assert res["builtins"]["bh-crawl"] is True and res["binaries"]["nuclei"] is False
    assert preflight.arsenal(_answers(every))["ok"] is True


def test_arsenal_checks_the_ported_hexstrike_tools(monkeypatch):
    reg = SimpleNamespace(
        TOOLS=[
            {"name": "nmap-lite", "binary": "nmap", "ported": True},
            {"name": "not-ported", "binary": "amass", "ported": False},
            {"name": "evil", "binary": "x; rm -rf /", "ported": True},
        ]
    )
    pkg = SimpleNamespace(registry=reg)
    monkeypatch.setitem(sys.modules, "bh.agent.hexstrike", pkg)
    monkeypatch.setitem(sys.modules, "bh.agent.hexstrike.registry", reg)
    every = {b for bins in preflight.BUILTIN_BINARIES.values() for b in bins}
    asked = []

    def answer(binaries):
        asked.extend(binaries)
        return _answers(every)(binaries)

    res = preflight.arsenal(answer)
    assert res["hexstrike"] == {"nmap-lite": False} and res["ok"] is True
    assert "amass" not in asked and not any(";" in b for b in asked)


def test_arsenal_that_cannot_run_removes_nothing(monkeypatch):
    monkeypatch.setattr(preflight, "hexstrike_binaries", lambda: None)

    def down(_b):
        raise OSError("podman missing")

    res = preflight.arsenal(down)
    assert res["missing"] == [] and "podman missing" in res["error"]
    assert preflight.arsenal(lambda b: "+ffuf\n")["error"].startswith("no answer for")
    assert run.missing_tools(res) == [] and run.missing_tools(None) == []


def test_missing_builtins_reach_the_system_prompt(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    pushed = {}

    def fake_prompt(scope, identities, *, missing_tools=()):
        return f"doctrine missing={','.join(missing_tools)}"

    monkeypatch.setattr(run, "build_system_prompt", fake_prompt)
    monkeypatch.setattr(run.stack, "push_file", lambda path, text, **k: None)
    monkeypatch.setattr(run, "push_system_prompt", lambda text: pushed.setdefault("system", text))
    monkeypatch.setattr(preflight, "arsenal", lambda _exec: {"ok": False, "missing": ["bh-scan"], "error": None})
    from bh import assets

    board = Board(tmp_path / "b.sqlite")
    assets.ensure(board)
    scope_file = tmp_path / "p.yaml"
    scope_file.write_text("program: p\n")
    checked = run.prepare_workdir(board, _scope(), scope_file, [])
    assert checked["missing"] == ["bh-scan"] and pushed["system"] == "doctrine missing=bh-scan"
    assert run.system_prompt_for(_scope(), [], ["bh-scan"]) == pushed["system"]
    pushed.clear()
    assert run.prepare_workdir(board, _scope(), scope_file, [], missing=[]) is None  # a rotation: no new check
    assert pushed["system"] == "doctrine missing="


def test_preview_reuses_the_last_arsenal_check(tmp_path):
    board = Board(tmp_path / "b.sqlite")
    identity.ensure(board)
    assert run.last_missing(board, "p") == []
    rid = board.run_start("p", "sonnet")
    board.run_set(rid, preflight=json.dumps({"ok": True, "arsenal": {"missing": ["bh-xss"]}}))
    assert run.last_missing(board, "p") == ["bh-xss"] and run.last_missing(board, "q") == []


# ------------------------------------------------------------------ UI: the tools in progress (read-only)
def test_agent_tools_parses_untrusted_lines():
    out = (
        "12\t95\tffuf\tffuf -u https://a.t/FUZZ -H Authorization: Bearer abc.def\t:: Progress: [10/100]\n"
        "garbage line\n"
        "7\t300\tbash\tbash -c sleep 1\t\n"
    )
    tools = run.stack.agent_tools(sh=lambda *a, **k: subprocess.CompletedProcess([], 0, out, ""))
    assert [t["pid"] for t in tools] == [7, 12]
    assert tools[1]["last"].startswith(":: Progress") and tools[1]["seconds"] == 95


def test_ui_tools_view_needs_auth_and_never_stops_anything(tmp_path, monkeypatch):
    sys.path.insert(0, str(ROOT / "tests"))
    try:
        from test_ui import _get, _serve
    finally:
        sys.path.remove(str(ROOT / "tests"))

    from bh.ui import server

    monkeypatch.setattr(server.stack, "container_running", lambda name: True)
    monkeypatch.setattr(
        server.stack, "agent_tools", lambda: [{"pid": 3, "seconds": 4, "name": "nuclei", "cmd": "c", "last": "l"}]
    )
    srv, cookie = _serve(tmp_path, monkeypatch)
    try:
        assert _get(srv, "/api/agent/tools")[0] == 401
        code, body = _get(srv, "/api/agent/tools", cookie)
        doc = json.loads(body)
        assert code == 200 and doc["running"] and doc["tools"][0]["name"] == "nuclei"
    finally:
        srv.shutdown()
        srv.server_close()
    src = (ROOT / "src" / "bh" / "ui" / "server.py").read_text()
    assert "/api/agent/tools" in src and "kill_agent(" not in src.split('"/api/agent/tools"')[1].split("if path")[0]


def test_a_programs_own_skill_is_linked_only_where_its_scope_names_it():
    """Lab run 72 (2026-11-27): the Juice Shop session listed msrc-copilot and msrc-onedrive."""
    from bh.scope import scope_from_dict

    lab = scope_from_dict({"program": "lab", "platform": "local", "in_scope": ["a.test"]})
    cop = scope_from_dict(
        {"program": "c", "platform": "local", "in_scope": ["b.test"], "cards": ["msrc-copilot", "bh-web-manual"]}
    )
    if run.allowed_skills(lab) is None:
        pytest.skip("skills off")
    assert not [n for n in run.allowed_skills(lab) if n.startswith("msrc-")]
    mine = [n for n in run.allowed_skills(cop) if n.startswith("msrc-")]
    assert mine == ["msrc-copilot"]
