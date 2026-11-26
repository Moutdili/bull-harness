"""W1-G: hooks on MCP tools (D23), the exemption of bounded bh-web outputs (R21), the turn budget steps (T7), and the
checks on the source tree (L8, relay betas), the entry point and the image (bh-js, xclip)."""

import json
import os
import re
import time
from pathlib import Path

import pytest

from bh.agent import contract as c
from bh.agent import hooks, mcp_policy

ROOT = Path(__file__).resolve().parents[1]


def _bash(cmd):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}, "session_id": "s"}


def _mcp(name, tool_input=None):
    return {"tool_name": name, "tool_input": tool_input or {}, "session_id": "s"}


def _reason(out):
    return out["hookSpecificOutput"]["permissionDecisionReason"] if out else None


@pytest.fixture
def bh(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_DIR", str(tmp_path))
    monkeypatch.delenv("BH_ROLE", raising=False)
    monkeypatch.delenv("BH_SCANNERS", raising=False)
    monkeypatch.setattr(
        mcp_policy,
        "MCP_TOOLS",
        {
            "mcp__lab__map": "mapper",
            "mcp__lab__fuzz": "scanner",
            "mcp__lab__fetch": "request",
            "mcp__lab__note": "note",
            "mcp__lab__wayback": "passive",
            "mcp__lab__page": "browser",
            "mcp__lab__typo": "not-a-class",
        },
    )
    return tmp_path


# ---------------------------------------------------------------- D23: MCP tools
def test_settings_route_mcp_tools_to_the_same_hooks():
    doc = json.loads((ROOT / "container/agent/hooks/settings.json").read_text())
    for event, cmd in (("PreToolUse", "hook-pre"), ("PostToolUse", "hook-post")):
        entries = {e["matcher"]: e["hooks"] for e in doc["hooks"][event]}
        assert set(entries) == {"Bash", "mcp__.*"}
        assert entries["mcp__.*"] == entries["Bash"] == [{"type": "command", "command": f"/opt/bh/bin/bh-agent {cmd}"}]
        assert re.search(next(m for m in entries if m != "Bash"), "mcp__server__tool")


def test_classify_reads_the_table_and_every_url_of_the_input(bh):
    nested = {"a": ["x https://t.test/a/1 y", {"b": "http://u.test:8080/z?q=1"}], "https://k.test/key": 1}
    klass, urls = mcp_policy.classify("mcp__lab__fetch", nested)
    assert klass == "request"
    assert urls == ["https://t.test/a/1", "http://u.test:8080/z?q=1", "https://k.test/key"]
    assert mcp_policy.classify("mcp__lab__nope", {})[0] == "unknown"
    assert mcp_policy.classify("mcp__lab__typo", {})[0] == "unknown"  # a class outside CLASSES
    assert mcp_policy.classify("Bash", {})[0] == "unknown"
    assert mcp_policy.classify("mcp__lab__map", None) == ("mapper", [])


def test_unknown_mcp_tool_is_refused(bh):
    out = hooks.pre_tool_use(_mcp("mcp__evil__anything", {"url": "https://t.test/"}))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert _reason(out).startswith(f"{c.RULES_MARK} unknown MCP tool")
    assert hooks.pre_tool_use(_mcp("mcp__lab__typo")) is not None


def test_mcp_scanner_refused_without_scanners_and_allowed_with(bh, monkeypatch):
    assert hooks.pre_tool_use(_mcp("mcp__lab__fuzz", {"target": "https://t.test/"})) is None
    monkeypatch.setenv("BH_SCANNERS", "0")
    out = hooks.pre_tool_use(_mcp("mcp__lab__fuzz", {"target": "https://t.test/"}))
    bash = hooks.pre_tool_use(_bash("nuclei -u https://t.test/"))
    assert _reason(out) == _reason(bash) == hooks.SCANNER_DENIAL
    assert hooks.pre_tool_use(_mcp("mcp__lab__map")) is None  # a mapper still runs


def test_mcp_request_is_locked_until_the_crawl_ran(bh, monkeypatch):
    monkeypatch.setenv("BH_SCANNERS", "0")  # the light phases: recon is not required, crawl is
    ev = _mcp("mcp__lab__fetch", {"request": {"url": "http://10.0.0.5:3000/api/Users/1"}})
    out = hooks.pre_tool_use(ev)
    assert _reason(out).startswith(c.LOCK_MARK) and "bh-crawl http://10.0.0.5:3000" in _reason(out)
    assert _reason(out) == hooks.lock_decision("curl -s http://10.0.0.5:3000/api/Users/1")
    assert not c.read_jsonl(bh / c.TOUCHED)
    c.record_phase(bh, "http://10.0.0.5:3000", "crawl", status="ok", count=1, raw="")
    assert hooks.pre_tool_use(ev) is None
    touched = c.read_jsonl(bh / c.TOUCHED)
    assert [(t["origin"], t["key"], t["via"]) for t in touched] == [
        ("http://10.0.0.5:3000", "GET /api/Users/{id}", "mcp")
    ]
    # a passive source is never locked
    assert hooks.pre_tool_use(_mcp("mcp__lab__fetch", {"url": "https://web.archive.org/cdx?url=x"})) is None


def test_the_verifier_gets_no_mcp_tool(bh, monkeypatch):
    monkeypatch.setenv("BH_ROLE", "verifier")
    for name in ("mcp__lab__map", "mcp__lab__note", "mcp__lab__page", "mcp__lab__nope"):
        assert _reason(hooks.pre_tool_use(_mcp(name))).startswith(c.RULES_MARK), name


def test_every_mcp_call_is_logged(bh, monkeypatch):
    monkeypatch.setenv("BH_SCANNERS", "0")
    hooks.pre_tool_use(_mcp("mcp__lab__map", {"u": "https://t.test/x"}))
    hooks.pre_tool_use(_mcp("mcp__lab__fuzz"))
    hooks.pre_tool_use(_mcp("mcp__x__y"))
    log = c.read_jsonl(bh / c.COMMANDS)
    assert [(r["tool"], r["klass"], r["decision"]) for r in log] == [
        ("mcp__lab__map", "mapper", "allow"),
        ("mcp__lab__fuzz", "scanner", "deny"),
        ("mcp__x__y", "unknown", "deny"),
    ]
    assert log[0]["urls"] == ["https://t.test/x"] and all(r["session"] == "s" and "ts" in r for r in log)


def test_an_mcp_hook_failure_refuses(bh, monkeypatch):
    def boom(*_a):
        raise RuntimeError("disk full")

    monkeypatch.setattr(c, "append_jsonl", boom)
    assert _reason(hooks.pre_tool_use(_mcp("mcp__lab__map"))).startswith(c.RULES_MARK)


def test_post_hook_never_rewrites_an_mcp_result(bh):
    big = [{"type": "text", "text": "x" * (hooks.MAX_CHARS + 10)}]
    assert hooks.post_tool_use({"tool_name": "mcp__lab__map", "tool_response": big}) is None
    assert hooks.post_tool_use({"tool_name": "mcp__lab__map", "tool_response": "short"}) is None
    assert hooks.post_tool_use({"tool_name": "mcp__lab__map", "tool_response": "y" * (hooks.MAX_CHARS + 1)}) is None
    rows = c.read_jsonl(bh / "trunc.jsonl")
    assert [r["tool"] for r in rows] == ["mcp__lab__map", "mcp__lab__map"]
    assert rows[1]["chars"] == hooks.MAX_CHARS + 1


def test_the_bash_hook_behaves_as_before(bh, monkeypatch):
    out = hooks.pre_tool_use(_bash("curl -s http://10.0.0.5:3000/api/Users"))
    assert _reason(out).startswith(c.LOCK_MARK)
    assert hooks.pre_tool_use(_bash("bh-crawl http://10.0.0.5:3000")) is None
    assert hooks.pre_tool_use({"tool_name": "Read", "tool_input": {"file_path": "/x"}}) is None
    assert hooks.pre_tool_use(_bash("")) is None
    log = c.read_jsonl(bh / c.COMMANDS)
    assert set(log[0]) == {"ts", "session", "cmd", "decision", "arsenal", "manual"}
    assert [r["decision"] for r in log] == ["deny", "allow"]
    monkeypatch.setenv("BH_SCANNERS", "0")
    assert _reason(hooks.pre_tool_use(_bash("sqlmap -u http://h/?q=1"))) == hooks.SCANNER_DENIAL
    assert hooks.pre_tool_use(_bash("bh-browse http://h/ --xss bhX1")) is None  # one page, one marker


# ---------------------------------------------------------------- bh-js is a mapper (line due to lot B)
def test_bh_js_is_a_mapper_for_the_hooks(bh, monkeypatch):
    mappers = (*c.MAPPERS, "bh-js") if "bh-js" not in c.MAPPERS else c.MAPPERS
    monkeypatch.setattr(c, "MAPPERS", mappers)
    monkeypatch.setattr(c, "_MAPPER_WORDS", c._words(mappers))
    cmd = "bh-js https://t.test/ /work/p/bundles --max 50"
    assert c.runs_mapper(cmd) and not c.runs_scanner(cmd) and not c.uses_manual_http(cmd)
    monkeypatch.setenv("BH_SCANNERS", "0")
    assert hooks.pre_tool_use(_bash(cmd)) is None  # not a scanner, not under the tool lock
    monkeypatch.setenv("BH_ROLE", "verifier")
    assert _reason(hooks.pre_tool_use(_bash(cmd))) == hooks.VERIFIER_DENIAL


# ---------------------------------------------------------------- R21: exempt
@pytest.mark.parametrize(
    "cmd",
    [
        "bh-web text",
        "bh-web frames --last 200",
        "bh-web outline",
        "bh-web outline --root 'main'",
        "bh-web text --clipboard",
        "bh-web net --body 3",
        "bh-web net --body=3",
        "/opt/bh/bin/bh-web text",
        """bh-web text --in 'div:has-text("a > b")'""",
        "bh-web outline 'ul > li'",
        'bh-web text "a | b; c & d (e)"',
        "bh-web text 'costs $5'",
    ],
)
def test_bounded_bh_web_outputs_are_exempt(cmd):
    assert hooks.exempt(cmd), cmd


@pytest.mark.parametrize(
    "cmd",
    [
        "bh-web net",
        "bh-web net --last 5",
        "bh-web text | cat",
        "bh-web outline 'ul' > /tmp/x",
        "bh-web text; cat big.json",
        "bh-web text\ncat big.json",
        "bh-web net --body 3 && cat big.json",
        "cat big.json && bh-web text",
        "bh-web text $(cat x)",
        'bh-web text "$(cat x)"',
        "bh-web text `cat x`",
        "bh-web outline 'unclosed",
        "echo bh-web text",
        "bh-web goto https://t.test/",
    ],
)
def test_anything_else_is_not_exempt(cmd):
    assert not hooks.exempt(cmd), cmd


def test_an_exempt_outline_is_shown_whole(bh):
    text = "\n".join(f"node {i}" for i in range(500))
    ev = {**_bash("bh-web outline 'nav > a'"), "tool_use_id": "t", "tool_response": {"stdout": text, "stderr": ""}}
    assert hooks.post_tool_use(ev) is None
    ev = {**_bash("bh-web outline | head"), "tool_use_id": "t", "tool_response": {"stdout": text, "stderr": ""}}
    assert "lines elided" in hooks.post_tool_use(ev)["hookSpecificOutput"]["updatedToolOutput"]["stdout"]


# ---------------------------------------------------------------- T7: budget steps
def _budget(d: Path, max_turns=100, used=0, ts=None):
    ts = time.time() - 5 if ts is None else ts
    (d / hooks.BUDGET).write_text(json.dumps({"max_turns": max_turns, "used": used, "ts": ts}))
    return ts


def _calls(n):
    for _ in range(n):
        hooks.pre_tool_use(_bash("ls"))


def _post(stdout="ok"):
    return hooks.post_tool_use({**_bash("ls"), "tool_use_id": "t", "tool_response": {"stdout": stdout}})


def _stdout(out):
    return out["hookSpecificOutput"]["updatedToolOutput"]["stdout"] if out else None


def test_each_budget_step_is_said_once(bh):
    _budget(bh, max_turns=100, used=60)
    _calls(9)  # 69 %
    assert _post() is None
    _calls(1)  # 70 %
    out = _stdout(_post("listing"))
    assert out == "listing\n" + hooks.BUDGET_LINE.format(pct=70)
    _calls(1)
    assert _post() is None  # said once
    _calls(14)  # 85 %
    assert _stdout(_post()).endswith(hooks.BUDGET_LINE.format(pct=85))
    _calls(10)  # 95 %
    assert _stdout(_post("")) == hooks.BUDGET_LINE.format(pct=95)
    _calls(20)
    assert _post() is None
    assert json.loads((bh / hooks.BUDGET_SEEN).read_text())["seen"] == [70, 85, 95]


def test_budget_counts_only_the_lines_since_ts(bh):
    _calls(50)  # an earlier segment
    time.sleep(0.01)
    _budget(bh, max_turns=10, used=0, ts=time.time())
    assert _post() is None
    _calls(7)
    assert _stdout(_post()).endswith(hooks.BUDGET_LINE.format(pct=70))
    assert hooks.calls_since(bh / c.COMMANDS, 0) == 57


def test_budget_steps_crossed_at_once_say_the_highest(bh):
    _budget(bh, max_turns=10, used=9)
    _calls(1)
    assert _stdout(_post()).endswith(hooks.BUDGET_LINE.format(pct=95))
    assert _post() is None


def test_a_new_budget_resets_the_steps(bh):
    _budget(bh, max_turns=10, used=7, ts=1.0)
    assert _stdout(_post()).endswith(hooks.BUDGET_LINE.format(pct=70))
    _budget(bh, max_turns=10, used=7, ts=2.0)
    assert _stdout(_post()).endswith(hooks.BUDGET_LINE.format(pct=70))


@pytest.mark.parametrize(
    "content", [None, "", "not json", "[]", '{"max_turns": 0, "used": 9, "ts": 1}', '{"max_turns": "x", "ts": 1}']
)
def test_no_or_bad_budget_says_nothing(bh, content):
    if content is not None:
        (bh / hooks.BUDGET).write_text(content)
    _calls(5)
    assert _post() is None


def test_budget_line_is_the_contract_and_never_asks_to_stop():
    line = hooks.BUDGET_LINE.format(pct=85)
    assert line == (
        "[bh-budget] 85% of the turn budget is used: save your state now with bh-note handoff. "
        "This is not a request to finish."
    )
    low = line.lower()
    assert "wrap up" not in low and "summary" not in low
    # "finish" appears only inside the contract's own negation
    assert low.count("finish") == 1 and "not a request to finish" in low


def test_budget_joins_a_truncated_output(bh):
    _budget(bh, max_turns=10, used=7)
    out = _stdout(_post("\n".join(f"l{i}" for i in range(500))))
    assert "lines elided" in out and out.endswith(hooks.BUDGET_LINE.format(pct=70))


def test_calls_since_reads_across_blocks(tmp_path):
    p = tmp_path / "commands.jsonl"
    c.append_jsonl(p, *({"cmd": "x" * 300} for _ in range(40)))
    lines = p.read_text().splitlines()
    ts = json.loads(lines[0])["ts"]
    assert hooks.calls_since(p, ts, block=97) == 40
    assert hooks.calls_since(p, ts + 3600, block=97) == 0
    assert hooks.calls_since(tmp_path / "missing", 0) == 0


# ---------------------------------------------------------------- L8, relay betas
def test_no_shell_true_or_os_system_in_the_sources():
    bad = []
    for f in (ROOT / "src/bh").rglob("*.py"):
        text = f.read_text()
        bad += [f"{f.relative_to(ROOT)}: {pat}" for pat in ("shell=True", "os.system(") if pat in text]
    assert not bad, bad


def test_relay_betas_never_let_tool_search_through():
    from bh.gate import policy

    bad = [b for b in policy.RELAY_BETAS_DEFAULT if "advanced-tool-use" in b or "tool-search" in b]
    assert not bad, bad


# ---------------------------------------------------------------- entry point and image
def test_bh_js_is_a_command_and_a_link():
    link = ROOT / "container/agent/bin/bh-js"
    assert link.is_symlink() and os.readlink(link) == "bh-agent"
    main = (ROOT / "src/bh/agent/main.py").read_text()
    assert 'cmd == "js"' in main and '"authz", "js"' in main


def test_xclip_is_pinned_in_the_image_and_checked():
    cf = (ROOT / "container/agent/Containerfile").read_text()
    assert re.search(r"^ARG XCLIP_VERSION$", cf, re.M)
    assert '"xclip=${XCLIP_VERSION}"' in cf and "command -v Xvfb x11vnc chromium xclip" in cf
    assert "command -v xclip" in (ROOT / "container/agent/check.sh").read_text()
