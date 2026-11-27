"""W3-G: the doctrine of tools and docs. Skills and the sandbox's MCP servers named in two lines (I8 kept), the shell
quoting line (T40), the narrowing line (T35), the Arsenal without the builtins the sandbox lacks, the judge's
false-positive lines (S2), and the docs that describe MCP, hooks and modules as they are (L9).
No podman, no Claude, no network."""

import importlib
import re
import sys
import types
from pathlib import Path

import pytest

from bh.agent import contract as c
from bh.gate import policy
from bh.runner import prompt
from bh.runner.prompt import OPENINGS, VERIFIER_DOCTRINE, build_system_prompt, build_verifier_prompt, doctrine
from bh.scope import scope_from_dict

ROOT = Path(__file__).resolve().parents[1]
ALL_OPENINGS = sorted(OPENINGS)
# the contract of wave W3: the tool names of the two sandbox servers
MCP_TOOLS = {
    *(
        f"mcp__bh__{t}"
        for t in (
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
        )
    ),
    *(f"mcp__hexstrike__{t}" for t in ("tools_list", "tool_help", "tool_run")),
}


@pytest.fixture(autouse=True)
def recall_shipped(monkeypatch):
    monkeypatch.delenv("BH_DOCTRINE_OPENING", raising=False)
    monkeypatch.setattr(policy, "ID_LIMIT", 6)
    monkeypatch.setattr(policy, "ID_WINDOW_S", 600)
    try:
        importlib.import_module("bh.agent.recall")
    except ImportError:
        monkeypatch.setitem(sys.modules, "bh.agent.recall", types.ModuleType("bh.agent.recall"))


def _scope(scanners: bool = True, **kw):
    return scope_from_dict(
        {"program": "p", "platform": "x", "in_scope": ["app.t.test"], "scanners_allowed": scanners, **kw}
    )


def _arsenal(doc: str) -> str:
    return doc.split("## Arsenal", 1)[1].split("\nHand-made requests:", 1)[0]


def _forbidden_tool_named(text: str) -> bool:
    return bool(
        c._SCANNER_WORDS.search(text)
        or c._SCANNER_EXTRA.search(text)
        or c._ZAP_ACTIVE.search(text)
        or c._AUTHZ_WRITE.search(text)
    )


# ------------------------------------------------------------------ skills and MCP: two lines, both variants
@pytest.mark.parametrize("opening", ALL_OPENINGS)
@pytest.mark.parametrize("scanners", [True, False])
def test_skills_and_mcp_are_two_lines_of_the_arsenal(scanners, opening):
    doc = doctrine(scanners, opening)
    lines = [ln for ln in doc.splitlines() if "skill" in ln.lower() or "mcp__" in ln]
    assert len(lines) == 2, lines
    assert all(ln in _arsenal(doc) for ln in lines)
    skills, mcp = lines
    assert "load the matching skill before you test" in skills
    assert "`mcp__bh__*` tools are these same commands" in mcp and "the same refusals" in mcp
    assert "`mcp__hexstrike__tools_list` says what else is installed and allowed on this program" in mcp
    # only names of the W3 contract, and no tool list copied out of the servers
    named = set(re.findall(r"mcp__\w+", doc))
    assert named <= MCP_TOOLS | {"mcp__bh__"}, named
    assert len(named) <= 2


@pytest.mark.parametrize("opening", ALL_OPENINGS)
def test_no_scanner_is_named_without_scanners(opening):
    """I8 with the new lines, for every opening, in the doctrine and in the full system prompt."""
    assert not _forbidden_tool_named(doctrine(False, opening))
    assert not _forbidden_tool_named(build_system_prompt(_scope(False)))
    assert not _forbidden_tool_named(prompt._SKILLS_MCP + prompt._REQUESTS + prompt._METHOD_LIGHT)


def test_no_insistence_and_no_closing_order_in_the_new_lines():
    new = [*prompt._SKILLS_MCP.splitlines(), _T40, _T35]
    for ln in new:
        assert not re.search(r"\b[A-Z]{3,}\b", ln.replace("MCP", "")), ln  # no capitals of insistence
        assert not re.search(r"(?i)\b(stop|finish|end the|summary)\b", ln), ln


# ------------------------------------------------------------------ T40 and T35
_T40 = (
    "  A body holding `$`, backquotes, double quotes or `!` goes between single quotes (or `curl -d @file`): else the "
    "shell changes it first."
)
_T35 = (
    "- An abnormal answer: first one variant that keeps the syntax, then two close controls at most, before you widen."
)


@pytest.mark.parametrize("scanners", [True, False])
def test_t40_quoting_line_sits_under_q(scanners):
    lines = doctrine(scanners).splitlines()
    i = lines.index(_T40)
    assert lines[i - 2].startswith("- `q [-a <identity>]") and lines[i + 1].startswith("- `qq ")


@pytest.mark.parametrize("scanners", [True, False])
def test_t35_narrowing_line_in_the_method(scanners):
    doc = doctrine(scanners)
    method = doc.split("## Method", 1)[1].split("\n## ", 1)[0]
    assert method.count(_T35) == 1 and doc.count(_T35) == 1


# ------------------------------------------------------------------ the honest Arsenal
def test_no_missing_tool_changes_nothing():
    for scanners in (True, False):
        s = _scope(scanners)
        assert (
            build_system_prompt(s)
            == build_system_prompt(s, missing_tools=())
            == build_system_prompt(s, missing_tools=["bh-nothing"])
        )


def test_a_missing_builtin_line_is_removed_with_its_continuation():
    full = build_system_prompt(_scope(True))
    out = build_system_prompt(_scope(True), missing_tools=["bh-authz", "bh-zap"])
    assert "bh-authz" not in _arsenal(out) and "bh-zap" not in _arsenal(out)
    assert "With 2+ identities" not in out  # bh-authz's continuation line
    removed = set(full.splitlines()) - set(out.splitlines())
    assert len(removed) == 3 and all(("bh-authz" in ln or "bh-zap" in ln or "2+ identities" in ln) for ln in removed)
    assert out.replace(_arsenal(out), "") == full.replace(_arsenal(full), "")  # nothing outside the Arsenal moves


def test_a_shared_line_keeps_the_other_builtin():
    out = _arsenal(build_system_prompt(_scope(True), missing_tools=["bh-crawl", "zap"]))
    assert "- `bh-recon <domain|url>` subdomains + live probe\n" in out and "bh-crawl" not in out
    assert "bh-zap" not in out  # a bare name is a builtin's name too
    out = _arsenal(build_system_prompt(_scope(True), missing_tools=["bh-recon"]))
    assert "\n- `bh-crawl <url>`   crawl + endpoints quoted in JS\n" in out and "bh-recon" not in out
    out = _arsenal(build_system_prompt(_scope(True), missing_tools=["bh-content", "bh-scan"]))
    assert "bh-content" not in out and "bh-scan" not in out and "- `bh-params <url>`" in out


def test_without_scanners_the_browse_observation_goes_with_bh_browse():
    out = _arsenal(build_system_prompt(_scope(False), missing_tools=["bh-browse"]))
    assert "bh-browse" not in out and "one URL, no `--routes`" not in out
    assert "- `bh-zap <url>" in out and "- `bh-recon <domain|url>`" in out
    assert prompt._SKILLS_MCP.rstrip("\n") in out  # the two harness lines stay


# ------------------------------------------------------------------ the judge (S2)
JUDGE_FAMILIES = {
    "accepted is not needed": "accepts is not one it needs: re-test with it and without",
    "by design": "By design:",
    "single-page app shell": "single-page app's shell",
    "public key": "public by construction",
    "demo data": "Demo or seed data",
    "edge 403": "from the edge (WAF, CDN) is not the application refusing",
    "empty write": "A write answered 200 or 204 proves nothing until the object, read back, shows the change",
    "chain": "A chain with one link nobody ran is a theory",
}
# measured before W3-G: 3556 bytes, 38 lines; W3-G adds 8 lines, 900 bytes, no more
JUDGE_SIZE = (3556 + 900, 38 + 8)


@pytest.mark.parametrize("family", list(JUDGE_FAMILIES))
def test_each_false_positive_family_has_its_line(family):
    lines = [ln for ln in VERIFIER_DOCTRINE.splitlines() if JUDGE_FAMILIES[family] in ln]
    assert len(lines) == 1 and lines[0].startswith("- ")


def test_judge_doctrine_size_is_raised_by_the_eight_lines_only():
    size, lines = len(VERIFIER_DOCTRINE.encode()), len(VERIFIER_DOCTRINE.splitlines())
    assert size <= JUDGE_SIZE[0] and lines <= JUDGE_SIZE[1], (size, lines)


def test_judge_gets_no_skill_and_no_tool():
    p = build_verifier_prompt(_scope(True), {"id": 1, "title": "t", "proof": "{}"}, {}, "e")
    low = p.lower()
    assert "mcp__" not in p and "skill" not in low and "hexstrike" not in low


# ------------------------------------------------------------------ L9: the docs say what the code does
def test_no_doc_says_no_mcp_server_is_loaded():
    texts = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
    stale = re.compile(r"ne chargent aucun serveur MCP|les hooks\s+ne voient que `Bash`")
    hits = [str(p.relative_to(ROOT)) for p in texts if stale.search(" ".join(p.read_text().split()))]
    assert not hits, hits


def test_architecture_describes_the_two_servers_and_the_hooks():
    arch = " ".join((ROOT / "docs" / "architecture.md").read_text().split())
    for needle in (
        "`bh-agent mcp bh`",
        "`bh-agent mcp hexstrike`",
        "Le juge n'en charge aucun",
        "20 outils MCP au plus",
        "pour `Bash` et pour `mcp__.*`",
        "`mcp_servers` (serveur MCP distant)",
    ):
        assert needle in arch, needle
    hooks = (ROOT / "container" / "agent" / "hooks" / "settings.json").read_text()
    assert '"matcher": "Bash"' in hooks and '"matcher": "mcp__.*"' in hooks  # what the doc says is registered


_README_PATH = re.compile(r"`((?:src|tests|container|scopes|docs)/[\w./-]*)`|\]\(((?:docs|src)/[\w./-]+)\)")


def test_every_path_the_readme_names_exists():
    """A path of another W3 lot is allowed only on a line that says W3 (the merge removes the mark)."""
    missing = []
    for line in (ROOT / "README.md").read_text().splitlines():
        for m in _README_PATH.finditer(line):
            rel = m.group(1) or m.group(2)
            if not (ROOT / rel).exists() and "(W3)" not in line:
                missing.append(rel)
    assert not missing, missing


def test_readme_layout_lists_the_new_modules_and_the_test_commands():
    text = (ROOT / "README.md").read_text()
    rows = [ln for ln in text.splitlines() if ln.startswith("| `src/")]
    for path in ("src/bh/skills/", "src/bh/agent/mcp/", "src/bh/agent/hexstrike/", "src/bh/lineage/"):
        assert any(r.startswith(f"| `{path}`") for r in rows), path
    assert "uv run pytest" in text and "uvx ruff@0.14.0 check src tests" in text
    assert "tests/escape/escape_check.sh" in text and (ROOT / "tests" / "escape" / "escape_check.sh").exists()


def test_notices_fill_hexstrike_and_strix_and_say_the_modification_rule():
    text = (ROOT / "THIRD_PARTY_NOTICES.md").read_text()
    hexstrike = text.split("## HexStrike AI", 1)[1].split("\n## ", 1)[0]
    assert "`src/bh/agent/hexstrike/" in hexstrike and "hexstrike_mcp.py" in hexstrike
    assert "hexstrike_server.py" in hexstrike
    strix = text.split("## Strix", 1)[1].split("\n## ", 1)[0]
    rows = [ln for ln in strix.splitlines() if ln.startswith("| `src/bh/skills/")]
    assert len(rows) >= 13 and all("`strix/skills/" in r for r in rows)
    assert "carries a prominent line saying that we modified it" in text
