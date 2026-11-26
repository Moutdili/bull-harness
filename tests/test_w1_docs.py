"""Wave W1, lot H: host docs and skills say what the code does. Text checks only: no podman, no network.

The skills of .claude/skills/ serve the operator, the orchestrator and the harness developer, never the hunter (the
folder is not mounted in the sandbox). A stale gesture there would still end up in a `--task` written from it.
"""

import re
from pathlib import Path

import pytest

from bh.agent import contract as c
from bh.gate import policy as pol

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / ".claude" / "skills"

# ------------------------------------------------------------------ R10: canary, stop gestures, bh-web, account names
R10_FILES = [
    ".claude/skills/msrc-ai-bug-bounty/SKILL.md",
    ".claude/skills/ai-red-team-pyrit/SKILL.md",
    ".claude/skills/msrc-copilot-studio-research/SKILL.md",
    "docs/research/15-msrc-premier-programme.md",
]
R10_STALE = ("BH-CANARY", "blocked other", "chemin HTTP, le préférer", "MSOBB")


@pytest.mark.parametrize("rel", R10_FILES)
def test_r10_no_stale_gesture(rel):
    text = (ROOT / rel).read_text()
    found = [s for s in R10_STALE if s in text]
    assert not found, f"{rel} still says {found}"
    for reason in re.findall(r"bh-note blocked ([a-z-]+)", text):
        assert reason in c.BLOCKER_REASONS, f"{rel}: `bh-note blocked {reason}` is no blocker reason"


@pytest.mark.parametrize("rel", R10_FILES[:3])
def test_r10_skills_name_the_real_canary(rel):
    text = (ROOT / rel).read_text()
    assert "BH-SECRET-<16 hex>" in text and "bh-note canary" in text
    assert c.CANARY_RE.pattern == r"BH-SECRET-[0-9a-f]{16}"  # the form the docs spell out


@pytest.mark.parametrize("rel", R10_FILES[1:])
def test_r10_stop_gestures_are_the_two_that_stop(rel):
    text = (ROOT / rel).read_text()
    for reason in sorted(c.STOP_REASONS):
        assert f'bh-note blocked {reason} "<where, no content>"' in text, f"{rel}: no {reason} gesture"


# ------------------------------------------------------------------ L6, D26: enumeration guard (green after lot D)
def test_enumeration_guard_docs_match_policy():
    limit, minutes = pol.ID_LIMIT, int(pol.ID_WINDOW_S) // 60
    line = next(ln for ln in (ROOT / "README.md").read_text().splitlines() if "Enumeration is capped" in ln)
    assert f"more than {limit} distinct ids" in line and f"{minutes} min" in line, line
    assert "query string" not in line and "id parameter" not in line  # path ids only since I6
    arch = " ".join((ROOT / "docs" / "architecture.md").read_text().split())
    assert f"au plus {limit} ids distincts par route en {minutes} min (le {limit + 1}e est refusé" in arch


# ------------------------------------------------------------------ L7: third-party notices
NOTICE_SECTIONS = (
    "## PentAGI",
    "## HexStrike AI",
    "## PentestGPT",
    "## Strix",
    "## Hermes Agent",
    "## obra/superpowers",
    "## gsd-build/get-shit-done",
    "## Not copied",
)


def test_third_party_notices_name_the_six_projects():
    text = (ROOT / "THIRD_PARTY_NOTICES.md").read_text()
    for name in ("PentAGI", "HexStrike", "PentestGPT", "Strix", "CAI", "Shannon"):
        assert name in text, name
    lines = text.splitlines()
    for title in NOTICE_SECTIONS:
        assert title in lines, title
    not_copied = (
        "Rien n'est copié de CAI (licence de recherche non commerciale) ni de Shannon (AGPL-3.0) : idées seulement."
    )
    assert not_copied in text


# ------------------------------------------------------------------ S1: 14 host skills
HOST_SKILLS = (
    "report-writing",
    "pre-submit-review",
    "swarm-handoff",
    "subagent-review-gates",
    "multi-angle-review",
    "program-triage",
    "third-party-repo-vetting",
    "vision-sessions",
    "systematic-debugging",
    "compose-podman-parity",
    "podman-disk-reclaim",
    "claude-p-headless",
    "token-cost-of-commands",
    "cvss-from-evidence",
)
SECRET_PATTERNS = re.compile(
    r"sk-ant-[\w-]{8,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY|"
    r"eyJ[\w-]{10,}\.[\w-]{10,}\.|xox[abp]-[\w-]{10,}|[\w.+-]+@[\w-]+(\.[\w-]+)*\.[a-z]{2,}"
)


def _cli_commands() -> set[str]:
    return set(re.findall(r'\bsub\.add_parser\(\s*"([a-z][a-z-]*)"', (ROOT / "src" / "bh" / "cli.py").read_text()))


@pytest.mark.parametrize("name", HOST_SKILLS)
def test_host_skill_is_there_and_reads(name):
    text = (SKILLS / name / "SKILL.md").read_text()
    m = re.match(r"---\n(.*?)\n---\n", text, re.S)
    assert m, f"{name}: no frontmatter"
    # one `key: value` per line, split on the first ": " (a description may hold ": ", which strict YAML refuses,
    # as in ai-red-team-pyrit and claude-p-headless: the frontmatter is kept as written)
    front = dict(ln.split(": ", 1) for ln in m.group(1).splitlines())
    assert set(front) == {"name", "description"}, front.keys()
    assert front["name"] == name and front["description"].strip()
    for key in ("Source:", "Modified:", "Role:"):
        assert re.search(rf"^{key} \S", text, re.M), f"{name}: no {key} line"


@pytest.mark.parametrize("name", HOST_SKILLS)
def test_host_skill_cites_only_real_bh_commands(name):
    cmds = _cli_commands()
    assert {"finding", "verify", "scope", "prune", "todo"} <= cmds  # the parser read is the real one
    for line in (SKILLS / name / "SKILL.md").read_text().splitlines():
        for sub in re.findall(r"(?<![\w/-])bh ([a-z][a-z-]*)", line):
            assert sub in cmds or "planned" in line, f"{name}: `bh {sub}` is no command: {line}"


@pytest.mark.parametrize("name", HOST_SKILLS)
def test_host_skill_holds_no_secret(name):
    m = SECRET_PATTERNS.search((SKILLS / name / "SKILL.md").read_text())
    assert m is None, f"{name}: {m.group(0)[:12]}..."


def test_the_two_corrections_of_the_host_skills():
    pre = (SKILLS / "pre-submit-review" / "SKILL.md").read_text()
    assert "planned: `bh outcome`" in pre and "bh finding outcome" not in pre and "item L4" not in pre
    swarm = (SKILLS / "swarm-handoff" / "SKILL.md").read_text()
    assert "More than eight lots in one wave, or any wave without an ownership matrix and a merge order" in swarm
    assert "about five lots" not in swarm


def test_the_sandbox_never_mounts_the_host_skills():
    assert not re.search(r"\.claude\b", (ROOT / "container" / "compose.yaml").read_text())


# ------------------------------------------------------------------ R39 (part) and the minor updates
def test_doc18_describes_the_spectator_screen():
    text = (ROOT / "docs" / "research" / "18-navigateur-persistant-captcha-humain.md").read_text()
    assert "human_watching" in text


def test_diagrams_say_they_are_outdated():
    first = (ROOT / "docs" / "diagrams.md").read_text().splitlines()[0]
    assert first == "Outdated since 2026-11-26: see docs/architecture.md; redrawn in wave W4."


def test_todo_points_to_the_plan():
    assert "roadmap-v4" in (ROOT / "docs" / "TODO.md").read_text().splitlines()[0]
