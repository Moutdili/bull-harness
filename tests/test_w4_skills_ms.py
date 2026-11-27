"""Wave W4, lot G: the four AI and Microsoft skills (S6) and the program skills of step 2 (D32, part).

Form (the one of W3, read by classes.all_skills without a list), commands that exist, free roles, payload host, no
scanner, no bounty figure, no Strix tool we lack, what was purged from Strix, attribution, and the rule that a skill
names no host and no route that a survey under docs/research/ does not hold. Text checks only: no network, no podman.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from bh import classes
from bh.agent import contract

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "src" / "bh" / "skills"
AGENT = ROOT / "src" / "bh" / "agent"
RESEARCH = ROOT / "docs" / "research"
NOTICES = ROOT / "THIRD_PARTY_NOTICES.md"

MS_SKILLS = ("agent-actions", "entra", "graph", "power-platform")
FROM_STRIX = {
    "agent-actions": (
        "strix/skills/vulnerabilities/agentic_system_security.md",
        "strix/skills/vulnerabilities/llm_prompt_injection.md",
        "strix/skills/technologies/llm_applications.md",
    ),
    "entra": ("strix/skills/protocols/oauth.md", "strix/skills/cloud/azure.md"),
}
SERVICES_D32 = ("onedrive",)  # services of step 2 with a host survey (brief W4-G); Outlook.com is not surveyed
RUBRICS = ["When", "Do", "Proof", "Never", "False positives", "Watch"]
PAYLOAD_SAID = 'the payload hosts of your scope block; none listed: `bh-note blocked other "no payload host declared"`'
STRIX_ONLY_TOOLS = ("jwt_tool", "ppfuzz", "agent-browser", "web_search", "repeat_request", "wait_for_user", "caido")
NOT_COMMANDS = {"bh-browser", "bh-web-manual"}
# what Strix's sources do that we never do: allowed only in the origin comment (the list of what was removed) and in
# Never (the ban itself)
PURGED = re.compile(
    r"enumerat|brute|bypass|privilege escalation|post-exploitation|managed identit|key vault|service principal"
    r"|device code|password grant|client credentials",
    re.I,
)
_HOST = re.compile(r"(?<![\w.<-])((?:[a-z0-9-]+\.)+(?:com|net|org|microsoft|live|cloud|io|ai|app))(?![\w-])", re.I)


def raw(name: str) -> str:
    return (SKILLS / name / "SKILL.md").read_text()


def split(name: str) -> tuple[dict, list[str]]:
    lines = raw(name).splitlines()
    assert lines[0] == "---", name
    end = lines.index("---", 1)
    meta = yaml.safe_load("\n".join(lines[1:end]))  # real YAML, as Claude Code reads it
    assert isinstance(meta, dict), name
    return meta, lines[end + 1 :]


def comment(name: str) -> str:
    _, body = split(name)
    assert body[0].startswith("<!--"), f"{name}: the origin comment opens right under the frontmatter"
    end = next(i for i, ln in enumerate(body) if ln.rstrip().endswith("-->"))
    return "\n".join(body[: end + 1])


def section(name: str, rubric: str) -> str:
    _, body = split(name)
    out, inside = [], False
    for line in body:
        if line.startswith("## "):
            inside = line[3:] == rubric
            continue
        if inside:
            out.append(line)
    return "\n".join(out)


def flat(text: str) -> str:
    return " ".join(text.split())


def without_comment(name: str) -> str:
    return raw(name).replace(comment(name), "")


def _commands() -> set[str]:
    main = (AGENT / "main.py").read_text()
    names = set(re.findall(r'cmd == "([a-z-]+)"', main))
    for group in re.findall(r"cmd in \(([^)]*)\)", main):
        names |= set(re.findall(r'"([a-z-]+)"', group))
    tools = re.search(r"^TOOLS = \(([^)]*)\)", main, re.M)
    assert tools, "main.py: TOOLS"
    names |= set(re.findall(r'"([a-z-]+)"', tools.group(1)))
    names.discard("TOOLS")
    return {n if n in ("q", "qq") else f"bh-{n}" for n in names} | {"bh-agent"}


def _survey() -> str:
    return "\n".join(p.read_text() for p in sorted(RESEARCH.glob("*.md")))


# ------------------------------------------------------------------ form
def test_the_four_skills_are_there_and_listed():
    listed = {s["name"]: s for s in classes.all_skills()}
    for name in MS_SKILLS:
        assert (SKILLS / name / "SKILL.md").is_file(), name
        assert name in listed and listed[name]["requires"] is None, name


@pytest.mark.parametrize("name", MS_SKILLS + tuple(f"msrc-{s}" for s in SERVICES_D32))
def test_form(name):
    meta, body = split(name)
    assert meta.get("name") == name and set(meta) <= {"name", "description", "requires"}
    desc = meta["description"]
    assert isinstance(desc, str) and desc.startswith("Use when") and len(desc) <= classes.DESCRIPTION_MAX, desc
    assert len(body) <= 150, len(body)
    assert re.findall(r"^## (.+)$", "\n".join(body), re.M) == RUBRICS
    for rubric in RUBRICS:
        assert section(name, rubric).strip(), rubric
    assert re.search(r"^\d+\. ", section(name, "Do"), re.M), "Do has numbered steps"
    comment(name)


@pytest.mark.parametrize("name", MS_SKILLS)
def test_origin_comment(name):
    head = comment(name)
    assert "Source:" in head and "Modified" in head, name
    if name in FROM_STRIX:
        one = flat(head)
        for origin in FROM_STRIX[name]:
            assert origin in one, origin
            assert (ROOT.parent / "strix" / origin).is_file() or not (ROOT.parent / "strix").is_dir(), origin
        assert "Copyright 2025 OmniSecure Inc." in one and "Apache License 2.0" in one
        assert "Modified from Strix (Apache-2.0) by bull-harness" in one and "Removed:" in one
    else:
        assert "strix/skills/" not in head or "no text taken" in head, name


# ------------------------------------------------------------------ commands and references
@pytest.mark.parametrize("name", MS_SKILLS)
def test_commands_exist(name):
    text, known = raw(name), _commands()
    for cmd in set(re.findall(r"(?<![\w./-])(bh-[a-z][a-z-]*[a-z])", text)) - NOT_COMMANDS:
        assert cmd in known, f"{name}: {cmd}"
    for span in re.findall(r"`([^`\n]+)`", text):
        for part in re.split(r"\s*(?:;|&&|&|\|)\s*", span):
            word = part.split(" ", 1)[0]
            if word in ("q", "qq") or word.startswith("bh-"):
                assert word in known | NOT_COMMANDS, f"{name}: {word}"
    note_subs = set(re.findall(r'add_parser\("([a-z-]+)"', (AGENT / "note.py").read_text()))
    web_doc = (AGENT / "web.py").read_text().split('"""', 2)[1]
    web_subs = set(re.findall(r"^\s+bh-web ([a-z-]+)", web_doc, re.M))
    for sub in re.findall(r"bh-note ([a-z-]+)", text):
        assert sub in note_subs, f"bh-note {sub}"
    for reasons in re.findall(r"bh-note blocked ([a-z|-]+)", text):
        for reason in reasons.split("|"):
            assert reason in contract.BLOCKER_REASONS, reason
    for sub in re.findall(r"bh-web ([a-z-]+)", text):
        assert sub in web_subs, f"bh-web {sub}"
    for kind in re.findall(r"-k ([a-z-]+)", text):
        assert kind in contract.FACT_KINDS, kind
    for why in re.findall(r"--why ([a-z]+)", text):
        assert why in contract.DEAD_END_WHY, why
    for cls in re.findall(r"--class ([a-z-]+)", text):
        assert cls in classes.BY_ID, cls


@pytest.mark.parametrize("name", MS_SKILLS + tuple(f"msrc-{s}" for s in SERVICES_D32))
def test_every_skill_named_exists(name):
    text = raw(name)
    refs = set(re.findall(r"\bskills? `([a-z0-9-]+)`", text)) | set(re.findall(r"the `([a-z0-9-]+)` skill", text))
    for m in re.finditer(r"\bskills ((?:`?[a-z0-9-]+`?(?:, | and )?)+)\(ours\)", flat(comment(name))):
        refs |= set(re.findall(r"[a-z0-9]+(?:-[a-z0-9]+)+", m.group(1)))
    for ref in refs:
        assert (SKILLS / ref / "SKILL.md").is_file(), ref


# ------------------------------------------------------------------ rules of every skill
@pytest.mark.parametrize("name", MS_SKILLS)
def test_no_scanner_no_example_domain_no_bounty_no_foreign_tool(name):
    text = raw(name)
    alt = "|".join(re.escape(s) for s in sorted(contract.SCANNERS, key=len, reverse=True))
    hit = re.search(rf"(?<![\w.-])({alt})(?![\w.-])|--write-own\b|--active\b", text, re.I)
    assert not hit, hit.group(0) if hit else ""
    assert classes.SCANNER_WORDS.search(text) is None
    assert "example.org" not in text and "example.com" not in text
    money = re.search(r"[$€£]\s?\d|\b\d[\d,.]*\s?(usd|eur|chf|dollars?|euros?)\b|\bbount(y|ies) of\b", text, re.I)
    assert not money, money.group(0) if money else ""
    assert not re.search(r"never stop|try \d+ more|to verify", text, re.I)
    for tool in STRIX_ONLY_TOOLS:
        assert tool not in text, tool


def test_no_skill_is_a_source_of_scope():
    for path in sorted(SKILLS.glob("*/SKILL.md")):
        assert "in scope by default" not in path.read_text().lower(), path.parent.name


@pytest.mark.parametrize("name", MS_SKILLS)
def test_what_strix_does_and_we_never_do_sits_in_never_only(name):
    never = section(name, "Never")
    for line in without_comment(name).splitlines():
        if PURGED.search(line):
            assert line in never, line


@pytest.mark.parametrize("name", MS_SKILLS + tuple(f"msrc-{s}" for s in SERVICES_D32))
def test_free_roles_and_payload_host(name):
    text = raw(name)
    assert not re.search(r"--victim user-[ab]|--attacker user-[ab]|--victim <[AB]>", text)
    if "--victim" in text:
        assert "--victim <identity> --attacker <the other>" in flat(text)
    if "<payload-host>" in text:
        assert flat(text).count(PAYLOAD_SAID) == 1


@pytest.mark.parametrize("name", MS_SKILLS + tuple(f"msrc-{s}" for s in SERVICES_D32))
def test_hosts_and_routes_are_in_a_survey(name):
    """A skill names no host and no route that a survey under docs/research/ does not hold."""
    survey, text = _survey(), without_comment(name)
    for host in set(_HOST.findall(text)):
        assert host in survey, f"{name}: host {host} is in no survey"
    for span in re.findall(r"`([^`\n]+)`", text):
        if span.startswith("/") and not span.startswith("/opt/"):
            assert span in survey, f"{name}: route {span} is in no survey"


# ------------------------------------------------------------------ each skill's own lines
def test_agent_actions():
    text, proof = flat(raw("agent-actions")), flat(section("agent-actions", "Proof"))
    assert "skill `prompt-injection`" in text and "skill `ai-connectors`" in text
    assert "who acts" in text.lower() and "for whom" in text.lower()
    assert "read back over HTTP" in text and "canary on the attacker's side" in text
    assert "Twin control: the same content minus the instruction" in flat(section("agent-actions", "Do"))
    assert "--proof proof.json" in proof and "--observation <canary>" in proof and "--control 0/3" in proof
    assert "write-needed" in section("agent-actions", "Never")


def test_entra_keeps_login_hosts_as_support_hosts():
    never = flat(section("entra", "Never"))
    assert "`login.microsoftonline.com`" in never and "`login.live.com`" in never
    assert "support hosts, never targets" in never
    when = flat(section("entra", "When"))
    assert "target's API" in when and "skill `oauth-oidc`" in when
    do = flat(section("entra", "Do"))
    assert "The other account's token" in do and "never type, copy or decode one" in do


def test_graph_only_when_the_scope_lists_it_and_ids_from_own_answers():
    when, do = flat(section("graph", "When")), flat(section("graph", "Do"))
    assert "Your scope block lists a host" in when and "the scope, not this skill" in when
    assert "Ids come only from the victim's own answers" in do
    assert "Never a guessed, incremented or listed id" in do
    survey = _survey()
    for route in re.findall(r"`(/v1\.0/[^`]+)`", raw("graph")):
        assert route in survey, route


def test_power_platform_is_dormant():
    when = flat(section("power-platform", "When"))
    assert "not applicable on personal accounts" in when
    assert "two identities of ours sit in one tenant of ours" in when
    assert not _HOST.search(without_comment("power-platform")), "a host named while no survey names one"
    assert "Dormant" in raw("power-platform").split("---", 2)[1]


# ------------------------------------------------------------------ D32 (part): program skills of step 2
@pytest.mark.parametrize("service", SERVICES_D32)
def test_program_skill_of_each_surveyed_service(service):
    name = f"msrc-{service}"
    scope = yaml.safe_load((ROOT / "scopes" / "msrc" / f"{service}.yaml").read_text())
    text = raw(name)
    for entry in scope["in_scope"]:
        host = re.sub(r"^https?://", "", entry["value"]).split("/", 1)[0]
        assert host in text, f"{name} does not name the scope's host {host}"
    never = flat(section(name, "Never"))
    assert "recipient not ours" in never and "enumerate ids" in never
    assert "home.microsoftpersonalcontent.com" in never  # surveyed, left out of the scope on purpose
    assert "| 1 |" in section(name, "Do") and "| 7 |" in section(name, "Do")


def test_no_outlook_skill():
    assert not (SKILLS / "msrc-outlook").exists()


# ------------------------------------------------------------------ THIRD_PARTY_NOTICES
def test_notices_rows_for_the_strix_skills_and_every_path_exists():
    text = NOTICES.read_text()
    strix = text.split("## Strix", 1)[1].split("\n## ", 1)[0]
    rows = [ln for ln in strix.splitlines() if ln.startswith("| `src/bh/skills/")]
    for name, origins in FROM_STRIX.items():
        row = next((r for r in rows if r.startswith(f"| `src/bh/skills/{name}/SKILL.md`")), None)
        assert row, name
        for origin in origins:
            assert f"`{origin}`" in row, origin
        assert "Removed:" in row
    for name in ("graph", "power-platform"):
        assert not any(r.startswith(f"| `src/bh/skills/{name}/") for r in rows), name
    for path in re.findall(r"^\| `((?:src|\.claude)/[^`]+)`", text, re.M):
        assert (ROOT / path).exists(), path
