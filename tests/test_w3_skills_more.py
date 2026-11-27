"""W3-H: the skills of new classes, the repatriated skills and their proof standards (src/bh/skills/).

Form of every skill (frontmatter, length, sections, origin comment), the commands it cites, I8 (no scanner named),
no example domain and no bounty figure; the five corrections of the repatriated skills; the guard of each class
adapted from Strix; classes_more.json; the fate of every Strix tool (THIRD_PARTY_NOTICES, lot G).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from bh import classes
from bh.agent import contract

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "src" / "bh" / "skills"
AGENT = ROOT / "src" / "bh" / "agent"
AUDIT = ROOT.parent / "inputs" / "skills-audit" / "skills"
STRIX_TOOLS = ROOT.parent / "strix" / "strix" / "tools"

REPATRIATED = (
    "proof-package",
    "false-positive-traps",
    "csrf",
    "type-confusion",
    "nosql-injection",
    "xxe",
    "web-cache",
    "saml",
    "websocket-origin",
    "graphql-schema-from-errors",
    "supabase",
    "wordpress-rest",
    "api-surface-mapping",
)
FROM_STRIX = (
    "race-condition",
    "mass-assignment",
    "jwt",
    "oauth-oidc",
    "request-smuggling",
    "prototype-pollution",
    "ssti",
    "subdomain-takeover",
    "postmessage",
    "function-level-authz",
    "nextjs",
    "firebase",
    "auth0",
)
WRITTEN = ("multi-tenant",)
OWNED = REPATRIATED + FROM_STRIX + WRITTEN
SECTIONS = ("When", "Do", "Proof", "Never", "False positives", "Watch")
STRIX_FP_MERGED = ("csrf", "nosql-injection", "xxe", "supabase")  # S2 point 5
PAYLOAD_HOST_FIXED = ("csrf", "websocket-origin", "web-cache")  # S2 point 1
NO_PAYLOAD_HOST = 'bh-note blocked other "no payload host declared"'
# names a skill cites that are not commands: the persistent browser service, a card of lot C
NOT_COMMANDS = {"bh-browser", "bh-web-manual"}
# tools of Strix we do not have (S2/T41: "tout appel à un outil que nous n'avons pas")
STRIX_ONLY_TOOLS = ("jwt_tool", "ppfuzz", "agent-browser", "web_search", "repeat_request", "wait_for_user", "caido")

# D21: the fate of each tool (or tool folder) of strix/strix/tools/, for THIRD_PARTY_NOTICES.md (lot G)
STRIX_TOOLS_FATE = {
    "agent_browser": "déjà couvert par le builtin `bh-browse` (et `bh-web` pour le navigateur persistant)",
    "agents_graph": "rejeté : un chasseur par segment, sans graphe de sous-agents qui se délèguent la chasse",
    "apply_patch": "déjà couvert par le builtin `Edit` (Claude Code)",
    "coverage": "déjà couvert par le builtin `bh-note cover`",
    "finish": "déjà couvert par le builtin `bh-note handoff` (le runner clôt le segment)",
    "load_skill": "déjà couvert par le builtin `Skill` (Claude Code)",
    "mcp": "rejeté : le chasseur n'ajoute aucun serveur MCP ; bh.agent.mcp_policy refuse tout outil inconnu",
    "notes": "déjà couvert par le builtin `bh-note fact`",
    "proxy": "déjà couvert par le builtin `bh-replay` (le gate journalise chaque requête ; `q` la rejoue)",
    "reporting": "déjà couvert par le builtin `bh-note finding`",
    "shell": "déjà couvert par le builtin `Bash` (Claude Code)",
    "test_objects": "déjà couvert par le builtin `bh-note canary` (nos objets portent un marqueur)",
    "thinking": "déjà couvert par le builtin `bh-note think`",
    "threat_model": "déjà couvert par le builtin `bh-note threat-model`",
    "todo": "déjà couvert par le builtin `bh-note intent`",
    "view_image": "déjà couvert par le builtin `Read` (Claude Code lit les images)",
    "wait_for_user": "rejeté : le chasseur n'attend l'opérateur que pour un challenge, par `bh-web wait-human`",
    "web_search": "rejeté : aucun moteur de recherche tiers ; seuls les hôtes de contract.PASSIVE_HOSTS",
}
_FATE = re.compile(r"^(porté en skill `(?P<skill>[a-z0-9-]+)`|déjà couvert par le builtin `[^`]+`|rejeté : .+)")


def _split(name: str) -> tuple[dict[str, str], list[str]]:
    lines = (SKILLS / name / "SKILL.md").read_text().splitlines()
    assert lines[0] == "---", name
    end = lines.index("---", 1)
    # real YAML, as Claude Code reads it: an unquoted ": " in a description is invalid there (W3 merge: csrf, xxe)
    meta = yaml.safe_load("\n".join(lines[1:end])) or {}
    assert isinstance(meta, dict), name
    return {k: str(v) for k, v in meta.items()}, lines[end + 1 :]


def _text(name: str) -> str:
    return (SKILLS / name / "SKILL.md").read_text()


def _section(name: str, title: str) -> str:
    _, body = _split(name)
    out, inside = [], False
    for line in body:
        if line.startswith("## "):
            inside = line[3:].startswith(title)
            continue
        if inside:
            out.append(line)
    return "\n".join(out)


def _comment(name: str) -> str:
    _, body = _split(name)
    assert body[0] == "<!--", f"{name}: the origin comment must open right under the frontmatter"
    return "\n".join(body[: body.index("-->") + 1])


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


def test_owned_folders_exist():
    for name in OWNED:
        assert (SKILLS / name / "SKILL.md").is_file(), name
    assert len(set(OWNED)) == 27


@pytest.mark.parametrize("name", OWNED)
def test_form(name):
    meta, body = _split(name)
    assert meta.get("name") == name
    assert set(meta) <= {"name", "description", "requires"}
    assert "requires" not in meta, f"{name}: none of these skills needs scanners"
    desc = meta.get("description", "")
    assert desc.startswith("Use when"), name
    assert len(desc) <= 200, (name, len(desc))
    assert len(body) <= 150, (name, len(body))
    headings = [line[3:] for line in body if line.startswith("## ")]
    for title in SECTIONS:
        assert any(h == title or h.startswith((f"{title}:", f"{title} ")) for h in headings), (name, title)
    comment = _comment(name).lower()
    assert "source" in comment and "modified" in comment, name


@pytest.mark.parametrize("name", OWNED)
def test_commands_exist(name):
    text, known = _text(name), _commands()
    for cmd in set(re.findall(r"(?<![\w./-])(bh-[a-z][a-z-]*[a-z])", text)) - NOT_COMMANDS:
        assert cmd in known, f"{name}: {cmd} is not a command of src/bh/agent/main.py"
    for span in re.findall(r"`([^`\n]+)`", text):
        for part in re.split(r"\s*(?:;|&&|&|\|)\s*", span):
            word = part.split(" ", 1)[0]
            if word in ("q", "qq") or word.startswith("bh-"):
                assert word in known | NOT_COMMANDS, f"{name}: {word}"


@pytest.mark.parametrize("name", OWNED)
def test_subcommands_exist(name):
    """`bh-note <sub>` and its blocked reasons, `bh-web <sub>`: the ones the sandbox knows."""
    text = _text(name)
    note_subs = set(re.findall(r'add_parser\("([a-z-]+)"', (AGENT / "note.py").read_text()))
    web_doc = (AGENT / "web.py").read_text().split('"""', 2)[1]
    web_subs = set(re.findall(r"^\s+bh-web ([a-z-]+)", web_doc, re.M))
    for sub in re.findall(r"bh-note ([a-z-]+)", text):
        assert sub in note_subs, f"{name}: bh-note {sub}"
    for reason in re.findall(r"bh-note blocked ([a-z-]+)", text):
        assert reason in contract.BLOCKER_REASONS, f"{name}: blocked {reason}"
    for sub in re.findall(r"bh-web ([a-z-]+)", text):
        assert sub in web_subs, f"{name}: bh-web {sub}"


@pytest.mark.parametrize("name", OWNED)
def test_no_scanner_no_example_domain_no_bounty(name):
    text = _text(name)
    alt = "|".join(re.escape(s) for s in sorted(contract.SCANNERS, key=len, reverse=True))
    hit = re.search(rf"(?<![\w.-])({alt})(?![\w.-])|--write-own\b|--active\b", text, re.I)
    assert not hit, f"{name} names a scanner (I8): {hit.group(0) if hit else ''}"
    assert "example.org" not in text and "example.com" not in text, name
    money = re.search(r"[$€£]\s?\d|\b\d[\d,.]*\s?(usd|eur|chf|dollars?|euros?)\b|\bbounty of\b", text, re.I)
    assert not money, f"{name}: a bounty figure: {money.group(0) if money else ''}"
    assert not re.search(r"never stop|try \d+ more", text, re.I), name
    for tool in STRIX_ONLY_TOOLS:
        assert tool not in text, f"{name}: {tool} is not a tool of ours"
    assert "to verify" not in text, f"{name}: a 'to verify' line left"


# ---------------------------------------------------------------- S2: the thirteen repatriated skills
@pytest.mark.parametrize("name", REPATRIATED)
def test_repatriated_keep_their_origin_lines(name):
    comment = _comment(name)
    assert "Source: hermes/" in comment and "Modified:" in comment and "Role:" in comment, name
    if (AUDIT / name / "SKILL.md").is_file():
        source = (AUDIT / name / "SKILL.md").read_text().splitlines()
        for line in source[4:8]:
            if line.startswith(("Source:", "Modified:", "Role:")):
                assert line in comment.splitlines(), (name, line[:40])
        meta, _ = _split(name)
        assert f"description: {meta['description']}" in source, f"{name}: description rewritten"


@pytest.mark.parametrize("name", PAYLOAD_HOST_FIXED)
def test_payload_host(name):
    text = _text(name)
    assert "<marker>.<payload-host>" in text
    assert "none listed in your scope block" in text and NO_PAYLOAD_HOST in text


def test_api_surface_mapping_challenge():
    step = _section("api-surface-mapping", "Do")
    assert "never work around it" in step
    assert "Without bh-browser on this program: `bh-note blocked captcha" in step
    assert "With\n   bh-browser: `bh-web wait-human`" in step and "bh-web-manual" in step


def test_websocket_origin_keeps_its_ban():
    when = " ".join(_section("websocket-origin", "When").split())
    assert "chat goes through bh-browser" in when and "never open a socket yourself" in when


@pytest.mark.parametrize("name", STRIX_FP_MERGED)
def test_strix_false_positives_merged(name):
    comment = " ".join(_comment(name).split())
    assert "hermes/" in comment and "strix/skills/" in comment and "Apache-2.0" in comment, name
    assert "(Strix)" in _section(name, "False positives"), name


def test_false_positive_traps_sections_kept():
    """Lot G reads the judge's lines from it: the source's sections are all still there, in order."""
    _, body = _split("false-positive-traps")
    titles = [line for line in body if line.startswith("## ")]
    assert titles[:4] == [
        "## When",
        "## Do: five questions",
        "## Six ways a model invents a finding",
        "## False positives by family",
    ]


# ---------------------------------------------------------------- T41, S9, D21
@pytest.mark.parametrize("name", FROM_STRIX)
def test_strix_attribution(name):
    comment = " ".join(_comment(name).split())
    assert "strix/skills/" in comment and "Copyright 2025 OmniSecure Inc." in comment, name
    assert "Apache License 2.0" in comment and "Modified from Strix (Apache-2.0) by bull-harness" in comment, name
    assert "removed" in comment, name


def test_request_smuggling_lab_only():
    never = " ".join(_section("request-smuggling", "Never").split()).lower()
    assert "any request that leaves a prefix queued on a shared connection" in never
    do = [line for line in _section("request-smuggling", "Do").splitlines() if line.strip()]
    assert do[0].startswith("1. ") and 'bh-note blocked other "request smuggling: not allowed by this program"' in do[0]
    assert "`platform: local`" in _section("request-smuggling", "When")


def test_class_guards():
    race = _text("race-condition")
    assert "Two requests, once" in race and "never a burst" in race
    assert all(f in _text("mass-assignment") for f in ("`role`", "`isAdmin`", "`verified`", "`plan`"))
    assert "brute-force a signing secret" in _section("jwt", "Never")
    oauth_fp = _section("oauth-oidc", "False positives")
    assert "public client" in oauth_fp and "`redirect_uri` the server validates on its side" in oauth_fp
    assert "harmless marker" in _text("prototype-pollution") and "runs code" in _section("prototype-pollution", "Never")
    ssti = _text("ssti")
    assert "91829*7" in ssti and 'bh-note blocked server-exec "ssti' in ssti
    assert "claim left to the operator" in _text("subdomain-takeover")
    assert "DOM before" in _text("postmessage") and "DOM after" in _text("postmessage")
    assert "`broken-access-control`" in _text("function-level-authz")


def test_multi_tenant():
    meta, _ = _split("multi-tenant")
    assert meta["description"] == (
        "Use when the product has organisations (tenants, workspaces) and your two identities sit in two of them"
    )
    never = _section("multi-tenant", "Never")
    assert "An organisation that is not ours" in never and "An invitation sent outside our accounts" in never
    assert "the class is `idor`" in _section("multi-tenant", "Watch")
    assert "victim organisation" in _section("multi-tenant", "Do")


# ---------------------------------------------------------------- S4: classes_more.json
NEW_IDS = {
    "csrf",
    "xxe",
    "websocket-origin",
    "type-confusion",
    "web-cache",
    "saml",
    "mass-assignment",
    "jwt",
    "oauth-oidc",
    "request-smuggling",
    "prototype-pollution",
    "ssti",
    "subdomain-takeover",
    "postmessage",
}
COMPLETED = {"nosqli": "nosql-injection", "race-condition": "race-condition"}


def _entries() -> list[dict]:
    return json.loads((SKILLS / "classes_more.json").read_text())


def test_classes_more_shape():
    entries = _entries()
    assert isinstance(entries, list)
    ids = [e["id"] for e in entries]
    assert len(ids) == len(set(ids)), "an id twice"
    assert set(ids) == NEW_IDS | set(COMPLETED)
    for e in entries:
        assert set(e) == {"id", "aliases", "path_signals", "param_signals", "evidence", "skill"}, e["id"]
        assert (SKILLS / e["skill"] / "SKILL.md").is_file() and e["skill"] in OWNED, e["id"]
        assert all(isinstance(a, str) and a == a.lower() for a in e["aliases"]), e["id"]
        for rx in e["path_signals"] + e["param_signals"]:
            re.compile(rx)
        ev = e["evidence"]
        assert "; control: " in ev and ev.endswith("."), e["id"]
        assert ev.index("; control: ") > 20, f"{e['id']}: the attack first, then the twin control"
        assert not re.search(r"[a-z0-9)\]]\. [A-Z]", ev), f"{e['id']}: evidence in one sentence"
    for cid, skill in COMPLETED.items():
        assert next(e for e in entries if e["id"] == cid)["skill"] == skill


def test_completed_classes_exist_and_csrf_alias_spares_logout():
    """nosqli and race-condition complete classes of classes.py; `csrf` never captures "Logout CSRF"."""
    assert set(COMPLETED) <= set(classes.BY_ID)
    csrf = next(e for e in _entries() if e["id"] == "csrf")
    assert "logout-csrf" not in csrf["aliases"] and "csrf-logout" not in csrf["aliases"]
    assert not any("logout" in a for a in csrf["aliases"])
    assert classes.canonical("Logout CSRF") != "csrf"
    assert classes.exclusion("Logout CSRF") != "csrf"


# ---------------------------------------------------------------- D21: every Strix tool has a fate
def test_strix_tools_fate_form():
    for tool, fate in STRIX_TOOLS_FATE.items():
        m = _FATE.match(fate)
        assert m, (tool, fate)
        if m.group("skill"):
            assert m.group("skill") in OWNED, tool
    for rejected in ("web_search", "wait_for_user", "agents_graph", "mcp"):
        assert STRIX_TOOLS_FATE[rejected].startswith("rejeté : ")


@pytest.mark.skipif(not STRIX_TOOLS.is_dir(), reason="../strix is not next to the repository")
def test_strix_tools_all_have_a_fate():
    folders = {p.name for p in STRIX_TOOLS.iterdir() if p.is_dir() and not p.name.startswith(("_", "."))}
    assert folders - set(STRIX_TOOLS_FATE) == set(), "a Strix tool without a fate"
    assert set(STRIX_TOOLS_FATE) - folders == set(), "a fate for a tool Strix does not have"
