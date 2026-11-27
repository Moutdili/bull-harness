"""Wave W4, lot G: the five diagrams of docs/diagrams.md stay true to the repository (L5), and the docs that sum the
blocks of W1 to W3 name what exists. Text checks only: no podman, no network, no mermaid renderer."""

import re
from pathlib import Path

import pytest
import yaml

from bh.board.db import FINDING_STATUS
from bh.gate import policy

ROOT = Path(__file__).resolve().parents[1]
DIAGRAMS = ROOT / "docs" / "diagrams.md"
COMPOSE = ROOT / "container" / "compose.yaml"
# Services the other lots of W4 add to container/compose.yaml (lot A: the out-of-band listener). The orchestrator
# empties this list once W4 is merged: from then on every service drawn must be one of compose.yaml.
W4_PENDING: tuple[str, ...] = ()  # emptied at the W4 merge: `oob` is a compose service now

_PATH = re.compile(r"((?:src/bh|container|tests|docs)/[\w./-]*[\w/])(?::(\d+)(?:-(\d+))?)?")
_LINE_REF = re.compile(r"`:(\d+)(?:-(\d+))?`")
_SERVICE = re.compile(r'\w+\["([a-z][a-z0-9-]*)(?:<br/>| ·| )[^"]*"\]:::ctr')
_STATUS = re.compile(r'\w+\["([a-z-]+)"\]:::status')


def _text() -> str:
    return DIAGRAMS.read_text()


def _blocks() -> list[str]:
    return re.findall(r"^```mermaid\n(.*?)^```$", _text(), re.S | re.M)


def _services() -> set[str]:
    return set(yaml.safe_load(COMPOSE.read_text())["services"])


# ------------------------------------------------------------------ (a) exactly five mermaid blocks
def test_exactly_five_mermaid_blocks():
    text = _text()
    assert text.count("```mermaid") == 5
    assert len(_blocks()) == 5


def test_each_block_has_a_title_and_three_reading_lines_at_most():
    parts = re.split(r"^## ", _text(), flags=re.M)[1:]
    assert len(parts) == 5
    for part in parts:
        title, _, rest = part.partition("\n")
        assert re.match(r"[1-5]\. \S", title), title
        before = rest.split("```mermaid", 1)[0]
        lines = [ln for ln in before.splitlines() if ln.strip()]
        assert 1 <= len(lines) <= 3, (title, lines)
        assert "Sources :" in rest.split("```", 2)[2], f"{title}: no sources under the diagram"


def test_comparison_with_other_tools_is_gone():
    text = _text()
    assert "Comparaison avec les outils étudiés" not in text
    others = ("PentAGI", "ARTEX", "HexStrike AI", "CyberStrikeAI", "Cairn", "sapper", "Claude-BugHunter", "Shannon")
    for other in others:
        assert other not in text, other


def test_titles_are_the_five_of_the_brief():
    titles = re.findall(r"^## (.+)$", _text(), re.M)
    assert titles == [
        "1. Runtime : qui parle à qui",
        "2. Un segment, en séquence",
        "3. Décision du gate pour une requête",
        "4. Cycle de vie d'un finding",
        "5. Lignée et mémoire",
    ]


# ------------------------------------------------------------------ (b) every src/bh path cited exists
def _cited_paths() -> list[tuple[str, int | None, int | None]]:
    out = []
    for m in _PATH.finditer(_text()):
        start = int(m.group(2)) if m.group(2) else None
        end = int(m.group(3)) if m.group(3) else None
        out.append((m.group(1).rstrip("."), start, end))
    return out


def test_every_path_cited_exists():
    cited = _cited_paths()
    assert any(p.startswith("src/bh/") for p, _, _ in cited)
    missing = sorted({p for p, _, _ in cited if not (ROOT / p).exists()})
    assert not missing, missing


def test_every_line_cited_is_inside_its_file():
    """`fichier:ligne` and the `:ligne` that follow it on the same source line point inside the file."""
    bad = []
    for line in _text().splitlines():
        current = None
        for m in re.finditer(rf"{_PATH.pattern}|{_LINE_REF.pattern}", line):
            if m.group(1):
                current = ROOT / m.group(1).rstrip(".")
                nums = [m.group(2), m.group(3)]
            else:
                nums = [m.group(4), m.group(5)]
            if current is None or not current.is_file():
                continue
            size = len(current.read_text().splitlines())
            for n in filter(None, nums):
                if not 1 <= int(n) <= size:
                    bad.append(f"{current.relative_to(ROOT)}:{n} (file has {size} lines)")
    assert not bad, bad


# ------------------------------------------------------------------ (c) every container drawn is a compose service
def test_every_container_drawn_is_a_service():
    drawn = set(_SERVICE.findall(_text()))
    services = _services()
    assert {"gate", "agent", "judge", "login", "browser", "audit", "juiceshop"} <= drawn
    unknown = drawn - services - set(W4_PENDING)
    assert not unknown, unknown
    for name in W4_PENDING:  # a pending service is drawn as W4 and is not in compose.yaml yet (else: empty the list)
        assert name in drawn and name not in services, name
        assert re.search(rf'{name} · [^"]*W4', _text()), f"{name} is not marked W4"


def test_runtime_shows_the_networks_and_what_the_agent_never_sees():
    runtime = _blocks()[0]
    compose = yaml.safe_load(COMPOSE.read_text())
    for net in compose["networks"]:
        assert f"réseau {net}" in runtime or f"{net}," in runtime or f'"{net}"' in runtime, net
    for hidden in ("secrets/", "var/lineage", "var/rules", ".claude/skills", "var/state", "var/board.sqlite"):
        assert hidden in runtime, hidden
    for seen in ("/work = var/work", "src/bh/agent ro", "src/bh/skills ro", "container/agent/hooks ro"):
        assert seen in runtime, seen
    # the agent's only arrows lead to the gate or, inside the sandbox, to bh-browser: never outside
    for m in re.finditer(r"^\s*AGENT -->\|[^|]*\| (\w+)", runtime, re.M):
        assert m.group(1) in ("GATE", "BROWSER"), m.group(0)


# ------------------------------------------------------------------ (d) every finding status cited is a real one
def test_every_status_drawn_is_in_finding_status():
    drawn = _STATUS.findall(_text())
    assert drawn, 'no status node (`["status"]:::status`) in the diagrams'
    assert set(drawn) <= FINDING_STATUS, set(drawn) - FINDING_STATUS
    assert set(drawn) == FINDING_STATUS, FINDING_STATUS - set(drawn)


def test_finding_status_line_cited_is_the_real_one():
    db = (ROOT / "src" / "bh" / "board" / "db.py").read_text().splitlines()
    m = re.search(r"src/bh/board/db\.py:(\d+)-(\d+)", _text())
    assert m, "FINDING_STATUS is cited with its lines"
    start, end = int(m.group(1)), int(m.group(2))
    assert db[start - 1].startswith("FINDING_STATUS = {") and db[end - 1] == "}"


# ------------------------------------------------------------------ the gate diagram follows policy.py
GATE_ORDER = (  # what _classify and classify_request check, in the order of the code
    ("is_system(host)", "API Claude ou adresse du gate"),
    ("self._target(url)", "scope.check"),
    ("self.protected(url)", "URL protégée"),
    ("self.recipient_check(", "recipient_guard"),
    ("if websocket:", "handshake websocket"),
    ('v.klass == "support"', "assets, auth, sso"),
    ("browser_only(self.scope, url)", "browser_only"),
    ("self._waf_cooldown(host, v)", "hôte en pause WAF"),
    ("method not in ALLOWED_METHODS", "méthode permise"),
    ("self._scanning(url)", "25 réponses 404"),
    ("self._enumeration(url", "policy.ID_LIMIT"),
    ("is_passive(host)", "source passive"),
)


def test_gate_diagram_follows_the_order_of_the_policy():
    code = (ROOT / "src" / "bh" / "gate" / "policy.py").read_text()
    body = code[code.index("    def classify_request(") : code.index("    def _docs_request(")]
    gate = _blocks()[2]
    code_pos = [body.index(needle) for needle, _ in GATE_ORDER]
    assert code_pos == sorted(code_pos), "GATE_ORDER no longer follows policy.py"
    drawn_pos = [gate.index(label) for _, label in GATE_ORDER]
    assert drawn_pos == sorted(drawn_pos), "the diagram's order differs from policy.py"
    assert policy.ID_LIMIT == 6 and policy.ID_WINDOW_S == 600 and "en 10 min" in gate
    assert policy.MISS_LIMIT == 25 and policy.MISS_WINDOW_S == 300 and "en 5 min" in gate


def test_w4_things_are_marked_and_dashed():
    lines = _text().splitlines()
    for thing in ("Tailscale Funnel", "double cadrage", "bh outcome", "fiches de technique", "oob"):
        hits = [ln for ln in lines if thing in ln]
        assert hits, thing
        assert all("W4" in ln for ln in hits), [ln for ln in hits if "W4" not in ln]
    assert _text().count("stroke-dasharray") >= 3


# ------------------------------------------------------------------ architecture, README, TODO
ARCH_SECTIONS = {
    "Auto-test du gate": "src/bh/runner/preflight.py",
    "URL protégées": "src/bh/gate/policy.py",
    "Garde de destinataires": "src/bh/gate/recipients.py",
    "Hôtes de charge": "src/bh/gate/policy.py",
    "Règles du programme": "src/bh/rules.py",
    "Sessions et plafonds": "src/bh/runner/supervisor.py",
    "Lignée et mémoire": "src/bh/lineage/",
    "Skills et MCP": "src/bh/skills/",
}


@pytest.mark.parametrize("title", sorted(ARCH_SECTIONS))
def test_architecture_has_a_short_section_per_block(title):
    arch = (ROOT / "docs" / "architecture.md").read_text()
    m = re.search(rf"^### {re.escape(title)}\b.*?\n(.*?)(?=^#{{2,3}} |\Z)", arch, re.S | re.M)
    assert m, title
    body = [ln for ln in m.group(1).splitlines() if ln.strip()]
    assert 1 <= len(body) <= 15, (title, len(body))
    assert ARCH_SECTIONS[title] in m.group(1), title
    for path in re.findall(r"`((?:src|container|scopes|docs|tests)/[\w./-]*)`", m.group(1)):
        assert (ROOT / path.rstrip(".")).exists() or "W4" in m.group(1), path


def test_readme_programs_are_the_msrc_scope_files():
    readme = (ROOT / "README.md").read_text()
    for f in sorted((ROOT / "scopes" / "msrc").glob("*.yaml")):
        assert f"scopes/msrc/{f.name}" in readme, f.name
    line = next(ln for ln in readme.splitlines() if "Enumeration is capped" in ln)
    assert "`policy.ID_LIMIT`" in line


def test_readme_layout_names_the_modules_of_src():
    readme = (ROOT / "README.md").read_text()
    rows = "\n".join(ln for ln in readme.splitlines() if ln.startswith("| `"))
    for mod in ("rules.py", "stats.py", "retention.py", "accounts/", "browser_service/", "lineage/", "verify.py"):
        assert mod in rows, mod


def test_todo_head_points_to_plan_and_merged_waves():
    head = (ROOT / "docs" / "TODO.md").read_text().splitlines()[0]
    assert "roadmap-v4" in head and "v4.2" in head
    for wave in ("W1", "W2", "W3"):
        assert wave in head, wave
