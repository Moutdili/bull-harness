"""Hashed identity of a run (T10): what made the segment what it is, in one condensate.

`setup()` gathers every knob that shapes a segment (model, effort, judge, budget, rendered system prompt, task
template, loaded cards, scope digest, rate, identity names and roles, Claude Code version of the image, daily caps,
fill and prompt budgets, BH_PREFLIGHT) into a canonical JSON document (sorted keys, no whitespace) and its sha256.
Wave W2 (D9) adds what makes an agent relaunchable as it was: the hook layer (`hooks_sha256`: the agent's
hooks/settings.json and bh.agent.mcp_policy), the gate policy (`policy_sha256`), the doctrine opening, the naming
rule (`pseudo_rule` = bh.lineage.names.TABLES_SHA256) and whether the pseudo is shown (BH_LINEAGE_PSEUDO), the score
weights (lot G's `score.weights_sha256()`, None while it does not exist) and the recall parameters.
Wave W3 adds what the agent is given to work with: `skills` (name and condensate of every skill linked into its HOME),
`mcp` (its MCP servers, condensates of container/agent/hooks/mcp.json, of the HexStrike registry and of the server
code; `enabled` False and no server with BH_MCP=0), `tools` (the --tools list) and `pinned` (the skills whose text
the task carries for this program and model, D34).
Two segments set up alike share a condensate; any change to one knob changes it. The document never holds a
secret: identities are names and roles (never a session, a credential or a recipe), texts are condensates.

`ensure()` adds the runs columns of wave W1 (idempotent, like bh.assets.ensure): the board schema itself is not
touched.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
from pathlib import Path

from bh import classes, redact

# (column, type) added to `runs`; created here, never in bh.board.db.MIGRATIONS
COLUMNS = (
    ("setup_sha256", "TEXT"),
    ("setup_json", "TEXT"),
    ("early_stop", "INTEGER"),  # legs that closed themselves on an announced action they never ran (T11)
    ("preflight", "TEXT"),  # the gate self-test this segment started after (T4), JSON
    ("phase", "TEXT"),  # D25: the phase a real program's run belongs to (NULL: lab, examples, verification)
    ("session", "TEXT"),  # D25: `<local date>-<n>` of the hunt session, NULL for a lone `bh run`
    ("friction", "TEXT"),  # D35: {"challenges_extra", "browser_429"} of a bh-browser segment
    ("quota", "TEXT"),  # R44: {"identity", "allot", "sent", "remaining_pct", "spent"} of a bh-browser segment
    ("decisions", "INTEGER"),  # T20: bh_decision events of the run (rotation, nudge, budget tier, WAF pause, stop)
    ("repeats", "INTEGER"),  # W3: tool calls the hooks refused as a repeat ([bh-repeat])
    ("fails", "INTEGER"),  # W3: [bh-fail] lines in the tool results
)


def ensure(board) -> None:
    have = {r["name"] for r in board.db.execute("PRAGMA table_info(runs)")}
    for col, typ in COLUMNS:
        if col not in have:
            board.db.execute(f"ALTER TABLE runs ADD COLUMN {col} {typ}")
    board.db.commit()


def canonical(doc) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


_VERSION_RE = re.compile(r"\b\d+\.\d+\.\d+\b")
_version_cache: dict[str, str | None] = {}


def claude_version() -> str | None:
    """`claude --version` in the agent image, read once per process; None when it cannot be read."""
    if "v" not in _version_cache:
        out = None
        try:
            from bh import stack

            r = stack.agent_sh("claude --version", timeout=20)
            m = _VERSION_RE.search(r.stdout or "") if r.returncode == 0 else None
            out = m.group(0) if m else None
        except Exception:  # noqa: BLE001 (podman missing, container down, a test without podman: unknown)
            out = None
        _version_cache["v"] = out
    return _version_cache["v"]


def preflight_setting(scope, env=None) -> str:
    """BH_PREFLIGHT as it applies to this scope: read for a `platform: local` program only, "1" elsewhere."""
    env = os.environ if env is None else env
    if scope.platform != "local":
        return "1"
    return "0" if str(env.get("BH_PREFLIGHT", "1")).strip() == "0" else "1"


def _card(name: str) -> dict:
    try:
        digest = sha256(classes.card_text(name))
    except OSError:
        digest = None
    return {"name": name, "sha256": digest}


_BH = Path(__file__).resolve().parents[1]  # src/bh
HOOK_FILES = (
    ("container/agent/hooks/settings.json", _BH.parents[1] / "container" / "agent" / "hooks" / "settings.json"),
    ("src/bh/agent/mcp_policy.py", _BH / "agent" / "mcp_policy.py"),
)
POLICY_FILE = _BH / "gate" / "policy.py"
DOCTRINE_OPENING = "a"  # default opening of the doctrine since wave W2


def file_sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def hooks_sha256() -> str:
    """One condensate for the hook layer: {repo-relative name: sha256 of the file (None if missing)}."""
    return sha256(canonical({name: file_sha256(p) for name, p in HOOK_FILES}))


def policy_sha256() -> str:
    return file_sha256(POLICY_FILE) or ""


def score_weights_sha256() -> str | None:
    """Lot G's score weights condensate; None while that module is not there (or cannot answer)."""
    for mod in ("bh.lineage.score", "bh.score"):
        try:
            module = importlib.import_module(mod)
        except ImportError:
            continue
        try:
            return str(module.weights_sha256())
        except Exception:  # noqa: BLE001 (an absent or broken score never stops a segment from starting)
            return None
    return None


MCP_FILE = _BH.parents[1] / "container" / "agent" / "hooks" / "mcp.json"
MCP_CODE = (_BH / "agent" / "mcp", _BH / "agent" / "hexstrike")  # the servers' code (lots A and B), when present
HEXSTRIKE_REGISTRY = _BH / "agent" / "hexstrike" / "registry.py"


def tree_sha256(root: Path) -> str | None:
    """One condensate for a directory: {relative path: sha256} of every file under it (links are not followed out of
    it), None when it does not exist. A file `root` is hashed as such."""
    if root.is_file():
        return file_sha256(root)
    if not root.is_dir():
        return None
    files = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and "__pycache__" not in p.parts:
            files[p.relative_to(root).as_posix()] = file_sha256(p)
    return sha256(canonical(files))


def mcp_enabled(env=None) -> bool:
    """BH_MCP=0: the hunter starts without its MCP servers."""
    env = os.environ if env is None else env
    return str(env.get("BH_MCP", "1")).strip() != "0"


def mcp_servers(path: Path = MCP_FILE) -> list[str]:
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError):
        return []
    servers = doc.get("mcpServers") if isinstance(doc, dict) else None
    return sorted(servers) if isinstance(servers, dict) else []


def mcp_setup(env=None) -> dict:
    """The hunter's MCP servers as this segment starts them. The condensates are kept with BH_MCP=0 too: what the
    image holds does not change, `enabled` and `servers` do."""
    on = mcp_enabled(env)
    return {
        "enabled": on,
        "servers": mcp_servers() if on else [],
        "config_sha256": file_sha256(MCP_FILE),
        "registry_sha256": file_sha256(HEXSTRIKE_REGISTRY),
        "code_sha256": sha256(canonical({p.name: tree_sha256(p) for p in MCP_CODE})),
    }


def skill_sha256(name: str) -> str | None:
    """Condensate of one skill's directory (every file of it), None when it cannot be read."""
    try:
        root = Path(classes.skills_dir()) / name
    except Exception:  # noqa: BLE001 (lot C's classes.skills_dir absent: the skill cannot be hashed)
        return None
    return tree_sha256(root)


def pseudo_shown_setting(env=None) -> str:
    """BH_LINEAGE_PSEUDO as the segment runs with it: "0" (pseudo hidden from the agent) or "1" (the default)."""
    env = os.environ if env is None else env
    return "0" if str(env.get("BH_LINEAGE_PSEUDO", "1")).strip() == "0" else "1"


def setup(
    scope,
    *,
    model: str,
    effort: str | None,
    verifier_model: str,
    max_turns: int,
    minutes: float,
    system_prompt: str,
    task_template: str,
    cards: list[str],
    max_runs_per_day: int,
    runs_per_session: int,
    sessions_per_day: int,
    fill_segment: int,
    fill_day: int,
    prompt_quantum: int,
    prompt_floor: int,
    doctrine_opening: str = DOCTRINE_OPENING,
    recall_params: dict | None = None,
    pseudo_shown: str | None = None,
    skills: list[str] | None = None,
    pinned: list[str] | None = None,
    tools: str | None = None,
    mcp: dict | None = None,
) -> tuple[str, dict]:
    """(sha256 of the canonical document, the document). `recall_params`: what the agent is given of its elders
    (counts, windows), numbers and names only; `pseudo_shown` defaults to BH_LINEAGE_PSEUDO. W3: `skills` the skills
    linked into the session (None: none, the cards path), `pinned` the skills the task carries in full, `tools` the
    --tools list, `mcp` the servers (mcp_setup() by default)."""
    try:  # the lineage is optional to a run (lineage_hooks): without it the setup still hashes
        from bh.lineage import names

        pseudo_rule = names.TABLES_SHA256
    except ImportError:
        pseudo_rule = None

    doc = {
        "model": model,
        "effort": effort,
        "verifier_model": verifier_model,
        "max_turns": int(max_turns),
        "minutes": float(minutes),
        "system_prompt_sha256": sha256(system_prompt),
        "task_template_sha256": sha256(task_template),
        "cards": [_card(n) for n in cards],
        "scope_digest": scope.digest,
        "scanners_on": bool(scope.scanners_on),
        "rate": float(scope.rate),
        # names and roles only: never a session, a credential or a login recipe
        "identities": sorted(
            ({"name": str(i.get("name", "")), "role": str(i.get("role") or "")} for i in scope.identities),
            key=lambda x: x["name"],
        ),
        "claude_code": claude_version(),
        "MAX_RUNS_PER_DAY": int(max_runs_per_day),
        "RUNS_PER_SESSION": int(runs_per_session),
        "SESSIONS_PER_DAY": int(sessions_per_day),
        "FILL_SEGMENT": int(fill_segment),
        "FILL_DAY": int(fill_day),
        "PROMPT_QUANTUM": int(prompt_quantum),
        "PROMPT_FLOOR": int(prompt_floor),
        "BH_PREFLIGHT": preflight_setting(scope),
        # D9 (wave W2)
        "hooks_sha256": hooks_sha256(),
        "policy_sha256": policy_sha256(),
        "doctrine_opening": str(doctrine_opening),
        "pseudo_rule": pseudo_rule,
        "pseudo_shown": pseudo_shown_setting() if pseudo_shown is None else str(pseudo_shown),
        "score_weights_sha256": score_weights_sha256(),
        "recall_params": redact.data(dict(recall_params or {})),
        # W3 (D18-D22, D34)
        "skills": None if skills is None else [{"name": n, "sha256": skill_sha256(n)} for n in sorted(skills)],
        "pinned": sorted(pinned or ()),
        "tools": tools,
        "mcp": mcp_setup() if mcp is None else mcp,
    }
    return sha256(canonical(doc)), doc
