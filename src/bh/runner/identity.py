"""Hashed identity of a run (T10): what made the segment what it is, in one condensate.

`setup()` gathers every knob that shapes a segment (model, effort, judge, budget, rendered system prompt, task
template, loaded cards, scope digest, rate, identity names and roles, Claude Code version of the image, daily caps,
fill and prompt budgets, BH_PREFLIGHT) into a canonical JSON document (sorted keys, no whitespace) and its sha256.
Two segments set up alike share a condensate; any change to one knob changes it. The document never holds a
secret: identities are names and roles (never a session, a credential or a recipe), texts are condensates.

`ensure()` adds the runs columns of wave W1 (idempotent, like bh.assets.ensure): the board schema itself is not
touched.
"""

from __future__ import annotations

import hashlib
import json
import os
import re

from bh import classes

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
) -> tuple[str, dict]:
    """(sha256 of the canonical document, the document)."""
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
    }
    return sha256(canonical(doc)), doc
