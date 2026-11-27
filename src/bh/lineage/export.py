"""MEMORY.md: a program's memory as Markdown a human reads, one section per cell (host | route family | class).

Deterministic: items sorted by key, then date, then id; dates from the rows (UTC), no time of export. Two exports of
the same board are identical byte for byte. The agent's text is escaped: a title cannot open a heading, a link or
an HTML tag, and a summary sits in an indented code block, where Markdown renders nothing.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

from bh.board import Board
from bh.lineage import store

FILE = "MEMORY.md"
_SPECIAL = re.compile(r"([\\`*_\[\]<>#|!])")


def _esc(s: object) -> str:
    return _SPECIAL.sub(r"\\\1", " ".join(str(s or "").split()))


def _date(ts: float | None) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(ts)) + "Z" if ts is not None else "?"


def _line(it: dict) -> list[str]:
    agent = "operator" if it["src_kind"] == store.OPERATOR else f"agent {it['agent_no']}"
    tags = [f"**{it['label']}**", agent, it["kind"]]
    if it["outcome"]:
        tags.append(it["outcome"])
    if it["identities"]:
        tags.append(f"as {_esc(it['identities'])}")
    if it["technique"]:
        tags.append(f"technique {_esc(it['technique'])}")
    when = _date(it["valid_from"])
    if it["valid_to"] is not None:
        when += f" → {_date(it['valid_to'])}, superseded by #{it['superseded_by']}"
    seen = f" · seen {it['seen']}x" if it["seen"] > 1 else ""
    out = [f"- {' · '.join(tags)} · #{it['id']} · {when}{seen}", f"  {_esc(it['title'])}"]
    if it["summary"]:
        out += [""] + [f"      {ln}" for ln in it["summary"].splitlines()] + [""]
    return out


def markdown(board: Board, program: str, out_dir: str | Path) -> Path:
    """Write out_dir/MEMORY.md for `program`; returns its path."""
    rows = store.items(board, program)
    cells: dict[str, list[dict]] = {}
    for it in rows:
        cells.setdefault(it["cell"], []).append(it)
    current = sum(it["valid_to"] is None for it in rows)
    out = [
        f"# Memory of {_esc(program)}",
        "",
        f"{len(rows)} items ({current} current), {len(cells)} cells. Labels: OBSERVED (seen by the gate), JUDGED "
        "(verdict of the verifier), ANCHORED (a receipt the host checked), NOTE (the agent's word).",
    ]
    for cell in sorted(cells):
        title = " | ".join(_esc(f) or "-" for f in cell.split("|")) if cell.strip("|") else "(whole program)"
        out += ["", f"## {title}", ""]
        for it in cells[cell]:
            out += _line(it)
    path = Path(out_dir) / FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    text = re.sub(r"\n{3,}", "\n\n", "\n".join(out)).rstrip("\n") + "\n"
    path.write_bytes(text.encode("utf-8"))
    return path
