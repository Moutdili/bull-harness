"""Small text helpers shared by the CLI, the runner and the UI."""

from __future__ import annotations

import json
import re

# Characters a reader does not see but a model or a terminal acts on (audit T3): zero-width spaces and joiners, the
# left-to-right / right-to-left marks, the bidirectional embeddings and overrides, the word joiner and invisible
# operators, the bidirectional isolates, and the byte order mark. Written for this harness from the Unicode ranges.
INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")


def escape_invisible(s: str) -> str:
    """Every invisible character shown as `\\u{XXXX}`: text of a hunter or a target can then hide nothing."""
    return INVISIBLE.sub(lambda m: f"\\u{{{ord(m.group()):04X}}}", s)


def escape_tree(obj):
    """escape_invisible on every string of a JSON-like value (keys included), the rest unchanged."""
    if isinstance(obj, str):
        return escape_invisible(obj)
    if isinstance(obj, dict):
        return {escape_tree(k) if isinstance(k, str) else k: escape_tree(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [escape_tree(v) for v in obj]
    return obj


def one_line(obj, n: int = 140) -> str:
    """Single-line preview for logs: newlines shown as ⏎, cut with an ellipsis."""
    s = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False)
    s = s.replace("\n", " ⏎ ")
    return s if len(s) <= n else s[: n - 1] + "…"


def clip(obj, n: int = 4000) -> str:
    """Multi-line clip for the UI, with the number of characters dropped."""
    s = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False)
    return s if len(s) <= n else s[:n] + f"\n… [{len(s) - n} chars clipped]"
