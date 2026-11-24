"""Small text helpers shared by the CLI, the runner and the UI."""

from __future__ import annotations

import json


def one_line(obj, n: int = 140) -> str:
    """Single-line preview for logs: newlines shown as ⏎, cut with an ellipsis."""
    s = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False)
    s = s.replace("\n", " ⏎ ")
    return s if len(s) <= n else s[: n - 1] + "…"


def clip(obj, n: int = 4000) -> str:
    """Multi-line clip for the UI, with the number of characters dropped."""
    s = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False)
    return s if len(s) <= n else s[:n] + f"\n… [{len(s) - n} chars clipped]"
