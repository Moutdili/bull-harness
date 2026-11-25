"""Call point: "a human challenge waits for Mio". Empty on purpose.

The first step is to measure, live with Mio, whether a challenge solved by hand in bh-browser unblocks the action at
all (docs/research/18). Only then does a push (ntfy or other) get wired here; the callers already pass what it needs.
"""

from __future__ import annotations


def captcha(program: str | None, identity: str | None, url: str) -> None:
    """Tell the operator that `program`/`identity` waits on a human challenge, to be solved at `url` (the UI's
    /captcha/ page). No-op for now."""
    return None
