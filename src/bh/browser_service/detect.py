"""Pure helpers of the browser service: "a human challenge is on screen", and what the agent may read.

A snapshot is what the controller reads from the page, reduced to plain data so the tests need no browser:

    {"url": str, "title": str, "text": str (visible text, head of the page),
     "frames": [{"url": str, "visible": bool}, ...]}   # every child frame, shadow roots included (page.frames)
"""

from __future__ import annotations

import re
from typing import Any

from bh import redact

CHALLENGE_HOSTS = ("challenges.cloudflare.com",)
# Interstitial and widget wording (Cloudflare's English pages, and the French they show to a French browser).
CHALLENGE_TEXT = re.compile(
    r"security check|verify you are human|verifying you are human|vérifiez que vous êtes (un )?humain"
    r"|vérification de sécurité",
    re.I,
)
MIN_SECRET = 6  # shorter values would redact ordinary words
REDACTED = "<redacted>"


def _challenge_frame(url: str) -> bool:
    m = re.match(r"https?://([^/:?#]+)", url or "", re.I)
    host = (m.group(1) if m else "").lower().rstrip(".")
    return any(host == h or host.endswith("." + h) for h in CHALLENGE_HOSTS)


def challenge(snapshot: dict[str, Any]) -> dict[str, Any]:
    """{"pending": bool, "reason": str | None}. Pending: a visible frame served by a challenge host (Turnstile's
    iframe), or the page text names a human check. A hidden Turnstile frame (invisible mode, already solved) is not
    a challenge for a human."""
    for f in snapshot.get("frames") or []:
        if isinstance(f, dict) and f.get("visible") and _challenge_frame(str(f.get("url") or "")):
            return {"pending": True, "reason": "turnstile-frame"}
    m = CHALLENGE_TEXT.search(str(snapshot.get("text") or "")[:20_000])
    if m:
        return {"pending": True, "reason": "text: " + m.group(0).lower()}
    return {"pending": False, "reason": None}


def scrub(text: str, secrets: set[str] | frozenset[str]) -> str:
    """Known secret values (the loaded session's) and JWTs out of a text the agent will read."""
    for s in sorted((s for s in secrets if len(s) >= MIN_SECRET), key=len, reverse=True):
        text = text.replace(s, REDACTED)
    return redact.JWT.sub(REDACTED, text)


def scrub_url(url: str, secrets: set[str] | frozenset[str]) -> str:
    return scrub(redact.url(url), secrets)


def scrub_obj(obj: Any, secrets: set[str] | frozenset[str]) -> Any:
    """Every string of a JSON-like value scrubbed (the last pass before a reply leaves the controller)."""
    if isinstance(obj, str):
        return scrub(obj, secrets)
    if isinstance(obj, dict):
        return {k: scrub_obj(v, secrets) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub_obj(v, secrets) for v in obj]
    return obj
