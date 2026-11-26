"""Pure helpers of the browser service: "a human challenge is on screen", and what the agent may read.

A snapshot is what the controller reads from the page, reduced to plain data so the tests need no browser:

    {"url": str, "title": str,
     "text": str (visible text: the whole of it, or its head and its tail when it is long),
     "text_len": int (length of the whole visible text; len(text) when absent),
     "frames": [{"url": str, "visible": bool | None}, ...]}   # every child frame, shadow roots included
                                                              # (page.frames); None: visibility unknown
"""

from __future__ import annotations

import json
import re
from typing import Any

from bh import redact

CHALLENGE_HOSTS = ("challenges.cloudflare.com",)
# Interstitial and widget wording (Cloudflare's English pages, the French they show to a French browser, and the
# label Copilot shows under a message held by Turnstile).
CHALLENGE_TEXT = re.compile(
    r"security check|verify you are human|verifying you are human|vérifiez que vous êtes (un )?humain"
    r"|vérification de sécurité|verification required|vérification requise",
    re.I,
)
# Titles of a full-page interstitial: the whole page is the challenge.
INTERSTITIAL_TITLE = re.compile(r"just a moment|attention required|un instant|one more step|security check", re.I)
SHORT_PAGE = 600  # below this many characters of visible text, the page is the challenge's (an interstitial)
MIN_SECRET = 6  # shorter values would redact ordinary words
REDACTED = "<redacted>"


def _challenge_frame(url: str) -> bool:
    m = re.match(r"https?://([^/:?#]+)", url or "", re.I)
    host = (m.group(1) if m else "").lower().rstrip(".")
    return any(host == h or host.endswith("." + h) for h in CHALLENGE_HOSTS)


def challenge(snapshot: dict[str, Any]) -> dict[str, Any]:
    """{"pending": bool, "reason": str | None}.

    Pending when:
    - a frame served by a challenge host is visible, or its visibility could not be read (fail closed);
    - the page text names a human check AND the text is credible as a challenge: a challenge-host frame exists
      (even hidden: the widget may be collapsed under the label), or the title is an interstitial's, or the page is
      short (an interstitial). A conversation that only quotes "security check" is not a challenge.
    A hidden Turnstile frame without such text (invisible mode, already solved) is not a challenge for a human."""
    frames = [f for f in snapshot.get("frames") or [] if isinstance(f, dict)]
    ch_frames = [f for f in frames if _challenge_frame(str(f.get("url") or ""))]
    for f in ch_frames:
        if f.get("visible") is True:
            return {"pending": True, "reason": "turnstile-frame"}
        if f.get("visible") is None:  # unknown: never let the agent act on what may be a challenge
            return {"pending": True, "reason": "turnstile-frame (visibility unknown)"}
    text = str(snapshot.get("text") or "")
    m = CHALLENGE_TEXT.search(text)
    if m:
        n = snapshot.get("text_len")
        n = n if isinstance(n, int) and not isinstance(n, bool) else len(text)
        title = str(snapshot.get("title") or "")
        if ch_frames or INTERSTITIAL_TITLE.search(title) or n < SHORT_PAGE:
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


# ---------------------------------------------------------------- websocket frames (bh-web frames)
FRAME_MAX = 2000  # characters kept of one frame
# A frame that carries a challenge answer is never kept, whatever its shape (SignalR `ChallengeProof`, Turnstile).
CHALLENGE_FRAME = re.compile(r"challengeproof|turnstile|cf-chl|cf_clearance", re.I)
TOKEN_KEY = re.compile(r"token", re.I)
# "…token…": "value" and …token…=value in text that is not JSON
_TOKEN_PAIR = re.compile(r"""(?i)(["']?[\w-]*token[\w-]*["']?\s*[:=]\s*["']?)([^"'&\s,}]+)""")


def _drop_tokens(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {
            k: (redact.placeholder("token") if TOKEN_KEY.search(str(k)) else _drop_tokens(v)) for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_drop_tokens(v) for v in obj]
    return obj


def frame_text(payload: Any, secrets: set[str] | frozenset[str]) -> str | None:
    """What the agent may read of one websocket frame, None when the frame must not be kept at all.

    Binary frames are reduced to their size. A frame naming a challenge (ChallengeProof, Turnstile, Cloudflare
    clearance) is dropped whole. In the others, the value of any key containing `token` is replaced (JSON records,
    SignalR's 0x1e-separated ones included, and key=value text), then credential keys, the session's values and JWTs
    are scrubbed."""
    if isinstance(payload, (bytes, bytearray)):
        return f"<binary {len(payload)} bytes>"
    s = str(payload)
    if CHALLENGE_FRAME.search(s):
        return None
    out = []
    for rec in s.split("\x1e"):
        if not rec:
            continue
        try:
            obj = json.loads(rec)
        except ValueError:
            out.append(redact.text(_TOKEN_PAIR.sub(lambda m: m.group(1) + redact.placeholder("token"), rec)))
            continue
        out.append(json.dumps(redact.data(_drop_tokens(obj)), ensure_ascii=False))
    text = scrub("\x1e".join(out), secrets)
    return text[:FRAME_MAX] + ("…" if len(text) > FRAME_MAX else "")


# ---------------------------------------------------------------- bh-web ws-rewrite (one client frame)
REWRITE_FIND = (8, 4096)  # characters of the string searched in one client frame
REWRITE_REPLACE_MAX = 4096


def rewrite_client_frame(message: Any, find: str, replace: str) -> tuple[Any, bool]:
    """(message to forward, rewritten?) for one frame the page sends. Only a text frame that contains `find` is
    changed, once (first occurrence). Never a binary frame, never a frame that carries a challenge answer
    (ChallengeProof, Turnstile, Cloudflare clearance): those go out exactly as the page wrote them."""
    if not isinstance(message, str) or not find or CHALLENGE_FRAME.search(message) or find not in message:
        return message, False
    return message.replace(find, replace, 1), True
