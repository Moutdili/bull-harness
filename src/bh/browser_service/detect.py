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
TAIL = 600  # the end of the page text: a chat's label under its last message (challenge, usage limit)
MIN_SECRET = 6  # shorter values would redact ordinary words
REDACTED = "<redacted>"


def _challenge_frame(url: str) -> bool:
    m = re.match(r"https?://([^/:?#]+)", url or "", re.I)
    host = (m.group(1) if m else "").lower().rstrip(".")
    return any(host == h or host.endswith("." + h) for h in CHALLENGE_HOSTS)


def tail(snapshot: dict[str, Any], n: int = TAIL) -> str:
    """The last `n` characters of the page text: where a chat shows the label under its last message."""
    return str(snapshot.get("text") or "")[-n:]


def challenge(snapshot: dict[str, Any], *, passthrough: bool = False) -> dict[str, Any]:
    """{"pending": bool, "reason": str | None}.

    Pending when:
    - a frame served by a challenge host is visible, or its visibility could not be read (fail closed);
    - the page text names a human check AND the text is credible as a challenge: a challenge-host frame exists
      (even hidden: the widget may be collapsed under the label), or the title is an interstitial's, or the page is
      short (an interstitial). A conversation that only quotes "security check" is not a challenge;
    - `passthrough` (the loaded scope has a third-party challenge host: the controller's default, fail closed): the
      label in the TAIL of the text (its last TAIL characters) is enough, frame or not (N2: the widget may render
      where the frame list does not reach). Quoted higher up in a long conversation, it still is not a challenge.
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
        if passthrough:
            mt = CHALLENGE_TEXT.search(tail(snapshot))
            if mt:
                return {"pending": True, "reason": "text (tail): " + mt.group(0).lower()}
    return {"pending": False, "reason": None}


# ---------------------------------------------------------------- the service's own usage limit (R35, R45)
# (expression, reach): a `day` label means no more prompt under this identity until the service's counter resets;
# any other reach is reported, never acted on. QUOTA_SCOPE_2 (the second label's reach) is to be measured live.
QUOTA_SCOPE_2 = "conversation"
_APOS = "['’]"
QUOTA_TEXT: list[tuple[str, str]] = [
    (f"you{_APOS}ve reached your daily limit", "day"),
    (f"that{_APOS}s the most i can say about that", QUOTA_SCOPE_2),
]
_QUOTA_RE = [(re.compile(expr, re.I), reach) for expr, reach in QUOTA_TEXT]
_UNTIL = re.compile(r"(?:check back at|resets at)\s+(\d{1,2}(?::\d{2})?(?:\s*[AaPp](?:\.[Mm]\.|[Mm]))?)", re.I)
_REMAINING = re.compile(r"\b(\d{1,3})\s?%\s+of your daily AI usage limit remaining", re.I)


def quota(snapshot: dict[str, Any]) -> dict[str, Any]:
    """{"spent": bool, "label": str | None, "until": str | None, "remaining_pct": int | None}, read in the TAIL of
    the page text only (a label quoted higher up in the conversation does not count).

    `spent`: a label of reach `day` ("You've reached your daily limit"). `label`: the label found (lower case),
    whatever its reach. `until`: the time after "check back at" / "resets at", as written ("12:00 AM").
    `remaining_pct`: N of the banner "N% of your daily AI usage limit remaining" (0 to 100)."""
    t = tail(snapshot)
    out: dict[str, Any] = {"spent": False, "label": None, "until": None, "remaining_pct": None}
    for rx, reach in _QUOTA_RE:
        m = rx.search(t)
        if m:
            out["label"] = m.group(0).lower().replace("’", "'")
            out["spent"] = reach == "day"
            break
    m = _UNTIL.search(t)
    if m:
        out["until"] = re.sub(r"\s+", " ", m.group(1).strip())
    m = _REMAINING.search(t)
    if m and 0 <= int(m.group(1)) <= 100:
        out["remaining_pct"] = int(m.group(1))
    return out


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


# ---------------------------------------------------------------- bh-web net --body, text --clipboard (R40, R41)
BODY_MAX = 4000  # characters of one response body the agent reads
CLIPBOARD_MAX = 2000
# A sign-in host or path is never read, even under a target prefix: its answers carry tokens and cookies.
SIGNIN_HOST = re.compile(r"(^|[.-])(login|logon|signin|sso|auth|account|accounts|oauth2?|sts)([.-]|$)", re.I)
SIGNIN_PATH = re.compile(r"/(oauth2?|token|authorize|signin|login)(/|$|\.)", re.I)
_DEFAULT_PORT = {"http": 80, "https": 443}


def _url_parts(u: str) -> tuple[str, str, int, str] | None:
    from urllib.parse import urlsplit

    try:
        p = urlsplit(u)
        port = p.port
    except ValueError:
        return None
    scheme = (p.scheme or "").lower()
    if scheme not in _DEFAULT_PORT or not p.hostname or p.username is not None or p.password is not None:
        return None
    return scheme, p.hostname.lower().rstrip("."), port or _DEFAULT_PORT[scheme], p.path or "/"


def under_target(url: str, targets: list[str] | tuple[str, ...]) -> bool:
    """Is `url` under one of the target URL prefixes (same scheme, host and port; the path under the prefix's, on a
    segment boundary)? An empty list covers nothing; a sign-in host or path is never covered."""
    u = _url_parts(url)
    if u is None or SIGNIN_HOST.search(u[1]) or SIGNIN_PATH.search(u[3]) or "/../" in u[3] + "/":
        return False
    for t in targets:
        p = _url_parts(t)
        if p is None or p[:3] != u[:3]:
            continue
        pre = p[3]
        if pre.endswith("/") and u[3].startswith(pre):
            return True
        if not pre.endswith("/") and (u[3] == pre or u[3].startswith(pre + "/")):
            return True
    return False


def target_host(url: str, targets: list[str] | tuple[str, ...]) -> bool:
    """Is the host of `url` the host of one of the target prefixes (net --denied: a failure elsewhere is kept)?"""
    u = _url_parts(url)
    return u is not None and any((p := _url_parts(t)) is not None and p[1] == u[1] for t in targets)


def body_kind(ctype: str) -> str:
    """ "json", "text" or "binary" for a Content-Type."""
    t = (ctype or "").split(";", 1)[0].strip().lower()
    if t == "application/json" or t.endswith("+json"):
        return "json"
    if t.startswith("text/"):
        return "text"
    return "binary"


def _charset(ctype: str) -> str:
    m = re.search(r"charset=\"?([\w.-]+)", ctype or "", re.I)
    return m.group(1) if m else "utf-8"


def body_text(data: bytes, ctype: str, secrets: set[str] | frozenset[str]) -> str:
    """A target response body as the agent may read it: decoded; JSON with every `…token…` key replaced, then the
    credential keys and JWTs (redact.data); any other text through redact.text; then the session's values."""
    try:
        s = data.decode(_charset(ctype), "replace")
    except LookupError:
        s = data.decode("utf-8", "replace")
    if body_kind(ctype) == "json":
        try:
            return scrub(json.dumps(redact.data(_drop_tokens(json.loads(s))), ensure_ascii=False), secrets)
        except ValueError:
            pass  # not JSON after all: read as text
    return scrub(redact.text(_TOKEN_PAIR.sub(lambda m: m.group(1) + redact.placeholder("token"), s)), secrets)


def clipboard_text(s: str, secrets: set[str] | frozenset[str]) -> str:
    return scrub(redact.text(s), secrets)


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
