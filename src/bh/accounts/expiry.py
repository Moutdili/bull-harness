"""When a session is known to end: written to `expires_at` of the session file, read by the session keeper.

Sources, in order of trust:
1. the `exp` claim of a JWT the session sends (decoded WITHOUT checking the signature: only to read `exp`, never
   to trust a claim), and an OAuth `expires_in`;
2. failing those, the Max-Age / Expires of the session's cookies, only those whose name says session (`sid`,
   `session`, `auth`, `token`, `jwt`, `login`...): a 30-minute bot cookie (`__cf_bm`) must not drive a login
   every 25 minutes.

The earliest one wins. None: nothing is known; the keeper then renews only on `session-dead`.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Iterable
from typing import Any

SESSIONISH = re.compile(r"sess|sid|auth|token|jwt|login|remember|identity|access", re.I)


def jwt_exp(token: str | None) -> float | None:
    """`exp` of a JWT (`header.payload.signature`, base64url), None for anything else. A `Bearer ` prefix is
    accepted. The signature is not checked: the value is only used to plan a login, never to trust the token."""
    if not isinstance(token, str):
        return None
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) != 3 or not parts[1] or len(parts[1]) > 8192:
        return None
    try:
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, TypeError):
        return None
    exp = claims.get("exp") if isinstance(claims, dict) else None
    if isinstance(exp, bool) or not isinstance(exp, (int, float)) or not 0 < exp < 1e11:
        return None
    return float(exp)


def from_expires_in(expires_in: Any, now: float) -> float | None:
    """OAuth `expires_in` (seconds, a number or a numeric string) as an absolute time."""
    if isinstance(expires_in, str) and expires_in.strip().isdigit():
        expires_in = int(expires_in.strip())
    if (
        isinstance(expires_in, bool)
        or not isinstance(expires_in, (int, float))
        or not 0 < expires_in < 10 * 365 * 86400
    ):
        return None
    return now + float(expires_in)


def cookie_expiries(jar: dict[str, dict[str, dict[str, Any]]] | None) -> list[float]:
    """Expiry times of the jar's session-like cookies (session.py jar shape)."""
    out = []
    for cookies in (jar or {}).values():
        for name, c in cookies.items():
            exp = c.get("expires") if isinstance(c, dict) else None
            if SESSIONISH.search(name) and isinstance(exp, (int, float)) and not isinstance(exp, bool) and exp > 0:
                out.append(float(exp))
    return out


def known(
    *,
    tokens: Iterable[str | None] = (),
    expires_in: Any = None,
    jar: dict | None = None,
    now: float,
) -> float | None:
    """The earliest known end of a session: JWT `exp` of `tokens` and `expires_in` first, cookies otherwise."""
    strong = [e for e in (jwt_exp(t) for t in tokens) if e is not None]
    if (e := from_expires_in(expires_in, now)) is not None:
        strong.append(e)
    if strong:
        return min(strong)
    weak = cookie_expiries(jar)
    return min(weak) if weak else None
