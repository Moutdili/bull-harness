"""TOTP (RFC 6238) over HOTP (RFC 4226), stdlib only. Computed on the host: the seed never leaves it.

The seed lives in `secrets/identities/<program>/<name>.json` under `totp`, in one of three shapes:

    "totp": "JBSWY3DPEHPK3PXP"                                    # base32 seed, defaults below
    "totp": "otpauth://totp/Label?secret=JBSWY3DPEHPK3PXP&digits=6&period=30&algorithm=SHA1"
    "totp": {"secret": "JBSWY3DPEHPK3PXP", "digits": 6, "period": 30, "algorithm": "SHA1"}

Defaults (RFC 6238 §4, and what authenticator apps assume): SHA-1, 30 s, 6 digits, T0 = 0.
Checked against the test vectors of RFC 6238 appendix B (tests/test_totp.py).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import struct
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlsplit

ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


class TotpError(ValueError):
    """A seed or a parameter that cannot be used. The message never holds the seed."""


@dataclass(frozen=True)
class Params:
    key: bytes
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"
    t0: int = 0

    def __repr__(self) -> str:  # never print the key
        return f"Params(digits={self.digits}, period={self.period}, algorithm={self.algorithm!r}, t0={self.t0})"


def hotp(key: bytes, counter: int, digits: int = 6, algorithm: str = "SHA1") -> str:
    """RFC 4226 §5.3: HMAC over the 8-byte counter, dynamic truncation, modulo 10^digits, left-padded."""
    algo = ALGORITHMS.get(algorithm.upper())
    if algo is None:
        raise TotpError(f"algorithm must be one of {sorted(ALGORITHMS)}")
    if not 6 <= digits <= 10:
        raise TotpError("digits must be between 6 and 10")
    if counter < 0:
        raise TotpError("counter must be >= 0")
    mac = hmac.new(key, struct.pack(">Q", counter), algo).digest()
    off = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[off : off + 4])[0] & 0x7FFFFFFF
    return str(code % 10**digits).zfill(digits)


def totp(p: Params, at: float | None = None) -> str:
    """The code valid at `at` (default: now)."""
    now = time.time() if at is None else at
    if p.period <= 0:
        raise TotpError("period must be > 0")
    return hotp(p.key, int((now - p.t0) // p.period), p.digits, p.algorithm)


def seconds_left(p: Params, at: float | None = None) -> float:
    """Seconds before the code valid at `at` changes."""
    now = time.time() if at is None else at
    return p.period - ((now - p.t0) % p.period)


def b32decode(secret: str) -> bytes:
    """Base32 as authenticator apps show it: spaces and dashes ignored, any case, padding optional."""
    s = re.sub(r"[\s-]", "", secret).upper().rstrip("=")
    if not s or not re.fullmatch(r"[A-Z2-7]+", s):
        raise TotpError("the TOTP seed is not base32")
    try:
        return base64.b32decode(s + "=" * (-len(s) % 8))
    except ValueError:
        raise TotpError("the TOTP seed is not base32") from None


def _int(v: Any, name: str, default: int) -> int:
    if v is None:
        return default
    try:
        n = int(v)
    except (TypeError, ValueError):
        raise TotpError(f"{name} must be an integer") from None
    return n


def params(doc: Any) -> Params:
    """The `totp` field of a credential (base32 string, otpauth:// URI or mapping) as Params."""
    if isinstance(doc, str) and doc.lower().startswith("otpauth://"):
        u = urlsplit(doc)
        if u.netloc.lower() != "totp":
            raise TotpError("only otpauth://totp/ URIs are supported (not hotp)")
        q = {k.lower(): v[0] for k, v in parse_qs(u.query).items()}
        doc = {
            "secret": q.get("secret", ""),
            "digits": q.get("digits"),
            "period": q.get("period"),
            "algorithm": q.get("algorithm"),
        }
    elif isinstance(doc, str):
        doc = {"secret": doc}
    if not isinstance(doc, dict) or not isinstance(doc.get("secret"), str):
        raise TotpError("totp must be a base32 seed, an otpauth://totp/ URI or {secret, digits?, period?, algorithm?}")
    algorithm = str(doc.get("algorithm") or "SHA1").upper().replace("-", "")
    if algorithm not in ALGORITHMS:
        raise TotpError(f"algorithm must be one of {sorted(ALGORITHMS)}")
    p = Params(
        key=b32decode(doc["secret"]),
        digits=_int(doc.get("digits"), "digits", 6),
        period=_int(doc.get("period"), "period", 30),
        algorithm=algorithm,
        t0=_int(doc.get("t0"), "t0", 0),
    )
    if not 6 <= p.digits <= 10 or p.period <= 0:
        raise TotpError("digits must be 6-10 and period > 0")
    return p


def fresh_code(p: Params, min_left: float = 5.0, at: float | None = None, sleep=time.sleep) -> str:
    """The current code, waiting for the next one when fewer than `min_left` seconds remain (the form must not
    receive a code that expires on the way)."""
    now = time.time() if at is None else at
    left = seconds_left(p, now)
    if left < min_left:
        sleep(left + 0.2)
        now += left + 0.2
    return totp(p, now)
