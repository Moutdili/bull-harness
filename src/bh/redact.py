"""Secrets out of everything the harness stores or shows: triager PoCs, finding PoCs, the gate's flow log.

One definition of "sensitive" for the whole project:
- headers that carry credentials (Authorization, Cookie, Set-Cookie, API keys, CSRF tokens...);
- keys (query string, JSON, form body) that name a credential or personal data (password, token, email...);
- JWTs anywhere.
Values become `<redacted:name>` placeholders. A redacted PoC can lose a forged token the exploit needs: the
triager PoC says so in a comment, and the human puts the value back from the stored proof.
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE_HEADER = re.compile(
    r"^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|apikey|x-auth-token|x-access-token|"
    r"x-csrf-token|x-xsrf-token|x-session-id|x-amz-security-token)$",
    re.I,
)
SENSITIVE_KEY = re.compile(
    r"(passw(or)?d|passwd|pwd|secret|token|api[_-]?key|apikey|session|sessid|sid|auth|otp|mfa|totp|"
    r"code_verifier|signature|sig|email|e-mail|login|username|phone|iban|card)$",
    re.I,
)
JWT = re.compile(r"\beyJ[\w-]{6,}\.[\w-]{6,}\.[\w-]*")
_HEADER_LINE = re.compile(  # "Cookie: a=b" anywhere: a header line, curl -H '...', a pasted request
    r"(?i)\b((?:proxy-)?authorization|cookie|set-cookie|x-api-key|x-auth-token|x-access-token|x-csrf-token"
    r"|x-xsrf-token)(\s*:\s*)([^'\"\n]+)"
)
_KEY_VALUE = re.compile(
    r"""(?i)(["']?(?:[\w-]*(?:passw(?:or)?d|pwd|secret|token|api[_-]?key|session|email))["']?\s*[:=]\s*["']?)"""
    r"""([^"'&\s,}]+)"""
)


def placeholder(name: str) -> str:
    return f"<redacted:{name}>"


def header(name: str, value: str) -> str:
    return placeholder(name.lower()) if SENSITIVE_HEADER.match(name) else JWT.sub(placeholder("jwt"), value)


def url(u: str) -> str:
    parts = urlsplit(u)
    if not parts.query:
        return JWT.sub(placeholder("jwt"), u)
    q = [
        (k, placeholder(k) if SENSITIVE_KEY.search(k) else JWT.sub(placeholder("jwt"), v))
        for k, v in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return urlunsplit(parts._replace(query=urlencode(q, safe="<>:")))


def data(obj):
    """JSON-like value: sensitive keys replaced, recursively; JWTs removed from strings."""
    if isinstance(obj, dict):
        return {k: placeholder(str(k)) if SENSITIVE_KEY.search(str(k)) else data(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [data(v) for v in obj]
    if isinstance(obj, str):
        return JWT.sub(placeholder("jwt"), obj)
    return obj


def body(b) -> str | dict | list:
    """A request body as the proof holds it: JSON object, JSON text, form text or anything else."""
    if isinstance(b, (dict, list)):
        return data(b)
    s = str(b)
    try:
        parsed = json.loads(s)
    except ValueError:
        parsed = None
    if isinstance(parsed, (dict, list)):
        return json.dumps(data(parsed))
    if "=" in s and "\n" not in s and " " not in s.strip():
        return urlencode([(k, placeholder(k) if SENSITIVE_KEY.search(k) else v) for k, v in parse_qsl(s)], safe="<>:")
    return text(s)


def text(s: str) -> str:
    """Free text (a PoC script, notes): header lines, key=value / "key": "value" pairs and JWTs."""
    s = _HEADER_LINE.sub(lambda m: m.group(1) + m.group(2) + placeholder(m.group(1).lower()), s)
    s = _KEY_VALUE.sub(lambda m: m.group(1) + placeholder("value"), s)
    return JWT.sub(placeholder("jwt"), s)
