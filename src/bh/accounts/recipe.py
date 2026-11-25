"""Enrollment recipe: the declarative `enroll` block of a scope identity, checked, rendered and read back.

Pure (no I/O): the scope loader validates with `check`, `bh.accounts.enroll` renders with `render`.

    enroll:
      email: "bh-{name}-{rand}@lab.local"                  # the address of a new account ({name}, {rand})
      signup: {method: POST, url: "...", json: {...}}      # optional: how to create the account
      login:  {method: POST, url: "...", json: {...}}      # required: how to get a session
      token: authentication.token                          # JSON path of the token in the login answer
      headers: {Authorization: "Bearer {token}"}           # the session's headers ({token})

Bodies (`json` or `form`) use `{email}`, `{password}`, `{answer}`, `{name}`. URLs take no placeholder (a secret
must never reach a URL, hence a log). A key that names a credential must hold a placeholder, never a literal:
the scope file reaches the gate and the agent's prompt.
"""

from __future__ import annotations

import re
from typing import Any

PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")
METHODS = ("GET", "POST")  # PUT/PATCH/DELETE need an identity at the gate: no login uses them
KEYS = {"email", "signup", "login", "token", "headers"}
REQUEST_KEYS = {"method", "url", "json", "form"}
EMAIL_VARS = frozenset({"name", "rand"})
BODY_VARS = frozenset({"email", "password", "answer", "name"})
HEADER_VARS = frozenset({"token"})
# body keys and header names that carry a credential: their value must be a template, never a literal
CREDENTIAL = re.compile(
    r"passw|pwd|secret|totp|otp|token|cookie|api[_-]?key|credential|session|auth|answer|pin\b", re.I
)
_PATH = re.compile(r"[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*")
# a token read from a login answer goes into a header: printable ASCII only, no space, no CR/LF (a second request)
TOKEN = re.compile(r"[\x21-\x7e]{1,4096}")


class RecipeError(ValueError):
    """A recipe that cannot be used. The message never holds a rendered value."""


def placeholders(obj: Any) -> set[str]:
    """Every `{name}` used in a string, a mapping (values) or a list."""
    if isinstance(obj, str):
        return set(PLACEHOLDER.findall(obj))
    if isinstance(obj, dict):
        return set().union(*(placeholders(v) for v in obj.values())) if obj else set()
    if isinstance(obj, list):
        return set().union(*(placeholders(v) for v in obj)) if obj else set()
    return set()


def _literal_credentials(obj: Any, where: str) -> list[str]:
    """Paths of credential-named keys whose value holds no placeholder (a literal secret)."""
    out: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{where}.{k}"
            literal = not isinstance(v, (dict, list)) and not (isinstance(v, str) and PLACEHOLDER.search(v))
            if CREDENTIAL.search(str(k)) and literal:
                out.append(p)
            else:
                out += _literal_credentials(v, p)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += _literal_credentials(v, f"{where}[{i}]")
    return out


def _check_request(req: Any, ctx: str) -> dict[str, Any]:
    if not isinstance(req, dict) or not {"method", "url"} <= set(req) or set(req) - REQUEST_KEYS:
        raise RecipeError(f"{ctx}: must be {{method, url, json | form}}")
    method = req["method"]
    if not isinstance(method, str) or method.upper() not in METHODS:
        raise RecipeError(f"{ctx}.method: one of {list(METHODS)}")
    url = req["url"]
    if not isinstance(url, str) or not re.match(r"https?://", url, re.I):
        raise RecipeError(f"{ctx}.url: an http(s) URL")
    if PLACEHOLDER.search(url):
        raise RecipeError(f"{ctx}.url: no placeholder in a URL (it would reach the logs)")
    if "json" in req and "form" in req:
        raise RecipeError(f"{ctx}: 'json' or 'form', not both")
    if "form" in req and (
        not isinstance(req["form"], dict) or not all(isinstance(v, str) for v in req["form"].values())
    ):
        raise RecipeError(f"{ctx}.form: a mapping of strings")
    if "json" in req and not isinstance(req["json"], (dict, list)):
        raise RecipeError(f"{ctx}.json: a mapping or a list")
    body = req.get("json", req.get("form"))
    if bad := placeholders(body) - BODY_VARS:
        raise RecipeError(f"{ctx}: unknown placeholders {sorted(bad)} (allowed: {sorted(BODY_VARS)})")
    if lit := _literal_credentials(body, ctx):
        raise RecipeError(f"{lit} hold a literal value; use a placeholder such as {{password}}")
    return {**req, "method": method.upper()}


def check(enroll: Any, ctx: str) -> dict[str, Any]:
    """The `enroll` block, validated (method upper-cased). Raises RecipeError."""
    if not isinstance(enroll, dict):
        raise RecipeError(f"{ctx}: a mapping")
    if unknown := set(enroll) - KEYS:
        raise RecipeError(f"{ctx}: unknown keys {sorted(unknown)} (allowed: {sorted(KEYS)})")
    if "login" not in enroll:
        raise RecipeError(f"{ctx}: 'login' is required")
    out: dict[str, Any] = {"login": _check_request(enroll["login"], f"{ctx}.login")}
    if "signup" in enroll:
        out["signup"] = _check_request(enroll["signup"], f"{ctx}.signup")
        if "email" not in enroll:
            raise RecipeError(f"{ctx}: 'email' is required with 'signup'")
    if "email" in enroll:
        email = enroll["email"]
        if not isinstance(email, str) or "@" not in email:
            raise RecipeError(f"{ctx}.email: a template such as 'bh-{{name}}-{{rand}}@example.com'")
        if bad := placeholders(email) - EMAIL_VARS:
            raise RecipeError(f"{ctx}.email: unknown placeholders {sorted(bad)} (allowed: {sorted(EMAIL_VARS)})")
        out["email"] = email
    headers = enroll.get("headers")
    if not isinstance(headers, dict) or not headers or not all(isinstance(v, str) for v in headers.values()):
        raise RecipeError(f"{ctx}.headers: a non-empty mapping of header templates")
    if bad := placeholders(headers) - HEADER_VARS:
        raise RecipeError(f"{ctx}.headers: unknown placeholders {sorted(bad)} (allowed: {sorted(HEADER_VARS)})")
    if lit := _literal_credentials(headers, f"{ctx}.headers"):
        raise RecipeError(f"{lit} hold a literal value; use {{token}}")
    out["headers"] = {str(k): v for k, v in headers.items()}
    if "token" in enroll:
        if not isinstance(enroll["token"], str) or not _PATH.fullmatch(enroll["token"]):
            raise RecipeError(f"{ctx}.token: a dotted JSON path such as 'authentication.token'")
        out["token"] = enroll["token"]
    elif "token" in placeholders(headers):
        raise RecipeError(f"{ctx}: headers use {{token}} but no 'token' path says where to read it")
    return out


def render(obj: Any, values: dict[str, str]) -> Any:
    """`obj` with every `{name}` of its strings replaced (mappings and lists walked, other values kept).
    A placeholder without a value raises RecipeError naming the placeholder, never a value."""

    def sub(m: re.Match) -> str:
        if m.group(1) not in values:
            raise RecipeError(f"no value for {{{m.group(1)}}}")
        return str(values[m.group(1)])

    if isinstance(obj, str):
        return PLACEHOLDER.sub(sub, obj)
    if isinstance(obj, dict):
        return {k: render(v, values) for k, v in obj.items()}
    if isinstance(obj, list):
        return [render(v, values) for v in obj]
    return obj


def render_request(req: dict[str, Any], values: dict[str, str]) -> dict[str, Any]:
    """{method, url, json | form} ready for the gate script."""
    out: dict[str, Any] = {"method": req["method"], "url": req["url"]}
    for key in ("json", "form"):
        if key in req:
            out[key] = render(req[key], values)
    return out


def json_path(doc: Any, path: str) -> Any:
    """The value at a dotted path (`authentication.token`, `data.0.id`), None when it is not there."""
    cur = doc
    for part in path.split("."):
        if isinstance(cur, dict):
            if part not in cur:
                return None
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
    return cur
