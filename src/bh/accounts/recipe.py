"""Enrollment recipe: the declarative `enroll` block of a scope identity, checked, rendered and read back.

Pure (no I/O): the scope loader validates with `check`, `bh.accounts.enroll` renders with `render`.
Three kinds (`kind`, default `json`):

    enroll:                                                # kind: json, one HTTP login run in the gate
      email: "bh-{name}-{rand}@lab.local"                  # the address of a new account ({name}, {rand})
      signup: {method: POST, url: "...", json: {...}}      # optional: how to create the account
      login:  {method: POST, url: "...", json: {...}}      # required: how to get a session
      token: authentication.token                          # JSON path of the token in the login answer
      headers: {Authorization: "Bearer {token}"}           # the session's headers ({token})

    enroll:                                                # kind: browser, headless Chromium in bh-login
      kind: browser
      email: ...                                           # optional, as above
      signup: {method: POST, url: ..., json: ...}          # optional: an HTTP sign-up, run in the gate first
      steps:                                               # the first one is a goto
        - {goto: "https://app.example/#/login"}
        - {click: "button.close-banner", optional: true}  # skipped when absent
        - {fill: "#email", value: "{email}"}
        - {fill: "#password", value: "{password}"}
        - {select: "#lang", value: "en"}
        - {click: "#loginButton"}
        - {totp: "#otp"}                                   # the current RFC 6238 code, computed on the host
        - {email_code: "#code", from: "app.example"}       # a code mailed by that domain (bh.accounts.mail)
        - {wait_for: {url: "#/search"}}                    # or {wait_for: "css"}, {wait_for: {selector: "css"}}
      capture:                                             # what becomes the session (defaults shown)
        cookies: true                                      # the context's cookies, in-scope domains only
        authorization: true                                # Authorization of the first authenticated request, and
                                                           # the last one seen per origin (I19: `origin_headers`)
        authorization_origins: []                          # targets whose own Authorization the login waits for
                                                           # (e.g. ["https://api.example/"]: another audience)
        local_storage: {}                                  # e.g. {token: {Authorization: "Bearer {value}"}}

    enroll:                                                # kind: oauth_refresh, the refresh token is a secret
      kind: oauth_refresh
      token_url: https://login.example/oauth2/v2.0/token   # POST grant_type=refresh_token, run in the gate
      client_id: 00000000-0000-0000-0000-000000000000      # public client id (a client secret stays a secret)
      scope: "openid offline_access https://api.example/.default"   # optional
      headers: {Authorization: "Bearer {access_token}"}   # the default

Bodies (`json` or `form`) and `fill`/`select` values use `{email}`, `{password}`, `{answer}`, `{name}`,
`{code_to}`. URLs take no placeholder (a secret must never reach a URL, hence a log). A key, or a field
selector, that names a
credential must hold a placeholder, never a literal: the scope file reaches the gate and the agent's prompt.
"""

from __future__ import annotations

import re
from typing import Any

PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")
METHODS = ("GET", "POST")  # PUT/PATCH/DELETE need an identity at the gate: no login uses them
KINDS = ("json", "browser", "oauth_refresh")
KEYS = {"kind", "email", "signup", "login", "token", "headers"}
BROWSER_KEYS = {"kind", "email", "signup", "steps", "capture"}
OAUTH_KEYS = {"kind", "token_url", "client_id", "scope", "headers"}
ACTIONS = ("goto", "fill", "click", "wait_for", "totp", "email_code", "select")
STEP_OPTIONS = {"value", "optional", "timeout", "from"}
CAPTURE_KEYS = {"cookies", "authorization", "local_storage", "authorization_origins"}
MAX_AUTH_ORIGINS = 8
OAUTH_VARS = frozenset({"access_token"})
MAX_STEPS = 40
REQUEST_KEYS = {"method", "url", "json", "form"}
EMAIL_VARS = frozenset({"name", "rand"})
BODY_VARS = frozenset({"email", "password", "answer", "name", "code_to"})  # code_to: inbox for login codes
HEADER_VARS = frozenset({"token"})
# body keys and header names that carry a credential: their value must be a template, never a literal
CREDENTIAL = re.compile(
    r"passw|pwd|secret|totp|otp|token|cookie|api[_-]?key|credential|session|auth|answer|pin\b", re.I
)
_PATH = re.compile(r"[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*")
# a token read from a login answer goes into a header: printable ASCII only, no space, no CR/LF (a second request)
TOKEN = re.compile(r"[\x21-\x7e]{1,4096}")
# a whole header value captured from a browser ("Bearer x"): printable ASCII, inner spaces allowed, no CR/LF
HEADER_VALUE = re.compile(r"[\x21-\x7e](?:[\x20-\x7e]{0,4094}[\x21-\x7e])?")
HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}")
# a cookie value the gate may put in a Cookie header (RFC 6265 cookie-octet: no space, quote, comma, ; or \)
COOKIE_VALUE = re.compile(r"[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]{0,4096}")
_DOMAIN = re.compile(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+")


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


def _check_signup_email(enroll: dict[str, Any], ctx: str, out: dict[str, Any]) -> None:
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


def _http_url(url: Any, ctx: str) -> str:
    if not isinstance(url, str) or not re.match(r"https?://[^\s/]", url, re.I) or any(ch.isspace() for ch in url):
        raise RecipeError(f"{ctx}: an http(s) URL")
    if PLACEHOLDER.search(url):
        raise RecipeError(f"{ctx}: no placeholder in a URL (it would reach the logs)")
    return url


def _selector(v: Any, ctx: str) -> str:
    if not isinstance(v, str) or not v.strip() or len(v) > 300 or "\n" in v:
        raise RecipeError(f"{ctx}: a selector (one line, at most 300 characters)")
    return v


def _check_step(step: Any, ctx: str) -> dict[str, Any]:
    """One browser step: exactly one action key, plus its options."""
    if not isinstance(step, dict):
        raise RecipeError(f"{ctx}: a mapping such as {{goto: URL}} or {{fill: CSS, value: '{{email}}'}}")
    actions = [k for k in step if k in ACTIONS]
    if len(actions) != 1:
        raise RecipeError(f"{ctx}: exactly one action among {list(ACTIONS)}")
    action = actions[0]
    if unknown := set(step) - {action} - STEP_OPTIONS:
        raise RecipeError(f"{ctx}: unknown keys {sorted(unknown)}")
    out: dict[str, Any] = {"action": action}
    arg = step[action]
    if action == "goto":
        out["url"] = _http_url(arg, f"{ctx}.goto")
    elif action == "wait_for":
        if isinstance(arg, str):
            arg = {"selector": arg}
        if not isinstance(arg, dict) or len(arg) != 1 or not set(arg) <= {"selector", "url"}:
            raise RecipeError(f"{ctx}.wait_for: a selector, {{selector: CSS}} or {{url: text the URL contains}}")
        key, val = next(iter(arg.items()))
        if key == "selector":
            out["selector"] = _selector(val, f"{ctx}.wait_for")
        elif not isinstance(val, str) or not val or len(val) > 300 or PLACEHOLDER.search(val):
            raise RecipeError(f"{ctx}.wait_for.url: a non-empty text without placeholder")
        else:
            out["url"] = val
    else:
        out["selector"] = _selector(arg, f"{ctx}.{action}")
    if action in ("fill", "select"):
        if not isinstance(step.get("value"), str):
            raise RecipeError(f"{ctx}: '{action}' needs a 'value' (a template such as '{{email}}')")
        val = step["value"]
        if bad := placeholders(val) - BODY_VARS:
            raise RecipeError(f"{ctx}.value: unknown placeholders {sorted(bad)} (allowed: {sorted(BODY_VARS)})")
        if CREDENTIAL.search(out["selector"]) and not PLACEHOLDER.search(val):
            raise RecipeError(f"{ctx}.value: the field {out['selector']!r} takes a credential; use a placeholder")
        out["value"] = val
    elif "value" in step:
        raise RecipeError(f"{ctx}: 'value' only goes with fill or select")
    if action == "email_code":
        dom = step.get("from")
        if not isinstance(dom, str) or not _DOMAIN.fullmatch(dom):
            raise RecipeError(f"{ctx}: 'email_code' needs 'from', the domain the code is mailed from")
        out["from"] = dom.lower()
    elif "from" in step:
        raise RecipeError(f"{ctx}: 'from' only goes with email_code")
    if "optional" in step:
        # an MFA prompt is conditional (a site asks for a code only sometimes): its field may be optional too
        if not isinstance(step["optional"], bool) or action not in ("click", "fill", "wait_for", "totp", "email_code"):
            raise RecipeError(f"{ctx}.optional: true or false, on click, fill, wait_for, totp or email_code only")
        out["optional"] = step["optional"]
    if "timeout" in step:
        t = step["timeout"]
        limit = 300 if action == "email_code" else 60
        if isinstance(t, bool) or not isinstance(t, (int, float)) or not 0 < t <= limit:
            raise RecipeError(f"{ctx}.timeout: seconds, at most {limit}")
        out["timeout"] = float(t)
    return out


def _check_browser(enroll: dict[str, Any], ctx: str) -> dict[str, Any]:
    if unknown := set(enroll) - BROWSER_KEYS:
        raise RecipeError(f"{ctx}: unknown keys {sorted(unknown)} (allowed: {sorted(BROWSER_KEYS)})")
    out: dict[str, Any] = {"kind": "browser"}
    _check_signup_email(enroll, ctx, out)
    steps = enroll.get("steps")
    if not isinstance(steps, list) or not steps or len(steps) > MAX_STEPS:
        raise RecipeError(f"{ctx}.steps: a list of 1 to {MAX_STEPS} steps")
    out["steps"] = [_check_step(s, f"{ctx}.steps[{i}]") for i, s in enumerate(steps)]
    if out["steps"][0]["action"] != "goto":
        raise RecipeError(f"{ctx}.steps[0]: the first step is a goto")
    cap = enroll.get("capture", {})
    if not isinstance(cap, dict) or set(cap) - CAPTURE_KEYS:
        raise RecipeError(f"{ctx}.capture: a mapping of {sorted(CAPTURE_KEYS)}")
    capture: dict[str, Any] = {
        "cookies": cap.get("cookies", True),
        "authorization": cap.get("authorization", True),
        "local_storage": cap.get("local_storage", {}),
    }
    if not isinstance(capture["cookies"], bool) or not isinstance(capture["authorization"], bool):
        raise RecipeError(f"{ctx}.capture: 'cookies' and 'authorization' are true or false")
    wanted = cap.get("authorization_origins", [])
    if (
        not isinstance(wanted, list)
        or len(wanted) > MAX_AUTH_ORIGINS
        or not all(isinstance(u, str) and _origin(u) for u in wanted)
        or (wanted and not capture["authorization"])
    ):
        raise RecipeError(
            f"{ctx}.capture.authorization_origins: at most {MAX_AUTH_ORIGINS} http(s) URLs, with authorization: true"
        )
    capture["authorization_origins"] = sorted({_origin(u) for u in wanted})
    ls = capture["local_storage"]
    if not isinstance(ls, dict) or len(ls) > 8:
        raise RecipeError(f"{ctx}.capture.local_storage: a mapping key -> {{Header: 'template with {{value}}'}}")
    for key, hdrs in ls.items():
        c = f"{ctx}.capture.local_storage.{key}"
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", key):
            raise RecipeError(f"{c}: a localStorage key ([A-Za-z0-9_.:-], at most 128)")
        if not isinstance(hdrs, dict) or not hdrs:
            raise RecipeError(f"{c}: a mapping {{Header: 'Bearer {{value}}'}}")
        for name, tmpl in hdrs.items():
            if not isinstance(name, str) or not HEADER_NAME.fullmatch(name):
                raise RecipeError(f"{c}: {name!r} is not a header name")
            if not isinstance(tmpl, str) or placeholders(tmpl) != {"value"}:
                raise RecipeError(f"{c}.{name}: a template holding {{value}} and no other placeholder")
    if not (capture["cookies"] or capture["authorization"] or ls):
        raise RecipeError(f"{ctx}.capture: nothing to capture")
    out["capture"] = capture
    return out


def _check_oauth(enroll: dict[str, Any], ctx: str) -> dict[str, Any]:
    if unknown := set(enroll) - OAUTH_KEYS:
        raise RecipeError(f"{ctx}: unknown keys {sorted(unknown)} (allowed: {sorted(OAUTH_KEYS)})")
    out: dict[str, Any] = {"kind": "oauth_refresh", "token_url": _http_url(enroll.get("token_url"), f"{ctx}.token_url")}
    cid = enroll.get("client_id")
    if not isinstance(cid, str) or not re.fullmatch(r"[A-Za-z0-9._:/@-]{1,200}", cid):
        raise RecipeError(f"{ctx}.client_id: the public client id (a client secret goes in the secrets file)")
    out["client_id"] = cid
    if "scope" in enroll:
        if not isinstance(enroll["scope"], str) or not re.fullmatch(r"[\x21-\x7e]+( [\x21-\x7e]+)*", enroll["scope"]):
            raise RecipeError(f"{ctx}.scope: space-separated OAuth scopes")
        out["scope"] = enroll["scope"]
    headers = enroll.get("headers", {"Authorization": "Bearer {access_token}"})
    if not isinstance(headers, dict) or not headers or not all(isinstance(v, str) for v in headers.values()):
        raise RecipeError(f"{ctx}.headers: a non-empty mapping of header templates")
    if bad := placeholders(headers) - OAUTH_VARS:
        raise RecipeError(f"{ctx}.headers: unknown placeholders {sorted(bad)} (allowed: {sorted(OAUTH_VARS)})")
    if lit := _literal_credentials(headers, f"{ctx}.headers"):
        raise RecipeError(f"{lit} hold a literal value; use {{access_token}}")
    out["headers"] = {str(k): v for k, v in headers.items()}
    return out


def kind(recipe: dict[str, Any] | None) -> str | None:
    """The kind of a checked recipe (`json` when absent: recipes written before kinds existed)."""
    return None if not recipe else recipe.get("kind", "json")


def _origin(url: str) -> str | None:
    from bh.agent.contract import origin

    return origin(url)


def auth_origins(recipe: dict[str, Any] | None) -> list[str]:
    """Origins a checked browser recipe waits for an Authorization of (they must be targets)."""
    return list(((recipe or {}).get("capture") or {}).get("authorization_origins") or [])


def urls(recipe: dict[str, Any] | None) -> list[tuple[str, str]]:
    """(where, URL) of every URL a checked recipe visits: all must be in scope."""
    if not recipe:
        return []
    out = [(f"enroll.{k}.url", recipe[k]["url"]) for k in ("signup", "login") if isinstance(recipe.get(k), dict)]
    steps = enumerate(recipe.get("steps") or [])
    out += [(f"enroll.steps[{i}].goto", s["url"]) for i, s in steps if s["action"] == "goto"]
    if recipe.get("token_url"):
        out.append(("enroll.token_url", recipe["token_url"]))
    return out


def check(enroll: Any, ctx: str) -> dict[str, Any]:
    """The `enroll` block, validated (method upper-cased, `kind` set). Raises RecipeError."""
    if not isinstance(enroll, dict):
        raise RecipeError(f"{ctx}: a mapping")
    k = enroll.get("kind", "json")
    if k not in KINDS:
        raise RecipeError(f"{ctx}.kind: one of {list(KINDS)}")
    if k == "browser":
        return _check_browser(enroll, ctx)
    if k == "oauth_refresh":
        return _check_oauth(enroll, ctx)
    if unknown := set(enroll) - KEYS:
        raise RecipeError(f"{ctx}: unknown keys {sorted(unknown)} (allowed: {sorted(KEYS)})")
    if "login" not in enroll:
        raise RecipeError(f"{ctx}: 'login' is required")
    out: dict[str, Any] = {"kind": "json", "login": _check_request(enroll["login"], f"{ctx}.login")}
    _check_signup_email(enroll, ctx, out)
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
