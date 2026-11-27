"""Sign up, log in and check the harness's own test accounts, without a human (issue 25).

The host owns the credential (`bh.accounts.secrets`) and the session file (`bh.gate.session` format). Three
recipe kinds (`bh.accounts.recipe`):

- `json`: the HTTP exchanges run in the gate, the only container that reaches the targets, as one stdlib script per
  call sent on stdin (`stack.gate_python`), through the gate's own proxy (127.0.0.1:8080): scope, rate and required
  headers apply as to any request. The credential travels inside that script on stdin, never in argv or the
  environment; the script answers with statuses, the token and the Set-Cookie of the login.
- `browser`: an optional HTTP sign-up as above, then headless Chromium in the `bh-login` container, behind the gate
  (`bh.accounts.browser`). TOTP codes are computed on the host (`bh.accounts.totp`), mailed codes read by the host
  (`bh.accounts.mail`). The session is the context's in-scope cookies, the first Authorization header seen, the
  last Authorization seen per in-scope target origin (`origin_headers`, I19: the gate sends each back to its own
  origin only, so `q -a` reaches an API of another audience with the right bearer), and declared localStorage keys
  rendered as headers.
- `oauth_refresh`: POST grant_type=refresh_token to the recipe's token URL, through the gate as for `json`. The
  refresh token (deposited once by a human at onboarding: first consent, MFA) lives in the secrets file; a new one
  returned by the server replaces it there BEFORE the session is written.

In every case the host writes the session (`session.save` under `session.lock`), with `expires_at` from what is
known (`bh.accounts.expiry`: JWT `exp`, OAuth `expires_in`, session cookies' Max-Age/Expires).

Limits (board meta): one login per identity and hour (`accounts-login:<name>:<program>`) unless forced (the session
keeper forces, under its own 5-minute limit), one sign-up per identity and hour (`accounts-signup:...`), and a new
account (a new address) only while the identity has no credential. A password, an answer, a code or a token never
appears in a return value, a message or an exception.
"""

from __future__ import annotations

import functools
import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from bh import paths, stack
from bh.accounts import browser, expiry, mail, totp
from bh.accounts import recipe as rc
from bh.accounts import secrets
from bh.agent.contract import origin
from bh.gate import session
from bh.scope import Scope
from bh.scope.psl import is_public_suffix

LOGIN_EVERY_S = 3600
SIGNUP_EVERY_S = 3600
REQUEST_TIMEOUT_S = 15
GATE_PROXY = "http://127.0.0.1:8080"
GATE_CA = "/gate-ca/mitmproxy-ca-cert.pem"

# Runs in the gate (python3 -I -). Stdlib only: the gate's /opt/bh/src may be older than the host's code.
# Redirects are not followed (a form login sets its cookie on the 302). Bodies never leave the script: a step
# reports its status, whether `expect` was found, the token at `token_path`, the values at `token_paths` (strings
# and numbers only) and, if asked, the Set-Cookie values.
GATE_SCRIPT = r"""
import json, os, ssl, sys, urllib.error, urllib.parse, urllib.request

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None

def _path(doc, path):
    for part in path.split("."):
        if isinstance(doc, dict) and part in doc:
            doc = doc[part]
        elif isinstance(doc, list) and part.isdigit() and int(part) < len(doc):
            doc = doc[int(part)]
        else:
            return None
    return doc

def main(raw):
    p = json.loads(raw)
    ctx = ssl.create_default_context(cafile=p["cafile"]) if os.path.exists(p["cafile"]) else None
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": p["proxy"], "https": p["proxy"]}),
        urllib.request.HTTPSHandler(context=ctx),
        _NoRedirect,
    )
    out = []
    for s in p["steps"]:
        headers = {"Accept": "application/json, */*", **s.get("headers", {})}
        data = None
        if "json" in s:
            data = json.dumps(s["json"]).encode()
            if not any(k.lower() == "content-type" for k in headers):
                headers["Content-Type"] = "application/json"
        elif "form" in s:
            data = urllib.parse.urlencode(s["form"]).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(s["url"], data=data, headers=headers, method=s["method"])
        rec = {"step": s["step"]}
        try:
            try:
                resp = opener.open(req, timeout=p["timeout"])
            except urllib.error.HTTPError as e:
                resp = e
            body = resp.read(1 << 20)
            rec["status"] = resp.status if hasattr(resp, "status") else resp.code
            hdrs = resp.headers
            if hdrs.get("X-BH-Gate"):
                rec["gate"] = body.decode("utf-8", "replace").strip()[:200]
            if "expect" in s:
                rec["match"] = s["expect"].encode() in body
            if "token_path" in s or "token_paths" in s:
                try:
                    doc = json.loads(body or b"null")
                except ValueError:
                    doc = None
                if "token_path" in s:
                    tok = _path(doc, s["token_path"])
                    rec["token"] = tok if isinstance(tok, str) and tok else None
                if "token_paths" in s:
                    vals = {}
                    for name, path in s["token_paths"].items():
                        v = _path(doc, path)
                        if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                            vals[name] = v
                    rec["tokens"] = vals
            if s.get("cookies"):
                rec["set_cookies"] = hdrs.get_all("Set-Cookie") or []
        except Exception as e:
            reason = getattr(e, "reason", "")
            rec["error"] = (type(e).__name__ + (": " + str(reason) if reason else ""))[:160]
        out.append(rec)
        if s.get("required") and (rec.get("error") or not 200 <= rec.get("status", 0) < 400):
            break
    sys.stdout.write(json.dumps(out))
"""


class AccountError(RuntimeError):
    """Enrollment failed. The message is one line and holds no credential or token. `cause` (T51): one of CAUSES
    when a login failed (the message then starts with `[<cause>] `), None otherwise."""

    def __init__(self, message: str = "", cause: str | None = None) -> None:
        super().__init__(message)
        self.cause = cause


@dataclass(frozen=True)
class Identity:
    program: str
    name: str
    decl: dict[str, Any]
    scope: Scope | None = field(default=None, compare=False, repr=False)

    @property
    def recipe(self) -> dict[str, Any] | None:
        return self.decl.get("enroll")

    @property
    def kind(self) -> str | None:
        return rc.kind(self.recipe)

    @property
    def probe(self) -> dict[str, Any] | None:
        return self.decl.get("probe")

    @property
    def session_file(self) -> Path:
        return paths.identities_dir(self.program) / f"{self.name}.json"


def identity(scope: Scope, name: str) -> Identity:
    decl = next((i for i in scope.identities if i["name"] == name), None)
    if decl is None:
        raise AccountError(f"{scope.program}: no identity {name!r} in the scope file")
    return Identity(scope.program, name, decl, scope)


# ---------------------------------------------------------------- the gate side
def _board(board):
    if board is not None:
        return board
    from bh.board import Board

    return Board()


def check_active(program: str) -> None:
    """The gate judges and injects for its active scope only: another program's scope would deny the targets
    or resolve X-BH-Identity in the wrong directory."""
    try:
        active = (yaml.safe_load(paths.active_scope().read_text(encoding="utf-8")) or {}).get("program")
    except (OSError, yaml.YAMLError, AttributeError):
        active = None
    if active != program:
        raise AccountError(f"the gate's active scope is {active or 'none'}, not {program}")


def _scrub(text: str, *secret_values: str | None) -> str:
    for v in secret_values:
        if v and len(v) >= 4:
            text = text.replace(v, "<redacted>")
    return text


def run_steps(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run the steps in the gate; one record per step run. Raises AccountError (one line) on any failure of the
    script itself."""
    payload = json.dumps({"proxy": GATE_PROXY, "cafile": GATE_CA, "timeout": REQUEST_TIMEOUT_S, "steps": steps})
    script = GATE_SCRIPT + f"\nmain({payload!r})\n"
    try:
        r = stack.gate_python(script, timeout=REQUEST_TIMEOUT_S * len(steps) + 15)
    except subprocess.TimeoutExpired:
        raise AccountError(f"the gate script timed out ({len(steps)} request(s))") from None
    except OSError as exc:
        raise AccountError(f"cannot run podman: {exc.strerror or type(exc).__name__}") from None
    try:
        out = json.loads(r.stdout)
        if not isinstance(out, list):
            raise ValueError
    except ValueError:
        tail = (r.stderr or "").strip().splitlines()[-1:] or ["no output"]
        raise AccountError(f"the gate script failed (rc {r.returncode}): {tail[0][:160]}") from None
    return out


def _why(rec: dict[str, Any] | None, what: str) -> str:
    if rec is None:
        return f"{what}: not run"
    if rec.get("error"):
        return f"{what}: {rec['error']}"
    if rec.get("gate"):
        return f"{what}: {rec['gate']}"
    return f"{what}: HTTP {rec.get('status')}"


# ---------------------------------------------------------------- probe
def expect_text(ident: Identity, template: str) -> str | None:
    """A probe's `expect` with `{email}` and `{name}` resolved on the host from the identity's credential (R43):
    the value goes to the gate script on stdin and nowhere else (never a log, a return value nor the session file,
    which keeps the template). None when a placeholder cannot be resolved."""
    if "{" not in template:
        return template
    cred = credential(ident) if "{email}" in template else {}
    values = _values(ident, cred or {})
    out = template
    for key in ("email", "name"):
        if "{" + key + "}" in out:
            if not values.get(key):
                return None
            out = out.replace("{" + key + "}", values[key])
    return out


def probe(ident: Identity) -> tuple[bool | None, str]:
    """Send the probe request under the identity (the gate injects its session): GET by default, or the declared
    `method` with its `headers` and `json` (R43). (True, detail) when the declared status comes back and the body
    holds `expect`; (False, detail) when the session is not accepted (a redirect is never followed: the status is
    the first answer's; a bearer the gate refuses as expired); (None, why) when nothing can be said: no probe
    declared, no session file, an `expect` placeholder without its value. Another gate refusal or a network error
    raises. The body and the resolved `expect` are never logged nor returned."""
    pr = ident.probe
    if not pr:
        return None, "no probe declared"
    if not ident.session_file.is_file():
        return None, "no session"
    # X-BH-Probe: the gate lends the identity's session to this request (it comes from the gate's own loopback);
    # every other enrollment request logs in with its own credentials and never borrows a session
    headers = {**(pr.get("headers") or {}), "X-BH-Identity": ident.name, "X-BH-Probe": "1"}
    step = {"step": "probe", "method": pr.get("method") or "GET", "url": pr["url"], "headers": headers}
    if "json" in pr:
        step["json"] = pr["json"]
    if pr.get("expect"):
        expect = expect_text(ident, pr["expect"])
        if expect is None:
            return None, "the probe's expected text names a value the credential does not hold"
        step["expect"] = expect
    rec = run_steps([step])[0]
    if rec.get("gate") and "identity bearer expired" in rec["gate"]:
        return False, "identity bearer expired"  # the gate withheld it: a new login renews it
    if rec.get("error") or rec.get("gate"):
        raise AccountError(_why(rec, "probe"))
    ok = rec.get("status") == pr["status"] and rec.get("match", True)
    detail = f"HTTP {rec.get('status')}" + ("" if rec.get("match", True) else ", expected text missing")
    return bool(ok), detail


# ---------------------------------------------------------------- session file
def _jwt_exp(token: str) -> float | None:  # kept for callers of the first version
    return expiry.jwt_exp(token)


def _take(board, key: str, every: float, what: str, now: float) -> None:
    try:
        last = float(board.meta_get(key, "0") or 0)
    except ValueError:
        last = 0.0
    if now - last < every:
        raise AccountError(f"{what} already tried {int((now - last) // 60)} min ago (at most one per hour)")
    board.meta_set(key, str(now))


def _save_session(ident: Identity, sess: dict[str, Any]) -> None:
    f = ident.session_file
    f.parent.mkdir(parents=True, exist_ok=True)
    with session.lock(f):
        session.save(f, sess)


def _new_session(ident: Identity, headers: dict[str, str], now: float) -> dict[str, Any]:
    return {
        "headers": headers,
        "origin_headers": {},
        "cookies": {},
        "expires_at": None,
        # the probe's URL, status and method; never its `expect` (a template that may name the account)
        "probe": (
            {"url": ident.probe["url"], "status": ident.probe["status"]}
            | ({"method": ident.probe["method"]} if ident.probe.get("method") else {})
            if ident.probe
            else None
        ),
        "updated": round(now, 3),
    }


def _write_session(ident: Identity, recipe: dict[str, Any], token: str | None, set_cookies: list[str]) -> None:
    """json kind: the recipe's headers with the login's token, the login answer's cookies."""
    now = time.time()
    if token is not None and not rc.TOKEN.fullmatch(token):
        raise AccountError("login: token refused (not 1-4096 printable ASCII characters)")
    sess = _new_session(ident, rc.render(recipe["headers"], {"token": token} if token else {}), now)
    session.merge(sess, recipe["login"]["url"], set_cookies, now)
    sess["expires_at"] = expiry.known(tokens=[token], jar=sess["cookies"], now=now)
    _save_session(ident, sess)


# ---------------------------------------------------------------- credentials
def credential(ident: Identity) -> dict[str, Any] | None:
    """What the identity logs in with: email + password (json, browser), a refresh token (oauth_refresh)."""
    if ident.kind == "oauth_refresh":
        doc = secrets.load_raw(ident.program, ident.name)
        return doc if doc and isinstance(doc.get("refresh_token"), str) and doc["refresh_token"] else None
    return secrets.load(ident.program, ident.name)


def _secret_values(cred: dict[str, Any]) -> list[str | None]:
    vals = [cred.get(k) for k in ("password", "answer", "refresh_token", "client_secret")]
    t = cred.get("totp")
    vals.append(t if isinstance(t, str) else t.get("secret") if isinstance(t, dict) else None)
    return [v for v in vals if isinstance(v, str)]


def _values(ident: Identity, cred: dict[str, Any]) -> dict[str, str]:
    return {
        "email": cred.get("email", ""),
        "password": cred.get("password", ""),
        "answer": cred.get("answer", ""),
        "code_to": cred.get("code_to") or cred.get("email", ""),  # sites ask to retype it before mailing a code
        "name": ident.name,
    }


# ---------------------------------------------------------------- json
def _login_json(ident: Identity, cred: dict[str, Any], *, signup: bool) -> None:
    recipe = ident.recipe
    assert recipe is not None
    values = _values(ident, cred)
    steps = []
    if signup:
        steps.append({"step": "signup", **rc.render_request(recipe["signup"], values)})
    login = {"step": "login", **rc.render_request(recipe["login"], values), "cookies": True, "required": True}
    if "token" in recipe:
        login["token_path"] = recipe["token"]
    steps.append(login)
    recs = {r["step"]: r for r in run_steps(steps)}
    rec = recs.get("login")
    if rec is None or rec.get("error") or rec.get("gate") or not 200 <= rec.get("status", 0) < 300:
        extra = f" ({_why(recs.get('signup'), 'signup')})" if signup else ""
        raise AccountError(_why(rec, "login") + extra)
    token = rec.get("token")
    if "token" in recipe and not token:
        raise AccountError(f"login: HTTP {rec.get('status')} but no token at {recipe['token']!r}")
    if token is not None and not (isinstance(token, str) and rc.TOKEN.fullmatch(token)):
        raise AccountError(
            f"login: the token at {recipe['token']!r} is not 1-4096 printable ASCII characters (refused)"
        )
    if not token and not rec.get("set_cookies"):
        raise AccountError("login: no token and no cookie in the answer")
    _write_session(ident, recipe, token, rec.get("set_cookies") or [])


# ---------------------------------------------------------------- browser
def _host_ok(ident: Identity, host: str) -> bool:
    """A cookie domain the session may keep: in scope, the host of a URL the identity itself declares, or an `sso`
    support host (or a parent domain of one): the application signs in silently there while in use, and the gate
    hands the identity's own cookies to that host only (bh.gate.addon)."""
    from bh.scope.enforce import check

    if not host or is_public_suffix(host):
        return False
    if ident.scope is not None and check(ident.scope, host):
        return True
    if ident.scope is not None and any(h == host or h.endswith("." + host) for h in ident.scope.support_hosts("sso")):
        return True
    own = [u for _, u in rc.urls(ident.recipe)] + list(ident.decl.get("origins") or [])
    return any((o := origin(u)) and o.split("://", 1)[1].rsplit(":", 1)[0].strip("[]") == host for u in own)


def _is_target(scope: Scope, url: str) -> bool:
    """R1: an origin (scheme://host:port) is a target when the scope covers it, or when an in-scope URL rule of the
    same scheme and port covers its host (`https://substrate.office.com/m365Copilot/` and the origin
    `https://substrate.office.com:443`): the bearer seen there is kept for that origin only, and the gate still
    judges every request on its full URL."""
    from bh.scope.model import origin_covered

    return origin_covered(scope, url)


def browser_jar(ident: Identity, cookies: list[dict[str, Any]], now: float) -> dict[str, dict[str, Any]]:
    """`context.cookies()` as a session jar: in-scope domains only, values a Cookie header can carry, bounded."""
    jar: dict[str, dict[str, Any]] = {}
    for c in cookies:
        if not isinstance(c, dict):
            continue
        name, value, dom = c.get("name"), c.get("value"), c.get("domain")
        if not (isinstance(name, str) and isinstance(value, str) and isinstance(dom, str)):
            continue
        if not session._TOKEN.fullmatch(name) or not rc.COOKIE_VALUE.fullmatch(value):
            continue
        host = dom.lstrip(".").lower()
        if not _host_ok(ident, host):
            continue
        exp = c.get("expires")
        exp = float(exp) if isinstance(exp, (int, float)) and not isinstance(exp, bool) and exp > 0 else None
        if exp is not None and exp <= now:
            continue
        cookies_of = jar.setdefault(host, {}) if host in jar or len(jar) < session.MAX_DOMAINS else None
        if cookies_of is None or (name not in cookies_of and len(cookies_of) >= session.MAX_COOKIES_PER_DOMAIN):
            continue
        path = c.get("path")
        cookies_of[name] = {
            "value": value,
            "path": path if isinstance(path, str) and path.startswith("/") else "/",
            "expires": exp,
            "host_only": not dom.startswith("."),
            "secure": c.get("secure") is True,
        }
    return jar


def browser_session(ident: Identity, result: dict[str, Any], now: float) -> dict[str, Any]:
    """The session a browser login's result makes (pure: tested without a browser). Raises AccountError."""
    recipe = ident.recipe
    assert recipe is not None
    cap = recipe["capture"]
    headers: dict[str, str] = {}
    tokens: list[str] = []
    auth, auth_url = result.get("authorization"), result.get("authorization_url")
    if cap["authorization"] and isinstance(auth, str) and auth:
        if not rc.HEADER_VALUE.fullmatch(auth):
            raise AccountError("login: the Authorization header seen is not printable ASCII (refused)")
        host = (
            (origin(auth_url) or "").split("://", 1)[-1].rsplit(":", 1)[0].strip("[]")
            if isinstance(auth_url, str)
            else ""
        )
        if _host_ok(ident, host):
            headers["Authorization"] = auth
            tokens.append(auth)
    origin_headers: dict[str, dict[str, str]] = {}
    per_origin = result.get("authorizations") if isinstance(result.get("authorizations"), dict) else {}
    if cap["authorization"]:
        for o, value in per_origin.items():
            if len(origin_headers) >= session.MAX_ORIGIN_HEADERS:
                break
            if not isinstance(o, str) or origin(o) != o or not isinstance(value, str) or not value:
                continue
            if not rc.HEADER_VALUE.fullmatch(value):
                raise AccountError("login: an Authorization header seen is not printable ASCII (refused)")
            # a target only: an identity's header never goes to a support host (sso, auth) nor out of scope
            if ident.scope is None or not _is_target(ident.scope, o):
                continue
            origin_headers[o] = {"Authorization": value}
            tokens.append(value)
    missing = [o for o in rc.auth_origins(recipe) if o not in origin_headers]
    if missing:
        raise AccountError(f"login: no Authorization seen on {', '.join(missing)} (capture.authorization_origins)")
    ls = result.get("local_storage") if isinstance(result.get("local_storage"), dict) else {}
    for key, hdrs in cap["local_storage"].items():
        v = ls.get(key)
        if not isinstance(v, str) or not v:
            raise AccountError(f"login: localStorage {key!r} is empty after the steps")
        if not rc.TOKEN.fullmatch(v):
            raise AccountError(f"login: localStorage {key!r} is not 1-4096 printable ASCII characters (refused)")
        tokens.append(v)
        for name, tmpl in hdrs.items():
            headers[name] = rc.render(tmpl, {"value": v})
    sess = _new_session(ident, headers, now)
    sess["origin_headers"] = origin_headers
    if cap["cookies"]:
        sess["cookies"] = browser_jar(ident, result.get("cookies") or [], now)
    if not headers and not sess["cookies"] and not origin_headers:
        raise AccountError("login: the browser ended with no cookie and no header to keep")
    sess["expires_at"] = expiry.known(tokens=tokens, jar=sess["cookies"], now=now)
    return sess


def _asker(ident: Identity, cred: dict[str, Any], steps: list[dict[str, Any]], since: float, notes: list[str]):
    """Answers the login script's questions: a TOTP code, a mailed code. A failure is noted, the answer is None."""

    def ask(msg: dict[str, Any]) -> str | None:
        need = msg.get("need")
        if need == "totp":
            if not cred.get("totp"):
                notes.append("no TOTP seed in the secrets file")
                return None
            try:
                return totp.fresh_code(totp.params(cred["totp"]))
            except totp.TotpError as exc:
                notes.append(f"totp: {exc}")
                return None
        if need == "email_code":
            i = msg.get("step")
            step = steps[i] if isinstance(i, int) and 0 <= i < len(steps) else {}
            if step.get("action") != "email_code":
                notes.append("email_code asked for a step that is not one")
                return None
            wait = min(step.get("timeout", browser.EMAIL_WAIT_S), browser.EMAIL_WAIT_S)
            try:
                # codes may go to another inbox than the account's address (`code_to`, from `bh accounts set`)
                code = mail.default().wait(cred.get("code_to") or cred["email"], step["from"], since, wait, want="code")
            except mail.MailError as exc:
                notes.append(f"mailbox: {exc}")
                return None
            if code is None:
                notes.append(f"no mail from {step['from']} within {int(wait)} s (or no mailbox configured)")
                return None
            if not re.fullmatch(r"\d{4,10}", code):
                notes.append("the mail holds a link, not a code")
                return None
            return code
        notes.append(f"unknown question {str(need)[:30]!r}")
        return None

    return ask


def _login_browser(ident: Identity, cred: dict[str, Any], *, signup: bool) -> None:
    recipe = ident.recipe
    assert recipe is not None
    values = _values(ident, cred)
    if signup:
        rec = run_steps([{"step": "signup", **rc.render_request(recipe["signup"], values)}])[0]
        if rec.get("error") or rec.get("gate") or not 200 <= rec.get("status", 0) < 400:
            raise AccountError(_why(rec, "signup"))
    steps = [{**s, "value": rc.render(s["value"], values)} if "value" in s else dict(s) for s in recipe["steps"]]
    notes: list[str] = []
    started = time.time() - 30
    try:
        result = browser.execute(
            {"steps": steps, "capture": recipe["capture"]}, _asker(ident, cred, recipe["steps"], started, notes)
        )
    except browser.BrowserError as exc:
        raise AccountError(f"browser login: {exc}" + (f" ({'; '.join(notes)})" if notes else "")) from None
    sess = browser_session(ident, result, time.time())
    _save_session(ident, sess)


# ---------------------------------------------------------------- oauth_refresh
OAUTH_PATHS = {
    "access_token": "access_token",
    "refresh_token": "refresh_token",
    "expires_in": "expires_in",
    "error": "error",
}


def _login_oauth(ident: Identity, cred: dict[str, Any]) -> None:
    recipe = ident.recipe
    assert recipe is not None
    form = {"grant_type": "refresh_token", "refresh_token": cred["refresh_token"], "client_id": recipe["client_id"]}
    if recipe.get("scope"):
        form["scope"] = recipe["scope"]
    if isinstance(cred.get("client_secret"), str) and cred["client_secret"]:
        form["client_secret"] = cred["client_secret"]
    step = {
        "step": "token",
        "method": "POST",
        "url": recipe["token_url"],
        "form": form,
        "token_paths": OAUTH_PATHS,
        "required": True,
    }
    rec = run_steps([step])[0]
    vals = rec.get("tokens") if isinstance(rec.get("tokens"), dict) else {}
    if rec.get("error") or rec.get("gate") or not 200 <= rec.get("status", 0) < 300:
        err = vals.get("error")
        code = f" ({err})" if isinstance(err, str) and re.fullmatch(r"[a-z_]{1,40}", err) else ""
        raise AccountError(_why(rec, "token refresh") + code)
    access = vals.get("access_token")
    if not isinstance(access, str) or not rc.TOKEN.fullmatch(access):
        raise AccountError("token refresh: no access_token of 1-4096 printable ASCII characters in the answer")
    now = time.time()
    new_rt = vals.get("refresh_token")
    if isinstance(new_rt, str) and new_rt != cred["refresh_token"]:
        if not rc.TOKEN.fullmatch(new_rt):
            raise AccountError("token refresh: the new refresh_token is not printable ASCII (refused, old one kept)")
        # rotated by the server: the old one may be dead already, so the new one is on disk before anything else
        secrets.save(ident.program, ident.name, {**cred, "refresh_token": new_rt, "rotated": round(now, 3)})
    sess = _new_session(ident, rc.render(recipe["headers"], {"access_token": access}), now)
    sess["expires_at"] = expiry.known(tokens=[access], expires_in=vals.get("expires_in"), now=now)
    _save_session(ident, sess)


# ---------------------------------------------------------------- login
def _login(ident: Identity, cred: dict[str, Any], *, signup: bool) -> None:
    """[sign-up,] log in, write the session: one pass over the recipe, each field filled once, never a retry here.
    Raises AccountError with its `cause` (T51), never with a secret in it."""
    try:
        if ident.kind == "oauth_refresh":
            _login_oauth(ident, cred)
        elif ident.kind == "browser":
            _login_browser(ident, cred, signup=signup)
        else:
            _login_json(ident, cred, signup=signup)
    except (AccountError, rc.RecipeError) as exc:
        raise _caused(_scrub(str(exc), *_secret_values(cred)), login_cause(ident.recipe, str(exc))) from None


# ---------------------------------------------------------------- why a login failed (T51)
CAUSES = ("ok", "credentials", "totp", "out-of-band", "challenge", "unknown")
# What the failed page or answer shows (the login script's `where`: URL, title, visible field names and button labels,
# never a value; or the HTTP status and the OAuth error code). Matched in this order.
_CHALLENGE = re.compile(
    r"captcha|turnstile|cf-chl|cf-mitigated|just a moment|challenge|\brobot\b|are you (a )?human|verify (that )?you|"
    r"bot (check|detection)|HTTP 429\b|too many (requests|attempts)",
    re.I,
)
_OUT_OF_BAND = re.compile(
    r"email_code|no mail from|mailbox|the mail holds a link|\bsms\b|text message|phone|\bpush\b|approve|"
    r"check your (e-?mail|inbox)|magic link|verification (e-?mail|link)|interaction_required|consent_required",
    re.I,
)
_TOTP = re.compile(r"\btotp\b|authenticator|one[- ]time|\b2fa\b|two[- ]factor|\bmfa\b|\botp\b|security code", re.I)
_PASSWORD_FIELD = re.compile(r"type=password", re.I)
_REJECTED = re.compile(
    r"HTTP (400|401|422)\b|invalid_grant|unauthorized_client|invalid_client|no credential stored|"
    r"no refresh token stored|(invalid|incorrect|wrong) (e-?mail|password|credentials|user)",
    re.I,
)
_STEP = re.compile(r"step \d+ \((\w+)\): (.*)", re.S)


def login_cause(recipe: dict[str, Any] | None, message: str) -> str:
    """The closed cause (CAUSES, never `ok`) of a failed login, from what the recipe's single pass returned: the
    failing step's action and the page it stopped on (browser), the status or OAuth error code (json,
    oauth_refresh). Pure."""
    m = _STEP.search(message)
    action, rest = (m.group(1), m.group(2)) if m else (None, message)
    has_totp = any(s.get("action") == "totp" for s in (recipe or {}).get("steps") or ())
    if _CHALLENGE.search(rest):
        return "challenge"
    if action == "email_code":
        return "out-of-band"
    if action == "totp":
        if "no code from the host" in rest or "TOTP" in message or "totp:" in message:
            return "totp"  # the field was there and no code could be computed: the seed
        return "credentials" if _PASSWORD_FIELD.search(rest) else "totp"  # never got to the code's page
    if "no TOTP seed" in message or message.startswith("totp:"):
        return "totp"
    if _OUT_OF_BAND.search(rest):
        return "out-of-band"
    if _TOTP.search(rest) and not has_totp:
        return "totp"  # the site asks for a second factor the recipe does not answer
    if _REJECTED.search(rest):
        return "credentials"
    if action is not None and _PASSWORD_FIELD.search(rest):
        return "credentials"  # still on a page with a password field after the submit: the password was refused
    return "unknown"


def _caused(message: str, cause: str) -> AccountError:
    return AccountError(f"[{cause}] {message}", cause=cause)


def _with_cause(fn):
    """Every AccountError out of a login entry point carries a cause: the runner posts it as a `login-failed`
    blocker (T51). One raised before any login (a limit, the gate's scope, a probe the gate refused) is `unknown`."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except AccountError as exc:
            if exc.cause is not None:
                raise
            raise _caused(str(exc), "unknown") from None

    return wrapper


def _confirmed(ident: Identity) -> str:
    """After a login: the probe must accept the new session."""
    ok, detail = probe(ident)
    if ok is False:
        raise _caused(f"logged in, but the probe refuses the session ({detail})", "unknown")
    return "probe ok" if ok else detail


def _no_credential(ident: Identity) -> AccountError:
    if ident.kind == "oauth_refresh":
        return _caused(
            f"{ident.name}: no refresh token stored; deposit it once (onboarding) in "
            f'secrets/identities/{ident.program}/{ident.name}.json as {{"refresh_token": ...}}',
            "credentials",
        )
    return _caused(f"{ident.name}: no credential stored and no 'signup' recipe", "credentials")


def _stamp_login(board, ident: Identity, now: float, force: bool) -> None:
    key = f"accounts-login:{ident.name}:{ident.program}"
    if force:
        board.meta_set(key, str(now))
    else:
        _take(board, key, LOGIN_EVERY_S, "login", now)


@_with_cause
def enroll(scope: Scope, name: str, *, board=None, force: bool = False) -> str:
    """Create the account if the program allows it and the identity has no credential, then log in and check.
    `force` lifts the hourly login limit (operator command), never the one-account rule. Returns a summary."""
    ident = identity(scope, name)
    if not ident.recipe:
        raise AccountError(f"{name}: no 'enroll' recipe in the scope file")
    check_active(scope.program)
    board = _board(board)
    now = time.time()
    cred, signup = credential(ident), False
    if cred is None:
        if ident.kind == "oauth_refresh" or "signup" not in ident.recipe:
            raise _no_credential(ident)
        if scope.self_signup is not True:
            raise AccountError(f"{scope.program}: self_signup is not true, no account is created")
        _take(board, f"accounts-signup:{name}:{scope.program}", SIGNUP_EVERY_S, "sign-up", now)
        cred = secrets.new(ident.recipe["email"], name)
        secrets.save(scope.program, name, cred)  # before the sign-up: a crash must not lose a live account
        signup = True
    _stamp_login(board, ident, now, force)
    _login(ident, cred, signup=signup)
    done = "token refreshed, " if ident.kind == "oauth_refresh" else "logged in, "
    return ("signed up, " if signup else "") + done + _confirmed(ident)


def diagnose(scope: Scope, name: str, *, board=None) -> str:
    """Why `name` cannot log in, one word of CAUSES (`bh accounts check`): one pass of the recipe, each field filled
    once and never twice (no sign-up, no second attempt), then the probe. `ok` when the probe accepts the new
    session (or none is declared). The login is stamped like a forced one (the runner does not retry at once); the
    session it gets is kept. No secret, no page content in the answer: the word only."""
    ident = identity(scope, name)
    if not ident.recipe:
        return "unknown"
    check_active(scope.program)
    board = _board(board)
    cred = credential(ident)
    if cred is None:
        return "credentials"
    _stamp_login(board, ident, time.time(), True)
    try:
        _login(ident, cred, signup=False)
        ok, _ = probe(ident)
    except AccountError as exc:
        return exc.cause if exc.cause in CAUSES else "unknown"
    return "unknown" if ok is False else "ok"


def _stale(board, ident: Identity) -> bool:
    try:
        mark = float(board.meta_get(f"identity-stale:{ident.name}:{ident.program}", "0") or 0)
    except ValueError:
        mark = 0.0
    f = ident.session_file
    return mark > (f.stat().st_mtime if f.exists() else 0.0)


@_with_cause
def refresh(scope: Scope, name: str, *, board=None, force: bool = False, probe_first: bool = True) -> str:
    """Probe first: a good session is only touched (`updated`), which lifts a false `identity-stale` mark.
    Otherwise log in with the stored credential; if that fails and the program allows sign-up, sign the same
    account up again (a lab that lost its database) and log in; with no credential, enroll.
    `probe_first=False` (the keeper, before a known expiry) logs in at once."""
    ident = identity(scope, name)
    if not ident.recipe:
        raise AccountError(f"{name}: no 'enroll' recipe in the scope file")
    check_active(scope.program)
    board = _board(board)
    if probe_first:
        ok, _ = probe(ident)
        if ok or (ok is None and ident.session_file.is_file() and not ident.probe and not _stale(board, ident)):
            session.update(ident.session_file, lambda s: True)
            return "session ok" if ok else "session kept (no probe declared)"
    cred = credential(ident)
    if cred is None:
        return enroll(scope, name, board=board, force=force)
    now = time.time()
    _stamp_login(board, ident, now, force)
    done = "token refreshed, " if ident.kind == "oauth_refresh" else "logged in, "
    try:
        _login(ident, cred, signup=False)
        return done + _confirmed(ident)
    except AccountError as first:
        if scope.self_signup is not True or "signup" not in ident.recipe:
            raise
        try:
            _take(board, f"accounts-signup:{name}:{scope.program}", SIGNUP_EVERY_S, "sign-up", now)
        except AccountError:
            raise first from None
        _login(ident, cred, signup=True)
        return "signed up again, logged in, " + _confirmed(ident)


def status(scope: Scope, name: str, *, board=None, live: bool = True) -> dict[str, Any]:
    """What `bh accounts ls` shows for one identity: no secret, no session value."""
    board = _board(board)
    ident = identity(scope, name)
    f = ident.session_file
    sess = session.load(f) if f.is_file() else None
    row: dict[str, Any] = {
        "name": name,
        "recipe": bool(ident.recipe),
        "credential": credential(ident) is not None,
        "session_age_s": int(time.time() - f.stat().st_mtime) if sess is not None else None,
        "expires_in_s": int(sess["expires_at"] - time.time()) if sess and sess.get("expires_at") else None,
        "stale": _stale(board, ident),
        "probe": "-",
    }
    if live and sess is not None and ident.probe:
        try:
            ok, detail = probe(ident)
            row["probe"] = ("ok" if ok else "FAIL") + f" ({detail})"
        except AccountError as exc:
            row["probe"] = f"? ({exc})"
    elif sess is None:
        row["probe"] = "no session"
    return row
