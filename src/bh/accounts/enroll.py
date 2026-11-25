"""Sign up, log in and check the harness's own test accounts, without a human (issue 25).

The host owns the credential (`bh.accounts.secrets`) and the session file (`bh.gate.session` format). The HTTP
exchanges run in the gate, the only container that reaches the targets, as one stdlib script per call sent on
stdin (`stack.gate_python`), through the gate's own proxy (127.0.0.1:8080): scope, rate and required headers apply
as to any request. The credential travels inside that script on stdin, never in argv or the environment; the
script answers with statuses, the token and the Set-Cookie of the login, and the host writes the session.

Limits (board meta): one login per identity and hour (`accounts-login:<name>:<program>`), one sign-up per identity
and hour (`accounts-signup:...`), and a new account (a new address) only while the identity has no credential.
A password, an answer or a token never appears in a return value, a message or an exception.
"""

from __future__ import annotations

import base64
import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from bh import paths, stack
from bh.accounts import recipe as rc
from bh.accounts import secrets
from bh.gate import session
from bh.scope import Scope

LOGIN_EVERY_S = 3600
SIGNUP_EVERY_S = 3600
REQUEST_TIMEOUT_S = 15
GATE_PROXY = "http://127.0.0.1:8080"
GATE_CA = "/gate-ca/mitmproxy-ca-cert.pem"

# Runs in the gate (python3 -I -). Stdlib only: the gate's /opt/bh/src may be older than the host's code.
# Redirects are not followed (a form login sets its cookie on the 302). Bodies never leave the script: a step
# reports its status, whether `expect` was found, the token at `token_path` and, if asked, the Set-Cookie values.
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
            data, headers["Content-Type"] = json.dumps(s["json"]).encode(), "application/json"
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
            if "token_path" in s:
                try:
                    tok = _path(json.loads(body or b"null"), s["token_path"])
                except ValueError:
                    tok = None
                rec["token"] = tok if isinstance(tok, str) and tok else None
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
    """Enrollment failed. The message is one line and holds no credential or token."""


@dataclass(frozen=True)
class Identity:
    program: str
    name: str
    decl: dict[str, Any]

    @property
    def recipe(self) -> dict[str, Any] | None:
        return self.decl.get("enroll")

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
    return Identity(scope.program, name, decl)


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
def probe(ident: Identity) -> tuple[bool | None, str]:
    """GET the probe URL under the identity (the gate injects its session). (True, detail) when the declared
    status comes back and the body holds `expect`; (False, detail) when the session is not accepted; (None, why)
    when nothing can be said: no probe declared, no session file. A gate refusal or a network error raises."""
    pr = ident.probe
    if not pr:
        return None, "no probe declared"
    if not ident.session_file.is_file():
        return None, "no session"
    step = {"step": "probe", "method": "GET", "url": pr["url"], "headers": {"X-BH-Identity": ident.name}}
    if pr.get("expect"):
        step["expect"] = pr["expect"]
    rec = run_steps([step])[0]
    if rec.get("error") or rec.get("gate"):
        raise AccountError(_why(rec, "probe"))
    ok = rec.get("status") == pr["status"] and rec.get("match", True)
    detail = f"HTTP {rec.get('status')}" + ("" if rec.get("match", True) else ", expected text missing")
    return bool(ok), detail


# ---------------------------------------------------------------- login
def _jwt_exp(token: str) -> float | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, TypeError):
        return None
    exp = claims.get("exp") if isinstance(claims, dict) else None
    return float(exp) if isinstance(exp, (int, float)) and not isinstance(exp, bool) else None


def _take(board, key: str, every: float, what: str, now: float) -> None:
    try:
        last = float(board.meta_get(key, "0") or 0)
    except ValueError:
        last = 0.0
    if now - last < every:
        raise AccountError(f"{what} already tried {int((now - last) // 60)} min ago (at most one per hour)")
    board.meta_set(key, str(now))


def _write_session(ident: Identity, recipe: dict[str, Any], token: str | None, set_cookies: list[str]) -> None:
    now = time.time()
    headers = rc.render(recipe["headers"], {"token": token} if token else {})
    sess: dict[str, Any] = {
        "headers": headers,
        "cookies": {},
        "expires_at": _jwt_exp(token) if token else None,
        "probe": {"url": ident.probe["url"], "status": ident.probe["status"]} if ident.probe else None,
        "updated": round(now, 3),
    }
    session.merge(sess, recipe["login"]["url"], set_cookies, now)
    f = ident.session_file
    f.parent.mkdir(parents=True, exist_ok=True)
    with session.lock(f):
        session.save(f, sess)


def _login(ident: Identity, cred: dict[str, Any], *, signup: bool) -> None:
    """[sign-up,] log in, write the session. Raises AccountError."""
    recipe = ident.recipe
    assert recipe is not None
    values = {
        "email": cred["email"],
        "password": cred["password"],
        "answer": cred.get("answer", ""),
        "name": ident.name,
    }
    steps = []
    if signup:
        steps.append({"step": "signup", **rc.render_request(recipe["signup"], values)})
    login = {"step": "login", **rc.render_request(recipe["login"], values), "cookies": True, "required": True}
    if "token" in recipe:
        login["token_path"] = recipe["token"]
    steps.append(login)
    try:
        recs = {r["step"]: r for r in run_steps(steps)}
        rec = recs.get("login")
        if rec is None or rec.get("error") or rec.get("gate") or not 200 <= rec.get("status", 0) < 300:
            extra = f" ({_why(recs.get('signup'), 'signup')})" if signup else ""
            raise AccountError(_why(rec, "login") + extra)
        token = rec.get("token")
        if "token" in recipe and not token:
            raise AccountError(f"login: HTTP {rec.get('status')} but no token at {recipe['token']!r}")
        if not token and not rec.get("set_cookies"):
            raise AccountError("login: no token and no cookie in the answer")
        _write_session(ident, recipe, token, rec.get("set_cookies") or [])
    except (AccountError, rc.RecipeError) as exc:
        raise AccountError(_scrub(str(exc), cred["password"], cred.get("answer"))) from None


def _confirmed(ident: Identity) -> str:
    """After a login: the probe must accept the new session."""
    ok, detail = probe(ident)
    if ok is False:
        raise AccountError(f"logged in, but the probe refuses the session ({detail})")
    return "probe ok" if ok else detail


def enroll(scope: Scope, name: str, *, board=None, force: bool = False) -> str:
    """Create the account if the program allows it and the identity has no credential, then log in and check.
    `force` lifts the hourly login limit (operator command), never the one-account rule. Returns a summary."""
    ident = identity(scope, name)
    if not ident.recipe:
        raise AccountError(f"{name}: no 'enroll' recipe in the scope file")
    check_active(scope.program)
    board = _board(board)
    now = time.time()
    cred, signup = secrets.load(scope.program, name), False
    if cred is None:
        if scope.self_signup is not True:
            raise AccountError(f"{scope.program}: self_signup is not true, no account is created")
        if "signup" not in ident.recipe:
            raise AccountError(f"{name}: no credential stored and no 'signup' recipe")
        _take(board, f"accounts-signup:{name}:{scope.program}", SIGNUP_EVERY_S, "sign-up", now)
        cred = secrets.new(ident.recipe["email"], name)
        secrets.save(scope.program, name, cred)  # before the sign-up: a crash must not lose a live account
        signup = True
    if not force:
        _take(board, f"accounts-login:{name}:{scope.program}", LOGIN_EVERY_S, "login", now)
    else:
        board.meta_set(f"accounts-login:{name}:{scope.program}", str(now))
    _login(ident, cred, signup=signup)
    return ("signed up, logged in, " if signup else "logged in, ") + _confirmed(ident)


def _stale(board, ident: Identity) -> bool:
    try:
        mark = float(board.meta_get(f"identity-stale:{ident.name}:{ident.program}", "0") or 0)
    except ValueError:
        mark = 0.0
    f = ident.session_file
    return mark > (f.stat().st_mtime if f.exists() else 0.0)


def refresh(scope: Scope, name: str, *, board=None, force: bool = False) -> str:
    """Probe first: a good session is only touched (`updated`), which lifts a false `identity-stale` mark.
    Otherwise log in with the stored credential; if that fails and the program allows sign-up, sign the same
    account up again (a lab that lost its database) and log in; with no credential, enroll."""
    ident = identity(scope, name)
    if not ident.recipe:
        raise AccountError(f"{name}: no 'enroll' recipe in the scope file")
    check_active(scope.program)
    board = _board(board)
    ok, _ = probe(ident)
    if ok or (ok is None and ident.session_file.is_file() and not ident.probe and not _stale(board, ident)):
        session.update(ident.session_file, lambda s: True)
        return "session ok" if ok else "session kept (no probe declared)"
    cred = secrets.load(scope.program, name)
    if cred is None:
        return enroll(scope, name, board=board, force=force)
    now = time.time()
    if not force:
        _take(board, f"accounts-login:{name}:{scope.program}", LOGIN_EVERY_S, "login", now)
    else:
        board.meta_set(f"accounts-login:{name}:{scope.program}", str(now))
    try:
        _login(ident, cred, signup=False)
        return "logged in, " + _confirmed(ident)
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
        "credential": secrets.load(scope.program, name) is not None,
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
