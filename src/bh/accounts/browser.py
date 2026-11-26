"""Browser logins: a `kind: browser` recipe run by headless Chromium in the `bh-login` container, driven by the host.

The container (compose service `login`) is the agent's image on the `sandbox` network only, HTTPS_PROXY=gate:8080:
every request of the login goes through the gate (scope, rate, required headers), like the agent's. It has no
/work, no Claude relay, no secret at rest. The host:

1. kills every process of the login user and wipes what a previous login left (`stack.reset_login`);
2. runs `python3 -I -c BOOT` there: the script below and then the payload (steps with their values rendered, so
   the password) travel on stdin, never in argv or the environment;
3. answers the script's questions on the same pipe: `{"need": "totp"}` gets the current RFC 6238 code (the seed
   stays on the host), `{"need": "email_code"}` the code read by the host's mailbox (bh.accounts.mail);
4. reads back `{"result": {...}}`: cookies of the context, the first Authorization header seen on a request, the
   last Authorization seen per origin (`authorizations`, I19: each origin's audience), the declared localStorage
   keys. The host turns that into the session file (bh.accounts.enroll).

The script makes a fresh HOME (and TMPDIR, so Chromium's profile lands there too) per login, trusts the gate CA in
that HOME's NSS database, and deletes it all on exit. A message from the script never carries a value: errors
name the step, the action and the kind of failure.
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import tempfile
import threading
from collections.abc import Callable
from typing import Any

from bh import stack

GATE_PROXY = "http://gate:8080"
GATE_CA = "/gate-ca/mitmproxy-ca-cert.pem"
LOGIN_TIMEOUT_S = 360  # a mailed code alone may take two minutes to arrive
STEP_TIMEOUT_S = 15
AUTH_WAIT_S = 8  # after the last step: how long to wait for a first authenticated request
EMAIL_WAIT_S = 120  # how long the host waits for a mailed code
ASK_SLACK_S = EMAIL_WAIT_S + 30

# argv of the container process: reads `<length>\n<script>` from stdin, then runs it (the payload follows).
BOOT = "import sys;n=int(sys.stdin.readline());exec(compile(sys.stdin.read(n),'<bh-login>','exec'))"

# Runs in bh-login (python3 -I). Stdlib + playwright (the agent image's). The protocol goes on a dup of fd 1;
# sys.stdout points at stderr so that nothing else can write a line the host would parse.
LOGIN_SCRIPT = r"""
import json, os, shutil, subprocess, sys, tempfile, time
from urllib.parse import urlsplit

OUT = os.fdopen(os.dup(1), "w", buffering=1)
sys.stdout = sys.stderr
HEAVY = {"image", "font", "media"}


class Fail(Exception):
    pass


MAX_ORIGINS = 16


def origin_of(url):
    try:
        p = urlsplit(url)
        port = p.port
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or not p.hostname:
        return None
    host = "[" + p.hostname + "]" if ":" in p.hostname else p.hostname.lower()
    return p.scheme + "://" + host + ":" + str(port or (443 if p.scheme == "https" else 80))


def emit(obj):
    OUT.write(json.dumps(obj) + "\n")
    OUT.flush()


def ask(what, i):
    emit({"need": what, "step": i})
    try:
        v = json.loads(sys.stdin.readline() or "null")
    except ValueError:
        v = None
    v = v.get("value") if isinstance(v, dict) else None
    return v if isinstance(v, str) and v else None


def trust(home, ca):
    for db in (home + "/.local/share/pki/nssdb", home + "/.pki/nssdb"):
        os.makedirs(db, 0o700)
        subprocess.run(["certutil", "-d", "sql:" + db, "-N", "--empty-password"], check=True, capture_output=True)
        subprocess.run(["certutil", "-d", "sql:" + db, "-A", "-t", "C,,", "-n", "bh-gate", "-i", ca],
                       check=True, capture_output=True)


# Where a failed login stopped, to fix the recipe: URL, title, visible fields (type/name/id) and button labels.
# Never a field's value: the page holds the password that was typed.
WHERE_JS = (
    '() => { const vis = e => !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length);'
    " const f = Array.from(document.querySelectorAll('input,textarea,select')).filter(vis).slic"
    "e(0, 8).map(e => e.tagName.toLowerCase() + '[type=' + (e.type || '') + (e.name ? ',name=' "
    "+ e.name : '') + (e.id ? ',id=' + e.id : '') + ']'); const b = Array.from(document.querySe"
    "lectorAll('button,[role=button],input[type=submit],a')).filter(vis).slice(0, 12).map(e => "
    "(e.innerText || e.value || e.id || '').trim().split(String.fromCharCode(10)).join(' ').sli"
    'ce(0, 30)).filter(x => x); return {fields: f, buttons: b}; }'
)


def where(page):
    try:
        d = page.evaluate(WHERE_JS)
        return ('at ' + page.url[:120] + ' title ' + repr(page.title()[:60]) + ' fields '
                + repr(d.get('fields')) + ' buttons ' + repr(d.get('buttons')))[:900]
    except Exception:
        return 'at (page unavailable)'


def run(p, home):
    from playwright.sync_api import Error as PwError
    from playwright.sync_api import TimeoutError as PwTimeout
    from playwright.sync_api import sync_playwright

    deadline = time.monotonic() + p["timeout"]
    auth = {}
    per_origin = {}

    def on_request(req):
        h = req.headers.get("authorization")
        if not h:
            return
        if "value" not in auth:
            auth["value"], auth["url"] = h, req.url
        o = origin_of(req.url)
        if o and (o in per_origin or len(per_origin) < MAX_ORIGINS):
            per_origin[o] = h  # the latest: a token refreshed during the login replaces the first

    def route(r):
        if r.request.resource_type in HEAVY:
            r.abort()
        else:
            r.continue_()

    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=True,
            proxy={"server": p["proxy"]},
            args=["--no-pings", "--disable-domain-reliability", "--disable-dev-shm-usage"],
            env=dict(os.environ),
        )
        try:
            ctx = browser.new_context(service_workers="block", viewport={"width": 1280, "height": 900})
            ctx.on("request", on_request)
            ctx.route("**/*", route)
            page = ctx.new_page()
            for i, s in enumerate(p["steps"]):
                a = s["action"]
                left = deadline - time.monotonic()
                if left < 1:
                    raise Fail(f"step {i} ({a}): login deadline reached")
                t = min(s.get("timeout", p["step_timeout"]), left) * 1000
                try:
                    if a == "goto":
                        page.goto(s["url"], wait_until="domcontentloaded", timeout=t)
                    elif a == "fill":
                        page.fill(s["selector"], s["value"], timeout=t)
                    elif a == "select":
                        page.select_option(s["selector"], s["value"], timeout=t)
                    elif a == "click":
                        page.click(s["selector"], timeout=t)
                    elif a == "wait_for" and "selector" in s:
                        page.wait_for_selector(s["selector"], timeout=t)
                    elif a == "wait_for":
                        end = time.monotonic() + t / 1000
                        while s["url"] not in page.url:
                            if time.monotonic() > end:
                                raise PwTimeout("url")
                            page.wait_for_timeout(200)
                    elif a in ("totp", "email_code"):
                        page.wait_for_selector(s["selector"], timeout=t)  # the field first: a fresh code
                        v = ask(a, i)
                        if v is None:
                            raise Fail(f"step {i} ({a}): no code from the host")
                        # typed, not filled: split code boxes (one digit each) move the focus themselves
                        page.locator(s["selector"]).first.click(timeout=t)
                        page.keyboard.type(v, delay=60)
                except PwTimeout:
                    if s.get("optional"):
                        continue
                    raise Fail(f"step {i} ({a}): timeout | {where(page)}") from None
                except PwError as e:
                    first = (str(e).strip().splitlines() or ["error"])[0][:160]
                    raise Fail(f"step {i} ({a}): {first} | {where(page)}") from None
            cap = p["capture"]
            if cap["authorization"]:
                end = time.monotonic() + max(0.0, min(p["auth_wait"], deadline - time.monotonic()))
                wanted = cap.get("authorization_origins") or []
                while time.monotonic() < end and (
                    "value" not in auth or any(o not in per_origin for o in wanted)
                ):
                    page.wait_for_timeout(250)
            cookies = ctx.cookies() if cap["cookies"] else []
            ls = {}
            for k in cap["local_storage"]:
                try:
                    v = page.evaluate("k => window.localStorage.getItem(k)", k)
                except PwError:
                    v = None
                ls[k] = v if isinstance(v, str) else None
            final = page.url
        finally:
            browser.close()
    return {
        "cookies": [
            {k: c.get(k) for k in ("name", "value", "domain", "path", "expires", "secure")} for c in cookies
        ],
        "authorization": auth.get("value"),
        "authorization_url": auth.get("url"),
        "authorizations": per_origin if p["capture"]["authorization"] else {},
        "local_storage": ls,
        "final_url": final,
    }


def main():
    p = json.loads(sys.stdin.readline())
    home = tempfile.mkdtemp(prefix="bh-login-")
    try:
        os.environ.update(HOME=home, TMPDIR=home, XDG_CONFIG_HOME=home + "/.config", XDG_CACHE_HOME=home + "/.cache")
        tempfile.tempdir = home
        try:
            trust(home, p["ca"])
        except (OSError, subprocess.CalledProcessError) as e:
            raise Fail("cannot trust the gate CA: " + type(e).__name__) from None
        emit({"result": run(p, home)})
    except Fail as e:
        emit({"error": str(e)})
    except Exception as e:
        emit({"error": "login script: " + type(e).__name__})
    finally:
        shutil.rmtree(home, ignore_errors=True)


main()
"""


class BrowserError(RuntimeError):
    """The browser login failed. One line, no value (the caller still scrubs the credential out of it)."""


Ask = Callable[[dict[str, Any]], str | None]


def execute(payload: dict[str, Any], ask: Ask, timeout: float = LOGIN_TIMEOUT_S) -> dict[str, Any]:
    """Run one browser login in bh-login: `payload` = {steps, capture} (values rendered), `ask` answers the
    script's `need` messages. Returns the script's result. Raises BrowserError."""
    full = {
        "proxy": GATE_PROXY,
        "ca": GATE_CA,
        "timeout": timeout,
        "step_timeout": STEP_TIMEOUT_S,
        "auth_wait": AUTH_WAIT_S,
        **payload,
    }
    errf = tempfile.TemporaryFile("w+")  # noqa: SIM115 (closed in finally) Chromium's chatter: a pipe read only at the end could fill and block
    try:
        stack.reset_login()
        proc = stack.login_popen(["python3", "-I", "-c", BOOT], stderr=errf)
    except (OSError, subprocess.SubprocessError, SystemExit) as exc:
        errf.close()
        raise BrowserError(f"cannot start the login container: {str(exc)[:160]}") from None
    timed_out = threading.Event()

    def kill() -> None:
        timed_out.set()
        with contextlib.suppress(OSError):
            proc.kill()

    timer = threading.Timer(timeout + ASK_SLACK_S, kill)  # the script keeps its own deadline; this one is a backstop
    timer.start()
    try:
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write(f"{len(LOGIN_SCRIPT)}\n{LOGIN_SCRIPT}{json.dumps(full)}\n")
        proc.stdin.flush()
        for line in proc.stdout:
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if not isinstance(msg, dict):
                continue
            if "need" in msg:
                value = ask(msg)
                proc.stdin.write(json.dumps({"value": value}) + "\n")
                proc.stdin.flush()
            elif isinstance(msg.get("result"), dict):
                return msg["result"]
            elif "error" in msg:
                raise BrowserError(str(msg["error"])[:300])
        if timed_out.is_set():
            raise BrowserError(f"the browser login timed out ({int(timeout)} s)")
        proc.wait(timeout=10)
        errf.seek(0)
        err = errf.read()[-4000:].strip().splitlines()[-1:] or ["no output"]
        raise BrowserError(f"the login script ended without a result (rc {proc.returncode}): {err[0][:160]}")
    except (OSError, subprocess.SubprocessError) as exc:
        raise BrowserError(f"login container: {type(exc).__name__}") from None
    finally:
        timer.cancel()
        errf.close()
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=10)
        with contextlib.suppress(OSError, subprocess.SubprocessError, SystemExit):
            stack.reset_login()  # nothing of this login survives it, whatever happened
