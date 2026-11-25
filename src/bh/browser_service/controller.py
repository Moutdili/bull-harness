"""The browser controller, run in bh-browser (`python3 -m bh.browser_service serve`).

One process owns the display (Xvfb), the screen server (x11vnc, loopback), the Chromium (headful, persistent
profile, behind the gate) and one Playwright client attached over CDP (loopback). Two doors lead to it:

- the agent's API, HTTP on the sandbox network, `POST /op` with `Authorization: Bearer $BH_BROWSER_TOKEN`:
  goto, fill, click, press, text, wait, state. Never cookies, storage, raw CDP, script evaluation or screenshots.
- the host's control socket (RUN_DIR, 0700): reached only by `podman exec -i ... host`, JSON on stdin:
  load_session, status, reset, human_done.

The browser is the distribution's Chromium as it ships: no flag that hides automation, no user agent of ours,
not headless. While a human challenge is on screen, click/fill/press are refused: the agent never touches it.
"""

from __future__ import annotations

import contextlib
import hmac
import json
import os
import queue
import re
from urllib.parse import urlsplit
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Protocol

from bh.browser_service import (
    AGENT_OPS,
    API_PORT,
    CDP_PORT,
    CTL_SOCK,
    DISPLAY,
    GATE_PROXY,
    HOST_OPS,
    PROFILE_ROOT,
    SCREEN,
    TOKEN_ENV,
    VNC_PORT,
)
from bh.browser_service.detect import challenge, scrub, scrub_obj, scrub_url

CHROMIUM = "/usr/bin/chromium"
TEXT_MAX = 8000
CSS_MAX = 300
FILL_MAX = 2000
URL_MAX = 2000
WAIT_MS_MAX = 30_000
STEP_TIMEOUT_MS = 15_000
GOTO_TIMEOUT_MS = 45_000
BODY_MAX = 16_384  # agent request
CTL_MAX = 1_000_000  # host request (a session's cookies)
MAX_COOKIES = 300
NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,40}")
COOKIE_NAME_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,1024}")
# Keys the agent may press: navigation and form keys. No function key (F12 is DevTools), no Ctrl/Alt chord.
KEYS = frozenset(
    {
        "Enter",
        "Tab",
        "Shift+Tab",
        "Escape",
        "Backspace",
        "Delete",
        "Space",
        "ArrowUp",
        "ArrowDown",
        "ArrowLeft",
        "ArrowRight",
        "Home",
        "End",
        "PageUp",
        "PageDown",
    }
)
HUMAN_NEEDED = (
    "a human challenge is on screen: the agent must not touch it. The operator is asked to solve it "
    "(bh browser view); poll state() until challenge.pending is false, or record the blocker and move on"
)


class Refused(ValueError):
    """The request is not one this door accepts (unknown op, unknown field, bad value)."""


class HumanNeeded(RuntimeError):
    pass


# ---------------------------------------------------------------- request validation
def _str(v: Any, field: str, lo: int, hi: int) -> str:
    if not isinstance(v, str) or not lo <= len(v) <= hi:
        raise Refused(f"{field}: a string of {lo} to {hi} characters")
    return v


_LOCAL_HOST = re.compile(
    r"^(localhost|.*\.localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[?::1?\]?|\[?::ffff:.*|browser)$", re.I
)


def _url(v: Any) -> str:
    u = _str(v, "url", 8, URL_MAX)
    if not re.match(r"https?://[^/\s]", u, re.I) or any(c.isspace() for c in u):
        raise Refused("url: http(s) only (no file:, chrome:, data:, javascript:, view-source:)")
    host = urlsplit(u).hostname or ""
    if _LOCAL_HOST.match(host.rstrip(".")):
        raise Refused("url: the browser's own container is not a target")
    return u


def _css(v: Any) -> str:
    return _str(v, "css", 1, CSS_MAX)


def _key(v: Any) -> str:
    if v not in KEYS:
        raise Refused(f"key: one of {', '.join(sorted(KEYS))}")
    return v


def _name(v: Any, field: str) -> str:
    if not isinstance(v, str) or not NAME_RE.fullmatch(v):
        raise Refused(f"{field}: [A-Za-z0-9_.-]{{1,40}}")
    return v


def _cookies(v: Any) -> list[dict[str, Any]]:
    if not isinstance(v, list) or len(v) > MAX_COOKIES:
        raise Refused(f"cookies: a list of at most {MAX_COOKIES}")
    out = []
    for c in v:
        if not isinstance(c, dict) or not COOKIE_NAME_RE.fullmatch(str(c.get("name"))):
            raise Refused("cookies: each one needs a valid name")
        if not isinstance(c.get("value"), str) or len(c["value"]) > 4096:
            raise Refused("cookies: value must be a string of at most 4096 characters")
        k = {"name": c["name"], "value": c["value"], "secure": c.get("secure") is True}
        if isinstance(c.get("url"), str):
            k["url"] = _url(c["url"])
        elif isinstance(c.get("domain"), str) and re.fullmatch(r"\.?[A-Za-z0-9.-]{1,253}", c["domain"]):
            k["domain"] = c["domain"]
            k["path"] = c["path"] if isinstance(c.get("path"), str) and c["path"].startswith("/") else "/"
        else:
            raise Refused("cookies: each one needs a url or a domain")
        exp = c.get("expires")
        if isinstance(exp, (int, float)) and not isinstance(exp, bool) and exp > 0:
            k["expires"] = float(exp)
        out.append(k)
    return out


def _secrets(v: Any) -> list[str]:
    if not isinstance(v, list) or len(v) > 1000 or not all(isinstance(s, str) and len(s) <= 8192 for s in v):
        raise Refused("secrets: a list of strings")
    return v


# op -> {field: (required, validator)}
SPEC: dict[str, dict[str, tuple[bool, Any]]] = {
    "goto": {"url": (True, _url)},
    "fill": {"css": (True, _css), "text": (True, lambda v: _str(v, "text", 0, FILL_MAX))},
    "click": {"css": (True, _css)},
    "press": {"key": (True, _key)},
    "text": {},
    "wait": {"css": (False, _css), "ms": (False, None)},
    "state": {},
    "load_session": {
        "program": (True, lambda v: _name(v, "program")),
        "identity": (True, lambda v: _name(v, "identity")),
        "cookies": (True, _cookies),
        "secrets": (False, _secrets),
    },
    "status": {},
    "reset": {},
    "human_done": {},
}


def validate(ops: frozenset[str], req: Any) -> tuple[str, dict[str, Any]]:
    """(op, arguments) of a request this door accepts. Raises Refused for anything else: an op outside `ops`
    (the agent asking for a host op, or for cookies, storage, CDP, eval, screenshot...), an unknown field, a bad
    value."""
    if not isinstance(req, dict) or not isinstance(req.get("op"), str):
        raise Refused('the request is a JSON object {"op": ...}')
    op = req["op"]
    if op not in ops or op not in SPEC:
        raise Refused(f"operation not allowed: {op[:40]!r}; allowed: {', '.join(sorted(ops))}")
    spec = SPEC[op]
    extra = set(req) - {"op"} - set(spec)
    if extra:
        raise Refused(f"{op}: unknown field(s) {', '.join(sorted(extra))[:120]}")
    args: dict[str, Any] = {}
    for field, (required, check) in spec.items():
        if field not in req:
            if required:
                raise Refused(f"{op}: missing {field}")
            continue
        args[field] = check(req[field]) if check else req[field]
    if op == "wait":
        if ("css" in args) == ("ms" in args):
            raise Refused("wait: exactly one of css or ms")
        if "ms" in args:
            ms = args["ms"]
            if isinstance(ms, bool) or not isinstance(ms, int) or not 0 <= ms <= WAIT_MS_MAX:
                raise Refused(f"wait: ms is an integer from 0 to {WAIT_MS_MAX}")
    return op, args


# ---------------------------------------------------------------- the controller (driver-agnostic)
class Driver(Protocol):
    def goto(self, url: str) -> None: ...
    def fill(self, css: str, text: str) -> None: ...
    def click(self, css: str) -> None: ...
    def press(self, key: str) -> None: ...
    def wait_css(self, css: str) -> None: ...
    def wait_ms(self, ms: int) -> None: ...
    def text(self) -> str: ...
    def snapshot(self) -> dict[str, Any]: ...
    def add_cookies(self, cookies: list[dict[str, Any]]) -> None: ...
    def wipe(self) -> None: ...


class Controller:
    """Requests in, replies out. Every reply is scrubbed of the loaded session's values and of JWTs; no reply ever
    carries a cookie, a storage value or a header."""

    def __init__(self, driver: Driver, clock=time.time) -> None:
        self.driver = driver
        self.clock = clock
        self.secrets: set[str] = set()
        self.identity: dict[str, str] | None = None
        self.cookies_loaded = 0
        self.human_done: float | None = None
        self.pending_since: float | None = None

    def handle(self, ops: frozenset[str], req: Any) -> tuple[int, dict[str, Any]]:
        try:
            op, args = validate(ops, req)
        except Refused as exc:
            return 400, {"error": str(exc)}
        try:
            out = getattr(self, "_op_" + op)(**args)
        except HumanNeeded as exc:
            out, code = {"error": "human-needed", "detail": str(exc), "state": self._state_dict()}, 409
            return code, scrub_obj(out, self.secrets)
        except Exception as exc:  # noqa: BLE001 (a page error is the agent's information, never a crash)
            first = (str(exc).strip().splitlines() or [""])[0][:200]
            return 502, scrub_obj({"error": f"{op}: {type(exc).__name__}: {first}"}, self.secrets)
        return 200, scrub_obj(out, self.secrets)

    # -- helpers
    def _state_dict(self) -> dict[str, Any]:
        snap = self.driver.snapshot()
        ch = challenge(snap)
        if ch["pending"]:
            if self.pending_since is None:
                self.pending_since = self.clock()
                print(f"bh-browser: human challenge on screen ({ch['reason']})", file=sys.stderr, flush=True)
        else:
            self.pending_since = None
        return {
            "url": scrub_url(str(snap.get("url") or ""), self.secrets),
            "title": scrub(str(snap.get("title") or ""), self.secrets)[:200],
            "challenge": {**ch, "since": self.pending_since},
            "human_done_at": self.human_done,
            "identity": self.identity["identity"] if self.identity else None,
        }

    def _guard(self) -> None:
        if challenge(self.driver.snapshot())["pending"]:
            raise HumanNeeded(HUMAN_NEEDED)

    # -- agent ops
    def _op_goto(self, url: str) -> dict[str, Any]:
        self.driver.goto(url)
        return self._state_dict()

    def _op_fill(self, css: str, text: str) -> dict[str, Any]:
        self._guard()
        self.driver.fill(css, text)
        return {"ok": True}

    def _op_click(self, css: str) -> dict[str, Any]:
        self._guard()
        self.driver.click(css)
        return self._state_dict()

    def _op_press(self, key: str) -> dict[str, Any]:
        self._guard()
        self.driver.press(key)
        return self._state_dict()

    def _op_wait(self, css: str | None = None, ms: int | None = None) -> dict[str, Any]:
        if css is not None:
            self.driver.wait_css(css)
        else:
            self.driver.wait_ms(int(ms or 0))
        return self._state_dict()

    def _op_text(self) -> dict[str, Any]:
        t = scrub(self.driver.text(), self.secrets)
        return {"text": t[:TEXT_MAX], "truncated": len(t) > TEXT_MAX}

    def _op_state(self) -> dict[str, Any]:
        return self._state_dict()

    # -- host ops
    def _op_load_session(
        self, program: str, identity: str, cookies: list[dict[str, Any]], secrets: list[str] | None = None
    ) -> dict[str, Any]:
        self.driver.add_cookies(cookies)
        self.secrets |= {c["value"] for c in cookies} | set(secrets or [])
        self.identity = {"program": program, "identity": identity}
        self.cookies_loaded = len(cookies)
        return {"ok": True, "program": program, "identity": identity, "cookies": len(cookies)}

    def _op_status(self) -> dict[str, Any]:
        return {
            **self._state_dict(),
            "program": self.identity["program"] if self.identity else None,
            "cookies_loaded": self.cookies_loaded,
        }

    def _op_reset(self) -> dict[str, Any]:
        self.driver.wipe()
        self.secrets.clear()
        self.identity, self.cookies_loaded, self.human_done, self.pending_since = None, 0, None, None
        return {"ok": True, "reset": True}

    def _op_human_done(self) -> dict[str, Any]:
        self.human_done = self.clock()
        print("bh-browser: the operator says the challenge is done", file=sys.stderr, flush=True)
        return {"ok": True, "human_done_at": self.human_done}


# ---------------------------------------------------------------- processes of the container
def xvfb_argv() -> list[str]:
    w, h = SCREEN
    return ["Xvfb", DISPLAY, "-screen", "0", f"{w}x{h}x24", "-nolisten", "tcp"]


def x11vnc_argv() -> list[str]:
    # -localhost: 127.0.0.1 of the container only. No password: nothing outside the container reaches the port (the
    # host's only path is `podman exec`), and a web page cannot speak raw RFB to it.
    return [
        "x11vnc",
        "-display",
        DISPLAY,
        "-localhost",
        "-rfbport",
        str(VNC_PORT),
        "-forever",
        "-shared",
        "-nopw",
        "-quiet",
        "-noxdamage",
    ]


def chromium_argv(profile: str, binary: str = CHROMIUM, proxy: str = GATE_PROXY) -> list[str]:
    """The distribution's Chromium as it ships. On purpose absent: --headless, --user-agent,
    --disable-blink-features (AutomationControlled), stealth extensions. `--no-sandbox`: Chromium's own sandbox
    needs user namespaces the hardened container does not give (the same as bh-login's Playwright launch)."""
    w, h = SCREEN
    return [
        binary,
        f"--user-data-dir={profile}",
        f"--remote-debugging-port={CDP_PORT}",  # headful Chromium binds it to 127.0.0.1
        f"--proxy-server={proxy}",
        "--proxy-bypass-list=<-loopback>",  # loopback via the gate too (refused): CDP, VNC, API unreachable
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-dev-shm-usage",
        "--no-sandbox",
        "--no-pings",
        "--disable-domain-reliability",
        "--password-store=basic",
        "--window-position=0,0",
        f"--window-size={w},{h}",
        "about:blank",
    ]


class Display:
    """Xvfb + x11vnc + Chromium, restarted when they die."""

    def __init__(self, profile_root: str = PROFILE_ROOT) -> None:
        self.profile = os.path.join(profile_root, "chromium")
        self.procs: dict[str, subprocess.Popen] = {}
        self.lock = threading.Lock()

    def _spawn(self, name: str, argv: list[str]) -> None:
        env = {**os.environ, "DISPLAY": DISPLAY}
        self.procs[name] = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, start_new_session=True)

    def _alive(self, name: str) -> bool:
        p = self.procs.get(name)
        return p is not None and p.poll() is None

    def _stop(self, name: str) -> None:
        p = self.procs.pop(name, None)
        if p and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=5)

    def _start_x(self) -> None:
        n = DISPLAY.lstrip(":")
        for leftover in (f"/tmp/.X{n}-lock", f"/tmp/.X11-unix/X{n}"):
            with contextlib.suppress(OSError):
                os.unlink(leftover)
        self._spawn("xvfb", xvfb_argv())
        end = time.monotonic() + 20
        while not os.path.exists(f"/tmp/.X11-unix/X{n}"):
            if time.monotonic() > end or not self._alive("xvfb"):
                raise RuntimeError("Xvfb did not start")
            time.sleep(0.2)

    def _start_chromium(self) -> None:
        os.makedirs(self.profile, mode=0o700, exist_ok=True)
        for f in ("SingletonLock", "SingletonSocket", "SingletonCookie"):  # left by an unclean stop
            with contextlib.suppress(OSError):
                os.unlink(os.path.join(self.profile, f))
        self._spawn("chromium", chromium_argv(self.profile))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        end = time.monotonic() + 40
        while True:
            try:
                with opener.open(f"http://127.0.0.1:{CDP_PORT}/json/version", timeout=2):
                    return
            except OSError:
                if time.monotonic() > end or not self._alive("chromium"):
                    raise RuntimeError("Chromium did not open its DevTools port") from None
                time.sleep(0.5)

    def ensure(self) -> None:
        with self.lock:
            if not self._alive("xvfb"):
                for n in ("chromium", "x11vnc"):
                    self._stop(n)
                self._start_x()
            if not self._alive("x11vnc"):
                self._spawn("x11vnc", x11vnc_argv())
            if not self._alive("chromium"):
                self._start_chromium()

    def wipe(self) -> None:
        with self.lock:
            self._stop("chromium")
            shutil.rmtree(self.profile, ignore_errors=True)
        self.ensure()

    def stop(self) -> None:
        with self.lock:
            for n in ("chromium", "x11vnc", "xvfb"):
                self._stop(n)


# ---------------------------------------------------------------- Playwright, attached over CDP


class PlaywrightDriver:
    """Attaches to the running Chromium (connect_over_cdp): Playwright launches nothing and changes no flag.
    Lives in one thread (the sync API is bound to the thread that started it)."""

    def __init__(self, display: Display) -> None:
        self.display = display
        self.pw: Any = None
        self.browser: Any = None

    def _page(self) -> Any:
        if self.browser is None or not self.browser.is_connected():
            self.display.ensure()
            if self.pw is None:
                from playwright.sync_api import sync_playwright

                self.pw = sync_playwright().start()
            self.browser = self.pw.chromium.connect_over_cdp(f"http://127.0.0.1:{CDP_PORT}", timeout=30_000)
        ctx = self.browser.contexts[0]  # the persistent profile's context
        pages = [p for p in ctx.pages if not p.is_closed()]
        return pages[-1] if pages else ctx.new_page()

    def goto(self, url: str) -> None:
        self._page().goto(url, wait_until="domcontentloaded", timeout=GOTO_TIMEOUT_MS)

    def fill(self, css: str, text: str) -> None:
        self._page().locator("css=" + css).first.fill(text, timeout=STEP_TIMEOUT_MS)

    def click(self, css: str) -> None:
        self._page().locator("css=" + css).first.click(timeout=STEP_TIMEOUT_MS)

    def press(self, key: str) -> None:
        self._page().keyboard.press(key)

    def wait_css(self, css: str) -> None:
        self._page().locator("css=" + css).first.wait_for(state="visible", timeout=STEP_TIMEOUT_MS)

    def wait_ms(self, ms: int) -> None:
        self._page().wait_for_timeout(ms)

    def text(self) -> str:
        return self._page().inner_text("body", timeout=STEP_TIMEOUT_MS)

    def snapshot(self) -> dict[str, Any]:
        page = self._page()
        frames = []
        for f in page.frames[1:]:
            visible = False
            with contextlib.suppress(Exception):
                el = f.frame_element()
                box = el.bounding_box()
                visible = bool(el.is_visible() and box and box["width"] > 0 and box["height"] > 0)
            frames.append({"url": f.url, "visible": visible})
        try:
            # Playwright reads it in its own isolated world: no script of ours runs in the page's world
            text = page.locator("body").inner_text(timeout=2000)[:20_000]
        except Exception:  # noqa: BLE001 (a page in the middle of a navigation)
            text = ""
        return {"url": page.url, "title": page.title(), "text": text, "frames": frames}

    def add_cookies(self, cookies: list[dict[str, Any]]) -> None:
        self._page()
        self.browser.contexts[0].add_cookies(cookies)

    def wipe(self) -> None:
        with contextlib.suppress(Exception):
            if self.browser is not None:
                self.browser.close()  # over CDP: disconnects, the process is stopped by the display
        self.browser = None
        self.display.wipe()


# ---------------------------------------------------------------- one thread owns the controller
class Worker(threading.Thread):
    def __init__(self, make) -> None:
        super().__init__(daemon=True)
        self.make = make
        self.jobs: queue.Queue = queue.Queue()

    def run(self) -> None:
        ctl = self.make()
        while True:
            ops, req, box, done = self.jobs.get()
            try:
                box.append(ctl.handle(ops, req))
            except BaseException as exc:  # noqa: BLE001
                box.append((500, {"error": type(exc).__name__}))
            done.set()

    def call(self, ops: frozenset[str], req: Any, timeout: float = 120) -> tuple[int, dict[str, Any]]:
        box: list = []
        done = threading.Event()
        self.jobs.put((ops, req, box, done))
        if not done.wait(timeout):
            return 504, {"error": "the browser did not answer in time"}
        return box[0]


# ---------------------------------------------------------------- the agent's door (HTTP, sandbox network)
class ApiHandler(BaseHTTPRequestHandler):
    server_version = "bh-browser"
    sys_version = ""
    timeout = 30

    def log_message(self, fmt, *args):
        pass

    def _reply(self, code: int, obj: dict[str, Any]) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._reply(404, {"error": "POST /op only"})

    def do_POST(self):
        token = self.server.token
        given = self.headers.get("Authorization", "")
        if not token or not hmac.compare_digest(given.encode(), f"Bearer {token}".encode()):
            return self._reply(401, {"error": "bearer token required"})
        if self.path != "/op":
            return self._reply(404, {"error": "POST /op only"})
        raw = self.headers.get("Content-Length") or "0"
        if not raw.isdigit() or int(raw) > BODY_MAX:
            return self._reply(413, {"error": f"body of at most {BODY_MAX} bytes"})
        try:
            req = json.loads(self.rfile.read(int(raw)) or b"{}")
        except ValueError:
            return self._reply(400, {"error": "the body is JSON"})
        code, out = self.server.call(AGENT_OPS, req)
        self._reply(code, out)


def api_server(call, token: str, host: str = "0.0.0.0", port: int = API_PORT) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((host, port), ApiHandler)
    srv.daemon_threads = True
    srv.token = token
    srv.call = call
    return srv


# ---------------------------------------------------------------- the host's door (unix socket, podman exec)
class CtlHandler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline(CTL_MAX + 1)
        try:
            req = json.loads(line)
        except ValueError:
            req = None
        code, out = self.server.call(HOST_OPS, req)
        self.wfile.write((json.dumps({"code": code, **out}) + "\n").encode())


def ctl_server(call, path: str = CTL_SOCK) -> socketserver.ThreadingUnixStreamServer:
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    os.chmod(os.path.dirname(path), 0o700)
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)
    srv = socketserver.ThreadingUnixStreamServer(path, CtlHandler)
    srv.daemon_threads = True
    srv.call = call
    return srv


def host_main(stdin=None, stdout=None, path: str = CTL_SOCK) -> int:
    """`podman exec -i bh-browser ... host`: one JSON request on stdin, one JSON reply on stdout."""
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    line = stdin.readline(CTL_MAX + 1)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(180)
            s.connect(path)
            s.sendall(line.encode() if line.endswith("\n") else (line + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
    except OSError as exc:
        stdout.write(json.dumps({"code": 503, "error": f"controller unreachable: {type(exc).__name__}"}) + "\n")
        return 1
    stdout.write(buf.decode("utf-8", "replace").strip() + "\n")
    try:
        return 0 if json.loads(buf).get("code") == 200 else 1
    except (ValueError, AttributeError):
        return 1


def serve() -> int:
    token = os.environ.get(TOKEN_ENV, "")
    if len(token) < 16:
        print(f"bh-browser: {TOKEN_ENV} is missing or too short (secrets/browser.env)", file=sys.stderr)
        return 2
    display = Display()
    display.ensure()
    worker = Worker(lambda: Controller(PlaywrightDriver(display)))
    worker.start()
    ctl = ctl_server(worker.call)
    threading.Thread(target=ctl.serve_forever, daemon=True).start()
    api = api_server(worker.call, token)

    def stop(signum, frame):
        display.stop()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)

    def watch() -> None:  # a dead x11vnc or Xvfb comes back without waiting for the agent's next request
        while True:
            time.sleep(5)
            with contextlib.suppress(Exception):
                if not (display._alive("xvfb") and display._alive("x11vnc")):
                    display.ensure()

    threading.Thread(target=watch, daemon=True).start()
    print(f"bh-browser: agent API on :{API_PORT}, control socket {CTL_SOCK}", file=sys.stderr, flush=True)
    api.serve_forever()
    return 0
