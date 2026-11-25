"""bull-harness web UI — stdlib only.

Security model:
- binds to the Tailscale IP (or 127.0.0.1), never 0.0.0.0 unless BH_UI_HOST says so;
- token login (secrets/ui.token) -> HttpOnly SameSite=Strict cookie;
- every POST also needs header `X-BH: 1` (forces a CORS preflight from any other origin);
- strict CSP, no inline script: agent output and target responses are untrusted and the
  front end only ever renders them with textContent;
- /captcha/ (the screen of bh-browser, for a human challenge Mio solves himself) is behind the same login: the
  page, the noVNC client files and the WebSocket (same origin only) all need the session cookie. The screen comes
  from the container through a `podman exec` pipe (bh.browser_service.host), never through a published port.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from bh import paths, stack
from bh.agent.contract import SEVERITIES, tail_jsonl
from bh.board import Board
from bh.text import clip

STATIC = Path(__file__).parent / "static"
COOKIE = "bh_ui"
SESSION_S = 30 * 86400
COOKIE_ATTRS = f"HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_S}"
# POST form: the token never lands in a URL (history, logs, Referer). No inline style/script (CSP).
LOGIN_PAGE = (
    b'<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
    b"<title>bull-harness login</title>"
    b'<form action="/login" method="post"><p>bull-harness - paste secrets/ui.token</p>'
    b'<input name="token" type="password" autocomplete="current-password" autofocus required> '
    b'<button type="submit">login</button></form>'
)
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)
# /captcha/ only: the noVNC client draws on a canvas, sets its cursor as a data: URL, and opens a WebSocket to this
# same origin ('self' covers ws:/wss: of this host, CSP Level 3). Still no inline script or style, no frame.
CAPTCHA_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)
CAPTCHA_FILES = {"captcha.js": "text/javascript", "captcha.css": "text/css"}
CAPTCHA_TUNNELS = 2  # screens open at once
EFFORTS = ("low", "medium", "high", "xhigh", "max")


def ui_run_pidfile() -> Path:
    return paths.var() / "ui-run.pid"


NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,40}")


def ui_token() -> str:
    p = paths.secrets_dir() / "ui.token"
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(secrets.token_urlsafe(24))
        p.chmod(0o600)
    return p.read_text().strip()


def new_session(token: str, now: float | None = None) -> str:
    """Stateless session cookie: issue time + random nonce + HMAC(token, both). The cookie is never the token
    itself, survives UI restarts, expires after SESSION_S, and every session dies when secrets/ui.token rotates."""
    nonce = f"{int(time.time() if now is None else now)}-{secrets.token_urlsafe(18)}"
    return f"{nonce}.{hmac.new(token.encode(), nonce.encode(), hashlib.sha256).hexdigest()}"


def session_valid(cookie: str, token: str, now: float | None = None) -> bool:
    nonce, _, mac = cookie.partition(".")
    expected = hmac.new(token.encode(), nonce.encode(), hashlib.sha256).hexdigest()
    if not nonce or not hmac.compare_digest(mac, expected):
        return False
    issued = nonce.split("-", 1)[0]
    age = (time.time() if now is None else now) - int(issued) if issued.isdigit() else -1
    return 0 <= age <= SESSION_S


def content_length(headers, limit: int) -> int:
    """A Content-Length the handler may read: absent = 0; negative, garbage or over `limit` = refused
    (read(-1) would block until the client closes the connection)."""
    raw = headers.get("Content-Length") or "0"
    if not raw.isdigit() or int(raw) > limit:
        raise ValueError("bad or oversized Content-Length")
    return int(raw)


def bounded(value, default: float, lo: float, hi: float) -> float:
    """A number from a request, finite and within [lo, hi]."""
    x = float(value) if value not in (None, "") else default
    if not lo <= x <= hi:  # also false for nan; inf is out of range
        raise ValueError(f"{value!r} is not within [{lo:g}, {hi:g}]")
    return x


def is_ui_run(pid: int) -> bool:
    """The pid file may outlive its run and the pid be reused: signal only a bh CLI process."""
    try:
        return b"bh.cli" in Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return False


def default_host() -> str:
    if os.environ.get("BH_UI_HOST"):
        return os.environ["BH_UI_HOST"]
    try:
        out = subprocess.run(["tailscale", "ip", "-4"], capture_output=True, text=True, timeout=5).stdout.split()
        if out:
            return out[0]
    except (OSError, subprocess.SubprocessError):
        pass
    return "127.0.0.1"


# ------------------------------------------------------------------ data helpers
def run_events(run_id: int, after: int = 0) -> dict:
    files = sorted(paths.runs_dir().glob(f"{run_id:05d}-*.jsonl"))
    if not files:
        return {"events": [], "next": after}
    events = []
    with open(files[0], encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            if i < after:
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            t = ev.get("type")
            if t == "assistant":
                for c in ev.get("message", {}).get("content", []):
                    if c.get("type") == "text" and c.get("text", "").strip():
                        events.append({"i": i, "kind": "text", "body": clip(c["text"])})
                    elif c.get("type") == "tool_use":
                        inp = c.get("input", {})
                        events.append(
                            {
                                "i": i,
                                "kind": "tool_use",
                                "tool": c.get("name"),
                                "body": clip(inp.get("command") or inp.get("description") or inp, 3000),
                            }
                        )
            elif t == "user":
                for c in ev.get("message", {}).get("content", []) or []:
                    if isinstance(c, dict) and c.get("type") == "tool_result":
                        content = c.get("content")
                        if isinstance(content, list):
                            content = "\n".join(x.get("text", "") for x in content if isinstance(x, dict))
                        events.append(
                            {
                                "i": i,
                                "kind": "tool_result",
                                "error": bool(c.get("is_error")),
                                "body": clip(content or "", 4000),
                            }
                        )
            elif t == "result":
                events.append(
                    {
                        "i": i,
                        "kind": "result",
                        "body": clip(ev.get("result") or ev.get("subtype", "")),
                        "turns": ev.get("num_turns"),
                        "cost": ev.get("total_cost_usd"),
                    }
                )
    return {"events": events, "next": (events[-1]["i"] + 1) if events else after}


# ------------------------------------------------------------------ handler
class Handler(BaseHTTPRequestHandler):
    server_version = "bh-ui"
    sys_version = ""
    timeout = 30  # a client that stops sending does not hold a thread forever

    def log_message(self, fmt, *args):  # quiet, but keep errors (everything with BH_UI_DEBUG=1)
        if os.environ.get("BH_UI_DEBUG") or (len(args) > 1 and str(args[1]).startswith(("4", "5"))):
            sys.stderr.write(f"ui {self.address_string()} - {fmt % args}\n")

    # -- plumbing
    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None, csp: str = CSP) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False, default=str).encode(), "application/json")

    def _authed(self) -> bool:
        cookies = dict(c.strip().split("=", 1) for c in self.headers.get("Cookie", "").split(";") if "=" in c)
        return session_valid(cookies.get(COOKIE, ""), self.server.token)

    def _login(self) -> None:
        try:
            n = content_length(self.headers, 4096)
        except ValueError:
            return self._send(400, b"bad request", "text/plain")
        form = {k: v[-1] for k, v in parse_qs(self.rfile.read(n).decode("utf-8", "replace")).items()}
        if not hmac.compare_digest(form.get("token", ""), self.server.token):
            return self._send(403, b"bad token", "text/plain")
        cookie = f"{COOKIE}={new_session(self.server.token)}; {COOKIE_ATTRS}"
        return self._send(303, b"", "text/plain", {"Set-Cookie": cookie, "Location": "/"})

    def _body(self) -> dict:
        body = json.loads(self.rfile.read(content_length(self.headers, 200_000)) or b"{}")
        if not isinstance(body, dict):
            raise ValueError("the body must be a JSON object")
        return body

    # -- routes
    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[-1] for k, v in parse_qs(u.query).items()}
        if not self._authed():
            return self._send(401, LOGIN_PAGE, "text/html; charset=utf-8")
        if u.path in ("/", "/index.html"):
            return self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
        if u.path in ("/app.js", "/app.css"):
            ctype = "text/javascript" if u.path.endswith(".js") else "text/css"
            return self._send(200, (STATIC / u.path.lstrip("/")).read_bytes(), ctype + "; charset=utf-8")
        if u.path.startswith("/api/"):
            try:
                return self._json(self.api_get(u.path, q))
            except KeyError as exc:
                return self._json({"error": f"not found: {exc}"}, 404)
            except Exception as exc:  # noqa: BLE001
                return self._json({"error": str(exc)}, 500)
        if u.path == "/captcha" or u.path.startswith("/captcha/"):
            return self._captcha(u.path)
        self._send(404, b"not found", "text/plain")

    # -- /captcha/: the browser's screen (only reached once _authed() said yes)
    def _captcha(self, path: str) -> None:
        if path == "/captcha":
            return self._send(301, b"", "text/plain", {"Location": "/captcha/"})
        if path == "/captcha/":
            body = (STATIC / "captcha.html").read_bytes()
            return self._send(200, body, "text/html; charset=utf-8", csp=CAPTCHA_CSP)
        name = path.removeprefix("/captcha/")
        if name in CAPTCHA_FILES:
            body = (STATIC / name).read_bytes()
            return self._send(200, body, CAPTCHA_FILES[name] + "; charset=utf-8", csp=CAPTCHA_CSP)
        if name == "ws":
            return self._captcha_ws()
        if name.startswith("novnc/"):
            try:
                files = self._novnc_files()
            except Exception as exc:  # noqa: BLE001
                return self._send(502, f"noVNC client unavailable: {exc}"[:300].encode(), "text/plain")
            body = files.get(name.removeprefix("novnc/"))
            if body is None:
                return self._send(404, b"not found", "text/plain")
            ctype = "text/javascript" if name.endswith((".js", ".mjs")) else "application/octet-stream"
            return self._send(200, body, ctype, {"Cache-Control": "private, max-age=3600"}, csp=CAPTCHA_CSP)
        return self._send(404, b"not found", "text/plain")

    def _novnc_files(self) -> dict[str, bytes]:
        loader = getattr(self.server, "novnc_files", None)
        if loader is None:
            from bh.browser_service.host import novnc_files as loader
        return loader()

    def _same_origin(self) -> bool:
        origin, host = urlparse(self.headers.get("Origin") or ""), self.headers.get("Host") or ""
        return bool(host) and origin.netloc == host and origin.scheme in ("http", "https")

    def _captcha_ws(self) -> None:
        from bh.ui import ws

        key = self.headers.get("Sec-WebSocket-Key")
        if (self.headers.get("Upgrade") or "").lower() != "websocket" or not ws.valid_key(key):
            return self._send(400, b"websocket only", "text/plain")
        if not self._same_origin():  # cross-site WebSocket hijacking: the cookie alone is not enough
            return self._send(403, b"forbidden", "text/plain")
        slots = self.server.__dict__.setdefault("captcha_slots", threading.BoundedSemaphore(CAPTCHA_TUNNELS))
        if not slots.acquire(blocking=False):
            return self._send(429, b"too many screens open", "text/plain")
        try:
            opener = getattr(self.server, "open_tunnel", None)
            if opener is None:
                from bh.browser_service.host import open_tunnel as opener
            try:
                proc = opener()
            except OSError as exc:
                return self._send(502, f"tunnel: {type(exc).__name__}".encode(), "text/plain")
            try:
                self.send_response(101)
                self.send_header("Upgrade", "websocket")
                self.send_header("Connection", "Upgrade")
                self.send_header("Sec-WebSocket-Accept", ws.accept_key(key or ""))
                offered = [p.strip() for p in (self.headers.get("Sec-WebSocket-Protocol") or "").split(",")]
                if "binary" in offered:
                    self.send_header("Sec-WebSocket-Protocol", "binary")
                self.end_headers()
                self.wfile.flush()
                self.connection.settimeout(None)  # a screen may stay still for minutes
                ws.relay(self.rfile, self.wfile, proc.stdin, proc.stdout)
            finally:
                self.close_connection = True
                with contextlib.suppress(OSError):
                    proc.kill()
                with contextlib.suppress(Exception):
                    proc.wait(timeout=10)
        finally:
            slots.release()

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/login":
            return self._login()
        if not self._authed() or self.headers.get("X-BH") != "1":
            return self._send(403, b"forbidden", "text/plain")
        try:
            return self._json(self.api_post(u.path, self._body()))
        except (KeyError, ValueError) as exc:
            return self._json({"error": str(exc)}, 400)
        except Exception as exc:  # noqa: BLE001
            return self._json({"error": str(exc)}, 500)

    # -- API
    def api_get(self, path: str, q: dict):
        b = Board()
        if path == "/api/status":
            from bh.scope import load_scope

            active = paths.active_scope()
            act = None
            if active.exists():
                try:
                    s = load_scope(active)
                    act = {"program": s.program, "platform": s.platform, "rps": s.max_rps}
                except Exception:  # noqa: BLE001
                    act = {"program": "?", "error": "invalid"}
            sev = {
                r["severity"] or "?": r["n"]
                for r in b.rows(
                    "SELECT severity, COUNT(*) n FROM findings "
                    "WHERE status NOT IN ('rejected','duplicate') GROUP BY severity"
                )
            }
            running = b.rows(
                "SELECT id, program, model, started FROM runs WHERE status='running' ORDER BY id DESC LIMIT 1"
            )
            return {
                "containers": {c: stack.container_running(c) for c in (stack.GATE, stack.AGENT, stack.BROWSER_CTR)},
                "active_scope": act,
                "severity": {s: sev.get(s, 0) for s in SEVERITIES},
                "findings_to_review": b.rows("SELECT COUNT(*) n FROM findings WHERE status IN ('new','verified')")[0][
                    "n"
                ],
                "to_submit": b.rows("SELECT COUNT(*) n FROM todos WHERE status='open' AND kind='submit'")[0]["n"],
                "inconclusive": b.rows("SELECT COUNT(*) n FROM findings WHERE status='inconclusive'")[0]["n"],
                "needs_proof": b.rows("SELECT COUNT(*) n FROM findings WHERE status='needs-proof'")[0]["n"],
                "blockers_24h": b.rows(
                    "SELECT COUNT(*) n FROM facts WHERE kind='blocker' AND created>=?", time.time() - 86400
                )[0]["n"],
                "facts": b.rows("SELECT COUNT(*) n FROM facts")[0]["n"],
                "runs": b.rows("SELECT COUNT(*) n FROM runs")[0]["n"],
                "running": dict(running[0]) if running else None,
                "worker": {"run": stack.pid_alive(ui_run_pidfile()), "log": "var/ui-run.log"},
                "now": time.time(),
            }
        if path == "/api/findings":
            return [
                dict(r)
                for r in b.rows(
                    "SELECT id, program, title, severity, vuln_class, url, status, created FROM findings ORDER BY "
                    "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
                    "WHEN 'low' THEN 3 ELSE 4 END, id DESC"
                )
            ]
        if m := re.fullmatch(r"/api/findings/(\d+)", path):
            rows = b.rows("SELECT * FROM findings WHERE id=?", int(m.group(1)))
            if not rows:
                raise KeyError("finding")
            f = dict(rows[0])
            host = urlparse(f.get("url") or "").netloc
            flows = [
                x for x in tail_jsonl(paths.flows_log(), 3000) if host and urlparse(x.get("url", "")).netloc == host
            ][-40:]
            f["flows"] = flows
            return f
        if path == "/api/todos":
            # Submissions only: todos of the retired kinds are history (status obsolete), not work.
            st = q.get("status", "open")
            return [
                dict(r) for r in b.rows("SELECT * FROM todos WHERE kind='submit' AND status=? ORDER BY id DESC", st)
            ]
        if path == "/api/blockers":
            return [
                dict(r)
                for r in b.rows(
                    "SELECT id, program, run_id, title, summary, evidence, created FROM facts "
                    "WHERE kind='blocker' ORDER BY id DESC LIMIT 100"
                )
            ]
        if path == "/api/runs":
            return [dict(r) for r in b.rows("SELECT * FROM runs ORDER BY id DESC LIMIT 50")]
        if path == "/api/captcha/status":
            if not stack.container_running(stack.BROWSER_CTR):
                return {"code": 503, "error": f"{stack.BROWSER_CTR} is not running (bh browser up)"}
            from bh.browser_service import host as bhost

            return bhost.call({"op": "status"}, timeout=60)
        if path == "/api/metrics":
            return self._metrics(b)
        if m := re.fullmatch(r"/api/runs/(\d+)/tools", path):
            return [dict(r) for r in b.rows("SELECT * FROM tool_calls WHERE run_id=? ORDER BY idx", int(m.group(1)))]
        if m := re.fullmatch(r"/api/runs/(\d+|latest)/events", path):
            rid = m.group(1)
            if rid == "latest":
                r = b.rows("SELECT id FROM runs ORDER BY id DESC LIMIT 1")
                if not r:
                    return {"run": None, "events": [], "next": 0}
                rid = r[0]["id"]
            data = run_events(int(rid), int(q.get("after", 0)))
            data["run"] = dict(b.rows("SELECT * FROM runs WHERE id=?", int(rid))[0])
            return data
        if path == "/api/flows":
            n = int(bounded(q.get("n"), 200, 1, 2000))
            flows = tail_jsonl(paths.flows_log(), n)
            g = q.get("grep")
            return [f for f in reversed(flows) if not g or g in f.get("url", "")]
        if m := re.fullmatch(r"/api/flows/([0-9A-Za-z-]+)", path):
            p = paths.flow_file(m.group(1))
            if not p.exists():
                raise KeyError("flow")
            return json.loads(p.read_text())
        if path == "/api/events":
            return list(reversed(tail_jsonl(paths.events_log(), int(bounded(q.get("n"), 200, 1, 2000)))))
        if path == "/api/programs":
            return self._programs(b)
        if m := re.fullmatch(r"/api/board/([A-Za-z0-9_.-]+)", path):
            prog = m.group(1)
            return {
                "facts": [dict(r) for r in b.rows("SELECT * FROM facts WHERE program=? ORDER BY id DESC", prog)],
                "intents": [dict(r) for r in b.rows("SELECT * FROM intents WHERE program=? ORDER BY id DESC", prog)],
                "identities": paths.identities(prog),
            }
        raise KeyError(path)

    def _metrics(self, b: Board) -> dict:
        """Observability: tokens, tools, gate and verifier per run; cost per verified finding."""
        runs = [
            dict(r)
            for r in b.rows(
                "SELECT r.*, (SELECT COUNT(*) FROM findings f WHERE f.run_id=r.id) AS findings_new, "
                "(SELECT COUNT(*) FROM findings f WHERE f.run_id=r.id AND f.status IN ('verified','submitted')) "
                "AS findings_verified, "
                "(SELECT SUM(cache_write) FROM turns t WHERE t.run_id=r.id) AS cache_write_turns "
                "FROM runs r ORDER BY r.id DESC LIMIT 60"
            )
        ]
        cost = sum((r["cost_usd"] or 0) + (r["verify_cost"] or 0) for r in runs)
        verified = sum(r["findings_verified"] for r in runs)
        calls = b.rows("SELECT kind, COUNT(*) n, SUM(ms) ms FROM tool_calls GROUP BY kind")
        return {
            "runs": runs,
            "cost": cost,
            "verified": verified,
            "cost_per_verified": cost / verified if verified else None,
            "tool_kinds": {r["kind"]: {"n": r["n"], "ms": r["ms"]} for r in calls},
        }

    def _programs(self, b: Board) -> list[dict]:
        from bh.scope import ScopeError, load_scope

        out = []
        for f in sorted(paths.scopes_dir().rglob("*.yaml")):
            if "examples" in f.parts:
                continue
            try:
                s = load_scope(f)
            except ScopeError as exc:
                out.append({"file": str(f.relative_to(paths.home())), "error": str(exc)})
                continue
            st = b.rows("SELECT COUNT(*) n, MAX(started) last FROM runs WHERE program=?", s.program)[0]
            out.append(
                {
                    "file": str(f.relative_to(paths.home())),
                    "program": s.program,
                    "platform": s.platform,
                    "in_scope": [r.value for r in s.in_scope],
                    "out_of_scope": [r.value for r in s.out_of_scope],
                    "rps": s.max_rps,
                    "automation": s.automation_allowed,
                    "headers": s.required_headers,
                    "runs": st["n"],
                    "last_run": st["last"],
                    "identities": paths.identities(s.program),
                }
            )
        return out

    def api_post(self, path: str, body: dict):
        b = Board()
        if m := re.fullmatch(r"/api/findings/(\d+)/status", path):
            b.set_finding(int(m.group(1)), body["status"], body.get("verdict") or None)
            return {"ok": True}
        if m := re.fullmatch(r"/api/todos/(\d+)/done", path):
            tid = int(m.group(1))
            # Mio ticks a submission done; an obsolete todo of a retired kind stays as it was.
            if not b.rows("SELECT 1 FROM todos WHERE id=? AND kind='submit' AND status='open'", tid):
                raise KeyError(f"open submit todo T{tid}")
            b.close_todo(tid)
            return {"ok": True}
        if path == "/api/identities":
            return self._save_identity(body)
        if path == "/api/captcha/done":
            from bh.browser_service import host as bhost

            return bhost.mark_done()
        if path == "/api/run":
            return self._start_run(body)
        if path == "/api/run/stop":
            pid = stack.pid_alive(ui_run_pidfile())
            if not pid or not is_ui_run(pid):
                return {"ok": False, "error": "no run started from the UI is alive"}
            os.killpg(os.getpgid(pid), signal.SIGINT)
            return {"ok": True, "stopped": pid}
        raise KeyError(path)

    def _save_identity(self, body: dict) -> dict:
        prog, name = body["program"], body["name"]
        if not NAME_RE.fullmatch(prog) or not NAME_RE.fullmatch(name):
            raise ValueError("program/name must match [A-Za-z0-9_.-]{1,40}")
        headers: dict[str, str] = {}
        for line in str(body.get("headers", "")).splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                k, v = k.strip(), v.strip()
                if re.fullmatch(r"[A-Za-z0-9-]{1,64}", k) and v and "\r" not in v and "\n" not in v:
                    headers[k] = v
        if not headers:
            raise ValueError("no valid 'Header: value' line")
        d = paths.identities_dir(prog)
        d.mkdir(parents=True, exist_ok=True)
        p = d / f"{name}.json"
        if p.exists() and not body.get("overwrite"):
            raise ValueError(f"identity '{name}' already exists for {prog}: tick 'replace' to overwrite it")
        # created 0600 from the start: the session never sits world-readable on disk
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps({"headers": headers, "updated": time.time()}))
        p.chmod(0o600)
        return {"ok": True, "identity": name, "headers": sorted(headers)}

    def _start_run(self, body: dict) -> dict:
        pidfile = ui_run_pidfile()
        if stack.pid_alive(pidfile):
            raise ValueError("a run started from the UI is already alive; stop it first")
        scope = Path(body["scope"])
        full = (paths.home() / scope).resolve()
        if not full.is_relative_to(paths.scopes_dir().resolve()) or not full.is_file():
            raise ValueError("scope must be a file under scopes/")
        mode = body.get("mode", "run")
        from bh.runner.run import DEFAULT_MODEL

        model = body.get("model") or DEFAULT_MODEL
        if not re.fullmatch(r"[a-z0-9.\[\]-]{2,40}", model):
            raise ValueError("bad model")
        minutes = bounded(body.get("minutes"), 20, 1, 24 * 60)
        turns = int(bounded(body.get("max_turns"), 40, 1, 1000))
        cmd = [sys.executable, "-m", "bh.cli"]
        if mode == "hunt":
            cmd += ["hunt", str(full), "--hours", str(bounded(body.get("hours"), 4, 0.1, 72))]
        else:
            cmd += ["run", str(full)]
            if body.get("task"):
                cmd += [f"--task={str(body['task'])[:2000]}"]  # one argv item: a leading "-" stays text
            if body.get("resume"):
                cmd += ["--resume"]
        cmd += ["--model", model, "--minutes", str(minutes), "--max-turns", str(turns)]
        if body.get("effort") in EFFORTS:
            cmd += ["--effort", body["effort"]]
        with open(paths.var() / "ui-run.log", "a") as log:  # the child keeps its own descriptor
            log.write(f"\n=== {time.strftime('%F %T')} {' '.join(cmd[2:])}\n")
            log.flush()
            p = subprocess.Popen(
                cmd,
                cwd=paths.home(),
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                env={**os.environ, "BH_HOME": str(paths.home()), "PYTHONUNBUFFERED": "1"},
            )
        pidfile.write_text(str(p.pid))
        return {"ok": True, "pid": p.pid}


def serve(host: str | None = None, port: int = 7340) -> None:
    host = host or default_host()
    srv = ThreadingHTTPServer((host, port), Handler)
    srv.token = ui_token()
    srv.daemon_threads = True
    srv.captcha_slots = threading.BoundedSemaphore(CAPTCHA_TUNNELS)
    print(f"bh ui on http://{host}:{port}/  (log in with the token in secrets/ui.token)", flush=True)
    srv.serve_forever()
