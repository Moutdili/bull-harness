"""bull-harness web UI — stdlib only.

Security model:
- binds to the Tailscale IP (or 127.0.0.1), never 0.0.0.0 unless BH_UI_HOST says so;
- token login (secrets/ui.token) -> HttpOnly SameSite=Strict cookie;
- every POST also needs header `X-BH: 1` (forces a CORS preflight from any other origin);
- strict CSP, no inline script: agent output and target responses are untrusted and the
  front end only ever renders them with textContent.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from bh.board import Board

STATIC = Path(__file__).parent / "static"
COOKIE = "bh_ui"
# No inline style/script: the CSP below forbids them. GET form -> existing /login?token= handler.
LOGIN_PAGE = (b'<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
              b'<title>bull-harness login</title><link rel="stylesheet" href="/static/app.css">'
              b'<form action="/login" method="get"><p>bull-harness - paste secrets/ui.token</p>'
              b'<input name="token" type="password" autocomplete="current-password" autofocus required> '
              b'<button type="submit">login</button></form>')
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
SEVERITIES = ["critical", "high", "medium", "low", "info"]
NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,40}")


def home() -> Path:
    return Path(os.environ.get("BH_HOME", Path.cwd()))


def ui_token() -> str:
    p = home() / "secrets" / "ui.token"
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(secrets.token_urlsafe(24))
        p.chmod(0o600)
    return p.read_text().strip()


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
def _tail_jsonl(path: Path, n: int) -> list[dict]:
    if not path.exists():
        return []
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        fh.seek(max(0, size - 400_000))
        lines = fh.read().splitlines()[-n:]
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def _clip(s, n=4000) -> str:
    s = s if isinstance(s, str) else json.dumps(s, ensure_ascii=False)
    return s if len(s) <= n else s[:n] + f"\n… [{len(s) - n} chars clipped]"


def run_events(run_id: int, after: int = 0) -> dict:
    files = sorted((home() / "var" / "runs").glob(f"{run_id:05d}-*.jsonl"))
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
                        events.append({"i": i, "kind": "text", "body": _clip(c["text"])})
                    elif c.get("type") == "tool_use":
                        inp = c.get("input", {})
                        events.append({"i": i, "kind": "tool_use", "tool": c.get("name"),
                                       "body": _clip(inp.get("command") or inp.get("description") or inp, 3000)})
            elif t == "user":
                for c in ev.get("message", {}).get("content", []) or []:
                    if isinstance(c, dict) and c.get("type") == "tool_result":
                        content = c.get("content")
                        if isinstance(content, list):
                            content = "\n".join(x.get("text", "") for x in content if isinstance(x, dict))
                        events.append({"i": i, "kind": "tool_result", "error": bool(c.get("is_error")),
                                       "body": _clip(content or "", 4000)})
            elif t == "result":
                events.append({"i": i, "kind": "result", "body": _clip(ev.get("result") or ev.get("subtype", "")),
                               "turns": ev.get("num_turns"), "cost": ev.get("total_cost_usd")})
    return {"events": events, "next": (events[-1]["i"] + 1) if events else after}


def proc_alive(pidfile: Path) -> int | None:
    try:
        pid = int(pidfile.read_text())
        os.kill(pid, 0)
        return pid
    except (OSError, ValueError):
        return None


# ------------------------------------------------------------------ handler
class Handler(BaseHTTPRequestHandler):
    server_version = "bh-ui"
    sys_version = ""

    def log_message(self, fmt, *args):  # quiet, but keep errors (everything with BH_UI_DEBUG=1)
        if os.environ.get("BH_UI_DEBUG") or (len(args) > 1 and str(args[1]).startswith(("4", "5"))):
            sys.stderr.write("ui %s - %s\n" % (self.address_string(), fmt % args))

    # -- plumbing
    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", CSP)
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
        return hmac.compare_digest(cookies.get(COOKIE, ""), self.server.token)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n > 200_000:
            raise ValueError("body too large")
        return json.loads(self.rfile.read(n) or b"{}")

    # -- routes
    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[-1] for k, v in parse_qs(u.query).items()}
        if u.path == "/login":
            if hmac.compare_digest(q.get("token", ""), self.server.token):
                return self._send(302, b"", "text/plain", {
                    "Set-Cookie": f"{COOKIE}={self.server.token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000",
                    "Location": "/"})
            return self._send(403, b"bad token", "text/plain")
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
        self._send(404, b"not found", "text/plain")

    def do_POST(self):
        u = urlparse(self.path)
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
            from bh.runner.run import AGENT, GATE, container_running
            from bh.scope import load_scope
            active = home() / "var" / "state" / "active-scope.yaml"
            act = None
            if active.exists():
                try:
                    s = load_scope(active)
                    act = {"program": s.program, "platform": s.platform, "rps": s.max_rps}
                except Exception:  # noqa: BLE001
                    act = {"program": "?", "error": "invalid"}
            sev = {r["severity"] or "?": r["n"] for r in b.rows(
                "SELECT severity, COUNT(*) n FROM findings WHERE status NOT IN ('rejected','duplicate') GROUP BY severity")}
            running = b.rows("SELECT id, program, model, started FROM runs WHERE status='running' ORDER BY id DESC LIMIT 1")
            return {
                "containers": {c: container_running(c) for c in (GATE, AGENT)},
                "active_scope": act,
                "severity": {s: sev.get(s, 0) for s in SEVERITIES},
                "findings_to_review": b.rows("SELECT COUNT(*) n FROM findings WHERE status IN ('new','verified')")[0]["n"],
                "open_todos": b.rows("SELECT COUNT(*) n FROM todos WHERE status='open'")[0]["n"],
                "facts": b.rows("SELECT COUNT(*) n FROM facts")[0]["n"],
                "runs": b.rows("SELECT COUNT(*) n FROM runs")[0]["n"],
                "running": dict(running[0]) if running else None,
                "worker": {"run": proc_alive(home() / "var" / "ui-run.pid"), "log": "var/ui-run.log"},
                "now": time.time(),
            }
        if path == "/api/findings":
            return [dict(r) for r in b.rows(
                "SELECT id, program, title, severity, vuln_class, url, status, created FROM findings ORDER BY "
                "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id DESC")]
        if m := re.fullmatch(r"/api/findings/(\d+)", path):
            rows = b.rows("SELECT * FROM findings WHERE id=?", int(m.group(1)))
            if not rows:
                raise KeyError("finding")
            f = dict(rows[0])
            host = urlparse(f.get("url") or "").netloc
            flows = [x for x in _tail_jsonl(home() / "var" / "state" / "flows.jsonl", 3000)
                     if host and urlparse(x.get("url", "")).netloc == host][-40:]
            f["flows"] = flows
            return f
        if path == "/api/todos":
            st = q.get("status", "open")
            return [dict(r) for r in b.rows("SELECT * FROM todos WHERE status=? ORDER BY id DESC", st)]
        if path == "/api/runs":
            return [dict(r) for r in b.rows("SELECT * FROM runs ORDER BY id DESC LIMIT 50")]
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
            n = min(int(q.get("n", 200)), 2000)
            flows = _tail_jsonl(home() / "var" / "state" / "flows.jsonl", n)
            g = q.get("grep")
            return [f for f in reversed(flows) if not g or g in f.get("url", "")]
        if m := re.fullmatch(r"/api/flows/([0-9A-Za-z-]+)", path):
            p = home() / "var" / "state" / "flows" / f"{m.group(1)}.json"
            if not p.exists():
                raise KeyError("flow")
            return json.loads(p.read_text())
        if path == "/api/events":
            return list(reversed(_tail_jsonl(home() / "var" / "state" / "events.jsonl", int(q.get("n", 200)))))
        if path == "/api/programs":
            return self._programs(b)
        if m := re.fullmatch(r"/api/board/([A-Za-z0-9_.-]+)", path):
            prog = m.group(1)
            return {
                "facts": [dict(r) for r in b.rows("SELECT * FROM facts WHERE program=? ORDER BY id DESC", prog)],
                "intents": [dict(r) for r in b.rows("SELECT * FROM intents WHERE program=? ORDER BY id DESC", prog)],
                "identities": self._identities(prog),
            }
        raise KeyError(path)

    def _programs(self, b: Board) -> list[dict]:
        from bh.scope import ScopeError, load_scope
        out = []
        for f in sorted((home() / "scopes").rglob("*.yaml")):
            if "examples" in f.parts:
                continue
            try:
                s = load_scope(f)
            except ScopeError as exc:
                out.append({"file": str(f.relative_to(home())), "error": str(exc)})
                continue
            st = b.rows("SELECT COUNT(*) n, MAX(started) last FROM runs WHERE program=?", s.program)[0]
            out.append({"file": str(f.relative_to(home())), "program": s.program, "platform": s.platform,
                        "in_scope": [r.value for r in s.in_scope], "out_of_scope": [r.value for r in s.out_of_scope],
                        "rps": s.max_rps, "automation": s.automation_allowed, "headers": s.required_headers,
                        "runs": st["n"], "last_run": st["last"], "identities": self._identities(s.program)})
        return out

    def _identities(self, program: str) -> list[str]:
        d = home() / "var" / "state" / "identities" / program
        return sorted(p.stem for p in d.glob("*.json")) if d.is_dir() else []

    def api_post(self, path: str, body: dict):
        b = Board()
        if m := re.fullmatch(r"/api/findings/(\d+)/status", path):
            b.set_finding(int(m.group(1)), body["status"], body.get("verdict") or None)
            return {"ok": True}
        if m := re.fullmatch(r"/api/todos/(\d+)/done", path):
            b.close_todo(int(m.group(1)))
            return {"ok": True}
        if path == "/api/identities":
            return self._save_identity(body)
        if path == "/api/run":
            return self._start_run(body)
        if path == "/api/run/stop":
            pid = proc_alive(home() / "var" / "ui-run.pid")
            if not pid:
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
        d = home() / "var" / "state" / "identities" / prog
        d.mkdir(parents=True, exist_ok=True)
        p = d / f"{name}.json"
        p.write_text(json.dumps({"headers": headers, "updated": time.time()}))
        p.chmod(0o600)
        if body.get("todo_id"):
            Board().close_todo(int(body["todo_id"]))
        return {"ok": True, "identity": name, "headers": sorted(headers)}

    def _start_run(self, body: dict) -> dict:
        pidfile = home() / "var" / "ui-run.pid"
        if proc_alive(pidfile):
            raise ValueError("a run started from the UI is already alive; stop it first")
        scope = Path(body["scope"])
        full = (home() / scope).resolve()
        if not str(full).startswith(str((home() / "scopes").resolve())) or not full.is_file():
            raise ValueError("scope must be a file under scopes/")
        mode = body.get("mode", "run")
        model = body.get("model") or "sonnet"
        if not re.fullmatch(r"[a-z0-9.\[\]-]{2,40}", model):
            raise ValueError("bad model")
        minutes = float(body.get("minutes") or 20)
        turns = int(body.get("max_turns") or 40)
        cmd = [sys.executable, "-m", "bh.cli"]
        if mode == "hunt":
            cmd += ["hunt", str(full), "--hours", str(float(body.get("hours") or 4))]
        else:
            cmd += ["run", str(full)]
            if body.get("task"):
                cmd += ["--task", str(body["task"])[:2000]]
            if body.get("fresh"):
                cmd += ["--fresh"]
        cmd += ["--model", model, "--minutes", str(minutes), "--max-turns", str(turns)]
        log = open(home() / "var" / "ui-run.log", "a")
        log.write(f"\n=== {time.strftime('%F %T')} {' '.join(cmd[2:])}\n")
        log.flush()
        p = subprocess.Popen(cmd, cwd=home(), stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                             env={**os.environ, "BH_HOME": str(home()), "PYTHONUNBUFFERED": "1"})
        pidfile.write_text(str(p.pid))
        return {"ok": True, "pid": p.pid}


def serve(host: str | None = None, port: int = 7340) -> None:
    host = host or default_host()
    srv = ThreadingHTTPServer((host, port), Handler)
    srv.token = ui_token()
    srv.daemon_threads = True
    print(f"bh ui on http://{host}:{port}/  (first visit: /login?token=… from secrets/ui.token)", flush=True)
    srv.serve_forever()
