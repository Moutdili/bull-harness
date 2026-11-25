"""Host side of the browser service: everything the host does to bh-browser goes through `podman exec -i`.

- `call`: one control request (load_session, status, reset, human_done) on stdin, one JSON reply on stdout;
- `identity_payload`: an identity's session file (read with bh.gate.session) turned into browser cookies;
- `novnc_files`: the noVNC client (the container's /usr/share/novnc), copied once into memory, served by the UI;
- `open_tunnel`: a byte pipe to x11vnc on the container's loopback (the UI's /captcha/ws relays it).

No port of bh-browser is published and no network is added: the screen reaches the host only through these
`podman exec` pipes, and the UI hands it out only behind its own login.
"""

from __future__ import annotations

import io
import json
import os
import posixpath
import secrets as _secrets
import subprocess
import tarfile
import threading
import time
from typing import Any

from bh import paths, stack
from bh.browser_service import TOKEN_ENV, VNC_PORT
from bh.browser_service.__main__ import BOOT

NOVNC_DIR = "/usr/share/novnc"
NOVNC_PARTS = ("core", "vendor")  # what core/rfb.js imports; the stock app/ UI is not served
NOVNC_MAX = 16_000_000
CALL_TIMEOUT_S = 180

# Runs in bh-browser (python3 -I): stdin -> x11vnc, x11vnc -> stdout, until either side closes.
PIPE = (
    "import os,socket,threading\n"
    f"s=socket.create_connection(('127.0.0.1',{VNC_PORT}),timeout=10);s.settimeout(None)\n"
    "def up():\n"
    "    while True:\n"
    "        d=os.read(0,65536)\n"
    "        if not d: break\n"
    "        s.sendall(d)\n"
    "    s.shutdown(socket.SHUT_WR)\n"
    "threading.Thread(target=up,daemon=True).start()\n"
    "while True:\n"
    "    d=s.recv(65536)\n"
    "    if not d: break\n"
    "    os.write(1,d)\n"
)


# ---------------------------------------------------------------- token of the agent API
def token_file():
    return paths.secrets_dir() / "browser.env"


def ensure_token() -> None:
    """secrets/browser.env (`BH_BROWSER_TOKEN=...`, 0600): read by compose for the agent and the browser only."""
    p = token_file()
    if p.exists():
        return
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(f"{TOKEN_ENV}={_secrets.token_urlsafe(32)}\n")


# ---------------------------------------------------------------- session -> cookies
def session_cookies(session: dict[str, Any]) -> list[dict[str, Any]]:
    """The jar of a session (bh.gate.session shape) as Playwright cookies. A host-only cookie is set by URL (the
    browser then keeps it host-only), a domain cookie by `.domain`. Expiry and Secure kept; HttpOnly unknown (the
    jar does not keep it), so left off."""
    out = []
    for dom, cookies in sorted((session.get("cookies") or {}).items()):
        for name, c in sorted(cookies.items()):
            path = c.get("path") or "/"
            k: dict[str, Any] = {"name": name, "value": c["value"], "secure": bool(c.get("secure"))}
            if c.get("host_only", True):
                k["url"] = f"https://{dom}{path}"
            else:
                k["domain"], k["path"] = "." + dom, path
            if c.get("expires"):
                k["expires"] = float(c["expires"])
            out.append(k)
    return out


def identity_payload(program: str, name: str) -> tuple[dict[str, Any], list[str]]:
    """(load_session request, header names that are not injected). Raises SystemExit when there is no session.
    The request carries the values on stdin only; the controller keeps them as its redaction list."""
    from bh.gate import session as gsession

    p = paths.identities_dir(program) / f"{name}.json"
    s = gsession.load(p)
    if s is None:
        raise SystemExit(f"no session for {program}/{name} ({p} missing or unreadable)")
    cookies = session_cookies(s)
    secrets = [v for v in s.get("headers", {}).values() if v] + [c["value"] for c in cookies]
    req = {"op": "load_session", "program": program, "identity": name, "cookies": cookies, "secrets": secrets}
    return req, sorted(s.get("headers", {}))


# ---------------------------------------------------------------- control calls
def _exec(argv: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["podman", "exec", "-i", "--user", stack.BROWSER_USER, stack.BROWSER_CTR, *argv], capture_output=True, **kw
    )


def call(req: dict[str, Any], timeout: float = CALL_TIMEOUT_S) -> dict[str, Any]:
    """One host request to the controller. The reply never holds a cookie or a header (the controller's rule)."""
    try:
        r = _exec(["python3", "-I", "-c", BOOT, "host"], input=json.dumps(req) + "\n", text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"code": 503, "error": f"podman exec {stack.BROWSER_CTR}: {type(exc).__name__}"}
    for line in reversed((r.stdout or "").strip().splitlines()):
        try:
            out = json.loads(line)
        except ValueError:
            continue
        if isinstance(out, dict):
            return out
    return {"code": 503, "error": f"no reply from {stack.BROWSER_CTR} (rc {r.returncode})"}


def done_file():
    return paths.var() / "browser" / "captcha-done.json"


def mark_done() -> dict[str, Any]:
    """The operator's "J'ai fini": a file the host reads (var/browser/captcha-done.json), and the controller's
    state() shows `human_done_at` to the agent."""
    f = done_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    rec = {"t": time.time()}
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(rec))
    os.replace(tmp, f)
    told = call({"op": "human_done"}, timeout=30).get("code") == 200
    return {"ok": True, "t": rec["t"], "browser_told": told}


def view_url(host: str | None = None, port: int = 7340) -> str:
    from bh.ui.server import default_host

    return f"http://{host or default_host()}:{port}/captcha/"


# ---------------------------------------------------------------- noVNC client files
def parse_tar(data: bytes, limit: int = NOVNC_MAX) -> dict[str, bytes]:
    """Regular files of a tar archive, by normalized relative path; nothing is written to disk, and a member that
    climbs out (`..`, absolute) is skipped."""
    out: dict[str, bytes] = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
        for m in tar:
            if not m.isreg():
                continue
            name = posixpath.normpath(m.name)
            if name.startswith(("/", "..")):
                continue
            total += m.size
            if total > limit:
                raise ValueError("the noVNC archive is too large")
            fh = tar.extractfile(m)
            if fh is not None:
                out[name] = fh.read()
    return out


_NOVNC: dict[str, bytes] | None = None
_NOVNC_LOCK = threading.Lock()


def novnc_files() -> dict[str, bytes]:
    """The noVNC client, once per UI process (`tar -h`: Debian may link vendor files to /usr/share/javascript)."""
    global _NOVNC
    with _NOVNC_LOCK:
        if _NOVNC is None:
            r = _exec(["tar", "-chf", "-", "-C", NOVNC_DIR, *NOVNC_PARTS], timeout=60)
            if r.returncode != 0:
                raise RuntimeError(f"cannot read the noVNC client in {stack.BROWSER_CTR} (rc {r.returncode})")
            _NOVNC = parse_tar(r.stdout)
        return _NOVNC


# ---------------------------------------------------------------- the screen tunnel
def open_tunnel() -> subprocess.Popen:
    """A byte pipe to x11vnc (127.0.0.1:VNC_PORT inside bh-browser): write RFB to stdin, read it from stdout."""
    return subprocess.Popen(
        ["podman", "exec", "-i", "--user", stack.BROWSER_USER, stack.BROWSER_CTR, "python3", "-I", "-c", PIPE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )
