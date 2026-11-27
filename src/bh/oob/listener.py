"""Out-of-band listener (T23, W4): stdlib, HTTP only, bound to a loopback address.

Tailscale Funnel publishes it under a `.ts.net` name; the orchestrator opens Funnel at the start of a run and resets
it after (no Tailscale command here). The callback a target's server may take is `https://<name>/c/<canary>`: for a
request whose path is exactly `/c/BH-SECRET-<16 hex>` (bh.agent.contract.CANARY_RE; a query is ignored, never kept),
one JSONL line `{"ts", "proto": "http", "token", "src"}` is appended to the journal, `src` being the peer address as
the socket gives it (no header is interpreted: behind Funnel it may be the local relay). Any other request writes
nothing.

What it keeps: the canary, the time, the peer address. Never a body (none is read), a header (read to the blank line
and dropped), the method, the rest of the URL, a port. The answer is the same bytes for every request, canary or not,
malformed or not: `204 No Content`, empty, the connection closed. It serves no content, hosts nothing and never
redirects. The journal is bounded: past `max_bytes` it rotates to `<name>.1` .. `<name>.<keep>` (the oldest dropped);
bh.runner.observation reads the live file and the rotated ones.

    python -I -m bh.oob.listener --port 8792 --journal var/oob/oob.jsonl
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import socket
import socketserver
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from bh.agent.contract import CANARY_RE

RESPONSE = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"  # the only bytes ever sent
CALLBACK_PREFIX = "/c/"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8792
DEFAULT_JOURNAL = "var/oob/oob.jsonl"
MAX_BYTES = 1 << 20  # live journal size before rotation
KEEP = 4  # rotated files kept
LINE_MAX = 8192  # request line and each header line; longer: nothing written
HEADERS_MAX = 100  # header lines read (and dropped) before answering
TIMEOUT = 5.0  # seconds a client has to send its request line and headers


def token_of(request_line: bytes) -> str | None:
    """The canary of a request line `METHOD /c/<canary>[?query] HTTP/x`, or None. The target may be absolute
    (`http://name/c/<canary>`); the path must be exactly `/c/` and one canary, nothing before or after it."""
    try:
        parts = request_line.decode("ascii").split()
    except UnicodeDecodeError:
        return None
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        return None
    target = parts[1]
    if "://" in target:
        try:
            target = urlsplit(target).path
        except ValueError:
            return None
    path = target.split("?", 1)[0].split("#", 1)[0]
    if not path.startswith(CALLBACK_PREFIX):
        return None
    token = path[len(CALLBACK_PREFIX) :]
    return token if CANARY_RE.fullmatch(token) else None


class Journal:
    """Append-only JSONL, bounded: past `max_bytes` the live file becomes `<name>.1` (and `.1` `.2`, ...), at most
    `keep` rotated files. One lock: lines are whole and ordered."""

    def __init__(self, path: str | Path, max_bytes: int = MAX_BYTES, keep: int = KEEP):
        self.path = Path(path)
        self.max_bytes, self.keep = max(256, int(max_bytes)), max(1, int(keep))
        self.lock = threading.Lock()

    def _rotate(self) -> None:
        for n in range(self.keep, 0, -1):
            src = self.path if n == 1 else self.path.with_name(f"{self.path.name}.{n - 1}")
            if src.exists():
                os.replace(src, self.path.with_name(f"{self.path.name}.{n}"))

    def write(self, token: str, src: str) -> None:
        line = json.dumps({"ts": time.time(), "proto": "http", "token": token, "src": src}) + "\n"
        data = line.encode()
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                size = self.path.stat().st_size
            except OSError:
                size = 0
            if size and size + len(data) > self.max_bytes:
                self._rotate()
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, data)
            finally:
                os.close(fd)


class Handler(socketserver.StreamRequestHandler):
    """Reads the request line and the headers (dropped), never a body; answers RESPONSE; closes."""

    timeout = TIMEOUT
    rbufsize = 0  # unbuffered: not one byte past the blank line is ever read from the socket
    server: Server

    def handle(self) -> None:
        token = None
        try:
            line = self.rfile.readline(LINE_MAX + 1)
            if len(line) <= LINE_MAX:
                token = token_of(line.rstrip(b"\r\n"))
                for _ in range(HEADERS_MAX):  # to the blank line, so the answer is not cut by an unread header
                    h = self.rfile.readline(LINE_MAX + 1)
                    if h in (b"\r\n", b"\n", b""):
                        break
                    if len(h) > LINE_MAX:
                        token = None
                        break
        except (OSError, ValueError):
            token = None
        if token is not None:
            with contextlib.suppress(OSError):  # the answer never depends on the journal
                self.server.journal.write(token, str(self.client_address[0]))
        try:
            self.wfile.write(RESPONSE)
            self.wfile.flush()
            self.connection.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, host: str, port: int, journal: Journal):
        self.journal = journal
        if ":" in host:
            self.address_family = socket.AF_INET6
        super().__init__((host, port), Handler)


def serve(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, journal: str | Path = DEFAULT_JOURNAL,
          max_bytes: int = MAX_BYTES, keep: int = KEEP) -> Server:  # fmt: skip
    """A bound server (not yet serving): call `serve_forever()` on it, `shutdown()` to stop."""
    return Server(host, port, Journal(journal, max_bytes, keep))


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="bh-oob", description="out-of-band listener: one line per /c/<canary>")
    ap.add_argument("--host", default=DEFAULT_HOST, help="address to bind (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=int(os.environ.get("BH_OOB_PORT", DEFAULT_PORT)))
    ap.add_argument("--journal", default=os.environ.get("BH_OOB_JOURNAL", DEFAULT_JOURNAL))
    ap.add_argument("--max-bytes", type=int, default=MAX_BYTES)
    ap.add_argument("--keep", type=int, default=KEEP)
    a = ap.parse_args(argv)
    srv = serve(a.host, a.port, a.journal, a.max_bytes, a.keep)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
