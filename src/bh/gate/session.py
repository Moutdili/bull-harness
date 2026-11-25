"""Identity sessions as the gate keeps them: injected headers, a cookie jar, session-dead detection.

Pure (no mitmproxy): the addon calls these functions, the tests call them directly.

Session file `var/state/identities/<program>/<name>.json` (gate: /state/identities/...), 0600, never mounted
in the agent. Every field but `headers` is optional, so a file of the old shape `{"headers": {...}}` still works:

    {
      "headers":    {"Authorization": "Bearer ..."},       # injected as is (a "Cookie" header joins the jar's)
      "cookies":    {"<domain>": {"<name>": {"value": "...", "path": "/", "expires": 1767225600.0 | null,
                                             "host_only": true, "secure": false}}},
      "expires_at": 1767225600.0 | null,                  # the session as a whole (written by the host's login)
      "probe":      {"url": "https://x/api/me", "status": 200} | null,
      "updated":    1764000000.0
    }

`<domain>` has no leading dot. `host_only` true: only that exact host gets the cookie; false: its subdomains too
(the RFC 6265 `Domain` attribute). A browser export (`context.cookies()`) writes `.example.com` for a domain
cookie: loading reads the leading dot as `host_only: false`. `expires` null is a session cookie: it lives as long
as the file (the gate is a browser that never closes). One cookie per (domain, name): a second path for the same
name replaces the first, a simplification no session cookie we know of needs.

Writers: the gate merges Set-Cookie under `lock()`, re-reads the file inside the lock, and replaces it with
`os.replace` (temp file in the same directory, 0600). Another writer (the host's login, issue 25) should write
the same way (temp + rename), and take `lock()` too when it read-modifies-writes.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

from bh.scope.normalize import norm_host, parse_ip
from bh.scope.psl import is_public_suffix

MAX_DOMAINS = 16  # a hostile target must not grow the session file without bound
MAX_COOKIES_PER_DOMAIN = 64
MAX_COOKIE_BYTES = 4096  # name + value, the usual browser limit
DEAD_WINDOW_S = 60  # at most one session-dead event per identity in this window
REDIRECTS = (301, 302, 303, 307, 308)
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")  # RFC 7230 token: a cookie name

Session = dict[str, Any]
Cookie = dict[str, Any]


# ---------------------------------------------------------------- load / save
def _norm_cookie(c: Any, now: float) -> Cookie | None:
    if not isinstance(c, dict) or not isinstance(c.get("value"), str):
        return None
    exp = c.get("expires")
    if isinstance(exp, bool) or not isinstance(exp, (int, float, type(None))):
        return None
    if exp is not None and exp < 0:  # Playwright writes -1 for a session cookie
        exp = None
    if exp is not None and exp <= now:
        return None
    path = c.get("path")
    return {
        "value": c["value"],
        "path": path if isinstance(path, str) and path.startswith("/") else "/",
        "expires": float(exp) if exp is not None else None,
        "host_only": c.get("host_only") is not False,
        "secure": c.get("secure") is True,
    }


def _norm_jar(raw: Any, now: float) -> dict[str, dict[str, Cookie]]:
    jar: dict[str, dict[str, Cookie]] = {}
    if not isinstance(raw, dict):
        return jar
    for dom, cookies in raw.items():
        if not isinstance(dom, str) or not isinstance(cookies, dict):
            continue
        domain_cookie = dom.startswith(".")
        try:
            d = norm_host(dom.lstrip("."))
        except ValueError:
            continue
        for name, c in cookies.items():
            if not isinstance(name, str) or not _TOKEN.fullmatch(name):
                continue
            if domain_cookie and isinstance(c, dict) and "host_only" not in c:
                nc = _norm_cookie({**c, "host_only": False}, now)
            else:
                nc = _norm_cookie(c, now)
            if nc is not None:
                jar.setdefault(d, {})[name] = nc
    return jar


def normalize(raw: Any, now: float | None = None) -> Session | None:
    """A session file's content in the current shape (expired cookies dropped), None if it is no session."""
    if not isinstance(raw, dict):
        return None
    now = time.time() if now is None else now
    headers = raw.get("headers") or {}
    if not isinstance(headers, dict):
        return None
    probe = raw.get("probe")
    exp = raw.get("expires_at")
    return {
        "headers": {str(k): str(v) for k, v in headers.items() if isinstance(v, str)},
        "cookies": _norm_jar(raw.get("cookies"), now),
        "expires_at": float(exp) if isinstance(exp, (int, float)) and not isinstance(exp, bool) else None,
        "probe": (
            {"url": probe["url"], "status": probe["status"]}
            if isinstance(probe, dict)
            and isinstance(probe.get("url"), str)
            and isinstance(probe.get("status"), int)
            and not isinstance(probe.get("status"), bool)
            else None
        ),
        "updated": raw.get("updated"),
    }


def load(path: Path, now: float | None = None) -> Session | None:
    try:
        return normalize(json.loads(path.read_text(encoding="utf-8")), now)
    except (OSError, ValueError):
        return None


def save(path: Path, session: Session) -> None:
    """Atomic replace: readers see the old file or the new one, never half of one. Created 0600."""
    fd, tmp = tempfile.mkstemp(prefix=f".{path.stem}.", suffix=".tmp", dir=path.parent)  # mkstemp: 0600
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(session, fh, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


_THREAD_LOCK = threading.Lock()


@contextlib.contextmanager
def lock(path: Path) -> Iterator[None]:
    """One writer at a time for this session: a thread lock (mitmproxy's workers) and an flock on a side file
    (other processes: the host's login). The lock file is `.<name>.lock`, not a `*.json`, so it is no identity."""
    with _THREAD_LOCK:
        fd = os.open(path.parent / f".{path.stem}.lock", os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)  # closing releases the flock


def update(path: Path, change: Callable[[Session], bool], now: float | None = None) -> bool:
    """Read, change in place, write back if `change` says it changed something. False (file untouched) when the
    file is gone or is no session: the gate never creates an identity."""
    with lock(path):
        session = load(path, now)
        if session is None or not change(session):
            return False
        session["updated"] = round(time.time() if now is None else now, 3)
        save(path, session)
        return True


# ---------------------------------------------------------------- Set-Cookie -> jar
def _expiry(value: str) -> float | None:
    try:
        return parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError, IndexError):
        pass
    try:  # the Netscape form "Wed, 21-Oct-2026 07:28:00 GMT"
        return parsedate_to_datetime(re.sub(r"(\d{1,2})-(\w{3})-(\d{2,4})", r"\1 \2 \3", value)).timestamp()
    except (TypeError, ValueError, IndexError):
        return None


def parse_set_cookie(header: str, now: float) -> dict[str, Any] | None:
    """One Set-Cookie value -> {name, value, domain, path, expires, secure, delete}. None if malformed.
    `expires`: absolute time from Max-Age (wins) or Expires, None for a session cookie."""
    first, *attrs = header.split(";")
    name, eq, value = first.partition("=")
    name, value = name.strip(), value.strip()
    if not eq or not _TOKEN.fullmatch(name) or len(name) + len(value) > MAX_COOKIE_BYTES:
        return None
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    out: dict[str, Any] = {"name": name, "value": value, "domain": None, "path": None, "secure": False}
    max_age: float | None = None
    expires: float | None = None
    for a in attrs:
        k, _, v = a.partition("=")
        k, v = k.strip().lower(), v.strip()
        if k == "max-age" and re.fullmatch(r"-?\d{1,12}", v):
            max_age = now + int(v) if int(v) > 0 else float("-inf")
        elif k == "expires":
            expires = _expiry(v)
        elif k == "domain" and v:
            out["domain"] = v.lstrip(".")
        elif k == "path" and v.startswith("/"):
            out["path"] = v
        elif k == "secure":
            out["secure"] = True
    out["expires"] = max_age if max_age is not None else expires
    out["delete"] = out["expires"] is not None and out["expires"] <= now
    if out["delete"]:
        out["expires"] = None
    return out


def _default_path(request_path: str) -> str:
    """RFC 6265 5.1.4: the directory of the request path."""
    p = request_path.split("?", 1)[0]
    if not p.startswith("/") or p.count("/") == 1:
        return "/"
    return p[: p.rindex("/")]


def _domain_matches(host: str, domain: str) -> bool:
    return host == domain or (host.endswith("." + domain) and parse_ip(host) is None)


def merge(session: Session, url: str, set_cookies: list[str], now: float | None = None) -> list[str]:
    """Fold the Set-Cookie values of one response into the jar. `url` is the request's, its host already judged
    in scope by the caller. A `Domain` that is not this host or one of its parents (another site), or that is a
    public suffix, is ignored. Max-Age <= 0 or an Expires in the past deletes. Returns the names changed."""
    now = time.time() if now is None else now
    parts = urlsplit(url)
    try:
        host = norm_host(parts.hostname or "")
    except ValueError:
        return []
    jar: dict[str, dict[str, Cookie]] = session.setdefault("cookies", {})
    changed: list[str] = []
    for raw in set_cookies:
        c = parse_set_cookie(raw, now)
        if c is None:
            continue
        host_only = True
        domain = host
        if c["domain"]:
            try:
                d = norm_host(c["domain"])
            except ValueError:
                continue
            if not _domain_matches(host, d):
                continue  # Domain of another site: never stored, never sent
            if d != host:
                if is_public_suffix(d):
                    continue  # Domain=co.uk would share the cookie with every site under it
                domain, host_only = d, False
            elif parse_ip(host) is None:
                host_only = False
        if c["secure"] and parts.scheme != "https":
            continue  # RFC 6265bis: an insecure origin cannot set a Secure cookie
        if c["delete"]:
            if jar.get(domain, {}).pop(c["name"], None) is not None:
                changed.append(c["name"])
                if not jar[domain]:
                    del jar[domain]
            continue
        cookies = jar.get(domain, {})
        if domain not in jar and len(jar) >= MAX_DOMAINS:
            continue
        if c["name"] not in cookies and len(cookies) >= MAX_COOKIES_PER_DOMAIN:
            continue
        new = {
            "value": c["value"],
            "path": c["path"] or _default_path(parts.path or "/"),
            "expires": c["expires"],
            "host_only": host_only,
            "secure": c["secure"],
        }
        if cookies.get(c["name"]) != new:
            jar.setdefault(domain, {})[c["name"]] = new
            changed.append(c["name"])
    return changed


def absorb(file: Path | None, url: str, set_cookies: list[str], *, in_scope: bool, now: float | None = None) -> bool:
    """The gate's entry point on a response: the Set-Cookie of an answer to a request made under an identity
    (`file`: that identity's session) to an in-scope target go into the jar. No identity, out of scope, or no
    Set-Cookie: the file is not touched. True if the file was rewritten."""
    if file is None or not in_scope or not set_cookies:
        return False
    return update(file, lambda s: bool(merge(s, url, set_cookies, now)), now)


def expire(session: Session, now: float | None = None) -> bool:
    """Drop the jar's expired cookies. True if one was dropped."""
    now = time.time() if now is None else now
    jar = session.get("cookies") or {}
    dropped = False
    for dom in list(jar):
        for name in [n for n, c in jar[dom].items() if c["expires"] is not None and c["expires"] <= now]:
            del jar[dom][name]
            dropped = True
        if not jar[dom]:
            del jar[dom]
    return dropped


# ---------------------------------------------------------------- jar -> Cookie header
def _path_matches(request_path: str, cookie_path: str) -> bool:
    if request_path == cookie_path:
        return True
    return request_path.startswith(cookie_path) and (cookie_path.endswith("/") or request_path[len(cookie_path)] == "/")


def cookies_for(session: Session, url: str, now: float | None = None) -> list[tuple[str, str]]:
    """(name, value) pairs of the jar that a browser would send to `url`: domain, path, Secure and expiry
    respected. Longer paths first (RFC 6265 5.4); for one name, the most specific domain wins."""
    now = time.time() if now is None else now
    parts = urlsplit(url)
    try:
        host = norm_host(parts.hostname or "")
    except ValueError:
        return []
    path = parts.path or "/"
    hits: list[tuple[int, int, str, str]] = []
    for dom, cookies in (session.get("cookies") or {}).items():
        if not _domain_matches(host, dom):
            continue
        for name, c in cookies.items():
            if c["host_only"] and host != dom:
                continue
            if c["expires"] is not None and c["expires"] <= now:
                continue
            if c["secure"] and parts.scheme != "https":
                continue
            if not _path_matches(path, c["path"]):
                continue
            hits.append((len(c["path"]), len(dom), name, c["value"]))
    hits.sort(key=lambda h: (-h[0], -h[1]))
    seen: set[str] = set()
    out = []
    for _, _, name, value in hits:
        if name not in seen:
            seen.add(name)
            out.append((name, value))
    return out


def parse_cookie_header(value: str | None) -> list[tuple[str, str]]:
    out = []
    for part in (value or "").split(";"):
        name, eq, val = part.strip().partition("=")
        if eq and name:
            out.append((name.strip(), val.strip()))
    return out


def combine(agent_cookie: str | None, identity: list[tuple[str, str]]) -> tuple[str | None, list[str]]:
    """The Cookie header sent under an identity, and the names of the agent's cookies it replaced.

    Rule: for a name the identity holds, the identity's value is sent and the agent's dropped; the agent's other
    cookies pass unchanged. A request under X-BH-Identity may write (PUT/PATCH/DELETE), and those writes must act
    as our own test account: an agent value for the session cookie (seen in some response, maybe someone else's)
    must not ride on the identity's permission. The replaced names are recorded in the flow, so the agent sees
    that its value was not sent; to send its own value, it sends the request without the identity."""
    ident_names = {n for n, _ in identity}
    agent = parse_cookie_header(agent_cookie)
    replaced = sorted({n for n, _ in agent if n in ident_names})
    pairs = identity + [(n, v) for n, v in agent if n not in ident_names]
    return ("; ".join(f"{n}={v}" for n, v in pairs) or None), replaced


def mask_set_cookie(header: str, placeholder: str) -> str:
    """The Set-Cookie line the agent receives under an identity: same name and attributes (HttpOnly, SameSite...
    stay testable), the value replaced by a placeholder. The real value only lives in the jar."""
    first, sep, attrs = header.partition(";")
    name, eq, _ = first.partition("=")
    return f"{name.strip()}={placeholder}{sep}{attrs}" if eq else placeholder


# ---------------------------------------------------------------- session-dead
def _same_page(a: str, b: str) -> bool:
    """Same scheme, host, port and path (trailing slash and query ignored)."""
    pa, pb = urlsplit(a), urlsplit(b)
    try:
        return (
            pa.scheme.lower() == pb.scheme.lower()
            and norm_host(pa.hostname or "") == norm_host(pb.hostname or "")
            and (pa.port or (443 if pa.scheme == "https" else 80)) == (pb.port or (443 if pb.scheme == "https" else 80))
            and (pa.path.rstrip("/") or "/") == (pb.path.rstrip("/") or "/")
        )
    except ValueError:
        return False


def dead_reason(
    method: str,
    url: str,
    status: int,
    location: str | None,
    *,
    login_url: str | None = None,
    probe: dict | None = None,
) -> str | None:
    """Why a response to a request under an identity says its session is dead, None if it does not:
    `401`; `login-redirect` (a redirect whose Location is the identity's declared login page);
    `probe` (a GET of the declared probe URL that does not answer the expected status)."""
    if status == 401:
        return "401"
    if status in REDIRECTS and location and login_url and _same_page(urljoin(url, location), login_url):
        return "login-redirect"
    if (
        isinstance(probe, dict)
        and method == "GET"
        and isinstance(probe.get("url"), str)
        and isinstance(probe.get("status"), int)
        and _same_page(url, probe["url"])
        and status != probe["status"]
    ):
        return "probe"
    return None


class DeadLimiter:
    """At most one session-dead event per identity in DEAD_WINDOW_S."""

    def __init__(self, window: float = DEAD_WINDOW_S) -> None:
        self.window = window
        self._last: dict[str, float] = {}

    def allow(self, identity: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        if now - self._last.get(identity, float("-inf")) < self.window:
            return False
        self._last[identity] = now
        return True
