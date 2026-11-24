"""Gate policy, independent of mitmproxy so it can be unit-tested.

Classes of destination:
- system  : the Claude API. Reached ONLY through the gate's relay listener (reverse proxy on RELAY_PORT,
            which injects the OAuth token); a direct CONNECT from the sandbox is denied, so the token
            never exists in the sandbox and no other credential can be used from it.
- passive : third-party recon sources (archives, CT logs). GET/HEAD without body only, no program
            headers, no identities, own rate limit, public IPs only. Never a target.
- target  : decided by bh.scope.check / check_resolved. Program headers, identities, rate limit.
Everything else is denied. Decisions are made on the real destination (the CONNECT target or the
absolute request URL), never on the Host header alone.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from bh.agent.contract import PASSIVE_DENY_PATHS, is_passive, origin, path_key
from bh.scope import Decision, Scope, check, check_resolved, load_scope

# Upstream of the relay (CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 removes telemetry hosts).
SYSTEM_HOSTS = ("api.anthropic.com",)
RELAY_PORT = 8081  # gate listener: --mode=reverse:https://api.anthropic.com@8081 (container/compose.yaml)
PASSIVE_RPS = 2.0
# Ports a domain/wildcard rule authorizes; a CIDR rule (explicit IP range, e.g. a lab) authorizes any port.
WEB_PORTS = frozenset({80, 443, 8000, 8008, 8080, 8443, 8888})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# Writes that may only be made as one of our identities (our own objects); POST stays open (login, search, forms).
IDENTITY_ONLY_METHODS = frozenset({"PUT", "PATCH", "DELETE"})
ALLOWED_METHODS = SAFE_METHODS | {"POST"} | IDENTITY_ONLY_METHODS
BACKOFF_FACTOR, BACKOFF_SECONDS, MIN_RPS = 0.5, 300.0, 0.2
MAX_BODY_BYTES = 1 << 20  # larger uploads look like resource exhaustion, not a proof
# Object-id enumeration (reading other users' objects one by one) is refused, not just discouraged:
# authenticated or API requests may touch at most ID_LIMIT distinct ids per route in ID_WINDOW_S.
ID_LIMIT, ID_WINDOW_S = 4, 600
# programs that forbid scanners: this many "not found" answers on one origin in the window is a brute-force
# (ffuf, dirb, a curl loop over a wordlist), whatever tool sent it. The origin pauses until the window clears.
MISS_LIMIT, MISS_WINDOW_S = 25, 300
_API_PATH = re.compile(r"/(api|rest|graphql|v\d+)(/|$)", re.I)


def is_system(host: str) -> bool:
    return host.lower().rstrip(".") in SYSTEM_HOSTS


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


@dataclass
class Verdict:
    allowed: bool
    klass: str  # system | passive | target | deny
    reason: str
    rule: str | None = None


def deny(reason: str, rule: str | None = None) -> Verdict:
    return Verdict(False, "deny", reason, rule)


class TokenBucket:
    def __init__(self, rps: float, burst: float | None = None):
        self.rps = rps
        self.capacity = burst if burst is not None else max(1.0, rps)
        self.tokens = self.capacity
        self.ts = time.monotonic()
        self.lock = asyncio.Lock()

    async def take(self) -> float:
        """Wait for a token. Returns seconds waited."""
        waited = 0.0
        async with self.lock:
            while True:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.ts) * self.rps)
                self.ts = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return waited
                delay = (1 - self.tokens) / self.rps
                waited += delay
                await asyncio.sleep(delay)


@dataclass
class Policy:
    scope_path: Path
    scope: Scope | None = None
    scope_mtime: float = -1.0
    scope_error: str | None = None
    buckets: dict[str, TokenBucket] = field(default_factory=dict)
    backoff_until: float = 0.0  # target rate is reduced until then (429 / 503 / WAF seen)
    ids_seen: dict[str, deque] = field(default_factory=dict)  # "origin route" -> deque[(ts, ids)]
    misses: dict[str, deque] = field(default_factory=dict)  # origin -> deque[ts of 404 answers]

    def reload(self) -> None:
        """Hot-reload on mtime. Any failure leaves NO scope: everything is denied (fail closed)."""
        try:
            mtime = self.scope_path.stat().st_mtime
        except OSError:
            self.scope, self.scope_error, self.scope_mtime = None, "no active scope", -1.0
            return
        if mtime == self.scope_mtime:
            return
        self.scope_mtime = mtime
        try:
            self.scope, self.scope_error = load_scope(self.scope_path), None
        except Exception as exc:  # noqa: BLE001 - whatever the parser raises, fail closed
            self.scope, self.scope_error = None, f"invalid active scope: {exc}"
        self.buckets.pop("target", None)
        self.backoff_until = 0.0
        self.ids_seen.clear()
        self.misses.clear()

    @property
    def program(self) -> str:
        return self.scope.program if self.scope else "-"

    # ------------------------------------------------------------------ decisions
    def _target(self, target: str) -> Verdict | None:
        """Scope verdict for a target, None when the scope has no opinion (not listed)."""
        self.reload()
        if self.scope is None:
            return deny(self.scope_error or "no scope")
        d: Decision = check(self.scope, target)
        if d.allowed:
            return Verdict(True, "target", d.reason, d.rule)
        if d.rule is not None:  # explicit out-of-scope rule wins over everything
            return deny(d.reason, d.rule)
        return None

    def classify_connect(self, host: str, port: int) -> Verdict:
        """CONNECT host:port, before any byte of the tunnel is seen."""
        if is_system(host):
            return deny(f"the Claude API is only reachable through the relay (gate:{RELAY_PORT})")
        authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        v = self._target(authority)
        if v is not None:
            if v.allowed and not (v.rule or "").startswith("cidr:") and port not in WEB_PORTS:
                return deny(f"port {port} is not a web port for a domain rule", v.rule)
            return v
        if is_passive(host):
            return Verdict(port == 443, "passive" if port == 443 else "deny", f"passive source {host}")
        return deny(self.scope_error or "not in scope")

    def classify_request(
        self,
        url: str,
        host: str,
        method: str,
        *,
        host_header: str | None = None,
        identity: str | None = None,
        body_len: int = 0,
        authenticated: bool = False,
    ) -> Verdict:
        """A decrypted request. `url`/`host` are the real destination, `host_header` what the client sent."""
        method = method.upper()
        if is_system(host):
            return deny(f"the Claude API is only reachable through the relay (gate:{RELAY_PORT})")
        v = self._target(url)
        if v is not None and v.allowed:
            if host_header and host_header.lower().rstrip(".") != host.lower().rstrip("."):
                alt = self._target(url.replace(f"//{host}", f"//{host_header}", 1))
                if alt is None or not alt.allowed:
                    return deny(f"Host header {host_header!r} is not in scope")
            if method not in ALLOWED_METHODS:
                return deny(f"method {method} not allowed")
            if method in IDENTITY_ONLY_METHODS and not identity:
                return deny(f"{method} only as one of your identities (X-BH-Identity)")
            if body_len > MAX_BODY_BYTES:
                return deny(f"request body over {MAX_BODY_BYTES} bytes")
            return self._scanning(url) or self._enumeration(url, authenticated or bool(identity)) or v
        if v is not None:
            return v
        if is_passive(host):
            if host_header and host_header.lower().rstrip(".") != host.lower().rstrip("."):
                return deny("passive source with a different Host header")
            if method not in ("GET", "HEAD") or body_len:
                return deny(f"passive source {host}: {method} not allowed")
            path = url.split("://", 1)[-1].partition("/")[2]
            if any(("/" + path).startswith(p) for p in PASSIVE_DENY_PATHS.get(host.lower(), ())):
                return deny(f"passive source {host}: path not allowed")
            return Verdict(True, "passive", f"passive source {host}")
        return deny(self.scope_error or "not in scope")

    def note_answer(self, url: str, status: int) -> None:
        """Target answers feed the scanner guard (only where the program forbids scanners)."""
        if status == 404 and self.scope is not None and not self.scope.scanners_on:
            self.misses.setdefault(origin(url) or "?", deque()).append(time.time())

    def _scanning(self, url: str) -> Verdict | None:
        if self.scope is None or self.scope.scanners_on:
            return None
        q = self.misses.get(origin(url) or "?")
        if not q:
            return None
        while q and q[0] < time.time() - MISS_WINDOW_S:
            q.popleft()
        if len(q) >= MISS_LIMIT:
            return deny(
                f"scanner signature: {len(q)} not-found answers in {MISS_WINDOW_S // 60} min and this program "
                "forbids automated scanners; stop guessing paths, test what the crawl found"
            )
        return None

    def _enumeration(self, url: str, authenticated: bool) -> Verdict | None:
        """Deny the (ID_LIMIT+1)-th distinct object id on one route within the window."""
        path = urlsplit(url).path
        key = path_key(path)
        if "{id}" not in key or not (authenticated or _API_PATH.search(path)):
            return None
        ids = "/".join(seg for seg, k in zip(path.split("/"), key.split("/"), strict=False) if k == "{id}")
        route = f"{origin(url)} {key}"
        now = time.time()
        seen_q = self.ids_seen.setdefault(route, deque())
        while seen_q and seen_q[0][0] < now - ID_WINDOW_S:
            seen_q.popleft()
        seen = {i for _, i in seen_q}
        if ids not in seen and len(seen) >= ID_LIMIT:
            return deny(
                f"id enumeration on {key}: over {ID_LIMIT} distinct ids in {ID_WINDOW_S // 60} min "
                "(prove access control with your own identities' objects)"
            )
        seen_q.append((now, ids))
        return None

    def check_ip(self, host: str, ip: str) -> Verdict:
        """After resolution, before connecting. Non-targets must resolve to public addresses."""
        if is_system(host) or is_passive(host):
            klass = "system" if is_system(host) else "passive"
            ok = is_public_ip(ip)
            return Verdict(ok, klass if ok else "deny", "non-target" if ok else f"{host} resolves to non-public {ip}")
        self.reload()
        if self.scope is None:
            return deny(self.scope_error or "no scope")
        d = check_resolved(self.scope, host, ip)
        return Verdict(d.allowed, "target" if d.allowed else "deny", d.reason, d.rule)

    # ------------------------------------------------------------------ rate
    def target_rps(self) -> float | None:
        if self.scope is None:
            return None
        rps = self.scope.rate
        if time.time() < self.backoff_until:
            rps = max(MIN_RPS, rps * BACKOFF_FACTOR)
        return rps

    def penalize(self) -> None:
        """The target pushed back (429, 503, WAF): slow down for a while."""
        self.backoff_until = time.time() + BACKOFF_SECONDS

    def bucket(self, klass: str) -> TokenBucket | None:
        rps = PASSIVE_RPS if klass == "passive" else self.target_rps() if klass == "target" else None
        if rps is None:
            return None
        b = self.buckets.get(klass)
        if b is None or b.rps != rps:
            b = self.buckets[klass] = TokenBucket(rps)
        return b
