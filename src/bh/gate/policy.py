"""Gate policy, independent of mitmproxy so it can be unit-tested.

Classes of destination:
- system  : the Claude API. TLS passthrough (never decrypted), no headers injected.
- passive : third-party recon sources (archives, CT logs). GET/HEAD without body only, no program
            headers, no identities, own rate limit, public IPs only. Never a target.
- target  : decided by bh.scope.check / check_resolved. Program headers, identities, rate limit.
Everything else is denied. Decisions are made on the real destination (the CONNECT target or the
absolute request URL), never on the Host header alone.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from dataclasses import dataclass, field
from pathlib import Path

from bh.agent.contract import PASSIVE_DENY_PATHS, is_passive
from bh.scope import Decision, Scope, check, check_resolved, load_scope

# Only what `claude -p` needs (CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 removes telemetry hosts).
SYSTEM_HOSTS = ("api.anthropic.com",)
SYSTEM_PORT = 443
PASSIVE_RPS = 2.0
# Ports a domain/wildcard rule authorizes; a CIDR rule (explicit IP range, e.g. a lab) authorizes any port.
WEB_PORTS = frozenset({80, 443, 8000, 8008, 8080, 8443, 8888})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# Writes that may only be made as one of our identities (our own objects); POST stays open (login, search, forms).
IDENTITY_ONLY_METHODS = frozenset({"PUT", "PATCH", "DELETE"})
ALLOWED_METHODS = SAFE_METHODS | {"POST"} | IDENTITY_ONLY_METHODS
BACKOFF_FACTOR, BACKOFF_SECONDS, MIN_RPS = 0.5, 300.0, 0.2


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
            return Verdict(port == SYSTEM_PORT, "system" if port == SYSTEM_PORT else "deny", "claude api")
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
        has_body: bool = False,
    ) -> Verdict:
        """A decrypted request. `url`/`host` are the real destination, `host_header` what the client sent."""
        method = method.upper()
        if is_system(host):
            return Verdict(True, "system", "claude api")
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
            return v
        if v is not None:
            return v
        if is_passive(host):
            if host_header and host_header.lower().rstrip(".") != host.lower().rstrip("."):
                return deny("passive source with a different Host header")
            if method not in ("GET", "HEAD") or has_body:
                return deny(f"passive source {host}: {method} not allowed")
            path = url.split("://", 1)[-1].partition("/")[2]
            if any(("/" + path).startswith(p) for p in PASSIVE_DENY_PATHS.get(host.lower(), ())):
                return deny(f"passive source {host}: path not allowed")
            return Verdict(True, "passive", f"passive source {host}")
        return deny(self.scope_error or "not in scope")

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
