"""Gate policy, independent of mitmproxy so it can be unit-tested.

Three classes of destination:
- system  : Claude API endpoints. TLS passthrough (never decrypted), no headers injected.
- passive : third-party recon sources (archives, CT logs). GET/HEAD only, no program
            headers, no identities, own rate limit. Never a target.
- target  : decided by bh.scope.check / check_resolved. Program headers + rate limit.
Everything else is denied.
"""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from bh.agent.contract import PASSIVE_SUFFIXES
from bh.scope import Decision, Scope, ScopeError, check, check_resolved, load_scope

SYSTEM_HOSTS = (
    "api.anthropic.com",
    "statsig.anthropic.com",
    "console.anthropic.com",
    "claude.ai",
    "platform.claude.com",
)
# Regex for mitmproxy --ignore-hosts (TLS passthrough).
SYSTEM_IGNORE_REGEX = "|".join(rf"^{re.escape(h)}:443$" for h in SYSTEM_HOSTS)

PASSIVE_RPS = 2.0


def _suffix_match(host: str, suffixes: tuple[str, ...]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == s or host.endswith("." + s) for s in suffixes)


def is_system(host: str) -> bool:
    return host.lower().rstrip(".") in SYSTEM_HOSTS


def is_passive(host: str) -> bool:
    return _suffix_match(host, PASSIVE_SUFFIXES)


@dataclass
class Verdict:
    allowed: bool
    klass: str  # system | passive | target | deny
    reason: str
    rule: str | None = None


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

    def reload(self) -> None:
        try:
            mtime = self.scope_path.stat().st_mtime
        except FileNotFoundError:
            self.scope, self.scope_error, self.scope_mtime = None, "no active scope", -1.0
            return
        if mtime == self.scope_mtime:
            return
        self.scope_mtime = mtime
        try:
            self.scope, self.scope_error = load_scope(self.scope_path), None
        except ScopeError as exc:
            self.scope, self.scope_error = None, f"invalid active scope: {exc}"
        self.buckets.pop("target", None)

    @property
    def program(self) -> str:
        return self.scope.program if self.scope else "-"

    def classify(self, target: str, host: str, method: str | None = None) -> Verdict:
        """target: URL (decrypted request) or host:port (CONNECT)."""
        if is_system(host):
            return Verdict(True, "system", "claude api")
        self.reload()
        reason = self.scope_error or "not in scope"
        if self.scope is not None:
            d: Decision = check(self.scope, target)
            if d.allowed:
                return Verdict(True, "target", d.reason, d.rule)
            if d.rule is not None:  # explicit out-of-scope rule wins over everything
                return Verdict(False, "deny", d.reason, d.rule)
            reason = d.reason
        if is_passive(host):
            if method is not None and method.upper() not in ("GET", "HEAD"):
                return Verdict(False, "deny", f"passive source {host}: {method} not allowed")
            return Verdict(True, "passive", f"passive source {host}")
        return Verdict(False, "deny", reason)

    def check_ip(self, host: str, ip: str) -> Verdict:
        if is_system(host) or is_passive(host):
            return Verdict(True, "system" if is_system(host) else "passive", "non-target")
        if self.scope is None:
            return Verdict(False, "deny", self.scope_error or "no scope")
        d = check_resolved(self.scope, host, ip)
        return Verdict(d.allowed, "target" if d.allowed else "deny", d.reason, d.rule)

    def bucket(self, klass: str) -> TokenBucket | None:
        if klass == "passive":
            rps = PASSIVE_RPS
        elif klass == "target" and self.scope is not None and self.scope.max_rps:
            rps = self.scope.max_rps
        else:
            return None
        b = self.buckets.get(klass)
        if b is None or b.rps != rps:
            b = self.buckets[klass] = TokenBucket(rps)
        return b
