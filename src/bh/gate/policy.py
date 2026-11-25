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
import contextlib
import ipaddress
import json
import re
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

from bh.agent.contract import (
    API_PATH,
    ID_SEGMENT,
    IDENTITY_ONLY_METHODS,
    PASSIVE_DENY_PATHS,
    is_passive,
    origin,
    path_key,
)
from bh.scope import Decision, Scope, check, check_resolved, load_scope

# Upstream of the relay (CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 removes telemetry hosts).
SYSTEM_HOSTS = ("api.anthropic.com",)
RELAY_PORT = 8081  # gate listener: --mode=reverse:https://api.anthropic.com@8081 (container/compose.yaml)
PASSIVE_RPS = 2.0
# Ports a domain/wildcard rule authorizes; a CIDR rule (explicit IP range, e.g. a lab) authorizes any port.
WEB_PORTS = frozenset({80, 443, 8000, 8008, 8080, 8443, 8888})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
# Writes that may only be made as one of our identities (our own objects); POST stays open (login, search, forms).
ALLOWED_METHODS = SAFE_METHODS | {"POST"} | IDENTITY_ONLY_METHODS
BACKOFF_FACTOR, BACKOFF_SECONDS, MIN_RPS = 0.5, 300.0, 0.2
# A host that keeps answering with a WAF challenge is paused, not retried: WAF_LIMIT challenges within
# WAF_WINDOW_S deny the host for WAF_COOLDOWN_S. Nobody solves challenges during a hunt.
WAF_LIMIT, WAF_WINDOW_S, WAF_COOLDOWN_S = 3, 600.0, 3600.0
MAX_BODY_BYTES = 1 << 20  # larger uploads look like resource exhaustion, not a proof
# Object-id enumeration (reading other users' objects one by one) is refused, not just discouraged:
# authenticated or API requests may touch at most ID_LIMIT distinct ids per route in ID_WINDOW_S.
ID_LIMIT, ID_WINDOW_S, ROUTES_MAX = 4, 600, 5000
# programs that forbid scanners: this many "not found" answers on one origin in the window is a brute-force
# (ffuf, dirb, a curl loop over a wordlist), whatever tool sent it. The origin pauses until the window clears.
MISS_LIMIT, MISS_WINDOW_S = 25, 300
# An id can also travel outside the path: ?id=7, {"orderId": 7}, GraphQL variables or `user(id: 7)`.
# A parameter counts when its name names an id and its value looks like one.
ID_KEY = re.compile(r"^(pk|key|ref|no|num|number)$|(id|uuid|_no|_number)$", re.I)
_GRAPHQL_ARG = re.compile(r'\b(\w+)\s*:\s*\\?"?([\w-]+)')
BODY_SCAN_BYTES = 64 << 10


def _now() -> float:
    """Wall clock of the rate and WAF decisions (tests replace it)."""
    return time.time()


def _host_key(host: str) -> str:
    return host.lower().rstrip(".")


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
    # In memory only: a gate restart lifts every pause (acceptable, the window is one hour).
    waf_seen: dict[str, deque] = field(default_factory=dict)  # host -> deque[ts of WAF answers]
    host_blocked_until: dict[str, float] = field(default_factory=dict)  # host -> end of its WAF cooldown

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
        # WAF pauses survive a scope reload: a new run on the same program must not hit the challenge again.

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
            return _web_port(v, port) or self._waf_cooldown(host, v) or v
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
        body: bytes | None = None,
        authenticated: bool = False,
    ) -> Verdict:
        """A decrypted request. `url`/`host` are the real destination, `host_header` what the client sent."""
        method = method.upper()
        if is_system(host):
            return deny(f"the Claude API is only reachable through the relay (gate:{RELAY_PORT})")
        v = self._target(url)
        if v is not None and v.allowed:
            if paused := self._waf_cooldown(host, v):
                return paused
            if bad_port := _web_port(v, _port(url)):
                return bad_port
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
            return self._scanning(url) or self._enumeration(url, authenticated or bool(identity), body) or v
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

    def _enumeration(self, url: str, authenticated: bool, body: bytes | None = None) -> Verdict | None:
        """Deny the (ID_LIMIT+1)-th distinct object id on one route within the window. The route is the path as
        the server's router sees it: case, //, a trailing slash, ;params and %xx do not make a new route.
        Ids carried by a parameter (query string, form or JSON body, GraphQL) count on "path ?name"."""
        path = _route_path(urlsplit(url).path)
        if not (authenticated or API_PATH.search(path)):
            return None
        key = path_key(path)
        routes: list[tuple[str, str]] = []
        if "{id}" in key:
            ids = "/".join(seg for seg, k in zip(path.split("/"), key.split("/"), strict=False) if k == "{id}")
            routes.append((key, ids))
        base = "/".join("{id}" if k == "{id}" else seg for seg, k in zip(path.split("/"), key.split("/"), strict=False))
        routes += [(f"{base} ?{name}", value) for name, value in sorted(id_params(url, body))]
        if not routes:
            return None
        now = time.time()
        wanted: dict[str, set[str]] = {}
        for route_key, ids in routes:
            wanted.setdefault(route_key, set()).add(ids)
        for route_key, ids in wanted.items():  # a batch of ids in one request counts like as many requests
            seen_q = self.ids_seen.setdefault(f"{origin(url)} {route_key}", deque())
            while seen_q and seen_q[0][0] < now - ID_WINDOW_S:
                seen_q.popleft()
            seen = {i for _, i in seen_q}
            if not ids <= seen and len(seen | ids) > ID_LIMIT:
                return deny(
                    f"id enumeration on {route_key}: over {ID_LIMIT} distinct ids in {ID_WINDOW_S // 60} min "
                    "(prove access control with your own identities' objects)"
                )
        for route_key, ids in wanted.items():  # recorded only once every id of the request is allowed
            self.ids_seen[f"{origin(url)} {route_key}"].extend((now, i) for i in ids)
        if len(self.ids_seen) > ROUTES_MAX:  # bounded memory: forget routes idle for a whole window
            for r in [r for r, q in self.ids_seen.items() if not q or q[-1][0] < now - ID_WINDOW_S]:
                del self.ids_seen[r]
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
        if _now() < self.backoff_until:
            rps = max(MIN_RPS, rps * BACKOFF_FACTOR)
        return rps

    def penalize(self, host: str | None = None, waf: bool = False) -> None:
        """The target pushed back (429, 503, WAF): slow down for a while. A WAF answer also counts against
        its host, which is paused after WAF_LIMIT of them within WAF_WINDOW_S."""
        now = _now()
        self.backoff_until = now + BACKOFF_SECONDS
        if not (waf and host) or is_system(host) or is_passive(host):  # only targets are ever paused
            return
        key = _host_key(host)
        for h in [h for h, until in self.host_blocked_until.items() if until <= now]:  # bounded memory
            del self.host_blocked_until[h]
        q = self.waf_seen.setdefault(key, deque())
        q.append(now)
        while q[0] <= now - WAF_WINDOW_S:
            q.popleft()
        if len(q) >= WAF_LIMIT:
            self.host_blocked_until[key] = now + WAF_COOLDOWN_S
            del self.waf_seen[key]

    def _waf_cooldown(self, host: str, v: Verdict) -> Verdict | None:
        """Deny an allowed target while its host is paused; whatever else the request carries (identity...)."""
        if not v.allowed:
            return None
        key = _host_key(host)
        until = self.host_blocked_until.get(key)
        if until is None:
            return None
        if until <= _now():
            del self.host_blocked_until[key]
            return None
        hhmm = time.strftime("%H:%M", time.gmtime(until))
        return deny(
            f"waf-cooldown: {key} until {hhmm} UTC (repeated WAF challenges; test another host)", "waf-cooldown"
        )

    def bucket(self, klass: str) -> TokenBucket | None:
        rps = PASSIVE_RPS if klass == "passive" else self.target_rps() if klass == "target" else None
        if rps is None:
            return None
        b = self.buckets.get(klass)
        if b is None or b.rps != rps:
            b = self.buckets[klass] = TokenBucket(rps)
        return b


def _web_port(v: Verdict, port: int) -> Verdict | None:
    """Domain rules cover web ports only (a CIDR rule is an explicit grant of the address, all ports)."""
    if v.allowed and not (v.rule or "").startswith("cidr:") and port not in WEB_PORTS:
        return deny(f"port {port} is not a web port for a domain rule", v.rule)
    return None


def _port(url: str) -> int:
    u = urlsplit(url)
    try:
        return u.port or (443 if u.scheme == "https" else 80)
    except ValueError:
        return -1


def id_params(url: str, body: bytes | None) -> set[tuple[str, str]]:
    """(name, value) pairs that carry an object id: query string, form or JSON body, GraphQL query text."""
    found: set[tuple[str, str]] = set()

    def add(name, value) -> None:
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            return
        v = str(value).strip()
        if ID_KEY.search(str(name)) and ID_SEGMENT.match(v):
            found.add((str(name).lower(), v.lower()))

    def walk(obj, depth=0) -> None:
        if depth > 8:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    walk(v, depth + 1)
                elif k == "query" and isinstance(v, str):
                    for name, value in _GRAPHQL_ARG.findall(v):
                        add(name, value)
                else:
                    add(k, v)
        elif isinstance(obj, list):
            for v in obj[:200]:
                walk(v, depth + 1)

    for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if k == "query":
            walk({"query": v})
        elif k == "variables":
            with contextlib.suppress(ValueError):
                walk(json.loads(v))
        else:
            add(k, v)
    if body:
        text = body[:BODY_SCAN_BYTES].decode("utf-8", "replace")
        try:
            walk(json.loads(text))
        except ValueError:
            if "=" in text and "\n" not in text.strip():
                for k, v in parse_qsl(text, keep_blank_values=True):
                    add(k, v)
    return found


def _route_path(path: str) -> str:
    path = re.sub(r";[^/]*", "", unquote(path)).lower()
    return re.sub(r"/{2,}", "/", path).rstrip("/") or "/"
