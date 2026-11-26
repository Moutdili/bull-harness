"""Gate policy, independent of mitmproxy so it can be unit-tested.

Classes of destination:
- system  : the Claude API. Reached ONLY through the gate's relay listener (reverse proxy on RELAY_PORT,
            which injects the OAuth token); a direct CONNECT from the sandbox is denied, so the token
            never exists in the sandbox and no other credential can be used from it.
- passive : third-party recon sources (archives, CT logs). GET/HEAD without body only, no program
            headers, no identities, own rate limit, public IPs only. Never a target.
- target  : decided by bh.scope.check / check_resolved. Program headers, identities, rate limit.
- support : hosts of the scope's `support` list, never targets. `assets` (what the targets' pages load): GET/HEAD
            without body from any sandbox client, no program headers, no identity, no Cookie / Authorization.
            `auth` (our own login): the enrollment sources only (the gate and bh-login), the login's methods;
            the hunter and the judge are refused ("login host, enrollment only"). `sso` (a login host the
            application calls while in use: silent sign-in iframe, token exchange): GET/HEAD without body only under
            the scope's `get_paths` (bh-browser: any path, it is the application), POST only on its `token_paths`
            (the enrollment sources: the login's methods anywhere); no program header, only the identity's own jar
            cookies for that host. `passthrough` (a third-party anti-bot challenge): CONNECT to 443 from bh-browser
            only, the TLS never intercepted (addon: ignore_hosts), nothing of ours inside, bounded
            (PassthroughGuard); a decrypted request to it is refused. Own rate limit, public IPs only, never a test
            (flows class `support`, outside the asset graph and the counts).
Websockets (scope `websockets: true`, refused otherwise): the handshake is a target request like any other
(scope, identity, program headers, rate); then every message is bounded and journaled (WsGuard).
The persistent browser (`browser`: the client is bh-browser, B2): when the scope has a passthrough host, only it may
open the passthrough tunnel and a websocket; a target path under the scope's `browser_only` prefixes is refused to
every other client, whatever the method ("browser only"). Its traffic is never paused by the WAF guard nor counted by
the not-found guard (a human passes its challenges, the application makes its own 404s).
Everything else is denied. Decisions are made on the real destination (the CONNECT target or the
absolute request URL), never on the Host header alone.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit

from bh.agent.contract import (
    API_PATH,
    IDENTITY_ONLY_METHODS,
    PASSIVE_DENY_PATHS,
    is_passive,
    origin,
    path_key,
)
from bh import redact
from bh.scope import Decision, Scope, check, check_resolved, load_scope
from bh.scope.enforce import browser_only, check_support_resolved, support_entry

# Upstream of the relay (CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 removes telemetry hosts).
SYSTEM_HOSTS = ("api.anthropic.com",)
RELAY_PORT = 8081  # gate listener: --mode=reverse:https://api.anthropic.com@8081 (container/compose.yaml)
PASSIVE_RPS = 2.0
# support hosts (assets a page loads, our login): their own bucket, so a page's twenty scripts neither wait behind the
# target's rate nor take from it; bounded all the same
SUPPORT_RPS, SUPPORT_BURST = 4.0, 8.0
# what an enrollment login may send to an `auth` support host
SUPPORT_AUTH_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST"})
# a passthrough tunnel (anti-bot challenge, never intercepted): new tunnels per minute, open at once, bytes both ways
# and lifetime per tunnel. A challenge loads a script and an iframe: a few tunnels, a few hundred kB.
PASSTHROUGH_PER_MIN, PASSTHROUGH_OPEN = 20, 6
PASSTHROUGH_MAX_BYTES, PASSTHROUGH_MAX_SECONDS = 16 << 20, 600.0  # overridable: BH_PASSTHROUGH_* (PassthroughGuard)
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
# authenticated or API requests may touch at most ID_LIMIT distinct ids per route in ID_WINDOW_S. Only the ids of the
# path count (I6): a query or body parameter (telemetry `eventid`, a search filter) is no object read.
ID_LIMIT, ID_WINDOW_S, ROUTES_MAX = 12, 600, 5000
# programs that forbid scanners: this many "not found" answers on one origin in the window is a brute-force
# (ffuf, dirb, a curl loop over a wordlist), whatever tool sent it. The origin pauses until the window clears.
MISS_LIMIT, MISS_WINDOW_S = 25, 300
# What makes an answer a WAF's own page (challenge, block page), not the application's. Never the Server header
# alone: Cloudflare or Akamai put their name on every answer they relay, the application's 403 included.
WAF_MARKERS = re.compile(
    rb"(Attention Required!? \| Cloudflare|Just a moment\.\.\.|cf-chl-|cf-error-details|error code: 1020|"
    rb"_Incapsula_Resource|Request unsuccessful\. Incapsula|Access Denied.{0,200}Reference #|"
    rb"The requested URL was rejected|Request blocked\..{0,100}(AWS|CloudFront)|Sucuri WebSite Firewall|"
    rb"captcha-delivery\.com|px-captcha)",
    re.I | re.S,
)
WAF_STATUS = (403, 429, 503)
WAF_SCAN_BYTES = 64 << 10


def _now() -> float:
    """Wall clock of the rate and WAF decisions (tests replace it)."""
    return time.time()


def _host_key(host: str) -> str:
    return host.lower().rstrip(".")


def is_system(host: str) -> bool:
    return host.lower().rstrip(".") in SYSTEM_HOSTS


def is_self_address(ip: str, local: frozenset[str] = frozenset()) -> bool:
    """The gate itself as a destination: loopback, the unspecified address, or one of the gate's own addresses
    (`local`). Refused whatever the scope says: an agent that chains the proxy onto itself escapes the flow log."""
    try:
        addr = ipaddress.ip_address(ip.strip("[]").split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return addr.is_loopback or addr.is_unspecified or str(addr) in local


def is_waf(status: int, headers: dict[str, str] | None, body: bytes | None) -> bool:
    """An answer the WAF made: `cf-mitigated`, or a challenge / block page in the body. The `Server` header and
    the status alone never count, so the application's own 403 behind Cloudflare is no WAF answer."""
    if status not in WAF_STATUS:
        return False
    if any(k.lower() == "cf-mitigated" for k in (headers or {})):
        return True
    return bool(WAF_MARKERS.search((body or b"")[:WAF_SCAN_BYTES]))


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


@dataclass
class Verdict:
    allowed: bool
    klass: str  # system | passive | target | support | deny
    reason: str
    rule: str | None = None
    support: str | None = None  # kind of a `support` verdict: "auth" | "assets" | "sso" | "passthrough"


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
    local_ips: frozenset[str] = frozenset()  # the gate's own addresses (never a destination, B3)
    ws_limits: WsLimits = field(default_factory=lambda: WsLimits.from_env())  # noqa: PLW0108 - defined below
    ws_limits_browser: WsLimits = field(default_factory=lambda: WsLimits.from_env(browser=True))
    ws_live: dict[str, WsGuard] = field(default_factory=dict)  # open websocket (flow id) -> its guard
    passthrough: PassthroughGuard = field(default_factory=lambda: PassthroughGuard.from_env())  # noqa: PLW0108 - below

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
        if d.support is not None:
            return Verdict(True, "support", d.reason, None, d.support)
        if d.rule is not None:  # explicit out-of-scope rule wins over everything
            return deny(d.reason, d.rule)
        return None

    def has_passthrough(self) -> bool:
        return self.scope is not None and any(s.kind == "passthrough" for s in self.scope.support)

    def classify_connect(self, host: str, port: int, *, enroll: bool = False, browser: bool = False) -> Verdict:
        """CONNECT host:port, before any byte of the tunnel is seen. `enroll`: the client is an enrollment source;
        `browser`: the client is bh-browser."""
        if is_system(host):
            return deny(f"the Claude API is only reachable through the relay (gate:{RELAY_PORT})")
        if is_self_address(host, self.local_ips):
            return deny(f"{host} is the gate itself", "self")
        authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        v = self._target(authority)
        if v is not None and v.klass == "support":
            if v.support == "passthrough" and port != 443:
                return deny(f"passthrough host {host}: port {port} (a TLS tunnel to 443 only, never in clear)")
            if v.support == "passthrough" and not browser:
                return deny(f"browser only: the challenge host {host} is reached by bh-browser only", "browser-only")
            if port not in (80, 443):
                return deny(f"support host {host}: port {port} (80 and 443 only)")
            return _support_client(v, host, enroll) or v
        if v is not None:
            return _web_port(v, port) or (None if browser else self._waf_cooldown(host, v)) or v
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
        enroll: bool = False,
        websocket: bool = False,
        browser: bool = False,
    ) -> Verdict:
        """A decrypted request. `url`/`host` are the real destination, `host_header` what the client sent.
        `enroll`: the client is an enrollment source (the gate itself, bh-login). `websocket`: an upgrade handshake.
        `browser`: the client is bh-browser (B2: websockets and `browser_only` paths are its own)."""
        method = method.upper()
        if is_system(host):
            return deny(f"the Claude API is only reachable through the relay (gate:{RELAY_PORT})")
        if is_self_address(host, self.local_ips):
            return deny(f"{host} is the gate itself", "self")
        v = self._target(url)
        if websocket:  # the scope opts in; then targets only, and the handshake goes through the target rules below
            if self.scope is None or not self.scope.websockets_on:
                return deny("websockets are not allowed: this program's scope does not enable them (websockets: true)")
            if v is None or v.klass != "target":
                return v if v is not None and not v.allowed else deny("websockets go to the scope's targets only")
            if not browser and self.has_passthrough():
                return deny("browser only: on this program a websocket is opened by bh-browser only", "browser-only")
            if method != "GET":
                return deny(f"websocket handshake with {method}")
            if len(self.ws_live) >= self.ws_limits.max_open:
                return deny(f"websockets: {self.ws_limits.max_open} already open (close one first)")
        if v is not None and v.klass == "support":
            return self._support_request(
                v, url, host, method, host_header=host_header, body_len=body_len, enroll=enroll, browser=browser
            )
        if v is not None and v.allowed:
            if not browser and self.scope is not None and (rule := browser_only(self.scope, url)):
                return deny(f"browser only: {rule.value} is driven through bh-browser (bh-web)", "browser-only")
            if not browser and (paused := self._waf_cooldown(host, v)):
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
            scanning = None if browser else self._scanning(url)
            return scanning or self._enumeration(url, authenticated or bool(identity)) or v
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

    def _support_request(
        self,
        v: Verdict,
        url: str,
        host: str,
        method: str,
        *,
        host_header: str | None,
        body_len: int,
        enroll: bool,
        browser: bool = False,
    ) -> Verdict:
        """A request to a support host: never a test. assets: GET/HEAD without body; auth: enrollment sources only;
        sso: GET/HEAD without body under the declared get_paths (bh-browser: anywhere), POST on the declared token
        paths (enrollment: the login's methods); passthrough:
        never decrypted, so a request seen here is refused (the tunnel was intercepted, or it is plain HTTP)."""
        if v.support == "passthrough":
            return deny(f"passthrough host {host}: CONNECT to 443 only, never intercepted nor in clear")
        if host_header and host_header.lower().rstrip(".") != host.lower().rstrip("."):
            return deny("support host with a different Host header")
        if _port(url) not in (80, 443):
            return deny(f"support host {host}: port {_port(url)} (80 and 443 only)")
        if why := _support_client(v, host, enroll):
            return why
        if v.support == "assets" and (method not in ("GET", "HEAD") or body_len):
            return deny(f"support host {host} (assets): GET/HEAD without body only, not {method}")
        if v.support == "auth" and method not in SUPPORT_AUTH_METHODS:
            return deny(f"support host {host} (login): method {method} not allowed")
        if v.support == "sso":
            if enroll:
                if method not in SUPPORT_AUTH_METHODS:
                    return deny(f"support host {host} (sso): method {method} not allowed")
            elif method == "POST":
                entry = support_entry(self.scope, url) if self.scope is not None else None
                if entry is None or not entry.token_path(urlsplit(url).path):
                    return deny(f"support host {host} (sso): POST only to its declared token_paths")
            elif method not in ("GET", "HEAD") or body_len:
                return deny(f"support host {host} (sso): GET/HEAD without body, or POST to a token path, not {method}")
            elif not browser:
                entry = support_entry(self.scope, url) if self.scope is not None else None
                if entry is None or not entry.get_path(urlsplit(url).path):
                    return deny(f"support host {host} (sso): GET only under its declared get_paths")
        if body_len > MAX_BODY_BYTES:
            return deny(f"request body over {MAX_BODY_BYTES} bytes")
        return v

    def passthrough_redirect(self, url: str, status: int, location: str | None) -> str | None:
        """A redirect to a passthrough host, answered to a request that named an identity: the browser would carry
        X-BH-Identity into the tunnel the gate never sees (a route's headers follow its redirects). Reason to refuse
        that answer, or None."""
        if status not in (301, 302, 303, 307, 308) or not location or self.scope is None:
            return None
        target = urljoin(url, location.strip())
        d = check(self.scope, target)
        if d.support == "passthrough":
            return f"redirect to the passthrough host {urlsplit(target).hostname} under an identity (never followed)"
        return None

    def note_answer(self, url: str, status: int, *, browser: bool = False) -> None:
        """Target answers feed the scanner guard (only where the program forbids scanners). bh-browser's are the
        application's own requests: never counted."""
        if status == 404 and not browser and self.scope is not None and not self.scope.scanners_on:
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
        """Deny the (ID_LIMIT+1)-th distinct object id on one route within the window. The route is the path as
        the server's router sees it: case, //, a trailing slash, ;params and %xx do not make a new route.
        Only the path's ids count (I6): parameters (query string, bodies) are not looked at."""
        path = _route_path(urlsplit(url).path)
        if not (authenticated or API_PATH.search(path)):
            return None
        key = path_key(path)
        if "{id}" not in key:
            return None
        ids = "/".join(seg for seg, k in zip(path.split("/"), key.split("/"), strict=False) if k == "{id}")
        routes = [(key, ids)]
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
        """After resolution, before connecting. Non-targets must resolve to public addresses; nothing may resolve
        to the gate itself (loopback, its own addresses), whatever the scope."""
        if is_self_address(ip, self.local_ips):
            return deny(f"{host} resolves to the gate itself ({ip})", "self")
        if is_system(host) or is_passive(host):
            klass = "system" if is_system(host) else "passive"
            ok = is_public_ip(ip)
            return Verdict(ok, klass if ok else "deny", "non-target" if ok else f"{host} resolves to non-public {ip}")
        self.reload()
        if self.scope is None:
            return deny(self.scope_error or "no scope")
        if check(self.scope, host).support is not None:
            d = check_support_resolved(self.scope, host, ip)
            return Verdict(d.allowed, "support" if d.allowed else "deny", d.reason, d.rule, d.support)
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
        rps = {"passive": PASSIVE_RPS, "support": SUPPORT_RPS}.get(klass)
        if klass == "target":
            rps = self.target_rps()
        if rps is None:
            return None
        b = self.buckets.get(klass)
        if b is None or b.rps != rps:
            b = self.buckets[klass] = TokenBucket(rps, SUPPORT_BURST if klass == "support" else None)
        return b

    # ------------------------------------------------------------------ websockets
    def ws_start(self, fid: str, now: float | None = None, *, browser: bool = False) -> str | None:
        """A websocket that completed its handshake. Refusal reason, or None (its guard is then live). bh-browser's
        connections live longer (WsLimits.from_env(browser=True)): the chat stays open while the page is."""
        self.reload()
        if self.scope is None or not self.scope.websockets_on:
            return "websockets are not allowed by the active scope"
        if fid not in self.ws_live and len(self.ws_live) >= self.ws_limits.max_open:
            return f"websockets: {self.ws_limits.max_open} already open"
        limits = self.ws_limits_browser if browser else self.ws_limits
        self.ws_live[fid] = WsGuard(limits, _now() if now is None else now)
        return None

    def ws_message(
        self, fid: str, size: int, *, binary: bool, from_client: bool, now: float | None = None
    ) -> str | None:
        """One frame of a live websocket. Refusal reason (drop it and close the connection), or None."""
        g = self.ws_live.get(fid)
        if g is None:
            return "websocket not opened through the gate's checks"
        return g.message(size, binary=binary, from_client=from_client, now=_now() if now is None else now)

    def ws_end(self, fid: str) -> WsGuard | None:
        return self.ws_live.pop(fid, None)


def _support_client(v: Verdict, host: str, enroll: bool) -> Verdict | None:
    """A login host is for enrollment only: the hunter and the judge never reach it."""
    if v.support == "auth" and not enroll:
        return deny(f"{host}: login host, enrollment only", f"support-auth:{host}")
    return None


# ------------------------------------------------------------------ websockets: bounds per connection
def _env_num(name: str, default: float, env=None) -> float:
    raw = (os.environ if env is None else env).get(name)
    try:
        value = float(raw) if raw else default
    except ValueError:
        return default
    return value if value > 0 else default


@dataclass(frozen=True)
class WsLimits:
    """Per connection: client messages per minute, bytes per client message (server: WS_SERVER_FACTOR times), lifetime;
    and how many connections may be open at once. Overridable in the gate's environment (BH_WS_*). Lifetime by default:
    600 s, WS_BROWSER_MAX_SECONDS (3600) for bh-browser; BH_WS_MAX_SECONDS, when set, applies to both."""

    msgs_per_min: int = 12
    max_bytes: int = 64 << 10
    max_seconds: float = 600.0
    max_open: int = 2

    @classmethod
    def from_env(cls, env=None, *, browser: bool = False) -> WsLimits:
        d = cls(max_seconds=WS_BROWSER_MAX_SECONDS) if browser else cls()
        return cls(
            msgs_per_min=int(_env_num("BH_WS_MSGS_PER_MIN", d.msgs_per_min, env)),
            max_bytes=int(_env_num("BH_WS_MAX_BYTES", d.max_bytes, env)),
            max_seconds=_env_num("BH_WS_MAX_SECONDS", d.max_seconds, env),
            max_open=int(_env_num("BH_WS_MAX_OPEN", d.max_open, env)),
        )


WS_BROWSER_MAX_SECONDS = 3600.0  # a bh-browser websocket (the chat page stays open)
WS_PREVIEW_CHARS = 200
WS_SERVER_FACTOR = 16  # a server frame (a streamed answer) may be this many times the client bound


@dataclass
class WsGuard:
    """One websocket's counters. Once a bound is crossed the connection is closed for good: every later frame, in
    either direction, is refused too (fail closed even if the connection outlives the kill)."""

    limits: WsLimits
    started: float
    client: int = 0
    server: int = 0
    binary: int = 0
    bytes_client: int = 0
    recent: deque = field(default_factory=deque)  # timestamps of client messages within the last minute
    closed: str | None = None

    def message(self, size: int, *, binary: bool, from_client: bool, now: float) -> str | None:
        if self.closed:
            return self.closed
        why = None
        if now - self.started > self.limits.max_seconds:
            why = f"websocket open for over {self.limits.max_seconds:.0f} s"
        elif size > (limit := self.limits.max_bytes * (1 if from_client else WS_SERVER_FACTOR)):
            why = f"websocket {'client' if from_client else 'server'} message of {size} bytes (over {limit})"
        elif from_client:
            while self.recent and self.recent[0] <= now - 60:
                self.recent.popleft()
            if len(self.recent) >= self.limits.msgs_per_min:
                why = f"websocket: over {self.limits.msgs_per_min} client messages per minute"
        if why:
            self.closed = why
            return why
        if from_client:
            self.recent.append(now)
            self.client += 1
            self.bytes_client += size
            self.binary += binary
        else:
            self.server += 1
        return None

    def counts(self) -> dict:
        return {"client": self.client, "server": self.server, "binary": self.binary, "bytes": self.bytes_client}


@dataclass
class PassthroughGuard:
    """Tunnels to `passthrough` hosts (an anti-bot challenge), never decrypted: what the gate can bound is how many
    open (per minute, at once), how many bytes each carries and for how long. Once a tunnel crosses a bound it is
    closed for good. The journal keeps the host, the bytes and the duration, nothing else."""

    per_min: int = PASSTHROUGH_PER_MIN
    max_open: int = PASSTHROUGH_OPEN
    max_bytes: int = PASSTHROUGH_MAX_BYTES
    max_seconds: float = PASSTHROUGH_MAX_SECONDS
    recent: deque = field(default_factory=deque)  # start times of the tunnels of the last minute
    live: dict[str, dict] = field(default_factory=dict)  # tunnel id -> {host, start, up, down, closed}

    @classmethod
    def from_env(cls, env=None) -> PassthroughGuard:
        """Bounds overridable in the gate's environment: BH_PASSTHROUGH_PER_MIN, _OPEN, _MAX_BYTES, _MAX_SECONDS."""
        return cls(
            per_min=int(_env_num("BH_PASSTHROUGH_PER_MIN", PASSTHROUGH_PER_MIN, env)),
            max_open=int(_env_num("BH_PASSTHROUGH_OPEN", PASSTHROUGH_OPEN, env)),
            max_bytes=int(_env_num("BH_PASSTHROUGH_MAX_BYTES", PASSTHROUGH_MAX_BYTES, env)),
            max_seconds=_env_num("BH_PASSTHROUGH_MAX_SECONDS", PASSTHROUGH_MAX_SECONDS, env),
        )

    def open(self, tid: str, host: str, now: float) -> str | None:
        """A tunnel about to start. Refusal reason, or None (it is then counted)."""
        while self.recent and self.recent[0] <= now - 60:
            self.recent.popleft()
        for stale in [k for k, t in self.live.items() if t["start"] < now - self.max_seconds - 60]:
            del self.live[stale]  # a tunnel whose end the gate never saw does not hold a slot forever
        if len(self.recent) >= self.per_min:
            return f"passthrough: over {self.per_min} new tunnels per minute"
        if tid not in self.live and len(self.live) >= self.max_open:
            return f"passthrough: {self.max_open} tunnels already open"
        self.recent.append(now)
        self.live[tid] = {"host": host, "start": now, "up": 0, "down": 0, "closed": None}
        return None

    def data(self, tid: str, size: int, *, from_client: bool, now: float) -> str | None:
        """Bytes relayed on a tunnel. Refusal reason (close it), or None."""
        t = self.live.get(tid)
        if t is None:
            return "passthrough tunnel not opened through the gate's checks"
        if t["closed"]:
            return t["closed"]
        t["up" if from_client else "down"] += size
        if t["up"] + t["down"] > self.max_bytes:
            t["closed"] = f"passthrough tunnel over {self.max_bytes} bytes"
        elif now - t["start"] > self.max_seconds:
            t["closed"] = f"passthrough tunnel open for over {self.max_seconds:.0f} s"
        return t["closed"]

    def end(self, tid: str, now: float) -> dict | None:
        """The journal record of a finished tunnel: host, bytes each way, seconds (and why it was closed)."""
        t = self.live.pop(tid, None)
        if t is None:
            return None
        rec = {"host": t["host"], "bytes_up": t["up"], "bytes_down": t["down"], "seconds": round(now - t["start"], 3)}
        if t["closed"]:
            rec["closed"] = t["closed"]
        return rec


def ws_message_record(content: bytes, *, binary: bool) -> dict:
    """What the journal keeps of a client message: size, sha256, and (text only) its first characters redacted."""
    rec = {"len": len(content), "sha256": hashlib.sha256(content).hexdigest(), "binary": binary}
    if not binary:
        rec["text"] = redact.text(content.decode("utf-8", "replace")[:WS_PREVIEW_CHARS])
    return rec


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


def _route_path(path: str) -> str:
    path = re.sub(r";[^/]*", "", unquote(path)).lower()
    return re.sub(r"/{2,}", "/", path).rstrip("/") or "/"


# ------------------------------------------------------------------ Claude API relay: what a request may ask for
# The relay holds the OAuth token: anything the body asks Anthropic to do runs with Mio's account. Server tools
# (web_search, web_fetch, code_execution, computer...), remote MCP servers, a code container or a URL source make
# Anthropic's infrastructure reach the network outside the gate: all refused. Shapes from the Messages API reference,
# https://platform.claude.com/docs/en/api/messages/create (`tools`: the `Tool object` has `type: optional "custom"
# or null`, `name` ^[a-zA-Z0-9_-]{1,128}$, `input_schema` {type: "object"}; every other tool variant has a reserved
# `type` such as `bash_20250124`, `web_search_20260209`, `computer_toolset_20260801`, `mcp_toolset`).
RELAY_BODY_MAX = 32 << 20
RELAY_WALK_MAX = 2_000_000  # JSON nodes looked at for URL / file sources; past this the body is refused
CLIENT_TOOL_KEYS = frozenset(
    {
        "type",
        "name",
        "description",
        "input_schema",
        "cache_control",
        "defer_loading",
        "eager_input_streaming",
        "input_examples",
        "strict",
        "allowed_callers",
    }
)
_TOOL_NAME = re.compile(r"[a-zA-Z0-9_-]{1,128}")
# top-level fields that hand Anthropic a network reach or a sandbox of its own
RELAY_EGRESS_FIELDS = ("mcp_servers", "container")
# Models per relay client (the container that sent the request), overridable with BH_RELAY_MODELS_AGENT /
# BH_RELAY_MODELS_JUDGE in the gate's environment (comma-separated ids; a set variable REPLACES the default list, so
# it names every model that client needs). Exact API ids: Claude Code resolves its aliases before sending.
# hunter: `sonnet` (DEFAULT_MODEL), `opus` as Claude Code 2.1.330 resolves them, or `claude-mythos-5-2` (a Mythos
# hunt, I10); judge: `opus` (BH_VERIFIER_MODEL) and the escalation model (BH_ESCALATION_MODEL).
# claude-haiku-5-5: Claude Code's own small model for background calls (seen 4 times in the relay log); a model
# gives no network access, refusing it would only break Claude Code in ways the run does not show
RELAY_MODELS_DEFAULT = {
    "agent": ("claude-sonnet-5-5", "claude-opus-5-5", "claude-mythos-5-2", "claude-haiku-5-5"),
    "judge": ("claude-opus-5-5", "claude-mythos-5-2", "claude-haiku-5-5"),
}
# anthropic-beta values the relay lets through (BH_RELAY_BETAS replaces the list). Taken from the beta table of
# Claude Code 2.1.330 (strings of the binary), keeping only those that change how a request is answered (auth,
# thinking, caching, context, output shape, fallback) and never what Anthropic does on its own: web search, MCP
# servers, files, environments, tool provenance (a server_url), tool search, advisor, fast mode, AFK / auto mode,
# side queries, "dangerous tool use" are left out. A refused value is named in the `blocked` event, and every
# relayed request logs its values (`relay` event): the list grows from the journal, one reviewed value at a time.
RELAY_BETAS_DEFAULT = frozenset(
    {
        "oauth-2025-04-20",
        "claude-code-20250219",
        "interleaved-thinking-2025-05-14",
        "context-1m-2025-08-07",
        "context-management-2025-06-27",
        "structured-outputs-2025-12-15",
        "effort-2025-11-24",
        "task-budgets-2026-03-13",
        "token-counting-2024-11-01",
        "prompt-caching-scope-2026-01-05",
        "prompt-caching-evict-2026-05-12",
        "cache-keepalive-2026-09-03",
        "extended-cache-ttl-2025-04-11",
        "cache-diagnosis-2026-04-07",
        "redact-thinking-2026-02-12",
        "thinking-resumption-2026-07-17",
        "resumption-2026-10-08",
        "thinking-token-count-2026-05-13",
        "thinking-display-updates-2026-08-18",
        "thinking-binding-controls-2026-08-01",
        "context-hint-2026-04-09",
        "mid-conversation-system-2026-04-07",
        "mid-conversation-system-clear-at-2026-08-21",
        "mid-conversation-tool-changes-2026-07-01",
        "per-turn-control-2026-07-01",
        "inline-tools-2026-09-15",
        "timing-2026-09-09",
        "server-side-fallback-2026-06-01",
        "server-side-fallback-2026-07-01",
        "fallback-credit-2026-06-01",
        "program-use-case-ids-2026-09-17",
        "message-threads-2026-08-12",
    }
)


def _csv_env(name: str, env=None) -> tuple[str, ...]:
    raw = (os.environ if env is None else env).get(name) or ""
    return tuple(v.strip() for v in raw.split(",") if v.strip())


def relay_models(env=None) -> dict[str, frozenset[str]]:
    """Models each relay client ("agent", "judge") may ask for."""
    return {
        role: frozenset(_csv_env(f"BH_RELAY_MODELS_{role.upper()}", env) or default)
        for role, default in RELAY_MODELS_DEFAULT.items()
    }


def relay_betas(env=None) -> frozenset[str]:
    return frozenset(_csv_env("BH_RELAY_BETAS", env) or RELAY_BETAS_DEFAULT)


def split_betas(values: list[str]) -> list[str]:
    """anthropic-beta header values (repeated header and/or comma lists) -> one value per entry."""
    return [b.strip() for v in values for b in v.split(",") if b.strip()]


def _client_tool(tool) -> str | None:
    """None for a client tool (run by Claude Code, in the sandbox, behind this gate), else why not."""
    if not isinstance(tool, dict):
        return "a tool that is not an object"
    kind, name = tool.get("type"), tool.get("name")
    label = repr(str(kind if kind is not None else name)[:60])
    if kind not in (None, "custom"):
        return f"server tool {label}"
    if extra := sorted(set(tool) - CLIENT_TOOL_KEYS):
        return f"tool {label} with fields {extra[:5]}"
    if not isinstance(name, str) or not _TOOL_NAME.fullmatch(name):
        return f"tool {label} without a client tool name"
    schema = tool.get("input_schema")
    if not isinstance(schema, dict) or schema.get("type") != "object":
        return f"tool {label} without an input_schema object"
    if tool.get("allowed_callers") not in (None, ["direct"]):
        return f"tool {label} callable from code execution"
    return None


def _remote_source(obj) -> str | None:
    """A content block whose `source` makes Anthropic fetch a URL or read an uploaded file."""
    stack, seen = [obj], 0
    while stack:
        node = stack.pop()
        seen += 1
        if seen > RELAY_WALK_MAX:
            return "a body too large to inspect"
        if isinstance(node, dict):
            src = node.get("source")
            if isinstance(src, dict) and src.get("type") in ("url", "file"):
                return f"a {src.get('type')} source"
            stack.extend(v for v in node.values() if isinstance(v, (dict, list)))
        elif isinstance(node, list):
            stack.extend(v for v in node if isinstance(v, (dict, list)))
    return None


def check_relay(
    body: bytes | None, betas: list[str], models: frozenset[str], allowed_betas: frozenset[str]
) -> tuple[str | None, str | None]:
    """Judge one Claude API request on the relay. Returns (refusal reason or None, model asked for).

    `models`: the ids this request may name (the client's list; for count_tokens, every relay model, since counting
    spends no generation). Refused: an anthropic-beta value off the list, a body that is not a JSON object, a model
    off the list, any server or non-client tool, `mcp_servers` / `container`, a URL or file source, fallbacks to a
    model off the list, fast mode."""
    for b in betas:
        if b not in allowed_betas:
            return f"anthropic-beta {b[:80]!r} is not on the gate's list", None
    if not body or len(body) > RELAY_BODY_MAX:
        return "unreadable body (empty or over the size limit)", None
    try:
        doc = json.loads(body)
    except (ValueError, RecursionError):
        return "unreadable body (not JSON)", None
    if not isinstance(doc, dict):
        return "unreadable body (not a JSON object)", None
    model = doc.get("model")
    model = model[:80] if isinstance(model, str) else None
    if model not in models:
        return f"model {model!r} is not allowed for this client (allowed: {sorted(models)})", model
    for key in RELAY_EGRESS_FIELDS:
        if doc.get(key) is not None:
            return f"{key} is not allowed (Anthropic would reach the network outside the gate)", model
    tools = doc.get("tools")
    if tools is not None:
        if not isinstance(tools, list):
            return "tools is not a list", model
        for tool in tools:
            if why := _client_tool(tool):
                return f"{why} is not allowed: client tools only", model
    fallbacks = doc.get("fallbacks")
    fallbacks_ok = fallbacks in (None, "default") or (
        isinstance(fallbacks, list)
        and all(isinstance(f, dict) and set(f) == {"model"} and f["model"] in models for f in fallbacks)
    )
    if not fallbacks_ok:
        return "fallbacks to a model this client may not use", model
    if doc.get("speed") is not None:
        return "speed is not allowed (fast mode spends the quota twice as fast)", model
    if why := _remote_source([doc.get("system"), doc.get("messages")]):
        return f"{why} is not allowed (Anthropic would fetch it)", model
    return None, model
