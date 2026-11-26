"""mitmproxy addon: `mitmdump -s addon.py --set bh_state=/state`.

Enforces bh.gate.policy on every CONNECT, TLS handshake, request and upstream connection,
rate-limits (with backoff when the target pushes back), injects program headers and identities,
and writes compact JSONL logs that the runner turns into board facts.

Identities (bh.gate.session): a request with X-BH-Identity to an in-scope target gets the identity's headers
(an `Authorization` captured for that very origin at enrollment, `origin_headers`, wins over the default one) and the
cookies of its jar. The Set-Cookie of the answer go into the jar (file rewritten atomically) and reach
the agent with their value masked. The identity's headers and static Cookie only go to the identity's origins
(session.identity_origins; none declared: every in-scope host). A redirect to the identity's `login_url`, a failed
probe, or 401 answers on session.UNAUTH_ROUTES distinct routes within session.UNAUTH_WINDOW_S write one
`session-dead` event (at most one per identity and minute, `ts` = when it was seen); a single 401 is no proof.
Enrollment requests (`_from_gate`) never borrow a session, except the host's session probe (bh.accounts.enroll.probe):
`X-BH-Probe: 1` from the gate's own loopback (never bh-login, never the sandbox) keeps its X-BH-Identity; the marker
is removed before the request leaves.

The persistent browser (bh-browser, compose service BH_BROWSER_HOST=`browser`, recognised by address like bh-login):
- B2: when the scope has a passthrough host, the passthrough CONNECT and every websocket handshake are its own, and a
  path under the scope's `browser_only` prefixes is refused to every other client ("browser only").
- I2: its traffic carries the identity the host loaded in it, read from `<state>/browser-identity.json`
  ({"program", "identity", "loaded_at"}, reloaded on mtime, ignored for another program or an unknown name): logged as
  that identity (flows, events), allowed the identity-only methods (PUT/PATCH/DELETE), its Set-Cookie folded into
  that identity's jar but NOT masked (the browser needs them); nothing is ever injected (it has its own cookies).
- I6: never paused by the WAF guard, never counted by the not-found guard; its websockets live
  policy.WS_BROWSER_MAX_SECONDS (BH_WS_MAX_SECONDS overrides). Its 429 / 503 still slow the shared rate (R20).
- R14: its Set-Cookie only ADD to the identity's jar; a deletion (past expiry, empty value) is ignored.
- R22: recognised only at an address on one of the gate's own interface networks (local_networks).
- R37: its "not in scope" refusals (a page polling a host of no program) are journaled once per host and
  NOISE_WINDOW_S, the next line of that host carrying `repeats`; every refusal still happens. Every `blocked` line
  names its `client` (agent, judge, browser, login, other): the runner counts the agent's and the judge's.
- R46: under its loaded identity, on a target URL whose origin is one of that identity's declared `origins`, its
  `Authorization: Bearer` is kept in the identity's `origin_headers` (session.learn_bearer, only when it changed;
  event `bearer-learned` {identity, origin}, never the value). The agent then gets it under X-BH-Identity on that
  origin only, masked `<identity:name>` in every flow file. A kept bearer whose JWT `exp` has passed is never sent:
  the request is refused ("identity bearer expired"), with one `bearer-expired` event per identity and minute.
Payload hosts (scope `payload_hosts`, policy docstring): GET/HEAD/OPTIONS from any sandbox client, every Cookie and
Authorization removed, no identity, no program header, flows class `payload`.

Canaries (I1, bh.gate.canary): every request URL and body, response body and websocket frame (both ways) is searched
for `BH-SECRET-<16 hex>` on its whole content (decoded, bounded to canary.SCAN_BYTES) before any truncation; each hit
is one `events.jsonl` line {"kind": "canary", "token", "where": request-url|request-body|response-body|ws-client|
ws-server, "host", "url" (redacted), "identity", "client": browser|agent|judge|login|other, "run", "ts"}. Nothing
around the token is kept. The relay (Claude API traffic) is not searched: the hunter's own context names the token.

Relay (Claude API, the only holder of the OAuth token): only the agent and judge containers, only the two calls
Claude Code makes, within the run's budget, and only a body policy.check_relay accepts: client tools only, no
`mcp_servers` / `container`, no URL source, anthropic-beta values on the list (policy.relay_betas), the model on
the client's list (policy.relay_models; BH_RELAY_MODELS_AGENT / BH_RELAY_MODELS_JUDGE in the gate's environment
replace a list, comma-separated).

Support hosts (scope `support`, policy docstring): `assets` lose Cookie / Authorization and get no program header
nor identity; `auth` are reached by the enrollment sources only (`_from_gate`), with their own cookies untouched
(the login needs them; bh-login keeps its own jar). `sso` (a login host the application calls while in use: GET under
its `get_paths` for the hunter and the judge, anywhere for bh-browser; POST on its `token_paths`) gets no program
header and no identity header; under X-BH-Identity it gets that identity's jar cookies for its host only, and its
Set-Cookie go back to the jar, masked to the client like a target's. Logged as class `support`, never a target flow.

Passthrough hosts (a third-party anti-bot challenge): the CONNECT is judged (bh-browser only, name, port 443, rate,
open tunnels), then the TLS is never intercepted. Mechanism, mitmproxy 12.3.1 (the gate image): the passthrough hosts
of the active scope go to the official options `ignore_hosts` (`^host:443$`, "Ignore host and forward all traffic
without processing it", matched on the ClientHello's SNI: https://docs.mitmproxy.org/stable/howto/ignore-domains/) and
`show_ignored_hosts` ("Record ignored flows ... even if we do not perform TLS interception"), so an ignored tunnel
still raises the TCP events (https://docs.mitmproxy.org/stable/api/events.html, "TCP Events": tcp_start, tcp_message)
and its bytes can be counted and bounded (policy.PassthroughGuard), then dropped from memory. Not `tls_clienthello` +
`ignore_connection`: that path relays through `TCPLayer(ignore=True)`, which has no flow and raises no event
(mitmproxy/proxy/layers/tls.py, ClientTLSLayer.receive_handshake_data; layers/tcp.py, TCPLayer.__init__), so nothing
could be counted. Raw TCP stays refused for every tunnel the CONNECT check did not register as passthrough (an SNI
that names a passthrough host inside another CONNECT is blackholed), and a tunnel whose first bytes are no TLS
ClientHello too. A passthrough tunnel's SNI that is not its host is not ignored, so it is intercepted, and every request
in it is refused (policy: a passthrough host is never seen decrypted). Journal: event `passthrough` {host, bytes_up,
bytes_down, seconds, closed?}.

Websockets (scope `websockets: true`): the handshake is judged by classify_request like any target request; then
the official hooks of mitmproxy 12 (https://docs.mitmproxy.org/stable/api/events.html, "WebSocket Events":
websocket_start, websocket_message, websocket_end; the last message is `flow.websocket.messages[-1]`, with
`from_client`, `is_text`, `content` and `drop()`) apply policy.WsGuard: a frame past a bound is dropped, the
connection closed (close_connection), and every later frame of that connection is dropped too, with one `blocked`
event per connection, not one per frame. Every message, both ways, is journaled (events `ws-message`: size, sha256,
200 first characters redacted).

Closing a connection (I18): `flow.kill()` does not close a websocket or a TCP tunnel in mitmproxy 12.3.1 (flow.py,
Flow.kill: "we cannot kill flows in transit", issue 4711; only the HTTP layer checks it, layers/http/__init__.py
check_killed). close_connection cancels the client connection's reader task, as mitmproxy's own inactivity watchdog
does (proxy/server.py, ConnectionHandler.on_timeout: `self.transports[self.client].handler.cancel(...)`); the handler
is found through the proxyserver addon (addons/proxyserver.py, Proxyserver.connections[client id], filled by
mode_servers.py `register_connection(handler.layer.context.client.id, handler)`). handle_client then closes every
transport of that client (server.py, handle_client: "closing transports..."). Internals of the pinned 12.3.1, not an
API: if they are missing, the old blackhole stays (each later message dropped), and the event says `closed: false`.

Fail closed: mitmproxy only logs exceptions raised by addons and lets the flow continue, so every
hook here catches its own errors and denies.

mitmdump reloads this file on change, not the modules it imports (policy, session, redact): after changing
those, restart the gate (`podman restart bh-gate`).
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import inspect
import ipaddress
import itertools
import json
import os
import re
import secrets
import socket
import struct
import threading
import time
from pathlib import Path

from mitmproxy import ctx, http, tcp, udp
from mitmproxy.net.http.url import parse_authority, unparse
from mitmproxy.proxy import mode_specs, server_hooks

from bh import paths, redact
from bh.accounts.expiry import jwt_exp
from bh.agent.contract import GATE_HEADER, IDENTITY_HEADER, origin
from bh.gate import canary, session
from bh.gate.policy import (
    SYSTEM_HOSTS,
    Policy,
    Verdict,
    check_relay,
    deny,
    is_waf,
    relay_betas,
    relay_models,
    split_betas,
    ws_message_record,
)

MAX_BODY = 16_384
PUSHBACK_STATUS = (429, 503)
# R37: bh-browser's "not in scope" refusals (a page polling a host of no program: admin.microsoft.com once a second)
# are journaled once per host and NOISE_WINDOW_S; the next line of that host carries `repeats`. Decisions unchanged.
NOISE_WINDOW_S, NOISE_HOSTS_MAX = 60.0, 1024
NOISE_REASON = "not in scope"
# R46: one `bearer-expired` event per identity and BEARER_EXPIRED_WINDOW_S
BEARER_EXPIRED_REASON, BEARER_EXPIRED_WINDOW_S = "identity bearer expired", 60
os.umask(0o077)  # logs and flow files hold target data and redacted sessions: owner-only


def _now() -> float:
    return round(time.time(), 3)


AGENT_HOST = os.environ.get("BH_AGENT_HOST", "agent")
JUDGE_HOST = os.environ.get("BH_JUDGE_HOST", "judge")  # the verifier's own container (compose service `judge`)
AUDIT_HOST = os.environ.get("BH_AUDIT_HOST", "audit")  # independent auditor (compose service `audit`)
# the only clients of the relay: the hunter's container and the judge's. Nothing else on the gate's networks.
RELAY_CLIENT_HOSTS = (AGENT_HOST, JUDGE_HOST, AUDIT_HOST)
# The only Claude API calls Claude Code makes with nonessential traffic off (measured 2026-11-24 on 2.1.330).
RELAY_PATHS = frozenset({("POST", "/v1/messages"), ("POST", "/v1/messages/count_tokens")})
RELAY_DEFAULT_MAX = 200  # requests per activation of a run when the runner names no budget
# headers that make a framework run another method than the request line's (POST + override = DELETE)
METHOD_OVERRIDES = ("X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override")


RELAY_ROLES = {AGENT_HOST: "agent", JUDGE_HOST: "judge", AUDIT_HOST: "audit"}
RELAY_MODELS = relay_models()  # role -> model ids it may ask for (BH_RELAY_MODELS_AGENT / _JUDGE)
RELAY_BETAS = relay_betas()  # anthropic-beta values let through (BH_RELAY_BETAS)
RELAY_IPS_TTL, RELAY_IPS_RETRY = 60.0, 5.0
_RELAY_IPS: tuple[float, dict[str, frozenset[str]]] = (0.0, {})


_IP_LITERAL = re.compile(r"[0-9.]+|\[?[0-9a-fA-F:]*:[0-9a-fA-F:.]*\]?")


def resolve_hosts(hosts, getaddrinfo=None) -> frozenset[str]:
    """Addresses of the compose services `hosts`. A service that is down resolves to nothing and does not
    hide the others (the agent keeps the relay while the judge restarts)."""
    getaddrinfo = getaddrinfo or socket.getaddrinfo
    ips: set[str] = set()
    for host in hosts:
        with contextlib.suppress(OSError):
            ips |= {str(i[4][0]) for i in getaddrinfo(host, 0)}
    return frozenset(ips)


def relay_client_allowed(peer: str, allowed: frozenset[str]) -> bool:
    """The relay serves the agent and the judge containers only: the gate also sits on the lab network, and a
    target must not reach the token."""
    return bool(peer) and peer in allowed


def _relay_ips(max_age: float = RELAY_IPS_TTL) -> dict[str, frozenset[str]]:
    """Addresses of the agent and judge containers (per compose service), cached `max_age` seconds."""
    global _RELAY_IPS
    if time.time() - _RELAY_IPS[0] > max_age:
        _RELAY_IPS = (time.time(), {h: resolve_hosts((h,)) for h in RELAY_CLIENT_HOSTS})
    return _RELAY_IPS[1]


def relay_roles(peer: str, table: dict[str, frozenset[str]]) -> frozenset[str]:
    """Roles ("agent", "judge") of the relay client at `peer`; empty for anyone else."""
    return frozenset(RELAY_ROLES.get(h, h) for h, ips in table.items() if relay_client_allowed(peer, ips))


def _relay_role(peer: str) -> frozenset[str]:
    """A recreated container gets a new IP: a refused peer triggers one fresh lookup (at most every few seconds)
    before the refusal stands."""
    return relay_roles(peer, _relay_ips()) or relay_roles(peer, _relay_ips(RELAY_IPS_RETRY))


def _relay_peer_ok(peer: str) -> bool:
    return bool(_relay_role(peer))


def relay_models_for(roles: frozenset[str], path: str) -> frozenset[str]:
    """Models a request may name. Messages: the client's list (the intersection if one address had two roles).
    count_tokens spends no generation: any relay model."""
    if not roles:
        return frozenset()
    if path.endswith("/count_tokens"):
        return frozenset().union(*RELAY_MODELS.values())
    return frozenset.intersection(*(RELAY_MODELS.get(r, frozenset()) for r in roles))


def local_addresses() -> frozenset[str]:
    """The gate's own addresses (every interface), from /proc: never a destination (policy.is_self_address)."""
    ips: set[str] = set()
    with contextlib.suppress(OSError):
        lines = Path("/proc/net/fib_trie").read_text().splitlines()
        for prev, line in itertools.pairwise(lines):
            if "/32 host LOCAL" in line:
                ips.add(prev.strip().split()[-1])
    with contextlib.suppress(OSError, ValueError, IndexError):
        for line in Path("/proc/net/if_inet6").read_text().splitlines():
            raw = line.split()[0]
            ips.add(str(ipaddress.ip_address(":".join(raw[i : i + 4] for i in range(0, 32, 4)))))
    with contextlib.suppress(OSError):
        ips |= {str(i[4][0]) for i in socket.getaddrinfo(socket.gethostname(), 0)}
    return frozenset(ips)


def _v4(hex_le: str) -> str:
    """An address of /proc/net/route (32-bit hex, host byte order: little-endian on the gate's x86/arm)."""
    return str(ipaddress.IPv4Address(struct.pack("<I", int(hex_le, 16))))


def local_networks(route: str | None = None, route6: str | None = None) -> frozenset:
    """R22: the networks the gate's interfaces sit on (routes without a gateway, not the default route, not `lo`),
    from /proc/net/route and /proc/net/ipv6_route (or the given texts). Unreadable: none, so no address passes."""
    nets: set = set()
    if route is None:
        with contextlib.suppress(OSError):
            route = Path("/proc/net/route").read_text()
    for line in (route or "").splitlines()[1:]:
        f = line.split()
        with contextlib.suppress(ValueError, IndexError, struct.error):
            if f[0] == "lo" or int(f[2], 16) or not int(f[7], 16):
                continue  # loopback, via a router, or the default route
            nets.add(ipaddress.ip_network(f"{_v4(f[1])}/{_v4(f[7])}", strict=False))
    if route6 is None:
        with contextlib.suppress(OSError):
            route6 = Path("/proc/net/ipv6_route").read_text()
    for line in (route6 or "").splitlines():
        f = line.split()
        with contextlib.suppress(ValueError, IndexError):
            plen = int(f[1], 16)
            if f[-1] == "lo" or int(f[4], 16) or not 0 < plen <= 128 or f[0].startswith("ff"):
                continue
            addr = ipaddress.IPv6Address(int(f[0], 16))
            nets.add(ipaddress.ip_network(f"{addr}/{plen}", strict=False))
    return frozenset(nets)


def on_local_networks(ips, nets) -> frozenset[str]:
    """The addresses of `ips` that belong to one of `nets` (R22): a name that resolves elsewhere (a poisoned resolver,
    a public address) is never taken for a container of the stack."""
    out = set()
    for ip in ips:
        with contextlib.suppress(ValueError):
            addr = ipaddress.ip_address(str(ip).split("%", 1)[0])
            if any(addr.version == n.version and addr in n for n in nets):
                out.add(str(ip))
    return frozenset(out)


LOGIN_HOST = os.environ.get("BH_LOGIN_HOST", "login")  # the host-driven browser login container (compose `login`)
_LOGIN_IPS: tuple[float, frozenset[str]] = (0.0, frozenset())


def _login_ips(max_age: float = RELAY_IPS_TTL) -> frozenset[str]:
    """Addresses of the login container, cached like the relay clients' (it may be down: then none)."""
    global _LOGIN_IPS
    if time.time() - _LOGIN_IPS[0] > max_age:
        _LOGIN_IPS = (time.time(), resolve_hosts((LOGIN_HOST,)))
    return _LOGIN_IPS[1]


LOOPBACK = ("127.0.0.1", "::1", "::ffff:127.0.0.1")
# the persistent headful browser (compose service `browser`, container bh-browser, docs/research/18)
BROWSER_HOST = os.environ.get("BH_BROWSER_HOST", "browser")
_BROWSER_IPS: tuple[float, frozenset[str]] = (0.0, frozenset())
# written by the host when it loads an identity into bh-browser: {"program": str, "identity": str|null, "loaded_at"}
BROWSER_IDENTITY = "browser-identity.json"
# the host's session probe (bh.accounts.enroll.probe): honoured from the gate's own loopback only
PROBE_HEADER = "X-BH-Probe"


def _peer(flow) -> str:
    return str((flow.client_conn.peername or ("?",))[0])


def _from_gate(flow: http.HTTPFlow) -> bool:
    """An enrollment request: from inside the gate (bh.accounts JSON recipes) or from the login container
    (browser recipes). Never the agent's testing; its bodies carry passwords and tokens."""
    peer = _peer(flow)
    return peer in LOOPBACK or peer in _login_ips()


def _browser_ips(max_age: float = RELAY_IPS_TTL) -> frozenset[str]:
    """Addresses of bh-browser, cached like the login container's (down: none). Only those on a network of the gate's
    own interfaces (R22): bh-browser is a container of the stack, never an address elsewhere."""
    global _BROWSER_IPS
    if time.time() - _BROWSER_IPS[0] > max_age:
        _BROWSER_IPS = (time.time(), on_local_networks(resolve_hosts((BROWSER_HOST,)), local_networks()))
    return _BROWSER_IPS[1]


def is_browser_peer(peer: str) -> bool:
    """The client is bh-browser. A recreated container gets a new IP: an unknown peer triggers one fresh lookup at
    most every few seconds (like the relay's clients)."""
    if not peer or peer in LOOPBACK:
        return False
    return peer in _browser_ips() or peer in _browser_ips(RELAY_IPS_RETRY)


def client_kind(flow) -> str:
    """Who sent this flow, for the journal: browser | agent | judge | login (enrollment) | other."""
    return peer_kind(_peer(flow))


def peer_kind(peer: str) -> str:
    """client_kind for an address."""
    if peer in LOOPBACK or peer in _login_ips():
        return "login"
    if is_browser_peer(peer):
        return "browser"
    roles = _relay_role(peer)
    return "agent" if "agent" in roles else "judge" if "judge" in roles else "other"


def close_connection(flow) -> bool:
    """Really close the client connection of `flow` (and with it every upstream connection of that client): cancel
    its reader task, as mitmproxy's inactivity watchdog does (module docstring, I18). False when the internals are
    not there or the connection is already gone: the caller's blackhole then stays the only guard."""
    try:
        handler = ctx.master.addons.get("proxyserver").connections[flow.client_conn.id]
        task = handler.transports[handler.client].handler
    except Exception:  # noqa: BLE001 - internals of the pinned mitmproxy; absent means "not closed"
        return False
    if task is None or task.done():
        return False
    task.cancel("bh-gate: closed")
    return True


def passthrough_patterns(hosts) -> list[str]:
    """mitmproxy `ignore_hosts` regexes for the passthrough hosts: the exact name on port 443, anchored (mitmproxy
    matches them with re.search on `host:port`, the SNI included). Exact hosts only (the scope refuses wildcards)."""
    return sorted({f"^{re.escape(h.lower().rstrip('.'))}:443$" for h in hosts if h and "*" not in h})


def starts_like_tls_hello(data: bytes) -> bool:
    """A TLS handshake record (0x16, version 3.x) carrying a ClientHello (handshake type 1)."""
    return len(data) > 5 and data[0] == 0x16 and data[1] == 0x03 and data[2] <= 0x04 and data[5] == 0x01


def _decoded(raw: bytes | None, encoding: str | None) -> bytes:
    """The body as the application sees it: Content-Encoding (gzip, br, deflate, zstd) removed, bounded to MAX_BODY
    bytes of output. A gzip body read as text is noise, and the flow file is where a share link or an id is read."""
    if not raw or not encoding:
        return raw or b""
    return canary.decode(raw, encoding, limit=MAX_BODY)


def _redacted_body(raw: bytes | None) -> str:
    """A body as the flow file keeps it: MAX_BODY bytes, credentials and JWTs replaced (bh.redact)."""
    out = redact.body((raw or b"")[:MAX_BODY].decode("utf-8", "replace"))
    return out if isinstance(out, str) else json.dumps(out, ensure_ascii=False)


def refuse(flow: http.HTTPFlow, v: Verdict) -> None:
    """The gate's refusal: a 403 marked X-BH-Gate, and a metadata flag a target response cannot fake."""
    body = f"bh-gate: DENIED ({v.reason}{' / ' + v.rule if v.rule else ''})\n".encode()
    flow.response = http.Response.make(403, body, {"Content-Type": "text/plain", GATE_HEADER: "denied"})
    flow.metadata["bh_denied"] = True


def fail_closed(hook):
    """Any exception in a hook denies the flow instead of letting mitmproxy continue it."""

    def on_error(hook_name: str, arg, exc: Exception) -> None:
        ctx.log.error(f"bh-gate: {hook_name} failed, denying: {exc!r}")
        if isinstance(arg, http.HTTPFlow) and arg.websocket is not None and hook_name.startswith("websocket"):
            with contextlib.suppress(Exception):  # the frame in hand is not forwarded, the connection is closed
                if arg.websocket.messages:
                    arg.websocket.messages[-1].drop()
            arg.kill()
        elif isinstance(arg, http.HTTPFlow):
            refuse(arg, deny(f"gate error in {hook_name}"))
        elif isinstance(arg, (tcp.TCPFlow, udp.UDPFlow)):
            arg.kill()
        elif isinstance(arg, server_hooks.ServerConnectionHookData):
            arg.server.error = "bh-gate: denied (gate error)"

    if inspect.iscoroutinefunction(hook):

        @functools.wraps(hook)
        async def async_wrapper(self, arg, *rest):
            try:
                return await hook(self, arg, *rest)
            except Exception as exc:  # noqa: BLE001 - deny on anything
                on_error(hook.__name__, arg, exc)
                return None

        return async_wrapper

    @functools.wraps(hook)
    def wrapper(self, arg, *rest):
        try:
            return hook(self, arg, *rest)
        except Exception as exc:  # noqa: BLE001 - deny on anything
            on_error(hook.__name__, arg, exc)
            return None

    return wrapper


class RelayTap:
    """Stream filter for the relay's SSE answer: passes every chunk through unchanged and reports the message id
    (`message_start`) and its `stop_reason` (`message_delta`) once each. Never raises: a parsing problem costs a
    journal line, not the answer."""

    _ID = re.compile(rb'"type"\s*:\s*"message_start"\s*,\s*"message"\s*:\s*\{\s*"id"\s*:\s*"(msg_[A-Za-z0-9_-]{1,80})"')
    _STOP = re.compile(rb'"stop_reason"\s*:\s*"([a-z_]{1,40})"')

    def __init__(self, report):
        self.report, self.tail, self.msg_id, self.stopped = report, b"", None, False

    def __call__(self, chunk: bytes) -> bytes:
        try:
            buf = self.tail + chunk
            if self.msg_id is None and (m := self._ID.search(buf)):
                self.msg_id = m.group(1).decode()
            if not self.stopped and (m := self._STOP.search(buf)):
                self.stopped = True
                self.report({"msg_id": self.msg_id, "stop_reason": m.group(1).decode()})
            self.tail = buf[-512:]  # a pattern cut between two chunks is found in the next one
        except Exception:  # noqa: BLE001 - observation only
            pass
        return chunk


class Gate:
    def __init__(self) -> None:
        self.policy: Policy | None = None
        self.state = Path("/state")
        self.seq = itertools.count(1)
        self._run: dict = {}
        self._run_mtime = -1.0
        self._relay_used: dict[float, int] = {}  # activation of a run (active-run mtime) -> relay requests
        # server connection id -> hostname asked for. server_connect pins the address to a vetted IP,
        # and with the eager connection strategy that happens before the TLS / TCP hooks run.
        self._dest: dict[str, str] = {}
        # client connection id -> (hostname, port) of the CONNECT that opened its tunnel. When mitmproxy reopens an
        # upstream connection inside that tunnel it dials the pinned IP, not the name: the name comes from here.
        self._tunnel_name: dict[str, tuple[str, int]] = {}
        self._dead = session.DeadLimiter()  # one session-dead event per identity per minute
        self._unauth = session.Unauthorized()  # 401 under an identity, per distinct route
        # server connection id -> passthrough host: the only tunnels whose raw bytes may be relayed
        self._tunnels: dict[str, str] = {}
        self._browser_ident: tuple[float, dict] = (-1.0, {})  # (mtime, content) of BROWSER_IDENTITY
        self._noise: dict[str, list] = {}  # R37: host -> [start of its window, refusals not journaled since]
        self._bearer_expired = session.DeadLimiter(BEARER_EXPIRED_WINDOW_S)  # one event per identity and minute

    def load(self, loader) -> None:
        loader.add_option("bh_state", str, "/state", "bull-harness state dir")

    def configure(self, updated) -> None:
        if "bh_state" not in updated and self.policy is not None:
            return  # another option changed: keep the policy and its rate-limit buckets
        self.state = Path(ctx.options.bh_state)
        (self.state / paths.FLOWS_DIR).mkdir(parents=True, exist_ok=True)
        self.policy = Policy(self.state / paths.ACTIVE_SCOPE, local_ips=local_addresses())
        self.policy.reload()
        if ctx.options.rawtcp:
            ctx.options.update(rawtcp=False)  # non-HTTP bytes are not relayed (tcp hooks below kill the rest)
        self._sync_passthrough()

    def _sync_passthrough(self) -> None:
        """mitmproxy's `ignore_hosts` = the active scope's passthrough hosts on 443 (module docstring); nothing else
        is ever left unintercepted. Called after every scope reload a CONNECT may see."""
        scope = self.policy.scope if self.policy else None
        wanted = passthrough_patterns(scope.support_hosts("passthrough") if scope else ())
        if list(ctx.options.ignore_hosts or []) != wanted:
            ctx.options.update(ignore_hosts=wanted, show_ignored_hosts=bool(wanted))

    def running(self) -> None:
        """Publish only the public CA cert for the agent; the CA key stays in the gate's confdir."""
        src = Path(ctx.options.confdir).expanduser() / "mitmproxy-ca-cert.pem"
        dst_dir = Path(os.environ.get("BH_CA_PUB", "/gate-ca"))

        def publish() -> None:  # the CA may be written just after `running`; never log an error at startup
            for _ in range(60):
                try:
                    dst_dir.mkdir(parents=True, exist_ok=True)
                    dst = dst_dir / "mitmproxy-ca-cert.pem"
                    dst.write_bytes(src.read_bytes())
                    dst.chmod(0o644)  # public certificate, read by the agent's entrypoint
                    return
                except OSError:
                    time.sleep(0.5)
            ctx.log.warn(f"bh-gate: could not publish CA cert from {src}")

        threading.Thread(target=publish, daemon=True).start()

    # ---- logging
    def _active_run(self) -> dict:
        """{run_id, program} of the segment in progress (written by the runner), {} between runs."""
        p = self.state / paths.ACTIVE_RUN
        try:
            mtime = p.stat().st_mtime
        except OSError:
            self._run, self._run_mtime = {}, -1.0
            return self._run
        if mtime != self._run_mtime:
            self._run_mtime = mtime
            try:
                self._run = json.loads(p.read_text())
            except (OSError, ValueError):
                self._run = {}
        return self._run

    def _log(self, name: str, rec: dict) -> None:
        rec.setdefault("ts", _now())
        rec.setdefault("program", self.policy.program if self.policy else "-")
        rec.setdefault("run", self._active_run().get("run_id"))
        try:
            with open(self.state / name, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except OSError as exc:  # logging must never decide a flow
            ctx.log.error(f"bh-gate: cannot write {name}: {exc}")

    def _browser_identity(self) -> str | None:
        """The identity the host loaded in bh-browser (BROWSER_IDENTITY, reloaded on mtime), for the active program
        and with a session file; None otherwise (no file, another program, unknown name, null)."""
        p = self.state / BROWSER_IDENTITY
        try:
            mtime = p.stat().st_mtime
        except OSError:
            self._browser_ident = (-1.0, {})
            return None
        if mtime != self._browser_ident[0]:
            try:
                doc = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                doc = None
            self._browser_ident = (mtime, doc if isinstance(doc, dict) else {})
        doc = self._browser_ident[1]
        name = doc.get("identity")
        if not isinstance(name, str) or doc.get("program") != self.policy.program:
            return None
        return name if self._identity_file(name) is not None else None

    def _canary(self, flow, where: str, data, *, encoding: str | None = None, url: str | None = None) -> None:
        """Journal every canary token in `data` (event `canary`, module docstring). Observation only: never raises,
        never decides the flow."""
        try:
            if isinstance(data, bytes) and encoding:
                data = canary.decode(data, encoding)
            tokens = canary.find(data)
            if not tokens:
                return
            if url is None:
                url, host = self._named(flow)
            else:
                host = flow.request.host if flow.request.method == "CONNECT" else self._named(flow)[1]
            client = client_kind(flow)
            identity = flow.metadata.get("bh_identity")
            if identity is None and client == "browser":  # at CONNECT the request hook has not tagged it yet
                identity = self._browser_identity()
            for tok in tokens:
                self._log(
                    paths.EVENTS,
                    {
                        "kind": "canary",
                        "token": tok,
                        "where": where,
                        "host": host,
                        "url": redact.url(url),
                        "identity": identity,
                        "client": client,
                    },
                )
        except Exception as exc:  # noqa: BLE001 - the scan must never cost a flow
            ctx.log.error(f"bh-gate: canary scan failed: {exc!r}")

    def _deny(self, flow: http.HTTPFlow, v: Verdict, where: str) -> None:
        refuse(flow, v)  # first: a failing log write must not let the request through
        url, host = self._named(flow)
        browser = bool(flow.metadata.get("bh_browser"))
        rec = {
            "kind": "blocked",
            "where": where,
            "url": redact.url(url),
            "method": flow.request.method,
            "reason": v.reason,
            "rule": v.rule,
            "client": "browser" if browser else client_kind(flow),
        }
        if browser and v.reason == NOISE_REASON and not canary.find(host):
            repeats = self._noise_count(str(host).lower().rstrip("."), time.time())
            if repeats is None:
                return  # counted: the host's next line carries it
            if repeats:
                rec["repeats"] = repeats
        self._log(paths.EVENTS, rec)

    def _noise_count(self, host: str, now: float) -> int | None:
        """R37: None when this refusal falls in the host's current window (counted, not journaled); otherwise the
        refusals counted since the host's last line (0 for a first one), and a new window starts."""
        st = self._noise.get(host)
        if st is not None and now - st[0] < NOISE_WINDOW_S:
            st[1] += 1
            return None
        if len(self._noise) >= NOISE_HOSTS_MAX:  # bounded memory: hosts whose window is over and nothing pending
            for h in [h for h, (t, n) in self._noise.items() if now - t >= NOISE_WINDOW_S and not n]:
                del self._noise[h]
            if len(self._noise) >= NOISE_HOSTS_MAX:
                self._noise.clear()
        self._noise[host] = [now, 0]
        return st[1] if st is not None else 0

    # ---- connection-level hooks
    @fail_closed
    def http_connect(self, flow: http.HTTPFlow) -> None:
        self._canary(flow, "request-url", flow.request.host, url=f"{flow.request.host}:{flow.request.port}")
        browser = is_browser_peer(_peer(flow))
        flow.metadata["bh_browser"] = browser
        v = self.policy.classify_connect(flow.request.host, flow.request.port, enroll=_from_gate(flow), browser=browser)
        self._sync_passthrough()  # classify_connect reloaded the scope: the ignored hosts follow it
        flow.metadata["bh_class"] = v.klass
        flow.metadata["bh_support"] = v.support
        if not v.allowed:
            self._deny(flow, v, "connect")
            return
        if not _IP_LITERAL.fullmatch(flow.request.host):
            self._tunnel_name[flow.client_conn.id] = (flow.request.host.lower().rstrip("."), flow.request.port)
        if v.support == "passthrough":
            host = flow.request.host.lower().rstrip(".")
            if why := self.policy.passthrough.open(flow.server_conn.id, host, time.time()):
                self._deny(flow, deny(why), "connect")
                return
            self._tunnels[flow.server_conn.id] = host

    @fail_closed
    def http_connect_error(self, flow: http.HTTPFlow) -> None:
        """A CONNECT that failed (upstream unreachable, refused): its passthrough slot is freed."""
        self._tunnel_end(flow.server_conn.id)

    def _tunnel_end(self, sid: str) -> None:
        host = self._tunnels.pop(sid, None)
        if host is None:
            return
        rec = self.policy.passthrough.end(sid, time.time())
        self._log(paths.EVENTS, {"kind": "passthrough", **(rec or {"host": host})})

    def _destination(self, server) -> tuple[str | None, int | None]:
        """(hostname asked for, port) of a server connection, even after the address was pinned to an IP."""
        if not server.address:
            return None, None
        return self._dest.get(server.id, server.address[0]), server.address[1]

    def _named(self, flow: http.HTTPFlow) -> tuple[str, str]:
        """(url, host) of a request under the hostname the client asked for. Inside a CONNECT tunnel
        mitmproxy takes the request host from the server address, which server_connect pinned to the
        vetted IP: map that IP back to the name it was vetted for. Every decision and log line uses this."""
        if dest := flow.metadata.get("bh_dest"):
            return dest
        req, srv = flow.request, flow.server_conn
        if req.method == "CONNECT":
            return req.url, req.host
        host = req.host
        if srv is not None and srv.address and (req.host, req.port) == tuple(srv.address):
            host = self._dest.get(srv.id, req.host)
        named = self._tunnel_name.get(flow.client_conn.id)
        if named and named[1] == req.port and _IP_LITERAL.fullmatch(host):
            host = named[0]  # a reopened upstream connection dialled the pinned IP of the tunnel's name
        dest = (unparse(req.scheme, host, req.port, req.path), host)
        flow.metadata["bh_dest"] = dest
        return dest

    @fail_closed
    def tcp_start(self, flow: tcp.TCPFlow) -> None:
        """Raw TCP (non-HTTP bytes in a tunnel, CRLF tricks, other ports) never leaves; except a passthrough tunnel
        that the CONNECT check registered (module docstring)."""
        if flow.server_conn.id in self._tunnels:
            flow.metadata["bh_passthrough"] = self._tunnels[flow.server_conn.id]
            with contextlib.suppress(RuntimeError):  # a silent tunnel is closed at its time limit too
                asyncio.get_running_loop().call_later(
                    self.policy.passthrough.max_seconds + 1, self._tunnel_expire, flow
                )
            return
        flow.kill()
        host, port = self._destination(flow.server_conn)
        self._log(
            paths.EVENTS,
            {
                "kind": "blocked",
                "where": "tcp",
                "host": host,
                "port": port,
                "reason": "raw TCP is not allowed",
                "client": client_kind(flow) if getattr(flow, "client_conn", None) is not None else None,
            },
        )

    @fail_closed
    def tcp_message(self, flow: tcp.TCPFlow) -> None:
        """kill() in tcp_start does not stop the first message: drop every byte of the tunnel. A passthrough tunnel:
        its first client bytes must be a TLS ClientHello; then only the byte count is kept, never the bytes."""
        msg = flow.messages[-1]
        sid = flow.server_conn.id
        host = flow.metadata.get("bh_passthrough")
        why = None if host and sid in self._tunnels else "raw TCP is not allowed"
        if why is None and msg.from_client and not flow.metadata.get("bh_tls_seen"):
            flow.metadata["bh_tls_seen"] = True
            if not starts_like_tls_hello(msg.content or b""):
                why = "passthrough: the tunnel does not start with a TLS ClientHello"
                self.policy.passthrough.live.get(sid, {})["closed"] = why
        if why is None:
            size = len(msg.content or b"")
            why = self.policy.passthrough.data(sid, size, from_client=msg.from_client, now=time.time())
        flow.messages.clear()  # never kept: the relay sends the message it holds, the flow keeps no copy
        if why:
            msg.content = b""
            flow.kill()
            close_connection(flow)
            if host and not flow.metadata.get("bh_pt_refused"):
                flow.metadata["bh_pt_refused"] = True
                self._log(paths.EVENTS, {"kind": "blocked", "where": "passthrough", "host": host, "reason": why})
            return

    def _tunnel_expire(self, flow: tcp.TCPFlow) -> None:
        try:
            t = self.policy.passthrough.live.get(flow.server_conn.id)
            if t is not None and not t["closed"]:
                t["closed"] = "passthrough tunnel time limit"
                flow.kill()  # if the close below fails, the next message of either side is dropped (tcp_message)
                closed = close_connection(flow)
                self._log(
                    paths.EVENTS,
                    {
                        "kind": "blocked",
                        "where": "passthrough",
                        "host": t["host"],
                        "reason": t["closed"],
                        "closed": closed,
                    },
                )
        except Exception as exc:  # noqa: BLE001 - a timer callback must never raise into the loop
            ctx.log.error(f"bh-gate: passthrough expiry failed: {exc!r}")

    def client_disconnected(self, client) -> None:
        self._tunnel_name.pop(client.id, None)

    def server_disconnected(self, data: server_hooks.ServerConnectionHookData) -> None:
        self._dest.pop(data.server.id, None)
        self._tunnel_end(data.server.id)

    @fail_closed
    def udp_start(self, flow: udp.UDPFlow) -> None:
        flow.kill()

    @fail_closed
    async def server_connect(self, data: server_hooks.ServerConnectionHookData) -> None:
        """Resolve and vet every upstream IP, then pin the connection to a vetted IP (no rebinding
        between this check and mitmproxy's own resolution)."""
        if not data.server.address:
            return
        host, port = data.server.address
        named = self._tunnel_name.get(data.client.id)
        if named and named[1] == port and _IP_LITERAL.fullmatch(host):
            host = named[0]  # reopened inside a tunnel: vet and pin the tunnel's name again, not a stale IP
        infos = await asyncio.get_running_loop().getaddrinfo(
            host, port, proto=socket.IPPROTO_TCP
        )  # no event-loop freeze
        for info in infos:
            ip = info[4][0]
            v = self.policy.check_ip(host, ip)
            if not v.allowed:
                self._log(
                    paths.EVENTS,
                    {
                        "kind": "blocked",
                        "where": "resolve",
                        "host": host,
                        "ip": ip,
                        "reason": v.reason,
                        "rule": v.rule,
                        "client": peer_kind(str((getattr(data.client, "peername", None) or ("?",))[0])),
                    },
                )
                data.server.error = f"bh-gate: DENIED {host} -> {ip} ({v.reason})"
                return
        if data.server.sni is None and not re.fullmatch(r"[0-9.]+|\[?[0-9a-fA-F:]+\]?", host):
            data.server.sni = host  # keep the name for TLS (virtual hosting) once the address is an IP
        self._dest[data.server.id] = host
        data.server.address = (infos[0][4][0], port)

    # ---- Claude API relay (reverse listener): the OAuth token exists only here
    @staticmethod
    def _is_relay(flow: http.HTTPFlow) -> bool:
        return isinstance(flow.client_conn.proxy_mode, mode_specs.ReverseMode)

    def _relay(self, flow: http.HTTPFlow) -> None:
        flow.metadata["bh_class"] = "relay"
        peer = (flow.client_conn.peername or ("?",))[0]
        roles = _relay_role(peer)
        if not roles:  # the gate also sits on the lab network: a target must not reach the token
            self._deny(flow, deny(f"relay: only the agent and judge containers may use it (not {peer})"), "relay")
            return
        token = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "")
        req = flow.request
        path = req.path.split("?")[0]
        run = self._active_run()
        betas = split_betas(req.headers.get_all("anthropic-beta"))
        body = req.get_content(strict=False) if req.method == "POST" else None
        why, model = check_relay(body, betas, relay_models_for(roles, path), RELAY_BETAS)
        self._log(
            paths.EVENTS,
            {
                "kind": "relay",
                "method": req.method,
                "path": path[:120],
                "model": model,
                "client": ",".join(sorted(roles)),
                "betas": [b[:80] for b in betas[:40]],  # what Claude Code really sends: the allowlist's source
            },
        )
        if not token:
            reason = "relay: no token in the gate"
        elif (req.method, path) not in RELAY_PATHS:
            reason = f"relay: {req.method} {path[:60]} is not a call Claude Code makes"
        elif not run:  # between runs the sandbox has no business spending the quota
            reason = "relay: no run in progress"
        elif why:  # what the body asks Anthropic to do (H1): judged before it costs any budget
            reason = f"relay: {why}"
        else:
            used = self._relay_used.get(self._run_mtime, 0)
            budget = run.get("relay_max") if isinstance(run.get("relay_max"), int) else RELAY_DEFAULT_MAX
            reason = f"relay: this run's budget of {budget} API requests is spent" if used >= budget else ""
            if not reason:
                self._relay_used = {self._run_mtime: used + 1}  # one activation at a time
        if reason:
            self._deny(flow, deny(reason), "relay")
            return
        flow.request.headers.pop("x-api-key", None)
        flow.request.headers["Authorization"] = f"Bearer {token}"
        # reverse mode derives Host from the server address, which server_connect pinned to an IP
        flow.request.host_header = SYSTEM_HOSTS[0]

    @fail_closed
    def responseheaders(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("bh_class") == "relay":
            # server-sent events: relayed as they come, never buffered or stored. Only the status, the message id
            # and its stop_reason are journaled, so the runner can check a quota stop (429) or a refusal it read in
            # claude's output against what really came back (runner.quota_confirmed / refusal_confirmed)
            self._log(paths.EVENTS, {"kind": "relay", "status": flow.response.status_code})
            flow.response.stream = RelayTap(lambda rec: self._log(paths.EVENTS, {"kind": "relay", **rec}))

    # ---- HTTP hooks
    @fail_closed
    async def request(self, flow: http.HTTPFlow) -> None:
        if flow.response is not None:  # already denied at CONNECT
            return
        self.policy.reload()  # first: the identity file below is looked up under the program in force (B2)
        if self._is_relay(flow):
            self._relay(flow)
            return
        req = flow.request
        identity = req.headers.pop(IDENTITY_HEADER, None)
        probe = req.headers.pop(PROBE_HEADER, None)  # never sent upstream, whoever set it
        peer = _peer(flow)
        browser = is_browser_peer(peer)
        flow.metadata["bh_browser"] = browser
        flow.metadata["bh_identity_asked"] = identity is not None  # the client sent one (see passthrough_redirect)
        if identity is not None and _from_gate(flow) and not (probe == "1" and peer in LOOPBACK):
            identity = None  # enrollment logs in with its own credentials: only the host's probe borrows a session
        if browser:
            identity = self._browser_identity()  # I2: the host's label, never a header of the page
        if identity is not None and self._identity_file(identity) is None:
            self._log(
                paths.EVENTS,
                {"kind": "identity-missing", "identity": identity[:60], "url": redact.url(self._named(flow)[0])},
            )
            identity = None  # an unknown name is no identity: it must not unlock writes
        flow.metadata["bh_identity"] = identity
        self._canary(flow, "request-url", self._named(flow)[0])
        self._canary(flow, "request-body", req.raw_content, encoding=req.headers.get("content-encoding"))
        if not req.path.startswith("/"):  # "@other.host/x" would re-parse as another destination
            self._deny(flow, deny("the request target must start with /"), "request")
            return
        # a websocket handshake: refused unless the scope enables websockets, then judged as a target request
        # (classify_request) and its frames bounded by the websocket_* hooks below
        websocket = "websocket" in req.headers.get("upgrade", "").lower()
        flow.metadata["bh_ws"] = websocket
        if req.authority and not (req.is_http2 or req.is_http3):  # absolute form inside a tunnel: sent unjudged
            self._deny(flow, deny("absolute-form request target inside a tunnel"), "request")
            return
        host_header = parse_authority(req.host_header, check=False)[0] if req.host_header else None
        url, host = self._named(flow)
        override = next((req.headers[h] for h in METHOD_OVERRIDES if h in req.headers), None)
        v = self.policy.classify_request(
            url,
            host,
            override.strip().upper() if override else req.method,
            host_header=host_header,
            identity=identity,
            body_len=len(req.raw_content or b""),
            body=req.raw_content if req.method not in ("GET", "HEAD") else None,
            authenticated=bool(identity or "authorization" in req.headers or "cookie" in req.headers),
            enroll=_from_gate(flow),
            websocket=websocket,
            browser=browser,
        )
        flow.metadata["bh_class"] = v.klass
        flow.metadata["bh_support"] = v.support
        if not v.allowed:
            self._deny(flow, v, "request")
            return
        bucket = self.policy.bucket(v.klass)
        if bucket is not None:
            flow.metadata["bh_wait"] = round(await bucket.take(), 3)
        flow.metadata["bh_ua"] = req.headers.get("User-Agent", "")  # before the program UA override
        if v.klass == "target":
            scope = self.policy.scope
            for k, val in scope.required_headers.items():
                req.headers[k] = val
            if scope.user_agent:
                req.headers["User-Agent"] = scope.user_agent
            if identity and browser:
                self._label_identity(flow, identity, learn=True)
            elif identity and (refused := self._apply_identity(flow, identity)):
                self._deny(flow, refused, "request")
                return
        elif v.klass == "support" and v.support == "sso":
            # the application's own sign-in: no program header, no UA override, no identity header; under an
            # identity, that identity's jar cookies for this host (the browser of our test account, nothing more)
            if identity and browser:
                self._label_identity(flow, identity)
            elif identity:
                self._apply_identity(flow, identity, cookies_only=True)  # cookies only: no bearer, no refusal
        elif v.klass in ("passive", "payload") or (v.klass == "support" and v.support == "assets"):
            # never applied off target: the journal must not claim it was. A payload host (D27) gets nothing of ours,
            # whoever asks (bh-browser's own cookies included)
            flow.metadata["bh_identity"] = None
            for k in ("Cookie", "Authorization"):
                req.headers.pop(k, None)
        # support `auth`: only enrollment reaches it (policy); its own cookies are the login's, left as they are

    def _identity_file(self, name: str) -> Path | None:
        """The identity's file for the active program, None for an unknown or malformed name."""
        if not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,39}", name):
            return None
        path = self.state / paths.IDENTITIES / self.policy.program / f"{name}.json"
        return path if path.is_file() else None

    def _session_info(self, name: str, path: Path, sess: dict) -> dict:
        decl = next((i for i in self.policy.scope.identities if i.get("name") == name), {})
        return {"file": str(path), "login_url": decl.get("login_url"), "probe": decl.get("probe") or sess.get("probe")}

    def _label_identity(self, flow: http.HTTPFlow, name: str, *, learn: bool = False) -> None:
        """bh-browser's traffic under the identity the host loaded (I2): nothing injected (the browser sends its own
        cookies and headers); only what the response needs to fold its Set-Cookie into that identity's jar.
        `learn` (a target request, R46): the browser's `Authorization: Bearer` is kept for that origin when the origin
        is one of the identity's declared `origins`, and masked in the flow file."""
        path = self._identity_file(name)
        sess = session.load(path) if path else None
        if path is None or sess is None:
            flow.metadata["bh_identity"] = None
            return
        flow.metadata["bh_session"] = self._session_info(name, path, sess)
        if learn:
            self._learn_bearer(flow, name, path, sess)

    def _learn_bearer(self, flow: http.HTTPFlow, name: str, path: Path, sess: dict) -> None:
        """R46: bh-browser's bearer, under its loaded identity, on a target URL whose origin the identity declares in
        `origins`: kept in `origin_headers[<origin>]` when it changed. Nothing else is learned (no other header, no
        other client, no origin outside `origins`, never a support host: the caller only calls it for a target)."""
        values = flow.request.headers.get_all("authorization")
        if len(values) != 1 or not session.BEARER.fullmatch(values[0]):
            return
        flow.metadata["bh_redact"] = {"authorization": f"<identity:{name}>"}  # the flow file never holds it
        url = self._named(flow)[0]
        o = origin(url)
        decl = next((i for i in self.policy.scope.identities if i.get("name") == name), {})
        declared = {origin(u) for u in decl.get("origins") or () if isinstance(u, str)}
        if o is None or o not in declared or session.known_bearer(sess, o) == values[0]:
            return
        try:
            if session.learn_bearer(path, o, values[0]):
                self._log(paths.EVENTS, {"kind": "bearer-learned", "identity": name, "origin": o})
        except OSError as exc:  # a file that cannot be written costs a stale bearer, never the request
            ctx.log.error(f"bh-gate: cannot keep the bearer of {name}: {type(exc).__name__}")

    def _apply_identity(self, flow: http.HTTPFlow, name: str, *, cookies_only: bool = False) -> Verdict | None:
        """Inject the identity's headers and the cookies its jar holds for this URL (bh.gate.session).
        Cookies: the jar (fresh, rotated by Set-Cookie) beats a static `Cookie` of `headers`; both beat an agent
        cookie of the same name (session.combine), whose name is then recorded in the flow.
        `cookies_only` (an `sso` host): the jar's cookies for this URL and nothing else, never a header.
        Returns a refusal when the bearer kept for this origin (`origin_headers`) is a JWT whose `exp` has passed
        (R46): it is not sent, and one `bearer-expired` event per identity and minute says so. A bearer without a
        readable `exp` is sent as before; a 401 to a live one stays the target's 401."""
        path = self._identity_file(name)
        url, host = self._named(flow)
        sess = session.load(path) if path else None
        if sess is None:
            self._log(paths.EVENTS, {"kind": "identity-missing", "identity": name, "url": redact.url(url)})
            return None
        req, mark = flow.request, f"<identity:{name}>"
        decl = next((i for i in self.policy.scope.identities if i.get("name") == name), {})
        # M7: the identity's headers (a bearer token...) and static Cookie only go to its own origins
        own = session.headers_go_to(decl, url) and not cookies_only
        # I19: a header captured on this very origin at enrollment (the bearer of that audience) goes back there only
        per_origin = {} if cookies_only else session.origin_headers_for(sess, url)
        bearer = next((v for k, v in per_origin.items() if k.lower() == "authorization"), None)
        if bearer is not None and (exp := jwt_exp(bearer)) is not None and exp <= time.time():
            now = _now()
            if self._bearer_expired.allow(name, now):
                self._log(paths.EVENTS, {"kind": "bearer-expired", "identity": name, "host": host, "ts": now})
            return deny(BEARER_EXPIRED_REASON)
        if not own and not per_origin:
            flow.metadata["bh_identity_withheld"] = True
        headers = {**(sess["headers"] if own else {}), **per_origin}
        injected = {k: v for k, v in headers.items() if k.lower() != "cookie"}
        for k, val in injected.items():
            req.headers[k] = val
        jar = session.cookies_for(sess, url)
        static = session.parse_cookie_header(next((v for k, v in headers.items() if k.lower() == "cookie"), ""))
        ident_cookies = jar + [(n, v) for n, v in static if n not in {j for j, _ in jar}]
        redacted = {k.lower(): mark for k in injected}
        if ident_cookies:
            cookie, replaced = session.combine("; ".join(req.headers.get_all("cookie")) or None, ident_cookies)
            req.headers["Cookie"] = cookie
            redacted["cookie"] = mark
            if replaced:
                flow.metadata["bh_cookie_replaced"] = replaced
        flow.metadata["bh_redact"] = redacted
        flow.metadata["bh_session"] = self._session_info(name, path, sess)
        return None

    def _identity_response(self, flow: http.HTTPFlow) -> None:
        """Under an identity, on an in-scope target: fold Set-Cookie into the jar (the agent gets them with the
        value masked) and report a dead session. Runs before the flow is recorded."""
        ident, info = flow.metadata.get("bh_identity"), flow.metadata.get("bh_session")
        if not ident or not info:
            return  # no identity applied (none asked, unknown name, or not a target): nothing to keep
        self._identity_cookies(flow)
        if flow.metadata.get("bh_browser"):
            return  # the browser's own session may differ from the jar: its 401s say nothing about the jar's
        resp, (url, host) = flow.response, self._named(flow)
        seen = _now()  # the event carries the time of the answer, not of its ingestion (H4)
        reason = session.dead_reason(
            flow.request.method,
            url,
            resp.status_code,
            resp.headers.get("location"),
            login_url=info["login_url"],
            probe=info["probe"],
        )
        routes = None
        if reason is None and resp.status_code == 401:
            # one 401 is an access rule (the control of an access test); 401 on several routes is a dead session
            routes = self._unauth.hit(ident, url, seen)
            reason = "401-repeated" if routes else None
        if reason and self._dead.allow(ident, seen):
            rec = {
                "kind": "session-dead",
                "ts": seen,
                "identity": ident,
                "host": host,
                "status": resp.status_code,
                "reason": reason,
                "url": redact.url(url),
            }
            if routes:
                rec["routes"] = routes
            self._log(paths.EVENTS, rec)

    def _identity_cookies(self, flow: http.HTTPFlow) -> None:
        """Under an applied identity, on a target or an `sso` host: its Set-Cookie go into the identity's jar and
        reach the client with their value masked (the agent never holds a session value of our accounts)."""
        ident, info = flow.metadata.get("bh_identity"), flow.metadata.get("bh_session")
        if not ident or not info:
            return
        resp, url = flow.response, self._named(flow)[0]
        set_cookies = resp.headers.get_all("set-cookie")
        if not set_cookies:
            return
        if not flow.metadata.get("bh_browser"):  # bh-browser keeps its cookies: they are its session (I2)
            # mask first: whatever happens to the jar, the agent never receives an identity's cookie value
            masked = [session.mask_set_cookie(v, f"<identity:{ident}>") for v in set_cookies]
            resp.headers.set_all("set-cookie", masked)
        kept = flow.metadata.get("bh_class") == "target" or flow.metadata.get("bh_support") == "sso"
        try:
            # R14: from bh-browser, additions only; a page that signs a cookie out does not empty the identity's jar
            deletions = not flow.metadata.get("bh_browser")
            session.absorb(Path(info["file"]), url, set_cookies, in_scope=kept, deletions=deletions)
        except OSError as exc:  # a jar that cannot be written costs a stale session, not the answer
            ctx.log.error(f"bh-gate: cannot update the session of {ident}: {exc}")

    @fail_closed
    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None or flow.metadata.get("bh_denied"):
            return
        flow.response.headers.pop(GATE_HEADER, None)  # only the gate's own refusals carry it
        if flow.metadata.get("bh_class") not in ("target", "passive", "support", "payload"):
            return
        resp = flow.response
        self._canary(flow, "response-body", resp.raw_content, encoding=resp.headers.get("content-encoding"))
        if flow.metadata.get("bh_identity_asked") and (
            why := self.policy.passthrough_redirect(
                self._named(flow)[0], flow.response.status_code, flow.response.headers.get("location")
            )
        ):
            self._identity_cookies(flow)  # a rotated cookie of ours still goes to the jar, never to the client
            self._deny(flow, deny(why), "response")
            return
        if flow.metadata.get("bh_class") == "payload":  # D27: one journal line (class payload), never a test
            self._record(flow, flow.response.status_code)
            return
        if flow.metadata.get("bh_class") == "support":  # one journal line, never a test nor a WAF count
            if flow.metadata.get("bh_support") == "sso":
                self._identity_cookies(flow)  # the identity's own sign-in cookies rotate in its jar
            self._record(flow, flow.response.status_code)
            return
        self._identity_response(flow)
        fid = self._record(flow, flow.response.status_code)
        if flow.metadata.get("bh_class") != "target":
            return
        resp = flow.response
        url, host = self._named(flow)
        browser = bool(flow.metadata.get("bh_browser"))
        self.policy.note_answer(url, resp.status_code, browser=browser)
        server = resp.headers.get("server", "").lower()
        # H3: only the WAF's own answers count (cf-mitigated, challenge or block page), never `Server: cloudflare`
        waf = is_waf(resp.status_code, dict.fromkeys(resp.headers.keys(), ""), resp.raw_content)
        if waf and not browser:  # I6: a human passes the browser's challenges, so only its WAF pause is skipped
            self.policy.penalize(host, waf=True)  # repeated WAF answers pause the host (policy.WAF_LIMIT)
        elif resp.status_code in PUSHBACK_STATUS:  # R20: bh-browser's 429 / 503 slow the shared rate down too
            self.policy.penalize(host, waf=False)
        if waf:
            self._log(
                paths.EVENTS,
                {
                    "kind": "waf",
                    "host": host,
                    "url": redact.url(url),
                    "status": resp.status_code,
                    "server": server,
                    "flow": fid,
                },
            )
        elif resp.status_code == 401:
            self._log(
                paths.EVENTS,
                {
                    "kind": "auth",
                    "host": host,
                    "url": redact.url(url),
                    "flow": fid,
                    "identity": flow.metadata.get("bh_identity"),
                },
            )

    @fail_closed
    def error(self, flow: http.HTTPFlow) -> None:
        """Requests that never got a response (timeouts, resets) are part of the audit trail too."""
        if flow.metadata.get("bh_class") in ("target", "passive", "support", "payload") and flow.response is None:
            self._record(flow, "error", str(flow.error)[:200] if flow.error else "error")

    def _record(self, flow: http.HTTPFlow, status, error: str | None = None) -> str:
        """One line in flows.jsonl (+ the full exchange for targets, identity values redacted)."""
        req, resp = flow.request, flow.response
        url, host = self._named(flow)
        fid = f"{int(time.time())}-{secrets.token_hex(3)}-{next(self.seq)}"
        body = (resp.raw_content or b"") if resp is not None else b""
        klass = flow.metadata.get("bh_class")
        if klass == "target" and _from_gate(flow):
            # account enrollment (bh.accounts runs in the gate through this proxy): its bodies carry passwords and
            # session tokens, so the exchange is not kept, and it is not the agent's testing (assets, counts)
            klass = "enroll"
        rec = {
            "id": fid,
            "class": klass,
            "method": req.method,
            "url": redact.url(url),  # tokens in query strings stay out of the log
            "status": status,
            "len": len(body),
            "ctype": resp.headers.get("content-type", "") if resp else "",
            "wait": flow.metadata.get("bh_wait", 0),
            "ua": flow.metadata.get("bh_ua", "")[:120],
            "identity": flow.metadata.get("bh_identity"),
        }
        if klass == "support":
            rec["support"] = flow.metadata.get("bh_support")  # auth | assets: not a target, not a test
        if flow.metadata.get("bh_identity_withheld"):
            rec["identity_headers"] = "withheld"  # not one of the identity's origins: jar cookies only
        if replaced := flow.metadata.get("bh_cookie_replaced"):
            rec["cookie_replaced"] = replaced  # agent cookies the identity's jar overrode (names only)
        if req.host_header and parse_authority(req.host_header, check=False)[0] != host:
            rec["host_header"] = req.host_header
        if error:
            rec["error"] = error
        self._log(paths.FLOWS, rec)
        if rec["class"] == "target":
            injected = flow.metadata.get("bh_redact") or {}
            full = {
                **rec,
                "request": {
                    "headers": [
                        (k, injected.get(k.lower()) or redact.header(k, v)) for k, v in req.headers.items(multi=True)
                    ],
                    "body": _redacted_body(_decoded(req.raw_content, req.headers.get("content-encoding"))),
                },
                "response": {
                    "headers": [(k, redact.header(k, v)) for k, v in resp.headers.items(multi=True)] if resp else [],
                    "body": _redacted_body(_decoded(body, resp.headers.get("content-encoding") if resp else None)),
                },
            }
            try:
                fd = os.open(self.state / paths.FLOWS_DIR / f"{fid}.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as fh:
                    fh.write(json.dumps(full, ensure_ascii=False))
            except OSError as exc:
                ctx.log.error(f"bh-gate: cannot write flow {fid}: {exc}")
        return fid

    # ---- websockets (scope `websockets: true`): mitmproxy 12 event hooks, see the module docstring
    def _ws_refuse(self, flow: http.HTTPFlow, why: str, where: str, *, drop: bool = True) -> None:
        """Drop the frame in hand, close the connection; one `blocked` event per connection (a zombie's later frames
        are dropped silently)."""
        if drop and flow.websocket is not None and flow.websocket.messages:
            flow.websocket.messages[-1].drop()  # first: the frame in hand never leaves
        if flow.metadata.get("bh_ws_refused"):
            return
        flow.metadata["bh_ws_refused"] = True
        with contextlib.suppress(Exception):  # an already killed flow raises: the close below still runs
            flow.kill()
        closed = close_connection(flow)
        self._log(
            paths.EVENTS,
            {
                "kind": "blocked",
                "where": where,
                "url": redact.url(self._named(flow)[0]),
                "reason": why,
                "closed": closed,
                "client": "browser" if flow.metadata.get("bh_browser") else client_kind(flow),
            },
        )

    @fail_closed
    def websocket_start(self, flow: http.HTTPFlow) -> None:
        if flow.metadata.get("bh_class") != "target" or not flow.metadata.get("bh_ws") or _from_gate(flow):
            self._ws_refuse(flow, "websocket not opened through the gate's handshake checks", "websocket")
            return
        if why := self.policy.ws_start(flow.id, browser=bool(flow.metadata.get("bh_browser"))):
            self._ws_refuse(flow, why, "websocket")
            return
        self._log(
            paths.EVENTS,
            {
                "kind": "websocket",
                "phase": "start",
                "ws": flow.id,
                "url": redact.url(self._named(flow)[0]),
                "identity": flow.metadata.get("bh_identity"),
            },
        )
        # a silent connection is closed at its time limit too (the frames check it as well)
        with contextlib.suppress(RuntimeError):
            limit = self.policy.ws_live[flow.id].limits.max_seconds
            asyncio.get_running_loop().call_later(limit + 1, self._ws_expire, flow)

    def _ws_expire(self, flow: http.HTTPFlow) -> None:
        try:
            if flow.id in self.policy.ws_live and flow.websocket is not None and flow.websocket.timestamp_end is None:
                self.policy.ws_live[flow.id].closed = "websocket time limit"
                self._ws_refuse(flow, "websocket time limit", "websocket", drop=False)  # no frame in hand
        except Exception as exc:  # noqa: BLE001 - a timer callback must never raise into the loop
            ctx.log.error(f"bh-gate: websocket expiry failed: {exc!r}")

    @fail_closed
    def websocket_message(self, flow: http.HTTPFlow) -> None:
        msg = flow.websocket.messages[-1]
        content = msg.content or b""
        binary = not msg.is_text
        self._canary(flow, "ws-client" if msg.from_client else "ws-server", content)
        why = self.policy.ws_message(flow.id, len(content), binary=binary, from_client=msg.from_client)
        if why:
            self._ws_refuse(flow, why, "websocket-message")
            return
        self._log(
            paths.EVENTS,
            {
                "kind": "ws-message",
                "ws": flow.id,
                "from": "client" if msg.from_client else "server",
                "identity": flow.metadata.get("bh_identity"),
                **ws_message_record(content, binary=binary),
            },
        )

    @fail_closed
    def websocket_end(self, flow: http.HTTPFlow) -> None:
        g = self.policy.ws_end(flow.id)
        rec = {"kind": "websocket", "phase": "end", "ws": flow.id, "url": redact.url(self._named(flow)[0])}
        if g is not None:
            rec.update(g.counts(), closed=g.closed)
        self._log(paths.EVENTS, rec)


addons = [Gate()]
