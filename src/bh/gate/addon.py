"""mitmproxy addon: `mitmdump -s addon.py --set bh_state=/state`.

Enforces bh.gate.policy on every CONNECT, TLS handshake, request and upstream connection,
rate-limits (with backoff when the target pushes back), injects program headers and identities,
and writes compact JSONL logs that the runner turns into board facts.

Identities (bh.gate.session): a request with X-BH-Identity to an in-scope target gets the identity's headers
and the cookies of its jar. The Set-Cookie of the answer go into the jar (file rewritten atomically) and reach
the agent with their value masked. The identity's headers and static Cookie only go to the identity's origins
(session.identity_origins; none declared: every in-scope host). A redirect to the identity's `login_url`, a failed
probe, or 401 answers on session.UNAUTH_ROUTES distinct routes within session.UNAUTH_WINDOW_S write one
`session-dead` event (at most one per identity and minute, `ts` = when it was seen); a single 401 is no proof.

Relay (Claude API, the only holder of the OAuth token): only the agent and judge containers, only the two calls
Claude Code makes, within the run's budget, and only a body policy.check_relay accepts: client tools only, no
`mcp_servers` / `container`, no URL source, anthropic-beta values on the list (policy.relay_betas), the model on
the client's list (policy.relay_models).

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
import threading
import time
from pathlib import Path

from mitmproxy import ctx, http, tcp, udp
from mitmproxy.net.http.url import parse_authority, unparse
from mitmproxy.proxy import mode_specs, server_hooks

from bh import paths, redact
from bh.agent.contract import GATE_HEADER, IDENTITY_HEADER
from bh.gate import session
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
)

MAX_BODY = 16_384
PUSHBACK_STATUS = (429, 503)
os.umask(0o077)  # logs and flow files hold target data and redacted sessions: owner-only


def _now() -> float:
    return round(time.time(), 3)


AGENT_HOST = os.environ.get("BH_AGENT_HOST", "agent")
JUDGE_HOST = os.environ.get("BH_JUDGE_HOST", "judge")  # the verifier's own container (compose service `judge`)
# the only clients of the relay: the hunter's container and the judge's. Nothing else on the gate's networks.
RELAY_CLIENT_HOSTS = (AGENT_HOST, JUDGE_HOST)
# The only Claude API calls Claude Code makes with nonessential traffic off (measured 2026-11-24 on 2.1.330).
RELAY_PATHS = frozenset({("POST", "/v1/messages"), ("POST", "/v1/messages/count_tokens")})
RELAY_DEFAULT_MAX = 200  # requests per activation of a run when the runner names no budget
# headers that make a framework run another method than the request line's (POST + override = DELETE)
METHOD_OVERRIDES = ("X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override")


RELAY_ROLES = {AGENT_HOST: "agent", JUDGE_HOST: "judge"}
RELAY_MODELS = relay_models()  # role -> model ids it may ask for (BH_RELAY_MODELS_AGENT / _JUDGE)
RELAY_BETAS = relay_betas()  # anthropic-beta values let through (BH_RELAY_BETAS)
RELAY_IPS_TTL, RELAY_IPS_RETRY = 60.0, 5.0
_RELAY_IPS: tuple[float, dict[str, frozenset[str]]] = (0.0, {})


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


def _from_gate(flow: http.HTTPFlow) -> bool:
    """The request comes from inside the gate container (account enrollment), not from the agent."""
    return (flow.client_conn.peername or ("?",))[0] in ("127.0.0.1", "::1", "::ffff:127.0.0.1")


def refuse(flow: http.HTTPFlow, v: Verdict) -> None:
    """The gate's refusal: a 403 marked X-BH-Gate, and a metadata flag a target response cannot fake."""
    body = f"bh-gate: DENIED ({v.reason}{' / ' + v.rule if v.rule else ''})\n".encode()
    flow.response = http.Response.make(403, body, {"Content-Type": "text/plain", GATE_HEADER: "denied"})
    flow.metadata["bh_denied"] = True


def fail_closed(hook):
    """Any exception in a hook denies the flow instead of letting mitmproxy continue it."""

    def on_error(hook_name: str, arg, exc: Exception) -> None:
        ctx.log.error(f"bh-gate: {hook_name} failed, denying: {exc!r}")
        if isinstance(arg, http.HTTPFlow):
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
        self._dead = session.DeadLimiter()  # one session-dead event per identity per minute
        self._unauth = session.Unauthorized()  # 401 under an identity, per distinct route

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

    def _deny(self, flow: http.HTTPFlow, v: Verdict, where: str) -> None:
        refuse(flow, v)  # first: a failing log write must not let the request through
        self._log(
            paths.EVENTS,
            {
                "kind": "blocked",
                "where": where,
                "url": redact.url(self._named(flow)[0]),
                "method": flow.request.method,
                "reason": v.reason,
                "rule": v.rule,
            },
        )

    # ---- connection-level hooks
    @fail_closed
    def http_connect(self, flow: http.HTTPFlow) -> None:
        v = self.policy.classify_connect(flow.request.host, flow.request.port)
        flow.metadata["bh_class"] = v.klass
        if not v.allowed:
            self._deny(flow, v, "connect")

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
        dest = (unparse(req.scheme, host, req.port, req.path), host)
        flow.metadata["bh_dest"] = dest
        return dest

    @fail_closed
    def tcp_start(self, flow: tcp.TCPFlow) -> None:
        """Raw TCP (non-HTTP bytes in a tunnel, CRLF tricks, other ports) never leaves."""
        flow.kill()
        host, port = self._destination(flow.server_conn)
        self._log(
            paths.EVENTS,
            {"kind": "blocked", "where": "tcp", "host": host, "port": port, "reason": "raw TCP is not allowed"},
        )

    @fail_closed
    def tcp_message(self, flow: tcp.TCPFlow) -> None:
        """kill() in tcp_start does not stop the first message: drop every byte of the tunnel."""
        flow.messages[-1].content = b""
        flow.kill()

    def server_disconnected(self, data: server_hooks.ServerConnectionHookData) -> None:
        self._dest.pop(data.server.id, None)

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
        infos = await asyncio.get_running_loop().getaddrinfo(
            host, port, proto=socket.IPPROTO_TCP
        )  # no event-loop freeze
        for info in infos:
            ip = info[4][0]
            v = self.policy.check_ip(host, ip)
            if not v.allowed:
                self._log(
                    paths.EVENTS,
                    {"kind": "blocked", "where": "resolve", "host": host, "ip": ip, "reason": v.reason, "rule": v.rule},
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
        if identity is not None and self._identity_file(identity) is None:
            self._log(
                paths.EVENTS,
                {"kind": "identity-missing", "identity": identity[:60], "url": redact.url(self._named(flow)[0])},
            )
            identity = None  # an unknown name is no identity: it must not unlock writes
        flow.metadata["bh_identity"] = identity
        if not req.path.startswith("/"):  # "@other.host/x" would re-parse as another destination
            self._deny(flow, deny("the request target must start with /"), "request")
            return
        if req.headers.get("upgrade", "").lower() == "websocket":  # frames after the handshake are not judged
            self._deny(flow, deny("websockets are not allowed: the gate cannot judge their frames"), "request")
            return
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
        )
        flow.metadata["bh_class"] = v.klass
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
            if identity:
                self._apply_identity(flow, identity)
        elif v.klass == "passive":
            for k in ("Cookie", "Authorization"):
                req.headers.pop(k, None)

    def _identity_file(self, name: str) -> Path | None:
        """The identity's file for the active program, None for an unknown or malformed name."""
        if not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,39}", name):
            return None
        path = self.state / paths.IDENTITIES / self.policy.program / f"{name}.json"
        return path if path.is_file() else None

    def _apply_identity(self, flow: http.HTTPFlow, name: str) -> None:
        """Inject the identity's headers and the cookies its jar holds for this URL (bh.gate.session).
        Cookies: the jar (fresh, rotated by Set-Cookie) beats a static `Cookie` of `headers`; both beat an agent
        cookie of the same name (session.combine), whose name is then recorded in the flow."""
        path = self._identity_file(name)
        url = self._named(flow)[0]
        sess = session.load(path) if path else None
        if sess is None:
            self._log(paths.EVENTS, {"kind": "identity-missing", "identity": name, "url": redact.url(url)})
            return
        req, mark = flow.request, f"<identity:{name}>"
        decl = next((i for i in self.policy.scope.identities if i.get("name") == name), {})
        # M7: the identity's headers (a bearer token...) and static Cookie only go to its own origins
        own = session.headers_go_to(decl, url)
        if not own:
            flow.metadata["bh_identity_withheld"] = True
        headers = sess["headers"] if own else {}
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
        flow.metadata["bh_session"] = {
            "file": str(path),
            "login_url": decl.get("login_url"),
            "probe": decl.get("probe") or sess.get("probe"),
        }

    def _identity_response(self, flow: http.HTTPFlow) -> None:
        """Under an identity, on an in-scope target: fold Set-Cookie into the jar (the agent gets them with the
        value masked) and report a dead session. Runs before the flow is recorded."""
        ident, info = flow.metadata.get("bh_identity"), flow.metadata.get("bh_session")
        if not ident or not info:
            return  # no identity applied (none asked, unknown name, or not a target): nothing to keep
        resp, (url, host) = flow.response, self._named(flow)
        set_cookies = resp.headers.get_all("set-cookie")
        if set_cookies:
            # mask first: whatever happens to the jar, the agent never receives an identity's cookie value
            resp.headers.set_all("set-cookie", [session.mask_set_cookie(v, f"<identity:{ident}>") for v in set_cookies])
            try:
                session.absorb(Path(info["file"]), url, set_cookies, in_scope=flow.metadata.get("bh_class") == "target")
            except OSError as exc:  # a jar that cannot be written costs a stale session, not the answer
                ctx.log.error(f"bh-gate: cannot update the session of {ident}: {exc}")
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

    @fail_closed
    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None or flow.metadata.get("bh_denied"):
            return
        flow.response.headers.pop(GATE_HEADER, None)  # only the gate's own refusals carry it
        if flow.metadata.get("bh_class") not in ("target", "passive"):
            return
        self._identity_response(flow)
        fid = self._record(flow, flow.response.status_code)
        if flow.metadata.get("bh_class") != "target":
            return
        resp = flow.response
        url, host = self._named(flow)
        self.policy.note_answer(url, resp.status_code)
        server = resp.headers.get("server", "").lower()
        # H3: only the WAF's own answers count (cf-mitigated, challenge or block page), never `Server: cloudflare`
        waf = is_waf(resp.status_code, dict.fromkeys(resp.headers.keys(), ""), resp.raw_content)
        if waf or resp.status_code in PUSHBACK_STATUS:
            self.policy.penalize(host, waf=waf)  # repeated WAF answers pause the host (policy.WAF_LIMIT)
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
        if flow.metadata.get("bh_class") in ("target", "passive") and flow.response is None:
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
                    "body": (req.raw_content or b"")[:MAX_BODY].decode("utf-8", "replace"),
                },
                "response": {
                    "headers": [(k, redact.header(k, v)) for k, v in resp.headers.items(multi=True)] if resp else [],
                    "body": body[:MAX_BODY].decode("utf-8", "replace"),
                },
            }
            try:
                fd = os.open(self.state / paths.FLOWS_DIR / f"{fid}.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as fh:
                    fh.write(json.dumps(full, ensure_ascii=False))
            except OSError as exc:
                ctx.log.error(f"bh-gate: cannot write flow {fid}: {exc}")
        return fid


addons = [Gate()]
