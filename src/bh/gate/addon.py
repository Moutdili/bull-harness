"""mitmproxy addon: `mitmdump -s addon.py --set bh_state=/state`.

Enforces bh.gate.policy on every CONNECT, TLS handshake, request and upstream connection,
rate-limits (with backoff when the target pushes back), injects program headers and identities,
and writes compact JSONL logs that the runner turns into board facts.

Fail closed: mitmproxy only logs exceptions raised by addons and lets the flow continue, so every
hook here catches its own errors and denies.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
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
from bh.gate.policy import SYSTEM_HOSTS, Policy, Verdict, deny

MAX_BODY = 16_384
WAF_MARKERS = re.compile(
    rb"(Attention Required!? \| Cloudflare|Just a moment\.\.\.|cf-chl-|_Incapsula_Resource|"
    rb"Request unsuccessful\. Incapsula|Access Denied.{0,200}Reference #|The requested URL was rejected|"
    rb"Request blocked\..{0,100}(AWS|CloudFront)|Sucuri WebSite Firewall|captcha-delivery\.com|px-captcha)",
    re.I | re.S,
)
PUSHBACK_STATUS = (429, 503)
os.umask(0o077)  # logs and flow files hold target data and redacted sessions: owner-only


def _now() -> float:
    return round(time.time(), 3)


AGENT_HOST = os.environ.get("BH_AGENT_HOST", "agent")
# The only Claude API calls Claude Code makes with nonessential traffic off (measured 2026-11-24 on 2.1.330).
RELAY_PATHS = frozenset({("POST", "/v1/messages"), ("POST", "/v1/messages/count_tokens")})
RELAY_DEFAULT_MAX = 200  # requests per activation of a run when the runner names no budget
# headers that make a framework run another method than the request line's (POST + override = DELETE)
METHOD_OVERRIDES = ("X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override")


_AGENT_IPS: tuple[float, frozenset[str]] = (0.0, frozenset())


def _agent_ips() -> frozenset[str]:
    """Addresses of the agent container (compose service name), cached a minute."""
    global _AGENT_IPS
    if time.time() - _AGENT_IPS[0] > 60:
        try:
            ips = frozenset(i[4][0] for i in socket.getaddrinfo(AGENT_HOST, 0))
        except OSError:
            ips = frozenset()
        _AGENT_IPS = (time.time(), ips)
    return _AGENT_IPS[1]


def _model(req: http.Request) -> str | None:
    """The `model` a Claude API request asks for (JSON body), None when there is none."""
    if req.method != "POST" or not req.raw_content or len(req.raw_content) > 32 << 20:
        return None
    try:
        model = json.loads(req.get_content(strict=False) or b"").get("model")
    except (ValueError, AttributeError):
        return None
    return model[:80] if isinstance(model, str) else None


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

    def load(self, loader) -> None:
        loader.add_option("bh_state", str, "/state", "bull-harness state dir")

    def configure(self, updated) -> None:
        if "bh_state" not in updated and self.policy is not None:
            return  # another option changed: keep the policy and its rate-limit buckets
        self.state = Path(ctx.options.bh_state)
        (self.state / paths.FLOWS_DIR).mkdir(parents=True, exist_ok=True)
        self.policy = Policy(self.state / paths.ACTIVE_SCOPE)
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
                "url": self._named(flow)[0],
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
        if peer not in _agent_ips():  # the gate also sits on the lab network: a target must not reach the token
            self._deny(flow, deny(f"relay: only the agent container may use it (not {peer})"), "relay")
            return
        token = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "")
        req = flow.request
        path = req.path.split("?")[0]
        run = self._active_run()
        self._log(paths.EVENTS, {"kind": "relay", "method": req.method, "path": path[:120], "model": _model(req)})
        if not token:
            reason = "relay: no token in the gate"
        elif (req.method, path) not in RELAY_PATHS:
            reason = f"relay: {req.method} {path[:60]} is not a call Claude Code makes"
        elif not run:  # between runs the sandbox has no business spending the quota
            reason = "relay: no run in progress"
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
            flow.response.stream = True  # server-sent events: relay as they come, never buffered or logged

    # ---- HTTP hooks
    @fail_closed
    async def request(self, flow: http.HTTPFlow) -> None:
        if flow.response is not None:  # already denied at CONNECT
            return
        if self._is_relay(flow):
            self._relay(flow)
            return
        req = flow.request
        identity = req.headers.pop(IDENTITY_HEADER, None)
        if identity is not None and self._identity_file(identity) is None:
            self._log(
                paths.EVENTS, {"kind": "identity-missing", "identity": identity[:60], "url": self._named(flow)[0]}
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
        path = self._identity_file(name)
        try:
            ident = json.loads(path.read_text()) if path else None
        except (OSError, ValueError):
            ident = None
        if not isinstance(ident, dict):
            self._log(paths.EVENTS, {"kind": "identity-missing", "identity": name, "url": self._named(flow)[0]})
            return
        injected = ident.get("headers") or {}
        for k, val in injected.items():
            flow.request.headers[k] = val
        flow.metadata["bh_redact"] = {k.lower(): f"<identity:{name}>" for k in injected}

    @fail_closed
    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None or flow.metadata.get("bh_denied"):
            return
        flow.response.headers.pop(GATE_HEADER, None)  # only the gate's own refusals carry it
        if flow.metadata.get("bh_class") not in ("target", "passive"):
            return
        fid = self._record(flow, flow.response.status_code)
        if flow.metadata.get("bh_class") != "target":
            return
        resp = flow.response
        url, host = self._named(flow)
        self.policy.note_answer(url, resp.status_code)
        body = resp.raw_content or b""
        server = resp.headers.get("server", "").lower()
        waf = resp.status_code in (403, *PUSHBACK_STATUS) and bool(
            "cf-mitigated" in resp.headers
            or WAF_MARKERS.search(body[:65536])
            or (resp.status_code == 403 and any(s in server for s in ("cloudflare", "akamai", "awselb")))
        )
        if waf or resp.status_code in PUSHBACK_STATUS:
            self.policy.penalize(host, waf=waf)  # repeated WAF answers pause the host (policy.WAF_LIMIT)
        if waf:
            self._log(
                paths.EVENTS,
                {
                    "kind": "waf",
                    "host": host,
                    "url": url,
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
                    "url": url,
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
        rec = {
            "id": fid,
            "class": flow.metadata.get("bh_class"),
            "method": req.method,
            "url": redact.url(url),  # tokens in query strings stay out of the log
            "status": status,
            "len": len(body),
            "ctype": resp.headers.get("content-type", "") if resp else "",
            "wait": flow.metadata.get("bh_wait", 0),
            "ua": flow.metadata.get("bh_ua", "")[:120],
            "identity": flow.metadata.get("bh_identity"),
        }
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
