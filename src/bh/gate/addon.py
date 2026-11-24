"""mitmproxy addon: `mitmdump -s addon.py --set bh_state=/state`.

Enforces bh.gate.policy on every CONNECT, request and upstream connection,
rate-limits, injects program headers and identities, and writes compact JSONL
logs that the runner turns into board facts / human todos.
"""

from __future__ import annotations

import itertools
import json
import os
import re
import socket
import threading
import time
from pathlib import Path

from mitmproxy import ctx, http
from mitmproxy.proxy import server_hooks

from bh.agent.contract import IDENTITY_HEADER
from bh.gate.policy import SYSTEM_IGNORE_REGEX, Policy, Verdict

MAX_BODY = 16_384
WAF_MARKERS = re.compile(
    rb"(Attention Required!? \| Cloudflare|Just a moment\.\.\.|cf-chl-|_Incapsula_Resource|"
    rb"Request unsuccessful\. Incapsula|Access Denied.{0,200}Reference #|The requested URL was rejected|"
    rb"Request blocked\..{0,100}(AWS|CloudFront)|Sucuri WebSite Firewall|captcha-delivery\.com|px-captcha)",
    re.I | re.S,
)


def _now() -> float:
    return round(time.time(), 3)


class Gate:
    def __init__(self) -> None:
        self.policy: Policy | None = None
        self.state = Path("/state")
        self.seq = itertools.count(1)

    def load(self, loader) -> None:
        loader.add_option("bh_state", str, "/state", "bull-harness state dir")

    def configure(self, updated) -> None:
        if "bh_state" not in updated and self.policy is not None:
            return  # another option changed: keep the policy and its rate-limit buckets
        self.state = Path(ctx.options.bh_state)
        (self.state / "flows").mkdir(parents=True, exist_ok=True)
        self.policy = Policy(self.state / "active-scope.yaml")
        self.policy.reload()
        # Claude API traffic is tunnelled untouched (TLS passthrough), never decrypted by the gate.
        if SYSTEM_IGNORE_REGEX not in ctx.options.ignore_hosts:
            ctx.options.update(ignore_hosts=[*ctx.options.ignore_hosts, SYSTEM_IGNORE_REGEX])

    def running(self) -> None:
        """Publish only the public CA cert for the agent; the CA key stays in the gate's confdir."""
        src = Path(ctx.options.confdir).expanduser() / "mitmproxy-ca-cert.pem"
        dst_dir = Path(os.environ.get("BH_CA_PUB", "/gate-ca"))

        def publish() -> None:  # the CA may be written just after `running`; never log an error at startup
            for _ in range(60):
                try:
                    dst_dir.mkdir(parents=True, exist_ok=True)
                    (dst_dir / "mitmproxy-ca-cert.pem").write_bytes(src.read_bytes())
                    return
                except OSError:
                    time.sleep(0.5)
            ctx.log.warn(f"bh-gate: could not publish CA cert from {src}")

        threading.Thread(target=publish, daemon=True).start()

    # ---- logging
    def _log(self, name: str, rec: dict) -> None:
        rec.setdefault("ts", _now())
        rec.setdefault("program", self.policy.program if self.policy else "-")
        with open(self.state / name, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def _deny(self, flow: http.HTTPFlow, v: Verdict, where: str) -> None:
        self._log(
            "events.jsonl",
            {
                "kind": "blocked",
                "where": where,
                "url": flow.request.pretty_url,
                "method": flow.request.method,
                "reason": v.reason,
                "rule": v.rule,
            },
        )
        body = f"bh-gate: DENIED ({v.reason}{' / ' + v.rule if v.rule else ''})\n".encode()
        flow.response = http.Response.make(403, body, {"Content-Type": "text/plain", "X-BH-Gate": "denied"})

    # ---- hooks
    def http_connect(self, flow: http.HTTPFlow) -> None:
        host, port = flow.request.host, flow.request.port
        v = self.policy.classify(f"{host}:{port}" if ":" not in host else f"[{host}]:{port}", host)
        flow.metadata["bh_class"] = v.klass
        if not v.allowed:
            self._deny(flow, v, "connect")

    def server_connect(self, data: server_hooks.ServerConnectionHookData) -> None:
        """Resolve and vet every upstream IP before mitmproxy connects (rebinding / internal pivot)."""
        if not data.server.address:
            return
        host, port = data.server.address
        try:
            infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except OSError as exc:
            data.server.error = f"bh-gate: resolve failed: {exc}"
            return
        for info in infos:
            ip = info[4][0]
            v = self.policy.check_ip(host, ip)
            if not v.allowed:
                self._log(
                    "events.jsonl",
                    {"kind": "blocked", "where": "resolve", "host": host, "ip": ip, "reason": v.reason, "rule": v.rule},
                )
                data.server.error = f"bh-gate: DENIED {host} -> {ip} ({v.reason})"
                return

    async def request(self, flow: http.HTTPFlow) -> None:
        if flow.response is not None:  # already denied at CONNECT
            return
        req = flow.request
        v = self.policy.classify(req.pretty_url, req.pretty_host, req.method)
        flow.metadata["bh_class"] = v.klass
        identity = req.headers.pop(IDENTITY_HEADER, None)
        flow.metadata["bh_identity"] = identity
        if not v.allowed:
            self._deny(flow, v, "request")
            return
        bucket = self.policy.bucket(v.klass)
        if bucket is not None:
            flow.metadata["bh_wait"] = round(await bucket.take(), 3)
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

    def _apply_identity(self, flow: http.HTTPFlow, name: str) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", name):
            return
        path = self.state / "identities" / self.policy.program / f"{name}.json"
        try:
            ident = json.loads(path.read_text())
        except (OSError, ValueError):
            self._log("events.jsonl", {"kind": "identity-missing", "identity": name, "url": flow.request.pretty_url})
            return
        for k, val in (ident.get("headers") or {}).items():
            flow.request.headers[k] = val

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None or flow.response.headers.get("X-BH-Gate") == "denied":
            return
        klass = flow.metadata.get("bh_class", "?")
        if klass != "target":
            return
        req, resp = flow.request, flow.response
        n = next(self.seq)
        fid = f"{int(time.time())}-{os.getpid()}-{n}"
        body = resp.raw_content or b""
        rec = {
            "id": fid,
            "method": req.method,
            "url": req.pretty_url,
            "status": resp.status_code,
            "len": len(body),
            "ctype": resp.headers.get("content-type", ""),
            "wait": flow.metadata.get("bh_wait", 0),
        }
        self._log("flows.jsonl", rec)
        full = {
            **rec,
            "request": {
                "headers": list(req.headers.items(multi=True)),
                "body": (req.raw_content or b"")[:MAX_BODY].decode("utf-8", "replace"),
            },
            "response": {
                "headers": list(resp.headers.items(multi=True)),
                "body": body[:MAX_BODY].decode("utf-8", "replace"),
            },
        }
        (self.state / "flows" / f"{fid}.json").write_text(json.dumps(full, ensure_ascii=False))
        server = resp.headers.get("server", "").lower()
        if resp.status_code in (403, 429, 503) and (
            "cf-mitigated" in resp.headers
            or WAF_MARKERS.search(body[:65536])
            or (resp.status_code == 403 and any(s in server for s in ("cloudflare", "akamai", "awselb")))
        ):
            self._log(
                "events.jsonl",
                {
                    "kind": "waf",
                    "host": req.pretty_host,
                    "url": req.pretty_url,
                    "status": resp.status_code,
                    "server": server,
                    "flow": fid,
                },
            )
        elif resp.status_code == 401:
            self._log(
                "events.jsonl",
                {
                    "kind": "auth",
                    "host": req.pretty_host,
                    "url": req.pretty_url,
                    "flow": fid,
                    "identity": flow.metadata.get("bh_identity"),
                },
            )


addons = [Gate()]
