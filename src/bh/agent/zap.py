"""bh-zap: one headless ZAP daemon per command, through the gate.

  bh-zap <url> [--as ID] [--spider|--ajax] [--active] [--timeout S] [--max-alerts N]

Without --active: spider (or AJAX spider, Chromium) + passive scan: a mapper. With --active: active scan of the
origin too, a scanner (refused when the program forbids scanners). The summary is at most 25 lines; alerts,
HAR, ZAP's log and home stay in raw/zap-<slug>-<ts>/.

Isolation: ZAP listens on a free 127.0.0.1 port with a random API key and a fresh home under raw/; every
outgoing request goes to the gate as upstream proxy (network.connection.httpProxy.*), so scope, rate, headers and
identities apply; --as adds X-BH-Identity on every request (Replacer rule). The context is the URL's origin only,
ZAP runs in protected mode, the AJAX spider keeps its strict scope check without allowed resources. No update
check, no telemetry (-silent -notel, start.* keys), no OAST service; out-of-band, DoS-like, time-based and
brute-force scan rules are disabled (DISABLED_RULES).

Only `run()` starts Java: bh-agent and the tests never need ZAP.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import secrets
import shlex
import signal
import socket
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from bh.agent import contract as c

SUMMARY_LINES = 25
LINE_CHARS = 240
DEFAULT_TIMEOUT = {False: 280, True: 540}  # passive / active; the Bash tool allows 600 s per command
MIN_TIMEOUT = 90  # ZAP alone needs ~20-40 s to start
MARGIN_S = 25  # kept at the end of the budget: collect alerts and messages, write raw, stop ZAP
DEFAULT_MAX_ALERTS = 10
# Heap: the agent container has mem_limit 6g shared with claude (node), Chromium (bh-browse, --ajax) and the other
# tools. ZAP's own default is 25 % of the memory it sees (1.5 GB here); 1 GB is enough for one origin since the
# history lives in the on-disk session database, and leaves room for Chromium during an AJAX spider.
XMX = "1024m"
JAR_LINK = Path("/opt/bh/zap.jar")  # set by the Containerfile to the Kali package's jar
JAR_GLOBS = ("/usr/share/zaproxy/zap-*.jar", "/opt/zaproxy/zap-*.jar")
CHROMIUM, CHROMEDRIVER = "/usr/bin/chromium", "/usr/bin/chromedriver"  # same Kali source, same version (--ajax)
CONTEXT = "bh"
RISKS = ("High", "Medium", "Low", "Informational")
SPIDER_THREADS = 2
ASCAN_THREADS_PER_HOST = 2
# Active rules never run (ids from https://www.zaproxy.org/docs/alerts/):
DISABLED_RULES = {
    # time-based injections: long sleeps stall the target (same doctrine as bh-sqli, techniques BEU only)
    "40019": "SQLi MySQL time based",
    "40020": "SQLi Hypersonic time based",
    "40021": "SQLi Oracle time based",
    "40022": "SQLi PostgreSQL time based",
    "40024": "SQLi SQLite time based",
    "40027": "SQLi MsSQL time based",
    "90039": "NoSQL MongoDB time based",
    # out of band: they need a callback server, which is outside the gate
    "40043": "Log4Shell (OAST)",
    "40046": "SSRF (OAST)",
    "40047": "Text4shell (OAST)",
    "40031": "Out of Band XSS (OAST)",
    # denial of service or near it
    "40044": "Exponential Entity Expansion (billion laughs)",
    "30001": "Buffer Overflow",
    "30002": "Format String Error",
    "90024": "Generic Padding Oracle (thousands of requests)",
    # brute force / enumeration of names
    "40035": "Hidden File Finder",
    "10095": "Backup File Disclosure",
    "40023": "Possible Username Enumeration",
}


# ------------------------------------------------------------------ arguments
def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bh-zap", description=__doc__.split("\n\n")[0], allow_abbrev=False)
    p.add_argument("url", help="start URL (https:// is assumed without a scheme)")
    p.add_argument("--as", dest="identity", help="identity name, sent as X-BH-Identity")
    crawl = p.add_mutually_exclusive_group()
    crawl.add_argument("--spider", dest="ajax", action="store_false", help="classic spider (default)")
    crawl.add_argument("--ajax", dest="ajax", action="store_true", help="AJAX spider (headless Chromium)")
    p.add_argument("--active", action="store_true", help="active scan too (a scanner)")
    p.add_argument("--timeout", type=int, help="seconds for the whole command (default 280, 540 with --active)")
    p.add_argument("--max-alerts", type=int, default=DEFAULT_MAX_ALERTS, help="alert groups shown")
    p.set_defaults(ajax=False)
    return p


def parse_args(argv: list[str]) -> argparse.Namespace:
    a = parser().parse_args(argv)
    if "://" not in a.url:
        a.url = "https://" + a.url
    a.timeout = max(MIN_TIMEOUT, a.timeout or DEFAULT_TIMEOUT[a.active])
    a.max_alerts = min(15, max(1, a.max_alerts))
    return a


def phase_kind(a: argparse.Namespace) -> str:
    return "scanner" if a.active else "mapper"


# ------------------------------------------------------------------ ZAP command line and policy (pure)
def gate_host_port(gate: str) -> tuple[str, int]:
    p = urlsplit(gate if "://" in gate else "http://" + gate)
    return p.hostname or "gate", p.port or 8080


def find_jar() -> Path | None:
    if JAR_LINK.exists():
        return JAR_LINK.resolve()
    from glob import glob

    found = sorted(p for g in JAR_GLOBS for p in glob(g))
    return Path(found[-1]) if found else None


def config_pairs(api_key: str, gate: str) -> list[tuple[str, str]]:
    """-config key=value pairs. Keys: network add-on ConnectionOptions (network.connection.*), core
    OptionsParamCheckForUpdates (start.*), oast add-on OastParam, selenium add-on SeleniumOptions."""
    host, port = gate_host_port(gate)
    return [
        ("api.key", api_key),
        ("start.checkForUpdates", "false"),
        ("start.checkAddonUpdates", "false"),
        ("start.installAddonUpdates", "false"),
        ("start.installScannerRules", "false"),
        ("start.downloadNewRelease", "false"),
        ("network.connection.httpProxy.enabled", "true"),
        ("network.connection.httpProxy.host", host),
        ("network.connection.httpProxy.port", str(port)),
        ("network.connection.httpProxy.authEnabled", "false"),
        ("network.connection.timeoutInSecs", "30"),  # the gate queues requests to keep the program rate
        ("oast.activeScanService", "None"),
        ("selenium.chromeBinary", CHROMIUM),
        ("selenium.chromeDriver", CHROMEDRIVER),
    ]


def zap_command(jar: Path, home: Path, port: int, api_key: str, gate: str) -> list[str]:
    cmd = [
        "java",
        f"-Xmx{XMX}",
        "-Djava.awt.headless=true",
        "-jar",
        str(jar),
        "-daemon",
        "-host",
        "127.0.0.1",
        "-port",
        str(port),
        "-dir",
        str(home),
        "-installdir",
        str(jar.parent),
        "-silent",  # no unsolicited request (update checks...)
        "-notel",  # no telemetry
    ]
    for k, v in config_pairs(api_key, gate):
        cmd += ["-config", f"{k}={v}"]
    return cmd


def redact(cmd: list[str], api_key: str) -> str:
    return shlex.join(cmd).replace(api_key, "<api-key>")


_HOST_OK = re.compile(r"^(\[[0-9a-f:.]+\]|[a-z0-9.-]+)$", re.I)


def context_regex(url: str) -> str:
    """Java regex matching the URL's origin only (scheme, host, port; the default port may be implicit)."""
    p = urlsplit(url)
    host = (p.hostname or "").lower()
    if p.scheme not in ("http", "https") or not host:
        raise ValueError(f"not an http(s) URL: {url!r}")
    shown = f"[{host}]" if ":" in host else host
    if not _HOST_OK.match(shown):
        raise ValueError(f"unexpected host: {host!r}")
    default = 443 if p.scheme == "https" else 80
    port = p.port or default
    port_re = f"(?::{default})?" if port == default else f":{port}"
    return rf"(?i)^{p.scheme}://\Q{shown}\E{port_re}(?:[/?#].*)?$"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ------------------------------------------------------------------ messages and alerts (pure)
_GATE_DENIED = re.compile(rf"(?im)^{re.escape(c.GATE_HEADER)}:\s*denied")


def parse_message(m: dict) -> tuple[str, str, int | None, bool, list[str]]:
    """ZAP API message -> (method, url, status, denied by the gate, body parameter names)."""
    req = str(m.get("requestHeader") or "")
    resp = str(m.get("responseHeader") or "")
    first = req.split("\r\n", 1)[0].split("\n", 1)[0].split(" ")
    method, url = (first[0], first[1]) if len(first) >= 2 else ("GET", "")
    st = re.match(r"HTTP/\S+\s+(\d{3})", resp)
    body = str(m.get("requestBody") or "")
    params: list[str] = []
    if "application/x-www-form-urlencoded" in req.lower() and body:
        params = [k for k, _ in parse_qsl(body, keep_blank_values=True)]
    return method.upper(), url, int(st.group(1)) if st else None, bool(_GATE_DENIED.search(resp)), params


def risk_counts(alerts: list[dict]) -> Counter:
    return Counter(str(a.get("risk", "?")) for a in alerts)


def group_alerts(alerts: list[dict]) -> list[dict]:
    """One entry per (risk, alert name), most severe first, the first instance kept with a count."""
    groups: dict[tuple[str, str], dict] = {}
    for a in alerts:
        k = (str(a.get("risk", "?")), str(a.get("alert") or a.get("name") or "?"))
        g = groups.setdefault(k, {**a, "count": 0})
        g["count"] += 1
    rank = {r: i for i, r in enumerate(RISKS)}
    return sorted(groups.values(), key=lambda g: (rank.get(str(g.get("risk")), 9), -g["count"]))


def _short(url: str, n: int = 70) -> str:
    p = urlsplit(url)
    s = (p.path or "/") + (f"?{p.query}" if p.query else "")
    return s if len(s) <= n else s[: n - 1] + "…"


def _flat(s: str, n: int) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


# ------------------------------------------------------------------ result and summary
@dataclass
class Result:
    url: str
    identity: str | None = None
    ajax: bool = False
    active: bool = False
    version: str = ""
    state: str = "ok"
    error: str = ""
    seconds: float = 0.0
    history: int = 0  # spider / proxied messages kept by ZAP
    ascan_requests: int = 0
    gate_denied: int = 0
    offsite: Counter = field(default_factory=Counter)  # host -> requests ZAP sent outside the origin
    alerts: list[dict] = field(default_factory=list)
    new_endpoints: int = 0
    ascan_ids: list[str] = field(default_factory=list)  # messages of the active scan
    touched: list[tuple[str, str]] = field(default_factory=list)  # (method, url) attacked by the active scan
    max_alerts: int = DEFAULT_MAX_ALERTS
    raw: str = ""


def render(r: Result) -> list[str]:
    """At most SUMMARY_LINES lines, each at most LINE_CHARS characters."""
    who = f" as={r.identity}" if r.identity else ""
    mode = ("ajax" if r.ajax else "spider") + ("+passive+active" if r.active else "+passive")
    ver = f"ZAP {r.version}, " if r.version else ""
    head = f"bh-zap {r.url}{who}: {mode}, {ver}{r.seconds:.0f} s [{r.state}]"
    body: list[str] = []
    if r.error:
        body.append(f"error: {r.error}")
    req = f"requests: {r.history + r.ascan_requests} (spider/history {r.history}, active {r.ascan_requests})"
    if r.gate_denied:
        req += f"; gate denied {r.gate_denied}"
    if r.offsite:
        req += "; offsite " + ", ".join(f"{h} ×{n}" for h, n in r.offsite.most_common(3))
    body.append(req)
    counts = risk_counts(r.alerts)
    body.append(
        f"alerts: {len(r.alerts)} — " + ", ".join(f"{k.lower()} {counts.get(k, 0)}" for k in RISKS)
        if r.alerts
        else "alerts: 0"
    )
    groups = group_alerts(r.alerts)
    budget = SUMMARY_LINES - 2 - len(body) - 1  # headline, raw line, the endpoints line
    shown = groups[: max(0, min(r.max_alerts, budget))]
    for g in shown:
        param = f" param={_flat(g.get('param', ''), 30)}" if g.get("param") else ""
        ev = f' ev="{_flat(g.get("evidence", ""), 60)}"' if g.get("evidence") else ""
        n = f" ×{g['count']}" if g["count"] > 1 else ""
        body.append(
            f"[{g.get('risk')}] {_flat(g.get('alert') or g.get('name') or '?', 60)}{n}: "
            f"{_short(str(g.get('url', '')))}{param}{ev}"
        )
    if len(groups) > len(shown):
        body.append(f"... {len(groups) - len(shown)} more alert kinds in raw alerts.json")
    body.append(f"new endpoints: {r.new_endpoints} (endpoints.jsonl, source zap)")
    lines = [head[:LINE_CHARS], *("  " + b[: LINE_CHARS - 2] for b in body)]
    return [*lines[: SUMMARY_LINES - 1], f"raw: {r.raw}/"]


# ------------------------------------------------------------------ ZAP API
class ZapError(RuntimeError):
    pass


class Api:
    """ZAP REST API on 127.0.0.1, never through HTTP(S)_PROXY (the agent's environment points at the gate)."""

    def __init__(self, port: int, key: str) -> None:
        self.base = f"http://127.0.0.1:{port}"
        self.key = key
        self._open = build_opener(ProxyHandler({})).open

    def _get(self, kind: str, path: str, params: dict, timeout: float) -> bytes:
        q = urlencode({k: v for k, v in params.items() if v is not None})
        req = Request(f"{self.base}/{kind}/{path}/?{q}", headers={"X-ZAP-API-Key": self.key})
        try:
            with self._open(req, timeout=timeout) as resp:
                return resp.read()
        except HTTPError as exc:
            detail = exc.read()[:300].decode(errors="replace")
            raise ZapError(f"{path}: HTTP {exc.code} {detail}") from exc
        except (URLError, OSError) as exc:
            raise ZapError(f"{path}: {exc}") from exc

    def json(self, path: str, timeout: float = 30, **params) -> dict:
        try:
            return json.loads(self._get("JSON", path, params, timeout))
        except ValueError as exc:
            raise ZapError(f"{path}: not JSON") from exc

    def other(self, path: str, timeout: float = 60, **params) -> bytes:
        return self._get("OTHER", path, params, timeout)


def _int(v, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


# ------------------------------------------------------------------ run
def run(a: argparse.Namespace, raw: Path, r: Result, origin_: str) -> list[tuple[str, str, list[str], int | None]]:
    """Start ZAP, crawl, scan, collect. Returns the in-scope (method, url, params, status) seen."""
    t0 = time.monotonic()
    deadline = t0 + a.timeout - MARGIN_S
    jar = find_jar()
    if jar is None:
        r.state, r.error = "error rc=127", "ZAP is not installed in this image (rebuild the agent image)"
        return []
    home = raw / "zap-home"
    home.mkdir(parents=True, exist_ok=True)
    port, key = free_port(), secrets.token_hex(16)
    cmd = zap_command(jar, home, port, key, c.gate())
    with open(raw / "cmd.txt", "a") as fh:
        fh.write(redact(cmd, key) + "\n")
    items: list[tuple[str, str, list[str], int | None]] = []
    out = open(raw / "zap.out", "w")  # noqa: SIM115 - closed in finally
    try:
        proc = subprocess.Popen(
            cmd, stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True
        )
    except OSError as exc:
        out.close()
        r.state, r.error = "error rc=127", f"cannot start java: {exc}"
        return []
    _PROCS.append(proc)
    api = Api(port, key)
    try:
        r.version = _wait_ready(api, proc, min(deadline, t0 + 120))
        ctx_id = _configure(api, a, origin_)
        # crawl share of the budget: the rest goes to the passive queue (and to the active scan with --active)
        timed_out = _crawl(api, a, t0 + (deadline - t0) * (0.4 if a.active else 0.85))
        _wait_passive(api, deadline)
        if a.active and time.monotonic() < deadline - 10:
            timed_out = _active(api, a, ctx_id, deadline, r) or timed_out
        elif a.active:
            timed_out = True
        if timed_out:
            r.state = "partial (timeout)"
        items = _collect(api, a, raw, r, origin_)
    except ZapError as exc:
        r.state, r.error = "error rc=1", str(exc)[:220]
        with contextlib.suppress(ZapError):
            items = _collect(api, a, raw, r, origin_)
    finally:
        _stop(api, proc)
        out.close()
        r.seconds = time.monotonic() - t0
    return items


_PROCS: list[subprocess.Popen] = []  # killed by the hard stop


def _wait_ready(api: Api, proc: subprocess.Popen, until: float) -> str:
    while time.monotonic() < until:
        if proc.poll() is not None:
            raise ZapError(f"ZAP exited at start (rc={proc.returncode}, see raw zap.out)")
        with contextlib.suppress(ZapError):
            return str(api.json("core/view/version", timeout=5).get("version", "?"))
        time.sleep(1)
    raise ZapError("ZAP did not answer on its API in time (see raw zap.out)")


def _configure(api: Api, a: argparse.Namespace, origin_: str) -> str:
    ctx = api.json("context/action/newContext", contextName=CONTEXT).get("contextId", "1")
    api.json("context/action/includeInContext", contextName=CONTEXT, regex=context_regex(a.url))
    api.json("context/action/setContextInScope", contextName=CONTEXT, booleanInScope="true")
    api.json("core/action/setMode", mode="protect")  # attacks only on URLs in scope
    if a.identity:  # Replacer: REQ_HEADER adds the header when it is absent
        api.json(
            "replacer/action/addRule",
            description="bh-identity",
            enabled="true",
            matchType="REQ_HEADER",
            matchRegex="false",
            matchString=c.IDENTITY_HEADER,
            replacement=a.identity,
        )
    api.json("spider/action/setOptionThreadCount", Integer=SPIDER_THREADS)
    api.json("spider/action/setOptionPostForm", Boolean="true" if a.active else "false")  # a mapper writes nothing
    if a.active:
        api.json("ascan/action/setOptionThreadPerHost", Integer=ASCAN_THREADS_PER_HOST)
        api.json("ascan/action/setOptionHostPerScan", Integer=1)
        api.json("ascan/action/disableScanners", ids=",".join(DISABLED_RULES))
    return str(ctx)


def _crawl(api: Api, a: argparse.Namespace, until: float) -> bool:
    """Returns True when the crawl was cut by the budget."""
    minutes = max(1, int((until - time.monotonic()) // 60))
    if a.ajax:
        api.json("ajaxSpider/action/setOptionBrowserId", String="chrome-headless")
        api.json("ajaxSpider/action/setOptionNumberOfBrowsers", Integer=1)
        api.json("ajaxSpider/action/setOptionMaxDuration", Integer=minutes)
        for res in api.json("ajaxSpider/view/allowedResources").get("allowedResources", []):  # strict scope only
            regex = res.get("regex") if isinstance(res, dict) else None
            if regex:
                api.json("ajaxSpider/action/removeAllowedResource", regex=regex)
        api.json("ajaxSpider/action/scan", url=a.url, inScope="true", contextName=CONTEXT)
        while time.monotonic() < until:
            if api.json("ajaxSpider/view/status").get("status") != "running":
                return False
            time.sleep(2)
        api.json("ajaxSpider/action/stop")
        return True
    api.json("spider/action/setOptionMaxDuration", Integer=minutes)
    sid = api.json("spider/action/scan", url=a.url, contextName=CONTEXT, recurse="true").get("scan", "0")
    while time.monotonic() < until:
        if _int(api.json("spider/view/status", scanId=sid).get("status")) >= 100:
            return False
        time.sleep(2)
    api.json("spider/action/stop", scanId=sid)
    return True


def _wait_passive(api: Api, until: float) -> None:
    while time.monotonic() < until:
        if _int(api.json("pscan/view/recordsToScan").get("recordsToScan"), 0) == 0:
            return
        time.sleep(1)


def _active(api: Api, a: argparse.Namespace, ctx_id: str, deadline: float, r: Result) -> bool:
    minutes = max(1, int((deadline - time.monotonic()) // 60))
    api.json("ascan/action/setOptionMaxScanDurationInMins", Integer=minutes)
    api.json("ascan/action/setOptionMaxRuleDurationInMins", Integer=max(1, minutes // 3))
    sid = api.json("ascan/action/scan", url=a.url, recurse="true", inScopeOnly="true", contextId=ctx_id).get(
        "scan", "0"
    )
    timed_out = True
    while time.monotonic() < deadline:
        if _int(api.json("ascan/view/status", scanId=sid).get("status")) >= 100:
            timed_out = False
            break
        time.sleep(3)
    if timed_out:
        api.json("ascan/action/stop", scanId=sid)
    for s in api.json("ascan/view/scans").get("scans", []):
        if str(s.get("id")) == str(sid):
            r.ascan_requests = _int(s.get("reqCount"))
    r.ascan_ids = _ascan_message_ids(api, sid)
    return timed_out


def _ascan_message_ids(api: Api, sid: str, limit: int = 3000) -> list[str]:
    ids: list[str] = []
    for item in api.json("ascan/view/messagesIds", scanId=sid).get("messagesIds", [])[:limit]:
        v = item.get("id") if isinstance(item, dict) else item
        if isinstance(v, list):  # some versions answer [[id, ...], ...]
            v = v[0] if v else None
        if v is not None and str(v).isdigit():
            ids.append(str(v))
    return ids


def _collect(api: Api, a: argparse.Namespace, raw: Path, r: Result, origin_: str) -> list:
    alerts: list[dict] = []
    start = 0
    while True:
        page = api.json("alert/view/alerts", baseurl="", start=start, count=500).get("alerts", [])
        alerts += page
        start += len(page)
        if len(page) < 500 or start >= 20000:
            break
    (raw / "alerts.json").write_text(json.dumps(alerts, ensure_ascii=False, indent=1))
    r.alerts = [x for x in alerts if c.origin(str(x.get("url", ""))) == origin_]

    msgs: list[dict] = []
    start = 0
    while True:
        page = api.json("core/view/messages", baseurl="", start=start, count=500).get("messages", [])
        msgs += page
        start += len(page)
        if len(page) < 500 or start >= 20000:
            break
    r.history = len(msgs)
    items = []
    for m in msgs:
        method, url, status, denied, params = parse_message(m)
        r.gate_denied += denied
        if c.origin(url) != origin_:
            r.offsite[c.host_of(url) or "?"] += 1
        elif not denied:
            items.append((method, url, c.query_params(url) + params, status))
    touched: set[tuple[str, str]] = set()
    ids = r.ascan_ids
    for i in range(0, len(ids), 100):
        for m in api.json("core/view/messagesById", ids=",".join(ids[i : i + 100])).get("messages", []):
            method, url, _status, denied, _params = parse_message(m)
            r.gate_denied += denied
            if c.origin(url) == origin_:
                touched.add((method, url.split("?")[0]))
    r.touched = sorted(touched)
    for path, kind in (("exim/other/exportHar", "exim"), ("core/other/messagesHar", "core")):
        try:
            (raw / "messages.har").write_bytes(api.other(path, baseurl=""))
            break
        except ZapError as exc:
            (raw / "har.err").write_text(f"{kind}: {exc}\n")
    return items


def _stop(api: Api, proc: subprocess.Popen) -> None:
    with contextlib.suppress(ZapError):
        api.json("core/action/shutdown", timeout=5)
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        _kill(proc)


def _kill(proc: subprocess.Popen) -> None:
    with contextlib.suppress(OSError):
        os.killpg(proc.pid, signal.SIGKILL)
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=5)


# ------------------------------------------------------------------ CLI
def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    a = parse_args(argv)
    if phase_kind(a) == "scanner" and not c.scanners_allowed():
        sys.exit(f"{c.RULES_MARK} bh-zap --active: this program forbids automated scanners")
    from bh.agent.tools import Job, _add_endpoints

    job = Job("zap", a.url, a.identity, a.timeout)
    (job.raw / "cmd.txt").write_text(shlex.join(["bh-zap", *argv]) + "\n")
    r = Result(url=a.url, identity=a.identity, ajax=a.ajax, active=a.active, max_alerts=a.max_alerts, raw=str(job.raw))

    def hard_stop(_sig, _frm) -> None:  # never past the budget, and never leave a JVM behind
        for p in _PROCS:
            _kill(p)
        print(f"bh-zap {a.url}: killed after {a.timeout + 30} s [error rc=124]\nraw: {job.raw}/", flush=True)
        os._exit(124)

    signal.signal(signal.SIGALRM, hard_stop)
    signal.alarm(a.timeout + 30)
    items = run(a, job.raw, r, job.origin)
    signal.alarm(0)
    r.new_endpoints = _add_endpoints(job, items, "zap")
    d = c.bh_dir()
    c.record_phase(d, job.origin, "zap", status=r.state, count=len(r.alerts), raw=str(job.raw))
    if not r.state.startswith("error"):
        c.record_phase(d, job.origin, "crawl", status=r.state, count=r.new_endpoints, raw=str(job.raw))
        if a.active:
            c.record_phase(d, job.origin, "scan", status=r.state, count=len(r.alerts), raw=str(job.raw))
    for method, url in r.touched:
        c.record_touched(d, [url], via="zap", method=method)
    with open(job.raw / "summary.json", "w") as fh:
        json.dump({"state": r.state, "alerts": dict(risk_counts(r.alerts)), "new": r.new_endpoints}, fh)
    print("\n".join(render(r)))
    if r.state.startswith("error"):
        sys.exit(1)
