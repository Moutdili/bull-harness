"""Builtins: the arsenal behind one compact interface.

Every builtin goes through the gate at the program rate limit, keeps the full tool
output under raw/, prints at most ~30 lines, and records what it covered:

  bh-recon   <domain|url>   subdomains (domains only) + live HTTP probe        httpx, subfinder
  bh-crawl   <url>          crawl + JS endpoint extraction + forms             katana
  bh-content <url>          content discovery, auto-calibrated                 ffuf + seclists
  bh-scan    <url>          template scan, tech-aware, no intrusive templates   nuclei
  bh-params  <url>          hidden parameter discovery                         arjun
  bh-sqli    <url> [--data] SQL injection test, level 1 / risk 1               sqlmap
  bh-xss     <url>          reflected XSS test                                 dalfox

Common options: --as <identity> (authenticated, header injected by the gate),
--timeout <s>. The tool lock (hooks.py) opens an origin once crawl, content and scan ran.
"""

from __future__ import annotations

import argparse
import math
import re
import shlex
import subprocess
import sys
import time
from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from bh.agent import contract as c

NUCLEI_TEMPLATES = Path("/opt/bh/nuclei-templates")
WORDLISTS = Path("/usr/share/seclists/Discovery/Web-Content")
# Never run: noisy, destructive or brute-force templates, and OOB templates (no interactsh through the gate).
NUCLEI_EXCLUDE_TAGS = "dos,fuzz,intrusive,bruteforce,brute-force,default-login,osint,oast,headless"
SUMMARY_LINES = 25
# Quoted absolute paths in JS/HTML, with the HTTP verb when the call site shows it
# (`http.put(base + "/rest/x")`, `axios.post("/api/y")`, `fetch("/z")`).
_JS_PATH = re.compile(
    r"""(?:\.(get|post|put|patch|delete)\s*\([^"'`()]{0,80}?)?["'`](/[A-Za-z0-9_\-./{}:%]*[A-Za-z][A-Za-z0-9_\-./{}:%]*(?:\?[^"'`\s<>]*)?)["'`]""",
    re.I,
)
_NOT_ENDPOINT = re.compile(r"^//|^/[^/]{0,1}$|\s|\.\.|^/(assets|static|fonts|images?|img|media|node_modules)/", re.I)


@dataclass
class Job:
    phase: str
    url: str
    identity: str | None
    timeout: int
    origin: str = ""
    raw: Path = field(default_factory=Path)
    lines: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        o = c.origin(self.url)
        if o is None:
            sys.exit(f"bh-{self.phase}: need an http(s) URL, got {self.url!r}")
        self.origin = o
        slug = re.sub(r"[^A-Za-z0-9.-]+", "_", urlsplit(self.url).netloc + urlsplit(self.url).path)[:60]
        self.raw = c.bh_dir() / c.RAW / f"{self.phase}-{slug}-{int(time.time())}"
        self.raw.mkdir(parents=True, exist_ok=True)

    # -- shared tool plumbing
    def headers(self) -> list[str]:
        return [f"{c.IDENTITY_HEADER}: {self.identity}"] if self.identity else []

    def exec(self, cmd: list[str], stdout: str | None = None, timeout: int | None = None) -> tuple[int, bool]:
        """Run a tool; stdout to raw/<stdout> (or discarded), stderr to raw/<tool>.err. Returns (rc, timed_out)."""
        name = Path(cmd[0]).name
        with open(self.raw / "cmd.txt", "a") as fh:
            fh.write(shlex.join(cmd) + "\n")
        out_cm = open(self.raw / stdout, "w") if stdout else nullcontext(subprocess.DEVNULL)  # noqa: SIM115 - entered below
        with out_cm as out, open(self.raw / f"{name}.err", "w") as err:
            try:
                rc = subprocess.run(
                    cmd, stdout=out, stderr=err, stdin=subprocess.DEVNULL, timeout=timeout or self.timeout
                ).returncode
                return rc, False
            except subprocess.TimeoutExpired:
                return 124, True
            except FileNotFoundError:
                return 127, False

    def last_error(self) -> str:
        for err in sorted(self.raw.glob("*.err")):
            lines = [x for x in err.read_text(errors="replace").splitlines() if x.strip()]
            if lines:
                return lines[-1][:300]
        return ""

    def finish(self, count: int, rc: int, timed_out: bool, headline: str) -> None:
        status = "partial (timeout)" if timed_out else ("ok" if rc == 0 else f"error rc={rc}")
        c.record_phase(c.bh_dir(), self.origin, self.phase, status=status, count=count, raw=str(self.raw))
        print(f"bh-{self.phase} {self.url}: {headline} [{status}]")
        if status.startswith("error") and (why := self.last_error()):
            print(f"  stderr: {why}")
        for line in self.lines[:SUMMARY_LINES]:
            print("  " + line)
        if len(self.lines) > SUMMARY_LINES:
            print(f"  ... {len(self.lines) - SUMMARY_LINES} more")
        print(f"raw: {self.raw}/")


def _rate_int() -> int:
    return max(1, math.floor(c.rps()))


def _flag_pairs(flag: str, values: list[str]) -> list[str]:
    return [x for v in values for x in (flag, v)]


def _add_endpoints(job: Job, items: list[tuple[str, str, list[str], int | None]], source: str) -> int:
    """items: (method, url, params, status). Dedup on (origin, key); returns the number of new endpoints."""
    d = c.bh_dir()
    known = {(e.get("origin"), e.get("key")) for e in c.read_jsonl(d / c.ENDPOINTS)}
    recs = []
    for method, url, params, status in items:
        k = c.endpoint_key(url, method)
        if k and k[0] == job.origin and k not in known and not c.STATIC_EXT.search(k[1]):
            known.add(k)
            recs.append(
                {
                    "origin": k[0],
                    "key": k[1],
                    "url": url,
                    "params": sorted(set(params)),
                    "status": status,
                    "source": source,
                }
            )
    if recs:
        c.append_jsonl(d / c.ENDPOINTS, *recs)
    return len(recs)


# ------------------------------------------------------------------ builtins
def recon(job: Job, target: str) -> None:
    hosts = job.raw / "hosts.txt"
    if "://" in target:
        hosts.write_text(target + "\n")
        rc_s = 0
    else:
        rc_s, _ = job.exec(
            ["subfinder", "-d", target, "-silent", "-all", "-proxy", c.gate(), "-timeout", "20"], stdout="subs.txt"
        )
        subs = (job.raw / "subs.txt").read_text().split() if (job.raw / "subs.txt").exists() else []
        hosts.write_text("\n".join(sorted({target, *subs})) + "\n")
    rc, to = job.exec(
        [
            "httpx-toolkit",
            "-l",
            str(hosts),
            "-silent",
            "-json",
            "-http-proxy",
            c.gate(),
            "-nfs",
            "-rl",
            str(_rate_int()),
            "-t",
            "5",
            "-timeout",
            "10",
            "-title",
            "-status-code",
            "-tech-detect",
            "-web-server",
            "-follow-redirects",
            "-no-color",
            *_flag_pairs("-H", job.headers()),
        ],
        stdout="httpx.jsonl",
    )
    live = c.read_jsonl(job.raw / "httpx.jsonl")
    for h in sorted(live, key=lambda x: (x.get("status_code", 0), x.get("url", ""))):
        tech = ",".join(h.get("tech") or [])[:60]
        job.lines.append(f"{h.get('status_code')} {h.get('url')}  {(h.get('title') or '')[:50]}  {tech}")
        if o := c.origin(h.get("url", "")):
            c.record_phase(c.bh_dir(), o, "recon", status="ok", count=1, raw=str(job.raw))
    n_names = len(hosts.read_text().split())
    job.finish(len(live), rc or rc_s, to, f"{n_names} names, {len(live)} live HTTP services")


def js_paths(text: str) -> list[tuple[str, str]]:
    """(METHOD, path) pairs quoted in JS/HTML. Static assets and protocol-relative URLs are dropped."""
    out = []
    for verb, path in _JS_PATH.findall(text):
        if not _NOT_ENDPOINT.search(path) and not c.STATIC_EXT.search(path.split("?")[0]):
            out.append(((verb or "GET").upper(), path))
    return out


def crawl(job: Job) -> None:
    resp_dir = job.raw / "responses"
    rc, to = job.exec(
        [
            "katana",
            "-u",
            job.url,
            "-proxy",
            c.gate(),
            "-rl",
            str(_rate_int()),
            "-c",
            "5",
            "-p",
            "2",
            "-d",
            "3",
            "-kf",
            "all",
            "-fx",
            "-fs",
            "fqdn",
            "-iqp",
            "-ef",
            "png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot,css,mp4,webm",
            "-ct",
            f"{max(30, job.timeout - 20)}s",
            "-jsonl",
            "-silent",
            "-nc",
            "-duc",
            "-sr",
            "-srd",
            str(resp_dir),
            *_flag_pairs("-H", job.headers()),
        ],
        stdout="katana.jsonl",
    )
    items = []
    for r in c.read_jsonl(job.raw / "katana.jsonl"):
        req, resp = r.get("request") or {}, r.get("response") or {}
        url = req.get("endpoint") or ""
        items.append((req.get("method") or "GET", url, c.query_params(url), resp.get("status_code")))
        for form in resp.get("forms") or []:
            action = form.get("action") or url
            items.append(((form.get("method") or "GET").upper(), action, form.get("parameters") or [], None))
    js = []
    for f in resp_dir.rglob("*.txt") if resp_dir.is_dir() else []:
        if f.name != "index.txt":
            js += [(m, job.origin + p, c.query_params(p), None) for m, p in js_paths(f.read_text(errors="replace"))]
    new = _add_endpoints(job, items, "crawl") + _add_endpoints(job, js, "js")
    eps = [e for e in c.read_jsonl(c.bh_dir() / c.ENDPOINTS) if e.get("origin") == job.origin]
    for e in sorted(eps, key=lambda e: (not e.get("params"), e["key"]))[:SUMMARY_LINES]:
        params = f" ?{','.join(e['params'])}" if e.get("params") else ""
        job.lines.append(f"{e['key']}{params}")
    job.finish(
        new,
        rc,
        to,
        f"{len(items)} URLs crawled, {len(js)} paths quoted in JS/HTML, {new} new endpoints "
        f"({len(eps)} known on this origin)",
    )


def content(job: Job, wordlist: str | None) -> None:
    wl = Path(wordlist) if wordlist else WORDLISTS / ("common.txt" if c.rps() >= 10 else "quickhits.txt")
    base = job.url.rstrip("/")
    rc, to = job.exec(
        [
            "ffuf",
            "-u",
            f"{base}/FUZZ",
            "-w",
            str(wl),
            "-x",
            c.gate(),
            "-rate",
            str(_rate_int()),
            "-t",
            "5",
            "-ac",
            "-maxtime",
            str(max(30, job.timeout - 15)),
            "-timeout",
            "10",
            "-of",
            "json",
            "-o",
            str(job.raw / "ffuf.json"),
            "-s",
            "-noninteractive",
            *_flag_pairs("-H", job.headers()),
        ]
    )
    results = (c.read_json(job.raw / "ffuf.json", {}) or {}).get("results") or []
    items = [("GET", r.get("url", ""), [], r.get("status")) for r in results]
    new = _add_endpoints(job, items, "content")
    for r in sorted(results, key=lambda r: (r.get("status", 0), r.get("url", "")))[:SUMMARY_LINES]:
        job.lines.append(f"{r.get('status')} {r.get('length', '?'):>7}B  {urlsplit(r.get('url', '')).path}")
    job.finish(len(results), rc, to, f"{len(results)} paths found with {wl.name}, {new} new endpoints")


def scan(job: Job, deep: bool) -> None:
    """Pass 1: templates matching the detected tech (-as). Pass 2: generic misconfigurations
    (high+), or with --deep exposures + misconfigurations (medium+, ~4.7k requests)."""
    if not NUCLEI_TEMPLATES.is_dir():
        sys.exit(f"bh-scan: nuclei templates missing at {NUCLEI_TEMPLATES} (mount var/tools/nuclei-templates)")
    common = [
        "-u",
        job.url,
        "-ud",
        str(NUCLEI_TEMPLATES),
        "-etags",
        NUCLEI_EXCLUDE_TAGS,
        "-proxy",
        c.gate(),
        "-rl",
        str(_rate_int()),
        "-c",
        "10",
        "-bs",
        "10",
        "-timeout",
        "7",
        "-mhe",
        "30",
        "-duc",
        "-ni",
        "-nc",
        "-silent",
        "-omit-raw",
        *_flag_pairs("-H", job.headers()),
    ]
    generic = (
        ["-t", str(NUCLEI_TEMPLATES / "http/exposures"), "-severity", "medium,high,critical"]
        if deep
        else ["-severity", "high,critical"]
    ) + ["-t", str(NUCLEI_TEMPLATES / "http/misconfiguration")]
    half = max(30, job.timeout // 2)
    rc1, to1 = job.exec(["nuclei", *common, "-as", "-jsonl", "-o", str(job.raw / "tech.jsonl")], timeout=half)
    rc2, to2 = job.exec(
        ["nuclei", *common, *generic, "-jsonl", "-o", str(job.raw / "generic.jsonl")], timeout=job.timeout - half
    )
    hits = c.read_jsonl(job.raw / "tech.jsonl") + c.read_jsonl(job.raw / "generic.jsonl")
    order = {s: i for i, s in enumerate(c.SEVERITIES)}
    for h in sorted(hits, key=lambda h: order.get((h.get("info") or {}).get("severity"), 9)):
        info = h.get("info") or {}
        extra = ",".join(h.get("extracted-results") or [])[:60]
        job.lines.append(
            f"[{info.get('severity')}] {h.get('template-id')}  {h.get('matched-at')}" + (f"  {extra}" if extra else "")
        )
    job.finish(
        len(hits),
        rc1 or rc2,
        to1 or to2,
        f"{len(hits)} template matches{' (deep)' if deep else ''}; triage them, info hits are rarely findings",
    )


def params(job: Job) -> None:
    out = job.raw / "arjun.json"
    rc, to = job.exec(
        [
            "arjun",
            "-u",
            job.url,
            "-oJ",
            str(out),
            "-t",
            "5",
            "-d",
            f"{1 / c.rps():.2f}",
            "-T",
            "10",
            "-q",
            *(["--headers", "\n".join(job.headers())] if job.identity else []),
        ]
    )
    found = {u: (v or {}).get("params") or [] for u, v in (c.read_json(out, {}) or {}).items()}
    for u, ps in found.items():
        job.lines.append(f"{u}  params: {', '.join(ps)}")
    _add_endpoints(job, [("GET", u, ps, None) for u, ps in found.items()], "params")
    c.record_touched(c.bh_dir(), [job.url], via="params")
    n = sum(len(p) for p in found.values())
    job.finish(n, rc, to, f"{n} hidden parameters")


def sqli(job: Job, data: str | None, param: str | None, level: int, technique: str) -> None:
    """Risk pinned to 1, techniques Boolean/Error/Union by default: time-based heavy queries stall the
    target (measured on Juice Shop: every request timed out) and stacked queries can write.
    Without -p only the URL/body parameters are tested, so level 3 adds boundaries (e.g. `'))`)
    without fuzzing every header."""
    if not param:
        names = c.query_params(job.url) + (
            sorted(set(re.findall(r'(?:^|[&{,]\s*"?)([A-Za-z0-9_.-]+)"?\s*[=:]', data))) if data else []
        )
        param = ",".join(dict.fromkeys(names)) or None
    cmd = [
        "sqlmap",
        "-u",
        job.url,
        "--batch",
        "--level",
        str(level),
        "--risk",
        "1",
        "--threads",
        "1",
        "--technique",
        technique,
        "--proxy",
        c.gate(),
        "--delay",
        f"{1 / c.rps():.2f}",
        "--timeout",
        "10",
        "--retries",
        "1",
        "--output-dir",
        str(job.raw / "out"),
        "--disable-coloring",
    ]
    cmd += (["--data", data] if data else []) + (["-p", param] if param else [])
    cmd += ["--headers", "\n".join(job.headers())] if job.identity else []
    rc, to = job.exec(cmd, stdout="sqlmap.log")
    log = (job.raw / "sqlmap.log").read_text(errors="replace") if (job.raw / "sqlmap.log").exists() else ""
    points = re.findall(r"Parameter: (.+?) \((\w+)\)\s*\n((?:\s+(?:Type|Title|Payload): .*\n)+)", log)
    for name, place, details in points:
        job.lines.append(f"INJECTABLE {place} parameter '{name}'")
        job.lines += [
            "    " + x.strip() for x in details.strip().splitlines() if x.strip().startswith(("Type", "Payload"))
        ][:6]
    if not points:
        job.lines += [
            x.strip()
            for x in log.splitlines()
            if re.search(r"(not injectable|does not seem|WAF|CRITICAL|might be injectable)", x)
        ][-6:]
    c.record_touched(c.bh_dir(), [job.url], via="sqli", method="POST" if data else "GET")
    job.finish(len(points), rc, to, f"{len(points)} injection point(s)")


def xss(job: Job) -> None:
    """dalfox 3.x (Rust): `dalfox scan URL`."""
    out = job.raw / "dalfox.json"
    rc, to = job.exec(
        [
            "dalfox",
            "scan",
            job.url,
            "--proxy",
            c.gate(),
            "--rate-limit",
            str(_rate_int()),
            "--workers",
            "5",
            "--timeout",
            "10",
            "--scan-timeout",
            str(max(30, job.timeout - 10)),
            "-S",
            "--no-color",
            "-f",
            "json",
            "-o",
            str(out),
            *_flag_pairs("-H", job.headers()),
        ]
    )
    data = c.read_json(out, [])
    pocs = (
        data
        if isinstance(data, list)
        else (data.get("findings") or data.get("results") or [])
        if isinstance(data, dict)
        else []
    )
    pocs = [p for p in pocs if isinstance(p, dict)]
    for p in pocs:
        job.lines.append(
            f"[{p.get('type', '?')}] param={p.get('param')} "
            f"{(p.get('data') or p.get('poc') or p.get('payload') or '')[:150]}"
        )
    c.record_touched(c.bh_dir(), [job.url], via="xss")
    job.finish(len(pocs), rc, to, f"{len(pocs)} XSS PoC(s) (V = verified in DOM, R = reflected)")


# ------------------------------------------------------------------ CLI
DEFAULT_TIMEOUT = {"recon": 240, "crawl": 240, "content": 270, "scan": 280, "params": 240, "sqli": 280, "xss": 240}


def main(phase: str, argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog=f"bh-{phase}", description=__doc__.split("\n\n")[0])
    p.add_argument("target", help="URL (or a bare domain for bh-recon)")
    p.add_argument("--as", dest="identity", help="identity name, sent as X-BH-Identity")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT[phase], help="seconds")
    if phase == "content":
        p.add_argument("--wordlist")
    if phase == "scan":
        p.add_argument("--deep", action="store_true", help="also exposures + medium misconfigs (slow)")
    if phase == "sqli":
        p.add_argument("--data", help="POST body, e.g. 'email=a&password=b' or JSON")
        p.add_argument("-p", "--param", help="parameters to test (default: those of the URL/body)")
        p.add_argument("--level", type=int, default=3, choices=[1, 2, 3])
        p.add_argument("--technique", default="BEU", help="sqlmap techniques (default BEU: no time-based, no stacked)")
    a = p.parse_args(argv)
    url = a.target if "://" in a.target else f"https://{a.target}"
    job = Job(phase, url, a.identity, a.timeout)
    match phase:
        case "recon":
            recon(job, a.target)
        case "crawl":
            crawl(job)
        case "content":
            content(job, a.wordlist)
        case "scan":
            scan(job, a.deep)
        case "params":
            params(job)
        case "sqli":
            sqli(job, a.data, a.param, a.level, a.technique)
        case "xss":
            xss(job)
