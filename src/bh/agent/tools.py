"""Builtins: the arsenal behind one compact interface.

Every builtin goes through the gate at the program rate limit, keeps the full tool
output under raw/, prints at most ~30 lines, and records what it covered:

  bh-recon   <domain|url>   subdomains (domains only) + live HTTP probe        httpx, subfinder
                            + archived URLs of the in-scope hosts, gf classes   gau + gf patterns
  bh-crawl   <url>          crawl + JS endpoint extraction + forms             katana
  bh-content <url>          content discovery, auto-calibrated                 ffuf + seclists
  bh-scan    <url>          template scan, tech-aware, no intrusive templates   nuclei
  bh-params  <url>          hidden parameter discovery                         arjun
  bh-sqli    <url> [--data] SQL injection test, level 3 / risk 1, BEU only     sqlmap
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
import shutil
import sys
import threading
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
# Archive step of bh-recon (gau 2.2.4). Only the providers the gate lets through as passive sources (contract
# PASSIVE_HOSTS): wayback = web.archive.org/cdx, otx = otx.alienvault.com, urlscan = urlscan.io/api/v1/search.
# commoncrawl is left out: gau 2.2.4 reads its index list from http://index.commoncrawl.org/collinfo.json
# (pkg/providers/commoncrawl/commoncrawl.go), a CONNECT to port 80 the gate refuses (passive is 443 only).
# gau only queries these indexes; nothing here ever fetches an archived page.
ARCHIVE_PROVIDERS = ("wayback", "otx", "urlscan")
ARCHIVE_MAX_URLS = 10_000
ARCHIVE_TIMEOUT = 120
ARCHIVE_BLACKLIST = "png,jpg,jpeg,gif,svg,ico,webp,woff,woff2,ttf,eot,otf,css,mp4,webm,mp3,pdf"
# gf patterns (tomnomnom/gf examples + 1ndianl33t/Gf-Patterns, pinned in the Containerfile): JSON files with
# grep flags and regexes. Applied here the way `gf <name>` does: (p1|p2|...), case-insensitive with -i.
GF_DIR = Path("/opt/bh/gf")
GF_CLASSES = ("sqli", "xss", "ssrf", "redirect", "idor", "lfi", "rce", "ssti")
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


def _safe_technique(value: str) -> str:
    """sqlmap techniques allowed on a bug bounty target: Boolean, Error, Union. Time-based heavy
    queries stall targets (measured on Juice Shop), stacked queries can write."""
    v = value.upper()
    if not v or set(v) - set("BEU"):
        raise argparse.ArgumentTypeError("only B, E and U are allowed")
    return v


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


# ------------------------------------------------------------------ archive (bh-recon)
# A scope rule as the sandbox sees it: (kind, host pattern, scheme, port, path prefix). The gate decides with
# bh.scope; this local copy only keeps what gets recorded in scope (out of scope always wins, CIDR/repo ignored).
ScopeRule = tuple[str, str, str | None, int | None, str | None]


def _rule(entry: object) -> ScopeRule | None:
    if isinstance(entry, dict):
        value, kind = str(entry.get("value", "")).strip(), entry.get("type")
    else:
        value, kind = str(entry).strip(), None
    if not value:
        return None
    if kind is None:
        kind = (
            "url"
            if "://" in value
            else "wildcard"
            if "*" in value and "/" not in value
            else "cidr"
            if "/" in value or re.fullmatch(r"[0-9.]+|[0-9a-fA-F:]*:[0-9a-fA-F:.]*", value)
            else "domain"
        )
    if kind in ("domain", "wildcard"):
        return kind, value.lower().rstrip("."), None, None, None
    if kind == "url":
        try:
            p = urlsplit(value)
            port = p.port
        except ValueError:
            return None
        if not p.hostname:
            return None
        port = port or (443 if p.scheme == "https" else 80)
        return "url", p.hostname.lower(), p.scheme.lower(), port, p.path or "/"
    return None


def scope_rules(path: Path) -> tuple[list[ScopeRule], list[ScopeRule]] | None:
    """(in, out) web rules of the scope.yaml the runner pushes to BH_DIR; None if absent or unreadable."""
    import yaml  # python3-yaml in the image

    try:
        doc = yaml.safe_load(path.read_text())
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("in_scope"), list):
        return None

    def rules(key: str) -> list[ScopeRule]:
        return [r for e in doc.get(key) or [] if (r := _rule(e))]

    return rules("in_scope"), rules("out_of_scope")


def _host_matches(pattern: str, host: str) -> bool:
    """Same reading as bh.scope.enforce: `*.x` = subdomains of x (not x), `api-*.x` = one label, else exact."""
    if pattern.startswith("*."):
        return host.endswith("." + pattern[2:])
    if "*" in pattern:
        label, _, rest = pattern.partition(".")
        h_label, _, h_rest = host.partition(".")
        head, _, tail = label.partition("*")
        return h_rest == rest and re.fullmatch(re.escape(head) + "[a-z0-9-]+" + re.escape(tail), h_label) is not None
    return host == pattern


def _rule_hits(rule: ScopeRule, url: str, *, out: bool) -> bool:
    kind, pattern, scheme, port, prefix = rule
    try:
        p = urlsplit(url)
        host, u_port = (p.hostname or "").lower(), p.port or (443 if p.scheme == "https" else 80)
    except ValueError:
        return False
    if not host or not _host_matches(pattern, host):
        return False
    if kind != "url":
        return True
    path, base = p.path or "/", (prefix or "/").rstrip("/")
    if out:  # wide on purpose, like enforce._path_hits_exclusion: any scheme/port, /x also bans /x.json, /x;y
        pl, bl = path.lower(), base.lower()
        return bl == "" or pl == bl or (pl.startswith(bl) and pl[len(bl)] in "/;.%")
    return p.scheme == scheme and u_port == port and (base == "" or path == base or path.startswith(base + "/"))


def in_scope(url: str, rules: tuple[list[ScopeRule], list[ScopeRule]] | None, domain: str) -> bool:
    """An archived URL is kept when the scope covers it (out of scope wins). Without a scope file, only the
    queried domain and its subdomains are kept."""
    if c.origin(url) is None:
        return False
    if rules is None:
        host = c.host_of(url)
        return host == domain or host.endswith("." + domain)
    ins, outs = rules
    return not any(_rule_hits(r, url, out=True) for r in outs) and any(_rule_hits(r, url, out=False) for r in ins)


def archive_query(target: str, rules: tuple[list[ScopeRule], list[ScopeRule]] | None) -> tuple[str, bool] | None:
    """(domain to ask the archives for, include subdomains), None when the scope covers nothing under it.
    A URL target asks for its host only; a bare domain also for its subdomains when a wildcard reaches them."""
    host = c.host_of(target) if "://" in target else target.lower().strip().rstrip(".")
    if not host or c.is_passive(host):
        return None
    if "://" in target:
        return (host, False) if rules is None or any(_host_matches(r[1], host) for r in rules[0]) else None
    if rules is None:
        return host, True
    patterns = [r[1] for r in rules[0]]

    def base(p: str) -> str:  # *.x.com -> x.com, api-*.x.com -> x.com, a.x.com -> a.x.com
        return p[2:] if p.startswith("*.") else p.partition(".")[2] if "*" in p else p

    covered = any(_host_matches(p, host) for p in patterns)
    # subdomains are worth asking for when a rule names something under the domain (*.x, api-*.x, a.x,
    # https://a.x/) or a wildcard above it covers its subdomains too
    subs = any(
        (base(p) == host and p != host)
        or base(p).endswith("." + host)
        or (p.startswith("*.") and host.endswith("." + base(p)))
        for p in patterns
    )
    if not (covered or subs):
        return None
    return host, subs


def gf_patterns(names: tuple[str, ...] = GF_CLASSES, directory: Path | None = None) -> dict[str, re.Pattern]:
    """name -> compiled gf pattern; a missing or malformed file is skipped (gf prints and skips it too)."""
    out = {}
    for name in names:
        doc = c.read_json((directory or GF_DIR) / f"{name}.json", None)
        if not isinstance(doc, dict):
            continue
        pattern = doc.get("pattern") or (
            "(" + "|".join(doc["patterns"]) + ")" if isinstance(doc.get("patterns"), list) and doc["patterns"] else ""
        )
        if not pattern:
            continue
        try:
            out[name] = re.compile(pattern, re.I if "i" in str(doc.get("flags", "")) else 0)
        except re.error:
            continue
    return out


def gf_classify(urls: list[str], patterns: dict[str, re.Pattern]) -> dict[str, list[str]]:
    """URLs with a query string matched by each gf pattern (one URL may land in several classes)."""
    with_params = [u for u in urls if c.query_params(u)]
    return {name: [u for u in with_params if rx.search(u)] for name, rx in patterns.items()}


def _stream(job: Job, cmd: list[str], stdout: str, max_lines: int, timeout: int) -> tuple[list[str], int, bool, bool]:
    """Run a tool and read its stdout line by line into raw/<stdout>, killing it after `max_lines` lines or
    `timeout` seconds. Returns (lines, rc, timed_out, capped)."""
    name = Path(cmd[0]).name
    with open(job.raw / "cmd.txt", "a") as fh:
        fh.write(shlex.join(cmd) + "\n")
    lines: list[str] = []
    fired: list[bool] = []

    def expire(proc: subprocess.Popen) -> None:
        fired.append(True)
        proc.kill()

    with open(job.raw / stdout, "w") as out, open(job.raw / f"{name}.err", "w") as err:
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=err, stdin=subprocess.DEVNULL, text=True, errors="replace"
            )
        except FileNotFoundError:
            return [], 127, False, False
        timer = threading.Timer(timeout, expire, (proc,))
        timer.start()
        capped = False
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                if not (line := line.strip()):
                    continue
                out.write(line + "\n")
                lines.append(line)
                if len(lines) >= max_lines:
                    capped = True
                    proc.kill()
                    break
        finally:
            timer.cancel()
            if proc.stdout:
                proc.stdout.close()
            rc = proc.wait()
    return lines, (0 if capped else rc), bool(fired) and not capped, capped


def _add_archive_endpoints(urls: list[str]) -> tuple[int, int, dict[str, int]]:
    """Archived URLs -> endpoints.jsonl (source `archive`), one per route family and origin, parameters merged
    over all the URLs of the family. Returns (families, new endpoints, new endpoints per origin)."""
    d = c.bh_dir()
    known = {(e.get("origin"), c.family(e.get("key", ""))) for e in c.read_jsonl(d / c.ENDPOINTS)}
    fams: dict[tuple[str, str], dict] = {}
    for url in urls:
        k = c.endpoint_key(url)
        if not k or c.STATIC_EXT.search(k[1].split(" ", 1)[-1]):
            continue
        rec = fams.setdefault((k[0], c.family(k[1])), {"origin": k[0], "key": k[1], "url": url, "params": set()})
        rec["params"].update(c.query_params(url))
    recs, per_origin = [], {}
    for fk, rec in fams.items():
        if fk in known:
            continue
        recs.append({**rec, "params": sorted(rec["params"]), "status": None, "source": "archive"})
        per_origin[rec["origin"]] = per_origin.get(rec["origin"], 0) + 1
    if recs:
        c.append_jsonl(d / c.ENDPOINTS, *recs)
    return len(fams), len(recs), per_origin


def archive(job: Job, target: str, max_urls: int = ARCHIVE_MAX_URLS, timeout: int = ARCHIVE_TIMEOUT) -> list[str]:
    """Historical URLs of the target from passive archives (gau), kept when in scope, recorded per route family,
    classed by gf. Returns the summary lines (put first in the bh-recon summary)."""
    gau = shutil.which("gau")
    if not gau:
        return ["archive: skipped, gau is not installed in this sandbox (image built before issue 32?)"]
    rules = scope_rules(c.bh_dir() / c.SCOPE)
    query = archive_query(target, rules)
    if query is None:
        return [f"archive: skipped, {target} is not covered by the scope (or is a passive source)"]
    domain, subs = query
    conf = job.raw / "gau.toml"
    # Own config file: ~/.gau.toml (which could point urlscan/otx at another host) is never read.
    conf.write_text(
        'threads = 1\nretries = 2\nsubdomains = {}\nproviders = [{}]\n[urlscan]\n  apikey = ""\n'.format(
            str(subs).lower(), ", ".join(f'"{p}"' for p in ARCHIVE_PROVIDERS)
        )
    )
    # gau's HTTP client (fasthttp) ignores HTTP(S)_PROXY: the gate is given explicitly (CONNECT, port 443).
    cmd = [
        gau,
        "--config",
        str(conf),
        "--providers",
        ",".join(ARCHIVE_PROVIDERS),
        "--proxy",
        c.gate(),
        "--threads",
        "1",
        "--retries",
        "2",
        "--timeout",
        "30",
        "--blacklist",
        ARCHIVE_BLACKLIST,
        *(["--subs"] if subs else []),
        domain,
    ]
    urls, rc, timed_out, capped = _stream(job, cmd, "gau.txt", max_urls, min(timeout, job.timeout))
    kept = sorted({u for u in urls if in_scope(u, rules, domain)})
    (job.raw / "archive-inscope.txt").write_text("".join(u + "\n" for u in kept))
    fams, new, per_origin = _add_archive_endpoints(kept)
    for o, n in per_origin.items():
        c.record_phase(c.bh_dir(), o, "archive", status="ok", count=n, raw=str(job.raw))
    state = " (cut at --max-urls)" if capped else " (timeout, partial)" if timed_out else f" (rc={rc})" if rc else ""
    lines = [
        f"archive: {len(urls)} URLs from {'+'.join(ARCHIVE_PROVIDERS)} for {'*.' if subs else ''}{domain}{state}, "
        f"{len(kept)} in scope, {fams} route families, {new} new endpoints (source archive)"
    ]
    err = [x for x in (job.raw / "gau.err").read_text(errors="replace").splitlines() if x.strip()]
    if not urls and err:
        lines.append(f"archive: gau stderr: {err[-1][:200]}")
    patterns = gf_patterns()
    if not patterns:
        lines.append(f"archive: gf patterns missing at {GF_DIR}, no classification")
        return lines
    classes = gf_classify(kept, patterns)
    for name, hits in classes.items():
        (job.raw / f"gf-{name}.txt").write_text("".join(u + "\n" for u in hits))
    n_params = sum(1 for u in kept if c.query_params(u))
    lines.append(f"gf ({n_params} URLs with params): " + " ".join(f"{n}={len(h)}" for n, h in classes.items()))
    return lines


# ------------------------------------------------------------------ builtins
def recon(job: Job, target: str, max_urls: int = ARCHIVE_MAX_URLS, use_archive: bool = True) -> None:
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
    if use_archive:
        job.lines += archive(job, target, max_urls)
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
    if phase == "recon":
        p.add_argument(
            "--max-urls", type=int, default=ARCHIVE_MAX_URLS, help="archived URLs read at most (gau is stopped there)"
        )
        p.add_argument("--no-archive", action="store_true", help="skip the archived URLs step (gau + gf)")
    if phase == "content":
        p.add_argument("--wordlist")
    if phase == "scan":
        p.add_argument("--deep", action="store_true", help="also exposures + medium misconfigs (slow)")
    if phase == "sqli":
        p.add_argument("--data", help="POST body, e.g. 'email=a&password=b' or JSON")
        p.add_argument("-p", "--param", help="parameters to test (default: those of the URL/body)")
        p.add_argument("--level", type=int, default=3, choices=[1, 2, 3])
        p.add_argument(
            "--technique",
            default="BEU",
            type=_safe_technique,
            help="subset of B, E, U (time-based and stacked queries are never allowed)",
        )
    a = p.parse_args(argv)
    if not c.scanners_allowed() and phase not in c.LIGHT_PHASES:
        sys.exit(f"{c.RULES_MARK} bh-{phase}: this program forbids automated scanners")
    url = a.target if "://" in a.target else f"https://{a.target}"
    job = Job(phase, url, a.identity, a.timeout)
    match phase:
        case "recon":
            recon(job, a.target, max(1, a.max_urls), not a.no_archive)
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
