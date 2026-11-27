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

Every summary ends with `next: <one action>`, written by the harness (T39). A failure prints
`[bh-fail] <class>: <action>` (bh.agent.fail, T36) and writes no endpoint, no lead and no tested route; a tool killed
at its time budget keeps what it found (`partial: true`), its routes are not marked tested and its phase is not done
(T37). bh-content and bh-sqli read the technology bh-recon (httpx) and bh-crawl (katana) recorded for the origin: the
extensions to try, the DBMS to test (T44); none known, the defaults.
"""

from __future__ import annotations

import argparse
import json
import math
import os
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
from bh.agent import fail

NUCLEI_TEMPLATES = Path("/opt/bh/nuclei-templates")
WORDLISTS = Path("/usr/share/seclists/Discovery/Web-Content")
# Never run: noisy, destructive or brute-force templates, and OOB templates (no interactsh through the gate).
# T42: a login form on an origin's home page (after redirects): a password input. httpx -er puts the matches in
# `extracts`; bh-recon writes `login_form` in endpoints.jsonl, the host believes it where the gate saw the origin.
LOGIN_FORM_RE = r"""<input[^>]{0,200}type=["']?password"""
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
# contract.phase_done counts every status but those that start with "error": a partial run is not a done phase
PARTIAL_STATUS = "error: partial (timeout)"
# T44: technology (as httpx / katana name it, matched as a word) -> what to try. Observed values only: an extension
# for the framework the origin runs, a DBMS only when a database itself was named.
TECH_EXT = (
    ("php", ".php"),
    ("asp.net", ".aspx"),
    ("iis", ".aspx"),
    ("coldfusion", ".cfm"),
    ("tomcat", ".jsp"),
    ("jsp", ".jsp"),
    ("java", ".jsp"),
    ("jboss", ".jsp"),
    ("perl", ".pl"),
)
TECH_EXT_MAX = 2  # each extension multiplies the wordlist's requests
TECH_DBMS = (
    ("mysql", "MySQL"),
    ("mariadb", "MySQL"),
    ("postgresql", "PostgreSQL"),
    ("microsoft sql server", "Microsoft SQL Server"),
    ("mssql", "Microsoft SQL Server"),
    ("oracle database", "Oracle"),
    ("sqlite", "SQLite"),
)
TECH_READ_LINES = 300  # katana.jsonl lines read per file for its response headers


@dataclass
class Job:
    phase: str
    url: str
    identity: str | None
    timeout: int
    origin: str = ""
    raw: Path = field(default_factory=Path)
    lines: list[str] = field(default_factory=list)
    rc: int = 0  # the first non-zero exit of its tools
    timed_out: bool = False
    fail: str | None = None  # the class of the first failure (bh.agent.fail)

    def __post_init__(self) -> None:
        o = c.origin(self.url)
        if o is None:
            sys.exit(fail.line("bad-argument", f"bh-{self.phase} needs an http(s) URL, got {self.url[:200]!r}"))
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
                rc, to = 124, True
            except FileNotFoundError:
                rc, to = 127, False
        self.note(rc, to, name)
        return rc, to

    def note(self, rc: int, timed_out: bool, tool: str | None = None) -> None:
        """Keep the first failure of the job's tools: its exit, its class (from that tool's stderr)."""
        self.timed_out = self.timed_out or timed_out
        if rc and not self.rc:
            self.rc = rc
        if (rc or timed_out) and self.fail is None:
            err = self.raw / f"{tool}.err" if tool else None
            text = err.read_text(errors="replace")[-4000:] if err is not None and err.is_file() else self.last_error()
            self.fail = fail.classify(rc, text, timed_out)

    @property
    def state(self) -> str:
        """ok, partial (killed at its time budget: what it found is kept, not counted) or error."""
        return "partial" if self.timed_out else "error" if self.rc else "ok"

    def last_error(self) -> str:
        for err in sorted(self.raw.glob("*.err")):
            lines = [x for x in err.read_text(errors="replace").splitlines() if x.strip()]
            if lines:
                return lines[-1][:300]
        return ""

    def finish(
        self,
        count: int,
        rc: int,
        timed_out: bool,
        headline: str,
        next_step: str = "",
        coverage: str = "",
        tail: str = "",
    ) -> None:
        """The summary: headline, at most SUMMARY_LINES lines, raw, the failure line, `coverage` (a builtin's
        `N routes in, N tested, missing: ...`) and last `next: <one action>` (then `; <tail>` when given)."""
        self.note(rc, timed_out)
        state = self.state
        status = {"ok": "ok", "partial": "partial (timeout)", "error": f"error rc={self.rc}"}[state]
        recorded = PARTIAL_STATUS if state == "partial" else status
        c.record_phase(c.bh_dir(), self.origin, self.phase, status=recorded, count=count, raw=str(self.raw))
        print(f"bh-{self.phase} {self.url}: {headline} [{status}]")
        if state == "partial":
            print("partial: true (killed at its time budget: what it found so far is below; not counted as done)")
        if state == "error" and (why := self.last_error()):
            print(f"  stderr: {why}")
        for line in self.lines[:SUMMARY_LINES]:
            print("  " + line)
        if len(self.lines) > SUMMARY_LINES:
            print(f"  ... {len(self.lines) - SUMMARY_LINES} more")
        print(f"raw: {self.raw}/")
        if state != "ok":
            print(fail.line(self.fail or "parse"))
        if coverage:
            print(coverage)
        step = self.fail_next() if state != "ok" else (next_step or "bh-note frontier")
        print(f"next: {step}" + (f"; {tail}" if tail else ""))

    def fail_next(self) -> str:
        """The one action after a failure, by class: never a retry of a rate limit."""
        k = self.fail or "parse"
        return {
            "timeout": f"bh-{self.phase} on a narrower target (one path), or with --timeout {self.timeout * 2}",
            "rate": "bh-note frontier: another lead; this one later",
            "missing-tool": "this step by hand with single requests (curl --max-time 30, q)",
            "bad-argument": f"bh-{self.phase} --help",
            "unreachable": f"curl -sS --max-time 10 -o /dev/null -w '%{{http_code}}' {self.origin}/",
            "auth": f"bh-{self.phase} {self.url} as another identity (--as) or none",
            "parse": f"ls -la {self.raw}/ and grep the tool's files there",
            "gate-denied": "bh-note frontier: another route in scope",
        }[k]


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
    """items: (method, url, params, status). Dedup on (origin, key); returns the number of new endpoints. A failed
    tool writes none (a partial one keeps what it observed)."""
    if job.state == "error":
        return 0
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


def _touched(job: Job, urls: list[str], via: str, method: str = "GET") -> None:
    """A route counts as tested only when the tool ran to the end."""
    if job.state == "ok":
        c.record_touched(c.bh_dir(), urls, via=via, method=method)


def next_phase(origin: str, running: str = "") -> str | None:
    """`bh-<phase> <origin>` for the first required phase not done on the origin (the `running` one aside: it is
    recorded once its summary is printed), None when all are."""
    missing = [p for p in c.missing_phases(c.bh_dir(), origin) if p != running]
    return f"bh-{missing[0]} {origin}" if missing else None


def route_coverage(origin: str, limit: int = 3) -> tuple[int, int, list[str]]:
    """(routes known on the origin, routes tested, the first untested ones): endpoints.jsonl against touched.jsonl,
    by route family, as the frontier counts them."""
    d = c.bh_dir()
    keys = list(
        dict.fromkeys(
            e.get("key", "")
            for e in c.read_jsonl(d / c.ENDPOINTS)
            if e.get("origin") == origin and e.get("key") and not c.STATIC_EXT.search(e.get("key", ""))
        )
    )
    tested = {c.family(t.get("key", "")) for t in c.read_jsonl(d / c.TOUCHED) if t.get("origin") == origin}
    missing = [k for k in keys if c.family(k) not in tested]
    return len(keys), len(keys) - len(missing), missing


def coverage_line(n_in: int, n_tested: int, missing: list[str], limit: int = 3) -> str:
    shown = ", ".join(missing[:limit]) + (f" (+{len(missing) - limit})" if len(missing) > limit else "")
    return f"{n_in} routes in, {n_tested} tested, missing: {shown or 'none'}"


# ------------------------------------------------------------------ technology (T44)
def _word_in(name: str, text: str) -> bool:
    return re.search(rf"(?<![\w.]){re.escape(name)}(?!\w)", text, re.I) is not None


def _head_jsonl(path: Path, n: int) -> list[dict]:
    out = []
    try:
        with open(path, errors="replace") as fh:
            for i, line in enumerate(fh):
                if i >= n:
                    break
                try:
                    doc = json.loads(line)
                except ValueError:
                    continue
                if isinstance(doc, dict):
                    out.append(doc)
    except OSError:
        pass
    return out


def login_form_seen(h: dict) -> bool:
    """httpx said the page (after redirects) holds a password field: its `extracts` for LOGIN_FORM_RE are not empty."""
    ex = h.get("extracts") if isinstance(h, dict) else None
    values = ex.values() if isinstance(ex, dict) else ex if isinstance(ex, list) else ()
    return any(bool(v) for v in values if isinstance(v, (str, list)))


def known_tech(origin: str) -> list[str]:
    """The technology names already recorded for `origin`: httpx's `tech` and `webserver` (bh-recon), katana's
    `technologies` and its Server / X-Powered-By headers (bh-crawl). Newest runs first, at most 5 of each."""
    raw = c.bh_dir() / c.RAW

    def newest(pattern: str) -> list[Path]:
        try:
            return sorted(raw.glob(pattern), key=lambda f: f.stat().st_mtime, reverse=True)[:5]
        except OSError:
            return []

    names: list[str] = []
    for f in newest("recon-*/httpx.jsonl"):
        for h in _head_jsonl(f, TECH_READ_LINES):
            if origin in (c.origin(str(h.get("url", ""))), c.origin(str(h.get("final_url", "")))):
                names += [str(x) for x in h.get("tech") or [] if isinstance(x, str)]
                names += [str(h["webserver"])] if isinstance(h.get("webserver"), str) else []
    for f in newest("crawl-*/katana.jsonl"):
        for r in _head_jsonl(f, TECH_READ_LINES):
            req, resp = r.get("request") or {}, r.get("response") or {}
            if not isinstance(req, dict) or not isinstance(resp, dict):
                continue
            if c.origin(str(req.get("endpoint", ""))) != origin:
                continue
            names += [str(x) for x in resp.get("technologies") or [] if isinstance(x, str)]
            headers = resp.get("headers") if isinstance(resp.get("headers"), dict) else {}
            for k, v in headers.items():
                if str(k).lower().replace("-", "_") in ("server", "x_powered_by") and isinstance(v, str):
                    names.append(v)
    return list(dict.fromkeys(n[:80] for n in names if n))


def tech_extensions(tech: list[str]) -> list[tuple[str, str]]:
    """(our name, extension) for the technology seen, at most TECH_EXT_MAX extensions."""
    out: dict[str, str] = {}
    for name, ext in TECH_EXT:
        if ext not in out and any(_word_in(name, t) for t in tech):
            out[ext] = name
    return [(name, ext) for ext, name in list(out.items())[:TECH_EXT_MAX]]


def tech_dbms(tech: list[str]) -> tuple[str, str] | None:
    """(our name, sqlmap --dbms value) when a database was named, else None."""
    for name, dbms in TECH_DBMS:
        if any(_word_in(name, t) for t in tech):
            return name, dbms
    return None


# ------------------------------------------------------------------ passive cache (lot D, optional)
def _cache(op: str, *args):
    """bh.agent.cache.get / put when the module is there; absent or failing: no cache."""
    try:
        from bh.agent import cache  # optional (lot D)
    except ImportError:
        return None
    try:
        return getattr(cache, op)(*args)
    except Exception:  # noqa: BLE001 - a cache is a help, never a reason to fail the step
        return None


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
    # bh.agent.cache (lot D): get(program, tool, args, scope_hash) -> raw path; put(..., raw_path, ttl_s)
    prog = os.environ.get("BH_PROGRAM") or c.bh_dir().parent.name
    key = [domain, "subs" if subs else "host", ",".join(ARCHIVE_PROVIDERS), max_urls]
    shash = _cache("scope_hash") or ""
    hit = _cache("get", prog, "recon-archive", key, shash)
    cached = None
    if isinstance(hit, str):
        try:
            cached = [u for u in Path(hit).read_text(errors="replace").splitlines() if u.strip()]
        except OSError:
            cached = None
    if cached is not None:
        urls, rc, timed_out, capped = cached[:max_urls], 0, False, len(cached) >= max_urls
        (job.raw / "gau.txt").write_text("".join(u + "\n" for u in urls))
        (job.raw / "gau.err").write_text("")
        from_cache = " (cached)"
    else:
        urls, rc, timed_out, capped = _stream(job, cmd, "gau.txt", max_urls, min(timeout, job.timeout))
        if rc == 0 and not timed_out:
            _cache("put", prog, "recon-archive", key, shash, job.raw / "gau.txt", 24 * 3600)
        from_cache = ""
    err_text = (job.raw / "gau.err").read_text(errors="replace") if (job.raw / "gau.err").is_file() else ""
    failed = bool(rc) and not timed_out
    kept = sorted({u for u in urls if in_scope(u, rules, domain)})
    (job.raw / "archive-inscope.txt").write_text("".join(u + "\n" for u in kept))
    fams, new, per_origin = (0, 0, {}) if failed else _add_archive_endpoints(kept)
    for o, n in per_origin.items():
        status = PARTIAL_STATUS if timed_out else "ok"
        c.record_phase(c.bh_dir(), o, "archive", status=status, count=n, raw=str(job.raw))
    state = " (cut at --max-urls)" if capped else " (timeout, partial)" if timed_out else f" (rc={rc})" if rc else ""
    lines = [
        f"archive: {len(urls)} URLs from {'+'.join(ARCHIVE_PROVIDERS)} for {'*.' if subs else ''}{domain}"
        f"{state}{from_cache}, {len(kept)} in scope, {fams} route families, {new} new endpoints (source archive)"
    ]
    err = [x for x in err_text.splitlines() if x.strip()]
    if not urls and err:
        lines.append(f"archive: gau stderr: {err[-1][:200]}")
    if failed or timed_out:
        lines.append("archive " + fail.line(fail.classify(rc, err_text[-4000:], timed_out)))
    if failed:
        return lines
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
            "-er",
            LOGIN_FORM_RE,
            *_flag_pairs("-H", job.headers()),
        ],
        stdout="httpx.jsonl",
    )
    live = c.read_jsonl(job.raw / "httpx.jsonl")
    if use_archive:
        job.lines += archive(job, target, max_urls)
    origins, homes = [], []
    for h in sorted(live, key=lambda x: (x.get("status_code", 0), x.get("url", ""))):
        tech = ",".join(h.get("tech") or [])[:60]
        login = login_form_seen(h)
        job.lines.append(
            f"{h.get('status_code')} {h.get('url')}  {(h.get('title') or '')[:50]}  {tech}"
            + ("  [login]" if login else "")
        )
        if o := c.origin(h.get("url", "")):
            origins.append(o)
            if job.state == "ok":
                c.record_phase(c.bh_dir(), o, "recon", status="ok", count=1, raw=str(job.raw))
                status = h.get("status_code") if isinstance(h.get("status_code"), int) else None
                homes.append(
                    {"origin": o, "key": "GET /", "url": o, "params": [], "status": status, "source": "recon",
                     "login_form": login}
                )  # fmt: skip
    if homes:  # T42: the host scores an origin with a login form only if the gate saw traffic to it
        c.append_jsonl(c.bh_dir() / c.ENDPOINTS, *homes)
    n_names = len(hosts.read_text().split())
    todo = [o for o in dict.fromkeys(origins) if next_phase(o, "recon")]
    job.finish(
        len(live),
        rc or rc_s,
        to,
        f"{n_names} names, {len(live)} live HTTP services",
        (next_phase(todo[0], "recon") if todo else None)
        or ("bh-note frontier" if origins else "bh-recon another name of the scope"),
    )


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
            # never follow a sign-out link: it kills the identity's session under the agent (audit §4)
            "-cos",
            r"(?i)(log-?out|sign-?out|logoff)",
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
    job.note(rc, to)
    new = _add_endpoints(job, items, "crawl") + _add_endpoints(job, js, "js")
    eps = [e for e in c.read_jsonl(c.bh_dir() / c.ENDPOINTS) if e.get("origin") == job.origin]
    for e in sorted(eps, key=lambda e: (not e.get("params"), e["key"]))[:SUMMARY_LINES]:
        params = f" ?{','.join(e['params'])}" if e.get("params") else ""
        job.lines.append(f"{e['key']}{params}")
    n_in, n_tested, missing = route_coverage(job.origin)
    after = next_phase(job.origin, "crawl")
    job.finish(
        new,
        rc,
        to,
        f"{len(items)} URLs crawled, {len(js)} paths quoted in JS/HTML, {new} new endpoints "
        f"({len(eps)} known on this origin)",
        after or (f"one hand-made request on {missing[0]}, then bh-note cover" if missing else "bh-note frontier"),
        coverage_line(n_in, n_tested, missing),
    )


def content(job: Job, wordlist: str | None) -> None:
    wl = Path(wordlist) if wordlist else WORDLISTS / ("common.txt" if c.rps() >= 10 else "quickhits.txt")
    base = job.url.rstrip("/")
    exts = tech_extensions(known_tech(job.origin))
    if exts:
        job.lines.append(
            "profile: " + ", ".join(f"{n} -> {e}" for n, e in exts) + " (technology bh-recon / bh-crawl recorded)"
        )
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
            *(["-e", ",".join(e for _, e in exts)] if exts else []),
            *_flag_pairs("-H", job.headers()),
        ]
    )
    results = (c.read_json(job.raw / "ffuf.json", {}) or {}).get("results") or []
    items = [("GET", r.get("url", ""), [], r.get("status")) for r in results]
    job.note(rc, to)
    new = _add_endpoints(job, items, "content")
    for r in sorted(results, key=lambda r: (r.get("status", 0), r.get("url", "")))[:SUMMARY_LINES]:
        job.lines.append(f"{r.get('status')} {r.get('length', '?'):>7}B  {urlsplit(r.get('url', '')).path}")
    job.finish(
        len(results),
        rc,
        to,
        f"{len(results)} paths found with {wl.name}, {new} new endpoints",
        next_phase(job.origin, "content") or "bh-note frontier",
    )


def scan(job: Job, deep: bool) -> None:
    """Pass 1: templates matching the detected tech (-as). Pass 2: generic misconfigurations
    (high+), or with --deep exposures + misconfigurations (medium+, ~4.7k requests)."""
    if not NUCLEI_TEMPLATES.is_dir():
        sys.exit(
            fail.line("missing-tool", f"nuclei templates missing at {NUCLEI_TEMPLATES}: test by hand (curl, q)")
            + "\nnext: bh-content or a hand-made request on the origin"
        )
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
        "reproduce the most severe match above by hand, one request (curl --max-time 30)"
        if hits
        else next_phase(job.origin, "scan") or "bh-note frontier",
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
    _touched(job, [job.url], via="params")
    n = sum(len(p) for p in found.values())
    job.finish(
        n,
        rc,
        to,
        f"{n} hidden parameters",
        f"bh-fuzz {shlex.quote(job.url)} -p <one parameter above>" if n else "bh-note frontier",
    )


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
    if profile := tech_dbms(known_tech(job.origin)):
        cmd += ["--dbms", profile[1]]
        job.lines.append(f"profile: {profile[0]} -> --dbms {profile[1]} (technology bh-recon / bh-crawl recorded)")
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
    method = "POST" if data else "GET"
    _touched(job, [job.url], via="sqli", method=method)
    route = f"{method} {c.path_key(urlsplit(job.url).path)}"
    job.finish(
        len(points),
        rc,
        to,
        f"{len(points)} injection point(s)",
        "write proof.json (attack + control), then bh-note finding --class sqli --proof proof.json"
        if points
        else f'bh-note cover "{route}" sqli clean -e {job.raw}/sqlmap.log',
    )


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
    _touched(job, [job.url], via="xss")
    job.finish(
        len(pocs),
        rc,
        to,
        f"{len(pocs)} XSS PoC(s) (V = verified in DOM, R = reflected)",
        "confirm one PoC in a page: bh-browse '<PoC URL>' --xss <MARKER> (a dialog or window.__bhxss)"
        if pocs
        else f'bh-note cover "GET {c.path_key(urlsplit(job.url).path)}" xss clean -e {job.raw}/dalfox.json',
    )


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
