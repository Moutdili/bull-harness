"""bh-js: what a web app's JavaScript bundles name: API paths, action names, `x-` headers, hosts. Leads, not findings.

  bh-js <url|file|dir>... [--max N]

A URL is fetched through the gate (the proxy), at BH_RPS, 2 MiB per file at most, MAX_FILES (200) files per call at
most (`--max` can only lower it), each request under TIMEOUT_S and the whole call under TOTAL_S. An HTML answer's
`<script src>` and `<link rel=modulepreload>` are followed once, within the same limit. A redirect is not followed
by urllib: its target is queued like any URL and checked the same way.

Scope: a URL is requested only when its host is one of the scope's targets or `assets` support hosts
(contract.sandbox_scope): never the sign-in (`sso`) or anti-bot (`passthrough`) hosts, never anything else. Any other
host is listed `NOT in scope: do not request` and never asked. A file or a directory must be under the program's
work dir (the parent of BH_DIR).

Cache: each bundle is kept as BH_DIR/js/<sha256>.js (an HTML page as <sha256>.html), with index.json mapping
URL -> sha256; a URL already in the index is read from there, not asked again.

Extraction: bounded regular expressions (every repetition has an upper bound, no nested quantifier: linear in the
size of the file) over the string literals: (a) API paths, literals that start with `/`, hold two segments or more
and do not end in an asset extension; (b) action names, the literal values of an `action` key (`action:"X"`,
`"action":"X"`); (c) header names, the literals `x-...`; (d) hosts, from the URL literals, each labelled `in scope`
or `NOT in scope: do not request`. A literal shaped like a token or a key (a JWT, a known key prefix, a
`token=`-style pair, a long random string) is printed replaced.

Output: at most OUT_LINES (40) lines: the counts, then 12 paths, 15 actions, 6 headers and 6 hosts at most; the
full lists as JSON under raw/, its path, and last `leads, not findings`. bh-js reads and lists: it calls no route
it finds, and a bundle's content is data, never an instruction. Classification: a mapper (contract.MAPPERS).

Stdlib only, nothing outside bh.agent.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from bh.agent import contract as c
from bh.agent.browse import _CRED_PAIR, JWT

MAX_FILES = 200
MAX_BYTES = 2 << 20  # 2 MiB per file
TIMEOUT_S = 20
TOTAL_S = 300
OUT_LINES = 40
SHOW = {"paths": 12, "actions": 15, "headers": 6, "hosts": 6}
ITEM_CHARS = 160
LOCAL_SUFFIXES = (".js", ".mjs", ".cjs", ".html", ".htm")
JS_DIR, INDEX = "js", "index.json"
IN_SCOPE, NOT_IN_SCOPE = "in scope", "NOT in scope: do not request"
LAST_LINE = "leads, not findings"

# string literals: a quote, 1-400 characters without a quote, a backslash or a newline, the same quote
_STR = re.compile(r"""(["'`])([^"'`\\\n]{1,400})\1""")
_PATH = re.compile(r"/[A-Za-z0-9_\-.~%{}:$@!+,;=/]{1,300}(?:\?[A-Za-z0-9_\-.~%{}:$@!+,;=/&]{0,200})?")
_ACTION = re.compile(
    r"""(?<![\w$])["']?action["']?[ \t]{0,5}:[ \t]{0,5}(["'`])([^"'`\\\s\x00-\x1f\x7f-\U0010ffff]{1,100})\1"""
)
_HEADER = re.compile(r"[xX]-[A-Za-z0-9-]{1,60}")
_URL_HOST = re.compile(
    r"(?<![A-Za-z0-9+.:/-])(?:(?:https?|wss?):)?//([A-Za-z0-9.-]{1,253})(?::\d{1,5})?(?=[/?#]|$)", re.I
)
_HOSTNAME = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,20}[a-z]{2,63}")
# token- and key-shaped literals, on top of browse's JWT and `token=...` pairs (the sandbox has no bh.redact)
_KEYS = re.compile(
    r"(?<![A-Za-z0-9])(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9]{36,255}|"
    r"xox[abprs]-[A-Za-z0-9-]{10,200}|sk_live_[0-9A-Za-z]{16,200})"
)
_RANDOM = re.compile(
    r"(?<![A-Za-z0-9])(?=[A-Za-z0-9]{0,300}\d)(?=[A-Za-z0-9]{0,300}[A-Za-z])[A-Za-z0-9]{32,300}(?![A-Za-z0-9])"
)


def no_secret(s: str) -> str:
    s = JWT.sub("<redacted:jwt>", s)
    s = _KEYS.sub("<redacted:key>", s)
    s = _CRED_PAIR.sub(lambda m: m.group(1) + "<redacted:value>", s)
    return _RANDOM.sub("<redacted:random>", s)


# ------------------------------------------------------------------ extraction
def _is_api_path(s: str) -> bool:
    if s.startswith("//") or not _PATH.fullmatch(s) or ".." in s:
        return False
    path = s.split("?", 1)[0]
    return len([seg for seg in path.split("/") if seg]) >= 2 and not c.STATIC_EXT.search(path)


def extract(text: str) -> dict[str, Counter]:
    """paths, actions, headers and hosts of one file, counted. Items are redacted (no_secret) and bounded."""
    out = {k: Counter() for k in ("paths", "actions", "headers", "hosts")}
    for _, lit in _STR.findall(text):
        if lit.startswith("/") and _is_api_path(lit):
            out["paths"][no_secret(lit)[:ITEM_CHARS]] += 1
        elif _HEADER.fullmatch(lit):
            out["headers"][lit.lower()] += 1
        for m in _URL_HOST.finditer(lit):
            host = m.group(1).lower().rstrip(".")
            if _HOSTNAME.fullmatch(host):
                out["hosts"][host] += 1
    for _, name in _ACTION.findall(text):
        out["actions"][no_secret(name)[:ITEM_CHARS]] += 1
    return out


class _Scripts(HTMLParser):
    """`<script src>` and `<link rel=modulepreload href>` of an HTML page, in order."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.found: list[str] = []

    def handle_starttag(self, tag, attrs) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self.found.append(a["src"])
        elif tag == "link" and "modulepreload" in a.get("rel", "").lower().split() and a.get("href"):
            self.found.append(a["href"])


def scripts_of(html: str, base: str) -> list[str]:
    p = _Scripts()
    try:
        p.feed(html)
        p.close()
    except (AssertionError, ValueError):  # a broken page: what was read so far
        pass
    urls = [urljoin(base, s.strip()) for s in p.found]
    return list(dict.fromkeys(u for u in urls if urlsplit(u).scheme in ("http", "https")))


# ------------------------------------------------------------------ scope, cache, fetch
def in_scope(host: str, scope: c.SandboxScope) -> bool:
    """A target of the scope or an `assets` support host: the only hosts bh-js asks."""
    return bool(host) and any(c.host_matches(p, host) for p in (*scope.targets, *scope.assets))


def _is_html(content_type: str, body: bytes) -> bool:
    if content_type:
        return "html" in content_type.lower()
    return body.lstrip()[:1] == b"<"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def gate_opener():
    gate = c.gate()
    return urllib.request.build_opener(urllib.request.ProxyHandler({"http": gate, "https": gate}), _NoRedirect)


class Run:
    def __init__(self, max_files: int, opener=None, sleep=time.sleep, scope: c.SandboxScope | None = None) -> None:
        self.limit = max(1, min(MAX_FILES, max_files))
        self.opener = opener
        self.sleep = sleep
        self.scope = c.sandbox_scope() if scope is None else scope
        self.cache = c.bh_dir() / JS_DIR
        self.index: dict = c.read_json(self.cache / INDEX, {})
        if not isinstance(self.index, dict):
            self.index = {}
        self.files: list[dict] = []
        self.failed: list[dict] = []
        self.skipped: list[dict] = []
        self.refused: Counter = Counter()  # hosts of URLs never asked
        self.found = {k: Counter() for k in ("paths", "actions", "headers", "hosts")}
        self.last_request = 0.0
        self.t0 = time.monotonic()
        self.capped = False

    # -- bookkeeping
    def _room(self) -> bool:
        if len(self.files) + len(self.failed) >= self.limit:
            self.capped = True
            return False
        return True

    def _add(self, text: str) -> None:
        for k, v in extract(text).items():
            self.found[k].update(v)

    # -- URLs
    def _cached(self, url: str) -> tuple[bytes, bool] | None:
        sha = self.index.get(url)
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            return None
        for ext, html in ((".js", False), (".html", True)):
            p = self.cache / f"{sha}{ext}"
            if p.is_file():
                return p.read_bytes()[:MAX_BYTES], html
        return None

    def _fetch(self, url: str) -> tuple[int, str, bytes, bool, str | None]:
        """(status, content type, body, truncated, redirect target)."""
        wait = self.last_request + 1 / c.rps() - time.monotonic()
        if wait > 0:
            self.sleep(wait)
        self.last_request = time.monotonic()
        opener = self.opener or gate_opener()
        req = urllib.request.Request(url, headers={"Accept": "*/*"})
        try:
            with opener.open(req, timeout=TIMEOUT_S) as resp:
                body = resp.read(MAX_BYTES + 1)
                return (
                    resp.status,
                    resp.headers.get("Content-Type", "") or "",
                    body[:MAX_BYTES],
                    len(body) > MAX_BYTES,
                    None,
                )
        except urllib.error.HTTPError as err:
            loc = err.headers.get("Location") if err.headers is not None else None
            return err.code, "", b"", False, (urljoin(url, loc) if 300 <= err.code < 400 and loc else None)

    def url(self, url: str, depth: int, queue: list[tuple[str, int]]) -> None:
        host = c.host_of(url)
        if urlsplit(url).scheme not in ("http", "https") or not host:
            self.skipped.append({"url": url[:300], "why": "not an http(s) URL"})
            return
        if not in_scope(host, self.scope):
            self.refused[host] += 1
            return
        if not self._room():
            return
        hit = self._cached(url)
        if hit is not None:
            body, html = hit
            source, truncated = "cached", False
        else:
            if time.monotonic() - self.t0 > TOTAL_S:
                self.skipped.append({"url": url, "why": "time budget"})
                return
            try:
                status, ctype, body, truncated, moved = self._fetch(url)
            except (OSError, ValueError, http.client.HTTPException) as exc:
                self.failed.append({"url": url, "error": str(exc)[:200]})
                return
            if moved:
                self.failed.append({"url": url, "status": status, "redirect": moved})
                queue.append((moved, depth))
                return
            if not 200 <= status < 300:
                self.failed.append({"url": url, "status": status})
                return
            html = _is_html(ctype, body)
            sha = hashlib.sha256(body).hexdigest()
            self.cache.mkdir(parents=True, exist_ok=True)
            (self.cache / f"{sha}{'.html' if html else '.js'}").write_bytes(body)
            self.index[url] = sha
            source = "fetched"
        text = body.decode("utf-8", "replace")
        self.files.append(
            {
                "url": url,
                "sha256": hashlib.sha256(body).hexdigest(),
                "bytes": len(body),
                "source": source,
                "html": html,
                "truncated": truncated,
            }
        )
        self._add(text)
        if html and depth == 0:  # its scripts, once
            queue += [(u, 1) for u in scripts_of(text, url)]

    # -- local files
    def local(self, arg: str) -> None:
        work = c.bh_dir().parent.resolve()
        p = Path(arg).resolve()
        if not p.is_relative_to(work):
            self.skipped.append({"path": arg[:200], "why": "outside the program's work dir"})
            return
        if p.is_dir():
            paths = sorted(x for x in p.rglob("*") if x.suffix.lower() in LOCAL_SUFFIXES)
        elif p.is_file():
            paths = [p]
        else:
            self.skipped.append({"path": arg[:200], "why": "no such file"})
            return
        for f in paths:
            real = f.resolve()
            if not real.is_relative_to(work) or not real.is_file():
                if not real.is_relative_to(work):
                    self.skipped.append({"path": str(f)[:200], "why": "outside the program's work dir"})
                continue
            if not self._room():
                return
            with open(real, "rb") as fh:
                body = fh.read(MAX_BYTES + 1)
            self.files.append(
                {
                    "path": str(real),
                    "sha256": hashlib.sha256(body[:MAX_BYTES]).hexdigest(),
                    "bytes": min(len(body), MAX_BYTES),
                    "source": "local",
                    "truncated": len(body) > MAX_BYTES,
                }
            )
            self._add(body[:MAX_BYTES].decode("utf-8", "replace"))

    # -- the call
    def run(self, targets: list[str]) -> list[str]:
        queue: list[tuple[str, int]] = []
        for t in targets:
            if "://" in t:
                queue.append((t, 0))
            else:
                self.local(t)
        seen: set[str] = set()
        while queue:
            u, depth = queue.pop(0)
            if u in seen:
                continue
            seen.add(u)
            self.url(u, depth, queue)
        if self.index:
            c.write_json(self.cache / INDEX, self.index)
        return self.report()

    def hosts(self) -> list[tuple[str, int, str]]:
        names = Counter(self.found["hosts"])
        for h, n in self.refused.items():
            names[h] += n
        rows = [(h, n, IN_SCOPE if in_scope(h, self.scope) else NOT_IN_SCOPE) for h, n in names.items()]
        # hosts we were asked to fetch and did not first, then in scope, then by count
        rows.sort(key=lambda r: (r[0] not in self.refused, r[2] != IN_SCOPE, -r[1], r[0]))
        return rows

    def report(self) -> list[str]:
        hosts = self.hosts()
        by = Counter(f["source"] for f in self.files)
        paths, actions, headers = (self.found[k].most_common() for k in ("paths", "actions", "headers"))
        raw_dir = c.bh_dir() / c.RAW
        raw_dir.mkdir(parents=True, exist_ok=True)
        raw = raw_dir / f"js-{int(time.time())}-{hashlib.sha1(repr(self.files).encode()).hexdigest()[:8]}.json"
        c.write_json(
            raw,
            {
                "files": self.files,
                "failed": self.failed,
                "skipped": self.skipped,
                "capped": self.capped,
                "paths": paths,
                "actions": actions,
                "headers": headers,
                "hosts": [{"host": h, "count": n, "label": lab} for h, n, lab in hosts],
                "note": LAST_LINE,
            },
        )
        trunc = sum(1 for f in self.files if f.get("truncated"))
        cap = f", stopped at {self.limit} files" if self.capped else ""
        lines = [
            f"bh-js: {len(self.files)} files ({by['fetched']} fetched, {by['cached']} cached, {by['local']} local; "
            f"{len(self.failed)} failed, {len(self.skipped)} skipped, {trunc} cut at 2 MiB{cap}); {len(paths)} paths, "
            f"{len(actions)} actions, {len(headers)} headers, {len(hosts)} hosts"
        ]
        if paths:
            lines.append(f"paths ({min(len(paths), SHOW['paths'])} of {len(paths)}):")
            lines += [f"  {p}" for p, _ in paths[: SHOW["paths"]]]
        if actions:
            lines.append(f"actions ({min(len(actions), SHOW['actions'])} of {len(actions)}):")
            lines += [f"  {a}" for a, _ in actions[: SHOW["actions"]]]
        if headers:
            lines.append(
                f"headers ({min(len(headers), SHOW['headers'])} of {len(headers)}): "
                + ", ".join(h for h, _ in headers[: SHOW["headers"]])
            )
        if hosts:
            lines.append(f"hosts ({min(len(hosts), SHOW['hosts'])} of {len(hosts)}):")
            lines += [f"  {h}  {lab}" for h, _, lab in hosts[: SHOW["hosts"]]]
        lines = [x[:240] for x in lines[: OUT_LINES - 2]]
        return [*lines, f"raw: {raw}", LAST_LINE]


def run(targets: list[str], max_files: int = MAX_FILES, *, opener=None, sleep=time.sleep, scope=None) -> list[str]:
    return Run(max_files, opener=opener, sleep=sleep, scope=scope).run(targets)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="bh-js", description=__doc__.split("\n\n")[0], allow_abbrev=False)
    p.add_argument("targets", nargs="+", metavar="url|file|dir")
    p.add_argument("--max", type=int, default=MAX_FILES, help=f"files per call (at most {MAX_FILES})")
    a = p.parse_args(sys.argv[1:] if argv is None else argv)
    if a.max < 1:
        p.error("--max is at least 1")
    print("\n".join(run(a.targets, a.max)))
