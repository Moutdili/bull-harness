"""Contract between the sandbox (builtins, hooks, bh-note) and the host (runner).

Everything about a program lives in its work dir, `BH_DIR` (= /work/<program>/.bh in
the container, var/work/<program>/.bh on the host):

  notes.jsonl      agent -> board inbox (bh-note), ingested by the runner
  coverage.json    {origin: {phase: {ts, status, count, raw}}}  written by builtins
  endpoints.jsonl  attack surface found by tools (crawl, content discovery)
  touched.jsonl    endpoints the agent actually tested (hook + test builtins)
  commands.jsonl   every Bash command + the hook decision (token / tool-usage metrics)
  manual-tested.json  endpoints the gate saw requested by hand, pushed by the runner each segment
  raw/             full tool outputs; the model only sees summaries
  frontier.md, facts.json, system.md, scope.yaml   pushed by the runner each segment

The tool lock: manual HTTP towards an origin is refused until every phase in
REQUIRED_PHASES has run on that origin (see hooks.pre_tool_use).
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

# Phases a builtin must have run on an origin before the agent may hand-craft requests to it.
REQUIRED_PHASES = ("crawl", "content", "scan")
ALL_PHASES = ("recon", *REQUIRED_PHASES, "params", "sqli", "xss")

# Third-party recon sources: never targets, never locked. The gate imports these too.
# Exact hosts only (no subdomains), GET/HEAD only; services that fetch arbitrary URLs or run tools
# server-side, serve arbitrary content (raw.githubusercontent.com) or sit on lapsed/personal domains
# are deliberately absent: each one is an exfiltration or injection channel.
PASSIVE_HOSTS = (
    "web.archive.org",
    "index.commoncrawl.org",
    "otx.alienvault.com",
    "urlscan.io",
    "crt.sh",
    "api.certspotter.com",
    "osv.dev",
    "api.osv.dev",
    "nvd.nist.gov",
    "services.nvd.nist.gov",
    "cveawg.mitre.org",
)
# Paths refused even on a passive host (server-side fetch of an arbitrary URL).
PASSIVE_DENY_PATHS = {"web.archive.org": ("/save",)}

IDENTITY_HEADER = "X-BH-Identity"
LOCK_MARK = "[bh-lock]"  # prefix of every hook denial, counted by the runner
SEVERITIES = ("critical", "high", "medium", "low", "info")  # most severe first
WORK_ROOT = "/work"  # the agent's work volume (var/work on the host)

NOTES, COVERAGE, ENDPOINTS, TOUCHED, COMMANDS = (
    "notes.jsonl",
    "coverage.json",
    "endpoints.jsonl",
    "touched.jsonl",
    "commands.jsonl",
)
FRONTIER, FACTS, SYSTEM, SCOPE, AGENT_PID, RAW, MANUAL_TESTED = (
    "frontier.md",
    "facts.json",
    "system.md",
    "scope.yaml",
    "agent.pid",
    "raw",
    "manual-tested.json",
)

STATIC_EXT = re.compile(r"\.(js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|otf|mp4|webm|mp3|pdf)$", re.I)
URL_RE = re.compile(r"https?://[^\s'\"<>|;)`\\]+")
_ID_SEGMENT = re.compile(r"^(\d+|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{16,}|[A-Za-z0-9_-]{24,})$", re.I)


# ------------------------------------------------------------------ locations
def bh_dir() -> Path:
    return Path(os.environ.get("BH_DIR", f"{WORK_ROOT}/.bh"))


def sandbox_dir(program: str) -> str:
    """BH_DIR of `program` as seen inside the agent container."""
    return f"{WORK_ROOT}/{program}/.bh"


def gate() -> str:
    return os.environ.get("BH_GATE", "http://gate:8080")


def rps() -> float:
    try:
        return max(0.2, float(os.environ.get("BH_RPS", "5")))
    except ValueError:
        return 5.0


# ------------------------------------------------------------------ URLs
def is_passive(host: str) -> bool:
    return host.lower().rstrip(".") in PASSIVE_HOSTS


def host_of(url: str) -> str:
    try:
        return (urlsplit(url.strip()).hostname or "").lower()
    except ValueError:
        return ""


def origin(url: str) -> str | None:
    """scheme://host:port, port always explicit. None if not an http(s) URL."""
    try:
        p = urlsplit(url.strip())
        port = p.port
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or not p.hostname:
        return None
    host = f"[{p.hostname}]" if ":" in p.hostname else p.hostname.lower()
    return f"{p.scheme}://{host}:{port or (443 if p.scheme == 'https' else 80)}"


def path_key(path: str) -> str:
    """Path template: ids collapse so /basket/1 and /basket/7 are one endpoint."""
    segs = [("{id}" if _ID_SEGMENT.match(s) else s) for s in (path or "/").split("?")[0].split("/")]
    return "/".join(segs) or "/"


def family(key: str) -> str:
    """Comparable form of an endpoint key. A JS literal ending in `/` (`"/rest/basket/" + id`) is the
    item route `/rest/basket/{id}`; the collection `/api/Users` stays distinct from `/api/Users/{id}`."""
    k = key.split("?")[0]
    return k + "{id}" if k.endswith("/") and not k.endswith(" /") else k


def endpoint_key(url: str, method: str = "GET") -> tuple[str, str] | None:
    o = origin(url)
    if o is None:
        return None
    return o, f"{method.upper()} {path_key(urlsplit(url).path)}"


def query_params(url: str) -> list[str]:
    return sorted({k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)})


# ------------------------------------------------------------------ files
def read_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1))
    os.replace(tmp, path)


def append_jsonl(path: Path, *records: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps({"ts": round(time.time(), 3), **rec}, ensure_ascii=False) + "\n")


def tail_jsonl(path: Path, n: int, window: int = 400_000) -> list[dict]:
    """Last `n` records, reading at most the last `window` bytes."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            fh.seek(max(0, fh.tell() - window))
            lines = fh.read().splitlines()[-n:]
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def read_jsonl(path: Path, offset: int = 0) -> list[dict]:
    out: list[dict] = []
    try:
        with open(path, "rb") as fh:
            fh.seek(offset)
            for line in fh:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return out


# ------------------------------------------------------------------ coverage
def record_phase(d: Path, origin_: str, phase: str, *, status: str, count: int, raw: str) -> None:
    cov = read_json(d / COVERAGE, {})
    cov.setdefault(origin_, {})[phase] = {"ts": round(time.time()), "status": status, "count": count, "raw": raw}
    write_json(d / COVERAGE, cov)


def phase_done(entry: dict | None) -> bool:
    """A phase counts once its tool ran to the end or to its time budget; a tool error does not."""
    return bool(entry) and not str(entry.get("status", "")).startswith("error")


def missing_phases(d: Path, origin_: str) -> list[str]:
    done = read_json(d / COVERAGE, {}).get(origin_, {})
    return [p for p in REQUIRED_PHASES if not phase_done(done.get(p))]


def record_touched(d: Path, urls: list[str], via: str, method: str = "GET") -> None:
    recs = []
    for u in urls:
        if "$" in u:  # unresolved shell variable: not a real endpoint
            continue
        k = endpoint_key(u, method)
        if k:
            recs.append({"origin": k[0], "key": k[1], "via": via})
    if recs:
        append_jsonl(d / TOUCHED, *recs)


# ------------------------------------------------------------------ surface (host + sandbox)
def _phase_mark(entry: dict | None) -> str:
    if not phase_done(entry):
        return "✗"
    return "✔" if entry.get("status") == "ok" else "~"


Tested = set[tuple[str, str]]


def _surface_data(d: Path, also_tested: Tested | None) -> tuple[dict, list, dict]:
    """(endpoints, untested endpoints sorted by value, coverage). Tested = touched by a builtin or a
    literal URL in a command (touched.jsonl), or requested by hand as seen by the gate (`also_tested`)."""
    eps: dict[tuple[str, str], dict] = {}
    for e in read_jsonl(d / ENDPOINTS):
        k = (e.get("origin", ""), e.get("key", ""))
        if not k[1] or STATIC_EXT.search(k[1]):
            continue
        cur = eps.setdefault(k, {"params": set(), "sources": set(), "status": e.get("status")})
        cur["params"].update(e.get("params") or [])
        cur["sources"].add(e.get("source", "?"))
    touched = {(t.get("origin"), family(t.get("key", ""))) for t in read_jsonl(d / TOUCHED)} | (also_tested or set())
    untested = [(k, v) for k, v in eps.items() if (k[0], family(k[1])) not in touched]
    untested.sort(
        key=lambda kv: (-len(kv[1]["params"]), not re.search(r"/(api|rest|graphql|v\d)/", kv[0][1]), kv[0][1])
    )
    return eps, untested, read_json(d / COVERAGE, {})


def surface_counts(d: Path, also_tested: Tested | None = None) -> tuple[int, int]:
    """(endpoints tested, required phases done across origins): the runner's progress measure."""
    eps, untested, cov = _surface_data(d, also_tested)
    phases = sum(phase_done(ph.get(p)) for ph in cov.values() for p in REQUIRED_PHASES)
    return len(eps) - len(untested), phases


def surface(d: Path, limit: int = 12, also_tested: Tested | None = None) -> str:
    """Frontier block: what the tools found and what nobody tested yet."""
    eps, untested, cov = _surface_data(d, also_tested)
    if not eps and not cov:
        return ""
    out = ["## attack surface (from your tools)"]
    for o, phases in cov.items():
        state = " ".join(f"{p}{_phase_mark(phases.get(p))}" for p in REQUIRED_PHASES)
        extra = " ".join(p for p in phases if p not in REQUIRED_PHASES)
        out.append(f"- {o}: {state}" + (f" · also {extra}" if extra else ""))
    with_params = sum(1 for v in eps.values() if v["params"])
    out.append(
        f"- {len(eps)} endpoints ({with_params} with params), {len(eps) - len(untested)} tested, "
        f"{len(untested)} untested. Next untested:"
    )
    for (o, key), v in untested[:limit]:
        params = f" ?{','.join(sorted(v['params']))}  → bh-sqli / bh-xss" if v["params"] else ""
        out.append(f"  - {key}{params}  [{o}; {'+'.join(sorted(v['sources']))}]")
    return "\n".join(out)


# ------------------------------------------------------------------ command classification (metrics)
_ARSENAL = re.compile(
    r"(^|[\s;&|(])(bh-(recon|crawl|content|scan|params|sqli|xss)|nuclei|sqlmap|ffuf|katana|dalfox|arjun|"
    r"httpx-toolkit|subfinder|feroxbuster|gobuster|dirsearch|nikto|wpscan|commix)(?=\s|$)"
)
_MANUAL = re.compile(r"(^|[\s;&|(`])(curl|wget|python3?|node|perl|ruby|nc|ncat|socat|http|xh)(?=\s|$)")
_HTTP_CLIENT = re.compile(r"^(curl|wget)$")
_BARE_TARGET = re.compile(r"^([a-z0-9-]+(\.[a-z0-9-]+)+|\[[0-9a-f:]+\])(:\d+)?(/\S*)?$", re.I)


def urls_in(cmd: str) -> list[str]:
    """URLs a command talks to: literal http(s) URLs, plus scheme-less `host[:port]/path` arguments
    of curl/wget (curl defaults them to http)."""
    urls = URL_RE.findall(cmd)
    in_client = False
    for tok in re.findall(r"[;&|()\n]|[^\s;&|()]+", cmd):
        word = tok.strip("'\"")
        if tok in ";&|()\n":
            in_client = False
        elif _HTTP_CLIENT.match(word):
            in_client = True
        elif (
            in_client
            and not word.startswith("-")
            and "://" not in word
            and _BARE_TARGET.match(word)
            and ("/" in word or ":" in word)
        ):
            urls.append("http://" + word)
    return urls


def uses_arsenal(cmd: str) -> bool:
    return bool(_ARSENAL.search(cmd))


def uses_manual_http(cmd: str) -> bool:
    return bool(_MANUAL.search(cmd)) and bool(urls_in(cmd))
