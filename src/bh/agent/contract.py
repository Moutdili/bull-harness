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
import shlex
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

# Phases a builtin must have run on an origin before the agent may hand-craft requests to it.
REQUIRED_PHASES = ("crawl", "content", "scan")
# Phases that are "automated scanners" in the sense of program rules. When a program forbids them
# (scope `scanners_allowed: false` -> BH_SCANNERS=0), only these remain usable and required:
LIGHT_PHASES = ("recon", "crawl")

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
GATE_HEADER = "X-BH-Gate"  # set by the gate on its own refusals only (it strips it from target answers)
LOCK_MARK = "[bh-lock]"  # prefix of every hook denial, counted by the runner
# Writes the gate allows only under one of our identities (our own objects); the gate and proof checks share it
IDENTITY_ONLY_METHODS = frozenset({"PUT", "PATCH", "DELETE"})
RULES_MARK = "[bh-rules]"  # prefix of a denial imposed by the program's rules
SEVERITIES = ("critical", "high", "medium", "low", "info")  # most severe first
WORK_ROOT = "/work"  # the agent's work volume (var/work on the host)
# Fact kinds the agent may write. "blocker" is not one: the host writes it from `bh-note blocked` and gate events.
FACT_KINDS = ("fact", "recon", "handoff", "dead-end")
# Why a lead is blocked. Nobody unblocks the agent during the hunt: a blocker closes the lead, it pages no one.
BLOCKER_REASONS = (
    "auth",
    "account",
    "waf",
    "captcha",
    "challenge",
    "sms",
    "kyc",
    "login-failed",
    "paid",
    "write-needed",
    "oob-needed",
    "refusal",
    "other",
)
BLOCKER_TTL_S = 7 * 86400  # older blockers leave the frontier: the obstacle may have gone

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
# ...|prefixed random ids such as bk_6c49e125463f (a digit is required, so user_settings stays a word)
ID_SEGMENT = re.compile(
    r"^(\d+|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{16,}|[A-Za-z0-9_-]{24,}|[A-Za-z]{1,8}[_-](?=[A-Za-z0-9]*\d)[A-Za-z0-9]{8,})$",
    re.I,
)


# ------------------------------------------------------------------ locations
def bh_dir() -> Path:
    return Path(os.environ.get("BH_DIR", f"{WORK_ROOT}/.bh"))


def sandbox_dir(program: str) -> str:
    """BH_DIR of `program` as seen inside the agent container."""
    return f"{WORK_ROOT}/{program}/.bh"


def gate() -> str:
    return os.environ.get("BH_GATE", "http://gate:8080")


def is_verifier() -> bool:
    """The independent verifier runs with BH_ROLE=verifier (set for its claude process, not by the agent)."""
    return os.environ.get("BH_ROLE") == "verifier"


def scanners_allowed() -> bool:
    """From the environment claude was started with (the agent's own shell exports do not reach the hooks)."""
    return os.environ.get("BH_SCANNERS", "1") != "0"


def required_phases(scanners: bool | None = None) -> tuple[str, ...]:
    allowed = scanners_allowed() if scanners is None else scanners
    return REQUIRED_PHASES if allowed else tuple(p for p in REQUIRED_PHASES if p in LIGHT_PHASES)


DEFAULT_RPS = 2.0  # req/s towards targets when the program states none (the scope and the gate use this one)


def rps() -> float:
    try:
        return max(0.2, float(os.environ.get("BH_RPS", DEFAULT_RPS)))
    except ValueError:
        return DEFAULT_RPS


# ------------------------------------------------------------------ URLs
def is_passive(host: str) -> bool:
    return host.lower().rstrip(".") in PASSIVE_HOSTS


def host_matches(pattern: str, host: str) -> bool:
    """Same reading as bh.scope.enforce: `*.x` = subdomains of x (not x), `api-*.x` = one label, else exact."""
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.endswith("." + pattern[2:])
    if "*" in pattern:
        label, _, rest = pattern.partition(".")
        h_label, _, h_rest = host.partition(".")
        head, _, tail = label.partition("*")
        return h_rest == rest and re.fullmatch(re.escape(head) + "[a-z0-9-]+" + re.escape(tail), h_label) is not None
    return host == pattern


@dataclass(frozen=True)
class SandboxScope:
    """What bh-browse needs of the scope beyond the page's own host: the `support` hosts it may load (`assets`:
    GET/HEAD; `sso`: the application's silent sign-in; `passthrough`: a third-party anti-bot challenge, never
    intercepted), the other targets of the scope (an API or chat host the page calls) and whether websockets to the
    targets are on. Never a boundary: the gate decides; this only keeps the browser from asking for what the gate
    would refuse anyway, and keeps our identity header away from hosts that must never see it."""

    assets: tuple[str, ...] = ()
    websockets: bool = False
    sso: tuple[str, ...] = ()
    passthrough: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()  # host patterns of the in-scope domain, wildcard and URL rules


SANDBOX_ENV = {  # environment variable -> SandboxScope field (comma-separated host patterns)
    "BH_SUPPORT_ASSETS": "assets",
    "BH_SUPPORT_SSO": "sso",
    "BH_SUPPORT_PASSTHROUGH": "passthrough",
    "BH_TARGET_HOSTS": "targets",
}


def _rule_host(entry) -> str | None:
    """Host pattern of an in-scope rule (`x.com`, `*.x.com`, `https://x.com/api/`), None for a CIDR, repo, other."""
    value = entry.get("value") if isinstance(entry, dict) else entry
    kind = entry.get("type") if isinstance(entry, dict) else None
    if not isinstance(value, str) or kind in ("cidr", "repo", "other"):
        return None
    value = value.strip().lower()
    if "://" in value:
        value = value.split("://", 1)[1].split("/", 1)[0].rsplit(":", 1)[0]
    if not value or "/" in value or re.fullmatch(r"[0-9.]+|\[?[0-9a-f:]+\]?", value):
        return None
    return value.rstrip(".")


def sandbox_scope(path: Path | None = None, env=None) -> SandboxScope:
    """From the environment when the runner sets it (SANDBOX_ENV: comma-separated host patterns, BH_WEBSOCKETS = 1),
    else from the scope.yaml the runner pushes to BH_DIR. Unreadable: nothing extra."""
    env = os.environ if env is None else env
    if any(k in env for k in SANDBOX_ENV) or "BH_WEBSOCKETS" in env:
        lists = {
            f: tuple(h.strip().lower() for h in env.get(k, "").split(",") if h.strip()) for k, f in SANDBOX_ENV.items()
        }
        return SandboxScope(websockets=env.get("BH_WEBSOCKETS") == "1", **lists)
    import yaml  # python3-yaml in the image; only bh-browse asks

    try:
        doc = yaml.safe_load((path or bh_dir() / SCOPE).read_text())
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return SandboxScope()
    if not isinstance(doc, dict):
        return SandboxScope()
    support = doc.get("support") if isinstance(doc.get("support"), list) else []

    def kind(k: str) -> tuple[str, ...]:
        return tuple(
            str(e["value"]).strip().lower().rstrip(".")
            for e in support
            if isinstance(e, dict) and e.get("kind") == k and isinstance(e.get("value"), str)
        )

    ins = doc.get("in_scope") if isinstance(doc.get("in_scope"), list) else []
    targets = tuple(h for h in (_rule_host(e) for e in ins) if h)
    return SandboxScope(kind("assets"), doc.get("websockets") is True, kind("sso"), kind("passthrough"), targets)


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
    segs = [("{id}" if ID_SEGMENT.match(s) else s) for s in (path or "/").split("?")[0].split("/")]
    return "/".join(segs) or "/"


def family(key: str) -> str:
    """Comparable form of an endpoint key. A JS literal ending in `/` (`"/rest/basket/" + id`) is the
    item route `/rest/basket/{id}`; the collection `/api/Users` stays distinct from `/api/Users/{id}`."""
    k = key.split("?", maxsplit=1)[0]
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
    return [p for p in required_phases() if not phase_done(done.get(p))]


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
    untested.sort(key=frontier_order)
    return eps, untested, read_json(d / COVERAGE, {})


# API-looking routes: the gate's enumeration guard and the frontier order both use this one definition
API_PATH = re.compile(r"/(api|rest|graphql|v\d+)(/|$)", re.I)


def is_client_route(key: str, sources: set[str]) -> bool:
    """A path only seen in JavaScript or in the browser and not API-looking: a single-page app route, which only
    a rendered page exercises (an HTTP GET returns the same shell for every route)."""
    return bool(sources) and sources <= {"js", "browse"} and not API_PATH.search(key)


def frontier_order(item: tuple[tuple[str, str], dict]) -> tuple:
    """Untested endpoints first by number of parameters, then API routes, then path."""
    (_, key), info = item
    return -len(info["params"]), not API_PATH.search(key), key


def format_surface(eps: dict, untested: list, cov: dict, phases: tuple[str, ...], limit: int = 12) -> str:
    """The frontier block, shared by the live sandbox view and the host's asset graph (bh.assets)."""
    if not eps and not cov:
        return ""
    out = ["## attack surface (from your tools)"]
    for o, done in cov.items():
        state = " ".join(f"{p}{_phase_mark(done.get(p))}" for p in phases)
        extra = " ".join(p for p in done if p not in phases)
        out.append(f"- {o}: {state}" + (f" · also {extra}" if extra else ""))
    with_params = sum(1 for v in eps.values() if v["params"])
    out.append(
        f"- {len(eps)} endpoints ({with_params} with params), {len(eps) - len(untested)} tested, "
        f"{len(untested)} untested. Next untested:"
    )
    for (o, key), v in untested[:limit]:
        hint = "  → bh-sqli / bh-xss" if phases == REQUIRED_PHASES else "  → test by hand, low rate"
        params = f" ?{','.join(sorted(v['params']))}{hint}" if v["params"] else ""
        if not params and is_client_route(key, v["sources"]):
            params = "  → bh-browse (client-side route: render it, hash routing is /#/path)"
        out.append(f"  - {key}{params}  [{o}; {'+'.join(sorted(v['sources']))}]")
    return "\n".join(out)


def surface(d: Path, limit: int = 12, also_tested: Tested | None = None, phases: tuple[str, ...] | None = None) -> str:
    """Live view from the sandbox files (bh-note frontier); the host renders the same block from its asset graph."""
    eps, untested, cov = _surface_data(d, also_tested)
    return format_surface(eps, untested, cov, phases or required_phases(), limit)


# ------------------------------------------------------------------ command classification (metrics)
# The one table of tools: hooks (program rules, verifier), metrics and builtins all read it.
# bh-browse maps; with --xss it tests (see _BROWSE_XSS). bh-zap maps (spider + passive); with --active it scans.
# bh-authz reads the known endpoints as each identity (a mapper); with --write-own it writes (a scanner, _AUTHZ_WRITE).
MAPPERS = (
    "bh-recon",
    "bh-crawl",
    "bh-browse",
    "bh-zap",
    "bh-authz",
    "katana",
    "subfinder",
    "httpx-toolkit",
    "httpx",
)
SCANNERS = (
    "bh-content",
    "bh-scan",
    "bh-params",
    "bh-sqli",
    "bh-xss",
    "nuclei",
    "sqlmap",
    "ghauri",
    "ffuf",
    "wfuzz",
    "feroxbuster",
    "gobuster",
    "dirsearch",
    "dirb",
    "nikto",
    "wpscan",
    "dalfox",
    "xsstrike",
    "arjun",
    "commix",
    "hydra",
    "medusa",
    "patator",
    "nmap",
    "masscan",
    "naabu",
    "whatweb",
    "wapiti",
    "skipfish",
    "zaproxy",
    "zap.sh",
    "jaeles",
    "x8",
    "paramspider",
    "crlfuzz",
)
_BUILTIN_SCANS = "|".join(t.removeprefix("bh-") for t in SCANNERS if t.startswith("bh-"))


def _words(names: tuple[str, ...]) -> re.Pattern:
    # a tool name as a word, also after a path (/usr/bin/x), an assignment (n=x) or a quote ('x', bash -c 'x')
    alt = "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
    return re.compile(rf"(?<![\w.-])({alt})(?![\w.-])", re.I)


_SCANNER_WORDS = _words(SCANNERS)
_MAPPER_WORDS = _words(MAPPERS)
# builtins called through the entry point, a deep crawl, httpx probing a wordlist of paths: scans too
_SCANNER_EXTRA = re.compile(
    rf"bh-agent\s+({_BUILTIN_SCANS})\b|katana\b[^;&|]*\s-d\s*[4-9]|httpx(-toolkit)?\b[^;&|]*\s-paths?\b"
)
# bh-browse --xss runs payloads: a scanner. Fail closed: --xss anywhere after bh-browse counts.
_BROWSE_XSS = re.compile(r"(?<![\w.-])(bh-browse|bh-agent\s+browse)(?![\w.-])[\s\S]*\s--xss\b")
# bh-zap --active runs ZAP's active scan: a scanner. Same fail-closed reading.
_ZAP_ACTIVE = re.compile(r"(?<![\w.-])(bh-zap|bh-agent\s+zap)(?![\w.-])[\s\S]*\s--active\b")
# bh-authz --write-own sends cross-identity writes: a scanner (programs without scanners refuse it). Same reading.
_AUTHZ_WRITE = re.compile(r"(?<![\w.-])(bh-authz|bh-agent\s+authz)(?![\w.-])[\s\S]*\s--write-own\b")


_SIMPLE_SEP = set(";&|\n()")


def without_commands(cmd: str, names: tuple[str, ...]) -> str:
    """`cmd` minus its simple commands whose first word is in `names` (a bh-note's quoted text is a note, not a
    tool run). Separators and parentheses split commands, so `bh-note x "$(nuclei ...)"` keeps `nuclei ...` as a
    command of its own; text inside other commands' quotes stays (`bash -c 'nuclei ...'` is still seen). An
    unparsable command is returned whole: never less strict."""
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|()<>\n")
    lex.whitespace, lex.whitespace_split, lex.commenters = " \t\r", True, ""
    try:
        tokens = list(lex)
    except ValueError:
        return cmd
    kept: list[list[str]] = [[]]
    for tok in tokens:
        if tok and set(tok) <= _SIMPLE_SEP:
            kept.append([])
        else:
            kept[-1].append(tok)
    rest = [shlex.join(w) for w in kept if w and w[0] not in names]
    return " ; ".join(rest + _substitutions(cmd))


_SUBST_OPEN = re.compile(r"[$<>]\(")


def _substitutions(cmd: str) -> list[str]:
    """Bodies of `$(...)`, process substitutions `<(...)` / `>(...)` and backquotes anywhere in `cmd`, quoted or
    not: bash runs `$(...)` inside double quotes, where a tokenizer sees one word, and a process substitution is a
    command of its own that the tokenizer leaves inside the command it is an argument of (stricter than bash in
    single quotes, never looser)."""
    out, i = [], 0
    while m := _SUBST_OPEN.search(cmd, i):
        depth, j = 1, m.end()
        while j < len(cmd) and depth:
            depth += {"(": 1, ")": -1}.get(cmd[j], 0)
            j += 1
        out.append(cmd[m.end() : j - 1 if not depth else j])
        i = j
    out += re.findall(r"`([^`]*)`", cmd)
    return [b for b in out if b.strip()]


def runs_scanner(cmd: str) -> bool:
    """Enforcement (fail closed): quotes are removed, not their content, so 'nuclei' or bash -c 'ffuf ...' count;
    a note that merely names a scanner is refused too, which is the safe side."""
    bare = cmd.replace("'", " ").replace('"', " ").replace("\\", "")
    return bool(
        _SCANNER_WORDS.search(bare)
        or _SCANNER_EXTRA.search(bare)
        or _BROWSE_XSS.search(bare)
        or _ZAP_ACTIVE.search(bare)
        or _AUTHZ_WRITE.search(bare)
    )


def runs_mapper(cmd: str) -> bool:
    bare = cmd.replace("'", " ").replace('"', " ")
    return bool(_MAPPER_WORDS.search(bare) or re.search(r"bh-agent\s+(recon|crawl|browse|zap|authz)\b", bare))


_MANUAL = re.compile(r"(^|[\s;&|(`])(curl|wget|python3?|node|perl|ruby|nc|ncat|socat|http|xh|qq?)(?=\s|$)")
_HTTP_CLIENT = re.compile(r"^(curl|wget)$")
_Q_CLIENT = re.compile(r"^qq?$")  # bh.agent.q: `/path` arguments use the origin saved in BH_DIR/q-base
_BARE_TARGET = re.compile(r"^([a-z0-9-]+(\.[a-z0-9-]+)+|\[[0-9a-f:]+\])(:\d+)?(/\S*)?$", re.I)


def urls_in(cmd: str) -> list[str]:
    """URLs a command talks to: literal http(s) URLs, scheme-less `host[:port]/path` arguments of curl/wget
    (curl defaults them to http), and `/path` arguments of q/qq on their saved origin."""
    urls = URL_RE.findall(cmd)
    in_client = in_q = False
    q_base = None
    for tok in re.findall(r"[;&|()\n]|[^\s;&|()]+", cmd):
        word = tok.strip("'\"")
        if tok in ";&|()\n":
            in_client = in_q = False
        elif _HTTP_CLIENT.match(word):
            in_client = True
        elif _Q_CLIENT.match(word):
            in_q = True
            q_base = q_base or _q_base()
        elif in_q and "://" in word:
            q_base = origin(word) or q_base
        elif in_q and word.startswith("/") and q_base:
            urls.append(q_base + word)
        elif (
            in_client
            and not word.startswith("-")
            and "://" not in word
            and _BARE_TARGET.match(word)
            and ("/" in word or ":" in word)
        ):
            urls.append("http://" + word)
    return urls


def _q_base() -> str | None:
    try:
        return (bh_dir() / "q-base").read_text().strip() or None
    except OSError:
        return None


def uses_arsenal(cmd: str) -> bool:
    """Metrics: one of our tools ran (callers drop quoted text first, a note naming sqlmap is not a run)."""
    return runs_scanner(cmd) or runs_mapper(cmd)


def uses_manual_http(cmd: str) -> bool:
    return bool(_MANUAL.search(cmd)) and bool(urls_in(cmd))
