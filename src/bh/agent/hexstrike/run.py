"""The three meta-tools: tools_list, tool_help, tool_run.

Origin: HexStrike AI (MIT, Copyright (c) 2026 Muhammad Osama (0x4m4)), hexstrike_mcp.py lines 267-5414 (one MCP
function per tool posting to hexstrike_server.py, which joined the command into a string and ran it in a shell).
Modified: rewritten from scratch around that table. One meta-tool runs any ported tool: every argument is checked
against the tool's parameters, the free `additional_args` is a list of tokens (no shell metacharacter, no proxy,
no rate, no forbidden flag, no write outside the work dir), the command is an argv list run without a shell with a
mandatory timeout (900 s at most). The full output goes under raw/, the model gets 25 lines at most.

A tool that fails gives no lead: its stdout is not summarised, only the last lines of its stderr.
Stdlib only.
"""

from __future__ import annotations

import difflib
import math
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from collections import deque
from pathlib import Path
from urllib.parse import urlsplit

from bh.agent import contract as c
from bh.agent.hexstrike import registry as r

DEFAULT_TIMEOUT = 300
MAX_TIMEOUT = 900
SUMMARY_LINES = 25
LINE_MAX = 300
LIST_PAGE = 50  # rows per tools_list page (with header and footer: under 60 lines)
MAX_TOKENS = 40
TOKEN_MAX = 256
STDERR_LINES = 5

# A token of additional_args with one of these is refused: the tool never sees a shell, a token that needs one
# was written for a shell and means something else here.
META = frozenset(" \t\n\r\x00\x0b\x0c;&|<>$`\\'\"(){}[]*?!#~")
# Flags refused for every tool (names without leading dashes; their unambiguous abbreviations too).
DENY = ("os-shell", "os-cmd", "os-pwn", "tamper", "config", "proxychains")
PROXY_WORDS = ("proxy", "socks")
TOR = ("tor", "tor-port", "tor-type", "check-tor")
# Flags whose value is a file the tool writes: it must stay in the work dir.
OUT_FLAGS = frozenset(
    {
        "o", "output", "output-file", "output-dir", "outdir", "od", "oA", "oN", "oX", "oG", "oJ", "oj", "log",
        "debug-log", "trace-log", "error-log", "srd", "store-response-dir", "me", "markdown-export", "je",
        "jsonl-export", "se", "sarif-export", "Save", "har-file-path", "f",
    }
)  # fmt: skip
URL_SCHEME = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*)://")
HTTP_URL = re.compile(r"https?://[^\s,]*", re.I)
EMBEDDED_PATH = re.compile(r"(?:^|(?<=[=,:@]))(/[^,=:@]*)")
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
HOST = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})*$")
CSV = re.compile(r"^[A-Za-z0-9_.:,+-]*$")
OFFSET = re.compile(r"^\+?(?:0x[0-9A-Fa-f]{1,16}|\d{1,12})$")
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


class Refused(Exception):
    """An argument or a tool refused before anything runs."""


# ------------------------------------------------------------------ places and environment
def work_dir() -> Path:
    """The program's work dir (/work/<program>): BH_DIR's parent."""
    return c.bh_dir().parent


def _roots() -> list[Path]:
    return [work_dir().resolve(), *(Path(p).resolve() for p in r.READ_ROOTS)]


def _inside(p: Path, roots: list[Path]) -> bool:
    return any(p == root or p.is_relative_to(root) for root in roots)


def resolve_path(value: str, base: str = "", write: bool = False) -> Path:
    """Absolute path of `value` (relative to `base` or the work dir), symlinks followed. Reads: work dir or the
    wordlist/template roots; writes: work dir only."""
    p = Path(value)
    if not p.is_absolute():
        p = Path(base or work_dir()) / p
    p = p.resolve()
    roots = [work_dir().resolve()] if write else _roots()
    if not _inside(p, roots):
        where = "the work dir" if write else "the work dir or the wordlist/template directories"
        raise Refused(f"path {value!r} is outside {where}")
    return p


def proxy() -> str:
    """The gate, as the environment gives it (the caller never chooses a proxy)."""
    for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        if os.environ.get(k):
            return os.environ[k]
    return c.gate()


def internal_vars(run_dir: Path) -> dict[str, str]:
    rps = c.rps()
    px = proxy()
    return {
        "_proxy": px,
        "_proxy_hostport": urlsplit(px).netloc or px,
        "_rate": str(max(1, math.floor(rps))),
        "_delay_s": f"{1 / rps:.2f}",
        "_delay_ms": str(max(1, int(1000 / rps))),
        "_run": str(run_dir),
        "_conf": str(run_dir / "conf.toml"),
    }


# ------------------------------------------------------------------ argument checks
def _clean(value: str, what: str, maxlen: int) -> str:
    if len(value) > maxlen:
        raise Refused(f"{what}: longer than {maxlen} characters")
    if any(ch in value for ch in "\n\r\x00") or any(ord(ch) < 32 and ch != "\t" for ch in value):
        raise Refused(f"{what}: line break or control character")
    return value


def _url(value: str, what: str) -> str:
    _clean(value, what, 2048)
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc or any(ch.isspace() for ch in value):
        raise Refused(f"{what}: need an http(s) URL, got {value[:80]!r}")
    return value


def check_param(tool: r.Tool, name: str, value: object):
    """The value to put in the command, or Refused."""
    p, chk = tool.param(name), tool.checks.get(name)
    if p is None:
        raise Refused(f"{tool.name} has no parameter {name!r}")
    if chk is None:
        raise Refused(f"{name}: not supported by this port")
    what, k = f"{tool.name}.{name}", chk.kind
    if k == "args":
        return value
    if k == "locked":
        if value != p.default:
            raise Refused(f"{what}: fixed to {p.default!r} ({chk.note})")
        return value
    if k == "bool":
        if not isinstance(value, bool):
            raise Refused(f"{what}: need true or false")
        return value
    if k == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            if isinstance(value, str) and value.isdigit() and len(value) < 10:
                value = int(value)
            else:
                raise Refused(f"{what}: need an integer")
        if not chk.lo <= value <= chk.hi:
            raise Refused(f"{what}: between {chk.lo} and {chk.hi}")
        return value
    if isinstance(value, int) and not isinstance(value, bool) and k == "offset":
        value = str(value)
    if not isinstance(value, str):
        raise Refused(f"{what}: need a string")
    if value == "" and p.default == "":
        return ""
    if k == "url":
        return _url(value, what)
    if k == "host":
        if not HOST.match(value):
            raise Refused(f"{what}: need a domain name, got {value[:80]!r}")
        return value.lower()
    if k == "hosts":
        items = [x.strip() for x in _clean(value, what, chk.maxlen).split(",") if x.strip()]
        if not items or len(items) > 50:
            raise Refused(f"{what}: 1 to 50 comma-separated hosts or URLs")
        for x in items:
            if "://" in x:
                _url(x, what)
            elif not HOST.match(x.rsplit(":", 1)[0] if re.search(r":\d{1,5}$", x) else x):
                raise Refused(f"{what}: {x[:80]!r} is neither a host nor an http(s) URL")
        return ",".join(items)
    if k == "path":
        return str(resolve_path(_clean(value, what, 1024), chk.base))
    if k == "offset":
        if not OFFSET.match(value):
            raise Refused(f"{what}: need a decimal or 0x number")
        return value
    if k == "csv":
        _clean(value, what, chk.maxlen)
        if not CSV.match(value) or value.startswith("-"):
            raise Refused(f"{what}: comma-separated words only")
        if chk.choices:
            bad = [x for x in value.split(",") if x and x not in chk.choices]
            if bad:
                raise Refused(f"{what}: {', '.join(bad)} not allowed (allowed: {', '.join(chk.choices)})")
        return value
    if k == "choice":
        if value not in chk.choices:
            raise Refused(f"{what}: one of {', '.join(repr(x) for x in chk.choices)}")
        return value
    return _clean(value, what, chk.maxlen)  # text


def _flag_hit(name: str, denied: tuple[str, ...]) -> str | None:
    """The denied flag `name` stands for: itself, or an abbreviation of it (getopt, argparse, Perl, Ruby)."""
    for d in denied:
        if name == d or (len(name) >= 2 and d.startswith(name)):
            return d
    return None


def _check_value_path(token: str, value: str, write: bool) -> None:
    """A file the tool writes stays in the work dir; any other URL is http(s); any absolute path in the token (whole,
    or after `=`, `,`, `:` or `@`, as in `file,/etc/passwd`) is in the work dir or a wordlist/template root."""
    if not value:
        return
    if write:
        resolve_path(value, write=True)
        return
    for scheme in URL_SCHEME.findall(value):
        if scheme.lower() not in ("http", "https"):
            raise Refused(f"{token!r}: only http(s) URLs")
    rest = HTTP_URL.sub(" ", value)
    for path in EMBEDDED_PATH.findall(rest):
        resolve_path(path)
    if ".." in rest:
        resolve_path(rest)


def check_args(tool: r.Tool, tokens: object) -> list[str]:
    """additional_args: a list of tokens, each checked; refused as a whole on the first bad token."""
    if tokens in (None, "", []):
        return []
    if not isinstance(tokens, list):
        raise Refused('additional_args: a list of tokens, e.g. ["-mc", "200"], not a command line')
    if not tool.free_args:
        raise Refused(f"{tool.name}: no additional_args for this tool")
    if len(tokens) > MAX_TOKENS:
        raise Refused(f"additional_args: {MAX_TOKENS} tokens at most")
    denied = DENY + tool.deny
    out: list[str] = []
    expect_out = False
    for i, t in enumerate(tokens):
        if not isinstance(t, str) or not t or len(t) > TOKEN_MAX:
            raise Refused(f"additional_args[{i}]: a non-empty string of {TOKEN_MAX} characters at most")
        if any(ch in META for ch in t) or not t.isprintable():
            raise Refused(f"additional_args[{i}] {t[:60]!r}: shell metacharacter or space (one token per element)")
        if t.startswith("@"):
            raise Refused(f"additional_args[{i}] {t[:60]!r}: argument files are refused")
        if expect_out:
            _check_value_path(t, t, write=True)
            expect_out = False
        elif t.startswith("-") and len(t) > 1:
            name, eq, value = t.lstrip("-").partition("=")
            low = name.lower()
            if any(w in low for w in PROXY_WORDS) or low in TOR or low.startswith("tor-"):
                raise Refused(f"{t!r}: the proxy comes from the environment (the gate)")
            hit = _flag_hit(name, denied)
            if hit:
                raise Refused(f"{t!r}: flag refused for {tool.name} ({hit})")
            if tool.posix and not t.startswith("--") and len(name) > 1:
                # -dVALUE is -d VALUE, -ab is -a -b: the first letter, and every letter of a bundle, is a flag
                letters = name if name.isalpha() else name[0]
                bad = [x for x in letters if x in denied]
                if bad:
                    raise Refused(f"{t!r}: flag refused for {tool.name} (-{bad[0]})")
                if name[0] in OUT_FLAGS and not name.isalpha():
                    _check_value_path(t, name[1:] + (eq + value), write=True)
            if len(name) >= 2 and "risk".startswith(name):
                v = value or (tokens[i + 1] if i + 1 < len(tokens) else "")
                if not (isinstance(v, str) and v.isdigit() and int(v) <= 1):
                    raise Refused(f"{t!r}: risk above 1 is refused")
            if tool.binary == "sqlmap" and len(name) >= 4 and "technique".startswith(name):
                v = value or (tokens[i + 1] if i + 1 < len(tokens) else "")
                if not (isinstance(v, str) and v and not set(v.upper()) - set("BEU")):
                    raise Refused(f"{t!r}: techniques B, E and U only")
            if name in OUT_FLAGS:
                if eq:
                    _check_value_path(t, value, write=True)
                else:
                    expect_out = True
            elif eq:
                _check_value_path(t, value, write=False)
        else:
            _check_value_path(t, t, write=False)
        out.append(t)
    if expect_out:
        raise Refused("additional_args: an output flag without its file")
    return out


def check_call(tool: r.Tool, args: object) -> dict:
    """Every argument checked; omitted ones take the run default (Tool.overrides) or the signature default."""
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise Refused("args: an object {parameter: value}")
    unknown = [k for k in args if tool.param(k) is None]
    if unknown:
        known = ", ".join(p.name for p in tool.params)
        raise Refused(f"{tool.name}: unknown parameter(s) {', '.join(map(str, unknown))} (known: {known})")
    values: dict = {}
    for p in tool.params:
        if p.name in args:
            values[p.name] = check_param(tool, p.name, args[p.name])
        elif p.required:
            raise Refused(f"{tool.name}: {p.name} is required")
        elif p.name in tool.overrides:
            values[p.name] = check_param(tool, p.name, tool.overrides[p.name])
        else:
            chk = tool.checks.get(p.name)
            values[p.name] = (
                p.default if chk is None or chk.kind in ("args", "locked") else check_param(tool, p.name, p.default)
            )
    if tool.need_one and not any(values.get(n) for n in tool.need_one):
        raise Refused(f"{tool.name}: give one of {', '.join(tool.need_one)}")
    values["additional_args"] = check_args(tool, args.get("additional_args"))
    return values


# ------------------------------------------------------------------ command
def render(tool: r.Tool, values: dict, internal: dict[str, str]) -> list[str]:
    """argv from the template: each element stays one token, whatever the values hold."""
    env = {**{k: v for k, v in values.items() if k != "additional_args"}, **internal}
    extra = list(values.get("additional_args") or [])
    out: list[str] = []
    placed = False
    for template in tool.argv:
        if template == "{additional_args}":
            out += extra
            placed = True
            continue
        tok = template
        m = r.GUARD.match(template)
        if m:
            neg, name, eq, rest = m.groups()
            v = env.get(name)
            keep = (str(v) == eq) if eq is not None else bool(v)
            if keep == bool(neg):
                continue
            tok = rest

        def sub(mm: re.Match, tok: str = tok) -> str:
            v = env[mm.group(1)]
            s = str(v)
            if tok.startswith(mm.group(0)) and s.startswith("-"):
                raise Refused(f"{mm.group(1)}: a value may not start with '-' (it would read as an option)")
            return s

        value = r.VAR.sub(sub, tok)
        if value:
            out.append(value)
    if not placed:
        out += extra
    return out


def summarize(path: Path, limit: int = SUMMARY_LINES) -> tuple[list[str], int]:
    """(at most `limit` lines: head and tail, total non-empty lines)."""
    half = (limit - 1) // 2
    head: list[str] = []
    tail: deque[str] = deque(maxlen=limit - 1 - half)
    n = 0
    if not path.exists():
        return [], 0
    with open(path, errors="replace") as fh:
        for raw in fh:
            line = ANSI.sub("", raw).rstrip()
            if not line.strip():
                continue
            n += 1
            line = line[:LINE_MAX]
            if len(head) < half:
                head.append(line)
            else:
                tail.append(line)
    if n <= limit:
        return head + list(tail), n
    return [*head, f"... {n - len(head) - len(tail)} more lines in the raw output ...", *tail], n


def _refusal(tool: r.Tool) -> str | None:
    if tool.klass == "refused":
        return f"{tool.name} is refused: {tool.why}"
    if tool.klass == "no-route":
        return f"{tool.name} has no route here: {tool.why}"
    if tool.klass == "scanner" and not c.scanners_allowed():
        return f"{c.RULES_MARK} {tool.name} is a scanner and this program forbids automated scanners"
    if not tool.ported:
        return f"{tool.name} is listed but {tool.why}"
    return None


def tool_run(name: object, args: object = None, timeout: object = None) -> dict:
    """Run one ported tool. Returns {ok, partial, rc, argv, lines, summary, raw} or {ok: False, refused}."""
    tool = r.TOOLS.get(name) if isinstance(name, str) else None
    if tool is None:
        return {"ok": False, "refused": f"unknown tool {name!r}: see tools_list"}
    why = _refusal(tool)
    if why:
        return {"ok": False, "tool": tool.name, "class": tool.klass, "refused": why}
    if timeout is None:
        timeout = DEFAULT_TIMEOUT
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= MAX_TIMEOUT:
        return {"ok": False, "tool": tool.name, "refused": f"timeout: an integer from 1 to {MAX_TIMEOUT} seconds"}
    try:
        values = check_call(tool, args)
        exe = shutil.which(tool.binary)
        if not exe:
            raise Refused(f"{tool.binary} is not installed in this sandbox")
        raw_root = c.bh_dir() / c.RAW
        raw_root.mkdir(parents=True, exist_ok=True)
        run_dir = Path(tempfile.mkdtemp(prefix=f"hexstrike-{tool.name}-", dir=raw_root))
        internal = internal_vars(run_dir)
        argv = [exe, *render(tool, values, internal)[1:]]
        stdin = render_stdin(tool, values, internal)
    except Refused as e:
        return {"ok": False, "tool": tool.name, "class": tool.klass, "refused": str(e)}
    if tool.conf:
        (run_dir / "conf.toml").write_text(tool.conf)
    (run_dir / "cmd.txt").write_text(shlex.join(argv) + "\n")
    work_dir().mkdir(parents=True, exist_ok=True)
    out, err = run_dir / "stdout.txt", run_dir / "stderr.txt"
    partial, rc = False, None
    with open(out, "w") as fo, open(err, "w") as fe:
        try:
            done = subprocess.run(
                argv,
                shell=False,
                timeout=timeout,
                stdout=fo,
                stderr=fe,
                input=stdin if stdin else None,
                stdin=None if stdin else subprocess.DEVNULL,
                text=True,
                cwd=work_dir(),
                env={**os.environ, "NO_COLOR": "1"},
            )
            rc = done.returncode
        except subprocess.TimeoutExpired:
            partial = True
        except OSError as e:
            fe.write(f"{e}\n")
            rc = 127
    ok = rc == 0
    lines, n = summarize(out) if ok or partial else ([], 0)
    mapped = record_map(tool, values, out, ok=ok, partial=partial, raw=run_dir) if ok or partial else None
    if mapped is not None and mapped["lines"] is not None:  # raw JSONL requests cost tokens: their endpoints say it
        lines = mapped["lines"]
    res = {
        "ok": ok,
        "partial": partial,
        "rc": rc,
        "tool": tool.name,
        "class": tool.klass,
        "argv": argv,
        "lines": n,
        "summary": lines,
        "raw": str(run_dir),
    }
    if not ok:
        res["stderr"] = summarize(err, STDERR_LINES)[0][-STDERR_LINES:]
    return res


_URL = re.compile(r"https?://[^\s\"'<>\\]+")
CRAWLERS = frozenset({"katana", "hakrawler", "gospider"})  # binaries whose run is the origin's crawl phase
PARTIAL = "error: partial (timeout)"  # bh.agent.tools.PARTIAL_STATUS: a cut run is not a done phase


def _found(out: Path) -> tuple[list[tuple[str, str]], bool]:
    """((method, url) of every endpoint a mapper printed, whether it printed JSONL requests): a JSONL request
    ({"request": {"method", "endpoint"}}), or any http(s) URL in a text line."""
    found: list[tuple[str, str]] = []
    structured = False
    try:
        text = out.read_text(errors="replace")
    except OSError:
        return found, structured
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("{"):
            try:
                doc = json.loads(line)
            except ValueError:
                doc = None
            req = doc.get("request") if isinstance(doc, dict) else None
            if isinstance(req, dict) and isinstance(req.get("endpoint"), str):
                found.append((str(req.get("method") or "GET").upper(), req["endpoint"]))
                structured = True
                continue
        found += [("GET", u.rstrip(".,;)]")) for u in _URL.findall(line)]
    return found, structured


def record_map(tool: r.Tool, values: dict, out: Path, *, ok: bool, partial: bool, raw: Path) -> dict | None:
    """What a mapper found goes where bh-crawl's does (lab, 2026-11-27: a katana crawl through MCP left the board's
    crawl phase at ✗): the target origin's new endpoints in ENDPOINTS, and the crawl phase for a crawler. Returns
    {"new", "lines"} (endpoint lines for the summary), None for a tool that is no mapper or has no http(s) target."""
    if tool.klass != "mapper":
        return None
    origin = c.origin(str(values.get("url") or ""))
    if not origin:
        return None
    d = c.bh_dir()
    known = {(e.get("origin"), e.get("key")) for e in c.read_jsonl(d / c.ENDPOINTS)}
    recs, seen = [], []
    found, structured = _found(out)
    for method, url in found:
        k = c.endpoint_key(url, method)
        if not k or k[0] != origin or c.STATIC_EXT.search(k[1]):
            continue
        seen.append(f"{method} {url}"[:300])
        if k in known:
            continue
        known.add(k)
        recs.append({"origin": k[0], "key": k[1], "url": url, "params": [], "status": None,
                     "source": f"hexstrike:{tool.name}"})  # fmt: skip
    if recs:
        c.append_jsonl(d / c.ENDPOINTS, *recs)
    if tool.binary in CRAWLERS:
        c.record_phase(d, origin, "crawl", status="ok" if ok else PARTIAL, count=len(recs), raw=str(raw))
    uniq = list(dict.fromkeys(seen))
    head = f"{len(uniq)} endpoint(s) of {origin}, {len(recs)} new (recorded as bh-crawl's); full output: {raw}"
    # JSONL requests (katana -jsonl) are long and repetitive: their endpoints replace them; a text output stays as is
    return {"new": len(recs), "lines": [head, *uniq[: SUMMARY_LINES - 1]] if structured else None}


def render_stdin(tool: r.Tool, values: dict, internal: dict[str, str]) -> str:
    if not tool.stdin:
        return ""
    env = {**values, **internal}
    return r.VAR.sub(lambda m: str(env[m.group(1)]), tool.stdin)


# ------------------------------------------------------------------ list and help
def _binary_state(tool: r.Tool) -> str:
    if not tool.binary:
        return "n/a"
    return "present" if shutil.which(tool.binary) else "absent"


def tools_list(category: object = None, page: object = 1) -> str:
    cats = r.categories()
    if category not in (None, "") and category not in cats:
        return f"unknown category {category!r}; categories: {', '.join(cats)}"
    rows = sorted(
        (t for t in r.TOOLS.values() if category in (None, "") or t.category == category), key=lambda t: t.name
    )
    pages = max(1, math.ceil(len(rows) / LIST_PAGE))
    if isinstance(page, bool) or not isinstance(page, int) or not 1 <= page <= pages:
        return f"page: an integer from 1 to {pages}"
    chunk = rows[(page - 1) * LIST_PAGE : page * LIST_PAGE]
    scope = f" in {category}" if category else ""
    out = [f"{len(rows)} HexStrike tools{scope}, page {page}/{pages}: name | class | ported | category | binary"]
    for t in chunk:
        state = "ported" if t.ported else "-"
        out.append(f"{t.name} | {t.klass} | {state} | {t.category} | {t.binary or '-'} {_binary_state(t)}")
    if page < pages:
        out.append(f"more: tools_list(page={page + 1}{f', category={category!r}' if category else ''})")
    out.append(f"categories: {', '.join(cats)}. Details: tool_help(name). Run: tool_run(name, args).")
    return "\n".join(out)


_SAMPLE = {
    "url": "https://app.example.com/",
    "host": "example.com",
    "hosts": "https://app.example.com",
    "path": "sample.txt",
    "text": "x",
    "csv": "",
    "offset": "0",
}


def example(tool: r.Tool) -> dict:
    """A safe call: required parameters only (sample values on example hosts), plus the tool's own example."""
    ex: dict = {}
    for p in tool.params:
        if p.required:
            chk = tool.checks.get(p.name)
            ex[p.name] = _SAMPLE.get(chk.kind if chk else "text", "x")
    ex.update(tool.example)
    return ex


def _describe(tool: r.Tool, p: r.Param) -> str:
    chk = tool.checks.get(p.name)
    d = "required" if p.required else f"default {p.default!r}"
    if p.name in tool.overrides:
        d += f", run default {tool.overrides[p.name]!r}"
    s = f"  {p.name}: {p.type}, {d}"
    if not tool.ported:
        return s
    if chk is None:
        return s + " (not supported)"
    k = chk.kind
    if k == "args" and not tool.free_args:
        return s + "; not accepted by this port"
    if k == "args":
        return s + "; a list of tokens, one per element, no shell metacharacter, no proxy/rate/output-outside flag"
    if k == "locked":
        return s + f"; fixed ({chk.note})"
    if k == "int":
        return s + f"; {chk.lo}..{chk.hi}"
    if k in ("choice", "csv") and chk.choices:
        return s + f"; {'one' if k == 'choice' else 'some'} of {', '.join(repr(x) for x in chk.choices)}"
    if k == "path":
        return s + "; a path in the work dir or the wordlist/template directories"
    return s + f"; {k}"


def tool_help(name: object) -> str:
    tool = r.TOOLS.get(name) if isinstance(name, str) else None
    if tool is None:
        near = difflib.get_close_matches(str(name), list(r.TOOLS), n=5)
        return f"unknown tool {name!r}" + (f"; close: {', '.join(near)}" if near else "; see tools_list")
    state = "ported" if tool.ported else "not ported"
    out = [
        f"{tool.name} ({tool.klass}, {state}, {tool.category}; HexStrike hexstrike_mcp.py:{tool.origin})",
        tool.help,
    ]
    if tool.why:
        out.append(tool.why)
    if tool.klass == "scanner":
        out.append("scanner: refused when the program forbids automated scanners.")
    out.append(f"binary: {tool.binary or '-'} ({_binary_state(tool)})")
    if tool.klass in ("refused", "no-route"):
        out.append(f"parameters: {len(tool.params)}, not shown (the tool cannot run here)")
    else:
        out.append("parameters:" if tool.params else "parameters: none")
        out += [_describe(tool, p) for p in tool.params]
    if tool.ported:
        ex = example(tool)
        out.append(f"example: tool_run(name={tool.name!r}, args={ex!r}, timeout={DEFAULT_TIMEOUT})")
        try:
            argv = render(tool, check_call(tool, ex), internal_vars(Path("<raw>")))
            out.append(f"runs: {shlex.join(argv)}")
        except Refused as e:  # the example names a file of the work dir that the check could not place
            out.append(f"(example not checkable here: {e})")
        out.append(f"output: 25 lines at most here, the full output under raw/; timeout {MAX_TIMEOUT} s at most.")
    return "\n".join(out)
