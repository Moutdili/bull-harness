"""Cache of passive calls (T47): a third-party answer already read is read again from raw/, not asked again.

  get(program, tool, args, scope_hash) -> raw path | None
  put(program, tool, args, scope_hash, raw_path, ttl_s)

Entries live under the program's `.bh` (BH_DIR when it is that program's, else /work/<program>/.bh), in
`cache/<tool>/<sha256>.json`: {ts, ttl, raw}. The key is the tool, its arguments and the scope's hash (a new scope
asks again). An entry is good while `ts + ttl` is ahead and its raw file still exists; the raw file must sit under the
program's `.bh/raw/` (put refuses anything else, get ignores it).

Never for a request to a target: put refuses any tool outside CACHE_TOOLS (`docs`, `cve`, `recon-archive`), which
only read third-party sources (Context7, the NVD, the URL archives).

Stdlib only, nothing outside bh.agent.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from pathlib import Path

from bh.agent import contract as c

CACHE_TOOLS = ("docs", "cve", "recon-archive")
CACHE_DIR = "cache"
DAY_S = 24 * 3600  # bh-docs and bh-cve keep an answer this long
TTL_MAX_S = 7 * DAY_S
_PROGRAM = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}")


def program_dir(program: str) -> Path:
    """The program's `.bh`: BH_DIR when it belongs to `program`, else /work/<program>/.bh."""
    if not isinstance(program, str) or not _PROGRAM.fullmatch(program) or ".." in program:
        raise ValueError(f"cache: bad program name {str(program)[:40]!r}")
    d = c.bh_dir()
    return d if d.parent.name == program else Path(c.sandbox_dir(program))


def key(tool: str, args, scope_hash: str) -> str:
    blob = json.dumps([tool, [str(a) for a in args], str(scope_hash or "")], ensure_ascii=False)
    return hashlib.sha256(blob.encode()).hexdigest()


def scope_hash(path: Path | None = None) -> str:
    """sha256 of the scope file the runner pushed (BH_DIR/scope.yaml), "" without one."""
    try:
        return hashlib.sha256((path or c.bh_dir() / c.SCOPE).read_bytes()).hexdigest()
    except OSError:
        return ""


def _entry(program: str, tool: str, args, scope_hash_: str) -> Path:
    if tool not in CACHE_TOOLS:
        raise ValueError(f"cache: {tool!r} is not a passive tool ({', '.join(CACHE_TOOLS)})")
    return program_dir(program) / CACHE_DIR / tool / f"{key(tool, args, scope_hash_)}.json"


def _under_raw(program: str, raw: Path) -> bool:
    try:
        root = (program_dir(program) / c.RAW).resolve()
        return raw.resolve().is_relative_to(root)
    except (OSError, ValueError):
        return False


def get(program: str, tool: str, args, scope_hash: str) -> str | None:
    """The raw path of a fresh entry, None otherwise (unknown tool, expired, missing or misplaced raw file)."""
    try:
        f = _entry(program, tool, args, scope_hash)
    except ValueError:
        return None
    rec = c.read_json(f, None)
    if not isinstance(rec, dict):
        return None
    ts, ttl, raw = rec.get("ts"), rec.get("ttl"), rec.get("raw")
    if not isinstance(ts, (int, float)) or not isinstance(ttl, (int, float)) or not isinstance(raw, str):
        return None
    if ts + min(ttl, TTL_MAX_S) <= time.time() or ts > time.time() + 60:
        return None
    p = Path(raw)
    if not p.is_file() or not _under_raw(program, p):
        return None
    return str(p)


def put(program: str, tool: str, args, scope_hash: str, raw_path, ttl_s: float) -> None:
    """Keep `raw_path` as the answer to (tool, args, scope_hash) for `ttl_s` seconds (TTL_MAX_S at most). Raises
    ValueError for a tool outside CACHE_TOOLS, a raw file outside the program's raw/ or a bad TTL."""
    f = _entry(program, tool, args, scope_hash)
    raw = Path(raw_path)
    if not raw.is_file() or not _under_raw(program, raw):
        raise ValueError(f"cache: {str(raw)[:120]} is not a file under the program's {c.RAW}/")
    if not isinstance(ttl_s, (int, float)) or ttl_s <= 0:
        raise ValueError("cache: ttl_s is a positive number of seconds")
    c.write_json(f, {"ts": round(time.time(), 3), "ttl": min(float(ttl_s), TTL_MAX_S), "raw": str(raw.resolve())})


def raw_file(program: str, stem: str, text: str, suffix: str = ".txt") -> Path:
    """Write `text` as the program's raw/<stem>-<time>-<pid>-<hash><suffix> (owner-only) and return its path."""
    d = program_dir(program) / c.RAW
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{stem}-{int(time.time())}-{os.getpid()}-{hashlib.sha1(text.encode()).hexdigest()[:8]}{suffix}"
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return p
