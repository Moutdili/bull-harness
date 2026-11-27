"""bh-recall: ask the lineage what it already knows, before testing an idea (stdlib only).

  bh-recall "<idea>" [--url U] [--class C] [--k N]   search: exact cell (with --url and --class), then full text
  bh-recall --map [route prefix]                     state of every cell: settled, open, candidate, stale
  bh-recall --cell <key>                             the items of one cell, strongest first
  bh-recall --run <n>                                what agent n left (its run summary)
  bh-recall --chain [n]                              the last n blocks of the lineage
  bh-recall --full <id>                              one item in full
  bh-recall --history <key>                          the items a cell replaced
  bh-recall --techniques "<idea>"                    technique cards the host drew from verified findings elsewhere

The sandbox has no database: this writes a request file in BH_DIR/recall/req/, the host answers in
BH_DIR/recall/res/ (bh.lineage.serve), and the answer is printed. No answer within WAIT_S seconds: it says so and
exits 0. A recall informs, it never forbids a test: cite its receipt with `bh-note intent ... --recall R-<id>`.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import secrets
import sys
import time
from pathlib import Path

from bh.agent import contract as c

WAIT_S = 8.0
POLL_S = 0.1
UNAVAILABLE = "recall UNAVAILABLE (test anyway; pass --recall none)"
MODES = ("map", "cell", "run", "chain", "full", "history", "techniques")
LIMITS = {"query": 500, "url": 2000, "class": 100, "arg": 500}  # the host checks them again


def base_dir() -> Path:
    return c.bh_dir() / "recall"


def _dirs(base: Path) -> tuple[Path, Path]:
    """req/ and res/, open to the host's user: under rootless podman the host is not the sandbox user, and it must
    delete a request and write an answer here."""
    req, res = base / "req", base / "res"
    for d in (base, req, res):
        d.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(d, 0o777)
    return req, res


def ask(request: dict, *, wait: float | None = None, base: Path | None = None) -> str | None:
    """Send one request, return the host's answer, or None when none came in time."""
    base = base or base_dir()
    wait = WAIT_S if wait is None else wait
    try:
        req, res = _dirs(base)
        rid = secrets.token_hex(8)
        doc = {"id": rid, **request}
        tmp = req / f".{rid}.tmp"
        tmp.write_text(json.dumps(doc))
        os.replace(tmp, req / f"{rid}.json")
    except OSError:
        return None
    out = res / f"{rid}.txt"
    end = time.monotonic() + wait
    while time.monotonic() < end:
        try:
            text = out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            time.sleep(POLL_S)
            continue
        with contextlib.suppress(OSError):
            out.unlink()
        return text
    with contextlib.suppress(OSError):
        (req / f"{rid}.json").unlink()  # too late: the host need not answer it any more
    return None


def parse(args: list[str]) -> dict:
    p = argparse.ArgumentParser(prog="bh-recall", description="What the lineage already knows (see bh-recall -h).")
    p.add_argument("idea", nargs="?", help="the idea, in a few words (search)")
    p.add_argument("--url", help="the endpoint: URL or 'METHOD URL' (with --class: exact cell)")
    p.add_argument("--class", dest="vuln_class", help="vulnerability class (idor, xss, ...)")
    p.add_argument("--k", type=int, help="cells shown, 1 to 20")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--map", nargs="?", const="", metavar="PREFIX", help="state of the cells (optional route prefix)")
    g.add_argument("--cell", metavar="KEY", help="items of one cell")
    g.add_argument("--run", metavar="N", help="run summary of agent N")
    g.add_argument("--chain", nargs="?", const="", metavar="N", help="last N blocks of the lineage")
    g.add_argument("--full", metavar="ID", help="one item in full")
    g.add_argument("--history", metavar="KEY", help="replaced items of a cell")
    g.add_argument("--techniques", metavar="IDEA", help="technique cards (methods, no program names) for an idea")
    a = p.parse_args(args)
    mode = next((m for m in MODES if getattr(a, m) is not None), "search")
    if mode == "search" and not (a.idea or "").strip():
        p.error("give the idea to search, or one of --map --cell --run --chain --full --history --techniques")
    if mode == "techniques" and not a.techniques.strip():
        p.error("--techniques needs the idea, in a few words")
    if mode != "search" and (a.idea or a.url or a.vuln_class or a.k is not None):
        p.error(f"--{mode} takes no idea, --url, --class or --k")
    if a.k is not None and not 1 <= a.k <= 20:
        p.error("--k is from 1 to 20")
    req = {
        "mode": mode,
        "query": a.idea if mode == "search" else None,
        "url": a.url,
        "class": a.vuln_class,
        "k": a.k,
        "arg": getattr(a, mode) if mode != "search" else None,
    }
    for f, n in LIMITS.items():
        if isinstance(req[f], str) and len(req[f]) > n:
            p.error(f"{'idea' if f == 'query' else f} is longer than {n} characters")
    return req


def main(args: list[str]) -> None:
    text = ask(parse(args))
    print((text or UNAVAILABLE).rstrip("\n"))
    sys.exit(0)
