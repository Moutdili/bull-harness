"""bh-flows: the traffic of the run in progress, as the gate logged it (stdlib only, read-only).

  bh-flows [--grep RE] [--status N] [--method M] [--as ID] [-n N]

One line per flow, newest last: `<id> <method> <status> <size> [<identity>] <url>`. The host writes the index
(BH_DIR/flows.idx.jsonl) at the start of every leg from the gate's journal, which lives outside the sandbox: URLs are
redacted (bh.redact.url), at most INDEX_MAX lines. This command never writes anything and never prints more than
MAX_LINES lines. `--grep` is a Python regular expression searched in the method and URL, under a time limit.
A flow id goes to `bh-note ... --flow <id>`.
"""

from __future__ import annotations

import argparse
import re
import signal
import sys
from collections.abc import Iterable
from pathlib import Path

from bh.agent import contract as c

INDEX = "flows.idx.jsonl"  # under BH_DIR; written by the host (bh.runner.run.write_flows_index)
INDEX_MAX = 2000  # lines the host keeps in the index (the newest)
FIELDS = ("id", "ts", "method", "url", "status", "size", "identity")
MAX_LINES = 30  # printed at most, whatever -n says
GREP_MAX = 200  # characters of a --grep pattern
GREP_BUDGET_S = 2.0  # wall time of every --grep match together
URL_SHOWN = 240


class _Timeout(Exception):
    pass


def index_path() -> Path:
    return c.bh_dir() / INDEX


def read_index(path: Path) -> list[dict]:
    """The index rows that have the expected shape; anything else is skipped (the file sits in the work tree)."""
    out = []
    for rec in c.read_jsonl(path):
        if not isinstance(rec, dict) or not isinstance(rec.get("id"), str) or not isinstance(rec.get("url"), str):
            continue
        out.append(rec)
    return out[-INDEX_MAX:]


def parse(args: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="bh-flows", description="The run's traffic, as the gate logged it.")
    p.add_argument("--grep", metavar="RE", help="regular expression searched in `METHOD URL`")
    p.add_argument("--status", type=int, metavar="N", help="HTTP status (e.g. 403)")
    p.add_argument("--method", metavar="M", help="HTTP method (e.g. POST)")
    p.add_argument("--as", dest="identity", metavar="ID", help="identity the gate attached (`none`: no identity)")
    p.add_argument("-n", type=int, default=MAX_LINES, metavar="N", help=f"lines (at most {MAX_LINES})")
    return p.parse_args(args)


def _status(rec: dict) -> int | None:
    v = rec.get("status")
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _keep(rec: dict, ns: argparse.Namespace) -> bool:
    if ns.status is not None and _status(rec) != ns.status:
        return False
    if ns.method and str(rec.get("method") or "").upper() != ns.method.upper():
        return False
    if ns.identity:
        ident = rec.get("identity") or "none"
        if str(ident) != ns.identity:
            return False
    return True


def _on_alarm(_sig, _frame):
    raise _Timeout


def grep(rows: Iterable[dict], pattern: re.Pattern, budget_s: float = GREP_BUDGET_S) -> tuple[list[dict], bool]:
    """(rows whose `METHOD URL` matches, timed_out). One time budget for the whole search (SIGALRM: the regex engine
    checks signals), so a pattern that backtracks without end costs at most `budget_s`."""
    out: list[dict] = []
    old = signal.signal(signal.SIGALRM, _on_alarm)
    signal.setitimer(signal.ITIMER_REAL, budget_s)
    try:
        for rec in rows:
            if pattern.search(f"{rec.get('method') or ''} {rec['url']}"[:4000]):
                out.append(rec)
    except _Timeout:
        return out, True
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)
    return out, False


def line(rec: dict) -> str:
    status = _status(rec)
    size = rec.get("size")
    size = size if isinstance(size, int) and not isinstance(size, bool) else "-"
    ident = rec.get("identity")
    url = re.sub(r"[\x00-\x1f\x7f]", "?", rec["url"])  # one flow, one line: a target controls part of the URL
    if len(url) > URL_SHOWN:
        url = url[: URL_SHOWN - 1] + "…"
    who = f" [{re.sub(r'[^A-Za-z0-9_.-]', '?', str(ident))[:40]}]" if ident else ""
    method = str(rec.get("method") or "?")[:10]
    return f"{rec['id'][:40]} {method} {status if status is not None else '-'} {size}{who} {url}"


def render(rows: list[dict], ns: argparse.Namespace) -> tuple[list[str], str]:
    """(lines, a note for stderr or "")."""
    note = ""
    rows = [r for r in rows if _keep(r, ns)]
    if ns.grep is not None:
        if len(ns.grep) > GREP_MAX:
            return [], f"bh-flows: --grep longer than {GREP_MAX} characters"
        try:
            pattern = re.compile(ns.grep, re.I)
        except re.error as exc:
            return [], f"bh-flows: bad --grep: {exc}"
        rows, timed_out = grep(rows, pattern)
        if timed_out:
            note = f"bh-flows: --grep stopped after {GREP_BUDGET_S:g}s, the matches so far are shown"
    n = max(1, min(int(ns.n or MAX_LINES), MAX_LINES))
    total = len(rows)
    shown = [line(r) for r in rows[-n:]]
    if total > n:
        note = (note + "\n" if note else "") + f"bh-flows: {total} flows match, the last {n} are shown"
    return shown, note


def main(args: list[str]) -> None:
    ns = parse(args)
    path = index_path()
    if not path.is_file():
        print("bh-flows: no traffic index yet (the host writes it at the start of every leg)", file=sys.stderr)
        sys.exit(0)
    shown, note = render(read_index(path), ns)
    if note:
        print(note, file=sys.stderr)
    if shown:
        print("\n".join(shown))
    elif not note:
        print("bh-flows: no flow matches", file=sys.stderr)
    sys.exit(0)
