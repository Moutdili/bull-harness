"""S8: the program's rule pages, read, dated, compared. Host only, never in a container.

`check(scope)` reads each `rules_url` of the scope (a plain GET: no cookie, no program header, no finding named, a
generic User-Agent), keeps its visible text, and compares it with the last reading. A new version is stored under
`var/rules/<program>/<UTC date and time>.txt` (one section per URL) with its SHA-256; a change opens a `rules-changed`
todo and stays unacknowledged until `ack(program)`. `fresh(program)` says whether a run may start: every page read
within FRESH_DAYS, no change left unacknowledged. A scope without `rules_url` is fresh.

What a page says never changes the scope nor a guard: nothing here interprets it. A human reads `diff(program)`.
"""

from __future__ import annotations

import contextlib
import difflib
import hashlib
import html.parser
import json
import os
import re
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from bh import paths

FRESH_DAYS = 7
FETCH_MAX = 4 << 20  # bytes of a page read
FETCH_TIMEOUT = 30.0
USER_AGENT = "Mozilla/5.0 (compatible; rules-reader/1.0)"  # generic: nothing of the program nor of us
TODO_KIND = "rules-changed"
STATE = "state.json"
_PROGRAM = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}")
_SECTION = "=== "  # a snapshot's section header: "=== <url>"


def rules_dir(program: str) -> Path:
    if not _PROGRAM.fullmatch(program or ""):
        raise ValueError(f"bad program name {program[:80]!r}")
    return paths.var() / "rules" / program


# ---------------------------------------------------------------- reading a page
class _Text(html.parser.HTMLParser):
    """Visible text of an HTML page, one line per block; scripts, styles and templates dropped."""

    SKIP = frozenset({"script", "style", "noscript", "template", "svg", "head"})
    BLOCK = frozenset(
        {"p", "div", "li", "tr", "br", "h1", "h2", "h3", "h4", "h5", "h6", "section", "article", "td", "th", "dd", "dt"}
    )

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.skip += 1
        elif tag in self.BLOCK:
            self.out.append("\n")

    def handle_endtag(self, tag):
        if tag in self.SKIP and self.skip:
            self.skip -= 1
        elif tag in self.BLOCK:
            self.out.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.out.append(data)


def visible_text(page: str) -> str:
    """The text a reader sees: tags out, whitespace runs folded, one block per line, empty lines dropped."""
    if "<" not in page:
        lines = page.splitlines()
    else:
        p = _Text()
        p.feed(page)
        p.close()
        lines = "".join(p.out).splitlines()
    return "\n".join(" ".join(line.split()) for line in lines if line.strip())


def _fetch(url: str) -> str:
    """One GET of a public page: https only, no cookie jar, no header of ours, bounded."""
    import urllib.request

    if not url.startswith("https://"):
        raise ValueError("https only")
    opener = urllib.request.build_opener()  # no HTTPCookieProcessor: no cookie is ever stored nor sent
    opener.addheaders = [("User-Agent", USER_AGENT), ("Accept", "text/html,text/plain")]
    with opener.open(urllib.request.Request(url, method="GET"), timeout=FETCH_TIMEOUT) as resp:
        raw = resp.read(FETCH_MAX + 1)
        charset = resp.headers.get_content_charset() or "utf-8"
    if len(raw) > FETCH_MAX:
        raise ValueError(f"page over {FETCH_MAX} bytes")
    return raw.decode(charset, "replace")


# ---------------------------------------------------------------- state
def _state(program: str) -> dict[str, Any]:
    try:
        doc = json.loads((rules_dir(program) / STATE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"urls": {}, "unacked": []}
    if not isinstance(doc, dict):
        return {"urls": {}, "unacked": []}
    doc.setdefault("urls", {})
    doc.setdefault("unacked", [])
    return doc


def _atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _save_state(program: str, doc: dict[str, Any]) -> None:
    _atomic(rules_dir(program) / STATE, json.dumps(doc, indent=1, sort_keys=True))


def _snapshots(program: str) -> list[Path]:
    d = rules_dir(program)
    return sorted(p for p in d.glob("*.txt") if not p.name.startswith(".")) if d.is_dir() else []


def _sections(path: Path) -> dict[str, str]:
    """{url: text} of a snapshot file."""
    out: dict[str, list[str]] = {}
    cur = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(_SECTION):
            cur = line[len(_SECTION) :].strip()
            out[cur] = []
        elif cur is not None:
            out[cur].append(line)
    return {u: "\n".join(lines).strip("\n") for u, lines in out.items()}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _todo(program: str, changed: list[str], stamp: str) -> int | None:
    """A `rules-changed` todo for the operator (None when the board refuses the kind or cannot be opened)."""
    try:
        from bh.board.db import Board

        board = Board()
        try:
            return board.add_todo(
                TODO_KIND,
                f"{program}: program rules changed",
                "Pages changed: " + ", ".join(changed) + f". Read `bh rules diff {program}`, then `bh rules ack "
                f"{program}`. Nothing in the scope or the gate changed with them.",
                program=program,
                dedup=f"{TODO_KIND}:{program}:{stamp}",
            )
        finally:
            board.db.close()
    except Exception:  # noqa: BLE001 - the todo is a reminder; the unacknowledged change already stops `fresh`
        return None


# ---------------------------------------------------------------- the four calls
def check(scope, *, fetch: Callable[[str], str] | None = None, now: float | None = None) -> dict[str, dict]:
    """Read every `rules_url` of `scope`. Returns {url: {"sha256", "changed", "path"}} (and "error" for a page that
    could not be read: its previous text is kept, its reading date is not renewed)."""
    urls = list(getattr(scope, "rules_url", ()) or ())
    if not urls:
        return {}
    program = scope.program
    fetch = fetch or _fetch
    now = time.time() if now is None else now
    st = _state(program)
    snaps = _snapshots(program)
    previous = _sections(snaps[-1]) if snaps else {}
    texts: dict[str, str] = {}
    out: dict[str, dict] = {}
    for url in urls:
        try:
            texts[url] = visible_text(fetch(url))
        except Exception as exc:  # noqa: BLE001 - one unreadable page is reported, never fatal
            out[url] = {"sha256": (st["urls"].get(url) or {}).get("sha256"), "changed": False, "path": None}
            out[url]["error"] = f"{exc.__class__.__name__}: {str(exc)[:200]}"
    changed = [u for u, t in texts.items() if u in st["urls"] and st["urls"][u].get("sha256") != _sha(t)]
    first = [u for u in texts if u not in st["urls"]]
    path = snaps[-1] if snaps else None
    if changed or first or path is None:
        stamp = time.strftime("%Y-%m-%dT%H%M%SZ", time.gmtime(now))
        body = {**previous, **texts}
        path = rules_dir(program) / f"{stamp}.txt"
        _atomic(path, "".join(f"{_SECTION}{u}\n{body[u]}\n" for u in urls if u in body))
    for url, text in texts.items():
        st["urls"][url] = {"sha256": _sha(text), "read": now, "path": str(path)}
        out[url] = {"sha256": _sha(text), "changed": url in changed, "path": str(path)}
    if changed:
        st["unacked"] = sorted(set(st["unacked"]) | set(changed))
        if (tid := _todo(program, changed, path.stem)) is not None:
            st["todo"] = tid
    st["checked"] = now
    _save_state(program, st)
    return out


def _scope_of(program: str):
    from bh.scope import load_scope

    for f in sorted(paths.scopes_dir().rglob("*.yaml")):
        try:
            s = load_scope(f)
        except Exception:  # noqa: BLE001 - another program's broken file says nothing of this one
            continue
        if s.program == program:
            return s
    return None


def fresh(program: str, now: float | None = None, *, scope=None) -> tuple[bool, str]:
    """(True, "") when a run may start on `program`: each rules page read within FRESH_DAYS days and no change left
    unacknowledged. A scope without `rules_url` is fresh; a program without a scope file is not."""
    scope = scope if scope is not None else _scope_of(program)
    if scope is None:
        return False, f"no scope file for {program}"
    urls = list(scope.rules_url)
    if not urls:
        return True, ""
    now = time.time() if now is None else now
    st = _state(program)
    for url in urls:
        rec = st["urls"].get(url)
        if not rec or not isinstance(rec.get("read"), (int, float)):
            return False, f"rules page never read: {url} (bh rules check {program})"
        days = (now - rec["read"]) / 86400
        if days > FRESH_DAYS:
            return False, f"rules page read {days:.0f} days ago (over {FRESH_DAYS}): {url} (bh rules check {program})"
    if st["unacked"]:
        return False, (
            f"rules changed, not acknowledged: {', '.join(st['unacked'])} (bh rules diff {program}, then ack)"
        )
    return True, ""


def ack(program: str) -> None:
    """The operator read the change: the program is fresh again (if its pages are recent). Closes the todo."""
    st = _state(program)
    st["unacked"] = []
    st["acked"] = time.time()
    tid = st.pop("todo", None)
    _save_state(program, st)
    if isinstance(tid, int):
        with contextlib.suppress(Exception):
            from bh.board.db import Board

            board = Board()
            try:
                board.close_todo(tid)
            finally:
                board.db.close()


def diff(program: str) -> str:
    """Lines added (`+`) and removed (`-`) between the two last readings, per page; "" when there is no change."""
    snaps = _snapshots(program)
    if len(snaps) < 2:
        return ""
    old, new = _sections(snaps[-2]), _sections(snaps[-1])
    out: list[str] = []
    for url in [*new, *(u for u in old if u not in new)]:
        a, b = old.get(url, "").splitlines(), new.get(url, "").splitlines()
        lines = [
            line
            for line in difflib.unified_diff(a, b, lineterm="", n=0)
            if line[:1] in "+-" and not line.startswith(("+++", "---"))
        ]
        if lines:
            out += [f"{_SECTION}{url}", *lines]
    return "\n".join(out)
