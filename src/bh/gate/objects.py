"""The test objects' registry (T32): which objects our identities created, so that a write lands on ours only.

The hunter does not declare its objects: the gate observes them. A POST under an identity (X-BH-Identity, or the
identity the host loaded in bh-browser) to a target, answered 2xx, registers the identifier the answer gives:

- the `Location` header, resolved against the request URL, on the same origin, whose path holds an id segment (the
  last one is the object; contract.ID_SEGMENT, the same test as the gate's id-enumeration guard);
- the top-level `id`, `uuid` or `key` of a JSON object body: an integer, or a string shaped like an id (`key`: digits
  or a UUID only, never a long opaque string that may be an API key of ours).
Anything else registers nothing: a nested id (`{"data": {"id": 7}}`), a list, an id-less Location, another origin, a
body past BODY_SCAN bytes. In doubt the registry does not register.

A PUT, PATCH or DELETE under an identity whose path holds an id is then looked up (`known`): the path's last id
segment must be the `object_id` of a row of the program (any of our identities: the attacker writes on the victim's
object, that is the test), and the segment before it (the collection, `notes` in /api/notes/5) one of the static
segments of that row's route. A path without an id segment is never looked up, so never refused. What the gate does
with an unknown object is policy.OBJECTS_MODE (`observe`: journaled, `enforce`: refused).

Storage: SQLite `<state>/objects.sqlite` (host: var/state, gate: /state; never mounted in the sandbox), table
`test_objects(program, identity, route, object_id, ts)` created by `ensure`. `rows` lists a program's objects for
the operator's clean-up (`bh objects <program>`). Every call here may raise (sqlite3.Error, OSError, an
ImportError where sqlite3 is missing: imported on use only): the gate catches it and neither registers nor refuses.
"""

from __future__ import annotations

import contextlib
import json
import re
import time
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote, urljoin, urlsplit

from bh.agent.contract import ID_SEGMENT, origin, path_key

if TYPE_CHECKING:  # imported where used: a gate image without sqlite3 loses the registry, never the addon
    import sqlite3

DB_NAME = "objects.sqlite"
TABLE = "test_objects"
ID_KEYS = ("id", "uuid", "key")
ID_MAX = 128  # longer: not an identifier we keep
BODY_SCAN = 1 << 20  # a JSON body longer than this is not parsed (nothing registered)
ROWS_MAX = 50_000  # rows per program; past it nothing more is registered (journaled by the gate)
TIMEOUT_S = 2.0
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def mode() -> str:
    """policy.OBJECTS_MODE read at call time; anything but `enforce` is `observe` (never refuse by mistake)."""
    from bh.gate import policy

    return "enforce" if policy.OBJECTS_MODE == "enforce" else "observe"


def db_path(state: Path | None = None) -> Path:
    if state is None:
        from bh import paths

        state = paths.state()
    return Path(state) / DB_NAME


def ensure(conn: sqlite3.Connection) -> None:
    """The registry's table and its lookup index (idempotent)."""
    conn.execute(
        f"CREATE TABLE IF NOT EXISTS {TABLE} ("
        "program TEXT NOT NULL, identity TEXT NOT NULL, route TEXT NOT NULL, object_id TEXT NOT NULL, "
        "ts REAL NOT NULL, PRIMARY KEY (program, identity, route, object_id))"
    )
    conn.execute(f"CREATE INDEX IF NOT EXISTS {TABLE}_object ON {TABLE} (program, object_id)")


@contextlib.contextmanager
def connect(state: Path | None = None) -> Iterator[sqlite3.Connection]:
    """A connection to the registry (created 0600 with its table when missing), committed and closed on exit."""
    path = db_path(state)
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(FileExistsError):
            path.touch(mode=0o600, exist_ok=False)
    import sqlite3

    conn = sqlite3.connect(path, timeout=TIMEOUT_S)
    try:
        ensure(conn)
        yield conn
        conn.commit()
    finally:
        conn.close()


# ------------------------------------------------------------------ identifiers (pure)
def _segments(path: str) -> list[str]:
    """The path as the server's router sees it (the gate's id guard's reading): %xx decoded, ;params dropped,
    lowercased, empty segments gone."""
    path = re.sub(r";[^/]*", "", unquote(path or "/")).lower()
    return [s for s in path.split("/") if s]


def route_of(path: str) -> str:
    """The route template of a path: /API/Notes/5/ -> /api/notes/{id}."""
    return path_key("/" + "/".join(_segments(path)))


def object_of(url: str) -> tuple[str, str] | None:
    """(collection, object_id) of a URL: its path's last id segment and the segment before it ("" when the id is
    the first segment). None when the path holds no id: such a write is never looked up."""
    segs = _segments(urlsplit(url).path)
    for i in range(len(segs) - 1, -1, -1):
        if len(segs[i]) <= ID_MAX and ID_SEGMENT.fullmatch(segs[i]):
            return (segs[i - 1] if i else ""), segs[i]
    return None


def id_value(key: str, value: object) -> str | None:
    """An identifier as the registry keeps it (lowercased: paths are compared lowercased), or None when doubtful."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value) if value >= 0 else None
    if not isinstance(value, str) or not 0 < len(value) <= ID_MAX or "/" in value:
        return None
    if key == "key" and not (value.isdigit() or _UUID.fullmatch(value)):
        return None
    return value.lower() if ID_SEGMENT.fullmatch(value) else None


def created(
    url: str, status: int, location: str | None, body: bytes | None, content_type: str | None = None
) -> list[tuple[str, str]]:
    """(route, object_id) pairs a 2xx answer to a creating POST gives (module docstring); [] when doubtful."""
    if not isinstance(status, int) or not 200 <= status < 300:
        return []
    out: list[tuple[str, str]] = []
    if location:
        with contextlib.suppress(ValueError):
            target = urljoin(url, location.strip())
            obj = object_of(target)
            if obj is not None and origin(target) is not None and origin(target) == origin(url):
                out.append((route_of(urlsplit(target).path), obj[1]))
    if body and len(body) <= BODY_SCAN and ("json" in (content_type or "").lower() or body.lstrip()[:1] == b"{"):
        try:
            doc = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            doc = None
        if isinstance(doc, dict):
            base = route_of(urlsplit(url).path).rstrip("/")
            for key in ID_KEYS:
                if (oid := id_value(key, doc.get(key))) is not None:
                    out.append((f"{base}/{{id}}", oid))
    return list(dict.fromkeys(out))


def _covers(route: str, collection: str) -> bool:
    return not collection or collection in [s for s in route.split("/") if s and s != "{id}"]


# ------------------------------------------------------------------ the table
def record(
    conn: sqlite3.Connection, program: str, identity: str, items: Iterable[tuple[str, str]], now: float | None = None
) -> list[tuple[str, str]]:
    """Register `items` for (program, identity); returns those that were new. Nothing past ROWS_MAX per program."""
    now = time.time() if now is None else now
    (count,) = conn.execute(f"SELECT COUNT(*) FROM {TABLE} WHERE program = ?", (program,)).fetchone()
    new = []
    for route, oid in items:
        if count >= ROWS_MAX:
            break
        cur = conn.execute(
            f"INSERT OR IGNORE INTO {TABLE} (program, identity, route, object_id, ts) VALUES (?, ?, ?, ?, ?)",
            (program, identity, route, oid, round(now, 3)),
        )
        if cur.rowcount:
            count += 1
            new.append((route, oid))
    return new


def known(conn: sqlite3.Connection, program: str, url: str) -> bool | None:
    """Whether the object a write on `url` targets is one of ours; None when the path holds no id (never refused)."""
    obj = object_of(url)
    if obj is None:
        return None
    collection, oid = obj
    found = conn.execute(f"SELECT route FROM {TABLE} WHERE program = ? AND object_id = ?", (program, oid)).fetchall()
    return any(_covers(route, collection) for (route,) in found)


def rows(program: str, state: Path | None = None) -> list[dict]:
    """A program's registered objects, oldest first (`bh objects <program>`): {identity, route, object_id, ts}."""
    path = db_path(state)
    if not path.exists():
        return []
    import sqlite3

    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=TIMEOUT_S)
    try:
        ensure_ok = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (TABLE,)).fetchone()
        if not ensure_ok:
            return []
        cur = conn.execute(
            f"SELECT identity, route, object_id, ts FROM {TABLE} WHERE program = ? ORDER BY ts, rowid", (program,)
        )
        return [{"identity": i, "route": r, "object_id": o, "ts": t} for i, r, o, t in cur.fetchall()]
    finally:
        conn.close()
