"""The baseline per role (T25): the routes the application's interface offers each of our identities, no attack.

The sandbox writes it (`bh-authz --baseline <url>`: `bh-browse <url> --routes --as <identity>` per identity) to
`<BH_DIR>/baseline/<identity>.json` = {"routes": [url, ...], "ts"}. That file is the hunter's word: the host copies
it (`copy`, called by the runner after a segment) to `var/state/baseline/<program>/<identity>.json` =
{"routes": [...], "ts"} keeping only the routes the gate saw requested under that very identity (flows.jsonl and its
rotated archives: same program, same identity, same origin and route template). A hash route (`/#/admin`) is judged
on the document that served it. The judge reads the host's copy: a vertical access finding is weighed against what
the interface already offers that role.

Bounds: a sandbox file over FILE_MAX bytes, or not the shape above, is ignored; at most ROUTES_MAX routes of at most
ROUTE_CHARS characters, http(s) only. An identity the scope does not declare is never copied.
"""

from __future__ import annotations

import contextlib
import gzip
import json
import os
import re
import tempfile
import time
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from bh import paths
from bh.agent.contract import origin
from bh.gate.objects import route_of

DIR = "baseline"
FILE_MAX = 1 << 20
ROUTES_MAX = 500
ROUTE_CHARS = 2000
_NAME = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,39}")


def sandbox_file(program: str, name: str) -> Path:
    """Host view of the sandbox's <BH_DIR>/baseline/<name>.json."""
    return paths.work_bh(program) / DIR / f"{name}.json"


def host_file(program: str, name: str) -> Path:
    return paths.state() / DIR / program / f"{name}.json"


def key(url: str) -> tuple[str, str] | None:
    """(origin, route template) of a URL; its fragment is not part of what the gate sees."""
    o = origin(url)
    if o is None:
        return None
    with contextlib.suppress(ValueError):
        return o, route_of(urlsplit(url).path)
    return None


def routes_of(doc: Any) -> list[str]:
    """The routes of a sandbox-written baseline, bounded; [] when it is not {"routes": [str, ...], ...}."""
    raw = doc.get("routes") if isinstance(doc, dict) else None
    if not isinstance(raw, list):
        return []
    out = [
        r
        for r in raw
        if isinstance(r, str) and 0 < len(r) <= ROUTE_CHARS and re.match(r"https?://", r, re.I) and key(r) is not None
    ]
    return list(dict.fromkeys(out))[:ROUTES_MAX]


def seen(flows: Iterable[dict], program: str, identity: str) -> set[tuple[str, str]]:
    """(origin, route) pairs of the gate's target flows under `identity` on `program`."""
    out = set()
    for f in flows:
        if not isinstance(f, dict) or f.get("identity") != identity or f.get("class") != "target":
            continue
        if f.get("program") != program or not isinstance(f.get("url"), str):
            continue
        if (k := key(f["url"])) is not None:
            out.add(k)
    return out


def keep(routes: Iterable[str], flows_seen: set[tuple[str, str]]) -> list[str]:
    """The routes whose (origin, route) the gate saw under the identity; the others are dropped."""
    return [r for r in routes if key(r) in flows_seen]


def _flow_lines(identity: str) -> Iterator[dict]:
    live = paths.flows_log()
    needle = json.dumps(identity).encode()
    for f in [*sorted(live.parent.glob(live.name + ".*.gz")), live]:
        opener = gzip.open if f.suffix == ".gz" else open
        try:
            with opener(f, "rb") as fh:
                for line in fh:
                    if needle not in line:
                        continue
                    with contextlib.suppress(ValueError):
                        yield json.loads(line)
        except OSError:
            continue


def _read(path: Path) -> Any:
    try:
        if path.is_symlink() or path.stat().st_size > FILE_MAX:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _save(path: Path, doc: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.stem}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def copy(scope, *, now: float | None = None, flows: Iterable[dict] | None = None) -> dict[str, int]:
    """Copy each declared identity's sandbox baseline to the host, filtered on the gate's flows (module docstring).
    Returns {identity: routes kept} for the identities that had a baseline. Never raises on a sandbox file."""
    now = round(time.time() if now is None else now, 3)
    flows = list(flows) if flows is not None else None
    out: dict[str, int] = {}
    for ident in scope.identities:
        name = ident.get("name")
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            continue
        doc = _read(sandbox_file(scope.program, name))
        if doc is None:
            continue
        routes = routes_of(doc)
        lines = flows if flows is not None else _flow_lines(name)
        kept = keep(routes, seen(lines, scope.program, name))
        _save(host_file(scope.program, name), {"routes": kept, "ts": now})
        out[name] = len(kept)
    return out
