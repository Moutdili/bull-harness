"""Canonical key of an attempt: `host|METHOD family|class|technique|id1,id2`, lower case.

Two attempts on the same thing get the same key whatever the case, the order of the identities or the ids in the
path: `/api/Users/12` and `/api/users/7` are both the route family `/api/users/{id}` (bh.agent.contract.path_key and
family), "Insecure Direct Object Reference" and "IDOR" are both `idor` (bh.classes.canonical). The first three fields
are the attempt's cell (key.cell): where and what, without how or as whom.

No URL parsing here (the package imports no network module, not even urllib.parse): contract.endpoint_key does it.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from bh import classes
from bh.agent import contract as c

SEP = "|"
FIELDS = 5
_DEFAULT_PORT = {"http": "80", "https": "443"}
_PATH_START = re.compile(r"^[^/]*")


def _field(value: object) -> str:
    """One field of the key: lower case, whitespace collapsed, the separators `|` and `,` replaced."""
    return " ".join(str(value or "").replace(SEP, "/").replace(",", " ").split()).lower()


def norm_host(value: str) -> str:
    """`https://A.example:443/x`, `a.example.`, `A.example:8443` -> `a.example`, `a.example`, `a.example:8443`.
    A default port is dropped, another one is kept (it is another service)."""
    s = str(value or "").strip()
    scheme = ""
    if "://" in s:
        scheme, s = s.split("://", 1)
        scheme = scheme.lower()
    s = re.split(r"[/?#]", s, maxsplit=1)[0].rsplit("@", 1)[-1]
    name, port = s, ""
    if s.startswith("["):  # [v6]:port
        name, _, rest = s.partition("]")
        name, port = name + "]", rest.removeprefix(":")
    elif s.count(":") == 1:
        name, port = s.split(":")
    if port in ("", _DEFAULT_PORT.get(scheme, "")) or (not scheme and port in ("80", "443")):
        port = ""
    return _field(name.rstrip(".") + (f":{port}" if port else ""))


def norm_route(method: str, path: str) -> str:
    """`GET /api/Users/12` -> `get /api/users/{id}`. `path` may be a full URL (its path is used) or a path; the query
    string is dropped. An unknown method is `*`. No method and no path: empty (a program-wide item)."""
    m = _field(method).upper() or "*"
    p = str(path or "").strip()
    if not p and m == "*":
        return ""
    if "://" in p:
        k = c.endpoint_key(p, m)
        p = k[1].split(" ", 1)[1] if k else _PATH_START.sub("", p.split("://", 1)[1])
    p = re.split(r"[?#]", p, maxsplit=1)[0]
    if not p.startswith("/"):
        p = "/" + p
    return _field(c.family(f"{m} {c.path_key(p)}"))


def norm_identities(value: Iterable[str] | str | None) -> str:
    """Identities sorted and deduplicated, comma-joined: ("user-b", "User-A") -> `user-a,user-b`."""
    items = value.split(",") if isinstance(value, str) else list(value or ())
    return ",".join(sorted({_field(i).replace(" ", "-") for i in items if _field(i)}))


def norm_class(value: str) -> str:
    return _field(classes.canonical(value)) if _field(value) else ""


def canonical(
    host: str,
    method: str,
    route: str,
    vuln_class: str,
    technique: str = "",
    identities: Iterable[str] | str = (),
) -> str:
    """`host|METHOD family|class|technique|id1,id2`, lower case."""
    fields = (norm_host(host), norm_route(method, route), norm_class(vuln_class), _field(technique))
    return SEP.join((*fields, norm_identities(identities)))


def cell(ckey: str) -> str:
    """The first three fields of a key: host, route family, class."""
    return SEP.join(ckey.split(SEP)[:3])


def split(ckey: str) -> dict[str, str]:
    """The five fields of a key by name (a short key gets empty fields)."""
    parts = (ckey.split(SEP) + [""] * FIELDS)[:FIELDS]
    return dict(zip(("host", "route", "vuln_class", "technique", "identities"), parts, strict=True))


def endpoint(ckey: str) -> str:
    """The first two fields: which endpoint, whatever the class (the grain of the gate's `gate_seen`)."""
    return SEP.join(ckey.split(SEP)[:2])
