"""Public suffixes (ICANN and private sections of the Public Suffix List, embedded, no network).

Used to refuse wildcards that would cover names nobody single-handedly owns: `*.co.uk`, `*.github.io`,
`api-*.co.uk`. The list is `public_suffix_list.dat` next to this file (version in its header).
"""

from __future__ import annotations

from functools import cache
from pathlib import Path

_FILE = Path(__file__).with_name("public_suffix_list.dat")


@cache
def _rules() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    exact, wild, exceptions = set(), set(), set()
    for raw in _FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        try:
            line = line.encode("idna").decode("ascii") if not line.isascii() else line.lower()
        except UnicodeError:
            continue  # a label Python's IDNA 2003 codec cannot encode: it cannot match a normalized host either
        if line.startswith("!"):
            exceptions.add(line[1:])
        elif line.startswith("*."):
            wild.add(line[2:])
        else:
            exact.add(line)
    return frozenset(exact), frozenset(wild), frozenset(exceptions)


def is_public_suffix(host: str) -> bool:
    """True if `host` (normalized: lowercase, punycode, no trailing dot) is itself a public suffix,
    like `com`, `co.uk`, `github.io` or `foo.ck` (from `*.ck`). A single label always counts as one."""
    exact, wild, exceptions = _rules()
    if "." not in host:
        return True
    if host in exceptions:
        return False
    if host in exact:
        return True
    return host.split(".", 1)[1] in wild
