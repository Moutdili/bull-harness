"""Technique cards (T18): the one thing that crosses from a program to the others, derived by the host.

derive(board, finding_id) reads a finding the verifier closed as `verified` or `verified-evidence`, and writes one card
in mem_items under the partition TECHNIQUES (`program = "*techniques*"`, kind `technique`, label JUDGED). The card is
built by this code from the structure of the finding's proof.json and from the verifier's structured verdict (status,
replay numbers), never from the finding's story, a step's name, a body marker or the judge's prose:

  class (bh.classes.canonical); route shape (contract.path_key + family: ids become `{id}`); per step its role, its
  identity as a template (`{user-a}`, `{user-b}` in order of appearance, `{anonymous}`), its method, the names of its
  query parameters, body keys and headers (values are `{value}`), what it expected (status, how many markers), what
  the replay saw (status, held or not); what the control showed against the attack; the proof level.

Hosts are `{host}` (`{host-2}`... for a second one). Every text goes through bh.lineage.store.clean (bh.redact, canaries
`<canary>`). Refusal (nothing is written, None is returned) when, our own `{templates}` taken out, the text still holds
a host name the scope or the asset graph names, one of their own labels, the program's name or one of its parts, an
identity's name, an e-mail address or a URL; or when the program's scope cannot be found. In doubt, no card.

Read back by bh.lineage.recall.navigate(board, program, "techniques", query) only (`bh-recall --techniques`).
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from bh import classes, paths
from bh.agent import contract as c
from bh.board import Board
from bh.lineage import key, store

TECHNIQUES = "*techniques*"  # the partition: no scope can be named so (a program name holds no `*`)
KIND = "technique"
LABEL = "JUDGED"
SOURCES = ("verified", "verified-evidence")
MAX_STEPS = 8
MAX_NAMES = 12  # parameter, body key or header names kept per step
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.\[\]-]{0,39}")
_HEADER = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,39}")
_TEMPLATE = re.compile(r"\{[a-z0-9-]{1,20}\}")
_MAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+")
_URL = re.compile(r"[a-z][a-z0-9+.-]{0,20}://", re.I)
_DROP_HEADERS = frozenset({"content-type", "content-length", "accept", "user-agent", "accept-encoding", "connection"})


# ------------------------------------------------------------------ inputs
def _json(value: object) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value) if isinstance(value, str) and value else None
    except ValueError:
        return None


def _steps(proof: object) -> list[dict]:
    data = _json(proof)
    steps = data.get("steps") if isinstance(data, dict) else None
    return [s for s in steps if isinstance(s, dict)][:MAX_STEPS] if isinstance(steps, list) else []


def _replay_round(replay: object) -> list[dict]:
    data = _json(replay)
    rounds = data.get("rounds") if isinstance(data, dict) else None
    first = rounds[0] if isinstance(rounds, list) and rounds and isinstance(rounds[0], list) else []
    return [r for r in first if isinstance(r, dict)]


def _scope_of(program: str):
    """The scope whose `program` is `program` (scopes/**/*.yaml), or None."""
    from bh.scope import load_scope

    for f in sorted(paths.scopes_dir().rglob("*.yaml")):
        try:
            s = load_scope(f)
        except Exception:  # noqa: BLE001 - another program's broken file says nothing of this one
            continue
        if s.program == program:
            return s
    return None


# ------------------------------------------------------------------ the card
class _Names:
    """Templates for hosts and identities, in order of appearance."""

    def __init__(self) -> None:
        self.hosts: dict[str, str] = {}
        self.ids: dict[str, str] = {}

    def host(self, h: str) -> str:
        if h not in self.hosts:
            self.hosts[h] = "{host}" if not self.hosts else f"{{host-{len(self.hosts) + 1}}}"
        return self.hosts[h]

    def identity(self, who: object) -> str:
        if not isinstance(who, str) or not who.strip():
            return "{anonymous}"
        if who not in self.ids:
            self.ids[who] = "{user-" + chr(ord("a") + min(len(self.ids), 25)) + "}"
        return self.ids[who]


def _route(url: object, method: str) -> tuple[str, str, list[str]] | None:
    """(host, route shape, query parameter names) of a step's URL, or None."""
    if not isinstance(url, str):
        return None
    k = c.endpoint_key(url, method)
    if k is None:
        return None
    try:
        parts = urlsplit(url)
        query = parse_qsl(parts.query, keep_blank_values=True)
    except ValueError:
        return None
    names = [n for n, _ in query if _NAME.fullmatch(n)][:MAX_NAMES]
    return (parts.hostname or "").lower(), c.family(k[1]).split(" ", 1)[1], list(dict.fromkeys(names))


def _body_keys(body: object) -> list[str]:
    data = _json(body)
    if isinstance(data, dict):
        names = [str(k) for k in data]
    elif isinstance(body, str) and "=" in body and "\n" not in body:
        names = [p.split("=", 1)[0] for p in body.split("&")]
    else:
        return []
    return list(dict.fromkeys(n for n in names if _NAME.fullmatch(n)))[:MAX_NAMES]


def _headers(headers: object) -> list[str]:
    if isinstance(headers, dict):
        items = list(headers)
    elif isinstance(headers, list):
        items = [h[0] for h in headers if isinstance(h, list | tuple) and h]
    else:
        return []
    names = [str(h) for h in items if isinstance(h, str) and _HEADER.fullmatch(h)]
    return list(dict.fromkeys(n for n in names if n.lower() not in _DROP_HEADERS))[:MAX_NAMES]


def _statuses(expect: dict) -> list[int]:
    st = expect.get("status")
    st = [st] if isinstance(st, int) else st if isinstance(st, list) else []
    return [s for s in st if isinstance(s, int) and not isinstance(s, bool) and 100 <= s <= 599][:6]


def _markers(expect: dict) -> str:
    out = []
    for k in ("contains", "absent", "regex"):
        v = expect.get(k)
        n = len(v) if isinstance(v, list) else int(isinstance(v, str) and bool(v))
        if n:
            out.append(f"{k} {n} marker{'s' if n > 1 else ''}")
    return ", ".join(out)


def _expect_text(expect: dict) -> str:
    st = _statuses(expect)
    parts = ([f"status {'/'.join(map(str, st))}"] if st else []) + ([m] if (m := _markers(expect)) else [])
    return " + ".join(parts) or "nothing stated"


def build(finding: dict) -> dict | None:
    """{"vuln_class", "method", "route", "title", "summary"} of a finding's card, or None (no class or no route)."""
    cls = classes.canonical(str(finding.get("vuln_class") or ""))
    if not cls:
        return None
    names = _Names()
    steps, seen = _steps(finding.get("proof")), _replay_round(finding.get("replay"))
    lines, roles, first = [], [], None
    attack_status: list[int] = []
    control_line = ""
    for i, st in enumerate(steps):
        method = str(st.get("method") or "GET").upper()
        method = method if re.fullmatch(r"[A-Z]{3,7}", method) else "GET"
        r = _route(st.get("url"), method)
        if r is None:
            return None
        host, route, qnames = r
        first = first or (method, route)
        role = st.get("role") if st.get("role") in ("setup", "attack", "control") else "step"
        who = names.identity(st.get("as"))
        expect = st.get("expect") if isinstance(st.get("expect"), dict) else {}
        where = names.host(host) + route + ("?" + "&".join(f"{n}={{value}}" for n in qnames) if qnames else "")
        extra = []
        if bk := _body_keys(st.get("body")):
            extra.append("body keys " + ", ".join(f"{k}={{value}}" for k in bk))
        if hd := _headers(st.get("headers")):
            extra.append("headers " + ", ".join(hd))
        if "browse" in st:
            extra.append("rendered in the browser")
        res = seen[i] if i < len(seen) else {}
        got = res.get("status") if isinstance(res.get("status"), int) else None
        saw = f"; replay saw {got}" + (" (held)" if res.get("ok") is True else " (not held)") if got else ""
        lines.append(
            f"step {i + 1} {role} as {who}: {method} {where}"
            + (f" [{'; '.join(extra)}]" if extra else "")
            + f" -> expects {_expect_text(expect)}{saw}"
        )
        roles.append(f"{role} {who}")
        if role == "attack" and not attack_status:
            attack_status = _statuses(expect)
        if role == "control" and not control_line:
            cs, absent = _statuses(expect), bool(expect.get("absent"))
            shown = []
            if cs and attack_status and set(cs) != set(attack_status):
                shown.append(
                    f"status {'/'.join(map(str, cs))} where the attack got {'/'.join(map(str, attack_status))}"
                )
            if absent:
                shown.append("the attack's marker absent")
            shown.append(f"as {who}" + (f", replay saw {got}" if got else ""))
            control_line = "control showed: " + "; ".join(shown)
    if first is None:  # no proof (an observation): the finding's URL gives the route
        r = _route(finding.get("url"), "GET")
        if r is None:
            return None
        names.host(r[0])
        first = ("GET", r[1])
    replay = _json(finding.get("replay")) or {}
    if finding.get("status") == "verified-evidence":
        level = "evidence the host observed (canary seen by the gate), judged"
    elif isinstance(replay, dict) and replay.get("reproduced") is True and not replay.get("control_disproves"):
        level = "proof replayed by the host: reproduced, the control held"
    else:
        level = "verified by the host's verifier"
    summary = [f"class: {cls}", f"proof level: {level}", *lines, *([control_line] if control_line else [])]
    title = f"{cls} · {first[0]} {first[1]}" + (" · " + " > ".join(roles) if roles else "")
    return {"vuln_class": cls, "method": first[0], "route": first[1], "title": title, "summary": "\n".join(summary)}


# ------------------------------------------------------------------ the refusal
def forbidden(board: Board, scope, finding: dict) -> tuple[list[str], list[str]]:
    """(host names, words) a card must not hold: what the gate's docs check forbids for this scope (hosts of every
    rule, their own labels, the program and its parts, the identities), plus every host of the program's asset
    graph and of the finding (its URL, its proof's steps) with their labels, and the identities its proof names."""
    from bh.gate.policy import docs_names
    from bh.scope.psl import is_public_suffix

    hosts, words = (list(x) for x in docs_names(scope))
    program = str(finding.get("program") or "")
    extra = []
    if _has(board, "assets"):
        extra = [r["key"] for r in board.rows("SELECT key FROM assets WHERE program=? AND kind='host'", program)]
    for u in [finding.get("url"), *(s.get("url") for s in _steps(finding.get("proof")))]:
        if isinstance(u, str) and (h := c.host_of(u)):
            extra.append(h)
    for h in extra:
        hosts.append(h)
        words += c.own_labels(h, is_public_suffix)
    words += [str(s.get("as")).lower() for s in _steps(finding.get("proof")) if isinstance(s.get("as"), str)]
    words.append(program.lower())  # its parts (generic words aside) are in docs_names already
    return list(dict.fromkeys(h for h in hosts if h)), list(dict.fromkeys(w for w in words if len(w) >= 3))


def refusal(text: str, hosts: list[str], words: list[str]) -> str | None:
    """Why `text` may not cross programs, or None. Our own templates are taken out first."""
    bare = _TEMPLATE.sub(" ", text)
    if _URL.search(bare):
        return "a URL"
    if _MAIL.search(bare):
        return "an e-mail address"
    if hit := c.names_in(bare, hosts, words):
        return f"a name of the program ({hit})"
    return None


def _has(board: Board, table: str) -> bool:
    return bool(board.db.execute("SELECT 1 FROM sqlite_master WHERE name=?", (table,)).fetchone())


# ------------------------------------------------------------------ derive
def derive(board: Board, finding_id: int, *, scope=None) -> int | None:
    """Write the technique card of a verified finding; its mem_items id, or None (not verified, nothing to derive,
    no scope found, or refused). `scope`: the program's Scope (default: looked up in scopes/ by the program's name).
    Idempotent: the same card again is one row seen twice (bh.lineage.store's deduplication)."""
    rows = board.rows("SELECT * FROM findings WHERE id=?", int(finding_id))
    if not rows:
        return None
    finding = dict(rows[0])
    if finding.get("status") not in SOURCES:
        return None
    scope = scope if scope is not None else _scope_of(str(finding.get("program") or ""))
    if scope is None or getattr(scope, "program", None) != finding.get("program"):
        return None
    card = build(finding)
    if card is None:
        return None
    ckey = key.canonical("*", card["method"], card["route"], card["vuln_class"])
    item = {
        "program": TECHNIQUES,
        "kind": "test",  # store.KINDS has no `technique` yet: the row is checked as a test, then typed below
        "ckey": ckey,
        "label": LABEL,
        "outcome": "confirmed",
        "title": card["title"],
        "summary": card["summary"],
        "src_kind": "finding",
        "src_id": None,  # nothing that points back to the program
    }
    row = store._prepare(item)
    row["kind"] = KIND
    hosts, words = forbidden(board, scope, finding)
    for text in (row["title"], row["summary"], row["ckey"]):
        if refusal(text, hosts, words):
            return None
    store.ensure(board)
    iid = store._put_row(board, row)
    board.db.commit()
    return iid
