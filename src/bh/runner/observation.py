"""Observation proof of a finding only the browser shows (audit I1): the host decides from the gate's journal.

The hunter plants a canary `BH-SECRET-<16 hex>` in the victim's data only, then records
`bh-note finding ... --observation <canary> --victim <B> --attacker <A>`. It never writes the verdict: the gate looks
for the canary pattern in every request, response and websocket frame it relays and logs one event per hit:

  {"kind": "canary", "token": "BH-SECRET-...", "where": "request|response|ws-client|ws-server",
   "identity": <identity name or null>, "client": "agent|browser|judge|...", "host": ..., "ts": ..., "program": ...}

Decision (pure, `decide`):
- the attacker's side saw it: a `response` or `ws-server` event whose identity is the attacker; or the victim's
  browser sent it (`request` from client `browser`, identity the victim) to a host outside the scope, which only a
  payload can have named (the gate refuses it and logs the hit);
- and no event shows it SENT (`request`, `ws-client`) by anyone but the victim before that first sighting. An unnamed
  sender counts as the attacker: the hunter holds both identities and the anonymous path too.
Both -> `verified-evidence`. Sent by someone else first -> `rejected` (the attacker typed it). Otherwise -> no
sighting, `inconclusive`. The judge reads the table and can only lower this verdict.
"""

from __future__ import annotations

import gzip
import json
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

from bh import paths
from bh.agent import contract as c

RECEIVED = frozenset({"response", "ws-server"})
SENT = frozenset({"request", "ws-client"})
TABLE_MAX = 20  # events shown to the judge and kept with the finding


def valid(obs: object) -> dict | None:
    """The sandbox-written observation, checked: {token, victim, attacker} or None."""
    if not isinstance(obs, dict):
        return None
    token, victim, attacker = obs.get("token"), obs.get("victim"), obs.get("attacker")
    if not (isinstance(token, str) and c.CANARY_RE.fullmatch(token)):
        return None
    if not all(isinstance(x, str) and 0 < len(x) <= 80 for x in (victim, attacker)) or victim == attacker:
        return None
    return {"token": token, "victim": victim, "attacker": attacker}


def _ts(e: dict) -> float:
    v = e.get("ts")
    return float(v) if isinstance(v, int | float) and not isinstance(v, bool) else float("inf")


def _row(e: dict) -> dict:
    return {
        k: (v if isinstance(v, int | float | type(None)) and not isinstance(v, bool) else str(v)[:120])
        for k in ("ts", "where", "identity", "client", "host")
        if (v := e.get(k)) is not None or k == "identity"
    }


def decide(events: Iterable[dict], obs: dict, offscope: Callable[[str], bool] = lambda _h: False) -> dict:
    """{"status", "why", "events"} from the canary events of one token (already filtered on it)."""
    token, victim, attacker = obs["token"], obs["victim"], obs["attacker"]
    evs = sorted(
        (e for e in events if isinstance(e, dict) and e.get("kind") == "canary" and e.get("token") == token), key=_ts
    )
    table = [_row(e) for e in evs[:TABLE_MAX]]

    def seen(e: dict) -> str | None:
        where, ident = e.get("where"), e.get("identity")
        if where in RECEIVED and ident == attacker:
            return f"received by {attacker} ({where}, client {e.get('client')})"
        host = e.get("host") if isinstance(e.get("host"), str) else ""
        if where == "request" and ident == victim and e.get("client") == "browser" and host and offscope(host):
            return f"sent by {victim}'s browser to {host}, a host outside the scope"
        return None

    first = next(((e, why) for e in evs if (why := seen(e))), None)
    if first is None:
        return {"status": "inconclusive", "why": f"the gate never saw {token} on {attacker}'s side", "events": table}
    at, why = _ts(first[0]), first[1]
    typed = [e for e in evs if e.get("where") in SENT and e.get("identity") != victim and _ts(e) <= at]
    if typed:
        e = typed[0]
        who = e.get("identity") or "an unnamed client"
        return {
            "status": "rejected",
            "why": f"{token} was sent by {who} ({e.get('where')}, client {e.get('client')}) before it was seen: "
            "the attacker supplied it",
            "events": table,
        }
    return {"status": "verified-evidence", "why": f"{token} {why}; never sent by anyone but {victim}", "events": table}


def _lines(path: Path, needle: bytes) -> Iterator[dict]:
    opener = gzip.open if path.suffix == ".gz" else open
    try:
        with opener(path, "rb") as fh:
            for line in fh:
                if needle not in line:
                    continue
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if isinstance(ev, dict):
                    yield ev
    except OSError:
        return


def journal(token: str, program: str | None = None) -> list[dict]:
    """The gate's canary events for `token`: the live journal and its rotated archives."""
    live = paths.events_log()
    files = [*sorted(live.parent.glob(live.name + ".*.gz")), live]
    needle = token.encode()
    out = []
    for f in files:
        for e in _lines(f, needle):
            if e.get("kind") == "canary" and (program is None or e.get("program") in (None, "-", program)):
                out.append(e)
    return out


def check(obs: dict, scope=None) -> dict:
    """The host's verdict for one observation, from the gate's journal."""

    def offscope(host: str) -> bool:
        """Neither a target nor a support host of the scope: only a payload sends the victim's browser there."""
        if scope is None:
            return False
        from bh.scope import check as scope_check

        support = [h for kind in ("assets", "sso", "passthrough", "auth") for h in scope.support_hosts(kind)]
        if any(c.host_matches(p, host) for p in support):
            return False
        return not scope_check(scope, f"https://{host}/").allowed

    return decide(journal(obs["token"], getattr(scope, "program", None)), obs, offscope)
