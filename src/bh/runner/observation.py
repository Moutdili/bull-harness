"""Observation proof of a finding only the browser shows (audit I1): the host decides from the gate's journal.

The hunter plants a canary `BH-SECRET-<16 hex>` in the victim's data only, then records
`bh-note finding ... --observation <canary> --victim <B> --attacker <A>`. It never writes the verdict: the gate looks
for the canary pattern in every request, response and websocket frame it relays and logs one event per hit:

  {"kind": "canary", "token": "BH-SECRET-...", "where": <one of bh.gate.canary.WHERE: request-url | request-body |
   response-body | ws-client | ws-server>, "identity": <identity name or null>, "client": <one of
   bh.gate.canary.CLIENTS: browser | agent | judge | login | other>, "host": ..., "url": ..., "ts": ..., ...}

Decision (pure, `decide`):
- the attacker's side saw it: a `response-body` or `ws-server` event whose identity is the attacker; or the victim's
  browser sent it (`request-url` / `request-body` from client `browser`, identity the victim) to a host outside the
  scope, which only a payload can have named (the gate refuses it and logs the hit);
- and no event shows it SENT (`request-url`, `request-body`, `ws-client`) by anyone but the victim before that first
  sighting. An unnamed sender counts as the attacker: the hunter holds both identities and the anonymous path too.
  An unknown `where` counts for neither side (shown in the table only).
Both -> `verified-evidence`. Sent by someone else first -> `rejected` (the attacker typed it). Otherwise -> no
sighting, `inconclusive`. The judge reads the table and can only lower this verdict.

The control (audit N6): the hunter also ran the same steps without A's payload, N times, and the canary crossed k of
them (`control: "k/N"`). A sighting proves the leak, not that A's content caused it (B's own prompt, a share B made):
without a well-formed control, or with k > 0, a sighting stays `inconclusive`. Never `verified-evidence` without it.
The host's verdict (`check`) always demands it (`need_control=True`); `decide` alone judges the sighting, and applies
the control as soon as the observation carries a `control` key, even a malformed one.
"""

from __future__ import annotations

import gzip
import json
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

from bh import paths
from bh.agent import contract as c

# the gate's values (bh.gate.canary.WHERE), split by direction
REQUEST = frozenset({"request-url", "request-body"})
RECEIVED = frozenset({"response-body", "ws-server"})
SENT = REQUEST | {"ws-client"}
TABLE_MAX = 20  # events shown to the judge and kept with the finding


def valid(obs: object) -> dict | None:
    """The sandbox-written observation, checked: {token, victim, attacker[, control]} or None. A missing or malformed
    control does not refuse the observation (the gate's table is still worth keeping): it is left out, and `decide`
    then stops at `inconclusive`."""
    if not isinstance(obs, dict):
        return None
    token, victim, attacker = obs.get("token"), obs.get("victim"), obs.get("attacker")
    if not (isinstance(token, str) and c.CANARY_RE.fullmatch(token)):
        return None
    if not all(isinstance(x, str) and 0 < len(x) <= 80 for x in (victim, attacker)) or victim == attacker:
        return None
    out = {"token": token, "victim": victim, "attacker": attacker}
    if c.parse_control(obs.get("control")) is not None:
        out["control"] = obs["control"]
    return out


def _ts(e: dict) -> float:
    v = e.get("ts")
    return float(v) if isinstance(v, int | float) and not isinstance(v, bool) else float("inf")


def _row(e: dict) -> dict:
    return {
        k: (v if isinstance(v, int | float | type(None)) and not isinstance(v, bool) else str(v)[:120])
        for k in ("ts", "where", "identity", "client", "host")
        if (v := e.get(k)) is not None or k == "identity"
    }


def decide(
    events: Iterable[dict],
    obs: dict,
    offscope: Callable[[str], bool] = lambda _h: False,
    *,
    need_control: bool = False,
) -> dict:
    """{"status", "why", "events"} from the canary events of one token (already filtered on it). The control (N6) is
    applied when `need_control` (the host's verdict, `check`) or when `obs` carries a `control` key."""
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
        if where in REQUEST and ident == victim and e.get("client") == "browser" and host and offscope(host):
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
    why = f"{token} {why}; never sent by anyone but {victim}"
    if not need_control and "control" not in obs:
        return {"status": "verified-evidence", "why": why, "events": table}
    control = c.parse_control(obs.get("control"))
    if control is None:
        return {
            "status": "inconclusive",
            "why": f"{why}; but no control without A's payload (k/N): A's content is not shown to be the cause",
            "events": table,
        }
    if control[0]:
        return {
            "status": "inconclusive",
            "why": f"{why}; but it also crossed in {control[0]}/{control[1]} control runs without A's payload",
            "events": table,
        }
    return {
        "status": "verified-evidence",
        "why": f"{why}; control without A's payload {control[0]}/{control[1]}",
        "events": table,
    }


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

    return decide(journal(obs["token"], getattr(scope, "program", None)), obs, offscope, need_control=True)
