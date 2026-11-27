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

Out of band (T23, W4): when the scope declares an `oob` listener (bh.scope.model.OobHost), its journal is read too.
Each of its lines `{"ts", "proto": "http", "token", "src"}` becomes an event `{"kind": "oob-http", "where": "oob-http",
"token", "ts", "src", "host": <the listener's value>}`. The gate never lets a client of the sandbox reach that host
(it is no target, no support host, no payload host), so a line there was sent from outside: the victim's canary left
the server side for the host the attacker's content named. That is a sighting like the two above, under the same
rules (sent first by anyone but the victim: `rejected`; no control: `inconclusive`).

A digest (lot B, W4): an observation may carry `token_sha256` (sha256 of the canary, 64 hex) instead of `token`; the
events are then matched on sha256(their token).

The control (audit N6): the hunter also ran the same steps without A's payload, N times, and the canary crossed k of
them (`control: "k/N"`). A sighting proves the leak, not that A's content caused it (B's own prompt, a share B made):
without a well-formed control, or with k > 0, a sighting stays `inconclusive`. Never `verified-evidence` without it.
The host's verdict (`check`) always demands it (`need_control=True`); `decide` alone judges the sighting, and applies
the control as soon as the observation carries a `control` key, even a malformed one.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

from bh import paths
from bh.agent import contract as c

# the gate's values (bh.gate.canary.WHERE), split by direction
REQUEST = frozenset({"request-url", "request-body"})
RECEIVED = frozenset({"response-body", "ws-server"})
SENT = REQUEST | {"ws-client"}
OOB = "oob-http"  # kind and `where` of a line of the out-of-band listener (T23)
KINDS = frozenset({"canary", OOB})
TABLE_MAX = 20  # events shown to the judge and kept with the finding
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _digest(token: object) -> str | None:
    return hashlib.sha256(token.encode()).hexdigest() if isinstance(token, str) else None


def same(obs: dict, token: object) -> bool:
    """Is `token` (one event's) the observation's canary? By value, or by sha256 when `obs` carries only
    `token_sha256`."""
    if isinstance(obs.get("token"), str):
        return token == obs["token"]
    want = obs.get("token_sha256")
    return isinstance(want, str) and _SHA256.fullmatch(want) is not None and _digest(token) == want


def label(obs: dict) -> str:
    """How a verdict names the canary: itself, or its digest's head when only the digest is known."""
    if isinstance(obs.get("token"), str):
        return obs["token"]
    return f"the canary (sha256 {str(obs.get('token_sha256'))[:12]}...)"


def valid(obs: object) -> dict | None:
    """The sandbox-written observation, checked: {token | token_sha256, victim, attacker[, control]} or None. A missing
    or malformed control does not refuse the observation (the gate's table is still worth keeping): it is left out,
    and `decide` then stops at `inconclusive`. `token` wins when both are given."""
    if not isinstance(obs, dict):
        return None
    token, victim, attacker = obs.get("token"), obs.get("victim"), obs.get("attacker")
    digest = obs.get("token_sha256")
    if isinstance(token, str) and c.CANARY_RE.fullmatch(token):
        key = {"token": token}
    elif token is None and isinstance(digest, str) and _SHA256.fullmatch(digest):
        key = {"token_sha256": digest}
    else:
        return None
    if not all(isinstance(x, str) and 0 < len(x) <= 80 for x in (victim, attacker)) or victim == attacker:
        return None
    out = {**key, "victim": victim, "attacker": attacker}
    if c.parse_control(obs.get("control")) is not None:
        out["control"] = obs["control"]
    return out


def _ts(e: dict) -> float:
    v = e.get("ts")
    return float(v) if isinstance(v, int | float) and not isinstance(v, bool) else float("inf")


def _row(e: dict) -> dict:
    return {
        k: (v if isinstance(v, int | float | type(None)) and not isinstance(v, bool) else str(v)[:120])
        for k in ("ts", "where", "identity", "client", "host", "src")
        if (v := e.get(k)) is not None or k == "identity"
    }


def decide(
    events: Iterable[dict],
    obs: dict,
    offscope: Callable[[str], bool] = lambda _h: False,
    *,
    need_control: bool = False,
) -> dict:
    """{"status", "why", "events"} from the canary events of one token (the gate's, and the out-of-band listener's
    `oob-http`). The control (N6) is applied when `need_control` (the host's verdict, `check`) or when `obs` carries a
    `control` key."""
    token, victim, attacker = label(obs), obs["victim"], obs["attacker"]
    evs = sorted(
        (e for e in events if isinstance(e, dict) and e.get("kind") in KINDS and same(obs, e.get("token"))), key=_ts
    )
    table = [_row(e) for e in evs[:TABLE_MAX]]

    def seen(e: dict) -> str | None:
        if e.get("kind") == OOB:
            # T23: only the target's server can reach the listener (the gate opens it to no client of the sandbox)
            return (
                f"reached our out-of-band listener {str(e.get('host'))[:120]} from {str(e.get('src'))[:60]}: it "
                "left the server side for the host A's content named"
            )
        if e.get("kind") != "canary":
            return None
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
    typed = [
        e
        for e in evs
        if e.get("kind") == "canary" and e.get("where") in SENT and e.get("identity") != victim and _ts(e) <= at
    ]
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


def _key(token: str) -> tuple[bytes, Callable[[object], bool]]:
    """What a line must hold, and how its token is compared: `token` is a canary or the sha256 of one."""
    if c.CANARY_RE.fullmatch(token):
        return token.encode(), lambda t: t == token
    return b"BH-SECRET-", lambda t: same({"token_sha256": token}, t)


def oob_events(token: str, oob) -> list[dict]:
    """T23: the out-of-band listener's lines for `token` (a canary or its sha256), as `oob-http` events. `oob` is the
    scope's OobHost (its `journal`, live and rotated: `<name>.<n>` or `<name>.*.gz`). A line that is not exactly
    {ts: number, proto: "http", token: canary, src: text} counts for nothing."""
    live = oob.journal_path
    files = [*sorted(p for p in live.parent.glob(live.name + ".*") if p.is_file()), live]
    needle, match = _key(token)
    out = []
    for f in files:
        for e in _lines(f, needle):
            t, ts, src = e.get("token"), e.get("ts"), e.get("src")
            if (
                e.get("proto") != "http"
                or not (isinstance(t, str) and c.CANARY_RE.fullmatch(t) and match(t))
                or isinstance(ts, bool)
                or not isinstance(ts, int | float)
            ):
                continue
            out.append(
                {"kind": OOB, "where": OOB, "token": t, "ts": float(ts), "src": str(src)[:60], "host": oob.value}
            )
    return out


def journal(token: str, program: str | None = None, oob=None) -> list[dict]:
    """The gate's canary events for `token` (a canary, or the sha256 of one): the live journal and its rotated
    archives; plus, when `oob` (the scope's OobHost) is given, the out-of-band listener's lines (T23)."""
    live = paths.events_log()
    files = [*sorted(live.parent.glob(live.name + ".*.gz")), live]
    needle, match = _key(token)
    out = []
    for f in files:
        for e in _lines(f, needle):
            if (
                e.get("kind") == "canary"
                and match(e.get("token"))
                and (program is None or e.get("program") in (None, "-", program))
            ):
                out.append(e)
    if oob is not None:
        out.extend(oob_events(token, oob))
    return out


def check(obs: dict, scope=None) -> dict:
    """The host's verdict for one observation, from the gate's journal (and the scope's out-of-band listener)."""

    def offscope(host: str) -> bool:
        """Neither a target nor a support host of the scope: only a payload sends the victim's browser there."""
        if scope is None:
            return False
        from bh.scope import check as scope_check

        support = [h for kind in ("assets", "sso", "passthrough", "auth") for h in scope.support_hosts(kind)]
        if any(c.host_matches(p, host) for p in support):
            return False
        return not scope_check(scope, f"https://{host}/").allowed

    key = obs["token"] if isinstance(obs.get("token"), str) else obs["token_sha256"]
    events = journal(key, getattr(scope, "program", None))
    if (oob := getattr(scope, "oob", None)) is not None:
        events = [*events, *oob_events(key, oob)]
    return decide(events, obs, offscope, need_control=True)
