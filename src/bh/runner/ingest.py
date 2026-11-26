"""Turn what the sandbox and the gate wrote into board rows.

Read offsets live in the board (host side), never in the sandbox, so the agent cannot
replay or hide its own notes.
"""

from __future__ import annotations

import contextlib
import json
import re
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

from bh import assets, paths, redact
from bh.agent import contract as c
from bh.agent import proof
from bh.board import Board
from bh.board.db import FINDING_FIELDS, HONESTY_FIELDS, HONESTY_MAX
from bh.classes import canonical
from bh.runner import observation
from bh.scope import Scope
from bh.text import one_line

AUTH_THRESHOLD = 3  # 401 answers on one host (and identity) before it counts as a wall, not a probe
# session-dead events with reason 401, on distinct routes of one identity, before it is marked stale (H4): a single
# 401 is often an access refusal (the control of a test), not a dead session. The gate applies a threshold too.
DEAD_401_ROUTES = 3
# Fact kinds and blocker reasons only the host writes: a note asking for them is downgraded (B6)
HOST_FACT_KINDS = frozenset({"blocker", "harness"})
HOST_BLOCKER_REASONS = frozenset({"refusal"})
_BRACKET_TITLE = re.compile(r"^\s*\[([^\]]*)\]")
INTENT_ID = re.compile(r"I?(\d{1,12})")


_IDENT = re.compile(r"[A-Za-z0-9_.@-]{1,64}")


class Receipts:
    """The response bodies of the gate's target flows of one run (T12), read lazily, once per ingestion. A quote is
    anchored only here: in what the gate kept (paths.flow_file, written by gate/addon.py `_record`, bodies already
    through bh.redact), never in a file of the sandbox. Response bodies only: what the target answered is a receipt,
    what the agent sent is not."""

    def __init__(self, program: str, run_id: int):
        self.program, self.run_id = program, run_id
        self._bodies: dict[str, list[str] | None] = {}
        self._recent: list[str] | None = None
        self._gate: set[str] | None = None

    def _forms(self, fid: str) -> list[str] | None:
        """The texts a quote of flow `fid` is compared against: the body as stored and, for a JSON body (stored
        re-serialized with ", " / ": " and \\u escapes), its compact and unescaped forms; each also through
        redact.text, as the quote is. None when the flow is not a target flow of this program and run."""
        if fid not in self._bodies:
            self._bodies[fid] = None
            try:
                doc = json.loads(paths.flow_file(fid).read_text(errors="replace"))
            except (OSError, ValueError):
                doc = None
            resp = doc.get("response") if isinstance(doc, dict) else None
            body = resp.get("body") if isinstance(resp, dict) else None
            if (
                isinstance(body, str)
                and body
                and doc.get("program") == self.program
                and doc.get("run") is not None
                and str(doc.get("run")) == str(self.run_id)
            ):
                forms = [body]
                try:
                    parsed = json.loads(body)
                except ValueError:
                    parsed = None
                if isinstance(parsed, dict | list):
                    forms += [
                        json.dumps(parsed, ensure_ascii=False),
                        json.dumps(parsed, ensure_ascii=False, separators=(",", ":")),
                    ]
                self._bodies[fid] = list(dict.fromkeys(forms + [redact.text(f) for f in forms]))
        return self._bodies[fid]

    def recent(self) -> list[str]:
        """Ids of the run's last RECENT_FLOWS target flows, newest first (flows.jsonl, the gate's log)."""
        if self._recent is None:
            ids = [
                f["id"]
                for f in c.tail_jsonl(paths.flows_log(), 10**6, 8_000_000)
                if f.get("class") == "target"
                and f.get("program") == self.program
                and f.get("run") is not None
                and str(f.get("run")) == str(self.run_id)
                and isinstance(f.get("id"), str)
                and c.FLOW_ID_RE.fullmatch(f["id"])
            ]
            self._recent = list(reversed(ids[-c.RECENT_FLOWS :]))
        return self._recent

    def find(self, quote: object, flow: object = None) -> str | None:
        """The id of the flow whose response body holds `quote` exactly (after bh.redact), None when none does or
        the quote is not one (one line, QUOTE_MIN..QUOTE_MAX characters). With `flow`, only that flow is read."""
        if not isinstance(quote, str) or "\n" in quote or "\r" in quote:
            return None
        if not c.QUOTE_MIN <= len(quote) <= c.QUOTE_MAX or not quote.strip():
            return None
        needle = redact.text(quote)
        named = isinstance(flow, str) and bool(flow)
        ids = ([flow] if c.FLOW_ID_RE.fullmatch(flow) else []) if named else self.recent()
        for fid in ids:
            if (forms := self._forms(fid)) and any(needle in h for h in forms):
                return fid
        return None

    def gate_endpoints(self) -> set[str]:
        if self._gate is None:
            self._gate = assets.gate_endpoints(self.run_id)
        return self._gate


@dataclass
class GateOutcome:
    """What the gate events of one segment left for the runner to act on."""

    blockers: int = 0  # blocker facts added
    waf_hosts: set[str] = field(default_factory=set)  # hosts that answered with a WAF challenge
    stale: set[str] = field(default_factory=set)  # identities whose session looks expired


def notes(
    board: Board, program: str, run_id: int, notes_file: Path, scope: Scope | None = None
) -> tuple[int, int, int]:
    """Ingest one rotated notes file in full. Returns (facts, findings, blockers).

    The runner renames notes.jsonl at the end of each segment, so the agent can neither replay
    old notes (truncate + rewrite) nor hide them behind a moved cursor.
    Migration: before rotation existed, a byte cursor (meta `notes:<program>`) marked what the
    single notes.jsonl had already given; it is honoured once, then dropped."""
    legacy_key = f"notes:{program}"
    skip = int(board.meta_get(legacy_key, "0"))
    if skip:
        board.db.execute("DELETE FROM meta WHERE k=?", (legacy_key,))
        board.db.commit()
    facts = findings = blockers = 0
    receipts = Receipts(program, run_id)
    for n in c.read_jsonl(notes_file, offset=skip):
        if not isinstance(n, dict):
            continue  # the sandbox writes this file: a malformed line is skipped, never fatal
        try:
            f, fi, t = _note(board, program, run_id, n, scope, receipts)
        except (TypeError, ValueError, OverflowError, sqlite3.Error) as exc:
            board.add_fact(
                program, "malformed note skipped", f"{exc!r}: {one_line(n, 300)}", kind="harness", run_id=run_id
            )
            continue
        facts, findings, blockers = facts + f, findings + fi, blockers + t
    return facts, findings, blockers


def _s(value, n: int = 2000) -> str:
    """A sandbox-written field as text (null, numbers, lists... are coerced, never trusted as typed)."""
    return "" if value is None else (value if isinstance(value, str) else json.dumps(value))[:n]


def _hunter_title(title: str) -> str:
    """A note's title never starts like a host-written one ("[refusal] ...", "[waf] ..."): brackets become parens."""
    return _BRACKET_TITLE.sub(r"(\1)", title, count=1)


def _hunter_reason(reason: str) -> str:
    """A blocker reason the hunter may give (the host alone records model refusals)."""
    return "other" if reason in HOST_BLOCKER_REASONS else reason


def _revive(board: Board, program: str, title: str, fields: dict, doc) -> int | None:
    """A new, valid proof under the title of a needs-proof finding (issue 34): that finding takes the proof and goes
    back to 'new' for one more verification (bh.verify rejects it if this proof has no differential either)."""
    if doc is None or not title:
        return None
    rows = board.rows(
        "SELECT id FROM findings WHERE program=? AND title=? AND status='needs-proof' ORDER BY id DESC LIMIT 1",
        program,
        title,
    )
    if not rows:
        return None
    fid = int(rows[0]["id"])
    keep = {
        k: v
        for k, v in fields.items()
        if k in ("severity", "summary", "poc", "evidence", "not_proven", *HONESTY_FIELDS)
    }
    board.finding_set(fid, proof=json.dumps(doc), replay=None, **keep)
    board.set_finding(fid, "new", "new proof received from the hunter: verified once more")
    return fid


def _note(
    board: Board, program: str, run_id: int, n: dict, scope: Scope | None, receipts: Receipts | None = None
) -> tuple[int, int, int]:
    """One note -> (facts, findings, blockers) added."""
    receipts = receipts or Receipts(program, run_id)
    match n.get("op"):
        case "fact" | "think":
            return _fact(board, program, run_id, n, receipts)
        case "threat-model":
            return _threat_model(board, program, run_id, n.get("title"), n.get("lines"), n.get("flow"), receipts)
        case "handoff":
            board.add_fact(program, *_handoff(n), kind="handoff", run_id=run_id)
            return 1, 0, 0
        case "intent":
            return _intent(board, program, run_id, n)
        case "reorder":
            _reorder(board, program, n.get("intents"))
        case "cover":
            return _cover(board, program, run_id, n, receipts)
        case "scope-request":
            return _scope_request(board, program, run_id, n)
        case "done":
            if m := INTENT_ID.fullmatch(_s(n.get("intent_id"), 20)):
                return _done(board, program, run_id, int(m.group(1)), n)
        case "finding":
            fields = {k: n.get(k) for k in FINDING_FIELDS if k not in ("vuln_class", "proof", "observation")}
            fields = {k: _s(v, HONESTY_MAX if k in HONESTY_FIELDS else 20000) for k, v in fields.items()}
            fields["poc"] = redact.text(fields.get("poc", ""))
            doc = n.get("proof")
            if doc is not None and proof.validate(doc):  # re-checked on the host: the sandbox check is advisory
                fields["not_proven"] = (fields.get("not_proven", "") + " [proof refused by the host]").strip()
                doc = None
            # an observation proof (I1) only without a replayable one; its verdict is the host's, never the note's
            obs = observation.valid(n.get("observation")) if doc is None and "observation" in n else None
            if doc is None and "observation" in n and obs is None:
                fields["not_proven"] = (fields.get("not_proven", "") + " [observation refused by the host]").strip()
            elif obs is not None and "control" not in obs:  # N6: kept, but the host's verdict stops at inconclusive
                fields["not_proven"] = (fields.get("not_proven", "") + " [no control k/N without A's payload]").strip()
            title = _s(n.get("title"), 300)
            if _revive(board, program, title, fields, doc) is not None:
                return 0, 1, 0
            fid = board.add_finding(
                program,
                title or "(untitled)",
                run_id=run_id,
                proof=doc,
                observation=obs,
                **fields,
                vuln_class=canonical(_s(n.get("vuln_class"), 80) or "unknown"),
            )
            if obs is not None:  # the gate's table as of now, for the board; the verification reads it again
                board.finding_set(fid, replay=json.dumps({"observation": observation.check(obs, scope)})[:200_000])
            if scope is not None and (excluded := scope.excludes(_s(n.get("vuln_class"), 80))):
                # the program does not pay for this class: rejected by the harness, not by the model's judgment
                board.set_finding(fid, "rejected", f"excluded by program policy (forbidden_vulns: {excluded})")
                return 0, 0, 0
            return 0, 1, 0
        case "blocked":
            reason = _hunter_reason(_s(n.get("reason"), 40))
            # what was tried and what would prove it (T13), each on its own line ahead of the detail (the summary is
            # bounded: they are never the part cut off). The next session reads them.
            detail = "\n".join(
                [
                    f"{label}: {_line(n.get(k), 600)}"
                    for k, label in (("tried", "tried"), ("would_prove", "would prove"))
                    if _line(n.get(k), 600)
                ]
                + [_s(n.get("detail"))]
            ).strip()
            gap = reason not in c.STOP_REASONS
            board.add_blocker(
                program,
                reason,
                _s(n.get("title"), 300),
                detail,
                run_id=run_id,
                host=_s(n.get("host"), 255) or None,
                **({"outcome": "open_proof_gap"} if gap else {}),
            )
            if (m := INTENT_ID.fullmatch(_s(n.get("intent"), 20))) and _own_intent(board, program, int(m.group(1))):
                board.close_intent(int(m.group(1)), f"blocked: {reason}", closure="open_proof_gap" if gap else None)
            return 0, 0, 1
        case "todo":  # written by an agent of the old doctrine: nobody answers todos during the hunt any more
            kind, title = _s(n.get("kind") or "other", 40), _s(n.get("title"), 300)
            if kind == "scope-question":  # a scope is never widened from the hunt: kept as a fact
                board.add_fact(program, title, _s(n.get("detail")), kind="out-of-scope", run_id=run_id)
                return 1, 0, 0
            board.add_blocker(program, _hunter_reason(kind), title, _s(n.get("detail")), run_id=run_id)
            return 0, 0, 1
    return 0, 0, 0


def _line(value, n: int) -> str:
    """A sandbox-written field as one line of text, bounded."""
    return " ".join(_s(value, n * 2).split())[:n]


def _identities(value) -> str | None:
    """`--as user-a,user-b`: identity names only, at most 8, comma-separated."""
    names = [x.strip() for x in _s(value, 600).split(",")]
    return ",".join(list(dict.fromkeys(x for x in names if _IDENT.fullmatch(x)))[:8]) or None


def _class(value) -> str | None:
    v = _line(value, 80)
    return canonical(v) or None if v else None


def _fact(board: Board, program: str, run_id: int, n: dict, receipts: Receipts) -> tuple[int, int, int]:
    """A fact (T12): typed by the note, anchored (`grounded`) by the host alone, when its quote is an exact substring
    of a response body the gate kept for this run. A wrong quote or an unknown flow leaves the fact, grounded 0."""
    kind = "think" if n.get("op") == "think" else _s(n.get("kind") or "fact", 40)
    kind = kind if kind in c.FACT_KINDS else "fact"
    if kind == "threat-model":
        lines = _s(n.get("summary"), 6000).splitlines()
        return _threat_model(board, program, run_id, n.get("title"), lines, n.get("flow"), receipts)
    title, summary = _hunter_title(_s(n.get("title"), 300)), _s(n.get("summary"))
    if kind == "handoff":  # read by the next session and the operator: no credential crosses it (T7)
        title, summary = redact.text(title), redact.text(summary)
    quote = n.get("quote") if isinstance(n.get("quote"), str) and kind != "think" else None
    flow = n.get("flow") if isinstance(n.get("flow"), str) and c.FLOW_ID_RE.fullmatch(n.get("flow")) else None
    # a flow the note names but that is no flow id anchors nothing: the run's other flows are not searched instead
    named_bad = n.get("flow") not in (None, "") and flow is None
    found = receipts.find(quote, flow) if quote is not None and not named_bad else None
    why = _line(n.get("why"), 500) or None
    if kind == "dead-end" and why not in c.DEAD_END_WHY:
        why = None  # a cause outside the list is not a cause the frontier shows
    board.add_fact(
        program,
        title,
        summary,
        _s(n.get("evidence")),
        # blocker and harness facts are the host's (add_blocker, ingestion): a note cannot forge them
        kind=kind,
        run_id=run_id,
        grounded=found is not None,
        quote=redact.text(_line(quote, c.QUOTE_MAX)) if quote else None,
        flow=found or flow,
        why=why,
        endpoint=c.endpoint_label(n.get("url")),
        vuln_class=_class(n.get("vuln_class")),
        technique=_line(n.get("technique"), 200) or None,
        identities=_identities(n.get("identities")),
    )
    return 1, 0, 0


def _threat_model(
    board: Board, program: str, run_id: int, title, lines, flow, receipts: Receipts
) -> tuple[int, int, int]:
    """The program's threat model (T16): a new one is the active one, the older ones stay with their dates. At most
    THREAT_MODEL_LINES lines; a line whose `<claim> :: <quote>` is not anchored in a response body of the run gets
    INFERRED from the host. grounded = 1 only when every line is anchored."""
    if not isinstance(lines, list):
        raise ValueError("threat model without lines")
    if flow not in (None, "") and not (isinstance(flow, str) and c.FLOW_ID_RE.fullmatch(flow)):
        flow = "-"  # named but not a flow id: no line is anchored (find reads no flow for it)
    out, anchored = [], 0
    for raw in lines:
        ln = _line(raw, 1000)
        if not ln:
            continue
        if len(out) == c.THREAT_MODEL_LINES:
            break
        claim, sep, quote = ln.partition(c.THREAT_QUOTE_SEP)
        ok = bool(sep and claim.strip()) and receipts.find(quote, flow) is not None
        anchored += ok
        out.append(redact.text(ln) + ("" if ok else c.INFERRED))
    if not out:
        raise ValueError("threat model without lines")
    board.add_fact(
        program,
        _hunter_title(_line(title, 300) or "threat model"),
        "\n".join(out),
        kind="threat-model",
        run_id=run_id,
        grounded=anchored == len(out),
    )
    return 1, 0, 0


def _anchored(board: Board, program: str, endpoint: str | None) -> bool:
    return bool(endpoint) and bool(
        board.rows(
            "SELECT 1 FROM facts WHERE program=? AND grounded=1 AND endpoint=? AND kind NOT IN ('think') LIMIT 1",
            program,
            endpoint,
        )
    )


def _intent(board: Board, program: str, run_id: int, n: dict) -> tuple[int, int, int]:
    """A typed intent (T15). Several may be open at once. A `prove` needs a grounded fact on the same endpoint: without
    one it is refused and a harness fact says so. The recall receipt is stored as written (lot C checks it)."""
    title = _s(n.get("title"), 300)
    kind = _s(n.get("kind"), 10)
    kind = kind if kind in c.INTENT_KINDS else None
    basis = m.group(0).upper() if (m := re.fullmatch(r"[Ff]\d{1,12}", _s(n.get("basis"), 20).strip())) else None
    after = m.group(0).upper() if (m := re.fullmatch(r"[Ii]\d{1,12}", _s(n.get("after"), 20).strip())) else None
    recall = _line(n.get("recall"), 100) or None
    endpoint = c.endpoint_label(n.get("url"))
    if kind == "prove" and not _anchored(board, program, endpoint):
        board.add_fact(
            program,
            "intent refused: prove without an anchored fact",
            f"{one_line(title, 200)!r} on {endpoint or '(no --url)'}: a prove intent needs a fact on the same endpoint "
            "whose --quote the host found in a response body (grounded); `--kind test` until then",
            kind="harness",
            run_id=run_id,
        )
        return 1, 0, 0
    board.add_intent(
        program,
        title,
        run_id=run_id,
        **{k: _s(n.get(k), c.CRITERION_MAX).strip() or None for k in c.REACHED},
        kind=kind,
        basis=basis,
        after=after,
        recall=recall,
        endpoint=endpoint,
        vuln_class=_class(n.get("vuln_class")),
    )
    return 0, 0, 0


def _own_intent(board: Board, program: str, iid: int) -> bool:
    return bool(board.rows("SELECT 1 FROM intents WHERE id=? AND program=?", iid, program))


def _reorder(board: Board, program: str, ids) -> None:
    """`bh-note reorder`: the open intents named, in that order, ahead of the others (frontier)."""
    named = [int(m.group(1)) for x in (ids if isinstance(ids, list) else []) if (m := INTENT_ID.fullmatch(_s(x, 20)))]
    open_ = {r["id"] for r in board.rows("SELECT id FROM intents WHERE program=? AND status='open'", program)}
    named = [i for i in dict.fromkeys(named) if i in open_]
    if named:
        board.set_intent_order(program, named + [i for i in board.intent_order(program) if i not in named])


def _cover(board: Board, program: str, run_id: int, n: dict, receipts: Receipts) -> tuple[int, int, int]:
    """Coverage of one (endpoint, class) (T14). `clean` stands only on an endpoint the gate saw requested by hand in
    this run (tests, rank `gate`): otherwise the host stores `retry` and a harness fact says why. Lack of information
    is never a proof of safety."""
    endpoint, klass = c.endpoint_label(n.get("endpoint")), _class(n.get("vuln_class"))
    outcome = _s(n.get("outcome"), 20)
    if endpoint is None or klass is None or outcome not in c.COVER_OUTCOMES:
        raise ValueError("cover needs an endpoint, a class and one of " + "|".join(c.COVER_OUTCOMES))
    seen = assets.gate_tested(board, program, endpoint, run_id, receipts.gate_endpoints())
    added = 0
    if outcome == "clean" and not seen:
        outcome, added = "retry", 1
        board.add_fact(
            program,
            f"clean refused: {endpoint} {klass}",
            f"the gate saw no request by hand to {endpoint} in run {run_id}: kept as retry (no clean without the "
            "gate's proof)",
            kind="harness",
            run_id=run_id,
            endpoint=endpoint,
            vuln_class=klass,
        )
    board.db.execute(
        "INSERT INTO coverage_class(program, endpoint, vuln_class, outcome, evidence, run_id, ts, gate_seen) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (program, endpoint, klass, outcome, _s(n.get("evidence"), 500), run_id, time.time(), int(seen)),
    )
    board.db.commit()
    return added, 0, 0


def _scope_request(board: Board, program: str, run_id: int, n: dict) -> tuple[int, int, int]:
    """D40: a pending request for the host's judge (lot F decides, the gate reads what was approved). Never a widening
    by itself. A prefix that is not an https URL without joker, query or fragment is refused with a harness fact."""
    prefix, why = c.scope_prefix(n.get("prefix")), redact.text(_line(n.get("why"), 1000))
    if prefix is None or not why:
        board.add_fact(
            program,
            "scope request refused",
            f"{one_line(_s(n.get('prefix'), 300), 300)!r}: an https URL prefix, no joker, query or fragment, with "
            "where it was seen",
            kind="harness",
            run_id=run_id,
        )
        return 1, 0, 0
    board.add_scope_request(program, prefix, why, run_id)
    return 0, 0, 0


def close_open_intents(board: Board, program: str, run_id: int) -> int:
    """The intents run `run_id` leaves open become `open_proof_gap` (T13): closed, never silently dropped. Returns
    how many. Lot F calls it when the agent of the run ends."""
    cur = board.db.execute(
        "UPDATE intents SET status='closed', closed=?, outcome='open_proof_gap', "
        "result=COALESCE(result, ?) WHERE program=? AND run_id=? AND status='open'",
        (time.time(), f"left open by run {run_id}", program, run_id),
    )
    board.db.commit()
    return cur.rowcount


def _handoff(n: dict) -> tuple[str, str]:
    """(title, summary) of a `bh-note handoff` (T7 a): "HANDOFF: <state>" and the four rubrics, one line each, in
    their fixed order. A rubric the note lacks is shown empty, never dropped. Both go through bh.redact."""
    rubric = {k: " ".join(_s(n.get(k), 480).split()) for k in ("state", "dead", "next", "files")}
    title = _hunter_title(f"HANDOFF: {rubric['state']}"[:300])
    return redact.text(title), redact.text("\n".join(f"{k}: {v}" for k, v in rubric.items()))


def _done(board: Board, program: str, run_id: int, iid: int, n: dict) -> tuple[int, int, int]:
    """Close an intent (T8). `reached` is kept only for an intent with exit criteria; such an intent closed without it
    is closed all the same, reached NULL, and a harness fact says so. `--reached abandon` also records the lead as a
    dead end, under the intent's title, in the run of this note. Returns (facts, findings, blockers) added."""
    rows = board.rows(
        "SELECT title, success, abandon, endpoint, vuln_class FROM intents WHERE id=? AND program=?", iid, program
    )
    reached = _s(n.get("reached"), 20)
    reached = reached if reached in c.REACHED else None
    closure = _s(n.get("closure"), 20)
    closure = closure if closure in c.INTENT_OUTCOMES else None
    outcome = _s(n.get("outcome"))
    if not rows:
        return 0, 0, 0  # an unknown id (or another program's) updates nothing
    intent = rows[0]
    if not (intent["success"] or intent["abandon"]):
        board.close_intent(iid, outcome, closure=closure)  # no criteria: nothing to reach (--reached not stored)
        return 0, 0, 0
    board.close_intent(iid, outcome, reached, closure=closure)
    if reached is None:
        board.add_fact(
            program,
            f"I{iid} closed without --reached",
            "the intent had exit criteria (--success / --abandon); its `done` did not say which one was met",
            kind="harness",
            run_id=run_id,
        )
        return 1, 0, 0
    if reached == "abandon":
        board.add_fact(
            program,
            _hunter_title(intent["title"]),
            f"abandoned (criterion: {_s(intent['abandon'], 300) or 'none given'}): {outcome}",
            kind="dead-end",
            run_id=run_id,
            why=why if (why := _s(n.get("why"), 20)) in c.DEAD_END_WHY else None,
            outcome=closure,
            endpoint=intent["endpoint"],
            vuln_class=intent["vuln_class"],
        )
        return 1, 0, 0
    return 0, 0, 0


def _ts(e: dict, default: float) -> float:
    """The event's own time (the gate stamps every event), `default` when it has none."""
    v = e.get("ts")
    return float(v) if isinstance(v, int | float) and not isinstance(v, bool) and v > 0 else default


def _route(e: dict, host: str) -> str:
    """The route a gate event is about (origin + method + path family), for counting distinct ones."""
    url = e.get("url") if isinstance(e.get("url"), str) else ""
    k = c.endpoint_key(url, _s(e.get("method") or "GET", 10))
    return f"{k[0]} {c.family(k[1])}" if k else f"{host} ?"


def _identity_dead(
    board: Board, program: str, run_id: int, out: GateOutcome, *, ident: str, host: str, title: str, ts: float
) -> None:
    """Mark an identity stale (meta `identity-stale:<ident>:<program>`: the runner leaves it out of the prompt
    and the judge until its session file is rewritten) and record one `auth` blocker per identity and run.
    The mark carries the time of the EVENT, not of the ingestion: a probe that failed before a login must not
    mark stale the session that login wrote afterwards (H4 b). The latest mark wins."""
    key = f"identity-stale:{ident}:{program}"
    with contextlib.suppress(ValueError):
        ts = max(ts, float(board.meta_get(key, "0") or 0))
    board.meta_set(key, str(ts))
    out.stale.add(ident)
    key = f"auth-blocker:{ident}:{program}"
    if board.meta_get(key) == str(run_id):
        return
    board.meta_set(key, str(run_id))
    board.add_blocker(
        program,
        "auth",
        title,
        f"left out until var/state/identities/{program}/{ident}.json is refreshed",
        run_id=run_id,
        host=host,
    )
    out.blockers += 1


def gate_events(board: Board, program: str, run_id: int, identities: list[str]) -> GateOutcome:
    """One summary fact for denials, blocker facts for walls (WAF, 401) and missing identities.

    `session-dead` with a redirect to the login page, a failed probe or `401-repeated` (the gate saw 401s on
    several distinct routes: its own threshold) -> that identity is stale at once (_identity_dead). The older
    single-401 reason (`401`, logs written before the gate thresholded) needs DEAD_401_ROUTES distinct routes.
    `GateOutcome.stale` lists the dead identities: the entry point for logging in again (issue 25).
    A 401 sent WITH an identity (`auth` event) never marks it: it is the control of an access test.
    401 sent WITHOUT one -> blocker only if the program has no identity at all: an agent probing
    unauthenticated access control on purpose has hit no wall."""
    out = GateOutcome()
    blocked: dict[str, int] = {}
    auth: dict[str, int] = {}  # host -> 401 answers sent without an identity
    dead401: dict[str, dict[str, tuple[str, float]]] = {}  # identity -> route -> (host, ts)
    missing: set[str] = set()
    now = time.time()
    for e in board.new_lines(paths.events_log(), "gate-events"):
        if e.get("program") not in (program, "-"):
            continue
        match e.get("kind"):
            case "blocked":
                host = re.sub(r"https?://([^/]+).*", r"\1", e.get("url") or e.get("host") or "?")
                blocked[host] = blocked.get(host, 0) + 1
            case "waf":
                host = _s(e.get("host") or "?", 255)
                if host not in out.waf_hosts:
                    out.waf_hosts.add(host)
                    board.add_blocker(
                        program,
                        "waf",
                        f"{host} answers with a WAF challenge",
                        f"status {e.get('status')} server={e.get('server')} url={e.get('url')} flow={e.get('flow')}",
                        run_id=run_id,
                        host=host,
                    )
                    out.blockers += 1
            case "auth":
                host, ident = _s(e.get("host") or "?", 255), _s(e.get("identity"), 80)
                if not ident:  # a 401 under an identity is an access refusal; the gate decides when it is death
                    auth[host] = auth.get(host, 0) + 1
            case "session-dead":
                if ident := _s(e.get("identity"), 80):
                    host = _s(e.get("host") or "?", 255)
                    reason = _s(e.get("reason"), 20)
                    if reason == "401" or (not reason and e.get("status") == 401):
                        dead401.setdefault(ident, {})[_route(e, host)] = (host, _ts(e, now))
                        continue
                    why = {
                        "login-redirect": "a redirect to its login page",
                        "probe": "a failed probe",
                        "401-repeated": "401 on several routes",
                    }
                    _identity_dead(
                        board,
                        program,
                        run_id,
                        out,
                        ident=ident,
                        host=host,
                        title=f"identity '{ident}': session dead on {host} "
                        f"({why.get(reason, 'status ' + _s(e.get('status'), 5))})",
                        ts=_ts(e, now),
                    )
            case "identity-missing":
                ident = _s(e.get("identity"), 80)
                if ident not in missing:
                    missing.add(ident)
                    board.add_fact(
                        program,
                        f"identity '{ident}' requested but not configured",
                        f"no var/state/identities/{program}/{ident}.json",
                        kind="harness",
                        run_id=run_id,
                    )
    for ident, routes in dead401.items():
        if len(routes) < DEAD_401_ROUTES:
            continue  # an access refusal on one or two objects is the finding's control, not a dead session
        host, ts = max(routes.values(), key=lambda v: v[1])
        _identity_dead(
            board,
            program,
            run_id,
            out,
            ident=ident,
            host=host,
            title=f"identity '{ident}': session dead on {host} (401 on {len(routes)} routes)",
            ts=ts,
        )
    for host, n in auth.items():
        if n < AUTH_THRESHOLD:
            continue
        if not identities:
            # once per host while the blocker is visible; past its TTL the wall is reported again if still there
            key = f"auth-wall:{host}:{program}"
            if now - float(board.meta_get(key, "0") or 0) < c.BLOCKER_TTL_S:
                continue
            board.meta_set(key, str(now))
            board.add_blocker(program, "auth", f"{host} requires a session ({n}x 401)", run_id=run_id, host=host)
            out.blockers += 1
    if blocked:
        top = sorted(blocked.items(), key=lambda kv: -kv[1])[:8]
        board.add_fact(
            program,
            f"gate denied {sum(blocked.values())} requests",
            ", ".join(f"{h} x{n}" for h, n in top),
            kind="blocked",
            run_id=run_id,
        )
    return out
