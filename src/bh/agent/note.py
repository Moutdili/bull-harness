"""bh-note — the agent's only way to write to the board (an inbox the runner ingests).

  bh-note fact "title" [-s summary] [-e evidence_path] [-k fact|recon|handoff|dead-end]
          [--quote "<exact substring of a response body>" [--flow <flow id>]]      # T12: anchored by the host
          [--url URL --class C --technique T --as user-a,user-b] [--why "<reason>"]
          # -k dead-end needs --why technical|environment|approach|external|rule
  bh-note think "<idea>" --why "<reason>"                 # D15: a line of your reasoning, never anchored
  bh-note threat-model "<title>" -l "<claim> :: <exact quote>" [-l ...] [--flow <id>]   # T16: at most 8 lines
  bh-note handoff --state "..." --dead "...|none" --next "..." --files "..."   # fact HANDOFF: <state>, 4 rubrics
  bh-note intent "what I will try next" --kind map|test|prove [--success "<signal>"] [--abandon "<signal>"]
          [--basis F<n>] [--after I<n>] [--url URL --class C] [--recall R-<id>|none]
          # test and prove need --recall (run `bh-recall "<idea>" --url U --class C` first); map does not
  bh-note reorder I4 I2 I7                                # the order of your open intents, first = next
  bh-note done I12 "outcome" [--outcome confirmed|ruled_out|open_proof_gap]  # an intent without criteria
  bh-note done I12 --reached success|abandon "outcome" [--outcome ...]       # an intent with --success / --abandon
  bh-note cover "GET /api/orders/{id}" idor clean|suspect|blocked|retry -e <file>   # T14: one (endpoint, class)
  bh-note scope-request "https://<prefix>" "<where it was seen: page, JS bundle, response>"   # D40: judged later
  bh-note finding "title" --severity high --class idor --url URL --proof proof.json \\
          --summary "..." --not-proven "..." [--poc-file poc.sh] HONESTY
  bh-note finding "title" --severity high --class prompt-injection --url URL \\
          --observation BH-SECRET-<16 hex> --victim user-b --attacker user-a --control 0/3 --summary "..." \\
          [-e transcript] HONESTY
          # a result only the browser shows: the host looks for that canary in the gate's journal (audit I1);
          # --control k/N: the same steps without A's payload, N runs, k canary crossings (N6)
  HONESTY = --counter "<best case against it>" --severity-if "<proof that would change the severity>"
            --severity-why "<why this severity>"   (all three required, never empty)
            [--proof-level 1|2|3] [--cvss CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N]
          # --proof-level (T27): 1 signal, 2 partial, 3 impact (default). 1 and 2 are kept as CANDIDATE facts, never
          # judged. --cvss (T28): the vector only; the host computes the score, the program's own scale wins
  bh-note canary           # prints a fresh BH-SECRET-<16 hex> to plant in the victim's data
  bh-note verdict F12 confirmed|rejected|inconclusive "reason" [--cvss <lower vector>] [--proof-level 1|2|3]
          # verifier only; --cvss and --proof-level can only lower the hunter's
  bh-note blocked auth|account|waf|captcha|...|other "what is blocked" --tried "<what you tried>" \\
          --would-prove "<what would prove it>" [-d detail] [--intent I3] [--host H]
  bh-note show 42          # full summary/evidence of fact 42
  bh-note frontier         # current board view (+ attack surface)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
from pathlib import Path

from bh.agent import contract as c
from bh.agent import proof


def _emit(rec: dict) -> None:
    c.append_jsonl(c.bh_dir() / c.NOTES, {**rec, "program": os.environ.get("BH_PROGRAM", "")})
    print(f"ok {rec['op']}")


# The honesty pass of a finding (T1): required with --proof as with --observation, one error line per missing field
HONESTY = (
    ("counter", "--counter", "the best case against this finding"),
    ("severity_if", "--severity-if", "the proof that would change its severity"),
    ("severity_why", "--severity-why", "why this severity"),
)
PROOF_LEVELS = (1, 2, 3)  # 1 signal, 2 partial, 3 impact (bh.classes.PROOF_LEVELS)
# A CVSS 3.1 base vector in the specification's order. Only the form is checked here: the host parses it again and
# computes the score (bh.cvss), the sandbox never does.
CVSS_RE = re.compile(r"(CVSS:3\.1/)?AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[HLN]/I:[HLN]/A:[HLN]")
CVSS_HELP = "a CVSS 3.1 base vector, CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_ in this order"
# The handoff's rubrics, in this order, all required (`--dead none` when nothing was abandoned). No credentials rubric.
HANDOFF = ("state", "dead", "next", "files")


def _blank(v: str | None) -> bool:
    return v is None or not v.strip()


def _one_line(v: str) -> str:
    return " ".join(v.split())


def _action_of(parser: argparse.ArgumentParser, name: str) -> argparse.Action | None:
    """The action argparse names `name` in its errors: `--a/-b`, an option string, a dest or a metavar."""
    parts = set(name.split("/"))
    for act in parser._actions:  # argparse keeps them there
        if parts & set(act.option_strings) or name in (act.dest, act.metavar):
            return act
    return None


def _valid(act: argparse.Action | None) -> str:
    if act is None:
        return ""
    if act.choices:
        return "valid: " + "|".join(str(x) for x in act.choices)
    return act.help.removeprefix("required: ") if act.help else ""


def field_errors(parser: argparse.ArgumentParser, message: str) -> list[str]:
    """argparse's one error, as one line per faulty field with the values that are valid."""
    if m := re.match(r"argument (\S+): invalid choice: (.+?) \(choose from .*\)$", message, re.S):
        act = _action_of(parser, m.group(1))
        return [f"{m.group(1)}: {m.group(2)[:60]} is not valid; {_valid(act)}"]
    if m := re.match(r"the following arguments are required: (.+)$", message, re.S):
        out = []
        for name in m.group(1).split(", "):
            why = _valid(_action_of(parser, name))
            out.append(f"{name} is required" + (f" ({why})" if why else ""))
        return out
    if m := re.match(r"argument (\S+): (.+)$", message, re.S):
        why = _valid(_action_of(parser, m.group(1)))
        return [f"{m.group(1)}: {m.group(2)}" + (f" ({why})" if why else "")]
    return [message]


class _Parser(argparse.ArgumentParser):
    """A refusal is one line per faulty field, with the valid values, never argparse's usage block."""

    def error(self, message: str):  # type: ignore[override]
        self.exit(2, f"{self.prog} refused:\n  - " + "\n  - ".join(field_errors(self, message)) + "\n")


def parser() -> argparse.ArgumentParser:
    p = _Parser(prog="bh-note")
    sub = p.add_subparsers(dest="op", required=True)
    f = sub.add_parser("fact")
    f.add_argument("title")
    f.add_argument("-s", "--summary", default="")
    f.add_argument("-e", "--evidence", default="")
    f.add_argument("-k", "--kind", default="fact", choices=c.FACT_KINDS)
    f.add_argument(
        "--quote", help=f"an exact substring of a response body: one line, {c.QUOTE_MIN}-{c.QUOTE_MAX} chars"
    )
    f.add_argument("--flow", help="the gate's flow id the quote is from (else the run's latest flows are searched)")
    f.add_argument("--why", help="why (required with -k dead-end: " + "|".join(c.DEAD_END_WHY) + ")")
    _typed(f)
    f.add_argument("--technique", help="the technique the fact is about")
    f.add_argument("--as", dest="identities", help="the identities involved, comma-separated (user-a,user-b)")
    t = sub.add_parser("think", help="a line of your reasoning: never anchored")
    t.add_argument("title")
    t.add_argument("--why", help="required: the reason")
    tm = sub.add_parser("threat-model", help="the program's threat model: replaces the previous one")
    tm.add_argument("title")
    tm.add_argument(
        "-l", "--line", action="append", default=[], help='"<claim> :: <exact quote>"; without a quote: (inferred)'
    )
    tm.add_argument("--flow", help="the gate's flow id the quotes are from")
    h = sub.add_parser("handoff", help="the state for the next session: four rubrics, all required")
    h.add_argument("--state", help="where the hunt stands")
    h.add_argument("--dead", help="leads abandoned, and why (`none` if none)")
    h.add_argument("--next", help="what to try next")
    h.add_argument("--files", help="the files that hold the work (paths)")
    i = sub.add_parser("intent")
    i.add_argument("title")
    i.add_argument("--success", help="the signal that the test worked, written before it runs")
    i.add_argument("--abandon", help="the signal (or number of tries) that ends it")
    i.add_argument("--kind", choices=c.INTENT_KINDS, help="map (no recall needed), test or prove")
    i.add_argument("--basis", help="F<n>: the finding this intent builds on")
    i.add_argument("--after", help="I<n>: the intent this one waits for")
    _typed(i)
    i.add_argument("--recall", help="R-<id> printed by bh-recall, or none (required with --kind test|prove)")
    r = sub.add_parser("reorder", help="the order of your open intents, first = next")
    r.add_argument("intent_ids", nargs="+")
    d = sub.add_parser("done")
    d.add_argument("intent_id")
    d.add_argument("outcome")
    d.add_argument("--reached", choices=c.REACHED, help="required when the intent has --success or --abandon")
    d.add_argument("--outcome", dest="closure", choices=c.INTENT_OUTCOMES, help="what the test established")
    d.add_argument("--why", choices=c.DEAD_END_WHY, help="with --reached abandon: why the lead is a dead end")
    cv = sub.add_parser("cover", help="coverage of one (endpoint, class)")
    cv.add_argument("endpoint", help='"METHOD /route" (or a URL)')
    cv.add_argument("vuln_class")
    cv.add_argument("outcome", choices=c.COVER_OUTCOMES)
    cv.add_argument("-e", "--evidence", help="required: the file that shows it")
    sr = sub.add_parser("scope-request", help="ask the host's judge for an https prefix the target uses")
    sr.add_argument("prefix")
    sr.add_argument("why", help="where it was seen: page, JS bundle, response")
    fi = sub.add_parser("finding")
    fi.add_argument("title")
    fi.add_argument("--severity", required=True, choices=c.SEVERITIES)
    fi.add_argument("--class", dest="vuln_class", required=True)
    fi.add_argument("--url", required=True)
    how = fi.add_mutually_exclusive_group(required=True)
    how.add_argument("--proof", help="proof.json: attack + control steps (see the doctrine)")
    how.add_argument(
        "--observation",
        metavar="CANARY",
        help="BH-SECRET-<16 hex> planted in the victim's data only; the host looks for it on the attacker's side",
    )
    fi.add_argument("--victim", help="with --observation: the identity whose data holds the canary")
    fi.add_argument("--attacker", help="with --observation: the identity that must never have sent it")
    fi.add_argument(
        "--control",
        metavar="k/N",
        help="with --observation: the same steps without A's payload, N runs; k = runs where the canary crossed",
    )
    fi.add_argument("-e", "--evidence", default="", help="with --observation: the exact prompts and outputs (a file)")
    fi.add_argument("--poc-file", help="optional script; the harness generates the triager PoC from the proof")
    fi.add_argument("--summary", required=True)
    fi.add_argument("--not-proven", default="")
    for _key, flag, what in HONESTY:
        fi.add_argument(flag, help=f"required: {what}")
    fi.add_argument(
        "--proof-level",
        type=int,
        choices=PROOF_LEVELS,
        default=3,
        help="1 signal, 2 partial (kept as a CANDIDATE fact, never judged), 3 impact (the default)",
    )
    fi.add_argument("--cvss", help=f"optional: {CVSS_HELP}; the host computes the score")
    v = sub.add_parser("verdict")
    v.add_argument("finding_id")
    v.add_argument("verdict", choices=["confirmed", "rejected", "inconclusive"])
    v.add_argument("reason")
    v.add_argument("--cvss", help=f"only to lower the hunter's vector: {CVSS_HELP}")
    v.add_argument("--proof-level", type=int, choices=PROOF_LEVELS, help="only to lower the hunter's proof level")
    b = sub.add_parser("blocked", help="a lead you cannot finish: recorded and closed, nobody unblocks it")
    b.add_argument("reason", choices=c.BLOCKER_REASONS)
    b.add_argument("title")
    b.add_argument("-d", "--detail", default="")
    b.add_argument("--tried", help="required: what you tried")
    b.add_argument("--would-prove", help="required: what would prove it, if the wall were not there")
    b.add_argument("--intent", help="the intent (I<n>) this blocker closes")
    b.add_argument("--host")
    sub.add_parser("show").add_argument("fact_id")
    sub.add_parser("canary", help="print a fresh canary for an observation proof")
    sub.add_parser("frontier")
    return p


def _typed(sp: argparse.ArgumentParser) -> None:
    sp.add_argument("--url", help='the endpoint: a URL, or "METHOD URL"')
    sp.add_argument("--class", dest="vuln_class", help="the vulnerability class")


def _refuse(what: str, bad: list[str]) -> None:
    if bad:
        sys.exit(f"{what} refused:\n  - " + "\n  - ".join(bad))


def _quote_errors(quote: str | None, flow: str | None) -> list[str]:
    bad = []
    if quote is not None:
        if "\n" in quote or "\r" in quote:
            bad.append("--quote is one line: quote one line of the body")
        if not c.QUOTE_MIN <= len(quote) <= c.QUOTE_MAX:
            bad.append(f"--quote is {c.QUOTE_MIN} to {c.QUOTE_MAX} characters, copied exactly from a response body")
    if flow is not None and not c.FLOW_ID_RE.fullmatch(flow):
        bad.append("--flow is a gate flow id (<seconds>-<6 hex>-<n>, as in the flow log)")
    return bad


def _typed_fields(a: argparse.Namespace) -> tuple[dict, list[str]]:
    """--url / --class of a fact or an intent: the endpoint must read as one."""
    out, bad = {}, []
    if a.url is not None:
        if c.endpoint_label(a.url) is None:
            bad.append('--url is a URL, or "METHOD URL" (GET https://t.test/api/orders/7)')
        out["url"] = a.url
    if a.vuln_class is not None:
        if _blank(a.vuln_class):
            bad.append("--class is empty")
        out["vuln_class"] = a.vuln_class.strip()
    return out, bad


def _fact(a: argparse.Namespace) -> None:
    if a.kind == "threat-model":
        sys.exit('a threat model: bh-note threat-model "<title>" -l "<claim> :: <exact quote>" [-l ...]')
    bad = _quote_errors(a.quote, a.flow)
    if a.flow is not None and a.quote is None:
        bad.append("--flow goes with --quote")
    if a.kind == "dead-end" and a.why not in c.DEAD_END_WHY:
        bad.append("-k dead-end needs --why " + "|".join(c.DEAD_END_WHY))
    if a.kind == "think" and _blank(a.why):
        bad.append('-k think needs --why (or: bh-note think "<idea>" --why "<reason>")')
    typed, more = _typed_fields(a)
    _refuse("fact", bad + more)
    rec = {"op": "fact", "title": a.title, "summary": a.summary, "evidence": a.evidence, "kind": a.kind, **typed}
    for k in ("quote", "flow", "why", "technique", "identities"):
        if getattr(a, k) is not None:
            rec[k] = getattr(a, k)
    _emit(rec)


def _think(a: argparse.Namespace) -> None:
    _refuse("think", ["the idea is empty"] * _blank(a.title) + ["--why is required and not empty"] * _blank(a.why))
    _emit({"op": "think", "title": _one_line(a.title), "why": _one_line(a.why)})


def _threat_model(a: argparse.Namespace) -> None:
    bad = []
    lines = [ln.strip() for ln in a.line]
    if not lines or len(lines) > c.THREAT_MODEL_LINES or any(not ln for ln in lines):
        bad.append(f"1 to {c.THREAT_MODEL_LINES} non-empty -l lines")
    for ln in lines:
        claim, sep, quote = ln.partition(c.THREAT_QUOTE_SEP)
        bad += _quote_errors(quote if sep else None, None)
        if sep and not claim.strip():
            bad.append(f"a line has a quote and no claim: {ln[:60]!r}")
    bad += _quote_errors(None, a.flow)
    _refuse("threat model", list(dict.fromkeys(bad)))
    _emit({"op": "threat-model", "title": a.title, "lines": lines, **({"flow": a.flow} if a.flow else {})})


def _recall_command(a: argparse.Namespace) -> str:
    return f'bh-recall "{a.title}" --url {a.url or "<URL>"} --class {a.vuln_class or "<class>"}'


def _intent_typed(a: argparse.Namespace) -> tuple[dict, list[str]]:
    rec, bad = _typed_fields(a)
    if a.kind is not None:
        rec["kind"] = a.kind
    if a.kind in c.RECALL_NEEDED and a.recall is None:
        bad.append(
            f"--kind {a.kind} needs --recall: run `{_recall_command(a)}` first, then add --recall R-<id> "
            "(or --recall none when it found nothing)"
        )
    if a.recall is not None and not c.RECALL_RE.fullmatch(a.recall):
        bad.append("--recall is R-<id> as bh-recall printed it, or none")
    if a.kind == "prove" and a.url is None:
        bad.append("--kind prove needs --url: the endpoint of your anchored fact (bh-note fact ... --quote --url)")
    if a.basis is not None and not re.fullmatch(r"F\d{1,12}", a.basis.strip()):
        bad.append("--basis is a finding id, F<n>")
    if a.after is not None and not re.fullmatch(r"I\d{1,12}", a.after.strip()):
        bad.append("--after is an intent id, I<n>")
    for k in ("basis", "after", "recall"):
        if getattr(a, k) is not None:
            rec[k] = getattr(a, k).strip()
    return rec, bad


def _reorder(a: argparse.Namespace) -> None:
    ids = [m.group(1) for x in a.intent_ids if (m := re.fullmatch(r"I?(\d{1,12})", x.strip()))]
    if len(ids) != len(a.intent_ids):
        sys.exit("bh-note reorder I<a> I<b> ...: intent ids only")
    _emit({"op": "reorder", "intents": [f"I{n}" for n in dict.fromkeys(ids)]})


def _cover(a: argparse.Namespace) -> None:
    bad = []
    if c.endpoint_label(a.endpoint) is None:
        bad.append('the endpoint is "METHOD /route" (GET /api/orders/{id}) or a URL')
    if _blank(a.vuln_class):
        bad.append("the class is empty")
    if _blank(a.evidence):
        bad.append("-e <file> is required: the file that shows it")
    elif not Path(a.evidence).is_file():
        bad.append(f"evidence file not found: {a.evidence}")
    _refuse("cover", bad)
    _emit(
        {
            "op": "cover",
            "endpoint": a.endpoint,
            "vuln_class": a.vuln_class.strip(),
            "outcome": a.outcome,
            "evidence": str(Path(a.evidence).resolve()),
        }
    )


def _scope_request(a: argparse.Namespace) -> None:
    bad = []
    if c.scope_prefix(a.prefix) is None:
        bad.append("the prefix is an https URL (https://host/path), no joker (*), no query (?), no fragment")
    if _blank(a.why):
        bad.append("say where it was seen: the page, the JS bundle or the response")
    _refuse("scope request", bad)
    rec = {"op": "scope-request", "kind": "scope-request", "prefix": a.prefix, "why": _one_line(a.why)}
    c.append_jsonl(c.bh_dir() / c.NOTES, {**rec, "run": None, "program": os.environ.get("BH_PROGRAM", "")})
    print("asked, pending: the host's judge decides after this segment; until then the gate refuses it")


def _blocked(a: argparse.Namespace) -> None:
    """A closed lead says what was tried and what would have proved it (T13). A stop (third-party data, server
    execution) is written at once: nothing is asked of it."""
    if a.reason not in c.STOP_REASONS:
        _refuse(
            "blocked",
            [
                f"{flag} is required and not empty"
                for flag, v in (("--tried", a.tried), ("--would-prove", a.would_prove))
                if _blank(v)
            ],
        )
    rec = {
        "op": "blocked",
        "reason": a.reason,
        "title": a.title,
        "detail": a.detail,
        "intent": a.intent or "",
        "host": a.host or "",
    }
    for k in ("tried", "would_prove"):
        if not _blank(getattr(a, k)):
            rec[k] = _one_line(getattr(a, k))
    _emit(rec)


def _observation_finding(a: argparse.Namespace) -> None:
    """A finding only the browser shows (audit I1). No proof.json: the host reads the gate's journal for the canary.
    The hunter's account of what happened is the summary; the verdict is the host's, never written here."""
    if not c.CANARY_RE.fullmatch(a.observation):
        sys.exit("the canary is BH-SECRET- and 16 lowercase hex characters (`bh-note canary` prints one)")
    if not a.victim or not a.attacker or a.victim == a.attacker:
        sys.exit("--observation needs --victim and --attacker, two different identities (A attacking A pays nothing)")
    if c.parse_control(a.control) is None:
        sys.exit(
            "--observation needs --control k/N: the same steps without A's payload, run N times (1-1000), the canary "
            "crossing k of them (0/3 when it never did)"
        )
    ev = Path(a.evidence) if a.evidence else None
    if ev is not None and not ev.is_file():
        sys.exit(f"evidence file not found: {ev}")
    _emit(
        {
            "op": "finding",
            "title": a.title,
            "severity": a.severity,
            "vuln_class": a.vuln_class,
            "url": a.url,
            "poc": "",
            "evidence": str(ev.resolve()) if ev else "",
            "observation": {"token": a.observation, "victim": a.victim, "attacker": a.attacker, "control": a.control},
            "summary": a.summary,
            "not_proven": a.not_proven,
            **_honesty(a),
        }
    )


def _honesty(a: argparse.Namespace) -> dict:
    """The honesty pass, the proof level and, when given, the CVSS vector (T27, T28)."""
    out = {key: getattr(a, key) for key, _flag, _what in HONESTY}
    out["proof_level"] = a.proof_level
    if a.cvss is not None:
        out["cvss"] = a.cvss.strip()
    return out


def _check_cvss(a: argparse.Namespace) -> None:
    if a.cvss is not None and not CVSS_RE.fullmatch(a.cvss.strip()):
        sys.exit(f"{a.op} refused:\n  - --cvss is {CVSS_HELP} (the host computes the score)")


def _check_honesty(a: argparse.Namespace) -> None:
    """Every finding argues against itself first (T1): one line per missing or empty field."""
    if missing := [
        f"{flag} is required and not empty: {what}" for key, flag, what in HONESTY if _blank(getattr(a, key))
    ]:
        sys.exit("finding refused:\n  - " + "\n  - ".join(missing))


def _handoff(a: argparse.Namespace) -> None:
    """The handoff fact (T7 a): four fixed rubrics, all required. An abandoned lead is written down (`--dead`), never
    dropped in silence: `--dead none` says there was none."""
    if bad := [
        f"--{k} is required and not empty" + (" (`--dead none` if nothing was abandoned)" if k == "dead" else "")
        for k in HANDOFF
        if _blank(getattr(a, k))
    ]:
        sys.exit("handoff refused:\n  - " + "\n  - ".join(bad))
    _emit({"op": "handoff", **{k: _one_line(getattr(a, k)) for k in HANDOFF}})


def _intent(a: argparse.Namespace) -> None:
    """Several intents may be open at once. --kind test|prove asks what the lineage already knows first (--recall);
    --kind map does not."""
    bad = [
        f"--{k} is empty: give the signal or leave the option out"
        for k in c.REACHED
        if getattr(a, k) is not None and _blank(getattr(a, k))
    ]
    typed, more = _intent_typed(a)
    _refuse("intent", bad + more)
    _emit(
        {
            "op": "intent",
            "title": a.title,
            **{k: getattr(a, k) for k in c.REACHED if getattr(a, k) is not None},
            **typed,
        }
    )


def _done(a: argparse.Namespace, d: Path) -> None:
    """`--reached` exactly when the intent has exit criteria. Intent ids are the board's, and notes.jsonl never holds
    them: the frontier snapshot does, with the criteria of each open intent on its line. An intent it does not list
    (closed, or written after the snapshot) is left to the host, which records a `done` without `--reached` on an
    intent with criteria as reached NULL, with a harness fact."""
    m = re.fullmatch(r"I?(\d{1,12})", a.intent_id.strip())
    if m is None:
        sys.exit(f'bh-note done I<n> "<outcome>": {a.intent_id!r} is not an intent id')
    n = int(m.group(1))
    frontier = (d / c.FRONTIER).read_text(errors="replace") if (d / c.FRONTIER).is_file() else ""
    has = c.intent_has_criteria(frontier, n)
    if has and a.reached is None:
        sys.exit(
            f'I{n} has exit criteria (--success / --abandon): bh-note done I{n} --reached success|abandon "<outcome>"'
        )
    if has is False and a.reached is not None:
        sys.exit(f'I{n} has no exit criteria: bh-note done I{n} "<outcome>" (no --reached)')
    if a.why is not None and a.reached != "abandon":
        sys.exit("--why goes with --reached abandon (why the lead is a dead end)")
    _emit(
        {
            "op": "done",
            "intent_id": a.intent_id,
            "outcome": a.outcome,
            **({"reached": a.reached} if a.reached else {}),
            **({"closure": a.closure} if a.closure else {}),
            **({"why": a.why} if a.why else {}),
        }
    )


def main(argv: list[str] | None = None) -> None:
    a = parser().parse_args(argv)
    d = c.bh_dir()
    if a.op == "show":
        rec = c.read_json(d / c.FACTS, {}).get(str(a.fact_id).lstrip("#"))
        print(
            json.dumps(rec, indent=1, ensure_ascii=False)
            if rec
            else "unknown fact (the snapshot refreshes each segment)"
        )
        return
    if a.op == "frontier":
        board = (d / c.FRONTIER).read_text() if (d / c.FRONTIER).exists() else "(no frontier yet)"
        manual = {tuple(x) for x in c.read_json(d / c.MANUAL_TESTED, [])}
        print(board + ("\n" + s if (s := c.surface(d, also_tested=manual)) else ""))
        return
    if a.op == "canary":  # nothing recorded: the gate sees it wherever it crosses
        print(f"BH-SECRET-{secrets.token_hex(8)}")
        return
    if a.op == "verdict" and not c.is_verifier():
        sys.exit("bh-note verdict is reserved to the independent verifier")
    if a.op != "verdict" and c.is_verifier():
        sys.exit("the verifier only records verdicts")
    if a.op in ("finding", "verdict"):
        _check_cvss(a)
    if a.op == "finding":
        _check_honesty(a)
    if a.op == "finding" and a.observation is not None:
        _observation_finding(a)
        return
    handlers = {
        "handoff": _handoff,
        "fact": _fact,
        "think": _think,
        "threat-model": _threat_model,
        "intent": _intent,
        "reorder": _reorder,
        "cover": _cover,
        "scope-request": _scope_request,
        "blocked": _blocked,
    }
    if a.op in handlers:
        handlers[a.op](a)
        return
    if a.op == "done":
        _done(a, d)
        return
    if a.op == "finding":
        try:
            proof_doc = json.loads(Path(a.proof).read_text())
        except (OSError, ValueError) as exc:
            sys.exit(f"cannot read the proof: {exc}")
        if errors := proof.validate(proof_doc):
            sys.exit("proof refused:\n  - " + "\n  - ".join(errors))
        poc = Path(a.poc_file) if a.poc_file else None
        if poc is not None and not poc.is_file():
            sys.exit(f"poc file not found: {poc}")
        _emit(
            {
                "op": "finding",
                "title": a.title,
                "severity": a.severity,
                "vuln_class": a.vuln_class,
                "url": a.url,
                "poc": poc.read_text()[:20000] if poc else "",
                "evidence": str(Path(a.proof).resolve()),
                "proof": proof_doc,
                "summary": a.summary,
                "not_proven": a.not_proven,
                **_honesty(a),
            }
        )
        return
    rec = {k: v for k, v in vars(a).items() if v is not None}
    if a.op == "verdict":  # the host gave this nonce to the verifier's process only: a planted verdict lacks it
        rec["nonce"] = os.environ.get("BH_VERDICT_NONCE", "")
    _emit(rec)
