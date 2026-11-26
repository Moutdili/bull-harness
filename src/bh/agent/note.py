"""bh-note — the agent's only way to write to the board (an inbox the runner ingests).

  bh-note fact "title" [-s summary] [-e evidence_path] [-k fact|recon|handoff|dead-end]
  bh-note handoff --state "..." --dead "...|none" --next "..." --files "..."   # fact HANDOFF: <state>, 4 rubrics
  bh-note intent "what I will try next" [--success "<signal>"] [--abandon "<signal or n tries>"]
  bh-note done I12 "outcome"                              # an intent without criteria
  bh-note done I12 --reached success|abandon "outcome"    # an intent with --success / --abandon
  bh-note finding "title" --severity high --class idor --url URL --proof proof.json \\
          --summary "..." --not-proven "..." [--poc-file poc.sh] HONESTY
  bh-note finding "title" --severity high --class prompt-injection --url URL \\
          --observation BH-SECRET-<16 hex> --victim user-b --attacker user-a --control 0/3 --summary "..." \\
          [-e transcript] HONESTY
          # a result only the browser shows: the host looks for that canary in the gate's journal (audit I1);
          # --control k/N: the same steps without A's payload, N runs, k canary crossings (N6)
  HONESTY = --counter "<best case against it>" --severity-if "<proof that would change the severity>"
            --severity-why "<why this severity>"   (all three required, never empty)
  bh-note canary           # prints a fresh BH-SECRET-<16 hex> to plant in the victim's data
  bh-note verdict F12 confirmed|rejected|inconclusive "reason"     # verifier only
  bh-note blocked auth|account|waf|captcha|...|other "what is blocked" [-d detail] [--intent I3] [--host H]
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
# The handoff's rubrics, in this order, all required (`--dead none` when nothing was abandoned). No credentials rubric.
HANDOFF = ("state", "dead", "next", "files")


def _blank(v: str | None) -> bool:
    return v is None or not v.strip()


def _one_line(v: str) -> str:
    return " ".join(v.split())


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bh-note")
    sub = p.add_subparsers(dest="op", required=True)
    f = sub.add_parser("fact")
    f.add_argument("title")
    f.add_argument("-s", "--summary", default="")
    f.add_argument("-e", "--evidence", default="")
    f.add_argument("-k", "--kind", default="fact", choices=c.FACT_KINDS)
    h = sub.add_parser("handoff", help="the state for the next session: four rubrics, all required")
    h.add_argument("--state", help="where the hunt stands")
    h.add_argument("--dead", help="leads abandoned, and why (`none` if none)")
    h.add_argument("--next", help="what to try next")
    h.add_argument("--files", help="the files that hold the work (paths)")
    i = sub.add_parser("intent")
    i.add_argument("title")
    i.add_argument("--success", help="the signal that the test worked, written before it runs")
    i.add_argument("--abandon", help="the signal (or number of tries) that ends it")
    d = sub.add_parser("done")
    d.add_argument("intent_id")
    d.add_argument("outcome")
    d.add_argument("--reached", choices=c.REACHED, help="required when the intent has --success or --abandon")
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
    v = sub.add_parser("verdict")
    v.add_argument("finding_id")
    v.add_argument("verdict", choices=["confirmed", "rejected", "inconclusive"])
    v.add_argument("reason")
    b = sub.add_parser("blocked", help="a lead you cannot finish: recorded and closed, nobody unblocks it")
    b.add_argument("reason", choices=c.BLOCKER_REASONS)
    b.add_argument("title")
    b.add_argument("-d", "--detail", default="")
    b.add_argument("--intent", help="the intent (I<n>) this blocker closes")
    b.add_argument("--host")
    sub.add_parser("show").add_argument("fact_id")
    sub.add_parser("canary", help="print a fresh canary for an observation proof")
    sub.add_parser("frontier")
    return p


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
    return {key: getattr(a, key) for key, _flag, _what in HONESTY}


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
    if bad := [
        f"--{k} is empty: give the signal or leave the option out"
        for k in c.REACHED
        if getattr(a, k) is not None and _blank(getattr(a, k))
    ]:
        sys.exit("intent refused:\n  - " + "\n  - ".join(bad))
    _emit({"op": "intent", "title": a.title, **{k: getattr(a, k) for k in c.REACHED if getattr(a, k) is not None}})


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
    _emit(
        {"op": "done", "intent_id": a.intent_id, "outcome": a.outcome, **({"reached": a.reached} if a.reached else {})}
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
    if a.op == "finding":
        _check_honesty(a)
    if a.op == "finding" and a.observation is not None:
        _observation_finding(a)
        return
    if a.op == "handoff":
        _handoff(a)
        return
    if a.op == "intent":
        _intent(a)
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
    if a.op == "blocked":
        _emit(
            {
                "op": "blocked",
                "reason": a.reason,
                "title": a.title,
                "detail": a.detail,
                "intent": a.intent or "",
                "host": a.host or "",
            }
        )
        return
    rec = {k: v for k, v in vars(a).items() if v is not None}
    if a.op == "verdict":  # the host gave this nonce to the verifier's process only: a planted verdict lacks it
        rec["nonce"] = os.environ.get("BH_VERDICT_NONCE", "")
    _emit(rec)
