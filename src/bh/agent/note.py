"""bh-note — the agent's only way to write to the board (an inbox the runner ingests).

  bh-note fact "title" [-s summary] [-e evidence_path] [-k fact|recon|handoff|dead-end]
  bh-note intent "what I will try next"
  bh-note done I12 "outcome"
  bh-note finding "title" --severity high --class idor --url URL --proof proof.json \\
          --summary "..." --not-proven "..." [--poc-file poc.sh]
  bh-note verdict F12 confirmed|rejected|inconclusive "reason"     # verifier only
  bh-note blocked auth|account|waf|captcha|...|other "what is blocked" [-d detail] [--intent I3] [--host H]
  bh-note show 42          # full summary/evidence of fact 42
  bh-note frontier         # current board view (+ attack surface)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from bh.agent import contract as c
from bh.agent import proof


def _emit(rec: dict) -> None:
    c.append_jsonl(c.bh_dir() / c.NOTES, {**rec, "program": os.environ.get("BH_PROGRAM", "")})
    print(f"ok {rec['op']}")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bh-note")
    sub = p.add_subparsers(dest="op", required=True)
    f = sub.add_parser("fact")
    f.add_argument("title")
    f.add_argument("-s", "--summary", default="")
    f.add_argument("-e", "--evidence", default="")
    f.add_argument("-k", "--kind", default="fact", choices=c.FACT_KINDS)
    sub.add_parser("intent").add_argument("title")
    d = sub.add_parser("done")
    d.add_argument("intent_id")
    d.add_argument("outcome")
    fi = sub.add_parser("finding")
    fi.add_argument("title")
    fi.add_argument("--severity", required=True, choices=c.SEVERITIES)
    fi.add_argument("--class", dest="vuln_class", required=True)
    fi.add_argument("--url", required=True)
    fi.add_argument("--proof", required=True, help="proof.json: attack + control steps (see the doctrine)")
    fi.add_argument("--poc-file", help="optional script; the harness generates the triager PoC from the proof")
    fi.add_argument("--summary", required=True)
    fi.add_argument("--not-proven", default="")
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
    sub.add_parser("frontier")
    return p


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
    if a.op == "verdict" and not c.is_verifier():
        sys.exit("bh-note verdict is reserved to the independent verifier")
    if a.op != "verdict" and c.is_verifier():
        sys.exit("the verifier only records verdicts")
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
