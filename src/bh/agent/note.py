"""bh-note — the agent's only way to write to the board (an inbox the runner ingests).

  bh-note fact "title" [-s summary] [-e evidence_path] [-k fact|recon|handoff|dead-end]
  bh-note intent "what I will try next"
  bh-note done I12 "outcome"
  bh-note finding "title" --severity high --class idor --url URL --poc-file poc.sh \\
          --summary "..." --not-proven "..."
  bh-note todo auth|waf|account|scope-question|refusal|other "title" [-d detail]
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

FACT_KINDS = ["fact", "recon", "handoff", "dead-end"]


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
    f.add_argument("-k", "--kind", default="fact", choices=FACT_KINDS)
    sub.add_parser("intent").add_argument("title")
    d = sub.add_parser("done")
    d.add_argument("intent_id")
    d.add_argument("outcome")
    fi = sub.add_parser("finding")
    fi.add_argument("title")
    fi.add_argument("--severity", required=True, choices=c.SEVERITIES)
    fi.add_argument("--class", dest="vuln_class", required=True)
    fi.add_argument("--url", required=True)
    fi.add_argument("--poc-file", required=True, help="script/curl that reproduces the issue")
    fi.add_argument("--summary", required=True)
    fi.add_argument("--not-proven", default="")
    t = sub.add_parser("todo")
    t.add_argument("kind")
    t.add_argument("title")
    t.add_argument("-d", "--detail", default="")
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
    if a.op == "finding":
        poc = Path(a.poc_file)
        if not poc.is_file():
            sys.exit(f"poc file not found: {poc}")
        _emit(
            {
                "op": "finding",
                "title": a.title,
                "severity": a.severity,
                "vuln_class": a.vuln_class,
                "url": a.url,
                "poc": poc.read_text()[:20000],
                "evidence": str(poc.resolve()),
                "summary": a.summary,
                "not_proven": a.not_proven,
            }
        )
        return
    _emit({k: v for k, v in vars(a).items() if v is not None})
