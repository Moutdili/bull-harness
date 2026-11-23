"""`bh` — bull-harness CLI (orchestrator entry point)."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from bh import __version__

COMPOSE = ["podman-compose", "-f", "container/compose.yaml"]


def _home() -> Path:
    return Path(os.environ.get("BH_HOME", Path.cwd()))


def _board():
    from bh.board import Board
    return Board()


# ---------------------------------------------------------------- scope
def _cmd_scope_check(args) -> int:
    from bh.scope import ScopeError, check, load_scope
    try:
        scope = load_scope(args.file)
    except ScopeError as exc:
        print(f"ERR {exc}", file=sys.stderr)
        return 2
    denied = 0
    for target in args.targets:
        d = check(scope, target)
        denied += not d.allowed
        rule = f" [{d.rule}]" if d.rule else ""
        print(f"{'ALLOW' if d.allowed else 'DENY '} {target} — {d.reason}{rule}")
    return 1 if denied else 0


def _cmd_scope_show(args) -> int:
    from bh.scope import ScopeError, load_scope
    try:
        s = load_scope(args.file)
    except ScopeError as exc:
        print(f"ERR {exc}", file=sys.stderr)
        return 2
    print(f"{s.platform}/{s.program}  digest={s.digest[:12]}  rps={s.max_rps}  automation={s.automation_allowed}")
    for label, rules in (("in", s.in_scope), ("out", s.out_of_scope)):
        for r in rules:
            print(f"  {label:3} {r}")
    for k, v in s.required_headers.items():
        print(f"  hdr {k}: {v}")
    return 0


# ---------------------------------------------------------------- stack
def _cmd_up(args) -> int:
    home = _home()
    env = home / "secrets" / "agent.env"
    if not env.exists():
        print("missing secrets/agent.env — create it with:\n"
              "  mkdir -p secrets && claude setup-token   # in YOUR terminal, then:\n"
              "  printf 'CLAUDE_CODE_OAUTH_TOKEN=%s\\n' '<token>' > secrets/agent.env && chmod 600 secrets/agent.env",
              file=sys.stderr)
        return 2
    for d in ("var/gate/conf", "var/state/identities", "var/gate-ca", "var/work", "var/runs"):
        (home / d).mkdir(parents=True, exist_ok=True)
    cmd = COMPOSE + ["up", "-d"] + (["--build"] if args.build else [])
    return subprocess.call(cmd, cwd=home)


def _cmd_down(args) -> int:
    return subprocess.call(COMPOSE + ["down"], cwd=_home())


def _cmd_status(args) -> int:
    from bh.runner.run import AGENT, GATE, container_running
    for c in (GATE, AGENT):
        print(f"{c:9} {'running' if container_running(c) else 'DOWN'}")
    active = _home() / "var" / "state" / "active-scope.yaml"
    if active.exists():
        from bh.scope import load_scope
        s = load_scope(active)
        print(f"active scope: {s.platform}/{s.program} (rps {s.max_rps})")
    b = _board()
    for r in b.rows("SELECT id, program, status, turns, cost_usd, datetime(started,'unixepoch','localtime') AS t "
                    "FROM runs ORDER BY id DESC LIMIT 5"):
        print(f"run {r['id']:>4} {r['t']} {r['program']:20} {r['status']:9} {r['turns'] or 0:>3} turns"
              + (f"  ${r['cost_usd']:.2f} eq." if r['cost_usd'] else ""))
    n_todo = b.rows("SELECT COUNT(*) AS n FROM todos WHERE status='open'")[0]["n"]
    n_find = b.rows("SELECT COUNT(*) AS n FROM findings WHERE status IN ('new','verified')")[0]["n"]
    print(f"open todos: {n_todo} · findings to review: {n_find}")
    return 0


# ---------------------------------------------------------------- runs
def _cmd_run(args) -> int:
    from bh.runner.run import run_segment
    res = run_segment(Path(args.scope), model=args.model, max_turns=args.max_turns, minutes=args.minutes,
                      resume=not args.fresh, extra_task=args.task or "")
    if res.text:
        print("\n" + res.text.strip())
    return 0 if res.status in ("ok", "max_turns", "timeout") else 1


def _cmd_hunt(args) -> int:
    from bh.runner.supervisor import hunt
    hunt([Path(f) for f in args.scopes], hours=args.hours, minutes=args.minutes, model=args.model,
         max_turns=args.max_turns)
    return 0


# ---------------------------------------------------------------- board views
def _cmd_todo(args) -> int:
    b = _board()
    if args.done:
        for t in args.done:
            b.close_todo(int(str(t).lstrip("T")))
        print(f"closed {len(args.done)}")
        return 0
    rows = b.rows("SELECT * FROM todos WHERE status=? ORDER BY id", "done" if args.all else "open")
    for r in rows:
        print(f"T{r['id']:<4} [{r['kind']:14}] {r['program'] or '-':16} {r['title']}")
        if args.verbose and r["detail"]:
            print(f"      {r['detail']}")
    if not rows:
        print("no open todo")
    return 0


def _cmd_finding(args) -> int:
    b = _board()
    if args.id is None:
        for r in b.rows("SELECT id, program, status, severity, vuln_class, title FROM findings ORDER BY id"):
            print(f"F{r['id']:<4} {r['status']:9} {r['severity'] or '?':8} {r['program']:16} [{r['vuln_class']}] {r['title']}")
        return 0
    fid = int(str(args.id).lstrip("F"))
    if args.set:
        b.set_finding(fid, args.set, args.verdict)
        print(f"F{fid} -> {args.set}")
        return 0
    r = b.rows("SELECT * FROM findings WHERE id=?", fid)
    if not r:
        print("unknown finding", file=sys.stderr)
        return 1
    r = dict(r[0])
    for k in ("title", "program", "status", "severity", "vuln_class", "url", "summary", "not_proven", "verdict", "evidence"):
        print(f"{k:11}: {r.get(k)}")
    print("poc:\n" + (r.get("poc") or ""))
    return 0


def _cmd_board(args) -> int:
    b = _board()
    if args.what == "frontier":
        print(b.frontier(args.program))
    else:
        for r in b.rows("SELECT id, kind, title, summary, evidence FROM facts WHERE program=? ORDER BY id", args.program):
            print(f"{r['id']:>4} ({r['kind']}) {r['title']}")
            if args.verbose:
                if r["summary"]:
                    print(f"      {r['summary']}")
                if r["evidence"]:
                    print(f"      ↳ {r['evidence']}")
    return 0


def _cmd_flows(args) -> int:
    path = _home() / "var" / "state" / "flows.jsonl"
    if not path.exists():
        print("no flows yet")
        return 0
    lines = path.read_text().splitlines()[-args.n:]
    for line in lines:
        f = json.loads(line)
        if args.grep and args.grep not in f.get("url", ""):
            continue
        t = time.strftime("%H:%M:%S", time.localtime(f["ts"]))
        print(f"{t} {f['status']} {f['method']:6} {f['len']:>7}B {f['url'][:140]}  ({f['id']})")
    return 0


def _todo_stub(name: str):
    def run(_) -> int:
        print(f"bh {name}: not implemented yet (see docs/TODO.md)", file=sys.stderr)
        return 3
    return run


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bh", description="bull-harness CLI")
    p.add_argument("--version", action="version", version=f"bh {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    scope = sub.add_parser("scope", help="hard scope files").add_subparsers(dest="scmd", required=True)
    c = scope.add_parser("check", help="decide targets against a scope file (rc 1 if any DENY)")
    c.add_argument("file"); c.add_argument("targets", nargs="+"); c.set_defaults(func=_cmd_scope_check)
    s = scope.add_parser("show", help="print a parsed scope file")
    s.add_argument("file"); s.set_defaults(func=_cmd_scope_show)

    u = sub.add_parser("up", help="start gate + agent containers"); u.add_argument("--build", action="store_true")
    u.set_defaults(func=_cmd_up)
    sub.add_parser("down", help="stop the stack").set_defaults(func=_cmd_down)
    sub.add_parser("status", help="stack, last runs, todo count").set_defaults(func=_cmd_status)

    def run_opts(sp):
        sp.add_argument("--model", default=os.environ.get("BH_MODEL", "sonnet"))
        sp.add_argument("--max-turns", type=int, default=60)
        sp.add_argument("--minutes", type=float, default=30)

    r = sub.add_parser("run", help="one agent segment on one program")
    r.add_argument("scope"); run_opts(r)
    r.add_argument("--fresh", action="store_true", help="new session instead of resuming")
    r.add_argument("--task", help="extra operator instruction for this segment")
    r.set_defaults(func=_cmd_run)

    h = sub.add_parser("hunt", help="autonomous supervisor rotating over programs")
    h.add_argument("scopes", nargs="+"); run_opts(h); h.add_argument("--hours", type=float, default=8)
    h.set_defaults(func=_cmd_hunt)

    t = sub.add_parser("todo", help="human todo")
    t.add_argument("--done", nargs="+", metavar="ID"); t.add_argument("--all", action="store_true")
    t.add_argument("-v", "--verbose", action="store_true"); t.set_defaults(func=_cmd_todo)

    f = sub.add_parser("finding", help="list / show / triage findings")
    f.add_argument("id", nargs="?"); f.add_argument("--set", choices=sorted(
        ["new", "verifying", "verified", "rejected", "submitted", "duplicate"]))
    f.add_argument("--verdict"); f.set_defaults(func=_cmd_finding)

    b = sub.add_parser("board", help="facts / frontier of a program")
    b.add_argument("what", choices=["frontier", "facts"]); b.add_argument("program")
    b.add_argument("-v", "--verbose", action="store_true"); b.set_defaults(func=_cmd_board)

    fl = sub.add_parser("flows", help="last requests seen by the gate (targets only)")
    fl.add_argument("-n", type=int, default=30); fl.add_argument("--grep"); fl.set_defaults(func=_cmd_flows)

    for name, helptext in (("plugin", "plugin manifests"), ("ui", "web dashboard"), ("alias", "token-saving aliases")):
        sub.add_parser(name, help=helptext).set_defaults(func=_todo_stub(name))
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
