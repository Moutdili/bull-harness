"""`bh` — bull-harness CLI (orchestrator entry point)."""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from bh import __version__, paths, stack

UI_PORT = 7340
NUCLEI_TEMPLATES_REPO = "https://github.com/projectdiscovery/nuclei-templates.git"
NUCLEI_TEMPLATES_TAG = "v10.5.2"  # pinned: bump deliberately, the scan profile depends on the layout


def _board():
    from bh.board import Board

    return Board()


def _load_scope_or_exit(file: str):
    from bh.scope import ScopeError, load_scope

    try:
        return load_scope(file)
    except ScopeError as exc:
        raise SystemExit(f"ERR {exc}") from exc


# ---------------------------------------------------------------- scope
def cmd_scope_check(args) -> int:
    from bh.scope import check

    scope = _load_scope_or_exit(args.file)
    denied = 0
    for target in args.targets:
        d = check(scope, target)
        denied += not d.allowed
        print(f"{'ALLOW' if d.allowed else 'DENY '} {target} — {d.reason}" + (f" [{d.rule}]" if d.rule else ""))
    return 1 if denied else 0


def cmd_scope_import(args) -> int:
    """Public YesWeHack program -> scopes/ywh/<slug>.yaml (never widens; automation left to the human)."""
    import yaml

    from bh.scope import ScopeError, scope_from_dict
    from bh.scope import yeswehack as ywh

    username = args.username or _researcher().get("BH_YWH_USERNAME")
    try:
        imp = ywh.convert(ywh.fetch(args.slug), username)
        scope_from_dict(imp.doc, args.slug)  # must load exactly like the file will
    except ScopeError as exc:
        raise SystemExit(f"ERR {exc}") from exc
    dst = paths.scopes_dir() / "ywh" / f"{args.slug}.yaml"
    if dst.exists() and not args.force:
        raise SystemExit(f"{dst} exists (add --force to overwrite)")
    dst.parent.mkdir(parents=True, exist_ok=True)
    header = (
        f"# Imported from YesWeHack ({imp.doc['source']}) on {imp.doc['synced_at']}.\n"
        "# Review before running: read the program rules, then set automation_allowed and max_rps.\n"
    )
    dst.write_text(header + yaml.safe_dump(imp.doc, sort_keys=False, allow_unicode=True, width=110))
    real = [r for r in imp.doc["in_scope"] if r.get("type") != "other"]
    print(
        f"wrote {dst.relative_to(paths.home())}: {len(real)} enforceable in-scope rules, "
        f"{len(imp.doc['out_of_scope'])} exclusions, {len(imp.doc['forbidden_vulns'])} non-qualifying classes"
    )
    ua, rps = imp.doc["user_agent"] or "(none required)", imp.doc["max_rps"] or "not stated (gate default 2)"
    print(f"user-agent: {ua} · max_rps: {rps}")
    if imp.doc["scanners_allowed"] is False:
        print("the rules forbid automated scanners: scanners_allowed=false (only bh-recon, bh-crawl and manual tests)")
    if imp.skipped:
        print("NOT enforced, translate by hand if you want them:\n  " + "\n  ".join(imp.skipped))
    if imp.conflicts:
        print(
            "out-of-scope text names LISTED assets, NOT applied (read the program text):\n  "
            + "\n  ".join(imp.conflicts)
        )
    if imp.rule_excerpts:
        print("rules lines about automation / rate / headers (read the full rules too):")
        print("  " + "\n  ".join(line[:200] for line in imp.rule_excerpts))
    print(
        "next: set automation_allowed and scanners_allowed (true/false) after reading the rules (the runner "
        "refuses while either is null); create test accounts with your "
        "@yeswehack.ninja alias and store them as identities (UI > Todo or var/state/identities)."
    )
    return 0


def _scope_for(program: str):
    """The scope file whose `program` is `program` (None if there is none)."""
    from bh.scope import ScopeError, load_scope

    for f in sorted(paths.scopes_dir().rglob("*.yaml")):
        try:
            s = load_scope(f)
        except ScopeError:
            continue
        if s.program == program:
            return s
    return None


def _researcher() -> dict[str, str]:
    """secrets/researcher.env: KEY=value lines (YWH alias e-mail, username). Never sent anywhere."""
    p = paths.secrets_dir() / "researcher.env"
    if not p.exists():
        return {}
    return dict(line.split("=", 1) for line in p.read_text().splitlines() if "=" in line and not line.startswith("#"))


def cmd_scope_show(args) -> int:
    s = _load_scope_or_exit(args.file)
    print(f"{s.platform}/{s.program}  digest={s.digest[:12]}  rps={s.max_rps}  automation={s.automation_allowed}")
    for label, rules in (("in", s.in_scope), ("out", s.out_of_scope)):
        for r in rules:
            print(f"  {label:3} {r}")
    for k, v in s.required_headers.items():
        print(f"  hdr {k}: {v}")
    return 0


# ---------------------------------------------------------------- stack
def cmd_up(args) -> int:
    if not (paths.secrets_dir() / "agent.env").exists():
        print(
            "missing secrets/agent.env — create it with:\n"
            "  claude setup-token   # in YOUR terminal, then:\n"
            "  printf 'CLAUDE_CODE_OAUTH_TOKEN=%s\\n' '<token>' > secrets/agent.env && chmod 600 secrets/agent.env",
            file=sys.stderr,
        )
        return 2
    if not (paths.tools_dir() / "nuclei-templates").is_dir():
        print("nuclei templates missing: run `bh tools fetch` first", file=sys.stderr)
        return 2
    for d in (
        paths.var() / "gate" / "conf",
        paths.state() / "identities",
        paths.var() / "gate-ca",
        paths.var() / "work",
        paths.runs_dir(),
    ):
        d.mkdir(parents=True, exist_ok=True)
    rc = stack.compose("up", "-d", *(["--build"] if args.build else []))
    if rc == 0 and not args.no_ui:
        ui_start_daemon(None, UI_PORT)
    return rc


def cmd_down(args) -> int:
    return stack.compose("down")


def cmd_tools_fetch(args) -> int:
    """Host-side downloads the sandbox cannot do (the gate blocks GitHub)."""
    dst = paths.tools_dir() / "nuclei-templates"
    if dst.is_dir():
        print(f"{dst} already present (delete it to refetch {NUCLEI_TEMPLATES_TAG})")
        return 0
    dst.parent.mkdir(parents=True, exist_ok=True)
    return subprocess.call(
        ["git", "clone", "-q", "--depth", "1", "--branch", NUCLEI_TEMPLATES_TAG, NUCLEI_TEMPLATES_REPO, str(dst)]
    )


def cmd_status(args) -> int:
    for name in (stack.GATE, stack.AGENT):
        print(f"{name:9} {'running' if stack.container_running(name) else 'DOWN'}")
    if paths.active_scope().exists():
        s = _load_scope_or_exit(str(paths.active_scope()))
        print(f"active scope: {s.platform}/{s.program} (rps {s.max_rps})")
    b = _board()
    for r in b.rows(
        "SELECT id, program, status, turns, cost_usd, arsenal_calls, manual_calls, locked_calls, "
        "datetime(started,'unixepoch','localtime') AS t FROM runs ORDER BY id DESC LIMIT 5"
    ):
        print(
            f"run {r['id']:>4} {r['t']} {r['program']:20} {r['status']:9} {r['turns'] or 0:>3} turns"
            f"  arsenal/manual/locked {r['arsenal_calls'] or 0}/{r['manual_calls'] or 0}/{r['locked_calls'] or 0}"
            + (f"  ${r['cost_usd']:.2f} eq." if r["cost_usd"] else "")
        )
    n_todo = b.rows("SELECT COUNT(*) AS n FROM todos WHERE status='open'")[0]["n"]
    n_find = b.rows("SELECT COUNT(*) AS n FROM findings WHERE status IN ('new','verified')")[0]["n"]
    print(f"open todos: {n_todo} · findings to review: {n_find}")
    return 0


# ---------------------------------------------------------------- runs
def cmd_run(args) -> int:
    from bh.runner.run import run_segment

    res = run_segment(
        Path(args.scope),
        model=args.model,
        max_turns=args.max_turns,
        minutes=args.minutes,
        resume=args.resume,
        extra_task=args.task or "",
        effort=args.effort,
    )
    if res.text:
        print("\n" + res.text.strip())
    return 0 if res.status in ("ok", "max_turns", "timeout") else 1


def cmd_verify(args) -> int:
    """Re-verify findings of a program (default: every finding still 'new')."""
    from bh.board import Board
    from bh.runner.run import activate_scope, run_lock, set_active_run
    from bh.verify import verify_finding, verify_pending

    scope = _load_scope_or_exit(args.scope)
    board = Board()
    with run_lock():
        run_id = board.run_start(scope.program, args.model)
        activate_scope(Path(args.scope))  # the replays go through the gate under this program's rules
        set_active_run(run_id, scope.program)  # tags the replays, and the gate relays the judge's calls
        try:
            if args.findings:
                for f in args.findings:
                    verify_finding(
                        board, scope, int(str(f).lstrip("F")), run_id=run_id, model=args.model, effort=args.effort
                    )
            else:
                print(
                    verify_pending(board, scope, run_id=run_id, model=args.model, effort=args.effort, limit=args.limit)
                )
        finally:
            set_active_run(None)
            board.run_end(run_id, status="ok", note="verification")
    return 0


def cmd_hunt(args) -> int:
    from bh.runner.supervisor import hunt

    hunt(
        [Path(f) for f in args.scopes],
        hours=args.hours,
        minutes=args.minutes,
        model=args.model,
        max_turns=args.max_turns,
        effort=args.effort,
    )
    return 0


# ---------------------------------------------------------------- board views
def cmd_todo(args) -> int:
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


def cmd_finding(args) -> int:
    b = _board()
    if args.id is None:
        for r in b.rows("SELECT id, program, status, severity, vuln_class, title FROM findings ORDER BY id"):
            sev = r["severity"] or "?"
            print(f"F{r['id']:<4} {r['status']:9} {sev:8} {r['program']:16} [{r['vuln_class']}] {r['title']}")
        return 0
    fid = int(str(args.id).lstrip("F"))
    if args.set:
        b.set_finding(fid, args.set, args.verdict)
        print(f"F{fid} -> {args.set}")
        return 0
    rows = b.rows("SELECT * FROM findings WHERE id=?", fid)
    if not rows:
        print("unknown finding", file=sys.stderr)
        return 1
    r = dict(rows[0])
    for k in (
        "title",
        "program",
        "status",
        "severity",
        "vuln_class",
        "url",
        "summary",
        "not_proven",
        "verdict",
        "evidence",
    ):
        print(f"{k:11}: {r.get(k)}")
    print("poc:\n" + (r.get("poc") or ""))
    return 0


def cmd_board(args) -> int:
    b = _board()
    if args.what == "frontier":
        from bh.runner.run import frontier

        scope = _scope_for(args.program)
        if scope is not None:
            from bh.assets import Graph

            Graph(b, scope).sync(None)
        print(frontier(b, args.program, scope))
    elif args.what == "reset":
        return board_reset(b, args.program, args.yes)
    else:
        for r in b.rows(
            "SELECT id, kind, title, summary, evidence FROM facts WHERE program=? ORDER BY id", args.program
        ):
            print(f"{r['id']:>4} ({r['kind']}) {r['title']}")
            if args.verbose:
                if r["summary"]:
                    print(f"      {r['summary']}")
                if r["evidence"]:
                    print(f"      ↳ {r['evidence']}")
    return 0


def board_reset(b, program: str, yes: bool) -> int:
    """Training labs: back up the board, forget the program, wipe its sandbox work dir."""
    if not yes:
        print(
            f"this deletes every fact, finding, todo and run of '{program}' and its /work dir; add --yes",
            file=sys.stderr,
        )
        return 2
    backup = paths.var() / f"board-{time.strftime('%Y%m%d-%H%M%S')}.sqlite"
    b.db.execute("VACUUM INTO ?", (str(backup),))
    deleted = b.reset_program(program)
    stack.wipe_program(program)
    shutil.rmtree(paths.stage(program), ignore_errors=True)
    print(f"backup {backup}; deleted {deleted}")
    return 0


def cmd_flows(args) -> int:
    from bh.agent.contract import tail_jsonl

    for f in tail_jsonl(paths.flows_log(), args.n):
        if args.grep and args.grep not in f.get("url", ""):
            continue
        t = time.strftime("%H:%M:%S", time.localtime(f["ts"]))
        print(f"{t} {f['status']} {f['method']:6} {f['len']:>7}B {f['url'][:140]}  ({f['id']})")
    return 0


def cmd_prune(args) -> int:
    from bh import retention
    from bh.runner.run import run_lock

    with run_lock():  # never while a segment reads or the gate writes for it
        out = retention.prune(days=retention.FLOW_DAYS if args.days is None else args.days)
    print(", ".join(f"{k}: {v}" for k, v in out.items()))
    return 0


# ---------------------------------------------------------------- UI daemon
def ui_pidfile() -> Path:
    return paths.var() / "ui.pid"


def ui_start_daemon(host: str | None, port: int) -> int:
    if pid := stack.pid_alive(ui_pidfile()):
        print(f"ui already running (pid {pid})")
        return 0
    paths.var().mkdir(exist_ok=True)
    cmd = [sys.executable, "-m", "bh.cli", "ui", "--foreground", "--port", str(port)] + (
        ["--host", host] if host else []
    )
    with open(paths.var() / "ui.log", "a") as log:  # the child keeps its own descriptor
        p = subprocess.Popen(
            cmd,
            cwd=paths.home(),
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env={**os.environ, "BH_HOME": str(paths.home())},
        )
    ui_pidfile().write_text(str(p.pid))
    time.sleep(1.5)
    if p.poll() is not None:
        print("ui failed to start, see var/ui.log", file=sys.stderr)
        return 1
    from bh.ui.server import default_host

    print(f"ui: http://{host or default_host()}:{port}/  (login with the token in secrets/ui.token)")
    return 0


def cmd_ui(args) -> int:
    if args.stop:
        if pid := stack.pid_alive(ui_pidfile()):
            os.kill(pid, signal.SIGTERM)
            print(f"ui stopped (pid {pid})")
        return 0
    if args.foreground:
        from bh.ui.server import serve

        serve(args.host, args.port)
        return 0
    return ui_start_daemon(args.host, args.port)


# ---------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bh", description="bull-harness CLI")
    p.add_argument("--version", action="version", version=f"bh {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    scope = sub.add_parser("scope", help="hard scope files").add_subparsers(dest="scmd", required=True)
    c = scope.add_parser("check", help="decide targets against a scope file (rc 1 if any DENY)")
    c.add_argument("file")
    c.add_argument("targets", nargs="+")
    c.set_defaults(func=cmd_scope_check)
    s = scope.add_parser("show", help="print a parsed scope file")
    s.add_argument("file")
    s.set_defaults(func=cmd_scope_show)
    im = scope.add_parser("import", help="import a public program (YesWeHack) into scopes/<platform>/")
    im.add_argument("platform", choices=["ywh"])
    im.add_argument("slug", help="program slug, as in https://yeswehack.com/programs/<slug>")
    im.add_argument(
        "--username", help="your YWH username (for the required User-Agent); default: secrets/researcher.env"
    )
    im.add_argument("--force", action="store_true", help="overwrite an existing scope file")
    im.set_defaults(func=cmd_scope_import)

    u = sub.add_parser("up", help="start gate + agent containers (+ web UI)")
    u.add_argument("--build", action="store_true")
    u.add_argument("--no-ui", action="store_true")
    u.set_defaults(func=cmd_up)
    sub.add_parser("down", help="stop the stack").set_defaults(func=cmd_down)
    tools = sub.add_parser("tools", help="host-side tool data").add_subparsers(dest="tcmd", required=True)
    tools.add_parser("fetch", help=f"clone nuclei-templates {NUCLEI_TEMPLATES_TAG} into var/tools").set_defaults(
        func=cmd_tools_fetch
    )
    ui = sub.add_parser("ui", help="web UI (daemon by default; binds the Tailscale IP)")
    ui.add_argument("--host")
    ui.add_argument("--port", type=int, default=UI_PORT)
    ui.add_argument("--foreground", action="store_true")
    ui.add_argument("--stop", action="store_true")
    ui.set_defaults(func=cmd_ui)
    sub.add_parser("status", help="stack, last runs, todo count").set_defaults(func=cmd_status)

    def run_opts(sp):
        from bh.runner.run import DEFAULT_MODEL

        sp.add_argument("--model", default=os.environ.get("BH_MODEL", DEFAULT_MODEL))
        sp.add_argument(
            "--effort", default=os.environ.get("BH_EFFORT"), choices=["low", "medium", "high", "xhigh", "max"]
        )
        sp.add_argument("--max-turns", type=int, default=60)
        sp.add_argument("--minutes", type=float, default=30)

    r = sub.add_parser("run", help="one agent segment on one program")
    r.add_argument("scope")
    run_opts(r)
    r.add_argument(
        "--resume",
        action="store_true",
        help="resume the last session instead of a fresh one "
        "(fresh is the default: cheaper, the board + HANDOFF carry the state)",
    )
    r.add_argument("--task", help="extra operator instruction for this segment")
    r.set_defaults(func=cmd_run)

    v = sub.add_parser("verify", help="independent verification of findings (replay + verifier session)")
    v.add_argument("scope")
    v.add_argument("findings", nargs="*", help="F12 F13 ... (default: every finding still 'new')")
    run_opts(v)
    v.add_argument("--limit", type=int, default=5)
    from bh.verify import VERIFIER_MODEL

    v.set_defaults(func=cmd_verify, model=VERIFIER_MODEL)  # the judge's model, not the hunter's

    h = sub.add_parser("hunt", help="autonomous supervisor rotating over programs")
    h.add_argument("scopes", nargs="+")
    run_opts(h)
    h.add_argument("--hours", type=float, default=8)
    h.set_defaults(func=cmd_hunt)

    t = sub.add_parser("todo", help="human todo")
    t.add_argument("--done", nargs="+", metavar="ID")
    t.add_argument("--all", action="store_true")
    t.add_argument("-v", "--verbose", action="store_true")
    t.set_defaults(func=cmd_todo)

    f = sub.add_parser("finding", help="list / show / triage findings")
    f.add_argument("id", nargs="?")
    from bh.board.db import FINDING_STATUS

    f.add_argument("--set", choices=sorted(FINDING_STATUS))
    f.add_argument("--verdict")
    f.set_defaults(func=cmd_finding)

    b = sub.add_parser("board", help="facts / frontier of a program, or reset it (labs)")
    b.add_argument("what", choices=["frontier", "facts", "reset"])
    b.add_argument("program")
    b.add_argument("-v", "--verbose", action="store_true")
    b.add_argument("--yes", action="store_true", help="confirm `reset`")
    b.set_defaults(func=cmd_board)

    fl = sub.add_parser("flows", help="last requests seen by the gate (targets only)")
    fl.add_argument("-n", type=int, default=30)
    fl.add_argument("--grep")
    fl.set_defaults(func=cmd_flows)

    pr = sub.add_parser("prune", help="delete gate flow files older than --days, rotate large gate logs")
    pr.add_argument("--days", type=float, default=None, help="default: BH_FLOW_DAYS or 14")
    pr.set_defaults(func=cmd_prune)
    return p


def _sigterm(signum, frame):  # SIGTERM behaves like Ctrl-C: runners kill the in-container agent
    raise KeyboardInterrupt


def main(argv: list[str] | None = None) -> int:
    signal.signal(signal.SIGTERM, _sigterm)
    signal.signal(signal.SIGHUP, _sigterm)  # terminal / SSH closed: same clean stop, the agent is killed
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
