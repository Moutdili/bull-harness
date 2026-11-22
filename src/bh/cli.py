"""`bh` — bull-harness CLI (orchestrator entry point)."""

from __future__ import annotations

import argparse
import sys

from bh import __version__


def _cmd_scope_check(args: argparse.Namespace) -> int:
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


def _cmd_scope_show(args: argparse.Namespace) -> int:
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


def _todo(name: str):
    def run(_: argparse.Namespace) -> int:
        print(f"bh {name}: not implemented yet (see docs/TODO.md)", file=sys.stderr)
        return 3
    return run


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bh", description="bull-harness CLI")
    p.add_argument("--version", action="version", version=f"bh {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    scope = sub.add_parser("scope", help="hard scope files").add_subparsers(dest="scmd", required=True)
    c = scope.add_parser("check", help="decide targets against a scope file (rc 1 if any DENY)")
    c.add_argument("file")
    c.add_argument("targets", nargs="+")
    c.set_defaults(func=_cmd_scope_check)
    s = scope.add_parser("show", help="print a parsed scope file")
    s.add_argument("file")
    s.set_defaults(func=_cmd_scope_show)

    for name, helptext in (
        ("plugin", "plugin manifests"),
        ("board", "shared fact board"),
        ("todo", "human todo"),
        ("run", "autonomous runner"),
        ("ui", "web dashboard"),
        ("alias", "token-saving aliases"),
    ):
        sub.add_parser(name, help=helptext).set_defaults(func=_todo(name))
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
