#!/usr/bin/env python3
"""From a real run to a replay fixture (T19 d): `tools/trace-to-fixture.py <run_id> <dir>`.

Run on the host, from the repository (BH_HOME, default the current directory). After a bug of the harness, the
orchestrator turns the run that showed it into a trace of tests/replay, then writes in its expected.json the state the
fix must give.

What it copies, for run <run_id> of program P (runs.program on the board):
  notes      var/work/P/.bh/notes-<run>-leg*.jsonl then notes-<run>.jsonl (the rotated notes, in ingestion order)
  events     the lines of var/state/events.jsonl tagged with the run
  flows      the lines of var/state/flows.jsonl tagged with the run, and their var/state/flows/<id>.json
  stream     var/runs/<run:05d>-P.jsonl (the claude stream-json)

Every string goes through bh.redact (`data` on JSON, `text` on every string value), then names are replaced by
templates: the scope's hosts and their subdomains by target-<n>.example, addresses of its CIDRs by 192.0.2.<n>, the
program by `program`, identity names by identity-<n>, any e-mail address by user-<n>@example.invalid. The fixture is
written only when no host of the scope and not the program's name is left anywhere in it (also written without its
dots: `shopexamplecom`); otherwise nothing is written and the exit code is 2. The fixture is marked
`"synthetic": false`; its expected.json is the board this code gives today (a baseline to correct by hand).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

from bh import paths, redact
from bh.agent import contract as c
from bh.board import Board
from bh.scope import ScopeError, load_scope

REPLAY = Path(__file__).resolve().parent.parent / "tests" / "replay"
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")


class Refused(RuntimeError):
    """A name of the scope survived the templating: nothing is written."""


def scope_for(program: str):
    for f in sorted(paths.scopes_dir().rglob("*.yaml")):
        try:
            s = load_scope(f)
        except ScopeError:
            continue
        if s.program == program:
            return s
    return None


class Templater:
    """Replaces the names of one scope by stable templates, in every string of a JSON value."""

    def __init__(self, program: str, scope) -> None:
        self.program = program
        self.bases: list[str] = []
        self.nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for rule in [*(scope.in_scope if scope else ()), *(s.rule for s in (scope.support if scope else ()))]:
            if rule.network is not None:
                self.nets.append(rule.network)
            elif rule.host:
                self.bases.append(rule.host.lower().removeprefix("*.").strip("."))
        self.bases = sorted({b for b in self.bases if b and "*" not in b}, key=len, reverse=True)
        self.idents = sorted(
            {str(i.get("name")) for i in (scope.identities if scope else ()) if isinstance(i.get("name"), str)},
            key=len,
            reverse=True,
        )
        self.hosts: dict[str, str] = {}
        self.ips: dict[str, str] = {}
        self.emails: dict[str, str] = {}
        self._host_rx = (
            re.compile(
                r"(?<![A-Za-z0-9-])((?:[A-Za-z0-9-]+\.)*(?:" + "|".join(re.escape(b) for b in self.bases) + r"))"
                r"(?![A-Za-z0-9-])",
                re.I,
            )
            if self.bases
            else None
        )

    def ident(self, name: str) -> str:
        return f"identity-{self.idents.index(name) + 1}" if name in self.idents else name

    def _host(self, m: re.Match) -> str:
        h = m.group(1).lower()
        return self.hosts.setdefault(h, f"target-{len(self.hosts) + 1}.example")

    def _ip(self, m: re.Match) -> str:
        s = m.group(0)
        try:
            ip = ipaddress.ip_address(s)
        except ValueError:
            return s
        if not any(ip in n for n in self.nets):
            return s
        return self.ips.setdefault(s, f"192.0.2.{len(self.ips) + 1}")

    def _email(self, m: re.Match) -> str:
        return self.emails.setdefault(m.group(0).lower(), f"user-{len(self.emails) + 1}@example.invalid")

    def text(self, s: str) -> str:
        s = redact.text(s)
        s = _EMAIL.sub(self._email, s)
        if self._host_rx is not None:
            s = self._host_rx.sub(self._host, s)
        if self.nets:
            s = _IPV4.sub(self._ip, s)
        if self.program:
            s = re.sub(rf"(?<![A-Za-z0-9]){re.escape(self.program)}(?![A-Za-z0-9])", "program", s)
        for name in self.idents:
            s = re.sub(rf"(?<![A-Za-z0-9_-]){re.escape(name)}(?![A-Za-z0-9_-])", self.ident(name), s)
        return s

    def value(self, v):
        if isinstance(v, dict):
            return {k: self.value(x) for k, x in v.items()}
        if isinstance(v, list):
            return [self.value(x) for x in v]
        if isinstance(v, str):
            return self.text(v)
        return v

    def record(self, rec):
        return self.value(redact.data(rec))

    def leftover(self, text: str) -> str | None:
        """A name of the scope still in `text` (a host, its dotless form, the program), None when there is none."""
        return c.names_in(text, hosts=self.bases, words=[self.program] if self.program else [])


def _jsonl(path: Path) -> list:
    out = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return out
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except ValueError:
            out.append(ln)  # kept as text: a malformed line is part of what the ingestion saw
    return out


def _ours(rec, run_id: int) -> bool:
    return isinstance(rec, dict) and rec.get("run") is not None and str(rec.get("run")) == str(run_id)


def collect(run_id: int, program: str) -> dict:
    """The run's files, as read on the host (nothing templated yet)."""
    bh = paths.work_bh(program)
    legs = sorted(bh.glob(f"notes-{run_id}-leg*.jsonl"), key=lambda p: int(re.sub(r"\D", "", p.stem.split("leg")[-1])))
    notes = [r for p in [*legs, bh / f"notes-{run_id}.jsonl"] for r in _jsonl(p)]
    events = [e for e in _jsonl(paths.events_log()) if _ours(e, run_id)]
    flows = [f for f in _jsonl(paths.flows_log()) if _ours(f, run_id)]
    docs = {}
    for f in flows:
        fid = f.get("id")
        if isinstance(fid, str) and c.FLOW_ID_RE.fullmatch(fid) and paths.flow_file(fid).is_file():
            try:
                docs[fid] = json.loads(paths.flow_file(fid).read_text(encoding="utf-8", errors="replace"))
            except ValueError:
                continue
    stream = _jsonl(paths.run_log(run_id, program))
    return {"notes": notes, "events": events, "flows": flows, "flow_docs": docs, "stream": stream}


def _dump(recs: list, t: Templater) -> str:
    return "".join(
        (json.dumps(t.record(r), ensure_ascii=False) if not isinstance(r, str) else t.text(r)) + "\n" for r in recs
    )


def convert(run_id: int, out: Path, *, board: Board | None = None, write_expected: bool = True) -> Path:
    """Write the fixture of run `run_id` to `out` (which must not exist or be empty). Raises Refused, ValueError."""
    out = Path(out)
    if out.exists() and any(out.iterdir()):
        raise ValueError(f"{out} exists and is not empty")
    board = board or Board(paths.board_db())
    rows = board.rows("SELECT program, model FROM runs WHERE id=?", run_id)
    if not rows:
        raise ValueError(f"no run {run_id} on the board")
    program = str(rows[0]["program"]).split("~", 1)[0]  # a reset archives a run's program as P~<date>
    scope = scope_for(program)
    t = Templater(program, scope)
    files = collect(run_id, program)
    texts = {
        "notes.jsonl": _dump(files["notes"], t),
        "events.jsonl": _dump(files["events"], t),
        "flows.jsonl": _dump(files["flows"], t),
        "stream.jsonl": _dump(files["stream"], t),
    }
    for fid, doc in files["flow_docs"].items():
        texts[f"flows/{fid}.json"] = json.dumps(t.record(doc), ensure_ascii=False)
    meta = {
        "synthetic": False,
        "about": f"converted from run {run_id} by tools/trace-to-fixture.py: describe the bug it pins",
        "program": "program",
        "run_id": run_id,
        "model": "replay",
        "identities": [t.ident(i) for i in sorted(t.idents)],
    }
    if scope is not None:
        meta["scope"] = {
            "program": "program",
            "platform": "local",
            "in_scope": [*t.hosts.values(), *t.ips.values()] or ["target-1.example"],
            "forbidden_vulns": list(scope.forbidden_vulns),
            "identities": [{"name": t.ident(i)} for i in sorted(t.idents)],
        }
    texts["trace.json"] = json.dumps(meta, indent=1) + "\n"
    for name, text in texts.items():
        if (hit := t.leftover(text)) is not None:
            raise Refused(f"{name}: a name of the scope survived the templating ({hit}); nothing written")
    tmp = Path(tempfile.mkdtemp(prefix=".trace-", dir=out.parent if out.parent.exists() else None))
    try:
        for name, text in texts.items():
            (tmp / name).parent.mkdir(parents=True, exist_ok=True)
            (tmp / name).write_text(text, encoding="utf-8")
        if write_expected:
            sys.path.insert(0, str(REPLAY))
            try:
                import harness  # tests/replay/harness.py

                work = Path(tempfile.mkdtemp(prefix="bh-replay-"))
                try:
                    board = harness.replay(tmp, work)
                    harness.write_expected(board, tmp)
                    board.db.close()
                finally:
                    shutil.rmtree(work, ignore_errors=True)
            finally:
                sys.path.remove(str(REPLAY))
        if out.exists():
            out.rmdir()
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(tmp), str(out))
    finally:
        if tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="trace-to-fixture", description=__doc__.split("\n\n")[0])
    p.add_argument("run_id", type=int)
    p.add_argument("dir", type=Path, help="the fixture directory to create (tests/replay/traces/<name>)")
    p.add_argument("--no-expected", action="store_true", help="do not replay the fixture to write expected.json")
    a = p.parse_args(argv)
    try:
        out = convert(a.run_id, a.dir, write_expected=not a.no_expected)
    except Refused as exc:
        print(f"trace-to-fixture: refused: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"trace-to-fixture: {exc}", file=sys.stderr)
        return 1
    print(f"fixture written: {out} (review expected.json: it is today's behaviour, not the fix's)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
