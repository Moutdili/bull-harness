"""D40: endpoint prefixes the judge approved for a program, merged into its scope by the gate.

`<state>/scope-extra/<program>.yaml` = {program: <program>, in_scope: [{value: "https://host/path/", note: "requested
run N, approved by judge, <date>"}, ...]}. The host writes it (approve, revoke: atomic); the gate's policy reads it
at every reload (bh.gate.policy.Policy.reload) and adds its entries to the scope's in_scope targets. A revoked prefix
is gone at the next reload. Each entry is an https URL prefix of one exact host: never a wildcard, a query, a support
host, a payload host, nor an administration host (`admin*`). A file that does not parse is ignored whole, an entry
that breaks a rule is ignored alone; both are reported (the gate journals `scope-extra-error`).
"""

from __future__ import annotations

import contextlib
import dataclasses
import os
import re
from pathlib import Path
from typing import Any

import yaml

from bh import paths
from bh.scope.model import Rule, RuleType, Scope, ScopeError, parse_rule, support_pattern

DIR = "scope-extra"
_PROGRAM = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}")
_PREFIX = re.compile(r"https://[^/?#@*\s\\]+/[^?#*\s\\]*")
ADMIN_LABEL = re.compile(r"admin", re.I)  # a first host label that starts with it names an administration console


def path(program: str, state: Path | None = None) -> Path | None:
    if not _PROGRAM.fullmatch(program or ""):
        return None
    return (paths.state() if state is None else Path(state)) / DIR / f"{program}.yaml"


def signature(program: str, state: Path | None = None) -> tuple[int, int, int] | None:
    """What changes when the file is rewritten (mtime, size, inode), None without a file."""
    f = path(program, state)
    try:
        st = f.stat() if f is not None else None
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size, st.st_ino) if st is not None else None


def entry_problem(scope: Scope, rule: Rule) -> str | None:
    """Why an approved prefix may not join `scope` (None: it may)."""
    from bh.scope.enforce import check, patterns_overlap  # enforce imports bh.scope.model

    if rule.type is not RuleType.URL or rule.scheme != "https" or not rule.host or "*" in rule.host:
        return "not an https URL prefix of one exact host"
    if ADMIN_LABEL.match(rule.host.split(".", 1)[0]):
        return "an administration host"
    if rule.host in scope.payload_hosts:
        return "a payload host"
    for s in scope.support:
        if patterns_overlap(rule.host, support_pattern(s.rule)):
            return f"a support host ({s.kind})"
    if (d := check(scope, rule.value)).rule is not None and not d.allowed:
        return f"excluded by the scope ({d.rule})"
    return None


def load(scope: Scope, state: Path | None = None) -> tuple[tuple[Rule, ...], list[str]]:
    """The approved prefixes that may join `scope`, and what was ignored (never an exception)."""
    f = path(scope.program, state)
    if f is None:
        return (), []
    try:
        text = f.read_text(encoding="utf-8")
    except FileNotFoundError:
        return (), []
    except OSError as exc:
        return (), [f"{f.name}: unreadable ({exc.__class__.__name__})"]
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return (), [f"{f.name}: invalid YAML, ignored"]
    if doc is None:
        return (), []
    if not isinstance(doc, dict) or not isinstance(doc.get("in_scope", []), list) or set(doc) - {"program", "in_scope"}:
        return (), [f"{f.name}: not a mapping {{program, in_scope: [...]}}, ignored"]
    if doc.get("program", scope.program) != scope.program:
        return (), [f"{f.name}: written for another program, ignored"]
    rules, errors = [], []
    for i, entry in enumerate(doc.get("in_scope") or []):
        ctx = f"{f.name}: in_scope[{i}]"
        value = entry.get("value") if isinstance(entry, dict) else None
        if not isinstance(value, str) or not _PREFIX.fullmatch(value) or set(entry) - {"value", "note"}:
            errors.append(f"{ctx}: not {{value: https://host/path, note}}, ignored")
            continue
        try:
            rule = parse_rule({"value": value, "type": "url", "note": str(entry.get("note", ""))[:300]}, ctx)
        except ScopeError as exc:
            errors.append(f"{exc}, ignored")
            continue
        if why := entry_problem(scope, rule):
            errors.append(f"{ctx} {value[:200]!r}: {why}, ignored")
            continue
        rules.append(rule)
    return tuple(rules), errors


def merged(scope: Scope, rules: tuple[Rule, ...]) -> Scope:
    """`scope` with the approved prefixes appended to its targets (the same object when there is none)."""
    if not rules:
        return scope
    return dataclasses.replace(scope, in_scope=scope.in_scope + rules)


# ---------------------------------------------------------------- host side: what `bh scope requests` writes
def _read(f: Path) -> list[dict[str, Any]]:
    try:
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return []
    items = doc.get("in_scope") if isinstance(doc, dict) else None
    return [e for e in items if isinstance(e, dict)] if isinstance(items, list) else []


def _write(f: Path, program: str, items: list[dict[str, Any]]) -> None:
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_name(f".{f.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)  # no secret; the gate's user reads it
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            yaml.safe_dump({"program": program, "in_scope": items}, fh, sort_keys=False)
        os.replace(tmp, f)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def approve(program: str, prefix: str, note: str, *, state: Path | None = None) -> Path:
    """Add one approved prefix (idempotent). The gate still checks each entry when it merges it."""
    f = path(program, state)
    if f is None or not _PREFIX.fullmatch(prefix):
        raise ValueError("an approved prefix is https://host/path for a valid program name")
    items = [e for e in _read(f) if e.get("value") != prefix]
    _write(f, program, [*items, {"value": prefix, "note": note[:300]}])
    return f


def revoke(program: str, prefix: str, *, state: Path | None = None) -> bool:
    """Remove one prefix; True when it was there. The gate drops it at its next reload."""
    f = path(program, state)
    if f is None:
        return False
    items = _read(f)
    kept = [e for e in items if e.get("value") != prefix]
    if len(kept) == len(items):
        return False
    _write(f, program, kept)
    return True
