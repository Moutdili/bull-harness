"""`bh scope new msrc <service> --from <survey>` (D32): a new MSRC service scope, written from a host survey.

The MSRC ground widens one service at a time, never by wildcard: every target of the file is a host or a prefix the
survey saw live (the table format of docs/research/21-releve-hotes-outlook-onedrive.md: `| Host, prefix | Role |
Methods seen | Route type |`, the host in backticks). `write(service, capture)` writes `scopes/msrc/<service>.yaml`:

- program `msrc-<service>`, platform msrc, our two identities (user-a, user-b);
- `scanners_allowed: false`, `max_rps: 2`, `forbidden_vulns: [dos]`, `automation_allowed: false` (Mio sets it after
  reading the rules);
- `payload_hosts` and `rules_url` taken from the Copilot scope (scopes/msrc/copilot.yaml);
- `recipient_guard` on the survey's send and share routes (a role or route type that sends, shares, invites or
  grants).

It refuses a wildcard host, a host the survey does not list, a file that already exists, and a survey with no host.
It ends with bh.scope.guards.check and says what is missing. Nothing is fetched: the survey is a local file.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from bh import paths

PLATFORM = "msrc"
SERVICE_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
COPILOT_PROGRAM = "msrc-copilot"
IDENTITIES = ({"name": "user-a", "role": "member", "tenant": "A"}, {"name": "user-b", "role": "member", "tenant": "B"})
MAX_RPS = 2
# A send or share route of the survey: its route type says so (`send`, envoi, partage, share, invitation, grant), or
# its role invites, shares or grants with a writing method. Guarded: the gate wants one of our two addresses in it.
SEND_ROUTE = re.compile(r"\b(send\w*|envoi\w*|partag\w*|shar\w*|invit\w*|grant\w*|destinataire)\b", re.I)
SHARE_ROLE = re.compile(r"\b(partag\w*|shar\w*|invit\w*|grant\w*)\b", re.I)
WRITE_METHOD = re.compile(r"\b(POST|PUT|PATCH|DELETE)\b")
NO_RECIPIENT = re.compile(r"aucun destinataire|no recipient", re.I)
_HOST = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", re.I)
_DATE = re.compile(r"\b(20\d\d-\d\d-\d\d)\b")


class ScaffoldError(ValueError):
    pass


def _cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _section(text: str, service: str) -> str:
    """The survey's `## ...` section that names the service, else the whole text."""
    parts = re.split(r"(?m)^(?=## )", text)
    for p in parts:
        head = p.splitlines()[0] if p.strip() else ""
        if head.startswith("## ") and service.lower() in head.lower():
            return p
    return text


def _value(cell: str) -> str | None:
    """The host or prefix of a survey cell: its first backticked value, cut at its first placeholder."""
    m = re.search(r"`([^`]+)`", cell)
    raw = (m.group(1) if m else cell).strip()
    raw = re.split(r"[<…(\s]", raw, maxsplit=1)[0].strip()
    return raw or None


def survey(capture: Path, service: str) -> list[dict[str, Any]]:
    """[{value, host, role, methods, route}] of the survey's tables (the service's section when there is one)."""
    try:
        text = Path(capture).read_text(encoding="utf-8")
    except OSError as exc:
        raise ScaffoldError(f"cannot read the survey {capture}: {type(exc).__name__}") from exc
    rows: list[dict[str, Any]] = []
    lines = _section(text, service).splitlines()
    for i, line in enumerate(lines):
        if not line.lstrip().startswith("|"):
            continue
        cells = _cells(line)
        if all(re.fullmatch(r":?-{3,}:?", c) for c in cells if c):
            continue  # the separator line
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        if nxt.lstrip().startswith("|") and all(re.fullmatch(r":?-{3,}:?", c) for c in _cells(nxt) if c):
            continue  # a header row
        value = _value(cells[0]) if cells else None
        if not value:
            continue
        host = re.sub(r"^https?://", "", value).split("/", 1)[0].lower()
        rows.append(
            {
                "value": value,
                "host": host,
                "role": cells[1] if len(cells) > 1 else "",
                "methods": cells[2] if len(cells) > 2 else "",
                "route": cells[3] if len(cells) > 3 else "",
            }
        )
    return rows


def _sends(r: dict[str, Any]) -> bool:
    """A route that names a recipient (see SEND_ROUTE): `link`, "aucun destinataire" / "no recipient" is not one."""
    if NO_RECIPIENT.search(r["route"]):
        return False
    return bool(SEND_ROUTE.search(r["route"]) or (SHARE_ROLE.search(r["role"]) and WRITE_METHOD.search(r["methods"])))


def _url_regex(value: str) -> str:
    """The recipient_guard regex of a surveyed prefix: anchored on its URL (a bare host: https://host/)."""
    url = value if "://" in value else f"https://{value}/"
    return "^" + re.escape(url)


def _copilot() -> dict[str, Any]:
    """payload_hosts and rules_url of the Copilot scope ({} when it cannot be read)."""
    import yaml

    candidates = [paths.scopes_dir() / PLATFORM / "copilot.yaml", *sorted(paths.scopes_dir().rglob("*.yaml"))]
    for f in candidates:
        try:
            doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            continue
        if isinstance(doc, dict) and doc.get("program") == COPILOT_PROGRAM:
            return {k: list(doc.get(k) or []) for k in ("payload_hosts", "rules_url")}
    return {}


def build(service: str, capture: Path, hosts: list[str] | None = None) -> dict[str, Any]:
    """The scope document (not written)."""
    if not SERVICE_RE.fullmatch(service or ""):
        raise ScaffoldError("service: lowercase letters, digits and '-', 40 at most")
    rows = survey(capture, service)
    if not rows:
        raise ScaffoldError(f"no host in the survey {capture} for {service}")
    for r in rows:
        if "*" in r["value"]:
            raise ScaffoldError(f"{r['value']!r}: a wildcard host; MSRC widens one surveyed host at a time")
        if not _HOST.fullmatch(r["host"]):
            raise ScaffoldError(f"{r['value']!r}: not a host name")
    if hosts:
        keep = []
        for h in hosts:
            if "*" in h:
                raise ScaffoldError(f"{h!r}: a wildcard host; MSRC widens one surveyed host at a time")
            hit = [r for r in rows if h in (r["value"], r["host"])]
            if not hit:
                raise ScaffoldError(f"{h!r} is not in the survey {capture}")
            keep += [r for r in hit if r not in keep]
        rows = keep
    seen = _DATE.search(Path(capture).read_text(encoding="utf-8"))
    when = f"seen {seen.group(1)}" if seen else "seen in the survey"
    in_scope, guard = [], []
    for r in rows:
        note = re.sub(r"\s+", " ", f"{r['role']} ({r['methods'] or '?'}), {when}").replace("`", "")[:300]
        if r["value"] not in [x["value"] for x in in_scope]:
            in_scope.append({"value": r["value"], "note": note})
        if _sends(r):
            guard.append({"url": _url_regex(r["value"]), "note": f"send or share route of the survey: {note}"[:300]})
    cp = _copilot()
    return {
        "schema": 1,
        "program": f"{PLATFORM}-{service}",
        "platform": PLATFORM,
        "automation_allowed": False,
        "scanners_allowed": False,
        "self_signup": False,
        "max_rps": MAX_RPS,
        "forbidden_vulns": ["dos"],
        "in_scope": in_scope,
        "recipient_guard": guard,
        "rules_url": cp.get("rules_url", []),
        "support": [],
        "out_of_scope": [],
        "payload_hosts": cp.get("payload_hosts", []),
        "identities": [dict(i) for i in IDENTITIES],
        "notes": (
            f"MSRC {service}, written by `bh scope new` from {Path(capture).name}: only the hosts the survey saw live, "
            "our two personal accounts only (user-a, user-b). automation_allowed stays false until Mio reads the "
            "program rules."
        ),
    }


def write(
    service: str,
    capture: Path,
    *,
    hosts: list[str] | None = None,
    say: Callable[[str], None] | None = print,
) -> Path:
    """Write scopes/msrc/<service>.yaml from the survey `capture`; refuses an existing file. Ends with the guards
    of the platform (bh.scope.guards.check): what is missing is said through `say`."""
    import yaml

    from bh.scope import ScopeError, scope_from_dict

    doc = build(service, Path(capture), hosts)
    dst = paths.scopes_dir() / PLATFORM / f"{service}.yaml"
    if dst.exists():
        raise ScaffoldError(f"{dst} already exists: edit it by hand")
    try:
        scope_from_dict(doc, str(dst))  # loads exactly like the file will
    except ScopeError as exc:
        raise ScaffoldError(str(exc)) from exc
    dst.parent.mkdir(parents=True, exist_ok=True)
    header = (
        f"# MSRC {service}: written by `bh scope new msrc {service} --from {Path(capture).name}`.\n"
        "# Hosts: the survey's only, each with its date. automation_allowed: false until Mio reads the program rules.\n"
    )
    with open(dst, "x", encoding="utf-8") as fh:  # "x": never over a file written meanwhile
        fh.write(header + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=110))
    if say is not None:
        for line in missing(dst):
            say(f"  missing: {line}")
    return dst


def missing(path: Path) -> list[str]:
    """What bh.scope.guards.check says of the written file (and that automation is still Mio's to allow)."""
    from bh.scope import ScopeError, load_scope
    from bh.scope.guards import check

    try:
        scope = load_scope(path)
    except ScopeError as exc:
        return [f"the file does not load: {exc}"]
    out = list(check(scope))
    if scope.automation_allowed is not True:
        out.append("automation_allowed is false: Mio sets it after reading the program rules")
    return out
