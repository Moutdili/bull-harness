"""Common guards of a scope file, by platform. `check(scope)` lists what is wrong (empty: the file conforms).

MSRC (`platform: msrc`): "in scope by default" speaks of the bounty, never of the gate. Every Microsoft service gets its
own file, its hosts seen live, its guards; no wildcard stands in for a survey. A scope of this platform must have:
- no target written as a wildcard (`*.x`, `api-*.x`, a URL with a `*` host), and no support host either, the asset
  wildcards already present excepted (MSRC_ASSET_WILDCARDS); never a wildcard under a Microsoft domain
  (MICROSOFT_DOMAINS), whatever its kind;
- no administration host as a target (first label `admin*`: admin.microsoft.com stays refused);
- `scanners_allowed: false`, `max_rps` at most MSRC_MAX_RPS, `dos` among `forbidden_vulns`;
- `payload_hosts` and `rules_url` not empty; the `recipient_guard` key present (empty only when the host survey names
  no `send` route for the service).
Reused for each new service (W4): a file that fails here is not ready to hunt on.
"""

from __future__ import annotations

import re

from bh.scope.model import RuleType, Scope, support_pattern

MICROSOFT_DOMAINS = (
    "microsoft.com",
    "live.com",
    "office.com",
    "office.net",
    "sharepoint.com",
    "onedrive.com",
    "outlook.com",
)
# login page assets of the Microsoft account, in the Copilot scope before these guards (GET/HEAD, nothing of ours)
MSRC_ASSET_WILDCARDS = frozenset({"*.msftauth.net", "*.msauth.net"})
MSRC_MAX_RPS = 2.0
_ADMIN = re.compile(r"admin", re.I)


def _under_microsoft(host: str) -> str | None:
    h = host.lower().lstrip("*.").rstrip(".")
    return next((d for d in MICROSOFT_DOMAINS if h == d or h.endswith("." + d)), None)


def _wild(value: str, host: str | None) -> bool:
    return "*" in value or "*" in (host or "")


def check(scope: Scope) -> list[str]:
    """What breaks the platform's guards (one line each); [] for a conforming scope or a platform without guards."""
    if scope.platform != "msrc":
        return []
    out: list[str] = []
    for rule in scope.in_scope:
        if rule.type in (RuleType.WILDCARD, RuleType.URL, RuleType.DOMAIN) and _wild(rule.value, rule.host):
            ms = _under_microsoft(rule.host or "")
            out.append(f"in_scope {rule.value!r}: a wildcard target" + (f" under {ms}" if ms else ""))
        if rule.type is RuleType.CIDR:
            out.append(f"in_scope {rule.value!r}: an address range, not a host seen live")
        if rule.host and _ADMIN.match(rule.host.lstrip("*.").split(".", 1)[0]):
            out.append(f"in_scope {rule.value!r}: an administration host")
    for s in scope.support:
        pattern = support_pattern(s.rule)
        if "*" not in pattern:
            continue
        if ms := _under_microsoft(pattern):
            out.append(f"support {s.rule.value!r} ({s.kind}): a wildcard under {ms}")
        elif s.kind != "assets" or s.rule.value.lower() not in MSRC_ASSET_WILDCARDS:
            out.append(f"support {s.rule.value!r} ({s.kind}): a wildcard support host")
    if scope.scanners_allowed is not False:
        out.append("scanners_allowed must be false")
    if scope.max_rps is None or scope.max_rps > MSRC_MAX_RPS:
        out.append(f"max_rps must be set and at most {MSRC_MAX_RPS:g}")
    if not any(str(v).strip().lower() == "dos" for v in scope.forbidden_vulns):
        out.append("forbidden_vulns must hold dos")
    if not scope.payload_hosts:
        out.append("payload_hosts must not be empty")
    if not scope.rules_url:
        out.append("rules_url must not be empty (the program's rule pages, read by `bh rules check`)")
    if scope.recipient_guard is None:
        out.append("recipient_guard must be present (empty only when the host survey names no send route)")
    return out
