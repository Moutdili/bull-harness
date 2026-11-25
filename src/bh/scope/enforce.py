"""The single scope decision function.

Layers call it with what they know:
- HTTP gate: full URL            -> check(url)
- SOCKS gate: host:port          -> check("host:443")
- DNS gate: hostname             -> check("host")
- after any DNS resolution       -> check_resolved(host, ip)

Precedence: out-of-scope always wins. Raw IPs are only reachable through an
explicit in-scope CIDR. A `support` host (assets the targets load, our own login)
is a third answer: not allowed as a target, not denied by an exclusion, `support`
set to its kind; the gate gives it its own narrow rules. Non-public IPs (loopback, RFC1918, link-local...) are
only reachable through an explicit in-scope CIDR, even when a hostname in scope
resolves to them (DNS rebinding / internal pivot protection).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from bh.scope.model import Rule, RuleType, Scope, Support
from bh.scope.normalize import IPAddress, Target, TargetError, parse_ip, parse_target


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    rule: str | None = None
    support: str | None = None  # "auth" | "assets": a support host of the scope (allowed stays False)

    def __bool__(self) -> bool:
        return self.allowed


def _host_matches(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        return host.endswith("." + pattern[2:])
    if "*" in pattern:  # `api-*.example.com`: one label, same parent, '*' = one or more label characters
        label, _, rest = pattern.partition(".")
        h_label, _, h_rest = host.partition(".")
        head, _, tail = label.partition("*")
        return h_rest == rest and re.fullmatch(re.escape(head) + "[a-z0-9-]+" + re.escape(tail), h_label) is not None
    return host == pattern


def patterns_overlap(a: str, b: str) -> bool:
    """Could one host match both patterns (`x.com`, `*.x.com`, `api-*.x.com`)? Conservative: True when unsure."""

    def parts(p: str) -> tuple[str, str]:  # (shape, base): exact / sub (*.base) / mid (one label under base)
        if p.startswith("*."):
            return "sub", p[2:]
        if "*" in p:
            return "mid", p.partition(".")[2]
        return "exact", p

    (ka, ba), (kb, bb) = parts(a), parts(b)
    if ka == "exact":
        return _host_matches(b, ba)
    if kb == "exact":
        return _host_matches(a, bb)
    if ka == "sub" and kb == "sub":
        return ba == bb or ba.endswith("." + bb) or bb.endswith("." + ba)
    if ka == "mid" and kb == "mid":
        return ba == bb
    sub, mid = (ba, bb) if ka == "sub" else (bb, ba)  # one label under `mid` is under `sub` when mid is (under) sub
    return mid == sub or mid.endswith("." + sub)


def _path_under(prefix: str, path: str) -> bool:
    base = prefix.rstrip("/")
    return base == "" or path == base or path.startswith(base + "/")


def _path_hits_exclusion(prefix: str, path: str) -> bool:
    """Out-of-scope prefix test, deliberately wide: case-insensitive, and `/checkout/` also
    covers `/checkout;x`, `/checkout.json`, `/checkout%..`."""
    base, p = prefix.rstrip("/").lower(), path.lower()
    return base == "" or p == base or (p.startswith(base) and p[len(base)] in "/;.%")


def _match(rule: Rule, t: Target, *, out: bool) -> bool:
    match rule.type:
        case RuleType.DOMAIN | RuleType.WILDCARD:
            if t.host is None:
                return False
            pattern = rule.host if rule.type is RuleType.DOMAIN or "*" in rule.host else "*." + rule.host
            return _host_matches(pattern, t.host)
        case RuleType.CIDR:
            return t.ip is not None and t.ip in rule.network
        case RuleType.URL:
            if t.host is None or not _host_matches(rule.host, t.host):
                return False
            # In-scope URL: exact scheme and port. Out-of-scope URL: any scheme/port,
            # so "https://x/admin/" out of scope also bans "http://x:8080/admin/".
            if not out and t.port is not None and t.port != rule.port:
                return False
            if not out and t.scheme is not None and t.scheme != rule.scheme:
                return False
            if t.path is None:
                # host-level check (DNS / SOCKS): an in-scope URL authorizes its host;
                # an out-of-scope URL with a path does not ban the whole host.
                return not out or rule.path == "/"
            variants = t.paths or (t.path,)
            if out:
                return any(_path_hits_exclusion(rule.path, p) for p in variants)
            return all(_path_under(rule.path, p) for p in variants)
        case _:
            return False


def _non_public(ip: IPAddress) -> bool:
    return not ip.is_global or ip.is_multicast


def check_target(scope: Scope, t: Target) -> Decision:
    for rule in scope.out_of_scope:
        if _match(rule, t, out=True):
            return Decision(False, "out-of-scope", str(rule))
    for rule in scope.in_scope:
        if _match(rule, t, out=False):
            return Decision(True, "in-scope", str(rule))
    if (s := support_of(scope, t)) is not None:
        return Decision(False, f"support host ({s.kind}: {s.rule.value}), not a target", support=s.kind)
    if t.ip is not None:
        return Decision(False, "raw IP not covered by an in-scope CIDR")
    return Decision(False, "not in scope")


def support_of(scope: Scope, t: Target) -> Support | None:
    """The support entry naming the target's host, if any (names only: an IP is never a support host)."""
    if t.host is None:
        return None
    return next((s for s in scope.support if _match(s.rule, t, out=False)), None)


def check(scope: Scope, target: str) -> Decision:
    try:
        t = parse_target(target)
    except TargetError as exc:
        return Decision(False, f"unparseable target: {exc}")
    # A raw IP can only be allowed by an explicit in-scope CIDR (see _match), so a
    # non-public literal IP is reachable only when the scope names it on purpose.
    return check_target(scope, t)


def check_resolved(scope: Scope, host: str, ip: str | IPAddress) -> Decision:
    """Call after resolving an authorized host. Fails closed."""
    addr = parse_ip(str(ip))
    if addr is None:
        return Decision(False, f"bad resolved address {ip!r}")
    host_decision = check(scope, host)
    if not host_decision:
        return host_decision
    as_target = Target(raw=str(addr), host=None, ip=addr, scheme=None, port=None, path=None, path_raw=None)
    for rule in scope.out_of_scope:
        if _match(rule, as_target, out=True):
            return Decision(False, f"{host} resolves to out-of-scope {addr}", str(rule))
    if _non_public(addr):
        for rule in scope.in_scope:
            if rule.type is RuleType.CIDR and addr in rule.network:
                return Decision(True, "non-public IP explicitly in scope", str(rule))
        return Decision(False, f"{host} resolves to non-public {addr}")
    return Decision(True, "resolved address allowed", host_decision.rule)


def check_support_resolved(scope: Scope, host: str, ip: str | IPAddress) -> Decision:
    """A support host after resolution: public addresses only (a support host never reaches an internal network,
    whatever the scope's CIDRs say), and never an out-of-scope address. `allowed` here means "may connect"."""
    addr = parse_ip(str(ip))
    if addr is None:
        return Decision(False, f"bad resolved address {ip!r}")
    d = check(scope, host)
    if d.support is None:
        return Decision(False, d.reason, d.rule)
    as_target = Target(raw=str(addr), host=None, ip=addr, scheme=None, port=None, path=None, path_raw=None)
    for rule in scope.out_of_scope:
        if _match(rule, as_target, out=True):
            return Decision(False, f"{host} resolves to out-of-scope {addr}", str(rule))
    if _non_public(addr):
        return Decision(False, f"support host {host} resolves to non-public {addr}")
    return Decision(True, "support host, public address", support=d.support)
