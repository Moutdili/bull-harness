"""Scope contract (schema v1).

A scope file is the hard boundary of what the agent may touch for one program.
Loading is strict: unknown keys, unsupported wildcard shapes and empty
in-scope lists are errors, because a typo in a scope file must fail closed.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from bh.agent.contract import DEFAULT_RPS  # one default rate for the scope, the gate and the sandbox
from bh.scope.normalize import DEFAULT_PORTS, norm_host, norm_path, parse_ip
from bh.scope.psl import is_public_suffix

SCHEMA_VERSION = 1


def canonical_vuln(name: str) -> str:
    """Canonical vulnerability class name (single definition in bh.classes)."""
    from bh.classes import canonical

    return canonical(name)


Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class ScopeError(ValueError):
    """Invalid scope file."""


class RuleType(StrEnum):
    DOMAIN = "domain"  # exact host
    WILDCARD = "wildcard"  # *.example.com : subdomains at any depth, NOT the apex
    URL = "url"  # scheme + host (+ port) + path prefix
    CIDR = "cidr"  # IP or network
    REPO = "repo"  # source repository (CVE mode), never matched on the network
    OTHER = "other"  # informational (mobile app id, hardware...), never matched


@dataclass(frozen=True)
class Rule:
    type: RuleType
    value: str
    note: str = ""
    host: str | None = None  # DOMAIN host, WILDCARD base (or `api-*.base` pattern), URL host (may hold a '*')
    network: Network | None = None
    scheme: str | None = None
    port: int | None = None
    path: str | None = None  # normalized prefix

    def __str__(self) -> str:
        return f"{self.type}:{self.value}"


# Support hosts: needed by the target's pages or by our own login, never targets themselves (another program's,
# or the vendor's own infrastructure). `assets`: GET/HEAD from anyone in the sandbox, nothing of ours attached.
# `auth`: the enrollment sources only (the gate itself and bh-login), never the hunter nor the judge.
# `sso`: the login hosts the application itself calls while in use (a silent sign-in in an iframe, a token exchange):
# GET/HEAD from anyone, POST only on the declared `token_paths`; an identity gets its own jar's cookies there, never a
# header of ours. `passthrough`: a third-party anti-bot challenge (its script, its iframe): CONNECT on 443 only, never
# intercepted, nothing of ours inside; the gate sees a host, a byte count and a duration, nothing else.
SUPPORT_KINDS = ("auth", "assets", "sso", "passthrough")
# kinds named host by host: a wildcard would widen a login exchange or a blind tunnel to hosts nobody looked at
EXACT_KINDS = frozenset({"sso", "passthrough"})
# `token_paths`: absolute paths, `*` standing for exactly one path segment (`/*/oauth2/v2.0/token`). `get_paths`: the
# same shapes, matched as prefixes on whole segments (`/*/oauth2/v2.0/authorize` covers `/t/oauth2/v2.0/authorize/x`)
_TOKEN_PATH = re.compile(r"(/(\*|[A-Za-z0-9._~-]+))+")
_SEGMENT = r"(?!\.+(?:/|$))[A-Za-z0-9._~-]+"  # one segment, never `.` nor `..`


def _path_glob(pattern: str) -> re.Pattern[str]:
    return re.compile("".join("/" + (_SEGMENT if part == "*" else re.escape(part)) for part in pattern.split("/")[1:]))


def _path_prefix_glob(pattern: str) -> re.Pattern[str]:
    """A get_paths pattern as a prefix: the pattern's segments, then any number of plain segments (never `.`, `..`,
    an encoded or an empty one: the server would resolve those to another path)."""
    head = "".join("/" + (_SEGMENT if part == "*" else re.escape(part)) for part in pattern.rstrip("/").split("/")[1:])
    return re.compile(head + f"(?:/{_SEGMENT})*/?")


@dataclass(frozen=True)
class Support:
    kind: str  # one of SUPPORT_KINDS
    rule: Rule  # a domain or wildcard rule (a domain for EXACT_KINDS)
    token_paths: tuple[str, ...] = ()  # `sso` only: where a POST may go (the token exchange), nowhere else
    # `sso` only: path prefixes a GET/HEAD from the hunter or the judge may reach (none declared: no GET at all)
    get_paths: tuple[str, ...] = ()

    def get_path(self, path: str) -> bool:
        """Is `path` (query excluded) under a declared get_paths prefix? Same segment rules as token_path."""
        return any(_path_prefix_glob(p).fullmatch(path) is not None for p in self.get_paths)

    def token_path(self, path: str) -> bool:
        """Is `path` (the request path, query excluded) a declared token exchange path? Exact segments, `*` = one
        segment of [A-Za-z0-9._~-]: an encoded, dotted, doubled or empty segment never matches."""
        return any(_path_glob(p).fullmatch(path) is not None for p in self.token_paths)

    def __str__(self) -> str:
        return f"support-{self.kind}:{self.rule.value}"


@dataclass(frozen=True)
class RecipientRule:
    """One `recipient_guard` entry: `url`, a regex searched case-insensitively in the request URL (scheme, host,
    path and query, raw and %-decoded); `note`, what route it is (from the host survey)."""

    url: str
    note: str = ""


@dataclass(frozen=True)
class Scope:
    program: str
    platform: str
    in_scope: tuple[Rule, ...]
    out_of_scope: tuple[Rule, ...] = ()
    max_rps: float | None = None
    required_headers: dict[str, str] = field(default_factory=dict)
    user_agent: str | None = None
    automation_allowed: bool | None = None  # None = unknown -> todo humaine
    scanners_allowed: bool | None = None  # None = unknown -> todo humaine; read it through scanners_on
    self_signup: bool | None = None  # the harness may create its own test accounts; None = forbidden
    # websocket handshakes to targets, frames judged and bounded by the gate; None/False = refused (the default)
    websockets: bool | None = None
    support: tuple[Support, ...] = ()  # hosts the targets or the login need, never targets (see Support)
    # URL prefixes of targets that only the persistent browser (bh-browser) may touch, whatever the method (the chat
    # hub): the hunter drives that browser, it never talks to these paths itself (bh.gate.policy)
    browser_only: tuple[Rule, ...] = ()
    cards: tuple[str, ...] = ()  # card names always given to the hunter on this program (bh.cards, runner)
    # T5: path regexes (case-insensitive, matched on the request path only) refused to every client, on top of
    # bh.gate.policy.PROTECTED_DEFAULT (sign-out, password and account changes, payment)
    protected_urls: tuple[str, ...] = ()
    # D27 (O28): data-free hosts the hunter may cite and load (GET/HEAD/OPTIONS, nothing of ours attached); never a
    # target, a subdomain of a target nor a support host. Read through `payload_hosts`.
    payload: tuple[str, ...] = ()
    # D31: routes that name a recipient (a mail, an invitation): for a request whose URL one of these regexes matches,
    # whoever sends it, the gate wants at least one e-mail address and every one of them our identities' own
    # (bh.gate.recipients). None = the key is absent (bh.scope.guards wants it on an MSRC scope); () = no `send` route
    recipient_guard: tuple[RecipientRule, ...] | None = None
    # S8: the program's public rule pages, read on the host only (bh.rules); never what decides the scope
    rules_url: tuple[str, ...] = ()
    forbidden_vulns: tuple[str, ...] = ()
    # {name, secret_ref?, login_url?, signup_url?, probe?: {url, status, expect?, method?, headers?, json?}, enroll?,
    # origins?, role?, tenant?}; never a secret
    identities: tuple[dict[str, Any], ...] = ()
    source: str | None = None
    synced_at: str | None = None
    notes: str = ""
    digest: str = ""  # sha256 of the canonical source document

    def excludes(self, vuln_class: str | None) -> str | None:
        """The program exclusion matching `vuln_class`, if any."""
        if not vuln_class:
            return None
        from bh.classes import exclusion

        canon = canonical_vuln(vuln_class)
        return next((f for f in self.forbidden_vulns if exclusion(f) == canon), None)

    @property
    def scanners_on(self) -> bool:
        """Automated scanners (ffuf, nuclei, sqlmap, dalfox...) may run: only when the program allows them.
        Unknown counts as forbidden (the runner refuses to start until a human decides), local labs excepted."""
        return self.scanners_allowed is True or (self.scanners_allowed is None and self.platform == "local")

    @property
    def websockets_on(self) -> bool:
        """Websockets to targets: only when the scope says `websockets: true` (absent or null = refused)."""
        return self.websockets is True

    @property
    def payload_hosts(self) -> list[str]:
        """Payload hosts (exact, normalized names); [] when the scope declares none."""
        return list(self.payload)

    def support_hosts(self, kind: str) -> tuple[str, ...]:
        """Host patterns (`a.x.com`, `*.x.com`, `api-*.x.com`) of the support entries of `kind`."""
        return tuple(support_pattern(s.rule) for s in self.support if s.kind == kind)

    @property
    def rate(self) -> float:
        """Effective request rate towards targets (req/s)."""
        return self.max_rps or DEFAULT_RPS


_TOP_KEYS = {
    "schema",
    "scanners_allowed",
    "self_signup",
    "program",
    "platform",
    "in_scope",
    "out_of_scope",
    "max_rps",
    "required_headers",
    "user_agent",
    "automation_allowed",
    "forbidden_vulns",
    "identities",
    "source",
    "synced_at",
    "notes",
    "support",
    "websockets",
    "browser_only",
    "cards",
    "protected_urls",
    "payload_hosts",
    "recipient_guard",
    "rules_url",
}
_RULE_KEYS = {"type", "value", "note"}
_SUPPORT_KEYS = {"value", "kind", "note", "type", "token_paths", "get_paths"}
_CARD = re.compile(r"[a-z0-9-]+")


def support_pattern(rule: Rule) -> str:
    """The host pattern enforce matches for a domain or wildcard rule (`*.base` for a leading wildcard)."""
    assert rule.host is not None
    return rule.host if rule.type is RuleType.DOMAIN or "*" in rule.host else "*." + rule.host


def parse_support(entry: Any, ctx: str) -> Support:
    """One `support` entry: {value, kind: auth|assets|sso|passthrough, note?, token_paths?, get_paths? (sso only)}.
    Domains and wildcards only (a support host is named, never an IP range or a URL prefix); `sso` and `passthrough`
    name one exact host each."""
    if not isinstance(entry, dict):
        raise ScopeError(f"{ctx}: a support entry is a mapping {{value, kind, note}}")
    if unknown := set(entry) - _SUPPORT_KEYS:
        raise ScopeError(f"{ctx}: unknown support keys {sorted(unknown)}")
    kind = entry.get("kind")
    if kind not in SUPPORT_KINDS:
        raise ScopeError(f"{ctx}: support kind must be one of {list(SUPPORT_KINDS)}, not {kind!r}")
    rule = parse_rule({k: v for k, v in entry.items() if k not in ("kind", "token_paths", "get_paths")}, ctx)
    if rule.type not in (RuleType.DOMAIN, RuleType.WILDCARD):
        raise ScopeError(f"{ctx}: a support host is a domain or a wildcard, not {rule.type.value} {rule.value!r}")
    if kind in EXACT_KINDS and rule.type is not RuleType.DOMAIN:
        raise ScopeError(f"{ctx}: a `{kind}` support host is one exact domain, not the wildcard {rule.value!r}")
    found = {}
    for key in ("token_paths", "get_paths"):
        paths = entry.get(key)
        if paths is not None and kind != "sso":
            raise ScopeError(f"{ctx}: '{key}' belongs to `sso` support hosts only")
        if paths is not None and (
            not isinstance(paths, list)
            or not paths
            or not all(isinstance(x, str) and _TOKEN_PATH.fullmatch(x.rstrip("/") or "x") for x in paths)
            or any(seg in (".", "..") for x in paths for seg in x.split("/"))
        ):
            raise ScopeError(
                f"{ctx}: '{key}' is a non-empty list of absolute paths, `*` for one whole segment "
                "(/*/oauth2/v2.0/token)"
            )
        found[key] = tuple(paths or ())
    if any(p.endswith("/") for p in found["token_paths"]):
        raise ScopeError(f"{ctx}: a token path names one exact path, without a trailing '/'")
    return Support(kind, rule, found["token_paths"], found["get_paths"])


def _infer_type(value: str) -> RuleType:
    if "://" in value:
        return RuleType.URL
    if value.startswith("*.") or ("*" in value and "/" not in value):
        return RuleType.WILDCARD
    if "/" in value or parse_ip(value) is not None:
        return RuleType.CIDR
    return RuleType.DOMAIN


_MID_LABEL = re.compile(r"[a-z0-9-]*\*[a-z0-9-]*")


def _check_wildcard_shape(value: str, ctx: str) -> None:
    """Two shapes: a leading `*.` (`*.example.com`), or one `*` inside the first label (`api-*.example.com`)."""
    if "*" not in value or (value.startswith("*.") and "*" not in value[2:]):
        return
    label, _, rest = value.partition(".")
    if value.count("*") == 1 and rest and label != "*" and _MID_LABEL.fullmatch(label.lower()):
        return
    raise ScopeError(
        f"{ctx}: unsupported wildcard {value!r} (a leading '*.' or one '*' inside the first label, as in 'api-*.x.com')"
    )


def _wild_host(value: str, ctx: str) -> str:
    """Normalized host of a wildcard: the base for `*.base`, the whole pattern for `api-*.base`.
    The base must be a name someone owns, never a public suffix (`*.co.uk`, `*.github.io`, `api-*.co.uk`)."""
    _check_wildcard_shape(value, ctx)
    label, _, rest = value.partition(".")
    base = norm_host(rest)
    if is_public_suffix(base):
        raise ScopeError(f"{ctx}: wildcard {value!r} would cover the public suffix {base!r}")
    return base if label == "*" else f"{label.lower()}.{base}"


def parse_rule(entry: Any, ctx: str) -> Rule:
    if isinstance(entry, str):
        value, note, rtype = entry.strip(), "", None
    elif isinstance(entry, dict):
        unknown = set(entry) - _RULE_KEYS
        if unknown:
            raise ScopeError(f"{ctx}: unknown rule keys {sorted(unknown)}")
        if "value" not in entry:
            raise ScopeError(f"{ctx}: rule without 'value'")
        value, note = str(entry["value"]).strip(), str(entry.get("note", ""))
        try:
            rtype = RuleType(entry["type"]) if "type" in entry else None
        except ValueError as exc:
            raise ScopeError(f"{ctx}: unknown rule type {entry['type']!r}") from exc
    else:
        raise ScopeError(f"{ctx}: rule must be a string or a mapping")
    if not value:
        raise ScopeError(f"{ctx}: empty rule")
    rtype = rtype or _infer_type(value)

    try:
        match rtype:
            case RuleType.DOMAIN:
                _check_wildcard_shape(value, ctx)
                if "*" in value:
                    raise ScopeError(f"{ctx}: {value!r} is a wildcard, use type 'wildcard'")
                return Rule(rtype, value, note, host=norm_host(value))
            case RuleType.WILDCARD:
                if "*" not in value:
                    raise ScopeError(f"{ctx}: wildcard {value!r} has no '*'")
                return Rule(rtype, value, note, host=_wild_host(value, ctx))
            case RuleType.CIDR:
                try:
                    net = ipaddress.ip_network(value, strict=False)
                except ValueError as exc:
                    raise ScopeError(f"{ctx}: bad CIDR {value!r}") from exc
                return Rule(rtype, value, note, network=net)
            case RuleType.URL:
                return _parse_url_rule(value, note, ctx)
            case RuleType.REPO | RuleType.OTHER:
                return Rule(rtype, value, note)
    except ScopeError:
        raise
    except ValueError as exc:  # TargetError and any parser error: a broken scope must fail closed, loudly
        raise ScopeError(f"{ctx}: {exc}") from exc
    raise ScopeError(f"{ctx}: unhandled rule type {rtype}")  # pragma: no cover


def _parse_url_rule(value: str, note: str, ctx: str) -> Rule:
    scheme, _, rest = value.partition("://")
    scheme = scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise ScopeError(f"{ctx}: unsupported scheme in {value!r}")
    authority, slash, path = rest.partition("/")
    path = (slash + path).split("?", 1)[0].split("#", 1)[0] or "/"
    if "@" in authority or "\\" in authority or not authority:
        raise ScopeError(f"{ctx}: bad authority in {value!r}")
    _check_wildcard_shape(authority, ctx)
    host_s, port = authority, None
    if authority.startswith("["):
        end = authority.find("]")
        if end == -1:
            raise ScopeError(f"{ctx}: bad IPv6 literal in {value!r}")
        host_s, tail = authority[: end + 1], authority[end + 1 :]
        if tail:
            if not tail.startswith(":") or not tail[1:].isdigit():
                raise ScopeError(f"{ctx}: bad port in {value!r}")
            port = int(tail[1:])
    elif ":" in authority:
        host_s, p = authority.rsplit(":", 1)
        if not p.isdigit():
            raise ScopeError(f"{ctx}: bad port in {value!r}")
        port = int(p)
    if port is not None and not 0 < port < 65536:
        raise ScopeError(f"{ctx}: port out of range in {value!r}")
    ip = parse_ip(host_s)
    if ip is not None:
        raise ScopeError(f"{ctx}: URL rules need a hostname; use a 'cidr' rule for {host_s}")
    if "*" in host_s:
        wild = _wild_host(host_s, ctx)
        host = "*." + wild if host_s.startswith("*.") else wild
    else:
        host = norm_host(host_s)
    normalized, _ = norm_path(path)
    return Rule(
        RuleType.URL, value, note, host=host, scheme=scheme, port=port or DEFAULT_PORTS[scheme], path=normalized
    )


def _canonical_digest(doc: dict[str, Any]) -> str:
    blob = json.dumps(doc, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


def scope_from_dict(doc: dict[str, Any], origin: str = "<dict>") -> Scope:
    if not isinstance(doc, dict):
        raise ScopeError(f"{origin}: top level must be a mapping")
    unknown = set(doc) - _TOP_KEYS
    if unknown:
        raise ScopeError(f"{origin}: unknown keys {sorted(unknown)}")
    if doc.get("schema", SCHEMA_VERSION) != SCHEMA_VERSION:
        raise ScopeError(f"{origin}: schema {doc.get('schema')} != {SCHEMA_VERSION}")
    for key in ("program", "platform"):
        if not isinstance(doc.get(key), str) or not doc[key].strip():
            raise ScopeError(f"{origin}: '{key}' is required")
    ins = doc.get("in_scope") or []
    outs = doc.get("out_of_scope") or []
    if not isinstance(ins, list) or not ins:
        raise ScopeError(f"{origin}: 'in_scope' must be a non-empty list")
    if not isinstance(outs, list):
        raise ScopeError(f"{origin}: 'out_of_scope' must be a list")
    in_rules = tuple(parse_rule(e, f"{origin}: in_scope[{i}]") for i, e in enumerate(ins))
    out_rules = tuple(parse_rule(e, f"{origin}: out_of_scope[{i}]") for i, e in enumerate(outs))
    sup = doc.get("support") or []
    if not isinstance(sup, list):
        raise ScopeError(f"{origin}: 'support' must be a list")
    support = tuple(parse_support(e, f"{origin}: support[{i}]") for i, e in enumerate(sup))
    _support_apart(in_rules, support, origin)

    max_rps = doc.get("max_rps")
    if max_rps is not None and (not isinstance(max_rps, (int, float)) or max_rps <= 0):
        raise ScopeError(f"{origin}: 'max_rps' must be a positive number")
    headers = doc.get("required_headers") or {}
    if not isinstance(headers, dict) or not all(isinstance(v, str) for v in headers.values()):
        raise ScopeError(f"{origin}: 'required_headers' must map names to strings")
    auto = doc.get("automation_allowed")
    if auto is not None and not isinstance(auto, bool):
        raise ScopeError(f"{origin}: 'automation_allowed' must be true, false or null")
    scanners = doc.get("scanners_allowed")
    if scanners is not None and not isinstance(scanners, bool):
        raise ScopeError(f"{origin}: 'scanners_allowed' must be true, false or null")
    signup = doc.get("self_signup")
    if signup is not None and not isinstance(signup, bool):
        raise ScopeError(f"{origin}: 'self_signup' must be true, false or null")
    websockets = doc.get("websockets")
    if websockets is not None and not isinstance(websockets, bool):
        raise ScopeError(f"{origin}: 'websockets' must be true, false or null")
    cards = doc.get("cards") or []
    if not isinstance(cards, list) or not all(isinstance(c, str) and _CARD.fullmatch(c) for c in cards):
        raise ScopeError(f"{origin}: 'cards' is a list of card names ([a-z0-9-]+)")
    identities = doc.get("identities") or []
    if not isinstance(identities, list):
        raise ScopeError(f"{origin}: 'identities' must be a list")
    identities = [_identity(ident, f"{origin}: identities[{i}]") for i, ident in enumerate(identities)]
    if len({i["name"] for i in identities}) != len(identities):
        raise ScopeError(f"{origin}: two identities share a name")

    scope = Scope(
        program=doc["program"].strip(),
        platform=doc["platform"].strip(),
        in_scope=in_rules,
        out_of_scope=out_rules,
        max_rps=float(max_rps) if max_rps is not None else None,
        required_headers={str(k): v for k, v in headers.items()},
        user_agent=doc.get("user_agent"),
        automation_allowed=auto,
        scanners_allowed=scanners,
        self_signup=signup,
        websockets=websockets,
        support=support,
        browser_only=_browser_only(doc.get("browser_only"), origin),
        cards=tuple(dict.fromkeys(cards)),
        protected_urls=_protected_urls(doc.get("protected_urls"), origin),
        payload=_payload_names(doc.get("payload_hosts"), origin),
        recipient_guard=_recipient_guard(doc.get("recipient_guard", ...), origin),
        rules_url=_rules_url(doc.get("rules_url"), origin),
        forbidden_vulns=tuple(doc.get("forbidden_vulns") or ()),
        identities=tuple(identities),
        source=doc.get("source"),
        synced_at=str(doc["synced_at"]) if doc.get("synced_at") is not None else None,
        notes=str(doc.get("notes") or ""),
        digest=_canonical_digest(doc),
    )
    _derived_origins_on_targets(scope, doc.get("identities") or [])
    _identity_urls_in_scope(scope, origin)
    _browser_only_on_targets(scope, origin)
    _payload_apart(scope, origin)
    return scope


def _protected_urls(raw: Any, origin: str) -> tuple[str, ...]:
    """`protected_urls`: regexes matched case-insensitively on the request path (never the query), added to the
    gate's defaults. A pattern that does not compile is an error (fail closed, like any typo)."""
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(r, str) and r.strip() for r in raw):
        raise ScopeError(f"{origin}: 'protected_urls' is a list of path regexes")
    for i, r in enumerate(raw):
        try:
            re.compile(r, re.I)
        except re.error as exc:
            raise ScopeError(f"{origin}: protected_urls[{i}] {r!r} is not a valid regex ({exc})") from exc
    return tuple(raw)


def _recipient_guard(raw: Any, origin: str) -> tuple[RecipientRule, ...] | None:
    """`recipient_guard: [{url: <regex>, note: <text>}]`. Absent: None; null or []: no route. A regex that does not
    compile, an unknown key or an empty pattern is an error (fail closed, like protected_urls)."""
    if raw is ...:
        return None
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ScopeError(f"{origin}: 'recipient_guard' is a list of {{url: <regex>, note: <text>}}")
    out = []
    for i, entry in enumerate(raw):
        ctx = f"{origin}: recipient_guard[{i}]"
        if not isinstance(entry, dict) or set(entry) - {"url", "note"}:
            raise ScopeError(f"{ctx}: a mapping {{url: <regex>, note: <text>}}")
        pattern, note = entry.get("url"), entry.get("note", "")
        if not isinstance(pattern, str) or not pattern.strip() or not isinstance(note, str):
            raise ScopeError(f"{ctx}: 'url' is a non-empty regex, 'note' a text")
        try:
            re.compile(pattern, re.I)
        except re.error as exc:
            raise ScopeError(f"{ctx}: {pattern!r} is not a valid regex ({exc})") from exc
        out.append(RecipientRule(pattern, note))
    return tuple(out)


def _rules_url(raw: Any, origin: str) -> tuple[str, ...]:
    """`rules_url`: the program's public rule pages, https URLs (no credentials, no wildcard)."""
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(u, str) for u in raw):
        raise ScopeError(f"{origin}: 'rules_url' is a list of https URLs")
    for i, u in enumerate(raw):
        try:
            parts = urlsplit(u)
            ok = parts.scheme == "https" and bool(parts.hostname) and parts.username is None
            ok = ok and parts.port in (None, 443)
        except ValueError:
            ok = False
        if not ok or "*" in u or any(c.isspace() for c in u):
            raise ScopeError(f"{origin}: rules_url[{i}] {u!r} is not an https URL of a public page")
    return tuple(dict.fromkeys(raw))


_HOSTNAME = re.compile(r"(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}")


def _payload_names(raw: Any, origin: str) -> tuple[str, ...]:
    """`payload_hosts`: exact host names (no wildcard, scheme, port, path nor IP), normalized."""
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(h, str) for h in raw):
        raise ScopeError(f"{origin}: 'payload_hosts' is a list of host names")
    out = []
    for i, h in enumerate(raw):
        try:
            name = norm_host(h)
        except ValueError:
            name = ""
        if not _HOSTNAME.fullmatch(name) or parse_ip(name) is not None or is_public_suffix(name):
            raise ScopeError(f"{origin}: payload_hosts[{i}] {h!r} is not one exact host name")
        out.append(name)
    return tuple(dict.fromkeys(out))


def _payload_apart(scope: Scope, origin: str) -> None:
    """A payload host is never a target (nor under one: a subdomain of a target), an excluded host nor a support
    host: what it receives carries nothing of ours, so it must be a host no rule of the program names."""
    from bh.scope.enforce import check, patterns_overlap  # enforce imports this module

    for i, h in enumerate(scope.payload):
        ctx = f"{origin}: payload_hosts[{i}] {h!r}"
        if check(scope, h) or origin_covered(scope, f"https://{h}/") or origin_covered(scope, f"http://{h}/"):
            raise ScopeError(f"{ctx} is an in-scope target")
        for rule in scope.in_scope + scope.out_of_scope:
            if rule.host is None:
                continue
            theirs = rule.host if rule.type is RuleType.URL else support_pattern(rule)
            base = theirs[2:] if theirs.startswith("*.") else theirs.partition(".")[2] if "*" in theirs else theirs
            if patterns_overlap(h, theirs) or h.endswith("." + base):
                raise ScopeError(f"{ctx} is (under) the host of the rule {rule.value!r}")
        for s in scope.support:
            if patterns_overlap(h, support_pattern(s.rule)):
                raise ScopeError(f"{ctx} is a support host ({s.kind}: {s.rule.value})")


def origin_covered(scope: Scope, url: str) -> bool:
    """R1: is the ORIGIN of `url` one of the scope's targets? The URL itself, or its host when an in-scope URL rule
    of the same scheme and port covers that host (`https://substrate.office.com/m365Copilot/` covers the origin
    `https://substrate.office.com:443`). Only says where an identity's captured header may be kept and sent: every
    request is still judged on its full URL by the gate, so a path outside the prefixes stays refused."""
    from bh.scope.enforce import check, check_target  # enforce imports this module
    from bh.scope.normalize import TargetError, parse_target

    if check(scope, url):
        return True
    try:
        t = parse_target(url)
    except TargetError:
        return False
    if t.scheme is None:
        return False
    host_level = type(t)(raw=t.raw, host=t.host, ip=t.ip, scheme=t.scheme, port=t.port, path=None, path_raw=None)
    return bool(check_target(scope, host_level))


def _browser_only(raw: Any, origin: str) -> tuple[Rule, ...]:
    """`browser_only`: URL prefixes `https://host/path` (one exact host, no wildcard, no query)."""
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(u, str) and u.strip() for u in raw):
        raise ScopeError(f"{origin}: 'browser_only' is a list of URL prefixes (https://host/path)")
    out = []
    for i, u in enumerate(raw):
        ctx = f"{origin}: browser_only[{i}]"
        if not _HTTP_URL.match(u) or "*" in u or "?" in u or "#" in u:
            raise ScopeError(f"{ctx}: {u!r} is not an http(s) URL prefix of one exact host (https://host/path)")
        out.append(parse_rule({"value": u, "type": "url"}, ctx))
    return tuple(out)


def _browser_only_on_targets(scope: Scope, origin: str) -> None:
    """A browser_only prefix narrows a target: its host must be one (a support or unknown host is an error)."""
    from bh.scope.enforce import check  # enforce imports this module

    for i, rule in enumerate(scope.browser_only):
        d = check(scope, rule.value)
        if not d:
            raise ScopeError(f"{origin}: browser_only[{i}] {rule.value!r} is not an in-scope target ({d.reason})")


def _support_apart(in_rules: tuple[Rule, ...], support: tuple[Support, ...], origin: str) -> None:
    """A host is a target or a support host, never both: a support value that an in-scope rule also covers (or that
    covers an in-scope host) is an error, so a support host can never be tested through an overlapping rule."""
    from bh.scope.enforce import patterns_overlap  # enforce imports this module

    for i, s in enumerate(support):
        mine = support_pattern(s.rule)
        for rule in in_rules:
            if rule.host is None:  # cidr / repo / other: no host name to collide with
                continue
            theirs = rule.host if rule.type is RuleType.URL else support_pattern(rule)
            if patterns_overlap(mine, theirs):
                raise ScopeError(
                    f"{origin}: support[{i}] {s.rule.value!r} overlaps in_scope {rule.value!r}: a host is a target "
                    "or a support host, never both"
                )
    for i, s in enumerate(support):
        for other in support[:i]:
            if other.kind != s.kind and patterns_overlap(support_pattern(s.rule), support_pattern(other.rule)):
                raise ScopeError(f"{origin}: support[{i}] {s.rule.value!r} is both {other.kind} and {s.kind}")


def _derived_origins_on_targets(scope: Scope, raw: list[Any]) -> None:
    """A browser login's derived `origins` (its goto pages) keep the targets only: a login host of `support` is
    visited by the login but never receives the identity's headers (they only go to targets anyway)."""
    from bh.scope.enforce import check  # enforce imports this module

    for ident, decl in zip(scope.identities, raw, strict=False):
        if isinstance(decl, dict) and "origins" not in decl and isinstance(ident.get("origins"), list):
            ident["origins"] = [o for o in ident["origins"] if check(scope, o)]
            if not ident["origins"]:
                del ident["origins"]


_IDENTITY_KEYS = {"name", "secret_ref", "login_url", "signup_url", "probe", "enroll", "origins", "role", "tenant"}
# role matrix (`admin`, `member`, `guest` / `A`, `B`): short labels, never secrets; they travel in
# BH_IDENTITY_ROLES as `name=role@tenant`, so no `=`, `@` or `,` inside
_LABEL = re.compile(r"[A-Za-z0-9_.-]{1,32}")
# a credential written into the scope file would reach the gate and the agent's prompt: refused by name
_SECRET_KEY = re.compile(r"passw|pwd|secret|totp|otp|token|cookie|api[_-]?key|credential|session", re.I)
_IDENTITY_NAME = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,39}")  # the shape the gate accepts in X-BH-Identity
_HTTP_URL = re.compile(r"https?://", re.I)


PROBE_KEYS = frozenset({"url", "status", "expect", "method", "headers", "json"})
PROBE_METHODS = ("GET", "POST")
PROBE_HEADERS = frozenset({"accept", "content-type", "x-route-id"})  # compared case-insensitively
PROBE_JSON_MAX = 2048  # bytes of the serialized body
PROBE_PLACEHOLDERS = frozenset({"email", "name"})  # resolved by the host from secrets/ at probe time (enroll)
_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_HEADER_VALUE = re.compile(r"[\x20-\x7e]{1,256}")


def _probe(probe: Any, ctx: str) -> None:
    """`probe: {url, status, expect?, method?, headers?, json?}` (R43). `expect` may hold `{email}` / `{name}`;
    `method` GET (default) or POST; `headers` only Accept, Content-Type, x-route-id; `json` (POST only) an object of
    at most PROBE_JSON_MAX bytes. Anything else is an error."""
    shape = (
        "{url: http(s) URL, status: HTTP status code, expect?: text in the body, method?: GET|POST, "
        "headers?: {Accept|Content-Type|x-route-id: text}, json?: object (POST)}"
    )
    if not isinstance(probe, dict) or not {"url", "status"} <= set(probe) or set(probe) - PROBE_KEYS:
        raise ScopeError(f"{ctx}: 'probe' must be {shape}")
    if (
        not isinstance(probe["url"], str)
        or not _HTTP_URL.match(probe["url"])
        or isinstance(probe["status"], bool)
        or not isinstance(probe["status"], int)
        or not 100 <= probe["status"] <= 599
    ):
        raise ScopeError(f"{ctx}: 'probe' must be {shape}")
    if "expect" in probe:
        expect = probe["expect"]
        if not isinstance(expect, str) or not expect:
            raise ScopeError(f"{ctx}: probe.expect is a non-empty text")
        if unknown := sorted(set(_PLACEHOLDER.findall(expect)) - PROBE_PLACEHOLDERS):
            raise ScopeError(f"{ctx}: probe.expect may only use {{email}} and {{name}}, not {unknown}")
    method = probe.get("method", "GET")
    if method not in PROBE_METHODS:
        raise ScopeError(f"{ctx}: probe.method is GET or POST, not {method!r}")
    if "headers" in probe:
        hdrs = probe["headers"]
        if not isinstance(hdrs, dict) or not hdrs:
            raise ScopeError(f"{ctx}: probe.headers is a mapping of Accept, Content-Type, x-route-id")
        for k, v in hdrs.items():
            if not isinstance(k, str) or k.lower() not in PROBE_HEADERS:
                raise ScopeError(
                    f"{ctx}: probe.headers: {str(k)[:40]!r} is not one of Accept, Content-Type, x-route-id"
                )
            if not isinstance(v, str) or not _HEADER_VALUE.fullmatch(v):
                raise ScopeError(f"{ctx}: probe.headers.{k}: 1-256 printable ASCII characters")
        if len({k.lower() for k in hdrs}) != len(hdrs):
            raise ScopeError(f"{ctx}: probe.headers names a header twice")
    if "json" in probe:
        body = probe["json"]
        if method != "POST":
            raise ScopeError(f"{ctx}: probe.json goes with method: POST")
        try:
            size = len(json.dumps(body, ensure_ascii=False).encode()) if isinstance(body, dict) else None
        except (TypeError, ValueError):
            size = None
        if size is None or size > PROBE_JSON_MAX:
            raise ScopeError(f"{ctx}: probe.json is an object of at most {PROBE_JSON_MAX} bytes once serialized")


def _identity(ident: Any, ctx: str) -> dict[str, Any]:
    """One declared identity. The YAML says how to log in and how to check the session, never with what:
    passwords, TOTP seeds and tokens live behind `secret_ref` (host side), so a key that names one is an error."""
    if not isinstance(ident, dict) or "name" not in ident:
        raise ScopeError(f"{ctx}: an identity is a mapping with at least 'name'")
    secret = sorted(str(k) for k in ident if str(k) != "secret_ref" and _SECRET_KEY.search(str(k)))
    if secret:
        raise ScopeError(f"{ctx}: {secret} look like secrets; keep them behind 'secret_ref', never in the scope file")
    unknown = set(ident) - _IDENTITY_KEYS
    if unknown:
        raise ScopeError(f"{ctx}: unknown identity keys {sorted(unknown)} (allowed: {sorted(_IDENTITY_KEYS)})")
    if not isinstance(ident["name"], str) or not _IDENTITY_NAME.fullmatch(ident["name"]):
        raise ScopeError(f"{ctx}: identity name must match {_IDENTITY_NAME.pattern}")
    for key in ("secret_ref", "login_url", "signup_url"):
        if key in ident and (not isinstance(ident[key], str) or not ident[key].strip()):
            raise ScopeError(f"{ctx}: '{key}' must be a non-empty string")
    for key in ("login_url", "signup_url"):
        if key in ident and not _HTTP_URL.match(ident[key]):
            raise ScopeError(f"{ctx}: '{key}' must be an http(s) URL")
    if "origins" in ident and (
        not isinstance(ident["origins"], list)
        or not ident["origins"]
        or not all(isinstance(u, str) and _HTTP_URL.match(u) for u in ident["origins"])
    ):
        raise ScopeError(f"{ctx}: 'origins' must be a non-empty list of http(s) URLs (where its headers may go)")
    if "probe" in ident:
        _probe(ident["probe"], ctx)
    for key in ("role", "tenant"):
        if key in ident and (not isinstance(ident[key], str) or not _LABEL.fullmatch(ident[key])):
            raise ScopeError(f"{ctx}: '{key}' must match {_LABEL.pattern} (e.g. admin, member, guest / A, B)")
    out = dict(ident)
    if "enroll" in ident:
        from bh.accounts.recipe import RecipeError, check
        from bh.agent.contract import origin

        try:
            out["enroll"] = recipe = check(ident["enroll"], f"{ctx}.enroll")
        except RecipeError as exc:
            raise ScopeError(str(exc)) from exc
        if recipe["kind"] == "browser" and "origins" not in ident:
            # M7: the captured Authorization goes to the pages the login visited, not to every host of the scope
            # (the gate adds the probe's and the sign-up's origins); an API on another origin is declared in `origins`
            seen = {origin(s["url"]) for s in recipe["steps"] if s["action"] == "goto"}
            out["origins"] = [f"{o}/" for o in sorted(o for o in seen if o)]
        if recipe["kind"] == "oauth_refresh" and not ({"origins", "probe", "login_url"} & set(ident)):
            raise ScopeError(
                f"{ctx}: an oauth_refresh identity declares 'origins' (or a probe): where its token may go"
            )
    return out


def _identity_urls_in_scope(scope: Scope, origin: str) -> None:
    """Login, signup and probe URLs are visited through the gate: a scope that names one outside itself is broken."""
    from bh.scope.enforce import check  # enforce imports this module

    from bh.accounts.recipe import auth_origins, urls

    for i, ident in enumerate(scope.identities):
        # where the login goes may be a `support` auth or sso host (enrollment reaches both); the probe and the
        # origins (where the identity's headers go) must be targets
        for key, u, login in (
            ("login_url", ident.get("login_url"), True),
            ("signup_url", ident.get("signup_url"), True),
            ("probe.url", (ident.get("probe") or {}).get("url"), False),
            *((k, u, True) for k, u in urls(ident.get("enroll"))),  # sign-up, login, gotos, the OAuth token URL
            *((f"origins[{j}]", u, False) for j, u in enumerate(ident.get("origins") or [])),
            *(
                (f"enroll.capture.authorization_origins[{j}]", u, False)
                for j, u in enumerate(auth_origins(ident.get("enroll")))
            ),
        ):
            if u is None:
                continue
            d = check(scope, u)
            if not d and key.startswith(("origins", "enroll.capture")) and origin_covered(scope, u):
                continue  # R1: an origin is judged on its host when a URL rule of the same scheme and port covers it
            if not d and not (login and d.support in ("auth", "sso")):
                raise ScopeError(f"{origin}: identities[{i}].{key} {u!r} is not in scope ({d.reason})")


def load_scope(path: str | Path) -> Scope:
    p = Path(path)
    try:
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ScopeError(f"{p}: invalid YAML: {exc}") from exc
    return scope_from_dict(doc, str(p))
