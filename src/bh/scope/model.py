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
    forbidden_vulns: tuple[str, ...] = ()
    # {name, secret_ref?, login_url?, signup_url?, probe?: {url, status}}; never a secret (see _identity)
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
    def rate(self) -> float:
        """Effective request rate towards targets (req/s)."""
        return self.max_rps or DEFAULT_RPS


_TOP_KEYS = {
    "schema",
    "scanners_allowed",
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
}
_RULE_KEYS = {"type", "value", "note"}


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
        forbidden_vulns=tuple(doc.get("forbidden_vulns") or ()),
        identities=tuple(identities),
        source=doc.get("source"),
        synced_at=str(doc["synced_at"]) if doc.get("synced_at") is not None else None,
        notes=str(doc.get("notes") or ""),
        digest=_canonical_digest(doc),
    )
    _identity_urls_in_scope(scope, origin)
    return scope


_IDENTITY_KEYS = {"name", "secret_ref", "login_url", "signup_url", "probe"}
# a credential written into the scope file would reach the gate and the agent's prompt: refused by name
_SECRET_KEY = re.compile(r"passw|pwd|secret|totp|otp|token|cookie|api[_-]?key|credential|session", re.I)
_IDENTITY_NAME = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9_.-]{0,39}")  # the shape the gate accepts in X-BH-Identity
_HTTP_URL = re.compile(r"https?://", re.I)


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
    if "probe" in ident:
        probe = ident["probe"]
        if (
            not isinstance(probe, dict)
            or set(probe) != {"url", "status"}
            or not isinstance(probe["url"], str)
            or not _HTTP_URL.match(probe["url"])
            or isinstance(probe["status"], bool)
            or not isinstance(probe["status"], int)
            or not 100 <= probe["status"] <= 599
        ):
            raise ScopeError(f"{ctx}: 'probe' must be {{url: http(s) URL, status: HTTP status code}}")
    return dict(ident)


def _identity_urls_in_scope(scope: Scope, origin: str) -> None:
    """Login, signup and probe URLs are visited through the gate: a scope that names one outside itself is broken."""
    from bh.scope.enforce import check  # enforce imports this module

    for i, ident in enumerate(scope.identities):
        for key, u in (
            ("login_url", ident.get("login_url")),
            ("signup_url", ident.get("signup_url")),
            ("probe.url", (ident.get("probe") or {}).get("url")),
        ):
            if u is not None and not (d := check(scope, u)):
                raise ScopeError(f"{origin}: identities[{i}].{key} {u!r} is not in scope ({d.reason})")


def load_scope(path: str | Path) -> Scope:
    p = Path(path)
    try:
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ScopeError(f"{p}: invalid YAML: {exc}") from exc
    return scope_from_dict(doc, str(p))
