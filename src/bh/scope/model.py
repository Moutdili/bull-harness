"""Scope contract (schema v1).

A scope file is the hard boundary of what the agent may touch for one program.
Loading is strict: unknown keys, unsupported wildcard shapes and empty
in-scope lists are errors, because a typo in a scope file must fail closed.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml

from bh.scope.normalize import DEFAULT_PORTS, norm_host, norm_path, parse_ip

SCHEMA_VERSION = 1
# Rate used when a program publishes none: conservative, the gate and the builtins both apply it.
DEFAULT_RPS = 2.0


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
    host: str | None = None  # DOMAIN host, WILDCARD base, URL host (may start with "*.")
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
    scanners_allowed: bool | None = None  # False = program forbids automated scanners (ffuf, nuclei, sqlmap...)
    forbidden_vulns: tuple[str, ...] = ()
    identities: tuple[dict[str, str], ...] = ()  # {name, secret_ref}; never the secret
    source: str | None = None
    synced_at: str | None = None
    notes: str = ""
    digest: str = ""  # sha256 of the canonical source document

    def excludes(self, vuln_class: str | None) -> str | None:
        """The program exclusion matching `vuln_class`, if any."""
        if not vuln_class:
            return None
        canon = canonical_vuln(vuln_class)
        return next((f for f in self.forbidden_vulns if canonical_vuln(f) == canon), None)

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
    if value.startswith("*."):
        return RuleType.WILDCARD
    if "/" in value or parse_ip(value) is not None:
        return RuleType.CIDR
    return RuleType.DOMAIN


def _check_wildcard_shape(value: str, ctx: str) -> None:
    if "*" in value and not (value.startswith("*.") and "*" not in value[2:]):
        raise ScopeError(f"{ctx}: unsupported wildcard {value!r} (only leading '*.' is allowed)")


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
                _check_wildcard_shape(value, ctx)
                if not value.startswith("*."):
                    raise ScopeError(f"{ctx}: wildcard must start with '*.'")
                return Rule(rtype, value, note, host=norm_host(value[2:]))
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
    host = "*." + norm_host(host_s[2:]) if host_s.startswith("*.") else norm_host(host_s)
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
    for i, ident in enumerate(identities):
        if not isinstance(ident, dict) or set(ident) - {"name", "secret_ref"} or "name" not in ident:
            raise ScopeError(f"{origin}: identities[{i}] must be {{name, secret_ref}}")

    return Scope(
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


def load_scope(path: str | Path) -> Scope:
    p = Path(path)
    try:
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ScopeError(f"{p}: invalid YAML: {exc}") from exc
    return scope_from_dict(doc, str(p))
