"""Import a public YesWeHack program into a scope file (TODO H5, public programs only).

Source: the public program API (`GET https://api.yeswehack.com/programs/<slug>`, no authentication).
Conversion never widens the program's scope:
- domains, URLs, `*.wildcards` and IPs/CIDRs map 1:1; `(a|b)` alternations expand to exact rules;
- a trailing `/*` becomes a URL path prefix;
- anything that cannot be expressed exactly (a `*` inside a path or a label, boolean expressions,
  free text, mobile apps) is NOT turned into a wider rule: it is kept as an informational `other`
  rule and listed for the human;
- hosts and URLs quoted in the free-text out-of-scope list become out-of-scope rules (excluding
  more is the safe direction);
- non-qualifying vulnerabilities become `forbidden_vulns` (findings of those classes are rejected);
- `automation_allowed` stays null: a human reads the rules and decides (the runner refuses until then).
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
from dataclasses import dataclass, field
from itertools import product
from typing import Any

from bh.scope.model import ScopeError, parse_rule

API = "https://api.yeswehack.com/programs/{slug}"
WEB_TYPES = {"web-application", "api", "ip-address", "wildcard", "other"}
_ALTERNATION = re.compile(r"\(([^()]+\|[^()]+)\)")
_URL_IN_TEXT = re.compile(r"https?://[^\s'\"<>),]+", re.I)
_HOST_IN_TEXT = re.compile(r"(?<![\w@/.-])((?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})(?![\w-])", re.I)
_PLACEHOLDER = re.compile(r"(:[a-z_]+:?|\{[^}]*\}|<[^>]*>|\bXX\b|\*)", re.I)
_RATE = re.compile(r"(\d+(?:[.,]\d+)?)\s*(?:requests?|reqs?|queries)\s*(?:/|per)\s*(second|sec|s|minute|min)\b", re.I)
_NO_SCANNERS = re.compile(
    r"(do not|don't|never|no|not (?:be )?allowed|prohibited|forbidden)[^.\n]{0,60}"
    r"(automated|automatic|automation)\s+(scanner|scanning|scan|tool)",
    re.I,
)
_RULE_HINTS = re.compile(r"(automat|scanner|scanning|\btool|rate|requests? per|header|user[- ]agent|vpn|brute)", re.I)


@dataclass
class Imported:
    doc: dict[str, Any]
    skipped: list[str] = field(default_factory=list)  # in-scope entries the human must translate by hand
    excluded_from_text: list[str] = field(default_factory=list)
    rule_excerpts: list[str] = field(default_factory=list)


def fetch(slug: str) -> dict:
    if not re.fullmatch(r"[a-z0-9-]{3,120}", slug):
        raise ScopeError(f"bad program slug {slug!r}")
    req = urllib.request.Request(
        API.format(slug=slug), headers={"User-Agent": "bull-harness", "Accept": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read())


def _expand(value: str) -> list[str]:
    """`*.doctolib.(fr|de)` -> [`*.doctolib.fr`, `*.doctolib.de`]."""
    parts = _ALTERNATION.split(value)
    choices = [p.split("|") if i % 2 else [p] for i, p in enumerate(parts)]
    return ["".join(c).strip() for c in product(*choices)]


def _web_rule(value: str) -> str | None:
    """Exact rule text for one in-scope value, or None if it cannot be expressed without widening."""
    v = re.sub(r"\s+", "", value)
    if not v:
        return None
    if "://" not in v and "/" in v:  # host/path without scheme
        v = "https://" + v
    if "://" in v:
        scheme, rest = v.split("://", 1)
        host, _, path = rest.partition("/")
        path = "/" + path
        if path.endswith("/*"):
            path = path[:-1]
        if "*" in path or "*" in host.lstrip("*."):
            return None
        return f"{scheme}://{host}{path}"
    if "*" in v and not (v.startswith("*.") and "*" not in v[2:]):
        return None
    return v


def _check(rule: str) -> bool:
    try:
        parse_rule(rule, "ywh")
    except ScopeError:
        return False
    return True


def _exclusions(texts: list[str]) -> list[str]:
    out: list[str] = []
    for text in texts:
        for url in _URL_IN_TEXT.findall(text):
            cut = _PLACEHOLDER.split(url, maxsplit=1)[0]  # stop at :folder:, {id}, XX, *
            if cut.count("/") >= 3 and _check(cut):
                out.append(cut)
        for host in _HOST_IN_TEXT.findall(_URL_IN_TEXT.sub(" ", text)):
            templated = re.search(r"(^|[.-])x{2,}([.-]|$)", host, re.I)  # ov-XX.example.ch: not a real host
            file_like = re.search(r"\.(png|jpe?g|pdf|html?|php|js|pub|txt|zip)$", host, re.I)
            if not templated and not file_like and _check(host):
                out.append(host.lower())
    return sorted(set(out))


def _max_rps(rules: str) -> float | None:
    rates = []
    for num, unit in _RATE.findall(rules or ""):
        n = float(num.replace(",", "."))
        rates.append(n / 60 if unit.lower().startswith("min") else n)
    return min(rates) if rates else None


def convert(program: dict, username: str | None) -> Imported:
    slug = program.get("slug") or program.get("pid") or "program"
    imp = Imported(doc={})
    in_scope: list[Any] = []
    for sc in program.get("scopes") or []:
        value, stype = str(sc.get("scope", "")), sc.get("scope_type", "")
        note = f"{sc.get('scope_type_name') or stype}, asset value {sc.get('asset_value') or '?'}"
        if stype in WEB_TYPES:
            rules = [r for v in _expand(value) if (r := _web_rule(v)) and _check(r)]
            if rules and all(_web_rule(v) for v in _expand(value)):
                in_scope += [{"value": r, "note": note} for r in rules]
                continue
            imp.skipped.append(value)
        in_scope.append({"type": "other", "value": value, "note": note + " (not enforceable as written)"})
    if not any(isinstance(r, dict) and r.get("type") != "other" for r in in_scope):
        raise ScopeError(f"{slug}: no in-scope web asset can be expressed exactly; write the scope by hand")

    oos_text = [str(x) for x in program.get("out_of_scope") or []]
    imp.excluded_from_text = _exclusions(oos_text)
    ua = program.get("user_agent") or None
    if ua and "<" in ua:
        if not username:
            raise ScopeError(f"{slug}: the program requires User-Agent {ua!r}; pass --username <your YWH username>")
        ua = re.sub(r"<[^>]*>", username, ua)
    rules_md = program.get("rules") or ""
    imp.rule_excerpts = [ln.strip() for ln in rules_md.splitlines() if _RULE_HINTS.search(ln)][:25]
    notes = [
        f"https://yeswehack.com/programs/{slug}",
        f"VPN required: {bool(program.get('vpn_active'))}",
        "Accounts: " + re.sub(r"\s+", " ", program.get("account_access") or "not specified")[:400],
        "Out of scope (program text): " + " | ".join(oos_text)[:1500],
    ]
    if imp.skipped:
        notes.append("In-scope entries NOT enforced (translate by hand if needed): " + " | ".join(imp.skipped))
    imp.doc = {
        "schema": 1,
        "program": f"ywh-{slug}"[:80],
        "platform": "yeswehack",
        "source": API.format(slug=slug),
        "synced_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "automation_allowed": None,
        "scanners_allowed": False if _NO_SCANNERS.search(rules_md) else None,
        "max_rps": _max_rps(rules_md),
        "user_agent": ua,
        "required_headers": {},
        "in_scope": in_scope,
        "out_of_scope": imp.excluded_from_text,
        "forbidden_vulns": [str(v) for v in program.get("non_qualifying_vulnerability") or []],
        "identities": [],
        "notes": "\n".join(notes),
    }
    return imp
