"""Vulnerability classes: one definition shared by the doctrine, the method cards, the verifier and
the program exclusions (forbidden_vulns).

Each class carries:
- aliases: how programs and the agent name it ("Denial of Service" -> dos);
- signals: regexes over the attack surface ("METHOD /path/{id}" keys, parameter names) that make its
  method card worth loading for a segment;
- evidence: the proof standard. The hunting agent reads it in the card, the verifier applies the same
  text, so "proven" means the same thing on both sides.
Cards live in src/bh/cards/<card>.md (written for this harness, ≤ 40 lines each).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

CARDS_DIR = Path(__file__).parent / "cards"
MAX_CARDS = 3  # per segment: cards are resent every turn


@dataclass(frozen=True)
class VulnClass:
    id: str
    aliases: tuple[str, ...] = ()
    path_signals: tuple[str, ...] = ()  # regexes on the endpoint key, e.g. "GET /api/Users/{id}"
    param_signals: tuple[str, ...] = ()  # regexes on parameter names
    evidence: str = ""
    card: bool = False  # has a method card
    weight: float = 1.0  # < 1 for signals that match broadly (every /api/ route, every login page)

    def __post_init__(self) -> None:  # `(r"x")` is a str, not a tuple: accept both
        for name in ("aliases", "path_signals", "param_signals"):
            value = getattr(self, name)
            if isinstance(value, str):
                object.__setattr__(self, name, (value,))

    def matches(self, key: str, params: Iterable[str]) -> float:
        """How strongly one endpoint calls for this class: 0, or weight (path) / 1.5 x weight (parameter)."""
        if any(re.fullmatch(rx, p, re.I) for p in params for rx in self.param_signals):
            return 1.5 * self.weight
        return self.weight if any(re.search(rx, key, re.I) for rx in self.path_signals) else 0.0


CLASSES: tuple[VulnClass, ...] = (
    VulnClass(
        "idor",
        ("bola", "insecure-direct-object-reference", "broken-object-level-authorization", "idor"),
        (r"\{id\}",),
        (r"(user|account|order|invoice|basket|cart|doc(ument)?|file|org|team|project)?_?id", r"uuid"),
        "Data that belongs to identity B is returned to identity A, or A changes B's object. Control: the same "
        "request for A's own object works and an unauthenticated request is refused. An empty 200, an OPTIONS "
        "or preflight answer, or public data is not access.",
        True,
    ),
    VulnClass(
        "auth",
        (
            "authentication-bypass",
            "broken-authentication",
            "auth-bypass",
            "jwt",
            "session",
            "account-takeover",
            "ato",
            "privilege-escalation",
            "auth",
        ),
        (r"/(login|signin|auth|token|session|oauth|sso|password|reset|2fa|mfa|otp|whoami|me|admin|role)",),
        (),
        "A resource or action reserved to an authenticated or more privileged user is reached without the needed "
        "credentials, or with a forged / altered token. Control: the same request without the bypass is refused. "
        "A token the attacker obtained legitimately is not a bypass.",
        True,
        0.5,
    ),
    VulnClass(
        "sqli",
        ("sql-injection", "sqli", "blind-sql-injection"),
        (r"/(search|filter|report|export|list)",),
        (r"q|query|search|filter|sort|order(by)?|where|category|id|name"),
        "Data extracted through the injection (database version, a table or column name, a row the user cannot "
        "otherwise read), or a boolean pair: a true and a false payload give consistently different answers on "
        "two runs. A database error tied to the payload is a lead, not a finding. Never time-based.",
        True,
    ),
    VulnClass(
        "nosqli",
        ("nosql-injection", "nosqli"),
        (),
        (),
        "Same standard as SQL injection: extracted data or a consistent boolean differential.",
        False,
    ),
    VulnClass(
        "xss",
        ("cross-site-scripting", "reflected-xss", "stored-xss", "dom-xss", "xss"),
        (r"/(search|comment|feedback|review|profile|message|post)",),
        (r"q|query|search|message|comment|name|title|text"),
        "The payload reaches an executable context unencoded (HTML tag or attribute, script, javascript: URL) and "
        "executes. Reflection alone, or a payload that is HTML-encoded, is not XSS. Without a browser, report the "
        "exact context and say that execution is not proven.",
        True,
    ),
    VulnClass(
        "ssrf",
        ("server-side-request-forgery", "ssrf"),
        (r"/(proxy|fetch|preview|import|webhook|callback|render|pdf|image)",),
        (r"url|uri|link|src|source|dest|redirect_uri|callback|webhook|image(_?url)?|feed|proxy|fetch|host"),
        "The target's server fetched a URL we chose and returned or acted on internal content (cloud metadata, an "
        "internal-only host). The sandbox has no out-of-band listener: a blind SSRF cannot be proven here; record "
        "it as a lead for the human.",
        True,
    ),
    VulnClass(
        "open-redirect",
        ("open-redirect", "unvalidated-redirect", "url-redirection"),
        (r"/(redirect|out|go|link|logout|login|callback)",),
        (r"redirect(_?uri|_?url)?|next|return(_?url|to)?|continue|to|goto|dest(ination)?|target|r|u|url"),
        "The response sends the browser to an external domain we supplied (Location header, meta refresh or JS). "
        "Control: a benign internal value stays internal. Most programs pay it only when chained (OAuth token leak).",
        True,
    ),
    VulnClass(
        "file-upload",
        ("unrestricted-file-upload", "file-upload", "upload"),
        (r"/(upload|file|avatar|image|import|attachment|media|document)s?",),
        (r"file|upload|attachment|avatar|image"),
        "An uploaded file is served back in a way that runs (stored XSS through SVG/HTML served inline, server-side "
        "execution) or overwrites something. Storing an arbitrary file alone is not a vulnerability.",
        True,
    ),
    VulnClass(
        "graphql",
        ("graphql",),
        (r"/(graphql|gql|graphiql)",),
        (),
        "Introspection alone is information. Proof is unauthorized data or a mutation reached through GraphQL; the "
        "IDOR and auth standards apply.",
        True,
    ),
    VulnClass(
        "business-logic",
        ("business-logic", "logic-flaw", "race-condition", "price-manipulation"),
        (
            r"/(basket|cart|checkout|order|payment|pay|coupon|voucher|wallet|transfer|price|discount|subscription|refund)",
        ),
        (r"price|amount|quantity|qty|discount|coupon|total"),
        "A rule of the business is broken on our own account (price, quantity, coupon reuse, a step skipped), shown "
        "with the state before and after and a control where the rule holds.",
        True,
    ),
    VulnClass(
        "info-disclosure",
        ("information-disclosure", "sensitive-data-exposure", "secret-leak", "info-disclosure"),
        (r"(\.git|\.env|backup|\.bak|config|debug|metrics|actuator|swagger|openapi|phpinfo|/ftp|/logs?|\.sql|\.zip)",),
        (),
        "An actual secret value (credential, API key, token, private key) or other users' personal data. Field "
        "names, public specs, version banners and by-design data are not disclosure.",
        True,
    ),
    VulnClass(
        "path-traversal",
        ("path-traversal", "directory-traversal", "lfi", "local-file-inclusion"),
        (r"/(download|file|files|static|view|read|template|include)",),
        (r"file(name)?|path|template|doc|page|download|include|dir|folder"),
        "The content of a file outside the served directory comes back (a known marker of a system file). Control: "
        "the same path without the traversal sequence gives different content.",
        True,
    ),
    VulnClass(
        "cors",
        ("cors", "cors-misconfiguration"),
        (r"/api/",),
        (),
        "A credentialed cross-origin read: Access-Control-Allow-Origin reflects an arbitrary origin AND "
        "Access-Control-Allow-Credentials is true, on an authenticated response that holds sensitive data.",
        True,
        0.1,
    ),
    # exclusion-only classes (no card): names programs use in their non-qualifying lists
    VulnClass("dos", ("denial-of-service", "ddos", "resource-exhaustion", "dos")),
    VulnClass("brute-force", ("bruteforce", "credential-stuffing", "password-spraying", "brute-force")),
    VulnClass("self-xss", ("self-xss",)),
    VulnClass("clickjacking", ("ui-redressing", "clickjacking")),
    VulnClass("csrf-logout", ("logout-csrf", "csrf-logout")),
    VulnClass("missing-headers", ("missing-security-headers", "security-headers", "missing-headers")),
    VulnClass("rate-limiting", ("rate-limit", "missing-rate-limit", "no-rate-limit", "rate-limiting")),
    VulnClass("version-disclosure", ("banner-disclosure", "banner", "version-disclosure")),
    VulnClass("social-engineering", ("phishing", "social-engineering")),
    VulnClass("spam", ("spam", "email-flooding")),
    VulnClass("physical", ("physical",)),
)
BY_ID = {c.id: c for c in CLASSES}
_ALIAS = {alias: c.id for c in CLASSES for alias in (*c.aliases, c.id)}


def canonical(name: str) -> str:
    """'Denial of Service' -> 'dos', 'Missing_Security headers' -> 'missing-headers'. Unknown names are slugged."""
    key = "-".join(str(name).lower().replace("_", " ").replace("/", " ").split())
    return _ALIAS.get(key, key)


def evidence(name: str) -> str:
    cls = BY_ID.get(canonical(name))
    return (
        cls.evidence if cls and cls.evidence else "Reproducible, real impact on a user or the company, with a control."
    )


def card_text(class_id: str) -> str:
    return (CARDS_DIR / f"{class_id}.md").read_text().strip()


def select_cards(
    endpoints: Iterable[tuple[str, Iterable[str]]],
    *,
    exclude: Iterable[str] = (),
    recently_used: Iterable[str] = (),
    limit: int = MAX_CARDS,
) -> list[str]:
    """Classes whose card fits this surface best. `endpoints`: (key, params) pairs; `exclude`: classes the
    program does not pay for; `recently_used`: cards of the last segments, ranked lower so methods rotate."""
    excluded = {canonical(x) for x in exclude}
    recent = list(recently_used)
    scores: dict[str, float] = {}
    for raw_key, raw_params in endpoints:
        params = list(raw_params)
        key = re.sub(r"/(?=$| )", "/{id}", raw_key.split("?")[0])  # JS literal "/basket/" + id -> "/basket/{id}"
        for cls in CLASSES:
            if cls.card and cls.id not in excluded:
                scores[cls.id] = scores.get(cls.id, 0) + cls.matches(key, params)
    ranked = sorted(((s - 0.5 * s * recent.count(cid), cid) for cid, s in scores.items() if s > 0), reverse=True)
    return [cid for _, cid in ranked[:limit]]


def cards_block(class_ids: list[str]) -> str:
    if not class_ids:
        return ""
    cards = [
        f"{card_text(c)}\nProof standard (the verifier applies exactly this): {BY_ID[c].evidence}" for c in class_ids
    ]
    return "\n\n".join(["# Method cards for this segment (picked from the attack surface)", *cards])
