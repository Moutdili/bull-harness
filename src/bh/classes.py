"""Vulnerability classes: one definition shared by the doctrine, the method cards, the verifier and
the program exclusions (forbidden_vulns).

Each class carries:
- aliases: how programs and the agent name it ("Denial of Service" -> dos);
- signals: regexes over the attack surface ("METHOD /path/{id}" keys, parameter names) that make its
  method card worth loading for a segment;
- evidence: the proof standard. The hunting agent reads it in the card, the verifier applies the same
  text, so "proven" means the same thing on both sides.
Cards live in src/bh/cards/<card>.md (written for this harness, ≤ 40 lines each). Skills (W3, the Skill tool of
Claude Code) live in src/bh/skills/<name>/SKILL.md: one per card, same name, plus skills of their own; a class's
skill is `skill_for(class_id)`. src/bh/skills/classes_more.json, when present, adds classes (or completes one) at
import.
"""

from __future__ import annotations

import dataclasses
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import yaml

CARDS_DIR = Path(__file__).parent / "cards"
SKILLS_DIR = Path(__file__).parent / "skills"
MORE_CLASSES = SKILLS_DIR / "classes_more.json"  # classes added by the skills (W3-H), merged at import
# first pass of the access-control classes (idor, broken-access-control): the builtin and the proof it leaves
AUTHZ_TOOL = (
    "`bh-authz` (after mapping, 2+ identities): every known endpoint as each identity and anonymous; it flags owner "
    "data seen by another identity (horizontal) or a role's answer given to a lower role (vertical). It leaves "
    "raw/authz-*/proof.json for the best candidate: read it, then `bh-note finding ... --class "
    "idor|broken-access-control --proof <that path>`."
)
# its write mode is a scanner (contract._AUTHZ_WRITE): shown only to a program that allows scanners
AUTHZ_WRITE = "With `--write-own` it also sends a cross-identity PATCH on your own objects."
# An observation proof (a canary the gate sees on the attacker's side) is only as good as the place it was planted
# (audit T2): shared by every class such a proof may support.
CANARY_PRIVATE = (
    " An observation proof (the canary seen by the gate on the attacker's side) proves nothing unless the place where "
    "the canary was planted is private to the victim by construction (the victim's own conversation, memory entry or "
    "file, never shared, public or readable by the attacker): a canary the attacker could read anyway crosses no "
    "boundary."
)
MAX_CARDS = 3  # per segment: cards are resent every turn
# T27: how far a proof goes, 1 to 3 (`bh-note finding ... --proof-level`). Only `impact` is a finding the judge sees;
# `signal` and `partial` are recorded as CANDIDATE facts (bh.runner.ingest). Our ceiling is one read or one record, on
# our own identities: never a dump, never a takeover.
PROOF_LEVELS = ("signal", "partial", "impact")
LEVEL_DEFAULTS = (
    "an answer differs when the input changes, nothing of value seen yet",
    "the flaw is reached, but what it gives was not read back, or only on one run, or without a control",
    "one read or one record that crosses the boundary, on our own identities, reproduced with its twin control",
)
RECIPE_DEFAULT = (
    "One request that shows the impact and its twin control (same route, the identity or the value changed); a read "
    "before a write, a write only on an object of our own identities, nothing else."
)
# T31: what makes two findings of a class one finding (verify.dedupe_key). In doubt, never one.
#   param      the parameter the proof aims at is part of the finding (XSS: a distinct parameter, a distinct finding)
#   origin     one finding per origin (information disclosure)
#   operation  one finding per operation on a resource: method + route family, whatever the parameter
#   route      the default: route family (method included) + the parameter aimed at
DEDUPE_RULES = ("param", "origin", "operation", "route")
# T26: a timed proof (SQLi): at least TIMED_MEASURES delayed attacks and one twin control without the delay, each at
# most MAX_ELAPSED_MS (bh.agent.proof.validate checks it)
TIMED_MEASURES, MAX_ELAPSED_MS = 3, 10_000


@dataclass(frozen=True)
class VulnClass:
    id: str
    aliases: tuple[str, ...] = ()
    path_signals: tuple[str, ...] = ()  # regexes on the endpoint key, e.g. "GET /api/Users/{id}"
    param_signals: tuple[str, ...] = ()  # regexes on parameter names
    evidence: str = ""
    card: bool = False  # has a method card
    weight: float = 1.0  # < 1 for signals that match broadly (every /api/ route, every login page)
    tool: str = ""  # the builtin that does the first pass for this class (shown with the card, not to the verifier)
    # what a program that allows scanners adds (a scanner of contract.SCANNERS or a scanner mode); never in the card
    # file itself, which the agent may read on any program (audit I8)
    scan: str = ""
    skill: str = ""  # the skill of src/bh/skills that holds its method, when it is not the card's name
    # T27: what `signal`, `partial` and `impact` (PROOF_LEVELS) mean for this class; () = LEVEL_DEFAULTS
    levels: tuple[str, ...] = ()
    recipe: str = ""  # T26: the least intrusive proof, written; "" = RECIPE_DEFAULT
    dedupe: str = "route"  # T31: one of DEDUPE_RULES

    def __post_init__(self) -> None:  # `(r"x")` is a str, not a tuple: accept both
        for name in ("aliases", "path_signals", "param_signals"):
            value = getattr(self, name)
            if isinstance(value, str):
                object.__setattr__(self, name, (value,))
        if self.levels and len(self.levels) != len(PROOF_LEVELS):
            raise ValueError(f"{self.id}: levels are {len(PROOF_LEVELS)} texts ({', '.join(PROOF_LEVELS)})")
        if self.dedupe not in DEDUPE_RULES:
            raise ValueError(f"{self.id}: dedupe is one of {', '.join(DEDUPE_RULES)}")

    def matches(self, key: str, params: Iterable[str]) -> float:
        """How strongly one endpoint calls for this class: 0, or weight (path) / 1.5 x weight (parameter)."""
        if any(re.fullmatch(rx, p, re.I) for p in params for rx in self.param_signals):
            return 1.5 * self.weight
        return self.weight if any(re.search(rx, key, re.I) for rx in self.path_signals) else 0.0


_CARD_CLASSES: tuple[VulnClass, ...] = (
    VulnClass(
        "idor",
        ("bola", "insecure-direct-object-reference", "broken-object-level-authorization", "idor"),
        (r"\{id\}",),
        (r"(user|account|order|invoice|basket|cart|doc(ument)?|file|org|team|project)?_?id", r"uuid"),
        "Data that belongs to identity B is returned to identity A, or A changes B's object. Control: the same "
        "request for A's own object works and an unauthenticated request is refused. An empty 200, an OPTIONS "
        "or preflight answer, or public data is not access." + CANARY_PRIVATE,
        True,
        tool=AUTHZ_TOOL,
        scan=AUTHZ_WRITE,
        levels=(
            "A's request naming B's object is not refused (a status, an empty or public answer)",
            "a field of B's object reaches A, but nothing private, or once only, or without the owner's control",
            "B's private data read by A, or one of B's objects changed by A and read back, with B's own request and "
            "a request without a session as controls",
        ),
        recipe="Two of our identities: B reads its own object (setup), A reads the same object (attack), no session "
        "(control). A read first; a write only on B's object of our own, read back once.",
        dedupe="operation",
    ),
    VulnClass(
        "broken-access-control",
        (
            "broken-access-control",
            "access-control",
            "missing-access-control",
            "improper-access-control",
            "bfla",
            "broken-function-level-authorization",
            "missing-function-level-access-control",
            "vertical-privilege-escalation",
        ),
        evidence="A lower-privileged identity (or no session) reads or performs what only a higher role, or only the "
        "object's owner or tenant, may: the answer holds that role's or owner's data, or the action takes effect. "
        "Control: the same request as an identity without the right, or without a session, is refused. The same "
        "public answer for everyone, or an answer without the protected data, is not a bypass." + CANARY_PRIVATE,
        card=True,
        tool=AUTHZ_TOOL,
        scan=AUTHZ_WRITE,
        levels=(
            "a route of a higher role answers a lower one with something else than a refusal",
            "the lower identity reaches the function, but its effect or the protected data is not shown",
            "the lower identity reads the protected data, or the action takes effect and is read back, with the "
            "refused twin as control",
        ),
        recipe="The same request as the higher identity (setup), as the lower one (attack), and without a session or "
        "as an identity without the right (control); an action only on an object of our own identities.",
        dedupe="operation",
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
        levels=(
            "an altered token or a missing credential gets an answer other than the usual refusal",
            "the protected route answers, but nothing reserved to the account is shown",
            "a resource or action reserved to one of our accounts reached without its credential, with the same "
            "request refused without the bypass",
        ),
        recipe="One request with the altered or missing credential (attack) and its twin with the untouched one "
        "removed (control), on our own accounts only; never a login of another person's account.",
        dedupe="operation",
    ),
    VulnClass(
        "sqli",
        ("sql-injection", "sqli", "blind-sql-injection"),
        (r"/(search|filter|report|export|list)",),
        (r"q|query|search|filter|sort|order(by)?|where|category|id|name"),
        "Data extracted through the injection (database version, a table or column name, a row the user cannot "
        "otherwise read), or a boolean pair: a true and a false payload give consistently different answers on "
        "two runs. A database error tied to the payload is a lead, not a finding. Time-based only as its recipe "
        "says: three delayed answers and a twin control without the delay, each request at most 10 s.",
        True,
        scan="`bh-sqli '<url with the parameter>'` (`--data` for a body, `--as user-a` for an authenticated one) "
        "runs Boolean/Error/Union only, never time-based; a point it finds is confirmed by hand with ONE read-only "
        "extraction.",
        levels=(
            "a database error tied to the payload",
            "a true/false or delayed/undelayed differential seen once, or without its control",
            "one read-only value extracted (the database version), or the differential reproduced on two runs with "
            "its control; never a table dumped",
        ),
        recipe="A boolean pair first (true and false payloads, one request each). Timing only when nothing else "
        "answers: three requests with a delay of at most 10 s, each expecting elapsed_ms_min, and one twin control "
        "without the delay expecting elapsed_ms_max, at the program's rate. One read-only value at most.",
        dedupe="param",
    ),
    VulnClass(
        "nosqli",
        ("nosql-injection", "nosqli"),
        (),
        (),
        "Same standard as SQL injection: extracted data or a consistent boolean differential.",
        False,
        levels=(
            "an operator in the input changes the answer's error",
            "an operator changes which documents come back, once or without control",
            "one value read through the operator on our own account, or a boolean differential on two runs with "
            "its control",
        ),
        recipe="An operator pair on our own account (`$ne` against `$eq` on the same field), one request each; "
        "nothing extracted character by character.",
        dedupe="param",
    ),
    VulnClass(
        "xss",
        ("cross-site-scripting", "reflected-xss", "stored-xss", "dom-xss", "xss"),
        (r"/(search|comment|feedback|review|profile|message|post)",),
        (r"q|query|search|message|comment|name|title|text"),
        "The payload reaches an executable context unencoded (HTML tag or attribute, script, javascript: URL) and "
        "executes. Reflection alone, or a payload that is HTML-encoded, is not XSS. Prove execution in a real "
        "browser: `bh-browse '<url with payload>' --xss <marker>` with a payload that calls alert('<marker>'); "
        "only `xss CONFIRMED (marker ...)` is proof. Client-side routes (`/#/...`) and DOM sinks are tested the "
        'same way; in proof.json such a step carries `"browse": {"xss": "<marker>"}`.',
        True,
        scan="`bh-xss '<url?param=x>'` for the reflected cases, before the method by hand.",
        levels=(
            "the payload comes back unencoded in the page",
            "it lands in an executable context, but no execution was seen (CSP, browser, sanitizer)",
            "it executes in a real browser on the target's origin: `xss CONFIRMED` from a browse step, with a "
            "benign twin as control",
        ),
        recipe='A browse step `"browse": {"xss": "<marker>"}` with a payload that only calls alert(\'<marker>\'), '
        "and its twin with a benign value; no cookie or token read, nothing sent anywhere.",
        dedupe="param",
    ),
    VulnClass(
        "ssrf",
        ("server-side-request-forgery", "ssrf"),
        (r"/(proxy|fetch|preview|import|webhook|callback|render|pdf|image)",),
        (r"url|uri|link|src|source|dest|redirect_uri|callback|webhook|image(_?url)?|feed|proxy|fetch|host"),
        "The target's server fetched a URL we chose, shown one of two ways: a request received on a host of ours "
        "(a listener the scope declares), or the content of an in-scope page the server read and returned or "
        "rendered. An internal address is never the proof and never requested (the program forbids it). No "
        'listener declared by the scope: `bh-note blocked oob-needed "<url and parameter>"`.',
        True,
        levels=(
            "the server's answer changes with the URL we give",
            "a request reached a host of ours, but we do not know it came from the target's server",
            "a request from the target's server received on a listener the scope declares, or an in-scope page the "
            "server read and returned, with a benign URL as control",
        ),
        recipe="One URL on a listener the scope declares (attack) and the same parameter with a benign in-scope URL "
        "(control); never an internal address, never a third party.",
        dedupe="param",
    ),
    VulnClass(
        "open-redirect",
        ("open-redirect", "unvalidated-redirect", "url-redirection"),
        (r"/(redirect|out|go|link|logout|login|callback)",),
        (r"redirect(_?uri|_?url)?|next|return(_?url|to)?|continue|to|goto|dest(ination)?|target|r|u|url"),
        "The response sends the browser to an external domain we supplied (Location header, meta refresh or JS). "
        "Control: a benign internal value stays internal. Most programs pay it only when chained (OAuth token leak).",
        True,
        levels=(
            "our value appears in a Location header or a script, not followed",
            "a redirect toward our value, shown by the raw answer only",
            "a real navigation ends on a payload host of the scope: `redirect CONFIRMED` from a browse step, with an "
            "internal value as control",
        ),
        recipe='A browse step `"browse": {"final_url": "https://<payload host>/<path>"}` on the redirecting URL, and '
        "its twin with an internal value; the destination is always a payload host of the scope, never a third party.",
        dedupe="param",
    ),
    VulnClass(
        "file-upload",
        ("unrestricted-file-upload", "file-upload", "upload"),
        (r"/(upload|file|avatar|image|import|attachment|media|document)s?",),
        (r"file|upload|attachment|avatar|image"),
        "An uploaded file is served back in a way that runs (stored XSS through SVG/HTML served inline, server-side "
        "execution) or overwrites something. Storing an arbitrary file alone is not a vulnerability.",
        True,
        levels=(
            "a file type the form should refuse is accepted",
            "the file is served back, but nothing runs or is overwritten",
            "the file served back runs in the target's origin (a marker of ours), or overwrites one of our own files, "
            "with a harmless file as control",
        ),
        recipe="One small file on our own account with a marker only (an SVG that calls alert('<marker>')), and the "
        "same upload with a harmless image as control; never a server-side payload.",
        dedupe="operation",
    ),
    VulnClass(
        "graphql",
        ("graphql",),
        (r"/(graphql|gql|graphiql)",),
        (),
        "Introspection alone is information. Proof is unauthorized data or a mutation reached through GraphQL; the "
        "IDOR and auth standards apply.",
        True,
        levels=(
            "introspection or a field suggestion",
            "an object of another identity named in an error or a partial answer",
            "unauthorized data or a mutation reached through GraphQL, under the IDOR or auth standard",
        ),
        recipe="One query (or one mutation on our own object) as the wrong identity, and the same as the owner or "
        "without a session; no batching, no alias lists.",
        dedupe="operation",
    ),
    VulnClass(
        "business-logic",
        ("business-logic", "logic-flaw", "price-manipulation"),
        (
            r"/(basket|cart|checkout|order|payment|pay|coupon|voucher|wallet|transfer|price|discount|subscription|refund)",
        ),
        (r"price|amount|quantity|qty|discount|coupon|total"),
        "A rule of the business is broken on our own account (price, quantity, coupon reuse, a step skipped), shown "
        "with the state before and after and a control where the rule holds.",
        True,
        levels=(
            "the server accepts a value the interface never sends",
            "the value is accepted, but the state after was not read back",
            "a business rule broken on our own account, state read before and after, with a control where it holds",
        ),
        recipe="State read, one request that breaks the rule on our own account, state read again; the same request "
        "with a legal value as control. Never a real payment.",
        dedupe="operation",
    ),
    VulnClass(
        "info-disclosure",
        ("information-disclosure", "sensitive-data-exposure", "secret-leak", "info-disclosure"),
        (r"(\.git|\.env|backup|\.bak|config|debug|metrics|actuator|swagger|openapi|phpinfo|/ftp|/logs?|\.sql|\.zip)",),
        (),
        "An actual secret value (credential, API key, token, private key) or other users' personal data. Field "
        "names, public specs, version banners and by-design data are not disclosure.",
        True,
        scan="Candidates also come from the hits of `bh-content` and `bh-scan`.",
        levels=(
            "a file or route answers that should not exist",
            "it holds names, versions or by-design data, but no secret value",
            "one actual secret value or another user's personal data read once; never used, never dumped",
        ),
        recipe="One GET of the file or route (attack) and the same path without the leaking part (control); the "
        "secret is shown redacted and never used.",
        dedupe="origin",
    ),
    VulnClass(
        "path-traversal",
        ("path-traversal", "directory-traversal", "lfi", "local-file-inclusion"),
        (r"/(download|file|files|static|view|read|template|include)",),
        (r"file(name)?|path|template|doc|page|download|include|dir|folder"),
        "The content of a file outside the served directory comes back (a known marker of a system file). Control: "
        "the same path without the traversal sequence gives different content.",
        True,
        levels=(
            "a traversal sequence changes the error",
            "a file outside the served directory is named or sized, not read",
            "a known marker of a system file comes back, with the same path without the sequence as control",
        ),
        recipe="One read of a harmless system file with a known marker, and its twin without the traversal; never "
        "a secret file, never a write.",
        dedupe="param",
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
        levels=(
            "an arbitrary Origin is reflected",
            "reflected with credentials allowed, on an answer without sensitive data",
            "a credentialed cross-origin read of our own account's sensitive data, with a benign origin as control",
        ),
        recipe="One request with an Origin of a payload host and our session (attack), and its twin with the "
        "target's own origin (control).",
        dedupe="operation",
    ),
    VulnClass(
        "prompt-injection",
        (
            "prompt-injection",
            "indirect-prompt-injection",
            "cross-domain-prompt-injection",
            "xpia",
            "llm-prompt-injection",
            "ai-prompt-injection",
        ),
        (r"/(chat|copilots?|assistants?|conversations?|completions?|prompts?|llm|genai|ai|bots?)(/|$| |\?)",),
        (r"prompt|system_?prompt|instructions?",),
        "Content that identity A controls (document, mail, page, file) makes the AI acting for identity B do "
        "something B did not ask and A may not do (an action in B's account), or return B's data to A. Proof: "
        "the canary BH-SECRET-<16 hex> planted in B's data only and seen by the gate on A's side (an observation "
        "proof: never sent by A), or the action seen in B's account read back, outside the model's prose, in k "
        "of N runs (N >= 3). Control: the same content without the "
        "instruction, or the same request by B without the poisoned source, shows neither. The model saying it "
        "leaked data, a jailbreak or harmful text, self-impact (attacker = victim) and system prompt extraction "
        "are not findings." + CANARY_PRIVATE,
        True,
        levels=(
            "the model follows an instruction from A's content in A's own session",
            "B's session acts on A's content, but neither the canary nor the action crossed",
            "the canary planted in B's data seen on A's side by the gate, or the action read back in B's account, in "
            "k of N runs with the control",
        ),
        recipe="A plants one instruction in content it owns; B, our other identity, asks its usual question; the "
        "canary planted only in B's data. N runs, the same without the instruction as control.",
    ),
)
# exclusion-only classes (no card): names programs use in their non-qualifying lists
_EXCLUSION_CLASSES: tuple[VulnClass, ...] = (
    VulnClass("dos", ("denial-of-service", "ddos", "resource-exhaustion", "dos")),
    VulnClass("race-condition", ("race-condition", "race-conditions")),  # excluding it must not drop business-logic
    VulnClass("brute-force", ("bruteforce", "credential-stuffing", "password-spraying", "brute-force")),
    VulnClass("self-xss", ("self-xss",)),
    VulnClass("clickjacking", ("ui-redressing", "clickjacking")),
    VulnClass("csrf-logout", ("logout-csrf", "csrf-logout")),
    VulnClass("missing-headers", ("missing-security-headers", "security-headers", "missing-headers")),
    VulnClass("rate-limiting", ("rate-limit", "missing-rate-limit", "no-rate-limit", "rate-limiting")),
    VulnClass("version-disclosure", ("banner-disclosure", "banner", "version-disclosure"), dedupe="origin"),
    VulnClass("social-engineering", ("phishing", "social-engineering")),
    VulnClass("spam", ("spam", "email-flooding")),
    VulnClass("physical", ("physical",)),
)
_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
# T31 rules of classes that classes_more.json adds (its entries carry no rule): the rest take `route`
DEDUPE_MORE = {"ssti": "param", "csrf": "operation", "mass-assignment": "operation"}


def _strings(entry: dict, key: str, where: str) -> tuple[str, ...]:
    value = entry.get(key) or ()
    if isinstance(value, str):
        value = (value,)
    if not isinstance(value, (list, tuple)) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"{where}: {key!r} is a list of strings")
    for v in value if key.endswith("signals") else ():
        re.compile(v)  # a bad regex fails here, at import, not in the middle of a segment
    return tuple(value)


def build_classes(more: Path | None = MORE_CLASSES) -> tuple[VulnClass, ...]:
    """The card classes, then those of `more` (classes_more.json, a list of {"id", "aliases", "path_signals",
    "param_signals", "evidence", "skill"}), then the exclusion-only classes. An id already defined is completed, never
    duplicated: its `skill` is set and its `evidence` filled when it had none (a standard already written stays, its
    aliases and signals too). No file: the built-in classes as they are. A malformed file raises (an error of the lot
    that wrote it, said at import)."""
    base = [*_CARD_CLASSES, *_EXCLUSION_CLASSES]
    if more is None or not more.is_file():
        return tuple(base)
    entries = json.loads(more.read_text())
    if not isinstance(entries, list):
        raise ValueError(f"{more.name}: a list of class objects")
    index = {c.id: i for i, c in enumerate(base)}
    added: list[VulnClass] = []
    for n, entry in enumerate(entries):
        where = f"{more.name}[{n}]"
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or not _NAME.fullmatch(entry["id"]):
            raise ValueError(f'{where}: an object with an "id" made of [a-z0-9-]')
        cid = entry["id"]
        evidence, skill = entry.get("evidence") or "", entry.get("skill") or ""
        if not isinstance(evidence, str) or not isinstance(skill, str) or (skill and not _NAME.fullmatch(skill)):
            raise ValueError(f'{where}: "evidence" is a string, "skill" a skill name')
        if cid in index:
            old = base[index[cid]]
            base[index[cid]] = dataclasses.replace(old, evidence=old.evidence or evidence, skill=skill or old.skill)
        elif any(c.id == cid for c in added):
            raise ValueError(f"{where}: {cid!r} appears twice")
        else:
            added.append(
                VulnClass(
                    cid,
                    _strings(entry, "aliases", where),
                    _strings(entry, "path_signals", where),
                    _strings(entry, "param_signals", where),
                    evidence,
                    skill=skill,
                    dedupe=DEDUPE_MORE.get(cid, "route"),
                )
            )
    n_card = len(_CARD_CLASSES)
    return (*base[:n_card], *added, *base[n_card:])


def alias_map(classes: Iterable[VulnClass]) -> dict[str, str]:
    """Alias -> class id. A built-in alias keeps its class: a class added later never takes a name over ("jwt" stays
    `auth` even if a `jwt` class is added), and an id is its own alias only when no other class claims it."""
    out: dict[str, str] = {}
    classes = list(classes)
    builtin = {c.id for c in (*_CARD_CLASSES, *_EXCLUSION_CLASSES)}
    for c in sorted(classes, key=lambda c: c.id not in builtin):  # built-in first, stable within each group
        for alias in (*c.aliases, c.id):
            out.setdefault(alias, c.id)
    return out


CLASSES: tuple[VulnClass, ...] = build_classes()
BY_ID = {c.id: c for c in CLASSES}
_ALIAS = alias_map(CLASSES)
# names distinctive enough to be found inside a longer phrase ("XSS (stored)", "Denial of Service (DoS) attacks");
# single words like "session" or "auth" are not ("Missing session timeout" is not every auth bug)
_DISTINCT = {
    "xss",
    "sqli",
    "ssrf",
    "idor",
    "bola",
    "lfi",
    "dos",
    "ddos",
    "clickjacking",
    "cors",
    "spam",
    "phishing",
    "bruteforce",
    "nosqli",
    "graphql",
    "xpia",
}
_IN_PHRASE = sorted(((a, cid) for a, cid in _ALIAS.items() if "-" in a or a in _DISTINCT), key=lambda ac: -len(ac[0]))
_FILLER = {"attack", "attacks", "vulnerability", "vulnerabilities", "issue", "issues", "bug", "bugs", "flaw", "flaws"}
# an exclusion with a condition ("without demonstrated impact", "unless chained") is the human's call
_QUALIFIED = re.compile(
    r"\b(without|unless|except|only|if|when|requires?|limited|low[- ]impact|no (real|proven))\b", re.I
)


def _slug(name: str) -> str:
    return "-".join(re.sub(r"[^a-z0-9]+", " ", str(name).lower()).split())


def canonical(name: str) -> str:
    """'Denial of Service (DoS) attacks' -> 'dos', 'XSS (stored)' -> 'xss', 'Missing_Security headers' ->
    'missing-headers'. Exact alias first, then the longest distinctive alias inside the phrase; else the slug."""
    key = _slug(name)
    if key in _ALIAS:
        return _ALIAS[key]
    padded = f"-{key}-"
    return next((cid for alias, cid in _IN_PHRASE if f"-{alias}-" in padded), key)


def exclusion(text: str) -> str | None:
    """The class a program's non-qualifying entry removes ENTIRELY, or None (a human reads it). Only an entry that is
    the class's name, give or take filler words, removes a class: "Denial of Service (DoS) attacks" -> dos, but
    "Pre-account takeover via OAuth" or "Open redirect without impact" remove nothing automatically."""
    if _QUALIFIED.search(str(text)):
        return None
    words = _slug(re.sub(r"\([^)]*\)", " ", str(text))).split("-")
    for lead in (("lack", "of"), ("absence", "of"), ("missing",), ("no",), ("any",), ("all",)):
        if tuple(words[: len(lead)]) == lead and len(words) > len(lead):
            stripped = words[len(lead) :]
            break
    else:
        stripped = words
    while stripped and stripped[-1] in _FILLER:
        stripped = stripped[:-1]
    for candidate in ("-".join(words), "-".join(stripped)):
        if candidate in _ALIAS:
            return _ALIAS[candidate]
    return None


def evidence(name: str) -> str:
    cls = BY_ID.get(canonical(name))
    return (
        cls.evidence if cls and cls.evidence else "Reproducible, real impact on a user or the company, with a control."
    )


def _cls(name: str) -> VulnClass | None:
    return BY_ID.get(str(name)) or BY_ID.get(canonical(str(name)))


def proof_levels(name: str) -> dict[str, str]:
    """{"signal": ..., "partial": ..., "impact": ...} for the class `name` (T27); the defaults for a class without
    its own."""
    cls = _cls(name)
    return dict(zip(PROOF_LEVELS, (cls.levels if cls and cls.levels else LEVEL_DEFAULTS), strict=True))


def level_name(level: object) -> str | None:
    """1 -> signal, 2 -> partial, 3 -> impact; None for anything else."""
    try:
        n = int(str(level))
    except ValueError:
        return None
    return PROOF_LEVELS[n - 1] if 1 <= n <= len(PROOF_LEVELS) else None


def recipe(name: str) -> str:
    """The least intrusive proof of the class `name`, written (T26); RECIPE_DEFAULT for a class without one."""
    cls = _cls(name)
    return cls.recipe if cls and cls.recipe else RECIPE_DEFAULT


def dedupe_rule(name: str) -> str:
    """The T31 rule of the class `name` (DEDUPE_RULES); `route` for an unknown class."""
    cls = _cls(name)
    return cls.dedupe if cls else "route"


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
    excluded = {e for x in exclude if (e := exclusion(x))}
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


_CARD_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
SANDBOX_CARDS_DIR = "/opt/bh/cards"  # src/bh/cards, mounted read-only in the agent container (compose.yaml)


def pinned_cards(scope) -> list[str]:
    """The scope's `cards:` (audit I7): always injected, from the first leg. Each must name a file of CARDS_DIR;
    a bad or missing one is an operator error, raised before the segment starts."""
    names = [str(n) for n in (getattr(scope, "cards", ()) or ())]
    for n in names:
        if not _CARD_NAME.fullmatch(n) or not (CARDS_DIR / f"{n}.md").is_file():
            raise ValueError(f"scope card {n!r}: no {CARDS_DIR.name}/{n}.md")
    return list(dict.fromkeys(names))


def _scanner_words():
    from bh.agent.contract import SCANNERS

    alt = "|".join(re.escape(n) for n in sorted(SCANNERS, key=len, reverse=True))
    # a scanner's name as a word, and the scanner modes of the mappers (contract: _BROWSE_XSS aside, which one page
    # with one marker keeps legal)
    return re.compile(rf"(?<![\w.-])({alt})(?![\w.-])|--write-own\b|--active\b", re.I)


SCANNER_WORDS = _scanner_words()


def no_scanner(text: str) -> str:
    """The lines of `text` that name no scanner (audit I8, R18): a guard behind the cards, which are written without
    one; a line dropped here is a card to fix (tests/test_w1_verify.py)."""
    return "\n".join(line for line in text.splitlines() if not SCANNER_WORDS.search(line))


def _card(c: str, scanners: bool = False) -> str:
    cls = BY_ID.get(c)
    text = card_text(c)
    if cls is not None and cls.card:
        text += (
            "\n"
            + (f"Tool: {cls.tool}\n" if cls.tool else "")
            + (f"Scanner (this program allows them): {cls.scan}\n" if scanners and cls.scan else "")
            + f"Proof standard (the verifier applies exactly this): {cls.evidence}\n"
            + f"Least intrusive proof: {recipe(c)}\n"
            + "Proof levels (`--proof-level`): "
            + "; ".join(f"{n} {name}: {text}" for n, (name, text) in enumerate(proof_levels(c).items(), 1))
        )
    return text if scanners else no_scanner(text)


def cards_block(class_ids: list[str], pinned: list[str] | tuple[str, ...] = (), *, scanners: bool = False) -> str:
    """Cards for one task: the scope's pinned ones first, then those picked from the attack surface (a pinned card is
    never repeated). Every card is also readable on demand under SANDBOX_CARDS_DIR.

    `scanners`: the program allows automated scanners (scope.scanners_on). False by default, so a caller that does
    not say gets the cards a scanner-free program reads: no tool of contract.SCANNERS, no scanner mode."""
    picked = [c for c in class_ids if c not in pinned]
    if not picked and not pinned:
        return ""
    out = []
    if pinned:
        out += ["# Program cards (pinned by the operator for this program)", *(_card(c, scanners) for c in pinned)]
    if picked:
        out += [
            "# Method cards for this segment (picked from the attack surface)",
            *(_card(c, scanners) for c in picked),
        ]
    out.append(f"Other cards: `Read {SANDBOX_CARDS_DIR}/<name>.md` ({', '.join(all_cards())}).")
    return "\n\n".join(out)


def all_cards() -> list[str]:
    return sorted(p.stem for p in CARDS_DIR.glob("*.md"))


# ------------------------------------------------------------------ skills (W3): src/bh/skills/<name>/SKILL.md
SKILL_FILE = "SKILL.md"
SKILL_REQUIRES = ("scanners",)  # the only value of `requires`: the skill names a scanner (audit I8)
DESCRIPTION_MAX = 200  # what the agent pays every turn: it says when to load the skill, nothing more


def skills_dir() -> Path:
    return SKILLS_DIR


def _skill_path(name: str) -> Path | None:
    path = SKILLS_DIR / str(name) / SKILL_FILE
    return path if _NAME.fullmatch(str(name)) and path.is_file() else None


def skill_frontmatter(text: str) -> dict:
    """The YAML between the opening `---` and the next one; {} when the text has none."""
    m = re.match(r"---\n(.*?)\n---(?:\n|$)", text, re.S)
    meta = yaml.safe_load(m.group(1)) if m else None
    return meta if isinstance(meta, dict) else {}


def skill_text(name: str) -> str:
    """The whole SKILL.md of a skill (frontmatter included). An unknown name raises."""
    path = _skill_path(name)
    if path is None:
        raise ValueError(f"skill {name!r}: no {SKILLS_DIR.name}/{name}/{SKILL_FILE}")
    return path.read_text().strip()


def all_skills() -> list[dict]:
    """Every skill of SKILLS_DIR, sorted by name: {"name", "description", "requires"} (`requires`: None or
    "scanners")."""
    out = []
    for path in sorted(SKILLS_DIR.glob(f"*/{SKILL_FILE}")):
        meta = skill_frontmatter(path.read_text())
        requires = meta.get("requires")
        out.append(
            {
                "name": str(meta.get("name") or path.parent.name),
                "description": str(meta.get("description") or ""),
                "requires": str(requires) if requires else None,
            }
        )
    return out


def skill_for(class_id: str) -> str | None:
    """The skill that holds a class's method: the class's own `skill`, else its card's name; None when no such skill
    exists on disk. An exact class id first (a class added by classes_more.json whose id is an older alias, `jwt`),
    then the canonical name ("BOLA" -> idor)."""
    cls = BY_ID.get(str(class_id)) or BY_ID.get(canonical(str(class_id)))
    if cls is None:
        return None
    for name in (cls.skill, cls.id if cls.card else ""):
        if name and _skill_path(name) is not None:
            return name
    return None


def pinned_skills(scope, model: str | None) -> list[str]:
    """Skills the scope pins for one model family (`pin_for_models: {<skill>: [<family>, ...]}`, lot D): pinned when
    the model id without its `claude-` prefix starts with one of the families ("claude-opus-5-5" -> "opus")."""
    pins = getattr(scope, "pin_for_models", None) or {}
    family = str(model or "").lower().removeprefix("claude-")
    if not family:
        return []
    out = []
    for skill, listed in pins.items() if hasattr(pins, "items") else pins:  # a dict, or its (skill, families) pairs
        families = (listed,) if isinstance(listed, str) else (listed or ())
        if any(str(f) and family.startswith(str(f).lower()) for f in families):
            out.append(str(skill))
    return out


def program_skills(scope, model: str | None = None) -> list[str]:
    """The skills given whole to the hunter on this program: the scope's `cards` (one skill per card, same name),
    then those pinned for `model`. Each must name a skill of SKILLS_DIR: a bad or missing one is an operator error,
    raised before the segment starts."""
    names = [str(n) for n in (getattr(scope, "cards", ()) or ())] + pinned_skills(scope, model)
    for n in names:
        if _skill_path(n) is None:
            raise ValueError(f"scope skill {n!r}: no {SKILLS_DIR.name}/{n}/{SKILL_FILE}")
    return list(dict.fromkeys(names))
