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
        scan="`bh-sqli '<url with the parameter>'` (`--data` for a body, `--as user-a` for an authenticated one) "
        "runs Boolean/Error/Union only, never time-based; a point it finds is confirmed by hand with ONE read-only "
        "extraction.",
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
        "executes. Reflection alone, or a payload that is HTML-encoded, is not XSS. Prove execution in a real "
        "browser: `bh-browse '<url with payload>' --xss <marker>` with a payload that calls alert('<marker>'); "
        "only `xss CONFIRMED (marker ...)` is proof. Client-side routes (`/#/...`) and DOM sinks are tested the "
        'same way; in proof.json such a step carries `"browse": {"xss": "<marker>"}`.',
        True,
        scan="`bh-xss '<url?param=x>'` for the reflected cases, before the method by hand.",
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
        ("business-logic", "logic-flaw", "price-manipulation"),
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
        scan="Candidates also come from the hits of `bh-content` and `bh-scan`.",
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
    VulnClass("version-disclosure", ("banner-disclosure", "banner", "version-disclosure")),
    VulnClass("social-engineering", ("phishing", "social-engineering")),
    VulnClass("spam", ("spam", "email-flooding")),
    VulnClass("physical", ("physical",)),
)
_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")


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
            + f"Proof standard (the verifier applies exactly this): {cls.evidence}"
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
