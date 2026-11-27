"""Wave W3, lot C: the cards become skills (D18), skills without scanners (I8), the lines of the skills audit merged
into the class skills (S3), cross-references, report-writing (L2), chaining, GraphQL (D21), the narrowing line
(T35, part)."""

import re
from pathlib import Path

import pytest
import yaml

from bh import classes
from bh.agent import contract

ROOT = Path(__file__).resolve().parents[1]
SKILLS = classes.SKILLS_DIR
CARDS = classes.CARDS_DIR
AGENT = ROOT / "src" / "bh" / "agent"
RUBRICS = ["When", "Do", "Proof", "Never", "False positives", "Watch"]
OURS = sorted(
    {p.stem for p in CARDS.glob("*.md")} | {"report-writing", "chaining", "scanner-playbook"}
)  # the folders of this lot
LOT_H = {
    "race-condition", "mass-assignment", "jwt", "oauth-oidc", "request-smuggling", "prototype-pollution", "ssti",
    "subdomain-takeover", "postmessage", "function-level-authz", "multi-tenant", "nextjs", "firebase", "auth0",
    "supabase", "proof-package", "false-positive-traps", "csrf", "type-confusion", "nosql-injection", "xxe",
    "web-cache", "saml", "websocket-origin", "graphql-schema-from-errors", "wordpress-rest", "api-surface-mapping",
    # wave W4: G (Microsoft services), F (white box), C (severity)
    "agent-actions", "entra", "graph", "power-platform", "whitebox", "cvss-from-evidence",
}  # fmt: skip
PROGRAM_CARDS = (
    "msrc-copilot", "msrc-onedrive", "bh-web-manual", "ai-connectors", "ai-conversation-isolation", "ai-file-upload",
    "ai-memory", "ai-output-rendering", "copilot-share", "copilot-server-actions", "prompt-injection",
)  # fmt: skip
CLASS_CARDS = (
    "idor", "auth", "sqli", "xss", "ssrf", "open-redirect", "file-upload", "graphql", "business-logic",
    "info-disclosure", "path-traversal", "cors", "broken-access-control",
)  # fmt: skip
PAYLOAD_SAID = 'the payload hosts of your scope block; none listed: `bh-note blocked other "no payload host declared"`'


def raw(name: str) -> str:
    return (SKILLS / name / "SKILL.md").read_text()


def parts(name: str) -> tuple[dict, str]:
    m = re.match(r"---\n(.*?)\n---\n(.*)", raw(name), re.S)
    assert m, name
    return yaml.safe_load(m.group(1)), m.group(2)


def section(name: str, rubric: str) -> str:
    body = parts(name)[1]
    m = re.search(rf"^## {re.escape(rubric)}\n(.*?)(?=^## |\Z)", body, re.S | re.M)
    assert m, (name, rubric)
    return m.group(1)


def flat(text: str) -> str:
    return " ".join(text.split())


def requires_scanners(name: str) -> bool:
    return parts(name)[0].get("requires") == "scanners"


# ------------------------------------------------------------------ D18: one skill per card, its form
def test_one_skill_per_card_and_only_our_folders_here():
    cards = {p.stem for p in CARDS.glob("*.md")}
    assert len(cards) == 24  # msrc-outlook has no card at this commit (said in the report)
    present = {p.parent.name for p in SKILLS.glob("*/SKILL.md")}
    assert cards <= present
    assert set(OURS) <= present and not (present - set(OURS) - LOT_H)
    for name in OURS:
        assert parts(name)[0]["name"] == name


@pytest.mark.parametrize("name", OURS)
def test_frontmatter_and_rubrics(name):
    meta, body = parts(name)
    assert set(meta) <= {"name", "description", "requires"}, meta
    desc = meta["description"]
    assert isinstance(desc, str) and desc.startswith("Use when") and len(desc) <= classes.DESCRIPTION_MAX, desc
    assert meta.get("requires") in (None, *classes.SKILL_REQUIRES)
    lines = body.rstrip("\n").splitlines()
    assert len(lines) <= 150, len(lines)
    assert lines[0].startswith("<!--"), "the origin comment sits under the frontmatter"
    assert re.findall(r"^## (.+)$", body, re.M) == RUBRICS
    for rubric in RUBRICS:
        assert section(name, rubric).strip(), rubric
    assert re.search(r"^\d+\. ", section(name, "Do"), re.M), "Do has numbered steps"


def test_all_skills_lists_ours_with_their_requirement():
    by_name = {s["name"]: s for s in classes.all_skills()}
    assert set(OURS) <= set(by_name)
    assert by_name["scanner-playbook"]["requires"] == "scanners"
    assert all(by_name[n]["requires"] is None for n in OURS if n != "scanner-playbook")


# ------------------------------------------------------------------ D18: every command exists
def _main_commands() -> set[str]:
    main = (AGENT / "main.py").read_text()
    return set(re.findall(r'"([a-z-]+)"', main))


@pytest.mark.parametrize("name", OURS)
def test_every_command_named_exists(name):
    text, known = raw(name), _main_commands()
    skills = {p.parent.name for p in SKILLS.glob("*/SKILL.md")} | LOT_H
    tokens = set(re.findall(r"(?<![\w./-])(bh-[a-z0-9-]+)", text)) - skills - {"bh-lock"}
    assert tokens, "a skill names at least one command"
    for cmd in tokens:
        assert cmd.removeprefix("bh-") in known, cmd
    for cmd in set(re.findall(r"`(qq?) ", text)):
        assert cmd in known, cmd
    note, web = (AGENT / "note.py").read_text(), (AGENT / "web.py").read_text()
    subs = set(re.findall(r'add_parser\(\s*"([a-z-]+)"', note))
    for sub in re.findall(r"`bh-note ([a-z-]+)", text):
        assert sub in subs, f"bh-note {sub}"
    for reasons in re.findall(r"bh-note blocked ([a-z|-]+)", text):
        for reason in reasons.split("|"):
            assert reason in contract.BLOCKER_REASONS, reason
    for sub in re.findall(r"`bh-web ([a-z-]+)", text):
        assert f'"{sub}"' in web, f"bh-web {sub}"


# ------------------------------------------------------------------ I8: no scanner outside scanner skills
@pytest.mark.parametrize("name", OURS)
def test_scanner_names_only_in_skills_that_require_scanners(name):
    named = classes.SCANNER_WORDS.search(raw(name))
    if requires_scanners(name):
        assert named, "requires: scanners on a skill that names none"
    else:
        assert not named, named.group()


def test_scanner_playbook_holds_the_scan_lines_and_the_hidden_parameters():
    text = raw("scanner-playbook")
    for cid in ("sqli", "xss", "info-disclosure"):
        assert flat(classes.BY_ID[cid].scan) in flat(text), cid
    assert "--write-own" in text
    for p in ("debug", "test", "admin", "redirect", "callback", "fields", "expand", "include", "sort", "order"):
        assert f"`{p}`" in section("scanner-playbook", "Do"), p


DISCARDED = ("seq 1 ", "ffuf", "gopher", "DROP TABLE", ".htaccess", "sqlmap --os", "xp_cmdshell")
PURGED = (
    r"never stop",
    r"try \d+ more",
    r"rockyou",
    r"default (credentials|passwords)",
    r"password list",
    r"X-Forwarded-For",
    r"rotat(e|ing|ion)",
    r"(waf|rate[- ]limit)s? (bypass|evasion)",
    r"(bypass|evade|evasion of) (the |a )?(waf|rate[- ]limit)",
    r"[$€£]\s?\d",
    r"\bbount(y|ies) of\b",
)


@pytest.mark.parametrize("name", OURS)
def test_nothing_discarded_or_purged_comes_back(name):
    text = raw(name)
    if not requires_scanners(name):
        for pattern in DISCARDED:
            assert pattern.lower() not in text.lower(), pattern
    for rx in PURGED:
        assert not re.search(rx, text, re.I), rx


# ------------------------------------------------------------------ cross-references
_REF = re.compile(r"\b(?:skill|card)s?\s+((?:`[a-z0-9-]+`(?:,\s*|\s+and\s+(?:the\s+skill\s+)?|\s+or\s+)?)+)")
_BARE = re.compile(r"\bcard\s+([a-z0-9]+(?:-[a-z0-9]+)+)\b")


@pytest.mark.parametrize("name", OURS)
def test_every_reference_names_an_existing_skill(name):
    text = raw(name)
    refs = {r for m in _REF.finditer(text) for r in re.findall(r"`([a-z0-9-]+)`", m.group(1))}
    refs |= set(_BARE.findall(text))
    for ref in refs:
        assert ref in OURS or ref in LOT_H, ref


# ------------------------------------------------------------------ D18: program and Copilot cards word for word
_LABEL = re.compile(r"^(When|Never|Do|Watch|Proof):(?: |$)")


@pytest.mark.parametrize("name", PROGRAM_CARDS)
def test_program_cards_are_kept_word_for_word(name):
    card = (CARDS / f"{name}.md").read_text().rstrip("\n").splitlines()
    skill, do = raw(name), section(name, "Do")
    assert card[0].removeprefix("## ") in skill
    for line in card[1:]:
        text = _LABEL.sub("", line)
        if text.strip():  # a label turned into a rubric: its first word may start with a capital now
            assert text in skill or text[:1].upper() + text[1:] in skill, line
    start = card.index("Do:")
    for line in card[start + 1 :]:
        if line[:1].isalpha():
            break
        assert line in do, line


# ------------------------------------------------------------------ S3: the lines of FUSIONS.md, in their rubric
FUSIONS = {
    "idor": [
        ("Do", "an array form (`id[]=<a>&id[]=<b>`, `id=<a>,<b>`)"),
        ("Do", "a sibling parameter name (`userId`, `user[id]`, `uid`,"),
        ("Do", "an identity header the server may read (`X-User-ID`)"),
        ("Do", "A collection that answers 403 says nothing about its items"),
        ("Do", "a GET that is refused may be accepted as POST, PUT or PATCH (on our own objects only)"),
        ("Watch", "Encoded ids (Base64: decode, change, re-encode; the `sub` of a JWT)"),
        ("Watch", "returns the encrypted form of any value you submit is an oracle"),
        ("Watch", "A different Content-Length between your object and the other's is the first signal"),
    ],
    "auth": [
        ("Do", "try your own token re-signed as HS256 with that key; check that `kid` and `jku` are not taken"),
        ("Do", "try a token without `exp`"),
        ("Do", "Does the session id change at login (fixation)? Is a session of one application accepted by a sibling"),
        ("Do", "call an authenticated API route right after the password step, without the code"),
        ("Do", "a login path (OAuth, SSO) that never asks for the code; does a password reset switch 2FA off?"),
        ("Do", "an empty or `null` token; another method or content type"),
        ("Do", "A reset link built from `X-Forwarded-Host` only shows in the mail: `bh-note blocked other"),
        ("Do", "Type changes on the e-mail field: skill `type-confusion`"),
        ("Never", "Loop over codes or tokens, even to show that no limit exists."),
    ],
    "sqli": [
        ("Watch", "Second order: a value stored now and used in a query later (a profile field read by a report)"),
        ("Watch", "Document databases and directory filters: skill `nosql-injection`."),
    ],
    "xss": [
        ("Watch", '`<script type="application/json">`: `</script>` ends the block whatever the JSON quoting'),
        ("Watch", "A filter applied before a charset conversion: a character the conversion turns into `<` passes"),
        ("Watch", "Only style can be injected: an attribute selector with a background URL reads a value of the page"),
    ],
    "ssrf": [
        ("When", "Less obvious sinks: PDF or screenshot generators (an image or frame in the HTML they render)"),
        ("When", 'media importers that follow playlists, webhooks, "import from URL"'),
    ],
    "open-redirect": [
        ("When", "Also `goto`, `continue`, `target`, `redir`, `rurl`, `callback`, and the redirect field of a login"),
        ("Do", "`https://<in-scope host>@<payload-host>`, a backslash form, a full-width colon"),
        ("Do", "CRLF in the parameter (`%0d%0aX-Bhx: 1`): a new header in the answer is header injection"),
        ("Watch", "A redirect never carries the session cookie to the other site"),
    ],
    "file-upload": [
        ("Do", "Extension handling with a harmless text file: a double extension, mixed case, a trailing `;`"),
        ("Do", "a field holding `=1+1` that comes back at the start of a CSV cell; many programs exclude it"),
        ("Do", "XML inside (SVG, DOCX, XLSX): skill `xxe`."),
    ],
    "graphql": [
        ("Do", "Introspection may be refused on POST and answered on GET (`?query={__typename}`)"),
        ("Do", "Refused everywhere: skill `graphql-schema-from-errors`."),
        ("Do", "Arguments named `filter`, `where`, `order` reach a query: test them with the skill `sqli`"),
    ],
    "business-logic": [
        ("Do", "Walk every screen of the flow once"),
        ("Do", "(`bh-web net`, or `bh-browse --routes`): the list of calls is the map"),
        ("Do", "a negative amount on a coupon or tip; a list of coupons; `payment_method: null`"),
        ("Do", "cancel then reactivate without paying"),
        ("Do", "a feature flag in a parameter or cookie; the last step called directly"),
        ("Do", "Check the total the server returns, not the parameter you sent. A 204 is not a success"),
        ("Do", "The whole flow without a session: if the first step answers anonymously, try each next step once."),
        ("Never", "Replay an action many times (votes, redemptions): two requests show it."),
    ],
    "info-disclosure": [
        ("When", "Database side files (`.db-wal`, `.db-journal`), source maps (check they are JSON)."),
        ("Do", "Check the content, not the status: a 200 HTML page of the same size on every path is the app shell"),
        ("Do", "Where versions leak: response headers, error pages, status or health routes, bundle comments."),
        ("Do", "A version and a CVE make a lead only when the exact version is in the advisory's range."),
        ("Watch", "Publishable keys are public by design: the finding is what the key gives access to."),
    ],
    "path-traversal": [
        ("Do", "the Windows form (`..\\..\\windows\\win.ini`)"),
        ("Do", "(`php://filter/convert.base64-encode/resource=<page>`): one file."),
        ("Never", "Wrappers or log files that lead to code running on the server: stop, `bh-note blocked server-exec"),
    ],
    "cors": [
        ("Do", "the preflight of a non-simple request is accepted (send the OPTIONS)"),
        ("Do", "the session cookie is `SameSite=None`. An API that takes only an `Authorization` header cannot be"),
        ("Do", "One condition missing: record a fact, not a finding"),
        ("Do", "JSONP: an authenticated endpoint that wraps the identity's data in a callback (`?callback=bhx12345`)"),
    ],
    "broken-access-control": [
        ("Do", "The same route under a sibling API version (`/v0/`, `/v1-beta/`) or another method may skip the role"),
        ("Watch", "A 403 from the edge (WAF, CDN) is not the application's answer; a 200 that is the app shell is not"),
        ("Watch", "Order of checks 401, then 400, then 403: a 400 before the 403 is weak ordering, not a bypass."),
    ],
    # Copilot and AI cards: Watch only
    "prompt-injection": [("Watch", "Delivery variants worth one of the 5 slots: text hidden with Unicode variation")],
    "ai-output-rendering": [("Watch", "a CSS URL toward `<marker>.<payload-host>` is one more context")],
    "ai-file-upload": [("Watch", "SVG is XML: if the file is fetched and parsed server-side, the skill `xxe` applies")],
    "ai-connectors": [("Watch", "an assistant with tools is also a request sender")],
    "copilot-share": [("Watch", "read the cache headers before concluding on revocation (skill `web-cache` for the")],
    "msrc-copilot": [("Watch", "Surface 8 (classic web): its class skills also count the skill `csrf` and the skill")],
}


@pytest.mark.parametrize("name", sorted(FUSIONS))
def test_fusion_lines_sit_in_their_rubric(name):
    for rubric, phrase in FUSIONS[name]:
        assert flat(phrase).lower() in flat(section(name, rubric)).lower(), (rubric, phrase)


def test_class_skills_carry_their_proof_standard_and_twin_control():
    for name in CLASS_CARDS:
        proof = flat(section(name, "Proof"))
        assert "proof.json" in proof and "control" in proof, name
        assert f"--class {name}" in proof or name == "idor", name


# ------------------------------------------------------------------ W1 acquis kept by the skills
def test_ssrf_skill_never_aims_at_an_internal_address():
    text, never = raw("ssrf"), section("ssrf", "Never")
    for bad in ("127.0.0.1", "169.254", "127.1", "[::1]", "0x7f", "2130706433", "localhost"):
        assert bad not in text, bad
    for line in text.splitlines():
        if re.search(r"metadata|decimal|hex\b", line, re.I) and not line.startswith("<!--"):
            assert line in never, line
    assert "loopback, link-local, cloud metadata or internal" in text
    assert "lead for the human" not in text
    for part in ("request received on a host of ours", 'bh-note blocked oob-needed "', "in-scope page"):
        assert part in flat(text), part


@pytest.mark.parametrize("name", OURS)
def test_payload_host_token_and_free_roles(name):
    text = raw(name)
    assert "example.org" not in text and "example.com" not in text
    if "<payload-host>" in text:
        assert flat(text).count(PAYLOAD_SAID) == 1
    assert "--victim user-b --attacker user-a" not in text and "--victim <B> --attacker <A>" not in text


def test_out_of_scope_hosts_and_program_phrases_stay():
    prog, share, conn = flat(raw("msrc-copilot")), flat(raw("copilot-share")), flat(raw("ai-connectors"))
    assert "never request them, `bh-note blocked other" in prog and "Notebooks (Loop) routes" in prog
    assert "request the share page host `copilot.cloud.microsoft` (not in the scope" in share
    assert "Google" in conn and "Notion" in conn and "Outlook" not in conn
    manual = flat(raw("bh-web-manual"))
    for part in ("human_watching", "`service daily limit`", "`--body <i>`", "`--clipboard`", "fills.segment_left"):
        assert part in manual, part


# ------------------------------------------------------------------ T35 (part): narrow before widening
@pytest.mark.parametrize("name", ["sqli", "xss", "ssrf", "path-traversal"])
def test_narrowing_line_in_watch(name):
    watch = flat(section(name, "Watch"))
    assert "An abnormal answer: first one variant that keeps the syntax" in watch
    assert "then two close witnesses at most" in watch and "before you widen anything" in watch
    assert not re.search(r"command injection|; ?id\b|\$\(|`id`|\|\| ?sleep", raw(name), re.I)


# ------------------------------------------------------------------ L2: report-writing
def test_report_writing_merges_both_origins():
    text = raw("report-writing")
    head = parts("report-writing")[1].split("-->")[0]
    for origin in ("skills-audit/skills/report-writing/SKILL.md", "counterevidence.md", "severity_calibration.md"):
        assert origin in head, origin
    assert "Apache-2.0" in head and "MIT" in head and "Modified:" in head
    f = flat(text)
    for part in (
        "Decide first",
        "No consequence for a user or the company = not a finding",
        "Title: the defect and the place",
        "Impact is what you observed, in the past tense",
        "Three readers",
        "best case against your own finding",
        "--severity-if",
        "open_proof_gap",
        "Downgrade, never delete",
        "These do not pay",
    ):
        assert part in f, part
    never = section("report-writing", "Never")
    assert "Dress the text to look human-written" in never
    for line in text.splitlines():
        if re.search(r"human-written|sound human|look human", line, re.I):
            assert line in never, line
    assert "MSRC" not in text and "Important =" not in text  # a program's bar stays in its skill


def test_chaining_skill():
    text = flat(raw("chaining"))
    for part in ("Pairs that pay", "One proof.json for the chain", "Claim past the last link you ran",
                 "Add severities together"):  # fmt: skip
        assert part in text, part


# ------------------------------------------------------------------ D21: GraphQL from Strix, purged
def test_graphql_takes_strix_without_what_we_refuse():
    text = raw("graphql")
    head = parts("graphql")[1].split("-->")[0]
    assert "strix/skills/protocols/graphql.md" in head and "Apache-2.0" in head and "Modified:" in head
    assert "skill `graphql-schema-from-errors`" in text
    for part in ("_entities", "_service { sdl }", "@defer", "node(id:)", "Relay"):
        assert part in text, part
    for bad in ("u1:user", "fragment x on User", "WAF Evasion", "Hash bruteforce", "HTTP/2 multiplexing",
                "homoglyph", "Batching to bypass"):  # fmt: skip
        assert bad.lower() not in text.lower(), bad
