"""W2-H: MSRC scope, step 1 (D30, D31, S8, D40, common guards).

No network, no socket: the gate's policy and a simulated mitmproxy (test_gate_browser_canary), the rules pages through
an injected `fetch`. Addresses are made up (`*.test`), never an account of ours."""

import gzip
import json
import re
from pathlib import Path
from typing import ClassVar

import pytest
import yaml

from bh import paths, rules
from bh.accounts import secrets
from bh.gate import policy as pol
from bh.gate import recipients
from bh.scope import ScopeError, load_scope, scope_from_dict
from bh.scope import extra as scope_extra
from bh.scope import guards
import test_gate_browser_canary as gbc
from test_gate_browser_canary import AGENT_IP, BROWSER_IP, JUDGE_IP, _events, _gate, _http, _load_browser, run

addon = gbc.addon

ROOT = Path(__file__).resolve().parents[1]
MSRC = ROOT / "scopes" / "msrc"
SURVEY = ROOT / "docs" / "research" / "21-releve-hotes-outlook-onedrive.md"
CARDS = ROOT / "src" / "bh" / "cards"
A, B, EVIL = "user-a@ours.test", "user-b@ours.test", "someone@elsewhere.test"
SEND = "https://mail.example.com/api/send"
LINK = "https://mail.example.com/api/createLink"
DOC = {
    "schema": 1,
    "program": "t",
    "platform": "test",
    "in_scope": ["mail.example.com", "app.example.com", "api.example.com"],
    "max_rps": 1000,
    "identities": [{"name": "user-a", "origins": ["https://app.example.com/"]}, {"name": "user-b"}],
    "recipient_guard": [{"url": r"^https://mail\.example\.com/api/send", "note": "send a mail"}],
    "payload_hosts": ["example.org"],
}


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    recipients._CACHE.clear()
    return tmp_path


def _secrets(program="t"):
    secrets.save(program, "user-a", {"email": A.upper(), "password": "pw-a"})  # case is not identity
    secrets.save(program, "user-b", {"email": B, "password": "pw-b"})


def _policy(home, doc=None, *, allowlist=True):
    state = paths.state()
    state.mkdir(parents=True, exist_ok=True)
    f = state / paths.ACTIVE_SCOPE
    f.write_text(yaml.safe_dump(doc or DOC))
    p = pol.Policy(f)
    p.reload()
    assert p.scope is not None, p.scope_error
    if allowlist:
        _secrets(p.scope.program)
        assert recipients.write_allowlist(p.scope) == state / recipients.FILE
    return p


def _send(p, url=SEND, body=b"", ctype="application/json", **kw):
    return p.classify_request(url, url.split("/")[2], "POST", body=body, body_len=len(body), content_type=ctype, **kw)


def _json(*to, bcc=()):
    return json.dumps(
        {
            "message": {
                "subject": "test",
                "toRecipients": [{"emailAddress": {"address": a}} for a in to],
                "bccRecipients": [{"emailAddress": {"address": a}} for a in bcc],
            }
        }
    ).encode()


def _multipart(fields: dict[str, str], boundary="b0undary") -> tuple[bytes, str]:
    parts = [
        f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode() for k, v in fields.items()
    ]
    return b"".join(parts) + f"--{boundary}--\r\n".encode(), f"multipart/form-data; boundary={boundary}"


# ------------------------------------------------------------------ D31: the scope key
def test_recipient_guard_and_rules_url_are_validated():
    s = scope_from_dict(DOC)
    assert s.recipient_guard[0].url.startswith("^https://mail") and s.recipient_guard[0].note == "send a mail"
    assert scope_from_dict({k: v for k, v in DOC.items() if k != "recipient_guard"}).recipient_guard is None
    assert scope_from_dict({**DOC, "recipient_guard": []}).recipient_guard == ()
    for bad in ([{"url": "(unclosed"}], [{"url": ""}], ["/send"], [{"url": "/send", "to": "x"}], "/send"):
        with pytest.raises(ScopeError, match="recipient_guard"):
            scope_from_dict({**DOC, "recipient_guard": bad})
    ok = scope_from_dict({**DOC, "rules_url": ["https://www.example.net/rules", "https://www.example.net/rules"]})
    assert ok.rules_url == ("https://www.example.net/rules",)
    for bad in (["http://x.example.net/"], ["https://user@x.example.net/"], ["https://*.example.net/"], "https://x/"):
        with pytest.raises(ScopeError, match="rules_url"):
            scope_from_dict({**DOC, "rules_url": bad})


# ------------------------------------------------------------------ D31: the allowlist
def test_allowlist_holds_digests_only_and_is_rewritten_atomically(home):
    _secrets()
    s = scope_from_dict(DOC)
    f = recipients.write_allowlist(s)
    doc = json.loads(f.read_text())
    assert doc["program"] == "t" and set(doc) == {"program", "sha256", "ts"}
    assert sorted(doc["sha256"]) == sorted(recipients.digest(a) for a in (A, B))
    assert "ours.test" not in f.read_text() and oct(f.stat().st_mode & 0o777) == "0o644"
    assert not list(f.parent.glob(".*.tmp"))
    assert recipients.allowed("t", B) and recipients.allowed("t", A.title())
    assert not recipients.allowed("t", EVIL) and not recipients.allowed("other", B)
    secrets.save("t", "user-b", {"email": "new-b@ours.test", "password": "x"})
    recipients.write_allowlist(s)  # reread when it changes
    assert recipients.allowed("t", "new-b@ours.test") and not recipients.allowed("t", B)


def test_no_address_no_list_and_a_broken_list_allows_nothing(home):
    s = scope_from_dict(DOC)
    assert recipients.write_allowlist(s) is None and not recipients.path().exists()
    assert not recipients.allowed("t", A)
    recipients.path().parent.mkdir(parents=True)
    recipients.path().write_text("{not json")
    assert not recipients.allowed("t", A)
    recipients.path().write_text(json.dumps({"program": "t", "sha256": ["short"]}))
    assert not recipients.allowed("t", A)


# ------------------------------------------------------------------ D31: the gate's decision
def test_a_send_to_the_other_account_passes_and_is_marked(home):
    p = _policy(home)
    v = _send(p, body=_json(B))
    assert v.allowed and v.recipients
    assert _send(p, body=_json(A, B)).allowed


@pytest.mark.parametrize(
    "body",
    [
        _json(EVIL),
        _json(B, bcc=[EVIL]),  # a third party in Bcc among ours
        _json(A, B, bcc=[B, EVIL.upper()]),
        b'{"to": "user-b@ours.test", "bcc": "someone\\u0040elsewhere.test"}',  # a JSON escape
        json.dumps({"to": [B, "someone%40elsewhere.test"]}).encode(),  # %-encoded
        json.dumps({"to": B, "html": "someone&#64;elsewhere.test"}).encode(),  # an HTML entity
    ],
)
def test_a_third_party_anywhere_in_a_json_body_is_refused(home, body):
    v = _send(_policy(home), body=body)
    assert not v.allowed and v.reason == "recipient not ours"
    assert "elsewhere" not in (v.rule or "") and "ours.test" not in (v.rule or "")


def test_form_bodies(home):
    p = _policy(home)
    form = "application/x-www-form-urlencoded"
    assert _send(p, body=f"to={B.replace('@', '%40')}&subject=hi".encode(), ctype=form).allowed
    for body in (f"to={B}&bcc={EVIL}", f"to={B}%2C{EVIL.replace('@', '%40')}", f"to={B}&cc=someone%2540elsewhere.test"):
        v = _send(p, body=body.encode(), ctype=form)
        assert not v.allowed and v.reason == "recipient not ours", body


def test_multipart_bodies(home):
    p = _policy(home)
    body, ctype = _multipart({"to": B, "subject": "hi"})
    assert _send(p, body=body, ctype=ctype).allowed
    body, ctype = _multipart({"to": B, "bcc": EVIL})
    assert not _send(p, body=body, ctype=ctype).allowed
    # a base64 part is decoded before it is read
    import base64

    hidden = base64.b64encode(EVIL.encode()).decode()
    body = (
        '--bb\r\nContent-Disposition: form-data; name="to"\r\n\r\n' + B + "\r\n"
        '--bb\r\nContent-Disposition: form-data; name="cc"\r\nContent-Transfer-Encoding: base64\r\n\r\n'
        + hidden
        + "\r\n--bb--\r\n"
    ).encode()
    assert not _send(p, body=body, ctype="multipart/form-data; boundary=bb").allowed
    body, _ = _multipart({"to": B})
    assert not _send(p, body=body, ctype="multipart/form-data").allowed  # no boundary: unreadable


def test_the_url_counts_and_a_get_is_judged_too(home):
    p = _policy(home)
    assert p.classify_request(f"{SEND}?to={B}", "mail.example.com", "GET").allowed
    v = p.classify_request(f"{SEND}?to={B}&cc={EVIL.replace('@', '%40')}", "mail.example.com", "GET")
    assert not v.allowed and v.reason == "recipient not ours"
    assert not p.classify_request(SEND, "mail.example.com", "GET").allowed  # no address at all
    assert not p.classify_request("https://mail.example.com/API/%73end", "mail.example.com", "GET").allowed


@pytest.mark.parametrize(
    "case",
    [
        "no address",
        "compressed",
        "over the bound",
        "not utf-8",
        "broken json",
        "no body to read",
        "no list",
        "other list",
    ],
)
def test_fail_closed(home, case):
    p = _policy(home, allowlist=case not in ("no list", "other list"))
    body, kw = _json(B), {}
    if case == "no address":
        body = json.dumps({"to": [{"id": "AAMk-recipient-by-id"}]}).encode()
    elif case == "compressed":
        body, kw = gzip.compress(_json(B)), {"content_encoding": "gzip"}
    elif case == "over the bound":
        body = _json(B) + b" " * recipients.READ_MAX
    elif case == "not utf-8":
        body = _json(B) + b"\xff\xfe"
    elif case == "broken json":
        body = _json(B)[:-3]
    elif case == "other list":
        _secrets("other")
        recipients.write_allowlist(scope_from_dict({**DOC, "program": "other"}))
    if case == "no body to read":
        v = p.classify_request(SEND, "mail.example.com", "POST", body=None, body_len=40)
    else:
        v = _send(p, body=body, **kw)
    assert not v.allowed and v.reason == "recipient not ours", (case, v)


def test_a_link_route_names_nobody_and_passes(home):
    p = _policy(home)
    v = _send(p, url=LINK, body=b'{"type": "view", "scope": "anonymous"}')
    assert v.allowed and not v.recipients
    assert _send(p, url=LINK, body=_json(EVIL)).allowed  # not a send route: the guard does not read it


def test_the_guard_holds_off_target_and_for_a_scope_without_the_key(home):
    doc = {**DOC, "recipient_guard": [{"url": r"^https://example\.org/send"}]}
    p = _policy(home, doc)
    v = p.classify_request("https://example.org/send?to=" + EVIL, "example.org", "GET")
    assert not v.allowed and v.reason == "recipient not ours"  # a payload host, judged by the guard first
    p = _policy(home, {k: v for k, v in DOC.items() if k != "recipient_guard"})
    assert _send(p, body=_json(EVIL)).allowed  # no key, no guard (bh.scope.guards wants it on MSRC)


def test_every_client_is_refused_and_the_journal_keeps_no_address(addon, home, tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "state", lambda: tmp_path)
    g = _gate(addon, tmp_path, DOC)
    _secrets()
    recipients.write_allowlist(g.policy.scope)
    _load_browser(tmp_path)
    hdr = [("content-type", "application/json")]
    for i, peer in enumerate((AGENT_IP, JUDGE_IP, BROWSER_IP)):
        f = run(g, _http(f"{SEND}?cc={EVIL}", "POST", headers=hdr, body=_json(B, bcc=[EVIL]), peer=peer, fid=f"r{i}"))
        assert f.metadata.get("bh_denied"), peer
    blocked = _events(tmp_path, "blocked")
    assert [e["reason"] for e in blocked] == ["recipient not ours"] * 3
    assert [e["client"] for e in blocked] == ["agent", "judge", "browser"]
    assert recipients.short(EVIL) in blocked[0]["rule"]
    f = run(g, _http(SEND, "POST", headers=hdr, body=_json(B), peer=AGENT_IP, fid="ok"))
    assert not f.metadata.get("bh_denied") and f.metadata["bh_recipients"]
    gbc._answer(f, 202, body=b"{}")
    g.response(f)
    for p in tmp_path.rglob("*"):
        if p.is_file() and "secrets" not in p.parts and p.name != recipients.FILE:
            text = p.read_text(errors="replace")
            for a in (EVIL, B, A, "elsewhere.test", "%40elsewhere", "ours.test"):
                assert a.lower() not in text.lower(), (p, a)


def test_scrub_hides_raw_and_encoded_addresses():
    for text in (EVIL, "someone%40elsewhere.test", "someone%2540elsewhere.test", "someone&#64;elsewhere.test"):
        out = recipients.scrub(f"https://x.test/send?to={text}&n=1")
        assert "elsewhere" not in out and "<address:" in out and out.endswith("&n=1"), out


# ------------------------------------------------------------------ D40: approved prefixes
def test_an_approved_prefix_opens_that_prefix_only_and_a_revoked_one_closes(home):
    p = _policy(home, allowlist=False)
    state = p.state_dir
    url = "https://files.example.com/v1/items/"
    assert not p.classify_request(url + "1", "files.example.com", "GET").allowed
    scope_extra.approve("t", url, "requested run 7, approved by judge, 2026-11-26", state=state)
    v = p.classify_request(url + "1", "files.example.com", "GET")
    assert v.allowed and v.klass == "target"
    assert not p.classify_request("https://files.example.com/v1/other", "files.example.com", "GET").allowed
    assert not p.classify_request("https://evil.files.example.com/v1/items/1", "evil.files.example.com", "GET").allowed
    assert scope_extra.revoke("t", url, state=state)
    assert not p.classify_request(url + "1", "files.example.com", "GET").allowed
    assert not scope_extra.revoke("t", url, state=state)


def test_a_corrupt_or_forbidden_entry_is_ignored_and_journaled(home):
    events = []
    p = _policy(home, {**DOC, "support": [{"value": "login.example.net", "kind": "sso"}]}, allowlist=False)
    p.on_event = events.append
    f = scope_extra.path("t", p.state_dir)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("in_scope: [ {value: broken")
    assert not p.classify_request("https://files.example.com/x", "files.example.com", "GET").allowed
    assert events and events[-1]["kind"] == "scope-extra-error" and "invalid YAML" in events[-1]["error"]
    assert p.scope is not None  # the scope itself stands
    f.write_text(
        yaml.safe_dump(
            {
                "program": "t",
                "in_scope": [
                    {"value": "https://*.example.com/", "note": "wildcard"},
                    {"value": "https://login.example.net/x/", "note": "support"},
                    {"value": "https://admin.example.com/", "note": "admin"},
                    {"value": "https://example.org/", "note": "payload"},
                    {"value": "https://files.example.com/a?b=1", "note": "query"},
                    {"value": "http://files.example.com/", "note": "clear"},
                    {"value": "https://files.example.com/ok/", "note": "fine"},
                ],
            }
        )
    )
    p.classify_request("https://app.example.com/", "app.example.com", "GET")
    errors = [e["error"] for e in events if e["kind"] == "scope-extra-error"]
    assert len(errors) == 1 + 6
    assert [r.value for r in p.scope.in_scope][-1] == "https://files.example.com/ok/"
    assert not p.classify_request("https://admin.example.com/", "admin.example.com", "GET").allowed
    f.write_text(yaml.safe_dump({"program": "another", "in_scope": [{"value": "https://files.example.com/ok/"}]}))
    assert not p.classify_request("https://files.example.com/ok/1", "files.example.com", "GET").allowed


# ------------------------------------------------------------------ common guards
def test_every_msrc_scope_file_passes_the_guards():
    files = sorted(MSRC.glob("*.yaml"))
    assert {f.name for f in files} >= {"copilot.yaml", "onedrive.yaml"}
    for f in files:
        s = load_scope(f)
        assert s.platform == "msrc", f
        assert guards.check(s) == [], (f.name, guards.check(s))


def test_the_guards_catch_each_breach():
    base = load_scope(MSRC / "onedrive.yaml")
    doc = yaml.safe_load((MSRC / "onedrive.yaml").read_text())
    assert guards.check(base) == []
    breaches = {
        "a wildcard target": {"in_scope": [*doc["in_scope"], "*.onedrive.com"]},
        "wildcard target under live.com": {"in_scope": [*doc["in_scope"], "https://*.live.com/x/"]},
        "administration host": {"in_scope": [*doc["in_scope"], "admin.microsoft.com"]},
        "wildcard support host": {"support": [{"value": "*.example.net", "kind": "assets"}]},
        "under office.net": {"support": [{"value": "*.cdn.office.net", "kind": "assets"}]},
        "auth wildcard": {"support": [{"value": "*.example.net", "kind": "auth"}]},
        "scanners_allowed": {"scanners_allowed": None},
        "max_rps": {"max_rps": 5},
        "dos": {"forbidden_vulns": []},
        "payload_hosts": {"payload_hosts": []},
        "rules_url must": {"rules_url": []},
        "recipient_guard must": {"recipient_guard": ...},
    }
    for word, change in breaches.items():
        d = {**doc, **change}
        d = {k: v for k, v in d.items() if v is not ...}
        problems = guards.check(scope_from_dict(d))
        assert problems and any(word.split()[-1] in p for p in problems), (word, problems)
    assert guards.check(scope_from_dict({**doc, "platform": "yeswehack", "max_rps": 9})) == []


# ------------------------------------------------------------------ D30: the scope files
def _survey() -> str:
    return SURVEY.read_text()


def test_onedrive_hosts_come_from_the_survey_with_its_date():
    s = load_scope(MSRC / "onedrive.yaml")
    survey = _survey()
    assert s.program == "msrc-onedrive" and s.platform == "msrc" and s.scanners_allowed is False
    assert [i["name"] for i in s.identities] == ["user-a", "user-b"]
    for rule in s.in_scope:
        assert rule.host in survey, rule.value
        assert "2026-11-26" in rule.note, rule.value
        assert "*" not in rule.value
    assert s.support == () and s.websockets_on is False
    assert s.cards == ("msrc-onedrive", "bh-web-manual")
    assert s.protected_urls == ()  # the gate's defaults (W1) apply as they are
    # no address of ours in a scope file
    for f in MSRC.glob("*.yaml"):
        assert not re.search(r"[\w.-]+@[\w-]+\.[a-z]{2,}", f.read_text()), f


def test_no_outlook_scope_without_its_survey():
    assert "Outlook.com (non relevé)" in _survey()
    assert not (MSRC / "outlook.yaml").exists()


def test_link_routes_are_not_guarded_and_invites_are(home):
    p = _policy(home, yaml.safe_load((MSRC / "onedrive.yaml").read_text()), allowlist=False)
    upload = "https://graph.microsoft.com/v1.0/me/drive/special/copilotuploads:/f.txt:/createUploadSession"
    v = p.classify_request(upload, "graph.microsoft.com", "POST", body=b"{}", body_len=2, identity="user-a")
    assert v.allowed and not v.recipients  # a `link` route of the survey: nobody named
    invite = "https://api.onedrive.com/v2.1/drives/abc/items/def/action.invite"
    body = json.dumps({"recipients": [{"email": EVIL}]}).encode()
    v = p.classify_request(
        invite, "api.onedrive.com", "POST", body=body, body_len=len(body), content_type="application/json"
    )
    assert not v.allowed and v.reason == "recipient not ours"


def test_copilot_scope_gains_its_rule_pages_only():
    s = load_scope(MSRC / "copilot.yaml")
    assert s.rules_url and all(u.startswith("https://www.microsoft.com/en-us/msrc/") for u in s.rules_url)
    assert s.recipient_guard == ()
    assert s.cards == ("msrc-copilot", "bh-web-manual")
    assert not any("onedrive" in c or "outlook" in c for c in s.cards)


# ------------------------------------------------------------------ D30: the program card
def _card() -> str:
    return (CARDS / "msrc-onedrive.md").read_text()


def test_the_onedrive_card_shape_and_doctrine():
    text = _card()
    assert len(text.strip().splitlines()) <= 50
    for head in ("When:", "Never:", "Do:", "Watch:", "Proof:", "Next:"):
        assert re.search(rf"^{head}", text, re.M), head
    flat = " ".join(text.split())
    assert "copilot" not in flat.lower() and "outlook" not in flat.lower()
    assert "`recipient not ours`" in flat and "address that is not the other account's" in flat
    assert "--victim <identity> --attacker <the other>" in flat
    assert "--victim user-b --attacker user-a" not in flat
    rows = [line for line in text.splitlines() if re.match(r"\s*\| \d+ \|", line)]
    assert len(rows) == 6 and "drive or file" in rows[0] and "Classic web" in rows[-1]


def test_every_command_of_the_card_exists():
    main = (ROOT / "src" / "bh" / "agent" / "main.py").read_text()
    known = set(re.findall(r'"([a-z-]+)"', main))
    cmds = set(re.findall(r"`(bh-[a-z-]+|qq?)\b", _card()))
    assert cmds >= {"bh-web", "bh-note", "q", "qq", "bh-crawl"}
    for cmd in cmds:
        name = cmd.removeprefix("bh-")
        assert name in known or (cmd in ("q", "qq") and '"qq"' in main), cmd


def test_every_route_and_host_of_the_card_is_in_the_survey_and_the_scope():
    text, survey = _card(), _survey()
    scope = load_scope(MSRC / "onedrive.yaml")

    def norm(s: str) -> str:
        return re.sub(r"<[^>]*>", "<>", s)

    for route in re.findall(r"`([^`]*/[^`]*)`", text):
        if route.startswith(("bh-", "q ", "qq ", "/opt/")) or " " in route:
            continue
        assert norm(route) in norm(survey), route
    for host in set(re.findall(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net))\b", text)):
        assert any(r.host == host for r in scope.in_scope), host


# ------------------------------------------------------------------ S8: rule pages
class Pages:
    def __init__(self, pages):
        self.pages, self.calls = dict(pages), []

    def __call__(self, url):
        self.calls.append(url)
        page = self.pages[url]
        if isinstance(page, Exception):
            raise page
        return page


R1, R2 = "https://www.example.net/rules", "https://www.example.net/terms"
RULED = {**DOC, "rules_url": [R1, R2]}
DAY = 86400.0
T0 = 1_790_000_000.0


@pytest.fixture
def board_kind(monkeypatch):
    from bh.board import db

    monkeypatch.setattr(db, "TODO_KINDS", db.TODO_KINDS | {rules.TODO_KIND})  # the line lot A adds


def test_rules_first_read_same_read_change_ack(home, board_kind):
    s = scope_from_dict(RULED)
    assert rules.fresh("t", T0, scope=s) == (False, rules.fresh("t", T0, scope=s)[1])
    assert "never read" in rules.fresh("t", T0, scope=s)[1]
    page = "<html><head><script>var x=1</script></head><body><p>Rule one.</p><p>Rule two.</p></body>"
    pages = Pages({R1: page, R2: "Terms."})
    out = rules.check(s, fetch=pages, now=T0)
    assert pages.calls == [R1, R2] and set(out) == {R1, R2}
    assert not out[R1]["changed"] and len(out[R1]["sha256"]) == 64
    snap = Path(out[R1]["path"])
    assert snap.parent == paths.var() / "rules" / "t" and snap.name == "2026-09-21T141320Z.txt"
    assert "Rule one.\nRule two." in snap.read_text() and "var x" not in snap.read_text()
    assert rules.fresh("t", T0 + 60, scope=s) == (True, "")
    again = rules.check(s, fetch=Pages(pages.pages), now=T0 + DAY)
    assert not again[R1]["changed"] and again[R1]["path"] == str(snap)  # same text: no new snapshot
    assert len(list(snap.parent.glob("*.txt"))) == 1
    pages.pages[R1] = "<p>Rule one.</p><p>Rule three.</p>"
    changed = rules.check(s, fetch=pages, now=T0 + 2 * DAY)
    assert changed[R1]["changed"] and not changed[R2]["changed"]
    ok, why = rules.fresh("t", T0 + 2 * DAY, scope=s)
    assert not ok and "not acknowledged" in why and R1 in why
    assert rules.diff("t") == f"=== {R1}\n-Rule two.\n+Rule three."
    from bh.board.db import Board

    todos = Board().rows("SELECT kind, status, program FROM todos")
    assert [tuple(t) for t in todos] == [("rules-changed", "open", "t")]
    rules.ack("t")
    assert rules.fresh("t", T0 + 2 * DAY, scope=s) == (True, "")
    assert [tuple(t) for t in Board().rows("SELECT status FROM todos")] == [("done",)]


def test_rules_go_stale_after_seven_days_and_a_failed_read_does_not_renew(home):
    s = scope_from_dict(RULED)
    rules.check(s, fetch=Pages({R1: "a", R2: "b"}), now=T0)
    assert rules.fresh("t", T0 + 7 * DAY - 1, scope=s)[0]
    ok, why = rules.fresh("t", T0 + 7 * DAY + 3600, scope=s)
    assert not ok and "over 7" in why
    out = rules.check(s, fetch=Pages({R1: OSError("unreachable"), R2: "b"}), now=T0 + 8 * DAY)
    assert "error" in out[R1] and not out[R1]["changed"]
    ok, why = rules.fresh("t", T0 + 8 * DAY, scope=s)
    assert not ok and R1 in why


def test_a_change_without_the_board_kind_still_stops_fresh(home):
    s = scope_from_dict(RULED)
    rules.check(s, fetch=Pages({R1: "a", R2: "b"}), now=T0)
    out = rules.check(s, fetch=Pages({R1: "a2", R2: "b"}), now=T0 + 60)
    assert out[R1]["changed"]
    assert not rules.fresh("t", T0 + 120, scope=s)[0]


def test_a_scope_without_rule_pages_is_fresh_and_reads_nothing(home):
    s = scope_from_dict(DOC)
    pages = Pages({})
    assert rules.check(s, fetch=pages) == {} and pages.calls == []
    assert rules.fresh("t", scope=s) == (True, "")
    assert rules.diff("t") == ""


def test_fresh_finds_the_scope_by_program(home):
    d = paths.scopes_dir() / "x"
    d.mkdir(parents=True)
    (d / "t.yaml").write_text(yaml.safe_dump(RULED))
    assert "never read" in rules.fresh("t")[1]
    assert rules.fresh("nobody") == (False, "no scope file for nobody")


def test_the_default_fetch_sends_no_cookie_and_no_program_header(monkeypatch):
    import urllib.request

    seen = {}

    class Resp:
        headers = type("H", (), {"get_content_charset": staticmethod(lambda: "utf-8")})()

        def read(self, n):
            return b"<p>ok</p>"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class Opener:
        addheaders: ClassVar[list] = []

        def open(self, req, timeout):
            seen["headers"] = dict(self.addheaders) | dict(req.header_items())
            seen["handlers"] = handlers
            return Resp()

    handlers = []

    def build_opener(*h):
        handlers.extend(h)
        return Opener()

    monkeypatch.setattr(urllib.request, "build_opener", build_opener)
    assert rules._fetch("https://www.example.net/rules") == "<p>ok</p>"
    assert handlers == [] and set(k.lower() for k in seen["headers"]) == {"user-agent", "accept"}
    with pytest.raises(ValueError):
        rules._fetch("http://www.example.net/rules")
