"""bh.accounts.mail: Gmail read-only mailbox, without network (the HTTP layer is a fake)."""

from __future__ import annotations

import base64
import json
import urllib.parse
from email.message import EmailMessage

import pytest

from bh.accounts import mail
from bh.cli import main

ALIAS = "tester+1@alias.example"
DOMAIN = "target.example"
SINCE = 1_764_000_000.0
SUBJECT = "Confirm-SUBJECT-MARKER"
BODY_MARK = "BODY-MARKER-xyz"


def _token_file(tmp_path, **extra):
    doc = {
        "token": "old-access",
        "refresh_token": "R-TOKEN",
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_id": "cid",
        "client_secret": "csec",
        "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
        **extra,
    }
    p = tmp_path / "google_token.json"
    p.write_text(json.dumps(doc))
    return p


def _mime(
    *,
    sender=f"no-reply@mail.{DOMAIN}",
    to=ALIAS,
    plain=None,
    html=None,
    auth: str | None = f"mx.google.com; dkim=pass header.i=@{DOMAIN}; spf=pass smtp.mailfrom=bounce.{DOMAIN}",
):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = sender, to, SUBJECT
    if auth is not None:
        m["Authentication-Results"] = auth
    m.set_content(plain if plain is not None else f"Hello {BODY_MARK}, see https://evil.example/x")
    m.add_alternative(
        html
        if html is not None
        else f'<p>{BODY_MARK}</p><a href="https://app.{DOMAIN}/confirm?t=abc&amp;u=1">go</a>'
        f' <a href="https://app.{DOMAIN}/second">2</a>',
        subtype="html",
    )
    return m.as_bytes()


class FakeHttp:
    def __init__(self, messages: dict[str, tuple[float, bytes]] | None = None, refresh=(200, None)):
        self.messages = messages or {}
        self.calls: list[tuple[str, str, dict | None, dict]] = []
        self.refresh = refresh

    def __call__(self, method, url, form, headers):
        self.calls.append((method, url, form, headers))
        if url.startswith("https://oauth2.googleapis.com/token"):
            status, body = self.refresh
            return status, body or json.dumps({"access_token": "ACCESS-1", "expires_in": 3599}).encode()
        assert headers["Authorization"] == "Bearer ACCESS-1"
        u = urllib.parse.urlsplit(url)
        if u.path.endswith("/messages"):
            return 200, json.dumps({"messages": [{"id": i, "threadId": i} for i in self.messages]}).encode()
        msg_id = u.path.rsplit("/", 1)[-1]
        when, raw = self.messages[msg_id]
        doc = {"id": msg_id, "internalDate": str(int(when * 1000)), "raw": base64.urlsafe_b64encode(raw).decode()}
        return 200, json.dumps(doc).encode()


def _box(tmp_path, http, **kw):
    return mail.GmailMailbox(_token_file(tmp_path), http=http, clock=lambda: SINCE + 10, sleep=lambda s: None, **kw)


def test_refresh_posts_refresh_grant_and_keeps_token_in_memory(tmp_path):
    http = FakeHttp()
    box = _box(tmp_path, http)
    before = (tmp_path / "google_token.json").read_text()
    box.refresh()
    method, url, form, _ = http.calls[0]
    assert method == "POST" and url == "https://oauth2.googleapis.com/token"
    assert form == {
        "grant_type": "refresh_token",
        "refresh_token": "R-TOKEN",
        "client_id": "cid",
        "client_secret": "csec",
    }
    assert box._access == "ACCESS-1"
    assert (tmp_path / "google_token.json").read_text() == before  # the owner's file is never written
    assert [p.name for p in tmp_path.iterdir()] == ["google_token.json"]


def test_refresh_error_is_one_line_without_secret(tmp_path):
    body = json.dumps({"error": "invalid_grant", "error_description": "Token has been expired or revoked."}).encode()
    box = _box(tmp_path, FakeHttp(refresh=(400, body)))
    with pytest.raises(mail.MailError) as exc:
        box.refresh()
    msg = str(exc.value)
    assert "invalid_grant" in msg and "HTTP 400" in msg
    assert "R-TOKEN" not in msg and "csec" not in msg


def test_query_is_built_and_injection_refused():
    assert mail.query(ALIAS, SINCE, DOMAIN) == f"to:{ALIAS} from:{DOMAIN} after:{int(SINCE)}"
    assert mail.query(ALIAS, SINCE) == f"to:{ALIAS} after:{int(SINCE)}"
    with pytest.raises(mail.MailError):
        mail.query("a@b.example OR from:x", SINCE)
    with pytest.raises(mail.MailError):
        mail.query(ALIAS, SINCE, "x.example OR y")


def test_wait_sends_the_query_and_returns_the_first_link_on_the_domain(tmp_path):
    http = FakeHttp({"m1": (SINCE + 5, _mime())})
    link = _box(tmp_path, http).wait(ALIAS, DOMAIN, SINCE, timeout=0)
    assert link == f"https://app.{DOMAIN}/confirm?t=abc&u=1"  # not evil.example, not the second link
    listing = next(c for c in http.calls if c[1].split("?")[0].endswith("/messages"))
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(listing[1]).query)["q"][0]
    assert listing[1].startswith("https://gmail.googleapis.com/gmail/v1/users/me/messages?")
    assert q == f"to:{ALIAS} from:{DOMAIN} after:{int(SINCE)}"
    get = [c for c in http.calls if "/messages/m1" in c[1]]
    assert get and "format=raw" in get[0][1]


def test_mail_from_another_domain_is_ignored(tmp_path):
    http = FakeHttp({"m1": (SINCE + 5, _mime(sender=f"x@{DOMAIN}.attacker.example"))})
    assert _box(tmp_path, http).wait(ALIAS, DOMAIN, SINCE, timeout=0) is None


def test_mail_failing_authentication_is_ignored(tmp_path):
    auth = "mx.google.com; dkim=pass header.i=@attacker.example; spf=fail smtp.mailfrom=target.example"
    http = FakeHttp({"m1": (SINCE + 5, _mime(auth=auth))})
    assert _box(tmp_path, http).wait(ALIAS, DOMAIN, SINCE, timeout=0) is None
    http = FakeHttp({"m1": (SINCE + 5, _mime(auth=None))})  # no header: nothing to check
    assert _box(tmp_path, http).wait(ALIAS, DOMAIN, SINCE, timeout=0) is not None


def test_mail_older_than_since_is_ignored(tmp_path):
    http = FakeHttp({"m1": (SINCE - 1, _mime())})
    assert _box(tmp_path, http).wait(ALIAS, DOMAIN, SINCE, timeout=0) is None


def test_mail_to_another_address_is_ignored(tmp_path):
    http = FakeHttp({"m1": (SINCE + 5, _mime(to="someone@else.example"))})
    assert _box(tmp_path, http).wait(ALIAS, DOMAIN, SINCE, timeout=0) is None


def test_numeric_code_when_no_link(tmp_path):
    plain = "Your code is 482913. Valid until 2026-11-25 12:00. See https://evil.example/1234"
    html = "<style>p{width:1000px}</style><p>Code: <b>482913</b></p>"
    http = FakeHttp({"m1": (SINCE + 5, _mime(plain=plain, html=html))})
    assert _box(tmp_path, http).wait(ALIAS, DOMAIN, SINCE, timeout=0) == "482913"


def test_wait_polls_until_timeout(tmp_path):
    now = [SINCE]
    sleeps: list[float] = []

    def sleep(s):
        sleeps.append(s)
        now[0] += s

    box = mail.GmailMailbox(_token_file(tmp_path), http=FakeHttp(), clock=lambda: now[0], sleep=sleep, poll_s=10)
    assert box.wait(ALIAS, DOMAIN, SINCE, timeout=25) is None
    assert sleeps == [10, 10, 5]


def test_log_has_id_and_domain_only(tmp_path, caplog):
    caplog.set_level("INFO", logger="bh.accounts.mail")
    http = FakeHttp({"m1": (SINCE + 5, _mime())})
    _box(tmp_path, http).wait(ALIAS, DOMAIN, SINCE, timeout=0)
    text = caplog.text
    assert "m1" in text and DOMAIN in text
    for leak in (SUBJECT, BODY_MARK, ALIAS, "confirm?t=abc", "ACCESS-1"):
        assert leak not in text


def test_mailbox_falls_back_without_file(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_GMAIL_TOKEN", str(tmp_path / "missing.json"))
    assert isinstance(mail.mailbox(), mail.NoMailbox)
    p = tmp_path / "no-refresh.json"
    p.write_text(json.dumps({"token": "x"}))
    monkeypatch.setenv("BH_GMAIL_TOKEN", str(p))
    assert isinstance(mail.mailbox(), mail.NoMailbox)
    monkeypatch.setenv("BH_GMAIL_TOKEN", str(_token_file(tmp_path)))
    assert isinstance(mail.mailbox(), mail.GmailMailbox)


def test_mail_check_prints_a_count_only(tmp_path, monkeypatch, capsys, caplog):
    caplog.set_level("DEBUG")
    home = tmp_path / "home"
    (home / "secrets").mkdir(parents=True)
    (home / "secrets" / "researcher.env").write_text(f"BH_YWH_EMAIL={ALIAS}\n")
    monkeypatch.setenv("BH_HOME", str(home))
    monkeypatch.setenv("BH_GMAIL_TOKEN", str(_token_file(tmp_path)))
    http = FakeHttp({"m1": (SINCE + 5, _mime()), "m2": (SINCE + 6, _mime())})
    monkeypatch.setattr(mail, "_urllib_http", http)
    assert main(["accounts", "mail-check"]) == 0
    out = capsys.readouterr()
    assert out.out == "token ok, 2 message(s) to te***@alias.example in 24 h\n"
    for leak in (SUBJECT, BODY_MARK, ALIAS, DOMAIN, "ACCESS-1", "R-TOKEN", "csec"):
        assert leak not in out.out + out.err + caplog.text
    assert not any("/messages/" in c[1] for c in http.calls)  # counting never opens a message
