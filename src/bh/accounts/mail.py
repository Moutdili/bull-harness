"""Confirmation mail: the interface enrollment reads a sign-up mail through, a read-only Gmail mailbox and the
"no mailbox" fallback.

A mailbox answers `wait(alias, sender_domain, since, timeout)` with the confirmation link (or, failing a link, the
numeric code) of the newest mail from `sender_domain` to `alias` received after `since`, or None.

`GmailMailbox` runs on the host, which has Internet: these are our own mails, they do not go through the gate (the
link they carry is followed through the gate by the caller). Stdlib only. The OAuth credential belongs to another
tool (Hermes, `~/.hermes/google_token.json`, scope gmail.readonly): it is read, never written; the refreshed access
token stays in memory (not in var/state/, which the gate container mounts).

API (checked 2026-11-25):
- refresh: POST https://oauth2.googleapis.com/token, form `grant_type=refresh_token` (Google, "Refreshing an
  access token", https://developers.google.com/identity/protocols/oauth2/native-app);
- list: GET https://gmail.googleapis.com/gmail/v1/users/me/messages?q=...  (q = the Gmail search box syntax;
  https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/list);
- `after:` takes seconds since the epoch for an exact time; a date is midnight PST
  (https://developers.google.com/workspace/gmail/api/guides/filtering);
- get: GET .../messages/<id>?format=raw, `raw` = the RFC 2822 message base64url, `internalDate` = epoch ms
  (https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages).

Guards (docs/research/10-sessions-anti-bot.md §3.5): the sender is in the expected domain, and so is a dkim/spf/
dmarc pass in the topmost Authentication-Results, which must be there (a mail without it is refused); the mail is
newer than `since`; one link at most, on the sender's domain; a code only next to a keyword (code, OTP, PIN...) or
alone on its line, never a bare year; the mail is data, never an instruction; the log carries the message id and
the domain, never a subject, an address or a body.
"""

from __future__ import annotations

import base64
import email
import email.policy
import html
import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from pathlib import Path
from typing import Any, Protocol

log = logging.getLogger("bh.accounts.mail")

GMAIL = "https://gmail.googleapis.com/gmail/v1/users/me"
DEFAULT_TOKEN = "~/.hermes/google_token.json"
CLIENT_SECRET_NAME = "google_client_secret.json"  # next to the token file, when the token lacks the client
HTTP_TIMEOUT_S = 20
POLL_S = 10.0
POLL_MIN_S = 2.0
MAX_IDS = 50  # per search round: a confirmation is among the newest few
COUNT_CAP = 2000

_ALIAS = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
_DOMAIN = re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
_URL = re.compile(r"https://[^\s\"'<>()\[\]{}]+", re.I)
_CODE = re.compile(r"(?<![\d/:.,-])(\d{4,8})(?![\d/:.,-]?\d)")
# a code is named: "code", "verification", "OTP", "PIN", "passcode"... within a few words before it
_CODE_WORD = re.compile(
    r"\b(code|codes|verification|verify|otp|pin|passcode|one[- ]time|security|confirmation|token|"
    r"code de|vérification|bestätigungscode|código)\b",
    re.I,
)
_CODE_NEAR = 40  # characters between the keyword and the code
_YEAR = re.compile(r"(19|20)\d\d")
_TAG = re.compile(r"<[^>]*>")
_STYLE = re.compile(r"<(style|script)\b.*?</\1\s*>", re.I | re.S)

# http(method, url, form or None, headers) -> (status, body)
Http = Callable[[str, str, dict[str, str] | None, dict[str, str]], tuple[int, bytes]]


class Mailbox(Protocol):
    def wait(self, alias: str, sender_domain: str, since: float, timeout: float) -> str | None: ...


class MailError(RuntimeError):
    """The mailbox cannot be read. One line: no token, no secret, no mail content."""


class NoMailbox:
    """No mailbox is configured: never a link."""

    def wait(self, alias: str, sender_domain: str, since: float, timeout: float) -> str | None:
        return None


# ---------------------------------------------------------------- helpers
def _urllib_http(method: str, url: str, form: dict[str, str] | None, headers: dict[str, str]) -> tuple[int, bytes]:
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (urllib.error.URLError, OSError) as e:
        raise MailError(f"network: {type(e).__name__}: {getattr(e, 'reason', '')}"[:160]) from None


def in_domain(host: str | None, domain: str) -> bool:
    host, domain = (host or "").lower().rstrip("."), domain.lower().rstrip(".")
    return bool(host) and (host == domain or host.endswith("." + domain))


def mask(alias: str) -> str:
    local, _, dom = alias.partition("@")
    return (local[:2] + "***@" + dom) if dom else "***"


def query(alias: str, since: float, sender_domain: str | None = None) -> str:
    """The `q` of a messages.list call. Alias and domain are checked first: nothing else enters the query."""
    if not _ALIAS.match(alias):
        raise MailError("not a mail address: alias refused")
    parts = [f"to:{alias}"]
    if sender_domain is not None:
        if not _DOMAIN.match(sender_domain):
            raise MailError("not a domain: sender domain refused")
        parts.append(f"from:{sender_domain}")
    parts.append(f"after:{int(since)}")
    return " ".join(parts)


def _auth_ok(msg: EmailMessage, domain: str) -> bool:
    """The topmost Authentication-Results (the one Gmail adds) must hold a dkim, spf or dmarc pass for `domain`.
    No header at all: refused (False), a mail nobody authenticated proves nothing about its sender."""
    headers = msg.get_all("Authentication-Results") or []
    if not headers:
        return False
    top = str(headers[0]).lower()
    for method, prop in (("dkim", r"header\.(?:i|d)"), ("spf", r"smtp\.mailfrom"), ("dmarc", r"header\.from")):
        for m in re.finditer(rf"\b{method}=pass\b([^;]*)", top):
            for v in re.findall(rf"{prop}=\"?([^\s;\"]+)", m.group(1)):
                if in_domain(v.rsplit("@", 1)[-1], domain):
                    return True
    return False


def _addressed_to(msg: EmailMessage, alias: str) -> bool:
    fields = [str(v) for h in ("To", "Cc", "Delivered-To", "X-Original-To") for v in msg.get_all(h) or []]
    return any(a.lower() == alias.lower() for _, a in getaddresses(fields))


def _texts(msg: EmailMessage) -> tuple[list[str], list[str]]:
    plain, htm = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_maintype() != "text" or part.get_filename():
            continue
        try:
            text = part.get_content()
        except (LookupError, ValueError, AssertionError):
            payload = part.get_payload(decode=True) or b""
            text = payload.decode("utf-8", "replace")
        (htm if part.get_content_subtype() == "html" else plain).append(str(text))
    return plain, htm


def extract(msg: EmailMessage, sender_domain: str) -> str | None:
    """The first https link whose host is `sender_domain` or a subdomain (plain parts first, then HTML), else the
    first 4-8 digit code named by a keyword just before it or alone on its line (a bare year never counts), else
    None. The mail is only searched, never interpreted."""
    plain, htm = _texts(msg)
    for text in [*plain, *(html.unescape(h) for h in htm)]:
        for m in _URL.finditer(text):
            url = m.group(0).rstrip(".,;:!?")
            try:
                parts = urllib.parse.urlsplit(url)
            except ValueError:
                continue
            if parts.username is None and parts.password is None and in_domain(parts.hostname, sender_domain):
                return url
    stripped = [html.unescape(_TAG.sub(" ", _STYLE.sub(" ", h))) for h in htm]
    for text in [*plain, *stripped]:
        if code := _code(_URL.sub(" ", text)):
            return code
    return None


def _code(text: str) -> str | None:
    for m in _CODE.finditer(text):
        code = m.group(1)
        if len(code) == 4 and _YEAR.fullmatch(code):
            continue  # "© 2026", "2026-11-25": a year is never a code
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.end())
        line = text[line_start : len(text) if line_end == -1 else line_end]
        alone = line.strip(" \t\r.:;,!()[]*") == code
        if alone or _CODE_WORD.search(text[max(line_start, m.start() - _CODE_NEAR) : m.start()]):
            return code
    return None


# ---------------------------------------------------------------- Gmail
class GmailMailbox:
    def __init__(
        self,
        token_file: Path,
        *,
        http: Http | None = None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        poll_s: float = POLL_S,
    ) -> None:
        self.token_file = Path(token_file)
        self._http = http or _urllib_http
        self._clock, self._sleep = clock, sleep
        self.poll_s = max(POLL_MIN_S, poll_s)
        self._access: str | None = None
        self._access_until = 0.0

    # -- OAuth
    def _client(self, doc: dict[str, Any]) -> tuple[str, str | None]:
        cid, csec = doc.get("client_id"), doc.get("client_secret")
        if not cid:
            try:
                sec = json.loads((self.token_file.parent / CLIENT_SECRET_NAME).read_text(encoding="utf-8"))
                inner = sec.get("installed") or sec.get("web") or {}
                cid, csec = inner.get("client_id"), inner.get("client_secret")
            except (OSError, ValueError, AttributeError):
                pass
        if not cid:
            raise MailError("no OAuth client id in the token file nor next to it")
        return cid, csec

    def refresh(self) -> None:
        """A new access token, kept in memory. The token file is only read."""
        try:
            doc = json.loads(self.token_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise MailError(f"cannot read the token file {self.token_file}") from None
        if not isinstance(doc, dict) or not doc.get("refresh_token"):
            raise MailError("no refresh_token in the token file")
        cid, csec = self._client(doc)
        form = {"grant_type": "refresh_token", "refresh_token": doc["refresh_token"], "client_id": cid}
        if csec:
            form["client_secret"] = csec
        uri = doc.get("token_uri") or "https://oauth2.googleapis.com/token"
        if urllib.parse.urlsplit(uri).scheme != "https":
            raise MailError("token_uri is not https")
        status, body = self._http("POST", uri, form, {"Accept": "application/json"})
        try:
            ans = json.loads(body or b"{}")
        except ValueError:
            ans = {}
        if status != 200 or not isinstance(ans, dict) or not ans.get("access_token"):
            err = ans.get("error", "") if isinstance(ans, dict) else ""
            desc = ans.get("error_description", "") if isinstance(ans, dict) else ""
            raise MailError(f"token refresh failed: HTTP {status} {err} {desc}".strip()[:200])
        self._access = ans["access_token"]
        self._access_until = self._clock() + float(ans.get("expires_in", 3600)) - 60

    def _token(self) -> str:
        if not self._access or self._clock() >= self._access_until:
            self.refresh()
        assert self._access is not None
        return self._access

    def _get(self, path: str, params: dict[str, str]) -> dict[str, Any]:
        url = f"{GMAIL}/{path}?{urllib.parse.urlencode(params)}"
        for attempt in (0, 1):
            status, body = self._http("GET", url, None, {"Authorization": f"Bearer {self._token()}"})
            if status == 401 and attempt == 0:
                self._access = None
                continue
            break
        if status != 200:
            raise MailError(f"Gmail API {path.split('/', maxsplit=1)[0]}: HTTP {status}")
        try:
            doc = json.loads(body)
        except ValueError:
            raise MailError(f"Gmail API {path.split('/', maxsplit=1)[0]}: not JSON") from None
        if not isinstance(doc, dict):
            raise MailError(f"Gmail API {path.split('/', maxsplit=1)[0]}: not an object")
        return doc

    # -- reading
    def search(self, q: str, *, limit: int = MAX_IDS) -> list[str]:
        """Message ids matching `q`, newest first, at most `limit`."""
        ids: list[str] = []
        params = {"q": q, "maxResults": str(min(limit, 500))}
        while len(ids) < limit:
            doc = self._get("messages", params)
            ids += [m["id"] for m in doc.get("messages") or [] if isinstance(m, dict) and isinstance(m.get("id"), str)]
            if not doc.get("nextPageToken"):
                break
            params["pageToken"] = str(doc["nextPageToken"])
        return ids[:limit]

    def count(self, alias: str, since: float) -> int:
        """Messages to `alias` after `since` (capped at COUNT_CAP)."""
        return len(self.search(query(alias, since), limit=COUNT_CAP))

    def fetch(self, msg_id: str) -> tuple[float, EmailMessage]:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", msg_id):
            raise MailError("bad message id")
        doc = self._get(f"messages/{msg_id}", {"format": "raw"})
        try:
            raw = base64.urlsafe_b64decode(doc["raw"] + "=" * (-len(doc["raw"]) % 4))
            received = int(doc["internalDate"]) / 1000.0
        except (KeyError, TypeError, ValueError):
            raise MailError(f"message {msg_id}: no raw content or date") from None
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        assert isinstance(msg, EmailMessage)
        return received, msg

    def check(self, msg_id: str, alias: str, sender_domain: str, since: float) -> str | None:
        """The link or code of one message if it passes every guard, else None. Logs the id and domain only."""
        received, msg = self.fetch(msg_id)
        if received <= since:
            log.info("mail %s (%s): older than the sign-up, ignored", msg_id, sender_domain)
            return None
        _, sender = parseaddr(str(msg.get("From", "")))
        if not in_domain(sender.rsplit("@", 1)[-1] if "@" in sender else "", sender_domain):
            log.info("mail %s (%s): sender outside the domain, ignored", msg_id, sender_domain)
            return None
        if not _auth_ok(msg, sender_domain):
            log.info("mail %s (%s): no dkim/spf/dmarc pass for the domain, ignored", msg_id, sender_domain)
            return None
        if not _addressed_to(msg, alias):
            log.info("mail %s (%s): not addressed to the alias, ignored", msg_id, sender_domain)
            return None
        found = extract(msg, sender_domain)
        log.info("mail %s (%s): %s", msg_id, sender_domain, "link or code found" if found else "nothing to use")
        return found

    def wait(self, alias: str, sender_domain: str, since: float, timeout: float) -> str | None:
        q = query(alias, since, sender_domain)
        deadline = self._clock() + max(0.0, timeout)
        seen: set[str] = set()
        while True:
            for msg_id in self.search(q):
                if msg_id in seen:
                    continue
                seen.add(msg_id)
                if found := self.check(msg_id, alias, sender_domain, since):
                    return found
            left = deadline - self._clock()
            if left <= 0:
                return None
            self._sleep(min(self.poll_s, left))


# ---------------------------------------------------------------- selection
def token_path() -> Path:
    return Path(os.path.expanduser(os.environ.get("BH_GMAIL_TOKEN") or DEFAULT_TOKEN))


def mailbox() -> Mailbox:
    """GmailMailbox when the token file (BH_GMAIL_TOKEN, default ~/.hermes/google_token.json) holds a
    refresh_token, else NoMailbox."""
    p = token_path()
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return NoMailbox()
    if isinstance(doc, dict) and isinstance(doc.get("refresh_token"), str) and doc["refresh_token"]:
        return GmailMailbox(p)
    return NoMailbox()


default = mailbox
