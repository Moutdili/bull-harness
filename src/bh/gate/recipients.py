"""D31: the recipient guard. "Only our accounts" for writes whose effect lands in a mailbox (a mail, an invitation).

A scope's `recipient_guard` names the routes that carry a recipient (`send` routes of the host survey, never a `link`
route, which names nobody). For a request whose URL one of them matches, whatever the client (the hunter, the judge,
bh-browser, enrollment), the gate wants at least one e-mail address in the URL or the body, and every address it
finds must be one of the program's identities. Anything else is refused, `recipient not ours`:
- no address recognized (a recipient named by an id is refused too: the gate cannot tell whose it is);
- one address that is not ours, among ours or alone (a third party in Bcc);
- no allowlist, or the allowlist of another program;
- a body it cannot read: compressed (Content-Encoding), over READ_MAX bytes, not UTF-8, a JSON or form body that does
  not parse, a multipart body without boundary or with defects.
No option loosens it.

The allowlist, `<state>/recipients.json` = {"program", "sha256": [sha256 of each address, lowercased], "ts"}, is
written by the host from `secrets/` (write_allowlist) and read by the gate (allowed), reread when the file changes.
Only digests travel: an address of ours never reaches the gate's files, and the refusal journals a truncated digest of
the refused addresses, never the address itself (scrub).
"""

from __future__ import annotations

import contextlib
import hashlib
import html
import json
import os
import re
import time
from collections.abc import Callable, Iterable
from email import message_from_bytes
from email import policy as email_policy
from email.message import Message
from pathlib import Path
from urllib.parse import unquote, unquote_plus

from bh import paths

FILE = "recipients.json"
REASON = "recipient not ours"
READ_MAX = 1 << 20  # bytes of a body the guard reads; a larger one is refused
DIGEST_SHOWN = 12  # hex characters of a digest a journal line keeps
_DECODE_ROUNDS = 3  # %-decoding passes over a text (a doubly encoded `%2540` is read as `@` too)
_NOT_IN_ADDRESS = r"\s@<>()\[\]{},;:\"'`/\\?&=#|"
ADDRESS = re.compile(rf"[^{_NOT_IN_ADDRESS}]+@[^{_NOT_IN_ADDRESS}]+")
# what scrub hides: an address, raw or with its `@` written %40, %2540, &#64; or @
_SCRUB = re.compile(rf"[^{_NOT_IN_ADDRESS}]+(?:@|%40|%2540|&#0*64;|&commat;|\\u0040)[^{_NOT_IN_ADDRESS}]+", re.I)
_HEX64 = re.compile(r"[0-9a-f]{64}")


def normalize(address: str) -> str:
    return address.strip().lower().rstrip(".")


def digest(address: str) -> str:
    return hashlib.sha256(normalize(address).encode("utf-8")).hexdigest()


def short(address: str) -> str:
    return digest(address)[:DIGEST_SHOWN]


def scrub(text: str) -> str:
    """`text` with every address (raw or encoded) replaced by `<address:<truncated digest>>`."""

    def one(m: re.Match[str]) -> str:
        raw = m.group(0)
        decoded = html.unescape(unquote(unquote(raw))).replace("\\u0040", "@")
        return f"<address:{short(decoded)}>"

    return _SCRUB.sub(one, text)


# ---------------------------------------------------------------- the allowlist (host writes, gate reads)
def path(state: Path | None = None) -> Path:
    return (paths.state() if state is None else Path(state)) / FILE


def write_allowlist(scope) -> Path | None:
    """Write `<state>/recipients.json` for `scope` from the identities' addresses in `secrets/` (host side). Atomic:
    the gate never reads half a list. No address at all: the file is removed (nothing is anyone's) and None."""
    from bh.accounts import secrets

    found = set()
    for ident in scope.identities:
        doc = secrets.load_raw(scope.program, str(ident.get("name", "")))
        email = (doc or {}).get("email")
        if isinstance(email, str) and ADDRESS.fullmatch(email.strip()):
            found.add(digest(email))
    f = path()
    if not found:
        with contextlib.suppress(FileNotFoundError):
            f.unlink()
        return None
    f.parent.mkdir(parents=True, exist_ok=True)
    rec = {"program": scope.program, "sha256": sorted(found), "ts": round(time.time(), 3)}
    tmp = f.with_name(f".{f.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)  # digests only; the gate's user reads it
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(rec, fh)
        os.replace(tmp, f)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    return f


_CACHE: dict[Path, tuple[tuple[int, int, int], dict | None]] = {}


def _load(f: Path) -> dict | None:
    """The allowlist document, reread when its mtime, size or inode changes; None when absent or malformed."""
    try:
        st = f.stat()
    except OSError:
        _CACHE.pop(f, None)
        return None
    sig = (st.st_mtime_ns, st.st_size, st.st_ino)
    hit = _CACHE.get(f)
    if hit is not None and hit[0] == sig:
        return hit[1]
    try:
        doc = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        doc = None
    ok = (
        isinstance(doc, dict)
        and isinstance(doc.get("program"), str)
        and isinstance(doc.get("sha256"), list)
        and all(isinstance(h, str) and _HEX64.fullmatch(h) for h in doc["sha256"])
    )
    doc = {"program": doc["program"], "sha256": frozenset(doc["sha256"])} if ok else None
    _CACHE[f] = (sig, doc)
    return doc


def allowed(program: str, address: str, *, state: Path | None = None) -> bool:
    """Gate side: is `address` one of `program`'s identities? False without a list, or with another program's."""
    doc = _load(path(state))
    return doc is not None and doc["program"] == program and digest(address) in doc["sha256"]


def has_list(program: str, *, state: Path | None = None) -> bool:
    doc = _load(path(state))
    return doc is not None and doc["program"] == program


# ---------------------------------------------------------------- the routes and the request
def matching(url: str, rules: Iterable) -> object | None:
    """The first `recipient_guard` rule whose regex is found in `url`, raw or %-decoded (case-insensitive)."""
    variants = [url]
    for _ in range(_DECODE_ROUNDS):
        nxt = unquote(variants[-1])
        if nxt == variants[-1]:
            break
        variants.append(nxt)
    for rule in rules:
        rx = _rx(rule.url)
        if any(rx.search(v) for v in variants):
            return rule
    return None


_RX: dict[str, re.Pattern[str]] = {}


def _rx(pattern: str) -> re.Pattern[str]:
    rx = _RX.get(pattern)
    if rx is None:
        rx = _RX[pattern] = re.compile(pattern, re.I)  # the scope validated it at load
    return rx


class Unreadable(ValueError):
    """A body the guard cannot read: the request is refused."""


def _variants(text: str) -> list[str]:
    out = [text, html.unescape(text)]
    cur = text
    for _ in range(_DECODE_ROUNDS):
        nxt = unquote_plus(cur)
        if nxt == cur:
            break
        out += [nxt, html.unescape(nxt)]
        cur = nxt
    return out


def _from_text(text: str) -> set[str]:
    return {normalize(m) for v in _variants(text) for m in ADDRESS.findall(v)}


def _walk_json(node, found: set[str], budget: list[int]) -> None:
    stack = [node]
    while stack:
        budget[0] -= 1
        if budget[0] < 0:
            raise Unreadable("JSON body too deep or too large")
        cur = stack.pop()
        if isinstance(cur, str):
            found |= _from_text(cur)
        elif isinstance(cur, dict):
            for k, v in cur.items():
                found |= _from_text(str(k))
                stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)


def _content_type(value: str | None) -> tuple[str, Message]:
    m = Message()
    m["Content-Type"] = value or "application/octet-stream"
    return m.get_content_type(), m


def _is_json(ctype: str) -> bool:
    return ctype.endswith("/json") or ctype.endswith("+json")


def _from_part(data: bytes, ctype: str, charset: str | None, *, top: bool) -> set[str]:
    """Addresses of one body (or multipart part): its text, its JSON strings, its form fields. At the top, a body that
    is not text is unreadable; inside a multipart, a binary part (a file) is scanned byte for byte."""
    try:
        text = data.decode(charset or "utf-8")
    except (UnicodeDecodeError, LookupError):
        if top:
            raise Unreadable("body is not text") from None
        text = data.decode("latin-1")
    found = _from_text(text)
    stripped = text.strip()
    if _is_json(ctype) or stripped[:1] in ("{", "["):
        try:
            doc = json.loads(stripped)
        except (ValueError, RecursionError):
            if _is_json(ctype):
                raise Unreadable("JSON body that does not parse") from None
        else:
            _walk_json(doc, found, [200_000])
    return found


def _from_multipart(header: str, body: bytes) -> set[str]:
    msg = message_from_bytes(f"Content-Type: {header}\r\n\r\n".encode("latin-1") + body, policy=email_policy.compat32)
    if not msg.is_multipart() or msg.defects:
        raise Unreadable("multipart body without boundary or with defects")
    found: set[str] = set()
    for part in msg.walk():
        if part.defects:
            raise Unreadable("multipart part with defects")
        if part.is_multipart():
            continue
        for k, v in part.items():  # Content-Disposition (a file name), any header of the part
            found |= _from_text(f"{k}: {v}")
        cte = (part.get("Content-Transfer-Encoding") or "").strip().lower()
        if cte not in ("", "7bit", "8bit", "binary", "base64", "quoted-printable"):
            raise Unreadable(f"multipart part with transfer encoding {cte[:20]!r}")
        payload = part.get_payload(decode=True) or b""
        found |= _from_part(payload, part.get_content_type(), part.get_content_charset(), top=False)
    return found


def addresses(
    url: str, body: bytes | None, *, body_len: int, content_type: str | None, content_encoding: str | None
) -> set[str]:
    """Every address the request names, in its URL and its body (normalized). Raises Unreadable when the body cannot
    be read in full."""
    found = _from_text(url)
    if body is None:
        if body_len:
            raise Unreadable("body not available to the guard")
        return found
    if len(body) > READ_MAX or body_len > READ_MAX:
        raise Unreadable(f"body over {READ_MAX} bytes")
    if content_encoding and content_encoding.strip().lower() not in ("", "identity"):
        raise Unreadable("compressed body (Content-Encoding)")
    if not body:
        return found
    ctype, m = _content_type(content_type)
    if ctype.startswith("multipart/"):
        return found | _from_multipart(content_type or "", body)
    found |= _from_part(body, ctype, m.get_content_charset(), top=True)
    return found


def judge(
    url: str,
    body: bytes | None,
    *,
    body_len: int,
    content_type: str | None,
    content_encoding: str | None,
    ok: Callable[[str], bool],
    has_list: bool,
) -> str | None:
    """None when the request may go (at least one address, every one ours), else why not, with no address in it
    (truncated digests of the refused ones)."""
    if not has_list:
        return "no allowlist of this program's addresses"
    try:
        found = addresses(url, body, body_len=body_len, content_type=content_type, content_encoding=content_encoding)
    except Unreadable as exc:
        return f"unreadable: {exc}"
    if not found:
        return "no e-mail address recognized"
    theirs = sorted(a for a in found if not ok(a))
    if theirs:
        more = f" (+{len(theirs) - 5})" if len(theirs) > 5 else ""
        return "not ours: " + ", ".join(short(a) for a in theirs[:5]) + more
    return None
