"""bh-fuzz: one parameter, a few probes, only what differs from the reference (T43).

  bh-fuzz <url> -p <param> [--data BODY] [--method GET|POST] [--as ID] [--max N] [--timeout S]

One reference request with the parameter's own value, then at most MAX_REQUESTS - 1 probes, each a short value that
breaks one syntax (quote, markup, template, path, separator, size, type). Kept: only the probes whose answer differs
from the reference, by status, by size (the probe's own echo set aside) or by reflection of the probe (raw or
transformed). Everything else is dropped. Sequential, through the gate (BH_GATE), one request every 1/BH_RPS seconds;
a rate limit, a gate refusal or an unreachable target stops the run at once, never retried.

Refused: an identifier parameter (`id`, `uid`, `user`..., or a value contract.ID_SEGMENT reads as one: fuzzing it
walks other people's objects), a program that forbids scanners (contract.scanners_allowed), the verifier.
The summary lists leads, never findings: each one is to be reproduced by hand. Raw exchanges in raw/fuzz-*/.
Stdlib only.
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import shlex
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from bh.agent import contract as c
from bh.agent import fail

MAX_REQUESTS = 20  # the reference included
DEFAULT_TIMEOUT = 120
REQUEST_TIMEOUT = 15
BODY_KEEP = 1 << 20
LAST_WORDS = "leads, not findings"
# Names that hold an object's identifier (the value is checked too, with contract.ID_SEGMENT)
ID_NAMES = re.compile(
    r"^(id|ids|uid|gid|uuid|guid|oid|pid|user|users|userid|username|account|accountid|owner|ownerid|customer|"
    r"customerid|member|memberid|tenant|tenantid|org|orgid)$",
    re.I,
)
ID_SUFFIX = re.compile(r"[_\-.\[](id|uid|uuid|guid)\]?$", re.I)  # user_id, order-id, filter[id]
ID_CAMEL = re.compile(r"[a-z](Id|ID|Uid|Uuid|Guid)$")  # userId, orderID (never paid, valid)
# (name, value template): {m} is the run's marker; a probe without it is not checked for reflection
PROBES = (
    ("quote", "{m}'"),
    ("dquote", '{m}"'),
    ("markup", "{m}<b>"),
    ("template", "{m}{{{{7*7}}}}"),
    ("expression", "{m}${{7*7}}"),
    ("path", "../{m}"),
    ("backslash", "{m}\\"),
    ("separator", "{m};"),
    ("pipe", "{m}|"),
    ("backtick", "{m}`"),
    ("crlf", "{m}\r\n"),
    ("nul", "{m}\x00"),
    ("unicode", "{m}İK"),
    ("long", "{m}" + "A" * 2048),
    ("empty", ""),
    ("negative", "-1"),
    ("zero", "0"),
    ("huge", "99999999999999999999"),
    ("bool", "true"),
)


@dataclass
class Answer:
    status: int
    body: bytes
    denied: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status > 0 and not self.denied


def is_identifier(name: str, value: str | None) -> bool:
    """An object identifier: by its name, or by its value as contract.ID_SEGMENT reads a path segment."""
    named = ID_NAMES.match(name) or ID_SUFFIX.search(name) or ID_CAMEL.search(name)
    return bool(named or (value and c.ID_SEGMENT.match(value)))


def place(url: str, data: str | None, param: str) -> tuple[str, str | None]:
    """Where the parameter lives ('query', 'form' or 'json') and its current value (None if absent: query)."""
    if data is not None:
        try:
            doc = json.loads(data)
        except ValueError:
            doc = None
        if isinstance(doc, dict) and param in doc:
            v = doc[param]
            return "json", v if isinstance(v, str) else json.dumps(v)
        form = dict(parse_qsl(data, keep_blank_values=True))
        if param in form:
            return "form", form[param]
    query = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
    return "query", query.get(param)


def build(url: str, data: str | None, param: str, where: str, value: str) -> tuple[str, bytes | None, str | None]:
    """(url, body, content type) with the parameter set to `value`, everything else as given."""
    if where == "json":
        doc = json.loads(data or "{}")
        doc[param] = value
        return url, json.dumps(doc).encode(), "application/json"
    if where == "form":
        pairs = [(k, value if k == param else v) for k, v in parse_qsl(data or "", keep_blank_values=True)]
        return url, urlencode(pairs).encode(), "application/x-www-form-urlencoded"
    p = urlsplit(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    pairs = (
        [(k, value if k == param else v) for k, v in pairs]
        if any(k == param for k, _ in pairs)
        else [
            *pairs,
            (param, value),
        ]
    )
    body = data.encode() if data is not None else None
    ctype = "application/x-www-form-urlencoded" if data is not None else None
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(pairs), "")), body, ctype


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def send(method: str, url: str, body: bytes | None, ctype: str | None, who: str | None) -> Answer:
    """One request through the gate; a redirect is an answer; nothing is retried."""
    headers = {"Accept": "*/*"}
    if who:
        headers[c.IDENTITY_HEADER] = who
    if ctype:
        headers["Content-Type"] = ctype
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": c.gate(), "https": c.gate()}), _NoRedirect
    )
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with opener.open(req, timeout=REQUEST_TIMEOUT) as resp:
            return Answer(resp.status, resp.read(BODY_KEEP), _gate_refused(resp.headers))
    except urllib.error.HTTPError as err:
        return Answer(err.code, err.read(BODY_KEEP) or b"", _gate_refused(err.headers))
    except urllib.error.URLError as err:
        refused = "403" in str(err.reason) and "unnel" in str(err.reason)  # a CONNECT the gate refused
        return Answer(403 if refused else 0, b"", refused, type(err.reason).__name__ if not refused else "")
    except (OSError, ValueError) as exc:
        return Answer(0, b"", False, type(exc).__name__)


def _gate_refused(headers) -> bool:
    return (headers.get(c.GATE_HEADER) or "").lower() == "denied"


def deviation(ref: Answer, ans: Answer, ref_value: str, value: str, marker: str | None) -> list[str]:
    """How `ans` differs from `ref`: status, size (each answer without its own echo of the value), reflection."""
    out = []
    if ans.status != ref.status:
        out.append(f"status {ref.status}->{ans.status}")
    v, rv = value.encode(errors="replace"), ref_value.encode(errors="replace")
    size = len(ans.body.replace(v, b"") if v else ans.body)
    ref_size = len(ref.body.replace(rv, b"") if rv else ref.body)
    if abs(size - ref_size) > max(32, ref_size // 20):
        out.append(f"size {size - ref_size:+d}B")
    if marker and marker.encode() in ans.body:
        out.append("reflected raw" if v in ans.body else "reflected transformed")
    return out


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="bh-fuzz", description=__doc__.split("\n\n")[0], allow_abbrev=False)
    p.add_argument("url")
    p.add_argument("-p", "--param", required=True, help="the one parameter to probe")
    p.add_argument("--data", help="request body (form or JSON); the parameter may live there")
    p.add_argument("--method", choices=("GET", "POST", "PUT", "PATCH"), help="default: GET, or POST with --data")
    p.add_argument("--as", dest="identity", help="identity name, sent as X-BH-Identity")
    p.add_argument(
        "--max", type=int, default=MAX_REQUESTS, help=f"requests at most, reference included ({MAX_REQUESTS})"
    )
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="seconds")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    a = parse_args(list(sys.argv[1:] if argv is None else argv))
    if c.is_verifier():
        sys.exit(f"{c.RULES_MARK} bh-fuzz: the verifier re-tests with single requests only")
    if not c.scanners_allowed():
        sys.exit(f"{c.RULES_MARK} bh-fuzz: this program forbids automated scanners")
    url = a.url if "://" in a.url else f"https://{a.url}"
    if c.origin(url) is None:
        sys.exit(fail.line("bad-argument", "bh-fuzz needs an http(s) URL"))
    where, value = place(url, a.data, a.param)
    if is_identifier(a.param, value):
        sys.exit(
            f"{c.RULES_MARK} bh-fuzz: {a.param[:40]!r} holds an object identifier; probing it walks other people's "
            "objects. Test it by hand with your own identities' ids (bh-authz compares them)."
        )
    from bh.agent.tools import Job  # raw dir, coverage and the summary's shape, as the other builtins

    job = Job("fuzz", url, a.identity, a.timeout)
    (job.raw / "cmd.txt").write_text(shlex.join(["bh-fuzz", *(argv if argv is not None else sys.argv[1:])]) + "\n")
    run(job, a, where, value)


def run(job, a: argparse.Namespace, where: str, value: str | None) -> list[tuple[str, list[str]]]:
    method = a.method or ("POST" if a.data is not None else "GET")
    limit = max(1, min(MAX_REQUESTS, a.max))
    pause = 1 / c.rps()
    deadline = time.monotonic() + max(5, a.timeout)
    marker = "bhf" + secrets.token_hex(3)
    ref_value = value if value is not None else marker + "ref"
    sent, leads, stop = 0, [], ""

    def one(v: str) -> Answer:
        nonlocal sent
        if sent:
            time.sleep(pause)
        u, body, ctype = build(job.url, a.data, a.param, where, v)
        ans = send(method, u, body, ctype, a.identity)
        sent += 1
        c.append_jsonl(
            job.raw / "exchanges.jsonl",
            {"value": v[:200], "url": u[:2000], "status": ans.status, "size": len(ans.body), "denied": ans.denied},
        )
        return ans

    def failure(ans: Answer) -> str:
        if ans.denied:
            return "gate-denied"
        if ans.status == 429:
            return "rate"
        if ans.status == 0:
            return "unreachable"
        return ""

    ref = one(ref_value)
    stop = failure(ref) or ("auth" if a.identity and ref.status == 401 else "")
    for name, template in PROBES[: limit - 1]:
        if stop:
            break
        if time.monotonic() >= deadline:
            job.timed_out = True
            break
        probe = template.format(m=marker)
        ans = one(probe)
        if stop := failure(ans):
            break
        if diff := deviation(ref, ans, ref_value, probe, marker if "{m}" in template else None):
            leads.append((name, diff))
    if stop:
        job.rc, job.fail = 1, stop
    elif job.timed_out:
        job.fail = "timeout"
    ok = not stop and not job.timed_out
    if not stop:  # a failed run keeps no lead (it observed a gate, a limit or nothing)
        c.write_json(job.raw / "leads.json", [{"probe": n, "deviation": d} for n, d in leads])
        for name, diff in leads:
            job.lines.append(f"{name:<10} {', '.join(diff)}")
    else:
        leads = []
    if ok:
        c.record_touched(c.bh_dir(), [job.url], via="fuzz", method=method)
    job.lines.insert(0, f"reference: {ref.status} {len(ref.body)}B ({where} parameter {a.param[:40]})")
    job.finish(
        len(leads),
        job.rc,
        job.timed_out,
        f"{sent} requests (1 reference + {sent - 1} probes), {len(leads)} deviations",
        "reproduce the first deviation above by hand, one request (curl --max-time 30)"
        if leads
        else f'bh-note cover "{method} {c.path_key(urlsplit(job.url).path)}" input clean -e {job.raw}/exchanges.jsonl',
        tail=LAST_WORDS,
    )
    return leads
