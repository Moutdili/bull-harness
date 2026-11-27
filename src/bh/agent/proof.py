"""Structured proof of a finding, and its deterministic replay (verifier stage A).

A proof is JSON the hunting agent writes next to a finding:

  {"steps": [
     {"name": "user-b reads its own basket", "role": "setup",   "as": "user-b", "method": "GET",
      "url": "https://t/rest/basket/7", "expect": {"status": [200], "contains": ["\\"UserId\\":27"]}},
     {"name": "user-a reads user-b's basket", "role": "attack", "as": "user-a", "method": "GET",
      "url": "https://t/rest/basket/7", "expect": {"status": [200], "contains": ["\\"UserId\\":27"]}},
     {"name": "without a session",           "role": "control", "as": null,    "method": "GET",
      "url": "https://t/rest/basket/7", "expect": {"status": [401, 403]}}
  ]}

Rules: at least one `attack` step and one `control` step; every step states what must be observed
(`status`, `contains`, `absent`, `regex`); an attack names a marker in the body (`contains`, `absent` or
`regex`), status alone proves nothing; a control is the TWIN of an attack (same method, origin and path:
only the identity, the query or the body differ) and must expect something different. Replay sends every
step through the gate (same scope, identities injected by the gate) and reports which expectations held: reads
twice, writes and setup steps once (they create state: a second booking of the same slot answers 409). The proof
is disproved when a control's answer satisfies its attack's expectation (no differential). No LLM involved.

A step that only a rendered page proves (DOM XSS, a client-side route) adds `"browse": {"xss": "<marker>"}`
(GET only): replay runs `bh-browse <url> --xss <marker>` in a throwaway work dir, reads the `summary.json` it
leaves there (status, dialogs, window.__bhxss, each with the origin of the frame it came from) and decides itself:
confirmed when a dialog's whole message, or the sentinel string, is the marker AND it came from a document of the
origin of the step's URL (a script run on another origin never confirms). The step's body is then one canonical
line written by the replay, never by the page: `xss CONFIRMED (marker <marker>) origin=<origin>` or
`xss none (marker <marker>)`. So the attack expects `{"contains": ["xss CONFIRMED (marker <marker>)"]}` and its
twin control (same route, benign value) expects `{"absent": ["xss CONFIRMED"]}`; the URL, the title and the
console never reach the body. A `"browse": {}` step (no marker) has the rendered DOM as its body, like any answer.

An open redirect is proved by a real navigation: `"browse": {"final_url": "https://<payload host>/<path>"}` (GET
only) runs bh-browse on the step's URL and compares where the browser ended (summary.json `final_url` when bh-browse
writes it, else the chain of HTTP redirects its har.json kept) with that prefix: same origin, path starting with the
prefix's path. The body is one canonical line, `redirect CONFIRMED (prefix <prefix>)` or `redirect none (prefix
<prefix>)`; the prefix is on another origin than the step (a payload host of the scope: never a third party).

Timing (a time-based SQL injection, plan T26): `expect` may hold `elapsed_ms_min` (an attack only) and `elapsed_ms_max`,
whole milliseconds, at most 10 000 each: no recipe waits more than 10 s per request. A proof with a timed attack has
at least three of them, each with a twin control without the delay whose `elapsed_ms_max` is below the attack's
`elapsed_ms_min`; a delay written in the payload (sleep, pg_sleep, WAITFOR DELAY) is at most 10 s, BENCHMARK is
refused (it loads the target). The replay sends them one after the other through the gate, at the program's rate,
and times each answer.

Fresh marker: when the marker sits as is in the step's URL (or body), the replay swaps it for a marker of its own,
drawn at random, and runs bh-browse with that one; the line still names the proof's marker, and the step's result
says `"marker": "fresh"`. A page that merely shows a marker planted beforehand (stored, cached) then shows the old
one, which confirms nothing. A marker absent from the URL cannot be swapped: the result says
`"marker": "hunter-chosen"` (a stored XSS, for instance: the judge weighs it).

Hostile input: the hunter writes the proof. Headers that carry an identity, a session or another method or host
(X-BH-Identity, Cookie, Authorization, Host, X-HTTP-Method-Override...) are refused: the identity is `as` only.
A regex runs in a child process with a timeout, and one that can backtrack (nested quantifiers, an alternation
under a quantifier) is refused when the proof is written.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from urllib.parse import unquote_plus, urljoin, urlsplit

from bh.agent import contract as c
from bh.agent.browse import xss_confirmed

ROLES = ("setup", "attack", "control")
METHODS = ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE")
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
TIMED_KEYS = ("elapsed_ms_min", "elapsed_ms_max")
EXPECT_KEYS = ("status", "contains", "absent", "regex", *TIMED_KEYS)
# the timing recipe (T26); the same numbers as bh.classes.TIMED_MEASURES / MAX_ELAPSED_MS (only bh/agent is in the
# sandbox, so they are repeated here and a test keeps them equal)
TIMED_MEASURES, MAX_ELAPSED_MS = 3, 10_000
MAX_HOPS = 10  # HTTP redirects followed in a browse step's har.json
_SLEEP = re.compile(r"\b(?:pg_)?sleep\s*\(\s*(\d+(?:\.\d+)?)", re.I)
_WAITFOR = re.compile(r"waitfor\s+delay\s+'(\d+):(\d+):(\d+(?:\.\d+)?)'", re.I)
_HEAVY = re.compile(r"\bbenchmark\s*\(|\bgenerate_series\s*\(|\brandomblob\s*\(", re.I)
MAX_STEPS, TIMEOUT_S, ROUNDS, SNIPPET, MAX_REGEX = 8, 20, 2, 300, 200
BROWSE_TIMEOUT_S = 90  # one rendered page through the gate (17-40 s measured on the lab)
REGEX_TIMEOUT_S = 5  # one regex search on one answer (at most 1 MiB), in a child process
MAX_SUMMARY = 1 << 20
_MARKER = re.compile(r"[A-Za-z0-9_]{4,32}")
# headers a step may not set: the identity goes through `as` only (the gate injects its session); no host or
# method switch behind the method and URL the control is compared on
FORBIDDEN_HEADERS = frozenset(
    h.lower()
    for h in (
        c.IDENTITY_HEADER,
        "Host",
        "Cookie",
        "Authorization",
        "X-HTTP-Method-Override",
        "X-Method-Override",
        "X-HTTP-Method",
    )
)
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}")
_HEADER_VALUE = re.compile(r"[\x20-\x7e\t]{0,4096}")
_REGEX_CHILD = "import re, sys\nbody = sys.stdin.read()\nsys.exit(0 if re.search(sys.argv[1], body) else 1)\n"
REGEX_TIMED_OUT = "regex timed out"


def validate(proof: object) -> list[str]:
    """Human-readable problems; empty when the proof can be replayed."""
    if not isinstance(proof, dict) or not isinstance(proof.get("steps"), list):
        return ['a proof is {"steps": [...]}']
    steps = proof["steps"]
    errors = []
    if not 2 <= len(steps) <= MAX_STEPS:
        errors.append(f"2 to {MAX_STEPS} steps")
    for i, st in enumerate(steps):
        where = f"step {i + 1}"
        if not isinstance(st, dict):
            errors.append(f"{where}: must be an object")
            continue
        if st.get("role") not in ROLES:
            errors.append(f"{where}: role must be one of {', '.join(ROLES)}")
        if str(st.get("method", "GET")).upper() not in METHODS:
            errors.append(f"{where}: method not allowed")
        if c.origin(str(st.get("url", ""))) is None:
            errors.append(f"{where}: url must be an absolute http(s) URL")
        if "$" in str(st.get("url", "")):
            errors.append(f"{where}: url contains an unresolved shell variable")
        errors += [f"{where}: {e}" for e in _header_problems(st.get("headers"))]
        if str(st.get("method", "GET")).upper() in c.IDENTITY_ONLY_METHODS and not st.get("as"):
            errors.append(
                f"{where}: the gate refuses PUT/PATCH/DELETE without an identity, so this step can never run; "
                "use another identity (user-b) as the control, not an anonymous request"
            )
        if "browse" in st:
            b = st["browse"]
            if not isinstance(b, dict) or set(b) - {"xss", "final_url"} or len(b) > 1:
                errors.append(f'{where}: browse is {{}}, {{"xss": "<marker>"}} or {{"final_url": "<prefix>"}}')
            elif "xss" in b and not _MARKER.fullmatch(str(b["xss"])):
                errors.append(f"{where}: the xss marker is 4-32 characters of [A-Za-z0-9_]")
            elif "final_url" in b:
                errors += [f"{where}: {e}" for e in _prefix_problems(b["final_url"], str(st.get("url", "")))]
            if str(st.get("method", "GET")).upper() != "GET":
                errors.append(f"{where}: a browse step is a GET (a page load)")
        exp = st.get("expect")
        if not isinstance(exp, dict) or not set(exp) & set(EXPECT_KEYS) or set(exp) - set(EXPECT_KEYS):
            errors.append(f"{where}: expect needs at least one of {', '.join(EXPECT_KEYS)} and nothing else")
        else:
            if any(not str(n) for k in ("contains", "absent") for n in (exp.get(k) or [])) or exp.get("regex") == "":
                errors.append(f"{where}: empty marker (an empty string matches every answer)")
            timed = "elapsed_ms_min" in exp
            if st.get("role") == "attack" and not (
                exp.get("contains") or exp.get("absent") or exp.get("regex") or timed
            ):
                errors.append(
                    f"{where}: an attack must name a body marker (contains, absent or regex) or a delay "
                    "(elapsed_ms_min), not a status"
                )
            errors += [f"{where}: {e}" for e in _timing_problems(st, exp)]
            if "regex" in exp:
                rx = str(exp["regex"])
                try:
                    re.compile(rx)
                except re.error as exc:
                    errors.append(f"{where}: bad regex: {exc}")
                if len(rx) > MAX_REGEX or backtracks(rx):
                    errors.append(
                        f"{where}: regex too long, or with a quantified group holding a quantifier or an "
                        "alternation ((a+)+, (a|ab)*); use contains instead"
                    )
    roles = [st.get("role") for st in steps if isinstance(st, dict)]
    if "attack" not in roles:
        errors.append("at least one step must have role 'attack' (the request that proves the impact)")
    if "control" not in roles:
        errors.append("at least one step must have role 'control' (the refused or benign twin of the attack)")
    attacks = [st for st in steps if isinstance(st, dict) and st.get("role") == "attack"]
    errors += _timed_proof_problems(steps, attacks)
    for i, st in enumerate(steps):
        if not isinstance(st, dict) or st.get("role") != "control":
            continue
        if any(st.get("expect") == a.get("expect") for a in attacks):
            errors.append("a control must expect something different from the attack")
        if not any(_twins(a, st) for a in attacks):
            errors.append(
                f"step {i + 1}: a control is the twin of an attack (same method, origin and path; only the "
                "identity, query or body change)"
            )
    return errors


def _ms(value: object) -> int | None:
    """A timing bound: a whole number of milliseconds, 1 to MAX_ELAPSED_MS; None otherwise."""
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_ELAPSED_MS:
        return None
    return value


def _timing_problems(st: dict, exp: dict) -> list[str]:
    """One step's timing bounds (T26): whole milliseconds up to 10 s, the minimum on an attack only, never on a
    browse step (a page load times the browser, not the query)."""
    errors = []
    for k in TIMED_KEYS:
        if k in exp and _ms(exp[k]) is None:
            errors.append(
                f"{k} is a whole number of milliseconds, 1 to {MAX_ELAPSED_MS} (no recipe waits more than "
                f"{MAX_ELAPSED_MS // 1000} s per request)"
            )
    if "elapsed_ms_min" in exp and st.get("role") != "attack":
        errors.append("elapsed_ms_min goes on an attack (the delayed request); its control says elapsed_ms_max")
    if set(exp) & set(TIMED_KEYS) and "browse" in st:
        errors.append("a browse step is not timed (a page load measures the browser)")
    if "elapsed_ms_min" in exp:
        errors += _delay_problems(st)
    return errors


def _delay_problems(st: dict) -> list[str]:
    """The delay a timed attack writes in its payload: at most MAX_ELAPSED_MS; a heavy query is refused."""
    body = st.get("body")
    text = (
        unquote_plus(str(st.get("url", "")))
        + "\n"
        + (json.dumps(body) if isinstance(body, (dict, list)) else str(body or ""))
    )
    errors = []
    if _HEAVY.search(text):
        errors.append("a heavy query (BENCHMARK, generate_series, randomblob) loads the target: use a sleep")
    seconds = [float(m.group(1)) for m in _SLEEP.finditer(text)]
    seconds += [int(h) * 3600 + int(m) * 60 + float(sec) for h, m, sec in _WAITFOR.findall(text)]
    if any(x * 1000 > MAX_ELAPSED_MS for x in seconds):
        errors.append(f"the payload waits more than {MAX_ELAPSED_MS // 1000} s")
    return errors


def _timed_proof_problems(steps: list, attacks: list[dict]) -> list[str]:
    """A timed proof (T26): at least TIMED_MEASURES delayed attacks, each with a twin control without the delay
    whose elapsed_ms_max is below the attack's elapsed_ms_min."""
    timed = [a for a in attacks if isinstance(a.get("expect"), dict) and _ms(a["expect"].get("elapsed_ms_min"))]
    if not timed:
        return []
    errors = []
    if len(timed) < TIMED_MEASURES:
        errors.append(
            f"a timed proof has at least {TIMED_MEASURES} delayed attacks (elapsed_ms_min), not {len(timed)}: one slow "
            "answer is the network"
        )
    controls = [
        s
        for s in steps
        if isinstance(s, dict)
        and s.get("role") == "control"
        and isinstance(s.get("expect"), dict)
        and _ms(s["expect"].get("elapsed_ms_max"))
    ]
    for a in timed:
        low = a["expect"]["elapsed_ms_min"]
        if not any(_twins(a, k) and k["expect"]["elapsed_ms_max"] < low for k in controls):
            errors.append(
                "a delayed attack needs a twin control without the delay (same route, no sleep) whose elapsed_ms_max "
                "is below the attack's elapsed_ms_min"
            )
            break
    return errors


def _prefix_problems(prefix: object, step_url: str) -> list[str]:
    """The prefix of an open-redirect step: an absolute http(s) URL with a path, no query or fragment, on another
    origin than the step (the payload host the redirect should not reach)."""
    if not isinstance(prefix, str) or len(prefix) > 500 or any(ch.isspace() for ch in prefix):
        return ["final_url is an absolute URL prefix (https://<payload host>/<path>)"]
    parts = urlsplit(prefix)
    if c.origin(prefix) is None or not parts.path.startswith("/") or parts.query or parts.fragment:
        return ["final_url is https://<host>/<path>: a path (at least /), no query, no fragment"]
    if c.origin(prefix) == c.origin(step_url):
        return ["final_url is on another origin than the step: a redirect inside the site is not open"]
    return []


def _header_problems(headers: object) -> list[str]:
    if headers is None:
        return []
    if not isinstance(headers, dict):
        return ["headers is an object {name: value}"]
    errors = []
    for k, v in headers.items():
        name = str(k)
        if not _HEADER_NAME.fullmatch(name) or not isinstance(v, (str, int, float)):
            errors.append(f"header {name[:40]!r}: a token name and a string value")
        elif not _HEADER_VALUE.fullmatch(str(v)):
            errors.append(f"header {name}: printable value, at most 4096 characters")
        elif name.lower() in FORBIDDEN_HEADERS:
            errors.append(
                f"header {name} is not allowed in a proof: the identity is `as` (the gate injects its session), "
                "the method and URL are the step's own"
            )
    return errors


def backtracks(rx: str) -> bool:
    """A quantified group (+, *, {n,}) whose content holds a quantifier or an alternation, at any depth:
    (a+)+, (x*)*, (a|a)+, (a|ab)*, ((a|b)c)+. Escapes and character classes are skipped. Conservative: a
    harmless (GET|POST)+ is refused too; `contains` says the same thing."""
    stack: list[bool] = []  # per open group: does it hold a quantifier or an alternation?
    i, n = 0, len(rx)
    while i < n:
        ch = rx[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "[":
            j = i + 1
            if j < n and rx[j] == "^":
                j += 1
            if j < n and rx[j] == "]":
                j += 1
            while j < n and rx[j] != "]":
                j += 2 if rx[j] == "\\" else 1
            i = j + 1
            continue
        if ch == "(":
            stack.append(False)
        elif ch == ")":
            risky = stack.pop() if stack else False
            nxt = rx[i + 1 : i + 2]
            unbounded = nxt in ("+", "*") or bool(re.match(r"\{\d*,", rx[i + 1 :]))
            if risky and unbounded:
                return True
            if stack:
                stack[-1] = stack[-1] or risky or nxt in ("+", "*", "{", "?")
        elif stack and (ch in "+*{|" or (ch == "?" and rx[i - 1] != "(")):  # `(?` opens an extension
            stack[-1] = True
        i += 1
    return False


def _search(rx: str, body: str) -> bool | None:
    """re.search in a child process killed after REGEX_TIMEOUT_S: True, False, or None (timed out or failed)."""
    try:
        p = subprocess.run(
            [sys.executable, "-I", "-c", _REGEX_CHILD, rx],
            input=body,
            capture_output=True,
            text=True,
            timeout=REGEX_TIMEOUT_S,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    return {0: True, 1: False}.get(p.returncode)


def _twins(attack: dict, control: dict) -> bool:
    """Same method and same origin + path: the control asks the same thing, refused or benign."""

    def where(st: dict) -> tuple[str, str | None, str]:
        url = str(st.get("url", ""))
        return str(st.get("method", "GET")).upper(), c.origin(url), urlsplit(url).path.rstrip("/") or "/"

    return where(attack) == where(control)


def _expect_holds(exp: dict, status: int, body: str, elapsed_ms: int | None = None) -> tuple[bool, list[str]]:
    misses = []
    for k, slow in (("elapsed_ms_min", True), ("elapsed_ms_max", False)):
        if k not in exp:
            continue
        if elapsed_ms is None:
            misses.append(f"{k}: the answer was not timed")
        elif (elapsed_ms < int(exp[k])) if slow else (elapsed_ms > int(exp[k])):
            misses.append(f"{elapsed_ms} ms, {k} {exp[k]}")
    if "status" in exp and status not in [
        int(s) for s in (exp["status"] if isinstance(exp["status"], list) else [exp["status"]])
    ]:
        misses.append(f"status {status} not in {exp['status']}")
    for needle in exp.get("contains") or []:
        if str(needle) not in body:
            misses.append(f"missing {str(needle)[:60]!r}")
    for needle in exp.get("absent") or []:
        if str(needle) in body:
            misses.append(f"present {str(needle)[:60]!r}")
    if exp.get("regex"):
        found = _search(str(exp["regex"]), body)
        if found is None:
            misses.append(REGEX_TIMED_OUT)
        elif not found:
            misses.append(f"regex {str(exp['regex'])[:60]!r} did not match")
    return not misses, misses


def marker_kind(step: dict) -> str | None:
    """`fresh` when the replay can swap the step's xss marker (it sits as is in the URL or the body),
    `hunter-chosen` otherwise; None for a step without a marker."""
    marker = (step.get("browse") or {}).get("xss") if isinstance(step.get("browse"), dict) else None
    if not marker:
        return None
    body = step.get("body")
    text = str(step.get("url", "")) + "\n" + (json.dumps(body) if isinstance(body, (dict, list)) else str(body or ""))
    return "fresh" if str(marker) in text else "hunter-chosen"


def fresh_marker() -> str:
    return "bh" + secrets.token_hex(8)  # 18 characters of [a-z0-9]: a valid bh-browse marker


def _browse(step: dict) -> tuple[int, str, bool]:
    """A rendered page (bh-browse, through the gate like every builtin): (status, canonical body, refused).
    The text bh-browse prints is never read: it carries the URL, the title and the console."""
    exe = shutil.which("bh-browse") or "/opt/bh/bin/bh-browse"
    url = str(step["url"])
    prefix = (step.get("browse") or {}).get("final_url")
    marker = (step.get("browse") or {}).get("xss")
    ran = str(marker) if marker else None
    if marker and marker_kind(step) == "fresh":
        ran = fresh_marker()
        url = url.replace(str(marker), ran)  # a browse step is a GET: the URL is all that is sent
    cmd = [exe, url, "--timeout", str(BROWSE_TIMEOUT_S - 10)]
    if step.get("as"):
        cmd += ["--as", str(step["as"])]
    if ran:
        cmd += ["--xss", ran]
    # the replay runs as the judge, whose HOME and default work dir may not exist or be writable: bh-browse
    # gets a throwaway work dir (raw files) and HOME (Chromium profile, gate CA) of its own
    with tempfile.TemporaryDirectory(prefix="bh-replay-") as tmp:
        env = {**os.environ, "BH_DIR": f"{tmp}/bh", "HOME": f"{tmp}/home"}
        Path(env["HOME"]).mkdir()
        subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=BROWSE_TIMEOUT_S, env=env, cwd=tmp
        )
        raw = _browse_raw(Path(env["BH_DIR"]) / c.RAW)
        summary = _read_summary(raw / "summary.json")
        if prefix:
            final = summary.get("final_url") if isinstance(summary.get("final_url"), str) else None
            if final is None:
                try:
                    final = har_final(json.loads(_read_text(raw / "har.json") or "null"), url)
                except ValueError:
                    final = None
            return (*redirect_body(summary, str(prefix), final), False)
        dom = "" if marker else _read_text(raw / "dom.html")
    status, body = browse_body(summary, str(marker) if marker else None, dom, c.origin(str(step["url"])), ran)
    return status, body, False


def reached(final: str | None, prefix: str) -> bool:
    """The navigation ended under `prefix`: same origin (contract.origin), path starting with the prefix's path."""
    if not isinstance(final, str) or c.origin(final) is None or c.origin(final) != c.origin(prefix):
        return False
    return urlsplit(final).path.startswith(urlsplit(prefix).path)


def redirect_body(summary: dict, prefix: str, final: str | None) -> tuple[int, str]:
    """(status, canonical line) of an open-redirect step: decided here, the URL itself never reaches the body."""
    st = summary.get("status")
    status = st if isinstance(st, int) and not isinstance(st, bool) and 100 <= st <= 599 else 0
    word = "CONFIRMED" if reached(final, prefix) else "none"
    return status, f"redirect {word} (prefix {prefix})"


def har_final(har: object, start: str) -> str | None:
    """Where the HTTP redirects starting at `start` led, from bh-browse's har.json: the Location (`redirectURL`) of
    each answer, followed MAX_HOPS times at most. The last URL is returned even when the browser never loaded it (a
    host outside the scope, refused). None when `start` is not in the file. Script and meta redirects are not seen
    here: summary.json's `final_url` covers them when bh-browse writes it."""
    entries = (har.get("log") or {}).get("entries") if isinstance(har, dict) else None
    if not isinstance(entries, list):
        return None
    by_url: dict[str, str] = {}
    for e in entries:
        req = e.get("request") if isinstance(e, dict) else None
        resp = e.get("response") if isinstance(e, dict) else None
        if not isinstance(req, dict) or not isinstance(req.get("url"), str):
            continue
        loc = resp.get("redirectURL") if isinstance(resp, dict) else None
        if not loc and isinstance(resp, dict):
            loc = next(
                (
                    h.get("value")
                    for h in resp.get("headers") or []
                    if isinstance(h, dict) and str(h.get("name", "")).lower() == "location"
                ),
                None,
            )
        by_url.setdefault(req["url"].split("#")[0], loc if isinstance(loc, str) else "")
    url = start.split("#")[0]
    if url not in by_url:
        return None
    for _ in range(MAX_HOPS):
        loc = by_url.get(url)
        if not loc:
            return url
        url = urljoin(url, loc).split("#")[0]
    return url


def _browse_raw(root: Path) -> Path:
    found = sorted(root.glob("browse-*/summary.json")) if root.is_dir() else []
    if len(found) != 1:
        raise ValueError("bh-browse left no summary (killed, refused or crashed)")
    return found[0].parent


def _read_text(path: Path) -> str:
    try:
        with open(path, "rb") as fh:
            return fh.read(MAX_SUMMARY).decode("utf-8", "replace")
    except OSError:
        return ""


def _read_summary(path: Path) -> dict:
    try:
        doc = json.loads(_read_text(path) or "null")
    except ValueError:
        doc = None
    if not isinstance(doc, dict):
        raise ValueError("bh-browse summary.json is not an object")
    return doc


_ORIGIN = re.compile(r"https?://(\[[0-9a-f:.]+\]|[a-z0-9._-]+):\d{1,5}")


def browse_body(
    summary: dict, marker: str | None, dom: str = "", origin: str | None = None, ran: str | None = None
) -> tuple[int, str]:
    """(status, body) of a browse step, decided here from bh-browse's structured summary: with a marker, one
    canonical line (`xss CONFIRMED (marker m) origin=o` / `xss none (marker m)`); without, the rendered DOM.
    `origin`: contract.origin of the step's URL, the only origin the marker may show on (None: never confirmed).
    `ran`: the marker bh-browse was given (a fresh one, see marker_kind); the line names the proof's `marker`."""
    st = summary.get("status")
    status = st if isinstance(st, int) and not isinstance(st, bool) and 100 <= st <= 599 else 0
    if not marker:
        return status, dom
    confirmed = (
        isinstance(origin, str)
        and _ORIGIN.fullmatch(origin) is not None
        and xss_confirmed(
            ran or marker, summary.get("dialogs"), summary.get("sentinel"), origin, summary.get("sentinel_origin")
        )
    )
    if confirmed:
        return status, f"xss CONFIRMED (marker {marker}) origin={origin}"
    return status, f"xss none (marker {marker})"


def _send(step: dict) -> tuple[int, str, bool]:
    """One request through the environment's proxy (the gate): (status, body, refused by the gate). Redirects are
    not followed: a 302 is an answer. Only the gate sets X-BH-Gate (it strips the header from target answers)."""
    if problems := _header_problems(step.get("headers")):  # replay never trusts that validate ran
        raise ValueError(problems[0])
    headers = {str(k): str(v) for k, v in (step.get("headers") or {}).items()}
    if step.get("as"):
        headers[c.IDENTITY_HEADER] = str(step["as"])
    body = step.get("body")
    data = (json.dumps(body) if isinstance(body, (dict, list)) else str(body)).encode() if body is not None else None
    if isinstance(body, (dict, list)):
        headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(
        str(step["url"]), data=data, headers=headers, method=str(step.get("method", "GET")).upper()
    )

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=TIMEOUT_S) as resp:
            return resp.status, resp.read(1 << 20).decode("utf-8", "replace"), _gate_refused(resp.headers)
    except urllib.error.HTTPError as err:
        return err.code, (err.read(1 << 20) or b"").decode("utf-8", "replace"), _gate_refused(err.headers)


def _timed(step: dict) -> tuple[int, str, bool, int | None]:
    """A step's answer and, for a request (not a page load), the milliseconds it took, read through to the body."""
    if "browse" in step:
        return (*_browse(step), None)
    t0 = time.monotonic()
    status, body, denied = _send(step)
    return status, body, denied, int((time.monotonic() - t0) * 1000)


def _gate_refused(headers) -> bool:
    return (headers.get(c.GATE_HEADER) or "").lower() == "denied"


def replay(proof: dict, rounds: int = ROUNDS) -> dict:
    """{"reproduced": bool, "control_disproves": bool, "rounds": [[step results]]}."""
    results = []
    control_disproves = False
    for n in range(rounds):
        round_, answers = [], []
        for st in proof["steps"]:
            if n and (st["role"] == "setup" or str(st.get("method", "GET")).upper() not in SAFE_METHODS):
                continue  # a write creates state (a booking, an object): replaying it would collide (409), not prove
            try:
                status, body, denied, elapsed = _timed(st)
                answers.append((st, status, body, elapsed))
                ok, misses = _expect_holds(st["expect"], status, body, elapsed)
                res = {
                    "name": st.get("name", ""),
                    "role": st["role"],
                    "status": status,
                    "ok": ok and not denied,
                    "misses": misses + (["refused by the gate"] if denied else []),
                    "len": len(body),
                    "sha1": hashlib.sha1(body.encode()).hexdigest()[:12],
                    "snippet": body[:SNIPPET],
                }
                if elapsed is not None and set(st["expect"]) & set(TIMED_KEYS):
                    res["elapsed_ms"] = elapsed
                if "browse" in st and (kind := marker_kind(st)):
                    res["marker"] = kind
                round_.append(res)
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                round_.append(
                    {
                        "name": st.get("name", ""),
                        "role": st["role"],
                        "status": None,
                        "ok": False,
                        "misses": [f"request failed: {exc}"[:200]],
                    }
                )
        results.append(round_)
        # no differential: a control's answer already satisfies what its attack claims to prove
        for a in (st for st in proof["steps"] if st["role"] == "attack"):
            for k, status, body, elapsed in answers:
                if k["role"] != "control" or not _twins(a, k):
                    continue
                holds, misses = _expect_holds(a["expect"], status, body, elapsed)
                if holds or REGEX_TIMED_OUT in misses:  # undecided counts against the proof
                    control_disproves = True
    every = [s for r in results for s in r]
    reproduced = all(s["ok"] for s in every)
    return {
        "reproduced": reproduced and not control_disproves,
        "control_disproves": control_disproves,
        "rounds": results,
    }


def main(argv: list[str]) -> None:
    """bh-agent replay <proof.json>: prints the replay result as JSON."""
    if len(argv) != 1:
        sys.exit("usage: bh-agent replay <proof.json>")
    proof = json.loads(Path(argv[0]).read_text())
    if errors := validate(proof):
        print(json.dumps({"invalid": errors}))
        return
    print(json.dumps(replay(proof)))
