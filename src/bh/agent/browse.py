"""bh-browse: one headless Chromium per command, through the gate.

  bh-browse <url> [--as ID] [--shot] [--clip CSS] [--full]
            [--fill CSS=VALUE]... [--click CSS]... [--submit CSS]
            [--wait-for CSS|networkidle] [--routes] [--xss MARKER] [--timeout S]

Text first: the summary is at most 25 lines; DOM, ARIA snapshot, HAR, console, dialogs, routes and the
screenshot stay in raw/browse-<slug>-<ts>/. Read shot.png only to decide something.

Network: every request goes to the gate (proxy). Requests to a host outside the target host and its
subdomains are aborted locally (no network) and counted; so are source maps, /favicon.ico (404 guard),
and images/fonts/media unless a screenshot is asked. Websockets are refused locally (the gate refuses
them anyway) and counted. Service workers are blocked so every request shows in the HAR and at the gate.

Classification: a mapper; with --xss a scanner (refused when the program forbids scanners).
This is the only sandbox module that imports playwright, inside run(): bh-agent starts without it.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shlex
import signal
import struct
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from bh.agent import contract as c
import contextlib

SUMMARY_LINES = 25
LINE_CHARS = 240
DEFAULT_TIMEOUT = 120
VIEWPORT = {"width": 1024, "height": 768}
# On top of Playwright's own background-traffic switches (docs/research/09-vision-headless.md §2, §4.5).
TELEMETRY_ARGS = ("--no-pings", "--disable-domain-reliability")
HEAVY_TYPES = frozenset({"image", "font", "media"})
MARKER = re.compile(r"^[A-Za-z0-9_]{4,32}$")
# A payload may prove execution without a dialog: window.__bhxss = '<marker>'. A string, so that HTML injection
# alone (<a id=__bhxss>, named access on window gives an element) never confirms.
SENTINEL = "__bhxss"
# Links never followed by --routes: they change state.
RISKY_LINK = re.compile(r"log-?out|sign-?out|delete|remove|destroy|unsubscribe|reset|deactivate", re.I)
MAX_ROUTE_VISITS = 25
MARGIN_S = 8  # seconds kept at the end of the budget to write the artifacts
SELECTOR_ENGINE = re.compile(r"^(css|xpath|text|role|id|data-test(?:-?id)?|alt|placeholder|label|title)=")
A11Y_ROLES = ("heading", "textbox", "searchbox", "combobox", "button", "link", "checkbox")
A11Y_LINE = re.compile(rf'^\s*- ({"|".join(A11Y_ROLES)}) "([^"]*)"(?:[^:]*: (.*))?')

# Records URLs set by pushState/replaceState and hash changes (SPA routes), read back by --routes.
ROUTE_HOOK = """(() => {
  const seen = (window.__bhRoutes = window.__bhRoutes || []);
  const note = () => { try { seen.push(String(location.href)); } catch (e) {} };
  for (const k of ['pushState', 'replaceState']) {
    const orig = history[k];
    history[k] = function (...a) { const r = orig.apply(this, a); note(); return r; };
  }
  window.addEventListener('hashchange', note);
})();"""

FORMS_JS = """() => {
  const names = (root) => [...root.querySelectorAll('input,select,textarea')]
    .filter(e => e.type !== 'hidden' || e.name).map(e => e.name || e.id || e.type).filter(Boolean);
  const out = [...document.forms].map(f => ({
    id: f.id || f.getAttribute('name') || '', method: (f.getAttribute('method') || 'GET').toUpperCase(),
    action: f.getAttribute('action') ? f.action : '', fields: names(f)}));
  const loose = [...document.querySelectorAll('input,select,textarea')].filter(e => !e.form)
    .map(e => e.name || e.id || e.getAttribute('aria-label') || e.type).filter(Boolean);
  if (loose.length) out.push({id: '(no form)', method: '', action: '', fields: loose});
  return out;
}"""


# ------------------------------------------------------------------ arguments
def split_fill(spec: str) -> tuple[str, str]:
    """`CSS=VALUE`: the first `=` outside brackets and quotes, after an optional `engine=` selector prefix
    (`role=textbox[name="Email"]=a@b`)."""
    m = SELECTOR_ENGINE.match(spec)
    start = m.end() if m else 0
    depth, quote = 0, ""
    for i in range(start, len(spec)):
        ch = spec[i]
        if quote:
            quote = "" if ch == quote else quote
        elif ch in "\"'":
            quote = ch
        elif ch in "[(":
            depth += 1
        elif ch in "])":
            depth = max(0, depth - 1)
        elif ch == "=" and depth == 0 and i > 0:
            return spec[:i], spec[i + 1 :]
    raise argparse.ArgumentTypeError(f"--fill wants CSS=VALUE, got {spec!r}")


class _Step(argparse.Action):
    """--fill/--click/--submit run in command-line order: all go to one `steps` list."""

    def __call__(self, parser, namespace, values, option_string=None):
        value = values
        if self.dest == "fill":
            try:
                value = split_fill(str(values))
            except argparse.ArgumentTypeError as exc:
                parser.error(str(exc))
        namespace.steps = [*(getattr(namespace, "steps", None) or []), (self.dest, value)]


def _marker(value: str) -> str:
    if not MARKER.match(value):
        raise argparse.ArgumentTypeError("the marker is 4-32 characters of [A-Za-z0-9_]")
    return value


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bh-browse", description=__doc__.split("\n\n")[0], allow_abbrev=False)
    p.add_argument("url", help="page to load (https:// is assumed without a scheme)")
    p.add_argument("--as", dest="identity", help="identity name, sent as X-BH-Identity")
    p.add_argument("--shot", action="store_true", help="PNG of the 1024x768 viewport")
    p.add_argument("--clip", metavar="CSS", help="screenshot of one element (implies --shot)")
    p.add_argument("--full", action="store_true", help="full-page screenshot (implies --shot, costs more tokens)")
    p.add_argument("--fill", action=_Step, metavar="CSS=VALUE", help="fill a field (repeatable, in order)")
    p.add_argument("--click", action=_Step, metavar="CSS", help="click an element (repeatable, in order)")
    p.add_argument("--submit", action=_Step, metavar="CSS", help="click and wait for the network to settle")
    p.add_argument("--wait-for", metavar="CSS|networkidle", help="what to wait for after the load")
    p.add_argument("--routes", action="store_true", help="follow in-app links and record SPA routes")
    p.add_argument("--xss", type=_marker, metavar="MARKER", help="record dialogs; CONFIRMED only if MARKER is seen")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="seconds for the whole command")
    p.set_defaults(steps=[])
    return p


def parse_args(argv: list[str]) -> argparse.Namespace:
    a = parser().parse_args(argv)
    a.shot = a.shot or bool(a.clip) or a.full
    a.timeout = max(15, a.timeout)
    if "://" not in a.url:
        a.url = "https://" + a.url
    return a


def phase_kind(a: argparse.Namespace) -> str:
    """Program rules: payloads (--xss) make it a scanner, otherwise it only maps."""
    return "scanner" if a.xss else "mapper"


# ------------------------------------------------------------------ pure helpers
def same_site(url: str, host: str) -> bool:
    """The target host or one of its subdomains. URLs without a host (data:, blob:) never reach the network."""
    h = c.host_of(url).rstrip(".")
    if not h:
        return True
    host = host.lower().rstrip(".")
    return h == host or h.endswith("." + host)


def route_decision(url: str, resource_type: str, host: str, shot: bool) -> str | None:
    """Why a request is aborted locally, or None to let it go to the gate."""
    if not same_site(url, host):
        return "offsite"
    path = urlsplit(url).path
    if path.endswith(".map"):
        return "sourcemap"
    if path == "/favicon.ico":
        return "favicon"
    if resource_type in HEAVY_TYPES and not shot:
        return resource_type
    return None


def spa_route(url: str) -> tuple[str, list[str]] | None:
    """`#/path?x=1` (or `#!/path`) -> ("GET /#/path", ["x"]); None without a fragment route."""
    p = urlsplit(url)
    frag = p.fragment.removeprefix("!")
    if not frag.startswith("/"):
        return None
    fpath, _, fquery = frag.partition("?")
    return f"GET {c.path_key(p.path)}#{c.path_key(fpath)}", c.query_params("http://x/?" + fquery)


Seen = list[tuple[str, str, int | None]]  # (method, url, status)
Items = list[tuple[str, str, list[str], int | None]]  # (key, url, params, status)


def endpoint_items(urls: Seen, origin_: str) -> Items:
    """(method, url, status) -> (key, url, params, status) on the target origin; SPA routes keep their fragment."""
    out = []
    for method, url, status in urls:
        if c.origin(url) != origin_:
            continue
        if route := spa_route(url):
            out.append((route[0], url, route[1], status))
        if k := c.endpoint_key(url, method):
            out.append((k[1], url.split("#")[0], c.query_params(url), status))
    return out


def add_endpoints(d: Path, origin_: str, items: Items) -> list[str]:
    """New (origin, key) pairs go to endpoints.jsonl with source `browse`; returns their keys."""
    known = {(e.get("origin"), e.get("key")) for e in c.read_jsonl(d / c.ENDPOINTS)}
    recs = []
    for key, url, params, status in items:
        if (origin_, key) in known or c.STATIC_EXT.search(key.split("#")[0]):
            continue
        known.add((origin_, key))
        rec = {"origin": origin_, "key": key, "url": url, "params": sorted(set(params)), "status": status}
        recs.append({**rec, "source": "browse"})
    if recs:
        c.append_jsonl(d / c.ENDPOINTS, *recs)
    return [r["key"] for r in recs]


def xss_confirmed(marker: str | None, dialogs: list[dict], sentinel: str | None) -> bool:
    if not marker:
        return False
    return any(marker in str(d.get("message", "")) for d in dialogs) or sentinel == marker


def png_size(path: Path) -> tuple[int, int]:
    try:
        head = path.read_bytes()[:24]
        return struct.unpack(">II", head[16:24]) if head[:8] == b"\x89PNG\r\n\x1a\n" else (0, 0)
    except OSError:
        return 0, 0


def image_tokens(w: int, h: int) -> int:
    """Estimate for one image read: the long edge is cut to 1568 px and the area to ~1.15 MP, then w*h/750."""
    if not w or not h:
        return 0
    s = min(1.0, 1568 / max(w, h), math.sqrt(1_150_000 / (w * h)))
    return round(w * s * h * s / 750)


def a11y_summary(aria: str, limit: int = 8) -> list[str]:
    out = []
    for line in aria.splitlines():
        if m := A11Y_LINE.match(line):
            role, name, value = m.groups()
            if name or value:
                out.append(f'{role} "{name[:40]}"' + (f" = {value[:20]}" if value else ""))
        if len(out) >= limit:
            break
    return out


# ------------------------------------------------------------------ result and summary
@dataclass
class Result:
    url: str
    identity: str | None = None
    status: int | None = None
    title: str = ""
    seconds: float = 0.0
    state: str = "ok"
    error: str = ""
    final_url: str = ""
    requests: int = 0
    blocked: Counter = field(default_factory=Counter)  # offsite host or local reason -> count
    gate_denied: int = 0
    websockets: int = 0
    xhr: list[tuple[str, str, int | None]] = field(default_factory=list)  # (method, url, status)
    steps: list[str] = field(default_factory=list)
    dialogs: list[dict] = field(default_factory=list)
    marker: str | None = None
    sentinel: str | None = None
    console_errors: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    routes: list[str] = field(default_factory=list)
    new_keys: list[str] = field(default_factory=list)
    a11y: list[str] = field(default_factory=list)
    shot: tuple[str, int, int] | None = None
    raw: str = ""


def _short(url: str) -> str:
    p = urlsplit(url)
    return (p.path or "/") + (f"?{p.query}" if p.query else "") + (f"#{p.fragment}" if p.fragment else "")


def render(r: Result) -> list[str]:
    """The summary the model reads: at most SUMMARY_LINES lines, each at most LINE_CHARS characters."""
    who = f" as={r.identity}" if r.identity else ""
    status = r.status if r.status is not None else "no response"
    head = f'bh-browse {r.url}{who}: {status}, title "{r.title[:60]}", {r.seconds:.1f} s [{r.state}]'
    body: list[str] = []
    if r.error:
        body.append(f"error: {r.error}")
    if r.final_url and r.final_url != r.url:
        body.append(f"final url: {r.final_url}")
    n_blocked = sum(r.blocked.values())
    blocked = ", ".join(f"{k} ×{v}" for k, v in r.blocked.most_common(4))
    more = f", +{len(r.blocked) - 4} more" if len(r.blocked) > 4 else ""
    req = f"requests: {r.requests} (in scope {r.requests - n_blocked}, blocked locally {n_blocked}"
    req += f": {blocked}{more})" if n_blocked else ")"
    if r.gate_denied:
        req += f"; gate denied {r.gate_denied}"
    body.append(req)
    if r.websockets:
        body.append(f"websockets: {r.websockets} refused (the gate forbids them; socket.io may fall back to polling)")
    if r.xhr:
        shown = " · ".join(f"{m} {_short(u)} {s}" for m, u, s in r.xhr[:6])
        body.append(f"xhr: {shown}" + (f" (+{len(r.xhr) - 6} in raw har.json)" if len(r.xhr) > 6 else ""))
    body += [f"step: {s}" for s in r.steps[:4]]
    confirmed = xss_confirmed(r.marker, r.dialogs, r.sentinel)
    verdict = f"xss CONFIRMED (marker {r.marker})" if confirmed else ""
    if r.dialogs:
        shown = " · ".join(f'{d.get("type")}("{str(d.get("message", ""))[:40]}")' for d in r.dialogs[:3])
        body.append(f"dialogs: {len(r.dialogs)} — {shown}" + (f" ← {verdict}" if verdict else ""))
    if verdict and not r.dialogs:
        body.append(f"{verdict} via window.{SENTINEL}")
    if r.marker and not confirmed:
        body.append(f"xss: marker {r.marker} not seen (no dialog, no window.{SENTINEL}): not confirmed")
    if r.console_errors:
        body.append(f"console: {len(r.console_errors)} errors ({r.console_errors[0][:120]})")
    for f in r.forms[:3]:
        target = f" → {f.get('method') or 'GET'} {_short(f['action'])}" if f.get("action") else ""
        body.append(f"form {f.get('id') or '?'}: ({', '.join(f.get('fields', [])[:8])}){target}")
    if len(r.forms) > 3:
        body.append(f"forms: +{len(r.forms) - 3} in raw dom.html")
    routes = [k.split(" ", 1)[1] for k in r.new_keys if "#" in k]
    if routes:
        extra = f" (+{len(routes) - 10} in raw)" if len(routes) > 10 else ""
        body.append(f"new routes: {' '.join(routes[:10])}{extra}")
    if r.new_keys:
        body.append(f"new endpoints: {len(r.new_keys)} (endpoints.jsonl, source browse)")
    elif r.routes:
        body.append(f"routes: {len(r.routes)} seen, none new (raw routes.txt)")
    if r.a11y:
        body.append("a11y: " + " · ".join(r.a11y))
    if r.shot:
        path, w, h = r.shot
        body.append(f"shot: {path} {w}x{h} ≈ {image_tokens(w, h)} tokens (Read it only if needed)")
    budget = SUMMARY_LINES - 2  # headline + raw line
    if len(body) > budget:
        body = [*body[: budget - 1], f"... {len(body) - budget + 1} more lines in raw"]
    lines = [head[:LINE_CHARS], *("  " + b[: LINE_CHARS - 2] for b in body)]
    return [*lines, f"raw: {r.raw}/"]


# ------------------------------------------------------------------ browser
def _state_file(identity: str | None) -> Path:
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", identity or "anon")[:40]
    return c.bh_dir() / c.RAW / f"browse-state-{name}.json"


def _same_document(a: str, b: str) -> bool:
    pa, pb = urlsplit(a), urlsplit(b)
    return (pa.scheme, pa.netloc, pa.path, pa.query) == (pb.scheme, pb.netloc, pb.path, pb.query)


def run(a: argparse.Namespace, raw: Path, r: Result) -> None:
    try:
        from playwright.sync_api import Error as PwError
        from playwright.sync_api import TimeoutError as PwTimeout
        from playwright.sync_api import sync_playwright
    except ImportError:
        r.state, r.error = "error rc=127", "playwright is not installed in this image (rebuild the agent image)"
        return
    t0 = time.monotonic()
    deadline = t0 + a.timeout - MARGIN_S
    host = urlsplit(a.url).hostname or ""
    r.marker = a.xss

    def left_ms(cap: float | None = None) -> float:
        s = max(1.0, deadline - time.monotonic())
        return 1000 * (min(s, cap) if cap else s)

    def on_route(route) -> None:
        req = route.request
        why = route_decision(req.url, req.resource_type, host, a.shot)
        if why is None:
            route.continue_()
            return
        r.blocked[c.host_of(req.url) if why == "offsite" else why] += 1
        route.abort("blockedbyclient")

    sockets: list = []  # mocked (never connected); closed from the main flow: close() inside the handler hangs

    def on_ws(ws) -> None:
        r.websockets += 1
        sockets.append(ws)

    def refuse_sockets() -> None:
        while sockets:
            with contextlib.suppress(PwError):
                sockets.pop().close(code=1008, reason="bh: websockets are refused")

    def on_response(resp) -> None:
        req = resp.request
        if resp.headers.get(c.GATE_HEADER.lower()):
            r.gate_denied += 1
        if req.resource_type in ("xhr", "fetch"):
            r.xhr.append((req.method, resp.url, resp.status))

    console: list[str] = []

    def on_console(msg) -> None:
        line = f"{msg.type}: {msg.text}"
        console.append(line)
        if msg.type == "error" and "ERR_BLOCKED_BY_CLIENT" not in msg.text:  # our own local blocks
            r.console_errors.append(msg.text.splitlines()[0] if msg.text else "error")

    def on_pageerror(exc) -> None:
        console.append(f"pageerror: {exc}")
        r.console_errors.append(f"pageerror: {str(exc).splitlines()[0] if str(exc) else exc}")

    def on_dialog(dialog) -> None:
        rec = {"type": dialog.type, "message": dialog.message}
        r.dialogs.append(rec)
        c.append_jsonl(raw / "dialogs.jsonl", rec)
        with contextlib.suppress(PwError):
            dialog.dismiss()

    def settle(cap: float | None) -> None:
        refuse_sockets()
        with contextlib.suppress(PwTimeout):
            page.wait_for_load_state("networkidle", timeout=left_ms(cap))
        refuse_sockets()

    state_file = _state_file(a.identity)
    seen_urls: Seen = []
    browser = ctx = page = None
    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch(headless=True, proxy={"server": c.gate()}, args=list(TELEMETRY_ARGS))
            ctx = browser.new_context(
                viewport=VIEWPORT,
                service_workers="block",
                record_har_path=str(raw / "har.json"),
                extra_http_headers={c.IDENTITY_HEADER: a.identity} if a.identity else None,
                storage_state=str(state_file) if state_file.is_file() else None,
            )
            ctx.set_default_timeout(left_ms(30))
            ctx.route("**/*", on_route)
            ctx.route_web_socket(re.compile(r".*"), on_ws)
            ctx.on("request", lambda _req: setattr(r, "requests", r.requests + 1))
            ctx.on("response", on_response)
            if a.routes:
                ctx.add_init_script(ROUTE_HOOK)
            page = ctx.new_page()
            page.on("console", on_console)
            page.on("pageerror", on_pageerror)
            page.on("dialog", on_dialog)

            resp = page.goto(a.url, wait_until="domcontentloaded", timeout=left_ms())
            r.status = resp.status if resp else None
            if a.wait_for == "networkidle":
                settle(None)
            elif a.wait_for:
                page.wait_for_selector(a.wait_for, timeout=left_ms())
            else:
                settle(15)

            for i, (kind, value) in enumerate(a.steps, 1):
                try:
                    if kind == "fill":
                        page.fill(value[0], value[1], timeout=left_ms(20))
                    else:
                        page.click(value, timeout=left_ms(20))
                        settle(15 if kind == "submit" else 3)
                except PwError as exc:
                    sel = value[0] if kind == "fill" else value
                    r.steps.append(f"{i} --{kind} {sel} failed: {str(exc).splitlines()[0][:120]}")
                    r.state = f"error step {i}"
                    break

            if a.xss:
                page.wait_for_timeout(min(1500, left_ms()))
                r.sentinel = _sentinel(page, PwError)

            links = _links(page, PwError)
            seen_urls.append(("GET", page.url, r.status))
            if a.routes:
                seen_urls += _explore(page, links, host=host, deadline=deadline, err=PwError, settle=settle)
                if a.xss and r.sentinel != a.xss:
                    r.sentinel = _sentinel(page, PwError)
            seen_urls += [("GET", u, None) for u in links if same_site(u, host)]

            r.final_url = page.url
            r.title = page.title()
            (raw / "dom.html").write_text(page.content())
            try:
                aria = page.locator("body").aria_snapshot(timeout=left_ms(15))
                (raw / "aria.yml").write_text(aria)
                r.a11y = a11y_summary(aria)
            except PwError as exc:
                (raw / "aria.yml").write_text(f"# aria snapshot failed: {exc}\n")
            try:
                r.forms = page.evaluate(FORMS_JS)
            except PwError:
                r.forms = []
            if a.shot:
                shot = raw / "shot.png"
                if a.clip:
                    page.locator(a.clip).first.screenshot(path=str(shot), timeout=left_ms(20))
                else:
                    page.screenshot(path=str(shot), full_page=a.full, timeout=left_ms(20))
                r.shot = (str(shot), *png_size(shot))
            ctx.storage_state(path=str(state_file))
        except PwTimeout as exc:
            r.state, r.error = "partial (timeout)", str(exc).splitlines()[0][:200]
        except PwError as exc:
            r.state, r.error = "error rc=1", str(exc).splitlines()[0][:200]
        finally:
            r.seconds = time.monotonic() - t0
            for closing in (ctx, browser):  # closing the context writes the HAR
                if closing is not None:
                    with contextlib.suppress(PwError):
                        closing.close()
            (raw / "console.log").write_text("\n".join(console) + ("\n" if console else ""))
    r.routes = sorted({u for _, u, _ in seen_urls if same_site(u, host)})
    (raw / "routes.txt").write_text("\n".join(r.routes) + ("\n" if r.routes else ""))
    seen_urls += [(m, u, s) for m, u, s in r.xhr]
    for f in r.forms:
        if f.get("action"):
            seen_urls.append((f.get("method") or "GET", f["action"], None))
    origin_ = c.origin(a.url) or ""
    items = endpoint_items(seen_urls, origin_)
    form_fields = {f["action"].split("#")[0]: f.get("fields") or [] for f in r.forms if f.get("action")}
    items = [(k, u, p + form_fields.get(u, []), s) for k, u, p, s in items]
    r.new_keys = add_endpoints(c.bh_dir(), origin_, items)


def _sentinel(page, err) -> str | None:
    for frame in page.frames:
        try:
            v = frame.evaluate("n => (typeof window[n] === 'string' ? window[n] : null)", SENTINEL)
        except err:
            continue
        if v:
            return v
    return None


def _links(page, err) -> list[str]:
    try:
        return list(dict.fromkeys(page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")))
    except err:
        return []


def _explore(page, links: list[str], *, host: str, deadline: float, err, settle) -> Seen:
    """Visit in-app hash routes of the current document (no new page load), breadth first, without links that
    change state. Other same-site links are recorded, not visited."""
    found: Seen = []
    queue = [u for u in links if same_site(u, host)]
    visited: set[str] = {page.url}
    visits = 0
    while queue and visits < MAX_ROUTE_VISITS and time.monotonic() < deadline - 5:
        u = queue.pop(0)
        if u in visited or RISKY_LINK.search(u) or not spa_route(u) or not _same_document(u, page.url):
            continue
        visited.add(u)
        visits += 1
        try:
            page.evaluate("h => { location.href = h; }", u)
            settle(3)
            found.append(("GET", page.url, None))
            queue += [x for x in _links(page, err) if x not in visited and same_site(x, host)]
        except err:
            continue
    with contextlib.suppress(err):
        found += [("GET", x, None) for x in page.evaluate("() => window.__bhRoutes || []")]
    return found


# ------------------------------------------------------------------ CLI
def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    a = parse_args(argv)
    if phase_kind(a) == "scanner" and not c.scanners_allowed():
        sys.exit(f"{c.RULES_MARK} bh-browse --xss: this program forbids automated scanners")
    from bh.agent.tools import Job  # raw dir and origin check, same scheme as the other builtins

    job = Job("browse", a.url, a.identity, a.timeout)
    (job.raw / "cmd.txt").write_text(shlex.join(["bh-browse", *argv]) + "\n")
    r = Result(url=a.url, identity=a.identity, raw=str(job.raw))

    def hard_stop(_sig, _frm) -> None:  # the sync API can hang past its own timeouts: never past the budget
        print(f"bh-browse {a.url}: killed after {a.timeout + 30} s [error rc=124]\nraw: {job.raw}/", flush=True)
        os._exit(124)

    signal.signal(signal.SIGALRM, hard_stop)
    signal.alarm(a.timeout + 30)
    run(a, job.raw, r)
    signal.alarm(0)
    with open(job.raw / "summary.json", "w") as fh:
        json.dump({"status": r.status, "state": r.state, "new": r.new_keys, "dialogs": r.dialogs}, fh)
    if a.xss:
        c.record_touched(c.bh_dir(), [a.url], via="browse-xss")
    c.record_phase(c.bh_dir(), job.origin, "browse", status=r.state, count=len(r.new_keys), raw=str(job.raw))
    print("\n".join(render(r)))
    if r.state.startswith("error"):
        sys.exit(1)
