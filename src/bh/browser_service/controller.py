"""The browser controller, run in bh-browser (`python3 -m bh.browser_service serve`).

One process owns the display (Xvfb), the screen server (x11vnc, loopback), the Chromium (headful, persistent
profile, behind the gate) and one Playwright client attached over CDP (loopback). Two doors lead to it:

- the agent's API, HTTP on the sandbox network, `POST /op` with `Authorization: Bearer $BH_BROWSER_TOKEN`:
  goto, fill, click, press, text, wait, state, outline, attr, net, tabs, upload, frames, switch. Never cookies,
  storage, raw CDP, script evaluation or screenshots.
- the host's control socket (RUN_DIR, 0700): reached only by `podman exec -i ... host`, JSON on stdin:
  load_session, status, reset, human_done, human_viewing, fill_budget_reset, switch_refused, snapshot.

The browser is the distribution's Chromium as it ships: no flag that hides automation, no user agent of ours,
not headless. While a human challenge is on screen, click/fill/press/upload are refused: the agent never touches
it. While the operator has the screen open, the agent may only read (state, text, frames).

One account per profile: the profile holds a marker {program, identity} (PROFILE_ROOT/bh-identity.json), written
by load_session and removed by reset; load_session refuses another identity until a reset. The marker is what
state() and status report, so it survives a restart of the container.
"""

from __future__ import annotations

import base64
import collections
import contextlib
import hmac
import json
import mimetypes
import os
import queue
import re
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Protocol
from urllib.parse import urlsplit

from bh import redact
from bh.browser_service import (
    AGENT_OPS,
    API_PORT,
    CDP_PORT,
    CTL_SOCK,
    DISPLAY,
    FILLS_FILE,
    GATE_PROXY,
    HOST_OPS,
    MARKER_FILE,
    PROFILE_ROOT,
    SCREEN,
    TOKEN_ENV,
    VIEWING_OPS,
    VNC_PORT,
)
from bh.browser_service.detect import (
    REWRITE_FIND,
    REWRITE_REPLACE_MAX,
    challenge,
    frame_text,
    rewrite_client_frame,
    scrub,
    scrub_obj,
    scrub_url,
)

CHROMIUM = "/usr/bin/chromium"
TEXT_MAX = 8000  # head of the page text, the default of `text`
TAIL_MAX = 20_000  # `text --tail N`
TEXT_READ_MAX = 2_000_000  # what is read of the page before it is cut
OUTLINE_MAX = 12_000
ATTR_MAX = 4000
CSS_MAX = 300
FILL_MAX = 2000
URL_MAX = 2000
WAIT_MS_MAX = 30_000
STEP_TIMEOUT_MS = 15_000
GOTO_TIMEOUT_MS = 45_000
UPLOAD_MAX = 256 * 1024  # bytes of one uploaded file
UPLOAD_B64_MAX = 4 * ((UPLOAD_MAX + 2) // 3)
BODY_MAX = UPLOAD_B64_MAX + 16_384  # agent request (an upload is the largest)
CTL_MAX = 1_000_000  # host request (a session's cookies)
MAX_COOKIES = 300
NET_KEEP, NET_LAST = 500, 200  # requests kept, at most returned by one `net`
FRAMES_KEEP, FRAMES_LAST = 300, 200  # websocket frames kept, at most returned by one `frames`
REWRITE_TTL_DEFAULT, REWRITE_TTL_MAX = 180, 600  # seconds a ws-rewrite rule stays armed
PUMP_S = 0.02  # while a websocket is routed, how often the idle worker lets Playwright forward its frames
# Prompts are bounded in number, not only in size (MSRC: never a flood of prompts). Per segment (the host resets it
# at prepare) and per identity and UTC day (persisted in the profile volume, a reset does not clear it).
FILL_SEGMENT = 80
FILL_DAY = 200
VIEWING_TTL_S = 600  # the UI re-asserts "the operator is looking" while its screen is open
COOKIE_SECRET_MIN = 8  # live cookie values at least this long are scrubbed from every reply
NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,40}")
ATTR_RE = re.compile(r"[A-Za-z_:][-A-Za-z0-9_:.]{0,60}")
FILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _.()-]{0,99}")
COOKIE_NAME_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,1024}")
# Keys the agent may press: navigation and form keys. No function key (F12 is DevTools), no Ctrl/Alt chord.
KEYS = frozenset(
    {
        "Enter",
        "Tab",
        "Shift+Tab",
        "Escape",
        "Backspace",
        "Delete",
        "Space",
        "ArrowUp",
        "ArrowDown",
        "ArrowLeft",
        "ArrowRight",
        "Home",
        "End",
        "PageUp",
        "PageDown",
    }
)
HUMAN_NEEDED = (
    "a human challenge is on screen: the agent must not touch it. The operator is asked to solve it "
    "(bh browser view); poll state() until challenge.pending is false, or record the blocker and move on"
)
HUMAN_VIEWING = (
    'the operator has the screen open: only state, text and frames are accepted until he clicks "J\'ai fini" '
    "(then he only watches) or closes it; poll state() until human_viewing is false"
)
SWITCH_NOTE = (
    "the host wipes the profile and loads this identity within a few seconds (only a live identity of this program); "
    "cost: a new app session, so one more human challenge. Poll `bh-web state` until identity is the one asked"
)


class Refused(ValueError):
    """The request is not one this door accepts (unknown op, unknown field, bad value)."""


class HumanNeeded(RuntimeError):
    pass


class Conflict(RuntimeError):
    """The profile holds another account: a reset comes first."""


class BudgetSpent(RuntimeError):
    pass


# ---------------------------------------------------------------- request validation
def _str(v: Any, field: str, lo: int, hi: int) -> str:
    if not isinstance(v, str) or not lo <= len(v) <= hi:
        raise Refused(f"{field}: a string of {lo} to {hi} characters")
    return v


def _int(v: Any, field: str, lo: int, hi: int) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise Refused(f"{field}: an integer from {lo} to {hi}")
    return v


def _bool(v: Any, field: str) -> bool:
    if not isinstance(v, bool):
        raise Refused(f"{field}: true or false")
    return v


_LOCAL_HOST = re.compile(
    r"^(localhost|.*\.localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[?::1?\]?|\[?::ffff:.*|browser)$", re.I
)


def _url(v: Any) -> str:
    u = _str(v, "url", 8, URL_MAX)
    if not re.match(r"https?://[^/\s]", u, re.I) or any(c.isspace() for c in u):
        raise Refused("url: http(s) only (no file:, chrome:, data:, javascript:, view-source:)")
    host = urlsplit(u).hostname or ""
    if _LOCAL_HOST.match(host.rstrip(".")):
        raise Refused("url: the browser's own container is not a target")
    return u


def _css(v: Any) -> str:
    return _str(v, "css", 1, CSS_MAX)


def _key(v: Any) -> str:
    if v not in KEYS:
        raise Refused(f"key: one of {', '.join(sorted(KEYS))}")
    return v


def _name(v: Any, field: str) -> str:
    if not isinstance(v, str) or not NAME_RE.fullmatch(v):
        raise Refused(f"{field}: [A-Za-z0-9_.-]{{1,40}}")
    return v


def _attr(v: Any) -> str:
    if not isinstance(v, str) or not ATTR_RE.fullmatch(v):
        raise Refused("name: an attribute name ([A-Za-z_:][-A-Za-z0-9_:.]{0,60})")
    return v


def _file_name(v: Any) -> str:
    if not isinstance(v, str) or not FILE_RE.fullmatch(v) or ".." in v:
        raise Refused("name: a file name of 1 to 100 characters [A-Za-z0-9 _.()-], no path")
    return v


def _content(v: Any) -> bytes:
    s = _str(v, "content_b64", 0, UPLOAD_B64_MAX)
    try:
        data = base64.b64decode(s, validate=True)
    except ValueError:
        raise Refused("content_b64: standard base64") from None
    if len(data) > UPLOAD_MAX:
        raise Refused(f"content_b64: at most {UPLOAD_MAX} bytes once decoded")
    return data


def _cookies(v: Any) -> list[dict[str, Any]]:
    if not isinstance(v, list) or len(v) > MAX_COOKIES:
        raise Refused(f"cookies: a list of at most {MAX_COOKIES}")
    out = []
    for c in v:
        if not isinstance(c, dict) or not COOKIE_NAME_RE.fullmatch(str(c.get("name"))):
            raise Refused("cookies: each one needs a valid name")
        if not isinstance(c.get("value"), str) or len(c["value"]) > 4096:
            raise Refused("cookies: value must be a string of at most 4096 characters")
        k = {"name": c["name"], "value": c["value"], "secure": c.get("secure") is True}
        if isinstance(c.get("url"), str):
            k["url"] = _url(c["url"])
        elif isinstance(c.get("domain"), str) and re.fullmatch(r"\.?[A-Za-z0-9.-]{1,253}", c["domain"]):
            k["domain"] = c["domain"]
            k["path"] = c["path"] if isinstance(c.get("path"), str) and c["path"].startswith("/") else "/"
        else:
            raise Refused("cookies: each one needs a url or a domain")
        exp = c.get("expires")
        if isinstance(exp, (int, float)) and not isinstance(exp, bool) and exp > 0:
            k["expires"] = float(exp)
        out.append(k)
    return out


def _secrets(v: Any) -> list[str]:
    if not isinstance(v, list) or len(v) > 1000 or not all(isinstance(s, str) and len(s) <= 8192 for s in v):
        raise Refused("secrets: a list of strings")
    return v


# op -> {field: (required, validator)}
SPEC: dict[str, dict[str, tuple[bool, Any]]] = {
    "goto": {"url": (True, _url)},
    "fill": {"css": (True, _css), "text": (True, lambda v: _str(v, "text", 0, FILL_MAX))},
    "click": {"css": (True, _css)},
    "press": {"key": (True, _key)},
    "text": {"css": (False, _css), "tail": (False, lambda v: _int(v, "tail", 1, TAIL_MAX))},
    "wait": {"css": (False, _css), "ms": (False, None)},
    "state": {},
    "outline": {"css": (False, _css)},
    "attr": {"css": (True, _css), "name": (True, _attr)},
    "net": {"last": (False, lambda v: _int(v, "last", 1, NET_LAST)), "denied": (False, lambda v: _bool(v, "denied"))},
    "tabs": {"select": (False, lambda v: _int(v, "select", 0, 50))},
    "upload": {"css": (True, _css), "name": (True, _file_name), "content_b64": (True, _content)},
    "frames": {"last": (False, lambda v: _int(v, "last", 1, FRAMES_LAST))},
    "switch": {"identity": (True, lambda v: _name(v, "identity"))},
    "ws_rewrite": {
        "find": (True, lambda v: _str(v, "find", *REWRITE_FIND)),
        "replace": (True, lambda v: _str(v, "replace", 0, REWRITE_REPLACE_MAX)),
        "url_contains": (False, lambda v: _str(v, "url_contains", 1, 120)),
        "ttl": (False, lambda v: _int(v, "ttl", 10, REWRITE_TTL_MAX)),
    },
    "load_session": {
        "program": (True, lambda v: _name(v, "program")),
        "identity": (True, lambda v: _name(v, "identity")),
        "cookies": (True, _cookies),
        "secrets": (False, _secrets),
    },
    "status": {},
    "reset": {"force": (False, lambda v: _bool(v, "force"))},
    "human_done": {},
    "human_viewing": {"on": (True, lambda v: _bool(v, "on"))},
    "fill_budget_reset": {},
    "snapshot": {},
    "switch_refused": {
        "identity": (True, lambda v: _name(v, "identity")),
        "reason": (True, lambda v: _str(v, "reason", 1, 200)),
    },
}


def validate(ops: frozenset[str], req: Any) -> tuple[str, dict[str, Any]]:
    """(op, arguments) of a request this door accepts. Raises Refused for anything else: an op outside `ops`
    (the agent asking for a host op, or for cookies, storage, CDP, eval, screenshot...), an unknown field, a bad
    value."""
    if not isinstance(req, dict) or not isinstance(req.get("op"), str):
        raise Refused('the request is a JSON object {"op": ...}')
    op = req["op"]
    if op not in ops or op not in SPEC:
        raise Refused(f"operation not allowed: {op[:40]!r}; allowed: {', '.join(sorted(ops))}")
    spec = SPEC[op]
    extra = set(req) - {"op"} - set(spec)
    if extra:
        raise Refused(f"{op}: unknown field(s) {', '.join(sorted(extra))[:120]}")
    args: dict[str, Any] = {}
    for field, (required, check) in spec.items():
        if field not in req:
            if required:
                raise Refused(f"{op}: missing {field}")
            continue
        args[field] = check(req[field]) if check else req[field]
    if op == "wait":
        if ("css" in args) == ("ms" in args):
            raise Refused("wait: exactly one of css or ms")
        if "ms" in args:
            ms = args["ms"]
            if isinstance(ms, bool) or not isinstance(ms, int) or not 0 <= ms <= WAIT_MS_MAX:
                raise Refused(f"wait: ms is an integer from 0 to {WAIT_MS_MAX}")
    return op, args


# ---------------------------------------------------------------- the controller (driver-agnostic)
class Driver(Protocol):
    def goto(self, url: str) -> None: ...
    def fill(self, css: str, text: str) -> None: ...
    def click(self, css: str) -> None: ...
    def press(self, key: str) -> None: ...
    def wait_css(self, css: str) -> None: ...
    def wait_ms(self, ms: int) -> None: ...
    def text(self, css: str | None = None) -> str: ...
    def outline(self, css: str | None = None) -> str: ...
    def attr(self, css: str, name: str) -> str | None: ...
    def upload(self, css: str, name: str, mime: str, data: bytes) -> None: ...
    def tabs(self) -> dict[str, Any]: ...
    def select_tab(self, index: int) -> None: ...
    def net(self) -> list[dict[str, Any]]: ...
    def frames(self) -> list[dict[str, Any]]: ...
    def ws_rewrite(self, find: str, replace: str, url_contains: str, ttl: int) -> dict[str, Any]: ...
    def cookie_values(self) -> list[str]: ...
    def snapshot(self) -> dict[str, Any]: ...
    def add_cookies(self, cookies: list[dict[str, Any]]) -> None: ...
    def wipe(self) -> None: ...


def _write_json(path: str, obj: Any) -> None:
    tmp = f"{path}.tmp.{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)
    os.replace(tmp, path)


class Controller:
    """Requests in, replies out. Every reply is scrubbed of the loaded session's values, of the cookies the
    browser holds now, and of JWTs; no reply ever carries a cookie, a storage value or a header.

    `store`: the directory of the identity marker and the fill budget (PROFILE_ROOT in the container). None keeps
    both in memory (tests)."""

    def __init__(
        self,
        driver: Driver,
        clock=time.time,
        store: str | None = None,
        fill_segment: int = FILL_SEGMENT,
        fill_day: int = FILL_DAY,
    ) -> None:
        self.driver = driver
        self.clock = clock
        self.store = store
        self.fill_segment, self.fill_day = fill_segment, fill_day
        self.secrets: set[str] = set()
        self.cookies_loaded = 0
        self.human_done: float | None = None
        self.pending_since: float | None = None
        self.cleared_at: float | None = None  # when the last challenge went away (the agent resumes after it)
        self.switch_requested: str | None = None
        self.switch_error: str | None = None
        self.viewing_until: float | None = None
        # "J'ai fini" with no challenge left: the open screen turns spectator (view-only in the UI) and the agent
        # goes on under the operator's eyes. A new challenge, a reset or the last screen closing ends it.
        self.watching = False
        self._mem: dict[str, Any] = {}  # marker and fills when there is no store

    def handle(self, ops: frozenset[str], req: Any) -> tuple[int, dict[str, Any]]:
        try:
            op, args = validate(ops, req)
        except Refused as exc:
            return 400, {"error": str(exc)}
        secrets = self._all_secrets()
        if op not in HOST_OPS and op not in VIEWING_OPS and self._viewing():
            out = {"error": "human-viewing", "detail": HUMAN_VIEWING, "state": self._state_dict()}
            return 409, scrub_obj(out, secrets)
        try:
            out = getattr(self, "_op_" + op)(**args)
        except HumanNeeded as exc:
            out = {"error": "human-needed", "detail": str(exc), "state": self._state_dict()}
            return 409, scrub_obj(out, secrets)
        except Conflict as exc:
            return 409, scrub_obj({"error": "profile-holds-another-identity", "detail": str(exc)}, secrets)
        except BudgetSpent as exc:
            return 429, scrub_obj({"error": "fill-budget", "detail": str(exc)}, secrets)
        except Exception as exc:  # noqa: BLE001 (a page error is the agent's information, never a crash)
            first = (str(exc).strip().splitlines() or [""])[0][:200]
            return 502, scrub_obj({"error": f"{op}: {type(exc).__name__}: {first}"}, secrets)
        return 200, scrub_obj(out, secrets | self._all_secrets())

    # -- persistent records (the profile volume)
    def _path(self, name: str) -> str | None:
        return os.path.join(self.store, name) if self.store else None

    def _read(self, name: str) -> Any:
        p = self._path(name)
        if p is None:
            return self._mem.get(name)
        try:
            with open(p, encoding="utf-8") as fh:
                return json.load(fh)
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            return {"corrupt": True}

    def _write(self, name: str, obj: Any) -> None:
        p = self._path(name)
        if p is None:
            if obj is None:
                self._mem.pop(name, None)
            else:
                self._mem[name] = obj
            return
        if obj is None:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(p)
            return
        os.makedirs(os.path.dirname(p), exist_ok=True)
        _write_json(p, obj)

    def marker(self) -> dict[str, Any] | None:
        """{program, identity, loaded_at} of the account the profile holds, None for an empty profile. A marker that
        cannot be read names an unknown account ("?"): nothing is loaded on top of it before a reset."""
        m = self._read(MARKER_FILE)
        if m is None:
            return None
        if not isinstance(m, dict) or not all(
            isinstance(m.get(k), str) and NAME_RE.fullmatch(m[k]) for k in ("program", "identity")
        ):
            return {"program": "?", "identity": "?", "loaded_at": None}
        return m

    @property
    def identity(self) -> dict[str, Any] | None:
        return self.marker()

    def _all_secrets(self) -> set[str]:
        """The host's list and the cookies the browser holds now (a cookie set after the load counts too)."""
        live: list[str] = []
        with contextlib.suppress(Exception):
            live = list(getattr(self.driver, "cookie_values", lambda: [])())
        return self.secrets | {v for v in live if isinstance(v, str) and len(v) >= COOKIE_SECRET_MIN}

    # -- fill budget
    def _day(self) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime(self.clock()))

    def _fills(self) -> dict[str, Any]:
        f = self._read(FILLS_FILE)
        if not isinstance(f, dict) or f.get("corrupt"):
            f = {}
        seg = f.get("segment") if isinstance(f.get("segment"), int) else 0
        day = self._day()
        days = {
            k: v
            for k, v in (f.get("days") or {}).items()
            if isinstance(v, dict) and v.get("day") == day and isinstance(v.get("n"), int)
        }
        return {"segment": seg, "days": days}

    def _who(self) -> str:
        m = self.marker()
        return m["identity"] if m else "-"

    def _fills_left(self) -> dict[str, int]:
        f = self._fills()
        used = (f["days"].get(self._who()) or {}).get("n", 0)
        return {"segment_left": max(0, self.fill_segment - f["segment"]), "day_left": max(0, self.fill_day - used)}

    def _check_fill(self) -> None:
        left = self._fills_left()
        if left["segment_left"] <= 0:
            raise BudgetSpent(
                f"{self.fill_segment} prompts typed this segment: the budget is spent. Read what you have "
                "(bh-web text --tail, bh-web frames) and work another surface; the next segment gets a new budget"
            )
        if left["day_left"] <= 0:
            raise BudgetSpent(
                f"{self.fill_day} prompts typed today as {self._who()}: the daily budget is spent (UTC day). "
                "Never flood the service: work an HTTP surface or another identity"
            )

    def _spend_fill(self) -> None:
        f = self._fills()
        who = self._who()
        f["segment"] += 1
        f["days"][who] = {"day": self._day(), "n": (f["days"].get(who) or {}).get("n", 0) + 1}
        self._write(FILLS_FILE, f)

    # -- helpers
    def _viewing(self) -> bool:
        """The operator has the screen in hand: the agent only reads. A spectator screen does not count."""
        return not self.watching and self._screen_open()

    def _screen_open(self) -> bool:
        return self.viewing_until is not None and self.clock() < self.viewing_until

    def _state_dict(self) -> dict[str, Any]:
        snap = self.driver.snapshot()
        ch = challenge(snap)
        if ch["pending"]:
            if self.pending_since is None:
                self.pending_since = self.clock()
                self.watching = False  # a new challenge: the screen is the operator's again
                print(f"bh-browser: human challenge on screen ({ch['reason']})", file=sys.stderr, flush=True)
        elif self.pending_since is not None:
            self.pending_since, self.cleared_at = None, self.clock()
            print("bh-browser: the human challenge is gone", file=sys.stderr, flush=True)
        m = self.marker()
        secrets = self._all_secrets()
        out = {
            "url": scrub_url(str(snap.get("url") or ""), secrets),
            "title": scrub(str(snap.get("title") or ""), secrets)[:200],
            "challenge": {**ch, "since": self.pending_since, "cleared_at": self.cleared_at},
            "human_done_at": self.human_done,
            "human_viewing": self._viewing(),
            "human_watching": self.watching and self._screen_open(),
            "identity": m["identity"] if m else None,
            "program": m["program"] if m else None,
            "switch_requested": self.switch_requested,
            "switch_error": self.switch_error,
            "fills": self._fills_left(),
        }
        if isinstance(snap.get("tabs"), int):
            out["tabs"] = {"count": snap["tabs"], "current": snap.get("tab")}
        return out

    def _guard(self) -> None:
        if challenge(self.driver.snapshot())["pending"]:
            raise HumanNeeded(HUMAN_NEEDED)

    # -- agent ops
    def _op_goto(self, url: str) -> dict[str, Any]:
        # a navigation during a challenge loses it, and the message already typed under it (which goes out by
        # itself once the operator passes the challenge): refused like click/fill/press
        self._guard()
        self.driver.goto(url)
        return self._state_dict()

    def _op_fill(self, css: str, text: str) -> dict[str, Any]:
        self._guard()
        self._check_fill()
        self.driver.fill(css, text)
        self._spend_fill()
        return {"ok": True, "fills": self._fills_left()}

    def _op_click(self, css: str) -> dict[str, Any]:
        self._guard()
        self.driver.click(css)
        return self._state_dict()

    def _op_press(self, key: str) -> dict[str, Any]:
        self._guard()
        self.driver.press(key)
        return self._state_dict()

    def _op_wait(self, css: str | None = None, ms: int | None = None) -> dict[str, Any]:
        if css is not None:
            self.driver.wait_css(css)
        else:
            self.driver.wait_ms(int(ms or 0))
        return self._state_dict()

    def _op_text(self, css: str | None = None, tail: int | None = None) -> dict[str, Any]:
        t = scrub(self.driver.text(css), self._all_secrets())
        if tail is not None:
            return {"text": t[-tail:], "truncated": len(t) > tail, "length": len(t), "from": "tail"}
        return {"text": t[:TEXT_MAX], "truncated": len(t) > TEXT_MAX, "length": len(t)}

    def _op_outline(self, css: str | None = None) -> dict[str, Any]:
        t = self.driver.outline(css)
        return {"outline": t[:OUTLINE_MAX], "truncated": len(t) > OUTLINE_MAX}

    def _op_attr(self, css: str, name: str) -> dict[str, Any]:
        v = self.driver.attr(css, name)
        return {
            "name": name,
            "value": None if v is None else v[:ATTR_MAX],
            "truncated": v is not None and len(v) > ATTR_MAX,
        }

    def _op_net(self, last: int = 50, denied: bool = False) -> dict[str, Any]:
        secrets = self._all_secrets()
        rows = [r for r in self.driver.net() if r.get("denied") or not denied][-last:]
        out = []
        for r in rows:
            row = {
                k: r.get(k) for k in ("t", "method", "status", "denied", "reason", "failure") if r.get(k) is not None
            }
            row["url"] = scrub_url(str(r.get("url") or ""), secrets)
            out.append(row)
        return {"requests": out, "count": len(out)}

    def _op_tabs(self, select: int | None = None) -> dict[str, Any]:
        if select is not None:
            self.driver.select_tab(select)
        t = self.driver.tabs()
        secrets = self._all_secrets()
        return {
            "current": t.get("current"),
            "tabs": [
                {"i": i, "url": scrub_url(str(p.get("url") or ""), secrets), "title": str(p.get("title") or "")[:120]}
                for i, p in enumerate(t.get("tabs") or [])
            ],
        }

    def _op_upload(self, css: str, name: str, content_b64: bytes) -> dict[str, Any]:
        self._guard()
        mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
        self.driver.upload(css, name, mime, content_b64)
        return {"ok": True, "name": name, "bytes": len(content_b64), "mime": mime}

    def _op_frames(self, last: int = 30) -> dict[str, Any]:
        secrets = self._all_secrets()
        out = []
        for f in self.driver.frames()[-last:]:
            # stored already filtered (frame_text at capture); scrubbed again with the session's values
            text = frame_text(str(f.get("text") or ""), secrets)
            if text is None:
                continue
            out.append(
                {"t": f.get("t"), "dir": f.get("dir"), "url": scrub_url(str(f.get("url") or ""), secrets), "text": text}
            )
        return {"frames": out, "count": len(out)}

    def _op_ws_rewrite(
        self, find: str, replace: str, url_contains: str = "/Chathub/", ttl: int = REWRITE_TTL_DEFAULT
    ) -> dict[str, Any]:
        """Arm ONE rewrite of the next client frame (sent by the page) that contains `find`, on a websocket opened
        after this call whose URL contains `url_contains`. One occurrence, then disarmed; a frame carrying a challenge
        answer is never touched (detect.rewrite_client_frame). Logged in `frames` (dir "rewrite") and on stderr."""
        print(
            f"bh-browser: ws-rewrite armed ({len(find)} -> {len(replace)} chars, "
            f"url contains {url_contains!r}, {ttl} s)",
            file=sys.stderr,
            flush=True,
        )
        return {"ok": True, **self.driver.ws_rewrite(find, replace, url_contains, ttl)}

    def _op_switch(self, identity: str) -> dict[str, Any]:
        m = self.marker()
        if m and m["identity"] == identity:
            return {"ok": True, "identity": identity, "note": "already the identity of the browser"}
        self.switch_requested, self.switch_error = identity, None
        print(f"bh-browser: the agent asks to switch to {identity}", file=sys.stderr, flush=True)
        return {"ok": True, "switch_requested": identity, "note": SWITCH_NOTE}

    def _op_state(self) -> dict[str, Any]:
        return self._state_dict()

    # -- host ops
    def _op_load_session(
        self, program: str, identity: str, cookies: list[dict[str, Any]], secrets: list[str] | None = None
    ) -> dict[str, Any]:
        m = self.marker()
        if m is not None and (m["program"], m["identity"]) != (program, identity):
            raise Conflict(
                f"the profile holds {m['program']}/{m['identity']}: reset it before loading {program}/{identity} "
                "(one account per profile)"
            )
        self.driver.add_cookies(cookies)
        self.secrets |= {c["value"] for c in cookies} | set(secrets or [])
        self._write(MARKER_FILE, {"program": program, "identity": identity, "loaded_at": self.clock()})
        self.cookies_loaded = len(cookies)
        if self.switch_requested == identity:
            self.switch_requested = None
        self.switch_error = None
        return {"ok": True, "program": program, "identity": identity, "cookies": len(cookies)}

    def _op_status(self) -> dict[str, Any]:
        return {**self._state_dict(), "cookies_loaded": self.cookies_loaded}

    def _op_reset(self, force: bool = False) -> dict[str, Any]:
        if not force:
            pending = False
            with contextlib.suppress(Exception):  # a browser that cannot answer is exactly what a reset repairs
                pending = challenge(self.driver.snapshot())["pending"]
            if pending:
                raise HumanNeeded(
                    "a human challenge is on screen: a reset would lose it and the message typed under it; "
                    "wait for the operator, or reset with force"
                )
        self._write(MARKER_FILE, None)  # first: a wipe that fails half-way never leaves a stale name
        self.driver.wipe()
        self.secrets.clear()
        self.cookies_loaded, self.human_done, self.pending_since = 0, None, None
        self.watching = False
        self.switch_requested = None
        return {"ok": True, "reset": True}

    def _op_human_done(self) -> dict[str, Any]:
        self.human_done = self.clock()
        pending = self._state_dict()["challenge"]["pending"]
        self.watching = not pending  # never hand the page back while a challenge is still on it
        print(
            "bh-browser: the operator says the challenge is done"
            + (" but it is still on screen" if pending else "; the screen is now a spectator"),
            file=sys.stderr,
            flush=True,
        )
        return {"ok": True, "human_done_at": self.human_done, "watching": self.watching, "challenge_pending": pending}

    def _op_human_viewing(self, on: bool) -> dict[str, Any]:
        self.viewing_until = self.clock() + VIEWING_TTL_S if on else None
        if not on:
            self.watching = False  # the next screen opened is the operator's hand again
        return {"ok": True, "human_viewing": self._viewing()}

    def _op_fill_budget_reset(self) -> dict[str, Any]:
        f = self._fills()
        f["segment"] = 0
        self._write(FILLS_FILE, f)
        return {"ok": True, "fills": self._fills_left()}

    def _op_snapshot(self) -> dict[str, Any]:
        """What detect.challenge() reads of the page (url, title, visible text head and tail, child frames), with
        its verdict: the host saves it as a test fixture (host.save_snapshot). Never the HTML: no hidden input (a
        Turnstile answer), no script, no attribute; and scrubbed like every reply."""
        snap = self.driver.snapshot()
        secrets = self._all_secrets()
        frames = [
            {"url": scrub_url(str(f.get("url") or ""), secrets), "visible": f.get("visible")}
            for f in snap.get("frames") or []
            if isinstance(f, dict)
        ]
        text = str(snap.get("text") or "")
        out = {
            "url": scrub_url(str(snap.get("url") or ""), secrets),
            "title": str(snap.get("title") or "")[:200],
            "text": text,
            "text_len": snap.get("text_len") if isinstance(snap.get("text_len"), int) else len(text),
            "frames": frames,
        }
        return {"snapshot": out, "challenge": challenge(out), "taken_at": self.clock()}

    def _op_switch_refused(self, identity: str, reason: str) -> dict[str, Any]:
        if self.switch_requested == identity:
            self.switch_requested = None
        self.switch_error = f"{identity}: {reason}"
        return {"ok": True}


# ---------------------------------------------------------------- processes of the container
def xvfb_argv() -> list[str]:
    w, h = SCREEN
    return ["Xvfb", DISPLAY, "-screen", "0", f"{w}x{h}x24", "-nolisten", "tcp"]


def x11vnc_argv() -> list[str]:
    # -localhost: 127.0.0.1 of the container only. No password: nothing outside the container reaches the port (the
    # host's only path is `podman exec`), and a web page cannot speak raw RFB to it.
    return [
        "x11vnc",
        "-display",
        DISPLAY,
        "-localhost",
        "-rfbport",
        str(VNC_PORT),
        "-forever",
        "-shared",
        "-nopw",
        "-quiet",
        "-noxdamage",
        # no clipboard either way: nothing the page copies reaches the operator's machine, nothing of his reaches
        # the page
        "-noclipboard",
        "-nosetclipboard",
    ]


def chromium_argv(profile: str, binary: str = CHROMIUM, proxy: str = GATE_PROXY) -> list[str]:
    """The distribution's Chromium as it ships. On purpose absent: --headless, --user-agent,
    --disable-blink-features (AutomationControlled), stealth extensions. `--no-sandbox`: Chromium's own sandbox
    needs user namespaces the hardened container does not give (the same as bh-login's Playwright launch)."""
    w, h = SCREEN
    return [
        binary,
        f"--user-data-dir={profile}",
        f"--remote-debugging-port={CDP_PORT}",  # headful Chromium binds it to 127.0.0.1
        f"--proxy-server={proxy}",
        "--proxy-bypass-list=<-loopback>",  # loopback via the gate too (refused): CDP, VNC, API unreachable
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-dev-shm-usage",
        "--no-sandbox",
        "--no-pings",
        "--disable-domain-reliability",
        "--password-store=basic",
        "--window-position=0,0",
        f"--window-size={w},{h}",
        "about:blank",
    ]


class Display:
    """Xvfb + x11vnc + Chromium, restarted when they die."""

    def __init__(self, profile_root: str = PROFILE_ROOT) -> None:
        self.profile = os.path.join(profile_root, "chromium")
        self.procs: dict[str, subprocess.Popen] = {}
        self.lock = threading.Lock()

    def _spawn(self, name: str, argv: list[str]) -> None:
        env = {**os.environ, "DISPLAY": DISPLAY}
        self.procs[name] = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, start_new_session=True)

    def _alive(self, name: str) -> bool:
        p = self.procs.get(name)
        return p is not None and p.poll() is None

    def _stop(self, name: str) -> None:
        p = self.procs.pop(name, None)
        if p and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=5)

    def _start_x(self) -> None:
        n = DISPLAY.lstrip(":")
        for leftover in (f"/tmp/.X{n}-lock", f"/tmp/.X11-unix/X{n}"):
            with contextlib.suppress(OSError):
                os.unlink(leftover)
        self._spawn("xvfb", xvfb_argv())
        end = time.monotonic() + 20
        while not os.path.exists(f"/tmp/.X11-unix/X{n}"):
            if time.monotonic() > end or not self._alive("xvfb"):
                raise RuntimeError("Xvfb did not start")
            time.sleep(0.2)

    def _start_chromium(self) -> None:
        os.makedirs(self.profile, mode=0o700, exist_ok=True)
        for f in ("SingletonLock", "SingletonSocket", "SingletonCookie"):  # left by an unclean stop
            with contextlib.suppress(OSError):
                os.unlink(os.path.join(self.profile, f))
        self._spawn("chromium", chromium_argv(self.profile))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        end = time.monotonic() + 40
        while True:
            try:
                with opener.open(f"http://127.0.0.1:{CDP_PORT}/json/version", timeout=2):
                    return
            except OSError:
                if time.monotonic() > end or not self._alive("chromium"):
                    raise RuntimeError("Chromium did not open its DevTools port") from None
                time.sleep(0.5)

    def ensure(self) -> None:
        with self.lock:
            if not self._alive("xvfb"):
                for n in ("chromium", "x11vnc"):
                    self._stop(n)
                self._start_x()
            if not self._alive("x11vnc"):
                self._spawn("x11vnc", x11vnc_argv())
            if not self._alive("chromium"):
                self._start_chromium()

    def wipe(self) -> None:
        with self.lock:
            self._stop("chromium")
            shutil.rmtree(self.profile, ignore_errors=True)
        self.ensure()

    def stop(self) -> None:
        with self.lock:
            for n in ("chromium", "x11vnc", "xvfb"):
                self._stop(n)


# ---------------------------------------------------------------- Playwright, attached over CDP
def snapshot_text(full: str, keep: int = 10_000) -> str:
    """Head and tail of a long page text: an interstitial's words are at the top, a chat's label under the last
    message is at the bottom."""
    return full if len(full) <= 2 * keep else full[:keep] + "\n…\n" + full[-keep:]


class PlaywrightDriver:
    """Attaches to the running Chromium (connect_over_cdp): Playwright launches nothing and changes no flag.
    Lives in one thread (the sync API is bound to the thread that started it).

    Tabs: the driven page is the one chosen (`tabs --select`), else the first open one. A popup never takes over
    silently: it is listed by `tabs`. Requests (all tabs) and websocket frames go to bounded buffers; a frame is
    filtered when it is captured (detect.frame_text), so a challenge answer or a token never sits in memory here."""

    def __init__(self, display: Display) -> None:
        self.display = display
        self.pw: Any = None
        self.browser: Any = None
        self.current: Any = None
        self.net_log: collections.deque = collections.deque(maxlen=NET_KEEP)
        self.frame_log: collections.deque = collections.deque(maxlen=FRAMES_KEEP)
        self.frames_dropped = 0
        self._seen_pages: set[int] = set()
        self._rule: dict[str, Any] | None = None  # bh-web ws-rewrite: one armed rewrite at most
        self._ws_routed = False
        self._routed_live = 0  # routed websockets still open (their frames need pumping)

    # -- connection and listeners
    def _context(self) -> Any:
        if self.browser is None or not self.browser.is_connected():
            self.display.ensure()
            if self.pw is None:
                from playwright.sync_api import sync_playwright

                self.pw = sync_playwright().start()
            self.browser = self.pw.chromium.connect_over_cdp(f"http://127.0.0.1:{CDP_PORT}", timeout=30_000)
            self.current, self._seen_pages = None, set()
            ctx = self.browser.contexts[0]  # the persistent profile's context
            ctx.on("page", self._attach)
            ctx.on("response", self._on_response)
            ctx.on("requestfailed", self._on_failed)
            for p in ctx.pages:
                self._attach(p)
            self._ws_routed = False
        return self.browser.contexts[0]

    def _attach(self, page: Any) -> None:
        if id(page) in self._seen_pages:
            return
        self._seen_pages.add(id(page))
        page.on("websocket", self._on_ws)

    def _on_response(self, resp: Any) -> None:
        with contextlib.suppress(Exception):
            req = resp.request
            denied = (resp.headers or {}).get("x-bh-gate") == "denied"
            rec = {"t": time.time(), "method": req.method, "url": resp.url, "status": resp.status, "denied": denied}
            if denied:
                rec["_resp"] = resp  # the reason is read later, outside the event (net)
            self.net_log.append(rec)

    def _on_failed(self, req: Any) -> None:
        with contextlib.suppress(Exception):
            failure = str(req.failure or "failed")[:120]
            self.net_log.append({"t": time.time(), "method": req.method, "url": req.url, "failure": failure})

    # -- bh-web ws-rewrite: only websockets opened while a rule is armed are routed through here
    def _rule_live(self) -> dict[str, Any] | None:
        r = self._rule
        return r if r and not r["used"] and time.time() < r["until"] else None

    def _ws_match(self, url: str) -> bool:
        r = self._rule_live()
        return bool(r) and r["url_contains"] in url

    def needs_pump(self) -> bool:
        return self._ws_routed and (self._routed_live > 0 or self._rule_live() is not None)

    def pump(self) -> None:
        self._page().wait_for_timeout(1)

    def _route_ws(self, route: Any) -> None:
        server = route.connect_to_server()
        url = route.url
        self._routed_live += 1
        closed = [False]

        def gone() -> None:
            if not closed[0]:
                closed[0] = True
                self._routed_live = max(0, self._routed_live - 1)

        def page_closed(code: Any = None, reason: Any = None) -> None:  # a close handler disables auto-forwarding
            gone()
            with contextlib.suppress(Exception):
                server.close(code=code, reason=reason or "")

        def server_closed(code: Any = None, reason: Any = None) -> None:
            gone()
            with contextlib.suppress(Exception):
                route.close(code=code, reason=reason or "")

        def from_page(message: Any) -> None:
            out, done = message, False
            r = self._rule_live()
            if r:
                out, done = rewrite_client_frame(message, r["find"], r["replace"])
            if done and r:
                r["used"] = True
                sizes = f"{len(r['find'])} -> {len(r['replace'])} chars"
                note = f"rewrote 1 occurrence ({sizes}) in a {len(message)}-char frame"
                self.frame_log.append({"t": time.time(), "dir": "rewrite", "url": redact.url(url), "text": note})
                print(f"bh-browser: ws-rewrite applied on {redact.url(url)[:80]}: {note}", file=sys.stderr, flush=True)
            self._frame("sent", url, out)  # what really left the browser (routed frames may not raise framesent)
            server.send(out)

        def from_server(message: Any) -> None:
            self._frame("recv", url, message)
            route.send(message)

        route.on_message(from_page)
        server.on_message(from_server)
        route.on_close(page_closed)
        server.on_close(server_closed)

    def ws_rewrite(self, find: str, replace: str, url_contains: str, ttl: int) -> dict[str, Any]:
        ctx = self._context()
        if not self._ws_routed:
            ctx.route_web_socket(self._ws_match, self._route_ws)
            self._ws_routed = True
        self._rule = {
            "find": find,
            "replace": replace,
            "url_contains": url_contains,
            "until": time.time() + ttl,
            "used": False,
        }
        return {
            "armed": True,
            "url_contains": url_contains,
            "expires_in": ttl,
            "applies_to": "websockets opened from now on",
        }

    def _on_ws(self, ws: Any) -> None:
        url = ws.url
        ws.on("framereceived", lambda payload: self._frame("recv", url, payload))
        ws.on("framesent", lambda payload: self._frame("sent", url, payload))

    def _frame(self, direction: str, url: str, payload: Any) -> None:
        text = frame_text(payload, frozenset())
        if text is None:
            self.frames_dropped += 1
            return
        self.frame_log.append({"t": time.time(), "dir": direction, "url": redact.url(url), "text": text})

    def _pages(self) -> list[Any]:
        return [p for p in self._context().pages if not p.is_closed()]

    def _page(self) -> Any:
        pages = self._pages()
        if self.current is not None and self.current in pages:
            return self.current
        self.current = pages[0] if pages else self._context().new_page()
        return self.current

    def _loc(self, css: str) -> Any:
        return self._page().locator("css=" + css).first

    # -- agent ops
    def goto(self, url: str) -> None:
        self._page().goto(url, wait_until="domcontentloaded", timeout=GOTO_TIMEOUT_MS)

    def fill(self, css: str, text: str) -> None:
        self._loc(css).fill(text, timeout=STEP_TIMEOUT_MS)

    def click(self, css: str) -> None:
        self._loc(css).click(timeout=STEP_TIMEOUT_MS)

    def press(self, key: str) -> None:
        self._page().keyboard.press(key)

    def wait_css(self, css: str) -> None:
        self._loc(css).wait_for(state="visible", timeout=STEP_TIMEOUT_MS)

    def wait_ms(self, ms: int) -> None:
        self._page().wait_for_timeout(ms)

    def text(self, css: str | None = None) -> str:
        return self._loc(css or "body").inner_text(timeout=STEP_TIMEOUT_MS)[:TEXT_READ_MAX]

    def outline(self, css: str | None = None) -> str:
        return self._loc(css or "body").aria_snapshot(timeout=STEP_TIMEOUT_MS)

    def attr(self, css: str, name: str) -> str | None:
        return self._loc(css).get_attribute(name, timeout=STEP_TIMEOUT_MS)

    def upload(self, css: str, name: str, mime: str, data: bytes) -> None:
        # in memory (FilePayload): no file is written in the container
        self._loc(css).set_input_files({"name": name, "mimeType": mime, "buffer": data}, timeout=STEP_TIMEOUT_MS)

    def tabs(self) -> dict[str, Any]:
        pages = self._pages()
        cur = self._page()
        out = []
        for p in pages:
            title = ""
            with contextlib.suppress(Exception):
                title = p.title()
            out.append({"url": p.url, "title": title})
        return {"tabs": out, "current": pages.index(cur) if cur in pages else None}

    def select_tab(self, index: int) -> None:
        pages = self._pages()
        if not 0 <= index < len(pages):
            raise ValueError(f"no tab {index} ({len(pages)} open)")
        self.current = pages[index]
        with contextlib.suppress(Exception):
            self.current.bring_to_front()

    def net(self) -> list[dict[str, Any]]:
        out = []
        for rec in list(self.net_log):
            resp = rec.pop("_resp", None)
            if resp is not None:
                with contextlib.suppress(Exception):
                    body = resp.text()[:300]
                    if body.startswith("bh-gate: DENIED"):
                        rec["reason"] = body.strip()[:200]
            out.append(rec)
        return out

    def frames(self) -> list[dict[str, Any]]:
        return list(self.frame_log)

    def cookie_values(self) -> list[str]:
        if self.browser is None or not self.browser.is_connected():
            return []
        return [c.get("value", "") for c in self.browser.contexts[0].cookies()]

    def snapshot(self) -> dict[str, Any]:
        page = self._page()
        frames = []
        for f in page.frames[1:]:
            url = f.url
            visible: bool | None = False
            try:
                el = f.frame_element()
                box = el.bounding_box()
                visible = bool(el.is_visible() and box and box["width"] > 0 and box["height"] > 0)
            except Exception:  # noqa: BLE001 (unknown: detect fails closed on a challenge host)
                visible = None
            frames.append({"url": url, "visible": visible})
        try:
            # Playwright reads it in its own isolated world: no script of ours runs in the page's world
            full = page.locator("body").inner_text(timeout=2000)
        except Exception:  # noqa: BLE001 (a page in the middle of a navigation)
            full = ""
        title = ""
        with contextlib.suppress(Exception):
            title = page.title()
        pages = self._pages()
        return {
            "url": page.url,
            "title": title,
            "text": snapshot_text(full),
            "text_len": len(full),
            "frames": frames,
            "tabs": len(pages),
            "tab": pages.index(page) if page in pages else None,
        }

    def add_cookies(self, cookies: list[dict[str, Any]]) -> None:
        self._context().add_cookies(cookies)

    def wipe(self) -> None:
        with contextlib.suppress(Exception):
            if self.browser is not None:
                self.browser.close()  # over CDP: disconnects, the process is stopped by the display
        self.browser, self.current = None, None
        self.net_log.clear()
        self.frame_log.clear()
        self.display.wipe()


# ---------------------------------------------------------------- one thread owns the controller
class Worker(threading.Thread):
    def __init__(self, make) -> None:
        super().__init__(daemon=True)
        self.make = make
        self.jobs: queue.Queue = queue.Queue()

    def run(self) -> None:
        ctl = self.make()
        while True:
            # Playwright's sync API only dispatches events inside one of its calls: while a websocket is routed
            # (bh-web ws-rewrite), its frames would wait for the agent's next command, so the idle loop pumps it.
            driver = getattr(ctl, "driver", None)
            needs = getattr(driver, "needs_pump", None)
            try:
                ops, req, box, done = self.jobs.get(timeout=PUMP_S if needs and needs() else None)
            except queue.Empty:
                with contextlib.suppress(Exception):
                    driver.pump()
                continue
            try:
                box.append(ctl.handle(ops, req))
            except BaseException as exc:  # noqa: BLE001
                box.append((500, {"error": type(exc).__name__}))
            done.set()

    def call(self, ops: frozenset[str], req: Any, timeout: float = 120) -> tuple[int, dict[str, Any]]:
        box: list = []
        done = threading.Event()
        self.jobs.put((ops, req, box, done))
        if not done.wait(timeout):
            return 504, {"error": "the browser did not answer in time"}
        return box[0]


# ---------------------------------------------------------------- the agent's door (HTTP, sandbox network)
class ApiHandler(BaseHTTPRequestHandler):
    server_version = "bh-browser"
    sys_version = ""
    timeout = 30

    def log_message(self, fmt, *args):
        pass

    def _reply(self, code: int, obj: dict[str, Any]) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._reply(404, {"error": "POST /op only"})

    def do_POST(self):
        token = self.server.token
        given = self.headers.get("Authorization", "")
        if not token or not hmac.compare_digest(given.encode(), f"Bearer {token}".encode()):
            return self._reply(401, {"error": "bearer token required"})
        if self.path != "/op":
            return self._reply(404, {"error": "POST /op only"})
        raw = self.headers.get("Content-Length") or "0"
        if not raw.isdigit() or int(raw) > BODY_MAX:
            return self._reply(413, {"error": f"body of at most {BODY_MAX} bytes"})
        try:
            req = json.loads(self.rfile.read(int(raw)) or b"{}")
        except ValueError:
            return self._reply(400, {"error": "the body is JSON"})
        code, out = self.server.call(AGENT_OPS, req)
        self._reply(code, out)


def api_server(call, token: str, host: str = "0.0.0.0", port: int = API_PORT) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((host, port), ApiHandler)
    srv.daemon_threads = True
    srv.token = token
    srv.call = call
    return srv


# ---------------------------------------------------------------- the host's door (unix socket, podman exec)
class CtlHandler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline(CTL_MAX + 1)
        try:
            req = json.loads(line)
        except ValueError:
            req = None
        code, out = self.server.call(HOST_OPS, req)
        self.wfile.write((json.dumps({"code": code, **out}) + "\n").encode())


def ctl_server(call, path: str = CTL_SOCK) -> socketserver.ThreadingUnixStreamServer:
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    os.chmod(os.path.dirname(path), 0o700)
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)
    srv = socketserver.ThreadingUnixStreamServer(path, CtlHandler)
    srv.daemon_threads = True
    srv.call = call
    return srv


def host_main(stdin=None, stdout=None, path: str = CTL_SOCK) -> int:
    """`podman exec -i bh-browser ... host`: one JSON request on stdin, one JSON reply on stdout."""
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    line = stdin.readline(CTL_MAX + 1)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(180)
            s.connect(path)
            s.sendall(line.encode() if line.endswith("\n") else (line + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
    except OSError as exc:
        stdout.write(json.dumps({"code": 503, "error": f"controller unreachable: {type(exc).__name__}"}) + "\n")
        return 1
    stdout.write(buf.decode("utf-8", "replace").strip() + "\n")
    try:
        return 0 if json.loads(buf).get("code") == 200 else 1
    except (ValueError, AttributeError):
        return 1


def serve() -> int:
    token = os.environ.get(TOKEN_ENV, "")
    if len(token) < 16:
        print(f"bh-browser: {TOKEN_ENV} is missing or too short (secrets/browser.env)", file=sys.stderr)
        return 2
    display = Display()
    display.ensure()
    worker = Worker(lambda: Controller(PlaywrightDriver(display), store=PROFILE_ROOT))
    worker.start()
    ctl = ctl_server(worker.call)
    threading.Thread(target=ctl.serve_forever, daemon=True).start()
    api = api_server(worker.call, token)

    def stop(signum, frame):
        display.stop()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)

    def watch() -> None:  # a dead x11vnc or Xvfb comes back without waiting for the agent's next request
        while True:
            time.sleep(5)
            with contextlib.suppress(Exception):
                if not (display._alive("xvfb") and display._alive("x11vnc")):
                    display.ensure()

    threading.Thread(target=watch, daemon=True).start()
    print(f"bh-browser: agent API on :{API_PORT}, control socket {CTL_SOCK}", file=sys.stderr, flush=True)
    api.serve_forever()
    return 0
