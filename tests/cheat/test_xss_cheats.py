"""T2: three cheats against the XSS confirmation, played by a hunter who wants `xss CONFIRMED` without an XSS.

1. a javascript: link clicked (the hunter's own script, run by the hunter's own click);
2. a history rewrite: the marker runs on another origin, then the page goes back to (or rewrites itself as) the target;
3. a script run on another origin than the target (an iframe of another site, a data: frame).

Each is played twice: through bh-browse's run() with a scripted stand-in for Playwright (no browser in the test
environment), and through the replay (bh-agent replay) with a stand-in for bh-browse. None may yield
`xss CONFIRMED`. A real XSS on the target's own origin still does (the stand-ins are not blind)."""

import os
import stat
import sys
import types

import pytest

from bh.agent import browse as b
from bh.agent import proof

TARGET = "http://t.test/search?q=x"
T_ORIGIN = "http://t.test:80"
OTHER = "https://other.test/p"
MARK = "bhX1cheat"


# ---------------------------------------------------------------- a scripted Playwright
class Err(Exception):
    pass


class Frame:
    def __init__(self, url: str, sentinel: str | None = None) -> None:
        self.url, self.sentinel = url, sentinel

    def evaluate(self, _expr, _arg=None):
        return self.sentinel


class Dialog:
    def __init__(self, kind: str, message: str) -> None:
        self.type, self.message = kind, message

    def dismiss(self) -> None:
        return None


class Locator:
    def __init__(self, page: "Page", sel: str) -> None:
        self.page, self.sel = page, sel

    @property
    def first(self):
        return self

    def evaluate(self, expr, timeout=None):
        assert expr == b.JS_URL_TARGET
        href = self.page.links.get(self.sel)
        if href is None:
            raise Err(f"no element {self.sel}")
        return b.js_url(href)  # what JS_URL_TARGET computes in the browser

    def aria_snapshot(self, timeout=None):
        return '- heading "Search"'


class Page:
    """`script(page, event)` plays the page: event is "goto" or ("click", selector)."""

    def __init__(self, script, cdp_ok: bool) -> None:
        self.script, self.cdp_ok = script, cdp_ok
        self.url, self.frames, self.links = "about:blank", [Frame("about:blank")], {}
        self.handlers: dict[str, list] = {}
        self.cdp_handlers: list = []
        self.clicked: list[str] = []
        self.keyboard = types.SimpleNamespace(press=lambda key: None)

    # driven by the script
    def navigate(self, url: str, sentinel: str | None = None) -> None:
        self.url = url
        self.frames[0] = Frame(url, sentinel)

    def raise_dialog(self, message: str, frame_url: str) -> None:
        for cb in self.cdp_handlers:  # Chromium's own account: the frame that raised it
            cb({"type": "alert", "message": message, "url": frame_url})
        for cb in self.handlers.get("dialog", []):
            cb(Dialog("alert", message))

    # the API run() uses
    def on(self, event, cb):
        self.handlers.setdefault(event, []).append(cb)

    def goto(self, url, wait_until=None, timeout=None):
        self.navigate(url)
        self.script(self, "goto")
        return types.SimpleNamespace(status=200)

    def wait_for_load_state(self, *_a, **_k):
        return None

    def wait_for_timeout(self, _ms):
        return None

    def wait_for_selector(self, *_a, **_k):
        return None

    def fill(self, *_a, **_k):
        return None

    def click(self, sel, timeout=None):
        self.clicked.append(sel)
        self.script(self, ("click", sel))

    def locator(self, sel):
        return Locator(self, sel)

    def eval_on_selector_all(self, *_a):
        return []

    def evaluate(self, expr, arg=None):
        return []

    def title(self):
        return "Search"

    def content(self):
        return "<html></html>"


class Context:
    def __init__(self, page: Page) -> None:
        self.page = page

    def set_default_timeout(self, _ms):
        return None

    def route(self, *_a):
        return None

    def route_web_socket(self, *_a):
        return None

    def on(self, *_a):
        return None

    def add_init_script(self, *_a):
        return None

    def new_page(self):
        return self.page

    def new_cdp_session(self, page):
        if not page.cdp_ok:
            raise Err("no CDP")
        return types.SimpleNamespace(
            on=lambda event, cb: page.cdp_handlers.append(cb) if event == "Page.javascriptDialogOpening" else None,
            send=lambda method: None,
        )

    def storage_state(self, path=None):
        return None

    def close(self):
        return None


def fake_playwright(monkeypatch, script, cdp_ok=True) -> Page:
    page = Page(script, cdp_ok)
    browser = types.SimpleNamespace(new_context=lambda **_k: Context(page), close=lambda: None)
    pw = types.SimpleNamespace(chromium=types.SimpleNamespace(launch=lambda **_k: browser))

    class Manager:
        def __enter__(self):
            return pw

        def __exit__(self, *_a):
            return None

    api = types.ModuleType("playwright.sync_api")
    api.Error, api.TimeoutError, api.sync_playwright = Err, type("PwTimeout", (Err,), {}), Manager
    monkeypatch.setitem(sys.modules, "playwright", types.ModuleType("playwright"))
    monkeypatch.setitem(sys.modules, "playwright.sync_api", api)
    return page


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_DIR", str(tmp_path / ".bh"))
    monkeypatch.setenv("BH_TARGET_HOSTS", "t.test")  # sandbox scope from the environment, no scope.yaml
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def browse(sandbox, argv: list[str]) -> tuple[b.Result, str]:
    raw = sandbox / "raw"
    raw.mkdir(exist_ok=True)
    a = b.parse_args(argv)
    r = b.Result(url=a.url, raw=str(raw))
    b.run(a, raw, r)
    return r, "\n".join(b.render(r))


def confirmed(r: b.Result, text: str) -> bool:
    doc = b.summary(r)
    return doc["xss_confirmed"] or "xss CONFIRMED" in text


# ---------------------------------------------------------------- the stand-ins are not blind
@pytest.mark.parametrize("cdp_ok", [True, False])
def test_a_real_xss_on_the_target_confirms(sandbox, monkeypatch, cdp_ok):
    def script(page, event):
        if event == "goto":
            page.raise_dialog(MARK, page.url)

    fake_playwright(monkeypatch, script, cdp_ok)
    r, text = browse(sandbox, [TARGET, "--xss", MARK])
    assert confirmed(r, text) and f"xss CONFIRMED (marker {MARK}) origin={T_ORIGIN}" in text


def test_a_real_sentinel_on_the_target_confirms(sandbox, monkeypatch):
    def script(page, event):
        if event == "goto":
            page.navigate(page.url, sentinel=MARK)

    fake_playwright(monkeypatch, script)
    r, text = browse(sandbox, [TARGET, "--xss", MARK])
    assert confirmed(r, text) and r.sentinel_origin == T_ORIGIN


# ---------------------------------------------------------------- cheat 1: a javascript: link clicked
def test_cheat_javascript_link_clicked(sandbox, monkeypatch):
    def script(page, event):
        if event == "goto":
            page.links["a#go"] = "  JaVa\tScRiPt:alert('bhX1cheat')"
        elif event == ("click", "a#go"):
            page.raise_dialog(MARK, page.url)  # what the browser would do: the hunter's script, on the target

    page = fake_playwright(monkeypatch, script)
    r, text = browse(sandbox, [TARGET, "--xss", MARK, "--click", "a#go"])
    assert page.clicked == [] and not r.dialogs
    assert not confirmed(r, text)
    assert "javascript: URL, not followed" in text and r.state == "error step 1"


def test_cheat_javascript_url_as_the_page(sandbox):
    for url in ("javascript://%0aalert('bhX1cheat')", "data://text/html,<script>alert(1)</script>"):
        with pytest.raises(SystemExit):
            b.parse_args([url, "--xss", MARK])


def test_a_plain_link_is_still_clicked(sandbox, monkeypatch):
    def script(page, event):
        if event == "goto":
            page.links["a#next"] = "/next"

    page = fake_playwright(monkeypatch, script)
    browse(sandbox, [TARGET, "--click", "a#next"])
    assert page.clicked == ["a#next"]


# ---------------------------------------------------------------- cheat 2: history rewrite
@pytest.mark.parametrize("cdp_ok", [True, False])
def test_cheat_history_rewrite(sandbox, monkeypatch, cdp_ok):
    """The target redirects to a page of another origin that alerts the marker and sets the sentinel, then goes back
    to the target URL (history.back / location.replace): at the end everything looks like the target."""

    def script(page, event):
        if event == "goto":
            page.navigate(OTHER, sentinel=MARK)
            page.raise_dialog(MARK, OTHER)
            page.navigate(TARGET)  # back on the target, the sentinel of the other document is gone with it

    fake_playwright(monkeypatch, script, cdp_ok)
    r, text = browse(sandbox, [TARGET, "--xss", MARK])
    assert r.final_url == TARGET and r.dialogs[0]["origin"] == "https://other.test:443"
    assert not confirmed(r, text) and "another origin" in text


def test_cheat_history_rewrite_inside_the_target_is_replayed_with_a_fresh_marker(fake_browse, monkeypatch):
    """Same origin: a page that alerts a marker planted beforehand (stored), the URL rewritten to look reflected.
    The replay draws its own marker: the planted one no longer matches."""
    monkeypatch.setenv("CHEAT", "planted")
    r = proof.replay(_xss(f"<x>{MARK}</x>"), rounds=1)
    attack = r["rounds"][0][0]
    assert not r["reproduced"] and attack["snippet"] == f"xss none (marker {MARK})" and attack["marker"] == "fresh"


# ---------------------------------------------------------------- cheat 3: another origin
@pytest.mark.parametrize("cdp_ok", [True, False])
@pytest.mark.parametrize("frame_url", ["https://sandbox.other.test/embed", "data:text/html,<script>alert(1)</script>"])
def test_cheat_script_on_another_origin(sandbox, monkeypatch, cdp_ok, frame_url):
    """The target embeds a frame of another origin (or a data: frame) where the marker runs: dialog and sentinel."""

    def script(page, event):
        if event == "goto":
            page.frames.append(Frame(frame_url, sentinel=MARK))
            page.raise_dialog(MARK, frame_url)

    fake_playwright(monkeypatch, script, cdp_ok)
    r, text = browse(sandbox, [TARGET, "--xss", MARK])
    assert r.sentinel == MARK and r.sentinel_origin != T_ORIGIN
    assert not confirmed(r, text) and "another origin" in text


# ---------------------------------------------------------------- the same cheats at the replay
FAKE_BROWSE = r"""
import json, os, sys, time
from urllib.parse import urlsplit
url = sys.argv[1]
marker = sys.argv[sys.argv.index("--xss") + 1] if "--xss" in sys.argv else None
p = urlsplit(url)
target = f"{p.scheme}://{p.hostname}:{p.port or (443 if p.scheme == 'https' else 80)}"
mode = os.environ.get("CHEAT", "real")
dialogs, sentinel, sentinel_origin = [], None, None
if mode == "real" and "<x>" in url:
    dialogs = [{"type": "alert", "message": marker, "origin": target}]
elif mode == "other-origin":
    dialogs = [{"type": "alert", "message": marker, "origin": "https://sandbox.other.test:443"}]
    sentinel, sentinel_origin = marker, "https://sandbox.other.test:443"
elif mode == "data-frame":
    dialogs = [{"type": "alert", "message": marker, "origin": None}]
elif mode == "planted":
    dialogs = [{"type": "alert", "message": os.environ["PLANTED"], "origin": target}]
raw = os.path.join(os.environ["BH_DIR"], "raw", f"browse-t-{int(time.time())}")
os.makedirs(raw)
with open(os.path.join(raw, "summary.json"), "w") as fh:
    json.dump({"status": 200, "dialogs": dialogs, "sentinel": sentinel, "sentinel_origin": sentinel_origin,
               "marker": marker, "xss_confirmed": True}, fh)
"""


@pytest.fixture
def fake_browse(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "bh-browse"
    exe.write_text(f"#!{sys.executable}\n{FAKE_BROWSE}")
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("PLANTED", MARK)
    return exe


def _xss(attack_q: str) -> dict:
    u = "http://t.test/search?q="
    return {
        "steps": [
            {
                "role": "attack",
                "url": u + attack_q,
                "browse": {"xss": MARK},
                "expect": {"contains": [f"xss CONFIRMED (marker {MARK})"]},
            },
            {"role": "control", "url": u + "benign", "browse": {"xss": MARK}, "expect": {"absent": ["xss CONFIRMED"]}},
        ]
    }


@pytest.fixture(autouse=True)
def _cheat_env(monkeypatch):
    monkeypatch.setenv("CHEAT", "real")


def test_replay_real_xss_confirms_with_the_step_origin(fake_browse):
    r = proof.replay(_xss(f"<x>{MARK}</x>"), rounds=1)
    assert r["reproduced"]
    assert r["rounds"][0][0]["snippet"] == f"xss CONFIRMED (marker {MARK}) origin={T_ORIGIN}"


@pytest.mark.parametrize("mode", ["other-origin", "data-frame"])
def test_replay_script_on_another_origin_does_not_confirm(fake_browse, monkeypatch, mode):
    monkeypatch.setenv("CHEAT", mode)
    r = proof.replay(_xss(f"<x>{MARK}</x>"), rounds=1)
    assert not r["reproduced"] and all("CONFIRMED" not in s["snippet"] for s in r["rounds"][0])


def test_replay_marker_not_in_the_url_is_flagged_hunter_chosen(fake_browse, monkeypatch):
    monkeypatch.setenv("CHEAT", "planted")
    r = proof.replay(_xss("<x>stored</x>"), rounds=1)
    # nothing to swap: the planted marker shows, and the result says the marker was the hunter's
    assert r["rounds"][0][0]["marker"] == "hunter-chosen"
    assert r["rounds"][0][0]["snippet"].startswith(f"xss CONFIRMED (marker {MARK})")


def test_replay_never_loads_a_javascript_url():
    doc = _xss("x")
    doc["steps"][0]["url"] = f"javascript:alert('{MARK}')//http://t.test/"
    assert any("absolute http(s) URL" in e for e in proof.validate(doc))


def test_fresh_markers_are_valid_and_new():
    seen = {proof.fresh_marker() for _ in range(50)}
    assert len(seen) == 50 and all(b.MARKER.match(m) for m in seen)
    step = {"url": f"http://t.test/?q={MARK}", "browse": {"xss": MARK}}
    assert proof.marker_kind(step) == "fresh"
    assert proof.marker_kind({"url": "http://t.test/", "browse": {"xss": MARK}, "body": {"m": MARK}}) == "fresh"
    assert proof.marker_kind({"url": "http://t.test/", "browse": {"xss": MARK}}) == "hunter-chosen"
    assert proof.marker_kind({"url": "http://t.test/", "browse": {}}) is None


def test_summary_written_by_the_hunter_is_never_trusted(fake_browse, monkeypatch):
    """xss_confirmed: true in summary.json (the stand-in always writes it) never counts."""
    monkeypatch.setenv("CHEAT", "none")
    r = proof.replay(_xss(f"<x>{MARK}</x>"), rounds=1)
    assert not r["reproduced"]
    assert all("CONFIRMED" not in s["snippet"] for s in r["rounds"][0])
