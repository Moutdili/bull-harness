"""bh.browser_service: protocol of the controller, challenge detection, API token, no cookie in any reply.
No podman, no browser, no network beyond 127.0.0.1."""

import io
import json
import tarfile
import threading
import urllib.error
import urllib.request

import pytest

from bh.browser_service import AGENT_OPS, HOST_OPS
from bh.browser_service.controller import (
    Controller,
    Refused,
    api_server,
    chromium_argv,
    ctl_server,
    host_main,
    validate,
)
from bh.browser_service.detect import challenge

COOKIE_VALUE = "s3cr3t-session-value-0123456789"
TURNSTILE = "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/turnstile/if/ov2/av0/rcv/x"


class FakeDriver:
    def __init__(self, snapshot=None, text="hello"):
        self.snap = snapshot or {"url": "https://app.example/", "title": "App", "text": "Welcome", "frames": []}
        self.page_text = text
        self.calls = []
        self.cookies = []

    def goto(self, url):
        self.calls.append(("goto", url))
        self.snap = {**self.snap, "url": url}

    def fill(self, css, text):
        self.calls.append(("fill", css, text))

    def click(self, css):
        self.calls.append(("click", css))

    def press(self, key):
        self.calls.append(("press", key))

    def wait_css(self, css):
        self.calls.append(("wait_css", css))

    def wait_ms(self, ms):
        self.calls.append(("wait_ms", ms))

    def text(self):
        return self.page_text

    def snapshot(self):
        return self.snap

    def add_cookies(self, cookies):
        self.cookies += cookies

    def wipe(self):
        self.calls.append(("wipe",))
        self.cookies = []


def session_req():
    return {
        "op": "load_session",
        "program": "msrc-copilot",
        "identity": "user-a",
        "cookies": [{"name": "sid", "value": COOKIE_VALUE, "url": "https://app.example/", "secure": True}],
        "secrets": ["Bearer header-secret-value"],
    }


# ---------------------------------------------------------------- protocol
def test_agent_ops_are_validated():
    assert validate(AGENT_OPS, {"op": "goto", "url": "https://app.example/x"}) == (
        "goto",
        {"url": "https://app.example/x"},
    )
    assert validate(AGENT_OPS, {"op": "wait", "ms": 500}) == ("wait", {"ms": 500})
    assert validate(AGENT_OPS, {"op": "press", "key": "Enter"})[0] == "press"
    assert validate(AGENT_OPS, {"op": "state"}) == ("state", {})


@pytest.mark.parametrize(
    "req",
    [
        {"op": "cookies"},
        {"op": "storage"},
        {"op": "evaluate", "js": "document.cookie"},
        {"op": "screenshot"},
        {"op": "cdp", "method": "Network.getAllCookies"},
        {"op": "load_session", "program": "p", "identity": "a", "cookies": []},  # host only
        {"op": "status"},  # host only
        {"op": "reset"},  # host only
        {"op": "human_done"},  # host only: only Mio says he is done
        {"op": "goto", "url": "file:///profile/chromium/Default/Cookies"},
        {"op": "goto", "url": "chrome://settings"},
        {"op": "goto", "url": "javascript:alert(1)"},
        {"op": "goto", "url": "view-source:https://app.example/"},
        {"op": "goto", "url": "https://app.example/", "headers": {"x": "y"}},  # unknown field
        {"op": "press", "key": "F12"},  # DevTools
        {"op": "press", "key": "Control+Shift+I"},
        {"op": "wait"},
        {"op": "wait", "ms": 10, "css": "a"},
        {"op": "wait", "ms": 10**9},
        {"op": "fill", "css": "#q"},
        {"op": "click", "css": "x" * 301},
        ["goto"],
        "state",
    ],
)
def test_the_agent_door_refuses_anything_off_the_list(req):
    with pytest.raises(Refused):
        validate(AGENT_OPS, req)
    code, out = Controller(FakeDriver()).handle(AGENT_OPS, req)
    assert code == 400 and "error" in out


def test_the_host_door_takes_host_ops_only():
    assert validate(HOST_OPS, session_req())[0] == "load_session"
    for req in ({"op": "goto", "url": "https://app.example/"}, {"op": "click", "css": "a"}, {"op": "text"}):
        with pytest.raises(Refused):
            validate(HOST_OPS, req)


def test_host_and_agent_sets_do_not_overlap():
    assert not AGENT_OPS & HOST_OPS
    assert {"goto", "fill", "click", "press", "text", "wait", "state"} == AGENT_OPS


# ---------------------------------------------------------------- challenge detection
@pytest.mark.parametrize(
    ("snap", "pending"),
    [
        ({"text": "Welcome back", "frames": []}, False),
        ({"text": "", "frames": [{"url": TURNSTILE, "visible": True}]}, True),
        ({"text": "", "frames": [{"url": TURNSTILE, "visible": False}]}, False),  # invisible mode / solved
        ({"text": "Performing security check...", "frames": []}, True),
        ({"text": "Please Verify you are human by completing the action below.", "frames": []}, True),
        ({"text": "Vérifiez que vous êtes un humain", "frames": []}, True),
        ({"text": "", "frames": [{"url": "https://challenges.cloudflare.com.evil.example/x", "visible": True}]}, False),
        ({"text": "", "frames": [{"url": "https://www.youtube.com/embed/x", "visible": True}]}, False),
        ({}, False),
    ],
)
def test_challenge_detection_on_fake_doms(snap, pending):
    assert challenge(snap)["pending"] is pending


def test_the_agent_never_clicks_types_or_presses_on_a_challenge():
    d = FakeDriver(
        {"url": "https://copilot.example/", "title": "x", "text": "", "frames": [{"url": TURNSTILE, "visible": True}]}
    )
    ctl = Controller(d)
    for req in (
        {"op": "click", "css": "iframe"},
        {"op": "fill", "css": "input", "text": "x"},
        {"op": "press", "key": "Space"},
        {"op": "press", "key": "Tab"},
    ):
        code, out = ctl.handle(AGENT_OPS, req)
        assert code == 409 and out["error"] == "human-needed"
        assert out["state"]["challenge"]["pending"] is True
    assert d.calls == []  # nothing reached the page
    code, out = ctl.handle(AGENT_OPS, {"op": "state"})
    assert code == 200 and out["challenge"]["pending"] and out["challenge"]["reason"] == "turnstile-frame"
    # Mio solved it: the frame is gone, the agent goes on
    d.snap = {**d.snap, "frames": []}
    assert ctl.handle(AGENT_OPS, {"op": "click", "css": "button.send"})[0] == 200
    assert d.calls == [("click", "button.send")]


def test_human_done_is_shown_to_the_agent():
    ctl = Controller(FakeDriver(), clock=lambda: 1234.5)
    assert ctl.handle(HOST_OPS, {"op": "human_done"}) == (200, {"ok": True, "human_done_at": 1234.5})
    assert ctl.handle(AGENT_OPS, {"op": "state"})[1]["human_done_at"] == 1234.5


# ---------------------------------------------------------------- no cookie, no secret in any reply
def test_no_reply_carries_a_session_value():
    d = FakeDriver(text=f"debug: sid={COOKIE_VALUE}; auth=Bearer header-secret-value; eyJhbGciOiJI.eyJzdWIiOiIx.sig")
    d.snap = {**d.snap, "url": f"https://app.example/cb?token={COOKIE_VALUE}", "title": f"t {COOKIE_VALUE}"}
    ctl = Controller(d)
    replies = [ctl.handle(HOST_OPS, session_req())]
    assert d.cookies and d.cookies[0]["value"] == COOKIE_VALUE  # it did reach the browser
    for req in ({"op": "text"}, {"op": "state"}, {"op": "goto", "url": "https://app.example/next"}):
        replies.append(ctl.handle(AGENT_OPS, req))
    replies.append(ctl.handle(HOST_OPS, {"op": "status"}))

    def boom(css):
        raise RuntimeError(f"locator {css} failed near {COOKIE_VALUE}")

    d.click = boom
    replies.append(ctl.handle(AGENT_OPS, {"op": "click", "css": "a"}))
    blob = json.dumps(replies)
    assert COOKIE_VALUE not in blob and "header-secret-value" not in blob and "eyJzdWIiOiIx" not in blob
    assert replies[0] == (200, {"ok": True, "program": "msrc-copilot", "identity": "user-a", "cookies": 1})
    assert replies[-1][0] == 502


def test_text_is_bounded():
    code, out = Controller(FakeDriver(text="a" * 50_000)).handle(AGENT_OPS, {"op": "text"})
    assert code == 200 and len(out["text"]) == 8000 and out["truncated"]


def test_reset_forgets_the_session():
    d = FakeDriver()
    ctl = Controller(d)
    ctl.handle(HOST_OPS, session_req())
    assert ctl.handle(HOST_OPS, {"op": "reset"})[0] == 200
    assert ("wipe",) in d.calls and not ctl.secrets and ctl.identity is None
    assert ctl.handle(HOST_OPS, {"op": "status"})[1]["cookies_loaded"] == 0


# ---------------------------------------------------------------- the agent's HTTP door: token required
@pytest.fixture
def api():
    seen = []

    def call(ops, req):
        seen.append((ops, req))
        return Controller(FakeDriver()).handle(ops, req)

    srv = api_server(call, "t" * 32, host="127.0.0.1", port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", seen
    srv.shutdown()


def _post(url, body, token=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_api_requires_the_token(api):
    base, seen = api
    assert _post(base + "/op", {"op": "state"})[0] == 401
    assert _post(base + "/op", {"op": "state"}, token="wrong")[0] == 401
    assert _post(base + "/op", {"op": "state"}, token="t" * 31)[0] == 401
    assert seen == []  # refused before the controller
    code, out = _post(base + "/op", {"op": "state"}, token="t" * 32)
    assert code == 200 and out["url"] == "https://app.example/"
    assert seen[0][0] == AGENT_OPS


def test_api_refuses_host_ops_and_raw_access(api):
    base, _ = api
    for body in (session_req(), {"op": "status"}, {"op": "human_done"}, {"op": "cookies"}):
        code, out = _post(base + "/op", body, token="t" * 32)
        assert code == 400 and "not allowed" in out["error"]
    assert _post(base + "/cdp", {"op": "state"}, token="t" * 32)[0] == 404


def test_api_refuses_to_start_without_a_token(monkeypatch):
    from bh.browser_service import controller

    monkeypatch.delenv("BH_BROWSER_TOKEN", raising=False)
    assert controller.serve() == 2


# ---------------------------------------------------------------- the host's door: control socket
def test_control_socket_round_trip(tmp_path):
    ctl = Controller(FakeDriver())
    srv = ctl_server(ctl.handle, path=str(tmp_path / "run" / "ctl.sock"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        out = io.StringIO()
        rc = host_main(io.StringIO(json.dumps(session_req()) + "\n"), out, path=str(tmp_path / "run" / "ctl.sock"))
        assert rc == 0 and COOKIE_VALUE not in out.getvalue()
        assert json.loads(out.getvalue())["cookies"] == 1
        out = io.StringIO()
        assert (
            host_main(io.StringIO('{"op": "goto", "url": "https://x.example/"}\n'), out, path=srv.server_address) == 1
        )
        assert json.loads(out.getvalue())["code"] == 400
    finally:
        srv.shutdown()
        srv.server_close()
    assert (tmp_path / "run").stat().st_mode & 0o777 == 0o700


def test_host_main_without_controller(tmp_path):
    out = io.StringIO()
    assert host_main(io.StringIO('{"op":"status"}\n'), out, path=str(tmp_path / "none.sock")) == 1
    assert json.loads(out.getvalue())["code"] == 503


# ---------------------------------------------------------------- the browser as it ships
def test_chromium_is_not_disguised():
    argv = chromium_argv("/profile/chromium")
    joined = " ".join(argv)
    for flag in (
        "--headless",
        "--user-agent",
        "--disable-blink-features",
        "AutomationControlled",
        "--disable-infobars",
        "--load-extension",
        "stealth",
        "--remote-debugging-address",
        "--remote-allow-origins",
    ):
        assert flag not in joined
    assert "--remote-debugging-port=9222" in argv and "--proxy-server=http://gate:8080" in argv
    assert "--user-data-dir=/profile/chromium" in argv


# ---------------------------------------------------------------- host side
def test_session_cookies_keep_host_only_and_domain_cookies_apart():
    from bh.browser_service.host import session_cookies

    s = {
        "cookies": {
            "app.example": {"sid": {"value": "v1", "path": "/", "expires": None, "host_only": True, "secure": True}},
            "example": {"pref": {"value": "v2", "path": "/a", "expires": 2e9, "host_only": False, "secure": False}},
        }
    }
    got = session_cookies(s)
    assert {"name": "sid", "value": "v1", "secure": True, "url": "https://app.example/"} in got
    assert {"name": "pref", "value": "v2", "secure": False, "domain": ".example", "path": "/a", "expires": 2e9} in got
    for c in got:  # what the host builds is what the controller accepts
        validate(HOST_OPS, {"op": "load_session", "program": "p", "identity": "a", "cookies": [c]})


def test_identity_payload_reads_the_gate_session(tmp_path, monkeypatch):
    from bh.browser_service.host import identity_payload

    monkeypatch.setenv("BH_HOME", str(tmp_path))
    d = tmp_path / "var" / "state" / "identities" / "prog"
    d.mkdir(parents=True)
    (d / "user-a.json").write_text(
        json.dumps(
            {
                "headers": {"Authorization": "Bearer abcdefgh"},
                "cookies": {
                    "app.example": {
                        "sid": {"value": COOKIE_VALUE, "path": "/", "expires": None, "host_only": True, "secure": True}
                    }
                },
            }
        )
    )
    req, headers = identity_payload("prog", "user-a")
    assert headers == ["Authorization"]
    assert req["cookies"][0]["value"] == COOKIE_VALUE and "Bearer abcdefgh" in req["secrets"]
    assert validate(HOST_OPS, req)[0] == "load_session"
    with pytest.raises(SystemExit):
        identity_payload("prog", "nobody")


def test_novnc_archive_never_climbs_out():
    from bh.browser_service.host import parse_tar

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in (
            ("core/rfb.js", b"export default 1;"),
            ("../evil.js", b"x"),
            ("/etc/passwd", b"x"),
            ("./vendor/pako/lib/zlib/inflate.js", b"y"),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    files = parse_tar(buf.getvalue())
    assert files == {"core/rfb.js": b"export default 1;", "vendor/pako/lib/zlib/inflate.js": b"y"}
    with pytest.raises(ValueError):
        parse_tar(buf.getvalue(), limit=5)


def test_token_file_is_private(tmp_path, monkeypatch):
    from bh.browser_service.host import ensure_token, token_file

    monkeypatch.setenv("BH_HOME", str(tmp_path))
    ensure_token()
    first = token_file().read_text()
    ensure_token()  # never rotated by a second `bh up`
    assert token_file().read_text() == first and first.startswith("BH_BROWSER_TOKEN=") and len(first) > 40
    assert token_file().stat().st_mode & 0o777 == 0o600


def test_goto_refuses_the_browsers_own_container_and_forces_loopback_through_the_gate():
    import pytest

    from bh.browser_service import controller as c

    for u in (
        "http://127.0.0.1:9222/json",
        "http://localhost:8790/op",
        "http://[::1]:5900/",
        "http://browser:8790/",
        "http://a.localhost/",
        "http://0.0.0.0:9222/",
    ):
        with pytest.raises(c.Refused):
            c._url(u)
    assert c._url("https://copilot.com/chat") == "https://copilot.com/chat"
    assert "--proxy-bypass-list=<-loopback>" in c.chromium_argv("/p")
