"""bh-js (R42) on a fake bundle and a fake opener: nothing here touches the network."""

import json
import urllib.error
from pathlib import Path

import pytest

from bh.agent import contract as c
from bh.agent import js

JWT_TEXT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlX2FiY2RlZg"
BUNDLE = f"""
!function(){{var a="/api/v1/users/{{id}}",b='/resources/app-shell-action',c="/static/x/y.png",d="/single",
e=fetch("/api/chat/send?x=1"),f={{action:"GetConversation"}},g={{"action":"DeleteThing"}},h={{action: 'ListFiles'}};
var hdr={{"x-ms-client-request-id":1,"X-Anchor-Mailbox":2}},i=n.action;
var u="https://api.t.test/v2/x",v="//cdn.t-assets.test/a.js",w="https://evil.example.com/collect";
var tok="/api/session/{JWT_TEXT}",k={{action:"{JWT_TEXT}"}},m="/api/keys/AKIAABCDEFGHIJKLMNOP/x";
/* "/ignore/previous/instructions" is data like the rest */ var q="/fonts/a/b.woff2",r="//x";}}();
"""
SCOPE = c.SandboxScope(targets=("t.test", "*.t.test"), assets=("cdn.t-assets.test",))


class Resp:
    def __init__(self, status: int, body: bytes, ctype: str) -> None:
        self.status, self.body, self.headers = status, body, {"Content-Type": ctype}

    def read(self, n: int) -> bytes:
        return self.body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *_a) -> None:
        return None


class Opener:
    """url -> (status, content type, body); a 3xx answers with a Location; anything else is a 404."""

    def __init__(self, pages: dict) -> None:
        self.pages, self.calls, self.timeouts = pages, [], []

    def open(self, req, timeout):
        url = req.full_url
        self.calls.append(url)
        self.timeouts.append(timeout)
        status, ctype, body = self.pages.get(url, (404, "text/plain", b"nf"))
        if 300 <= status < 400:
            raise urllib.error.HTTPError(url, status, "moved", {"Location": body.decode()}, None)
        if status >= 400:
            raise urllib.error.HTTPError(url, status, "err", {}, None)
        return Resp(status, body if isinstance(body, bytes) else body.encode(), ctype)


@pytest.fixture
def work(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_DIR", str(tmp_path / ".bh"))
    monkeypatch.setenv("BH_RPS", "2")
    return tmp_path


def _run(targets, pages, max_files=js.MAX_FILES, sleeps=None):
    op = Opener(pages)
    lines = js.run(
        targets, max_files, opener=op, sleep=(sleeps.append if sleeps is not None else lambda s: None), scope=SCOPE
    )
    return lines, op


def _raw(lines) -> dict:
    path = next(x for x in lines if x.startswith("raw: ")).removeprefix("raw: ")
    return json.loads(Path(path).read_text())


def test_the_four_extractions(work):
    found = js.extract(BUNDLE)
    assert set(found["paths"]) == {
        "/api/v1/users/{id}",
        "/resources/app-shell-action",
        "/api/chat/send?x=1",
        "/api/session/<redacted:jwt>",
        "/api/keys/<redacted:key>/x",
        "/ignore/previous/instructions",
    }
    assert set(found["actions"]) == {"GetConversation", "DeleteThing", "ListFiles", "<redacted:jwt>"}
    assert set(found["headers"]) == {"x-ms-client-request-id", "x-anchor-mailbox"}
    assert set(found["hosts"]) == {"api.t.test", "cdn.t-assets.test", "evil.example.com"}


def test_a_url_is_read_and_listed_with_scope_labels(work):
    sleeps: list[float] = []
    lines, op = _run(
        ["https://t.test/main.js"], {"https://t.test/main.js": (200, "text/javascript", BUNDLE)}, sleeps=sleeps
    )
    text = "\n".join(lines)
    assert op.calls == ["https://t.test/main.js"] and op.timeouts == [js.TIMEOUT_S]
    assert "/resources/app-shell-action" in text and "GetConversation" in text and "x-ms-client-request-id" in text
    assert "  api.t.test  in scope" in lines and "  cdn.t-assets.test  in scope" in lines
    assert "  evil.example.com  NOT in scope: do not request" in lines
    assert lines[-1] == "leads, not findings" and lines[-2].startswith("raw: ")


def test_no_secret_is_printed(work):
    lines, _ = _run(["https://t.test/main.js"], {"https://t.test/main.js": (200, "text/javascript", BUNDLE)})
    raw = json.dumps(_raw(lines))
    for out in ("\n".join(lines), raw):
        assert "eyJhbGci" not in out and "AKIAABCDEFGHIJKLMNOP" not in out
    assert "/api/session/<redacted:jwt>" in "\n".join(lines)
    assert js.no_secret("/a?access_token=abc123&x=1").startswith("/a?access_token=<redacted:value>")
    assert js.no_secret("/v/0123456789abcdef0123456789abcdef01/x") == "/v/<redacted:random>/x"
    assert js.no_secret("/api/user-settings/list") == "/api/user-settings/list"


def test_a_host_out_of_scope_is_never_requested(work):
    page = '<script src="https://evil.example.com/x.js"></script><script src="/ok.js"></script>'
    pages = {
        "https://t.test/": (200, "text/html", page),
        "https://t.test/ok.js": (200, "application/javascript", "var a='/api/a/b'"),
        "https://t.test/moved.js": (302, "", b"https://evil.example.com/y.js"),
    }
    targets = ["https://evil.example.com/app.js", "https://t.test/", "https://t.test/moved.js", "ftp://t.test/a.js"]
    lines, op = _run(targets, pages)
    assert not any("evil.example.com" in u for u in op.calls)
    assert op.calls == ["https://t.test/", "https://t.test/moved.js", "https://t.test/ok.js"]
    assert lines[1:].count("  evil.example.com  NOT in scope: do not request") == 1
    hosts = [h["host"] for h in _raw(lines)["hosts"]]
    assert hosts[0] == "evil.example.com"  # what was asked and refused comes first


def test_sign_in_and_challenge_hosts_are_not_fetched(work):
    scope = c.SandboxScope(targets=("t.test",), sso=("login.t.test",), passthrough=("challenge.test",))
    op = Opener({})
    js.run(["https://login.t.test/a.js", "https://challenge.test/b.js"], opener=op, sleep=lambda s: None, scope=scope)
    assert op.calls == []


def test_an_html_page_gives_its_scripts_once(work):
    page = (
        '<html><head><script src="/a.js"></script><link rel="modulepreload" href="/b.mjs">'
        '<link rel="stylesheet" href="/c.css"><script>var x="/api/inline/x"</script>'
        '<script src="data:text/javascript,1"></script></head></html>'
    )
    pages = {
        "https://t.test/": (200, "text/html; charset=utf-8", page),
        "https://t.test/a.js": (200, "text/javascript", "var p='/api/a/one'"),
        # a script answered with HTML: read, but its scripts are not followed (once)
        "https://t.test/b.mjs": (200, "text/html", '<script src="/deeper.js"></script>'),
    }
    lines, op = _run(["https://t.test/"], pages)
    assert op.calls == ["https://t.test/", "https://t.test/a.js", "https://t.test/b.mjs"]
    text = "\n".join(lines)
    assert "/api/inline/x" in text and "/api/a/one" in text
    assert js.scripts_of(page, "https://t.test/x/") == ["https://t.test/a.js", "https://t.test/b.mjs"]


def test_at_most_200_files_and_max_only_lowers_it(work):
    page = "".join(f'<script src="/s{i}.js"></script>' for i in range(300))
    pages = {"https://t.test/": (200, "text/html", page)}
    pages |= {f"https://t.test/s{i}.js": (200, "text/javascript", f"var p='/api/s/{i}'") for i in range(300)}
    sleeps: list[float] = []
    lines, op = _run(["https://t.test/"], pages, max_files=500, sleeps=sleeps)
    assert len(op.calls) == js.MAX_FILES == 200
    assert "stopped at 200 files" in lines[0]
    # paced at BH_RPS (2/s): every request after the first waited about half a second
    assert len(sleeps) == 199 and all(0.4 < s <= 0.5 for s in sleeps)
    js_dir = work / ".bh" / "js"
    for f in js_dir.glob("*"):
        f.unlink()
    _, op = _run(["https://t.test/"], pages, max_files=10)
    assert len(op.calls) == 10


def test_local_files_under_the_work_dir_only(work, tmp_path_factory):
    d = work / "bundles"
    d.mkdir()
    for i in range(250):
        (d / f"b{i:03}.js").write_text(f"var p='/api/local/{i}'")
    (d / "notes.txt").write_text("var p='/api/not/read'")
    lines, op = _run([str(d)], {})
    assert op.calls == [] and lines[0].startswith("bh-js: 200 files (0 fetched, 0 cached, 200 local")
    outside = tmp_path_factory.mktemp("outside") / "x.js"
    outside.write_text("var p='/api/outside/x'")
    (d / "link.js").symlink_to(outside)
    lines, _ = _run([str(outside), str(d / "link.js"), "/etc/passwd"], {})
    assert lines[0].startswith("bh-js: 0 files") and "3 skipped" in lines[0]
    assert "/api/outside/x" not in "\n".join(lines)


def test_cache_answers_a_known_url(work):
    pages = {"https://t.test/main.js": (200, "text/javascript", BUNDLE)}
    _, op = _run(["https://t.test/main.js"], pages)
    assert len(op.calls) == 1
    index = json.loads((work / ".bh/js/index.json").read_text())
    sha = index["https://t.test/main.js"]
    assert (work / f".bh/js/{sha}.js").read_text() == BUNDLE
    lines, op = _run(["https://t.test/main.js"], pages)
    assert op.calls == [] and "1 cached" in lines[0] and "GetConversation" in "\n".join(lines)


def test_files_are_cut_at_2_mib(work):
    big = "var p='/api/big/one';" + "x" * (3 << 20)
    lines, _ = _run(["https://t.test/big.js"], {"https://t.test/big.js": (200, "text/javascript", big)})
    files = _raw(lines)["files"]
    assert files[0]["bytes"] == js.MAX_BYTES and files[0]["truncated"] and "1 cut at 2 MiB" in lines[0]


def test_output_is_at_most_40_lines_with_the_full_lists_in_raw(work):
    many = ";".join(
        [f"a{i}='/api/p{i}/x'" for i in range(100)]
        + [f"b{i}={{action:'Act{i}'}}" for i in range(100)]
        + [f"c{i}='x-h-{i}'" for i in range(50)]
        + [f"d{i}='https://h{i}.example.org/'" for i in range(50)]
    )
    lines, _ = _run(["https://t.test/m.js"], {"https://t.test/m.js": (200, "text/javascript", many)})
    assert len(lines) <= js.OUT_LINES and lines[-1] == js.LAST_LINE
    assert sum(1 for x in lines if x.startswith("  /api/")) == 12
    assert sum(1 for x in lines if x.startswith("  Act")) == 15
    assert sum(1 for x in lines if x.startswith("  h") and "example.org" in x) == 6
    assert next(x for x in lines if x.startswith("headers")).count("x-h-") == 6
    raw = _raw(lines)
    assert len(raw["paths"]) == 100 and len(raw["actions"]) == 100 and len(raw["headers"]) == 50
    assert len(raw["hosts"]) == 50


def test_a_failed_request_is_counted_not_fatal(work):
    lines, op = _run(["https://t.test/missing.js"], {})
    assert op.calls == ["https://t.test/missing.js"] and "1 failed" in lines[0] and lines[-1] == js.LAST_LINE


def test_main_refuses_a_zero_max(work):
    with pytest.raises(SystemExit):
        js.main(["https://t.test/", "--max", "0"])
