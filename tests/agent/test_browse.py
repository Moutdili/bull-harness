"""bh-browse without a browser: arguments, program rules, the local route filter, endpoints and the summary.
The live check (Juice Shop, through the gate) runs in the agent container."""

import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from bh.agent import browse as b
from bh.agent import contract as c
from bh.agent import hooks

ROOT = Path(__file__).resolve().parents[2]


def test_args_keep_step_order_and_imply_shot():
    steps = ["--fill", "#email=a@b.c", "--fill", 'input[name="pw"]=x=y', "--click", "#go"]
    a = b.parse_args(["lab:3000/#/login", *steps, "--clip", "h1"])
    assert a.url == "https://lab:3000/#/login"
    assert a.steps == [("fill", ("#email", "a@b.c")), ("fill", ('input[name="pw"]', "x=y")), ("click", "#go")]
    assert a.shot and a.clip == "h1" and not a.full and a.xss is None
    assert b.parse_args(["http://h/", "--full"]).shot
    assert b.parse_args(["http://h/"]).steps == []  # no list shared between calls


def test_fill_split_and_marker_validation():
    assert b.split_fill('role=textbox[name="E=mail"]=a@b') == ('role=textbox[name="E=mail"]', "a@b")
    assert b.split_fill("#q=") == ("#q", "")
    with pytest.raises(SystemExit):
        b.parse_args(["http://h/", "--fill", "#nofield"])
    with pytest.raises(SystemExit):
        b.parse_args(["http://h/", "--xss", "<x>"])
    with pytest.raises(SystemExit):  # no abbreviation: --xs would dodge the scanner classification
        b.parse_args(["http://h/", "--xs", "bhX1"])


def test_mapper_without_xss_scanner_with_it():
    assert b.phase_kind(b.parse_args(["http://h/"])) == "mapper"
    assert b.phase_kind(b.parse_args(["http://h/", "--xss", "bhX1"])) == "scanner"
    for cmd in ("bh-browse http://h/", "bh-agent browse http://h/ --routes"):
        assert c.runs_mapper(cmd) and not c.runs_scanner(cmd) and c.uses_arsenal(cmd), cmd
    for cmd in (
        "bh-browse 'http://h/#/s?q=x' --xss bhX1",
        "/opt/bh/bin/bh-browse http://h/ --as a --xss=bhX1",
        "bh-agent browse http://h/ \\\n  --xss bhX1",
    ):
        assert c.runs_scanner(cmd), cmd
    assert not c.uses_manual_http("bh-browse http://h/")  # not a hand-made request: no tool lock


def test_xss_refused_without_scanners(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("BH_DIR", str(tmp_path))
    monkeypatch.setenv("BH_SCANNERS", "0")
    ev = {"tool_name": "Bash", "tool_input": {"command": "bh-browse http://h/ --xss bhX1"}}
    reason = hooks.pre_tool_use(ev)["hookSpecificOutput"]["permissionDecisionReason"]
    assert reason.startswith(c.RULES_MARK)
    assert hooks.pre_tool_use({"tool_name": "Bash", "tool_input": {"command": "bh-browse http://h/"}}) is None
    with pytest.raises(SystemExit) as exc:
        b.main(["http://h/", "--xss", "bhX1"])
    assert str(exc.value).startswith(c.RULES_MARK)
    assert not (tmp_path / c.RAW).exists()  # refused before anything ran


def test_route_filter_drops_offsite_and_noise():
    host = "app.example.com"
    assert b.route_decision("https://app.example.com/api/x", "xhr", host, False) is None
    assert b.route_decision("https://cdn.app.example.com/a.js", "script", host, False) is None  # subdomain
    assert b.route_decision("https://fonts.gstatic.com/x.woff2", "font", host, True) == "offsite"
    assert b.route_decision("https://evilapp.example.com/", "document", host, False) == "offsite"
    assert b.route_decision("https://example.com/", "document", host, False) == "offsite"  # parent is not in
    assert b.route_decision("https://app.example.com/main.js.map", "other", host, False) == "sourcemap"
    assert b.route_decision("https://app.example.com/favicon.ico", "other", host, True) == "favicon"
    assert b.route_decision("https://app.example.com/logo.png", "image", host, False) == "image"
    assert b.route_decision("https://app.example.com/logo.png", "image", host, True) is None  # --shot
    assert b.same_site("data:text/plain,x", host)


def test_spa_routes_become_endpoints(tmp_path):
    assert b.spa_route("http://h:3000/#/search?q=1") == ("GET /#/search", ["q"])
    assert b.spa_route("http://h/#!/track/42") == ("GET /#/track/{id}", [])
    assert b.spa_route("http://h/#top") is None
    o = "http://h:3000"
    seen = [("GET", "http://h:3000/#/search?q=1", None), ("POST", "http://h:3000/rest/user/login", 401)]
    seen += [("GET", "https://other/x", 200), ("GET", "http://h:3000/main.js", 200)]
    items = b.endpoint_items(seen, o)
    assert b.add_endpoints(tmp_path, o, items) == ["GET /#/search", "GET /", "POST /rest/user/login"]
    assert b.add_endpoints(tmp_path, o, items) == []  # dedup on (origin, key)
    recs = c.read_jsonl(tmp_path / c.ENDPOINTS)
    assert {r["source"] for r in recs} == {"browse"} and recs[0]["params"] == ["q"]


def test_xss_verdict_needs_the_marker():
    alert = [{"type": "alert", "message": "bhX1"}]
    assert b.xss_confirmed("bhX1", alert, None)
    assert b.xss_confirmed("bhX1", [], "bhX1")
    assert not b.xss_confirmed("bhX1", [{"type": "alert", "message": "1"}], None)
    assert not b.xss_confirmed(None, alert, None)


def _fake(**kw) -> b.Result:
    r = b.Result(url="http://h:3000/", identity="alice", status=200, title="OWASP Juice Shop", seconds=2.8)
    r.requests, r.blocked, r.websockets = 41, Counter({"cdnjs.cloudflare.com": 6, "image": 2}), 1
    r.xhr = [("GET", f"http://h:3000/api/x{i}?a=1", 200) for i in range(30)]
    r.dialogs, r.marker = [{"type": "alert", "message": "bhX1"}], "bhX1"
    r.console_errors = ["TypeError: x"] * 5
    form = {"method": "POST", "action": "http://h:3000/rest/x", "fields": ["a", "b"]}
    r.forms = [{**form, "id": f"f{i}"} for i in range(9)]
    r.new_keys = [f"GET /#/r{i}" for i in range(40)] + ["GET /api/Users"]
    r.a11y = b.a11y_summary('- heading "Welcome" [level=1]\n- textbox "Email": alice@x\n- button "Log in"\n- img')
    r.steps = [f"{i} --click #x failed: timeout" for i in range(10)]
    r.shot, r.raw = ("/work/.bh/raw/browse-x/shot.png", 1024, 768), "/work/.bh/raw/browse-x"
    for k, v in kw.items():
        setattr(r, k, v)
    return r


def test_summary_is_bounded_and_says_what_matters():
    lines = b.render(_fake())
    text = "\n".join(lines)
    assert len(lines) <= b.SUMMARY_LINES and all(len(x) <= b.LINE_CHARS for x in lines)
    assert lines[0].startswith('bh-browse http://h:3000/ as=alice: 200, title "OWASP Juice Shop"')
    assert "xss CONFIRMED (marker bhX1)" in text and "cdnjs.cloudflare.com ×6" in text
    assert lines[-1] == "raw: /work/.bh/raw/browse-x/"
    small = "\n".join(b.render(_fake(dialogs=[], steps=[], forms=[], xhr=[])))
    assert "not confirmed" in small and "CONFIRMED" not in small.replace("not confirmed", "")
    assert 'heading "Welcome"' in small and 'textbox "Email" = alice@x' in small and "1049 tokens" in small


def test_bh_agent_starts_without_playwright(tmp_path):
    """The sandbox entry point and every other builtin import nothing from playwright."""
    code = (
        "import sys; sys.modules['playwright'] = None; "  # any import of playwright now raises ImportError
        "from bh.agent import main, tools, hooks, contract, browse; "
        "assert 'playwright.sync_api' not in sys.modules; print('ok')"
    )
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "BH_DIR": str(tmp_path)}
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=False)
    assert out.stdout.strip() == "ok", out.stderr


def test_missing_playwright_is_an_error_not_a_crash(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "playwright", None)  # an image without playwright
    r = b.Result(url="http://h/")
    b.run(b.parse_args(["http://h/"]), tmp_path, r)
    assert r.state.startswith("error") and "playwright is not installed" in r.error


def test_bh_browse_is_a_link_to_the_entry_point():
    link = ROOT / "container/agent/bin/bh-browse"
    assert link.is_symlink() and os.readlink(link) == "bh-agent"
