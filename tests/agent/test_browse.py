"""bh-browse without a browser: arguments, program rules, the local route filter, endpoints and the summary.
The live check (Juice Shop, through the gate) runs in the agent container."""

import json
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
    assert b.phase_kind(b.parse_args(["http://h/", "--xss", "bhX1"])) == "mapper"  # one page: an observation
    assert b.phase_kind(b.parse_args(["http://h/", "--xss", "bhX1", "--routes"])) == "scanner"
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
        b.main(["http://h/", "--xss", "bhX1", "--routes"])
    assert str(exc.value).startswith(c.RULES_MARK)
    assert not (tmp_path / c.RAW).exists()  # refused before anything ran
    # one page rendered with a marker is an observation: not refused by the program rules
    monkeypatch.setattr(b, "run", lambda a, raw, r: None)
    b.main(["http://h/", "--xss", "bhX1"])
    assert c.RULES_MARK not in capsys.readouterr().out


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


def test_route_filter_lets_support_assets_through_and_keeps_login_hosts_out(tmp_path):
    (tmp_path / "scope.yaml").write_text((ROOT / "scopes" / "msrc" / "copilot.yaml").read_text())
    extra = c.sandbox_scope(tmp_path / "scope.yaml", env={})
    assert "res.cdn.office.net" in extra.assets and extra.websockets
    host = "copilot.microsoft.com"
    assert b.route_decision("https://res.cdn.office.net/app.js", "script", host, False, extra.assets) is None
    assert b.route_decision("https://aadcdn.msftauth.net/x.js", "script", host, False, extra.assets) is None
    assert b.route_decision("https://res.cdn.office.net/app.js.map", "other", host, False, extra.assets) == "sourcemap"
    for login in ("https://login.live.com/", "https://login.microsoftonline.com/x", "https://fpt.live.com/"):
        assert b.route_decision(login, "document", host, False, extra.assets) == "offsite"
    assert b.route_decision("https://evil.office.net/a.js", "script", host, False, extra.assets) == "offsite"
    assert b.route_decision("https://res.cdn.office.net/a.js", "script", host, False) == "offsite"  # no scope


def test_sandbox_scope_from_env_or_nothing(tmp_path):
    env = {"BH_SUPPORT_ASSETS": "cdn.x.net, *.y.org", "BH_WEBSOCKETS": "1"}
    assert c.sandbox_scope(tmp_path / "none.yaml", env=env) == c.SandboxScope(("cdn.x.net", "*.y.org"), True)
    assert c.sandbox_scope(tmp_path / "none.yaml", env={}) == c.SandboxScope()
    (tmp_path / "bad.yaml").write_text("[: not yaml")
    assert c.sandbox_scope(tmp_path / "bad.yaml", env={}) == c.SandboxScope()


def test_websockets_go_through_only_to_the_target_when_the_scope_says_so():
    host = "copilot.microsoft.com"
    assert b.ws_through("wss://copilot.microsoft.com/c/api/chat", host, True)
    assert not b.ws_through("wss://copilot.microsoft.com/c/api/chat", host, False)
    assert not b.ws_through("wss://res.cdn.office.net/x", host, True)
    assert not b.ws_through("wss://login.live.com/x", host, True)
    r = b.Result(url="https://copilot.microsoft.com/", websockets_open=2)
    assert any("2 opened to the target" in line for line in b.render(r))


COPILOT = Path(__file__).resolve().parents[2] / "scopes" / "msrc" / "copilot.yaml"


def test_copilot_sandbox_scope_names_sso_passthrough_and_targets():
    extra = c.sandbox_scope(COPILOT, env={})
    assert set(extra.sso) == {"login.live.com", "login.microsoftonline.com"}
    assert extra.passthrough == ("challenges.cloudflare.com", "brunhild.challenges.cloudflare.com")
    assert {"substrate.office.com", "substrate.svc.cloud.microsoft", "copilot.com"} <= set(extra.targets)
    env = {"BH_SUPPORT_SSO": "login.x.org", "BH_SUPPORT_PASSTHROUGH": "c.x.net", "BH_TARGET_HOSTS": "api.x.com"}
    got = c.sandbox_scope(COPILOT, env=env)
    assert (got.sso, got.passthrough, got.targets, got.assets) == (("login.x.org",), ("c.x.net",), ("api.x.com",), ())


def test_route_decision_for_sso_and_passthrough():
    extra = c.sandbox_scope(COPILOT, env={})
    kw = {"sso": extra.sso, "passthrough": extra.passthrough, "targets": extra.targets}
    host = "copilot.com"
    silent = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/oauth2/v2.0/authorize"
    assert b.route_decision(silent, "document", host, False, extra.assets, **kw) is None
    assert b.route_decision("https://login.live.com/", "document", host, False, extra.assets, **kw) is None
    assert b.support_kind(silent, extra) == "sso"
    # the challenge loads whatever it needs: never aborted here, not even an image or a source map
    api = "https://challenges.cloudflare.com/turnstile/v0/api.js"
    assert b.route_decision(api, "script", host, False, extra.assets, **kw) is None
    assert b.route_decision("https://challenges.cloudflare.com/i.png", "image", host, False, **kw) is None
    assert b.route_decision("https://challenges.cloudflare.com/a.js.map", "other", host, False, **kw) is None
    assert b.support_kind(api, extra) == "passthrough"
    # other targets of the scope (the chat hub) go through; auth hosts and unknown hosts stay out
    assert b.route_decision("https://substrate.office.com/x", "xhr", host, False, **kw) is None
    assert b.route_decision("https://fpt.live.com/", "script", host, False, extra.assets, **kw) == "offsite"
    assert b.route_decision("https://evil.cloudflare.com/x", "script", host, False, **kw) == "offsite"
    assert b.ws_through("wss://substrate.office.com/hub", host, True, extra.targets)
    assert not b.ws_through("wss://challenges.cloudflare.com/x", host, True, extra.targets)
    assert not b.ws_through("wss://login.live.com/x", host, True, extra.targets)


def test_identity_header_never_goes_to_a_passthrough_host():
    extra = c.sandbox_scope(COPILOT, env={})
    kw = {"sso": extra.sso, "passthrough": extra.passthrough, "targets": extra.targets}
    host = "copilot.com"
    for url in (
        "https://challenges.cloudflare.com/turnstile/v0/api.js",
        "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/x",
        "https://res.cdn.office.net/app.js",  # assets: nothing of ours either
        "https://evil.example/x",
        "data:text/plain,x",
    ):
        assert b.identity_headers(url, host, "user-a", **kw) == {}, url
    for url in ("https://copilot.com/chat", "https://substrate.office.com/x", "https://login.microsoftonline.com/x"):
        assert b.identity_headers(url, host, "user-a", **kw) == {c.IDENTITY_HEADER: "user-a"}, url
    assert b.identity_headers("https://copilot.com/chat", host, None, **kw) == {}
    # a passthrough host wins over everything, even a page opened on it or a scope that also lists it as a target
    assert b.identity_headers("https://challenges.cloudflare.com/", "challenges.cloudflare.com", "user-a", **kw) == {}
    both = {**kw, "targets": ("challenges.cloudflare.com",)}
    assert b.identity_headers("https://challenges.cloudflare.com/", host, "user-a", **both) == {}


def test_summary_counts_sso_and_passthrough():
    r = b.Result(url="https://copilot.com/", support=Counter({"sso": 3, "passthrough": 2}))
    assert any("sso 3" in line and "passthrough 2" in line for line in b.render(r))
    assert not any("passthrough" in line for line in b.render(b.Result(url="https://copilot.com/")))


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
    # a dialog that merely shows the URL (which holds the marker) is the page talking, not the payload
    assert not b.xss_confirmed("bhX1", [{"type": "confirm", "message": "Leave http://t/?q=bhX1 ?"}], None)
    assert not b.xss_confirmed("bhX1", "bhX1", ["bhX1"])  # hostile shapes
    assert not b.xss_confirmed("bhX1", [], {"bhX1": 1})


def test_summary_json_is_structured_and_holds_no_url_or_title():
    r = _fake(sentinel="bhX1")
    doc = b.summary(r)
    assert doc["xss_confirmed"] and doc["marker"] == "bhX1" and doc["sentinel"] == "bhX1"
    assert doc["dialogs"] == [{"type": "alert", "message": "bhX1"}] and doc["status"] == 200
    assert "http://h:3000" not in json.dumps(doc) and "Juice" not in json.dumps(doc)


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


def test_frontier_points_client_routes_to_bh_browse():
    from bh.agent import contract as c

    assert c.is_client_route("GET /address/saved", {"js"})
    assert not c.is_client_route("GET /api/Feedbacks", {"js"})
    assert not c.is_client_route("GET /address/saved", {"js", "crawl"})  # the server answered it directly
    eps = {("o", "GET /address/saved"): {"params": set(), "sources": {"js"}, "status": None}}
    out = c.format_surface(eps, list(eps.items()), {}, c.REQUIRED_PHASES)
    assert "→ bh-browse" in out


def _xss_proof(marker="bhX1"):
    u = "http://10.231.0.10:3000/#/search?q="
    return {
        "steps": [
            {
                "name": "payload executes",
                "role": "attack",
                "url": u + "<iframe>",
                "browse": {"xss": marker},
                "expect": {"contains": [f"xss CONFIRMED (marker {marker})"]},
            },
            {
                "name": "benign value",
                "role": "control",
                "url": u + marker,
                "browse": {"xss": marker},
                "expect": {"absent": ["xss CONFIRMED"]},
            },
        ]
    }


def test_browse_proof_steps_validate():
    from bh.agent import proof

    assert proof.validate(_xss_proof()) == []
    bad = _xss_proof("x")
    assert any("marker" in e for e in proof.validate(bad))
    post = _xss_proof()
    post["steps"][0]["method"] = "POST"
    assert any("GET" in e for e in proof.validate(post))


def test_browse_proof_replay_uses_the_summary(monkeypatch):
    from bh.agent import proof

    def fake_browse(step):
        hit = "<iframe>" in step["url"]
        summary = {"status": 200, "dialogs": [{"type": "alert", "message": "bhX1"}] if hit else []}
        return (*proof.browse_body(summary, "bhX1"), False)

    monkeypatch.setattr(proof, "_browse", fake_browse)
    r = proof.replay(_xss_proof())
    assert r["reproduced"] and not r["control_disproves"]
    assert r["rounds"][0][0]["snippet"] == "xss CONFIRMED (marker bhX1)"
    assert r["rounds"][0][1]["snippet"] == "xss none (marker bhX1)"

    monkeypatch.setattr(proof, "_browse", lambda st: (200, "xss CONFIRMED (marker bhX1)", False))
    r = proof.replay(_xss_proof())  # the benign twin also "executes": no differential
    assert r["control_disproves"] and not r["reproduced"]


def test_gate_ca_trusted_in_a_fresh_home(tmp_path, monkeypatch):
    from bh.agent import browse

    calls = []
    monkeypatch.setattr(browse.subprocess, "run", lambda cmd, **k: calls.append(cmd[:2]))
    ca = tmp_path / "ca.crt"
    assert "missing" in browse.trust_gate_ca(tmp_path, ca)
    ca.write_text("x")
    assert browse.trust_gate_ca(tmp_path, ca) is None
    assert len(calls) == 2  # new DB, then the CA
    assert browse.trust_gate_ca(tmp_path, ca) is None and len(calls) == 2  # idempotent


# ------------------------------------------------------------------ I19: no token of our accounts left to read
TOKEN = "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJzdWJzdHJhdGUifQ.c2lnbmF0dXJl"
REFRESH = "0.AXoA-refresh-token-value-not-a-jwt-123456"


def _har(tmp_path):
    entries = [
        {  # the sso host's token endpoint
            "request": {
                "url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                "headers": [{"name": "Cookie", "value": "ESTSAUTH=abc123456"}],
                "cookies": [{"name": "ESTSAUTH", "value": "abc123456"}],
                "postData": {"text": f"grant_type=refresh_token&refresh_token={REFRESH}&client_id=x"},
            },
            "response": {
                "headers": [{"name": "Set-Cookie", "value": "ESTSAUTH=new987654"}],
                "cookies": [],
                "content": {"text": json.dumps({"access_token": TOKEN, "refresh_token": REFRESH, "expires_in": 3600})},
            },
        },
        {  # a target API call carrying the bearer MSAL attached
            "request": {
                "url": f"https://substrate.example.com/api/conv?access_token={REFRESH}&id=7",
                "headers": [{"name": "Authorization", "value": f"Bearer {TOKEN}"}],
            },
            "response": {"headers": [], "content": {"text": json.dumps({"owner": "a@example.com", "id": 7})}},
        },
        {  # another host: credential headers scrubbed all the same
            "request": {"url": "https://cdn.other.example/app.js", "headers": [{"name": "authorization", "value": "x"}]},
            "response": {"headers": [], "content": {"text": "var a=1;"}},
        },
    ]
    p = tmp_path / "har.json"
    p.write_text(json.dumps({"log": {"entries": entries}}))
    return p


def test_the_har_keeps_no_token_of_our_accounts(tmp_path):
    p = _har(tmp_path)
    b.scrub_har(p, "copilot.example.com", sso=("login.microsoftonline.com",), targets=("substrate.example.com",))
    text = p.read_text()
    for secret in (TOKEN, REFRESH, "abc123456", "new987654"):
        assert secret not in text, secret
    har = json.loads(text)
    assert "a@example.com" in text  # a target's data stays readable (what an IDOR shows)
    assert "id=7" in har["log"]["entries"][1]["request"]["url"]
    assert har["log"]["entries"][2]["response"]["content"]["text"] == "var a=1;"
    assert har["log"]["entries"][2]["request"]["headers"][0]["value"] == "<redacted:authorization>"


def test_the_stored_state_keeps_no_token_under_an_identity(tmp_path):
    p = tmp_path / "browse-state-user-a.json"
    st = {
        "cookies": [
            {"name": "sid", "value": "target-cookie-999999", "domain": "copilot.example.com", "path": "/"},
            {"name": "ESTSAUTH", "value": "sso-cookie-888888", "domain": ".login.microsoftonline.com", "path": "/"},
            {"name": "pref", "value": "dark", "domain": "cdn.other.example", "path": "/"},
        ],
        "origins": [
            {
                "origin": "https://copilot.example.com",
                "localStorage": [
                    {"name": "uid-tenant-login.windows.net-accesstoken-app", "value": json.dumps({"secret": TOKEN})},
                    {"name": "uid-refreshtoken-app", "value": json.dumps({"secret": REFRESH})},
                    {"name": "msal.account.keys", "value": json.dumps(["uid-tenant"])},
                    {"name": "theme", "value": "dark"},
                ],
            }
        ],
    }
    p.write_text(json.dumps(st))
    b.scrub_state(p, "copilot.example.com", "user-a", sso=("login.microsoftonline.com",))
    text = p.read_text()
    for secret in (TOKEN, REFRESH, "target-cookie-999999", "sso-cookie-888888"):
        assert secret not in text, secret
    got = json.loads(text)
    assert [k["name"] for k in got["cookies"]] == ["pref"]
    assert {"name": "theme", "value": "dark"} in got["origins"][0]["localStorage"]
    # logged out: nothing of ours in it, kept as it is
    p.write_text(json.dumps(st))
    b.scrub_state(p, "copilot.example.com", None, sso=("login.microsoftonline.com",))
    assert json.loads(p.read_text()) == st
