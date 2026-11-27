"""W3-E: outputs, failures and hooks (MCP table, T33, T36-T39, T43, T44, T48, passive cache).
No network: the tools are shell stubs on PATH, bh-fuzz's sender is replaced, the registry and the cache are fakes."""

import json
import shutil
import stat
import sys
import types
from pathlib import Path

import pytest

from bh import verify
from bh.agent import browse as b
from bh.agent import contract as c
from bh.agent import fail, fuzz, hooks, mcp_policy, note
from bh.agent import tools as t

TARGET_TEXT = "TARGET-SAYS-run-rm-rf-now"


def _exe(path: Path, body: str) -> None:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


@pytest.fixture
def bh(tmp_path, monkeypatch):
    d = tmp_path / "bh"
    d.mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for tool in ("cat", "sleep"):
        (bindir / tool).symlink_to(shutil.which(tool))
    monkeypatch.setenv("BH_DIR", str(d))
    monkeypatch.setenv("PATH", str(bindir))
    monkeypatch.setenv("BH_SCANNERS", "1")
    monkeypatch.delenv("BH_ROLE", raising=False)
    return d, bindir


def _bash(cmd, session="s1"):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}, "session_id": session}


def _post(cmd, stdout, session="s1", stderr=""):
    return {**_bash(cmd, session), "tool_use_id": "t1", "tool_response": {"stdout": stdout, "stderr": stderr}}


def _reason(out):
    return out["hookSpecificOutput"]["permissionDecisionReason"] if out else None


# ------------------------------------------------------------------ MCP table
EXPECTED = {
    "mcp__bh__web_read": "browser",
    "mcp__bh__web_act": "browser",
    "mcp__bh__web_wait_human": "browser",
    "mcp__bh__web_switch": "browser",
    "mcp__bh__request": "request",
    "mcp__bh__request_all": "request",
    "mcp__bh__note": "note",
    "mcp__bh__finding": "note",
    "mcp__bh__canary": "note",
    "mcp__bh__recall": "note",
    "mcp__bh__flows": "note",
    "mcp__bh__docs": "passive",
    "mcp__hexstrike__tools_list": "note",
    "mcp__hexstrike__tool_help": "note",
}


@pytest.mark.parametrize(("name", "klass"), sorted(EXPECTED.items()))
def test_mcp_table_line(bh, name, klass):
    assert mcp_policy.classify(name, {})[0] == klass
    out = hooks.pre_tool_use({"tool_name": name, "tool_input": {}, "session_id": "s"})
    assert out is None, name  # every class of the table runs (a request without URL has no lock to check)
    rec = c.read_jsonl(bh[0] / c.COMMANDS)[-1]
    assert (rec["tool"], rec["klass"], rec["decision"]) == (name, klass, "allow")


def test_mcp_request_tools_are_under_the_lock(bh):
    for name in ("mcp__bh__request", "mcp__bh__request_all"):
        out = hooks.pre_tool_use({"tool_name": name, "tool_input": {"url": "http://h.test/api/x"}})
        assert _reason(out).startswith(c.LOCK_MARK), name


def _registry(monkeypatch, tools):
    pkg, reg = types.ModuleType("bh.agent.hexstrike"), types.ModuleType("bh.agent.hexstrike.registry")
    reg.TOOLS = tools
    pkg.registry = reg
    monkeypatch.setitem(sys.modules, "bh.agent.hexstrike", pkg)
    monkeypatch.setitem(sys.modules, "bh.agent.hexstrike.registry", reg)


def _run(tool, **arguments):
    return {"tool_name": mcp_policy.HEXSTRIKE_RUN, "tool_input": {"name": tool, **arguments}, "session_id": "s"}


def test_hexstrike_tool_run_takes_the_registry_class(bh, monkeypatch):
    ns = types.SimpleNamespace
    _registry(
        monkeypatch,
        {
            "jq": ns(klass="local"),
            "amass": ns(klass="passive"),
            "msf": ns(klass="refused", reason="exploitation frameworks are never run"),
            "nc": ns(klass="no-route", reason="raw TCP cannot cross the gate"),
            "nmap": ns(klass="scanner"),
        },
    )
    assert hooks.pre_tool_use(_run("jq")) is None
    assert hooks.pre_tool_use(_run("amass")) is None
    refused = _reason(hooks.pre_tool_use(_run("msf")))
    assert refused.startswith(c.RULES_MARK) and "msf" in refused and "exploitation frameworks are never run" in refused
    no_route = _reason(hooks.pre_tool_use(_run("nc")))
    assert "no-route" in no_route and "raw TCP cannot cross the gate" in no_route
    assert "unknown MCP tool" in _reason(hooks.pre_tool_use(_run("not-in-registry")))
    assert hooks.pre_tool_use(_run("nmap")) is None  # a program that allows scanners
    monkeypatch.setenv("BH_SCANNERS", "0")  # MSRC
    assert "forbids automated scanners" in _reason(hooks.pre_tool_use(_run("nmap")))
    assert [r["klass"] for r in c.read_jsonl(bh[0] / c.COMMANDS)] == [
        "local",
        "passive",
        "refused",
        "no-route",
        "unknown",
        "scanner",
        "scanner",
    ]


def test_hexstrike_without_registry_is_refused(bh, monkeypatch):
    monkeypatch.setitem(sys.modules, "bh.agent.hexstrike", None)  # the module is not there: ImportError
    assert mcp_policy.classify(mcp_policy.HEXSTRIKE_RUN, {"name": "jq"})[0] == "unknown"
    assert "unknown MCP tool" in _reason(hooks.pre_tool_use(_run("jq")))
    _registry(monkeypatch, {"jq": types.SimpleNamespace(klass="local")})
    assert mcp_policy.classify(mcp_policy.HEXSTRIKE_RUN, {})[0] == "unknown"  # no tool name
    assert mcp_policy.classify(mcp_policy.HEXSTRIKE_RUN, {"name": ["jq"]})[0] == "unknown"


# ------------------------------------------------------------------ T33 repetition
def test_third_identical_command_is_refused_with_its_answer(bh):
    d, _ = bh
    cmd = "grep -c x   /work/a.txt"
    out = "\n".join(f"line {i}" for i in range(40))
    for _ in range(2):
        assert hooks.pre_tool_use(_bash(cmd)) is None
        hooks.post_tool_use(_post(cmd, out))
    reason = _reason(hooks.pre_tool_use(_bash("grep  -c x /work/a.txt")))  # spaces normalized
    lines = reason.splitlines()
    assert lines[0] == "[bh-repeat] this exact command already ran twice; its answer will not change:"
    assert lines[1:16] == [f"line {i}" for i in range(15)] and "line 15" not in reason
    raw = Path(lines[-1].removeprefix("raw: "))
    assert raw.read_text() == out
    assert hooks.pre_tool_use(_bash(cmd, session="s2")) is None  # another session starts again
    assert c.read_jsonl(d / c.COMMANDS)[-2]["decision"] == "deny"


@pytest.mark.parametrize(
    "cmd",
    [
        "bh-agent replay /work/proof.json",
        "bh-web text",
        "bh-note frontier",
        "bh-recall 'idor on orders' --url http://h/ --class idor",
        "sleep 5",
        "cat x | bh-web net --body 3",
    ],
)
def test_repetition_exemptions(bh, cmd):
    for _ in range(3):
        hooks.post_tool_use(_post(cmd, "same"))
    assert hooks.pre_tool_use(_bash(cmd)) is None


# ------------------------------------------------------------------ T36 typed failures
def test_fail_line_and_classes():
    assert fail.line("rate", "wait") == "[bh-fail] rate: wait"
    for k in fail.CLASSES:
        assert fail.line(k).startswith(f"[bh-fail] {k}: ") and "\n" not in fail.line(k)
    assert len(set(fail.ACTIONS.values())) == len(fail.CLASSES) == 8
    cases = [
        ((124, "", False), "timeout"),
        ((0, "", True), "timeout"),
        ((127, "", False), "missing-tool"),
        ((1, "HTTP 429 Too Many Requests", False), "rate"),
        ((1, "X-BH-Gate: denied", False), "gate-denied"),
        ((1, "flag provided but not defined: -zz", False), "bad-argument"),
        ((2, "", False), "bad-argument"),
        ((1, "dial tcp 10.0.0.1:443: connect: connection refused", False), "unreachable"),
        ((1, "401 Unauthorized", False), "auth"),
        ((1, "json: cannot unmarshal", False), "parse"),
        ((1, "", False), "parse"),
    ]
    for args, klass in cases:
        assert fail.classify(*args) == klass, args
    assert "retry" not in fail.ACTIONS["rate"].replace("nothing is retried", "")


def _katana(bindir, lines, rc=0, err="", sleep=0):
    rows = "\n".join(json.dumps(x) for x in lines)
    _exe(
        bindir / "katana",
        f'cat <<"EOF"\n{rows}\nEOF\n'
        + (f"echo '{err}' >&2\n" if err else "")
        + (f"exec sleep {sleep}\n" if sleep else "")
        + f"exit {rc}\n",
    )


def _row(url):
    return {"request": {"endpoint": url, "method": "GET"}, "response": {"status_code": 200}}


def test_failed_builtin_says_its_class_and_writes_nothing(bh, capsys):
    d, bindir = bh
    _katana(bindir, [_row("http://h.test/a?x=1")], rc=1, err=f"dial tcp: connection refused {TARGET_TEXT}")
    t.crawl(t.Job("crawl", "http://h.test/", None, 30))
    out = capsys.readouterr().out.splitlines()
    fail_lines = [x for x in out if x.startswith(fail.MARK)]
    assert fail_lines == [fail.line("unreachable")] and TARGET_TEXT not in fail_lines[0]
    assert out[-1].startswith("next: curl -sS --max-time 10")
    assert c.read_jsonl(d / c.ENDPOINTS) == [] and c.read_jsonl(d / c.TOUCHED) == []
    assert c.missing_phases(d, "http://h.test:80")[0] == "crawl"


def test_partial_builtin_keeps_its_output_and_is_not_done(bh, capsys):
    d, bindir = bh
    _katana(bindir, [_row("http://h.test/a?x=1")], sleep=5)
    t.crawl(t.Job("crawl", "http://h.test/", None, 1))
    out = capsys.readouterr().out
    assert "[partial (timeout)]" in out and "\npartial: true" in out and fail.line("timeout") in out
    assert [e["key"] for e in c.read_jsonl(d / c.ENDPOINTS)] == ["GET /a"]  # what it observed is kept
    assert c.read_jsonl(d / c.TOUCHED) == []
    entry = c.read_json(d / c.COVERAGE, {})["http://h.test:80"]["crawl"]
    assert not c.phase_done(entry) and "crawl" in c.missing_phases(d, "http://h.test:80")


def test_rate_limit_stops_fuzz_without_retry(bh, monkeypatch, capsys):
    d, _ = bh
    monkeypatch.setenv("BH_RPS", "1000")
    sent = []

    def send(method, url, body, ctype, who):
        sent.append(url)
        return fuzz.Answer(429 if len(sent) == 3 else 200, b"ok " + TARGET_TEXT.encode())

    monkeypatch.setattr(fuzz, "send", send)
    fuzz.main(["http://h.test/s?q=shoes", "-p", "q"])
    out = capsys.readouterr().out
    assert len(sent) == 3 and fail.line("rate") in out
    assert out.strip().splitlines()[-1] == "next: bh-note frontier: another lead; this one later; leads, not findings"
    assert c.read_jsonl(d / c.TOUCHED) == [] and not list((d / c.RAW).glob("fuzz-*/leads.json"))
    assert TARGET_TEXT not in "".join(x for x in out.splitlines() if x.startswith(fail.MARK))


def test_note_refusal_is_one_line_per_field_with_valid_values(capsys):
    with pytest.raises(SystemExit):
        note.main(["finding", "t", "--url", "http://h/", "--proof", "p.json"])
    err = capsys.readouterr().err
    assert "bh-note finding refused:" in err
    assert "  - --severity is required (valid: critical|high|medium|low|info)" in err
    assert "  - --class is required" in err and "  - --summary is required" in err
    with pytest.raises(SystemExit):
        note.main(["blocked", "nope", "title"])
    err = capsys.readouterr().err
    assert "reason: 'nope' is not valid; valid: auth|account|waf|" in err and "usage:" not in err


# ------------------------------------------------------------------ T37 outputs
def test_binary_output_shows_hex_and_path(bh):
    out = hooks.post_tool_use(_post("cat img.png", "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + "x" * 50))
    shown = out["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
    assert shown.startswith("[bh] binary stdout") and "c2 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44" in shown
    path = Path(shown.split("Full stdout: ")[1].split(" (")[0])
    assert path.read_text().startswith("\x89PNG")
    one_bad = hooks.post_tool_use(_post("curl -m 5 http://h/", "caf� " + "ok " * 200))
    assert one_bad is None  # one broken character in a page: not binary


def test_minified_bundle_is_named_not_cut(bh):
    js = "!function(e){var t={};" + "x" * 30_000 + 'fetch("/api/x")}();'
    out = hooks.post_tool_use(_post("curl -m 5 http://h/main.js", js + "\n//# sourceMappingURL=main.js.map"))
    shown = out["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
    assert shown.startswith("[bh] minified js stdout: 2 lines") and "bh-crawl" in shown and "x" * 100 not in shown
    assert hooks.bundle_type('{"a": 1}') == "json" and hooks.bundle_type(".a{color:red}") == "css"
    long_text = "\n".join(f"line {i}" for i in range(500))
    shown = hooks.post_tool_use(_post("seq 500", long_text))["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
    assert "lines elided" in shown  # neither binary nor bundle: head and tail as before


# ------------------------------------------------------------------ T38 timeouts
@pytest.mark.parametrize(
    "cmd",
    [
        "curl -s http://h.test/",
        "curl -sS -H 'x: y' http://h.test/ | jq .",
        "ls && wget http://h.test/a",
        "X=1 curl http://h.test/",
        "curl -dm=1 http://h.test/",  # -d takes `m=1`: no time limit
    ],
)
def test_unbounded_curl_or_wget_is_refused_with_the_form(bh, cmd):
    for phase in c.REQUIRED_PHASES:  # the lock is open: only the time limit is missing
        c.record_phase(bh[0], "http://h.test:80", phase, status="ok", count=1, raw="")
    reason = _reason(hooks.pre_tool_use(_bash(cmd)))
    assert reason.startswith("[bh-fail] bad-argument:") and "run instead:" in reason
    assert "curl --max-time 30" in reason or "wget --timeout=30" in reason


@pytest.mark.parametrize(
    "cmd",
    [
        "curl -m 10 http://h.test/",
        "curl -sSm10 http://h.test/",
        "curl --max-time 5 http://h.test/",
        "timeout 20 curl http://h.test/",
        "wget -T 10 http://h.test/",
        "wget --timeout=10 http://h.test/",
        "echo curl http://h.test/",
        "q /api/x",
        "python3 -c 'print(1)'",
        "grep curl notes.txt",
    ],
)
def test_bounded_or_other_commands_pass(bh, cmd):
    assert hooks.timeout_decision(cmd) is None


# ------------------------------------------------------------------ T39 last line
def test_crawl_ends_with_coverage_then_next(bh, capsys):
    d, bindir = bh
    c.append_jsonl(d / c.TOUCHED, {"origin": "http://h.test:80", "key": "GET /a", "via": "manual"})
    _katana(bindir, [_row("http://h.test/a"), _row("http://h.test/b?id=1")])
    t.crawl(t.Job("crawl", "http://h.test/", None, 30))
    out = capsys.readouterr().out.strip().splitlines()
    assert out[-2] == "2 routes in, 1 tested, missing: GET /b"
    assert out[-1] == "next: bh-content http://h.test:80"


def test_verdict_paragraph_is_bounded_by_the_code():
    assert len(verify.verdict_paragraph("word " * 1000)) == verify.VERDICT_MAX == 600
    assert verify.verdict_paragraph("a\n\n b") == "a b"


# ------------------------------------------------------------------ T43 bh-fuzz
class App:
    """A search page: reflects q raw, answers 500 to a quote."""

    def __init__(self):
        self.sent = []

    def __call__(self, method, url, body, ctype, who):
        from urllib.parse import parse_qs, urlsplit

        self.sent.append(url)
        q = parse_qs(urlsplit(url).query, keep_blank_values=True).get("q", [""])[0]
        if q.endswith("'"):
            return fuzz.Answer(500, b"error")
        return fuzz.Answer(200, b"<p>results for " + q.encode() + b"</p>" + b"x" * 500)


def test_fuzz_keeps_only_deviations(bh, monkeypatch, capsys):
    d, _ = bh
    monkeypatch.setenv("BH_RPS", "1000")
    app = App()
    monkeypatch.setattr(fuzz, "send", app)
    fuzz.main(["http://h.test/search?q=shoes", "-p", "q", "--max", "50"])
    out = capsys.readouterr().out.strip().splitlines()
    assert len(app.sent) == fuzz.MAX_REQUESTS == 20
    assert out[-1].startswith("next: reproduce the first deviation") and out[-1].endswith("leads, not findings")
    assert any(x.strip().startswith("quote") and "status 200->500" in x for x in out)
    assert any(x.strip().startswith("markup") and "reflected raw" in x for x in out)
    assert not any(x.strip().startswith("negative") for x in out)  # same status, same size once the echo is set aside
    leads = json.loads(next((d / c.RAW).glob("fuzz-*/leads.json")).read_text())
    assert {x["probe"] for x in leads} >= {"quote", "markup"}
    assert c.read_jsonl(d / c.TOUCHED)[-1]["via"] == "fuzz"


@pytest.mark.parametrize(
    ("url", "param"),
    [
        ("http://h.test/o?id=5", "id"),
        ("http://h.test/o?uid=a", "uid"),
        ("http://h.test/o?user=bob", "user"),
        ("http://h.test/o?orderId=x", "orderId"),
        ("http://h.test/o?order_id=x", "order_id"),
        ("http://h.test/o?ref=12345", "ref"),  # the value reads as an identifier
    ],
)
def test_fuzz_refuses_identifiers(bh, monkeypatch, url, param):
    monkeypatch.setattr(fuzz, "send", lambda *a: pytest.fail("nothing is sent"))
    with pytest.raises(SystemExit, match=r"\[bh-rules\].*identifier"):
        fuzz.main([url, "-p", param])


def test_fuzz_identifier_names_are_words():
    assert not fuzz.is_identifier("paid", "yes") and not fuzz.is_identifier("valid", "1x")
    assert not fuzz.is_identifier("q", "shoes")


def test_fuzz_refused_where_scanners_are_forbidden(bh, monkeypatch):
    monkeypatch.setenv("BH_SCANNERS", "0")
    monkeypatch.setattr(fuzz, "send", lambda *a: pytest.fail("nothing is sent"))
    with pytest.raises(SystemExit, match="forbids automated scanners"):
        fuzz.main(["http://h.test/s?q=a", "-p", "q"])


def test_fuzz_body_parameter():
    assert fuzz.place("http://h/x", '{"q": "a", "n": 1}', "q") == ("json", "a")
    assert fuzz.place("http://h/x", "q=a&n=1", "n") == ("form", "1")
    _, body, ctype = fuzz.build("http://h/x", "q=a&n=1", "q", "form", "z'")
    assert body == b"q=z%27&n=1" and ctype == "application/x-www-form-urlencoded"


# ------------------------------------------------------------------ T44 profiles
def _tech(d, tech):
    rec = d / c.RAW / "recon-h-1"
    rec.mkdir(parents=True)
    (rec / "httpx.jsonl").write_text(json.dumps({"url": "http://h.test", "tech": tech, "webserver": "nginx"}) + "\n")


def _recorder(bindir, name, args_file, out=""):
    _exe(bindir / name, f'printf "%s\\n" "$@" > {args_file}\n' + (f"cat <<'EOF'\n{out}\nEOF\n" if out else ""))


def test_content_and_sqli_follow_the_recorded_technology(bh, tmp_path, capsys):
    d, bindir = bh
    _tech(d, ["PHP:8.1", "MySQL"])
    _recorder(bindir, "ffuf", tmp_path / "ffuf.args")
    _recorder(bindir, "sqlmap", tmp_path / "sqlmap.args")
    t.content(t.Job("content", "http://h.test/", None, 30), None)
    args = (tmp_path / "ffuf.args").read_text().split("\n")
    assert args[args.index("-e") + 1] == ".php"
    t.sqli(t.Job("sqli", "http://h.test/p?cat=1", None, 30), None, None, 3, "BEU")
    args = (tmp_path / "sqlmap.args").read_text().split("\n")
    assert args[args.index("--dbms") + 1] == "MySQL"
    assert "profile: php -> .php" in capsys.readouterr().out


def test_without_known_technology_nothing_changes(bh, tmp_path):
    _, bindir = bh
    _recorder(bindir, "ffuf", tmp_path / "ffuf.args")
    _recorder(bindir, "sqlmap", tmp_path / "sqlmap.args")
    t.content(t.Job("content", "http://h.test/", None, 30), None)
    t.sqli(t.Job("sqli", "http://h.test/p?cat=1", None, 30), None, None, 3, "BEU")
    assert "-e" not in (tmp_path / "ffuf.args").read_text().split("\n")
    assert "--dbms" not in (tmp_path / "sqlmap.args").read_text().split("\n")
    assert t.tech_extensions(["JavaScript", "jQuery"]) == [] and t.tech_dbms(["PostgreSQL:15"])[1] == "PostgreSQL"


def test_crawl_headers_give_the_technology_too(bh):
    d, _ = bh
    rec = d / c.RAW / "crawl-h-1"
    rec.mkdir(parents=True)
    row = {"request": {"endpoint": "http://h.test/"}, "response": {"headers": {"x_powered_by": "ASP.NET"}}}
    (rec / "katana.jsonl").write_text(json.dumps(row) + "\n")
    assert t.tech_extensions(t.known_tech("http://h.test:80")) == [("asp.net", ".aspx")]


# ------------------------------------------------------------------ T48 page inventory
def test_browse_names_keys_and_forms_never_values():
    secret = "s3cr3t-token-value"
    r = b.Result(url="http://h.test/", status=200, raw="/r")
    b.merge_inventory(
        r,
        [{"id": "login", "method": "POST", "action": "http://h.test/login", "fields": ["email", "password"]}],
        {"local": ["authToken", "cart"], "session": ["csrf"]},
    )
    b.merge_inventory(
        r,
        [{"id": "login", "method": "POST", "action": "http://h.test/login", "fields": ["email", "password"]}],
        {"local": ["authToken", "lang"]},
    )
    r.console_errors = [f"[step {i}] E{i}" for i in range(8)]
    r.steps = ["1 --fill #pw failed: timeout"]
    text = "\n".join(b.render(r))
    assert "storage keys: localStorage authToken, cart, lang · sessionStorage csrf" in text
    assert "form login: POST /login fields: email, password" in text and text.count("form login") == 1
    assert "console errors: 8: [step 0] E0" in text and "[step 4] E4" in text and "E5" not in text and "+3" in text
    assert secret not in text and "getItem" not in b.STORAGE_JS and ".value" not in b.FORMS_JS
    assert text.splitlines()[-1].startswith("next: submit the first form")


def test_browse_xss_not_confirmed_says_no_proof():
    r = b.Result(url="http://h.test/", marker="bhX1", raw="/r")
    lines = b.render(r)
    assert lines[-2] == fail.NO_PROOF == "[bh] no proof.json on this test" and lines[-1].startswith("next: grep")
    r.state = "error step 1"
    assert fail.line("bad-argument") in b.render(r)


# ------------------------------------------------------------------ passive cache (lot D)
def test_archive_uses_the_cache_when_there(bh, tmp_path, monkeypatch):
    d, bindir = bh
    (d / c.SCOPE).write_text("in_scope: [example.com]\n")
    store = {}
    cache = types.ModuleType("bh.agent.cache")
    cache.get = store.get
    cache.put = store.__setitem__
    monkeypatch.setitem(sys.modules, "bh.agent.cache", cache)
    _recorder(bindir, "gau", tmp_path / "gau.args", out="https://example.com/a?x=1")
    lines = t.archive(t.Job("recon", "https://example.com", None, 30), "example.com")
    assert (tmp_path / "gau.args").exists() and list(store.values()) == [["https://example.com/a?x=1"]]
    (tmp_path / "gau.args").unlink()
    lines = t.archive(t.Job("recon", "https://example.com", None, 30), "example.com")
    assert not (tmp_path / "gau.args").exists() and "(cached)" in lines[0] and "1 in scope" in lines[0]


def test_archive_without_cache_module(bh, tmp_path, monkeypatch):
    d, bindir = bh
    (d / c.SCOPE).write_text("in_scope: [example.com]\n")
    monkeypatch.setitem(sys.modules, "bh.agent.cache", None)
    _recorder(bindir, "gau", tmp_path / "gau.args", out="https://example.com/a?x=1")
    lines = t.archive(t.Job("recon", "https://example.com", None, 30), "example.com")
    assert (tmp_path / "gau.args").exists() and "(cached)" not in lines[0]
