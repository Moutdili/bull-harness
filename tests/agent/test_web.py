import base64
import json

import pytest

from bh.agent import web


def test_request_for_maps_each_command_and_refuses_the_rest():
    assert web.request_for(["state"]) == {"op": "state"}
    assert web.request_for(["goto", "https://copilot.com/chat"]) == {"op": "goto", "url": "https://copilot.com/chat"}
    assert web.request_for(["fill", "textarea", "hi there"]) == {"op": "fill", "css": "textarea", "text": "hi there"}
    assert web.request_for(["press", "Enter"]) == {"op": "press", "key": "Enter"}
    assert web.request_for(["wait", "1500"]) == {"op": "wait", "ms": 1500}
    assert web.request_for(["wait", "#x"]) == {"op": "wait", "css": "#x"}
    for bad in ([], ["cookies"], ["goto"], ["fill", "a"], ["state", "x"], ["eval", "1"]):
        assert web.request_for(bad) is None


def test_wait_human_returns_once_cleared_and_gives_up_at_the_timeout(capsys):
    states = iter([{"challenge": {"pending": True, "since": 1.0}}, {"challenge": {"pending": False}, "url": "u"}])
    assert web.wait_human(100, call=lambda r, t: next(states), sleep=lambda s: None) == 0
    t = iter(range(0, 1000, 50))
    pending = {"challenge": {"pending": True, "since": 1.0}}
    assert web.wait_human(100, call=lambda r, t_: pending, sleep=lambda s: None, clock=lambda: next(t)) == 3
    err = capsys.readouterr().err
    assert "blocked captcha" not in err and "bh-web wait-human" in err and "bh-note intent" in err  # R5


def test_without_a_token_bh_web_says_the_browser_is_unavailable(monkeypatch):
    monkeypatch.delenv("BH_BROWSER_TOKEN", raising=False)
    assert "not available" in web._call({"op": "state"})["error"]


def test_bh_web_counts_as_manual_interaction_not_a_scanner():
    from bh.agent import contract as c

    assert c.uses_manual_http("bh-web goto https://copilot.com/chat")
    assert not c.uses_arsenal("bh-web goto https://copilot.com/chat")


def test_request_for_covers_every_reading_and_driving_command(tmp_path):
    rf = web.request_for
    assert rf(["click", "button#send"]) == {"op": "click", "css": "button#send"}
    assert rf(["text"]) == {"op": "text"}
    assert rf(["text", "--css", "main"]) == {"op": "text", "css": "main"}
    assert rf(["text", "--tail", "2000"]) == {"op": "text", "tail": 2000}
    assert rf(["text", "--css", "main", "--tail", "50"]) == {"op": "text", "css": "main", "tail": 50}
    assert rf(["outline"]) == {"op": "outline"}
    assert rf(["outline", "--css", "form"]) == {"op": "outline", "css": "form"}
    assert rf(["attr", "a.share", "href"]) == {"op": "attr", "css": "a.share", "name": "href"}
    assert rf(["net"]) == {"op": "net"}
    assert rf(["net", "--last", "20", "--denied"]) == {"op": "net", "last": 20, "denied": True}
    assert rf(["frames"]) == {"op": "frames"}
    assert rf(["frames", "--last", "5"]) == {"op": "frames", "last": 5}
    assert rf(["tabs"]) == {"op": "tabs"}
    assert rf(["tabs", "--select", "1"]) == {"op": "tabs", "select": 1}
    assert rf(["switch", "victim"]) == {"op": "switch", "identity": "victim"}
    f = tmp_path / "doc.pdf"
    f.write_bytes(b"%PDF-1.4 x")
    assert rf(["upload", "input[type=file]", str(f)]) == {
        "op": "upload",
        "css": "input[type=file]",
        "name": "doc.pdf",
        "content_b64": base64.b64encode(b"%PDF-1.4 x").decode(),
    }
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * (web.UPLOAD_MAX + 1))
    for bad in (
        ["text", "--tail"],  # value missing
        ["text", "--tail", "-5"],
        ["text", "--tail", "abc"],
        ["text", "--bogus", "1"],
        ["outline", "--tail", "5"],  # an option of another command
        ["net", "--last"],
        ["frames", "--denied"],
        ["tabs", "--select", "x"],
        ["attr", "a"],
        ["switch"],
        ["switch", "a", "b"],
        ["upload", "input", str(tmp_path / "missing")],
        ["upload", "input", str(big)],  # over 256 KiB
        ["upload", "input"],
        ["click"],
    ):
        assert rf(bad) is None, bad


def test_every_agent_op_has_a_command_and_no_host_op_does():
    from bh.browser_service import AGENT_OPS, HOST_OPS

    for op in AGENT_OPS:
        assert f"bh-web {op.replace('_', '-')}" in web.__doc__, op  # ws_rewrite is `bh-web ws-rewrite`
    for op in HOST_OPS:
        assert web.request_for([op]) is None and web.request_for([op, "x"]) is None, op


def test_wait_human_tells_the_agent_how_to_resume(capsys):
    states = iter([{"challenge": {"pending": True}}, {"challenge": {"pending": False, "cleared_at": 9.0}, "url": "u"}])
    assert web.wait_human(100, call=lambda r, t: next(states), sleep=lambda s: None) == 0
    out = capsys.readouterr()
    assert json.loads(out.out) == {"challenge": "cleared", "url": "u", "cleared_at": 9.0, "human_done_at": None}
    assert web.RESUME in out.err and "text --tail" in out.err and "pending message" in out.err


def test_wait_human_reports_an_unreachable_browser(capsys):
    assert (
        web.wait_human(100, call=lambda r, t: {"error": "bh-browser unreachable: OSError"}, sleep=lambda s: None) == 1
    )
    assert "unreachable" in capsys.readouterr().out


def test_wait_human_ends_before_the_bash_tool_timeout():
    """The runner gives each Bash call BASH_DEFAULT_TIMEOUT_MS (330 s): a wait-human that outlives it is killed and
    its answer lost. Worst case: every poll takes its whole STATE_TIMEOUT_S."""
    from bh.runner.run import BASH_TIMEOUT_MS

    limit = int(BASH_TIMEOUT_MS["BASH_DEFAULT_TIMEOUT_MS"]) / 1000
    now = [0.0]
    asked = []

    def slow_call(req, timeout):
        asked.append(timeout)
        now[0] += timeout
        return {"challenge": {"pending": True, "since": 1.0}}

    def sleep(s):
        now[0] += s

    assert web.wait_human(web.WAIT_HUMAN_S, call=slow_call, sleep=sleep, clock=lambda: now[0]) == 3
    assert now[0] <= web.WAIT_HUMAN_S + web.STATE_TIMEOUT_S < limit
    assert set(asked) == {web.STATE_TIMEOUT_S}


def test_wait_human_timeout_is_capped(monkeypatch):
    seen = []
    monkeypatch.setattr(web, "wait_human", lambda t: seen.append(t) or 0)
    for argv in (["wait-human"], ["wait-human", "--timeout", "9999"], ["wait-human", "--timeout", "60"]):
        with pytest.raises(SystemExit):
            web.main(argv)
    assert seen == [web.WAIT_HUMAN_S, web.WAIT_HUMAN_S, 60]
    with pytest.raises(SystemExit) as e:
        web.main(["wait-human", "--timeout", "-1"])
    assert "bh-web" in str(e.value.code)  # the usage


def test_switch_prints_its_cost(capsys):
    assert web._print({"ok": True, "switch_requested": "victim", "note": "x"}, "switch") == 0
    err = capsys.readouterr().err
    assert err.strip() == web.SWITCH_COST
    assert "one more human challenge" in err  # a challenge for each switch
    assert web._print({"ok": True, "identity": "victim", "note": "already"}, "switch") == 0
    assert capsys.readouterr().err == ""  # already that identity: no cost


def test_print_exit_codes(capsys):
    assert web._print({"error": "human-needed"}, "click") == 3
    assert "wait-human" in capsys.readouterr().err
    assert web._print({"error": "human-viewing"}, "fill") == 3
    assert web._print({"error": "fill-budget"}, "fill") == 4
    assert web._print({"error": "goto: TimeoutError: x"}, "goto") == 1
    assert web._print({"text": "abc", "truncated": True, "length": 9, "from": "tail"}, "text") == 0
    assert "truncated at the start: 9" in capsys.readouterr().out


def test_wait_human_waits_for_the_screen_to_be_handed_back(capsys):
    """N3: the challenge is gone but the operator still has the screen; rc 0 only once he clicks J'ai fini."""
    states = iter(
        [
            {"challenge": {"pending": True}, "human_viewing": True},
            {"challenge": {"pending": False}, "human_viewing": True},
            {"challenge": {"pending": False}, "human_viewing": False, "human_done_at": 5.0},
        ]
    )
    assert web.wait_human(100, call=lambda r, t: next(states), sleep=lambda s: None) == 0
    assert '"cleared"' in capsys.readouterr().out
    t = iter([0, 200])
    viewing = {"challenge": {"pending": False}, "human_viewing": True}
    assert web.wait_human(100, call=lambda r, t_: viewing, sleep=lambda s: None, clock=lambda: next(t)) == 3


def test_ws_rewrite_command_line(tmp_path):
    tok = tmp_path / "tok.txt"
    tok.write_text("eyJCCCCCC\n")
    assert web.request_for(["ws-rewrite", "eyJBBBBBB", f"@{tok}", "--url-contains", "/Chathub/", "--ttl", "120"]) == {
        "op": "ws_rewrite",
        "find": "eyJBBBBBB",
        "replace": "eyJCCCCCC",
        "url_contains": "/Chathub/",
        "ttl": 120,
    }
    assert web.request_for(["ws-rewrite", "only-one"]) is None
    assert web.request_for(["ws-rewrite", "a", "b", "--bogus", "1"]) is None
    assert web.request_for(["ws-rewrite", "@/nonexistent/file", "b"]) is None
