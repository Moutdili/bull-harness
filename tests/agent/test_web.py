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
    assert "blocked captcha" in capsys.readouterr().err


def test_without_a_token_bh_web_says_the_browser_is_unavailable(monkeypatch):
    monkeypatch.delenv("BH_BROWSER_TOKEN", raising=False)
    assert "not available" in web._call({"op": "state"})["error"]


def test_bh_web_counts_as_manual_interaction_not_a_scanner():
    from bh.agent import contract as c

    assert c.uses_manual_http("bh-web goto https://copilot.com/chat")
    assert not c.uses_arsenal("bh-web goto https://copilot.com/chat")
