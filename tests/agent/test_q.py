"""q / qq: short requests that the tool lock and the "tested" record see like curl."""

import pytest

from bh.agent import contract as c
from bh.agent import hooks, q

T = "http://10.0.0.5:3000"


def _ev(cmd):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}, "session_id": "s"}


def test_resolve_and_remember(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_DIR", str(tmp_path))
    assert q.read_base() is None
    with pytest.raises(SystemExit, match="no origin yet"):
        q.resolve("/api/x", None)
    with pytest.raises(SystemExit, match="neither"):
        q.resolve("api/x", T)
    q.remember(T + "/rest/a?b=1")
    assert q.read_base() == T
    assert q.resolve("/api/x", q.read_base()) == T + "/api/x"
    q.remember("https://web.archive.org/cdx?url=x")  # a passive source never becomes the origin
    assert q.read_base() == T


def test_urls_in_resolves_q_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_DIR", str(tmp_path))
    assert c.urls_in("q /rest/basket/1") == []  # no origin saved: nothing to resolve
    q.remember(T)
    assert c.urls_in("q -a user-a /rest/basket/1") == [T + "/rest/basket/1"]
    assert c.urls_in("qq /rest/basket/2; echo /not/a/request") == [T + "/rest/basket/2"]
    other = "http://10.0.0.6:8080"
    assert c.urls_in(f"q {other}/a && q /b") == [other + "/a", other + "/b"]  # as at run time: /b uses the new origin
    assert c.uses_manual_http("qq /rest/basket/1")
    assert not c.uses_manual_http("grep -q foo file /etc/x") and not c.uses_manual_http("jq . /tmp/x")


def test_lock_applies_to_q(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_DIR", str(tmp_path))
    q.remember(T)
    out = hooks.pre_tool_use(_ev("qq /api/Users"))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    for p in c.REQUIRED_PHASES:
        c.record_phase(tmp_path, T, p, status="ok", count=0, raw="")
    assert hooks.pre_tool_use(_ev("q -a user-a /api/Users/3")) is None
    assert c.read_jsonl(tmp_path / c.TOUCHED)[-1]["key"] == "GET /api/Users/{id}"


def test_qq_refuses_writes(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_DIR", str(tmp_path))
    for args in (["-X", "DELETE", "/x"], ["-d", "a=1", "/x"], ["-j", "{}", "/x"]):
        with pytest.raises(SystemExit, match="GET only"):
            q.main("qq", args)
