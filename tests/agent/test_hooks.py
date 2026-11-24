from bh.agent import contract as c
from bh.agent import hooks


def _ev(cmd):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}, "session_id": "s"}


def test_lock_until_phases_ran(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_DIR", str(tmp_path))
    out = hooks.pre_tool_use(_ev("curl -s http://10.0.0.5:3000/api/Users"))
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny" and reason.startswith(c.LOCK_MARK)
    assert "bh-crawl http://10.0.0.5:3000" in reason and "bh-scan http://10.0.0.5:3000" in reason
    assert hooks.pre_tool_use(_ev("bh-crawl http://10.0.0.5:3000")) is None  # builtins always pass
    assert hooks.pre_tool_use(_ev("curl -s https://web.archive.org/cdx?url=x")) is None  # passive source
    for p in c.REQUIRED_PHASES:
        c.record_phase(tmp_path, "http://10.0.0.5:3000", p, status="ok", count=0, raw="")
    assert hooks.pre_tool_use(_ev("curl -s http://10.0.0.5:3000/api/Users")) is None
    touched = c.read_jsonl(tmp_path / c.TOUCHED)
    assert touched[-1]["key"] == "GET /api/Users"
    log = c.read_jsonl(tmp_path / c.COMMANDS)
    assert [r["decision"] for r in log] == ["deny", "allow", "allow", "allow"]


def test_post_hook_truncates(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_DIR", str(tmp_path))
    text = "\n".join(f"line {i}" for i in range(500))
    out = hooks.post_tool_use(
        {"tool_name": "Bash", "tool_use_id": "t1", "tool_response": {"stdout": text, "stderr": ""}}
    )
    shown = out["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
    assert len(shown.splitlines()) < 50 and "lines elided" in shown
    raw = next((tmp_path / c.RAW).glob("*stdout.log"))
    assert raw.read_text() == text
    assert hooks.post_tool_use({"tool_name": "Bash", "tool_response": {"stdout": "short"}}) is None
