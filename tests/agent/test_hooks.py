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


def test_program_that_forbids_scanners(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_DIR", str(tmp_path))
    monkeypatch.setenv("BH_SCANNERS", "0")
    for cmd in ("bh-scan http://h", "nuclei -u http://h", "sqlmap -u 'http://h/?q=1' --batch", "bh-content http://h"):
        out = hooks.pre_tool_use(_ev(cmd))
        assert out and out["hookSpecificOutput"]["permissionDecisionReason"].startswith(c.RULES_MARK), cmd
    assert hooks.pre_tool_use(_ev("bh-crawl http://h")) is None
    assert c.required_phases() == ("crawl",)
    c.record_phase(tmp_path, "http://h:80", "crawl", status="ok", count=1, raw="")
    assert hooks.pre_tool_use(_ev("curl -s http://h/api")) is None  # crawl alone unlocks the origin


def test_builtin_refuses_when_scanners_are_forbidden(monkeypatch, capsys):
    import pytest

    from bh.agent import tools

    monkeypatch.setenv("BH_SCANNERS", "0")
    with pytest.raises(SystemExit, match="forbids automated scanners"):
        tools.main("scan", ["http://h"])


def test_scanner_detection_sees_through_quotes_paths_and_the_entry_point():
    for cmd in (
        "'nuclei' -u http://h",
        "bash -c 'ffuf -u http://h/FUZZ -w w'",
        "/usr/bin/nuclei -u http://h",
        "n=nuclei; $n -u http://h",
        "/opt/bh/bin/bh-agent content http://h",
        "hydra -l a -P p h http-post-form x",
        "nmap --script vuln h",
        "dirb http://h",
        "httpx-toolkit -l hosts -path words.txt",
        "katana -u http://h -d 6",
    ):
        assert c.runs_scanner(cmd), cmd
    for cmd in ("bh-crawl http://h", "katana -u http://h -d 3", "curl -s http://h/api", "bh-note fact 'mapped /api'"):
        assert not c.runs_scanner(cmd), cmd


def test_bh_web_text_and_frames_are_shown_whole(tmp_path, monkeypatch):
    """A chat's answer sits at the end of `bh-web text --tail N`: the hook must not elide it (bounded by bh-browser)."""
    monkeypatch.setenv("BH_DIR", str(tmp_path))
    text = "\n".join(f"line {i}" for i in range(500)) + "\nTHE-CHAT-ANSWER"

    def post(cmd, stdout=text, stderr=""):
        ev = {**_ev(cmd), "tool_use_id": "t1", "tool_response": {"stdout": stdout, "stderr": stderr}}
        return hooks.post_tool_use(ev)

    for cmd in ("bh-web text --tail 20000", "bh-web text", "bh-web frames --last 200", "/opt/bh/bin/bh-web text"):
        assert post(cmd) is None, cmd
        assert hooks.exempt(cmd)
    # a long stderr is still shrunk, the stdout stays whole
    out = post("bh-web text", stderr="\n".join(["e"] * 500))["hookSpecificOutput"]["updatedToolOutput"]
    assert out["stdout"] == text and "lines elided" in out["stderr"]
    # anything else, or a composed command, is truncated as before
    for cmd in (
        "bh-web net",
        "bh-web text | cat",
        "bh-web text; cat big.json",
        "cat big.json && bh-web text",
        "bh-web text > /tmp/x",
        "bh-web text $(cat x)",
        "q https://a.test/ # bh-web text",
        "echo bh-web text",
    ):
        assert not hooks.exempt(cmd), cmd
        shown = post(cmd)["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        assert "lines elided" in shown, cmd
    # beyond the browser's own bound, the usual head + tail
    assert post("bh-web text", stdout="x\n" * (hooks.EXEMPT_CHARS // 2 + 10)) is not None
