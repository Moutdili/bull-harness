"""bh-zap without ZAP: arguments, program rules, the ZAP command line, the context regex, messages and the summary.
The live check (lab, through the gate) runs in the agent container after a build."""

import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

from bh.agent import contract as c
from bh.agent import hooks
from bh.agent import zap as z

ROOT = Path(__file__).resolve().parents[2]


def test_args_defaults_and_modes():
    a = z.parse_args(["lab:3000/"])
    assert a.url == "https://lab:3000/" and not a.ajax and not a.active and a.identity is None
    assert a.timeout == 280 and a.max_alerts == z.DEFAULT_MAX_ALERTS
    a = z.parse_args(["http://h/", "--ajax", "--active", "--as", "user-a", "--max-alerts", "99"])
    assert a.ajax and a.active and a.identity == "user-a" and a.timeout == 540 and a.max_alerts == 15
    assert z.parse_args(["http://h/", "--timeout", "5"]).timeout == z.MIN_TIMEOUT
    with pytest.raises(SystemExit):
        z.parse_args(["http://h/", "--spider", "--ajax"])
    with pytest.raises(SystemExit):  # no abbreviation: --act would dodge the scanner classification
        z.parse_args(["http://h/", "--act"])


def test_mapper_without_active_scanner_with_it():
    assert z.phase_kind(z.parse_args(["http://h/"])) == "mapper"
    assert z.phase_kind(z.parse_args(["http://h/", "--active"])) == "scanner"
    for cmd in ("bh-zap http://h/", "bh-agent zap http://h/ --ajax --as a"):
        assert c.runs_mapper(cmd) and not c.runs_scanner(cmd) and c.uses_arsenal(cmd), cmd
    for cmd in (
        "bh-zap http://h/ --active",
        "/opt/bh/bin/bh-zap 'http://h/' --as a --active",
        "bh-agent zap h --active",
    ):
        assert c.runs_scanner(cmd), cmd
    assert not c.uses_manual_http("bh-zap http://h/")


def test_active_refused_without_scanners(monkeypatch, tmp_path):
    monkeypatch.setenv("BH_DIR", str(tmp_path))
    monkeypatch.setenv("BH_SCANNERS", "0")
    ev = {"tool_name": "Bash", "tool_input": {"command": "bh-zap http://h/ --active"}}
    reason = hooks.pre_tool_use(ev)["hookSpecificOutput"]["permissionDecisionReason"]
    assert reason.startswith(c.RULES_MARK)
    assert hooks.pre_tool_use({"tool_name": "Bash", "tool_input": {"command": "bh-zap http://h/"}}) is None
    with pytest.raises(SystemExit) as exc:
        z.main(["http://h/", "--active"])
    assert str(exc.value).startswith(c.RULES_MARK)
    assert not (tmp_path / c.RAW).exists()  # refused before anything ran


def test_command_line_goes_through_the_gate_and_is_isolated(tmp_path):
    cmd = z.zap_command(Path("/usr/share/zaproxy/zap-2.17.0.jar"), tmp_path / "home", 41234, "k3y", "http://gate:8080")
    joined = " ".join(cmd)
    assert cmd[0] == "java" and f"-Xmx{z.XMX}" in cmd and "-daemon" in cmd
    assert cmd[cmd.index("-host") + 1] == "127.0.0.1" and cmd[cmd.index("-port") + 1] == "41234"
    assert cmd[cmd.index("-dir") + 1] == str(tmp_path / "home")
    assert cmd[cmd.index("-installdir") + 1] == "/usr/share/zaproxy"
    assert "-silent" in cmd and "-notel" in cmd
    configs = dict(cmd[i + 1].split("=", 1) for i, x in enumerate(cmd) if x == "-config")
    assert configs["network.connection.httpProxy.enabled"] == "true"
    assert configs["network.connection.httpProxy.host"] == "gate"
    assert configs["network.connection.httpProxy.port"] == "8080"
    assert configs["api.key"] == "k3y"
    for k in ("start.checkForUpdates", "start.checkAddonUpdates", "start.installAddonUpdates"):
        assert configs[k] == "false"
    assert configs["oast.activeScanService"] == "None"
    assert "k3y" not in z.redact(cmd, "k3y") and "<api-key>" in z.redact(cmd, "k3y")
    assert "0.0.0.0" not in joined
    assert z.gate_host_port("http://10.0.0.2:3128") == ("10.0.0.2", 3128)


def test_disabled_rules_cover_oob_dos_time_and_brute_force():
    for rid in ("40019", "40027", "40043", "40046", "40044", "90024", "40035", "10095"):
        assert rid in z.DISABLED_RULES
    assert all(r.isdigit() for r in z.DISABLED_RULES)


def _java_like(regex: str) -> re.Pattern:
    """Python has no \\Q..\\E: quote the literal part the way Java would read it."""
    return re.compile(re.sub(r"\\Q(.*?)\\E", lambda m: re.escape(m.group(1)), regex))


def test_context_regex_is_the_origin_only():
    rx = z.context_regex("http://10.231.0.10:3000/#/login")
    assert "\\Q10.231.0.10\\E" in rx
    m = _java_like(rx)
    assert m.match("http://10.231.0.10:3000/") and m.match("http://10.231.0.10:3000/rest/x?q=1")
    assert m.match("http://10.231.0.10:3000")
    for bad in (
        "http://10.231.0.10:3001/",
        "https://10.231.0.10:3000/",
        "http://10.231.0.100:3000/",
        "http://10x231.0.10:3000/",
        "http://10.231.0.10:3000.evil.com/",
        "http://evil.com/?http://10.231.0.10:3000/",
    ):
        assert not m.match(bad), bad
    m = _java_like(z.context_regex("https://App.Example.com/a"))
    assert m.match("https://app.example.com/x") and m.match("https://app.example.com:443/x")
    assert not m.match("https://cdn.app.example.com/x") and not m.match("https://app.example.com.evil/x")
    with pytest.raises(ValueError):
        z.context_regex("ftp://h/")


def test_messages_parse_gate_denial_and_form_params():
    m = {
        "requestHeader": "POST http://h:3000/login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n",
        "requestBody": "email=a&password=b",
        "responseHeader": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n",
    }
    assert z.parse_message(m) == ("POST", "http://h:3000/login", 200, False, ["email", "password"])
    denied = {
        "requestHeader": "GET http://cdn.x/a.js HTTP/1.1\r\n",
        "responseHeader": "HTTP/1.1 403\r\nx-bh-gate: denied\r\n",
    }
    assert z.parse_message(denied)[2:4] == (403, True)


def _alerts(n: int) -> list[dict]:
    risks = ["High", "Medium", "Low", "Informational"]
    return [
        {
            "risk": risks[i % 4],
            "alert": f"Alert kind {i % 20} " + "x" * 80,
            "url": f"http://h:3000/rest/products/search?q={i}" + "y" * 200,
            "param": "q",
            "evidence": "<script>alert(1)</script>\n" * 10,
        }
        for i in range(n)
    ]


def test_summary_is_bounded_and_says_what_matters():
    r = z.Result(
        url="http://h:3000/",
        identity="user-a",
        active=True,
        version="2.17.0",
        seconds=312,
        history=420,
        ascan_requests=3100,
        gate_denied=7,
        offsite=Counter({"cdn.x": 5}),
        alerts=_alerts(200),
        new_endpoints=12,
        max_alerts=15,
        raw="/work/.bh/raw/zap-x",
    )
    lines = z.render(r)
    text = "\n".join(lines)
    assert len(lines) <= z.SUMMARY_LINES and all(len(x) <= z.LINE_CHARS for x in lines)
    assert lines[0].startswith("bh-zap http://h:3000/ as=user-a: spider+passive+active, ZAP 2.17.0")
    assert "requests: 3520" in text and "gate denied 7" in text and "cdn.x ×5" in text
    assert "high 50, medium 50, low 50, informational 50" in text
    assert lines[1 + 2].lstrip().startswith("[High]")  # most severe first, after error-free head lines
    assert "more alert kinds in raw alerts.json" in text and "new endpoints: 12" in text
    assert lines[-1] == "raw: /work/.bh/raw/zap-x/"
    small = z.render(z.Result(url="http://h/", raw="/r", state="error rc=127", error="ZAP is not installed"))
    assert "alerts: 0" in "\n".join(small) and "error: ZAP is not installed" in small[1]


def test_missing_zap_is_an_error_not_a_crash(tmp_path, monkeypatch):
    monkeypatch.setattr(z, "JAR_LINK", tmp_path / "nope.jar")
    monkeypatch.setattr(z, "JAR_GLOBS", (str(tmp_path / "none-*.jar"),))
    r = z.Result(url="http://h/")
    assert z.run(z.parse_args(["http://h/"]), tmp_path, r, "http://h:80") == []
    assert r.state == "error rc=127" and "not installed" in r.error


def test_bh_agent_starts_without_zap(tmp_path):
    """Importing the entry point and bh.agent.zap starts no Java and needs no ZAP."""
    code = (
        "from bh.agent import main, zap, contract; import sys; assert 'bh.agent.tools' not in sys.modules; print('ok')"
    )
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "BH_DIR": str(tmp_path), "PATH": "/nonexistent"}
    out = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, check=False)
    assert out.stdout.strip() == "ok", out.stderr


def test_bh_zap_is_a_link_to_the_entry_point():
    link = ROOT / "container/agent/bin/bh-zap"
    assert link.is_symlink() and os.readlink(link) == "bh-agent"
