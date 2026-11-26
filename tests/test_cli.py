from pathlib import Path

import pytest

from bh.cli import build_parser, main

DEMO = str(Path(__file__).resolve().parents[1] / "scopes" / "examples" / "demo.yaml")


def test_every_subcommand_has_help(capsys):
    parser = build_parser()
    subs = parser._subparsers._group_actions[0].choices
    for name in subs:
        with pytest.raises(SystemExit) as exc:
            main([name, "--help"])
        assert exc.value.code == 0, name
    assert {"scope", "up", "down", "tools", "ui", "status", "run", "hunt", "todo", "finding", "board", "flows"} <= set(
        subs
    )


def test_scope_check_exit_codes(capsys):
    assert main(["scope", "check", DEMO, "https://a.example.com/x"]) == 0
    assert main(["scope", "check", DEMO, "https://admin.example.com/"]) == 1
    out = capsys.readouterr().out
    assert "ALLOW https://a.example.com/x" in out and "DENY  https://admin.example.com/" in out


def test_board_reset_needs_confirmation(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    assert main(["board", "reset", "demo"]) == 2


def test_blockers_command_is_in_help(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    assert "blockers" in out and "post-triage todo: verified findings to submit" in out


def test_todo_lists_submissions_only(tmp_path, monkeypatch, capsys):
    import time

    from bh.board import Board

    monkeypatch.setenv("BH_HOME", str(tmp_path))
    b = Board()
    b.add_todo("submit", "F7 verified XSS", program="lab")
    b.db.execute(
        "INSERT INTO todos(program, kind, title, status, created) VALUES ('lab','waf','old waf todo','obsolete',?)",
        (time.time(),),
    )
    b.db.execute(
        "INSERT INTO todos(program, kind, title, status, created) VALUES ('lab','auth','old auth todo','open',?)",
        (time.time(),),
    )
    b.db.commit()
    assert main(["todo"]) == 0
    out = capsys.readouterr().out
    assert "F7 verified XSS" in out and "old waf todo" not in out and "old auth todo" not in out


def test_blockers_command_lists_blocker_facts(tmp_path, monkeypatch, capsys):
    from bh.board import Board

    monkeypatch.setenv("BH_HOME", str(tmp_path))
    b = Board()
    b.add_blocker("lab", "auth", "session expired", host="a.example.com")
    b.add_blocker("other", "waf", "captcha")
    b.add_fact("lab", "not a blocker")
    assert main(["blockers", "lab"]) == 0
    out = capsys.readouterr().out
    assert "[auth] session expired" in out and "host:a.example.com" in out
    assert "captcha" not in out and "not a blocker" not in out


def test_accounts_set_stores_hidden_values(tmp_path, monkeypatch, capsys):
    import getpass
    import json
    import os

    from bh import cli

    monkeypatch.setenv("BH_HOME", str(tmp_path))
    answers = iter(["s3cret-Pw", "s3cret-Pw", "JBSWY3DPEHPK3PXP"])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(answers))
    assert cli.main(["accounts", "set", "msrc-copilot", "user-a", "--email", "msobb-a@outlook.test"]) == 0
    out = capsys.readouterr().out
    assert "s3cret" not in out and "JBSWY3DP" not in out
    f = tmp_path / "secrets" / "identities" / "msrc-copilot" / "user-a.json"
    assert oct(os.stat(f).st_mode & 0o777) == "0o600"
    d = json.loads(f.read_text())
    assert d["email"] == "msobb-a@outlook.test" and d["password"] == "s3cret-Pw" and d["totp"] == "JBSWY3DPEHPK3PXP"


def test_accounts_set_accepts_grouped_keys_and_explains_errors(tmp_path, monkeypatch, capsys):
    import getpass
    import json

    import pytest

    from bh import cli

    monkeypatch.setenv("BH_HOME", str(tmp_path))
    nbsp = " "
    answers = iter(["pw-123456", "pw-123456", f"jbsw{nbsp}y3dp{nbsp}ehpk 3pxp\n"])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(answers))
    assert cli.main(["accounts", "set", "p", "user-a", "--email", "a@b.test"]) == 0
    f = tmp_path / "secrets" / "identities" / "p" / "user-a.json"
    assert json.loads(f.read_text())["totp"] == "JBSWY3DPEHPK3PXP"
    answers = iter(["", "123456"])  # the 6-digit code instead of the key
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(answers))
    with pytest.raises(SystemExit) as exc:
        cli.main(["accounts", "set", "p", "user-a", "--email", "a@b.test"])
    assert "digit 1" in str(exc.value) and "123456" not in str(exc.value)


def test_browser_subcommands_have_help(capsys):
    for sub in ("up", "down", "status", "load", "reset", "view"):
        with pytest.raises(SystemExit) as exc:
            main(["browser", sub, "--help"])
        assert exc.value.code == 0, sub
    with pytest.raises(SystemExit) as exc:
        main(["browser", "--help"])
    assert exc.value.code == 0 and "captcha" not in capsys.readouterr().err


def test_browser_view_prints_the_captcha_page(capsys):
    assert main(["browser", "view", "--host", "100.64.0.1"]) == 0
    assert "http://100.64.0.1:7340/captcha/" in capsys.readouterr().out


def test_browser_reset_needs_confirmation(capsys):
    assert main(["browser", "reset"]) == 2


def test_browser_load_goes_through_host_load(monkeypatch, capsys):
    """`bh browser load` uses host.load, which writes browser-identity.json for the gate (I2)."""
    from bh.browser_service import host as bhost

    calls = []
    monkeypatch.setattr(bhost, "identity_payload", lambda program, name: ({"op": "load"}, ["X-Api-Key"]))
    monkeypatch.setattr(
        bhost, "load", lambda program, name, scope=None: calls.append((program, name)) or {"code": 200, "cookies": 3}
    )
    monkeypatch.setattr(bhost, "call", lambda *a, **k: pytest.fail("a raw call skips browser-identity.json"))
    assert main(["browser", "load", DEMO, "user-a"]) == 0
    out = capsys.readouterr().out
    assert calls == [("demo", "user-a")] and "3 cookie(s)" in out and "X-Api-Key" in out


def test_browser_reset_goes_through_host_reset_with_force(monkeypatch, capsys):
    from bh.browser_service import host as bhost

    calls = []
    monkeypatch.setattr(bhost, "reset", lambda program="", force=False: calls.append((program, force)) or {"code": 200})
    monkeypatch.setattr(bhost, "call", lambda *a, **k: pytest.fail("a raw call skips browser-identity.json"))
    assert main(["browser", "reset", "--yes"]) == 0
    assert main(["browser", "reset", "--yes", "--force", "--scope", DEMO]) == 0
    assert calls == [("", False), ("demo", True)]
    assert main(["browser", "reset", "--force"]) == 2 and len(calls) == 2  # --force never replaces --yes
