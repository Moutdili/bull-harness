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
