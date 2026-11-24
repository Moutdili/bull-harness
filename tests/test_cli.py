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
