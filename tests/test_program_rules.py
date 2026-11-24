"""Program rules a human must decide before an agent runs (automation, scanners): unknown = refuse."""

import pytest

from bh.board import Board
from bh.runner import run
from bh.scope.model import Rule, Scope


def _scope(platform="yeswehack", automation=True, scanners=None) -> Scope:
    return Scope(
        program="p",
        platform=platform,
        in_scope=(Rule("domain", "example.com"),),
        automation_allowed=automation,
        scanners_allowed=scanners,
    )


@pytest.mark.parametrize(
    ("platform", "scanners", "on"),
    [
        ("yeswehack", True, True),
        ("yeswehack", False, False),
        ("yeswehack", None, False),  # unknown = forbidden, never "allowed by default"
        ("local", None, True),  # the lab
        ("local", False, False),
    ],
)
def test_scanners_on_fails_closed(platform, scanners, on):
    s = _scope(platform, scanners=scanners)
    assert s.scanners_on is on


def test_runner_refuses_unknown_scanner_rule(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    with pytest.raises(SystemExit, match="scanners_allowed"):
        run.check_automation(b, _scope(scanners=None))
    assert [r["title"] for r in b.rows("SELECT title FROM todos")] == ["p: " + run.HUMAN_DECISIONS["scanners_allowed"]]
    run.check_automation(b, _scope(scanners=False))  # decided: runs (light phases only)
    run.check_automation(b, _scope("local", scanners=None))  # lab exempt


def test_runner_refuses_forbidden_automation(tmp_path):
    with pytest.raises(SystemExit, match="automation_allowed is false"):
        run.check_automation(Board(tmp_path / "b.sqlite"), _scope(automation=False, scanners=True))
