"""Program rules decided at onboarding before an agent runs (automation, scanners): unknown = refuse."""

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
    with pytest.raises(run.ProgramNotReady, match="scanners_allowed") as exc:
        run.check_automation(_scope(scanners=None))
    assert exc.value.fields == ["scanners_allowed"] and isinstance(exc.value, SystemExit)
    assert b.rows("SELECT * FROM todos") == []  # onboarding is not asked mid-hunt
    assert set(run.ONBOARDING_DECISIONS) == {"automation_allowed", "scanners_allowed"}
    run.check_automation(_scope(scanners=False))  # decided: runs (light phases only)
    run.check_automation(_scope("local", scanners=None))  # lab exempt


def test_runner_refuses_forbidden_automation():
    with pytest.raises(run.ProgramNotReady, match="automation_allowed is false"):
        run.check_automation(_scope(automation=False, scanners=True))
