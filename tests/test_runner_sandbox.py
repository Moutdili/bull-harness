"""The agent's session cannot be configured by anything the previous segment left in the work tree."""

from bh.runner import run
from bh.scope import scope_from_dict


def test_no_mcp_server_can_be_loaded():
    scope = scope_from_dict({"program": "p", "platform": "x", "in_scope": ["example.com"]})
    cmd = run.agent_command(scope, "t", run_id=1, model="sonnet", max_turns=5, effort=None, session=None)
    assert "--strict-mcp-config" in cmd and "--mcp-config" not in cmd


def test_planted_config_is_removed():
    for name in ("CLAUDE.md", ".claude", ".mcp.json"):
        assert f'"$1/{name}"' in run._WORK_SCRIPT and f'"$2/{name}"' in run._WORK_SCRIPT
