from bh.runner.prompt import DOCTRINE, build_system_prompt, build_task
from bh.scope import scope_from_dict


def test_doctrine_never_offers_a_human_channel():
    assert "todo" not in DOCTRINE.lower() and "human" not in DOCTRINE.lower()
    assert "bh-note blocked" in DOCTRINE


def test_no_identity_means_an_auth_wall_is_a_blocker():
    scope = scope_from_dict({"program": "p", "platform": "x", "in_scope": ["*.t.test"]})
    assert "blocker" in build_system_prompt(scope).split("## Program:")[1]


def test_refused_lead_is_closed_in_the_next_task():
    assert "do not retry" in build_task("board", first=False, refused="x")
    assert "refusal" not in build_task("board", first=False)


def test_identities_line_says_sessions_are_checked():
    from bh.runner.prompt import scope_block
    from bh.scope import scope_from_dict

    s = scope_from_dict({"program": "p", "platform": "x", "in_scope": ["a.test"]})
    block = scope_block(s, ["user-a", "user-b"])
    assert "user-a, user-b" in block and "not a dead session" in block
