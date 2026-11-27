"""D34 (part): `pin_for_models: {<skill>: [<family>, ...]}` in a scope, validated at load, read through
Scope.pin_for_models."""

from pathlib import Path

import pytest

from bh.scope import ScopeError, load_scope, scope_from_dict

ROOT = Path(__file__).resolve().parents[2]
BASE = {"schema": 1, "program": "p", "platform": "test", "in_scope": ["app.example.com"]}


def test_absent_key_is_an_empty_dict():
    assert scope_from_dict(dict(BASE)).pin_for_models == {}
    assert scope_from_dict({**BASE, "pin_for_models": None}).pin_for_models == {}


def test_a_valid_key_is_read_back():
    s = scope_from_dict({**BASE, "pin_for_models": {"prompt-injection": ["opus", "mythos"], "xss": ["sonnet"]}})
    assert s.pin_for_models == {"prompt-injection": ["opus", "mythos"], "xss": ["sonnet"]}
    s.pin_for_models["xss"].append("opus")  # a copy: the scope stays as loaded
    assert s.pin_for_models["xss"] == ["sonnet"]


@pytest.mark.parametrize(
    "value",
    [
        ["prompt-injection"],  # not a mapping
        "prompt-injection",
        {"Prompt_Injection": ["opus"]},  # not a card name
        {"prompt-injection": "opus"},  # not a list
        {"prompt-injection": []},  # empty
        {"prompt-injection": ["Opus"]},  # not lowercase
        {"prompt-injection": ["opus", 3]},
        {"prompt-injection": ["claude opus"]},
        {3: ["opus"]},
    ],
)
def test_a_malformed_value_is_a_scope_error(value):
    with pytest.raises(ScopeError, match="pin_for_models"):
        scope_from_dict({**BASE, "pin_for_models": value})


def test_copilot_pins_prompt_injection_for_opus_and_mythos():
    assert load_scope(ROOT / "scopes" / "msrc" / "copilot.yaml").pin_for_models == {
        "prompt-injection": ["opus", "mythos"]
    }
    for other in (ROOT / "scopes").rglob("*.yaml"):
        if other.name != "copilot.yaml":
            assert load_scope(other).pin_for_models == {}, other
