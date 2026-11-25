"""A proof step the gate would always refuse is rejected when the finding is written, with the way out."""

from bh.agent import proof


def test_anonymous_write_step_is_refused():
    u = "http://t.test/api/Addresss/8"
    doc = {
        "steps": [
            {"name": "a", "role": "attack", "as": "user-a", "method": "PATCH", "url": u, "expect": {"contains": ["x"]}},
            {"name": "c", "role": "control", "as": None, "method": "PATCH", "url": u, "expect": {"status": [401]}},
        ]
    }
    errors = proof.validate(doc)
    assert any("PUT/PATCH/DELETE without an identity" in e for e in errors)
    doc["steps"][1]["as"] = "user-b"
    assert not any("without an identity" in e for e in proof.validate(doc))
