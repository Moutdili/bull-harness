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


def test_setup_steps_run_once(monkeypatch):
    calls = []

    def fake_send(step):
        calls.append(step["role"])
        if step["role"] == "setup":
            return (201 if calls.count("setup") == 1 else 409), '{"id": 7}', False
        return (200, '{"owner": "b"}', False) if step.get("as") == "user-a" else (403, "no", False)

    monkeypatch.setattr(proof, "_send", fake_send)
    u = "http://t.test/api/v1/bookings/7"
    doc = {
        "steps": [
            {
                "name": "b books",
                "role": "setup",
                "as": "user-b",
                "method": "POST",
                "url": "http://t.test/api/v1/bookings",
                "expect": {"status": [201]},
            },
            {
                "name": "a reads",
                "role": "attack",
                "as": "user-a",
                "method": "GET",
                "url": u,
                "expect": {"contains": ['"owner": "b"']},
            },
            {"name": "anon", "role": "control", "as": None, "method": "GET", "url": u, "expect": {"status": [403]}},
        ]
    }
    r = proof.replay(doc)
    assert r["reproduced"] and calls.count("setup") == 1 and calls.count("attack") == 2


def test_write_attack_runs_once(monkeypatch):
    seen = []

    def fake_send(step):
        seen.append(step["method"])
        first = seen.count("POST") == 1
        if step["method"] == "POST":
            return (201, '{"cost": -40}', False) if first else (409, "taken", False)
        return 200, '{"cost": 10}', False

    monkeypatch.setattr(proof, "_send", fake_send)
    u = "http://t.test/api/v1/bookings"
    doc = {
        "steps": [
            {
                "name": "negative",
                "role": "attack",
                "as": "user-a",
                "method": "POST",
                "url": u,
                "body": {"extra": -5},
                "expect": {"status": [201], "regex": r'"cost": -\d+'},
            },
            {
                "name": "positive",
                "role": "control",
                "as": "user-a",
                "method": "POST",
                "url": u,
                "body": {"extra": 1},
                "expect": {"status": [201, 409], "absent": ['"cost": -']},
            },
        ]
    }
    r = proof.replay(doc)
    assert seen.count("POST") == 2  # attack once, control once
    assert r["reproduced"], r
