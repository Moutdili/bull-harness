import re

import pytest

from bh import classes
from bh.scope import canonical_vuln


def test_aliases_have_one_source():
    assert canonical_vuln("Denial of Service") == classes.canonical("DDoS") == "dos"
    assert classes.canonical("Broken Object Level Authorization") == "idor"
    assert classes.canonical("some new class") == "some-new-class"


def test_every_card_exists_is_short_and_has_a_proof_standard():
    for cls in classes.CLASSES:
        if cls.card:
            text = classes.card_text(cls.id)
            assert text.startswith("## ") and len(text.splitlines()) <= 40, cls.id
            assert cls.evidence, cls.id
    block = classes.cards_block(["idor"])
    assert "Proof standard" in block and classes.BY_ID["idor"].evidence in block


def test_selection_follows_the_surface():
    juice = [
        ("GET /rest/basket/{id}", []),
        ("GET /api/Users/{id}", []),
        ("GET /rest/products/search", ["q"]),
        ("POST /file-upload", []),
        ("GET /ftp", []),
        ("GET /rest/user/whoami", []),
    ]
    picked = classes.select_cards(juice)
    assert "idor" in picked and "sqli" in picked and len(picked) <= classes.MAX_CARDS
    assert "sqli" not in classes.select_cards(juice, exclude=["SQL Injection"])  # program exclusion wins
    rotated = classes.select_cards(juice, recently_used=["idor", "idor"])
    assert rotated[0] != "idor"
    assert classes.select_cards([]) == []


def test_program_exclusions_remove_a_class_only_when_they_name_it():
    from bh.classes import canonical, exclusion

    assert exclusion("Denial of Service (DoS) attacks") == "dos"
    assert exclusion("Self XSS") == "self-xss" and exclusion("Open Redirect") == "open-redirect"
    assert exclusion("Lack of rate-limiting") == "rate-limiting"
    for narrow in (
        "Pre-account takeover (e.g. account creation via oAuth)",  # not every auth bug
        "Open redirect without demonstrated impact",  # conditional: a human decides
        "Cross-Site Scripting (XSS) impacting other users",
        "Race condition without Critical risk for PII",
        "Missing session timeout",
    ):
        assert exclusion(narrow) is None, narrow
    assert exclusion("Race condition") == "race-condition"  # and business-logic stays payable
    assert canonical("XSS (stored)") == "xss" and canonical("self-xss") == "self-xss"  # the hunter's own naming


def test_blind_ssrf_is_a_blocker_not_a_lead_for_someone():
    text = classes.BY_ID["ssrf"].evidence
    assert 'bh-note blocked oob-needed "' in text and "human" not in text


def test_prompt_injection_card_loads_with_its_cross_user_standard():
    cls = classes.BY_ID["prompt-injection"]
    assert cls.card and classes.canonical("Indirect Prompt Injection") == "prompt-injection"
    text = classes.card_text("prompt-injection")
    assert text.startswith("## ") and len(text.splitlines()) <= 40
    for part in ("When:", "Do:", "Watch:", "Never:", "BH-SECRET-<16 hex>", "--observation", "oob-needed"):
        assert part in text, part
    assert "BH-SECRET-<16 hex>" in cls.evidence and "Control:" in cls.evidence
    # audit B7/R7: the chat goes through bh-web only, never another path to the assistant
    assert "HTTP path" not in text and "websockets: N refused" not in text
    assert "bh-web" in text and "Never look for another path to send prompts" in text
    block = classes.cards_block(["prompt-injection"])
    assert text in block and cls.evidence in block
    assert classes.select_cards([("POST /api/chat", ["prompt"])])[0] == "prompt-injection"
    # a conditional exclusion ("without impact on another user") stays for a human; the bare name removes it
    assert classes.exclusion("Prompt injection without impact on another user") is None
    assert classes.exclusion("Prompt injection") == "prompt-injection"


def test_access_control_cards_point_at_bh_authz_and_its_proof():
    for cid in ("idor", "broken-access-control"):
        tool = classes.BY_ID[cid].tool
        assert "bh-authz" in tool and "proof.json" in tool and "--proof" in tool, cid
        assert "bh-authz" not in classes.evidence(cid)  # the verifier's standard does not name a hunter's tool
    assert "Tool: `bh-authz`" in classes.cards_block(["idor"])
    assert classes.canonical("Broken Access Control") == "broken-access-control"
    assert classes.canonical("BOLA") == "idor" and classes.canonical("privilege-escalation") == "auth"


# ------------------------------------------------------------------ W3-C: skills, pins, classes_more.json
def _scope(**kw):
    from types import SimpleNamespace

    return SimpleNamespace(**kw)


def test_skill_for_each_card_class_and_none_without_one():
    for cls in classes.CLASSES:
        if cls.card:
            assert classes.skill_for(cls.id) == cls.id, cls.id
    assert classes.skill_for("BOLA") == "idor" and classes.skill_for("Broken Access Control") == "broken-access-control"
    assert classes.skill_for("dos") is None and classes.skill_for("no such class") is None
    assert classes.skills_dir() == classes.SKILLS_DIR and classes.skills_dir().name == "skills"


def test_skill_text_and_all_skills():
    text = classes.skill_text("idor")
    assert text.startswith("---\nname: idor\n") and "## Proof" in text
    for bad in ("../cards", "idor/../idor", "no-such-skill", ""):
        with pytest.raises(ValueError):
            classes.skill_text(bad)
    listed = {s["name"]: s for s in classes.all_skills()}
    assert set(classes.all_cards()) <= set(listed)
    assert all(set(s) == {"name", "description", "requires"} for s in listed.values())
    assert listed["scanner-playbook"]["requires"] == "scanners" and listed["idor"]["requires"] is None


def test_pinned_skills_follow_the_model_family():
    s = _scope(cards=(), pin_for_models={"prompt-injection": ["opus", "mythos"]})
    assert classes.pinned_skills(s, "claude-sonnet-5-5") == []
    assert classes.pinned_skills(s, "claude-opus-5-5") == ["prompt-injection"]
    assert classes.pinned_skills(s, "claude-mythos-1") == ["prompt-injection"]
    assert classes.pinned_skills(s, "opus") == ["prompt-injection"]  # an alias without the prefix
    assert classes.pinned_skills(s, None) == [] and classes.pinned_skills(s, "") == []
    assert classes.pinned_skills(_scope(cards=()), "claude-opus-5-5") == []  # no pin_for_models (before lot D)
    frozen = _scope(pin_for_models=(("prompt-injection", ("opus", "mythos")),))  # a frozen scope may hold pairs
    assert classes.pinned_skills(frozen, "claude-mythos-1") == ["prompt-injection"]
    assert classes.pinned_skills(_scope(pin_for_models={"prompt-injection": "opus"}), "claude-opus-5-5") == [
        "prompt-injection"
    ]
    assert classes.pinned_skills(_scope(pin_for_models={"prompt-injection": "opus"}), "claude-o3") == []


def test_program_skills_are_the_scope_cards_then_the_pins():
    s = _scope(cards=("msrc-copilot", "bh-web-manual"), pin_for_models={"prompt-injection": ["opus", "mythos"]})
    assert classes.program_skills(s) == ["msrc-copilot", "bh-web-manual"]
    assert classes.program_skills(s, "claude-sonnet-5-5") == ["msrc-copilot", "bh-web-manual"]
    assert classes.program_skills(s, "claude-opus-5-5") == ["msrc-copilot", "bh-web-manual", "prompt-injection"]
    s2 = _scope(cards=("prompt-injection",), pin_for_models={"prompt-injection": ["mythos"]})
    assert classes.program_skills(s2, "claude-mythos-1") == ["prompt-injection"]  # never twice
    for bad in (("../../etc/passwd",), ("msrc-nowhere",)):
        with pytest.raises(ValueError):
            classes.program_skills(_scope(cards=bad))
    with pytest.raises(ValueError):
        classes.program_skills(_scope(cards=(), pin_for_models={"nope": ["opus"]}), "claude-opus-5-5")


def test_classes_more_json_completes_and_adds(tmp_path, monkeypatch):
    import json

    more = tmp_path / "classes_more.json"
    more.write_text(
        json.dumps(
            [
                {"id": "nosqli", "aliases": ["nosql"], "evidence": "new text", "skill": "nosql-injection"},
                {"id": "race-condition", "evidence": "Two requests at once break a rule.", "skill": "race-condition"},
                {
                    "id": "jwt",
                    "aliases": ["jwt", "json-web-token"],
                    "path_signals": [r"/\.well-known/jwks"],
                    "evidence": "A forged token is accepted.",
                    "skill": "jwt",
                },
                {"id": "csrf", "aliases": ["csrf", "cross-site-request-forgery", "logout-csrf"], "skill": "csrf"},
            ]
        )
    )
    built = classes.build_classes(more)
    ids = [c.id for c in built]
    assert len(ids) == len(set(ids)) == len(classes.build_classes(None)) + 2
    by_id = {c.id: c for c in built}
    first_exclusion = ids.index("dos")
    assert ids.index("prompt-injection") < ids.index("jwt") < ids.index("csrf") < first_exclusion  # card, more, excl
    nosqli = by_id["nosqli"]
    assert nosqli.skill == "nosql-injection" and nosqli.evidence == classes.BY_ID["nosqli"].evidence  # kept
    assert nosqli.aliases == classes.BY_ID["nosqli"].aliases
    race = by_id["race-condition"]
    assert race.evidence == "Two requests at once break a rule." and race.skill == "race-condition"
    assert ids.index("race-condition") > first_exclusion  # completed in place, not moved
    aliases = classes.alias_map(built)
    assert aliases["jwt"] == "auth" and aliases["json-web-token"] == "jwt"  # a built-in alias keeps its class
    assert aliases["logout-csrf"] == "csrf-logout" and aliases["cross-site-request-forgery"] == "csrf"
    assert classes.exclusion("Logout CSRF") == "csrf-logout"
    assert classes.build_classes(tmp_path / "absent.json") == classes.build_classes(None)
    # skill_for: the exact id first, then the alias; only a skill present on disk
    skills = tmp_path / "skills"
    (skills / "jwt").mkdir(parents=True)
    (skills / "jwt" / "SKILL.md").write_text("---\nname: jwt\ndescription: Use when x.\n---\n")
    monkeypatch.setattr(classes, "SKILLS_DIR", skills)
    monkeypatch.setattr(classes, "BY_ID", by_id)
    assert classes.skill_for("jwt") == "jwt" and classes.skill_for("csrf") is None  # no csrf folder here
    for bad in ({"aliases": []}, {"id": "Bad Id"}, {"id": "x", "skill": "../y"}, {"id": "x", "aliases": [1]},
                {"id": "x", "path_signals": ["("]}):  # fmt: skip
        more.write_text(json.dumps([bad]))
        with pytest.raises((ValueError, re.error)):
            classes.build_classes(more)
    more.write_text(json.dumps([{"id": "x"}, {"id": "x"}]))
    with pytest.raises(ValueError):
        classes.build_classes(more)


def test_the_installed_classes_keep_their_ids_and_aliases():
    builtin = classes.build_classes(None)
    for c in builtin:
        assert classes.canonical(c.id) == c.id, c.id
        for a in c.aliases:
            assert classes.canonical(a) == c.id, a
    assert classes.exclusion("Logout CSRF") == "csrf-logout"
    # the card path still works until lot F switches
    assert classes.pinned_cards(_scope(cards=("idor",))) == ["idor"] and classes.card_text("idor").startswith("## ")
