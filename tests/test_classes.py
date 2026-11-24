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
