"""The hook never takes a note's text for a tool run, and the verifier may render a page with bh-browse."""

from bh.agent import contract as c
from bh.agent import hooks


def test_without_commands_keeps_hidden_runs():
    assert c.without_commands('bh-note verdict F8 confirmed "ran bh-browse, nuclei said nothing"', ("bh-note",)) == ""
    assert "nuclei" in c.without_commands("bh-note fact x; nuclei -u http://t", ("bh-note",))
    assert "nuclei" in c.without_commands('bh-note fact "$(nuclei -u http://t)"', ("bh-note",))
    assert "nuclei" in c.without_commands("bash -c 'nuclei -u http://t'", ("bh-note",))
    assert c.without_commands('bh-note fact "unbalanced', ("bh-note",)) == 'bh-note fact "unbalanced'


def test_verifier_rules(monkeypatch):
    monkeypatch.setenv("BH_ROLE", "verifier")
    assert hooks.rules_decision('bh-note verdict F8 confirmed "bh-browse --xss showed it; no nuclei"') is None
    assert hooks.rules_decision("bh-browse 'http://t/#/search?q=x' --xss abcd") is None
    assert hooks.rules_decision("bh-crawl http://t") is not None
    assert hooks.rules_decision('bh-note fact "x"; nuclei -u http://t') is not None


def test_hunter_note_mentioning_a_scanner_is_not_a_scan(monkeypatch):
    monkeypatch.delenv("BH_ROLE", raising=False)
    monkeypatch.setenv("BH_SCANNERS", "0")
    assert hooks.rules_decision('bh-note fact "nuclei found nothing here" -k dead-end') is None
    assert hooks.rules_decision("nuclei -u http://t") is not None


def test_process_substitution_is_a_command_of_its_own(monkeypatch):
    """A `<(...)` / `>(...)` argument runs its command: removing the bh-note must not remove it."""
    assert "nuclei" in c.without_commands("bh-note fact x <(nuclei -u http://t)", ("bh-note",))
    assert "nuclei" in c.without_commands("bh-note fact x >(nuclei -u http://t)", ("bh-note",))
    assert "nuclei" in c.without_commands('bh-note fact "x" <( echo; $(nuclei -u http://t) )', ("bh-note",))
    monkeypatch.delenv("BH_ROLE", raising=False)
    monkeypatch.setenv("BH_SCANNERS", "0")
    assert hooks.rules_decision("bh-note fact x <(nuclei -u http://t)") is not None
    assert hooks.rules_decision("bh-note fact x >(ffuf -u http://t/FUZZ)") is not None
    monkeypatch.setenv("BH_ROLE", "verifier")
    assert hooks.rules_decision("bh-note fact x <(nuclei -u http://t)") is not None
    assert hooks.rules_decision("bh-browse http://t/ <(bh-crawl http://t)") is not None
    assert hooks.rules_decision("bh-browse 'http://t/#/search?q=x' --xss abcd") is None
