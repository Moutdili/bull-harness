import json
from pathlib import Path

import pytest

from bh.scope import ScopeError, check, scope_from_dict
from bh.scope.yeswehack import _expand, _web_rule, convert

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "ywh-infomaniak.json"  # public API, 2026-11-24


def test_rules_never_widen():
    assert _web_rule("manager.infomaniak.com/v3/*") == "https://manager.infomaniak.com/v3/"
    assert _web_rule("kdrive.infomaniak.com/app/*/preview/*") is None  # mid-path wildcard
    assert _web_rule("storage*.infomaniak.com") is None  # mid-label wildcard
    assert _web_rule("*. vfsevisa.id") == "*.vfsevisa.id"
    assert _expand("*.doctolib.(fr|de)") == ["*.doctolib.fr", "*.doctolib.de"]


def test_infomaniak_import():
    imp = convert(json.loads(FIXTURE.read_text()), username="mio")
    s = scope_from_dict(imp.doc, "fixture")
    assert s.user_agent == "Infomaniak-YWH-Bugbounty/mio" and s.automation_allowed is None
    assert s.scanners_allowed is False  # "Do not use automated scanners or tools ..." in the rules
    assert check(s, "https://login.infomaniak.com/x").allowed
    assert check(s, "https://manager.infomaniak.com/v3/a").allowed
    assert not check(
        s, "https://acronis.infomaniak.com/"
    ).allowed  # quoted in the out-of-scope text: wins over *.infomaniak.com
    assert "storage*.infomaniak.com" in imp.skipped
    assert not any("xx" in h for h in imp.excluded_from_text)
    assert s.excludes("Denial of Service (DoS) attacks") or s.forbidden_vulns


def test_username_required_when_the_user_agent_needs_it():
    with pytest.raises(ScopeError, match="username"):
        convert(json.loads(FIXTURE.read_text()), username=None)


def test_skipped_entries_do_not_widen():
    program = {
        "slug": "demo",
        "scopes": [
            {"scope": "api.demo.test", "scope_type": "api"},
            {"scope": "storage*.demo.test", "scope_type": "web-application"},
            {"scope": "app.demo.test/v1/*/admin", "scope_type": "web-application"},
        ],
    }
    s = scope_from_dict(convert(program, None).doc, "demo")
    assert check(s, "https://api.demo.test/").allowed
    for url in ("https://storage1.demo.test/", "https://app.demo.test/v1/x/admin", "https://demo.test/"):
        assert not check(s, url).allowed, url
