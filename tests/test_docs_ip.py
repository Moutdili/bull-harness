"""A docs query never carries an IP literal (lab 2026-11-27: a scope written as a CIDR, 10.231.0.10/32, names no host,
so neither bh-docs nor the gate saw its target in `bh-docs react "10.231.0.10 juice shop"`, which reached Context7)."""

import pytest

from bh.agent import contract as c
from bh.gate import policy
from bh.scope import scope_from_dict

REFUSED = [
    "10.231.0.10 juice shop",
    "fe80::1 binding",
    "::1 localhost",
    "bind 0.0.0.0",
    "1.2.3.4:8080 port",
    "2001:db8::8a2e:370:7334",
]
ADMITTED = [
    "react 18.2.0 hooks",
    "python 3.12.1",
    "time 12:30:45",
    "std::vector push_back",
    "Foo::Bar::baz",
    "useEffect cleanup",
]


@pytest.mark.parametrize("text", REFUSED)
def test_ip_literals_are_refused(text):
    assert c.docs_text_why(text) == "docs query: an IP address"


@pytest.mark.parametrize("text", ADMITTED)
def test_versions_and_scope_operators_pass(text):
    assert c.docs_text_why(text) is None


def test_the_gate_refuses_a_cidr_scopes_target_in_a_docs_query():
    scope = scope_from_dict({"program": "lab", "platform": "local", "in_scope": ["10.231.0.10/32"]})
    url = "https://context7.com/api/v2/libs/search?libraryName=react&query=10.231.0.10+juice+shop"
    assert policy.docs_query_ok(url, None, scope) is False
    clean = "https://context7.com/api/v2/libs/search?libraryName=react&query=useEffect+cleanup"
    assert policy.docs_query_ok(clean, None, scope) is True
