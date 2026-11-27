"""T32: the test objects' registry. The gate registers what our identities create and looks up what they write;
`observe` (the default) journals an unknown object, `enforce` refuses it. No network, mitmproxy simulated."""

import json
import sqlite3

import pytest

from bh import paths
from bh.agent.contract import IDENTITY_HEADER
from bh.gate import objects
from bh.gate import policy as pol
import test_gate_browser_canary as gbc
from test_gate_browser_canary import _answer, _events, _gate, _http, run

addon = gbc.addon  # the simulated mitmproxy fixture

SCOPE = {
    "schema": 1,
    "program": "t",
    "platform": "test",
    "in_scope": ["app.example.com"],
    "max_rps": 1000,
    "identities": [{"name": "user-a"}, {"name": "user-b"}],
}
A = [(IDENTITY_HEADER, "user-a")]
B = [(IDENTITY_HEADER, "user-b")]
JSON = [("Content-Type", "application/json")]


def _g(addon, tmp_path):
    g = _gate(addon, tmp_path, SCOPE)
    (tmp_path / paths.IDENTITIES / "t" / "user-b.json").write_text(json.dumps({"headers": {}}))
    return g


def _create(g, url, who, status=201, headers=(), body=b"{}", fid="c"):
    f = run(g, _http(url, "POST", who, b"{}", fid=fid))
    assert not f.metadata.get("bh_denied")
    _answer(f, status, list(headers), body)
    g.response(f)
    return f


def _write(g, url, who, method="PUT", headers=(), peer=None, fid="w"):
    kw = {"peer": peer} if peer else {}
    return run(g, _http(url, method, [*who, *headers], b'{"title": "x"}', fid=fid, **kw))


def _unknown(tmp_path):
    return _events(tmp_path, "object-unknown")


# ------------------------------------------------------------------ what a creation gives (pure)
@pytest.mark.parametrize(
    "location, body, ctype, expected",
    [
        ("/api/notes/42", b"", "", [("/api/notes/{id}", "42")]),
        ("https://app.example.com/api/Notes/42?x=1", b"", "", [("/api/notes/{id}", "42")]),
        ("https://other.example.com/api/notes/42", b"", "", []),  # another origin: doubtful
        ("/api/notes/latest", b"", "", []),  # no id segment
        (None, b'{"id": 7, "title": "t"}', "application/json", [("/api/notes/{id}", "7")]),
        (
            None,
            b'{"id": 7, "uuid": "0B2C3D4E-1111-2222-3333-444455556666"}',
            "application/json; charset=utf-8",
            [("/api/notes/{id}", "7"), ("/api/notes/{id}", "0b2c3d4e-1111-2222-3333-444455556666")],
        ),
        (None, b'{"key": "123"}', "application/json", [("/api/notes/{id}", "123")]),
        (None, b'{"key": "sk_' b'live_AbCdEfGhIjKlMnOpQrStUvWxYz"}', "application/json", []),  # maybe a secret of ours
        (None, b'{"data": {"id": 7}}', "application/json", []),  # nested: not the first level
        (None, b'[{"id": 7}]', "application/json", []),
        (None, b'{"id": true}', "application/json", []),
        (None, b'{"id": "not an id"}', "application/json", []),
        (None, b'{"id": -1}', "application/json", []),
        (None, b"id=7", "text/plain", []),
    ],
)
def test_what_a_creating_answer_registers(location, body, ctype, expected):
    assert objects.created("https://app.example.com/api/notes", 201, location, body, ctype) == expected


def test_only_a_2xx_answer_registers():
    for status in (199, 302, 400, 500):
        assert objects.created("https://app.example.com/api/notes", status, "/api/notes/1", b'{"id": 1}') == []


def test_the_object_of_a_write_is_its_last_path_id():
    assert objects.object_of("https://x/api/users/7/notes/9") == ("notes", "9")
    assert objects.object_of("https://x/API/Notes/9;jsessionid=1/") == ("notes", "9")
    assert objects.object_of("https://x/9") == ("", "9")
    assert objects.object_of("https://x/api/me") is None
    assert objects.object_of("https://x/api/notes/9/title") == ("notes", "9")


def test_the_default_mode_is_observe_and_anything_else_reads_as_observe(monkeypatch):
    assert pol.OBJECTS_MODE == "observe" and objects.mode() == "observe"
    monkeypatch.setattr(pol, "OBJECTS_MODE", "ENFORCE ")
    assert objects.mode() == "observe"
    monkeypatch.setattr(pol, "OBJECTS_MODE", "enforce")
    assert objects.mode() == "enforce"


# ------------------------------------------------------------------ at the gate
def test_a_creation_is_registered_and_its_writes_are_known(addon, tmp_path, monkeypatch):
    monkeypatch.setattr(pol, "OBJECTS_MODE", "enforce")
    g = _g(addon, tmp_path)
    _create(g, "https://app.example.com/api/notes", B, headers=JSON, body=b'{"id": 12, "title": "mine"}')
    _create(g, "https://app.example.com/api/files", A, headers=[("Location", "/api/files/abc-123456789")], fid="c2")
    rows = objects.rows("t", tmp_path)
    assert [(r["identity"], r["route"], r["object_id"]) for r in rows] == [
        ("user-b", "/api/notes/{id}", "12"),
        ("user-a", "/api/files/{id}", "abc-123456789"),
    ]
    assert [e["object_id"] for e in _events(tmp_path, "object-registered")] == ["12", "abc-123456789"]
    # B's note written by A (the cross-account test) and by B; the version-prefixed route of the same collection
    for who, url in [
        (A, "https://app.example.com/api/notes/12"),
        (B, "https://app.example.com/api/v2/notes/12/"),
        (A, "https://app.example.com/api/files/ABC-123456789"),
    ]:
        for method in ("PUT", "PATCH", "DELETE"):
            assert not _write(g, url, who, method).metadata.get("bh_denied"), (who, url, method)
    assert _unknown(tmp_path) == []


def test_an_unknown_object_is_journaled_in_observe_and_let_through(addon, tmp_path):
    g = _g(addon, tmp_path)
    _create(g, "https://app.example.com/api/notes", B, headers=JSON, body=b'{"id": 12}')
    f = _write(g, "https://app.example.com/api/users/12?token=hunter2", A, "PATCH")  # another collection
    assert not f.metadata.get("bh_denied")
    (ev,) = _unknown(tmp_path)
    assert ev["would_refuse"] is True and ev["mode"] == "observe"
    assert (ev["identity"], ev["method"], ev["route"], ev["object_id"], ev["client"]) == (
        "user-a",
        "PATCH",
        "/api/users/{id}",
        "12",
        "agent",
    )
    assert "hunter2" not in ev["url"]
    assert _events(tmp_path, "blocked") == []


def test_an_unknown_object_is_refused_in_enforce(addon, tmp_path, monkeypatch):
    monkeypatch.setattr(pol, "OBJECTS_MODE", "enforce")
    g = _g(addon, tmp_path)
    f = _write(g, "https://app.example.com/api/notes/99", A, "DELETE")
    assert f.metadata.get("bh_denied")
    (ev,) = _unknown(tmp_path)
    assert ev["would_refuse"] is True and ev["mode"] == "enforce"
    (blocked,) = _events(tmp_path, "blocked")
    assert blocked["reason"] == pol.OBJECTS_REASON == "not one of your test objects"
    # a method override is the method the server runs
    f = _write(g, "https://app.example.com/api/notes/98", A, "POST", [("X-HTTP-Method-Override", "PUT")], fid="o")
    assert f.metadata.get("bh_denied")


@pytest.mark.parametrize("mode", ["observe", "enforce"])
def test_a_route_without_a_path_id_is_never_refused(addon, tmp_path, monkeypatch, mode):
    monkeypatch.setattr(pol, "OBJECTS_MODE", mode)
    g = _g(addon, tmp_path)
    for url in (
        "https://app.example.com/api/me",
        "https://app.example.com/profile/settings",
        "https://app.example.com/",
    ):
        for method in ("PUT", "PATCH", "DELETE"):
            assert not _write(g, url, A, method).metadata.get("bh_denied"), (url, method)
    assert _unknown(tmp_path) == []


def test_reads_and_posts_are_never_looked_up(addon, tmp_path, monkeypatch):
    monkeypatch.setattr(pol, "OBJECTS_MODE", "enforce")
    g = _g(addon, tmp_path)
    assert not _write(g, "https://app.example.com/api/notes/5", A, "GET").metadata.get("bh_denied")
    assert not _write(g, "https://app.example.com/api/notes/5", A, "POST").metadata.get("bh_denied")
    assert _unknown(tmp_path) == []


def test_the_hosts_own_requests_are_never_looked_up(addon, tmp_path, monkeypatch):
    """The canary's plant and the probe come from the gate's loopback under X-BH-Probe: the host, not the hunter."""
    monkeypatch.setattr(pol, "OBJECTS_MODE", "enforce")
    g = _g(addon, tmp_path)
    f = _write(g, "https://app.example.com/api/profile/7", [*B, ("X-BH-Probe", "1")], "PATCH", peer="127.0.0.1")
    assert f.metadata["bh_identity"] == "user-b" and not f.metadata.get("bh_denied")
    assert _unknown(tmp_path) == []


def test_a_broken_registry_never_refuses_nor_breaks_a_flow(addon, tmp_path, monkeypatch):
    monkeypatch.setattr(pol, "OBJECTS_MODE", "enforce")
    g = _g(addon, tmp_path)
    objects.db_path(tmp_path).write_bytes(b"this is not a database" * 100)
    assert not _write(g, "https://app.example.com/api/notes/99", A).metadata.get("bh_denied")
    f = _create(g, "https://app.example.com/api/notes", A, headers=JSON, body=b'{"id": 5}')
    assert f.response.status_code == 201 and not f.metadata.get("bh_denied")
    assert {e["where"] for e in _events(tmp_path, "objects-error")} == {"lookup", "register"}
    assert _unknown(tmp_path) == []


def test_the_table_is_created_by_ensure_and_listed_for_the_cleanup(tmp_path):
    conn = sqlite3.connect(tmp_path / "x.sqlite")
    objects.ensure(conn)
    objects.ensure(conn)  # idempotent
    cols = [r[1] for r in conn.execute(f"PRAGMA table_info({objects.TABLE})")]
    assert objects.TABLE == "test_objects" and cols == ["program", "identity", "route", "object_id", "ts"]
    conn.close()
    assert objects.rows("t", tmp_path) == []
    with objects.connect(tmp_path) as c:
        assert objects.record(c, "t", "user-a", [("/api/n/{id}", "1"), ("/api/n/{id}", "1")], now=5.0) == [
            ("/api/n/{id}", "1")
        ]
        assert objects.record(c, "u", "user-a", [("/api/n/{id}", "2")], now=6.0)
        assert objects.known(c, "t", "https://x/api/n/1") is True
        assert objects.known(c, "t", "https://x/api/other/1") is False
        assert objects.known(c, "t", "https://x/api/n/2") is False  # another program's object
        assert objects.known(c, "t", "https://x/api/n") is None
    assert objects.rows("t", tmp_path) == [{"identity": "user-a", "route": "/api/n/{id}", "object_id": "1", "ts": 5.0}]
    assert oct(objects.db_path(tmp_path).stat().st_mode & 0o777) == "0o600"
