import json
import stat

import pytest

from bh.ui.server import Handler


def test_identity_save_is_private_and_never_silently_overwritten(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    body = {"program": "lab", "name": "user-a", "headers": "Cookie: s=1\nbad header\nAuthorization: Bearer x"}
    assert Handler._save_identity(None, body)["headers"] == ["Authorization", "Cookie"]
    p = tmp_path / "var" / "state" / "identities" / "lab" / "user-a.json"
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    with pytest.raises(ValueError, match="already exists"):
        Handler._save_identity(None, {**body, "headers": "Cookie: s=2"})
    Handler._save_identity(None, {**body, "headers": "Cookie: s=2", "overwrite": True})
    assert json.loads(p.read_text())["headers"] == {"Cookie": "s=2"}
    with pytest.raises(ValueError):
        Handler._save_identity(None, {**body, "name": "../x"})


def test_session_cookie_is_not_the_token():
    from bh.ui.server import new_session, session_valid

    s = new_session("tok")
    assert "tok" not in s and session_valid(s, "tok")
    assert not session_valid(s, "other-token") and not session_valid("tok", "tok") and not session_valid("", "tok")


def test_session_expires():
    from bh.ui.server import SESSION_S, new_session, session_valid

    s = new_session("tok", now=1_000_000)
    assert session_valid(s, "tok", now=1_000_000 + SESSION_S - 1)
    assert not session_valid(s, "tok", now=1_000_000 + SESSION_S + 1)
    assert not session_valid(s, "tok", now=1_000_000 - 3600)  # issued in the future: forged clock


def test_request_numbers_are_bounded():
    import pytest

    from bh.ui.server import bounded, content_length

    assert content_length({}, 10) == 0 and content_length({"Content-Length": "7"}, 10) == 7
    for bad in ("-1", "abc", "11", "1e3"):
        with pytest.raises(ValueError):
            content_length({"Content-Length": bad}, 10)
    assert bounded(None, 20, 1, 60) == 20 and bounded("5", 20, 1, 60) == 5
    for bad in ("inf", "nan", "0", "1e9"):
        with pytest.raises(ValueError):
            bounded(bad, 20, 1, 60)


def test_stop_signals_only_a_bh_process():
    import os

    from bh.ui.server import is_ui_run

    assert not is_ui_run(os.getpid())  # pytest, not the bh CLI
    assert not is_ui_run(1)


def _serve(tmp_path, monkeypatch):
    """A real UI server on an ephemeral 127.0.0.1 port (the OS picks a free one), with a logged-in cookie."""
    import threading
    from http.server import ThreadingHTTPServer

    from bh.ui.server import COOKIE, new_session

    monkeypatch.setenv("BH_HOME", str(tmp_path))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.token = "tok"
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"{COOKIE}={new_session('tok')}"


def _get(srv, path, cookie=None):
    import urllib.error
    import urllib.request

    req = urllib.request.Request(f"http://127.0.0.1:{srv.server_address[1]}{path}")
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def test_blockers_api_needs_auth_and_lists_blocker_facts(tmp_path, monkeypatch):
    from bh.board import Board

    srv, cookie = _serve(tmp_path, monkeypatch)
    try:
        b = Board()
        b.add_blocker("lab", "waf", "challenge on login", host="a.example.com")
        b.add_fact("lab", "plain fact")
        assert _get(srv, "/api/blockers")[0] == 401
        code, body = _get(srv, "/api/blockers", cookie)
        rows = json.loads(body)
        assert code == 200 and len(rows) == 1
        assert rows[0]["title"] == "[waf] challenge on login" and rows[0]["evidence"] == "host:a.example.com"
    finally:
        srv.shutdown()
        srv.server_close()


def test_todos_api_returns_submissions_only(tmp_path, monkeypatch):
    import time

    from bh.board import Board

    srv, cookie = _serve(tmp_path, monkeypatch)
    try:
        b = Board()
        b.add_todo("submit", "F1 verified")
        # add_todo refuses the retired kinds: an old-model todo can only exist from before the migration
        b.db.execute(
            "INSERT INTO todos(program, kind, title, status, created) VALUES ('lab','waf','old waf','obsolete',?)",
            (time.time(),),
        )
        b.db.execute(
            "INSERT INTO todos(program, kind, title, status, created) VALUES ('lab','auth','old auth','open',?)",
            (time.time(),),
        )
        b.db.commit()
        for q in ("", "?status=obsolete", "?status=open"):
            titles = [t["title"] for t in json.loads(_get(srv, f"/api/todos{q}", cookie)[1])]
            assert "old waf" not in titles and "old auth" not in titles
        assert [t["kind"] for t in json.loads(_get(srv, "/api/todos", cookie)[1])] == ["submit"]
        status = json.loads(_get(srv, "/api/status", cookie)[1])
        assert status["to_submit"] == 1 and "open_todos" not in status
    finally:
        srv.shutdown()
        srv.server_close()
