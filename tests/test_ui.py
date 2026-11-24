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
