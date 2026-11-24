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
