import pytest

from bh.agent import contract as c
from bh.agent import note


@pytest.fixture
def bh_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_DIR", str(tmp_path))
    monkeypatch.setenv("BH_PROGRAM", "p")
    monkeypatch.delenv("BH_ROLE", raising=False)
    return tmp_path


def test_blocked_writes_one_note(bh_dir):
    note.main(["blocked", "waf", "a.test challenges every request", "-d", "403 cf", "--intent", "I3", "--host", "a.t"])
    note.main(["blocked", "account", "IDOR needs a 2nd account"])
    assert [{k: v for k, v in r.items() if k != "ts"} for r in c.read_jsonl(bh_dir / c.NOTES)] == [
        {
            "op": "blocked",
            "reason": "waf",
            "title": "a.test challenges every request",
            "detail": "403 cf",
            "intent": "I3",
            "host": "a.t",
            "program": "p",
        },
        {
            "op": "blocked",
            "reason": "account",
            "title": "IDOR needs a 2nd account",
            "detail": "",
            "intent": "",
            "host": "",
            "program": "p",
        },
    ]


@pytest.mark.parametrize(
    "argv",
    [
        ["todo", "auth", "need a session"],  # the human is out of the hunt: no todo channel any more
        ["blocked", "bored", "x"],  # reasons are a closed list
        ["fact", "x", "-k", "blocker"],  # blocker facts are host-written
    ],
)
def test_refused(bh_dir, argv):
    with pytest.raises(SystemExit) as exc:
        note.main(argv)
    assert exc.value.code == 2  # argparse error
    assert not (bh_dir / c.NOTES).exists()
