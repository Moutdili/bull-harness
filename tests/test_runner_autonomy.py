"""The runner acts on the walls of a segment without a human: refusals, WAF hosts, expired identities."""

import json
import os
import time

from bh import paths
from bh.assets import Graph
from bh.board import Board
from bh.runner import ingest, run
from bh.scope import scope_from_dict


def _board(tmp_path, monkeypatch) -> Board:
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    return Board(tmp_path / "var" / "board.sqlite")


def _env(cmd: list[str], key: str) -> str:
    return next(x.split("=", 1)[1] for x in cmd if x.startswith(f"{key}="))


def test_stale_identity_is_not_offered(tmp_path, monkeypatch):
    b = _board(tmp_path, monkeypatch)
    now = time.time()
    d = paths.identities_dir("p")
    d.mkdir(parents=True)
    for name in ("alice", "bob"):
        (d / f"{name}.json").write_text("{}")
        os.utime(d / f"{name}.json", (now - 1000, now - 1000))
    b.meta_set("identity-stale:alice:p", str(now - 500))  # the gate saw alice expire after her file was written
    b.meta_set("identity-stale:carol:p", str(now - 500))  # a scope identity without a file: stale too
    scope = scope_from_dict(
        {"program": "p", "platform": "x", "in_scope": ["a.test"], "identities": [{"name": "carol"}, {"name": "dan"}]}
    )
    assert run.live_identities(b, "p") == ["bob"]
    names = run.live_identities(b, "p", also=[i["name"] for i in scope.identities])
    cmd = run.agent_command(scope, "t", run_id=1, model="m", max_turns=5, effort=None, session=None, identities=names)
    assert _env(cmd, "BH_IDENTITIES") == "bob,dan"
    os.utime(d / "alice.json", (now, now))  # the file was refreshed: the mark is lifted
    assert run.live_identities(b, "p") == ["alice", "bob"]


def test_a_mark_nobody_can_check_is_not_final(tmp_path, monkeypatch):
    """H4 (c): an identity without recipe nor probe (made in the UI) cannot be re-checked by the runner: its stale
    mark lapses, instead of keeping it out until someone rewrites the file. A verifiable one keeps its mark."""
    b = _board(tmp_path, monkeypatch)
    now = time.time()
    d = paths.identities_dir("p")
    d.mkdir(parents=True)
    for name in ("ui", "probed"):
        (d / f"{name}.json").write_text("{}")
        os.utime(d / f"{name}.json", (now - 9 * 3600, now - 9 * 3600))
        b.meta_set(f"identity-stale:{name}:p", str(now - 7 * 3600))
    probe = {"url": "http://a.test/me", "status": 200}
    scope = scope_from_dict(
        {
            "program": "p",
            "platform": "local",
            "in_scope": ["a.test"],
            "identities": [{"name": "probed", "probe": probe}],
        }
    )
    assert run.live_identities(b, "p", scope=scope, now=now - 2 * 3600) == []  # 5 h old: both still out
    assert run.live_identities(b, "p", scope=scope, now=now) == ["ui"]  # 7 h old: only the unverifiable lapses


def test_a_probe_only_identity_is_probed_and_a_good_probe_lifts_the_mark(tmp_path, monkeypatch):
    """H4 (c): no recipe, a probe: probed before the segment when marked; ok lifts the mark, a failure keeps it."""
    from bh.accounts import enroll as en

    b = _board(tmp_path, monkeypatch)
    now = time.time()
    d = paths.identities_dir("p")
    d.mkdir(parents=True)
    (d / "alice.json").write_text("{}")
    os.utime(d / "alice.json", (now - 100, now - 100))
    b.meta_set("identity-stale:alice:p", str(now - 50))
    probe = {"url": "http://a.test/me", "status": 200}
    scope = scope_from_dict(
        {"program": "p", "platform": "local", "in_scope": ["a.test"], "identities": [{"name": "alice", "probe": probe}]}
    )
    answers = [(False, "HTTP 401"), (True, "HTTP 200")]
    probed = []

    def fake_probe(ident):
        probed.append(ident.name)
        return answers.pop(0)

    monkeypatch.setattr(en, "probe", fake_probe)
    monkeypatch.setattr(en, "refresh", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no recipe: no login")))
    assert run.refresh_identities(b, scope, 1) == {"alice"}  # bad probe: still out of the segment
    assert run.refresh_identities(b, scope, 2) == set()  # good probe: back
    assert probed == ["alice", "alice"]
    assert run.live_identities(b, "p", scope=scope) == ["alice"]
    assert run.refresh_identities(b, scope, 3) == set() and probed == ["alice", "alice"]  # not marked: not probed


def test_finish_on_refusal_records_a_blocker_not_a_todo(tmp_path, monkeypatch):
    b = _board(tmp_path, monkeypatch)
    scope = scope_from_dict({"program": "p", "platform": "local", "in_scope": ["a.test"]})
    rid = b.run_start("p", "m")
    flows = paths.flows_log()
    flows.parent.mkdir(parents=True, exist_ok=True)
    flows.write_text(
        json.dumps({"run": rid, "class": "target", "method": "GET", "url": "https://x.other.test/"}) + "\n"
    )
    monkeypatch.setattr(run, "rotate_notes", lambda prog, run_id: tmp_path / "none.jsonl")
    monkeypatch.setattr(ingest, "gate_events", lambda *a: ingest.GateOutcome(blockers=1, waf_hosts={"a.test"}))
    res = run.SegmentResult(program="p", run_id=rid, status="refusal")
    res.tool_log = [{"cmd": "sqlmap -u https://a.test/x"}, {"cmd": ""}]
    run.finish(b, res, scope, (0, 0), effort=None, note="refused")

    assert b.rows("SELECT COUNT(*) n FROM todos")[0]["n"] == 0
    blockers = b.rows("SELECT title, summary, evidence FROM facts WHERE kind='blocker'")
    assert [r["title"] for r in blockers] == ["[refusal] https://a.test/x"]  # the page, not the run
    assert blockers[0]["summary"].startswith("sqlmap -u https://a.test/x\ncause: a.test/x\nlog: ")
    assert blockers[0]["evidence"] == "host:a.test"
    assert not res.refusal_repeat
    assert len(run.recent_refusals(b, "p")) == 1
    assert res.new_blockers == 2  # the gate's WAF blocker + the refusal
    assert b.rows("SELECT blockers FROM runs WHERE id=?", rid)[0]["blockers"] == 2
    assert "a.test" in Graph(b, scope).blocked()  # the WAF host is set aside for an hour
    oos = b.rows("SELECT summary FROM facts WHERE kind='out-of-scope'")
    assert [r["summary"] for r in oos] == ["x.other.test"]
    # the next run of the program is told which lead is closed
    assert run.last_refusal(b, "p", b.run_start("p", "m")) == "sqlmap -u https://a.test/x"


def test_the_same_page_refused_again_is_one_cause(tmp_path, monkeypatch):
    """M8: three refusals that follow the same page (whatever the query) count once; another page counts again."""
    b = _board(tmp_path, monkeypatch)
    scope = scope_from_dict({"program": "p", "platform": "local", "in_scope": ["a.test"]})
    monkeypatch.setattr(run, "rotate_notes", lambda prog, run_id: tmp_path / "none.jsonl")
    monkeypatch.setattr(ingest, "gate_events", lambda *a: ingest.GateOutcome())
    repeats = []
    for cmd in (
        "q https://a.test/page?x=1",
        "q 'https://a.test/page/?x=2'",
        "bh-browse https://a.test/page",
        "q https://a.test/other",
    ):
        res = run.SegmentResult(program="p", run_id=b.run_start("p", "m"), status="refusal")
        res.tool_log = [{"cmd": cmd}]
        run.finish(b, res, scope, (0, 0), effort=None, note="refused")
        repeats.append(res.refusal_repeat)
    assert repeats == [False, True, True, False]
    assert len(run.recent_refusals(b, "p")) == 2


def test_refusal_cause_prefers_the_command_then_the_reported_page():
    c = run.refusal_cause("q -a alice https://A.test/api/x?id=1 | head", ["https://evil.test/"])
    assert (c["url"], c["host"], c["key"]) == ("https://A.test/api/x?id=1", "a.test", "a.test/api/x")
    c = run.refusal_cause("cat out.html", ["https://a.test/p", "https://link.test/"])
    assert c["key"] == "a.test/p"  # the page the tool reports on, not a link in its body
    assert run.refusal_cause("python3 x.py", [])["key"] == "cmd:python3 x.py"


def test_refusal_window_is_seven_days(tmp_path, monkeypatch):
    b = _board(tmp_path, monkeypatch)
    now = time.time()
    b.meta_set("refusals:p", json.dumps([now - 8 * 86400, now - 3600, "junk"]))
    assert run.record_refusal(b, "p", now) == 2
    assert run.recent_refusals(b, "p", now) == [now - 3600, now]
    b.meta_set("refusals:p", "not json")
    assert run.recent_refusals(b, "p", now) == []


def test_pending_findings_counts_every_waiting_proof(tmp_path, monkeypatch):
    b = _board(tmp_path, monkeypatch)
    b.add_finding("p", "with proof", proof={"steps": []})  # left 'new' by an earlier segment
    b.add_finding("p", "no proof")
    done = b.add_finding("p", "judged", proof={"steps": []})
    b.set_finding(done, "rejected")
    assert run.pending_findings(b, "p") == 1


def test_identity_without_session_is_refreshed_once_an_hour(tmp_path, monkeypatch):
    from bh.accounts import enroll as en

    b = _board(tmp_path, monkeypatch)
    login = {"method": "POST", "url": "http://a.test/login", "json": {"email": "{email}", "password": "{password}"}}
    recipe = {"login": login, "token": "t", "headers": {"Authorization": "Bearer {token}"}}
    scope = scope_from_dict(
        {
            "program": "p",
            "platform": "local",
            "in_scope": ["a.test"],
            "identities": [{"name": "alice", "enroll": recipe}, {"name": "bob"}],
        }
    )
    calls = []

    def failing(scope, name, board):
        calls.append(name)
        raise en.AccountError("login: HTTP 401")

    monkeypatch.setattr(en, "refresh", failing)
    assert run.refresh_identities(b, scope, 1) == {"alice"}
    assert run.refresh_identities(b, scope, 2) == {"alice"}  # within the hour: no second attempt
    assert calls == ["alice"]  # bob has no recipe: never touched
    blockers = b.rows("SELECT title FROM facts WHERE program='p' AND kind='blocker'")
    assert [r["title"] for r in blockers] == ["[login-failed] identity alice"]
    assert not b.rows("SELECT 1 FROM todos WHERE program='p'")

    def ok(scope, name, board):
        calls.append(name)
        d = paths.identities_dir("p")
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{name}.json").write_text('{"headers": {}}')
        return "logged in, probe ok"

    monkeypatch.setattr(en, "refresh", ok)
    b.meta_set("accounts-attempt:alice:p", "0")  # the hour has passed
    assert run.refresh_identities(b, scope, 3) == set()
    b.meta_set("identity-stale:alice:p", str(time.time() + 10))  # the gate saw the session die afterwards
    b.meta_set("accounts-attempt:alice:p", "0")
    calls.clear()
    assert run.refresh_identities(b, scope, 4) == {"alice"}  # `ok` rewrote the file before the mark: still stale
    assert calls == ["alice"]


def test_a_false_stale_mark_is_lifted_at_the_next_segment(tmp_path, monkeypatch):
    """A 401 that was an authorization refusal marks the identity stale; the next segment probes it again at once
    (no hourly wait after a success), and a good probe rewrites the session file, which lifts the mark."""
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    from bh.accounts import enroll as en

    b = Board(tmp_path / "board.sqlite")
    recipe = {
        "login": {"method": "POST", "url": "http://a.test/login", "json": {"email": "{email}"}},
        "token": "t",
        "headers": {"Authorization": "Bearer {token}"},
    }
    scope = scope_from_dict(
        {
            "program": "p",
            "platform": "local",
            "in_scope": ["a.test"],
            "identities": [{"name": "alice", "enroll": recipe}],
        }
    )
    calls = []

    def probe_ok(scope, name, board):
        calls.append(name)
        d = paths.identities_dir("p")
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{name}.json").write_text('{"headers": {}}')
        return "session ok"

    monkeypatch.setattr(en, "refresh", probe_ok)
    assert run.refresh_identities(b, scope, 1) == set()
    f = paths.identities_dir("p") / "alice.json"
    os.utime(f, (time.time() - 100, time.time() - 100))
    b.meta_set("identity-stale:alice:p", str(time.time() - 50))  # false session-dead during segment 1
    assert run.live_identities(b, "p") == []
    assert run.refresh_identities(b, scope, 2) == set()  # probed again right away, mark lifted
    assert calls == ["alice", "alice"]
