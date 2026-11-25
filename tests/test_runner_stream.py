"""The stream of `claude -p` is written by a process the hunter shares a uid with (M6, M8, B8): a line that is not a
JSON object never crashes the runner, and a refusal or a quota stop is believed only where a second source agrees.
No podman, no Claude: the leg is replaced by lines fed to the real stream reader."""

import io
import json
import time

import pytest

from bh import paths
from bh.board import Board
from bh.runner import ingest, run
from bh.scope import scope_from_dict


class Proc:
    def __init__(self, lines):
        self.stdout = iter(lines)


def _read(lines) -> run.SegmentResult:
    res = run.SegmentResult(program="p", run_id=1)
    run.consume_stream(
        Proc([x if isinstance(x, str) else json.dumps(x) + "\n" for x in lines]), io.StringIO(), res, lambda s: None
    )
    return res


def _assistant(mid, content=(), stop=None):
    return {"type": "assistant", "message": {"id": mid, "content": list(content), "stop_reason": stop}}


def _bash(tid, cmd):
    return {"type": "tool_use", "id": tid, "name": "Bash", "input": {"command": cmd}}


def _result(tid, text):
    return {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": tid, "content": text}]}}


def test_lines_that_are_not_objects_or_have_odd_types_are_skipped():
    res = _read(
        [
            "[1]\n",
            "42\n",
            '"assistant"\n',
            "null\n",
            "not json\n",
            {"type": "assistant", "message": [1]},
            {"type": "assistant", "message": {"id": ["x"], "content": "text", "usage": [1]}},
            {
                "type": "assistant",
                "message": {"id": "m1", "content": [1, {"type": "tool_use", "id": {}, "input": [2]}]},
            },
            {"type": "assistant", "message": {"id": "m2", "content": [{"type": "text", "text": 5}]}},
            {
                "type": "user",
                "message": {"content": [{"type": "tool_result", "tool_use_id": ["u"], "content": [{"text": 3}]}]},
            },
            {"type": "user", "message": "x"},
            {"type": "system", "subtype": "init", "session_id": {"a": 1}},
            {"type": "rate_limit_event", "rate_limit_info": "rejected"},
            _assistant("m3", [_bash("t1", "q https://a.test/")]),
            _result("t1", "ok"),
        ]
    )
    assert [t["id"] for t in res.turn_log] == ["m1", "m2", "m3"]
    assert res.tool_calls == 2 and res.tool_log[-1]["ms"] is not None
    assert res.rate_limit == {} and res.session_id is None


def test_merge_result_ignores_fields_of_the_wrong_type():
    res = run.SegmentResult(program="p", run_id=1)
    run.merge_result(
        res,
        {
            "subtype": "success",
            "num_turns": "9",
            "total_cost_usd": "1",
            "usage": [1],
            "result": {"x": 1},
            "session_id": 3,
        },
    )
    assert (res.turns, res.cost_usd, res.usage, res.text, res.status) == (0, 0.0, {}, "", "ok")


def test_a_far_reset_is_dropped():
    now = time.time()
    info = run.rate_limit_info({"status": "rejected", "resetsAt": now + 7 * 86400}, now)
    assert info["resetsAt"] == now + 7 * 86400
    assert "resetsAt" not in run.rate_limit_info({"status": "rejected", "resetsAt": now + 8 * 86400 + 60}, now)
    assert "resetsAt" not in run.rate_limit_info({"status": "rejected", "resetsAt": "soon"}, now)


def test_the_refusal_is_tied_to_the_last_command_and_page():
    res = _read(
        [
            _assistant("m1", [_bash("t1", "q https://a.test/one")]),
            _result("t1", "200 https://a.test/one"),
            _assistant("m2", [_bash("t2", "bh-browse https://a.test/blog/post?id=7")]),
            _result("t2", "bh-browse https://a.test/blog/post?id=7: 200, title 'x'\nsee https://elsewhere.test/"),
            _assistant("m3", stop="refusal"),
        ]
    )
    assert res.status == "refusal" and res.refusal_id == "m3"
    assert res.refusal_cause["key"] == "a.test/blog/post"
    assert res.refusal_cause["cmd"] == "bh-browse https://a.test/blog/post?id=7"


# ------------------------------------------------------------------ the cross-checks
def test_refusal_needs_the_relay_once_it_logs_message_ids():
    res = run.SegmentResult(program="p", run_id=1, status="refusal", refusal_id="msg_1")
    plain = [{"kind": "relay", "run": 1, "method": "POST"}]
    assert run.refusal_confirmed(res, plain)  # no ids logged yet: the stream's word stands (CVP side)
    assert run.refusal_confirmed(res, [])
    assert run.refusal_confirmed(res, [{"kind": "relay", "msg_id": "msg_1", "stop_reason": "refusal"}])
    assert run.refusal_confirmed(res, [{"kind": "relay", "msg_id": "msg_1"}])
    assert not run.refusal_confirmed(res, [{"kind": "relay", "msg_id": "msg_2"}])  # forged id
    assert not run.refusal_confirmed(res, [{"kind": "relay", "msg_id": "msg_1", "stop_reason": "end_turn"}])


def test_quota_needs_the_stream_and_a_second_source():
    res = run.SegmentResult(program="p", run_id=1, rate_limit={"status": "rejected"})
    assert not run.quota_confirmed(res, "", [])  # the stream alone
    assert run.quota_confirmed(res, "Claude AI usage limit reached", [])  # + stderr
    assert run.quota_confirmed(res, "", [{"kind": "relay", "status": 429}])
    # once the relay logs statuses, they decide: a forged stderr is not enough
    assert not run.quota_confirmed(res, "usage limit reached", [{"kind": "relay", "status": 200}])
    res.rate_limit = {"status": "allowed"}
    assert not run.quota_confirmed(res, "usage limit reached", [{"kind": "relay", "status": 429}])


def test_relay_events_reads_this_run_from_the_offset(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    log = paths.events_log()
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(json.dumps({"kind": "relay", "run": 5, "status": 429}) + "\n")
    at = run.events_size()
    with open(log, "a") as fh:
        for rec in ({"kind": "relay", "run": 5}, {"kind": "relay", "run": 6}, {"kind": "blocked", "run": 5}, [1]):
            fh.write(json.dumps(rec) + "\n")
    assert run.relay_events(5, at) == [{"kind": "relay", "run": 5}]
    assert run.relay_events(5, 10**9) == [{"kind": "relay", "run": 5, "status": 429}, {"kind": "relay", "run": 5}]


# ------------------------------------------------------------------ the segment
@pytest.fixture
def seg(tmp_path, monkeypatch):
    """_run_locked with podman and Claude replaced: each leg feeds `lines` to the real stream reader."""
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    board = Board(tmp_path / "var" / "board.sqlite")
    scope = scope_from_dict({"program": "p", "platform": "local", "in_scope": ["a.test"]})
    scope_file = tmp_path / "p.yaml"
    scope_file.write_text("program: p\n")
    for name in ("activate_scope", "clean_sandbox", "clean_leg", "prepare_workdir", "set_active_run"):
        monkeypatch.setattr(run, name, lambda *a, **k: None)
    monkeypatch.setattr(run.retention, "prune", lambda: None)
    monkeypatch.setattr(run.stack, "kill_agent", lambda *a, **k: None)
    monkeypatch.setattr(run, "pick_cards", lambda *a: [])
    monkeypatch.setattr(run, "rotate_notes", lambda *a: tmp_path / "none.jsonl")
    monkeypatch.setattr(ingest, "gate_events", lambda *a: ingest.GateOutcome())

    def no_podman(*a, **k):
        raise AssertionError("a test reached podman")

    monkeypatch.setattr(run.stack, "agent_sh", no_podman)
    order: list[str] = []
    monkeypatch.setattr(run, "refresh_identities", lambda *a, **k: order.append("refresh") or set())
    import bh.verify

    monkeypatch.setattr(bh.verify, "verify_pending", lambda *a, **k: order.append("verify"))
    spec = {"lines": [], "stderr": "", "relay": []}

    def fake_leg(cmd, log, err_path, res, say, *, program, timeout_s, bh_dir=None, context_limit=None):
        err_path.write_text(spec["stderr"])
        ev = paths.events_log()
        ev.parent.mkdir(parents=True, exist_ok=True)
        with open(ev, "a") as fh:
            fh.writelines(json.dumps({"kind": "relay", "run": res.run_id, **r}) + "\n" for r in spec["relay"])
        lines = [json.dumps(x) + "\n" for x in spec["lines"]]
        result = run.consume_stream(Proc(lines), log, res, say)
        return result, False

    monkeypatch.setattr(run, "run_leg", fake_leg)

    def go(**kw):
        spec.update(kw)
        order.clear()
        res = run._run_locked(
            scope,
            scope_file,
            board,
            model="m",
            max_turns=60,
            minutes=60,
            resume=False,
            quiet=True,
            extra_task="",
            effort=None,
        )
        return res, order

    return board, go


DONE = {"type": "result", "subtype": "success", "num_turns": 1, "result": "done", "session_id": "s"}


def test_model_text_never_makes_a_quota_stop(seg):
    """B8: a segment that ends quoting 'usage limit reached' from a target page is not a quota stop."""
    board, go = seg
    board.add_finding("p", "waiting", proof={"steps": []})
    end = {**DONE, "subtype": "error_max_turns", "result": "the page says: usage limit reached, resets at 5pm"}
    res, order = go(lines=[_assistant("m1"), end])
    assert res.status == "max_turns"
    assert order == ["refresh", "refresh", "verify"]  # M1: identities refreshed before the verification


def test_forged_rate_limit_event_alone_is_not_a_quota_stop(seg):
    board, go = seg
    board.add_finding("p", "waiting", proof={"steps": []})
    forged = {
        "type": "rate_limit_event",
        "rate_limit_info": {"status": "rejected", "resetsAt": time.time() + 7 * 86400},
    }
    res, order = go(lines=[forged, _assistant("m1"), DONE])
    assert res.status == "ok" and res.quota_claimed
    assert order == ["refresh"]  # no verification after a quota claim, confirmed or not


def test_rate_limit_event_with_a_relay_429_is_a_quota_stop(seg):
    _, go = seg
    ev = {"type": "rate_limit_event", "rate_limit_info": {"status": "rejected"}}
    res, _ = go(lines=[_assistant("m1"), ev, {**DONE, "subtype": "error", "is_error": True}], relay=[{"status": 429}])
    assert res.status == "quota"


def test_a_refusal_the_relay_never_streamed_is_ignored(seg):
    board, go = seg
    res, _ = go(lines=[_assistant("m9", stop="refusal")], relay=[{"msg_id": "m1"}])
    assert res.status == "error"
    assert not board.rows("SELECT 1 FROM facts WHERE title LIKE '[refusal]%'")
    assert run.recent_refusals(board, "p") == []


def test_a_streamed_refusal_closes_its_page(seg):
    board, go = seg
    lines = [
        _assistant("m1", [_bash("t1", "q https://a.test/blog?x=1")]),
        _result("t1", "200"),
        _assistant("m2", stop="refusal"),
    ]
    res, _ = go(lines=lines, relay=[{"msg_id": "m1"}, {"msg_id": "m2", "stop_reason": "refusal"}])
    assert res.status == "refusal" and not res.refusal_repeat
    assert [r["title"] for r in board.rows("SELECT title FROM facts WHERE kind='blocker'")] == [
        "[refusal] https://a.test/blog?x=1"
    ]
    res, _ = go(lines=lines, relay=[{"msg_id": "m2"}])
    assert res.status == "refusal" and res.refusal_repeat  # same page: counted once
    assert len(run.recent_refusals(board, "p")) == 1
