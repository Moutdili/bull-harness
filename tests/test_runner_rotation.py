"""Context rotation (issue 10, TODO 4.2b): past a context threshold the next leg is a fresh session from the board,
with a HANDOFF on the board; past twice the threshold the leg is cut after its turn. No podman, no Claude."""

import io
import json

import pytest

from bh.board import Board
from bh.runner import ingest, run
from bh.runner.prompt import build_task
from bh.scope import scope_from_dict

LIMIT = 1000


def _turn(ctx: int, i: int = 0) -> dict:
    return {"id": f"m{ctx}-{i}", "input": 10, "cache_read": ctx - 30, "cache_write": 20, "output": 5}


def test_turn_context_sums_input_and_cache():
    assert run.turn_context({"input": 3, "cache_read": 8000, "cache_write": 1200, "output": 400}) == 9203
    assert run.turn_context({"input": None, "cache_read": 5}) == 5  # missing or null fields count as 0
    assert run.leg_context([_turn(500), _turn(1500), _turn(900)]) == (900, 1500)
    assert run.leg_context([]) == (0, 0)


def test_build_task_rotation_line():
    plain = build_task("board", first=False)
    rotated = build_task("board", first=False, rotated=True)
    assert "rotated on a context threshold" not in plain
    assert rotated.startswith("The previous session of this segment was rotated on a context threshold")
    assert "HANDOFF" in rotated and "do not redo" in rotated


# ------------------------------------------------------------------ consume_stream guard (2x threshold)
def _assistant(msg_id: str, ctx: int, tool: bool = True) -> str:
    content = [{"type": "tool_use", "id": f"t-{msg_id}", "name": "Bash", "input": {"command": "ls"}}] if tool else []
    usage = {"input_tokens": 10, "cache_read_input_tokens": ctx - 10, "cache_creation_input_tokens": 0}
    return json.dumps({"type": "assistant", "message": {"id": msg_id, "usage": usage, "content": content}}) + "\n"


def _tool_result(msg_id: str) -> str:
    block = {"type": "tool_result", "tool_use_id": f"t-{msg_id}", "content": "ok"}
    return json.dumps({"type": "user", "message": {"content": [block]}}) + "\n"


def test_stream_stops_after_the_turn_past_the_hard_limit():
    lines = [_assistant("a", 900), _tool_result("a"), _assistant("b", 2500)]
    events: list[str] = []

    class Proc:
        stdout = iter([*lines, "STOP-MARK\n", _tool_result("b"), _assistant("c", 2600), _tool_result("c")])

    def stop():
        events.append(f"stop after {len(res.turn_log)} turns")

    res = run.SegmentResult(program="p", run_id=1)
    run.consume_stream(Proc(), io.StringIO(), res, lambda s: None, limit=2 * LIMIT, stop=stop)
    # turn b went over 2000: stopped once, when b's tool result came back (not mid-turn, not again on c)
    assert events == ["stop after 2 turns"]
    assert res.overflow


def test_stream_without_limit_never_stops():
    class Proc:
        stdout = iter([_assistant("a", 99_000), _tool_result("a")])

    res = run.SegmentResult(program="p", run_id=1)
    run.consume_stream(Proc(), io.StringIO(), res, lambda s: None)  # the verifier's call: no limit
    assert not res.overflow


# ------------------------------------------------------------------ the segment loop
@pytest.fixture
def seg(tmp_path, monkeypatch):
    """_run_locked with every podman / Claude call replaced. `legs` scripts each leg: contexts, overflow, notes."""
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    board = Board(tmp_path / "var" / "board.sqlite")
    scope = scope_from_dict({"program": "p", "platform": "local", "in_scope": ["a.test"]})
    scope_file = tmp_path / "p.yaml"
    scope_file.write_text("program: p\n")
    monkeypatch.setattr(run, "CONTEXT_ROTATE_TOKENS", LIMIT)
    for name in ("activate_scope", "clean_sandbox", "prepare_workdir", "set_active_run", "push_budget"):
        monkeypatch.setattr(run, name, lambda *a, **k: None)
    monkeypatch.setattr(run, "browser_status", lambda call=None: None)
    monkeypatch.setattr(run.identity, "claude_version", lambda: "2.1.330")
    state = {"legs": [], "cmds": [], "limits": [], "cleaned": []}
    monkeypatch.setattr(run, "clean_leg", lambda prog, home: state["cleaned"].append((len(state["cmds"]), home)))

    def no_podman(*a, **k):
        raise AssertionError("a test reached podman")

    monkeypatch.setattr(run.stack, "agent_sh", no_podman)
    monkeypatch.setattr(run.stack.subprocess, "run", no_podman)
    monkeypatch.setattr(run.retention, "prune", lambda: None)
    monkeypatch.setattr(run.stack, "kill_agent", lambda *a, **k: None)
    monkeypatch.setattr(run, "refresh_identities", lambda *a, **k: set())
    monkeypatch.setattr(run, "pick_cards", lambda *a: [])
    monkeypatch.setattr(ingest, "gate_events", lambda *a: ingest.GateOutcome())
    notes_dir = tmp_path / "notes"
    notes_dir.mkdir()
    inbox = notes_dir / "notes.jsonl"  # the sandbox's notes.jsonl

    def rotate(prog, rid, leg=None):  # like the real one: move the inbox under a per-run (per-leg) name
        dst = notes_dir / (f"notes-{rid}.jsonl" if leg is None else f"notes-{rid}-leg{leg}.jsonl")
        if inbox.exists():
            inbox.replace(dst)
        return dst

    monkeypatch.setattr(run, "rotate_notes", rotate)

    def fake_leg(cmd, log, err_path, res, say, *, program, timeout_s, bh_dir=None, context_limit=None):
        err_path.touch()
        spec = state["legs"][len(state["cmds"])]
        state["cmds"].append(cmd)
        state["limits"].append(context_limit)
        res.overflow = False
        for i, ctx in enumerate(spec["ctx"]):
            res.turn_log.append(_turn(ctx, i))
            res.tool_calls += 1
            res.tool_log.append({"cmd": f"bh-crawl https://a.test/{len(state['cmds'])}-{i}"})
        with open(inbox, "a") as fh:
            fh.writelines(json.dumps(n) + "\n" for n in spec.get("notes", []))
        if spec.get("overflow"):
            res.overflow = True
            return None, False
        sid = f"s{len(state['cmds'])}"
        res.session_id = sid
        return {"subtype": "success", "num_turns": len(spec["ctx"]), "session_id": sid, "result": "done"}, False

    monkeypatch.setattr(run, "run_leg", fake_leg)

    def go(legs: list[dict], max_turns: int = 60):
        state["legs"] = legs
        res = run._run_locked(
            scope,
            scope_file,
            board,
            model="m",
            max_turns=max_turns,
            minutes=60,
            resume=False,
            quiet=True,
            extra_task="",
            effort=None,
        )
        return res, state

    return board, go


def _resumes(cmd: list[str]) -> str | None:
    return cmd[cmd.index("--resume") + 1] if "--resume" in cmd else None


def test_no_rotation_under_the_threshold(seg):
    board, go = seg
    res, st = go([{"ctx": [500, 800, 900]}, {"ctx": [950]}])
    assert res.legs == 2  # the 2nd leg used one tool: it ends the segment, as before
    assert _resumes(st["cmds"][1]) == "s1"  # nudged in the same session
    assert res.rotations == 0
    assert res.leg_context == [900, 950]
    assert st["limits"] == [2 * LIMIT, 2 * LIMIT]
    # M5: the sandbox is scrubbed before the 2nd leg (after the 1st exited), in the segment's HOME
    assert st["cleaned"] == [(1, run.sandbox_home(res.run_id))]
    # no rotation HANDOFF; the segment closed without one of the agent's: the runner's closing one (T22)
    titles = [r["title"] for r in board.rows("SELECT title FROM facts WHERE kind='handoff'")]
    assert titles == ["HANDOFF (runner): segment closed (ok)"]


def test_rotation_above_the_threshold_starts_a_fresh_session(seg):
    board, go = seg
    handoff = {"op": "fact", "title": "HANDOFF: api mapped", "kind": "handoff", "summary": "next: /api/orders"}
    res, st = go([{"ctx": [600, 900, 1200], "notes": [handoff]}, {"ctx": [800]}])
    assert res.legs == 2 and res.rotations == 1
    assert _resumes(st["cmds"][1]) is None  # fresh session, not --resume
    task = st["cmds"][1][st["cmds"][1].index("-p") + 1]
    assert "rotated on a context threshold" in task
    assert "HANDOFF: api mapped" in task  # the frontier was rebuilt from the notes ingested at rotation
    # the agent wrote its HANDOFF: the runner did not add one at the rotation (only at the close, T22: the last leg
    # wrote none)
    assert [r["title"] for r in board.rows("SELECT title FROM facts WHERE kind='handoff'")] == [
        "HANDOFF: api mapped",
        "HANDOFF (runner): segment closed (ok)",
    ]
    assert res.new_facts == 1  # counted once, though ingested mid-segment
    log = [json.loads(x) for x in run.paths.run_log(res.run_id, "p").read_text().splitlines()]
    legs = [x for x in log if x.get("type") == "bh_leg"]
    assert [(x["context_max"], x["rotate"]) for x in legs] == [(1200, True), (800, False)]


def test_runner_writes_the_handoff_when_missing(seg):
    board, go = seg
    notes = [
        {"op": "intent", "title": "test IDOR on /api/orders/{id}"},
        {"op": "fact", "title": "sqli on /search: WAF blocks", "kind": "dead-end"},
    ]
    res, st = go([{"ctx": [900, 1100], "notes": notes}, {"ctx": [750]}])
    assert res.rotations == 1
    rows = board.rows(
        "SELECT title, summary, run_id FROM facts WHERE kind='handoff' AND title LIKE '%context rotation%'"
    )
    assert len(rows) == 1
    assert rows[0]["title"] == "HANDOFF (runner): context rotation at 1100 tokens"
    assert rows[0]["run_id"] == res.run_id
    assert "Open intents: I1 test IDOR on /api/orders/{id}" in rows[0]["summary"]
    assert "Dead ends (do not redo): sqli on /search: WAF blocks" in rows[0]["summary"]
    assert "Last command: bh-crawl https://a.test/1-1" in rows[0]["summary"]
    task = st["cmds"][1][st["cmds"][1].index("-p") + 1]
    assert "HANDOFF (runner)" in task


def test_overflow_at_twice_the_threshold_cuts_the_leg_then_rotates(seg):
    board, go = seg
    res, st = go([{"ctx": [900, 1500, 2100], "overflow": True}, {"ctx": [800]}])
    assert st["limits"][0] == 2 * LIMIT  # the guard the stream reader enforces
    assert res.legs == 2 and res.rotations == 1
    assert _resumes(st["cmds"][1]) is None
    assert res.turns == 3 + 1  # the cut leg's turns are counted from the turn log
    assert res.status == "ok"
    assert board.rows("SELECT title FROM facts WHERE kind='handoff'")[0]["title"].startswith("HANDOFF (runner)")


def test_rotation_metrics_are_stored(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    board = Board(tmp_path / "var" / "board.sqlite")
    rid = board.run_start("p", "m")
    board.run_set(rid, rotations=2, max_context=31000)
    row = board.rows("SELECT rotations, max_context FROM runs WHERE id=?", rid)[0]
    assert (row["rotations"], row["max_context"]) == (2, 31000)


# ------------------------------------------------------------------ audit I11 and Mio's resume rule, in the loop
def test_stop_note_ends_the_segment_and_parks_the_program(seg, tmp_path, monkeypatch):
    board, go = seg
    pushed: list = []
    real = run.StopWatcher
    monkeypatch.setattr(
        run,
        "StopWatcher",
        lambda prog, rid, **kw: real(
            prog, rid, path=tmp_path / "notes" / "notes.jsonl", notify=lambda t, m: pushed.append(m), **kw
        ),
    )
    stop = {"op": "blocked", "reason": "server-exec", "title": "id ran on the server"}
    res, st = go([{"ctx": [500, 600], "notes": [stop]}, {"ctx": [500]}])
    assert len(st["cmds"]) == 1 and res.status == "parked"  # no second leg, nothing judged
    assert run.parked("p")["reason"] == "server-exec" and len(pushed) == 1 and "id ran" not in pushed[0]
    titles = [r["title"] for r in board.rows("SELECT title FROM facts WHERE kind='blocker'")]
    assert "[server-exec] id ran on the server" in titles


def test_pending_challenge_opens_the_next_leg(seg, monkeypatch):
    _board, go = seg
    monkeypatch.setattr(run, "has_browser", lambda scope: True)
    monkeypatch.setattr(run, "browser_status", lambda call=None: {"challenge": {"pending": True}})
    _res, st = go([{"ctx": [500, 600], "notes": [{"op": "intent", "title": "send prompt 3"}]}, {"ctx": [500]}])
    task = st["cmds"][1][st["cmds"][1].index("-p") + 1]
    assert task.startswith("A human challenge was pending: `bh-web state` first, then resume")
