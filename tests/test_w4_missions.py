"""W4-D: missions (T17), chains (T29), parking (T21), progress review (T34), cost cap (T50) and the lines owed to the
other lots of W4. No podman, no Claude, no network."""

import json
import re
import sys
import types

import pytest

from bh import paths
from bh.agent import contract as c
from bh.agent import hooks
from bh.assets import Graph
from bh.board import Board
from bh.runner import identity, lineage_hooks, missions, run, supervisor
from bh.runner.prompt import MAIL_LINE, build_system_prompt, build_task, build_verifier_prompt, scope_block
from bh.runner.run import SegmentResult
from bh.scope import scope_from_dict

ORIGIN = "https://app.t.test:443"
# words that would tell the agent how or when to finish
FINISHING = re.compile(r"\b(finish\w*|stop\w*|end|ends|ending|wrap\w*|conclu\w*|done|final\w*|complete\w*|summar\w*)\b")


def _board(tmp_path, monkeypatch) -> Board:
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    return Board(tmp_path / "var" / "board.sqlite")


def _scope(**kw):
    return scope_from_dict({"program": "p", "platform": "local", "in_scope": ["app.t.test"], **kw})


class _With:
    """A scope with fields other lots add (lot A: `cost_cap_usd`, the `oob` support kind; lot H: `mail_from`)."""

    def __init__(self, scope, oob=(), **fields):
        self._scope, self._oob = scope, tuple(oob)
        self.__dict__.update(fields)

    def support_hosts(self, kind):
        return self._oob if kind == "oob" else self._scope.support_hosts(kind)

    def __getattr__(self, name):
        return getattr(self._scope, name)


def _surface(b, scope):
    g = Graph(b, scope)
    g.endpoint(ORIGIN, "GET /api/users/{id}", "tool", ["id"])
    g.endpoint(ORIGIN, "GET /redirect", "tool", ["url"])
    b.db.commit()


def _given(b, mission, program="p"):
    """A run of `program` that carried `mission` (what the next draw reads)."""
    missions.ensure(b)
    rid = b.run_start(program, "m")
    b.run_set(rid, mission=missions.dumps(mission))
    b.run_end(rid, status="ok")
    return rid


def _cover(b, endpoint, cls, outcome, rid):
    b.db.execute(
        "INSERT INTO coverage_class(program, endpoint, vuln_class, outcome, run_id, ts, gate_seen) "
        "VALUES ('p', ?, ?, ?, ?, ?, 1)",
        (endpoint, cls, outcome, rid, float(rid)),
    )
    b.db.commit()


# ------------------------------------------------------------------ T17: budgets
def test_budgets_floor_ceiling_and_one_extension_of_half():
    assert missions.TURNS == {"map": 15, "test": 40, "prove": 25, "chain": 30, "free": 50}
    assert (missions.FLOOR, missions.CEIL) == (15, 80)
    assert missions.clamp(3) == 15 and missions.clamp(500) == 80 and missions.clamp(40) == 40
    for kind in missions.KINDS:
        m = missions.make(kind)
        assert missions.FLOOR <= m["turns"] <= missions.CEIL
        ext = missions.extension_turns(m)
        assert ext == min(m["turns"] // 2, missions.CEIL - m["turns"]) and m["turns"] + ext <= missions.CEIL
    assert missions.extension_turns(missions.make("free")) == 25
    assert missions.extension_turns({"turns": 80}) == 0
    assert missions.extension_turns(None) == 0
    with pytest.raises(ValueError):
        missions.make("plan")


def test_shipped_off(monkeypatch):
    monkeypatch.delenv("BH_MISSIONS", raising=False)
    assert missions.setting() == "0" and not missions.enabled()
    assert run.draw_mission(None, None, print) is None  # off: not even the board is read
    monkeypatch.setenv("BH_MISSIONS", "1")
    assert missions.enabled()
    monkeypatch.setenv("BH_MISSIONS", "yes")
    assert not missions.enabled()


# ------------------------------------------------------------------ T17: the order of the draw
def test_first_draw_on_an_unmapped_program_is_a_map(tmp_path, monkeypatch):
    b, scope = _board(tmp_path, monkeypatch), _scope()
    m = missions.next(b, scope)
    assert m["kind"] == "map" and m["turns"] == 15 and m["skill"] == "api-surface-mapping" and m["surface"] is None
    _given(b, m)
    _given(b, missions.next(b, scope))
    assert missions.next(b, scope)["kind"] == "free"  # mapping twice found nothing: no third map


def test_order_prove_then_test_by_value_then_second_pass_then_chain(tmp_path, monkeypatch):
    b, scope = _board(tmp_path, monkeypatch), _scope()
    _surface(b, scope)
    fid = b.add_fact("p", "CANDIDATE: user ids leak", kind="fact", endpoint="GET /api/users/{id}", vuln_class="idor")
    # 1. the candidate first
    m = missions.next(b, scope)
    got = (m["kind"], m["ref"], m["vuln_class"], m["skill"], m["turns"])
    assert got == ("prove", f"fact:{fid}", "idor", "idor", 25)
    _given(b, m)
    # 2. then the untested pairs, in value order (no Graph.score here: the program's skills, then the match)
    seen = []
    while (m := missions.next(b, scope))["kind"] == "test" and m["pass"] == 1:
        assert m["turns"] == 40 and m["skill"] and m["surface"].startswith(ORIGIN)
        seen.append((m["surface"].split(" ", 1)[1], m["vuln_class"]))
        rid = _given(b, m)
        _cover(b, seen[-1][0], seen[-1][1], "clean", rid)
    assert m["kind"] == "free"  # the 5th draw is a free hunt
    _given(b, m)
    assert seen[0] == ("GET /api/users/{id}", "idor")
    assert len(seen) == len(set(seen)) == 3
    rest = []
    while (m := missions.next(b, scope))["kind"] == "test" and m["pass"] == 1:
        rest.append((m["surface"].split(" ", 1)[1], m["vuln_class"]))
        rid = _given(b, m)
        _cover(b, rest[-1][0], rest[-1][1], "clean", rid)
        if len(missions.history(b, "p")) % 5 == 4:
            _given(b, missions.next(b, scope))  # the free one in five
    all_pairs = {(p["endpoint"], p["vuln_class"]) for p in missions.pairs(b, scope)}
    assert set(seen) | set(rest) == all_pairs
    # 3. a second pass on a valuable pair settled once, with another skill than the first
    assert m["kind"] == "test" and m["pass"] == 2 and m["ref"].startswith("pair2:")
    assert m["skill"] != missions.skill_used(missions.history(b, "p"), {"endpoint": m["surface"].split(" ", 1)[1],
                                                                       "vuln_class": m["vuln_class"]})  # fmt: skip
    if m["vuln_class"] == "idor":
        assert m["skill"] == "multi-tenant"


def test_chain_after_two_findings_the_judge_did_not_reject(tmp_path, monkeypatch):
    b, scope = _board(tmp_path, monkeypatch), _scope()
    _given(b, missions.make("map", ref="map:0"))
    _given(b, missions.make("map", ref="map:1"))
    a = b.add_finding("p", "A")
    b.set_finding(a, "verified")
    r = b.add_finding("p", "R")
    b.set_finding(r, "rejected")
    assert missions.chain_pairs(b, "p") == []
    i = b.add_finding("p", "I")
    b.set_finding(i, "inconclusive")
    assert missions.chain_pairs(b, "p") == [(a, i)]
    Graph(b, scope).endpoint(ORIGIN, "GET /about", "tool", [])  # mapped, nothing a class calls for
    b.db.commit()
    m = missions.next(b, scope)
    assert (m["kind"], m["surface"], m["skill"], m["turns"]) == ("chain", f"F{a}+F{i}", "chaining", 30)
    _given(b, m)
    assert missions.next(b, scope)["kind"] == "free"  # one chain per pair


def test_free_hunt_one_draw_in_five(tmp_path, monkeypatch):
    b, scope = _board(tmp_path, monkeypatch), _scope()
    _surface(b, scope)
    kinds = []
    for _ in range(10):
        m = missions.next(b, scope)
        kinds.append(m["kind"])
        _given(b, m)
    assert kinds[4] == kinds[9] == "free" and kinds[:4] == ["test"] * 4


def test_same_board_same_draw(tmp_path, monkeypatch):
    b, scope = _board(tmp_path, monkeypatch), _scope()
    _surface(b, scope)
    first = missions.next(b, scope, now=1.0)
    assert all(missions.next(b, scope, now=1.0) == first for _ in range(3))
    other = Board(tmp_path / "var" / "copy.sqlite")
    _surface(other, scope)
    assert missions.next(other, scope, now=1.0) == first


def test_value_order_uses_the_graph_score_when_there_is_one(tmp_path, monkeypatch):
    b, scope = _board(tmp_path, monkeypatch), _scope()
    _surface(b, scope)
    redirect = b.rows("SELECT id FROM assets WHERE key=?", f"{ORIGIN} GET /redirect")[0]["id"]
    monkeypatch.setattr(Graph, "score", lambda self, aid: 9.0 if aid == redirect else 1.0, raising=False)
    assert missions.next(b, scope)["surface"] == f"{ORIGIN} GET /redirect"


def test_a_class_the_program_excludes_is_never_a_mission(tmp_path, monkeypatch):
    b, scope = _board(tmp_path, monkeypatch), _scope(forbidden_vulns=["IDOR"])
    _surface(b, scope)
    assert "idor" not in {p["vuln_class"] for p in missions.pairs(b, scope)}


def test_a_tested_pair_is_not_drawn_again(tmp_path, monkeypatch):
    b, scope = _board(tmp_path, monkeypatch), _scope()
    _surface(b, scope)
    _cover(b, "GET /api/users/{id}", "idor", "suspect", b.run_start("p", "m"))
    assert missions.next(b, scope)["ref"] != "pair:GET /api/users/{id}|idor"


# ------------------------------------------------------------------ T17: the mission's task
def test_mission_task_names_objective_skill_budget_and_never_how_to_finish():
    m = missions.make("test", surface=f"{ORIGIN} GET /api/users/{{id}}", vuln_class="idor", skill="idor", ref="x")
    task = build_task("BOARD", first=False, max_turns=m["turns"], mission=m)
    block = task.split("# Mission (set by the host)\n", 1)[1].split("\n\n# Board", 1)[0]
    assert "Objective: test `idor` on `GET https://app.t.test:443/api/users/{id}`." in block
    assert "Skill: load `idor` with the Skill tool" in block and "Budget: 40 turns for this mission." in block
    for kind in missions.KINDS:
        mm = missions.make(kind, surface="F1+F2" if kind == "chain" else "GET /x", vuln_class="xss", skill="xss")
        b = build_task("B", first=False, max_turns=mm["turns"], mission=mm).split("# Board")[0]
        assert not FINISHING.search(b.lower().replace("dead ends", "").replace("finish mapping", "")), (kind, b)
    assert task.index("# Mission") < task.index("# Board")


def test_without_a_mission_the_task_is_unchanged():
    for kw in ({}, {"first": True}, {"rotated": True, "lineage": "L"}):
        base = {"first": False, **kw}
        assert build_task("B", max_turns=60, **base) == build_task("B", max_turns=60, mission=None, **base)
    task = build_task("B", first=False, max_turns=60)
    assert "Mission" not in task and MAIL_LINE not in task
    assert "then take the next most promising lead (open intents first" in task


def test_setup_records_bh_missions_and_the_cost_cap():
    scope = _scope()
    common = dict(model="m", effort=None, verifier_model="v", max_turns=60, minutes=30, system_prompt="s",
                  task_template="t", cards=[], max_runs_per_day=33, runs_per_session=11, sessions_per_day=3,
                  fill_segment=1, fill_day=1, prompt_quantum=10, prompt_floor=6, mcp={})  # fmt: skip
    sha0, doc0 = identity.setup(scope, **common)
    assert doc0["BH_MISSIONS"] == "0" and doc0["cost_cap_usd"] is None
    sha1, doc1 = identity.setup(scope, **common, missions="1")
    sha2, _ = identity.setup(scope, **common, cost_cap_usd=5.0)
    assert len({sha0, sha1, sha2}) == 3 and doc1["BH_MISSIONS"] == "1"


def test_the_mission_enters_the_birth_record(monkeypatch):
    born = {}

    def birth(board, scope, run_id, *, setup_sha256, parent_no=None, mission=None):
        born.update(mission=mission, parent=parent_no)
        return {"no": 7 + len(born.get("all", [])), "pseudo": "x"}

    for name, mod in {
        "bh.lineage": types.ModuleType("bh.lineage"),
        "bh.lineage.identity": types.SimpleNamespace(birth=birth, close=lambda *a: None),
    }.items():
        monkeypatch.setitem(sys.modules, name, mod)
    for name in ("store", "recall", "score", "archive", "chain", "serve", "block"):
        monkeypatch.setitem(sys.modules, f"bh.lineage.{name}", None)
    monkeypatch.setattr(lineage_hooks, "say", lambda line: None)
    m = missions.dumps(missions.make("test", surface="GET /x", vuln_class="xss", skill="xss"))
    agent = lineage_hooks.start(None, _scope(), 1, "sha", mission=m)
    assert born["mission"] == m and agent["mission"] == m
    lineage_hooks.rotate(None, _scope(), agent, 1)
    assert born["mission"] == m  # the agent born on a rotation keeps the segment's mission
    lineage_hooks._reset()


# ------------------------------------------------------------------ T17: the host's extension
def test_extension_on_a_recent_anchored_fact_or_a_new_gate_test(tmp_path, monkeypatch):
    b, scope = _board(tmp_path, monkeypatch), _scope()
    m = missions.make("test", surface=f"{ORIGIN} GET /api/users/{{id}}", vuln_class="idor", skill="idor")
    rid = b.run_start("p", "m")
    assert not missions.extension_due(b, "p", m, rid, 0, logged=set())
    assert missions.extension_due(b, "p", m, rid, 1, logged=set())
    assert missions.extension_due(b, "p", m, rid, 0, logged={"GET /api/users/{id}"})
    assert not missions.extension_due(b, "p", m, rid, 0, logged={"GET /other"})  # another surface
    Graph(b, scope).tested(ORIGIN, "GET /api/users/{id}", "gate", rid - 1 if rid > 1 else 0)
    b.db.commit()
    assert not missions.extension_due(b, "p", m, rid, 0, logged={"GET /api/users/{id}"})  # not new
    assert not missions.extension_due(b, "p", {"turns": 80}, rid, 1, logged=set())  # the ceiling


def test_extend_mission_counts_anchored_facts_of_the_last_turns_only(tmp_path, monkeypatch):
    b, scope = _board(tmp_path, monkeypatch), _scope()
    rid = b.run_start("p", "m")
    notes = tmp_path / "notes.jsonl"
    notes.write_text(
        json.dumps({"ts": 100.0, "op": "fact", "title": "old"}) + "\n"
        + json.dumps({"ts": 200.0, "op": "fact", "title": "new"}) + "\n"
    )  # fmt: skip
    monkeypatch.setattr(run, "rotate_notes", lambda prog, run_id, leg=None: notes)
    grounded = {"new"}

    def fake_notes(board, prog, run_id, path, scope=None):
        n = 0
        for rec in c.read_jsonl(path):
            board.add_fact(prog, rec["title"], run_id=run_id, grounded=rec["title"] in grounded)
            n += 1
        return n, 0, 0

    monkeypatch.setattr(run.ingest, "notes", fake_notes)
    monkeypatch.setattr(missions, "gate_new_test", lambda *a, **k: False)
    res = SegmentResult(program="p", run_id=rid)
    res.turn_log = [{"ts": float(t)} for t in range(100, 220, 10)]  # the last 10 turns start at 130
    m = missions.make("test", surface="GET /x", vuln_class="xss", skill="xss")
    assert run.extend_mission(b, scope, res, m, None) == 20 and res.new_facts == 2
    grounded.clear()
    grounded.add("old")  # an anchored fact older than the last ten turns: no extension
    res2 = SegmentResult(program="p", run_id=rid)
    res2.turn_log = res.turn_log
    assert run.extend_mission(b, scope, res2, m, None) == 0


def test_a_mission_session_is_nudged_back_to_its_objective():
    assert run.continue_prompt(None) == run.CONTINUE_PROMPT == run.continue_prompt(missions.make("free"))
    text = run.continue_prompt(missions.make("prove"))
    assert "mission's objective" in text and "program card" not in text
    assert not FINISHING.search(text.lower())


def test_decisions_mission_and_extension_are_known():
    for what in ("mission", "extension"):
        assert run.decision_event(what, 3, now=1.0) == {"type": "bh_decision", "what": what, "run_id": 3, "ts": 1.0}


# ------------------------------------------------------------------ T29: chains
def test_chain_intent_once_per_pair_names_the_skill(tmp_path, monkeypatch):
    b = _board(tmp_path, monkeypatch)
    ids = []
    for status in ("verified", "verified-evidence", "rejected", "inconclusive"):
        ids.append(b.add_finding("p", status))
        b.set_finding(ids[-1], status)
    assert run.chain_intents(b, "p") and run.chain_intents(b, "p") == []
    titles = [r["title"] for r in b.rows("SELECT title FROM intents WHERE program='p' ORDER BY id")]
    f = [ids[0], ids[1], ids[3]]
    assert titles == [missions.chain_title(x, y) for x, y in ((f[0], f[1]), (f[0], f[2]), (f[1], f[2]))]
    assert all("skill chaining" in t and "own proof.json" in t for t in titles)
    rows = b.rows("SELECT run_id, kind, basis, status FROM intents")
    assert {(r["run_id"], r["kind"], r["status"]) for r in rows} == {(None, "test", "open")}
    b.db.execute("UPDATE intents SET status='closed'")
    b.db.commit()
    assert run.chain_intents(b, "p") == []  # closed since: still once per pair


def test_chaining_skill_says_the_chain_has_its_own_proof():
    from bh import classes

    text = " ".join(classes.skill_text("chaining").split())
    assert "chain F<a>+F<b>" in text and "the chain's own file" in text and "One proof.json for the chain" in text


def test_after_verification_runs_the_other_lots_steps(tmp_path, monkeypatch):
    b = _board(tmp_path, monkeypatch)
    a, n = b.add_finding("p", "A"), b.add_finding("p", "N")
    before = {a: "new", n: "new"}
    b.set_finding(a, "verified")
    calls = []
    derive = types.SimpleNamespace(derive=lambda bd, f: calls.append(("d", f)))
    monkeypatch.setitem(sys.modules, "bh.techniques", derive)
    monkeypatch.setattr(run.importlib.import_module("bh.stats"), "poc_shot", lambda p, f: calls.append(("s", f)),
                        raising=False)  # fmt: skip
    browser = _scope(support=[{"value": "challenges.cloudflare.com", "kind": "passthrough"}])
    assert run.after_verification(b, browser, before, print) == [a]
    assert calls == [("d", a), ("s", a)]
    calls.clear()
    b.set_finding(n, "verified-evidence")
    assert run.after_verification(b, _scope(), {a: "verified", n: "new"}, print) == [n]
    assert calls == [("d", n)]  # no persistent browser: no screenshot


# ------------------------------------------------------------------ T21: parking
def _hunt(tmp_path, monkeypatch, script, **scope_kw):
    """hunt() over programs whose fake segments write in the board: script[name] = list of 'barren' / 'fact' /
    'endpoint'."""
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    clock = {"t": 1_000_000.0}
    calls: list[str] = []

    def fake_run(scope_file, **kw):
        name, board = scope_file.stem, kw["board"]
        calls.append(name)
        clock["t"] += 600
        rid = board.run_start(name, "m")
        step = script[name].pop(0) if script[name] else "barren"
        scope = scope_from_dict({"program": name, "platform": "local", "in_scope": [f"{name}.test"]})
        if step == "fact":
            board.add_fact(name, "anchored", run_id=rid, grounded=True)
        elif step == "endpoint":
            Graph(board, scope).tested(f"https://{name}.test:443", f"GET /e{len(calls)}", "gate", rid)
        board.run_end(rid, status="ok", cost_usd=1.0)
        board.db.commit()
        return SegmentResult(program=name, run_id=rid, status="ok", progress=1)

    monkeypatch.setattr(supervisor, "run_segment", fake_run)
    monkeypatch.setattr(supervisor.time, "time", lambda: clock["t"])
    monkeypatch.setattr(supervisor.time, "sleep", lambda s: clock.__setitem__("t", clock["t"] + s))
    load = supervisor.load_scope
    monkeypatch.setattr(supervisor, "load_scope", lambda f: _With(load(f), **scope_kw))  # lot A parses the cap
    files = []
    for n in script:
        p = tmp_path / f"{n}.yaml"
        p.write_text(f"program: {n}\nplatform: local\nin_scope: [{n}.test]\n")
        files.append(p)
    return calls, files, clock


def test_three_barren_segments_in_a_row_park_the_program(tmp_path, monkeypatch, capsys):
    calls, files, _ = _hunt(tmp_path, monkeypatch, {"a": ["barren", "barren", "fact", "barren", "endpoint"],
                                                    "b": ["fact", "barren", "barren", "barren"]})  # fmt: skip
    supervisor.hunt(files, hours=3, minutes=10, model="m", max_turns=5, runs=10)
    out = capsys.readouterr().out
    assert calls.count("b") == 4 and "b: parked until the end of the hunt (3 segments in a row" in out
    assert "a: parked" not in out  # the anchored fact and the new endpoint each start the count again
    log = paths.run_log(max(r["id"] for r in Board().rows("SELECT id FROM runs WHERE program='b'")), "b")
    assert json.loads(log.read_text().splitlines()[-1])["what"] == "park"


def test_barren_reads_the_tables_not_the_notes(tmp_path, monkeypatch):
    b = _board(tmp_path, monkeypatch)
    scope = _scope()
    r1 = b.run_start("p", "m")
    assert not supervisor.barren(b, "p", r1)  # not closed yet: nothing known
    b.run_end(r1, status="ok")
    Graph(b, scope).tested(ORIGIN, "GET /a", "gate", r1)
    b.add_fact("p", "a note, not anchored", run_id=r1)
    b.db.commit()
    assert not supervisor.barren(b, "p", r1)  # a new endpoint the gate saw
    r2 = b.run_start("p", "m")
    b.run_end(r2, status="ok")
    Graph(b, scope).tested(ORIGIN, "GET /a", "gate", r2)
    for i in range(20):
        b.add_fact("p", f"note {i}", run_id=r2)
    b.db.commit()
    assert supervisor.barren(b, "p", r2)  # the same endpoint again, twenty notes: nothing new
    b.add_fact("p", "anchored", run_id=r2, grounded=True)
    assert not supervisor.barren(b, "p", r2)
    assert not supervisor.barren(b, "p", 999)  # a run the board does not hold is not read as barren


# ------------------------------------------------------------------ T50: the cost cap
def test_cost_cap_pauses_the_program_and_says_so(tmp_path, monkeypatch, capsys):
    calls, files, _ = _hunt(tmp_path, monkeypatch, {"a": ["fact"] * 9}, cost_cap_usd=2.5)
    supervisor.hunt(files, hours=3, minutes=10, model="m", max_turns=5, runs=9)
    out = capsys.readouterr().out
    assert calls == ["a", "a", "a"]  # $1 a run: the third reaches $3 >= $2.50, nothing starts after it
    assert "a: cost cap reached ($3.00 of $2.50" in out and "every program is parked or paused" in out
    b = Board()
    last = max(r["id"] for r in b.rows("SELECT id FROM runs WHERE program='a'"))
    ev = json.loads(paths.run_log(last, "a").read_text().splitlines()[-1])
    assert ev["type"] == "bh_decision" and ev["what"] == "pause" and ev["run_id"] == last
    assert b.rows("SELECT COUNT(*) n FROM facts WHERE program='a'")[0]["n"] == 3  # nothing lost
    assert not run.parked("a")  # paused, not parked


def test_cost_counts_the_judge_and_refuses_a_lone_run(tmp_path, monkeypatch):
    b = _board(tmp_path, monkeypatch)
    scope = _With(_scope(), cost_cap_usd=1.0)
    rid = b.run_start("p", "m")
    b.run_end(rid, status="ok", cost_usd=0.6)
    assert supervisor.cost_capped(b, scope) is None
    b.run_set(rid, verify_cost=0.4)
    assert "cost cap reached ($1.00 of $1.00" in supervisor.cost_capped(b, scope)
    assert supervisor.cost_cap(_scope()) is None and supervisor.cost_cap(_With(_scope(), cost_cap_usd=0)) is None
    f = tmp_path / "p.yaml"
    f.write_text("program: p\nplatform: local\nin_scope: [app.t.test]\n")
    monkeypatch.setattr(run, "load_scope", lambda _f: scope)
    with pytest.raises(run.ProgramNotReady, match="cost cap reached"):
        run.run_segment(f, board=b)


# ------------------------------------------------------------------ T34: the progress review
def _post(d, cmd="ls", tool="Bash"):
    ev = {"tool_name": tool, "tool_use_id": "t", "tool_input": {"command": cmd}, "tool_response": {"stdout": "ok"}}
    out = hooks.post_tool_use(ev)
    return (out or {}).get("hookSpecificOutput", {}).get("updatedToolOutput", {}).get("stdout", "")


def test_review_after_fifteen_calls_without_a_note_once_per_slice(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_DIR", str(tmp_path))
    monkeypatch.delenv("BH_ROLE", raising=False)
    said = [i for i in range(1, 46) if hooks.REVIEW_MARK in _post(tmp_path)]
    assert said == [15, 30, 45]
    c.append_jsonl(tmp_path / c.NOTES, {"op": "fact", "title": "x"})
    outs = [_post(tmp_path) for _ in range(16)]
    assert [i for i, o in enumerate(outs) if hooks.REVIEW_MARK in o] == [15]  # 15 calls after the note's own


def test_review_text_six_questions_recall_frontier_and_nothing_about_finishing(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_DIR", str(tmp_path))
    text = next(o for o in (_post(tmp_path) for _ in range(15)) if o)
    review = text.split(hooks.REVIEW_MARK, 1)[1]
    assert len(re.findall(r"^\d\. ", review, re.M)) == 6 and "`bh-recall`" in review and "`bh-note frontier`" in review
    for q in ("learned", "closed", "prove", "surface", "write down"):
        assert q in review
    assert not FINISHING.search(hooks.REVIEW_TEXT.lower())


def test_review_counts_mcp_calls_and_says_it_on_the_next_bash(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_DIR", str(tmp_path))
    for _ in range(15):
        assert hooks.post_tool_use({"tool_name": "mcp__bh__q", "tool_response": {"x": 1}}) is None
    assert hooks.REVIEW_MARK in _post(tmp_path)


def test_no_review_for_the_verifier_and_a_new_leg_starts_over(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_DIR", str(tmp_path))
    monkeypatch.setenv("BH_ROLE", "verifier")
    assert not any(hooks.REVIEW_MARK in _post(tmp_path) for _ in range(30))
    monkeypatch.delenv("BH_ROLE")
    for _ in range(14):
        _post(tmp_path)
    (tmp_path / hooks.BUDGET).write_text(json.dumps({"max_turns": 1000, "used": 0, "ts": 5.0}))
    assert hooks.REVIEW_MARK not in _post(tmp_path)  # a new leg: the count starts again


# ------------------------------------------------------------------ lines owed to the other lots
def test_lot_a_oob_host_line_and_no_oob_blocker():
    scope = _With(_scope(), oob=("oob.bh.example",))
    block = scope_block(scope)
    line = "a callback to `https://oob.bh.example/c/<canary>` is observed by the host; one request, nothing else"
    assert f"{line} in the URL" in block
    assert "oob-needed" not in build_system_prompt(scope)
    plain = build_system_prompt(_scope())
    assert "oob-needed" in plain and "callback to" not in plain
    assert "callback to" not in scope_block(scope, verifier=True)


def test_lot_c_cvss_and_proof_level(monkeypatch):
    from bh.runner.prompt import VERIFIER_DOCTRINE, doctrine

    monkeypatch.setitem(sys.modules, "bh.agent.recall", types.ModuleType("bh.agent.recall"))
    assert '--proof-level <level> --cvss "<CVSS:3.1 vector>"' in doctrine(True)
    assert "never raise" not in VERIFIER_DOCTRINE.lower()  # the judge's lines: test_w3_doctrine bounds it (lot C's)
    p = build_verifier_prompt(_scope(), {"id": 1, "proof": "{}", "cvss": "CVSS:3.1/AV:N", "proof_level": "L2"}, {}, "")
    assert "cvss: CVSS:3.1/AV:N" in p and "proof_level: L2" in p
    assert "cvss:" not in build_verifier_prompt(_scope(), {"id": 1, "proof": "{}"}, {}, "")


def test_lot_h_mail_server_and_its_line(monkeypatch):
    events = []

    class MailServer:
        def __init__(self, program, run_id, scope):
            events.append(("init", program, run_id))

        def start(self):
            events.append("start")

        def stop(self):
            events.append("stop")

    monkeypatch.setitem(sys.modules, "bh.mailserve", types.SimpleNamespace(MailServer=MailServer))
    assert run.start_mail(_scope(), 4, print) is None and events == []  # no mail_from: nothing starts
    server = run.start_mail(_With(_scope(), mail_from=("noreply@t.test",)), 4, print)
    run.stop_mail(server)
    assert events == [("init", "p", 4), "start", "stop"]
    assert MAIL_LINE in build_task("B", first=False, mail=True)
    assert MAIL_LINE == "`bh-mail <identity>` reads the mail your test identities received during this segment."


def test_lot_b_canary_variable_and_baseline_copy(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    cmd = run.agent_command(_scope(), "t", run_id=1, model="m", max_turns=5, effort=None, session=None,
                            identities=[], canary_at=12.5)  # fmt: skip
    assert "BH_CANARY_AT=12.500" in cmd
    assert not any(x.startswith("BH_CANARY_AT=") for x in run.agent_command(
        _scope(), "t", run_id=1, model="m", max_turns=5, effort=None, session=None, identities=[]))  # fmt: skip
    assert run.save_baseline("p") is None
    src = paths.work_bh("p") / run.BASELINE_FILE
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text('{"x": 1}')
    dst = run.save_baseline("p")
    assert dst == paths.state() / "baseline" / "p.json" and dst.read_text() == '{"x": 1}'
    src.unlink()
    src.symlink_to(tmp_path / "elsewhere")
    (tmp_path / "elsewhere").write_text("secret")
    assert run.save_baseline("p") is None  # a link is never followed
    monkeypatch.setitem(sys.modules, "bh.gate.canary", types.SimpleNamespace(planted_at=lambda prog: 42))
    assert run.planted_canary_at("p") == 42.0
