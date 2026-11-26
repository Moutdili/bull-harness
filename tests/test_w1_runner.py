"""Wave W1, lot F (runner): gate preflight (T4), no automatic replay (T9), hashed run identity (T10), early stops
(T11), phases / sessions / caps (D25), friction (D35), prompt budget (R44), `bh browser up` reload (R36), budget.json
(T7). No podman, no socket: every container call is replaced."""

from __future__ import annotations

import ast
import inspect
import json
import time
from pathlib import Path

import pytest

from bh import paths
from bh.board import Board
from bh.runner import identity, ingest, preflight, run, supervisor
from bh.scope import scope_from_dict

NOW = 1_795_000_000.0  # a fixed clock: 2026-11-18 (local date computed by the code under test)


def _lines(profile: str, checks: list[tuple[str, bool]], summary: dict | None = None) -> str:
    out = [
        json.dumps({"check": n, "profile": profile, "want": "blocked", "got": "blocked" if ok else "allowed", "ok": ok})
        for n, ok in checks
    ]
    fails = sum(1 for _, ok in checks if not ok)
    if summary is not False:
        out.append(json.dumps(summary or {"summary": True, "checks": len(checks), "fails": fails}))
    return "\n".join(out) + "\n"


LAB_OK = [
    ("refuse:out-of-scope-ip", True),
    ("positive:in-scope-target-answers", True),
    ("positive:relay-refuses-without-run", True),
    ("witness:in-scope-request-passes", True),
]
MSRC_OK = [("refuse:sso-post", True), ("refuse:passthrough-agent", True)]


def _scope(platform: str = "local", passthrough: bool = False, **extra):
    doc = {"program": f"p-{platform}", "platform": platform, "in_scope": ["a.test"], **extra}
    if platform != "local":
        doc.setdefault("automation_allowed", True)
        doc.setdefault("scanners_allowed", True)
    if passthrough:
        doc["support"] = [{"value": "challenges.example", "kind": "passthrough"}]
    return scope_from_dict(doc)


# ------------------------------------------------------------------ T4 preflight
@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    paths.state().mkdir(parents=True, exist_ok=True)
    return tmp_path


def _pre(scope, outputs: dict[str, str], *, up=True, **kw):
    seen: list = []

    def ex(profile):
        seen.append(("exec", profile, paths.active_run().exists()))
        return outputs[profile]

    res = preflight.run(
        scope,
        exec_suite=ex,
        activate=lambda f: seen.append(("activate", Path(f).name)),
        lab_up=lambda: up,
        settle=lambda: None,
        **kw,
    )
    return res, seen


def test_preflight_lab_passes_and_runs_before_any_active_run(home):
    paths.active_run().write_text('{"run_id": 3}')  # a leftover: the relay check needs no run in progress
    res, seen = _pre(_scope(), {"lab": _lines("lab", LAB_OK)})
    assert res["ok"] and res["profiles"]["lab"]["checks"] == 4
    assert seen == [("activate", "juiceshop.yaml"), ("exec", "lab", False)]  # lab scope, no active-run.json


@pytest.mark.parametrize(
    "out, why",
    [
        ("PASS something\n" + _lines("lab", LAB_OK), "not a JSON object"),
        (_lines("lab", [*LAB_OK[:3], ("witness:in-scope-request-passes", False)]), "failed"),
        (_lines("lab", LAB_OK, summary=False), "no summary"),
        (_lines("lab", LAB_OK, summary={"summary": True, "checks": 9, "fails": 0}), "summary says"),
        (_lines("lab", LAB_OK[:3]), "missing: witness:in-scope-request-passes"),
        (_lines("lab", [LAB_OK[0], LAB_OK[3]]), "missing: positive:in-scope-target-answers"),
        (_lines("msrc", LAB_OK), "profile 'msrc'"),
        ("", "no summary"),
    ],
)
def test_preflight_lab_failures_cancel(home, out, why):
    res, _ = _pre(_scope(), {"lab": out})
    assert not res["ok"] and why in res["error"]
    with pytest.raises(preflight.PreflightFailed, match="hunt cancelled"):
        preflight.require(
            _scope(), exec_suite=lambda p: out, activate=lambda f: None, lab_up=lambda: True, settle=lambda: None
        )


def test_preflight_msrc_profile_only_with_a_passthrough_host_and_without_positives(home, tmp_path):
    real = _scope("yeswehack", passthrough=True)
    res, seen = _pre(
        real, {"lab": _lines("lab", LAB_OK), "msrc": _lines("msrc", MSRC_OK)}, scope_file=tmp_path / "m.yaml"
    )
    assert res["ok"] and set(res["profiles"]) == {"lab", "msrc"}
    assert [s for s in seen if s[0] == "activate"] == [("activate", "juiceshop.yaml"), ("activate", "m.yaml")]
    res, seen = _pre(_scope("yeswehack"), {"lab": _lines("lab", LAB_OK)})
    assert res["ok"] and set(res["profiles"]) == {"lab"}
    bad = {"lab": _lines("lab", LAB_OK), "msrc": _lines("msrc", [("refuse:sso-post", False)])}
    res, _ = _pre(real, bad, scope_file=tmp_path / "m.yaml")
    assert not res["ok"] and res["error"].startswith("profile msrc")


def test_preflight_refuses_when_the_lab_is_down(home):
    res, seen = _pre(_scope("yeswehack"), {}, up=False)
    assert not res["ok"] and seen == []
    assert "prerequisite of every hunt, a real one included" in res["error"]


def test_preflight_env_is_read_for_local_programs_only(capsys):
    said: list[str] = []
    assert preflight.enabled(_scope(), env={"BH_PREFLIGHT": "0"}) is False
    assert preflight.enabled(_scope("yeswehack"), env={"BH_PREFLIGHT": "0"}, say=said.append) is True
    assert said and "ignored" in said[0]
    assert preflight.enabled(_scope(), env={}) is True
    assert identity.preflight_setting(_scope("yeswehack"), {"BH_PREFLIGHT": "0"}) == "1"


def test_run_segment_preflights_under_the_lock_before_the_segment(home, monkeypatch, tmp_path):
    order: list[str] = []
    f = tmp_path / "lab.yaml"
    f.write_text("program: lab\nplatform: local\nin_scope: [a.test]\n")
    monkeypatch.setattr(run.stack, "container_running", lambda n: True)
    monkeypatch.setattr(preflight, "require", lambda scope, **kw: order.append("preflight") or {"ok": True})
    monkeypatch.setattr(run, "_run_locked", lambda *a, **kw: order.append(("seg", kw["preflight"])) or "res")
    monkeypatch.delenv("BH_PREFLIGHT", raising=False)
    assert run.run_segment(f, board=Board(tmp_path / "b.sqlite"), quiet=True) == "res"
    assert order == ["preflight", ("seg", {"ok": True})]
    order.clear()
    run.run_segment(f, board=Board(tmp_path / "b.sqlite"), quiet=True, preflight={"ok": True, "cached": 1})
    assert order == [("seg", {"ok": True, "cached": 1})]  # a hunt's later segments reuse its result

    def failed(scope, **kw):
        raise preflight.PreflightFailed("preflight failed, hunt cancelled: x")

    monkeypatch.setattr(preflight, "require", failed)
    order.clear()
    with pytest.raises(SystemExit, match="hunt cancelled"):
        run.run_segment(f, board=Board(tmp_path / "b.sqlite"), quiet=True)
    assert order == []  # no segment after a failed preflight


# ------------------------------------------------------------------ T9 no automatic replay
def _journal(flows=(), events=()):
    paths.state().mkdir(parents=True, exist_ok=True)
    paths.flows_log().write_text("".join(json.dumps(f) + "\n" for f in flows))
    paths.events_log().write_text("".join(json.dumps(e) + "\n" for e in events))


def test_left_the_sandbox_reads_the_gate_journal(home):
    _journal(
        flows=[
            {"run": 7, "ts": NOW + 1, "method": "GET", "class": "target"},
            {"run": 7, "ts": NOW + 2, "method": "POST", "class": "enroll"},  # the host's login, not the run's
            {"run": 8, "ts": NOW + 3, "method": "DELETE", "class": "target"},
            {"run": 7, "ts": NOW - 5, "method": "PUT", "class": "target"},  # before `since`
        ],
        events=[{"run": 7, "ts": NOW + 4, "kind": "ws-message", "from": "server"}],
    )
    assert run.left_the_sandbox(7, NOW) is False
    for flows, events in (
        ([{"run": 7, "ts": NOW + 1, "method": "POST", "class": "target"}], []),
        ([{"run": 7, "ts": NOW + 1, "method": "patch", "class": "support"}], []),
        ([], [{"run": 7, "ts": NOW + 1, "kind": "ws-message", "from": "client"}]),
        ([], [{"run": 7, "ts": NOW + 1, "kind": "fill"}]),
        ([], [{"run": 7, "ts": NOW + 1, "kind": "bh-web", "op": "fill"}]),
    ):
        _journal(flows, events)
        assert run.left_the_sandbox(7, NOW) is True


def test_an_automatic_resume_after_effects_starts_from_the_board(home, tmp_path):
    b = Board(tmp_path / "b.sqlite")
    rid = b.run_start("p", "m")
    b.run_set(rid, session_id="sess-1")
    started = b.rows("SELECT started FROM runs WHERE id=?", rid)[0]["started"]
    _journal([{"run": rid, "ts": started + 1, "method": "GET", "class": "target"}])
    assert run.resumable(b, "p") == "sess-1"
    _journal([{"run": rid, "ts": started + 1, "method": "POST", "class": "target"}])
    assert run.resumable(b, "p") is None
    assert "replay" in inspect.signature(run.challenge_resume).parameters
    assert "resume" not in run.challenge_resume(b, "p", replay=False).split("[bh]")[0].replace("`bh-web state`", "")


# ------------------------------------------------------------------ T10 hashed run identity
def _setup(scope=None, **over):
    kw = dict(
        model="sonnet",
        effort=None,
        verifier_model="opus",
        max_turns=60,
        minutes=30,
        system_prompt="doctrine v1",
        task_template="task {board}",
        cards=["idor"],
        max_runs_per_day=33,
        runs_per_session=11,
        sessions_per_day=3,
        fill_segment=80,
        fill_day=45,
        prompt_quantum=10,
        prompt_floor=6,
    )
    kw.update(over)
    return identity.setup(scope or _scope("yeswehack"), **kw)


@pytest.fixture
def fixed_version(monkeypatch):
    monkeypatch.setattr(identity, "claude_version", lambda: "2.1.330")


def test_identical_segments_share_the_condensate(fixed_version):
    a, doc = _setup()
    b, _ = _setup()
    assert a == b and len(a) == 64
    assert identity.canonical(doc) == json.dumps(doc, sort_keys=True, separators=(",", ":"))
    assert doc["claude_code"] == "2.1.330" and doc["BH_PREFLIGHT"] == "1"


def test_a_card_changes_the_condensate(fixed_version, monkeypatch):
    base, _ = _setup()
    assert _setup(cards=["idor", "xss"])[0] != base
    real = identity.classes.card_text
    monkeypatch.setattr(identity.classes, "card_text", lambda n: real(n) + "\nedited")
    assert _setup()[0] != base  # same name, other text


def test_the_scope_changes_the_condensate(fixed_version):
    assert _setup(_scope("yeswehack"))[0] != _setup(_scope("yeswehack", max_rps=1))[0]


def test_the_model_changes_the_condensate(fixed_version):
    assert _setup()[0] != _setup(model="opus", verifier_model="sonnet")[0]


def test_the_budget_changes_the_condensate(fixed_version):
    base = _setup()[0]
    assert _setup(max_turns=61)[0] != base and _setup(minutes=31)[0] != base and _setup(fill_day=46)[0] != base


def test_the_doctrine_changes_the_condensate(fixed_version):
    base = _setup()[0]
    assert _setup(system_prompt="doctrine v2")[0] != base and _setup(task_template="task2 {board}")[0] != base


def test_no_secret_in_the_setup(fixed_version, home):
    from bh import redact

    secret = "S3cr3t-pa55word-xyz"
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.c2lnbmF0dXJl"
    sc = _scope(
        "yeswehack",
        identities=[
            {
                "name": "user-a",
                "role": "user",
                "tenant": "t1",
                "secret_ref": "user-a",
                "probe": {"url": "https://a.test/me", "status": 200},
            }
        ],
    )
    d = paths.identities_dir(sc.program)
    d.mkdir(parents=True)
    (d / "user-a.json").write_text(json.dumps({"cookies": {"sid": secret}, "headers": {"Authorization": jwt}}))
    _, doc = _setup(sc)
    text = identity.canonical(doc)
    assert secret not in text and jwt not in text and "Bearer" not in text
    assert not redact.JWT.search(text)

    def keys(o):
        if isinstance(o, dict):
            for k, v in o.items():
                yield k, v
                yield from keys(v)
        elif isinstance(o, list):
            for v in o:
                yield from keys(v)

    # the only key shaped like a secret's is a cap, and its value is a count
    assert {k: v for k, v in keys(doc) if redact.SENSITIVE_KEY.search(k)} == {"RUNS_PER_SESSION": 11}
    assert doc["identities"] == [{"name": "user-a", "role": "user"}]


def test_ensure_adds_the_columns_once(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    identity.ensure(b)
    identity.ensure(b)
    cols = {r["name"] for r in b.db.execute("PRAGMA table_info(runs)")}
    assert {c for c, _ in identity.COLUMNS} <= cols


# ------------------------------------------------------------------ T11 early stops
@pytest.mark.parametrize(
    "text",
    [
        "Mapped the API. Next, I will test the IDOR on /orders.",
        "Found nothing on /search. I'll now look at the upload.",
        "Proceeding to the share page.",
        "Checking the next surface...",
        "Checking the next surface…",
        "Now I will send the second prompt",
    ],
)
def test_announced_actions(text):
    assert run.announced_action(text)


@pytest.mark.parametrize(
    "text", ["", "F3 recorded with its proof. HANDOFF updated.", "I tested /orders: 403 for every other id."]
)
def test_finished_texts(text):
    assert not run.announced_action(text)


# ------------------------------------------------------------------ the segment, every container call replaced
@pytest.fixture
def seg(home, monkeypatch, tmp_path):
    board = Board(tmp_path / "var" / "board.sqlite")
    scope_file = tmp_path / "p.yaml"
    scope_file.write_text("program: p\n")
    for name in ("activate_scope", "clean_sandbox", "clean_leg", "prepare_workdir", "set_active_run"):
        monkeypatch.setattr(run, name, lambda *a, **k: None)

    def no_podman(*a, **k):
        raise AssertionError("a test reached podman")

    monkeypatch.setattr(run.stack, "agent_sh", no_podman)
    monkeypatch.setattr(run.stack.subprocess, "run", no_podman)
    monkeypatch.setattr(run.retention, "prune", lambda: None)
    monkeypatch.setattr(run.stack, "kill_agent", lambda *a, **k: None)
    monkeypatch.setattr(run, "refresh_identities", lambda *a, **k: set())
    monkeypatch.setattr(run, "pick_cards", lambda *a: [])
    monkeypatch.setattr(run, "rotate_notes", lambda *a: tmp_path / "none.jsonl")
    monkeypatch.setattr(ingest, "gate_events", lambda *a: ingest.GateOutcome())
    monkeypatch.setattr(identity, "claude_version", lambda: "2.1.330")
    st: dict = {"cmds": [], "budget": [], "legs": [], "status": [None], "prepared": []}
    monkeypatch.setattr(run, "push_budget", lambda prog, mt, used: st["budget"].append((prog, mt, used)))
    monkeypatch.setattr(run, "browser_status", lambda call=None: st["status"][0])

    def fake_leg(cmd, log, err_path, res, say, *, program, timeout_s, bh_dir=None, context_limit=None):
        err_path.touch()
        spec = st["legs"][len(st["cmds"])]
        st["cmds"].append(cmd)
        res.overflow = False
        for i in range(spec.get("tools", 3)):
            res.turn_log.append({"id": f"m{len(st['cmds'])}-{i}", "input": 10, "cache_read": 100})
            res.tool_calls += 1
            res.tool_log.append({"cmd": "bh-crawl https://a.test/"})
        res.session_id = f"s{len(st['cmds'])}"
        n = spec.get("tools", 3)
        return {"subtype": "success", "num_turns": n, "session_id": res.session_id, "result": spec["text"]}, False

    monkeypatch.setattr(run, "run_leg", fake_leg)

    def go(legs, scope=None, **kw):
        st["legs"], st["cmds"] = legs, []
        res = run._run_locked(
            scope or _scope(),
            scope_file,
            board,
            model="m",
            max_turns=60,
            minutes=60,
            resume=False,
            quiet=True,
            extra_task="",
            effort=None,
            **kw,
        )
        return res, [c[c.index("-p") + 1] for c in st["cmds"]]

    return board, go, st


def test_early_stop_is_counted_and_the_next_leg_is_told(seg):
    board, go, st = seg
    res, tasks = go([{"text": "Next, I will test /orders."}, {"text": "F1 recorded.", "tools": 1}])
    assert len(tasks) == 2 and tasks[1].startswith(run.EARLY_STOP_LINE)
    assert run.EARLY_STOP_LINE not in tasks[0]
    assert board.rows("SELECT early_stop FROM runs WHERE id=?", res.run_id)[0]["early_stop"] == 1
    assert st["budget"] == [("p-local", 60, 0), ("p-local", 60, 3)]  # T7: budget.json before every leg


def test_early_stop_on_the_last_leg_tells_the_next_segment(seg):
    board, go, _ = seg
    res, tasks = go([{"text": "I'll now check the upload...", "tools": 1}])
    assert board.rows("SELECT early_stop FROM runs WHERE id=?", res.run_id)[0]["early_stop"] == 1
    _, tasks = go([{"text": "done", "tools": 1}])
    assert run.EARLY_STOP_LINE in tasks[0]
    _, tasks = go([{"text": "done", "tools": 1}])
    assert run.EARLY_STOP_LINE not in tasks[0]  # said once


def test_the_segment_records_its_setup_and_texts(seg):
    board, go, _ = seg
    res, tasks = go([{"text": "done", "tools": 1}], phase=None, session=None, preflight={"ok": True})
    row = board.rows("SELECT * FROM runs WHERE id=?", res.run_id)[0]
    assert len(row["setup_sha256"]) == 64 and json.loads(row["setup_json"])["model"] == "m"
    assert json.loads(row["preflight"]) == {"ok": True}
    assert paths.run_text(res.run_id, "task").read_text() == tasks[0]
    assert (
        "Scope" in paths.run_text(res.run_id, "system").read_text()
        or paths.run_text(res.run_id, "system").stat().st_size
    )
    res2, _ = go([{"text": "done", "tools": 1}])
    assert board.rows("SELECT setup_sha256 FROM runs WHERE id=?", res2.run_id)[0]["setup_sha256"] == row["setup_sha256"]


def test_browser_segment_allots_prompts_and_records_quota_and_friction(seg, monkeypatch):
    board, go, st = seg
    real = _scope("yeswehack", passthrough=True)
    monkeypatch.setattr(run.browser_watch, "wanted", lambda scope: True)

    def prepare(scope, ids, say=None, *, prompts=None):
        st["prepared"].append(prompts)
        return "user-a"

    class Watcher:
        def __init__(self, **kw):
            pass

        def start(self):
            return self

        def stop(self):
            pass

    monkeypatch.setattr(run.browser_watch, "prepare", prepare)
    monkeypatch.setattr(run.browser_watch, "ChallengeWatcher", Watcher)
    quotas = {"user-a": {"sent": 5, "left": 40, "remaining_pct": 88, "spent": False, "until": NOW}}
    st["status"][0] = {"quotas": quotas, "counters": {"challenges": 1, "sessions": 1}}
    # runs_left 11 with 40 left: k = 4, not served -> 0 prompt, said in the task
    res, tasks = go([{"text": "done", "tools": 1}], scope=real, runs_left=11)
    assert st["prepared"] == [{"user-a": 0}]
    assert tasks[0].rstrip().endswith(run.NO_PROMPT_LINE)
    # runs_left 9: served, 10 prompts; at the close 3 challenges for 2 sessions, two 429 of the browser
    st["status"][0] = {"quotas": quotas, "counters": {"challenges": 1, "sessions": 1}}
    paths.flows_log().write_text("")
    res, tasks = go([{"text": "done", "tools": 1}], scope=real, runs_left=9)
    assert st["prepared"][-1] == {"user-a": 10} and run.NO_PROMPT_LINE not in tasks[0]
    row = board.rows("SELECT friction, quota FROM runs WHERE id=?", res.run_id)[0]
    assert json.loads(row["quota"]) == {
        "identity": "user-a",
        "allot": 10,
        "sent": 5,
        "remaining_pct": 88,
        "spent": False,
    }
    assert json.loads(row["friction"]) == {"challenges_extra": 0, "browser_429": 0}
    # unreadable status: no allotment (today's behaviour), NULL columns
    st["status"][0] = None
    res, tasks = go([{"text": "done", "tools": 1}], scope=real, runs_left=9)
    assert st["prepared"][-1] is None
    row = board.rows("SELECT friction, quota FROM runs WHERE id=?", res.run_id)[0]
    assert row["friction"] is None and row["quota"] is None


def test_local_program_never_gets_an_allotment():
    assert run.browser_prompts(_scope(), {"quotas": {"a": {"left": 40}}}, 3, lambda m: None) is None
    said: list[str] = []
    assert run.browser_prompts(_scope("yeswehack"), {"counters": {}}, 3, said.append) is None and said


def test_friction_from_status_and_journal(home):
    paths.flows_log().write_text(
        "".join(
            json.dumps(f) + "\n"
            for f in (
                {"run": 4, "status": 429, "client": "browser"},
                {"run": 4, "status": 503, "client": "browser"},
                {"run": 4, "status": 429, "client": "agent"},
                {"run": 5, "status": 429, "client": "browser"},
                {"run": 4, "status": 200, "client": "browser"},
            )
        )
    )
    start = {"counters": {"challenges": 2, "sessions": 2}}
    end = {"counters": {"challenges": 6, "sessions": 3}}
    assert run.friction(start, end, 4, 0) == {"challenges_extra": 3, "browser_429": 2}
    assert run.friction(start, {"counters": {"challenges": 3, "sessions": 3}}, 4, 0)["challenges_extra"] == 0
    assert run.friction(start, None, 4, 0) is None  # unreadable: NULL
    assert run.friction(None, {"counters": {"challenges": 1, "sessions": 1}}, 4, 0)["challenges_extra"] == 0


def test_quota_record_keeps_clock_mismatch():
    st = {"quotas": {"u": {"sent": 1, "left": 44, "remaining_pct": 97, "spent": False, "clock_mismatch": 3600}}}
    assert run.quota_record(st, "u", {"u": 10})["clock_mismatch"] == 3600
    assert run.quota_record(st, "v", {"u": 10}) is None
    assert run.quota_record(None, "u", None) is None


# ------------------------------------------------------------------ D25 caps
def test_caps_are_literals_in_the_module():
    tree = ast.parse(Path(inspect.getsourcefile(supervisor)).read_text())
    found = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            found[node.targets[0].id] = node.value
    want = {
        "RUNS_PER_SESSION": 11,
        "SESSIONS_PER_DAY": 3,
        "MAX_RUNS_PER_DAY": 33,
        "RUNS_PER_PHASE": 33,
        "PROMPT_QUANTUM": 10,
        "PROMPT_FLOOR": 6,
    }
    for name, value in want.items():
        assert isinstance(found[name], ast.Constant) and found[name].value == value, name
        assert (
            sum(1 for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Store))
            == 1
        )


def _row(b: Board, *, phase="sonnet", session=None, started=NOW, program="real"):
    identity.ensure(b)
    cur = b.db.execute(
        "INSERT INTO runs(program, model, started, status, phase, session) VALUES (?,?,?,?,?,?)",
        (program, "m", started, "ok", phase, session),
    )
    b.db.commit()
    return cur.lastrowid


def test_admit_refuses_the_12th_run_of_a_session(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    day = supervisor.day_of(NOW)
    sess = supervisor.open_session(b, "sonnet", NOW)
    assert sess == f"{day}-1"
    for _ in range(11):
        supervisor.admit(b, _scope("yeswehack"), phase="sonnet", session=sess, now=NOW)
        _row(b, session=sess)
    with pytest.raises(supervisor.CapReached, match="run 12 refused"):
        supervisor.admit(b, _scope("yeswehack"), phase="sonnet", session=sess, now=NOW)


def test_the_4th_session_of_a_day_is_refused(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    for _ in range(3):
        sess = supervisor.open_session(b, "sonnet", NOW)
        _row(b, session=sess)
    assert supervisor.sessions_on_day(b, supervisor.day_of(NOW))[-1].endswith("-3")
    with pytest.raises(supervisor.CapReached, match=r"session 4 .* refused"):
        supervisor.open_session(b, "sonnet", NOW + 60)
    # the next day opens again (a session's runs stay on the day it started, even past midnight)
    assert supervisor.open_session(b, "sonnet", NOW + 86400).endswith("-1")


def test_the_34th_run_of_the_day_is_refused_bh_run_included(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    for i in range(3):
        for _ in range(11 if i < 2 else 10):
            _row(b, phase="p1" if i == 0 else "p2", session=f"{supervisor.day_of(NOW)}-{i + 1}")
    lone = supervisor.admit(b, _scope("yeswehack"), phase="p2", session=None, now=NOW)  # the 33rd: a lone bh run
    assert lone == ("p2", None)
    _row(b, phase="p2", session=None)
    with pytest.raises(supervisor.CapReached, match="run 34 of the day refused"):
        supervisor.admit(b, _scope("yeswehack"), phase="p2", session=None, now=NOW)
    assert supervisor.admit(b, _scope(), phase="p2", session=None, now=NOW) == (None, None)  # the lab: no cap


def test_the_phase_stops_at_33_runs(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    for d in range(3):
        for _ in range(11):
            _row(b, phase="sonnet", session=f"{supervisor.day_of(NOW + d * 86400)}-1", started=NOW + d * 86400)
    with pytest.raises(supervisor.CapReached, match="phase sonnet: 33/33"):
        supervisor.admit(b, _scope("yeswehack"), phase="sonnet", session=None, now=NOW + 3 * 86400)
    with pytest.raises(supervisor.CapReached, match="the phase is over"):
        supervisor.open_session(b, "sonnet", NOW + 3 * 86400)


def test_a_real_program_needs_a_phase(tmp_path):
    with pytest.raises(supervisor.CapReached, match="--phase NAME"):
        supervisor.admit(Board(tmp_path / "b.sqlite"), _scope("yeswehack"), phase=None, session=None, now=NOW)
    with pytest.raises(supervisor.CapReached, match="letters, digits"):
        supervisor.admit(Board(tmp_path / "b.sqlite"), _scope("yeswehack"), phase="a b", session=None, now=NOW)


def _scope_file(tmp_path, name, platform):
    p = tmp_path / f"{name}.yaml"
    extra = "automation_allowed: true\nscanners_allowed: true\n" if platform != "local" else ""
    p.write_text(f"program: {name}\nplatform: {platform}\nin_scope: [{name}.test]\n{extra}")
    return p


@pytest.fixture
def hunt_env(home, monkeypatch):
    clock = {"t": NOW}
    calls: list[dict] = []

    def fake_run(scope_file, **kw):
        calls.append({"program": scope_file.stem, **kw})
        clock["t"] += 600
        b = Board()
        rid = b.run_start(scope_file.stem, "m")
        b.run_set(rid, phase=kw.get("phase"), session=kw.get("session"))
        return run.SegmentResult(program=scope_file.stem, run_id=rid, status="ok", progress=1, preflight={"ok": True})

    monkeypatch.setattr(supervisor, "run_segment", fake_run)
    monkeypatch.setattr(supervisor.time, "time", lambda: clock["t"])
    monkeypatch.setattr(supervisor.time, "sleep", lambda s: clock.__setitem__("t", clock["t"] + s))
    return clock, calls


def test_a_session_runs_11_then_stops(home, hunt_env, tmp_path, capsys):
    _, calls = hunt_env
    files = [_scope_file(tmp_path, "r1", "yeswehack"), _scope_file(tmp_path, "r2", "yeswehack")]
    supervisor.hunt(files, hours=24, minutes=10, model="m", max_turns=5, phase="sonnet")
    assert len(calls) == 11 and "complete: 11/11" in capsys.readouterr().out
    assert [c["program"] for c in calls[:4]] == ["r1", "r2", "r1", "r2"]  # least recently run first
    assert {c["session"] for c in calls} == {f"{supervisor.day_of(NOW)}-1"} and {c["phase"] for c in calls} == {
        "sonnet"
    }
    assert calls[0]["preflight"] is True and calls[1]["preflight"] is True and calls[2]["preflight"] == {"ok": True}
    assert calls[0]["runs_left"] == 17  # (11 + 2 x 11) / 2 programs, rounded up
    # two more sessions that day, then the 4th is refused
    for _ in range(2):
        supervisor.hunt(files, hours=24, minutes=10, model="m", max_turns=5, phase="sonnet")
    with pytest.raises(supervisor.CapReached, match="phase sonnet: 33/33"):
        supervisor.hunt(files, hours=24, minutes=10, model="m", max_turns=5, phase="sonnet")
    with pytest.raises(supervisor.CapReached, match=r"session 4 .* refused"):
        supervisor.hunt(files, hours=24, minutes=10, model="m", max_turns=5, phase="opus")
    assert len(calls) == 33


def test_runs_only_lowers_a_session(home, hunt_env, tmp_path):
    _, calls = hunt_env
    files = [_scope_file(tmp_path, "r1", "yeswehack")]
    supervisor.hunt(files, hours=24, minutes=10, model="m", max_turns=5, phase="sonnet", runs=4)
    assert len(calls) == 4
    with pytest.raises(SystemExit, match="at most 11"):
        supervisor.hunt(files, hours=24, minutes=10, model="m", max_turns=5, phase="sonnet", runs=12)


def test_a_real_hunt_without_phase_is_refused_the_lab_runs_without(home, hunt_env, tmp_path):
    _, calls = hunt_env
    with pytest.raises(SystemExit, match="--phase NAME"):
        supervisor.hunt([_scope_file(tmp_path, "r1", "yeswehack")], hours=1, minutes=10, model="m", max_turns=5)
    assert calls == []
    supervisor.hunt([_scope_file(tmp_path, "lab", "local")], hours=1, minutes=10, model="m", max_turns=5, runs=3)
    assert len(calls) == 3 and {c["phase"] for c in calls} == {None} and {c["session"] for c in calls} == {None}
    b = Board()
    assert supervisor.runs_on_day(b, supervisor.day_of(NOW)) == 0  # the lab consumed nothing
    assert supervisor.status_line(b, NOW) is None


def test_status_line(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    day = supervisor.day_of(NOW)
    for _ in range(11):
        _row(b, session=f"{day}-1")
    for _ in range(4):
        _row(b, session=f"{day}-2")
    assert supervisor.status_line(b, NOW) == "phase sonnet: 15/33 · session 2/3: 4/11"


# ------------------------------------------------------------------ R44 prompt allotment
def test_allotment_concentrates_one_identity_at_40():
    quotas = {"u": {"left": 40}}
    served = []
    for runs_left in range(11, 0, -1):
        got = supervisor.prompt_allotment(quotas, runs_left)["u"]
        if got:
            served.append(runs_left)
            quotas["u"]["left"] -= got
    assert served == [9, 6, 4, 3]


def test_allotment_edges():
    assert supervisor.prompt_allotment({"u": {"left": 40}}, 4) == {"u": 10}  # k >= runs_left: served
    assert supervisor.prompt_allotment({"u": {"left": 40}, "v": {"left": 26}}, 2) == {"u": 10, "v": 10}
    assert supervisor.prompt_allotment({"u": {"left": 5}}, 1) == {"u": 0}  # k = 0
    assert supervisor.prompt_allotment({"u": {"left": 46}, "v": {"left": 3}}, 1) == {"u": 10, "v": 0}
    assert supervisor.prompt_allotment({"u": {"left": 7}}, 1) == {"u": 7}
    assert supervisor.prompt_allotment({"u": {"left": "x"}}, 1) == {"u": 0}


def test_a_simulated_day_never_exceeds_45_per_identity():
    left = {"a": 45, "b": 45}
    sent = {"a": 0, "b": 0}
    for runs_left in range(33, 0, -1):
        got = supervisor.prompt_allotment({k: {"left": v} for k, v in left.items()}, runs_left)
        for k, v in got.items():
            sent[k] += v
            left[k] -= v
    assert all(v <= 45 for v in sent.values()) and all(v >= 0 for v in left.values())
    assert sent == {"a": 40, "b": 40}  # a remainder of 5 is under PROMPT_FLOOR: never a run of 5 prompts


def test_runs_left_counts_the_day_over_the_programs(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    day = supervisor.day_of(NOW)
    assert supervisor.runs_left(b, None, 1, NOW) == 1  # a lone bh run
    assert supervisor.runs_left(b, f"{day}-1", 1, NOW) == 33
    for _ in range(5):
        _row(b, session=f"{day}-1")
    assert supervisor.runs_left(b, f"{day}-1", 1, NOW) == 6 + 22
    assert supervisor.runs_left(b, f"{day}-1", 3, NOW) == 10  # ceil(28 / 3)


# ------------------------------------------------------------------ R36, T7
def test_browser_up_says_the_reloaded_identity(monkeypatch, capsys):
    from bh import cli
    from bh.browser_service import watch

    monkeypatch.setattr(watch, "reload_marked", lambda call=None, say=None: "user-a", raising=False)
    assert cli.browser_reload() == "user-a"
    monkeypatch.setattr(watch, "reload_marked", lambda call=None, say=None: None, raising=False)
    assert cli.browser_reload() is None
    monkeypatch.delattr(watch, "reload_marked", raising=False)
    assert cli.browser_reload() is None


def test_budget_json_is_pushed_by_stack(monkeypatch):
    pushed = []
    monkeypatch.setattr(run.stack, "push_file", lambda path, text, **kw: pushed.append((path, json.loads(text))))
    run.push_budget("p", 60, 12)
    path, doc = pushed[0]
    assert path == "/work/p/.bh/budget.json" and doc["max_turns"] == 60 and doc["used"] == 12
    assert isinstance(doc["ts"], float) and abs(doc["ts"] - time.time()) < 60


def test_cli_hunt_and_run_take_phase_and_runs():
    from bh import cli

    a = cli.build_parser().parse_args(["hunt", "x.yaml", "--phase", "sonnet", "--runs", "5", "--hours", "3"])
    assert (a.phase, a.runs, a.hours) == ("sonnet", 5, 3)
    assert cli.build_parser().parse_args(["run", "x.yaml", "--phase", "opus"]).phase == "opus"
