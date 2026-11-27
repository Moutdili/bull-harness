"""W4-E: platform outcomes (L4), cost per outcome (L3), the streak alert (L10), the checklist before a submission (L1),
the one-off PoC screenshot (D12), the program's cost in the UI (T50), `bh accounts check` (T51), the lines owed to
other lots, and `bh scope new` (D32). No podman, no network, no browser: every host call is simulated."""

import base64
import http.client
import json
import shutil
import stat
import sys
import threading
import time
import types
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from bh import stats
from bh.board import Board
from bh.browser_service import AGENT_OPS, HOST_OPS
from bh.browser_service.controller import Controller
from bh.cli import main
from bh.lineage import score
from bh.ui.server import COOKIE, Handler, new_session

REPO = Path(__file__).resolve().parents[1]
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
TOKEN = "ui-test-token"
P = "msrc-copilot"
TURNSTILE = "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/turnstile/if/ov2/av0/rcv/x"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    (tmp_path / "scopes" / "msrc").mkdir(parents=True)
    for name in ("copilot.yaml", "onedrive.yaml"):
        shutil.copy(REPO / "scopes" / "msrc" / name, tmp_path / "scopes" / "msrc" / name)
    return tmp_path


@pytest.fixture
def board(home):
    from bh.runner import identity

    b = Board()
    identity.ensure(b)  # runs.phase, runs.setup_sha256 (W2)
    yield b
    b.db.close()


def run(b, program=P, cost=1.0, verify=0.0, phase="sonnet"):
    cur = b.db.execute(
        "INSERT INTO runs(program, model, started, status, cost_usd, verify_cost, phase) VALUES (?,?,?,?,?,?,?)",
        (program, "m", time.time(), "ok", cost, verify, phase),
    )
    b.db.commit()
    return cur.lastrowid


def finding(b, rid, status="verified", program=P, cls="idor", url="https://copilot.com/api/c/1", **kw):
    fid = b.add_finding(program, "t", run_id=rid, vuln_class=cls, url=url, **kw)
    b.set_finding(fid, status)
    return fid


def row(b, fid):
    return dict(b.rows("SELECT outcome, bounty, outcome_note FROM findings WHERE id=?", fid)[0])


# ------------------------------------------------------------------ L4: the one writer
def test_set_outcome_columns_and_refusals(board):
    rid = run(board)
    fid = finding(board, rid)
    stats.ensure(board)
    stats.ensure(board)  # idempotent
    cols = {r["name"] for r in board.db.execute("PRAGMA table_info(findings)")}
    assert {"outcome", "bounty", "outcome_ts", "outcome_note"} <= cols
    out = stats.set_outcome(board, fid, "paid", bounty=300, note="triaged fast")
    assert out["outcome"] == "paid" and out["bounty"] == 300.0
    assert row(board, fid) == {"outcome": "paid", "bounty": 300.0, "outcome_note": "triaged fast"}
    with pytest.raises(ValueError):
        stats.set_outcome(board, fid, "rewarded")
    with pytest.raises(ValueError, match="bounty"):
        stats.set_outcome(board, fid, "informative", bounty=50)
    for bad in (-1, float("nan"), "lots", True):
        with pytest.raises(ValueError):
            stats.set_outcome(board, fid, "paid", bounty=bad)
    with pytest.raises(ValueError):
        stats.set_outcome(board, fid, "paid", note="x" * (stats.NOTE_MAX + 1))
    with pytest.raises(KeyError):
        stats.set_outcome(board, 999, "paid")
    for status in ("new", "rejected", "inconclusive", "needs-proof", "duplicate"):
        other = finding(board, rid, status)
        with pytest.raises(ValueError, match="only a"):
            stats.set_outcome(board, other, "accepted")
    for status in ("verified-evidence", "submitted"):
        assert stats.set_outcome(board, finding(board, rid, status), "accepted")["ok"]


def _ui(home):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.token = TOKEN
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _post(srv, path, body, *, cookie=True, origin=None, xbh=True):
    port = srv.server_address[1]
    h = {"Content-Type": "application/json", "Host": f"127.0.0.1:{port}"}
    h["Origin"] = origin or f"http://127.0.0.1:{port}"
    if xbh:
        h["X-BH"] = "1"
    if cookie:
        h["Cookie"] = f"{COOKIE}={new_session(TOKEN)}"
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("POST", path, body=json.dumps(body), headers=h)
    r = c.getresponse()
    return r.status, r.read()


def test_cli_and_ui_write_the_same_line(board, home, capsys):
    rid = run(board)
    a, b2 = finding(board, rid), finding(board, rid)
    assert main(["outcome", f"F{a}", "paid", "--bounty", "500", "--note", "nice"]) == 0
    assert "paid" in capsys.readouterr().out
    srv = _ui(home)
    try:
        body = {"outcome": "paid", "bounty": 500, "note": "nice"}
        assert _post(srv, f"/api/finding/{b2}/outcome", body, cookie=False)[0] == 401
        assert _post(srv, f"/api/finding/{b2}/outcome", body, origin="http://evil.example")[0] == 403
        assert _post(srv, f"/api/finding/{b2}/outcome", body, xbh=False)[0] == 403
        assert "outcome" not in row(board, b2) or row(board, b2)["outcome"] is None  # nothing written so far
        code, raw = _post(srv, f"/api/finding/{b2}/outcome", body)
        assert code == 200 and json.loads(raw)["outcome"] == "paid"
        assert _post(srv, f"/api/finding/{b2}/outcome", {**body, "judge": 1})[0] == 400
        assert _post(srv, "/api/finding/999/outcome", body)[0] == 404
    finally:
        srv.shutdown()
        srv.server_close()
    assert row(board, a) == row(board, b2) == {"outcome": "paid", "bounty": 500.0, "outcome_note": "nice"}
    assert main(["outcome", f"F{a}", "informative", "--bounty", "5"]) == 2  # refused, said, nothing changed
    assert row(board, a)["outcome"] == "paid"


def test_both_paths_call_set_outcome(board, home, monkeypatch):
    seen = []
    monkeypatch.setattr(
        stats,
        "set_outcome",
        lambda *a, **k: seen.append(a) or {"ok": True, "program": P, "outcome": "na", "bounty": None, "ledger": 0},
    )
    rid = run(board)
    fid = finding(board, rid)
    assert main(["outcome", f"F{fid}", "na"]) == 0
    srv = _ui(home)
    try:
        assert _post(srv, f"/api/finding/{fid}/outcome", {"outcome": "na"})[0] == 200
    finally:
        srv.shutdown()
        srv.server_close()
    assert [x[1:3] for x in seen] == [(fid, "na"), (fid, "na")]


# ------------------------------------------------------------------ the ledger: weights, retroactive outcome
LINEAGE = (
    "CREATE TABLE IF NOT EXISTS agents (no INTEGER, pseudo TEXT, program TEXT, generation INTEGER, "
    "run_id INTEGER, status TEXT);"
)


def _agent_finding(board, no=1, url="https://copilot.com/api/c/1"):
    board.db.executescript(LINEAGE)
    rid = run(board)
    board.db.execute("INSERT INTO agents VALUES (?,?,?,?,?,?)", (no, f"p{no}", P, no, rid, "done"))
    board.db.commit()
    return finding(board, rid, url=url)


def _signals(board):
    return sorted(
        (r["signal"], r["points"])
        for r in board.rows("SELECT signal, points FROM ledger WHERE program=?", P)
        if r["signal"].startswith(("finding", "outcome"))
    )


def test_outcome_is_retroactive_and_weighted(board):
    fid = _agent_finding(board)
    score.compute(board, P)
    assert _signals(board) == [("finding_verified", 100)]
    stats.set_outcome(board, fid, "paid", bounty=1000)
    assert _signals(board) == [("finding_verified", 100), ("outcome_paid", 300)]
    stats.set_outcome(board, fid, "duplicate")
    assert _signals(board) == [("finding_verified", 100), ("outcome_duplicate", 0)]
    for o in ("informative", "na"):  # the verified credit is withdrawn
        stats.set_outcome(board, fid, o)
        assert _signals(board) == [("outcome_informative", -40)]


def test_a_weights_file_moves_the_outcome(board, home):
    fid = _agent_finding(board)
    stats.set_outcome(board, fid, "paid")
    assert {"outcome_paid", "outcome_accepted", "outcome_duplicate", "outcome_informative"} <= set(score.WEIGHTS)
    before = score.weights_sha256()
    paid = lambda: [e.points for e in score.entries(board, P) if e.signal == "outcome_paid"]  # noqa: E731
    assert paid() == [300]
    score.weights_path().parent.mkdir(parents=True, exist_ok=True)
    score.weights_path().write_text(json.dumps({"outcome_paid": 777}))
    assert paid() == [777] and score.weights_sha256() != before


def test_honor_roll_says_not_to_resubmit_the_shape(board):
    fid = _agent_finding(board, url="https://copilot.com/api/c/1\u200b")
    stats.set_outcome(board, fid, "na")
    lines = score.honor_roll(board, P)
    assert lines == [line for line in lines if "\u200b" not in line]
    assert lines[-1].startswith(f"F{fid} idor") and "not applicable" in lines[-1]
    assert "do not report this shape again" in lines[-1]


# ------------------------------------------------------------------ L3: cost per outcome
def test_stats_on_three_outcomes(board):
    r1, r2 = run(board, cost=6.0, verify=1.5), run(board, cost=2.0, verify=0.5, phase="opus")
    a, p, i = finding(board, r1), finding(board, r1), finding(board, r2, "submitted")
    finding(board, r2, "rejected")
    stats.set_outcome(board, a, "accepted")
    stats.set_outcome(board, p, "paid", bounty=500)
    stats.set_outcome(board, i, "informative")
    s = stats.summary(board, program=P)
    assert set(stats.KEYS) <= set(s) and set(stats.OUTCOME_KEYS) <= set(s)  # W2's keys kept, W4's added
    assert s["cost_usd"]["total"] == 10.0 and s["cost_per_verified"] == round(10 / 3, 4)
    assert s["outcomes"] == {"accepted": 1, "paid": 1, "informative": 1}
    assert s["cost_per_accepted"] == 5.0 and s["cost_per_paid"] == 10.0
    assert s["verified_to_accepted"] == round(2 / 3, 4) and s["bounty_total"] == 500.0
    opus = next(g for g in s["groups"] if g["phase"] == "opus")
    assert opus["cost_per_paid"] == "n/a" and opus["cost_per_accepted"] == "n/a"  # no division by zero
    text = stats.table(s)
    assert "$/paid" in text and "paid 1" in text and "verified -> accepted: 67%" in text


# ------------------------------------------------------------------ L10: the streak alert
def test_streak_alert_never_parks(board, home, capsys, monkeypatch):
    rid = run(board)
    fids = [finding(board, rid) for _ in range(6)]
    for f, o in zip(fids, ["paid", "duplicate", "informative", "na", "duplicate"], strict=False):
        stats.set_outcome(board, f, o)
    assert stats.alert_lines(board) == []  # the paid one is among the last five
    stats.set_outcome(board, fids[5], "informative")
    lines = stats.alert_lines(board)
    assert len(lines) == 1 and P in lines[0] and "consider parking" in lines[0] and "nothing was parked" in lines[0]
    assert main(["stats", "--program", P]) == 0
    assert "ALERT msrc-copilot" in capsys.readouterr().out
    from bh import stack
    from bh.runner import supervisor

    monkeypatch.setattr(stack, "container_running", lambda name: False)
    monkeypatch.setattr(supervisor, "status_line", lambda b, now: "")
    assert main(["status"]) == 0
    assert "ALERT msrc-copilot" in capsys.readouterr().out
    from bh.runner import run as runmod

    assert runmod.parked(P) is None  # proposed, never done


# ------------------------------------------------------------------ L1: the checklist
def test_checklist_text(board, monkeypatch):
    r = run(board)
    other = finding(board, run(board, program="msrc-onedrive"), "verified", program="msrc-onedrive")
    sent = finding(
        board,
        r,
        "submitted",
        proof=json.dumps(
            {
                "steps": [
                    {"role": "setup", "as": "user-b", "method": "GET"},
                    {"role": "attack", "as": "user-a", "method": "GET"},
                ]
            }
        ),
    )
    fid = finding(
        board,
        r,
        "verified",
        proof=json.dumps(
            {
                "steps": [
                    {"role": "setup", "as": "user-b", "method": "GET"},
                    {"role": "attack", "as": "user-a", "method": "GET"},
                ]
            }
        ),
    )
    from bh import verify

    monkeypatch.setattr(verify, "dedupe_key", lambda f: f"idor|{f.get('url')}", raising=False)
    lines = stats.checklist(board, fid, fence=lambda v: f"<<{v}>>")
    text = "\n".join(lines)
    assert "class <<idor>>" in text  # the hunter's class: canonical, inside the fence
    assert stats._key("a\u202eb<script>") == "a\\u{202E}b?script?"  # a key: escaped, key characters only
    assert "(a) internal duplicates (verify.dedupe_key, msrc programs)" in text
    assert f"F{other} (msrc-onedrive" in text and f"F{sent} (msrc-copilot" in text
    assert "(b) search the program's published reports and hacktivity by hand" in text
    assert "route family <</api/c/{id}>>" in text and "product copilot" in text
    assert "(c) replay the proof yourself right before sending" in text
    assert "(d) root cause: class <<idor" in text and "mechanism GET cross-identity" in text
    assert f"already submitted on this cause: F{sent} (msrc-copilot, open)" in text
    assert "Two open reports on one cause" in text
    assert "(e) program rules: last read never" in text and "bh rules check" in text
    assert '(f) Copilot: the report says "the test ran on copilot.com"' in text
    assert "nothing below is sent anywhere" in lines[0]
    # without lot C's key: verify.duplicate_of, program by program
    monkeypatch.delattr(verify, "dedupe_key")
    text = "\n".join(stats.checklist(board, fid))
    assert "(a) internal duplicates (verify.duplicate_of" in text and f"F{other}" in text
    stats.set_outcome(board, sent, "duplicate")
    text = "\n".join(stats.checklist(board, fid))
    assert f"F{sent} (msrc-copilot, duplicate)" in text and "Two open reports" not in text


def test_todo_and_finding_print_the_checklist(board, capsys):
    rid = run(board)
    fid = finding(board, rid, "verified-evidence", url="https://copilot.com/c/9")
    board.add_todo("submit", f"F{fid} verified by observation: t", "replay it", program=P, dedup=f"{P}:submit:F{fid}")
    assert main(["todo", "-v"]) == 0
    out = capsys.readouterr().out
    assert "untrusted-hunter-text" in out and f"Before submitting F{fid}" in out and "(f) Copilot" in out
    assert main(["finding", f"F{fid}"]) == 0
    assert "(c) replay the proof yourself" in capsys.readouterr().out
    assert main(["todo"]) == 0
    assert "Before submitting" not in capsys.readouterr().out  # -v only


def test_submit_fid():
    assert stats.submit_fid({"dedup": "msrc-copilot:submit:F12", "title": "F3 x"}) == 12
    assert stats.submit_fid({"dedup": None, "title": "F7 verified: x"}) == 7
    assert stats.submit_fid({"dedup": None, "title": "nothing"}) is None


# ------------------------------------------------------------------ D12: the PoC screenshot
class FakeHost:
    def __init__(self, **status):
        self.status = {"code": 200, "program": P, "identity": "user-a", "challenge": {"pending": False}, **status}
        self.ops = []

    def __call__(self, req, timeout=None):
        self.ops.append(req["op"])
        if req["op"] == "status":
            return self.status
        if req["op"] == "shot":
            return {"code": 200, "png_b64": base64.b64encode(PNG).decode(), "bytes": len(PNG)}
        return {"code": 400, "error": "unknown"}


def _verified_with_todo(board):
    fid = finding(board, run(board))
    board.add_todo(
        "submit", f"F{fid} verified: t", "replay the triager PoC, then submit", program=P, dedup=f"{P}:submit:F{fid}"
    )
    return fid


def test_poc_shot_stores_the_png_and_cites_it(board, home):
    fid = _verified_with_todo(board)
    host = FakeHost()
    path = stats.poc_shot(P, fid, board=board, call=host, running=lambda: True)
    assert path == home / "var" / "lineage" / P / "poc" / f"F{fid}.png"
    assert path.read_bytes() == PNG and stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert host.ops == ["status", "shot"]
    detail = board.rows("SELECT detail FROM todos WHERE dedup=?", f"{P}:submit:F{fid}")[0]["detail"]
    assert str(path) in detail and "review before sending" in detail
    stats.poc_shot(P, fid, board=board, call=FakeHost(), running=lambda: True)
    detail = board.rows("SELECT detail FROM todos WHERE dedup=?", f"{P}:submit:F{fid}")[0]["detail"]
    assert detail.count("PoC screenshot") == 1  # cited once
    assert "var/work" not in str(path) and "judge" not in str(path)  # never under a mounted directory


@pytest.mark.parametrize(
    "status, running",
    [
        ({"challenge": {"pending": True}}, True),
        ({"human_viewing": True}, True),
        ({"human_watching": True}, True),
        ({"program": "msrc-onedrive"}, True),
        ({"code": 503, "error": "down"}, True),
        ({}, False),
    ],
)
def test_poc_shot_never_during_a_challenge_or_with_the_operator(board, home, status, running):
    fid = _verified_with_todo(board)
    host = FakeHost(**status)
    assert stats.poc_shot(P, fid, board=board, call=host, running=lambda: running) is None
    assert "shot" not in host.ops
    assert not (home / "var" / "lineage" / P / "poc").exists()


def test_poc_shot_never_raises_and_skips_what_it_must(board, home):
    fid = _verified_with_todo(board)

    def boom(req, timeout=None):
        raise RuntimeError("podman gone")

    assert stats.poc_shot(P, fid, board=board, call=boom, running=lambda: True) is None
    onedrive = finding(board, run(board, program="msrc-onedrive"), program="msrc-onedrive")
    host = FakeHost(program="msrc-onedrive")
    assert stats.poc_shot("msrc-onedrive", onedrive, board=board, call=host, running=lambda: True) is None
    assert host.ops == []  # no persistent browser on that scope: not even a status call
    rejected = finding(board, run(board), "rejected")
    assert stats.poc_shot(P, rejected, board=board, call=FakeHost(), running=lambda: True) is None
    assert stats.poc_shot("../etc", fid, board=board, call=FakeHost(), running=lambda: True) is None
    bad = FakeHost()
    bad_png = {"code": 200, "png_b64": base64.b64encode(b"GIF89a").decode()}
    assert (
        stats.poc_shot(
            P,
            fid,
            board=board,
            call=lambda r, timeout=None: bad.status if r["op"] == "status" else bad_png,
            running=lambda: True,
        )
        is None
    )


class ShotDriver:
    def __init__(self, frames=()):
        self.snap = {"url": "https://copilot.com/chats/1", "title": "Copilot", "text": "hi", "frames": list(frames)}
        self.shots = 0

    def snapshot(self):
        return self.snap

    def screenshot(self):
        self.shots += 1
        return PNG

    def cookie_values(self):
        return []


def test_controller_shot_is_a_host_op_refused_on_a_challenge_or_a_viewer():
    assert "shot" in HOST_OPS and "shot" not in AGENT_OPS
    d = ShotDriver()
    ctl = Controller(d)
    code, out = ctl.handle(AGENT_OPS, {"op": "shot"})
    assert code == 400 and d.shots == 0  # the agent's door never has it
    code, out = ctl.handle(HOST_OPS, {"op": "shot"})
    assert code == 200 and base64.b64decode(out["png_b64"]) == PNG and out["url"].startswith("https://copilot.com")
    ctl.handle(HOST_OPS, {"op": "human_viewing", "on": True})
    code, out = ctl.handle(HOST_OPS, {"op": "shot"})
    assert code == 409 and out["error"] == "screen-busy" and d.shots == 1
    ctl.handle(HOST_OPS, {"op": "human_viewing", "on": False})
    d.snap["frames"] = [{"url": TURNSTILE, "visible": True}]
    code, out = ctl.handle(HOST_OPS, {"op": "shot"})
    assert code == 409 and "challenge" in out["detail"] and d.shots == 1


# ------------------------------------------------------------------ T50: the program's cost in the UI
def test_programs_show_cost_cap_and_cost_per_verified(board, home):
    finding(board, run(board, cost=3.0, verify=1.0))
    srv = _ui(home)
    try:
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
        c.request("GET", "/api/programs", headers={"Cookie": f"{COOKIE}={new_session(TOKEN)}"})
        progs = {p["program"]: p for p in json.loads(c.getresponse().read())}
    finally:
        srv.shutdown()
        srv.server_close()
    cp = progs[P]
    assert cp["cost_usd"] == 4.0 and cp["cost_per_verified"] == 4.0 and "cost_cap_usd" in cp
    assert progs["msrc-onedrive"]["cost_per_verified"] == "n/a" and cp["alerts"] == []
    js = (REPO / "src" / "bh" / "ui" / "static" / "app.js").read_text()
    assert "/api/finding/${f.id}/outcome" in js and "plafond" in js


# ------------------------------------------------------------------ T51 and the lines owed to other lots
def test_accounts_check_prints_one_cause_per_identity(home, monkeypatch, capsys):
    from bh.accounts import enroll

    monkeypatch.setattr(enroll, "diagnose", lambda scope, name: f"session-expired:{name}\u200b", raising=False)
    assert main(["accounts", "check", str(home / "scopes" / "msrc" / "copilot.yaml")]) == 0
    out = capsys.readouterr().out
    assert "user-a" in out and "session-expired:user-b\\u{200B}" in out
    monkeypatch.delattr(enroll, "diagnose")
    assert main(["accounts", "check", str(home / "scopes" / "msrc" / "copilot.yaml"), "user-a"]) == 2


def test_objects_tools_fetch_and_audit_are_guarded(board, home, monkeypatch, capsys):
    assert main(["objects", P]) == 0 and "no test_objects table" in capsys.readouterr().out
    board.db.execute("CREATE TABLE test_objects (id INTEGER PRIMARY KEY, program TEXT, kind TEXT, ref TEXT)")
    board.db.execute("INSERT INTO test_objects(program, kind, ref) VALUES (?,?,?)", (P, "conversation", "c-1\u202e"))
    board.db.commit()
    assert main(["objects", P]) == 0
    out = capsys.readouterr().out
    assert "untrusted-hunter-text" in out and "c-1\\u{202E}" in out
    got = {}
    monkeypatch.setitem(
        sys.modules,
        "bh.whitebox",
        types.SimpleNamespace(fetch=lambda url, commit: got.update(url=url, commit=commit) or Path("/tmp/src")),
    )
    assert main(["tools", "fetch", "--repo", "https://github.com/o/r", "--commit", "abc1234"]) == 0
    assert got == {"url": "https://github.com/o/r", "commit": "abc1234"}
    assert main(["tools", "fetch", "--repo", "https://github.com/o/r"]) == 2
    assert main(["tools", "fetch", "--repo", "file:///etc", "--commit", "abc1234"]) == 2
    oracle = home / "oracle.json"
    oracle.write_text("{}")
    monkeypatch.setitem(
        sys.modules,
        "bh.audit",
        types.SimpleNamespace(
            run_audit=lambda b, run_id, o: {"run": run_id, "oracle": str(o)},
            render=lambda r: f"audit of run {r['run']}",
        ),
    )
    assert main(["audit", "7", "--oracle", str(oracle)]) == 0
    assert "audit of run 7" in capsys.readouterr().out
    monkeypatch.setitem(sys.modules, "bh.audit", None)  # absent: one clear line, nothing done
    assert main(["audit", "7"]) == 2


# ------------------------------------------------------------------ D32: bh scope new
SURVEY = """# 99 — Relevé des hôtes Outlook (2026-11-30)

## Outlook.com (relevé)

| Hôte, préfixe | Rôle | Méthodes vues | Type de route |
|---|---|---|---|
| `https://outlook.live.com/mail/` | interface web | GET | lecture |
| `https://outlook.live.com/owa/service.svc?action=SendItem` | envoi d'un message à un destinataire | POST | send |
| `https://outlook.live.com/owa/<id>/share` | partage d'un dossier | POST | écriture |
| `substrate.office.com` (`/api/beta/me/messages`) | API | GET | lecture |
| `https://outlook.live.com/owa/attach` | partage d'une pièce jointe | PUT | écriture (`link` : aucun destinataire) |

## OneDrive (autre service)

| Hôte, préfixe | Rôle | Méthodes vues | Type de route |
|---|---|---|---|
| `https://onedrive.live.com/` | interface | GET | lecture |
"""


def test_scope_new_from_a_survey(home, capsys):
    from bh import scope_scaffold
    from bh.scope import load_scope
    from bh.scope.guards import check

    cap = home / "survey.md"
    cap.write_text(SURVEY)
    assert main(["scope", "new", "msrc", "outlook", "--from", str(cap)]) == 0
    out = capsys.readouterr().out
    dst = home / "scopes" / "msrc" / "outlook.yaml"
    assert f"wrote {dst}" in out and "missing: automation_allowed is false" in out
    s = load_scope(dst)
    assert s.program == "msrc-outlook" and s.platform == "msrc" and s.automation_allowed is False
    assert s.scanners_allowed is False and s.max_rps == 2 and "dos" in s.forbidden_vulns
    assert [i["name"] for i in s.identities] == ["user-a", "user-b"]
    cp = load_scope(home / "scopes" / "msrc" / "copilot.yaml")
    assert s.payload_hosts == cp.payload_hosts and s.rules_url == cp.rules_url
    values = [r.value for r in s.in_scope]
    assert "https://outlook.live.com/mail/" in values and "substrate.office.com" in values
    assert not any("onedrive" in v for v in values)  # the service's section only
    guarded = [g.url for g in s.recipient_guard]
    assert any("SendItem" in g for g in guarded) and any("owa/" in g for g in guarded)
    assert not any("attach" in g or "mail/" in g for g in guarded)  # `link`, reading: not a send
    assert check(s) == []
    assert main(["scope", "new", "msrc", "outlook", "--from", str(cap)]) == 2  # never over a file
    assert "already exists" in capsys.readouterr().err
    with pytest.raises(scope_scaffold.ScaffoldError, match="not in the survey"):
        scope_scaffold.build("outlook", cap, hosts=["evil.example"])
    with pytest.raises(scope_scaffold.ScaffoldError, match="wildcard"):
        scope_scaffold.build("outlook", cap, hosts=["*.live.com"])
    kept = scope_scaffold.build("outlook", cap, hosts=["substrate.office.com"])
    assert [r["value"] for r in kept["in_scope"]] == ["substrate.office.com"]
    wild = home / "wild.md"
    wild.write_text(SURVEY.replace("`substrate.office.com`", "`*.office.com`"))
    with pytest.raises(scope_scaffold.ScaffoldError, match="wildcard"):
        scope_scaffold.build("outlook", wild)
    with pytest.raises(scope_scaffold.ScaffoldError, match="service"):
        scope_scaffold.build("../x", cap)
