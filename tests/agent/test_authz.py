"""bh-authz without a network: a fake application behind a simulated `_send` (no request leaves the test)."""

import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from bh.agent import authz as az
from bh.agent import contract as c
from bh.agent import hooks
from bh.agent import proof as pf

ROOT = Path(__file__).resolve().parents[2]
ORIGIN = "http://lab:8000"
USERS = {
    "user-a": {"id": 11, "email": "alice@corp.test", "username": "alice_m", "org_id": 1},
    "user-b": {"id": 12, "email": "bob@corp.test", "username": "bobby_k", "org_id": 2},
    "admin-a": {"id": 1, "email": "root@corp.test", "username": "admin_r", "org_id": 1},
}


class App:
    """Rooms: /api/v1/me, /api/v1/bookings (own list), /api/v1/bookings/<id> (read and PATCH), an admin list.
    `secure`: objects and the admin list check the caller. `gate_denies`: paths the gate refuses."""

    def __init__(self, secure=False, gate_denies=()):
        self.secure = secure
        self.gate_denies = gate_denies
        self.bookings = {
            101: {"id": 101, "user_id": 11, "title": "standup", "room": "Elm"},
            102: {"id": 102, "user_id": 12, "title": "1:1", "room": "Oak"},
            999: {"id": 999, "user_id": 77, "title": "board", "room": "Ash"},  # a real third user's
        }
        self.calls = []

    def __call__(self, method, url, who, body=None):
        self.calls.append((method, urlsplit(url).path, who, body))
        path = urlsplit(url).path
        if any(path.startswith(p) for p in self.gate_denies):
            return az.Answer(403, b"bh-gate: DENIED (id enumeration)", "text/plain", denied=True)
        if who is None:
            return az.Answer(401, b'{"error":"login required"}', "application/json")
        me = USERS[who]
        if path == "/api/v1/me":
            return self.json(me)
        if path == "/api/v1/bookings":
            return self.json({"items": [b for b in self.bookings.values() if b["user_id"] == me["id"]]})
        if path.startswith("/api/v1/bookings/"):
            tail = path.rsplit("/", 1)[1]
            b = self.bookings.get(int(tail)) if tail.isdigit() else None
            if b is None:
                return az.Answer(404, b"{}")
            if self.secure and b["user_id"] != me["id"]:
                return az.Answer(403, b'{"error":"forbidden"}', "application/json")
            if method == "PATCH":
                b.update(body or {})
            return self.json(b)
        if path == "/api/v1/admin/users":
            if self.secure and who != "admin-a":
                return az.Answer(403, b'{"error":"forbidden"}', "application/json")
            return self.json([{"name": "x", "n": 3}])
        return az.Answer(404, b"not found")

    @staticmethod
    def json(doc):
        return az.Answer(200, json.dumps(doc).encode(), "application/json")


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("BH_DIR", str(tmp_path))
    monkeypatch.setenv("BH_IDENTITIES", "user-a,user-b")
    monkeypatch.delenv("BH_IDENTITY_ROLES", raising=False)
    monkeypatch.delenv("BH_ROLE", raising=False)
    monkeypatch.delenv("BH_SCANNERS", raising=False)
    return tmp_path


def run(monkeypatch, app, argv, capsys=None):
    monkeypatch.setattr(az, "_send", app)
    az.main(argv)
    out = capsys.readouterr().out if capsys else ""
    summaries = sorted((Path(os.environ["BH_DIR"]) / c.RAW).glob("authz-*/summary.json"))
    return json.loads(summaries[-1].read_text()), out


def row(summary, path):
    return next(r for r in summary["rows"] if urlsplit(r["url"]).path == path)


def test_markers_are_learned_from_each_me_page_and_only_unique_ones_kept():
    ms = az.markers_of({"id": 11, "email": "alice@corp.test", "username": "alice_m", "org": {"id": 1}, "role": "x"})
    kinds = {(m.kind, m.value) for m in ms}
    assert {("id", "11"), ("email", "alice@corp.test"), ("name", "alice_m"), ("tenant", "1")} <= kinds
    shared = az.unique_markers({"a": {az.Marker("tenant", "org_id", "1")}, "b": {az.Marker("tenant", "org_id", "1")}})
    assert shared == {"a": set(), "b": set()}  # a tenant both share proves nothing
    # a short id counts only under an owner-like key, a string as a whole word
    m = {az.Marker("id", "id", "11")}
    assert az.find(m, az.Answer(200, b'{"user_id": 11, "n": 11}'))[0][1] == '"user_id": 11'
    assert not az.find(m, az.Answer(200, b'{"count": 11, "page": 110}'))
    assert not az.find(m, az.Answer(200, b'{"id": 11, "room": {"id": 11}}'))  # objects' own ids
    nested = az.find(m, az.Answer(200, b'{"ref": "x", "organizer": {"name": "a", "id": 11}}'))
    assert nested[0][1] == '"organizer": {"name": "a", "id": 11'
    assert not az.find({az.Marker("email", "email", "al@c.test")}, az.Answer(200, b"xal@c.testy"))


def test_markers_learned_live(env, monkeypatch):
    s, _ = run(monkeypatch, App(), [f"{ORIGIN}/api/v1/bookings"])
    assert s["me"] == {"user-a": "/api/v1/me", "user-b": "/api/v1/me"}
    a = {tuple(m) for m in s["markers"]["user-a"]}
    assert ("email", "email", "alice@corp.test") in a and ("id", "id", "11") in a


def test_horizontal_candidate_from_the_owners_own_listing(env, monkeypatch, capsys):
    app = App()
    s, out = run(monkeypatch, app, [f"{ORIGIN}/api/v1/bookings"], capsys)
    r = row(s, "/api/v1/bookings/101")  # the owner's item, expanded from its own list
    assert r["kind"] == "horizontal" and r["via"] == "expand" and list(r["hits"]) == ["user-b"]
    assert r["answers"]["anon"][0] == 401
    assert "[horizontal]" in out and "marker" in out and "seen: user-b" in out
    assert not any(p.endswith(("/102", "/999")) for _, p, _, _ in app.calls)  # no id sweep, no one else's object
    assert row(s, "/api/v1/bookings")["kind"] == ""  # each identity lists its own: sane


def test_vertical_candidate_with_roles(env, monkeypatch, capsys):
    monkeypatch.setenv("BH_IDENTITIES", "admin-a,user-a")
    monkeypatch.setenv("BH_IDENTITY_ROLES", "user-a=member@A,admin-a=admin@A")
    s, out = run(monkeypatch, App(), [f"{ORIGIN}/api/v1/admin/users"], capsys)
    r = row(s, "/api/v1/admin/users")
    assert r["kind"] == "vertical" and "user-a (member) gets what admin-a (admin) gets" in r["note"]
    assert "[vertical]" in out
    roles = az.roles(["user-a", "x"], "user-a=member@A")
    assert roles["user-a"] == az.Role("member", "A") and roles["x"] == az.Role("user", "x")
    assert az.roles(["p", "q"], "")["p"].tenant != az.roles(["p", "q"], "")["q"].tenant  # default: distinct tenants


def test_no_candidate_when_the_app_refuses_properly(env, monkeypatch, capsys):
    monkeypatch.setenv("BH_IDENTITIES", "admin-a,user-a,user-b")
    monkeypatch.setenv("BH_IDENTITY_ROLES", "user-a=member@A,user-b=member@B,admin-a=admin@A")
    s, out = run(
        monkeypatch,
        App(secure=True),
        [f"{ORIGIN}/api/v1/bookings/101", f"{ORIGIN}/api/v1/admin/users", "--owner", "user-a"],
        capsys,
    )
    assert all(not r["kind"] for r in s["rows"]) and s["proof"] is None
    assert row(s, "/api/v1/bookings/101")["answers"]["user-b"][0] == 403
    assert "0 candidates, 2 sane" in out


def test_write_own_changes_and_restores_the_owners_object_only(env, monkeypatch, capsys):
    app = App()
    s, out = run(monkeypatch, app, [f"{ORIGIN}/api/v1/bookings", "--write-own"], capsys)
    writes = [(m, p, w) for m, p, w, _ in app.calls if m in ("PATCH", "PUT", "DELETE")]
    assert writes[0] == ("PATCH", "/api/v1/bookings/101", "user-b")  # another of our identities, our object
    assert writes[-1] == ("PATCH", "/api/v1/bookings/101", "user-a")  # the owner restores it
    assert all(m != "DELETE" for m, _, _ in writes)
    assert app.bookings[101]["title"] == "standup"
    w = s["writes"][0]
    assert w["effect"] and w["restored"] and "WRITE PATCH /api/v1/bookings/{id} by user-b" in out


def test_no_write_on_an_object_no_identity_of_ours_owns(env, monkeypatch, capsys):
    app = App()
    s, _ = run(monkeypatch, app, [f"{ORIGIN}/api/v1/bookings/999", "--write-own"], capsys)
    assert not [x for x in app.calls if x[0] != "GET"]  # not one write sent
    assert s["writes"] == [] and app.bookings[999]["title"] == "board"
    # and without any marker (no "me" page), ownership is unknown: no write either
    blind = App()
    monkeypatch.setattr(az, "learn", lambda *a, **k: (set(), ""))
    run(monkeypatch, blind, [f"{ORIGIN}/api/v1/bookings/101", "--write-own"])
    assert not [x for x in blind.calls if x[0] != "GET"]


def test_gate_refusals_are_counted_and_never_retried(env, monkeypatch, capsys):
    app = App(gate_denies=("/api/v1/bookings/",))
    s, out = run(monkeypatch, app, [f"{ORIGIN}/api/v1/bookings"], capsys)
    assert s["denied"] == 3  # owner, user-b and anonymous: one each
    assert len([x for x in app.calls if x[1] == "/api/v1/bookings/101"]) == 3
    assert "1 refused by the gate (3 denied requests" in out


def test_proof_json_is_ready_and_valid(env, monkeypatch, capsys):
    s, out = run(monkeypatch, App(), [f"{ORIGIN}/api/v1/bookings"], capsys)
    proof = json.loads(Path(s["proof"]).read_text())
    assert pf.validate(proof) == []
    roles = {st["role"]: st for st in proof["steps"]}
    assert roles["attack"]["as"] == "user-b" and roles["control"]["as"] is None
    needle = roles["attack"]["expect"]["contains"][0]
    assert needle in ("alice@corp.test", '"user_id": 11') and roles["control"]["expect"]["absent"] == [needle]
    assert f"--proof {s['proof']}" in out
    # coverage and the tested list
    assert "authz" in c.read_json(env / c.COVERAGE, {})[ORIGIN]
    keys = {t["key"] for t in c.read_jsonl(env / c.TOUCHED)}
    assert {"GET /api/v1/bookings", "GET /api/v1/bookings/{id}"} <= keys


def test_write_proof_is_valid_too(env, monkeypatch):
    s, _ = run(monkeypatch, App(), [f"{ORIGIN}/api/v1/bookings/101", "--write-own"])
    proof = json.loads(Path(s["proof"]).read_text())
    assert pf.validate(proof) == [] and proof["steps"][0]["method"] == "PATCH" and proof["steps"][0]["as"] == "user-b"


def test_write_own_refused_without_scanners(env, monkeypatch):
    monkeypatch.setenv("BH_SCANNERS", "0")
    app = App()
    monkeypatch.setattr(az, "_send", app)
    with pytest.raises(SystemExit) as exc:
        az.main([f"{ORIGIN}/api/v1/bookings", "--write-own"])
    assert str(exc.value).startswith(c.RULES_MARK) and app.calls == []
    deny = hooks.pre_tool_use({"tool_name": "Bash", "tool_input": {"command": f"bh-authz {ORIGIN}/x --write-own"}})
    assert deny["hookSpecificOutput"]["permissionDecisionReason"].startswith(c.RULES_MARK)
    assert hooks.pre_tool_use({"tool_name": "Bash", "tool_input": {"command": f"bh-authz {ORIGIN}/x"}}) is None
    with pytest.raises(SystemExit):  # no abbreviation that would dodge the classification
        az.parse_args([f"{ORIGIN}/x", "--write"])


def test_refused_to_the_verifier(env, monkeypatch):
    monkeypatch.setenv("BH_ROLE", "verifier")
    app = App()
    monkeypatch.setattr(az, "_send", app)
    with pytest.raises(SystemExit) as exc:
        az.main([f"{ORIGIN}/api/v1/bookings"])
    assert str(exc.value).startswith(c.RULES_MARK) and app.calls == []
    for cmd in (f"bh-authz {ORIGIN}/x", f"bh-agent authz {ORIGIN}/x"):
        deny = hooks.pre_tool_use({"tool_name": "Bash", "tool_input": {"command": cmd}})
        assert deny["hookSpecificOutput"]["permissionDecisionReason"].startswith(c.RULES_MARK), cmd


def test_classification():
    for cmd in ("bh-authz http://h/", "bh-agent authz --owner user-b"):
        assert c.runs_mapper(cmd) and not c.runs_scanner(cmd) and c.uses_arsenal(cmd), cmd
    for cmd in ("bh-authz http://h/ --write-own", "/opt/bh/bin/bh-authz --max 3 --write-own 'http://h/'"):
        assert c.runs_scanner(cmd), cmd
    assert not c.uses_manual_http("bh-authz http://h/")


def test_output_stays_within_25_lines(env, monkeypatch, capsys):
    monkeypatch.setenv("BH_IDENTITIES", "user-a,user-b,admin-a")
    urls = [f"{ORIGIN}/api/v1/bookings/101?v={i}" for i in range(40)]
    s, out = run(monkeypatch, App(), [*urls, "--max", "40", "--write-own"], capsys)
    assert len([r for r in s["rows"] if r["kind"]]) == 40
    lines = out.strip().splitlines()
    assert len(lines) <= az.MAX_LINES and "more candidates in summary.json" in out and lines[-3].startswith("raw: ")
    assert lines[-2] == "1 routes in, 1 tested, missing: none"  # one route, 40 query strings
    assert lines[-1].startswith("next: read ")


def test_401_guard_stops_an_identity_before_the_gate_marks_its_session_dead(env, monkeypatch):
    class Locked(App):
        def __call__(self, method, url, who, body=None):
            if who == "user-b":
                self.calls.append((method, urlsplit(url).path, who, body))
                return az.Answer(401, b"{}")
            return super().__call__(method, url, who, body)

    app = Locked()
    run(monkeypatch, app, [f"{ORIGIN}/api/v1/a", f"{ORIGIN}/api/v1/b", f"{ORIGIN}/api/v1/c", f"{ORIGIN}/api/v1/d"])
    routes = {p for _, p, w, _ in app.calls if w == "user-b"}
    assert len(routes) == az.GUARD_401


def test_known_endpoints_api_first_and_never_logout(env):
    c.append_jsonl(
        env / c.ENDPOINTS,
        {"origin": ORIGIN, "key": "GET /about", "url": f"{ORIGIN}/about"},
        {"origin": ORIGIN, "key": "GET /api/v1/rooms/{id}", "url": f"{ORIGIN}/api/v1/rooms/3"},
        {"origin": ORIGIN, "key": "GET /logout", "url": f"{ORIGIN}/logout"},
        {"origin": ORIGIN, "key": "POST /api/v1/login", "url": f"{ORIGIN}/api/v1/login"},
    )
    c.append_jsonl(
        env / c.TOUCHED, {"origin": ORIGIN, "key": "GET /api/v1/orders/{id}"}, {"origin": ORIGIN, "key": "GET /x"}
    )
    urls = [e.url for e in az.known_endpoints("both", {"GET"})]
    assert urls == [f"{ORIGIN}/api/v1/rooms/3", f"{ORIGIN}/about", f"{ORIGIN}/x"]


def test_bh_authz_is_a_link_to_the_entry_point():
    link = ROOT / "container/agent/bin/bh-authz"
    assert link.is_symlink() and os.readlink(link) == "bh-agent"
