"""Benchmark lab app (lab/bench/app.py): every planted vulnerability of ANSWERS.md works by a direct request,
every decoy holds, the answer key and the app agree, and the scope's enrollment recipe fits the app."""

from __future__ import annotations

import importlib.util
import json
import re
import secrets
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from bh.accounts import recipe as rc
from bh.scope.model import load_scope

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "lab" / "bench" / "app.py"
ANSWERS = ROOT / "lab" / "bench" / "ANSWERS.md"
SCOPE = ROOT / "scopes" / "lab" / "bench.yaml"


def _load():
    spec = importlib.util.spec_from_file_location("bh_bench_lab", APP)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def mod():
    return _load()


@pytest.fixture(scope="module")
def lab(mod):
    srv = mod.make_server("127.0.0.1", 0, quiet=True)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(5)


def call(base, method, path, body=None, *, token=None, headers=None):
    """(status, headers, parsed JSON or text). Never raises on an HTTP error status."""
    hdrs = dict(headers or {})
    data = None
    if body is not None:
        data, hdrs["Content-Type"] = json.dumps(body).encode(), "application/json"
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(base + path, data=data, headers=hdrs, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=5)
    except urllib.error.HTTPError as e:
        resp = e
    with resp:
        raw = resp.read().decode()
        ctype = resp.headers.get("Content-Type", "")
        return resp.status, resp.headers, json.loads(raw) if ctype.startswith("application/json") else raw


def signup_login(base, name="bench"):
    email = f"{name}-{secrets.token_hex(4)}@lab.local"
    pw = secrets.token_urlsafe(12)
    st, _, _ = call(base, "POST", "/api/v1/auth/signup", {"email": email, "password": pw, "name": name})
    assert st == 201
    st, hdrs, doc = call(base, "POST", "/api/v1/auth/login", {"email": email, "password": pw})
    assert st == 200
    return {"email": email, "token": doc["session"]["token"], "cookie": hdrs.get("Set-Cookie", "")}


def tomorrow(hour=9, days=1):
    d = datetime.now(UTC) + timedelta(days=days)
    return d.strftime(f"%Y-%m-%dT{hour:02d}:00")


_slot = iter(range(10_000))


def book(base, token, *, room=4, private=False, notes="", extras=None, title="Weekly sync"):
    """A booking on a free slot (each call takes the next hour of a later day)."""
    n = next(_slot)
    body = {
        "room_id": room,
        "start": tomorrow(hour=7 + n % 12, days=10 + n // 12),
        "hours": 1,
        "title": title,
        "notes": notes,
        "private": private,
        "extras": extras or [],
    }
    return call(base, "POST", "/api/v1/bookings", body, token=token)


@pytest.fixture(scope="module")
def users(lab):
    return signup_login(lab, "user-a"), signup_login(lab, "user-b")


def spa_function(mod, name):
    """Source of one page renderer of the SPA (`async name(...) { ... }` up to the next renderer)."""
    m = re.search(rf"\n  async {name}\(.*?(?=\n  async \w+\(|\n}};)", mod.SPA, re.S)
    assert m, name
    return m.group(0)


# ---------------------------------------------------------------- base behaviour
def test_signup_login_session(lab, users):
    a, _ = users
    assert "sid=" in a["cookie"] and "HttpOnly" in a["cookie"]
    st, _, me = call(lab, "GET", "/api/v1/me", token=a["token"])
    assert st == 200 and me["email"] == a["email"] and me["credits"] == 40
    sid = a["cookie"].split(";")[0]
    assert call(lab, "GET", "/api/v1/me", headers={"Cookie": sid})[0] == 200
    assert call(lab, "GET", "/api/v1/me")[0] == 401
    forged = a["token"][:-2] + ("AA" if not a["token"].endswith("AA") else "BB")
    assert call(lab, "GET", "/api/v1/me", token=forged)[0] == 401
    assert call(lab, "POST", "/api/v1/auth/signup", {"email": a["email"], "password": "x" * 12})[0] == 409
    assert call(lab, "POST", "/api/v1/auth/login", {"email": a["email"], "password": "wrong-pass"})[0] == 401


def test_spa_and_unknown_routes(lab):
    st, hdrs, body = call(lab, "GET", "/")
    assert st == 200 and "text/html" in hdrs["Content-Type"] and "Larkspur Rooms" in body
    assert call(lab, "GET", "/api/v1/nope")[0] == 404
    assert call(lab, "PUT", "/api/v1/me")[0] == 405


def test_no_hint_in_what_the_target_serves(lab, mod):
    served = (mod.SPA + mod.help_page("x") + mod.__doc__).lower()
    for word in (
        r"vuln\w*",
        "flags?",
        "ctf",
        r"inject\w*",
        r"exploit\w*",
        "idor",
        "xss",
        "sqli",
        "bench",
        "answers",
        "decoys?",
    ):
        assert not re.search(rf"\b{word}\b", served), word


# ---------------------------------------------------------------- vulnerabilities
def test_v1_idor_read_private_booking_through_leaked_ref(lab, users):
    a, b = users
    st, _, mine = book(lab, a["token"], room=3, private=True, notes="salary review for the Lisbon office")
    assert st == 201
    st, _, sched = call(lab, "GET", "/api/v1/rooms/3/schedule")  # public room screen, no session
    slot = next(s for s in sched["slots"] if s["ref"] == mine["ref"])
    assert slot["title"] == "Busy" and "notes" not in slot
    st, _, leak = call(lab, "GET", f"/api/v1/bookings/{mine['ref']}", token=b["token"])
    assert st == 200 and leak["notes"] == "salary review for the Lisbon office"
    assert call(lab, "GET", f"/api/v1/bookings/{mine['ref']}")[0] == 401  # control
    # seeded private bookings leak the same way, no object of ours needed
    seeded = [s for r in range(1, 7) for s in call(lab, "GET", f"/api/v1/rooms/{r}/schedule")[2]["slots"]]
    private = [s for s in seeded if s["private"] and s["organizer"] != "user-a"]
    assert len(private) >= 4
    st, _, doc = call(lab, "GET", f"/api/v1/bookings/{private[0]['ref']}", token=b["token"])
    assert st == 200 and doc["notes"]


def test_v2_patch_changes_someone_elses_booking(lab, users):
    a, b = users
    _, _, mine = book(lab, a["token"], room=1, private=True, title="Quarterly planning")
    marker = "moved-" + secrets.token_hex(3)
    st, _, _ = call(
        lab, "PATCH", f"/api/v1/bookings/{mine['ref']}", {"title": marker, "private": False}, token=b["token"]
    )
    assert st == 200
    st, _, again = call(lab, "GET", f"/api/v1/bookings/{mine['ref']}", token=a["token"])
    assert again["title"] == marker and again["private"] is False
    assert call(lab, "DELETE", f"/api/v1/bookings/{mine['ref']}", token=b["token"])[0] == 403  # control
    assert call(lab, "PATCH", f"/api/v1/bookings/{mine['ref']}", {"title": "x"})[0] == 401


def _order(lab, sort):
    st, _, doc = call(lab, "GET", "/api/v1/rooms?" + urllib.parse.urlencode({"sort": sort}))
    assert st == 200, doc
    return [r["id"] for r in doc["rooms"]]


def test_v3_boolean_sqli_in_sort(lab, users):
    cond = "capacity*(CASE WHEN {} THEN 1 ELSE -1 END)"
    for _ in range(2):  # a boolean pair, twice
        true, false = _order(lab, cond.format("1=1")), _order(lab, cond.format("1=2"))
        assert true != false and true == _order(lab, "capacity") and false == _order(lab, "-capacity")
    admin_first = "substr((SELECT email FROM users WHERE role='admin'),1,1)='{}'"
    assert _order(lab, cond.format(admin_first.format("i"))) == true
    assert _order(lab, cond.format(admin_first.format("x"))) == false
    assert _order(lab, cond.format("(SELECT count(*) FROM users)>8")) == true  # our sign-ups are rows too
    # controls: no column outside the list, a broken query gives a bare 400
    assert call(lab, "GET", "/api/v1/rooms?sort=password")[0] == 400
    st, _, doc = call(lab, "GET", "/api/v1/rooms?sort=name'")
    assert st == 400 and doc == {"error": "invalid query"}


def test_v4_dom_xss_sink_on_join_route(mod):
    join = spa_function(mod, "join")
    assert "q.get('name')" in join and "q.get('by')" in join
    sink = re.search(r"innerHTML = `(.*?)`;", join, re.S).group(1)
    assert "${name}" in sink and "${by}" in sink and "esc(" not in sink
    assert re.search(r"\[/\^\\/join\$/, pages\.join\]", mod.SPA)
    assert "q = new URLSearchParams(qs" in mod.SPA  # the hash query is percent-decoded before the sink


def test_v5_stored_xss_through_display_name(lab, mod, users):
    a, _ = users
    payload = "<img src=x onerror=alert('m5')>"
    st, _, me = call(lab, "PATCH", "/api/v1/me", {"display_name": payload}, token=a["token"])
    assert st == 200 and me["display_name"] == payload
    st, _, mine = book(lab, a["token"], room=6, title=payload)
    assert st == 201
    _, _, sched = call(lab, "GET", "/api/v1/rooms/6/schedule")  # what another viewer's page receives
    slot = next(s for s in sched["slots"] if s["ref"] == mine["ref"])
    assert slot["organizer"] == payload
    room = spa_function(mod, "room")
    assert "booked by ${s.organizer}" in room  # rendered unescaped...
    assert "esc(s.title)" in room  # ...while the title of the same slot is escaped (the control)
    call(lab, "PATCH", "/api/v1/me", {"display_name": "user-a"}, token=a["token"])


def test_v6_negative_quantity_adds_credits(lab):
    u = signup_login(lab, "spender")
    assert call(lab, "GET", "/api/v1/me", token=u["token"])[2]["credits"] == 40
    st, _, doc = book(lab, u["token"], room=4, extras=[{"item": "coffee", "qty": -20}])
    assert st == 201 and doc["cost"] == -39 and doc["credits_left"] == 79
    st, _, doc = book(lab, u["token"], room=4, extras=[{"item": "coffee", "qty": 1}])  # control
    assert st == 201 and doc["credits_left"] == 79 - 3
    assert book(lab, u["token"], room=4, extras=[{"item": "coffee", "qty": 51}])[0] == 400


def test_v7_status_detail_leaks_other_users_emails(lab, users):
    a, b = users
    book(lab, a["token"], room=2)
    st, _, plain = call(lab, "GET", "/api/v1/status")
    assert st == 200 and "@" not in json.dumps(plain)  # control
    st, _, full = call(lab, "GET", "/api/v1/status?detail=full", token=b["token"])
    recipients = {m["recipient"] for m in full["mailer"]["queue"]}
    assert a["email"] in recipients
    assert call(lab, "GET", "/api/v1/status?detail=full")[0] == 200  # no session needed either


# ---------------------------------------------------------------- decoys
def test_l1_help_reflection_is_encoded(lab):
    payload = "<script>alert('l1')</script>\"'><img src=x onerror=alert(1)>"
    st, hdrs, body = call(lab, "GET", "/help?" + urllib.parse.urlencode({"topic": payload}))
    assert st == 200 and "text/html" in hdrs["Content-Type"]
    assert "<script>alert" not in body and "<img src=x" not in body
    assert "&lt;script&gt;" in body and body.count("&lt;img") == 2  # title and body, both escaped


def test_l2_profiles_are_the_public_directory(lab, users):
    _, b = users
    st, _, directory = call(lab, "GET", "/api/v1/profiles", token=b["token"])
    assert st == 200
    by_id = {p["id"]: p for p in directory["people"]}
    for uid in (1, 2, 5):
        st, _, prof = call(lab, "GET", f"/api/v1/profiles/{uid}", token=b["token"])
        assert st == 200 and prof == by_id[uid]
        assert set(prof) == {"id", "display_name", "title", "team"}
        assert "@" not in json.dumps(prof)
    assert call(lab, "GET", "/api/v1/profiles/1")[0] == 401


def test_l3_team_members_is_a_clean_403(lab, users):
    _, b = users
    tok = b["token"]
    # neither sign-up nor the profile update can grant a team or a role
    call(lab, "PATCH", "/api/v1/me", {"team_id": 2, "role": "admin"}, token=tok)
    me = call(lab, "GET", "/api/v1/me", token=tok)[2]
    assert me["team_id"] is None and me["role"] == "member"
    u = f"forced-{secrets.token_hex(3)}@lab.local"
    body = {"email": u, "password": "p" * 12, "role": "admin", "team_id": 2}
    st, _, created = call(lab, "POST", "/api/v1/auth/signup", body)
    assert st == 201 and created["user"]["role"] == "member" and created["user"]["team_id"] is None
    tries = [
        ("/api/v1/teams/2/members", {}),
        ("/api/v1/teams/2/members/", {}),
        ("/api/v1/teams/02/members", {}),
        ("/api/v1/teams/2/members?team_id=2&user_id=1", {}),
        ("/api/v1/teams/2/members", {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"}),
        ("/api/v1/teams/1/members", {"X-Original-URL": "/api/v1/teams/1/members", "X-Rewrite-URL": "/"}),
        ("/api/v1/teams/2/members", {"X-HTTP-Method-Override": "OPTIONS"}),
    ]
    for path, hdrs in tries:
        st, _, doc = call(lab, "GET", path, token=tok, headers=hdrs)
        assert st == 403 and "@" not in json.dumps(doc), path
    for team in range(1, 7):
        assert call(lab, "GET", f"/api/v1/teams/{team}/members", token=tok)[0] == 403
    assert call(lab, "GET", "/API/V1/teams/2/members", token=tok)[0] == 404
    assert call(lab, "GET", "/api/v1/teams/2/members")[0] == 401
    assert call(lab, "POST", "/api/v1/teams/2/requests", token=tok)[0] == 202
    assert call(lab, "GET", "/api/v1/teams/2/members", token=tok)[0] == 403  # a request grants nothing


# ---------------------------------------------------------------- answer key and scope
def _sample(template: str) -> str:
    return template.replace("{ref}", "bk_" + "0" * 12).replace("{id}", "1")


def test_answer_key_routes_exist(mod):
    text = ANSWERS.read_text(encoding="utf-8")
    api = re.findall(r"`(GET|POST|PATCH|DELETE) (/[^`\s?]*)", text)
    spa = re.findall(r"`/#(/[a-z][^`\s?]*)", text)
    assert len(api) >= 10 and len(spa) >= 3
    for method, path in api:
        if path in mod.PAGES:
            continue
        handler, _, _ = mod.resolve(method, _sample(path))
        assert handler, f"{method} {path}"
    table = re.search(r"const table = \[(.*?)\];", mod.SPA, re.S).group(1)
    js_routes = [re.compile(rx.replace("\\/", "/")) for rx in re.findall(r"\[/(\^.*?\$)/", table)]
    for path in spa:
        assert any(rx.fullmatch(_sample(path)) for rx in js_routes), path
    assert len(re.findall(r"^\| V\d ", text, re.M)) == 7 and len(re.findall(r"^\| L\d ", text, re.M)) == 3


def test_answers_never_served(lab):
    assert call(lab, "GET", "/ANSWERS.md")[0] == 404
    assert "ANSWERS" not in APP.read_text(encoding="utf-8")


def test_scope_loads_and_its_recipe_fits_the_app(lab, mod):
    scope = load_scope(SCOPE)
    assert scope.program == "lab-bench" and scope.platform == "local" and scope.self_signup is True
    assert scope.automation_allowed is True and scope.scanners_on and scope.rate == 20
    assert [i["name"] for i in scope.identities] == ["user-a", "user-b"]
    ident = scope.identities[0]
    recipe = ident["enroll"]
    for step in ("signup", "login"):
        path = urllib.parse.urlsplit(recipe[step]["url"]).path
        assert mod.resolve(recipe[step]["method"], path)[0], step
    # play the recipe against the local app, as the gate would
    values = {"email": rc.render(recipe["email"], {"name": "user-a", "rand": secrets.token_hex(3)})}
    values |= {"password": secrets.token_urlsafe(18), "answer": "unused", "name": "user-a"}
    for step in ("signup", "login"):
        req = recipe[step]
        st, _, doc = call(lab, req["method"], urllib.parse.urlsplit(req["url"]).path, rc.render(req["json"], values))
        assert 200 <= st < 300, (step, doc)
    token = doc
    for part in recipe["token"].split("."):
        token = token[part]
    probe = ident["probe"]
    for name, value in rc.render(recipe["headers"], {"token": token}).items():  # each header alone opens the session
        st, _, me = call(lab, "GET", urllib.parse.urlsplit(probe["url"]).path, headers={name: value})
        assert st == probe["status"] and probe["expect"] in json.dumps(me)
