"""W4-F: the surface score and the clones (T42), the technique cards and their only reader (T18), the white-box lane
(T49). No network, no podman: git is simulated, the gate's log and flow files are written by hand."""

import json
import re
import time
from types import SimpleNamespace

import pytest

from bh import assets, classes, paths, whitebox
from bh.agent import contract as c
from bh.agent import recall as client
from bh.assets import Graph
from bh.board import Board
from bh.lineage import recall, store, techniques
from bh.scope import scope_from_dict

P = "p"
ORIG = "https://a.t.test:443"
_NAV = " ".join(
    f'<li><a href="/c/{w}">{w}</a></li>'
    for w in ("shoes", "shirts", "hats", "bags", "coats", "socks", "belts", "boots", "gloves", "scarves", "jackets")
)


def _home_page(brand: str) -> str:
    """One storefront template, the brand changes: what a set of white-label clones answers on /."""
    return (
        f'<html><head><title>{brand} store</title><link rel="stylesheet" href="/s.css"></head><body>'
        f'<div class="nav"><ul>{_NAV}</ul></div><div class="main"><h1>Welcome to {brand}</h1>'
        "<p>Sign in to see your orders, track your parcel and manage your account.</p>"
        '<form><input name="q"><button>Search</button></form></div><div class="footer"><a href="/privacy">privacy</a> '
        '<a href="/terms">terms</a> <a href="/careers">careers</a> <a href="/press">press</a></div></body></html>'
    )


HOME_WORDS = _home_page("alpha")
OTHER_PAGE = (
    "<html><head><title>Developer docs</title></head><body><main><h1>API reference</h1><p>Authentication tokens rate "
    "limits pagination errors webhooks sdk downloads changelog versioning</p><pre>curl -X GET /v1/things</pre><p>Each "
    "endpoint returns JSON objects with an id field and timestamps.</p></main></body></html>"
)


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    return tmp_path


def _scope(**extra):
    return scope_from_dict({"program": P, "platform": "x", "in_scope": ["*.t.test"], **extra})


def _jsonl(path, recs, append=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a" if append else "w") as fh:
        fh.write("".join(json.dumps(r) + "\n" for r in recs))


def _work(home):
    return home / "var" / "work" / P / ".bh"


_SEQ = iter(range(1, 10**6))


def _flow(rid, url, *, method="GET", ua="curl/8.1", status=200, identity=None, body=None):
    fid = f"1700000000-abcdef-{next(_SEQ)}"
    rec = {"id": fid, "run": rid, "class": "target", "method": method, "url": url, "ua": ua, "status": status}
    if identity:
        rec["identity"] = identity
    if body is not None:
        f = paths.flow_file(fid)
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(json.dumps({**rec, "response": {"headers": [], "body": body}}))
    return rec


def _graph(home, endpoints, flows, rid=None):
    b = Board(home / "var" / "board.sqlite")
    rid = rid or b.run_start(P, "m")
    _jsonl(_work(home) / c.ENDPOINTS, endpoints)
    _jsonl(paths.flows_log(), [f(rid) if callable(f) else f for f in flows])
    g = Graph(b, _scope())
    g.sync(rid)
    return b, g, rid


def _eid(b, key):
    return b.rows("SELECT id FROM assets WHERE program=? AND kind='endpoint' AND key=?", P, key)[0]["id"]


# ------------------------------------------------------------------ T42: the score
def test_the_endpoint_seen_behind_the_login_goes_first(home):
    eps = [
        {"origin": ORIG, "key": "GET /pub/list", "params": ["q"], "source": "crawl"},
        {"origin": ORIG, "key": "GET /me/settings", "params": [], "source": "crawl"},
    ]
    # the gate saw both asked (a crawler), only the second under one of our identities
    flows = [
        lambda r: _flow(r, "https://a.t.test/pub/list?q=1", ua="katana"),
        lambda r: _flow(r, "https://a.t.test/me/settings", ua="katana", identity="user-a"),
    ]
    b, g, _ = _graph(home, eps, flows)
    pub, me = _eid(b, f"{ORIG} GET /pub/list"), _eid(b, f"{ORIG} GET /me/settings")
    assert g.signals(me)["identity"] == 1 and g.signals(pub)["identity"] == 0
    assert g.score(me) > g.score(pub)
    _, untested, _ = g.surface(c.REQUIRED_PHASES)
    assert [k for k, _ in untested] == [(ORIG, "GET /me/settings"), (ORIG, "GET /pub/list")]
    # without the score, the older order put the endpoint with a parameter first
    assert sorted(untested, key=c.frontier_order)[0][0] == (ORIG, "GET /pub/list")
    # deterministic: the same board, the same numbers and the same order
    assert [g.score(x) for x in (me, pub)] == [Graph(b, _scope()).score(x) for x in (me, pub)]
    assert g.surface(c.REQUIRED_PHASES)[1] == untested
    # the frontier shows the rank, never the number
    block = g.render(c.REQUIRED_PHASES)
    assert "  - #1 GET /me/settings" in block and "  - #2 GET /pub/list" in block
    assert str(g.score(me)) not in block and "score" not in block


def test_each_signal_comes_from_a_column_or_the_gate(home):
    eps = [
        {"origin": ORIG, "key": "POST /api/orders/{id}", "params": ["a", "b"], "source": "js"},
        {"origin": ORIG, "key": "GET /", "params": [], "source": "recon", "login_form": True},
    ]
    b, g, rid = _graph(home, eps, [])
    eid = _eid(b, f"{ORIG} POST /api/orders/{{id}}")
    s = g.signals(eid)
    assert (s["api"], s["write"], s["id_in_path"], s["param"], s["identity"]) == (1, 1, 1, 2, 0)
    assert s["new"] == 1  # first seen after the start of the latest run
    assert s["login"] == 0  # the sandbox's word alone: the gate saw no traffic to that origin
    assert s["cross_account_open"] == 1
    _jsonl(paths.flows_log(), [_flow(rid, "https://a.t.test/", ua="httpx")], append=True)
    g.sync(rid)
    assert g.signals(eid)["login"] == 1  # now the gate saw the origin
    # a cross-account class covered with the gate's word closes that signal; a sandbox claim (gate_seen 0) does not
    ins = (
        "INSERT INTO coverage_class(program, endpoint, vuln_class, outcome, run_id, ts, gate_seen) "
        "VALUES (?,?,?,?,?,?,?)"
    )
    b.db.execute(ins, (P, "POST /api/orders/{id}", "idor", "clean", rid, time.time(), 0))
    assert g.signals(eid)["cross_account_open"] == 1
    b.db.execute(ins, (P, "POST /api/orders/{id}", "idor", "clean", rid, time.time(), 1))
    assert g.signals(eid)["cross_account_open"] == 0
    expected = sum(assets.SCORE_WEIGHTS[k] * v for k, v in g.signals(eid).items())
    assert g.score(eid) == pytest.approx(expected)
    # an origin scores its best endpoint, a host its best origin; anything else 0
    oid = b.rows("SELECT id FROM assets WHERE program=? AND kind='origin' AND key=?", P, ORIG)[0]["id"]
    hid = b.rows("SELECT id FROM assets WHERE program=? AND kind='host' AND key='a.t.test'", P)[0]["id"]
    assert g.score(oid) == g.score(hid) == max(g.score(eid), g.score(_eid(b, f"{ORIG} GET /")))
    assert g.score(10**9) == 0.0
    # a later run: the endpoint is no longer new
    rid2 = b.run_start(P, "m")
    assert g.signals(eid)["new"] == 0 and rid2


def test_the_sandbox_cannot_claim_an_identity_or_a_fingerprint(home):
    eps = [
        {"origin": ORIG, "key": "GET /x", "source": "crawl", "identity_seen": True, "simhash": "0" * 16},
        {"origin": ORIG, "key": "GET /y", "source": "crawl", "login_form": "yes"},  # mistyped: the entry is dropped
    ]
    b, g, _ = _graph(home, eps, [])
    assert g.signals(_eid(b, f"{ORIG} GET /x"))["identity"] == 0
    assert not b.rows("SELECT 1 FROM assets WHERE key=?", f"{ORIG} GET /y")
    assert g.clusters() == {}


# ------------------------------------------------------------------ T42: the clones
def test_clones_by_the_home_page_the_gate_saw(home):
    o2, o3, o4 = "https://b.t.test:443", "https://c.t.test:443", "https://d.t.test:443"
    eps = [{"origin": o, "key": "GET /api/items", "params": [], "source": "crawl"} for o in (ORIG, o2, o3, o4)]
    other, clone = OTHER_PAGE, _home_page("bravo")
    flows = [
        lambda r: _flow(r, "https://a.t.test/", ua="httpx", body=HOME_WORDS),
        lambda r: _flow(r, "https://b.t.test/", ua="httpx", body=clone),  # the same template, another brand
        lambda r: _flow(r, "https://c.t.test/", ua="httpx", body=other),
        lambda r: _flow(r, "https://d.t.test/", ua="httpx"),  # no body kept: no fingerprint, no cluster
    ]
    _, g, rid = _graph(home, eps, flows)
    h1 = assets.simhash(HOME_WORDS)
    assert assets.hamming(h1, assets.simhash(clone)) <= assets.CLONE_HAMMING
    assert assets.hamming(h1, assets.simhash(other)) > assets.CLONE_HAMMING
    assert g.clusters() == {ORIG: [o2]}
    _, untested, _ = g.surface(c.REQUIRED_PHASES)
    assert {k[0] for k, _ in untested} == {ORIG, o3, o4}  # one origin of the cluster enters the list
    block = g.render(c.REQUIRED_PHASES)
    assert f"- {o2}: clone of {ORIG}" in block
    # a home page that is not a 2xx, or too short, gives no fingerprint
    assert assets.simhash("Not Found") is None
    _jsonl(paths.flows_log(), [_flow(rid, "https://c.t.test/", ua="httpx", status=500, body=HOME_WORDS)], append=True)
    g.sync(rid)
    assert g.clusters() == {ORIG: [o2]}


def test_no_body_seen_no_cluster_and_sandbox_files_are_not_read(home):
    o2 = "https://b.t.test:443"
    eps = [{"origin": o, "key": "GET /", "params": [], "source": "recon"} for o in (ORIG, o2)]
    (_work(home)).mkdir(parents=True, exist_ok=True)
    (_work(home) / "home.html").write_text(HOME_WORDS)  # a sandbox file is never a source
    _, g, _ = _graph(home, eps, [lambda r: _flow(r, "https://a.t.test/", ua="httpx")])
    assert g.clusters() == {}
    assert len(g.surface(c.REQUIRED_PHASES)[1]) == 2  # no cluster: both origins stay in the list


# ------------------------------------------------------------------ T18: technique cards
BASKET = "https://shop.acme.test/rest/basket/7?view=full"
OWNER = {"status": [200], "contains": ['"UserId":27']}
PROOF = {
    "steps": [
        {"name": "acme user-b reads its basket", "role": "setup", "as": "bob", "method": "GET", "url": BASKET,
         "expect": OWNER},
        {"name": "alice reads bob's", "role": "attack", "as": "alice", "method": "GET", "url": BASKET, "expect": OWNER},
        {"name": "anonymous", "role": "control", "as": None, "method": "GET", "url": BASKET,
         "expect": {"status": [401, 403]}},
    ]
}  # fmt: skip
REPLAY = {
    "reproduced": True,
    "control_disproves": False,
    "rounds": [
        [
            {"role": "setup", "status": 200, "ok": True},
            {"role": "attack", "status": 200, "ok": True},
            {"role": "control", "status": 403, "ok": True},
        ]
    ],
}
ACME = {"program": "acme", "platform": "x", "in_scope": ["*.acme.test"], "identities": []}


def _finding(b, status="verified", proof=PROOF, program="acme", url="https://shop.acme.test/rest/basket/7"):
    fid = b.add_finding(program, "acme basket of bob readable by alice", vuln_class="BOLA", url=url, proof=proof)
    b.finding_set(fid, replay=json.dumps(REPLAY))
    b.set_finding(fid, status)
    return fid


def _acme_scope(**kw):
    return scope_from_dict({**ACME, **kw})


def _card(b, iid):
    return dict(b.rows("SELECT * FROM mem_items WHERE id=?", iid)[0])


def test_a_clean_card_from_a_verified_finding(home):
    b = Board(home / "var" / "board.sqlite")
    iid = techniques.derive(b, _finding(b), scope=_acme_scope())
    assert iid is not None
    card = _card(b, iid)
    assert (card["program"], card["kind"], card["label"]) == ("*techniques*", "technique", "JUDGED")
    text = card["title"] + "\n" + card["summary"] + "\n" + card["ckey"]
    assert card["vuln_class"] == "idor" and "/rest/basket/{id}" in card["route"]
    assert "{user-a}" in text and "{user-b}" in text and "{anonymous}" in text and "{host}" in text
    assert "view={value}" in text
    for leak in ("acme", "bob", "alice", "shop", "UserId", "27", "basket of"):
        assert leak not in text.replace("/rest/basket/{id}", ""), leak
    assert "control showed: status 401/403 where the attack got 200" in card["summary"]
    assert "replayed by the host: reproduced, the control held" in card["summary"]
    # the same finding again: one row seen twice
    assert techniques.derive(b, _finding(b), scope=_acme_scope()) == iid
    assert _card(b, iid)["seen"] == 2


def test_refused_when_a_name_of_the_scope_survives(home):
    b = Board(home / "var" / "board.sqlite")
    steps = json.loads(json.dumps(PROOF))
    for s in steps["steps"]:
        s["url"] = "https://shop.acme.test/acme-portal/basket/7"
    assert techniques.derive(b, _finding(b, proof=steps), scope=_acme_scope()) is None
    # an identity's name in the route: refused too
    for s in steps["steps"]:
        s["url"] = "https://shop.acme.test/rest/users/alice/basket"
    assert techniques.derive(b, _finding(b, proof=steps), scope=_acme_scope()) is None
    # a host of the program's asset graph (out of scope, discovered) named by a body key: refused
    for s in steps["steps"]:
        s["url"] = "https://shop.acme.test/rest/basket/7"
        s["body"] = {"partnerco": 1}
    assets.ensure(b)
    b.db.execute(
        "INSERT INTO assets(program, kind, key, in_scope, first_seen, last_seen) "
        "VALUES ('acme','host','partnerco.example',0,0,0)"
    )
    assert techniques.derive(b, _finding(b, proof=steps), scope=_acme_scope()) is None
    store.ensure(b)
    assert not b.rows("SELECT 1 FROM mem_items WHERE program='*techniques*'")
    # no scope found for the program: refused (in doubt, no card)
    assert techniques.derive(b, _finding(b)) is None


def test_a_rejected_or_open_finding_gives_nothing(home):
    b = Board(home / "var" / "board.sqlite")
    for status in ("rejected", "new", "inconclusive", "needs-proof"):
        assert techniques.derive(b, _finding(b, status=status), scope=_acme_scope()) is None
    assert techniques.derive(b, 10**6, scope=_acme_scope()) is None
    assert not b.rows("SELECT 1 FROM sqlite_master WHERE name='mem_items'") or not b.rows(
        "SELECT 1 FROM mem_items WHERE program='*techniques*'"
    )


def test_the_scope_is_found_by_the_program_name(home):
    (home / "scopes").mkdir()
    (home / "scopes" / "acme.yaml").write_text(json.dumps(ACME))
    b = Board(home / "var" / "board.sqlite")
    assert techniques.derive(b, _finding(b)) is not None


def test_an_observation_without_proof_uses_the_finding_url(home):
    b = Board(home / "var" / "board.sqlite")
    iid = techniques.derive(b, _finding(b, status="verified-evidence", proof=None), scope=_acme_scope())
    card = _card(b, iid)
    assert "evidence the host observed" in card["summary"] and "/rest/basket/{id}" in card["title"]


# ------------------------------------------------------------------ T18: the one reader
def test_techniques_are_read_through_their_mode_only(home):
    b = Board(home / "var" / "board.sqlite")
    iid = techniques.derive(b, _finding(b), scope=_acme_scope())
    store.put(b, {"program": "other", "kind": "test", "label": "NOTE", "host": "x.other.test", "method": "GET",
                  "route": "/rest/basket/1", "vuln_class": "idor", "title": "basket idor tried on other"})  # fmt: skip
    text = recall.navigate(b, P, "techniques", "idor basket")
    assert f"#{iid}" in text and "{user-a}" in text
    data = re.search(r"<lineage-data-(\w+)>\n(.*)\n</lineage-data-\1>", text, re.S)
    assert data and len(data.group(2).splitlines()) <= recall.TECHNIQUE_LINES
    assert "other" not in text
    assert "0 cards" in recall.navigate(b, P, "techniques", "smuggling")
    # a normal search, map or full never returns a card nor another program's item
    for q in ("idor basket", "basket", "technique"):
        res = recall.search(b, P, q)
        assert res["verdict"] == "NEW" and not res["hits"], res
    assert "nothing on record" in recall.navigate(b, P, "map")
    assert "no such item" in recall.navigate(b, P, "full", str(iid))
    # the partition is never a program
    assert recall.navigate(b, techniques.TECHNIQUES, "map") == recall.UNAVAILABLE_LINE
    assert recall.search(b, techniques.TECHNIQUES, "idor")["verdict"] == "UNAVAILABLE"


def test_the_client_asks_for_techniques():
    req = client.parse(["--techniques", "idor on a basket route"])
    assert req["mode"] == "techniques" and req["arg"] == "idor on a basket route" and req["query"] is None
    with pytest.raises(SystemExit):
        client.parse(["--techniques", "x", "--url", "https://a/"])
    from bh.lineage import serve

    assert "techniques" in serve.MODES


# ------------------------------------------------------------------ T49: the white-box lane
SHA = "a" * 40
REPO = "https://github.com/example-org/shop-api.git"


def _fake_git(monkeypatch, head=SHA):
    calls = []

    def run(*args, cwd=None):
        calls.append(args)
        if args[0] == "init":
            (paths.Path(args[-1]) / ".git").mkdir(parents=True)
        elif args[0] == "checkout":
            (cwd / "app").mkdir()
            (cwd / "app" / "routes.py").write_text("ROUTES = []\n")
        elif args[0] == "rev-parse":
            return head + "\n"
        return ""

    monkeypatch.setattr(whitebox, "_git", run)
    return calls


def test_fetch_pins_the_commit_without_network(home, monkeypatch):
    calls = _fake_git(monkeypatch)
    d = whitebox.fetch(REPO, SHA)
    assert d == home / "var" / "tools" / "whitebox" / f"shop-api@{SHA}"
    assert (d / "app" / "routes.py").is_file() and not (d / ".git").exists()
    assert json.loads((d / whitebox.MARK).read_text())["commit"] == SHA
    assert [a[0] for a in calls] == ["init", "fetch", "checkout", "rev-parse"]
    assert calls[1][-2:] == (REPO, SHA)
    assert whitebox.fetch(REPO, SHA) == d and len(calls) == 4  # already there: no git
    _fake_git(monkeypatch, head="b" * 40)
    with pytest.raises(whitebox.WhiteboxError):
        whitebox.fetch(REPO, "c" * 40)
    assert not list((home / "var" / "tools" / "whitebox").glob(".*tmp"))
    for url, sha in (("http://github.com/a/b", SHA), ("https://u:p@github.com/a/b", SHA), (REPO, "abc123")):
        with pytest.raises(whitebox.WhiteboxError):
            whitebox.fetch(url, sha)


def test_without_the_key_nothing_is_mounted_nor_offered(home, monkeypatch):
    _fake_git(monkeypatch)
    whitebox.fetch(REPO, SHA)
    mount = home / "var" / "whitebox-mount"
    mount.mkdir(parents=True)
    (mount / f"leftover@{SHA}").mkdir()  # another program's repository from the last segment
    doc = {"program": P, "platform": "x", "in_scope": ["*.t.test"]}
    assert not whitebox.declared(doc) and not whitebox.declared(_scope())
    assert whitebox.stage(doc) == ([], []) and list(mount.iterdir()) == []
    assert whitebox.task_line([]) is None


def test_with_the_key_its_repositories_only_are_mounted(home, monkeypatch, tmp_path):
    _fake_git(monkeypatch)
    whitebox.fetch(REPO, SHA)
    other = {"repo": "https://github.com/example-org/not-fetched", "commit": "d" * 40}
    doc = {"program": P, "whitebox": [{"repo": REPO, "commit": SHA}, other]}
    assert whitebox.declared(doc)
    f = tmp_path / "scope.yaml"
    f.write_text(json.dumps(doc))
    assert whitebox.entries(f) == whitebox.entries(doc)
    # a Scope that carries the key (lot A) is read the same way; one without the attribute declares nothing
    assert whitebox.entries(SimpleNamespace(whitebox=tuple(doc["whitebox"]))) == whitebox.entries(doc)
    assert not whitebox.declared(SimpleNamespace(program=P))
    mounted, missing = whitebox.stage(doc)
    assert mounted == [f"shop-api@{SHA}"] and missing == [f"not-fetched@{'d' * 40}"]
    assert (home / "var" / "whitebox-mount" / mounted[0] / "app" / "routes.py").is_file()
    assert (home / "var" / "whitebox-mount" / whitebox.METHOD).read_text() == whitebox.METHOD_SRC.read_text()
    line = whitebox.task_line(mounted)
    assert f"/opt/bh/whitebox/shop-api@{SHA}/" in line and "/opt/bh/whitebox/METHOD.md" in line and "read-only" in line
    # declared but none fetched: nothing mounted, the method neither
    assert whitebox.stage({"program": P, "whitebox": [other]}) == ([], [f"not-fetched@{'d' * 40}"])
    assert list((home / "var" / "whitebox-mount").iterdir()) == []
    for bad in ([{"repo": REPO}], [{"repo": REPO, "commit": SHA, "x": 1}], "x", [{"repo": "ftp://h/a", "commit": SHA}]):
        with pytest.raises(whitebox.WhiteboxError):
            whitebox.entries({"whitebox": bad})


def test_the_method_is_not_in_the_catalogue_offered_to_every_program():
    # a catalogue skill would be offered to every program (the runner filters on `requires: scanners` only)
    assert "whitebox" not in {s["name"] for s in classes.all_skills()}
    assert not (classes.skills_dir() / "whitebox" / classes.SKILL_FILE).exists()
    text = whitebox.METHOD_SRC.read_text()
    meta = classes.skill_frontmatter(text)
    assert meta["name"] == "whitebox" and "requires" not in meta
    assert meta["description"].startswith("Use when") and len(meta["description"]) <= classes.DESCRIPTION_MAX
    assert "proof.json" in text and "--kind test" in text and "data" in text and "read-only" in text
    assert not classes.SCANNER_WORDS.search(text)
