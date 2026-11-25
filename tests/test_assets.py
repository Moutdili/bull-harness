import json
import time

from bh.agent import contract as c
from bh.assets import Graph
from bh.board import Board
from bh.scope import scope_from_dict


def _write(path, recs):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in recs))


def test_graph_from_sandbox_and_gate(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    scope = scope_from_dict({"program": "p", "platform": "x", "in_scope": ["*.t.test"]})
    b = Board(tmp_path / "var" / "board.sqlite")
    rid = b.run_start("p", "m")
    o = "https://a.t.test:443"
    d = tmp_path / "var" / "work" / "p" / ".bh"
    _write(
        d / c.ENDPOINTS,
        [
            {"origin": o, "key": "GET /api/Users/", "params": [], "source": "js"},
            {"origin": o, "key": "GET /search", "params": ["q"], "source": "crawl"},
            {"origin": o, "key": "GET /main.js", "params": [], "source": "crawl"},
        ],
    )
    c.write_json(
        d / c.COVERAGE, {o: {"crawl": {"status": "ok"}, "content": {"status": "ok"}, "scan": {"status": "error rc=1"}}}
    )
    _write(
        tmp_path / "var" / "state" / "flows.jsonl",
        [
            {"run": rid, "class": "target", "method": "GET", "url": "https://a.t.test/api/Users/12", "ua": "curl/8.1"},
            {
                "run": rid,
                "class": "target",
                "method": "GET",
                "url": "https://a.t.test/search?q=x",
                "ua": "Fuzz Faster U Fool",
                "status": 200,
            },
            # a scanner probe that found nothing: not an endpoint (nuclei paths flooded the lab frontier)
            {
                "run": rid,
                "class": "target",
                "method": "GET",
                "url": "https://a.t.test/_matrix/v1",
                "ua": "Nuclei",
                "status": 404,
            },
            {"run": None, "class": "target", "method": "GET", "url": "https://a.t.test/search", "ua": "curl/8.1"},
            {"run": rid, "class": "target", "method": "GET", "url": "https://evil.other.test/", "ua": "katana"},
        ],
    )
    g = Graph(b, scope)
    g.sync(rid)
    phases = c.REQUIRED_PHASES
    assert g.counts(phases) == (1, 2)  # /api/Users/{id} tested by hand; scan errored -> not covered
    block = g.render(phases)
    assert "2 endpoints (1 with params), 1 tested, 1 untested" in block and "main.js" not in block
    assert "evil.other.test" in block  # discovered, shown as not in scope
    assert b.rows("SELECT COUNT(*) n FROM todos")[0]["n"] == 0  # recorded, nobody is asked
    assert g.new_out_of_scope == ["evil.other.test"]
    oos = b.rows("SELECT in_scope FROM assets WHERE key='evil.other.test'")[0]["in_scope"]
    assert oos == 0
    fid = b.add_finding("p", "IDOR", vuln_class="idor", url="https://a.t.test/api/Users/12")
    g.link("https://a.t.test/api/Users/12", "finding", fid)
    assert b.rows("SELECT COUNT(*) n FROM asset_links WHERE ref_kind='finding'")[0]["n"] == 1


def test_forged_sandbox_files_do_not_count_as_progress(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    scope = scope_from_dict({"program": "p", "platform": "x", "in_scope": ["*.t.test"]})
    b = Board(tmp_path / "var" / "board.sqlite")
    rid = b.run_start("p", "m")
    o = "https://never.t.test:443"
    d = tmp_path / "var" / "work" / "p" / ".bh"
    _write(d / c.TOUCHED, [{"origin": o, "key": f"GET /api/x{i}", "via": "tool"} for i in range(200)])
    c.write_json(d / c.COVERAGE, {o: {p: {"status": "ok"} for p in c.REQUIRED_PHASES}})
    _write(tmp_path / "var" / "state" / "flows.jsonl", [])
    g = Graph(b, scope)
    g.sync(rid)
    assert g.counts(c.REQUIRED_PHASES) == (0, 0)  # the gate saw nothing: claims are not progress
    _write(
        tmp_path / "var" / "state" / "flows.jsonl",
        [{"run": rid, "class": "target", "method": "GET", "url": "https://never.t.test/api/x1", "ua": "sqlmap/1.9"}],
    )
    g.sync(rid)
    assert g.counts(c.REQUIRED_PHASES) == (1, len(c.REQUIRED_PHASES))  # claim + gate traffic: counted


def test_blocked_host_leaves_untested_until_its_deadline(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    scope = scope_from_dict({"program": "p", "platform": "x", "in_scope": ["*.t.test"]})
    g = Graph(Board(tmp_path / "var" / "board.sqlite"), scope)
    g.endpoint("https://a.t.test:443", "GET /api/a", "crawl")
    g.endpoint("https://b.t.test:443", "GET /api/b", "crawl")
    g.mark_blocked("a.t.test", "waf", time.time() + 3600)
    _, untested, _ = g.surface(c.REQUIRED_PHASES)
    assert [k for k, _ in untested] == [("https://b.t.test:443", "GET /api/b")]
    block = g.render(c.REQUIRED_PHASES)
    assert "a.t.test: blocked (waf) until " in block and "/api/a" not in block
    g.mark_blocked("a.t.test", "waf", time.time() - 1)  # deadline passed: back in the list
    assert len(g.surface(c.REQUIRED_PHASES)[1]) == 2 and "blocked" not in g.render(c.REQUIRED_PHASES)


def test_program_reset_forgets_the_asset_graph(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    b = Board(tmp_path / "board.sqlite")
    scope = scope_from_dict({"program": "p", "platform": "x", "in_scope": ["a.t.test"]})
    g = Graph(b, scope)
    g.tested("https://a.t.test", "GET /api/x", "gate", None)
    other = Graph(b, scope_from_dict({"program": "q", "platform": "x", "in_scope": ["b.t.test"]}))
    other.tested("https://b.t.test", "GET /api/y", "gate", None)
    b.db.commit()
    assert b.reset_program("p")["assets"] >= 1
    assert not b.rows("SELECT 1 FROM assets WHERE program='p'")
    assert b.rows("SELECT 1 FROM assets WHERE program='q'")  # other programs keep theirs
    assert b.rows("SELECT COUNT(*) n FROM tests")[0]["n"] == 1


def test_malformed_sandbox_values_are_skipped_never_fatal(tmp_path, monkeypatch):
    """M4: a dict or a list where a string is expected drops that entry; sync never raises."""
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    scope = scope_from_dict({"program": "p", "platform": "x", "in_scope": ["*.t.test"]})
    b = Board(tmp_path / "var" / "board.sqlite")
    o = "https://a.t.test:443"
    d = tmp_path / "var" / "work" / "p" / ".bh"
    _write(
        d / c.ENDPOINTS,
        [
            [1],
            "text",
            {"origin": o, "key": {"a": 1}},
            {"origin": o, "key": "GET /x", "source": {"a": 1}},
            {"origin": o, "key": "GET /y", "status": [200]},
            {"origin": o, "key": "GET /z", "params": {"q": 1}},
            {"origin": [o], "key": "GET /w"},
            {"origin": o, "key": "GET /ok", "params": ["q", {"x": 1}], "status": 200},
        ],
    )
    c.write_json(
        d / c.COVERAGE,
        {
            o: {
                "crawl": {"status": {"a": 1}},
                "content": {"status": "ok", "ts": [1]},
                "scan": {"status": "ok", "raw": ["x"]},
                "recon": {"status": "ok", "ts": 10**400},
                "params": {"status": "ok", "ts": 1.5, "raw": "/work/x"},
            },
            "https://b.t.test:443": [1],
        },
    )
    _write(d / c.TOUCHED, [[1], {"origin": o, "key": "GET /t", "via": {"a": 1}}, {"origin": o, "key": ["x"]}])
    _write(tmp_path / "var" / "state" / "flows.jsonl", [])
    n = Graph(b, scope).sync(None)
    assert n["endpoints"] == 1 and n["coverage"] == 1 and n["tests"] == 0
    keys = {r["key"] for r in b.rows("SELECT key FROM assets WHERE kind='endpoint'")}
    assert keys == {f"{o} GET /ok"}
    assert [tuple(r) for r in b.rows("SELECT phase, status, ts, raw FROM coverage")] == [
        ("params", "ok", 1.5, "/work/x")
    ]
