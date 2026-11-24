import json

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
    todos = [r["title"] for r in b.rows("SELECT title FROM todos")]
    assert any("evil.other.test" in t and "not in scope" in t for t in todos)
    oos = b.rows("SELECT in_scope FROM assets WHERE key='evil.other.test'")[0]["in_scope"]
    assert oos == 0
    fid = b.add_finding("p", "IDOR", vuln_class="idor", url="https://a.t.test/api/Users/12")
    g.link("https://a.t.test/api/Users/12", "finding", fid)
    assert b.rows("SELECT COUNT(*) n FROM asset_links WHERE ref_kind='finding'")[0]["n"] == 1
