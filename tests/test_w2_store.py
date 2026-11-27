"""W2-B: the memory store of the lineage (bh.lineage: key, store, export, embed)."""

from __future__ import annotations

import ast
import json
import re
import time
from pathlib import Path

import pytest

from bh import assets
from bh.board import Board
from bh.board import db as board_db
from bh.lineage import embed, export, key, store

SRC = Path(__file__).resolve().parents[1] / "src"
CANARY = "BH-SECRET-0123456789abcdef"


@pytest.fixture
def board(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    b = Board(tmp_path / "var" / "board.sqlite")
    store.ensure(b)
    return b


def _item(**kw):
    base = {
        "program": "p",
        "kind": "dead-end",
        "label": "NOTE",
        "host": "a.t.test",
        "method": "GET",
        "route": "/api/users/1",
        "vuln_class": "idor",
        "title": "user-a cannot read the basket of user-b",
        "summary": "403 on every id",
        "agent_no": 1,
    }
    return base | kw


def _count(b, where="program='p'"):
    return b.db.execute(f"SELECT COUNT(*) FROM mem_items WHERE {where}").fetchone()[0]


# ------------------------------------------------------------------ D2: canonical key
def test_key_ignores_case_identity_order_and_path_ids():
    k1 = key.canonical("A.T.test", "get", "/api/Users/12", "IDOR", "Swap-ID", ("user-b", "User-A"))
    k2 = key.canonical("a.t.test", "GET", "/api/users/7", "idor", "swap-id", ["user-a", "user-b"])
    k3 = key.canonical(
        "https://a.t.test:443",
        "GET",
        "https://a.t.test/api/users/99?x=1",
        "Insecure Direct Object Reference",
        "swap-id",
        "user-b,user-a",
    )
    assert k1 == k2 == k3 == "a.t.test|get /api/users/{id}|idor|swap-id|user-a,user-b"
    assert k1 == k1.lower()
    assert key.cell(k1) == "a.t.test|get /api/users/{id}|idor"
    # the collection and the item stay distinct, a JS literal ending in / is the item route
    assert key.canonical("h", "GET", "/api/users", "") != key.canonical("h", "GET", "/api/users/3", "")
    assert key.canonical("h", "GET", "/api/users/", "") == key.canonical("h", "GET", "/api/users/3", "")
    # another port is another service; the separators never leak from a field
    assert key.canonical("h:8443", "GET", "/", "").startswith("h:8443|")
    assert key.canonical("h", "GET", "/", "", "a|b, c").count("|") == 4


# ------------------------------------------------------------------ schema
CONTRACT = {
    "mem_items": "id program kind ckey cell host route vuln_class technique identities outcome label title summary "
    "agent_no run_id src_kind src_id valid_from valid_to superseded_by seen text_hash created",
    "mem_receipts": "id program agent_no run_id query ckey verdict hits ts",
    "agents": "no pseudo program generation parent_no run_id setup_sha256 birth_sha256 relaunch_of born closed status",
    "blocks": "no program prev_hash block_hash body ts",
    "ledger": "id program agent_no signal points ref_kind ref_id ts",
}


def test_ensure_creates_the_contract_tables_idempotently(board):
    store.ensure(board)
    store.ensure(board)
    for table, cols in CONTRACT.items():
        assert [r[1] for r in board.db.execute(f"PRAGMA table_info({table})")] == cols.split()
    assert board.db.execute("SELECT 1 FROM sqlite_master WHERE name='mem_fts'").fetchone()
    assert not set(store.TABLES) & set(board_db.PROGRAM_TABLES)
    # a plain reset keeps the lineage
    store.put(board, _item())
    board.reset_program("p")
    assert _count(board) == 1


# ------------------------------------------------------------------ D3: full-text index
def test_index_is_redacted_and_canaries_hidden(board):
    iid = store.put(
        board,
        _item(
            title=f"canary {CANARY} crossed to user-a",
            summary="replayed with\nAuthorization: Bearer abcdefgh12345678\nthe tested baskets leak",
        ),
    )
    assert store.fts_mode(board) == "fts5"
    title, summary = board.db.execute("SELECT title, summary FROM mem_fts WHERE rowid=?", (iid,)).fetchone()
    for text in (title, summary, *board.db.execute("SELECT title, summary FROM mem_items").fetchone()):
        assert CANARY not in text and "abcdefgh12345678" not in text
    assert "<canary>" in title and "<redacted:authorization>" in summary
    # porter stems: "testing" finds "tested"; program isolation
    assert [r["id"] for r in store.search(board, "p", "testing basket")] == [iid]
    assert store.search(board, "other", "basket") == []


def test_like_fallback_when_fts5_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "fts5_available", lambda: False)
    b = Board(tmp_path / "board.sqlite")
    store.ensure(b)
    assert store.fts_mode(b) == "like"
    iid = store.put(b, _item(title=f"basket_leak {CANARY}"))
    store.put(b, _item(program="q", title="basket_leak elsewhere"))
    assert "<canary>" in b.db.execute("SELECT title FROM mem_fts WHERE id=?", (iid,)).fetchone()[0]
    assert [r["id"] for r in store.search(b, "p", "basket_leak")] == [iid]
    assert store.search(b, "p", "nothing%here") == []
    assert store.purge(b, "p")["mem_fts"] == 1


def test_fts5_probe_reads_this_sqlite():
    assert isinstance(store.fts5_available(), bool)


# ------------------------------------------------------------------ D5: dated and superseded
def test_supersede_closes_the_old_item_and_links_the_new(board):
    old = store.put(board, _item(kind="candidate", title="maybe idor on baskets"))
    new = store.supersede(board, old, _item(kind="dead-end", title="no idor on baskets", outcome="ruled_out"))
    o = board.db.execute("SELECT * FROM mem_items WHERE id=?", (old,)).fetchone()
    n = board.db.execute("SELECT * FROM mem_items WHERE id=?", (new,)).fetchone()
    assert o["valid_to"] is not None and o["superseded_by"] == new
    assert n["valid_to"] is None and n["valid_from"] >= o["valid_from"]
    assert _count(board) == 2  # the old one stays readable
    assert [r["id"] for r in store.search(board, "p", "baskets")] == [new]
    assert {r["id"] for r in store.search(board, "p", "baskets", current=False)} == {old, new}
    with pytest.raises(ValueError):
        store.supersede(board, old, _item())  # already closed
    with pytest.raises(ValueError):
        store.supersede(board, new, _item(program="q"))  # another program


def test_purge_forgets_one_program_only(board, tmp_path):
    store.put(board, _item())
    store.put(board, _item(program="q"))
    leads = _write(tmp_path / "leads.jsonl", [_lead()])
    assert store.import_items(board, "p", leads) == store.import_items(board, "q", leads) == (1, 0)
    board.meta_set("lineage-import:xp", "[]")  # a program whose name ends like p's
    out = store.purge(board, "p")
    assert out["mem_items"] == 2
    assert _count(board) == 0 and _count(board, "program='q'") == 2
    assert board.meta_get("lineage-import:q") and board.meta_get("lineage-import:xp")
    assert store.import_items(board, "p", leads) == (1, 0)  # its import cursor went with it


def _deletes_mem_items(src: str) -> list[int]:
    return [src.count("\n", 0, m.start()) + 1 for m in re.finditer(r"\bDELETE\b[^;]{0,80}?\bmem_items\b", src, re.I)]


def test_no_delete_on_mem_items_outside_purge():
    allowed = set()
    tree = ast.parse((SRC / "bh/lineage/store.py").read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "purge":
            allowed = set(range(node.lineno, node.end_lineno + 1))
    assert allowed
    offenders = []
    for path in SRC.rglob("*.py"):
        lines = _deletes_mem_items(path.read_text())
        if path.name == "store.py" and path.parent.name == "lineage":
            lines = [n for n in lines if n not in allowed]
        offenders += [f"{path.relative_to(SRC)}:{n}" for n in lines]
    assert offenders == []
    assert _deletes_mem_items("x = 'DELETE FROM mem_items WHERE 1'")  # the detector itself works


# ------------------------------------------------------------------ D6: dedup at write time
def test_same_key_same_text_is_one_row_seen_twice(board):
    a = store.put(board, _item(title="User-A cannot read  the basket of user-b", route="/api/users/3"))
    b = store.put(board, _item(title="user-a cannot read the basket of USER-B"))
    assert a == b and _count(board) == 1
    assert board.db.execute("SELECT seen FROM mem_items WHERE id=?", (a,)).fetchone()[0] == 2


def test_same_key_near_title_merges_into_the_oldest(board):
    a = store.put(board, _item(title="idor baskets user-a reads user-b basket ruled out by 403"))
    b = store.put(board, _item(title="idor baskets user-a reads user-b basket ruled out by 403 again", summary="x"))
    assert (
        store.jaccard(
            "idor baskets user-a reads user-b basket ruled out by 403",
            "idor baskets user-a reads user-b basket ruled out by 403 again",
        )
        >= 0.8
    )
    assert a == b and _count(board) == 1
    row = board.db.execute("SELECT seen, summary FROM mem_items WHERE id=?", (a,)).fetchone()
    assert row["seen"] == 2 and row["summary"] == "403 on every id"  # the oldest is kept


def test_other_key_or_doubt_does_not_merge(board):
    store.put(board, _item())
    store.put(board, _item(vuln_class="xss"))  # another key, same text
    store.put(board, _item(title="mass assignment on the profile"))  # same key, other title
    store.put(board, _item(outcome="ruled_out"))  # same key and text, another outcome
    store.put(board, _item(label="ANCHORED"))  # another label
    store.put(board, _item(src_kind="operator", agent_no=0))  # the operator's word is not the agent's
    store.put(board, _item(program="q"))  # another program
    assert _count(board) == 6 and _count(board, "program='q'") == 1


def test_put_refuses_a_bad_item(board):
    for bad in ({"kind": "nope"}, {"label": "VERIFIED"}, {"outcome": "maybe"}, {"title": " "}, {"program": ""}):
        with pytest.raises(ValueError):
            store.put(board, _item(**bad))


# ------------------------------------------------------------------ D2 (ingestion of a run), D13 (run summary)
LOT_A_FACTS = (
    "grounded INTEGER",
    "why TEXT",
    "endpoint TEXT",
    "vuln_class TEXT",
    "outcome TEXT",
    "technique TEXT",
    "identities TEXT",
)


def _lot_a(b):
    have = {r[1] for r in b.db.execute("PRAGMA table_info(facts)")}  # lot A ships some of them since W2
    for col in LOT_A_FACTS:
        if col.split()[0] not in have:
            b.db.execute(f"ALTER TABLE facts ADD COLUMN {col}")
    b.db.execute(
        "CREATE TABLE IF NOT EXISTS coverage_class (program TEXT, endpoint TEXT, vuln_class TEXT, outcome TEXT, "
        "evidence TEXT, run_id INTEGER, ts REAL, gate_seen INTEGER)"
    )


def _fact(b, rid, kind, title, **cols):
    fid = b.add_fact("p", title, cols.pop("summary", ""), cols.pop("evidence", ""), kind=kind, run_id=rid)
    if cols:
        b.db.execute(f"UPDATE facts SET {', '.join(f'{k}=?' for k in cols)} WHERE id=?", (*cols.values(), fid))
    return fid


def _hunt(b):
    """A run of program p as lot A will leave it: coverage by class, grounded facts, findings, a handoff."""
    _lot_a(b)
    rid = b.run_start("p", "m")
    b.run_end(
        rid, status="done", turns=40, cost_usd=1.5, gate_requests=120, gate_denied=3, gate_errors=1, gate_pushback=0
    )
    users, orders = "https://a.t.test:443 GET /api/users/{id}", "https://a.t.test:443 GET /api/orders/{id}"
    now = time.time()
    b.db.executemany(
        "INSERT INTO coverage_class VALUES (?,?,?,?,?,?,?,?)",
        [
            ("p", users, "idor", "ruled_out", "403 for user-a on user-b's ids", rid, now, 1),
            ("p", orders, "idor", "open_proof_gap", "never sent", rid, now, 0),
            ("q", users, "idor", "confirmed", "other program", rid, now, 1),
        ],
    )
    f = {
        "anchored": _fact(
            b,
            rid,
            "dead-end",
            "no idor on users",
            grounded=1,
            endpoint="GET https://a.t.test/api/users/12",
            vuln_class="idor",
            outcome="ruled-out",
            why="not-vulnerable",
            identities='["user-b","user-a"]',
            summary=f"canary {CANARY} never crossed",
        ),
        "unseen": _fact(b, rid, "dead-end", "no idor on orders", grounded=1, endpoint=orders, vuln_class="idor"),
        "think": _fact(b, rid, "think", "the ids look sequential", grounded=0, endpoint=users),
        "candidate": _fact(
            b, rid, "candidate", "export endpoint may leak", endpoint="POST https://a.t.test/api/export"
        ),
        "plain": _fact(b, rid, "fact", "a plain fact is not ingested"),
    }
    b.add_blocker("p", "waf", "cloudflare challenge on /admin", run_id=rid, host="a.t.test")
    _fact(
        b, rid, "handoff", "HANDOFF: users done", summary="state: users done\ndead: idor users\nnext: orders\nfiles: x"
    )
    proof = {
        "steps": [
            {"role": "setup", "as": "user-b", "method": "GET", "url": "https://a.t.test/api/carts/7"},
            {"role": "attack", "as": "user-a", "method": "GET", "url": "https://a.t.test/api/carts/7"},
        ]
    }
    fv = b.add_finding(
        "p",
        "user-a reads user-b's cart",
        rid,
        vuln_class="idor",
        url="https://a.t.test/api/carts/7",
        severity="high",
        proof=proof,
    )
    b.set_finding(fv, "verified", "The attack returned user-b's cart; the control was refused.\n\nDetails follow.")
    b.add_finding("p", "still waiting for the verifier", rid, vuln_class="xss")
    assets.ensure(b)
    b.db.execute(
        "INSERT INTO assets(program, kind, key, first_seen, last_seen) VALUES ('p','endpoint',?,0,0)", (users,)
    )
    b.db.execute("INSERT INTO tests(asset_id, evidence, run_id, ts) VALUES (last_insert_rowid(), 'gate', ?, 0)", (rid,))
    b.db.commit()
    return rid, f, fv


def _by_src(b, src_kind, src_id):
    return b.db.execute(
        "SELECT * FROM mem_items WHERE program='p' AND src_kind=? AND src_id=? AND valid_to IS NULL",
        (src_kind, str(src_id)),
    ).fetchone()


def test_ingest_run_labels_come_from_the_gate_and_the_judge(board):
    rid, f, fv = _hunt(board)
    n = store.ingest_run(board, "p", rid, 3)
    assert n == _count(board) == 10  # 1 test, 2 coverage, 1 finding, 5 notes (the blocker too), 1 summary
    anchored = _by_src(board, "fact", f["anchored"])
    assert anchored["label"] == "ANCHORED" and anchored["outcome"] == "ruled_out" and anchored["agent_no"] == 3
    assert anchored["ckey"] == "a.t.test|get /api/users/{id}|idor||user-a,user-b"
    assert "<canary>" in anchored["summary"] and CANARY not in anchored["summary"]
    assert _by_src(board, "fact", f["unseen"])["label"] == "NOTE"  # grounded, but the gate never saw orders
    assert _by_src(board, "fact", f["think"])["label"] == "NOTE"  # seen endpoint, not grounded
    assert _by_src(board, "fact", f["candidate"])["label"] == "NOTE"
    assert _by_src(board, "fact", f["plain"]) is None
    blocker = board.db.execute("SELECT * FROM mem_items WHERE kind='blocker'").fetchone()
    assert blocker["label"] == "NOTE" and blocker["host"] == "a.t.test"
    finding = _by_src(board, "finding", fv)
    assert finding["label"] == "JUDGED" and finding["outcome"] == "confirmed"
    assert finding["ckey"] == "a.t.test|get /api/carts/{id}|idor||user-a,user-b"
    assert finding["summary"] == "[verified/high] The attack returned user-b's cart; the control was refused."
    test = board.db.execute("SELECT * FROM mem_items WHERE src_kind='test'").fetchone()
    assert test["label"] == "OBSERVED" and test["route"] == "get /api/users/{id}"
    cov = {r["route"]: r["label"] for r in board.db.execute("SELECT * FROM mem_items WHERE src_kind='coverage'")}
    assert cov == {"get /api/users/{id}": "OBSERVED", "get /api/orders/{id}": "NOTE"}
    # never OBSERVED where the gate did not see the endpoint
    seen = {"a.t.test|get /api/users/{id}"}
    for r in board.db.execute("SELECT ckey FROM mem_items WHERE label='OBSERVED'"):
        assert key.endpoint(r["ckey"]) in seen
    assert _count(board, "program='q'") == 0


def test_run_summary_skeleton_then_handoff_notes(board):
    rid, _, _ = _hunt(board)
    store.ingest_run(board, "p", rid, 3)
    s = board.db.execute("SELECT * FROM mem_items WHERE kind='run-summary'").fetchone()
    lines = s["summary"].splitlines()
    assert len(lines) <= store.SUMMARY_LINES
    assert lines[0] == f"run {rid} · agent 3 · done · 40 turns · $1.50"
    assert lines[1] == "gate: 120 requests, 3 denied, 1 errors, 0 pushed back"
    assert lines[2] == "findings: new 1, verified 1"
    assert lines[3] == "coverage: idor 2 (gate-seen 1)"
    assert lines[4] == "blockers: 1 (waf 1)"
    assert lines[5:] == [
        "[NOTE] state: users done",
        "[NOTE] dead: idor users",
        "[NOTE] next: orders",
        "[NOTE] files: x",
    ]
    assert s["label"] == "NOTE" and s["cell"] == "||"


def test_ingest_run_is_idempotent_and_supersedes_what_changed(board):
    rid, _, fv = _hunt(board)
    store.ingest_run(board, "p", rid, 3)
    before = _count(board)
    assert store.ingest_run(board, "p", rid, 3) == 0
    assert _count(board) == before
    assert board.db.execute("SELECT MAX(seen) FROM mem_items").fetchone()[0] == 1
    old = _by_src(board, "finding", fv)["id"]
    board.set_finding(fv, "submitted")
    assert store.ingest_run(board, "p", rid, 3) == 2  # the finding, and the summary (findings: submitted 1)
    new = _by_src(board, "finding", fv)
    assert new["summary"].startswith("[submitted/high]")
    assert board.db.execute("SELECT superseded_by FROM mem_items WHERE id=?", (old,)).fetchone()[0] == new["id"]


def test_ingest_run_of_another_program_reads_nothing(board):
    rid, _, _ = _hunt(board)
    assert store.ingest_run(board, "q", rid, 1) == 0
    assert _count(board, "1") == 0


def test_ingest_run_without_lot_a_columns(board):
    """Columns lot A adds read as empty: a note is NOTE, no coverage by class, the summary still comes."""
    rid = board.run_start("p", "m")
    fid = board.add_fact("p", "no sqli on search", kind="dead-end", run_id=rid)
    assert store.ingest_run(board, "p", rid, 1) == 2
    assert _by_src(board, "fact", fid)["label"] == "NOTE"


# ------------------------------------------------------------------ D7: Markdown export
def test_export_is_deterministic_and_labelled(board, tmp_path):
    rid, _, _ = _hunt(board)
    store.ingest_run(board, "p", rid, 3)
    old = store.put(board, _item(kind="candidate", title="# not a heading <b>x</b>", route="/api/zz"))
    store.supersede(board, old, _item(kind="dead-end", title="closed", route="/api/zz"))
    store.put(board, _item(program="q", title="secret of q"))
    p1 = export.markdown(board, "p", tmp_path / "e1")
    p2 = export.markdown(board, "p", tmp_path / "e2")
    assert p1.name == "MEMORY.md" and p1.read_bytes() == p2.read_bytes()
    text = p1.read_text()
    assert "secret of q" not in text
    assert "## a.t.test \\| get /api/users/{id} \\| idor" not in text  # cell fields are joined, not escaped pipes
    assert "## a.t.test | get /api/users/{id} | idor" in text and "## (whole program)" in text
    entries = [ln for ln in text.splitlines() if ln.startswith("- ")]
    assert len(entries) == _count(board)
    for ln in entries:
        assert re.match(r"- \*\*(OBSERVED|JUDGED|ANCHORED|NOTE)\*\* · (agent \d+|operator) · ", ln)
    assert "superseded by #" in text and "\\# not a heading \\<b\\>x\\</b\\>" in text
    # one section per cell, in key order
    heads = [ln[3:] for ln in text.splitlines() if ln.startswith("## ")]
    cells = [r[0] for r in board.db.execute("SELECT DISTINCT cell FROM mem_items WHERE program='p' ORDER BY cell")]
    assert heads == [" | ".join(f or "-" for f in c.split("|")) if c != "||" else "(whole program)" for c in cells]
    assert len(heads) == 8 and "a.t.test | - | -" in heads and heads[-1] == "(whole program)"


# ------------------------------------------------------------------ D36: the operator's leads
def _flow(tmp_path, fid, body, program="p"):
    d = tmp_path / "var" / "state" / "flows"
    d.mkdir(parents=True, exist_ok=True)
    rec = {"id": fid, "class": "target", "program": program, "response": {"headers": [], "body": body}}
    (d / f"{fid}.json").write_text(json.dumps(rec))


def _lead(**kw):
    base = {
        "kind": "dead-end",
        "method": "POST",
        "url": "https://copilot.t.test/c/api/conversations/123",
        "class": "idor",
        "technique": "swap conversation id",
        "identities": ["user-b", "user-a"],
        "why": "not-vulnerable",
        "title": "conversation ids are bound to the session",
        "summary": "user-a gets 404 on user-b's conversation",
    }
    return base | kw


def _write(path, lines):
    path.write_text("".join((x if isinstance(x, str) else json.dumps(x)) + "\n" for x in lines))
    return path


def test_import_valid_file_anchors_only_a_true_quote(board, tmp_path):
    _flow(tmp_path, "1700000000-abc123-1", '{"error": "conversation not found for this user"}')
    _flow(tmp_path, "1700000000-abc123-2", '{"error": "conversation not found for this user"}', program="q")
    path = _write(
        tmp_path / "leads.jsonl",
        [
            _lead(flow="1700000000-abc123-1", quote="conversation not found"),
            _lead(
                kind="candidate",
                why="untested",
                title="memory entries may be shared",
                url="https://copilot.t.test/m",
                flow="1700000000-abc123-1",
                quote="this text is not in the body",
            ),
            _lead(
                title="other program flow",
                url="https://copilot.t.test/x",
                flow="1700000000-abc123-2",
                quote="conversation not found",
            ),
            _lead(
                title="missing flow",
                url="https://copilot.t.test/y",
                flow="1700000000-nope-9",
                quote="conversation not found",
            ),
        ],
    )
    assert store.import_items(board, "p", path) == (4, 0)
    rows = {r["title"]: r for r in board.db.execute("SELECT * FROM mem_items")}
    first = rows["conversation ids are bound to the session"]
    assert first["label"] == "ANCHORED" and first["outcome"] == "ruled_out"
    assert first["agent_no"] == 0 and first["src_kind"] == "operator" and first["run_id"] is None
    assert first["ckey"] == "copilot.t.test|post /c/api/conversations/{id}|idor|swap conversation id|user-a,user-b"
    assert rows["memory entries may be shared"]["label"] == "NOTE"  # false quote
    assert rows["memory entries may be shared"]["outcome"] is None
    assert rows["other program flow"]["label"] == "NOTE"
    assert rows["missing flow"]["label"] == "NOTE"
    assert not board.db.execute("SELECT 1 FROM mem_items WHERE label IN ('OBSERVED', 'JUDGED')").fetchone()


def test_import_skips_and_counts_malformed_lines(board, tmp_path):
    bad = [
        "not json",
        "[1, 2]",
        _lead(kind="finding"),
        _lead(why="because"),
        _lead(method="GE T"),
        _lead(url="ftp://x.test/a"),
        _lead(identities="user-a"),
        _lead(identities=["user a"]),
        _lead(title=""),
        _lead(title="x" * 301),
        _lead(summary=7),
        _lead(flow="../../etc/passwd"),
        _lead(extra="field"),
        {k: v for k, v in _lead().items() if k != "why"},
    ]
    path = _write(tmp_path / "leads.jsonl", [_lead(), "", *bad])
    assert store.import_items(board, "p", path) == (1, len(bad))
    assert _count(board) == 1


def test_import_twice_doubles_nothing(board, tmp_path):
    path = _write(
        tmp_path / "leads.jsonl",
        [_lead(), _lead(title="conversation ids are bound to the session !"), _lead(kind="candidate", why="untested")],
    )
    first = store.import_items(board, "p", path)
    rows = board.db.execute("SELECT id, seen FROM mem_items ORDER BY id").fetchall()
    assert first == (3, 0) and len(rows) == 2  # the near-duplicate title merged at write time
    assert store.import_items(board, "p", path) == (0, 3)
    assert board.db.execute("SELECT id, seen FROM mem_items ORDER BY id").fetchall() == rows


def test_import_redacts_like_put(board, tmp_path):
    path = _write(tmp_path / "leads.jsonl", [_lead(summary=f"planted {CANARY}; Cookie: sid=abcdef0123456789")])
    store.import_items(board, "p", path)
    summary = board.db.execute("SELECT summary FROM mem_items").fetchone()[0]
    assert CANARY not in summary and "abcdef0123456789" not in summary and "<canary>" in summary


# ------------------------------------------------------------------ D1: embeddings, not wired; nothing leaves
def test_embedder_is_an_unwired_protocol():
    assert embed.ENABLED is False
    assert getattr(embed.Embedder, "_is_protocol", False)
    assert not [
        n for n in vars(embed).values() if isinstance(n, type) and n is not embed.Embedder and hasattr(n, "embed")
    ]


NETWORK = {"socket", "urllib", "http", "requests"}


def test_lineage_imports_no_network_module():
    files = sorted((SRC / "bh/lineage").glob("*.py"))
    assert {f.name for f in files} >= {"__init__.py", "store.py", "key.py", "export.py", "embed.py"}
    bad = []
    for f in files:
        for node in ast.walk(ast.parse(f.read_text())):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""] if node.level == 0 else []
            # urllib.parse only splits strings: no socket behind it
            bad += [f"{f.name}: {n}" for n in names if n.split(".")[0] in NETWORK and n != "urllib.parse"]
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "__import__":
                bad.append(f"{f.name}: __import__")
    assert bad == []


def test_backfill_pours_pre_lineage_runs_dated_at_their_end(board):
    """Run 69 (lab, 2026-11-27): the first agent of the lineage started with "0 items" in memory although 68 runs
    had worked the program. backfill() pours those runs, as agent #0, dated when they ran."""
    rid, _, fv = _hunt(board)
    board.db.execute("UPDATE runs SET started=?, ended=? WHERE id=?", (1000.0, 2000.0, rid))
    board.db.commit()
    n = store.backfill(board, "p")
    assert n > 0 and _count(board) > 0
    rows = board.db.execute("SELECT agent_no, valid_from, created FROM mem_items WHERE program='p'").fetchall()
    assert {r["agent_no"] for r in rows} == {0} and {r["valid_from"] for r in rows} == {2000.0}
    assert {r["created"] for r in rows} == {2000.0}
    assert store.backfill(board, "p") == 0  # idempotent
    assert _by_src(board, "finding", fv)["label"] == "JUDGED"


def test_backfill_skips_runs_an_agent_owns(board):
    rid, _, _ = _hunt(board)
    store.ensure(board)  # holds the agents table (lot D writes its rows)
    board.db.execute("INSERT INTO agents(no, program, run_id) VALUES (1, 'p', ?)", (rid,))
    board.db.commit()
    assert store.backfill(board, "p") == 0 and _count(board) == 0
