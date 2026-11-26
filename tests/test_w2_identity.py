"""W2-D: agent number and pseudo (D8), full setup card (D9), hash chains (D10), trace archive (D11), T20 count."""

import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from bh.board import Board
from bh.lineage import archive, chain, names
from bh.lineage import identity as lineage
from bh.runner import identity

ROOT = Path(__file__).resolve().parents[1]
PSEUDO_RE = re.compile(r"^[A-Z][a-z]+ [A-Z][a-z]+( [IVX]+)?$")
ORIGINALS = {
    "Captain Crunch", "Phiber Optik", "Acid Burn", "Zero Cool", "Crash Override", "Lord Nikon", "Dark Dante",
    "Dark Tangent", "Space Rogue", "Weld Pond", "Brian Oblivion", "Solar Designer", "Aleph One", "Knight Lightning",
    "Taran King", "Erik Bloodaxe", "Lex Luthor", "Susy Thunder", "Halvar Flake", "Mister Robot", "Professor Falken",
}  # fmt: skip

# contract of lot B (bh.lineage.store.ensure): absent from this worktree, created here
AGENTS_DDL = """
CREATE TABLE IF NOT EXISTS agents (no INTEGER PRIMARY KEY, pseudo TEXT, program TEXT, generation INTEGER,
  parent_no INTEGER, run_id INTEGER, setup_sha256 TEXT, birth_sha256 TEXT, relaunch_of INTEGER, born REAL,
  closed REAL, status TEXT);
CREATE TABLE IF NOT EXISTS blocks (no INTEGER, program TEXT, prev_hash TEXT, block_hash TEXT, body TEXT, ts REAL);
"""


@pytest.fixture
def board(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    b = Board(tmp_path / "board.sqlite")
    try:
        from bh.lineage import store  # lot B, once merged

        store.ensure(b)
    except ImportError:
        b.db.executescript(AGENTS_DDL)
    identity.ensure(b)
    return b


def _scope(**kw):
    base = {
        "program": "juiceshop",
        "platform": "local",
        "digest": "d" * 64,
        "scanners_on": True,
        "rate": 2.0,
        "identities": [
            {"name": "alice", "role": "user", "password": "hunter2-SECRET", "cookie": "sid=COOKIE-SECRET-42"},
            {"name": "bob", "role": "admin", "session": "SESSION-SECRET-7"},
        ],
    }
    base.update(kw)
    return SimpleNamespace(**base)


def _setup(monkeypatch, **kw):
    monkeypatch.setitem(identity._version_cache, "v", "2.1.0")  # no podman in tests
    args = {
        "model": "opus",
        "effort": "high",
        "verifier_model": "sonnet",
        "max_turns": 80,
        "minutes": 30.0,
        "system_prompt": "system",
        "task_template": "task",
        "cards": [],
        "max_runs_per_day": 6,
        "runs_per_session": 3,
        "sessions_per_day": 2,
        "fill_segment": 10,
        "fill_day": 40,
        "prompt_quantum": 5,
        "prompt_floor": 2,
    }
    args.update(kw)
    return identity.setup(_scope(), **args)


# ------------------------------------------------------------------ D8 names
def test_tables_are_pinned():
    assert len(names.HEADS) == 21 and len(names.TAILS) == 26 and len(names.FORBIDDEN) == 21
    assert {" ".join(p) for p in names.FORBIDDEN} == ORIGINALS
    # validated by Mio: a change to a table or to the forbidden pairs must be deliberate
    assert names.TABLES_SHA256 == "cb1a92bb0f410f9ca30ee615864bf3610c7243268a00d652f9fb91f529e583e3"


def test_every_pair_is_walked_and_no_original_comes_out():
    seen = set()
    for h in range(len(names.HEADS)):
        for t in range(len(names.TAILS)):
            p = names.pair(h, t)
            assert p not in ORIGINALS and PSEUDO_RE.match(p)
            assert p.split()[0] == names.HEADS[h]
            seen.add((h, t))
    assert len(seen) == 546
    assert names.pair(names.HEADS.index("Dark"), names.TAILS.index("Dante")) == "Dark Rogue"  # two hops


def test_pseudo_is_deterministic_and_well_formed():
    for no in range(1, 400):
        p = names.pseudo(no, "juiceshop")
        assert p == names.pseudo(no, "juiceshop") and PSEUDO_RE.match(p) and p not in ORIGINALS
    assert names.pseudo(7, "a") != names.pseudo(7, "b") or names.pseudo(8, "a") != names.pseudo(8, "b")


def test_worn_pair_takes_a_roman_numeral():
    base = names.pseudo(3, "x")
    assert names.pseudo(3, "x", [base]) == f"{base} II"
    assert names.pseudo(3, "x", [base, f"{base} II", f"{base} III"]) == f"{base} IV"
    assert PSEUDO_RE.match(names.pseudo(3, "x", [base] + [f"{base} {names.roman(n)}" for n in range(2, 30)]))
    assert names.label(142) == "#0142"


def test_birth_numbers_generations_parents_and_close(board):
    a = lineage.birth(board, _scope(), 1, setup_sha256="s1")
    b = lineage.birth(board, _scope(), 1, setup_sha256="s1")  # a context rotation: a new agent, same run
    c = lineage.birth(board, "lab-other", 2, setup_sha256="s1")
    d = lineage.birth(board, _scope(), 3, setup_sha256="s1", parent_no=a["no"], mission="m")
    assert (a["no"], b["no"], c["no"], d["no"]) == (1, 2, 3, 4)
    assert (a["generation"], b["generation"], c["generation"], d["generation"]) == (1, 2, 1, 3)
    assert (a["parent_no"], b["parent_no"], c["parent_no"], d["parent_no"]) == (None, 1, None, 1)
    pseudos = [r[0] for r in board.db.execute("SELECT pseudo FROM agents")]
    assert len(set(pseudos)) == 4 and all(PSEUDO_RE.match(p) for p in pseudos)
    lineage.close(board, 1, "done")
    lineage.close(board, 1, "crashed")  # the first closing stands
    assert tuple(board.db.execute("SELECT status FROM agents WHERE no=1").fetchone()) == ("done",)
    # a number is never reused, even when its row is gone
    board.db.execute("DELETE FROM agents WHERE no=4")
    assert lineage.birth(board, _scope(), 4, setup_sha256="s1")["no"] == 5


def test_pseudo_never_reaches_a_path():
    d = archive.agent_dir("juiceshop", 142, "Zero Plague II")
    assert d.parts[-3:] == ("lineage", "juiceshop", "0142-zero-plague-ii")
    assert archive.slug("Ex/../Ploit Ä") == "ex-ploit"
    with pytest.raises(ValueError):
        archive.agent_dir("../etc", 1, "Zero Plague")


# ------------------------------------------------------------------ D9 setup card
def test_setup_card_has_the_w2_fields_and_no_secret(monkeypatch):
    monkeypatch.setenv("BH_LINEAGE_PSEUDO", "0")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "sk-ant-oat01-REALSECRET")
    digest, doc = _setup(monkeypatch, recall_params={"elders": 3, "api_token": "TOKEN-SECRET-9"})
    w2 = ("hooks_sha256", "policy_sha256", "doctrine_opening", "pseudo_rule", "pseudo_shown", "score_weights_sha256")
    for key in (*w2, "recall_params", "MAX_RUNS_PER_DAY", "SESSIONS_PER_DAY", "FILL_DAY"):
        assert key in doc
    assert re.fullmatch(r"[0-9a-f]{64}", doc["hooks_sha256"]) and re.fullmatch(r"[0-9a-f]{64}", doc["policy_sha256"])
    assert doc["doctrine_opening"] == "a" and doc["pseudo_rule"] == names.TABLES_SHA256 and doc["pseudo_shown"] == "0"
    assert doc["recall_params"]["elders"] == 3
    text = identity.canonical(doc)
    for secret in ("hunter2", "COOKIE-SECRET", "SESSION-SECRET", "TOKEN-SECRET", "REALSECRET", "sid="):
        assert secret not in text
    assert digest == identity.sha256(text)


def test_relaunch_check_names_the_field_that_moved(board, monkeypatch):
    digest, doc = _setup(monkeypatch)
    run_id = board.run_start("juiceshop", "opus")
    board.run_set(run_id, setup_sha256=digest, setup_json=identity.canonical(doc))
    ag = lineage.birth(board, _scope(), run_id, setup_sha256=digest)
    assert lineage.relaunch_check(board, ag["no"], doc) == []
    _, moved = _setup(monkeypatch, max_turns=81, doctrine_opening="b")
    assert lineage.relaunch_check(board, ag["no"], moved) == ["doctrine_opening", "max_turns"]
    monkeypatch.setattr(identity, "POLICY_FILE", ROOT / "README.md")  # the gate policy changed
    _, moved = _setup(monkeypatch)
    assert lineage.relaunch_check(board, ag["no"], moved) == ["policy_sha256"]


def test_diff_gives_digests_and_counters(board, monkeypatch):
    rows, rids = [], []
    for prompt, turns in (("one", 10), ("two", 25)):
        digest, doc = _setup(monkeypatch, system_prompt=prompt)
        rid = board.run_start("juiceshop", "opus")
        board.run_set(rid, setup_sha256=digest, setup_json=identity.canonical(doc), turns=turns)
        rows.append(lineage.birth(board, _scope(), rid, setup_sha256=digest))
        rids.append(rid)
    board.add_finding("juiceshop", "idor", run_id=rids[1])
    out = lineage.diff(board, rows[0]["no"], rows[1]["no"])
    assert set(out["digests"]) >= {"setup_sha256", "system_prompt_sha256"} and out["fields"] == {}
    assert out["counters"]["a"]["turns"] == 10 and out["counters"]["b"]["turns"] == 25
    assert (out["counters"]["a"]["findings"], out["counters"]["b"]["findings"]) == (0, 1)


def test_birth_sha256_binds_its_four_inputs():
    base = lineage.birth_sha256("s", "block", "mission", "2026-11-26")
    assert base == lineage.birth_sha256("s", "block", "mission", "2026-11-26")
    for args in (("t", "block", "mission", "2026-11-26"), ("s", "blocK", "mission", "2026-11-26"),
                 ("s", "block", "other", "2026-11-26"), ("s", "block", "mission", "2026-11-27")):  # fmt: skip
        assert lineage.birth_sha256(*args) != base


# ------------------------------------------------------------------ D10 chains
def test_trace_chains_and_finds_the_changed_byte(tmp_path):
    p = tmp_path / "trace.jsonl"
    t = chain.Trace(p)
    assert t.head() == chain.GENESIS
    hashes = [t.append({"type": "tool", "n": i, "text": "é"}) for i in range(6)]
    assert t.head() == hashes[-1] and chain.verify(p) == (True, None)
    assert chain.Trace(p).head() == hashes[-1]  # reopened: the chain goes on
    chain.Trace(p).append({"type": "end"})
    assert chain.verify(p) == (True, None)
    raw = p.read_bytes()
    lines = raw.split(b"\n")
    offset = sum(len(x) + 1 for x in lines[:3])
    for pos in range(offset, offset + len(lines[3])):  # every byte of line 3, one at a time
        bad = bytearray(raw)
        bad[pos] ^= 0x01
        p.write_bytes(bytes(bad))
        assert chain.verify(p) == (False, 3), pos
    p.write_bytes(raw)
    assert chain.verify(p) == (True, None)


def test_key_order_does_not_change_the_hash(tmp_path):
    a = chain.Trace(tmp_path / "a").append({"type": "x", "a": 1, "b": {"c": 2, "d": 3}}, ts=1.5)
    b = chain.Trace(tmp_path / "b").append({"b": {"d": 3, "c": 2}, "a": 1, "type": "x"}, ts=1.5)
    assert a == b == chain.event_hash(chain.GENESIS, 0, 1.5, {"type": "x", "a": 1, "b": {"c": 2, "d": 3}})


def test_bh_decision_events_are_taken_as_is_and_counted(tmp_path):
    p = tmp_path / "t.jsonl"
    t = chain.Trace(p)
    ev = {"type": "bh_decision", "decision": "pivot", "why": ["no 200 in 40 tries"], "intent": 3}
    t.append(ev)
    t.append({"type": "tool"})
    t.append(dict(ev, decision="stop"))
    assert json.loads(p.read_text().splitlines()[0])["event"] == ev
    assert chain.count(p, "bh_decision") == 2 and chain.count(p, "tool") == 1 and chain.count(p, "none") == 0


def test_blocks_chain_per_program_and_find_the_changed_byte(board):
    nos = [lineage.birth(board, _scope(), 1, setup_sha256="s")["no"] for _ in range(3)]
    other = lineage.birth(board, "other", 2, setup_sha256="s")["no"]
    hashes = [
        chain.close_block(board, no, "h" * 64, {"findings": i, "cookie": "sid=COOKIE-SECRET"})
        for i, no in enumerate(nos)
    ]
    chain.close_block(board, other, "h" * 64, {})
    with pytest.raises(ValueError):
        chain.close_block(board, nos[0], "h" * 64, {})
    assert chain.verify_blocks(board, "juiceshop") == (True, None)
    assert chain.verify_blocks(board, "other") == (True, None)
    body = json.loads(board.db.execute("SELECT body FROM blocks WHERE no=?", (nos[1],)).fetchone()[0])
    assert body["prev_hash"] == hashes[0] and body["pseudo"] and "COOKIE-SECRET" not in json.dumps(body)
    assert set(body) >= {"no", "pseudo", "program", "setup_sha256", "parent_no", "trace_head", "summary", "prev_hash"}
    (orig,) = board.db.execute("SELECT body FROM blocks WHERE no=?", (nos[1],)).fetchone()
    tampered = orig.replace('"findings":1', '"findings":7')
    assert tampered != orig
    board.db.execute("UPDATE blocks SET body=? WHERE no=?", (tampered, nos[1]))
    assert chain.verify_blocks(board, "juiceshop") == (False, nos[1])
    board.db.execute("UPDATE blocks SET body=?, ts=ts+1 WHERE no=?", (orig, nos[1]))
    assert chain.verify_blocks(board, "juiceshop") == (False, nos[1])


# ------------------------------------------------------------------ D11 archive
def test_archive_carries_no_cookie_and_no_token(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    cookie, token = "COOKIEVAL-7f3a9", "TESTTOKEN-91bc2"
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl"
    stream = tmp_path / "stream.jsonl"
    stream.write_text(
        "\n".join(
            [
                json.dumps({"type": "assistant", "message": {"content": [{"type": "tool_use", "input": {
                    "command": f"curl -H 'Cookie: sid={cookie}' -H 'Authorization: Bearer {token}' https://t/"}}]}}),
                json.dumps({"type": "user", "content": f"set-cookie: sid={cookie}\n{{\"access_token\": \"{token}\"}}"}),
                json.dumps({"type": "result", "session_token": token, "note": jwt, "Cookie": f"sid={cookie}"}),
                f"plain line token={token} cookie: {cookie}",
            ]
        )
        + "\n"
    )  # fmt: skip
    hooks = tmp_path / "hooks.jsonl"
    hooks.write_text(json.dumps({"hook": "PreToolUse", "cmd": f"wget --header='Cookie: a={cookie}'"}) + "\n")
    d = archive.agent_dir("juiceshop", 7, "Zero Plague")
    man = archive.write(
        d,
        identity={"no": 7, "pseudo": "Zero Plague", "auth": f"Bearer {token}", "notes": f"x-api-key: {token}"},
        system_prompt=f"registered as #0007 Zero Plague. Cookie: sid={cookie}",
        task=f"api_key={token}",
        stream_path=stream,
        hooks_path=hooks,
    )
    files = sorted(p for p in d.iterdir())
    assert {p.name for p in files} == {"identity.json", "system_prompt.txt", "task.txt", "stream.jsonl",
                                       "hooks.jsonl", "manifest.json"}  # fmt: skip
    for p in files:
        text = p.read_text()
        assert cookie not in text and token not in text and jwt not in text, p.name
    manifest = json.loads(man.read_text())
    import hashlib

    for name, digest in manifest["files"].items():
        assert hashlib.sha256((d / name).read_bytes()).hexdigest() == digest
    assert "registered as" in (d / "system_prompt.txt").read_text()


def test_archive_notes_a_missing_stream(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    man = archive.write(tmp_path / "a", identity={}, system_prompt="", task="", stream_path=None,
                        hooks_path=tmp_path / "nope")  # fmt: skip
    assert json.loads(man.read_text())["absent"] == ["stream.jsonl", "hooks.jsonl"]


def test_no_container_mounts_the_lineage():
    compose = yaml.safe_load((ROOT / "container" / "compose.yaml").read_text())
    for name, svc in compose["services"].items():
        for vol in svc.get("volumes") or []:
            src = (vol if isinstance(vol, str) else vol.get("source", "")).split(":", 1)[0].rstrip("/")
            assert "lineage" not in src, (name, vol)
            assert src not in ("..", "../var", ".", "/"), (name, vol)  # nothing that contains var/lineage
