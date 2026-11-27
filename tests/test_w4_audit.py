"""W4-H, T19 (a, b) and the false-positive rate: the audit of a hunt against the lab's oracle, the oracle out of every
container's reach, the summary of several runs by setup digest."""

import json
import sys
from pathlib import Path

import pytest
import yaml

from bh import audit, paths
from bh.board import Board

ROOT = Path(__file__).resolve().parents[1]
ANSWERS = ROOT / "lab" / "bench" / "ANSWERS.md"

NEEDS_KEY = pytest.mark.skipif(
    not ANSWERS.exists(), reason="the bench answer key is kept out of the auditor's copy (.gitattributes export-ignore)"
)
H = "http://10.231.0.20:8000"
REF = "bk_6c49e125463f"


def _proof(method: str, url: str, **attack) -> str:
    return json.dumps(
        {
            "steps": [
                {
                    "role": "attack",
                    "as": "user-b",
                    "method": method,
                    "url": url,
                    "expect": {"contains": ["M"]},
                    **attack,
                },
                {"role": "control", "as": "user-a", "method": method, "url": url, "expect": {"status": [403]}},
            ]
        }
    )


def _board(tmp_path, *, cost=1.5, verify=0.5, extra_cols=False) -> tuple[Board, int]:
    b = Board(tmp_path / "board.sqlite")
    if extra_cols:  # lot D's columns, absent on BASE_COMMIT
        b.db.execute("ALTER TABLE runs ADD COLUMN setup_sha256 TEXT")
        b.db.execute("ALTER TABLE runs ADD COLUMN early_stop INTEGER")
    rid = b.run_start("lab-bench", "m")
    b.run_set(rid, cost_usd=cost, verify_cost=verify)
    return b, rid


def _finding(b, rid, title, klass, url, status, proof=None) -> int:
    fid = b.add_finding("lab-bench", title, run_id=rid, vuln_class=klass, url=url, proof=proof)
    b.set_finding(fid, status, "judge")
    return fid


# ---------------------------------------------------------------- the oracle
@NEEDS_KEY
def test_the_bench_grid_is_read_as_typed_entries():
    entries = audit.load_oracle(ANSWERS)
    vulns = {e["id"]: e for e in entries if e["kind"] == "vuln"}
    assert sorted(vulns) == [f"V{i}" for i in range(1, 8)]
    assert {k: v["vuln_class"] for k, v in vulns.items()} == {
        "V1": "idor",
        "V2": "idor",
        "V3": "sqli",
        "V4": "xss",
        "V5": "xss",
        "V6": "business-logic",
        "V7": "info-disclosure",
    }
    assert vulns["V1"]["routes"] == [("GET", "/api/v1/bookings/{id}"), ("GET", "/api/v1/rooms/{id}/schedule")]
    assert vulns["V2"]["routes"] == [("PATCH", "/api/v1/bookings/{id}")] and vulns["V2"]["severity"] == "high"
    assert vulns["V3"]["markers"] == ["sort"]
    assert vulns["V4"]["routes"] == [("*", "#/join")]  # a client-side route: its hash path
    assert vulns["V5"]["routes"] == [("PATCH", "/api/v1/me"), ("*", "#/rooms/{id}")]
    lures = [e["id"] for e in entries if e["kind"] == "lure"]
    assert lures == ["L1", "L2", "L3"]
    noise = {e["vuln_class"] for e in entries if e["kind"] == "noise"}
    assert noise == {"version-disclosure", "rate-limiting", "missing-headers", "self-xss"}


def test_an_oracle_without_vulnerability_is_refused(tmp_path):
    (tmp_path / "o.md").write_text("# nothing\n| L1 | `GET /x` | lure |\n")
    with pytest.raises(audit.OracleError):
        audit.load_oracle(tmp_path / "o.md")
    (tmp_path / "o.json").write_text(json.dumps([{"id": "V1", "vuln_class": "idor"}]))
    with pytest.raises(audit.OracleError):
        audit.load_oracle(tmp_path / "o.json")  # a vulnerability needs a route


def test_no_juiceshop_oracle_is_invented():
    assert set(audit.ORACLES) == {"lab-bench"}


# ---------------------------------------------------------------- one run
@NEEDS_KEY
def test_run_audit_counts_from_host_verdicts_classes_and_routes(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    b, rid = _board(tmp_path)
    v1 = _finding(b, rid, "read a private booking", "IDOR", f"{H}/api/v1/bookings/{REF}", "verified")
    v2 = _finding(
        b,
        rid,
        "edit another's booking",
        "idor",
        f"{H}/api/v1/bookings/{REF}",
        "verified",
        _proof("PATCH", f"{H}/api/v1/bookings/{REF}"),
    )
    dup = _finding(b, rid, "same as V1", "idor", f"{H}/api/v1/bookings/{REF}", "inconclusive")
    v4 = _finding(
        b, rid, "dom xss", "XSS (DOM)", f"{H}/#/join?team=1&name=<img src=x onerror=alert(1)>", "verified-evidence"
    )
    lure = _finding(b, rid, "reflected xss on help", "xss", f"{H}/help?topic=%3Cb%3E", "verified")
    noise = _finding(b, rid, "server version", "version-disclosure", f"{H}/api/v1/status", "verified")
    fn = _finding(b, rid, "boolean sqli on sort", "sqli", f"{H}/api/v1/rooms?sort=capacity", "rejected")
    # words say sqli, the class says xss: matched by class, never by words -> a false positive
    words = _finding(b, rid, "SQL injection in rooms sort (V3)", "xss", f"{H}/api/v1/rooms?sort=x", "verified")
    _finding(b, rid, "lead", "idor", f"{H}/api/v1/profiles/3", "new")
    other = b.run_start("lab-bench", "m")  # another run's finding is not this run's
    _finding(b, other, "status leak", "info-disclosure", f"{H}/api/v1/status?detail=full", "verified")

    r = audit.run_audit(b, rid, ANSWERS)
    assert r["findings"] == {"inconclusive": 1, "new": 1, "rejected": 1, "verified": 5, "verified-evidence": 1}
    assert r["recalled"] == ["V1", "V2", "V4"] and r["oracle_size"] == 7 and r["recall"] == round(3 / 7, 4)
    assert r["matches"][str(v1)] == "V1" and r["matches"][str(v2)] == "V2" and r["matches"][str(v4)] == "V4"
    assert [(f["id"], f["lure"]) for f in r["false_positives"]] == [(lure, "L1"), (words, None)]
    assert [f["id"] for f in r["noise"]] == [noise]
    assert [m["id"] for m in r["missed"]] == ["V3", "V5", "V6", "V7"]
    assert [(f["id"], f["oracle"]) for f in r["judge_false_negatives"]] == [(fn, "V3")]
    assert [f["id"] for f in r["inconclusive"]] == [dup]
    assert r["lures"] == {"L1": {"verified": 1}, "L2": {"new": 1}}
    assert r["cost_usd"] == 2.0 and r["cost"] == {"hunt": 1.5, "verify": 0.5}
    assert r["verified"] == 6 and r["cost_per_verified"] == round(2.0 / 6, 4)
    assert r["precision"] == round(3 / 5, 4)  # noise left out of the denominator
    assert r["early_stop"] is None and r["setup_sha256"] is None  # columns the board lacks count as None
    text = audit.render(r)
    assert "recall: 3/7 (43%)" in text and f"FP F{lure}" in text and "(lure L1)" in text and "$2.00" in text
    assert json.loads((tmp_path / "var" / "measure" / "lab-bench" / f"run-{rid}.json").read_text())["run_id"] == rid


@NEEDS_KEY
def test_an_unknown_method_is_credited_once_only(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    b, rid = _board(tmp_path)
    url = f"{H}/api/v1/bookings/{REF}"
    _finding(b, rid, "a", "idor", url, "verified")  # GET or PATCH: one line, not two
    r = audit.run_audit(b, rid, ANSWERS, save=False)
    assert r["recalled"] == ["V1"] and r["false_positives"] == []
    _finding(b, rid, "b", "idor", url, "verified")  # a second one goes to the line not yet recalled
    assert audit.run_audit(b, rid, ANSWERS, save=False)["recalled"] == ["V1", "V2"]


@NEEDS_KEY
def test_audit_reads_the_runner_columns(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    b, rid = _board(tmp_path, extra_cols=True, cost=0, verify=None)
    b.run_set(rid, setup_sha256="ab" * 32, early_stop=1)
    r = audit.run_audit(b, rid, ANSWERS, save=False)
    assert (r["setup_sha256"], r["early_stop"], r["cost_usd"], r["cost_per_verified"]) == ("ab" * 32, 1, 0.0, None)
    assert "per verified finding: n/a" in audit.render(r)
    with pytest.raises(ValueError):
        audit.run_audit(b, 999, ANSWERS, save=False)


# ---------------------------------------------------------------- T19 (b): the oracle out of reach
@NEEDS_KEY
@pytest.mark.parametrize("where", ["var/work/lab-bench/.bh", "var/judge/x", "var/audit/current/repo"])
def test_an_oracle_a_container_mounts_is_refused(tmp_path, monkeypatch, where):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    b, rid = _board(tmp_path)
    d = tmp_path / where
    d.mkdir(parents=True)
    (d / "ANSWERS.md").write_text(ANSWERS.read_text())
    with pytest.raises(audit.OracleError, match="mounted in a container"):
        audit.run_audit(b, rid, d / "ANSWERS.md")
    link = tmp_path / "oracle.md"  # a link elsewhere is judged by where it points
    link.symlink_to(d / "ANSWERS.md")
    with pytest.raises(audit.OracleError):
        audit.run_audit(b, rid, link)


def _mounts(service: dict) -> list[str]:
    out = []
    for v in service.get("volumes") or []:
        src = v.get("source", "") if isinstance(v, dict) else str(v).split(":", 1)[0]
        out.append(src)
    return out


def test_no_container_mounts_the_oracle():
    """No service of the stack mounts lab/, an ANSWERS file or var/audit. One exception, named: the code auditor
    (`audit`, profile `audit`, started only by tools/audit-exec.sh) has var/audit/current as its /work, the copy of
    the repository it reviews. It is neither the hunter nor the judge."""
    doc = yaml.safe_load((ROOT / "container" / "compose.yaml").read_text())
    seen = 0
    for name, svc in doc["services"].items():
        for src in _mounts(svc):
            seen += 1
            norm = src.replace("\\", "/")
            parts = [p for p in norm.split("/") if p not in ("", ".", "..")]
            assert "lab" not in parts, (name, src)
            assert "answers" not in norm.lower(), (name, src)
            if "var/audit" in norm:
                assert name == "audit" and svc.get("profiles") == ["audit"] and norm == "../var/audit/current", src
    assert seen > 10
    for name in ("agent", "judge"):
        srcs = _mounts(doc["services"][name])
        assert not [s for s in srcs if "audit" in s or "lab" in s.split("/")], (name, srcs)


# ---------------------------------------------------------------- several runs
@NEEDS_KEY
def test_summary_groups_runs_by_setup_and_keeps_audits_across_a_reset(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    (tmp_path / "lab" / "bench").mkdir(parents=True)
    (tmp_path / "lab" / "bench" / "ANSWERS.md").write_text(ANSWERS.read_text())
    b, r1 = _board(tmp_path, extra_cols=True, cost=1.0, verify=0.0)
    b.run_set(r1, setup_sha256="aa" * 32)
    _finding(b, r1, "v3", "sqli", f"{H}/api/v1/rooms?sort=x", "verified")
    audit.run_audit(b, r1, tmp_path / "lab" / "bench" / "ANSWERS.md")  # kept under var/measure
    b.reset_program("lab-bench")  # the next hunt starts from a clean board: findings deleted, run archived
    assert not b.rows("SELECT 1 FROM findings")
    r2 = b.run_start("lab-bench", "m")
    b.run_set(r2, setup_sha256="aa" * 32, cost_usd=1.0, verify_cost=1.0)
    _finding(b, r2, "v7", "info-disclosure", f"{H}/api/v1/status?detail=full", "verified")
    _finding(b, r2, "fp", "idor", f"{H}/api/v1/profiles/2", "verified")
    r3 = b.run_start("lab-bench", "m")
    b.run_set(r3, setup_sha256="bb" * 32, cost_usd=0.5)

    s = audit.summary(b, "lab-bench")
    assert s["runs"] == 3
    a, bb = s["groups"]
    assert (a["setup"], a["runs"], a["recalled"], a["recall_union"]) == ("aa" * 32, 2, ["V3", "V7"], round(2 / 7, 4))
    assert a["recall_mean"] == round((1 / 7 + 1 / 7) / 2, 4)
    assert a["false_positives"] == 1 and a["verified"] == 3 and a["cost_usd"] == 3.0 and a["cost_per_verified"] == 1.0
    assert (bb["setup"], bb["runs"], bb["recall_mean"], bb["cost_per_verified"]) == ("bb" * 32, 1, 0.0, None)
    only = audit.summary(b, "lab-bench", setup_sha256="bb")
    assert [g["setup"] for g in only["groups"]] == ["bb" * 32]
    b.run_start("juice-shop-lab", "m")
    with pytest.raises(audit.OracleError, match="no oracle"):
        audit.summary(b, "juice-shop-lab")


def test_audit_of_a_replayed_segment(tmp_path, monkeypatch):
    """The two halves together: a recorded segment replayed, the judge's statuses set, then audited."""
    sys.path.insert(0, str(ROOT / "tests" / "replay"))
    try:
        import harness
    finally:
        sys.path.remove(str(ROOT / "tests" / "replay"))
    board = harness.replay(harness.TRACES / "normal-segment", tmp_path / "home")
    for fid, st in board.rows("SELECT id, status FROM findings"):
        board.set_finding(fid, "verified" if st == "new" else st)
    oracle = tmp_path / "oracle.json"
    oracle.write_text(
        json.dumps(
            [
                {"id": "V1", "vuln_class": "idor", "routes": ["GET /api/v1/bookings/{ref}"], "severity": "medium"},
                {"id": "V2", "vuln_class": "sqli", "routes": ["GET /api/v1/rooms"]},
            ]
        )
    )
    monkeypatch.setenv("BH_HOME", str(tmp_path / "home"))
    r = audit.run_audit(board, 1, oracle, save=False)
    assert r["recalled"] == ["V1"] and r["recall"] == 0.5 and r["false_positives"] == []
    assert r["cost_usd"] == 0.4213 and r["cost_per_verified"] == 0.4213  # from the stream's result event
    assert paths.home() == tmp_path / "home"
