import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from bh.agent import proof
from bh.board import Board
from bh.scope import scope_from_dict
from bh.verify import decide, duplicate_of, triager_poc


class Target(BaseHTTPRequestHandler):
    """/basket/7 belongs to user-b. VULNERABLE: any session reads it. Without a session: 401."""

    vulnerable = True

    def do_GET(self):
        who = self.headers.get("X-BH-Identity")  # no gate in tests: the identity name reaches the server
        if not who:
            code, body = 401, b'{"error":"login"}'
        elif who == "user-b" or self.vulnerable:
            code, body = 200, b'{"UserId":27,"items":[]}'
        else:
            code, body = 403, b'{"error":"forbidden"}'
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def target(monkeypatch):
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.delenv(var, raising=False)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def idor_proof(base, control_expect=None):
    return {
        "steps": [
            {
                "name": "owner",
                "role": "setup",
                "as": "user-b",
                "method": "GET",
                "url": f"{base}/basket/7",
                "expect": {"status": [200], "contains": ['"UserId":27']},
            },
            {
                "name": "other user",
                "role": "attack",
                "as": "user-a",
                "method": "GET",
                "url": f"{base}/basket/7",
                "expect": {"status": [200], "contains": ['"UserId":27']},
            },
            {
                "name": "no session",
                "role": "control",
                "as": None,
                "method": "GET",
                "url": f"{base}/basket/7",
                "expect": control_expect or {"status": [401, 403]},
            },
        ]
    }


def test_validation_requires_attack_and_a_different_control():
    assert proof.validate({"steps": []})
    p = idor_proof("http://t")
    assert proof.validate(p) == []
    no_control = {"steps": [s for s in p["steps"] if s["role"] != "control"]}
    assert any("control" in e for e in proof.validate(no_control))
    same = idor_proof("http://t", control_expect={"status": [200], "contains": ['"UserId":27']})
    assert any("different" in e for e in proof.validate(same))
    bad_url = idor_proof("$B")
    assert proof.validate(bad_url)


def test_replay_reproduces_a_real_idor(target):
    Target.vulnerable = True
    r = proof.replay(idor_proof(target))
    assert r["reproduced"] and not r["control_disproves"] and len(r["rounds"]) == 2


def test_replay_fails_when_the_bug_is_not_there(target):
    Target.vulnerable = False
    r = proof.replay(idor_proof(target))
    assert not r["reproduced"]
    misses = [m for rnd in r["rounds"] for s in rnd for m in s["misses"]]
    assert any("status 403" in m for m in misses)


def test_decision_table():
    ok = {"reproduced": True, "control_disproves": False}
    assert decide(ok, "confirmed", "x")[0] == "verified"
    assert decide(ok, "rejected", "by design")[0] == "rejected"
    assert decide(ok, "inconclusive", "x")[0] == "inconclusive"
    assert (
        decide({"reproduced": False, "rounds": []}, "confirmed", "x")[0] == "inconclusive"
    )  # B cannot invent a success
    assert decide({"reproduced": False, "control_disproves": True}, "confirmed", "x")[0] == "rejected"


def test_triager_poc_has_program_headers_and_no_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    ident = tmp_path / "var" / "state" / "identities" / "p"
    ident.mkdir(parents=True)
    (ident / "user-a.json").write_text(json.dumps({"headers": {"Authorization": "Bearer SECRET"}}))
    scope = scope_from_dict(
        {
            "program": "p",
            "platform": "x",
            "in_scope": ["t.test"],
            "user_agent": "YWH-mio",
            "required_headers": {"X-Bug-Bounty": "mio"},
        }
    )
    poc = triager_poc(scope, idor_proof("https://t.test"))
    assert "SECRET" not in poc and "X-BH-Identity" not in poc
    assert "Authorization: <Authorization of account user-a>" in poc
    assert "User-Agent: YWH-mio" in poc and "X-Bug-Bounty: mio" in poc


def test_duplicates(tmp_path):
    b = Board(tmp_path / "b.sqlite")
    f1 = b.add_finding("p", "IDOR basket", vuln_class="idor", url="https://t.test/basket/7")
    f2 = b.add_finding("p", "IDOR basket again", vuln_class="idor", url="https://t.test/basket/9")
    f3 = b.add_finding("p", "SQLi", vuln_class="sqli", url="https://t.test/basket/9")
    row = lambda fid: dict(b.rows("SELECT * FROM findings WHERE id=?", fid)[0])  # noqa: E731
    assert duplicate_of(b, row(f2)) == f1
    assert duplicate_of(b, row(f3)) is None


def test_validation_refuses_empty_proofs():
    base = "http://t"
    empty = {
        "steps": [
            {"role": "attack", "method": "GET", "url": f"{base}/", "expect": {"status": [200]}},
            {"role": "control", "method": "GET", "url": f"{base}/api/nope", "expect": {"status": [404, 500]}},
        ]
    }
    errors = proof.validate(empty)
    assert any("body marker" in e for e in errors) and any("twin" in e for e in errors)
    blank = idor_proof(base, control_expect={"status": [401], "regex": ""})
    assert any("empty marker" in e for e in proof.validate(blank))


def test_replay_is_disproved_when_the_control_satisfies_the_attack(target):
    """A control that 'expects' 403 but gets the same data as the attack: no differential, whatever its sha1."""
    Target.vulnerable = True
    p = idor_proof(target)
    p["steps"][2] |= {"as": "user-c", "expect": {"status": [403]}}  # another session: the server answers 200
    r = proof.replay(p)
    assert r["control_disproves"] and not r["reproduced"]
    assert decide(r, "confirmed", "x")[0] == "rejected"


def test_decision_needs_a_real_boolean():
    assert decide({"reproduced": "yes"}, "confirmed", "x")[0] == "inconclusive"
