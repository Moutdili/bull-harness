"""Stage A against a hostile hunter: every field of proof.json is chosen by someone who wants it to pass."""

import json
import os
import stat
import sys

import pytest

from bh.agent import proof

MARK = "abcd1234"
FORGED = f"xss CONFIRMED (marker {MARK})"

# Stands in for bh-browse: prints a text summary that echoes the URL (as the real one does) and writes the
# structured summary.json the replay reads. A dialog opens only when the URL holds the real payload.
FAKE_BROWSE = r"""
import json, os, sys, time
url = sys.argv[1]
marker = sys.argv[sys.argv.index("--xss") + 1] if "--xss" in sys.argv else None
mode = os.environ.get("FAKE_MODE", "ok")
if mode == "nosummary":
    print(f"bh-browse {url}: killed [error rc=124]")
    sys.exit(124)
raw = os.path.join(os.environ["BH_DIR"], "raw", f"browse-t-{int(time.time())}")
os.makedirs(raw)
dialogs = [{"type": "alert", "message": marker}] if "<svg/onload" in url else []
doc = {"status": 200, "state": "ok", "dialogs": dialogs, "sentinel": None, "marker": marker,
       "xss_confirmed": True}  # the replay never trusts this field
if mode == "hostile":
    doc = {"status": "200", "dialogs": {"message": marker}, "sentinel": [marker], "xss_confirmed": True}
with open(os.path.join(raw, "summary.json"), "w") as fh:
    json.dump(doc, fh)
with open(os.path.join(raw, "dom.html"), "w") as fh:
    fh.write(f"<html><title>{url}</title><body>rendered</body></html>")
print(f'bh-browse {url}: 200, title "{url}", 1.0 s [ok]')
print(f"  console: 1 errors ({url})")
"""


@pytest.fixture
def fake_browse(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    exe = bindir / "bh-browse"
    exe.write_text(f"#!{sys.executable}\n{FAKE_BROWSE}")
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    return exe


def _xss(attack_q: str, control_q: str = "benign") -> dict:
    u = "http://t.test/page?q="
    return {
        "steps": [
            {
                "name": "attack",
                "role": "attack",
                "url": u + attack_q,
                "browse": {"xss": MARK},
                "expect": {"contains": [FORGED]},
            },
            {
                "name": "control",
                "role": "control",
                "url": u + control_q,
                "browse": {"xss": MARK},
                "expect": {"absent": ["xss CONFIRMED"]},
            },
        ]
    }


# ---------------------------------------------------------------- H2: the browser step
def test_marker_in_the_url_does_not_confirm(fake_browse):
    doc = _xss(FORGED)  # the audit's attack: the verdict string sits in the query, nothing runs
    assert proof.validate(doc) == []
    r = proof.replay(doc, rounds=1)
    assert not r["reproduced"]
    attack = r["rounds"][0][0]
    assert attack["snippet"] == f"xss none (marker {MARK})" and "t.test" not in attack["snippet"]


def test_a_real_dialog_confirms(fake_browse):
    r = proof.replay(_xss(f"<svg/onload=alert('{MARK}')>"))
    assert r["reproduced"] and not r["control_disproves"]
    assert [s["snippet"] for s in r["rounds"][0]] == [FORGED, f"xss none (marker {MARK})"]


def test_hostile_summary_shapes_never_confirm(fake_browse, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "hostile")
    r = proof.replay(_xss(f"<svg/onload=alert('{MARK}')>"), rounds=1)
    assert not r["reproduced"] and r["rounds"][0][0]["status"] == 0


def test_no_summary_fails_the_step(fake_browse, monkeypatch):
    monkeypatch.setenv("FAKE_MODE", "nosummary")
    r = proof.replay(_xss(f"<svg/onload=alert('{MARK}')>"), rounds=1)
    assert not r["reproduced"]
    assert all("no summary" in s["misses"][0] for s in r["rounds"][0])


def test_browse_without_marker_reads_the_dom_only(fake_browse):
    status, body, _ = proof._browse({"url": "http://t.test/#/x", "browse": {}})
    assert status == 200 and "rendered" in body and "console" not in body


def test_canonical_body():
    assert proof.browse_body({"status": 200, "dialogs": [{"message": MARK}]}, MARK) == (200, FORGED)
    assert proof.browse_body({"status": 200, "sentinel": MARK}, MARK) == (200, FORGED)
    assert proof.browse_body({"status": True, "dialogs": [{"message": f"x {MARK}"}]}, MARK) == (
        0,
        f"xss none (marker {MARK})",
    )


# ---------------------------------------------------------------- M3: headers
def _idor(headers: dict, method: str = "GET", as_: str | None = None) -> dict:
    u = "http://t.test/api/basket/7"
    return {
        "steps": [
            {"role": "attack", "as": "user-a", "method": method, "url": u, "expect": {"contains": ['"UserId":27']}},
            {"role": "control", "as": as_, "method": method, "url": u, "headers": headers, "expect": {"status": [401]}},
        ]
    }


@pytest.mark.parametrize(
    "name",
    [
        "X-BH-Identity",
        "x-bh-identity",
        "X-Bh-IDENTITY",
        "Host",
        "Cookie",
        "authorization",
        "X-HTTP-Method-Override",
        "X-Method-Override",
        "X-HTTP-Method",
    ],
)
def test_identity_host_and_method_headers_are_refused(name):
    errors = proof.validate(_idor({name: "user-b"}))
    assert any("not allowed in a proof" in e for e in errors), errors
    with pytest.raises(ValueError):
        proof._send(_idor({name: "user-b"})["steps"][1])  # replay does not rely on validate


def test_anonymous_write_stays_refused_with_an_identity_header():
    errors = proof.validate(_idor({"X-BH-Identity": "user-b"}, method="DELETE"))
    assert any("without an identity" in e for e in errors) and any("not allowed" in e for e in errors)


def test_bad_header_shapes():
    assert proof.validate(_idor(["X-BH-Identity", "user-b"]))  # type: ignore[arg-type]
    assert any("printable" in e for e in proof.validate(_idor({"X-Test": "a\r\nX-BH-Identity: user-b"})))
    assert any("token name" in e for e in proof.validate(_idor({"X Test": "a"})))
    assert proof.validate(_idor({"Accept": "application/json"})) == []


# ---------------------------------------------------------------- B11: regex
@pytest.mark.parametrize("rx", ["(a|a)+$", "(a|ab)*", "(a+)+", "(x*)*", "(a{2,})+", "((a|b)c)+", "(?:a|b){2,}"])
def test_backtracking_regex_is_refused(rx):
    doc = _idor({})
    doc["steps"][0]["expect"] = {"regex": rx}
    assert any("alternation" in e for e in proof.validate(doc))


@pytest.mark.parametrize("rx", [r'"UserId":\d+', r"(?i)admin", r"[(|)]+x", r"(abc)+", r"(a|b){2}", r"\(a|b\)+"])
def test_plain_regex_is_accepted(rx):
    doc = _idor({})
    doc["steps"][0]["expect"] = {"regex": rx}
    assert proof.validate(doc) == []


def test_regex_replay_is_bounded(monkeypatch):
    monkeypatch.setattr(proof, "REGEX_TIMEOUT_S", 0.5)
    ok, misses = proof._expect_holds({"regex": "(a|a)+$"}, 200, "a" * 40 + "b")
    assert not ok and misses == [proof.REGEX_TIMED_OUT]
    assert proof._expect_holds({"regex": r'"UserId":\d+'}, 200, '{"UserId":27}') == (True, [])


def test_undecided_control_counts_against_the_proof(monkeypatch):
    """A regex that only times out on the control's answer must not hide the missing differential."""
    monkeypatch.setattr(proof, "_search", lambda rx, body: None if body == "control" else True)

    def send(step):
        return (200, "attack", False) if step["role"] == "attack" else (401, "control", False)

    monkeypatch.setattr(proof, "_send", send)
    doc = _idor({})
    doc["steps"][0]["expect"] = {"regex": "x"}
    r = proof.replay(doc, rounds=1)
    assert r["control_disproves"] and not r["reproduced"]


def test_proof_file_round_trip(tmp_path, capsys):
    p = tmp_path / "proof.json"
    p.write_text(json.dumps(_idor({"X-BH-Identity": "user-b"})))
    proof.main([str(p)])
    assert "not allowed in a proof" in capsys.readouterr().out
