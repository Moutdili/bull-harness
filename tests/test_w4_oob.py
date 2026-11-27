"""W4-A (T23): an out-of-band listener published by Tailscale Funnel; the scope keys other W4 lots read.

Loopback only: the listener is bound on 127.0.0.1 with an ephemeral port; no container is started, no Tailscale."""

import contextlib
import hashlib
import json
import re
import socket
import threading
from pathlib import Path

import pytest
import yaml

from bh.gate import policy as pol
from bh.oob import listener
from bh.runner import observation
from bh.scope import ScopeError, check, load_scope, scope_from_dict
from bh.scope import extra as scope_extra
from bh.scope import guards
from bh.scope.model import parse_rule

ROOT = Path(__file__).resolve().parents[1]
OOB_NAME = "fedora-hp.tail13dc8b.ts.net"
TOKEN = "BH-SECRET-0123456789abcdef"
OTHER = "BH-SECRET-fedcba9876543210"


def _doc(tmp_path, **over):
    doc = {
        "schema": 1,
        "program": "t",
        "platform": "test",
        "in_scope": ["app.example.com", "*.api.example.com"],
        "support": [
            {"value": "cdn.example.net", "kind": "assets"},
            {"value": f"{OOB_NAME}:8443", "kind": "oob", "journal": str(tmp_path / "oob" / "oob.jsonl")},
        ],
        "payload_hosts": ["example.org"],
        "identities": [{"name": "user-a"}, {"name": "user-b"}],
    }
    doc.update(over)
    return doc


def _oob(tmp_path, value=f"{OOB_NAME}:8443", **extra):
    return {"value": value, "kind": "oob", "journal": str(tmp_path / "oob.jsonl"), **extra}


# ------------------------------------------------------------------ T23, scope
def test_oob_support_entry_is_parsed_kept_apart_and_shown_as_written(tmp_path):
    s = scope_from_dict(_doc(tmp_path))
    assert s.support_hosts("oob") == (f"{OOB_NAME}:8443",)
    assert s.oob.value == f"{OOB_NAME}:8443" and s.oob.host == OOB_NAME and s.oob.port == 8443
    assert s.oob.journal_path == tmp_path / "oob" / "oob.jsonl"
    assert s.oob.callback(TOKEN) == f"https://{OOB_NAME}:8443/c/{TOKEN}"
    assert [x.kind for x in s.support] == ["assets"]  # never a support host the gate would open
    assert not check(s, f"https://{OOB_NAME}:8443/c/{TOKEN}").allowed
    assert check(s, f"https://{OOB_NAME}:8443/").support is None
    # 443: no port in the value; 443 and 10000 admitted as written
    assert scope_from_dict(_doc(tmp_path, support=[_oob(tmp_path, OOB_NAME)])).support_hosts("oob") == (OOB_NAME,)
    for port in (443, 10000):
        v = f"{OOB_NAME}:{port}"
        assert scope_from_dict(_doc(tmp_path, support=[_oob(tmp_path, v)])).support_hosts("oob") == (v,)
    # without it, nothing
    bare = scope_from_dict(_doc(tmp_path, support=[]))
    assert bare.oob is None and bare.support_hosts("oob") == ()


@pytest.mark.parametrize("port", ["80", "8080", "22", "444", "0", "65536", "", "x"])
def test_oob_port_other_than_funnel_ones_is_refused(tmp_path, port):
    with pytest.raises(ScopeError, match="port"):
        scope_from_dict(_doc(tmp_path, support=[_oob(tmp_path, f"{OOB_NAME}:{port}")]))


@pytest.mark.parametrize(
    "value",
    [
        "https://fedora-hp.tail13dc8b.ts.net",
        f"{OOB_NAME}/c/",
        "*.tail13dc8b.ts.net",
        "ts.net",
        "tail13dc8b.ts.net",
        "100.64.0.1",
        "oast.pro",
        "abc.interact.sh",
        "",
    ],
)
def test_oob_value_is_one_funnel_name(tmp_path, value):
    with pytest.raises(ScopeError):
        scope_from_dict(_doc(tmp_path, support=[_oob(tmp_path, value)]))


def test_oob_entry_shape_one_per_scope_and_journal(tmp_path):
    two = [_oob(tmp_path), _oob(tmp_path, "other.tail13dc8b.ts.net")]
    with pytest.raises(ScopeError, match="one `oob`"):
        scope_from_dict(_doc(tmp_path, support=two))
    for bad in ("relative/oob.jsonl", "", "/var/../etc/x", None, 3):
        with pytest.raises(ScopeError, match="journal"):
            scope_from_dict(_doc(tmp_path, support=[{**_oob(tmp_path), "journal": bad}]))
    with pytest.raises(ScopeError, match="journal"):
        scope_from_dict(_doc(tmp_path, support=[{"value": OOB_NAME, "kind": "oob"}]))
    with pytest.raises(ScopeError, match="unknown keys"):
        scope_from_dict(_doc(tmp_path, support=[{**_oob(tmp_path), "token_paths": ["/x"]}]))
    with pytest.raises(ScopeError, match="unknown support keys"):  # `journal` belongs to `oob` only
        scope_from_dict(_doc(tmp_path, support=[{"value": "cdn.example.net", "kind": "assets", "journal": "/x"}]))
    ok = scope_from_dict(_doc(tmp_path, support=[{**_oob(tmp_path), "journal": "~/bh/var/oob/oob.jsonl"}]))
    assert ok.oob.journal_path == Path("~/bh/var/oob/oob.jsonl").expanduser()


def test_oob_is_never_a_target_a_subdomain_of_one_a_payload_or_a_support_host(tmp_path):
    cases = [
        {"in_scope": ["app.example.com", OOB_NAME]},
        {"in_scope": ["app.example.com", "*.tail13dc8b.ts.net"]},
        {"in_scope": ["app.example.com", "tail13dc8b.ts.net"]},  # a subdomain of a target
        {"in_scope": ["app.example.com", f"https://{OOB_NAME}:8443/x/"]},
        {"out_of_scope": [OOB_NAME]},
        {"payload_hosts": [OOB_NAME]},
        {"support": [_oob(tmp_path), {"value": OOB_NAME, "kind": "assets"}]},
    ]
    for over in cases:
        with pytest.raises(ScopeError):
            scope_from_dict(_doc(tmp_path, **{"support": [_oob(tmp_path)], **over}))


def test_no_scope_file_declares_an_oob_host():
    for f in sorted((ROOT / "scopes").rglob("*.yaml")):
        assert load_scope(f).oob is None, f
        assert "oob" not in f.read_text(), f


def test_an_approved_prefix_never_lands_on_the_listener(tmp_path):
    s = scope_from_dict(_doc(tmp_path))
    rule = parse_rule({"value": f"https://{OOB_NAME}/c/", "type": "url"}, "t")
    assert scope_extra.entry_problem(s, rule) == "the out-of-band listener"


# ------------------------------------------------------------------ gate: the listener opens nothing to the sandbox
def test_gate_refuses_the_listener_to_every_client(tmp_path):
    p = tmp_path / "state" / "active-scope.yaml"
    p.parent.mkdir()
    p.write_text(yaml.safe_dump(_doc(tmp_path)))
    g = pol.Policy(p)
    g.reload()
    assert g.scope is not None and g.scope.oob is not None, g.scope_error
    url = f"https://{OOB_NAME}:8443/c/{TOKEN}"
    for kw in ({}, {"browser": True}, {"enroll": True}):
        for port in (443, 8443, 10000):
            assert not g.classify_connect(OOB_NAME, port, **kw).allowed, (kw, port)
        for m in ("GET", "HEAD", "POST"):
            v = g.classify_request(url, OOB_NAME, m, **kw)
            assert not v.allowed and v.klass not in ("support", "payload", "target"), (kw, m, v)
    assert g.classify_request("https://app.example.com/", "app.example.com", "GET").allowed  # the scope is live


# ------------------------------------------------------------------ guards (W2) on the MSRC scopes
@pytest.mark.parametrize("f", sorted((ROOT / "scopes" / "msrc").glob("*.yaml")), ids=lambda f: f.stem)
def test_msrc_scopes_still_pass_their_guards(f, tmp_path):
    s = load_scope(f)
    assert guards.check(s) == []
    doc = yaml.safe_load(f.read_text())
    doc["support"] = [*(doc.get("support") or []), _oob(tmp_path)]
    assert guards.check(scope_from_dict(doc, str(f))) == []  # an `oob` entry does not break them either


# ------------------------------------------------------------------ keys owed to other lots
def test_cost_cap_usd(tmp_path):
    assert scope_from_dict(_doc(tmp_path)).cost_cap_usd is None
    assert scope_from_dict(_doc(tmp_path, cost_cap_usd=12)).cost_cap_usd == 12.0
    assert scope_from_dict(_doc(tmp_path, cost_cap_usd=0.5)).cost_cap_usd == 0.5
    for bad in (0, -1, True, "10", [], float("inf"), float("nan")):
        with pytest.raises(ScopeError, match="cost_cap_usd"):
            scope_from_dict(_doc(tmp_path, cost_cap_usd=bad))


def test_private_field(tmp_path):
    pf = {"url": "https://app.example.com/api/me", "method": "GET", "field": "profile.phone"}
    s = scope_from_dict(_doc(tmp_path, identities=[{"name": "user-a"}, {"name": "user-b", "private_field": pf}]))
    assert s.identities[1]["private_field"] == pf
    bads = [
        {**pf, "url": "https://elsewhere.example.net/me"},  # not in scope
        {**pf, "url": "ftp://app.example.com/me"},
        {**pf, "method": "DELETE"},
        {**pf, "field": ""},
        {**pf, "field": "a b"},
        {"url": pf["url"], "method": "GET"},
        {**pf, "extra": 1},
        "profile.phone",
    ]
    for bad in bads:
        with pytest.raises(ScopeError, match="private_field"):
            scope_from_dict(_doc(tmp_path, identities=[{"name": "user-a", "private_field": bad}]))


def test_whitebox(tmp_path):
    commit = "0123456789abcdef0123456789abcdef01234567"
    wb = [{"repo": "https://github.com/acme/app", "commit": commit}]
    assert scope_from_dict(_doc(tmp_path, whitebox=wb)).whitebox == ({"repo": wb[0]["repo"], "commit": commit},)
    bads = [
        {"repo": "http://github.com/acme/app", "commit": commit},
        {"repo": "https://user:pw@github.com/acme/app", "commit": commit},
        {"repo": "git@github.com:acme/app.git", "commit": commit},
        {"repo": "https://github.com/acme/app", "commit": commit[:39]},
        {"repo": "https://github.com/acme/app", "commit": "g" * 40},
        {"repo": "https://github.com/acme/app", "commit": "main"},
        {"repo": "https://github.com/acme/app"},
        {"repo": "https://github.com/acme/app", "commit": commit, "branch": "main"},
    ]
    for bad in bads:
        with pytest.raises(ScopeError, match="whitebox"):
            scope_from_dict(_doc(tmp_path, whitebox=[bad]))
    with pytest.raises(ScopeError, match="whitebox"):
        scope_from_dict(_doc(tmp_path, whitebox={"repo": "https://github.com/acme/app", "commit": commit}))


def test_mail_from(tmp_path):
    s = scope_from_dict(_doc(tmp_path, mail_from=["accountprotection.Microsoft.com", "microsoft.com"]))
    assert s.mail_from == ("accountprotection.microsoft.com", "microsoft.com")
    for bad in (["no-reply@microsoft.com"], ["*.microsoft.com"], ["10.0.0.1"], ["com"], ["co.uk"], [""], "x.com", [3]):
        with pytest.raises(ScopeError, match="mail_from"):
            scope_from_dict(_doc(tmp_path, mail_from=bad))


# ------------------------------------------------------------------ T23, listener (loopback)
@pytest.fixture
def served(tmp_path):
    journal = tmp_path / "oob.jsonl"
    srv = listener.serve("127.0.0.1", 0, journal)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1], journal
    srv.shutdown()
    srv.server_close()


def _ask(port: int, raw: bytes, body: bytes = b"", *, eof: bool = False) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        s.sendall(raw)
        if eof:
            s.shutdown(socket.SHUT_WR)

        def push():
            with contextlib.suppress(OSError):  # the listener closed without reading it
                s.sendall(body)

        pusher = threading.Thread(target=push, daemon=True)
        if body:
            pusher.start()
        data = b""
        while chunk := s.recv(4096):
            data += chunk
        return data


def _lines(journal: Path) -> list[dict]:
    return [json.loads(x) for x in journal.read_text().splitlines()] if journal.exists() else []


def test_listener_writes_one_line_for_a_valid_canary(served):
    port, journal = served
    out = _ask(port, f"GET /c/{TOKEN} HTTP/1.1\r\nHost: {OOB_NAME}\r\nX-Secret: zzz\r\n\r\n".encode())
    assert out == listener.RESPONSE == b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
    (line,) = _lines(journal)
    assert set(line) == {"ts", "proto", "token", "src"}
    assert line["proto"] == "http" and line["token"] == TOKEN and line["src"] == "127.0.0.1"
    assert isinstance(line["ts"], float)
    assert "zzz" not in journal.read_text() and OOB_NAME not in journal.read_text()
    # a query is ignored, never kept
    _ask(port, f"HEAD /c/{OTHER}?leak=abc HTTP/1.1\r\n\r\n".encode())
    assert [x["token"] for x in _lines(journal)] == [TOKEN, OTHER] and "leak" not in journal.read_text()


@pytest.mark.parametrize(
    "target",
    [
        "/",
        "/c/",
        "/c/BH-SECRET-0123456789ABCDEF",
        "/c/BH-SECRET-0123456789abcde",
        f"/c/{TOKEN}0",
        f"/c/{TOKEN}/",
        f"/c/{TOKEN}/x",
        f"/x/c/{TOKEN}",
        f"/C/{TOKEN}",
        f"/?c={TOKEN}",
        f"//c/{TOKEN}",
    ],
)
def test_listener_writes_nothing_without_a_canary_path(served, target):
    port, journal = served
    assert _ask(port, f"GET {target} HTTP/1.1\r\nHost: x\r\n\r\n".encode()) == listener.RESPONSE
    assert _lines(journal) == []


@pytest.mark.parametrize(
    "raw",
    [b"", b"garbage\r\n\r\n", b"GET\r\n\r\n", b"\xff\xfe /c/x HTTP/1.1\r\n\r\n", b"GET /c/" + b"a" * 9000 + b"\r\n"],
)
def test_listener_answers_the_same_bytes_to_anything(served, raw):
    port, journal = served
    assert _ask(port, raw, eof=True) == listener.RESPONSE
    assert _lines(journal) == []


def test_listener_never_reads_a_body(served):
    port, journal = served
    head = f"POST /c/{TOKEN} HTTP/1.1\r\nHost: x\r\nContent-Length: 1048576\r\n\r\n".encode()
    # announced, never sent: the answer comes at once (a listener that waited for the body would time out here)
    assert _ask(port, head) == listener.RESPONSE
    # sent in full: the same bytes, and the same one line
    assert _ask(port, head, b"B" * (1 << 20)) == listener.RESPONSE
    assert _ask(port, b"POST / HTTP/1.1\r\nContent-Length: 1048576\r\n\r\n", b"B" * (1 << 20)) == listener.RESPONSE
    lines = _lines(journal)
    assert [x["token"] for x in lines] == [TOKEN, TOKEN] and "B" * 8 not in journal.read_text()


def test_listener_journal_is_bounded_and_rotates(tmp_path):
    j = listener.Journal(tmp_path / "oob.jsonl", max_bytes=1000, keep=2)
    for _ in range(200):
        j.write(TOKEN, "127.0.0.1")
    files = sorted(p.name for p in tmp_path.iterdir())
    assert files == ["oob.jsonl", "oob.jsonl.1", "oob.jsonl.2"]
    assert all(p.stat().st_size <= 1000 for p in tmp_path.iterdir())
    assert oct((tmp_path / "oob.jsonl").stat().st_mode & 0o777) == "0o600"


def test_listener_defaults_to_the_loopback():
    assert listener.DEFAULT_HOST == "127.0.0.1"
    src = (ROOT / "src" / "bh" / "oob" / "listener.py").read_text()
    assert not re.search(r"^\s*(import|from)\s+(?!__future__|argparse|json|os|socket|socketserver|threading|time|"
                         r"pathlib|urllib\.parse|bh\.agent\.contract|contextlib)", src, re.M)  # fmt: skip
    assert "tailscale" not in src.split('"""', 2)[2].lower()  # no Tailscale command in the code


# ------------------------------------------------------------------ T23, container
def test_compose_oob_service_is_isolated_and_started_by_no_command():
    doc = yaml.safe_load((ROOT / "container" / "compose.yaml").read_text())
    svc = doc["services"]["oob"]
    assert svc["profiles"] == ["oob"]
    assert svc["ports"] and all(p.startswith("127.0.0.1:") for p in svc["ports"])
    assert svc["volumes"] == ["../var/oob:/journal:Z"]
    assert "sandbox" not in svc["networks"] and "egress" not in svc["networks"] and "lab" not in svc["networks"]
    assert "oob" in doc["networks"]  # its own network, shared with no other service (below)
    assert svc["cap_drop"] == ["ALL"] and "cap_add" not in svc and "no-new-privileges" in svc["security_opt"]
    assert str(svc["user"]).split(":")[0] not in ("0", "root") and svc["read_only"] is True
    assert not any(k in svc for k in ("env_file", "privileged", "network_mode", "pid", "ipc"))
    # no other service exposes a port, none joins the oob network
    for name, other in doc["services"].items():
        if name != "oob":
            assert "ports" not in other and "oob" not in (other.get("networks") or []), name
    containerfile = (ROOT / "container" / "oob" / "Containerfile").read_text()
    code = "\n".join(x for x in containerfile.splitlines() if not x.startswith("#"))
    assert re.search(r"^USER 10001", code, re.M) and "tailscale" not in code.lower()
    assert "8792" in containerfile and "/journal/oob.jsonl" in containerfile
    # no command of the harness starts it: the profile is named by nothing under src/ (but the listener) nor tools/
    for f in [*(ROOT / "src").rglob("*.py"), *(ROOT / "tools").rglob("*")]:
        if f.is_file() and "oob" not in f.parts:
            text = f.read_text(errors="replace")
            assert not re.search(r"profile[\"' ,=]+oob|bh-oob\b|\boob\.listener", text), f


# ------------------------------------------------------------------ T23, observation
OBS = {"token": TOKEN, "victim": "user-b", "attacker": "user-a"}


def _gate_events(tmp_path, monkeypatch, events):
    monkeypatch.setenv("BH_HOME", str(tmp_path))
    state = tmp_path / "var" / "state"
    state.mkdir(parents=True, exist_ok=True)
    (state / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events))


def _oob_lines(scope, *lines):
    p = scope.oob.journal_path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("".join(json.dumps(x) + "\n" for x in lines))


def test_observation_oob_line_with_the_victims_canary_verifies(tmp_path, monkeypatch):
    s = scope_from_dict(_doc(tmp_path))
    _gate_events(tmp_path, monkeypatch, [])
    _oob_lines(
        s,
        {"ts": 10.0, "proto": "http", "token": TOKEN, "src": "127.0.0.1"},
        {"ts": 11.0, "proto": "http", "token": OTHER, "src": "127.0.0.1"},
        {"ts": 9.0, "proto": "dns", "token": TOKEN, "src": "x"},  # not a line of ours: ignored
        "garbage",
    )
    evs = observation.journal(TOKEN, "t", s.oob)
    assert [(e["kind"], e["ts"]) for e in evs] == [("oob-http", 10.0)]
    out = observation.check({**OBS, "control": "0/3"}, s)
    assert out["status"] == "verified-evidence", out
    assert "out-of-band listener" in out["why"] and out["events"][0]["where"] == "oob-http"
    assert out["events"][0]["host"] == f"{OOB_NAME}:8443" and out["events"][0]["src"] == "127.0.0.1"
    # the listener's rotated file is read too
    s.oob.journal_path.rename(s.oob.journal_path.with_name("oob.jsonl.1"))
    assert observation.check({**OBS, "control": "0/3"}, s)["status"] == "verified-evidence"
    # a scope without the listener never reads it
    bare = scope_from_dict(_doc(tmp_path, support=[]))
    assert observation.check({**OBS, "control": "0/3"}, bare)["status"] == "inconclusive"


def test_observation_oob_canary_sent_by_the_attacker_is_rejected(tmp_path, monkeypatch):
    s = scope_from_dict(_doc(tmp_path))
    sent = {"kind": "canary", "token": TOKEN, "where": "request-url", "identity": "user-a", "client": "agent",
            "host": "app.example.com", "ts": 5.0, "program": "t"}  # fmt: skip
    _gate_events(tmp_path, monkeypatch, [sent])
    _oob_lines(s, {"ts": 10.0, "proto": "http", "token": TOKEN, "src": "127.0.0.1"})
    out = observation.check({**OBS, "control": "0/3"}, s)
    assert out["status"] == "rejected" and "the attacker supplied it" in out["why"]
    # an unnamed sender counts as the attacker; the victim's own send does not
    _gate_events(tmp_path, monkeypatch, [{**sent, "identity": None}])
    assert observation.check({**OBS, "control": "0/3"}, s)["status"] == "rejected"
    _gate_events(tmp_path, monkeypatch, [{**sent, "identity": "user-b"}])
    assert observation.check({**OBS, "control": "0/3"}, s)["status"] == "verified-evidence"


def test_observation_oob_without_control_is_inconclusive(tmp_path, monkeypatch):
    s = scope_from_dict(_doc(tmp_path))
    _gate_events(tmp_path, monkeypatch, [])
    _oob_lines(s, {"ts": 10.0, "proto": "http", "token": TOKEN, "src": "127.0.0.1"})
    for obs in (OBS, {**OBS, "control": "1/3"}, {**OBS, "control": "x"}):
        out = observation.check(obs, s)
        assert out["status"] == "inconclusive", obs


def test_observation_by_digest(tmp_path, monkeypatch):
    s = scope_from_dict(_doc(tmp_path))
    digest = hashlib.sha256(TOKEN.encode()).hexdigest()
    obs = observation.valid({"token_sha256": digest, "victim": "user-b", "attacker": "user-a", "control": "0/3"})
    assert obs == {"token_sha256": digest, "victim": "user-b", "attacker": "user-a", "control": "0/3"}
    assert observation.valid({"token_sha256": "ab" * 31, "victim": "user-b", "attacker": "user-a"}) is None
    assert observation.valid({"token": "nope", "token_sha256": digest, "victim": "b", "attacker": "a"}) is None
    _gate_events(tmp_path, monkeypatch, [])
    _oob_lines(s, {"ts": 10.0, "proto": "http", "token": TOKEN, "src": "127.0.0.1"})
    out = observation.check(obs, s)
    assert out["status"] == "verified-evidence" and TOKEN not in out["why"]
    # the gate's events by digest too, attacker first: rejected
    sent = {"kind": "canary", "token": TOKEN, "where": "request-body", "identity": "user-a", "client": "agent",
            "ts": 1.0, "program": "t"}  # fmt: skip
    _gate_events(tmp_path, monkeypatch, [sent])
    assert observation.check(obs, s)["status"] == "rejected"
    other = hashlib.sha256(OTHER.encode()).hexdigest()
    assert observation.check({**obs, "token_sha256": other}, s)["status"] == "inconclusive"


# ------------------------------------------------------------------ the four skills, with and without a listener
SKILLS = ROOT / "src" / "bh" / "skills"


@pytest.mark.parametrize("name", ["ssrf", "xxe", "prompt-injection", "ai-connectors"])
def test_skills_say_both_cases(name):
    text = " ".join((SKILLS / name / "SKILL.md").read_text().split())
    assert "support (oob)" in text  # the scope block's line (lot D renders it)
    assert "https://<oob host>/c/" in text and "<canary>" in text
    assert "one call" in text and "--observation <canary>" in text and "--control 0/N" in text
    assert 'bh-note blocked oob-needed "' in text  # without the listener, as before
    assert "No `support (oob)` line" in text or "No `support (oob)` host" in text
    assert not re.search(r"interactsh|burpcollaborator|oast\.|webhook\.site|requestbin", text, re.I)
    assert "no out-of-band listener" not in text.lower().replace("there is no out-of-band listener;", "")


def test_ssrf_keeps_its_ban_on_internal_addresses():
    text = (SKILLS / "ssrf" / "SKILL.md").read_text()
    never = text.split("## Never", 1)[1].split("##", 1)[0]
    assert "loopback, link-local, cloud metadata or internal" in never
    assert "Put anything but the canary in a callback URL" in never
