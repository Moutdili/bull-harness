"""bh-browser controller, second pass (audit docs/research/19): one account per profile (B3), challenge detection on
a real-shaped DOM (B4), switch (I2), reading and driving ops (I3), websocket frames (I4), the operator at the screen
(I12), the fill budget (I17), resuming after a challenge. No browser, no podman."""

import base64
import json
from html.parser import HTMLParser
from pathlib import Path
from typing import ClassVar

import pytest

from bh.browser_service import AGENT_OPS, HOST_OPS
from bh.browser_service.controller import FILL_SEGMENT, UPLOAD_MAX, Controller, Refused, validate, x11vnc_argv
from bh.browser_service.detect import challenge, frame_text
from test_browser_service import COOKIE_VALUE, TURNSTILE, FakeDriver, session_req

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------- a DOM -> snapshot, as the driver reads it
class _Snap(HTMLParser):
    SKIP: ClassVar[set[str]] = {"script", "style", "head", "title"}

    def __init__(self):
        super().__init__()
        self.text, self.frames, self.title, self._skip, self._in_title = [], [], "", 0, False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in self.SKIP:
            self._skip += 1
        if tag == "title":
            self._in_title = True
        if tag == "iframe":
            hidden = "hidden" in a or "display:none" in (a.get("style") or "").replace(" ", "")
            self.frames.append({"url": a.get("src") or "", "visible": not hidden})

    def handle_endtag(self, tag):
        if tag in self.SKIP:
            self._skip -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif not self._skip and data.strip():
            self.text.append(data.strip())


def snapshot_of(html: str, url="https://copilot.microsoft.com/chats/x") -> dict:
    p = _Snap()
    p.feed(html)
    text = "\n".join(p.text)
    return {"url": url, "title": p.title.strip(), "text": text, "text_len": len(text), "frames": p.frames}


COPILOT = (FIXTURES / "copilot_verification_required.html").read_text()


# ---------------------------------------------------------------- B4: detection
def test_the_copilot_verification_required_dom_is_a_pending_challenge():
    snap = snapshot_of(COPILOT)
    assert snap["text_len"] > 600 and "Verification required" in snap["text"]
    assert challenge(snap)["pending"] is True
    # the label alone holds even if the widget's iframe is collapsed (hidden) under it
    hidden = {**snap, "frames": [{**f, "visible": False} for f in snap["frames"]]}
    got = challenge(hidden)
    assert got["pending"] is True and got["reason"] == "text: verification required"


def test_a_conversation_quoting_security_check_is_not_a_challenge():
    html = COPILOT.replace("<span>Verification required</span>", "").replace(
        'src="https://challenges.cloudflare.com', 'src="https://www.youtube.com'
    )
    html = html.replace("Now give me three", "What is a security check and how do I verify you are human? Give three")
    snap = snapshot_of(html)
    assert "security check" in snap["text"] and snap["text_len"] > 600
    assert challenge(snap)["pending"] is False


def test_unknown_visibility_of_a_challenge_frame_fails_closed():
    assert challenge({"text": "", "frames": [{"url": TURNSTILE, "visible": None}]})["pending"] is True
    # a frame of another host whose visibility is unknown is not a challenge
    assert challenge({"text": "", "frames": [{"url": "https://ads.example/x", "visible": None}]})["pending"] is False


@pytest.mark.parametrize(
    ("snap", "pending"),
    [
        ({"title": "Just a moment...", "text": "x" * 5000 + " Verify you are human"}, True),  # interstitial title
        ({"title": "Chat", "text": "Vérification requise"}, True),  # short page
        ({"title": "Chat", "text": "y" * 700 + " verification required"}, False),  # long page, no frame, no title
    ],
)
def test_the_text_rule_needs_a_frame_a_title_or_a_short_page(snap, pending):
    assert challenge({**snap, "frames": []})["pending"] is pending


# ---------------------------------------------------------------- B3: one account per profile
def test_the_marker_survives_a_restart_and_blocks_another_identity(tmp_path):
    ctl = Controller(FakeDriver(), store=str(tmp_path), clock=lambda: 100.0)
    assert ctl.handle(HOST_OPS, session_req())[0] == 200
    marker = json.loads((tmp_path / "bh-identity.json").read_text())
    assert marker == {"program": "msrc-copilot", "identity": "user-a", "loaded_at": 100.0}
    # a new controller (container restarted) reads it back
    again = Controller(FakeDriver(), store=str(tmp_path))
    code, st = again.handle(HOST_OPS, {"op": "status"})
    assert code == 200 and (st["program"], st["identity"]) == ("msrc-copilot", "user-a")
    assert again.handle(AGENT_OPS, {"op": "state"})[1]["identity"] == "user-a"
    # another identity on the same profile: refused, nothing added to the browser
    d = FakeDriver()
    ctl2 = Controller(d, store=str(tmp_path))
    code, out = ctl2.handle(HOST_OPS, {**session_req(), "identity": "user-b"})
    assert code == 409 and out["error"] == "profile-holds-another-identity" and d.cookies == []
    # the same identity again (a refresh of its cookies) is fine; after a reset, user-b loads
    assert ctl2.handle(HOST_OPS, session_req())[0] == 200
    assert ctl2.handle(HOST_OPS, {"op": "reset"})[0] == 200
    assert not (tmp_path / "bh-identity.json").exists()
    assert ctl2.handle(HOST_OPS, {**session_req(), "identity": "user-b"})[0] == 200


def test_an_unreadable_marker_names_an_unknown_account(tmp_path):
    (tmp_path / "bh-identity.json").write_text("{not json")
    ctl = Controller(FakeDriver(), store=str(tmp_path))
    assert ctl.handle(HOST_OPS, session_req())[0] == 409


# ---------------------------------------------------------------- resume after a challenge
def _pending_driver():
    return FakeDriver(
        {"url": "https://copilot.example/", "title": "x", "text": "", "frames": [{"url": TURNSTILE, "visible": True}]}
    )


def test_goto_and_reset_never_reload_the_page_during_a_challenge(tmp_path):
    d = _pending_driver()
    ctl = Controller(d, store=str(tmp_path))
    ctl.handle(HOST_OPS, session_req())
    code, out = ctl.handle(AGENT_OPS, {"op": "goto", "url": "https://copilot.example/"})
    assert code == 409 and out["error"] == "human-needed"
    code, out = ctl.handle(HOST_OPS, {"op": "reset"})
    assert code == 409 and out["error"] == "human-needed"
    code, out = ctl.handle(AGENT_OPS, {"op": "upload", "css": "input", "name": "a.txt", "content_b64": "eA=="})
    assert code == 409
    assert d.calls == []  # nothing reached the page: the typed message stays in the composer
    assert (tmp_path / "bh-identity.json").exists()
    # the host may still force it (prepare: two accounts mixed is worse than a lost challenge)
    assert ctl.handle(HOST_OPS, {"op": "reset", "force": True})[0] == 200 and ("wipe",) in d.calls


def test_cleared_at_tells_when_the_challenge_went_away():
    now = [10.0]
    d = _pending_driver()
    ctl = Controller(d, clock=lambda: now[0])
    st = ctl.handle(AGENT_OPS, {"op": "state"})[1]
    assert st["challenge"]["pending"] and st["challenge"]["since"] == 10.0 and st["challenge"]["cleared_at"] is None
    d.snap = {**d.snap, "frames": []}
    now[0] = 20.0
    st = ctl.handle(AGENT_OPS, {"op": "state"})[1]
    assert not st["challenge"]["pending"] and st["challenge"]["cleared_at"] == 20.0
    now[0] = 30.0
    assert ctl.handle(AGENT_OPS, {"op": "state"})[1]["challenge"]["cleared_at"] == 20.0  # kept


# ---------------------------------------------------------------- I17: fill budget
def test_the_81st_fill_of_a_segment_is_refused_and_the_host_resets_it(tmp_path):
    ctl = Controller(FakeDriver(), store=str(tmp_path), clock=lambda: 1_700_000_000.0)
    ctl.handle(HOST_OPS, session_req())
    for _ in range(FILL_SEGMENT):
        assert ctl.handle(AGENT_OPS, {"op": "fill", "css": "textarea", "text": "hi"})[0] == 200
    code, out = ctl.handle(AGENT_OPS, {"op": "fill", "css": "textarea", "text": "hi"})
    assert code == 429 and out["error"] == "fill-budget" and "80 prompts" in out["detail"]
    assert ctl.handle(AGENT_OPS, {"op": "state"})[1]["fills"]["segment_left"] == 0
    assert ctl.handle(HOST_OPS, {"op": "fill_budget_reset"})[0] == 200
    assert ctl.handle(AGENT_OPS, {"op": "fill", "css": "textarea", "text": "hi"})[0] == 200


def test_the_daily_budget_is_per_identity_and_survives_a_reset_and_a_restart(tmp_path):
    day = 1_700_000_000.0
    d = FakeDriver()
    ctl = Controller(d, store=str(tmp_path), clock=lambda: day, fill_segment=1000, fill_day=3)
    ctl.handle(HOST_OPS, session_req())
    for _ in range(3):
        assert ctl.handle(AGENT_OPS, {"op": "fill", "css": "t", "text": "x"})[0] == 200
    ctl.handle(HOST_OPS, {"op": "reset"})
    ctl.handle(HOST_OPS, session_req())
    again = Controller(FakeDriver(), store=str(tmp_path), clock=lambda: day, fill_segment=1000, fill_day=3)
    code, out = again.handle(AGENT_OPS, {"op": "fill", "css": "t", "text": "x"})
    assert code == 429 and "daily" in out["detail"]
    # another identity has its own day; the next UTC day starts over
    again.handle(HOST_OPS, {"op": "reset"})
    again.handle(HOST_OPS, {**session_req(), "identity": "user-b"})
    assert again.handle(AGENT_OPS, {"op": "fill", "css": "t", "text": "x"})[0] == 200
    later = Controller(FakeDriver(), store=str(tmp_path), clock=lambda: day + 86400, fill_segment=1000, fill_day=3)
    later.handle(HOST_OPS, {"op": "reset"})
    later.handle(HOST_OPS, session_req())
    assert later.handle(AGENT_OPS, {"op": "fill", "css": "t", "text": "x"})[0] == 200


def test_a_failed_fill_does_not_spend_the_budget():
    d = FakeDriver()

    def boom(css, text):
        raise RuntimeError("no such element")

    d.fill = boom
    ctl = Controller(d)
    assert ctl.handle(AGENT_OPS, {"op": "fill", "css": "t", "text": "x"})[0] == 502
    assert ctl.handle(AGENT_OPS, {"op": "state"})[1]["fills"]["segment_left"] == FILL_SEGMENT


# ---------------------------------------------------------------- I12: the operator at the screen
def test_while_the_operator_looks_the_agent_only_reads():
    now = [1000.0]
    d = FakeDriver()
    ctl = Controller(d, clock=lambda: now[0])
    assert ctl.handle(HOST_OPS, {"op": "human_viewing", "on": True})[0] == 200
    for req in (
        {"op": "goto", "url": "https://app.example/"},
        {"op": "click", "css": "a"},
        {"op": "fill", "css": "t", "text": "x"},
        {"op": "press", "key": "Enter"},
        {"op": "wait", "ms": 10},
        {"op": "switch", "identity": "user-b"},
    ):
        code, out = ctl.handle(AGENT_OPS, req)
        assert code == 409 and out["error"] == "human-viewing", req
    assert d.calls == []
    for req in ({"op": "state"}, {"op": "text"}, {"op": "frames"}):
        assert ctl.handle(AGENT_OPS, req)[0] == 200
    assert ctl.handle(AGENT_OPS, {"op": "state"})[1]["human_viewing"] is True
    ctl.handle(HOST_OPS, {"op": "human_viewing", "on": False})
    assert ctl.handle(AGENT_OPS, {"op": "click", "css": "a"})[0] == 200
    # a UI that died without saying "off": the flag lapses after its TTL
    ctl.handle(HOST_OPS, {"op": "human_viewing", "on": True})
    now[0] += 601
    assert ctl.handle(AGENT_OPS, {"op": "click", "css": "a"})[0] == 200


def test_j_ai_fini_turns_the_open_screen_into_a_spectator_and_the_agent_goes_on():
    now = [1000.0]
    d = FakeDriver()
    ctl = Controller(d, clock=lambda: now[0])
    ctl.handle(HOST_OPS, {"op": "human_viewing", "on": True})
    assert ctl.handle(AGENT_OPS, {"op": "click", "css": "a"})[0] == 409
    code, out = ctl.handle(HOST_OPS, {"op": "human_done"})
    assert code == 200 and out["watching"] is True and out["challenge_pending"] is False
    st = ctl.handle(AGENT_OPS, {"op": "state"})[1]
    assert st["human_viewing"] is False and st["human_watching"] is True
    assert ctl.handle(AGENT_OPS, {"op": "click", "css": "a"})[0] == 200
    # the UI keeps re-asserting "on" while the screen stays open: still a spectator
    ctl.handle(HOST_OPS, {"op": "human_viewing", "on": True})
    assert ctl.handle(AGENT_OPS, {"op": "press", "key": "Enter"})[0] == 200


def test_a_new_challenge_gives_the_screen_back_to_the_operator():
    d = FakeDriver()
    ctl = Controller(d, clock=lambda: 1000.0)
    ctl.handle(HOST_OPS, {"op": "human_viewing", "on": True})
    ctl.handle(HOST_OPS, {"op": "human_done"})
    d.snap = {**d.snap, "frames": [{"url": TURNSTILE, "visible": True}]}
    st = ctl.handle(AGENT_OPS, {"op": "state"})[1]
    assert st["challenge"]["pending"] and st["human_viewing"] is True and st["human_watching"] is False
    d.snap = {**d.snap, "frames": []}
    assert ctl.handle(AGENT_OPS, {"op": "click", "css": "a"})[0] == 409  # solved, but not handed back yet


def test_j_ai_fini_while_the_challenge_is_still_there_keeps_the_agent_off():
    d = FakeDriver()
    d.snap = {**d.snap, "frames": [{"url": TURNSTILE, "visible": True}]}
    ctl = Controller(d, clock=lambda: 1000.0)
    ctl.handle(HOST_OPS, {"op": "human_viewing", "on": True})
    code, out = ctl.handle(HOST_OPS, {"op": "human_done"})
    assert code == 200 and out["watching"] is False and out["challenge_pending"] is True
    assert ctl.handle(AGENT_OPS, {"op": "state"})[1]["human_viewing"] is True


def test_closing_the_last_screen_ends_the_spectator_mode():
    ctl = Controller(FakeDriver(), clock=lambda: 1000.0)
    ctl.handle(HOST_OPS, {"op": "human_viewing", "on": True})
    ctl.handle(HOST_OPS, {"op": "human_done"})
    ctl.handle(HOST_OPS, {"op": "human_viewing", "on": False})
    ctl.handle(HOST_OPS, {"op": "human_viewing", "on": True})  # reopened: the operator's hand again
    assert ctl.handle(AGENT_OPS, {"op": "click", "css": "a"})[0] == 409


def test_the_agent_cannot_set_human_viewing():
    with pytest.raises(Refused):
        validate(AGENT_OPS, {"op": "human_viewing", "on": False})


# ---------------------------------------------------------------- I2: switch
def test_switch_is_recorded_for_the_host_and_cleared_by_the_load():
    ctl = Controller(FakeDriver())
    ctl.handle(HOST_OPS, session_req())
    code, out = ctl.handle(AGENT_OPS, {"op": "switch", "identity": "user-b"})
    assert code == 200 and out["switch_requested"] == "user-b" and "challenge" in out["note"]
    assert ctl.handle(HOST_OPS, {"op": "status"})[1]["switch_requested"] == "user-b"
    ctl.handle(HOST_OPS, {"op": "reset"})
    ctl.handle(HOST_OPS, {**session_req(), "identity": "user-b"})
    st = ctl.handle(AGENT_OPS, {"op": "state"})[1]
    assert st["identity"] == "user-b" and st["switch_requested"] is None
    ctl.handle(AGENT_OPS, {"op": "switch", "identity": "ghost"})
    ctl.handle(HOST_OPS, {"op": "switch_refused", "identity": "ghost", "reason": "not a live identity"})
    st = ctl.handle(AGENT_OPS, {"op": "state"})[1]
    assert st["switch_requested"] is None and "not a live identity" in st["switch_error"]
    with pytest.raises(Refused):
        validate(AGENT_OPS, {"op": "switch", "identity": "../user-b"})


# ---------------------------------------------------------------- I3: reading and driving
def test_text_tail_gives_the_end_of_a_long_chat():
    page = "old " * 5000 + "LAST ANSWER: 42"
    code, out = Controller(FakeDriver(text=page)).handle(AGENT_OPS, {"op": "text", "tail": 3000})
    assert code == 200 and out["text"].endswith("LAST ANSWER: 42") and len(out["text"]) == 3000
    assert out["truncated"] and out["length"] == len(page)
    assert validate(AGENT_OPS, {"op": "text", "css": "main", "tail": 10})[1] == {"css": "main", "tail": 10}
    with pytest.raises(Refused):
        validate(AGENT_OPS, {"op": "text", "tail": 0})


def test_outline_attr_tabs():
    d = FakeDriver()
    d.attrs = {("a.share", "href"): "https://copilot.example/shares/abc123"}
    ctl = Controller(d)
    assert "textbox" in ctl.handle(AGENT_OPS, {"op": "outline"})[1]["outline"]
    out = ctl.handle(AGENT_OPS, {"op": "attr", "css": "a.share", "name": "href"})[1]
    assert out["value"] == "https://copilot.example/shares/abc123"
    with pytest.raises(Refused):
        validate(AGENT_OPS, {"op": "attr", "css": "a", "name": "on click"})
    code, out = ctl.handle(AGENT_OPS, {"op": "tabs", "select": 0})
    assert code == 200 and out["current"] == 0 and ("select_tab", 0) in d.calls


def test_net_reports_gate_refusals_with_redacted_urls():
    d = FakeDriver()
    d.net_rows = [
        {"t": 1, "method": "GET", "url": "https://app.example/api?access_token=abcdef123456", "status": 200},
        {
            "t": 2,
            "method": "POST",
            "url": "https://evil.example/x",
            "status": 403,
            "denied": True,
            "reason": "bh-gate: DENIED (x)",
        },
    ]
    ctl = Controller(d)
    out = ctl.handle(AGENT_OPS, {"op": "net"})[1]
    assert out["count"] == 2 and "abcdef123456" not in json.dumps(out)
    out = ctl.handle(AGENT_OPS, {"op": "net", "denied": True})[1]
    assert [r["method"] for r in out["requests"]] == ["POST"] and out["requests"][0]["reason"].startswith("bh-gate")


def test_upload_is_in_memory_and_bounded():
    d = FakeDriver()
    ctl = Controller(d)
    data = b"%PDF-1.4 hello"
    code, out = ctl.handle(
        AGENT_OPS,
        {"op": "upload", "css": "input[type=file]", "name": "doc.pdf", "content_b64": base64.b64encode(data).decode()},
    )
    assert code == 200 and out["bytes"] == len(data)
    assert d.calls == [("upload", "input[type=file]", "doc.pdf", "application/pdf", data)]
    for bad in (
        {"name": "../etc/passwd", "content_b64": "eA=="},
        {"name": "a.txt", "content_b64": "not base64!"},
        {"name": "a.txt", "content_b64": base64.b64encode(b"x" * (UPLOAD_MAX + 1)).decode()},
    ):
        with pytest.raises(Refused):
            validate(AGENT_OPS, {"op": "upload", "css": "input", **bad})


# ---------------------------------------------------------------- I4: websocket frames
CHALLENGE_TOKEN = "0.ZmFrZS10dXJuc3RpbGUtdG9rZW4tdmFsdWUtMTIzNDU2Nzg5"


def test_no_frame_output_carries_a_challenge_token():
    raw = [
        json.dumps({"type": 1, "target": "ChallengeProof", "arguments": [{"token": CHALLENGE_TOKEN}]}) + "\x1e",
        json.dumps({"type": 1, "target": "send", "arguments": [{"text": "hello", "turnstileToken": CHALLENGE_TOKEN}]}),
        json.dumps({"event": "appendText", "text": "Paris is the capital", "messageId": "m1"}) + "\x1e",
        f"auth token={CHALLENGE_TOKEN}&x=1",
        json.dumps({"meta": {"accessToken": CHALLENGE_TOKEN, "id_token": "eyJhbGciOiJI.eyJzdWIiOiIx.sig"}}),
        b"\x00\x01binary",
    ]
    kept = [frame_text(p, set()) for p in raw]
    assert kept[0] is None and kept[1] is None  # ChallengeProof, a Turnstile answer: dropped whole
    assert kept[3] is not None and kept[4] is not None  # token values replaced, the rest kept
    assert kept[2] and "Paris is the capital" in kept[2]
    assert kept[5] == "<binary 8 bytes>"
    d = FakeDriver()
    d.frame_rows = [
        {"t": i, "dir": "recv", "url": "wss://substrate.example/hub", "text": t} for i, t in enumerate(kept) if t
    ]
    out = Controller(d).handle(AGENT_OPS, {"op": "frames", "last": 50})[1]
    blob = json.dumps(out) + json.dumps(kept)
    assert CHALLENGE_TOKEN not in blob and "eyJzdWIiOiIx" not in blob
    assert out["count"] == 4


# ---------------------------------------------------------------- minor: late cookies, x11vnc clipboard
def test_a_cookie_set_after_the_load_is_scrubbed_too():
    d = FakeDriver(text="your new session: late-cookie-value-987654")
    d.late_cookies = ["late-cookie-value-987654"]
    out = Controller(d).handle(AGENT_OPS, {"op": "text"})[1]
    assert "late-cookie-value-987654" not in out["text"]
    ctl = Controller(FakeDriver(text=f"x {COOKIE_VALUE}"))
    ctl.handle(HOST_OPS, session_req())
    assert COOKIE_VALUE not in json.dumps(ctl.handle(AGENT_OPS, {"op": "text"}))


def test_x11vnc_exchanges_no_clipboard():
    argv = x11vnc_argv()
    assert "-noclipboard" in argv and "-nosetclipboard" in argv and "-localhost" in argv


# ---------------------------------------------------------------- B4 follow-up: a real snapshot, host only
def test_snapshot_is_a_host_op_the_agent_cannot_ask():
    with pytest.raises(Refused):
        validate(AGENT_OPS, {"op": "snapshot"})
    assert validate(HOST_OPS, {"op": "snapshot"}) == ("snapshot", {})
    with pytest.raises(Refused):
        validate(HOST_OPS, {"op": "snapshot", "html": True})


def test_snapshot_is_what_detect_reads_scrubbed_and_feeds_challenge_back(tmp_path, monkeypatch):
    from bh.browser_service import host

    snap = snapshot_of(COPILOT)
    snap["text"] += f"\nsid={COOKIE_VALUE}"
    snap["url"] = f"https://copilot.microsoft.com/chats/x?access_token={COOKIE_VALUE}"
    d = FakeDriver(snapshot=snap)
    ctl = Controller(d, clock=lambda: 42.0)
    ctl.handle(HOST_OPS, session_req())
    code, out = ctl.handle(HOST_OPS, {"op": "snapshot"})
    assert code == 200 and out["challenge"]["pending"] is True and out["taken_at"] == 42.0
    assert set(out["snapshot"]) == {"url", "title", "text", "text_len", "frames"}  # never the HTML
    assert COOKIE_VALUE not in json.dumps(out)
    assert any("challenges.cloudflare.com" in f["url"] for f in out["snapshot"]["frames"])

    monkeypatch.setenv("BH_HOME", str(tmp_path))
    f = tmp_path / "snap.json"
    got = host.save_snapshot(f, call_=lambda req: {"code": code, **out} if req == {"op": "snapshot"} else {})
    assert got == {"ok": True, "file": str(f), "challenge": out["challenge"]}
    assert f.stat().st_mode & 0o777 == 0o600
    saved = json.loads(f.read_text())
    assert challenge(saved["snapshot"]) == saved["challenge"]  # the file is a fixture detect can be tested on
    assert host.save_snapshot(f, call_=lambda req: {"code": 503, "error": "down"})["code"] == 503


# ---------------------------------------------------------------- bh-web ws-rewrite (Mio, 2026-11-26)
def test_rewrite_changes_one_occurrence_of_a_client_text_frame():
    from bh.browser_service.detect import rewrite_client_frame

    frame = '{"arguments":[{"conversationTransferToken":"eyJBBBB","x":"eyJBBBB"}]}\x1e'
    out, done = rewrite_client_frame(frame, "eyJBBBB", "eyJCCCC")
    assert done and out == '{"arguments":[{"conversationTransferToken":"eyJCCCC","x":"eyJBBBB"}]}\x1e'
    assert rewrite_client_frame(frame, "absent-string", "x") == (frame, False)


def test_rewrite_never_touches_a_challenge_frame_nor_a_binary_one():
    from bh.browser_service.detect import rewrite_client_frame

    proof = '{"arguments":[{"type":"ChallengeProof","method":"CloudflareTurnstile","token":"abcdefgh"}]}'
    assert rewrite_client_frame(proof, "abcdefgh", "zzzzzzzz") == (proof, False)
    blob = b"abcdefgh-binary"
    assert rewrite_client_frame(blob, "abcdefgh", "zzzzzzzz") == (blob, False)


def test_ws_rewrite_is_an_agent_op_validated_and_handed_to_the_driver():
    d = FakeDriver()
    armed = []
    d.ws_rewrite = lambda find, replace, url_contains, ttl: armed.append((find, replace, url_contains, ttl)) or {
        "armed": True
    }
    ctl = Controller(d)
    code, out = ctl.handle(AGENT_OPS, {"op": "ws_rewrite", "find": "eyJBBBBBB", "replace": "eyJCCCCCC"})
    assert code == 200 and out["ok"] and armed == [("eyJBBBBBB", "eyJCCCCCC", "/Chathub/", 180)]
    for bad in (
        {"op": "ws_rewrite", "find": "short", "replace": "x"},  # under 8 characters: too vague to aim
        {"op": "ws_rewrite", "find": "eyJBBBBBB", "replace": "x", "ttl": 3600},
        {"op": "ws_rewrite", "find": "eyJBBBBBB", "replace": "x", "extra": 1},
    ):
        assert ctl.handle(AGENT_OPS, bad)[0] == 400, bad
    assert len(armed) == 1


def test_ws_rewrite_waits_like_any_action_while_the_operator_has_the_screen():
    ctl = Controller(FakeDriver(), clock=lambda: 1000.0)
    ctl.handle(HOST_OPS, {"op": "human_viewing", "on": True})
    code, out = ctl.handle(AGENT_OPS, {"op": "ws_rewrite", "find": "eyJBBBBBB", "replace": "eyJCCCCCC"})
    assert code == 409 and out["error"] == "human-viewing"
