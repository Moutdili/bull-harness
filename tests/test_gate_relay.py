"""The Claude API relay judges what a request asks Anthropic to do (H1): client tools only, no MCP servers, no URL
sources, anthropic-beta on a list, the model bound to the container that asks."""

import json
import os
import time
from types import SimpleNamespace

import pytest

from bh import paths
from bh.gate import policy as pol

AGENT, JUDGE = frozenset({"agent"}), frozenset({"judge"})
BASH = {"name": "Bash", "description": "run", "input_schema": {"type": "object", "properties": {}}}


def body(**kw) -> bytes:
    doc = {"model": "claude-sonnet-5-5", "max_tokens": 10, "messages": [{"role": "user", "content": "hi"}]}
    doc.update(kw)
    return json.dumps(doc).encode()


def check(b, betas=(), models=None):
    models = pol.relay_models()["agent"] if models is None else models
    return pol.check_relay(b, list(betas), models, pol.relay_betas())


def test_a_claude_code_request_passes():
    tools = [BASH, {**BASH, "name": "Read", "type": "custom", "strict": True, "cache_control": {"type": "ephemeral"}}]
    why, model = check(
        body(tools=tools), ["oauth-2025-04-20", "claude-code-20250219", "interleaved-thinking-2025-05-14"]
    )
    assert why is None and model == "claude-sonnet-5-5"
    image = {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AA=="}}
    assert check(body(messages=[{"role": "user", "content": [image]}]))[0] is None


@pytest.mark.parametrize(
    "tool",
    [
        {"type": "web_search_20260209", "name": "web_search"},
        {"type": "web_fetch_20260209", "name": "web_fetch"},
        {"type": "code_execution_20260521", "name": "code_execution"},
        {"type": "computer_toolset_20260801", "name": "computer"},
        {"type": "bash_20250124", "name": "bash"},
        {"type": "mcp_toolset", "mcp_server_name": "x"},
        {"type": "advisor_20260301", "name": "advisor", "model": "claude-opus-5-5"},
        {"type": "tool_search_tool_regex", "name": "tool_search_tool_regex"},
        {"name": "web_search"},  # no input_schema: not a client tool
        {**BASH, "input_schema": {"type": "string"}},
        {**BASH, "name": "has space"},
        {**BASH, "allowed_callers": ["code_execution_20260120"]},
        {**BASH, "max_uses": 5},  # a server tool's field on a client-shaped tool
        "web_search",
    ],
)
def test_server_or_non_client_tools_are_refused(tool):
    why, _ = check(body(tools=[BASH, tool]))
    assert why and "client tools only" in why


def test_egress_fields_url_sources_and_unreadable_bodies_are_refused():
    mcp = [{"type": "url", "url": "https://evil.test/mcp", "name": "x"}]
    assert "mcp_servers" in check(body(mcp_servers=mcp))[0]
    assert "container" in check(body(container={"skills": []}))[0]
    url_doc = {"type": "document", "source": {"type": "url", "url": "https://evil.test/x.pdf"}}
    nested = {"type": "tool_result", "tool_use_id": "t", "content": [url_doc]}
    assert "url source" in check(body(messages=[{"role": "user", "content": [nested]}]))[0]
    assert "file source" in check(body(system=[{"type": "image", "source": {"type": "file", "file_id": "f"}}]))[0]
    assert "tools is not a list" in check(body(tools={"name": "x"}))[0]
    for bad in (b"", None, b"{not json", b"[1, 2]", b'"x"', b" " * (pol.RELAY_BODY_MAX + 1)):
        assert check(bad)[0].startswith("unreadable body"), bad[:20] if bad else bad


def test_anthropic_beta_outside_the_list_is_refused():
    for beta in ("mcp-servers-2025-12-04", "web-search-2025-03-05", "files-api-2025-04-14", "fast-mode-2026-02-01"):
        why, _ = check(body(), ["oauth-2025-04-20", beta])
        assert why == f"anthropic-beta {beta!r} is not on the gate's list"
    assert pol.split_betas(["oauth-2025-04-20, claude-code-20250219", " x "]) == [
        "oauth-2025-04-20",
        "claude-code-20250219",
        "x",
    ]
    assert pol.relay_betas({"BH_RELAY_BETAS": "a,b"}) == {"a", "b"}


def test_model_bound_to_the_client():
    models = pol.relay_models()
    assert models["agent"] == {"claude-sonnet-5-5", "claude-opus-5-5"}
    assert models["judge"] == {"claude-opus-5-5", "claude-mythos-5-2"}
    assert check(body(model="claude-mythos-5-2"))[0].startswith("model 'claude-mythos-5-2' is not allowed")
    assert check(body(model="claude-mythos-5-2"), models=models["judge"])[0] is None
    assert check(body(model="claude-haiku-5-5"))[0].startswith("model 'claude-haiku-5-5'")
    assert check(body(model=None))[0].startswith("model None")
    env = {"BH_RELAY_MODELS_AGENT": "claude-haiku-5-5"}
    assert pol.relay_models(env)["agent"] == {"claude-haiku-5-5"}
    assert pol.relay_models(env)["judge"] == models["judge"]
    # fallbacks may not reach another model; the server's "default" routing stays allowed
    assert check(body(fallbacks="default"))[0] is None
    assert check(body(fallbacks=[{"model": "claude-opus-5-5"}]))[0] is None
    assert "fallbacks" in check(body(fallbacks=[{"model": "claude-mythos-5-2"}]))[0]
    assert "speed" in check(body(speed="fast"))[0]


# ------------------------------------------------------------------ the relay hook, mitmproxy simulated
@pytest.fixture
def addon(monkeypatch):
    """bh.gate.addon without mitmproxy (only in the gate image): stub modules, umask restored after import."""
    import importlib
    import sys
    import types
    from unittest import mock

    for name in ("mitmproxy", "mitmproxy.net", "mitmproxy.net.http", "mitmproxy.net.http.url", "mitmproxy.proxy"):
        mod = types.ModuleType(name)
        mod.__getattr__ = lambda attr: mock.MagicMock(name=attr)
        monkeypatch.setitem(sys.modules, name, mod)
    monkeypatch.delitem(sys.modules, "bh.gate.addon", raising=False)
    old = os.umask(0o022)
    os.umask(old)
    try:
        mod = importlib.import_module("bh.gate.addon")
    finally:
        os.umask(old)
    monkeypatch.setattr(mod, "_RELAY_IPS", (time.time(), {"agent": {"10.89.0.5"}, "judge": {"10.89.0.6"}}))
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "oauth-secret")
    yield mod
    sys.modules.pop("bh.gate.addon", None)


class Headers(dict):
    def get_all(self, name):
        return [v for k, v in self.items() if k.lower() == name.lower()]


def _flow(peer, content, path="/v1/messages?beta=true", betas="oauth-2025-04-20"):
    headers = Headers({"anthropic-beta": betas, "x-api-key": "dummy"} if betas else {"x-api-key": "dummy"})
    req = SimpleNamespace(
        method="POST",
        path=path,
        headers=headers,
        get_content=lambda strict=False: content,
        url=f"http://gate:8081{path}",
        host="gate",
        port=8081,
        scheme="http",
        host_header="gate:8081",
    )
    return SimpleNamespace(
        request=req,
        client_conn=SimpleNamespace(peername=(peer, 40000)),
        server_conn=None,
        metadata={"bh_dest": (req.url, "gate")},
        response=None,
    )


def _gate(addon, tmp_path):
    g = addon.Gate()
    g.state = tmp_path
    (tmp_path / paths.ACTIVE_RUN).write_text(json.dumps({"run_id": 7, "relay_max": 5}))
    return g


def _events(tmp_path):
    p = tmp_path / paths.EVENTS
    return [json.loads(line) for line in p.read_text().splitlines()] if p.exists() else []


def test_relay_lets_a_clean_request_through_with_the_token(addon, tmp_path):
    g = _gate(addon, tmp_path)
    f = _flow("10.89.0.5", body(tools=[BASH]))
    g._relay(f)
    assert not f.metadata.get("bh_denied")
    assert f.request.headers["Authorization"] == "Bearer oauth-secret" and "x-api-key" not in f.request.headers
    (ev,) = _events(tmp_path)
    assert ev["kind"] == "relay" and ev["client"] == "agent" and ev["model"] == "claude-sonnet-5-5"
    assert ev["betas"] == ["oauth-2025-04-20"]


@pytest.mark.parametrize(
    ("peer", "content", "betas", "expect"),
    [
        (
            "10.89.0.5",
            body(tools=[{"type": "web_search_20260209", "name": "web_search"}]),
            "oauth-2025-04-20",
            "server",
        ),
        ("10.89.0.5", body(mcp_servers=[{"type": "url", "url": "https://x", "name": "x"}]), None, "mcp_servers"),
        ("10.89.0.5", body(), "oauth-2025-04-20,mcp-servers-2025-12-04", "anthropic-beta"),
        ("10.89.0.5", b"\x00garbage", None, "unreadable"),
        ("10.89.0.5", body(model="claude-mythos-5-2"), None, "model"),  # the hunter may not use the judge's model
        ("10.89.0.6", body(model="claude-sonnet-5-5"), None, "model"),  # nor the judge the hunter's
    ],
)
def test_relay_refuses_what_the_body_asks(addon, tmp_path, *, peer, content, betas, expect):
    g = _gate(addon, tmp_path)
    f = _flow(peer, content, betas=betas)
    g._relay(f)
    assert f.metadata.get("bh_denied")
    assert "Authorization" not in f.request.headers  # the token never rides on a refused request
    blocked = [e for e in _events(tmp_path) if e["kind"] == "blocked"]
    assert len(blocked) == 1 and expect in blocked[0]["reason"]
    assert g._relay_used.get(g._run_mtime, 0) == 0  # a refused body costs no budget


def test_count_tokens_accepts_any_relay_model_but_the_same_body_rules(addon, tmp_path):
    g = _gate(addon, tmp_path)
    f = _flow("10.89.0.6", body(model="claude-sonnet-5-5"), path="/v1/messages/count_tokens?beta=true")
    g._relay(f)
    assert not f.metadata.get("bh_denied")
    tool = {"type": "web_fetch_20260209", "name": "web_fetch"}
    f = _flow("10.89.0.6", body(model="claude-opus-5-5", tools=[tool]), path="/v1/messages/count_tokens")
    g._relay(f)
    assert f.metadata.get("bh_denied")
    f = _flow("10.89.0.6", body(model="claude-haiku-5-5"), path="/v1/messages/count_tokens")
    g._relay(f)
    assert f.metadata.get("bh_denied")


def test_relay_roles_follow_the_compose_service(addon):
    table = {"agent": frozenset({"10.89.0.5"}), "judge": frozenset({"10.89.0.6"})}
    assert addon.relay_roles("10.89.0.5", table) == {"agent"}
    assert addon.relay_roles("10.89.0.6", table) == {"judge"}
    assert addon.relay_roles("10.231.0.10", table) == frozenset()
    assert addon.relay_models_for(frozenset(), "/v1/messages") == frozenset()
    assert addon.relay_models_for(frozenset({"agent", "judge"}), "/v1/messages") == {"claude-opus-5-5"}


# ------------------------------------------------------------------ the target hooks touched by the same review
SCOPE = """program: {program}
platform: x
in_scope: [a.t, b.t]
identities:
  - name: user-a
    login_url: https://a.t/login
"""


class Msg(SimpleNamespace):
    """A request or response of the simulated flow."""


def _target_gate(addon, tmp_path, program="p"):
    from bh.gate.policy import Policy

    (tmp_path / paths.ACTIVE_SCOPE).write_text(SCOPE.format(program=program))
    ident = tmp_path / paths.IDENTITIES / program / "user-a.json"
    ident.parent.mkdir(parents=True, exist_ok=True)
    ident.write_text(json.dumps({"headers": {"Authorization": "Bearer tok-a"}}))
    (tmp_path / paths.FLOWS_DIR).mkdir(exist_ok=True)
    g = addon.Gate()
    g.state = tmp_path
    g.policy = Policy(tmp_path / paths.ACTIVE_SCOPE)
    g.policy.reload()
    return g


class H(Headers):
    def items(self, multi=False):
        return list(dict.items(self))

    def set_all(self, name, values):
        self[name] = values[0] if values else ""


def _target_flow(url, status=200, resp_headers=None, body=b"", identity="user-a"):
    req = Msg(
        method="GET", headers=H({"X-BH-Identity": identity} if identity else {}), host_header=None, raw_content=b""
    )
    resp = Msg(status_code=status, headers=H(resp_headers or {}), raw_content=body)
    host = url.split("/")[2]
    return SimpleNamespace(
        request=req,
        response=resp,
        metadata={"bh_dest": (url, host), "bh_class": "target", "bh_identity": identity},
        client_conn=SimpleNamespace(peername=("10.89.0.5", 1)),
        server_conn=None,
    )


def _hit(g, url, status=200, **kw):
    f = _target_flow(url, status, **kw)
    if f.metadata["bh_identity"]:
        g._apply_identity(f, f.metadata["bh_identity"])
    g.response(f)
    return f


def test_one_401_under_an_identity_is_no_dead_session_three_routes_are(addon, tmp_path):
    g = _target_gate(addon, tmp_path)
    for i in range(5):
        _hit(g, f"https://a.t/api/orders/{i}?token=s3cret", 401)  # an access test: one route
    assert not [e for e in _events(tmp_path) if e["kind"] == "session-dead"]
    auth = [e for e in _events(tmp_path) if e["kind"] == "auth"]
    assert auth and all("s3cret" not in e["url"] for e in auth)  # B4
    before = time.time()
    _hit(g, "https://a.t/api/me", 401)
    _hit(g, "https://b.t/api/profile", 401)
    (dead,) = [e for e in _events(tmp_path) if e["kind"] == "session-dead"]
    assert dead["reason"] == "401-repeated" and dead["routes"] == 3 and dead["identity"] == "user-a"
    assert before - 1 <= dead["ts"] <= time.time() + 1


def test_a_login_redirect_is_still_a_dead_session_at_once(addon, tmp_path):
    g = _target_gate(addon, tmp_path)
    _hit(g, "https://a.t/account", 302, resp_headers={"location": "/login?next=/account"})
    (dead,) = [e for e in _events(tmp_path) if e["kind"] == "session-dead"]
    assert dead["reason"] == "login-redirect"


def test_identity_headers_withheld_outside_its_origins(addon, tmp_path):
    g = _target_gate(addon, tmp_path)
    own = _target_flow("https://a.t/api/me")
    g._apply_identity(own, "user-a")
    assert own.request.headers.get("Authorization") == "Bearer tok-a"
    other = _target_flow("https://b.t/echo")  # in scope, not the identity's origin
    g._apply_identity(other, "user-a")
    assert "Authorization" not in other.request.headers and other.metadata["bh_identity_withheld"]
    g.response(other)
    (rec,) = [json.loads(x) for x in (tmp_path / paths.FLOWS).read_text().splitlines()]
    assert rec["identity_headers"] == "withheld"


def test_application_403_behind_cloudflare_is_no_waf_challenge(addon, tmp_path, monkeypatch):
    g = _target_gate(addon, tmp_path)
    for _ in range(5):
        _hit(g, "https://a.t/api/orders/2", 403, resp_headers={"Server": "cloudflare"}, body=b'{"error":"forbidden"}')
    assert not [e for e in _events(tmp_path) if e["kind"] == "waf"] and not g.policy.host_blocked_until
    _hit(g, "https://a.t/x?session=abc", 403, resp_headers={"cf-mitigated": "challenge"}, identity=None)
    (waf,) = [e for e in _events(tmp_path) if e["kind"] == "waf"]
    assert "abc" not in waf["url"]  # B4


def test_the_policy_is_reloaded_before_the_identity_file_is_looked_up(addon, tmp_path, monkeypatch):
    """B2: right after a scope change, the identity is looked up under the new program."""
    import asyncio

    g = _target_gate(addon, tmp_path, program="old")
    (tmp_path / paths.IDENTITIES / "old" / "user-a.json").unlink()
    _target_gate(addon, tmp_path, program="new")  # writes the new scope and new/user-a.json
    os.utime(tmp_path / paths.ACTIVE_SCOPE, (time.time() + 5, time.time() + 5))
    monkeypatch.setattr(addon.Gate, "_is_relay", staticmethod(lambda flow: False))
    f = _target_flow("https://a.t/x")
    f.response = None
    f.request.path, f.request.authority, f.request.is_http2, f.request.is_http3 = "/x", "", False, False
    asyncio.run(g.request(f))
    assert g.policy.program == "new" and f.metadata["bh_identity"] == "user-a"
    assert not [e for e in _events(tmp_path) if e["kind"] == "identity-missing"]
