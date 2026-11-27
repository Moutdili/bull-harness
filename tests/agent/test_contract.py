from bh.agent import contract as c


def test_origin_and_keys():
    assert c.origin("http://10.0.0.1:3000/a?b=1") == "http://10.0.0.1:3000"
    assert c.origin("https://Example.COM/x") == "https://example.com:443"
    assert c.origin("ftp://x") is None and c.origin("not a url") is None
    assert c.path_key("/rest/basket/17/items/0f8fad5b-d9cb-469f-a165-70867728950e") == "/rest/basket/{id}/items/{id}"
    assert c.endpoint_key("http://h/api/Users/3?x=1", "post") == ("http://h:80", "POST /api/Users/{id}")
    assert c.family("GET /rest/basket/") == c.family("GET /rest/basket/{id}") == "GET /rest/basket/{id}"
    assert c.family("GET /api/Users") != c.family("GET /api/Users/{id}")  # collection != item
    assert c.query_params("http://h/s?q=1&a=&q=2") == ["a", "q"]


def test_command_classification():
    assert c.uses_manual_http("curl -s http://h/x")
    assert c.uses_manual_http("curl -s 10.231.0.10:3000/api/x")  # scheme-less, after options
    assert not c.uses_manual_http("curl -o out.txt poc.sh")
    assert c.uses_arsenal("nuclei -u http://h")  # direct tool use counts as arsenal
    assert c.uses_manual_http("U=http://h; curl $U/x | jq .")
    assert not c.uses_manual_http("curl -s $U/x")  # no literal URL: nothing to lock on
    assert not c.uses_manual_http("bh-sqli 'http://h/s?q=1'")
    assert not c.uses_manual_http("grep http://h raw.log")
    assert c.uses_arsenal("bh-crawl http://h && bh-content http://h")
    assert not c.uses_arsenal("bh-note fact x")


def test_phases_and_surface(tmp_path):
    o = "http://h:80"
    assert c.missing_phases(tmp_path, o) == list(c.REQUIRED_PHASES)
    for p in c.REQUIRED_PHASES:
        c.record_phase(tmp_path, o, p, status="ok", count=1, raw="/r")
    assert c.missing_phases(tmp_path, o) == []
    c.append_jsonl(
        tmp_path / c.ENDPOINTS,
        {"origin": o, "key": "GET /api/Users", "params": [], "source": "js"},
        {"origin": o, "key": "GET /rest/search", "params": ["q"], "source": "crawl"},
        {"origin": o, "key": "GET /main.js", "params": [], "source": "crawl"},
    )
    c.record_touched(tmp_path, ["http://h/api/Users/12", "http://h/$x"], via="manual")  # item, unresolved var
    assert "0 tested" in c.surface(tmp_path)  # the item does not cover the collection
    c.record_touched(tmp_path, ["http://h/api/Users"], via="manual")
    s = c.surface(tmp_path)
    assert "2 endpoints (1 with params), 1 tested, 1 untested" in s
    assert "GET /rest/search ?q" in s and "main.js" not in s


def test_blocker_contract():
    assert c.FACT_KINDS == ("fact", "recon", "handoff", "dead-end", "think", "threat-model")
    assert "blocker" not in c.FACT_KINDS  # host-written only
    assert {"auth", "waf", "captcha", "write-needed", "oob-needed", "refusal", "other"} <= set(c.BLOCKER_REASONS)
    assert len(set(c.BLOCKER_REASONS)) == len(c.BLOCKER_REASONS) and c.BLOCKER_REASONS[-1] == "other"
    assert c.BLOCKER_TTL_S == 7 * 86400


def test_bh_js_maps_and_never_scans():
    assert c.runs_mapper("bh-js https://t.test/") and not c.runs_scanner("bh-js https://t.test/")


def test_endpoint_label_is_the_method_and_the_route_family():
    assert c.endpoint_label("https://t.test/api/orders/7?x=1") == "GET /api/orders/{id}"
    assert c.endpoint_label("post https://t.test:8443/api/orders") == "POST /api/orders"
    assert c.endpoint_label("DELETE /api/orders/7") == "DELETE /api/orders/{id}"
    assert c.endpoint_label("/rest/basket/") == "GET /rest/basket/{id}"
    for bad in ("", "orders", "GET orders", "//evil.test/x", "ftp://t.test/x", None, 7, "GET /a b"):
        assert c.endpoint_label(bad) is None


def test_scope_prefix_is_an_https_prefix_without_joker():
    assert c.scope_prefix("https://API.t.test/v2/") == "https://api.t.test/v2/"
    assert c.scope_prefix("https://t.test") == "https://t.test/"
    assert c.scope_prefix("https://t.test:8443/a") == "https://t.test:8443/a"
    for bad in (
        "http://t.test/",
        "https://*.t.test/",
        "https://t.test/a?b=1",
        "https://t.test/#x",
        "https://u:p@t.test/",
        "https://10.0.0.1/",
        "https://localhost/",
        "https://t.test/a b",
        None,
    ):
        assert c.scope_prefix(bad) is None


# ------------------------------------------------------------------ W3-D: passive tools, docs names
def test_bh_docs_and_bh_cve_are_neither_locked_nor_manual_http():
    assert not c.uses_manual_http('bh-docs react "useEffect cleanup"')
    assert not c.uses_manual_http("bh-cve nginx 1.18.0 --severity high")
    assert not c.uses_manual_http('/opt/bh/bin/bh-docs express "router"')
    # another command beside them, or a substitution inside them, still counts
    assert c.uses_manual_http('bh-docs react "x" ; curl https://t.test/a')
    assert c.uses_manual_http('bh-docs react "$(curl -s https://t.test/a)"')
    assert "bh-docs" in c.PASSIVE_TOOLS and "bh-cve" in c.PASSIVE_TOOLS
    assert not c.is_passive("context7.com") and c.is_docs("Context7.com.")
    assert c.is_passive("services.nvd.nist.gov")


def test_own_labels_keep_the_registrable_name():
    assert c.own_labels("api.acmecorp.com") == ["acmecorp"]
    assert c.own_labels("*.widgets-intl.io") == ["widgets-intl"]
    assert c.own_labels("copilot.microsoft.com") == ["copilot", "microsoft"]
    assert c.own_labels("api.com") == ["api"]  # the registrable label always counts
    assert c.own_labels("x.example.co.uk", lambda h: h in ("co.uk", "uk")) == ["example"]
    assert c.own_labels("api-*.acmecorp.com") == ["acmecorp"]


def test_docs_text_why():
    hosts, words = ("app.acmecorp.com",), ("acmecorp", "victim-a")
    assert c.docs_text_why("useEffect cleanup", hosts=hosts, words=words) is None
    assert c.docs_text_why("ACMECORP sessions", hosts=hosts, words=words) == c.DOCS_REASON
    assert c.docs_text_why("acmecorporate sessions", hosts=hosts, words=words) is None  # a whole word only
    assert c.docs_text_why("app-acmecorp-com", hosts=hosts) == c.DOCS_REASON
    assert c.docs_text_why("a/b/c") == "docs query: a path of more than one segment"
    assert c.docs_text_why("C:\\Users\\me") == "docs query: a path of more than one segment"
    assert c.docs_text_why("ftp://x") == "docs query: a URL"
    assert c.docs_text_why("me@x.org") == "docs query: an e-mail address"
    assert c.docs_text_why("a\x00b") == "docs query: a control character"


# ------------------------------------------------------------------ W4-H: bh-mail is a note
def test_bh_mail_is_a_note_neither_locked_nor_manual_nor_a_scanner(tmp_path, monkeypatch):
    from bh.agent import hooks

    monkeypatch.setenv("BH_DIR", str(tmp_path))  # no phase has run: any manual HTTP would be locked
    monkeypatch.setenv("BH_SCANNERS", "0")
    for cmd in (
        "bh-mail user-b",
        "bh-mail user-a --since-min 30",
        "/opt/bh/bin/bh-mail user-b",
        "bh-agent mail user-b",
    ):
        assert not c.uses_manual_http(cmd), cmd
        assert not c.runs_scanner(cmd) and not c.runs_mapper(cmd) and not c.uses_arsenal(cmd), cmd
        assert hooks.lock_decision(cmd) is None and hooks.rules_decision(cmd) is None, cmd
    assert "bh-mail" in c.HOST_SERVED_TOOLS and "bh-recall" in c.HOST_SERVED_TOOLS
    # what runs beside it, or inside a substitution, is judged as itself
    assert c.uses_manual_http("bh-mail user-b ; curl http://t.test/a")
    assert hooks.lock_decision('bh-mail "$(curl -s http://t.test/a)"') is not None
    assert c.runs_scanner("bh-mail user-b && nuclei -u http://t.test")
