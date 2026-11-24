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
