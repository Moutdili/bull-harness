from bh.agent.tools import js_paths


def test_js_paths():
    js = (
        "this.http.get(this.hostServer+`/rest/user/whoami`);"
        "this.http.put(this.hostServer+`/rest/continue-code/apply/`+e,{});"
        'fetch("/api/Products?q=1"); a="/a"; b="//cdn.x/y.js"; c="/assets/i18n/en.json"; d="/main.js"'
    )
    assert js_paths(js) == [
        ("GET", "/rest/user/whoami"),
        ("PUT", "/rest/continue-code/apply/"),
        ("GET", "/api/Products?q=1"),
    ]
