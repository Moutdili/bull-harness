from bh import redact
from bh.scope import scope_from_dict
from bh.verify import triager_poc

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"


def test_triager_poc_carries_no_credential_or_personal_value():
    scope = scope_from_dict(
        {"schema": 1, "program": "p", "platform": "local", "in_scope": ["app.example.com"]}, origin="t"
    )
    proof = {
        "steps": [
            {
                "role": "setup",
                "method": "POST",
                "url": "https://app.example.com/login",
                "body": {"email": "mio+a@yeswehack.ninja", "password": "S3cret-Passw0rd!"},
                "expect": {"status": [200]},
            },
            {
                "role": "attack",
                "method": "GET",
                "url": f"https://app.example.com/api/users/2?access_token={JWT}&x=1",
                "headers": {"Authorization": f"Bearer {JWT}", "Cookie": "session=4f9d2c7e1b"},
                "expect": {"contains": ["email"]},
            },
        ]
    }
    poc = triager_poc(scope, proof)
    for secret in ("S3cret-Passw0rd!", "mio+a@yeswehack.ninja", "4f9d2c7e1b", "eyJhbGciOiJIUzI1NiJ9"):
        assert secret not in poc, secret
    assert "x=1" in poc and "/api/users/2" in poc  # the exploit itself stays readable


def test_free_text_and_malformed_proofs():
    assert JWT not in redact.text(f"curl -H 'Authorization: Bearer {JWT}' https://h/")
    assert "hunter2" not in redact.text('{"password": "hunter2"}') and "hunter2" not in redact.text("password=hunter2")
    scope = scope_from_dict({"schema": 1, "program": "p", "platform": "local", "in_scope": ["h.example"]}, origin="t")
    assert triager_poc(scope, {"steps": ["nope", {"url": 5, "headers": "x"}]})  # never raises
