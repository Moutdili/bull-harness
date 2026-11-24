"""Create two Juice Shop accounts and store them as gate identities (lab only).

Run inside the gate container, the only one that reaches the lab network:
  podman exec -i bh-gate python3 - < lab/juiceshop/register_identities.py
Juice Shop keeps its DB in memory: rerun after every restart of bh-lab-juiceshop.
"""
import json
import secrets
import urllib.request

BASE = "http://10.231.0.10:3000"
OUT = "/state/identities/lab-juiceshop"


def post(path, body):
    req = urllib.request.Request(BASE + path, json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


for name in ("user-a", "user-b"):
    email, pw = f"bh-{name}-{secrets.token_hex(3)}@lab.local", secrets.token_urlsafe(14)
    post("/api/Users", {"email": email, "password": pw, "passwordRepeat": pw,
                        "securityQuestion": {"id": 1}, "securityAnswer": secrets.token_hex(4)})
    auth = post("/rest/user/login", {"email": email, "password": pw})["authentication"]
    ident = {"headers": {"Authorization": f"Bearer {auth['token']}", "Cookie": f"token={auth['token']}"},
             "note": f"lab account {email}, basket {auth.get('bid')}"}
    with open(f"{OUT}/{name}.json", "w") as fh:
        json.dump(ident, fh)
    print(name, email, "basket", auth.get("bid"))
