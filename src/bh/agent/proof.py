"""Structured proof of a finding, and its deterministic replay (verifier stage A).

A proof is JSON the hunting agent writes next to a finding:

  {"steps": [
     {"name": "user-b reads its own basket", "role": "setup",   "as": "user-b", "method": "GET",
      "url": "https://t/rest/basket/7", "expect": {"status": [200], "contains": ["\\"UserId\\":27"]}},
     {"name": "user-a reads user-b's basket", "role": "attack", "as": "user-a", "method": "GET",
      "url": "https://t/rest/basket/7", "expect": {"status": [200], "contains": ["\\"UserId\\":27"]}},
     {"name": "without a session",           "role": "control", "as": null,    "method": "GET",
      "url": "https://t/rest/basket/7", "expect": {"status": [401, 403]}}
  ]}

Rules: at least one `attack` step and one `control` step; every step states what must be observed
(`status`, `contains`, `absent`, `regex`); an attack names a marker in the body (`contains`, `absent` or
`regex`), status alone proves nothing; a control is the TWIN of an attack (same method, origin and path:
only the identity, the query or the body differ) and must expect something different. Replay sends every
step through the gate (same scope, identities injected by the gate), twice, and reports which
expectations held. The proof is disproved when a control's answer satisfies its attack's expectation
(no differential). No LLM involved.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

from urllib.parse import urlsplit

from bh.agent import contract as c

ROLES = ("setup", "attack", "control")
METHODS = ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE")
EXPECT_KEYS = ("status", "contains", "absent", "regex")
MAX_STEPS, TIMEOUT_S, ROUNDS, SNIPPET = 8, 20, 2, 300


def validate(proof: object) -> list[str]:
    """Human-readable problems; empty when the proof can be replayed."""
    if not isinstance(proof, dict) or not isinstance(proof.get("steps"), list):
        return ['a proof is {"steps": [...]}']
    steps = proof["steps"]
    errors = []
    if not 2 <= len(steps) <= MAX_STEPS:
        errors.append(f"2 to {MAX_STEPS} steps")
    for i, st in enumerate(steps):
        where = f"step {i + 1}"
        if not isinstance(st, dict):
            errors.append(f"{where}: must be an object")
            continue
        if st.get("role") not in ROLES:
            errors.append(f"{where}: role must be one of {', '.join(ROLES)}")
        if str(st.get("method", "GET")).upper() not in METHODS:
            errors.append(f"{where}: method not allowed")
        if c.origin(str(st.get("url", ""))) is None:
            errors.append(f"{where}: url must be an absolute http(s) URL")
        if "$" in str(st.get("url", "")):
            errors.append(f"{where}: url contains an unresolved shell variable")
        exp = st.get("expect")
        if not isinstance(exp, dict) or not set(exp) & set(EXPECT_KEYS) or set(exp) - set(EXPECT_KEYS):
            errors.append(f"{where}: expect needs at least one of {', '.join(EXPECT_KEYS)} and nothing else")
        else:
            if any(not str(n) for k in ("contains", "absent") for n in (exp.get(k) or [])) or exp.get("regex") == "":
                errors.append(f"{where}: empty marker (an empty string matches every answer)")
            if st.get("role") == "attack" and not (exp.get("contains") or exp.get("absent") or exp.get("regex")):
                errors.append(f"{where}: an attack must name a body marker (contains, absent or regex), not a status")
            if "regex" in exp:
                try:
                    re.compile(str(exp["regex"]))
                except re.error as exc:
                    errors.append(f"{where}: bad regex: {exc}")
    roles = [st.get("role") for st in steps if isinstance(st, dict)]
    if "attack" not in roles:
        errors.append("at least one step must have role 'attack' (the request that proves the impact)")
    if "control" not in roles:
        errors.append("at least one step must have role 'control' (the refused or benign twin of the attack)")
    attacks = [st for st in steps if isinstance(st, dict) and st.get("role") == "attack"]
    for i, st in enumerate(steps):
        if not isinstance(st, dict) or st.get("role") != "control":
            continue
        if any(st.get("expect") == a.get("expect") for a in attacks):
            errors.append("a control must expect something different from the attack")
        if not any(_twins(a, st) for a in attacks):
            errors.append(
                f"step {i + 1}: a control is the twin of an attack (same method, origin and path; only the "
                "identity, query or body change)"
            )
    return errors


def _twins(attack: dict, control: dict) -> bool:
    """Same method and same origin + path: the control asks the same thing, refused or benign."""

    def where(st: dict) -> tuple[str, str | None, str]:
        url = str(st.get("url", ""))
        return str(st.get("method", "GET")).upper(), c.origin(url), urlsplit(url).path.rstrip("/") or "/"

    return where(attack) == where(control)


def _expect_holds(exp: dict, status: int, body: str) -> tuple[bool, list[str]]:
    misses = []
    if "status" in exp and status not in [
        int(s) for s in (exp["status"] if isinstance(exp["status"], list) else [exp["status"]])
    ]:
        misses.append(f"status {status} not in {exp['status']}")
    for needle in exp.get("contains") or []:
        if str(needle) not in body:
            misses.append(f"missing {str(needle)[:60]!r}")
    for needle in exp.get("absent") or []:
        if str(needle) in body:
            misses.append(f"present {str(needle)[:60]!r}")
    if exp.get("regex") and not re.search(str(exp["regex"]), body):
        misses.append(f"regex {str(exp['regex'])[:60]!r} did not match")
    return not misses, misses


def _send(step: dict) -> tuple[int, str]:
    """One request through the environment's proxy (the gate). Redirects are not followed: a 302 is an answer."""
    headers = {str(k): str(v) for k, v in (step.get("headers") or {}).items()}
    if step.get("as"):
        headers[c.IDENTITY_HEADER] = str(step["as"])
    body = step.get("body")
    data = (json.dumps(body) if isinstance(body, (dict, list)) else str(body)).encode() if body is not None else None
    if isinstance(body, (dict, list)):
        headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(
        str(step["url"]), data=data, headers=headers, method=str(step.get("method", "GET")).upper()
    )

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=TIMEOUT_S) as resp:
            return resp.status, resp.read(1 << 20).decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return err.code, (err.read(1 << 20) or b"").decode("utf-8", "replace")


def replay(proof: dict, rounds: int = ROUNDS) -> dict:
    """{"reproduced": bool, "control_disproves": bool, "rounds": [[step results]]}."""
    results = []
    control_disproves = False
    for _ in range(rounds):
        round_, answers = [], []
        for st in proof["steps"]:
            try:
                status, body = _send(st)
                answers.append((st, status, body))
                ok, misses = _expect_holds(st["expect"], status, body)
                denied = "bh-gate: DENIED" in body
                round_.append(
                    {
                        "name": st.get("name", ""),
                        "role": st["role"],
                        "status": status,
                        "ok": ok and not denied,
                        "misses": misses + (["refused by the gate"] if denied else []),
                        "len": len(body),
                        "sha1": hashlib.sha1(body.encode()).hexdigest()[:12],
                        "snippet": body[:SNIPPET],
                    }
                )
            except (OSError, ValueError) as exc:
                round_.append(
                    {
                        "name": st.get("name", ""),
                        "role": st["role"],
                        "status": None,
                        "ok": False,
                        "misses": [f"request failed: {exc}"[:200]],
                    }
                )
        results.append(round_)
        # no differential: a control's answer already satisfies what its attack claims to prove
        for a in (st for st in proof["steps"] if st["role"] == "attack"):
            for k, status, body in answers:
                if k["role"] == "control" and _twins(a, k) and _expect_holds(a["expect"], status, body)[0]:
                    control_disproves = True
    every = [s for r in results for s in r]
    reproduced = all(s["ok"] for s in every)
    return {
        "reproduced": reproduced and not control_disproves,
        "control_disproves": control_disproves,
        "rounds": results,
    }


def main(argv: list[str]) -> None:
    """bh-agent replay <proof.json>: prints the replay result as JSON."""
    if len(argv) != 1:
        sys.exit("usage: bh-agent replay <proof.json>")
    proof = json.loads(Path(argv[0]).read_text())
    if errors := validate(proof):
        print(json.dumps({"invalid": errors}))
        return
    print(json.dumps(replay(proof)))
