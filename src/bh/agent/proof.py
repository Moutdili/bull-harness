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
(`status`, `contains`, `absent`, `regex`); a control is the refused or benign twin of the attack and
must expect something different. Replay sends every step through the gate (same scope, identities
injected by the gate), twice, and reports which expectations held. No LLM involved.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

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
        elif "regex" in exp:
            try:
                re.compile(str(exp["regex"]))
            except re.error as exc:
                errors.append(f"{where}: bad regex: {exc}")
    roles = [st.get("role") for st in steps if isinstance(st, dict)]
    if "attack" not in roles:
        errors.append("at least one step must have role 'attack' (the request that proves the impact)")
    if "control" not in roles:
        errors.append("at least one step must have role 'control' (the refused or benign twin of the attack)")
    attacks = [st.get("expect") for st in steps if isinstance(st, dict) and st.get("role") == "attack"]
    if any(st.get("expect") in attacks for st in steps if isinstance(st, dict) and st.get("role") == "control"):
        errors.append("a control must expect something different from the attack")
    return errors


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
    for _ in range(rounds):
        round_ = []
        for st in proof["steps"]:
            try:
                status, body = _send(st)
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
    every = [s for r in results for s in r]
    reproduced = all(s["ok"] for s in every)
    # the control answered like the attack (same status and same body): there is no differential to prove
    pairs = [(a, k) for r in results for a in r if a["role"] == "attack" for k in r if k["role"] == "control"]
    control_disproves = any(
        a.get("sha1") and a.get("sha1") == k.get("sha1") and a["status"] == k["status"] for a, k in pairs
    )
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
