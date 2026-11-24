"""Independent verification of findings (plan v2, step 2).

  new finding ──► dedup ──► stage A: deterministic replay of proof.json (2 rounds, through the gate)
                         ──► stage B: fresh claude session, verifier role, single requests, bounded
                         ──► decision ──► verified (+ todo submit) | rejected | inconclusive (+ todo verify)
                         └─► triager PoC generated from the proof (sessions as placeholders)

Decision table (deterministic, B can only lower a deterministic success, never invent one):
  control answered exactly like the attack          -> rejected (no differential)
  B rejected                                         -> rejected
  A reproduced and B confirmed                       -> verified
  anything else                                      -> inconclusive
"""

from __future__ import annotations

import json
import shlex
import time
from pathlib import Path

from bh import classes, paths, stack
from bh.agent import contract as c
from bh.board import Board
from bh.runner import prompt as prompts
from bh.runner import run as runner
from bh.scope import Scope
from bh.text import one_line

VERIFIER_TURNS, VERIFIER_MINUTES = 8, 5
REPLAY_TIMEOUT_S = 420
ACTIVE = ("new", "verifying", "verified", "inconclusive", "submitted")
_PLACEHOLDERS = ",".join("?" * len(ACTIVE))


def verify_dir(program: str, fid: int) -> str:
    """The verifier's own work dir in the sandbox (fresh for every verification)."""
    return f"{c.WORK_ROOT}/{program}/.verify/F{fid}"


def host_verify_dir(program: str, fid: int) -> Path:
    return paths.work_bh(program).parent / ".verify" / f"F{fid}"


# ------------------------------------------------------------------ pieces
def duplicate_of(board: Board, finding: dict) -> int | None:
    """An earlier active finding of the same class on the same resource family."""
    key = c.endpoint_key(finding.get("url") or "", "GET")
    if key is None:
        return None
    for r in board.rows(
        f"SELECT id, url FROM findings WHERE program=? AND vuln_class=? AND id<? AND status IN ({_PLACEHOLDERS})",
        finding["program"],
        finding["vuln_class"],
        finding["id"],
        *ACTIVE,
    ):
        other = c.endpoint_key(r["url"] or "", "GET")
        if other and other[0] == key[0] and c.family(other[1]) == c.family(key[1]):
            return int(r["id"])
    return None


def stage_a(program: str, fid: int, proof: dict) -> dict:
    """Deterministic replay inside the agent container (so it goes through the gate like the hunter did)."""
    path = f"{verify_dir(program, fid)}/proof.json"
    stack.push_file(path, json.dumps(proof))
    r = stack.agent_sh('/opt/bh/bin/bh-agent replay "$1"', path, timeout=REPLAY_TIMEOUT_S)
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"reproduced": False, "control_disproves": False, "error": one_line(r.stderr or r.stdout, 300)}


def stage_b(
    board: Board, scope: Scope, finding: dict, replay: dict, *, run_id: int, model: str, effort: str | None, say
) -> tuple[str, str]:
    """Fresh claude session in the verifier role. Returns (verdict, reason); ('inconclusive', why) on failure."""
    prog, fid = scope.program, finding["id"]
    vdir = verify_dir(prog, fid)
    stack.push_file(
        f"{vdir}/{c.SYSTEM}",
        prompts.build_verifier_prompt(scope, finding, replay, classes.evidence(finding["vuln_class"])),
    )
    task = (
        f"Verify finding F{fid}. The proof is at {vdir}/proof.json. Re-test it, then record exactly one "
        f"`bh-note verdict F{fid} ...`."
    )
    cmd = runner.agent_command(
        scope,
        task,
        run_id=run_id,
        model=model,
        max_turns=VERIFIER_TURNS,
        effort=effort,
        session=None,
        bh_dir=vdir,
        extra_env={"BH_ROLE": "verifier"},
    )
    log_path = paths.runs_dir() / f"{run_id:05d}-{prog}-verify-F{fid}-{int(time.time())}.jsonl"
    res = runner.SegmentResult(program=prog, run_id=run_id)
    with open(log_path, "x", buffering=1) as log:
        result, timed_out = runner.run_leg(
            cmd, log, log_path.with_suffix(".stderr"), res, say, prog, VERIFIER_MINUTES * 60, bh_dir=vdir
        )
    runner.merge_result(res, result)
    board.db.execute("UPDATE runs SET verify_cost=COALESCE(verify_cost, 0) + ? WHERE id=?", (res.cost_usd, run_id))
    board.db.commit()
    verdicts = [
        n
        for n in c.read_jsonl(host_verify_dir(prog, fid) / c.NOTES)
        if n.get("op") == "verdict" and str(n.get("finding_id", "")).lstrip("F") == str(fid)
    ]
    if not verdicts:
        return "inconclusive", "the verifier recorded no verdict" + (" (timeout)" if timed_out else "")
    return verdicts[-1]["verdict"], str(verdicts[-1].get("reason", ""))[:2000]


def decide(replay: dict, verdict: str, reason: str) -> tuple[str, str]:
    if replay.get("control_disproves"):
        return "rejected", "stage A: the control answered exactly like the attack, there is no differential"
    if verdict == "rejected":
        return "rejected", f"verifier: {reason}"
    if replay.get("reproduced") and verdict == "confirmed":
        return "verified", f"replayed twice with its control; verifier: {reason}"
    stage = "replayed" if replay.get("reproduced") else "NOT replayed (" + one_line(_misses(replay), 160) + ")"
    return "inconclusive", f"stage A {stage}; verifier {verdict}: {reason}"


def _misses(replay: dict) -> str:
    if replay.get("error"):
        return replay["error"]
    return (
        "; ".join(
            f"{s.get('name')}: {', '.join(s.get('misses') or [])}"
            for r in replay.get("rounds") or []
            for s in r
            if not s.get("ok")
        )
        or "unknown"
    )


def triager_poc(scope: Scope, proof: dict) -> str:
    """curl commands a triager can run outside the harness: program headers included, sessions as placeholders."""
    lines = [f"# {scope.platform}/{scope.program} — generated from the replayed proof", "set -u"]
    for i, st in enumerate(proof.get("steps") or [], 1):
        hdrs = dict(scope.required_headers)
        if scope.user_agent:
            hdrs["User-Agent"] = scope.user_agent
        hdrs.update({str(k): str(v) for k, v in (st.get("headers") or {}).items()})
        if st.get("as"):
            for name in _identity_headers(scope.program, str(st["as"])):
                hdrs[name] = f"<{name} of account {st['as']}>"
        parts = ["curl", "-sk", "-i", "-X", str(st.get("method", "GET")).upper(), str(st["url"])]
        for k, v in hdrs.items():
            parts += ["-H", f"{k}: {v}"]
        if st.get("body") is not None:
            body = st["body"]
            parts += ["--data-raw", json.dumps(body) if isinstance(body, (dict, list)) else str(body)]
        lines += [
            "",
            f"# step {i} ({st.get('role')}): {st.get('name', '')}",
            f"# expect: {json.dumps(st.get('expect'))}",
            shlex.join(parts),
        ]
    return "\n".join(lines) + "\n"


def _identity_headers(program: str, name: str) -> list[str]:
    try:
        return sorted(json.loads((paths.identities_dir(program) / f"{name}.json").read_text()).get("headers", {}))
    except (OSError, ValueError):
        return ["Cookie"]


# ------------------------------------------------------------------ orchestration
def verify_finding(
    board: Board, scope: Scope, fid: int, *, run_id: int, model: str, effort: str | None, say=print
) -> str:
    rows = board.rows("SELECT * FROM findings WHERE id=? AND program=?", fid, scope.program)
    if not rows:
        raise SystemExit(f"F{fid} is not a finding of {scope.program}")
    finding = dict(rows[0])
    if not finding.get("proof"):
        board.set_finding(fid, "inconclusive", "no structured proof (finding recorded before the verifier existed)")
        return "inconclusive"
    if dup := duplicate_of(board, finding):
        board.set_finding(fid, "duplicate", f"same class and resource as F{dup}")
        say(f"  ↳ F{fid} duplicate of F{dup}")
        return "duplicate"
    board.set_finding(fid, "verifying")
    proof = json.loads(finding["proof"])
    stack.agent_sh('rm -rf -- "$1"', verify_dir(scope.program, fid), user="root")
    replay = stage_a(scope.program, fid, proof)
    say(
        f"  ↳ F{fid} stage A: reproduced={replay.get('reproduced')} control_disproves={replay.get('control_disproves')}"
    )
    if replay.get("control_disproves"):
        verdict, reason = "rejected", "control answered like the attack"
    else:
        verdict, reason = stage_b(board, scope, finding, replay, run_id=run_id, model=model, effort=effort, say=say)
    status, why = decide(replay, verdict, reason)
    board.finding_set(fid, replay=json.dumps(replay)[:200_000], poc_triager=triager_poc(scope, proof))
    board.set_finding(fid, status, why)
    if status == "verified":
        board.add_todo(
            "submit",
            f"F{fid} verified: {finding['title']}",
            "replay the triager PoC, then submit",
            program=scope.program,
            dedup=f"{scope.program}:submit:F{fid}",
        )
    elif status == "inconclusive":
        board.add_todo(
            "verify",
            f"F{fid} inconclusive: {finding['title']}",
            why,
            program=scope.program,
            dedup=f"{scope.program}:verify:F{fid}",
        )
    say(f"  ↳ F{fid} {status}: {one_line(why, 200)}")
    return status


def verify_pending(
    board: Board, scope: Scope, *, run_id: int, model: str, effort: str | None, say=print, limit: int = 10
) -> dict[str, int]:
    """Verify the unverified findings that carry a proof, newest first (bounded: each one costs a claude session)."""
    out: dict[str, int] = {}
    for r in board.rows(
        "SELECT id FROM findings WHERE program=? AND status='new' AND proof IS NOT NULL ORDER BY id DESC LIMIT ?",
        scope.program,
        limit,
    ):
        status = verify_finding(board, scope, int(r["id"]), run_id=run_id, model=model, effort=effort, say=say)
        out[status] = out.get(status, 0) + 1
        time.sleep(1)
    return out
