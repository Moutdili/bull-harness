"""Independent verification of findings (plan v2, step 2).

  new finding ──► dedup ──► stage A: deterministic replay of proof.json (2 rounds, through the gate)
                         ──► stage B: fresh claude session, verifier role, single requests, bounded
                         ──► decision ──► verified (+ todo submit) | rejected | inconclusive
                                      └─► inconclusive, never escalated: stage B once more with a second judge
                                          (ESCALATION_MODEL, fresh context, new nonce), same stage A, same decision
                         └─► triager PoC generated from the proof (sessions as placeholders)

Decision table (deterministic, B can only lower a deterministic success, never invent one):
  control answered exactly like the attack          -> rejected (no differential)
  B rejected                                         -> rejected
  A reproduced and B confirmed                       -> verified
  anything else                                      -> inconclusive

No human verifies during the hunt: an inconclusive finding opens no todo, it stays visible in the Findings tab.
A technical error sends the finding back to 'new' for a later pass; the second one leaves it inconclusive.
"""

from __future__ import annotations

import json
import os
import secrets
import shlex
import subprocess
import time
from pathlib import Path

from bh import classes, paths, redact, stack
from bh.agent import contract as c
from bh.board import Board
from bh.runner import prompt as prompts
from bh.runner import run as runner
from bh.scope import Scope
from bh.text import one_line

VERIFIER_TURNS, VERIFIER_MINUTES = 8, 5
# the judge is not the hunter's model (correlated errors); BH_VERIFIER_MODEL overrides
VERIFIER_MODEL = os.environ.get("BH_VERIFIER_MODEL", "opus")
# second judge for what the first one leaves inconclusive (decision of 2026-11-25), once per finding
ESCALATION_MODEL = os.environ.get("BH_ESCALATION_MODEL", "claude-mythos-5-2")
ESCALATION_EFFORT = "high"
MAX_VERIFY_ERRORS = 2  # an error is a breakdown, not a doubt: retried on a later pass, never escalated
REPLAY_TIMEOUT_S = 420
# a new finding is a duplicate of these (a rejected one too: re-proposing it would cost a verifier session each time)
ACTIVE = ("new", "verifying", "verified", "inconclusive", "submitted", "rejected")
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
    stack.push_file(path, json.dumps(proof), user=stack.JUDGE)
    try:
        r = stack.agent_sh('/opt/bh/bin/bh-agent replay "$1"', path, user=stack.JUDGE, timeout=REPLAY_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return {"reproduced": False, "control_disproves": False, "error": f"replay over {REPLAY_TIMEOUT_S}s"}
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
        user=stack.JUDGE,
    )
    nonce = secrets.token_hex(16)  # only this claude process gets it: a verdict without it was not written by it
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
        extra_env={"BH_ROLE": "verifier", "HOME": runner.sandbox_home(f"{run_id}-F{fid}"), "BH_VERDICT_NONCE": nonce},
        user=stack.JUDGE,
    )
    log_path = paths.runs_dir() / f"{run_id:05d}-{prog}-verify-F{fid}-{int(time.time())}.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)
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
        if n.get("op") == "verdict"
        and str(n.get("finding_id", "")).lstrip("F") == str(fid)
        and secrets.compare_digest(str(n.get("nonce", "")), nonce)
    ]
    if not verdicts:
        return "inconclusive", "the verifier recorded no verdict" + (" (timeout)" if timed_out else "")
    return verdicts[-1]["verdict"], str(verdicts[-1].get("reason", ""))[:2000]


def decide(replay: dict, verdict: str, reason: str) -> tuple[str, str]:
    if replay.get("control_disproves"):
        return "rejected", "stage A: the control answered exactly like the attack, there is no differential"
    if verdict == "rejected":
        return "rejected", f"verifier: {reason}"
    if replay.get("reproduced") is True and verdict == "confirmed":
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
    """curl commands a triager can run outside the harness: program headers included, sessions and every
    credential or personal value as placeholders (bh.redact). Robust to a malformed stored proof."""
    lines = [
        f"# {scope.platform}/{scope.program} — generated from the replayed proof",
        "# credentials and personal data are <redacted:...>: put your own test-account values back before running",
        "set -u",
    ]
    for i, st in enumerate(s for s in (proof.get("steps") or []) if isinstance(s, dict)):
        hdrs = dict(scope.required_headers)
        if scope.user_agent:
            hdrs["User-Agent"] = scope.user_agent
        raw_headers = st.get("headers") if isinstance(st.get("headers"), dict) else {}
        hdrs.update({str(k): redact.header(str(k), str(v)) for k, v in raw_headers.items()})
        if st.get("as"):
            for name in _identity_headers(scope.program, str(st["as"])):
                hdrs[name] = f"<{name} of account {st['as']}>"
        parts = ["curl", "-sk", "-i", "-X", str(st.get("method", "GET")).upper(), redact.url(str(st.get("url", "")))]
        for k, v in hdrs.items():
            parts += ["-H", f"{k}: {v}"]
        if st.get("body") is not None:
            body = redact.body(st["body"])
            parts += ["--data-raw", json.dumps(body) if isinstance(body, (dict, list)) else str(body)]
        lines += [
            "",
            f"# step {i + 1} ({st.get('role')}): {st.get('name', '')}",
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
    """`model` is the verifier's (VERIFIER_MODEL by default in callers), not the hunter's."""
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
    try:
        return _verify(board, scope, finding, run_id=run_id, model=model, effort=effort, say=say)
    except Exception as exc:  # noqa: BLE001 - never leave a finding stuck in 'verifying'
        key = f"verify-err:F{fid}:{scope.program}"
        errors = int(board.meta_get(key, "0") or 0) + 1
        board.meta_set(key, str(errors))
        why = f"verification error {errors}/{MAX_VERIFY_ERRORS}: {exc!r}"[:500]
        # below the bound the finding goes back in the queue: a later verify_pending retries it
        status = "inconclusive" if errors >= MAX_VERIFY_ERRORS else "new"
        board.set_finding(fid, status, why)
        say(f"  ↳ F{fid} {status}: {one_line(why, 200)}")
        return status


def _verify(board: Board, scope: Scope, finding: dict, *, run_id: int, model: str, effort: str | None, say) -> str:
    fid = finding["id"]
    proof = json.loads(finding["proof"])
    # nothing of the hunter survives into the verification: its processes, HOME, user site, the old verdicts.
    # The verification runs as its own Unix user, in a work dir and HOME the hunter cannot write.
    home = runner.sandbox_home(f"{run_id}-F{fid}")
    runner.clean_sandbox(scope.program, home)
    stack.prepare_judge(home, verify_dir(scope.program, fid))
    replay = stage_a(scope.program, fid, proof)
    say(
        f"  ↳ F{fid} stage A: reproduced={replay.get('reproduced')} control_disproves={replay.get('control_disproves')}"
    )
    board.finding_set(fid, replay=json.dumps(replay)[:200_000], poc_triager=triager_poc(scope, proof))
    if replay.get("control_disproves"):
        status, why = decide(replay, "rejected", "control answered like the attack")
    else:
        verdict, reason = stage_b(board, scope, finding, replay, run_id=run_id, model=model, effort=effort, say=say)
        status, why = decide(replay, verdict, reason)
        why = f"[judge {model}] {why}"
        key = f"escalated:F{fid}:{scope.program}"
        if status == "inconclusive" and not board.meta_get(key):
            board.meta_set(key, ESCALATION_MODEL)  # before the call: a crash in it does not escalate again
            status, why = _escalate(
                board, scope, finding, proof=proof, replay=replay, home=home, first=why, run_id=run_id, say=say
            )
    board.set_finding(fid, status, why)
    if status == "verified":
        board.add_todo(
            "submit",
            f"F{fid} verified: {finding['title']}",
            "replay the triager PoC, then submit",
            program=scope.program,
            dedup=f"{scope.program}:submit:F{fid}",
        )
    say(f"  ↳ F{fid} {status}: {one_line(why, 200)}")
    return status


def _escalate(
    board: Board, scope: Scope, finding: dict, *, proof: dict, replay: dict, home: str, first: str, run_id: int, say
) -> tuple[str, str]:
    """Stage B again with the second judge, recombined with the same stage A. Returns (status, verdict text)."""
    fid, vdir = finding["id"], verify_dir(scope.program, finding["id"])
    say(f"  ↳ F{fid} inconclusive for the first judge, second judge {ESCALATION_MODEL}")
    # fresh context: the first judge's processes, HOME and work dir (its notes, its verdict) are gone
    stack.prepare_judge(home, vdir)
    stack.push_file(f"{vdir}/proof.json", json.dumps(proof), user=stack.JUDGE)
    verdict, reason = stage_b(
        board, scope, finding, replay, run_id=run_id, model=ESCALATION_MODEL, effort=ESCALATION_EFFORT, say=say
    )
    status, why = decide(replay, verdict, reason)
    if status == "inconclusive":
        return status, f"neither judge decided. {first} | [judge {ESCALATION_MODEL}] {why}"
    return status, f"[judge {ESCALATION_MODEL}] {why} | first judge: {first}"


def verify_pending(
    board: Board, scope: Scope, *, run_id: int, model: str, effort: str | None, say=print, limit: int = 10
) -> dict[str, int]:
    """Verify the unverified findings that carry a proof, newest first (bounded: each one costs a claude session)."""
    out: dict[str, int] = {}
    for r in board.rows(
        # 'verifying' = a verification that died with the process: picked up again
        "SELECT id FROM findings WHERE program=? AND status IN ('new', 'verifying') AND proof IS NOT NULL "
        "ORDER BY id DESC LIMIT ?",
        scope.program,
        limit,
    ):
        status = verify_finding(board, scope, int(r["id"]), run_id=run_id, model=model, effort=effort, say=say)
        out[status] = out.get(status, 0) + 1
        time.sleep(1)
    return out
