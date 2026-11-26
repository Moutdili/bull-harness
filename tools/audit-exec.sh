#!/usr/bin/env bash
# Independent audit that RUNS the code (container/audit): an auditor model in bh-audit, with Bash, on a COPY of HEAD.
#
#   tools/audit-exec.sh <prompt.md> [model=claude-mythos-5-2] [effort=max] [max_turns=250] [context files...]
#
# - Refuses while a hunt is running (var/state/active-run.json).
# - Copies `git archive HEAD` to var/audit/<id>/repo (+ the context files, + an empty out/), mounted as /work.
# - Activates the LAB scope for the whole audit (its live checks can only reach the lab, never a real program) and a
#   relay budget for the `audit` role; restores the previous scope and closes the relay on exit, whatever happens.
# - Runs `claude -p` inside bh-audit with --dangerously-skip-permissions: safe there, the container has no host
#   file, no secret, no route out but the gate. The auditor writes in /work/repo/out (var/audit/<id>/repo/out).
# Result: var/audit/<id>/result.json (+ .md with the final answer), the auditor's files in var/audit/<id>/work/repo/out
# (owned by the container's user: read them as is, delete with `podman unshare rm -rf`).
set -euo pipefail
cd "$(dirname "$0")/.."
prompt=${1:?usage: tools/audit-exec.sh <prompt.md> [model] [effort] [max_turns] [context files...]}
model=${2:-claude-mythos-5-2} effort=${3:-max} turns=${4:-250}
shift $(( $# < 4 ? $# : 4 ))
LAB_SCOPE=scopes/lab/juiceshop.yaml
STATE=var/state

[ -f "$STATE/active-run.json" ] && { echo "a run is active ($STATE/active-run.json): no audit during a hunt" >&2; exit 2; }
podman container exists bh-gate && [ "$(podman inspect -f '{{.State.Running}}' bh-gate)" = true ] \
  || { echo "the gate is down: bh up first" >&2; exit 2; }
podman image exists localhost/bh-audit:dev \
  || { echo "no image: podman build -t localhost/bh-audit:dev -f container/audit/Containerfile ." >&2; exit 2; }

id=$(date +%Y%m%d-%H%M%S)
# a real directory, not a symlink: the :Z mount relabels what it is given, and SELinux would keep a symlink's
# target unreadable in the container. Renamed to var/audit/<id> once the audit is over.
# The container owns what it mounts (its entrypoint hands /work to hunter): the script's own files (result,
# previous scope) live beside it in var/audit/<id>/, never in the mount.
W=var/audit/current M=var/audit/$id
[ -e "$W" ] && { echo "$W exists (an audit running, or a leftover: podman unshare rm -rf $W)" >&2; exit 2; }
mkdir -p "$W/repo/out" "$M"
git archive HEAD | tar -x -C "$W/repo"
git log --oneline -40 > "$W/repo/GIT-LOG.txt"
for f in "$@"; do cp "$f" "$W/repo/"; done
cp "$STATE/active-scope.yaml" "$M/prev-scope.yaml" 2>/dev/null || true

activate() { uv run python -c "from pathlib import Path; from bh.runner.run import activate_scope; activate_scope(Path('$1'))"; }
cleanup() {
  rm -f "$STATE/active-run.json"
  if [ -s "$M/prev-scope.yaml" ]; then activate "$M/prev-scope.yaml"; fi
  podman-compose -f container/compose.yaml --profile audit down audit >/dev/null 2>&1 || true
  podman unshare mv "$W" "$M/work"
  echo "audit $id: scope restored, relay closed, bh-audit removed; results in $M (auditor files: $M/work/repo/out)" >&2
}
trap cleanup EXIT

activate "$LAB_SCOPE"
printf '{"run_id": %d, "program": "bh-audit", "relay_max": %d}\n' "$(date +%s)" $(( turns * 3 + 30 )) > "$STATE/active-run.json"
podman-compose -f container/compose.yaml --profile audit up -d --no-deps --force-recreate audit >/dev/null
sleep 3

podman exec -i --user hunter -w /work/repo -e HOME=/tmp/audit-home bh-audit \
  claude -p "$(cat "$prompt")" --model "$model" --effort "$effort" --dangerously-skip-permissions \
  --tools "Bash,Read,Grep,Glob,Write,Edit" --disable-slash-commands --strict-mcp-config \
  --max-turns "$turns" --output-format json < /dev/null > "$M/result.json" 2> "$M/stderr.txt" || true
python3 - "$M" <<'PY'
import json, sys
w = sys.argv[1]
try:
    d = json.load(open(f"{w}/result.json"))
except ValueError:
    print(f"no JSON result: see {w}/stderr.txt"); sys.exit(1)
open(f"{w}/result.md", "w").write(d.get("result") or "")
print("turns", d.get("num_turns"), "cost", d.get("total_cost_usd"), d.get("subtype"))
PY
