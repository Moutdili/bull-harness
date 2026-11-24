# bull-harness

Autonomous bug bounty harness: one Claude Code agent in a Kali sandbox whose only network
path is a scope-enforcing gate. The host keeps the state (board), the human keeps the
decisions (todo, triage, submission).

```
 host (Fedora, rootless podman)
 ├─ bh CLI ─ runner ─ supervisor        var/board.sqlite: facts, intents, findings, todos, runs
 ├─ bh ui (Tailscale IP, token)         var/state: active scope, gate logs, identities
 │
 ├─ gate  (mitmproxy + bh.gate)  ── only container on the "egress" network
 │     scope allowlist · rate limit · program headers · identity injection · flow log
 │
 └─ agent (Kali + claude -p)     ── "sandbox" network: no route out except the gate
       bh.agent: builtins (bh-recon/crawl/content/scan/params/sqli/xss), bh-note, hooks
```

## Layout

| Path | Role |
|---|---|
| `src/bh/scope/` | scope schema v1 and the single decision function `check()` |
| `src/bh/gate/` | mitmproxy addon + policy (system / passive / target / deny) |
| `src/bh/agent/` | code that runs **inside** the sandbox (stdlib only): contract, builtins, hooks, bh-note |
| `src/bh/runner/` | one segment (`run.py`), board ingestion (`ingest.py`), doctrine (`prompt.py`), supervisor |
| `src/bh/board/` | SQLite board |
| `src/bh/ui/` | web UI (stdlib server, CSP, token cookie) |
| `src/bh/paths.py`, `stack.py`, `text.py` | filesystem layout, podman operations, text helpers |
| `container/` | compose file, agent and gate images, hook settings, `bh-agent` entry point |
| `scopes/` | one YAML per program (`scopes/lab/juiceshop.yaml` is the training lab) |
| `lab/` | lab helpers (Juice Shop identities) |

## First start

```sh
uv sync
claude setup-token                       # in your own terminal; never paste the token in a chat
printf 'CLAUDE_CODE_OAUTH_TOKEN=%s\n' '<token>' > secrets/agent.env && chmod 600 secrets/agent.env
uv run bh tools fetch                    # pinned nuclei-templates (the sandbox cannot reach GitHub)
uv run bh up --build                     # gate + agent (+ UI); first build takes a while
podman-compose -f container/compose.yaml --profile lab up -d juiceshop   # optional training target
podman exec -i bh-gate python3 - < lab/juiceshop/register_identities.py # lab accounts user-a / user-b
```

Recreate only the agent (never the whole pod while the lab runs):
`podman-compose -f container/compose.yaml up -d --force-recreate --no-deps agent`.

## Real programs (YesWeHack)

```sh
uv run bh scope import ywh <slug> --username <your YWH username>   # public program -> scopes/ywh/<slug>.yaml
```
The import never widens a scope and leaves `automation_allowed` to you; programs whose rules forbid
automated scanners get `scanners_allowed: false`. Full checklist: `docs/premiere-cible-ywh.md`.

## Running

```sh
uv run bh run scopes/lab/juiceshop.yaml --effort medium --minutes 30 --max-turns 50   # one segment
uv run bh hunt scopes/x.yaml scopes/y.yaml --hours 4 --effort medium                  # supervisor
uv run bh status · bh todo · bh finding [ID] [--set verified] · bh board frontier <program>
uv run bh board reset <program> --yes    # labs only: backup + forget the program + wipe its /work
```

Each segment is a fresh `claude -p` session (the board and the HANDOFF fact carry the state;
`--resume` opts into resuming, which re-reads the whole history every turn). Stopping `bh run` /
`bh hunt` (Ctrl-C, SIGTERM) kills the agent inside the container too.

## How the agent is kept honest

- **Scope**: the gate refuses anything `bh.scope.check()` does not allow; the sandbox has no other route.
  Raw TCP, exotic methods, unauthenticated writes, id enumeration and oversized bodies are refused too
  (`tests/escape/escape_check.sh` runs every bypass against the live gate).
- **Credentials**: the Claude OAuth token lives only in the gate, which relays the API on `gate:8081`;
  the agent holds a placeholder. Identity sessions are injected by the gate and redacted in its logs.
- **Tool lock**: hand-made HTTP to an origin is refused (PreToolUse hook) until `bh-crawl`,
  `bh-content` and `bh-scan` ran on it; the attack surface they find is put on the board as a work queue.
- **Data safety**: doctrine forbids state changes on objects not owned by our identities.
- **Findings**: 7-question gate + PoC file + "not proven" section; a human replays before submitting.
- **Metrics**: every run records arsenal / manual / locked command counts and token usage (`bh status`, UI).

## Tests

```sh
uv run pytest            # scope, gate policy, board, ingestion, sandbox contract, hooks, builtins parsing
podman exec -i --user hunter bh-agent bash -s < tests/escape/escape_check.sh   # live escape suite
uvx ruff check src tests
```
