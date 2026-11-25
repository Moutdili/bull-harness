---
id: 27
title: "Validation live du swarm autonomie"
labels: [P0, area:ops, owner:claude, owner:mio, measure]
status: closed
---

# Validation live du swarm autonomie

Commits 1e44589..e78d606 sur feat/autonomy.

**Acceptation :** gate redémarré ; suite d'évasion 29/29 ; un run lab sans aucune todo hors submit ; un .mcp.json planté n'est pas chargé (stream-json : aucun outil mcp__)

Plan : [docs/plan-v3.md](../plan-v3.md)

## Résultat du 2026-11-25 (commit f3120a8)

- `podman restart bh-gate`, puis `podman exec -i --user hunter bh-agent bash -s < tests/escape/escape_check.sh` : **29/29 PASS**, `failures: 0`.
- `uv run bh run scopes/lab/juiceshop.yaml --max-turns 12 --minutes 15` : run 19, 8 tours, $0.14 éq., `+0 blockers`, aucune todo créée.
- Événement `init` du stream-json (`var/runs/00019-*.jsonl`) : `tools: ['Bash', 'Read']`, `mcp_servers: []`.
- Board : migration `todos-v2` appliquée (4 `account` et 2 `other` → `obsolete`) ; ouvertes : 4 `submit` seulement.
- Reste : planter un `.mcp.json` pendant un segment n'est pas rejoué (l'effacement + `--strict-mcp-config` sont couverts par `tests/test_runner_sandbox.py`) ; un vrai refus du modèle et une vraie pause WAF n'ont pas été provoqués (pas de déclencheur sur le lab).
