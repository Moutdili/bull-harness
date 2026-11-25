---
id: 3
title: "Isoler le juge dans son propre conteneur"
labels: [P0, area:verify, owner:claude, build]
status: doing
---

# Isoler le juge dans son propre conteneur

Point ouvert de la revue Mythos. Le juge lit du texte de la cible (arXiv:2507.08794, 2508.21669).

**Acceptation :** le juge ne voit ni /work du chasseur ni ses processus ; F1 revérifié

Plan : [docs/plan-v3.md](../plan-v3.md)

## Fait (code, 2026-11-25) — reste la validation live

- `container/compose.yaml` : service `judge` (`bh-judge`), image `localhost/bh-agent:dev`, réseau `sandbox` seul,
  même durcissement que `agent` (`no-new-privileges`, `cap_drop: ALL` + mêmes caps, `init: true`), 1024 pids, 4 Go.
  Son `/work` est `var/judge` (`:Z`), jamais `var/work`. CA du gate, `/opt/bh/bin`, hooks et code sandbox en lecture
  seule ; pas de modèles nuclei. Environnement commun agent/juge par ancre YAML (`x-sandbox-environment`).
- Relais du gate (`addon.py`) : `resolve_hosts` / `relay_client_allowed` admettent les IP de `agent` et `judge`
  (`BH_JUDGE_HOST`), rien d'autre ; une IP refusée relance au plus une résolution toutes les 5 s (juge recréé).
  Budget de requêtes inchangé : celui du run actif.
- `stack.py` : `agent_sh`, `push_file` prennent `container=` ; `prepare_judge` tourne dans `bh-judge` (process `judge`
  tués et attendus, `/tmp/bh-home-*` et fichiers temporaires du juge effacés, HOME et dossier recréés) ;
  `kill_agent` suit le dossier (`/work/<p>/.verify/...` → `bh-judge`) ; `in_container` réoriente la commande
  `claude -p` construite par `runner.agent_command` ; `wipe_program` vide aussi `var/judge/<p>`.
- `verify.py` : étages A et B dans `bh-judge`, preuve et prompt poussés, verdict relu dans
  `var/judge/<p>/.verify/F<id>/notes.jsonl` (nonce inchangé). Juge arrêté : `skipped`, finding laissé `new`.
- `bh up` crée `var/judge` ; `bh status` affiche `bh-judge`.

## Validation live (à faire, la stack tourne)

```
mkdir -p var/judge
podman-compose -f container/compose.yaml up -d --no-deps judge
# mitmdump recharge addon.py seul ; sinon, entre deux runs : podman restart bh-gate
podman exec bh-judge ls -A /work                            # vide (ou .verify) : rien de var/work
podman exec bh-judge ps -eo user,pid,args                   # aucun process du chasseur (keep-alive seul)
podman exec bh-agent ls /work/juiceshop/.verify 2>&1        # absent côté chasseur
uv run bh verify scopes/lab/juiceshop.yaml F1               # F1 revérifié
podman unshare ls var/judge/juiceshop/.verify/F1/           # notes.jsonl avec le verdict
grep '"relay' var/state/events.jsonl | tail                 # appels du juge relayés, aucun refus pour son IP
```
