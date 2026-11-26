---
id: 10
title: "Masquage des anciennes observations ou rotation sur seuil de contexte (4.2b)"
labels: [P1, area:tokens, owner:claude, build]
status: open
---

# Masquage des anciennes observations ou rotation sur seuil de contexte (4.2b)

Selon la mesure P0. arXiv:2508.21433, 2510.00615.

**Acceptation :** à contexte égal, coût par tour -30 % sur le lab sans perte de findings

Plan : [docs/plan-v3.md](../plan-v3.md)

## Implémentation (2026-11-25) : rotation, pas masquage

Le contexte interne de Claude Code n'est pas modifiable (pas de masquage d'observations dans une session).
Le levier retenu est la **rotation** entre les legs d'un segment (`src/bh/runner/run.py`).

- **Mesure** : `turn_context(turn)` = `input + cache_read + cache_write` d'un tour de `turn_log` ;
  `leg_context(turns)` = (dernier tour, max) d'un leg. Le max par leg part dans le log du segment, une ligne
  `{"type": "bh_leg", "leg", "turns", "context_last", "context_max", "threshold", "overflow", "rotate"}`.
- **Seuil** : `CONTEXT_ROTATE_TOKENS` = 30 000, surchargeable par `BH_CONTEXT_ROTATE_TOKENS`. Justification
  (plan v3 §1) : base 8,4 à 10,3 k par tour, pic 19,4 k sur 22 tours (run 12). 30 k = 3 × la base,
  1,5 × le pic mesuré : un segment sain ne tourne jamais, un segment dont les observations s'empilent tourne.
- **Rotation** : si le dernier tour d'un leg dépasse le seuil, le leg suivant est une session neuve (pas de
  `--resume`). Avant, le runner ingère les notes du leg (`notes-<run>-leg<n>.jsonl`), écrit lui-même un fait
  `handoff` si aucun n'a été ingéré depuis le début du leg (« HANDOFF (runner): context rotation at N tokens » :
  findings du run, intents ouverts, dead-ends et faits du leg, dernière commande, chaque ligne bornée), resynchronise
  le graphe et repousse la frontière dans la sandbox. La tâche vient de `build_task(..., rotated=True)` :
  lire le HANDOFF et les faits, ne pas refaire.
- **Garde-fou** : à 2 × le seuil dans un leg, le lecteur du flux arrête le leg quand les résultats d'outils du
  tour en cours sont revenus (même kill que le timeout : `stack.kill_agent` puis `proc.kill`), compte les tours
  depuis `turn_log`, puis rotation (sauf si temps, tours ou `MAX_LEGS` sont épuisés).
- **Métriques** : `SegmentResult.rotations`, `SegmentResult.leg_context`, ligne finale « N context rotation(s) ».
  `finish` écrit `runs.rotations` et `runs.max_context` **seulement si les colonnes existent** (`run_set_known`).
  Changement requis dans `src/bh/board/db.py` (hors périmètre de ce lot) : ajouter à `MIGRATIONS`
  `("runs", "rotations", "INTEGER")` et `("runs", "max_context", "INTEGER")`.
- Tests : `tests/test_runner_rotation.py` (calcul, sous le seuil, au-dessus sans `--resume`, HANDOFF auto,
  coupure à 2 × le seuil, colonnes absentes).

## Mesure d'acceptation (à faire en live, aucun chiffre encore)

Critère : coût par tour −30 % à findings égaux. Aux mesures actuelles (pic 19 k), un segment lab de 60 tours
ne franchit probablement pas 30 k : la comparaison utilise donc un seuil abaissé pour la variante B, puis
on rejoue au défaut si B gagne.

1. Prérequis : migration `db.py` ci-dessus appliquée ; `bh up` ; Juice Shop du lab démarré.
2. Variante A (sans rotation) :
   `bh board reset lab-juiceshop --yes`, puis
   `BH_CONTEXT_ROTATE_TOKENS=10000000 bh run scopes/lab/juiceshop.yaml --max-turns 60 --minutes 45`.
3. Variante B (avec rotation) : même reset, puis
   `BH_CONTEXT_ROTATE_TOKENS=15000 bh run scopes/lab/juiceshop.yaml --max-turns 60 --minutes 45`
   (même modèle, même effort, même heure de la journée si possible ; 2 paires A/B au minimum).
4. Comparer, pour chaque run (`sqlite3 var/board.sqlite`) :
   `SELECT id, status, turns, cost_usd, input_tokens, cache_read, cache_write, output_tokens, rotations,
   max_context, cost_usd*1.0/turns AS cost_per_turn FROM runs WHERE program='lab-juiceshop' ORDER BY id DESC LIMIT 4;`
   le contexte par tour : `SELECT run_id, AVG(input+cache_read+cache_write), MAX(input+cache_read+cache_write)
   FROM turns GROUP BY run_id ORDER BY run_id DESC LIMIT 4;`
   et les findings : `SELECT run_id, COUNT(*), GROUP_CONCAT(vuln_class) FROM findings GROUP BY run_id ORDER BY run_id DESC LIMIT 4;`
5. Acceptation : B a `rotations ≥ 1`, `cost_per_turn(B) ≤ 0,7 × cost_per_turn(A)` sur la moyenne des paires,
   et le même ensemble de classes de findings vérifiés. Sinon : noter les chiffres ici, garder le seuil à 30 k
   ou l'ajuster d'après `max_context`.
