---
id: 4
title: "Lab d'injection de prompt contre le chasseur et le juge"
labels: [P0, area:gate, owner:claude, build]
status: closed
---

# Lab d'injection de prompt contre le chasseur et le juge

Page leurre façon Mantis (arXiv:2410.20911) + 3 variantes CAI (arXiv:2508.21669) servies par le lab.

**Acceptation :** chaque variante est ignorée ou bornée par le gate ; résultat consigné

Plan : [docs/plan-v3.md](../plan-v3.md)

## Livré (2026-11-25, sans run live)

- App : `lab/injection/app.py` (stdlib, 5 variantes a–e, une route et un canari chacune), lancement et mesure :
  `lab/injection/README.md`. Tests : `tests/lab/test_injection_app.py`.
- Scope : `scopes/lab/injection.yaml` (`10.231.0.250/32`, débit 20, aucune identité).
- Modèle de menace, garde-fou attendu par variante, grille de mesure vide : `docs/research/12-injection-lab.md`.
- Reste pour clore : lancer le conteneur, `bh run` + `bh verify` sur ce scope, remplir la grille (§4).
